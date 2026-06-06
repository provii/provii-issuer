// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Nonce Durable Object for atomic replay prevention.
//!
//! Provides single-writer atomicity for nonce check-and-set operations,
//! eliminating the TOCTOU race window present in KV-based nonce storage.
//! Each DO instance stores nonces as individual keys with TTL-based expiry.
//!
//! Sharded across 25 instances via consistent hashing of the nonce value.

use crate::error::ApiError;
use serde::{Deserialize, Serialize};
use worker::*;

/// IV-211: Maximum body size for DO requests (4 KB). Nonce check-and-set
/// payloads are tiny; anything larger is suspicious.
const MAX_DO_BODY_SIZE: usize = 4096;

/// Maximum TTL a caller may request for a nonce (24 hours).
const MAX_NONCE_TTL_SECONDS: u64 = 86_400;

/// Maximum number of nonces stored per shard before triggering cleanup.
const MAX_NONCE_CAPACITY: u32 = 10_000;

/// IV-210: Typed request body for nonce check-and-set. Replaces untyped
/// serde_json::Value to enforce schema at deserialisation time.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NonceCheckRequest {
    nonce: String,
    ttl_seconds: u64,
}

/// Stored nonce record with creation and expiry timestamps.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NonceRecord {
    nonce: String,
    created_at: u64,
    expires_at: u64,
}

impl NonceRecord {
    /// Returns `true` when the nonce has NOT expired at the given
    /// timestamp. The boundary condition is inclusive: a record whose
    /// `expires_at` equals `now` is still valid, matching the `>=`
    /// check in `check_and_set_internal`.
    fn is_valid_at(&self, now: u64) -> bool {
        self.expires_at >= now
    }
}

/// Durable Object for atomic nonce consumption.
///
/// The single-writer guarantee of Durable Objects means that two concurrent
/// requests with the same nonce will be serialised: one succeeds, one is
/// rejected. This is impossible to achieve with KV's eventual consistency.
#[durable_object]
pub struct NonceDO {
    state: State,
    #[allow(dead_code)] // Required by #[durable_object] proc macro
    env: Env,
}

impl DurableObject for NonceDO {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path();

        match (req.method(), path) {
            (Method::Post, "/check-and-set") => self.handle_check_and_set(req).await,
            _ => ApiError::NotFound("Not found".into()).to_response(),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        let now = Date::now().as_millis() / 1000;
        let map = self.state.storage().list().await?;
        let keys_array = js_sys::Array::from(&map.keys());
        let key_count = keys_array.length().min(MAX_NONCE_CAPACITY);
        let mut deleted = 0u32;
        let mut earliest_remaining: Option<u64> = None;

        for i in 0..key_count {
            let Some(key) = keys_array.get(i).as_string() else {
                continue;
            };
            if !key.starts_with("nonce:") {
                continue;
            }

            let existing: Option<Vec<u8>> = self
                .state
                .storage()
                .get::<Vec<u8>>(&key)
                .await
                .ok()
                .flatten();
            if let Some(data) = existing {
                if let Ok(record) = serde_json::from_slice::<NonceRecord>(&data) {
                    if !record.is_valid_at(now) {
                        let _ = self.state.storage().delete(&key).await;
                        deleted = deleted.saturating_add(1);
                    } else {
                        earliest_remaining = Some(match earliest_remaining {
                            Some(e) => e.min(record.expires_at),
                            None => record.expires_at,
                        });
                    }
                }
            }
        }

        if let Some(next_expiry) = earliest_remaining {
            let delay_secs = next_expiry.saturating_sub(now).max(1);
            let delay_ms = i64::try_from(delay_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
            self.state.storage().set_alarm(delay_ms).await?;
        }

        crate::log!("NonceDO: alarm cleaned {} expired nonces", deleted);
        Response::ok("Cleanup completed")
    }
}

impl NonceDO {
    /// Atomically check whether a nonce has been consumed, and consume it if not.
    ///
    /// Returns 200 with `{"stored": true}` on first use, or 409 with
    /// `{"stored": false}` if the nonce was already consumed.
    async fn handle_check_and_set(&self, mut req: Request) -> Result<Response> {
        // IV-211: Enforce body size limit on DO requests.
        let body_bytes = req
            .bytes()
            .await
            .map_err(|e| worker::Error::RustError(format!("Failed to read body: {}", e)))?;
        if body_bytes.len() > MAX_DO_BODY_SIZE {
            return ApiError::PayloadTooLarge("Request body too large".into()).to_response();
        }

        // IV-210: Deserialise into typed struct rather than serde_json::Value.
        let parsed: NonceCheckRequest = serde_json::from_slice(&body_bytes)
            .map_err(|e| worker::Error::RustError(format!("Invalid JSON: {}", e)))?;

        let stored = self
            .check_and_set_internal(&parsed.nonce, parsed.ttl_seconds)
            .await?;

        if stored {
            Response::from_json(&serde_json::json!({
                "stored": true,
                "message": "Nonce stored successfully"
            }))
        } else {
            Ok(Response::from_json(&serde_json::json!({
                "stored": false,
                "message": "Nonce already used"
            }))?
            .with_status(409))
        }
    }

    /// Core check-and-set logic. Checks DO storage for the nonce, and if absent
    /// (or expired), inserts it. Returns true if newly stored, false if replay.
    async fn check_and_set_internal(&self, nonce: &str, ttl_seconds: u64) -> Result<bool> {
        if ttl_seconds == 0 {
            return Err(worker::Error::RustError(
                "ttl_seconds must be at least 1".into(),
            ));
        }
        if ttl_seconds > MAX_NONCE_TTL_SECONDS {
            return Err(worker::Error::RustError(format!(
                "ttl_seconds exceeds maximum of {}",
                MAX_NONCE_TTL_SECONDS
            )));
        }

        let storage_key = format!("nonce:{}", nonce);

        let existing: Option<Vec<u8>> = self
            .state
            .storage()
            .get::<Vec<u8>>(&storage_key)
            .await
            .map_err(|e| worker::Error::RustError(format!("Failed to check nonce: {}", e)))?;

        if let Some(data) = existing {
            match serde_json::from_slice::<NonceRecord>(&data) {
                Ok(record) => {
                    let now = Date::now().as_millis() / 1000;

                    if record.is_valid_at(now) {
                        return Ok(false);
                    }
                    let _ = self.state.storage().delete(&storage_key).await;
                }
                Err(_) => {
                    return Ok(false);
                }
            }
        }

        // Capacity check: if nonce count exceeds threshold, purge expired entries first
        let map = self.state.storage().list().await?;
        let entry_count = js_sys::Array::from(&map.keys()).length();
        if entry_count >= MAX_NONCE_CAPACITY {
            self.purge_expired_nonces().await?;
        }

        let now = Date::now().as_millis() / 1000;

        let record = NonceRecord {
            nonce: nonce.to_string(),
            created_at: now,
            expires_at: now.saturating_add(ttl_seconds),
        };

        let data =
            serde_json::to_vec(&record).map_err(|e| worker::Error::RustError(e.to_string()))?;
        self.state
            .storage()
            .put(&storage_key, data)
            .await
            .map_err(|e| worker::Error::RustError(format!("Failed to store nonce: {}", e)))?;

        // Schedule alarm for cleanup at expiry time
        let alarm_offset_ms = i64::try_from(ttl_seconds.saturating_mul(1000)).unwrap_or(i64::MAX);
        self.state.storage().set_alarm(alarm_offset_ms).await?;

        Ok(true)
    }

    /// Purge expired nonces to reclaim capacity.
    async fn purge_expired_nonces(&self) -> Result<()> {
        let now = Date::now().as_millis() / 1000;
        let map = self.state.storage().list().await?;
        let keys_array = js_sys::Array::from(&map.keys());
        let key_count = keys_array.length().min(MAX_NONCE_CAPACITY);

        for i in 0..key_count {
            let Some(key) = keys_array.get(i).as_string() else {
                continue;
            };
            if !key.starts_with("nonce:") {
                continue;
            }
            let existing: Option<Vec<u8>> = self
                .state
                .storage()
                .get::<Vec<u8>>(&key)
                .await
                .ok()
                .flatten();
            if let Some(data) = existing {
                if let Ok(record) = serde_json::from_slice::<NonceRecord>(&data) {
                    if !record.is_valid_at(now) {
                        let _ = self.state.storage().delete(&key).await;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_record_serialisation_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let record = NonceRecord {
            nonce: "abc123".to_string(),
            created_at: 1000,
            expires_at: 1300,
        };
        let bytes = serde_json::to_vec(&record)?;
        let decoded: NonceRecord = serde_json::from_slice(&bytes)?;
        assert_eq!(decoded.nonce, "abc123");
        assert_eq!(decoded.created_at, 1000);
        assert_eq!(decoded.expires_at, 1300);
        Ok(())
    }

    #[test]
    fn test_storage_key_format() {
        let key = format!("nonce:{}", "deadbeef01234567");
        assert_eq!(key, "nonce:deadbeef01234567");
    }

    #[test]
    fn test_expiry_check_not_expired() {
        let record = NonceRecord {
            nonce: "abc".to_string(),
            created_at: 1000,
            expires_at: 1300,
        };
        assert!(
            record.is_valid_at(1000),
            "nonce must be valid at creation time"
        );
        assert!(
            record.is_valid_at(1200),
            "nonce must be valid before expiry"
        );
    }

    #[test]
    fn test_expiry_check_expired() {
        let record = NonceRecord {
            nonce: "abc".to_string(),
            created_at: 1000,
            expires_at: 1300,
        };
        assert!(
            !record.is_valid_at(1301),
            "nonce must be invalid after expiry"
        );
        assert!(
            !record.is_valid_at(u64::MAX),
            "nonce must be invalid at far future"
        );
    }

    #[test]
    fn test_expiry_check_boundary() {
        let record = NonceRecord {
            nonce: "abc".to_string(),
            created_at: 1000,
            expires_at: 1300,
        };
        // At exact boundary, nonce is still valid (>=)
        assert!(
            record.is_valid_at(1300),
            "nonce must be valid at exact expiry time"
        );
        assert!(
            !record.is_valid_at(1301),
            "nonce must be invalid one second after expiry"
        );
    }

    #[test]
    fn test_nonce_record_deny_unknown_fields_not_enforced() {
        // NonceRecord is an internal storage type. Ensure extra fields
        // in stored JSON do not break deserialisation (forward compat
        // for schema evolution).
        let json = r#"{"nonce":"x","created_at":1,"expires_at":2,"extra":"ignored"}"#;
        let record: NonceRecord =
            serde_json::from_str(json).expect("extra fields must be tolerated"); // nosemgrep: expect-on-external-input
        assert_eq!(record.nonce, "x");
        assert_eq!(record.created_at, 1);
        assert_eq!(record.expires_at, 2);
    }

    #[test]
    fn test_nonce_check_request_rejects_unknown_fields() {
        // NonceCheckRequest uses deny_unknown_fields. Extra fields in
        // the DO request body must be rejected to prevent parameter
        // smuggling.
        let json = r#"{"nonce":"x","ttl_seconds":60,"extra":"bad"}"#;
        let result = serde_json::from_str::<NonceCheckRequest>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields must reject extra fields"
        );
    }
}
