// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Durable Object implementation for atomic resource consumption.
//!
//! Provides globally coordinated, race-condition-free resource consumption across all Cloudflare edge locations.
//! Each Durable Object instance handles atomic operations for a specific resource (e.g., one-time tokens, nonces, challenges).
//!
//! ## Features
//! - Atomic consume operations (no race conditions)
//! - Idempotency checking (prevent double-consumption)
//! - TTL-based automatic cleanup
//! - Global coordination across edge network
//! - One-time use token enforcement
//!
//! ## Use Cases
//! 1. **Pickup Token Consumption**: Ensure credential pickup tokens are only used once
//! 2. **Challenge Consumption**: Prevent YubiKey challenge reuse
//! 3. **Nonce Validation**: Guarantee nonces are consumed exactly once
//! 4. **Quota Enforcement**: Atomic increment/decrement of quotas
//!
//! ## Race Condition Prevention
//!
//! Without Durable Objects, KV's eventual consistency allows race conditions:
//! ```text
//! Time  Request A                Request B
//! ----  --------                --------
//! T0    GET pickup:ABC          -
//! T1    (returns value)         GET pickup:ABC
//! T2    DELETE pickup:ABC       (returns value)
//! T3    -                       DELETE pickup:ABC
//!       ✓ SUCCESS               ✓ SUCCESS (DOUBLE CONSUMPTION!)
//! ```
//!
//! With Durable Objects, atomic operations prevent this:
//! ```text
//! Time  Request A                Request B
//! ----  --------                --------
//! T0    POST /consume           -
//! T1    (check consumed=false)  POST /consume
//! T2    (set consumed=true)     (check consumed=true)
//! T3    ✓ SUCCESS               ✗ REJECTED (already consumed)
//! ```
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐
//! │   Worker    │
//! │  (routes.rs)│
//! └──────┬──────┘
//!        │ 1. Atomic check-and-consume
//!        ▼
//! ┌─────────────────────────┐
//! │  ResourceLockDO         │
//! │  (Durable Object)       │
//! │  ┌─────────────────┐    │
//! │  │ consumed: bool  │    │ ◄─ Atomic state
//! │  │ timestamp: i64  │    │
//! │  │ metadata: JSON  │    │
//! │  └─────────────────┘    │
//! └──────┬──────────────────┘
//!        │ 2. If not consumed, retrieve from KV
//!        ▼
//! ┌─────────────┐
//! │ KV Storage  │
//! │  (pickup:*) │
//! └─────────────┘
//! ```

use crate::error::ApiError;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use worker::*;

/// Return the current epoch seconds from `Date::now()` as `i64`, clamped
/// to `i64::MAX` (unreachable in practice since JS timestamps are sub-2^53).
#[inline]
fn now_epoch_secs() -> i64 {
    let millis = Date::now().as_millis();
    // as_millis returns u64; dividing by 1000 first keeps the value well
    // within i64 range for any realistic timestamp.
    #[allow(clippy::arithmetic_side_effects)]
    let secs = millis / 1000;
    i64::try_from(secs).unwrap_or(i64::MAX)
}

/// Return the TTL in seconds for a given resource type.
///
/// Single source of truth for consumption record TTLs. Used by
/// `consume_resource`, `check_consumed`, and the `alarm` handler.
fn resource_ttl_seconds(resource_type: &str) -> i64 {
    match resource_type {
        "pickup" => 300,    // 5 minutes (matches PICKUP_TTL_SECONDS)
        "challenge" => 120, // 2 minutes (matches CHALLENGE_TTL_SECONDS)
        "nonce" => 300,     // 5 minutes (matches NONCE_TTL_SECONDS)
        "quota" => 3600,    // 1 hour (session lifetime)
        _ => 300,           // Default 5 minutes
    }
}

/// Validate a lock name or resource key for length and charset.
/// Permitted: ASCII alphanumeric, hyphen, underscore, colon, period.
fn validate_lock_name(name: &str) -> std::result::Result<(), ApiError> {
    if name.is_empty() {
        return Err(ApiError::BadRequest("Lock name must not be empty".into()));
    }
    if name.len() > MAX_LOCK_NAME_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "Lock name too long (max {} characters)",
            MAX_LOCK_NAME_LENGTH
        )));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b':' || b == b'.')
    {
        return Err(ApiError::BadRequest(
            "Lock name contains invalid characters (allowed: alphanumeric, hyphen, underscore, colon, period)".into(),
        ));
    }
    Ok(())
}

/// Request to consume a one-time resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeResourceRequest {
    /// Type of resource being consumed (e.g., "pickup", "challenge", "nonce")
    pub resource_type: String,
    /// Unique identifier for the resource
    pub resource_id: String,
    /// Optional metadata to store with consumption record
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Response from resource consumption check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumeResourceResponse {
    /// Whether consumption is allowed (true = first time, false = already consumed)
    pub allowed: bool,
    /// Human-readable reason for the result
    pub reason: String,
    /// Timestamp when resource was first consumed (if already consumed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<i64>,
    /// Metadata from first consumption (if already consumed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_metadata: Option<serde_json::Value>,
}

/// Request to check if a resource has been consumed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckConsumedRequest {
    /// Type of resource
    pub resource_type: String,
    /// Resource identifier
    pub resource_id: String,
}

/// Response from consumption check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckConsumedResponse {
    /// Whether the resource has been consumed
    pub consumed: bool,
    /// Timestamp when consumed (if consumed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<i64>,
    /// Metadata from consumption (if consumed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Maximum TTL for a held lock (30 seconds).
pub const MAX_LOCK_TTL_SECONDS: i64 = 30;

/// Maximum length for a lock name / resource key (256 bytes).
const MAX_LOCK_NAME_LENGTH: usize = 256;

/// Maximum length for a lock token (256 bytes). Prevents abuse via
/// oversized tokens that waste storage and constant-time comparison time.
const MAX_LOCK_TOKEN_LENGTH: usize = 256;

/// Maximum entries returned from a single list() call during alarm cleanup.
const MAX_LIST_ENTRIES: u32 = 1000;

/// Maximum body size accepted by DO endpoints (4 KiB).
const MAX_DO_BODY_SIZE: usize = 4096;

/// Number of ResourceLockDO shards for distributing load.
pub const RESOURCE_LOCK_SHARD_COUNT: usize = 25;

/// Request to acquire a mutex-style lock on a resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcquireLockRequest {
    /// Caller-chosen token to prove ownership when releasing.
    pub lock_token: String,
    /// Lock TTL in seconds (capped at MAX_LOCK_TTL_SECONDS).
    pub ttl_seconds: u64,
    /// Resource key for per-resource isolation within a shard.
    /// When multiple resources hash to the same DO shard, this field
    /// ensures each resource gets its own storage key.
    #[serde(default)]
    pub resource_key: String,
}

/// Response from lock acquisition attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquireLockResponse {
    /// Whether the lock was acquired.
    pub acquired: bool,
    /// Human-readable reason.
    pub reason: String,
}

/// Request to release a previously acquired lock.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseLockRequest {
    /// Must match the token used to acquire.
    pub lock_token: String,
    /// Resource key for per-resource isolation within a shard.
    /// Must match the resource_key used during acquire.
    #[serde(default)]
    pub resource_key: String,
}

/// Response from lock release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseLockResponse {
    /// Whether the lock was released.
    pub released: bool,
    /// Human-readable reason.
    pub reason: String,
}

/// Internal storage for a held lock.
#[derive(Clone, Serialize, Deserialize)]
struct LockRecord {
    lock_token: String,
    acquired_at: i64,
    expires_at: i64,
    /// Resource key, stored so alarm cleanup can identify which resource this lock belongs to.
    #[serde(default)]
    resource_key: String,
}

impl core::fmt::Debug for LockRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LockRecord")
            .field("lock_token", &"[REDACTED]")
            .field("acquired_at", &self.acquired_at)
            .field("expires_at", &self.expires_at)
            .field("resource_key", &self.resource_key)
            .finish()
    }
}

/// Internal storage format for consumption records.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConsumptionRecord {
    /// Timestamp when resource was consumed
    consumed_at: i64,
    /// Resource type for debugging
    resource_type: String,
    /// Resource ID for debugging
    resource_id: String,
    /// Optional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
}

/// Durable Object for atomic resource consumption and mutual exclusion.
///
/// Each instance is identified by a unique name (resource_type:resource_id)
/// and provides atomic operations to prevent race conditions.
///
/// Supports two usage patterns:
/// - **Consume**: One-time atomic consumption (challenges, nonces, pickup tokens)
/// - **Lock/Unlock**: Mutex-style acquire/release for KV read-modify-write
#[durable_object]
pub struct ResourceLockDO {
    state: State,
    env: Env,
}

impl DurableObject for ResourceLockDO {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path().to_string();
        let method = req.method();

        // Enforce body size limit on POST endpoints before parsing.
        if method == Method::Post {
            let body_bytes = req.bytes().await?;
            if body_bytes.len() > MAX_DO_BODY_SIZE {
                return ApiError::PayloadTooLarge("Request body too large".into()).to_response();
            }
            // Re-wrap the body into a new Request so downstream handlers can
            // call req.json() as before.
            let body_str = match String::from_utf8(body_bytes) {
                Ok(s) => s,
                Err(_) => {
                    return ApiError::BadRequest("Request body is not valid UTF-8".into())
                        .to_response();
                }
            };
            let headers = worker::Headers::new();
            headers.set("Content-Type", "application/json")?;
            let mut init = RequestInit::new();
            init.with_method(Method::Post)
                .with_headers(headers)
                .with_body(Some(wasm_bindgen::JsValue::from_str(&body_str)));
            let rebuilt = Request::new_with_init(url.as_str(), &init)?;
            return match path.as_str() {
                "/consume" => self.consume_resource(rebuilt).await,
                "/check" => self.check_consumed(rebuilt).await,
                "/reset" => self.reset_resource(rebuilt).await,
                "/acquire" => self.handle_acquire_lock(rebuilt).await,
                "/release" => self.handle_release_lock(rebuilt).await,
                _ => ApiError::NotFound("Not Found".into()).to_response(),
            };
        }

        match (method, path.as_str()) {
            (Method::Get, "/health") => Response::ok("OK"),
            _ => ApiError::NotFound("Not Found".into()).to_response(),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        // Scan all storage keys for expired consumed:* and lock:* entries.
        // Multiple resources may share a shard, so we iterate over all keys
        // and delete only those whose TTL has elapsed.
        let now = now_epoch_secs();
        let map = self.state.storage().list().await?;
        let mut deleted = 0u32;
        let mut earliest_remaining: Option<i64> = None;

        // Collect key names from the JS Map. Convert the Map's key iterator
        // into a JS Array so we can index it; closures passed to
        // Map::for_each cannot be async, so we need indexed access.
        let keys_array = js_sys::Array::from(&map.keys());
        let mut storage_keys: Vec<String> = Vec::new();
        let key_count = keys_array.length().min(MAX_LIST_ENTRIES);
        for i in 0..key_count {
            if let Some(k) = keys_array.get(i).as_string() {
                storage_keys.push(k);
            }
        }

        for key in &storage_keys {
            if key.starts_with("consumed:") {
                let record: Option<ConsumptionRecord> =
                    self.state.storage().get(key).await.ok().flatten();
                if let Some(r) = record {
                    let ttl = resource_ttl_seconds(&r.resource_type);
                    let expires_at = r.consumed_at.saturating_add(ttl);
                    if now >= expires_at {
                        let _ = self.state.storage().delete(key).await;
                        deleted = deleted.saturating_add(1);
                    } else {
                        earliest_remaining = Some(match earliest_remaining {
                            Some(e) => e.min(expires_at),
                            None => expires_at,
                        });
                    }
                }
            } else if key.starts_with("lock:") {
                let record: Option<LockRecord> = self.state.storage().get(key).await.ok().flatten();
                if let Some(r) = record {
                    if now >= r.expires_at {
                        let _ = self.state.storage().delete(key).await;
                        deleted = deleted.saturating_add(1);
                    } else {
                        earliest_remaining = Some(match earliest_remaining {
                            Some(e) => e.min(r.expires_at),
                            None => r.expires_at,
                        });
                    }
                }
            }
        }

        // Reschedule alarm for the next expiry if any records remain
        if let Some(next_expiry) = earliest_remaining {
            let delay_ms = next_expiry.saturating_sub(now).max(1).saturating_mul(1000);
            self.state.storage().set_alarm(delay_ms).await?;
            crate::log!(
                "ResourceLockDO: alarm cleaned {} records, rescheduled for next expiry",
                deleted
            );
        } else {
            crate::log!(
                "ResourceLockDO: alarm cleaned {} records, no remaining entries",
                deleted
            );
        }

        Response::ok("Cleanup completed")
    }
}

impl ResourceLockDO {
    /// Atomically consume a one-time resource.
    ///
    /// This is the core method that prevents race conditions. It:
    /// 1. Checks if the resource has already been consumed (ATOMIC READ)
    /// 2. If not consumed, marks it as consumed (ATOMIC WRITE)
    /// 3. Returns success/failure in a single atomic operation
    ///
    /// ## Concurrency Safety
    ///
    /// Because Durable Objects guarantee single-threaded execution per instance,
    /// this method is inherently atomic. No two requests can execute this method
    /// simultaneously for the same resource.
    ///
    /// ## Example
    ///
    /// ```json
    /// // Request
    /// POST /consume
    /// {
    ///   "resource_type": "pickup",
    ///   "resource_id": "ABC123DEF4567890",
    ///   "metadata": {
    ///     "session_id": "uuid-here",
    ///     "ip_address": "1.2.3.4"
    ///   }
    /// }
    ///
    /// // Response (first attempt)
    /// {
    ///   "allowed": true,
    ///   "reason": "Resource consumed successfully"
    /// }
    ///
    /// // Response (second attempt)
    /// {
    ///   "allowed": false,
    ///   "reason": "Resource already consumed",
    ///   "consumed_at": 1700000000,
    ///   "first_metadata": { ... }
    /// }
    /// ```
    async fn consume_resource(&self, mut req: Request) -> Result<Response> {
        let body: ConsumeResourceRequest = req.json().await?;

        // Validate resource_type and resource_id format.
        if let Err(e) = crate::storage::validate_identifier(&body.resource_type, "resource_type") {
            return e.to_response();
        }
        if let Err(e) = crate::storage::validate_identifier(&body.resource_id, "resource_id") {
            return e.to_response();
        }

        // Per-resource storage key within the shard. Multiple resources may
        // hash to the same DO shard, so the key must include the resource
        // identity to prevent cross-resource overwrites.
        let key = format!("consumed:{}:{}", body.resource_type, body.resource_id);

        // ATOMIC OPERATION: Check if already consumed
        let existing: Option<ConsumptionRecord> =
            self.state.storage().get(&key).await.ok().flatten();

        if let Some(record) = existing {
            // Check whether the existing record has expired. If the alarm
            // has not yet fired but the TTL window has elapsed, treat it
            // as expired: delete the stale record and allow re-consumption.
            let now = now_epoch_secs();
            let ttl_seconds = resource_ttl_seconds(&record.resource_type);

            if now > record.consumed_at.saturating_add(ttl_seconds) {
                crate::log!(
                    "Resource {}:{} consumption record expired (consumed_at={}, ttl={}s), allowing re-consumption",
                    body.resource_type,
                    body.resource_id,
                    record.consumed_at,
                    ttl_seconds
                );
                let _ = self.state.storage().delete(&key).await;
                // Fall through to the fresh-consumption path below.
            } else {
                // Resource already consumed and still within TTL window.
                crate::log!(
                    "Resource {}:{} already consumed at {}",
                    body.resource_type,
                    body.resource_id,
                    record.consumed_at
                );

                return Response::from_json(&ConsumeResourceResponse {
                    allowed: false,
                    reason: "Resource already consumed".to_string(),
                    consumed_at: Some(record.consumed_at),
                    first_metadata: record.metadata,
                });
            }
        }

        // Resource not consumed yet - mark as consumed
        let now = now_epoch_secs();

        let record = ConsumptionRecord {
            consumed_at: now,
            resource_type: body.resource_type.clone(),
            resource_id: body.resource_id.clone(),
            metadata: body.metadata,
        };

        // ATOMIC OPERATION: Store consumption record
        self.state.storage().put(&key, record).await?;

        // Set alarm for TTL-based cleanup
        let ttl_seconds = resource_ttl_seconds(&body.resource_type);

        // set_alarm(i64) is an offset from now in milliseconds
        let alarm_offset_ms = ttl_seconds.saturating_mul(1000);
        self.state.storage().set_alarm(alarm_offset_ms).await?;

        crate::log!(
            "Resource {}:{} consumed successfully, TTL={}s",
            body.resource_type,
            body.resource_id,
            ttl_seconds
        );

        Response::from_json(&ConsumeResourceResponse {
            allowed: true,
            reason: "Resource consumed successfully".to_string(),
            consumed_at: None,
            first_metadata: None,
        })
    }

    /// Check if a resource has been consumed without consuming it.
    ///
    /// This is useful for idempotency checks where you want to know
    /// if a resource was already consumed but don't want to consume it yourself.
    ///
    /// ## Example
    ///
    /// ```json
    /// // Request
    /// POST /check
    /// {
    ///   "resource_type": "pickup",
    ///   "resource_id": "ABC123DEF4567890"
    /// }
    ///
    /// // Response (consumed)
    /// {
    ///   "consumed": true,
    ///   "consumed_at": 1700000000,
    ///   "metadata": { ... }
    /// }
    ///
    /// // Response (not consumed)
    /// {
    ///   "consumed": false
    /// }
    /// ```
    async fn check_consumed(&self, mut req: Request) -> Result<Response> {
        let body: CheckConsumedRequest = req.json().await?;

        // Validate resource_type and resource_id format.
        if let Err(e) = crate::storage::validate_identifier(&body.resource_type, "resource_type") {
            return e.to_response();
        }
        if let Err(e) = crate::storage::validate_identifier(&body.resource_id, "resource_id") {
            return e.to_response();
        }

        let key = format!("consumed:{}:{}", body.resource_type, body.resource_id);

        // Check if consumed
        let record: Option<ConsumptionRecord> = self.state.storage().get(&key).await.ok().flatten();

        match record {
            Some(r) => {
                // Check whether the record has expired before reporting
                // consumed:true. Without this, callers would see a stale
                // "consumed" flag for records whose TTL has elapsed but whose
                // alarm cleanup has not yet fired.
                let now = now_epoch_secs();
                let ttl_seconds = resource_ttl_seconds(&r.resource_type);
                if now > r.consumed_at.saturating_add(ttl_seconds) {
                    // Expired: clean up and report not consumed.
                    let _ = self.state.storage().delete(&key).await;
                    Response::from_json(&CheckConsumedResponse {
                        consumed: false,
                        consumed_at: None,
                        metadata: None,
                    })
                } else {
                    Response::from_json(&CheckConsumedResponse {
                        consumed: true,
                        consumed_at: Some(r.consumed_at),
                        metadata: r.metadata,
                    })
                }
            }
            None => Response::from_json(&CheckConsumedResponse {
                consumed: false,
                consumed_at: None,
                metadata: None,
            }),
        }
    }

    /// Reset a resource (for testing only).
    ///
    /// This allows resetting the consumption state of a resource.
    /// **WARNING**: This should only be used in testing environments.
    /// Production deployments should disable this endpoint.
    ///
    /// ## Example
    ///
    /// ```json
    /// POST /reset
    /// {
    ///   "resource_type": "pickup",
    ///   "resource_id": "ABC123DEF4567890"
    /// }
    /// ```
    async fn reset_resource(&self, mut req: Request) -> Result<Response> {
        let body: CheckConsumedRequest = req.json().await?;

        // Use an allowlist of permitted environments instead of a
        // blocklist. Novel or unknown environment names are treated as
        // production and denied. Only explicitly listed non-production
        // environments may perform resets.
        //
        // NOTE: This endpoint is only reachable via internal Durable Object
        // fetch (not exposed as a public HTTP route). The environment
        // allowlist is defence-in-depth: even if a caller somehow reaches
        // this handler, production environments are unconditionally blocked.
        let environment = self
            .env
            .var("ENVIRONMENT")
            .map(|v| v.to_string().to_lowercase())
            .unwrap_or_else(|_| "production".to_string());

        let allowed_reset_envs = ["sandbox", "development", "test", "staging"];
        if !allowed_reset_envs.contains(&environment.as_str()) {
            crate::log!(
                "[SECURITY] Reset attempt blocked in environment={} for resource {}:{}",
                environment,
                body.resource_type,
                body.resource_id
            );
            return ApiError::Forbidden("Reset not allowed in this environment".into())
                .to_response();
        }

        // Validate resource_type and resource_id format before using in
        // storage key to prevent injection into the key namespace.
        if let Err(e) = crate::storage::validate_identifier(&body.resource_type, "resource_type") {
            return e.to_response();
        }
        if let Err(e) = crate::storage::validate_identifier(&body.resource_id, "resource_id") {
            return e.to_response();
        }

        let key = format!("consumed:{}:{}", body.resource_type, body.resource_id);

        // Delete the consumption record
        self.state.storage().delete(&key).await?;

        crate::log!(
            "[AUDIT] Resource {}:{} reset in environment={}",
            body.resource_type,
            body.resource_id,
            environment
        );

        Response::from_json(&ConsumeResourceResponse {
            allowed: true,
            reason: "Resource reset successfully".to_string(),
            consumed_at: None,
            first_metadata: None,
        })
    }

    /// Acquire a mutex-style lock on this DO instance.
    ///
    /// The caller provides a unique `lock_token` and a `ttl_seconds` value.
    /// If no lock is currently held (or the existing lock has expired), the
    /// lock is granted. Otherwise acquisition is rejected.
    ///
    /// The lock_token must be presented again to release the lock.
    /// TTL is capped at 30 seconds to prevent indefinite resource starvation.
    ///
    /// ## Concurrency Safety
    ///
    /// Durable Objects guarantee single-threaded execution per instance, so
    /// the check-then-set is inherently atomic.
    async fn handle_acquire_lock(&self, mut req: Request) -> Result<Response> {
        let body: AcquireLockRequest = req.json().await?;

        if body.lock_token.is_empty() {
            return ApiError::BadRequest("lock_token is required".into()).to_response();
        }

        if body.lock_token.len() > MAX_LOCK_TOKEN_LENGTH {
            return ApiError::BadRequest(format!(
                "lock_token too long (max {} characters)",
                MAX_LOCK_TOKEN_LENGTH
            ))
            .to_response();
        }

        if body.ttl_seconds == 0 {
            return ApiError::BadRequest("ttl_seconds must be at least 1".into()).to_response();
        }

        if let Err(e) = validate_lock_name(&body.resource_key) {
            return e.to_response();
        }

        let ttl = i64::try_from(body.ttl_seconds)
            .unwrap_or(i64::MAX)
            .min(MAX_LOCK_TTL_SECONDS);
        let now = now_epoch_secs();
        // Per-resource storage key within the shard. Multiple resources may
        // hash to the same DO shard, so include the resource key.
        let lock_key = format!("lock:{}", body.resource_key);

        // Check for an existing, non-expired lock
        let existing: Option<LockRecord> = self.state.storage().get(&lock_key).await.ok().flatten();

        if let Some(record) = existing {
            if now < record.expires_at {
                // Lock is still held by another caller
                return Response::from_json(&AcquireLockResponse {
                    acquired: false,
                    reason: "Lock held by another caller".to_string(),
                });
            }
            // Existing lock has expired; fall through to grant
        }

        // Grant the lock
        let record = LockRecord {
            lock_token: body.lock_token,
            acquired_at: now,
            expires_at: now.saturating_add(ttl),
            resource_key: body.resource_key,
        };
        self.state.storage().put(&lock_key, record).await?;

        // set_alarm(i64) is an offset from now in milliseconds
        let alarm_offset_ms = ttl.saturating_add(1).saturating_mul(1000);
        self.state.storage().set_alarm(alarm_offset_ms).await?;

        Response::from_json(&AcquireLockResponse {
            acquired: true,
            reason: "Lock acquired".to_string(),
        })
    }

    /// Release a previously acquired lock.
    ///
    /// The caller must provide the same `lock_token` used to acquire the lock.
    /// If the token does not match (or the lock has already expired), the
    /// release is rejected or treated as a no-op respectively.
    async fn handle_release_lock(&self, mut req: Request) -> Result<Response> {
        let body: ReleaseLockRequest = req.json().await?;

        if body.lock_token.is_empty() {
            return ApiError::BadRequest("lock_token is required".into()).to_response();
        }

        if body.lock_token.len() > MAX_LOCK_TOKEN_LENGTH {
            return ApiError::BadRequest(format!(
                "lock_token too long (max {} characters)",
                MAX_LOCK_TOKEN_LENGTH
            ))
            .to_response();
        }

        if let Err(e) = validate_lock_name(&body.resource_key) {
            return e.to_response();
        }

        // Per-resource storage key within the shard.
        let lock_key = format!("lock:{}", body.resource_key);
        let existing: Option<LockRecord> = self.state.storage().get(&lock_key).await.ok().flatten();

        match existing {
            Some(record) => {
                // Constant-time comparison: lock_token is a secret value
                // that proves ownership. Timing differences could let an
                // attacker brute-force valid tokens.
                let tokens_match: bool = record
                    .lock_token
                    .as_bytes()
                    .ct_eq(body.lock_token.as_bytes())
                    .into();
                if !tokens_match {
                    return Response::from_json(&ReleaseLockResponse {
                        released: false,
                        reason: "Token mismatch".to_string(),
                    });
                }
                self.state.storage().delete(&lock_key).await?;
                Response::from_json(&ReleaseLockResponse {
                    released: true,
                    reason: "Lock released".to_string(),
                })
            }
            None => {
                // Lock already expired or was never held
                Response::from_json(&ReleaseLockResponse {
                    released: true,
                    reason: "Lock not held (already expired or released)".to_string(),
                })
            }
        }
    }
}

/// Compute the shard index for a given resource key.
///
/// Uses the same consistent-hashing approach as NonceDO sharding.
///
/// FNV-1a is not cryptographic, so an attacker who controls
/// the resource key could concentrate requests onto a single shard. In
/// practice resource keys are server-generated random UUIDs, making
/// shard prediction infeasible (same reasoning as provii-verifier ADV-VA-035).
pub fn shard_index(resource_key: &str) -> usize {
    // Deterministic hash for cross-isolate shard consistency.
    let h = crate::hash::deterministic_shard_hash(resource_key);
    #[allow(clippy::cast_possible_truncation)]
    let idx = (h as usize) % RESOURCE_LOCK_SHARD_COUNT;
    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    INTEGRATION TEST DOCUMENTATION                        */
    /* ========================================================================== */

    /* ResourceLockDO requires a Cloudflare Workers Durable Objects runtime
       environment and cannot be unit tested without mocking the entire DO
       infrastructure. These tests should be performed in integration tests.

       Test Requirements:

       Atomic Consumption Tests
       ------------------------
       [ ] First consume() call succeeds with allowed=true
       [ ] Second consume() call fails with allowed=false
       [ ] Concurrent consume() calls (100+) - only ONE succeeds
       [ ] consume() returns consumed_at timestamp on subsequent calls
       [ ] consume() returns first_metadata on subsequent calls
       [ ] consume() stores metadata correctly

       Check Consumed Tests
       -------------------
       [ ] check_consumed() returns false before consumption
       [ ] check_consumed() returns true after consumption
       [ ] check_consumed() returns consumed_at after consumption
       [ ] check_consumed() returns metadata after consumption
       [ ] check_consumed() doesn't consume the resource itself

       TTL and Cleanup Tests
       --------------------
       [ ] Pickup resources expire after 300 seconds
       [ ] Challenge resources expire after 120 seconds
       [ ] Nonce resources expire after 300 seconds
       [ ] Quota resources expire after 3600 seconds
       [ ] Alarm triggers cleanup at TTL expiration
       [ ] Expired resources can be consumed again (new instance)

       Reset Tests (Testing Only)
       --------------------------
       [ ] reset() works in sandbox environment
       [ ] reset() fails in production environment
       [ ] reset() allows re-consumption after reset
       [ ] reset() clears metadata

       Error Handling
       -------------
       [ ] Empty resource_type returns 400
       [ ] Empty resource_id returns 400
       [ ] Invalid JSON returns appropriate error
       [ ] Missing request body returns appropriate error

       Race Condition Prevention
       -------------------------
       [ ] 1000 concurrent consume() calls - exactly 1 succeeds
       [ ] Interleaved consume() and check_consumed() - consistent state
       [ ] Rapid consume() retries - all but first rejected

       Integration with Worker
       ----------------------
       [ ] Worker can obtain DO stub by name
       [ ] Worker can call consume() via fetch
       [ ] Worker can call check_consumed() via fetch
       [ ] DO instance is unique per resource_type:resource_id
       [ ] Multiple resources use separate DO instances

       Example Test Scenario:
       ---------------------
       1. Create pickup token: ABC123DEF4567890
       2. Get DO stub: id_from_name("pickup:ABC123DEF4567890")
       3. Call consume() → allowed=true
       4. Call consume() → allowed=false, consumed_at=T
       5. Call check_consumed() → consumed=true, consumed_at=T
       6. Wait 301 seconds → resource expired
       7. New DO instance -> consume() -> allowed=true (fresh state)

       Acquire/Release Lock Tests
       --------------------------
       [ ] acquire() succeeds when no lock held
       [ ] acquire() fails when lock already held by another token
       [ ] acquire() succeeds when previous lock has expired
       [ ] release() succeeds with matching token
       [ ] release() fails with mismatched token
       [ ] release() succeeds when lock already expired (idempotent)
       [ ] TTL is capped at MAX_LOCK_TTL_SECONDS (30s)
       [ ] Alarm cleans up expired locks
    */

    #[test]
    fn test_shard_index_deterministic() {
        let idx1 = shard_index("challenge:abc123");
        let idx2 = shard_index("challenge:abc123");
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn test_shard_index_within_bounds() {
        for i in 0..1000 {
            let key = format!("test:{}", i);
            let idx = shard_index(&key);
            assert!(idx < RESOURCE_LOCK_SHARD_COUNT);
        }
    }

    #[test]
    fn test_shard_index_distributes() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..500 {
            let key = format!("resource:{}", i);
            seen.insert(shard_index(&key));
        }
        // With 500 keys across 25 shards we should hit most of them
        assert!(seen.len() > 15);
    }

    #[test]
    fn test_resource_ttl_pickup() {
        assert_eq!(resource_ttl_seconds("pickup"), 300);
    }

    #[test]
    fn test_resource_ttl_challenge() {
        assert_eq!(resource_ttl_seconds("challenge"), 120);
    }

    #[test]
    fn test_resource_ttl_nonce() {
        assert_eq!(resource_ttl_seconds("nonce"), 300);
    }

    #[test]
    fn test_resource_ttl_quota() {
        assert_eq!(resource_ttl_seconds("quota"), 3600);
    }

    #[test]
    fn test_resource_ttl_unknown_defaults() {
        assert_eq!(resource_ttl_seconds("unknown"), 300);
        assert_eq!(resource_ttl_seconds(""), 300);
    }

    #[test]
    fn test_validate_lock_name_valid() {
        assert!(validate_lock_name("abc-123").is_ok());
        assert!(validate_lock_name("resource:lock_key.v1").is_ok());
        assert!(validate_lock_name("a").is_ok());
    }

    #[test]
    fn test_validate_lock_name_empty() {
        assert!(validate_lock_name("").is_err());
    }

    #[test]
    fn test_validate_lock_name_too_long() {
        let long_name = "a".repeat(MAX_LOCK_NAME_LENGTH + 1);
        assert!(validate_lock_name(&long_name).is_err());
    }

    #[test]
    fn test_validate_lock_name_max_length_ok() {
        let max_name = "a".repeat(MAX_LOCK_NAME_LENGTH);
        assert!(validate_lock_name(&max_name).is_ok());
    }

    #[test]
    fn test_validate_lock_name_invalid_chars() {
        assert!(validate_lock_name("has space").is_err());
        assert!(validate_lock_name("has/slash").is_err());
        assert!(validate_lock_name("has@at").is_err());
        assert!(validate_lock_name("has\nnewline").is_err());
    }

    #[test]
    fn test_validate_lock_name_allowed_special_chars() {
        assert!(validate_lock_name("hyphen-ok").is_ok());
        assert!(validate_lock_name("underscore_ok").is_ok());
        assert!(validate_lock_name("colon:ok").is_ok());
        assert!(validate_lock_name("period.ok").is_ok());
    }

    #[test]
    fn test_consume_resource_request_deserialize() {
        let json_str = r#"{"resource_type":"pickup","resource_id":"abc"}"#;
        let req: ConsumeResourceRequest = serde_json::from_str(json_str).unwrap();
        assert_eq!(req.resource_type, "pickup");
        assert_eq!(req.resource_id, "abc");
        assert!(req.metadata.is_none());
    }

    #[test]
    fn test_consume_resource_request_with_metadata() {
        let json_str = r#"{"resource_type":"nonce","resource_id":"x","metadata":{"k":"v"}}"#;
        let req: ConsumeResourceRequest = serde_json::from_str(json_str).unwrap();
        assert!(req.metadata.is_some());
    }

    #[test]
    fn test_consume_resource_request_deny_unknown_fields() {
        let json_str = r#"{"resource_type":"pickup","resource_id":"abc","extra":"bad"}"#;
        let result: std::result::Result<ConsumeResourceRequest, _> = serde_json::from_str(json_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_lock_record_debug_redacts_token() {
        let record = LockRecord {
            lock_token: "secret-token-value".to_string(),
            acquired_at: 1000,
            expires_at: 1030,
            resource_key: "test:key".to_string(),
        };
        let debug_output = format!("{:?}", record);
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("secret-token-value"));
    }

    #[test]
    fn test_consume_response_serialization() {
        let resp = ConsumeResourceResponse {
            allowed: true,
            reason: "first consumption".to_string(),
            consumed_at: None,
            first_metadata: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"allowed\":true"));
        assert!(!json.contains("consumed_at"));
    }

    #[test]
    fn test_check_consumed_response_with_timestamp() {
        let resp = CheckConsumedResponse {
            consumed: true,
            consumed_at: Some(1717200000),
            metadata: Some(serde_json::json!({"key": "val"})),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("1717200000"));
        assert!(json.contains("\"key\":\"val\""));
    }

    #[test]
    fn test_acquire_lock_request_deny_unknown() {
        let json_str = r#"{"lock_token":"t","ttl_seconds":10,"resource_key":"k","extra":"bad"}"#;
        let result: std::result::Result<AcquireLockRequest, _> = serde_json::from_str(json_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_release_lock_request_roundtrip() {
        let json_str = r#"{"lock_token":"tok123","resource_key":"res:1"}"#;
        let req: ReleaseLockRequest = serde_json::from_str(json_str).unwrap();
        assert_eq!(req.lock_token, "tok123");
        assert_eq!(req.resource_key, "res:1");
    }
}
