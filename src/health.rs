// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Health check endpoint providing system status and diagnostics for issuer service.

use crate::secret_cache::{self, CachedHashedSecret};
use serde::Serialize;
use std::cell::RefCell;
use worker::*;

/// Fallback API version when the `API_VERSION` env var is not set.
const FALLBACK_API_VERSION: &str = "2.0.0";

// Per-isolate cache for STATUS_API_TOKEN. Stores only the Argon2id PHC
// hash and 6-char fingerprint; the plaintext is zeroised at cache time.
thread_local! {
    static STATUS_TOKEN_CACHE: RefCell<Option<CachedHashedSecret>> = const { RefCell::new(None) };
}

// Per-isolate cache for STATUS_API_TOKEN_PREVIOUS during
// rotation overlap windows. Treated as optional; absence outside a
// rotation window is normal and not surfaced as a failure.
thread_local! {
    static STATUS_TOKEN_PREV_CACHE: RefCell<Option<CachedHashedSecret>> = const { RefCell::new(None) };
}

/// Test-only reset for both STATUS_API_TOKEN cache slots. Mode B rotation
/// drills call this between rotation steps so the next status request
/// observes the fresh binding values without waiting for TTL expiry.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn reset_for_testing() {
    STATUS_TOKEN_CACHE.with(|c| *c.borrow_mut() = None);
    STATUS_TOKEN_PREV_CACHE.with(|c| *c.borrow_mut() = None);
}

/// Identifies which STATUS_API_TOKEN slot satisfied a
/// status-endpoint request. Surfaced on the structured log line as
/// `secret_version_used` per `OBSERVABILITY.md` §1 schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusTokenSlot {
    /// Request authenticated against `STATUS_API_TOKEN` (current).
    Current,
    /// Request authenticated against `STATUS_API_TOKEN_PREVIOUS`
    /// during a rotation overlap window.
    Previous,
}

impl StatusTokenSlot {
    /// Role-name-suffix label per `OBSERVABILITY.md` §1 schema; used as
    /// the `secret_version_used` field value on the request log.
    pub fn label(self) -> &'static str {
        match self {
            Self::Current => "STATUS_API_TOKEN_PROD",
            Self::Previous => "STATUS_API_TOKEN_PROD_PREVIOUS",
        }
    }
}

/// Overall health status of the service.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// All systems operational.
    Healthy,
    /// Service operational but some subsystems degraded.
    Degraded,
    /// Critical failures detected.
    Unhealthy,
}

/// SECURITY: Basic health check response (unauthenticated).
/// Contains only essential liveness information without sensitive system details.
#[derive(Debug, Clone, Serialize)]
pub struct BasicHealthResponse {
    /// Overall service health status.
    pub status: HealthStatus,

    /// Current timestamp in seconds since epoch.
    pub timestamp: i64,

    /// API version.
    pub version: String,
}

/// Health check response structure (authenticated).
/// Contains detailed subsystem health checks and metrics.
#[derive(Debug, Clone, Serialize)]
pub struct HealthCheckResponse {
    /// Overall service health status.
    pub status: HealthStatus,

    /// Current timestamp in seconds since epoch.
    pub timestamp: i64,

    /// API version.
    pub version: String,

    /// Detailed subsystem health checks.
    pub checks: HealthChecks,
}

/// Individual subsystem health checks.
#[derive(Debug, Clone, Serialize)]
pub struct HealthChecks {
    /// KV storage availability.
    pub kv_storage: SubsystemHealth,

    /// Configuration availability.
    pub config: SubsystemHealth,

    /// Nonce DO availability.
    pub nonce_do: SubsystemHealth,

    /// SSRF-085: Service URL configuration validity.
    pub service_urls: SubsystemHealth,

    /// Secret store binding availability.
    pub secret_store: SubsystemHealth,

    /// Rate limits KV namespace availability.
    pub rate_limits_kv: SubsystemHealth,

    /// Resource lock DO (used for lockout enforcement) availability.
    pub resource_lock_do: SubsystemHealth,
}

/// Health status of an individual subsystem.
#[derive(Debug, Clone, Serialize)]
pub struct SubsystemHealth {
    /// Whether the subsystem is operational.
    pub operational: bool,

    /// Whether the subsystem is degraded (operational but impaired).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub degraded: bool,

    /// Optional message providing additional context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Optional metrics for this subsystem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<serde_json::Value>,
}

impl SubsystemHealth {
    /// Create a healthy subsystem status.
    pub fn healthy() -> Self {
        Self {
            operational: true,
            degraded: false,
            message: None,
            metrics: None,
        }
    }

    /// Create a healthy subsystem with a message.
    pub fn healthy_with_message(message: impl Into<String>) -> Self {
        Self {
            operational: true,
            degraded: false,
            message: Some(message.into()),
            metrics: None,
        }
    }

    /// Create a degraded subsystem status (operational but impaired).
    #[allow(dead_code)]
    pub fn degraded(message: impl Into<String>) -> Self {
        Self {
            operational: true,
            degraded: true,
            message: Some(message.into()),
            metrics: None,
        }
    }

    /// Create an unhealthy subsystem status.
    pub fn unhealthy(message: impl Into<String>) -> Self {
        Self {
            operational: false,
            degraded: false,
            message: Some(message.into()),
            metrics: None,
        }
    }
}

impl Default for SubsystemHealth {
    fn default() -> Self {
        Self::healthy()
    }
}

/// Performs a lightweight health check (no expensive I/O operations).
/// Returns a minimal `BasicHealthResponse` suitable for unauthenticated callers.
pub async fn health_check(env: &Env) -> worker::Result<BasicHealthResponse> {
    Ok(BasicHealthResponse {
        status: HealthStatus::Healthy,
        timestamp: chrono::Utc::now().timestamp(),
        version: env
            .var("API_VERSION")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| FALLBACK_API_VERSION.to_string()),
    })
}

/// SECURITY: Detailed health check with full subsystem probes (requires authentication).
/// Performs actual KV reads and DO connectivity checks to verify subsystem liveness.
pub async fn health_check_detailed(env: &Env) -> worker::Result<HealthCheckResponse> {
    let now = chrono::Utc::now().timestamp();

    // Probe KV storage by reading a key that should always be available.
    let kv_health = match env.kv("ISSUER_CONFIG") {
        Ok(store) => match store.get("issuer_config").text().await {
            Ok(Some(_)) => SubsystemHealth::healthy_with_message("KV read OK"),
            Ok(None) => SubsystemHealth::healthy_with_message("KV accessible (no config key)"),
            Err(_) => SubsystemHealth::unhealthy("kv_read_error".to_string()),
        },
        Err(_) => SubsystemHealth::unhealthy("kv_binding_error".to_string()),
    };

    // Probe config availability.
    let config_health = match crate::storage::get_issuer_config(env).await {
        Ok(_) => SubsystemHealth::healthy_with_message("config loaded"),
        Err(_) => SubsystemHealth::unhealthy("config_error".to_string()),
    };

    // Probe nonce DO connectivity.
    let nonce_health = match env.durable_object(crate::bindings::ISSUER_NONCE_DO) {
        Ok(namespace) => match namespace.id_from_name("health-probe") {
            Ok(_) => SubsystemHealth::healthy_with_message("DO binding OK"),
            Err(_) => SubsystemHealth::unhealthy("do_id_error".to_string()),
        },
        Err(_) => SubsystemHealth::unhealthy("do_binding_error".to_string()),
    };

    // SSRF-085: Validate configured service URLs at health-check time.
    // Catches misconfigurations before they could be wired into fetch calls.
    let service_url_health = {
        let mut issues: Vec<String> = Vec::new();
        if let Ok(url) = env.var("WORKER_BASE_URL") {
            if let Err(e) = crate::ssrf_protection::validate_service_url(&url.to_string()) {
                issues.push(format!("WORKER_BASE_URL: {}", e));
            }
        }
        if issues.is_empty() {
            SubsystemHealth::healthy_with_message("service URLs valid")
        } else {
            SubsystemHealth::unhealthy(issues.join("; "))
        }
    };

    // Probe secret store binding by attempting to access STATUS_API_TOKEN.
    let secret_store_health = match env.secret_store("STATUS_API_TOKEN") {
        Ok(store) => match store.get().await {
            Ok(Some(_)) => SubsystemHealth::healthy_with_message("secret store accessible"),
            Ok(None) => SubsystemHealth::healthy_with_message("secret store binding OK (no value)"),
            Err(_) => SubsystemHealth::unhealthy("secret_store_read_error"),
        },
        Err(_) => SubsystemHealth::unhealthy("secret_store_binding_error"),
    };

    // Probe ISSUER_RATE_LIMITS KV namespace.
    let rate_limits_kv_health = match env.kv(crate::bindings::ISSUER_RATE_LIMITS) {
        Ok(store) => match store.get("health_probe").text().await {
            Ok(_) => SubsystemHealth::healthy_with_message("rate limits KV accessible"),
            Err(_) => SubsystemHealth::unhealthy("rate_limits_kv_read_error"),
        },
        Err(_) => SubsystemHealth::unhealthy("rate_limits_kv_binding_error"),
    };

    // Probe RESOURCE_LOCK DO (lockout enforcement).
    let resource_lock_do_health = match env.durable_object(crate::bindings::RESOURCE_LOCK_DO) {
        Ok(namespace) => match namespace.id_from_name("health-probe-lock") {
            Ok(_) => SubsystemHealth::healthy_with_message("resource lock DO binding OK"),
            Err(_) => SubsystemHealth::unhealthy("resource_lock_do_id_error"),
        },
        Err(_) => SubsystemHealth::unhealthy("resource_lock_do_binding_error"),
    };

    // Determine overall status from subsystem checks.
    let all_checks = [
        &kv_health,
        &config_health,
        &nonce_health,
        &service_url_health,
        &secret_store_health,
        &rate_limits_kv_health,
        &resource_lock_do_health,
    ];
    let has_unhealthy = all_checks.iter().any(|c| !c.operational);
    let has_degraded = all_checks.iter().any(|c| c.degraded);

    let overall_status = if has_unhealthy {
        HealthStatus::Unhealthy
    } else if has_degraded {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    };

    Ok(HealthCheckResponse {
        status: overall_status,
        timestamp: now,
        version: env
            .var("API_VERSION")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| FALLBACK_API_VERSION.to_string()),
        checks: HealthChecks {
            kv_storage: kv_health,
            config: config_health,
            nonce_do: nonce_health,
            service_urls: service_url_health,
            secret_store: secret_store_health,
            rate_limits_kv: rate_limits_kv_health,
            resource_lock_do: resource_lock_do_health,
        },
    })
}

/// Authenticate a status/metrics request using STATUS_API_TOKEN with
/// dual-slot acceptance during rotation overlap windows.
///
/// Returns `Ok(slot)` identifying which slot satisfied the verify, or
/// `Err` with a 401 response if neither slot matches.
///
/// SECURITY: Verification uses Argon2id with constant-time comparison
/// (via the `argon2` crate internally). The plaintext token is never
/// cached; only the Argon2id PHC hash is stored per-isolate. A memory
/// dump therefore reveals no recoverable secret material (F-06 fix).
///
/// Dual-slot accept ordering is current-first, then
/// previous (`STATUS_API_TOKEN_PREVIOUS`). Caller MUST log the
/// returned slot under `secret_version_used` per `OBSERVABILITY.md`
/// §1.
///
/// SECURITY: Never logs the actual token value.
pub async fn authenticate_status_request(
    headers: &worker::Headers,
    env: &Env,
) -> Result<StatusTokenSlot, crate::error::ApiError> {
    // Load both slots through the Argon2id-at-cache-time path.
    // Current must be present (otherwise the endpoint is unconfigured
    // and denies); previous is optional and a missing binding is
    // normal outside rotation windows.
    let (current_hash, _current_fp) =
        match secret_cache::get_or_fetch_hashed(&STATUS_TOKEN_CACHE, || async {
            fetch_status_token(env, "STATUS_API_TOKEN").await
        })
        .await
        {
            Ok(pair) => pair,
            Err(reason) => {
                crate::audit::audit_log(
                    env,
                    "status_auth_failed",
                    "unknown",
                    "Status endpoint authentication failed (token not configured)",
                    &serde_json::json!({"reason": reason}),
                )
                .await;
                return Err(crate::error::ApiError::Unauthorized(
                    "Status endpoint not configured".into(),
                ));
            }
        };

    let previous_hash = secret_cache::get_or_fetch_hashed(&STATUS_TOKEN_PREV_CACHE, || async {
        fetch_status_token(env, "STATUS_API_TOKEN_PREVIOUS").await
    })
    .await
    .ok()
    .and_then(|(h, _fp)| h);

    // Class 6 internal API key: resolve the candidate
    // credential from `Authorization: Bearer <token>`. The shape check
    // itself is not secret-dependent.
    let authorization_header = headers.get("Authorization").ok().flatten();
    let provided_token = match resolve_status_credential(authorization_header.as_deref()) {
        Some(t) => t,
        None => {
            crate::audit::audit_log(
                env,
                "status_auth_failed",
                "unknown",
                "Status endpoint authentication failed (missing header)",
                &serde_json::json!({"reason": "missing_header"}),
            )
            .await;
            return Err(crate::error::ApiError::Unauthorized(
                "Missing Authorization header".into(),
            ));
        }
    };

    match verify_status_token_slots(
        &provided_token,
        current_hash.as_deref(),
        previous_hash.as_deref(),
    ) {
        Some(StatusTokenSlot::Current) => Ok(StatusTokenSlot::Current),
        Some(StatusTokenSlot::Previous) => {
            crate::log!("[StatusAuth] Token verified with previous slot (rotation window active)");
            Ok(StatusTokenSlot::Previous)
        }
        None => {
            crate::audit::audit_log(
                env,
                "status_auth_failed",
                "unknown",
                "Status endpoint authentication failed (invalid token)",
                &serde_json::json!({"reason": "invalid_token"}),
            )
            .await;
            Err(crate::error::ApiError::Unauthorized(
                "Invalid status token".into(),
            ))
        }
    }
}

/// Extract the status-endpoint credential from an `Authorization`
/// header value. Accepts only the RFC 9110 `Authorization: Bearer <token>`
/// shape.
///
/// Takes a raw `&str` argument rather than a `worker::Headers` so the
/// header-shape tests can be exercised on the native cargo-test target
/// without constructing a wasm-bound `Headers` instance.
fn resolve_status_credential(authorization: Option<&str>) -> Option<String> {
    authorization
        .and_then(crate::security::extract_bearer_token)
        .map(str::to_string)
}

/// Argon2id dual-slot verify for the status-token path.
///
/// Returns `Some(StatusTokenSlot::Current)` if the credential verifies
/// against the current slot's Argon2id hash,
/// `Some(StatusTokenSlot::Previous)` if it verifies against a populated
/// previous slot during a rotation window, or `None` if neither slot
/// accepts.
///
/// SECURITY: Verification delegates to the `argon2` crate's
/// `verify_password`, which performs constant-time comparison of the
/// derived hash internally (CWE-208). The early return on a current-slot
/// match is not a secret-dependent branch (it returns only when the
/// secret matches).
fn verify_status_token_slots(
    provided: &str,
    current_hash: Option<&str>,
    previous_hash: Option<&str>,
) -> Option<StatusTokenSlot> {
    if let Some(hash) = current_hash {
        if crate::hash::verify_api_key(provided, hash) {
            return Some(StatusTokenSlot::Current);
        }
    }

    if let Some(hash) = previous_hash {
        if crate::hash::verify_api_key(provided, hash) {
            return Some(StatusTokenSlot::Previous);
        }
    }

    None
}

/// Fetch a status-token slot from the Secrets Store binding.
///
/// Returns `Err` with a reason string if the binding is unavailable,
/// the secret is missing, or the value is empty.
async fn fetch_status_token(env: &Env, binding: &str) -> Result<String, String> {
    let store = env
        .secret_store(binding)
        .map_err(|_| "token_binding_missing".to_string())?;
    match store.get().await {
        Ok(Some(t)) if !t.is_empty() => Ok(t),
        Ok(Some(_)) => Err("token_empty".to_string()),
        Ok(None) => Err("token_not_configured".to_string()),
        Err(_) => Err("token_read_failed".to_string()),
    }
}

/// Resolve the 6-char fingerprint of the
/// STATUS_API_TOKEN slot that satisfied a verify, for emission as the
/// `x-secret-version` HTTP response header. Reads the fingerprint from
/// the per-isolate Argon2id cache populated by the auth path (no
/// Secrets Store round-trip on the hot path; no plaintext involved).
///
/// Returns the `"000000"` sentinel if the underlying slot value is
/// unavailable (e.g. cache eviction between auth and header attach).
pub async fn status_secret_version_header(env: &Env, used: StatusTokenSlot) -> String {
    match used {
        StatusTokenSlot::Current => {
            match secret_cache::get_or_fetch_hashed(&STATUS_TOKEN_CACHE, || async {
                fetch_status_token(env, "STATUS_API_TOKEN").await
            })
            .await
            {
                Ok((_hash, fp)) => fp,
                Err(_) => "000000".to_string(),
            }
        }
        StatusTokenSlot::Previous => {
            match secret_cache::get_or_fetch_hashed(&STATUS_TOKEN_PREV_CACHE, || async {
                fetch_status_token(env, "STATUS_API_TOKEN_PREVIOUS").await
            })
            .await
            {
                Ok((_hash, fp)) => fp,
                Err(_) => "000000".to_string(),
            }
        }
    }
}

/// Emit the `secret_version` log object for a
/// status-endpoint request per `OBSERVABILITY.md` §1 schema. The
/// fingerprint of each loaded slot is logged alongside the slot label
/// that satisfied the verify. The `STATUS_API_TOKEN_PREVIOUS` entry
/// reads `"000000"` when no previous slot is bound.
///
/// SECURITY: Fingerprints are public-safe (24-bit one-way digests) and
/// are explicitly permitted on logs per `OBSERVABILITY.md` §1.
pub async fn log_status_secret_version(env: &Env, used: StatusTokenSlot, route: &str) {
    // Read the current slot fingerprint from the Argon2id cache
    // (already populated by the auth path so this is a hot read).
    let current_fp = match secret_cache::get_or_fetch_hashed(&STATUS_TOKEN_CACHE, || async {
        fetch_status_token(env, "STATUS_API_TOKEN").await
    })
    .await
    {
        Ok((_hash, fp)) => fp,
        Err(_) => "000000".to_string(),
    };
    let previous_fp = match secret_cache::get_or_fetch_hashed(&STATUS_TOKEN_PREV_CACHE, || async {
        fetch_status_token(env, "STATUS_API_TOKEN_PREVIOUS").await
    })
    .await
    {
        Ok((_hash, fp)) => fp,
        Err(_) => "000000".to_string(),
    };

    crate::log!(
        r#"{{"type":"REQUEST_COMPLETE","service":"provii-issuer","route":"{route}","secret_version":{{"STATUS_API_TOKEN_PROD":"{current}","STATUS_API_TOKEN_PROD_PREVIOUS":"{previous}"}},"secret_version_used":"{used_label}"}}"#,
        route = route,
        current = current_fp,
        previous = previous_fp,
        used_label = used.label(),
    );
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_lazy_continuation
)]
mod tests {
    use super::*;

    /// Hash a token with the same Argon2id helper used in production so
    /// the dual-slot tests exercise the real verify path.
    fn hash(token: &str) -> String {
        crate::hash::hash_api_key(token).expect("Argon2id hash must succeed in tests")
    }

    /* ========================================================================== */
    /*    STATUS_API_TOKEN dual-slot helpers                                      */
    /* ========================================================================== */

    #[test]
    fn test_status_token_slot_labels() {
        // Labels feed the secret_version_used log field per
        // OBSERVABILITY.md §1; they must match the wrangler binding
        // names exactly so Grafana queries can correlate slot use
        // against the binding inventory.
        assert_eq!(StatusTokenSlot::Current.label(), "STATUS_API_TOKEN_PROD");
        assert_eq!(
            StatusTokenSlot::Previous.label(),
            "STATUS_API_TOKEN_PROD_PREVIOUS"
        );
    }

    #[test]
    fn test_status_token_slot_labels_are_distinct() {
        // Panel 2 (dual-slot traffic ratio) groups by
        // secret_version_used; identical labels would collapse the
        // panel.
        assert_ne!(
            StatusTokenSlot::Current.label(),
            StatusTokenSlot::Previous.label()
        );
    }

    /* ========================================================================== */
    /*    Class 6 internal API key header-shape matrix                             */
    /*    Mirrors provii-verifier/src/security/status_auth.rs 8-scenario tests       */
    /* ========================================================================== */

    /// 1. Bearer current-slot match: dual-bind active, caller presents
    /// the current token via the Class 6 canonical shape. Verify must
    /// accept against the current slot (Argon2id).
    #[test]
    fn status_bearer_current_matches() {
        let credential =
            resolve_status_credential(Some("Bearer current-token")).expect("bearer present");
        let current_hash = hash("current-token");
        let previous_hash = hash("previous-token");
        let slot =
            verify_status_token_slots(&credential, Some(&current_hash), Some(&previous_hash));
        assert_eq!(slot, Some(StatusTokenSlot::Current));
    }

    /// 2. Bearer previous-slot match: rotation-window scenario. The
    /// current slot rejects; the previous slot accepts.
    #[test]
    fn status_bearer_previous_matches() {
        let credential =
            resolve_status_credential(Some("Bearer previous-token")).expect("bearer present");
        let current_hash = hash("current-token");
        let previous_hash = hash("previous-token");
        let slot =
            verify_status_token_slots(&credential, Some(&current_hash), Some(&previous_hash));
        assert_eq!(slot, Some(StatusTokenSlot::Previous));
    }

    /// 3. Bearer wrong token: rejects under both slots.
    #[test]
    fn status_bearer_wrong_token_rejects() {
        let credential =
            resolve_status_credential(Some("Bearer not-the-right-token")).expect("bearer present");
        let current_hash = hash("current-token");
        let previous_hash = hash("previous-token");
        let slot =
            verify_status_token_slots(&credential, Some(&current_hash), Some(&previous_hash));
        assert_eq!(slot, None);
    }

    /// 4. `Authorization: Basic ...` is not a bearer credential.
    #[test]
    fn status_authorization_basic_scheme_rejected() {
        let credential = resolve_status_credential(Some("Basic dXNlcjpwYXNz"));
        assert_eq!(credential, None);
    }

    /// 5. Lowercase `bearer` scheme is accepted per RFC 9110 §11.1.
    #[test]
    fn status_bearer_lowercase_scheme_matches() {
        let credential =
            resolve_status_credential(Some("bearer current-token")).expect("bearer present");
        let current_hash = hash("current-token");
        let slot = verify_status_token_slots(&credential, Some(&current_hash), None);
        assert_eq!(slot, Some(StatusTokenSlot::Current));
    }

    /// 6. Missing Authorization header yields None.
    #[test]
    fn status_missing_authorization_rejected() {
        assert_eq!(resolve_status_credential(None), None);
    }

    /// 7. `Authorization: Bearer ` with empty credential yields None.
    #[test]
    fn status_bearer_empty_credential_rejected() {
        let credential = resolve_status_credential(Some("Bearer "));
        assert_eq!(credential, None);
    }

    /// Argon2id roundtrip: hash + verify must succeed for the same token
    /// and fail for a different one.
    #[test]
    fn status_argon2id_roundtrip() {
        let token = "test-status-token-roundtrip";
        let phc = hash(token);
        assert!(crate::hash::verify_api_key(token, &phc));
        assert!(!crate::hash::verify_api_key("wrong-token", &phc));
    }

    /// Argon2id hash format: must produce a PHC string starting with
    /// `$argon2id$`.
    #[test]
    fn status_argon2id_format() {
        let phc = hash("test-status-token-format");
        assert!(phc.starts_with("$argon2id$"));
    }
}
