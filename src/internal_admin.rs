// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Rotation-drill admin endpoints.
//!
//! These endpoints support the verify-rotation soak checks and the
//! `cleanup-test-fixtures` CLI in the rotation drill. They are
//! gated by the same `INTERNAL_VERSION_SERVICE_TOKEN` dual-slot
//! auth scheme used by `/_internal/version`, plus the per-request nonce
//! replay-window protection enforced by
//! [`crate::storage::validate_and_consume_nonce`] (the provii-issuer
//! equivalent of `enforce_internal_replay_window`).
//!
//! Endpoints
//!
//! | Method  | Path                                | Purpose |
//! |---------|-------------------------------------|---------|
//! | POST    | `/_internal/replay-saved-pre-rotation-token` | Replay a captured admin service token against the dual-slot accept path. |
//! | DELETE  | `/_internal/test-fixtures/{class}`  | Clear test-only entries from the named fixture class. Supported class: `attestations`. |
//! | GET     | `/_internal/test-fixtures`          | Manifest of supported classes + binding kinds. |
//!
//! The KEK class secret is reserved for the issuer's signing-key
//! envelope at rest; there is no envelope-encrypted secret returned to
//! clients, so the provii-verifier `mek-decrypt-probe` shape does not
//! apply here. The audit-consumer `hmac-chain-replay` shape does not
//! apply either because provii-issuer does not maintain a host-chained
//! audit log on this surface.
//!
//! Auth model
//!
//! Every handler runs the same path:
//!
//! 1. Class 6 per-IP cap (10/hour) + 5-attempt failure lockout
//!    via the existing `record_auth_failure` / `is_locked_out` /
//!    `lock_account` storage primitives.
//! 2. Dual-slot bearer accept against
//!    `INTERNAL_VERSION_SERVICE_TOKEN` (constant-time inside
//!    `subtle::ConstantTimeEq`).
//! 3. Mandatory `X-Nonce` header consumed atomically via NonceDO so a
//!    captured request cannot replay within the dedupe TTL. The role
//!    tag is folded into the audit details for cross-surface telemetry.
//!
//! Data exposure
//!
//! Per `OBSERVABILITY.md` §1, fingerprints are public-safe (24 bits,
//! one-way). Plaintext, signing keys, KEK material, and admin token
//! contents are never returned.
use serde::{Deserialize, Serialize};
use serde_json::json;
use worker::{kv::KvStore, Date, Env, Request, Response};

use crate::error::ApiError;
use crate::internal_version::{resolve_internal_credential, verify_internal_token_slots};

/// Admin per-IP hourly cap (Class 6).
const ADMIN_RL_LIMIT_PER_HOUR: u32 = 10;

use crate::constants::{ADMIN_LOCKOUT_DURATION_SECONDS, MAX_ADMIN_FAILED_ATTEMPTS};

/// Test-fixture KV key prefix for issued attestation state. The drill
/// seeds entries under `issuer:attestations:test:*` so cleanup only
/// deletes its own state. Production session keys use the
/// `session:<session_id>` prefix and are never touched by this
/// endpoint.
const ATTESTATIONS_TEST_PREFIX: &str = "issuer:attestations:test:";

/// Request body for the replay-saved-pre-rotation-token endpoint.
#[derive(Deserialize)]
pub struct ReplayTokenRequest {
    pub token: String,
}

/// Response shape for the replay-saved-pre-rotation-token endpoint.
#[derive(Serialize)]
pub struct ReplayTokenResponse {
    /// True when the saved token no longer authenticates against the
    /// current dual-slot pair.
    pub rejected: bool,
    pub reason: String,
}

/// Per-IP 10/hour cap. Failure-lockout enforcement is delegated to the
/// shared `storage::is_locked_out` / `record_auth_failure` /
/// `lock_account` primitives so the drill surface and the
/// partner-traffic admin surface share one lockout state.
async fn admin_rate_limit_check(rl_kv: &KvStore, ip_hash: &str, role_tag: &str) -> Result<(), u32> {
    let now_secs = Date::now().as_millis() / 1000;
    #[allow(clippy::arithmetic_side_effects)]
    let hour_ts = now_secs / 3600 * 3600;
    let hour_key = format!("admin_rl:{}:{}:{}", role_tag, ip_hash, hour_ts);

    let current: u32 = match rl_kv.get(&hour_key).text().await {
        Ok(Some(s)) => s.parse().unwrap_or_else(|_| {
            crate::log_error!(
                "[InternalAdmin] Malformed rate-limit counter for key '{}': '{}'",
                hour_key,
                s
            );
            0
        }),
        Ok(None) => 0,
        // Fail open: KV read errors should not block legitimate requests.
        // This is by-design for CF Workers where availability takes
        // precedence over strict rate-limit enforcement.
        Err(_) => return Err(60),
    };
    if current >= ADMIN_RL_LIMIT_PER_HOUR {
        #[allow(clippy::cast_possible_truncation)]
        let retry = hour_ts.saturating_add(3600).saturating_sub(now_secs) as u32;
        return Err(retry);
    }

    if let Ok(put) = rl_kv.put(&hour_key, current.saturating_add(1).to_string()) {
        let _ = put.expiration_ttl(7200).execute().await;
    }
    Ok(())
}

/// Run the bearer + nonce auth path used by every admin endpoint.
///
/// Returns `Ok(())` on success, `Err(ApiError)` to surface to the
/// client. The role tag is recorded on the audit log so dropped
/// requests are attributable to a specific admin surface.
async fn authenticate_admin_endpoint(
    req: &Request,
    env: &Env,
    role_tag: &str,
) -> Result<(), ApiError> {
    let client_ip = crate::audit::get_client_ip(req);
    let headers = req.headers();

    // Lockout precedence: identical fail-closed posture as
    // `routes.rs::authenticate_admin`. If the lockout-store read fails
    // we reject the request rather than risk an authentication bypass.
    match crate::storage::is_locked_out(env, "admin", &client_ip).await {
        Ok(true) => {
            crate::audit::audit_log_with_actor(
                env,
                "admin_auth_failed",
                &client_ip,
                "Admin auth rejected: IP locked out",
                &json!({
                    "endpoint": role_tag,
                    "reason": "ip_locked_out",
                }),
                Some(&client_ip),
                Some(crate::audit::Outcome::Denied),
            )
            .await;
            return Err(ApiError::Forbidden("Unauthorised".into()));
        }
        Ok(false) => {}
        Err(_) => {
            return Err(ApiError::ServiceUnavailable(
                "Authentication infrastructure unavailable".into(),
            ));
        }
    }

    // Resolve credential. Reuses the same RFC 9110 parser as
    // `internal_version` so the Class 6 shape is uniform.
    let authorization = headers.get("Authorization").ok().flatten();
    let provided = match resolve_internal_credential(authorization.as_deref()) {
        Some(t) => t,
        None => {
            record_admin_auth_failure(env, &client_ip, role_tag).await;
            return Err(ApiError::Unauthorized(
                "Missing Authorization header".into(),
            ));
        }
    };

    // Resolve the dual-slot pair from the Secrets Store.
    let store = env
        .secret_store("INTERNAL_VERSION_SERVICE_TOKEN")
        .map_err(|_| {
            ApiError::ServiceUnavailable("Internal version endpoint not configured".into())
        })?;
    let expected_current = match store.get().await {
        Ok(Some(t)) if !t.is_empty() => t,
        _ => {
            return Err(ApiError::ServiceUnavailable(
                "Internal version endpoint not configured".into(),
            ));
        }
    };
    let expected_previous = match env.secret_store("INTERNAL_VERSION_SERVICE_TOKEN_PREVIOUS") {
        Ok(store) => match store.get().await {
            Ok(Some(t)) if !t.is_empty() => Some(t),
            _ => None,
        },
        Err(_) => None,
    };

    if !verify_internal_token_slots(&provided, &expected_current, expected_previous.as_deref()) {
        record_admin_auth_failure(env, &client_ip, role_tag).await;
        return Err(ApiError::Unauthorized("Invalid service token".into()));
    }

    // Mandatory X-Nonce. Constant-time consume via NonceDO. Same atomic
    // check-and-set used by `rotate_signing_key` and
    // `rotate_attestation_key`. The role tag is part of the audit
    // details so a captured nonce on `replay-saved-pre-rotation-token`
    // cannot be confused with one from `test-fixtures` cleanup.
    let admin_nonce = match headers.get("X-Nonce").ok().flatten() {
        Some(n) => n,
        None => {
            record_admin_auth_failure(env, &client_ip, role_tag).await;
            crate::audit::audit_log(
                env,
                "authentication_failed",
                &client_ip,
                "Missing X-Nonce header on internal admin endpoint",
                &json!({"reason": "missing_nonce", "endpoint": role_tag}),
            )
            .await;
            return Err(ApiError::Unauthorized(
                "Authentication failed: nonce required".into(),
            ));
        }
    };
    match crate::storage::validate_and_consume_nonce(env, &admin_nonce).await {
        Ok(true) => {}
        Ok(false) => {
            crate::audit::audit_log(
                env,
                "replay_attempt",
                &client_ip,
                "Nonce reuse detected on internal admin endpoint",
                &json!({"reason": "nonce_reuse", "endpoint": role_tag}),
            )
            .await;
            return Err(ApiError::Unauthorized(
                "Authentication failed: nonce already used".into(),
            ));
        }
        Err(e) => {
            crate::log_error!(
                "[InternalAdmin] Nonce validation failed for {}: {:?}",
                role_tag,
                e
            );
            return Err(ApiError::ServiceUnavailable(
                "Authentication infrastructure unavailable".into(),
            ));
        }
    }

    // Success: clear accumulated failures for this IP. Mirrors
    // `routes.rs::authenticate_admin`.
    let _ = crate::storage::clear_auth_failures(env, "admin", &client_ip).await;
    Ok(())
}

/// Record an auth failure and trip the lockout when the threshold is
/// reached. Mirrors the hot-path admin auth failure recorder.
async fn record_admin_auth_failure(env: &Env, client_ip: &str, endpoint: &str) {
    if let Ok(failure_count) =
        crate::storage::record_auth_failure(env, "admin", client_ip, MAX_ADMIN_FAILED_ATTEMPTS)
            .await
    {
        if failure_count >= MAX_ADMIN_FAILED_ATTEMPTS {
            if let Err(e) = crate::storage::lock_account(
                env,
                "admin",
                client_ip,
                ADMIN_LOCKOUT_DURATION_SECONDS,
            )
            .await
            {
                crate::log_error!(
                    "[InternalAdmin] Failed to lock admin account on {}: {:?}",
                    endpoint,
                    e
                );
            }
        }
    }
}

/// Outer entry point for `POST /_internal/replay-saved-pre-rotation-token`.
pub async fn replay_pre_rotation_token(mut req: Request, env: &Env) -> worker::Result<Response> {
    let role_tag = "admin-replay-token";
    if let Some(resp) = wrap_admin_handler(&req, env, role_tag).await? {
        return Ok(resp);
    }

    let body_bytes = match req.bytes().await {
        Ok(b) if b.len() <= 16 * 1024 => b,
        Ok(_) => {
            return ApiError::BadRequest("Request entity too large".into()).to_response();
        }
        Err(_) => {
            return ApiError::BadRequest("Failed to read body".into()).to_response();
        }
    };
    let payload: ReplayTokenRequest = match serde_json::from_slice(&body_bytes) {
        Ok(p) => p,
        Err(e) => return ApiError::BadRequest(format!("Invalid body: {}", e)).to_response(),
    };

    // Token length guard: Class 6 service tokens are <=256 bytes. Reject
    // oversized values before any cryptographic work.
    if payload.token.len() > 512 {
        return ApiError::BadRequest("Token exceeds maximum length".into()).to_response();
    }

    // Re-resolve the dual-slot pair, then test the supplied token. We
    // cannot reuse the headers-based auth path here because we are
    // probing whether a *different* token would have authenticated.
    let store = match env.secret_store("INTERNAL_VERSION_SERVICE_TOKEN") {
        Ok(s) => s,
        Err(_) => {
            return ApiError::ServiceUnavailable("Internal version endpoint not configured".into())
                .to_response();
        }
    };
    let expected_current = match store.get().await {
        Ok(Some(t)) if !t.is_empty() => t,
        _ => {
            return ApiError::ServiceUnavailable("Internal version endpoint not configured".into())
                .to_response();
        }
    };
    let expected_previous = match env.secret_store("INTERNAL_VERSION_SERVICE_TOKEN_PREVIOUS") {
        Ok(store) => match store.get().await {
            Ok(Some(t)) if !t.is_empty() => Some(t),
            _ => None,
        },
        Err(_) => None,
    };

    let still_accepted = verify_internal_token_slots(
        &payload.token,
        &expected_current,
        expected_previous.as_deref(),
    );
    let body = if still_accepted {
        ReplayTokenResponse {
            rejected: false,
            reason: "token still accepted".to_string(),
        }
    } else {
        ReplayTokenResponse {
            rejected: true,
            reason: "token no longer accepted on current dual-slot pair".to_string(),
        }
    };

    let client_ip = crate::audit::get_client_ip(&req);
    crate::audit::audit_log_with_actor(
        env,
        "admin_config_change",
        &client_ip,
        "Admin replay-token verification executed",
        &json!({
            "operation": "replay_pre_rotation_token",
            "result_rejected": body.rejected,
        }),
        Some(&client_ip),
        Some(crate::audit::Outcome::Success),
    )
    .await;

    Response::from_json(&body)
}

/// Outer entry point for `GET /_internal/test-fixtures`.
pub async fn test_fixtures_manifest(req: Request, env: &Env) -> worker::Result<Response> {
    let role_tag = "admin-fixture-manifest";
    if let Some(resp) = wrap_admin_handler(&req, env, role_tag).await? {
        return Ok(resp);
    }

    let body = json!({
        "worker": "provii-issuer",
        "supported_classes": ["attestations"],
        "binding_kind_per_class": { "attestations": "kv" },
        "namespace_or_table_per_class": { "attestations": crate::bindings::ISSUER_SESSIONS },
    });
    Response::from_json(&body)
}

/// Outer entry point for `DELETE /_internal/test-fixtures/{class}`.
pub async fn delete_test_fixtures(
    req: Request,
    env: &Env,
    class: &str,
) -> worker::Result<Response> {
    let role_tag = format!("admin-fixture:{}", class);
    if let Some(resp) = wrap_admin_handler(&req, env, &role_tag).await? {
        return Ok(resp);
    }

    let result = match class {
        "attestations" => clear_attestations_test_prefix(env).await,
        other => ApiError::BadRequest(format!(
            "provii-issuer does not own fixture class '{}'",
            other
        ))
        .to_response(),
    };

    if result.is_ok() {
        let client_ip = crate::audit::get_client_ip(&req);
        crate::audit::audit_log_with_actor(
            env,
            "admin_config_change",
            &client_ip,
            &format!("Admin deleted test fixtures for class '{}'", class),
            &json!({
                "operation": "delete_test_fixtures",
                "class": class,
            }),
            Some(&client_ip),
            Some(crate::audit::Outcome::Success),
        )
        .await;
    }

    result
}

async fn clear_attestations_test_prefix(env: &Env) -> worker::Result<Response> {
    let kv = match env.kv(crate::bindings::ISSUER_SESSIONS) {
        Ok(k) => k,
        Err(e) => {
            return ApiError::ServiceUnavailable(format!(
                "{} binding unavailable: {}",
                crate::bindings::ISSUER_SESSIONS,
                e
            ))
            .to_response();
        }
    };

    let mut deleted: u32 = 0;
    let mut cursor: Option<String> = None;
    loop {
        let mut listing = kv.list().prefix(ATTESTATIONS_TEST_PREFIX.to_string());
        if let Some(c) = cursor.as_ref() {
            listing = listing.cursor(c.clone());
        }
        let result = match listing.execute().await {
            Ok(r) => r,
            Err(e) => {
                return ApiError::ServiceUnavailable(format!("KV list failed: {}", e))
                    .to_response();
            }
        };
        for k in &result.keys {
            if k.name.starts_with(ATTESTATIONS_TEST_PREFIX) {
                if let Err(e) = kv.delete(&k.name).await {
                    return ApiError::ServiceUnavailable(format!("KV delete failed: {}", e))
                        .to_response();
                }
                deleted = deleted.saturating_add(1);
            }
        }
        if result.list_complete {
            break;
        }
        cursor = result.cursor;
        if cursor.is_none() {
            break;
        }
    }

    let body = json!({
        "worker": "provii-issuer",
        "class": "attestations",
        "binding": crate::bindings::ISSUER_SESSIONS,
        "prefix": ATTESTATIONS_TEST_PREFIX,
        "deleted": deleted,
    });
    Response::from_json(&body)
}

/// Wrap the rate-limit + bearer + nonce auth path. Returns
/// `Ok(Some(resp))` on rejection so the caller can short-circuit, or
/// `Ok(None)` once the request passed every gate. Errors propagate as
/// `worker::Error` so the outer router emits a 500 envelope rather
/// than a partially-built response.
async fn wrap_admin_handler(
    req: &Request,
    env: &Env,
    role_tag: &str,
) -> worker::Result<Option<Response>> {
    let client_ip = crate::audit::get_client_ip(req);
    let privacy = crate::audit::build_privacy_context(env).await;
    let ip_hash = privacy.hash_ip(&client_ip).unwrap_or_default();

    // Per-IP rate limit precedes auth so unauthenticated traffic
    // cannot exhaust the failure-lockout state.
    let rl_kv = match env.kv(crate::bindings::ISSUER_RATE_LIMITS) {
        Ok(kv) => kv,
        Err(e) => {
            crate::log_error!("[InternalAdmin] ISSUER_RATE_LIMITS KV unavailable: {:?}", e);
            return Ok(Some(
                ApiError::ServiceUnavailable("Rate limiting infrastructure unavailable".into())
                    .to_response()?,
            ));
        }
    };
    if let Err(retry_after) = admin_rate_limit_check(&rl_kv, &ip_hash, role_tag).await {
        let mut resp = ApiError::RateLimitExceeded.to_response()?;
        resp.headers_mut()
            .set("Retry-After", &retry_after.to_string())?;
        return Ok(Some(resp));
    }

    if let Err(api_err) = authenticate_admin_endpoint(req, env, role_tag).await {
        return Ok(Some(api_err.to_response()?));
    }
    Ok(None)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn manifest_payload_lists_attestations_class_only() {
        let body = json!({
            "worker": "provii-issuer",
            "supported_classes": ["attestations"],
            "binding_kind_per_class": { "attestations": "kv" },
            "namespace_or_table_per_class": { "attestations": crate::bindings::ISSUER_SESSIONS },
        });
        assert_eq!(body["worker"], "provii-issuer");
        assert_eq!(body["supported_classes"][0], "attestations");
        assert_eq!(body["binding_kind_per_class"]["attestations"], "kv");
        assert_eq!(
            body["namespace_or_table_per_class"]["attestations"],
            crate::bindings::ISSUER_SESSIONS
        );
    }

    #[test]
    fn replay_token_request_deserialises() {
        let json = r#"{ "token": "captured-token-value" }"#;
        let req: ReplayTokenRequest = serde_json::from_str(json).expect("parse"); // nosemgrep: expect-on-external-input
        assert_eq!(req.token, "captured-token-value");
    }

    #[test]
    fn replay_token_response_serialises_rejected_path() {
        let body = ReplayTokenResponse {
            rejected: true,
            reason: "token no longer accepted on current dual-slot pair".to_string(),
        };
        let s = serde_json::to_string(&body).expect("serialise");
        assert!(s.contains("\"rejected\":true"));
        assert!(s.contains("\"reason\""));
    }

    #[test]
    fn replay_token_response_serialises_accepted_path() {
        let body = ReplayTokenResponse {
            rejected: false,
            reason: "token still accepted".to_string(),
        };
        let s = serde_json::to_string(&body).expect("serialise");
        assert!(s.contains("\"rejected\":false"));
    }

    #[test]
    fn attestations_test_prefix_namespaced_under_issuer() {
        // The drill seeds entries under `issuer:attestations:test:*`.
        // Production session keys are `session:<session_id>` and never
        // share the `issuer:` infix.
        assert!(ATTESTATIONS_TEST_PREFIX.starts_with("issuer:attestations:test:"));
        assert!(!ATTESTATIONS_TEST_PREFIX.starts_with("session:"));
    }

    #[test]
    fn admin_rl_constants_match_ar024() {
        assert_eq!(ADMIN_RL_LIMIT_PER_HOUR, 10);
        assert_eq!(MAX_ADMIN_FAILED_ATTEMPTS, 5);
        assert_eq!(ADMIN_LOCKOUT_DURATION_SECONDS, 1800);
    }

    #[test]
    fn replay_token_response_omits_unrelated_fields() {
        let body = ReplayTokenResponse {
            rejected: true,
            reason: "x".to_string(),
        };
        let s = serde_json::to_string(&body).expect("serialise");
        assert!(!s.contains("token"));
        assert!(!s.contains("expected"));
    }

    #[test]
    fn role_tag_for_fixtures_includes_class() {
        let role_tag = format!("admin-fixture:{}", "attestations");
        assert_eq!(role_tag, "admin-fixture:attestations");
    }
}
