// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! `/_internal/version` endpoint for rotation-drill observability.
//!
//! Returns the Worker's deployed_at timestamp, git_sha, and the full
//! 8-char fingerprint of every active rotation-capable secret slot.
//! Used by the rotation-drill harness to:
//!
//! 1. confirm a `wrangler deploy` has propagated globally before the
//!    test continues (the `/v1/...` business endpoints can serve from
//!    a stale isolate for up to ~60s after deploy);
//! 2. correlate the 6-char request-log fingerprint against the full
//!    8-char value for definitive identification.
//!
//! Auth model (sandbox and production share one path):
//!
//! Both environments require `Authorization: Bearer <token>` matching
//! the dual-slot `INTERNAL_VERSION_SERVICE_TOKEN` pair from the Secrets
//! Store. Constant-time comparison via `subtle::ConstantTimeEq`.
//!
//! The sandbox-only `Cf-Access-Authenticated-User-Email` arm is not
//! used because a workers.dev hostname or any Worker URL that bypasses
//! the Access-protected route is reachable without traversing Access,
//! so the header signal alone is not a defensible authentication
//! boundary. The token-based check works uniformly across hostnames.
//!
//! `INTERNAL_VERSION_SERVICE_TOKEN` is a Class 6 internal API key;
//! the `Authorization: Bearer` shape is the canonical Class 6
//! contract.
//!
//! The endpoint never returns secret values. The published 8-char
//! fingerprint is one-way derived (sha256 prefix) and therefore
//! public-safe per `OBSERVABILITY.md` §1; the only material
//! difference between this and the request-log surface is the extra 8
//! bits of disambiguation entropy.
use crate::error::ApiError;
use crate::secret_fingerprint::fingerprint8;
use worker::{Env, Headers, Response};
use zeroize::Zeroize;

/// Result of resolving a rotation-capable secret-slot fingerprint for
/// the `/_internal/version` body. `None` is reported as the JSON
/// literal `null`.
///
/// `binding` is the wrangler.toml Secrets Store binding name (read
/// site). `role_key` is the public role-name suffix emitted as the
/// JSON object key per `OBSERVABILITY.md` §1; the binding-name
/// prefix is dropped because `"service": "provii-issuer"` is already on
/// the request log line.
#[derive(Debug, Clone)]
struct SlotFingerprint {
    role_key: &'static str,
    value: Option<String>,
}

/// Request handler. Returns a JSON body with the per-slot
/// 8-char fingerprints. Authentication is uniform across environments:
/// `Authorization: Bearer <token>` matched against the dual-slot
/// `INTERNAL_VERSION_SERVICE_TOKEN` pair.
pub async fn handle_internal_version(
    headers: &Headers,
    env: &Env,
) -> std::result::Result<Response, ApiError> {
    authenticate(headers, env).await?;

    let slots = collect_slot_fingerprints(env).await;
    build_response(env, &slots)
}

/// Verify a request against the dual-slot
/// `INTERNAL_VERSION_SERVICE_TOKEN` pair from the Secrets Store.
///
/// Accepts only `Authorization: Bearer <token>` (Class 6 canonical
/// shape).
///
/// The credential is verified against the current slot first, then the
/// previous slot if the binding is populated. Both comparisons run
/// under `subtle::ConstantTimeEq` after a fixed-size SHA-256 length
/// blind. The early return on a current-slot match is not a
/// secret-dependent branch (it returns only when the secret matches; a
/// caller cannot infer which slot satisfied the verify from the
/// timing).
async fn authenticate(headers: &Headers, env: &Env) -> std::result::Result<(), ApiError> {
    // Resolve the candidate credential. The shape check (scheme
    // literal, single space delimiter) is not secret-dependent.
    let authorization = headers.get("Authorization").ok().flatten();
    let provided = match resolve_internal_credential(authorization.as_deref()) {
        Some(t) => t,
        None => {
            return Err(ApiError::Unauthorized(
                "Missing Authorization header".into(),
            ));
        }
    };

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

    // Optional previous slot for rotation overlap windows. Absence is
    // the steady state; only populated mid-rotation per RUNBOOKS.md.
    let expected_previous = match env.secret_store("INTERNAL_VERSION_SERVICE_TOKEN_PREVIOUS") {
        Ok(store) => match store.get().await {
            Ok(Some(t)) if !t.is_empty() => Some(t),
            _ => None,
        },
        Err(_) => None,
    };

    if verify_internal_token_slots(&provided, &expected_current, expected_previous.as_deref()) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized("Invalid service token".into()))
    }
}

/// Extract the internal-service credential from an `Authorization`
/// header value. Accepts only the RFC 9110 `Authorization: Bearer <token>`
/// shape.
///
/// Takes a raw `&str` argument rather than a `worker::Headers` so the
/// header-shape tests can be exercised on the native cargo-test target
/// without constructing a wasm-bound `Headers` instance.
pub(crate) fn resolve_internal_credential(authorization: Option<&str>) -> Option<String> {
    authorization
        .and_then(crate::security::extract_bearer_token)
        .map(str::to_string)
}

/// Constant-time dual-slot verify for the internal-service-token path.
///
/// Returns `true` if the credential matches either the current slot or
/// a populated previous slot, `false` otherwise. Comparison runs under
/// `subtle::ConstantTimeEq` after a fixed-size SHA-256 length blind.
pub(crate) fn verify_internal_token_slots(
    provided: &str,
    current: &str,
    previous: Option<&str>,
) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    let h_provided = Sha256::digest(provided.as_bytes());

    let h_current = Sha256::digest(current.as_bytes());
    if bool::from(h_current.ct_eq(&h_provided)) {
        return true;
    }

    if let Some(prev) = previous {
        let h_prev = Sha256::digest(prev.as_bytes());
        if bool::from(h_prev.ct_eq(&h_provided)) {
            return true;
        }
    }

    false
}

/// Read every rotation-capable Secrets Store binding the provii-issuer
/// owns and emit its 8-char fingerprint. Bindings that are absent
/// (legitimate steady-state for `_PREVIOUS` slots) are reported as
/// `null` rather than as the `"00000000"` sentinel; the harness
/// distinguishes "no slot bound" from "slot bound to all-zero value".
///
/// IP_HASH_SALT is a special case: it is a hash-salt class secret
/// rather than a dual-slot secret, so only the active slot is read.
/// ISSUER_ED25519_KEYS is a kid-keyed KV-resident keyset (Class 7),
/// not a Secrets Store binding; its fingerprint is exposed by the
/// request-log path on each issuance, not here.
async fn collect_slot_fingerprints(env: &Env) -> Vec<SlotFingerprint> {
    // (binding_name_for_secret_store_read, role_key_for_json_output).
    // Role-keys follow OBSERVABILITY.md §1: `_PROD` suffix on every
    // active key, `_PROD_PREVIOUS` on overlap-window slots, no
    // `ISSUER_` Worker-name prefix (the `service` log field carries
    // it). Sandbox emissions stay `_PROD` shape too because Workers
    // are env-keyed via `wrangler --env`, not via per-env field
    // names; the emission shape is uniform across deploys.
    let slots: &[(&str, &'static str)] = &[
        ("STATUS_API_TOKEN", "STATUS_API_TOKEN_PROD"),
        (
            "STATUS_API_TOKEN_PREVIOUS",
            "STATUS_API_TOKEN_PROD_PREVIOUS",
        ),
        ("ADMIN_API_KEY", "ADMIN_API_KEY_PROD"),
        ("ADMIN_API_KEY_PREVIOUS", "ADMIN_API_KEY_PROD_PREVIOUS"),
        ("ISSUER_KEK", "KEK_PROD"),
        ("ISSUER_KEK_PREVIOUS", "KEK_PROD_PREVIOUS"),
        ("ISSUER_IP_HASH_SALT", "IP_HASH_SALT_PROD"),
    ];

    let mut out: Vec<SlotFingerprint> = Vec::with_capacity(slots.len());
    for &(binding, role_key) in slots {
        out.push(SlotFingerprint {
            role_key,
            value: read_fingerprint(env, binding).await,
        });
    }
    out
}

/// Read one Secrets Store slot and return its 8-char fingerprint, or
/// `None` if the binding is absent / the value is empty. Errors are
/// folded into `None` rather than surfaced; the endpoint is purely
/// observational.
async fn read_fingerprint(env: &Env, binding: &str) -> Option<String> {
    let store = env.secret_store(binding).ok()?;
    match store.get().await {
        Ok(Some(mut v)) if !v.is_empty() => {
            let fp = fingerprint8(v.as_bytes());
            v.zeroize();
            Some(fp)
        }
        _ => None,
    }
}

fn build_response(env: &Env, slots: &[SlotFingerprint]) -> std::result::Result<Response, ApiError> {
    let deployed_at = env
        .var("WORKERS_BUILD_DEPLOYED_AT")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let git_sha = env
        .var("WORKERS_BUILD_GIT_SHA")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let mut secret_versions = serde_json::Map::with_capacity(slots.len());
    for sf in slots {
        let v = match sf.value.as_ref() {
            Some(fp) => serde_json::Value::String(fp.clone()),
            None => serde_json::Value::Null,
        };
        secret_versions.insert(sf.role_key.to_string(), v);
    }

    let body = serde_json::json!({
        "service": "provii-issuer",
        "deployed_at": deployed_at,
        "git_sha": git_sha,
        "secret_versions": serde_json::Value::Object(secret_versions),
    });

    let mut resp = Response::from_json(&body).map_err(|e| {
        ApiError::Internal(format!("Failed to build /_internal/version body: {}", e))
    })?;
    resp.headers_mut()
        .set("Content-Type", "application/json; charset=utf-8")
        .map_err(|e| ApiError::Internal(format!("Failed to set Content-Type: {}", e)))?;
    resp.headers_mut()
        .set(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, private, max-age=0",
        )
        .map_err(|e| ApiError::Internal(format!("Failed to set Cache-Control: {}", e)))?;
    Ok(resp)
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
    // Integration of `handle_internal_version` requires a Worker
    // `Env` (Secrets Store reads). The fingerprint helpers are
    // covered by `secret_fingerprint::tests`. The bearer-shape parser
    // is covered by `crate::security::header_parsing::tests`. The
    // header-shape resolver and the dual-slot verify are exercised
    // here as pure functions; the full auth path is exercised by the
    // rotation drill harness smoke test against the deployed
    // sandbox-issuer Worker. The `Cf-Access` header-shape predicate
    // is not used (workers.dev hostname bypass concern).
    use super::{resolve_internal_credential, verify_internal_token_slots};

    /* ========================================================================== */
    /*    Class 6 internal API key header-shape matrix                             */
    /*    Mirrors provii-verifier/src/security/status_auth.rs 8-scenario tests       */
    /* ========================================================================== */

    /// 1. Bearer current-slot match.
    #[test]
    fn internal_bearer_current_matches() {
        let credential =
            resolve_internal_credential(Some("Bearer current-token")).expect("bearer present");
        assert!(verify_internal_token_slots(
            &credential,
            "current-token",
            Some("previous-token")
        ));
    }

    /// 2. Bearer previous-slot match (rotation-window scenario).
    #[test]
    fn internal_bearer_previous_matches() {
        let credential =
            resolve_internal_credential(Some("Bearer previous-token")).expect("bearer present");
        assert!(verify_internal_token_slots(
            &credential,
            "current-token",
            Some("previous-token")
        ));
    }

    /// 3. Bearer wrong token rejects under both slots.
    #[test]
    fn internal_bearer_wrong_token_rejects() {
        let credential = resolve_internal_credential(Some("Bearer not-the-right-token"))
            .expect("bearer present");
        assert!(!verify_internal_token_slots(
            &credential,
            "current-token",
            Some("previous-token")
        ));
    }

    /// 4. `Authorization: Basic ...` is not a bearer credential.
    #[test]
    fn internal_authorization_basic_scheme_rejected() {
        assert_eq!(
            resolve_internal_credential(Some("Basic dXNlcjpwYXNz")),
            None
        );
    }

    /// 5. Lowercase `bearer` accepted per RFC 9110 §11.1.
    #[test]
    fn internal_bearer_lowercase_scheme_matches() {
        let credential =
            resolve_internal_credential(Some("bearer current-token")).expect("bearer present");
        assert!(verify_internal_token_slots(
            &credential,
            "current-token",
            None
        ));
    }

    /// 6. Missing Authorization header yields None.
    #[test]
    fn internal_missing_authorization_rejected() {
        assert_eq!(resolve_internal_credential(None), None);
    }

    /// 7. `Authorization: Bearer ` empty credential yields None.
    #[test]
    fn internal_bearer_empty_credential_rejected() {
        assert_eq!(resolve_internal_credential(Some("Bearer ")), None);
    }
}
