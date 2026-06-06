// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! HTTP route handlers for the issuer service.

use crate::crypto::{self, KeyManager};
use crate::error::ApiError;
use crate::secret_cache::{self, CachedHashedSecret};
use crate::session::{validate_timestamp, AUTH_FAILURE_MESSAGE};
use crate::storage;
use crate::types::*;
use crate::validation;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_valid::Validate as _;
use std::cell::RefCell;
use worker::*;

// Per-isolate cache for ADMIN_API_KEY. Stores only the Argon2id PHC
// hash and 6-char fingerprint; the plaintext is zeroised at cache time.
thread_local! {
    static ADMIN_KEY_CACHE: RefCell<Option<CachedHashedSecret>> = const { RefCell::new(None) };
}

// Per-isolate cache for ADMIN_API_KEY_PREVIOUS.
thread_local! {
    static ADMIN_KEY_PREV_CACHE: RefCell<Option<CachedHashedSecret>> = const { RefCell::new(None) };
}

/// Test-only reset for both ADMIN_API_KEY cache slots. Mode B rotation
/// drills call this between rotation steps so the next admin request
/// observes the fresh binding values without waiting for TTL expiry.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn reset_for_testing() {
    ADMIN_KEY_CACHE.with(|c| *c.borrow_mut() = None);
    ADMIN_KEY_PREV_CACHE.with(|c| *c.borrow_mut() = None);
}

/// Identifies which `ADMIN_API_KEY` slot satisfied a verify so
/// the caller can emit the `secret_version_used` log field and the
/// `x-secret-version` response header per `OBSERVABILITY.md` §1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdminKeySlot {
    Current,
    Previous,
}

impl AdminKeySlot {
    /// Slot label for the structured-log `secret_version_used` field.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Current => "ADMIN_API_KEY_PROD",
            Self::Previous => "ADMIN_API_KEY_PROD_PREVIOUS",
        }
    }
}

const MAX_VALIDITY_DAYS: u32 = 36500;

/// Resolve the `ISSUER_RATE_LIMITS` and `RATE_LIMIT_CONFIG` KV bindings
/// in one call. Returns `Err` with a 503 response when either binding is
/// unavailable (fail-closed).
///
/// Four admin handlers (`rotate_signing_key`, `check_key_health`,
/// `rotate_attestation_key`, `create_attestation`) previously duplicated
/// this 16-line pair of match blocks verbatim. Extracting into a helper
/// removes the duplication without introducing a new abstraction.
fn resolve_rate_limit_kvs(
    env: &worker::Env,
) -> std::result::Result<(worker::kv::KvStore, worker::kv::KvStore), worker::Result<Response>> {
    let rl_kv = match env.kv("ISSUER_RATE_LIMITS") {
        Ok(kv) => kv,
        Err(e) => {
            crate::log_error!("[RateLimit] ISSUER_RATE_LIMITS KV unavailable: {:?}", e);
            return Err(ApiError::ServiceUnavailable(
                "Rate limiting infrastructure unavailable".into(),
            )
            .to_response());
        }
    };
    let cfg_kv = match env.kv("RATE_LIMIT_CONFIG") {
        Ok(kv) => kv,
        Err(e) => {
            crate::log_error!("[RateLimit] RATE_LIMIT_CONFIG KV unavailable: {:?}", e);
            return Err(ApiError::ServiceUnavailable(
                "Rate limiting infrastructure unavailable".into(),
            )
            .to_response());
        }
    };
    Ok((rl_kv, cfg_kv))
}

/// Maximum length for the schema-string identifier accepted by the
/// blind-issuance path (`POST /v1/issuance/blind`). Applies to short
/// ASCII identifiers such as `"provii.age/0"`. This is distinct from
/// `crate::types::MAX_SCHEMA_VALUE_URL_LENGTH`, which bounds the
/// possibly-fully-qualified schema URL accepted on session requests.
const MAX_SCHEMA_LENGTH: usize = 128;
// Used by test assertions only.
#[cfg(test)]
const MAX_KID_LENGTH: usize = 64;

// Admin API key brute-force protection, sourced from shared constants.
use crate::constants::{ADMIN_LOCKOUT_DURATION_SECONDS, MAX_ADMIN_FAILED_ATTEMPTS};

/// Add anti-caching headers to a response (OWASP ASVS V14.2.2)
pub(crate) fn add_anti_caching_headers(mut response: Response) -> worker::Result<Response> {
    response.headers_mut().set(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, private",
    )?;
    response.headers_mut().set("Pragma", "no-cache")?;
    response.headers_mut().set("Expires", "0")?;
    Ok(response)
}

/// Read the default quota per hour from env var, with fallback.
///
/// Falls back to 500/hr when `DEFAULT_QUOTA_PER_HOUR` is missing or
/// unparseable. This is intentionally permissive to avoid rejecting legitimate
/// traffic due to a missing env var.
fn get_default_quota(env: &Env) -> u32 {
    match env.var("DEFAULT_QUOTA_PER_HOUR") {
        Ok(v) => match v.to_string().parse() {
            Ok(n) => n,
            Err(_) => {
                crate::log!("[CONFIG] DEFAULT_QUOTA_PER_HOUR unparseable; using default 500/hr");
                500
            }
        },
        Err(_) => {
            crate::log!("[CONFIG] DEFAULT_QUOTA_PER_HOUR not set; using default 500/hr");
            500
        }
    }
}

/// Read the blind issuance limit per hour from env var, with fallback.
fn get_blind_issuance_limit(env: &Env) -> u32 {
    env.var("BLIND_ISSUANCE_LIMIT_PER_HOUR")
        .ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(1000)
}

/// M3: per-issuer hourly cap on attestation NONCE CONSUMPTION.
///
/// Nonce consumption happens for every attestation BEFORE the expensive
/// Ed25519 verify, including replays and attestations that later fail verify
/// or issuance. A legitimate issuer's nonce-consume rate tracks its successful
/// issuance rate, which is already bounded by `BLIND_ISSUANCE_LIMIT_PER_HOUR`
/// (the sharded per-issuer counter). This is therefore a WIDER tripwire set at
/// a multiple of the issuance cap: a legitimate issuer hits the issuance cap
/// first and is rejected there, so this counter only trips on abnormal
/// nonce-burn (mass replay / a misbehaving client), which is exactly the
/// signal we want to surface.
///
/// The limit is `BLIND_ISSUANCE_LIMIT_PER_HOUR * NONCE_CONSUME_LIMIT_MULTIPLIER`
/// (multiplier default 3, clamped to 2..=3 per the hardening scope), unless an
/// explicit absolute `ATTESTATION_NONCE_LIMIT_PER_HOUR` is set, which wins.
/// `saturating_mul` keeps the product in range.
fn get_attestation_nonce_limit(env: &Env) -> u32 {
    // Explicit absolute override takes precedence.
    if let Some(absolute) = env
        .var("ATTESTATION_NONCE_LIMIT_PER_HOUR")
        .ok()
        .and_then(|v| v.to_string().parse::<u32>().ok())
    {
        return absolute;
    }

    let base = get_blind_issuance_limit(env);
    let multiplier = env
        .var("NONCE_CONSUME_LIMIT_MULTIPLIER")
        .ok()
        .and_then(|v| v.to_string().parse::<u32>().ok())
        .unwrap_or(3);
    // Clamp + saturating-multiply live in issuer_logic so the derivation is
    // unit-tested without a Worker Env.
    issuer_logic::rate_limiting::nonce_limit_from_issuance_cap(base, multiplier)
}

fn is_ascii_identifier(value: &str, max_len: usize) -> bool {
    if value.is_empty() || value.len() > max_len {
        return false;
    }

    // Only printable ASCII excluding space (0x21..=0x7E) is permitted.
    // Identifiers are used as storage keys; interior spaces would be
    // ambiguous and could collide after normalisation.
    value.chars().all(|c| c.is_ascii_graphic())
}

/// Verify an admin API key against `ADMIN_API_KEY`, with fallback to
/// `ADMIN_API_KEY_PREVIOUS` during key rotation.
///
/// SECURITY: Verification uses Argon2id with constant-time comparison
/// (via the `argon2` crate internally). The plaintext key is never
/// cached; only the Argon2id PHC hash is stored per-isolate. A memory
/// dump therefore reveals no recoverable secret material (F-06 fix).
///
/// # Rotation window operational procedure
///
/// `ADMIN_API_KEY_PREVIOUS` has no automatic expiry. It remains valid for as
/// long as the secret exists in the Secrets Store. Operators MUST remove
/// `ADMIN_API_KEY_PREVIOUS` from the Secrets Store once the rotation window
/// closes (all callers have migrated to the new key). Recommended rotation
/// procedure:
///
/// 1. Set `ADMIN_API_KEY` to the new key value in Secrets Store.
/// 2. Copy the old key value into `ADMIN_API_KEY_PREVIOUS`.
/// 3. Deploy and confirm all callers authenticate with the new key.
/// 4. Delete `ADMIN_API_KEY_PREVIOUS` from Secrets Store within 24 hours.
///
/// Failing to remove the previous key leaves a stale credential that an
/// attacker could use indefinitely if compromised.
///
/// Returns `Some(slot)` identifying which slot satisfied the verify, or
/// `None` if neither slot matched.
///
/// ACCEPTED RISK (ADV-IA-01-005): The sequential slot check is susceptible
/// to timing side-channels that reveal which slot (current vs previous)
/// matched. Compensating controls: IP-based lockout after 5 failures
/// (`MAX_ADMIN_FAILED_ATTEMPTS`) and 30-minute cooldown window make
/// online timing attacks infeasible in practice.
async fn verify_admin_api_key(env: &Env, provided: &str) -> Option<AdminKeySlot> {
    // Try current key via per-isolate Argon2id cache.
    if let Ok((Some(current_hash), _fp)) =
        secret_cache::get_or_fetch_hashed(&ADMIN_KEY_CACHE, || async {
            fetch_admin_secret(env, "ADMIN_API_KEY").await
        })
        .await
    {
        if crate::hash::verify_api_key(provided, &current_hash) {
            return Some(AdminKeySlot::Current);
        }
    }

    // Fallback: try previous key via per-isolate Argon2id cache (rotation window).
    if let Ok((Some(prev_hash), _fp)) =
        secret_cache::get_or_fetch_hashed(&ADMIN_KEY_PREV_CACHE, || async {
            fetch_admin_secret(env, "ADMIN_API_KEY_PREVIOUS").await
        })
        .await
    {
        if crate::hash::verify_api_key(provided, &prev_hash) {
            crate::log!("[Admin] API key verified with previous key (rotation window) - remove ADMIN_API_KEY_PREVIOUS from Secrets Store after rotation completes");
            return Some(AdminKeySlot::Previous);
        }
    }

    None
}

/// 6-char fingerprint of the matched ADMIN_API_KEY slot per
/// `OBSERVABILITY.md` §1, for the `x-secret-version` response header.
/// Reads from the per-isolate Argon2id cache populated by the auth path
/// (no plaintext involved).
async fn admin_key_fingerprint_for_slot(env: &Env, slot: AdminKeySlot) -> String {
    match slot {
        AdminKeySlot::Current => {
            match secret_cache::get_or_fetch_hashed(&ADMIN_KEY_CACHE, || async {
                fetch_admin_secret(env, "ADMIN_API_KEY").await
            })
            .await
            {
                Ok((_hash, fp)) => fp,
                Err(_) => "000000".to_string(),
            }
        }
        AdminKeySlot::Previous => {
            match secret_cache::get_or_fetch_hashed(&ADMIN_KEY_PREV_CACHE, || async {
                fetch_admin_secret(env, "ADMIN_API_KEY_PREVIOUS").await
            })
            .await
            {
                Ok((_hash, fp)) => fp,
                Err(_) => "000000".to_string(),
            }
        }
    }
}

/// emit the `secret_version` structured-log object for an admin
/// endpoint per `OBSERVABILITY.md` §1. Logged after a successful admin
/// auth so the request log line carries the rotation observable.
async fn log_admin_secret_version(env: &Env, used: AdminKeySlot, route: &str) {
    let current_fp = match secret_cache::get_or_fetch_hashed(&ADMIN_KEY_CACHE, || async {
        fetch_admin_secret(env, "ADMIN_API_KEY").await
    })
    .await
    {
        Ok((_hash, fp)) => fp,
        Err(_) => "000000".to_string(),
    };
    let previous_fp = match secret_cache::get_or_fetch_hashed(&ADMIN_KEY_PREV_CACHE, || async {
        fetch_admin_secret(env, "ADMIN_API_KEY_PREVIOUS").await
    })
    .await
    {
        Ok((_hash, fp)) => fp,
        Err(_) => "000000".to_string(),
    };

    crate::log!(
        r#"{{"type":"REQUEST_COMPLETE","service":"provii-issuer","route":"{route}","secret_version":{{"ADMIN_API_KEY_PROD":"{current}","ADMIN_API_KEY_PROD_PREVIOUS":"{previous}"}},"secret_version_used":"{used_label}"}}"#,
        route = route,
        current = current_fp,
        previous = previous_fp,
        used_label = used.label(),
    );
}

/// Fetch a single secret string from the Secrets Store binding.
///
/// Returns `Err` if the binding is unavailable or the secret is absent.
/// Used by the cached admin key lookups .
async fn fetch_admin_secret(env: &Env, binding: &str) -> Result<String, String> {
    let store = env
        .secret_store(binding)
        .map_err(|e| format!("{} binding unavailable: {:?}", binding, e))?;
    match store.get().await {
        Ok(Some(val)) if !val.is_empty() => Ok(val),
        Ok(Some(_)) => Err(format!("{} is empty", binding)),
        Ok(None) => Err(format!("{} not found", binding)),
        Err(e) => Err(format!("Failed to read {}: {:?}", binding, e)),
    }
}

/// Admin API key authentication outcome: either a deny `Response` to
/// be returned to the client, or the slot label that satisfied the
/// verify (for `secret_version_used` log emission and the
/// `x-secret-version` response header per `OBSERVABILITY.md` §1).
pub(crate) enum AdminAuthOutcome {
    /// Authentication failed; return this `Response` to the client.
    Deny(Response),
    /// Authentication succeeded under the carried slot.
    Allow(AdminKeySlot),
}

/// Extract the admin credential from the `Authorization: Bearer <token>`
/// header. Returns `None` if the header is absent or malformed.
fn extract_admin_credential(headers: &Headers) -> Option<String> {
    let authorization = headers.get("Authorization").ok().flatten();
    resolve_admin_credential(authorization.as_deref())
}

/// Resolve the admin credential from an `Authorization` header value.
///
/// Accepts only the RFC 9110 `Authorization: Bearer <token>` shape.
/// Returns `None` if the header is absent, empty, or carries a
/// non-Bearer scheme.
///
/// The shape check (scheme literal, single space delimiter) is not
/// secret-dependent and shares the parser used by the status-token
/// path so both Class 6 surfaces parse RFC 9110 identically.
fn resolve_admin_credential(authorization: Option<&str>) -> Option<String> {
    authorization
        .and_then(crate::security::extract_bearer_token)
        .map(str::to_string)
}

/// Admin API key authentication with lockout protection.
///
/// Matches the fail-closed lockout pattern used by
/// `authenticate_yubikey` in session.rs. Lockout is keyed by client IP
/// since admin auth has no named account identifier.
///
/// Returns `Ok(AdminAuthOutcome::Allow(slot))` on success or
/// `Ok(AdminAuthOutcome::Deny(response))` with a client-safe error
/// response on failure. The matched slot is threaded back so
/// the calling handler can emit the rotation observability fields.
async fn authenticate_admin(
    env: &Env,
    admin_api_key: &str,
    client_ip: &str,
    endpoint: &str,
) -> worker::Result<AdminAuthOutcome> {
    // Check lockout BEFORE attempting verification
    match storage::is_locked_out(env, "admin", client_ip).await {
        Ok(true) => {
            crate::log_error!("[Admin] Locked-out IP attempted admin auth on {}", endpoint,);
            let _ = crate::audit::audit_log_with_actor(
                env,
                "admin_auth_failed",
                client_ip,
                "Admin auth rejected: IP locked out",
                &serde_json::json!({
                    "endpoint": endpoint,
                    "reason": "ip_locked_out",
                }),
                Some(client_ip),
                Some(crate::audit::Outcome::Denied),
            )
            .await;
            return Ok(AdminAuthOutcome::Deny(
                ApiError::Forbidden("Unauthorised".into()).to_response()?,
            ));
        }
        Ok(false) => {} // Not locked out, proceed
        Err(e) => {
            // fail closed on storage error
            crate::log_error!(
                "[Admin] Lockout check failed for {}: {:?}; rejecting (fail-closed)",
                endpoint,
                e,
            );
            return Ok(AdminAuthOutcome::Deny(
                ApiError::ServiceUnavailable("Authentication infrastructure unavailable".into())
                    .to_response()?,
            ));
        }
    }

    // Verify the key
    let matched_slot = match verify_admin_api_key(env, admin_api_key).await {
        Some(slot) => slot,
        None => {
            crate::log_error!("[Admin] Invalid admin API key attempted for {}", endpoint,);

            // Record failure and check threshold
            match storage::record_auth_failure(env, "admin", client_ip, MAX_ADMIN_FAILED_ATTEMPTS)
                .await
            {
                Ok(failure_count) => {
                    if failure_count >= MAX_ADMIN_FAILED_ATTEMPTS {
                        if let Err(e) = storage::lock_account(
                            env,
                            "admin",
                            client_ip,
                            ADMIN_LOCKOUT_DURATION_SECONDS,
                        )
                        .await
                        {
                            crate::log_error!("Failed to lock admin account: {:?}", e,);
                        }
                        crate::audit::audit_log_detailed(
                            env,
                            "account_locked",
                            client_ip,
                            "Admin IP locked after repeated authentication failures",
                            &serde_json::json!({
                                "endpoint": endpoint,
                                "failure_count": failure_count,
                                "lockout_duration_seconds": ADMIN_LOCKOUT_DURATION_SECONDS,
                            }),
                            crate::audit::DetailedAuditFields {
                                event_category: provii_audit::EventCategory::SecurityEvent,
                                actor_id: client_ip,
                                outcome: Some(crate::audit::Outcome::Denied),
                                severity: Some(provii_audit::Severity::Critical),
                            },
                        )
                        .await;
                    }
                }
                Err(e) => {
                    // Fail closed: cannot track failures, reject anyway
                    crate::log_error!(
                        "record_auth_failure storage error for admin IP: {:?}; rejecting (fail-closed)",
                        e,
                    );
                }
            }

            let _ = crate::audit::audit_log_with_actor(
                env,
                "admin_auth_failed",
                client_ip,
                &format!("Admin authentication failed for {}", endpoint),
                &serde_json::json!({
                    "endpoint": endpoint,
                    "reason": "invalid_admin_key",
                }),
                Some(client_ip),
                Some(crate::audit::Outcome::Failure),
            )
            .await;

            return Ok(AdminAuthOutcome::Deny(
                ApiError::Forbidden("Unauthorised".into()).to_response()?,
            ));
        }
    };

    // Success: clear any accumulated failures for this IP.
    // Audit the counter-clear so tamper analysis can correlate auth
    // successes with prior failure sequences.
    if storage::clear_auth_failures(env, "admin", client_ip)
        .await
        .is_ok()
    {
        // Only log when there were failures to clear (avoids noise on
        // first-attempt successes). The clear_auth_failures fn returns
        // Ok(()) unconditionally so we cannot distinguish; log at trace
        // level for all successes.
        crate::log!("[Admin] Auth failure counter cleared for IP after successful auth");
    }

    Ok(AdminAuthOutcome::Allow(matched_slot))
}

/// Generate a random challenge payload for YubiKey flows.
/// Uses 32 bytes (256 bits) for cryptographic strength against brute-force attacks.
fn generate_challenge() -> crate::error::Result<Vec<u8>> {
    let mut challenge = vec![0u8; 32];
    getrandom::getrandom(&mut challenge).map_err(|e| {
        crate::error::ApiError::CryptoError(format!("Challenge generation failed: {}", e))
    })?;
    Ok(challenge)
}

/// Provision a YubiKey challenge for officer authentication.
///
/// The officer (provii-mobile) calls this endpoint before `POST /v1/attestation/create`
/// to obtain a server-generated challenge, which they then sign with their YubiKey
/// via HMAC-SHA1 challenge-response. The resulting HMAC + `challenge_id` is sent in
/// the attestation request's `authorizer` envelope for validation.
pub async fn generate_yubikey_challenge(
    mut req: Request,
    ctx: RouteContext<()>,
) -> worker::Result<Response> {
    let env = ctx.env.clone();
    let client_ip = crate::audit::get_client_ip(&req);

    // IP rate limit BEFORE body parse to defend against DoS.
    let rl_kv = match env.kv("ISSUER_RATE_LIMITS") {
        Ok(kv) => kv,
        Err(e) => {
            crate::log_error!("[RateLimit] ISSUER_RATE_LIMITS KV unavailable: {:?}", e);
            return ApiError::ServiceUnavailable("Rate limiting infrastructure unavailable".into())
                .to_response();
        }
    };
    // Hash the IP before using it in the KV key so plaintext
    // addresses are never stored as KV key names.
    let hashed_ip = crate::audit::build_privacy_context(&env)
        .await
        .hash_ip(&client_ip)
        .unwrap_or_default();
    let ip_key = format!("challenge_ip:{}", hashed_ip);
    let ip_limit: u32 = env
        .var("CHALLENGE_IP_LIMIT_PER_HOUR")
        .ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(60);
    let rl_result = crate::rate_limiting::check_blind_issuance(&rl_kv, &ip_key, ip_limit).await;
    if !rl_result.allowed {
        return crate::rate_limiting::rate_limit_or_unavailable_response(&rl_result);
    }

    // Parse request body
    let data: ChallengeRequest = match req.json().await {
        Ok(d) => d,
        Err(_e) => {
            // R8: offload the best-effort reject audit to wait_until so the 400
            // returns before the AUDIT_QUEUE send. Inline fallback is MANDATORY
            // (take_worker_context is single-shot). audit_log swallows errors so
            // this can never become a 5xx.
            {
                let audit_env = env.clone();
                let audit_ip = client_ip.clone();
                let emit = move |env: Env, ip: String| async move {
                    crate::audit::audit_log(
                        &env,
                        "challenge_rejected",
                        &ip,
                        "Failed to parse challenge request body",
                        &serde_json::json!({
                            "reason": "json_parse_failure",
                            "endpoint": "/v1/challenge",
                        }),
                    )
                    .await;
                };
                if let Some(ctx) = crate::take_worker_context() {
                    ctx.wait_until(emit(audit_env, audit_ip));
                } else {
                    emit(audit_env, audit_ip).await;
                }
            }
            return ApiError::BadRequest("Invalid request format".into()).to_response();
        }
    };

    if let Err(e) = data.validate() {
        crate::audit::audit_log(
            &env,
            "challenge_rejected",
            &client_ip,
            "Challenge request schema validation failed",
            &serde_json::json!({
                "reason": "schema_validation_failure",
                "endpoint": "/v1/challenge",
                "error": format!("{}", e),
            }),
        )
        .await;
        return ApiError::BadRequest("Invalid request payload".into()).to_response();
    }

    // Lockout check mirrors authenticate_yubikey: a locked officer cannot obtain
    // new challenges either. Fail-closed on storage error.
    //
    // R6: re-key the READ to the SAME (hashed officer_id, hashed source IP)
    // composite the SET path (record_officer_failure_and_reject) and the other
    // READ (authenticate_yubikey) use. Re-keying only one site would let a
    // roaming officer be evaluated against a different bucket and silently
    // neuter the lock. This endpoint stays strictly READ-ONLY on lockout: it
    // never calls record_auth_failure / lock_account and never increments any
    // failure counter (the per-IP check below is read-only too).
    let lockout_actor =
        crate::session::officer_lockout_actor_id(&env, &data.officer_id, &client_ip).await;
    match storage::is_locked_out(&env, "officer", &lockout_actor).await {
        Ok(true) => {
            return ApiError::Unauthorized(AUTH_FAILURE_MESSAGE.into()).to_response();
        }
        Ok(false) => {}
        Err(e) => {
            crate::log_error!("[challenge] lockout storage error: {:?}", e);
            return ApiError::ServiceUnavailable(
                "Authentication infrastructure unavailable".into(),
            )
            .to_response();
        }
    }

    // R6: read-only per-IP throttle. A source IP that has exceeded the hourly
    // officer auth-failure cap is throttled out of obtaining further challenges,
    // bounding a roaming attacker without locking any single victim officer.
    // READ-ONLY: never increments the failure counter, preserving the /v1/challenge
    // read-only-on-lockout contract.
    if crate::session::authfail_ip_exceeded(&env, &client_ip).await {
        return ApiError::Unauthorized(AUTH_FAILURE_MESSAGE.into()).to_response();
    }

    // Officer must exist and be active. Do NOT leak whether the ID exists on failure:
    // return the same AUTH_FAILURE_MESSAGE used by authenticate_yubikey.
    match storage::get_officer_by_id(&env, &data.officer_id).await {
        Ok(Some(officer)) if officer.active => {}
        _ => {
            return ApiError::Unauthorized(AUTH_FAILURE_MESSAGE.into()).to_response();
        }
    }

    // Generate challenge bytes and persist.
    let challenge_bytes = match generate_challenge() {
        Ok(b) => b,
        Err(e) => return e.to_response(),
    };

    let ttl = crate::session::CHALLENGE_TTL_SECONDS;
    let stored = match storage::create_challenge(
        &env,
        data.officer_id.clone(),
        challenge_bytes,
        ttl,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return e.to_response(),
    };

    let response = ChallengeResponse {
        challenge_id: stored.challenge_id.clone(),
        challenge: hex::encode(&stored.challenge),
        expires_at: stored.expires_at,
    };

    let resp = Response::from_json(&response)?.with_status(201);
    add_anti_caching_headers(resp)
}

/// Expose the issuer's public keys in JWKS format.
pub async fn jwks(_req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let env = ctx.env.clone();

    let config = match storage::get_issuer_config(&env).await {
        Ok(c) => c,
        Err(e) => {
            crate::log_error!("Failed to get config: {:?}", e);
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    // JWKS only needs the public verification key. Avoid loading and
    // decrypting the private signing key to reduce blast radius.
    // Pass the already-fetched config to skip a redundant KV read.
    let vk =
        match storage::get_public_key_only_with_config(&env, &config.default_kid, Some(&config))
            .await
        {
            Ok(vk) => vk,
            Err(e) => {
                crate::log_error!("Failed to get public key: {:?}", e);
                return ApiError::Internal("Internal server error".into()).to_response();
            }
        };

    let key_manager = match KeyManager::from_public_key(config.default_kid.clone(), vk) {
        Ok(km) => km,
        Err(e) => {
            crate::log_error!("Failed to create key manager: {:?}", e);
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    let jwks = JwkSet {
        keys: key_manager.get_jwks(),
    };

    let mut response = Response::from_json(&jwks)?;

    // P3-17: If a key rotation happened within the last 60 seconds (flagged by
    // the jwks:rotated_at KV key with 60s TTL), serve the JWKS with no-cache so
    // relying parties immediately pick up the new key. Otherwise default to a
    // 10-minute public cache.
    let recently_rotated = if let Ok(config_kv) = env.kv(crate::bindings::ISSUER_CONFIG) {
        matches!(config_kv.get("jwks:rotated_at").text().await, Ok(Some(_)))
    } else {
        false
    };

    if recently_rotated {
        response
            .headers_mut()
            .set("Cache-Control", "max-age=0, no-cache")?;
    } else {
        response
            .headers_mut()
            .set("Cache-Control", "public, max-age=600")?;
    }

    Ok(response)
}

/// Trial-verify: derive the ordered list of `(slot_label, kid)`
/// pairs the blind-issuance verify path will try in turn. Returns
/// `default_kid` first, optionally followed by `previous_kid` when the
/// issuer is mid-rotation. Slot labels are stable identifiers used as
/// the `secret_version_used` value on success-path structured logs;
/// they intentionally mirror the `IssuerConfig` field names so log
/// readers can follow the rotation state without a translation table.
///
/// The slot list is evaluated against KV under each kid; eligibility
/// (record present + active + within validity window) is checked
/// per-slot in the handler. This helper carries no eligibility logic
/// itself so it can be exercised without a Worker `Env`.
fn trial_verify_candidate_slots(config: &IssuerConfig) -> Vec<(&'static str, String)> {
    let mut slots: Vec<(&'static str, String)> = Vec::with_capacity(2);
    slots.push(("default_kid", config.default_kid.clone()));
    if let Some(prev) = config.previous_kid.as_ref() {
        slots.push(("previous_kid", prev.clone()));
    }
    slots
}

/// Per-slot reason a candidate was rejected during the trial-verify
/// eligibility check. Surfaced on the audit log when no slot is
/// eligible so operators can distinguish "no record" from "outside
/// validity" mid-rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EligibilityReject {
    /// `record.active == false`, explicit retirement of the kid.
    Inactive,
    /// `now < record.valid_from`, kid not yet activated.
    NotYetValid,
    /// `now > record.valid_until`, kid expired, where `valid_until > 0`.
    Expired,
    /// `record.verifying_key` is not a well-formed Ed25519 verifying key.
    /// Indicates a corrupted KV record; treat as ineligible rather than
    /// crashing the verify path.
    VerifyingKeyDecode,
}

impl EligibilityReject {
    /// Stable machine-readable reason code for audit/log emission.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Inactive => "key_inactive",
            Self::NotYetValid => "key_outside_validity",
            Self::Expired => "key_outside_validity",
            Self::VerifyingKeyDecode => "verifying_key_decode",
        }
    }
}

/// Pure predicate that decides whether a `(record, now)` pair is
/// eligible to participate in the trial-verify candidate list.
/// Extracted from the inline eligibility logic at the Phase 5
/// candidate-slot loop in `blind_issuance` so it can be unit-tested
/// without a Worker `Env`.
///
/// Returns `Ok(VerifyingKey)` when the record is active, `now` lies
/// within `[valid_from, valid_until]`, and the verifying-key bytes
/// decode to a valid Ed25519 point. Returns `Err(reason)` otherwise.
///
/// `valid_until == 0` is treated as "no expiry", matching the
/// `IssuerEd25519Key` doc comment contract.
pub(crate) fn is_eligible(
    record: &IssuerEd25519Key,
    now: u64,
) -> std::result::Result<ed25519_dalek::VerifyingKey, EligibilityReject> {
    if !record.active {
        return Err(EligibilityReject::Inactive);
    }
    if now < record.valid_from {
        return Err(EligibilityReject::NotYetValid);
    }
    // valid_until == 0 means "no expiry" per the IssuerEd25519Key doc comment.
    // Only check expiry when a non-zero valid_until is set.
    if record.valid_until != 0 && now > record.valid_until {
        return Err(EligibilityReject::Expired);
    }
    ed25519_dalek::VerifyingKey::from_bytes(&record.verifying_key)
        .map_err(|_| EligibilityReject::VerifyingKeyDecode)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::items_after_test_module,
    clippy::doc_lazy_continuation
)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    IS_ASCII_IDENTIFIER TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_is_ascii_identifier_valid() {
        assert!(is_ascii_identifier("provii.age/0", 128));
        assert!(is_ascii_identifier("gov:2025-08", 64));
        assert!(is_ascii_identifier("client-123", 64));
        assert!(is_ascii_identifier("officer-456", 64));
    }

    #[test]
    fn test_is_ascii_identifier_valid_special_chars() {
        assert!(is_ascii_identifier("a.b/c-d_e:f", 128));
        assert!(is_ascii_identifier("test@example.com", 128));
        assert!(is_ascii_identifier("path/to/resource", 128));
    }

    #[test]
    fn test_is_ascii_identifier_empty_string() {
        assert!(!is_ascii_identifier("", 128));
        assert!(!is_ascii_identifier("", 64));
    }

    #[test]
    fn test_is_ascii_identifier_exceeds_max_length() {
        assert!(!is_ascii_identifier("a".repeat(129).as_str(), 128));
        assert!(!is_ascii_identifier("a".repeat(65).as_str(), 64));
    }

    #[test]
    fn test_is_ascii_identifier_exactly_max_length() {
        assert!(is_ascii_identifier(&"a".repeat(128), 128));
        assert!(is_ascii_identifier(&"a".repeat(64), 64));
    }

    #[test]
    fn test_is_ascii_identifier_leading_whitespace() {
        assert!(!is_ascii_identifier(" test", 64));
        assert!(!is_ascii_identifier("  test", 64));
        assert!(!is_ascii_identifier("\ttest", 64));
    }

    #[test]
    fn test_is_ascii_identifier_trailing_whitespace() {
        assert!(!is_ascii_identifier("test ", 64));
        assert!(!is_ascii_identifier("test  ", 64));
        assert!(!is_ascii_identifier("test\t", 64));
    }

    #[test]
    fn test_is_ascii_identifier_internal_whitespace() {
        // Spaces are rejected: identifiers are storage keys and must not
        // contain whitespace (ADV-IA-39-002).
        assert!(!is_ascii_identifier("hello world", 64));
        // Tabs are also rejected (non-graphic).
        assert!(!is_ascii_identifier("test\tvalue", 64));
    }

    #[test]
    fn test_is_ascii_identifier_control_characters() {
        assert!(!is_ascii_identifier("test\n", 64));
        assert!(!is_ascii_identifier("test\r", 64));
        assert!(!is_ascii_identifier("test\0", 64));
        assert!(!is_ascii_identifier("\x01test", 64));
    }

    #[test]
    fn test_is_ascii_identifier_unicode() {
        assert!(!is_ascii_identifier("café", 64));
        assert!(!is_ascii_identifier("test🎉", 64));
        assert!(!is_ascii_identifier("日本語", 64));
    }

    #[test]
    fn test_is_ascii_identifier_numbers() {
        assert!(is_ascii_identifier("123", 64));
        assert!(is_ascii_identifier("test123", 64));
        assert!(is_ascii_identifier("123test", 64));
    }

    #[test]
    fn test_is_ascii_identifier_schema_examples() {
        assert!(is_ascii_identifier("provii.age/0", MAX_SCHEMA_LENGTH));
        assert!(is_ascii_identifier("provii.identity/1", MAX_SCHEMA_LENGTH));
        assert!(is_ascii_identifier("gov.au/homeaffairs", MAX_SCHEMA_LENGTH));
    }

    #[test]
    fn test_is_ascii_identifier_kid_examples() {
        assert!(is_ascii_identifier("gov:2025-08", MAX_KID_LENGTH));
        assert!(is_ascii_identifier("key-1", MAX_KID_LENGTH));
        assert!(is_ascii_identifier("issuer-key-2025", MAX_KID_LENGTH));
    }

    /* ========================================================================== */
    /*                    GENERATE_CHALLENGE TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_generate_challenge_length() -> Result<(), Box<dyn std::error::Error>> {
        let challenge = generate_challenge()?;
        assert_eq!(challenge.len(), 32);
        Ok(())
    }

    #[test]
    fn test_generate_challenge_uniqueness() -> Result<(), Box<dyn std::error::Error>> {
        // Generate multiple challenges and ensure they're unique
        let mut challenges = std::collections::HashSet::new();
        for _ in 0..100 {
            challenges.insert(generate_challenge()?);
        }
        // Should have 100 unique challenges (statistically very likely)
        assert!(challenges.len() > 95); // Allow tiny chance of collision
        Ok(())
    }

    #[test]
    fn test_generate_challenge_non_zero() -> Result<(), Box<dyn std::error::Error>> {
        // Ensure challenge is not all zeros (statistically impossible)
        let challenge = generate_challenge()?;
        assert!(challenge.iter().any(|&b| b != 0));
        Ok(())
    }

    #[test]
    fn test_generate_challenge_consistency() -> Result<(), Box<dyn std::error::Error>> {
        // Each call should generate 32 bytes
        for _ in 0..10 {
            let challenge = generate_challenge()?;
            assert_eq!(challenge.len(), 32);
        }
        Ok(())
    }

    #[test]
    fn test_generate_challenge_randomness() -> Result<(), Box<dyn std::error::Error>> {
        // Generate multiple challenges and verify they have good distribution
        let challenges: Vec<Vec<u8>> = (0..20)
            .map(|_| generate_challenge())
            .collect::<Result<Vec<_>, _>>()?;

        // Check that not all challenges are identical
        let first = &challenges[0];
        let all_same = challenges.iter().all(|c| c == first);
        assert!(!all_same, "Challenges should not all be identical");
        Ok(())
    }

    /* ========================================================================== */
    /*                    CONSTANTS VALIDATION TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_constants_values() {
        assert_eq!(MAX_VALIDITY_DAYS, 36500); // 100 years
        assert_eq!(MAX_SCHEMA_LENGTH, 128);
        assert_eq!(MAX_KID_LENGTH, 64);
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                  */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        #[test]
        fn prop_is_ascii_identifier_length_bounds(s in "\\PC*") {
            // Any string exceeding max_len should be rejected
            let result = is_ascii_identifier(&s, 10);
            if s.len() > 10 {
                assert!(!result, "String length {} exceeds max_len 10", s.len());
            }
        }

        #[test]
        fn prop_is_ascii_identifier_empty_rejected(max_len in 1usize..1000) {
            // Empty string should always be rejected regardless of max_len
            assert!(!is_ascii_identifier("", max_len));
        }

        #[test]
        fn prop_is_ascii_identifier_ascii_only(s in "[a-zA-Z0-9._:/\\-@]+") {
            // Pure ASCII alphanumeric + common punctuation should pass for reasonable lengths
            let result = is_ascii_identifier(&s, 1000);
            if !s.is_empty() && s.len() <= 1000 && s.trim() == s {
                assert!(result, "Pure ASCII string '{}' should be accepted", s);
            }
        }

        #[test]
        fn prop_is_ascii_identifier_no_control_chars(
            s in "[a-zA-Z0-9]+",
            control_char in 0u8..32u8,
        ) {
            // Any string with control characters should be rejected
            let mut with_control = s.clone();
            with_control.push(control_char as char);
            assert!(!is_ascii_identifier(&with_control, 1000));
        }

        #[test]
        fn prop_is_ascii_identifier_whitespace_trimming(
            s in "[a-zA-Z0-9]+",
            leading_spaces in 0usize..5,
            trailing_spaces in 0usize..5,
        ) {
            // Leading or trailing whitespace should be rejected
            let mut with_whitespace = " ".repeat(leading_spaces);
            with_whitespace.push_str(&s);
            with_whitespace.push_str(&" ".repeat(trailing_spaces));

            let result = is_ascii_identifier(&with_whitespace, 1000);
            if leading_spaces > 0 || trailing_spaces > 0 {
                assert!(!result, "String with whitespace should be rejected");
            }
        }

        #[test]
        fn prop_generate_challenge_always_32_bytes(_seed in 0u64..1000) {
            let challenge = generate_challenge().unwrap();
            assert_eq!(challenge.len(), 32, "Challenge must always be 32 bytes");
        }

        #[test]
        fn prop_generate_challenge_sufficient_entropy(_iterations in 0u32..100) {
            // Generate multiple challenges and ensure at least one byte varies
            let challenges: Vec<Vec<u8>> = (0..10).map(|_| generate_challenge().unwrap()).collect();

            // Check that not all challenges are identical
            let first = &challenges[0];
            let all_same = challenges.iter().all(|c| c == first);
            assert!(!all_same, "Challenges should have entropy");
        }
    }

    /* ========================================================================== */
    /*                    ADDITIONAL EDGE CASE TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_is_ascii_identifier_boundary_lengths() {
        // Test exact boundary conditions for different max lengths
        assert!(is_ascii_identifier("a", 1));
        assert!(is_ascii_identifier(&"a".repeat(64), 64));
        assert!(is_ascii_identifier(&"a".repeat(128), 128));
        assert!(is_ascii_identifier(&"a".repeat(256), 256));

        assert!(!is_ascii_identifier(&"a".repeat(2), 1));
        assert!(!is_ascii_identifier(&"a".repeat(65), 64));
        assert!(!is_ascii_identifier(&"a".repeat(129), 128));
        assert!(!is_ascii_identifier(&"a".repeat(257), 256));
    }

    #[test]
    fn test_is_ascii_identifier_all_printable_ascii() {
        // Test all printable ASCII characters (32-126)
        for i in 32u8..=126 {
            let c = i as char;
            let s = c.to_string();
            let result = is_ascii_identifier(&s, 10);

            // Only control characters should fail
            if i < 32 || i == 127 {
                assert!(!result, "Control character {} should be rejected", i);
            }
        }
    }

    #[test]
    fn test_is_ascii_identifier_mixed_case() {
        assert!(is_ascii_identifier("AbCdEfGh", 64));
        assert!(is_ascii_identifier("UPPERCASE", 64));
        assert!(is_ascii_identifier("lowercase", 64));
        assert!(is_ascii_identifier("MixedCase123", 64));
    }

    #[test]
    fn test_is_ascii_identifier_special_punctuation() {
        // Test various punctuation characters
        assert!(is_ascii_identifier("test.example", 64));
        assert!(is_ascii_identifier("test:key", 64));
        assert!(is_ascii_identifier("test/path", 64));
        assert!(is_ascii_identifier("test-value", 64));
        assert!(is_ascii_identifier("test_var", 64));
        assert!(is_ascii_identifier("test@domain", 64));
        assert!(is_ascii_identifier("test+extra", 64));
        assert!(is_ascii_identifier("test=value", 64));
    }

    #[test]
    fn test_is_ascii_identifier_url_components() {
        assert!(is_ascii_identifier("https://example.com", 64));
        assert!(is_ascii_identifier("user@host:port", 64));
        assert!(is_ascii_identifier("scheme://path/to/resource", 128));
    }

    #[test]
    fn test_generate_challenge_distribution() -> Result<(), Box<dyn std::error::Error>> {
        // Generate many challenges and verify reasonable byte distribution
        let mut byte_sums = [0u64; 32];
        let iterations = 1000;

        for _ in 0..iterations {
            let challenge = generate_challenge()?;
            for (i, &byte) in challenge.iter().enumerate() {
                byte_sums[i] += byte as u64;
            }
        }

        // Each byte position should have average around 127.5 (middle of 0-255)
        // Allow for statistical variance
        for (i, &sum) in byte_sums.iter().enumerate() {
            let avg = sum / iterations;
            assert!(
                avg > 100 && avg < 155,
                "Byte position {} has suspicious distribution: avg={}",
                i,
                avg
            );
        }
        Ok(())
    }

    #[test]
    fn test_generate_challenge_bit_entropy() -> Result<(), Box<dyn std::error::Error>> {
        // Ensure each bit position has reasonable entropy
        let mut bit_counts = [0u32; 256]; // 32 bytes * 8 bits
        let iterations = 1000;

        for _ in 0..iterations {
            let challenge = generate_challenge()?;
            for (byte_idx, &byte) in challenge.iter().enumerate() {
                for bit_idx in 0..8 {
                    if (byte & (1 << bit_idx)) != 0 {
                        bit_counts[byte_idx * 8 + bit_idx] += 1;
                    }
                }
            }
        }

        // Each bit should be set roughly 50% of the time
        // Allow for statistical variance (40% to 60%)
        for (i, &count) in bit_counts.iter().enumerate() {
            let percentage = (count as f64 / iterations as f64) * 100.0;
            assert!(
                percentage > 40.0 && percentage < 60.0,
                "Bit {} has suspicious distribution: {}%",
                i,
                percentage
            );
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_constants_relationships() {
        assert!(
            MAX_VALIDITY_DAYS >= 365,
            "Max validity should be at least 1 year"
        );
        assert!(
            MAX_SCHEMA_LENGTH > MAX_KID_LENGTH,
            "Schema length should exceed kid length"
        );
    }

    /* ========================================================================== */
    /*                    ARGON2ID ADMIN KEY VERIFICATION TESTS                 */
    /* ========================================================================== */

    #[test]
    fn test_argon2id_admin_key_roundtrip() {
        let key = "admin_secret_key_12345";
        let phc = crate::hash::hash_api_key(key).expect("hash must succeed");
        assert!(crate::hash::verify_api_key(key, &phc));
    }

    #[test]
    fn test_argon2id_admin_key_wrong_key_rejects() {
        let phc = crate::hash::hash_api_key("admin_secret_key_12345").expect("hash must succeed");
        assert!(!crate::hash::verify_api_key("admin_secret_key_54321", &phc));
    }

    #[test]
    fn test_argon2id_admin_key_empty_key_roundtrip() {
        let phc = crate::hash::hash_api_key("").expect("hash must succeed");
        assert!(crate::hash::verify_api_key("", &phc));
        assert!(!crate::hash::verify_api_key("non-empty", &phc));
    }

    #[test]
    fn test_argon2id_admin_key_single_bit_difference() {
        let phc = crate::hash::hash_api_key("admin_key_000").expect("hash must succeed");
        assert!(!crate::hash::verify_api_key("admin_key_001", &phc));
    }

    #[test]
    fn test_argon2id_admin_key_format() {
        let phc = crate::hash::hash_api_key("admin_secret_key_AAAAAAA").expect("hash must succeed");
        assert!(phc.starts_with("$argon2id$"));
    }

    /* ========================================================================== */
    /*                    INTEGRATION TEST DOCUMENTATION                        */
    /* ========================================================================== */

    /* The following HTTP handler functions require Cloudflare Workers runtime mocking
       and are not testable with standard unit tests. They should be tested in
       integration tests with either:
       1. A real Cloudflare Workers environment (wrangler dev)
       2. Mock Worker Request/Response/RouteContext for testing
       3. E2E tests against deployed Workers

       HTTP Handlers requiring integration testing:

       generate_yubikey_challenge(req, ctx) -> Response
       -----------------------------------------------
       Success path:
       - Valid officer_id in request body
       - Officer exists and is active
       - Challenge generated (32 bytes / 256 bits)
       - Challenge stored with 120s TTL
       - Response contains challenge_id, hex challenge, expires_at
       - Audit log entry created

       Error paths:
       - Invalid JSON body (400)
       - Officer not found (404)
       - Inactive officer (403)
       - Storage failure (500)

       create_attestation(req, ctx) -> Response
       -----------------------------------------
       Officer flow:
       - Valid request with actor="officer"
       - Authorizer format="yubikey"
       - Timestamp validation
       - YubiKey authentication (challenge consumption)
       - Schema validation (ASCII, max 128 chars)
       - Kid validation (ASCII, max 64 chars)
       - Validity capping (max 36500 days)
       - Session creation with Officer actor
       - Officer binding
       - Audit log entry
       - Response: session_id, kid, schema, iat, exp, expires_at

       Client flow:
       - Valid request with actor="client"
       - Authorizer format="client"
       - Timestamp validation
       - HMAC verification (canonical message)
       - X-API-Key header validation
       - Rate limiting check
       - Schema allowlist validation
       - Validity capping per client policy
       - Session creation with Client actor
       - Client binding
       - Audit log entry
       - Response: session_id, kid, schema, iat, exp, expires_at

       Error paths:
       - Invalid JSON (400)
       - Invalid timestamp (401)
       - Invalid actor (not "officer" or "client") (400)
       - Officer using client auth (400)
       - Client using yubikey auth (400)
       - Invalid schema (empty, too long, non-ASCII, control chars, Unicode) (400)
       - Invalid kid (empty, too long, non-ASCII) (400)
       - Zero validity_days (400)
       - Invalid YubiKey auth (401)
       - Invalid client HMAC (401)
       - Rate limit exceeded (429)
       - Schema not in client allowlist (403)
       - Validity exceeds client max (403)

       SECURITY: Session Ownership Validation Test Scenarios
       -------------------------------------------------------
       These scenarios validate the horizontal privilege escalation fix:

       1. Officer A creates session, Officer B tries to access:
          - Officer A authenticates with YubiKey and creates session
          - Session binds to Officer A (session.officer_id = "officer-A")
          - Officer B authenticates with YubiKey for same session
          - Ownership check: bound_officer ("officer-A") != officer_id ("officer-B")
          - Result: REJECT with 403 "Session bound to different officer"
          - Audit log: session_ownership_violation with details

       2. Client A creates session, Client B tries to access:
          - Client A authenticates with API key and creates session
          - Session binds to Client A (session.client_id = "client-A")
          - Client B authenticates with API key for same session
          - Ownership check: bound_client ("client-A") != client_id ("client-B")
          - Result: REJECT with 403 "Session bound to different client"
          - Audit log: session_ownership_violation with details

       3. Officer creates session, same Officer accesses:
          - Officer authenticates with YubiKey and creates session
          - Session binds to Officer (session.officer_id = "officer-1")
          - Same Officer authenticates again for access
          - Ownership check: bound_officer ("officer-1") == officer_id ("officer-1")
          - Result: ALLOW - proceeds with rate limiting and operation
          - Normal audit log

       4. Client creates session, same Client accesses:
          - Client authenticates with API key and creates session
          - Session binds to Client (session.client_id = "client-1")
          - Same Client authenticates again for access
          - Ownership check: bound_client ("client-1") == client_id ("client-1")
          - Result: ALLOW - proceeds with rate limiting and operation
          - Normal audit log

       5. Unbound session, first access binds and allows:
          - Session exists but session.officer_id = None and session.client_id = None
          - Officer/Client authenticates for first time on this session
          - Ownership check: session not yet bound (None case)
          - Result: ALLOW - binds session to actor and proceeds with operation
          - Session updated with officer_id or client_id
          - Normal audit log

       6. Session reuse with existing auth:
          - Session already bound and authenticated
          - Request uses session auth (no fresh auth needed)
          - No ownership validation needed (already validated on first auth)
          - Session TTL extended
          - Result: ALLOW - proceeds directly to operation
          - Normal audit log

       Implementation details:
       - Validation occurs AFTER successful authentication
       - Validation occurs BEFORE rate limiting (fail fast)
       - Validation occurs BEFORE schema checks
       - Validation occurs BEFORE session binding updates
       - Audit logging captures all violation attempts
       - Error messages are clear but don't leak sensitive info
       - Status code 403 (Forbidden) indicates authorization failure
       - Fail-closed approach: reject if uncertain

       jwks(req, ctx) -> Response
       --------------------------
       Success path:
       - Config loaded
       - Keypair retrieved for default_kid
       - KeyManager created
       - JWKS generated
       - Cache-Control header set (max-age=3600)
       - Response: JwkSet with keys array

       Error paths:
       - Config loading failure (500)
       - Keypair retrieval failure (500)
       - KeyManager construction failure (500)

       Integration test scenarios:
       1. Officer attestation flow: challenge → create_attestation → blind_issuance
       2. Client attestation flow: create_attestation → blind_issuance
       3. Challenge replay prevention
       4. Session expiry handling
       5. Attestation nonce enforcement
       6. Rate limiting enforcement
       7. Timestamp replay protection
       8. Concurrent operations (challenge consumption)
       9. Schema allowlist enforcement
       10. Validity capping for officers and clients
       11. Session auth reuse vs fresh auth
       12. Error propagation and status codes
       13. Audit logging for all critical events
       14. Security header presence
       15. CORS header presence on /v1/ paths
    */

    /* ========================================================================== */
    /*             CHILD DOB GUARD LOGIC TESTS                                   */
    /* ========================================================================== */

    /// Helper: returns true if dob_days would be rejected for client (app-to-app) issuers
    /// (i.e. the person is under 18).
    fn is_child_dob(dob_days: i32) -> bool {
        let now_days = (chrono::Utc::now().timestamp() / 86400) as i32;
        // Pre-1970 DOBs (negative dob_days) always yield age > 18
        let age_days = now_days - dob_days;
        age_days < 6574 // 18 years ≈ 365.25 * 18
    }

    #[test]
    fn test_child_dob_guard_adult() {
        // An adult born ~30 years ago: ~10958 days ago
        let now_days = (chrono::Utc::now().timestamp() / 86400) as i32;
        let adult_dob = now_days - 10958; // ~30 years old
        assert!(!is_child_dob(adult_dob), "Adult DOB should not be rejected");
    }

    #[test]
    fn test_child_dob_guard_child() {
        // A child born ~5 years ago: ~1826 days ago
        let now_days = (chrono::Utc::now().timestamp() / 86400) as i32;
        let child_dob = now_days - 1826; // ~5 years old
        assert!(
            is_child_dob(child_dob),
            "Child DOB should be rejected for client auth"
        );
    }

    #[test]
    fn test_child_dob_guard_exactly_18() {
        // Exactly 18 years = 6574 days
        let now_days = (chrono::Utc::now().timestamp() / 86400) as i32;
        let exactly_18_dob = now_days - 6574;
        assert!(
            !is_child_dob(exactly_18_dob),
            "Exactly 18 should not be rejected"
        );
    }

    #[test]
    fn test_child_dob_guard_just_under_18() {
        // 17 years 364 days = 6573 days
        let now_days = (chrono::Utc::now().timestamp() / 86400) as i32;
        let under_18_dob = now_days - 6573;
        assert!(
            is_child_dob(under_18_dob),
            "Just under 18 should be rejected"
        );
    }

    #[test]
    fn test_child_dob_guard_newborn() {
        let now_days = (chrono::Utc::now().timestamp() / 86400) as i32;
        assert!(is_child_dob(now_days), "Newborn DOB should be rejected");
    }

    /// Mirrors the full guard from create_attestation: returns true if the
    /// request should be REJECTED (child DOB + client auth).
    fn should_reject_child_guard(auth_format: &str, dob_days: i32) -> bool {
        if auth_format == "client" {
            let now_days = (chrono::Utc::now().timestamp() / 86400) as i32;
            // Pre-1970 DOBs (negative dob_days) always yield age > 18
            let age_days = now_days - dob_days;
            age_days < 6574
        } else {
            false
        }
    }

    #[test]
    fn test_child_guard_officer_bypasses_for_child_dob() {
        // Officers (yubikey) must always be allowed to attest any DOB,
        // including minors, because they verify in person.
        let now_days = (chrono::Utc::now().timestamp() / 86400) as i32;
        let child_dob = now_days - 1826; // ~5 years old
        assert!(
            !should_reject_child_guard("yubikey", child_dob),
            "Officer (yubikey) must not be blocked for child DOB"
        );
    }

    #[test]
    fn test_child_guard_officer_bypasses_for_newborn() {
        let now_days = (chrono::Utc::now().timestamp() / 86400) as i32;
        assert!(
            !should_reject_child_guard("yubikey", now_days),
            "Officer (yubikey) must not be blocked for newborn DOB"
        );
    }

    #[test]
    fn test_child_guard_client_blocked_for_child_dob() {
        let now_days = (chrono::Utc::now().timestamp() / 86400) as i32;
        let child_dob = now_days - 1826; // ~5 years old
        assert!(
            should_reject_child_guard("client", child_dob),
            "Client (app-to-app) must be blocked for child DOB"
        );
    }

    #[test]
    fn test_child_guard_client_allowed_for_adult_dob() {
        let now_days = (chrono::Utc::now().timestamp() / 86400) as i32;
        let adult_dob = now_days - 10958; // ~30 years old
        assert!(
            !should_reject_child_guard("client", adult_dob),
            "Client (app-to-app) must not be blocked for adult DOB"
        );
    }

    #[test]
    fn test_child_guard_client_blocked_for_just_under_18() {
        let now_days = (chrono::Utc::now().timestamp() / 86400) as i32;
        let under_18_dob = now_days - 6573; // 17y 364d
        assert!(
            should_reject_child_guard("client", under_18_dob),
            "Client must be blocked for just-under-18 DOB"
        );
    }

    #[test]
    fn test_child_guard_client_allowed_for_exactly_18() {
        let now_days = (chrono::Utc::now().timestamp() / 86400) as i32;
        let exactly_18_dob = now_days - 6574;
        assert!(
            !should_reject_child_guard("client", exactly_18_dob),
            "Client must not be blocked for exactly-18 DOB"
        );
    }

    #[test]
    fn test_child_guard_unknown_format_not_blocked() {
        // Any non-"client" format should not trigger the guard
        let now_days = (chrono::Utc::now().timestamp() / 86400) as i32;
        let child_dob = now_days - 1826;
        assert!(
            !should_reject_child_guard("other", child_dob),
            "Unknown auth format must not trigger child guard"
        );
    }

    /* ========================================================================== */
    /*                    TRIAL VERIFY CANDIDATE SLOTS                      */
    /* ========================================================================== */

    fn fixture_issuer_config(default_kid: &str, previous_kid: Option<&str>) -> IssuerConfig {
        IssuerConfig {
            issuer_id: "did:provii:issuer".to_string(),
            rp_id: "provii.id".to_string(),
            default_kid: default_kid.to_string(),
            previous_kid: previous_kid.map(str::to_string),
            default_policy: PolicyConfig {
                schema: "provii.age/0".to_string(),
                validity_days: 365,
                v: 1,
            },
        }
    }

    #[test]
    fn trial_verify_steady_state_only_default_kid() {
        // No rotation in flight: candidate list is exactly one entry.
        let cfg = fixture_issuer_config("v1", None);
        let slots = trial_verify_candidate_slots(&cfg);
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].0, "default_kid");
        assert_eq!(slots[0].1, "v1");
    }

    #[test]
    fn trial_verify_overlap_default_then_previous() {
        // Mid-rotation: default_kid is tried first so freshly-signed
        // attestations short-circuit on the active key, and previous_kid
        // is only reached when an attestation predates the rotation.
        let cfg = fixture_issuer_config("v2", Some("v1"));
        let slots = trial_verify_candidate_slots(&cfg);
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].0, "default_kid");
        assert_eq!(slots[0].1, "v2");
        assert_eq!(slots[1].0, "previous_kid");
        assert_eq!(slots[1].1, "v1");
    }

    #[test]
    fn trial_verify_post_rotation_drop_only_default_kid() {
        // Once the rotation overlap closes, previous_kid is cleared and
        // attestations signed under the dropped key no longer redeem.
        // This mirrors the integration scenario where v1-signed
        // attestations stop verifying after default_kid="v3" /
        // previous_kid=Some("v2") is set: only v3 + v2 are in scope.
        let cfg = fixture_issuer_config("v3", Some("v2"));
        let slots = trial_verify_candidate_slots(&cfg);
        let kids: Vec<&str> = slots.iter().map(|(_, k)| k.as_str()).collect();
        assert!(kids.contains(&"v3"), "v3 must be in scope as default_kid");
        assert!(kids.contains(&"v2"), "v2 must be in scope as previous_kid");
        assert!(!kids.contains(&"v1"), "v1 must be out of overlap window");
    }

    #[test]
    fn trial_verify_slot_labels_match_config_fields() {
        // The `secret_version_used` log value pulls directly from these
        // labels; renaming a config field without updating the label
        // would silently change the schema readers depend on.
        let cfg = fixture_issuer_config("active", Some("retiring"));
        let slots = trial_verify_candidate_slots(&cfg);
        let labels: Vec<&str> = slots.iter().map(|(l, _)| *l).collect();
        assert_eq!(labels, vec!["default_kid", "previous_kid"]);
    }

    #[test]
    fn trial_verify_candidate_list_capped_at_two() {
        // Constant-time discipline: the loop is bounded so a forged
        // signature pays a fixed verification cost regardless of which
        // slot would have matched. Two is the hard ceiling.
        let cfg = fixture_issuer_config("v2", Some("v1"));
        let slots = trial_verify_candidate_slots(&cfg);
        assert!(slots.len() <= 2);
    }

    /* ========================================================================== */
    /*    is_eligible() pure-predicate unit tests                                 */
    /* ========================================================================== */

    /// Build an `IssuerEd25519Key` fixture parameterised by the four
    /// is_eligible inputs that the predicate inspects. The
    /// verifying-key bytes default to a real Ed25519 generator-derived
    /// public key so the decode arm passes; tests that exercise the
    /// decode-failure branch override `verifying_key` directly.
    fn fixture_record(
        active: bool,
        valid_from: u64,
        valid_until: u64,
        verifying_key: [u8; 32],
    ) -> IssuerEd25519Key {
        IssuerEd25519Key {
            issuer_id: "did:provii:issuer".to_string(),
            kid: "v1".to_string(),
            issuer_name: "Test Issuer".to_string(),
            verifying_key,
            valid_from,
            valid_until,
            active,
            created_at: 0,
        }
    }

    /// Real Ed25519 verifying-key bytes derived from a deterministic
    /// signing seed; used for the happy-path and three of the four
    /// is_eligible test cases. The fourth test (decode-failure) uses
    /// an all-zero array, which `VerifyingKey::from_bytes` rejects as
    /// a low-order point (decode-time check is sufficient: the
    /// predicate exercises the same `from_bytes` path).
    fn known_good_verifying_key() -> [u8; 32] {
        use ed25519_dalek::SigningKey;
        let seed = [7u8; 32];
        SigningKey::from_bytes(&seed).verifying_key().to_bytes()
    }

    #[test]
    fn is_eligible_active_false_returns_inactive() {
        // Test case 1 of 4: explicit retirement
        // of the kid via `active=false` produces the Inactive reject
        // reason regardless of validity window.
        let rec = fixture_record(false, 0, u64::MAX, known_good_verifying_key());
        let now = 1_700_000_000;
        let res = is_eligible(&rec, now);
        assert!(matches!(res, Err(EligibilityReject::Inactive)));
        assert_eq!(
            res.err().map(EligibilityReject::reason),
            Some("key_inactive")
        );
    }

    #[test]
    fn is_eligible_valid_from_after_now_returns_not_yet_valid() {
        // Test case 2 of 4: kid scheduled for future activation; not
        // yet eligible.
        let now: u64 = 1_700_000_000;
        let valid_from = now.saturating_add(60);
        let rec = fixture_record(true, valid_from, u64::MAX, known_good_verifying_key());
        let res = is_eligible(&rec, now);
        assert!(matches!(res, Err(EligibilityReject::NotYetValid)));
        assert_eq!(
            res.err().map(EligibilityReject::reason),
            Some("key_outside_validity")
        );
    }

    #[test]
    fn is_eligible_valid_until_before_now_returns_expired() {
        // Test case 3 of 4: kid past its expiry; ineligible.
        let now: u64 = 1_700_000_000;
        let valid_until = now.saturating_sub(1);
        let rec = fixture_record(true, 0, valid_until, known_good_verifying_key());
        let res = is_eligible(&rec, now);
        assert!(matches!(res, Err(EligibilityReject::Expired)));
        assert_eq!(
            res.err().map(EligibilityReject::reason),
            Some("key_outside_validity")
        );
    }

    #[test]
    fn is_eligible_verifying_key_decode_failure_returns_decode_reject() {
        // Test case 4 of 4: KV record has corrupted verifying-key
        // bytes. The encoding `y = 2` (little-endian byte 0 = 2,
        // remaining bytes zero) is not a valid Ed25519 y-coordinate
        // because `x² = (y² - 1)/(d·y² + 1)` evaluates to a non-QR
        // for that y, so decompression fails. `is_eligible` must
        // surface this as a structured reject rather than panicking
        // the verify path.
        let mut bad_bytes = [0u8; 32];
        bad_bytes[0] = 2;
        // Sanity-check that the chosen encoding is rejected by the
        // underlying decoder; if a future upgrade ever accepted it
        // the test below would silently pass on the Ok arm and the
        // refactor's regression coverage would lapse. We pick a
        // different invalid encoding in that case.
        let mut chosen: [u8; 32] = bad_bytes;
        if ed25519_dalek::VerifyingKey::from_bytes(&chosen).is_ok() {
            // y = 1 (the only valid point with y=1 is the identity,
            // which IS a valid Ed25519 point; skip)
            // Try a few small y values that are very unlikely to lie
            // on the curve; ZIP-215 / Ed25519 decompression rejects
            // most random y. y=4 has the same QR-failing structure.
            for &candidate_y in &[4u8, 5u8, 6u8, 7u8, 8u8] {
                let mut candidate = [0u8; 32];
                candidate[0] = candidate_y;
                if ed25519_dalek::VerifyingKey::from_bytes(&candidate).is_err() {
                    chosen = candidate;
                    break;
                }
            }
        }
        assert!(
            ed25519_dalek::VerifyingKey::from_bytes(&chosen).is_err(),
            "could not find an invalid Ed25519 verifying-key encoding for the fixture"
        );

        let rec = fixture_record(true, 0, u64::MAX, chosen);
        let now = 1_700_000_000;
        let res = is_eligible(&rec, now);
        assert!(matches!(res, Err(EligibilityReject::VerifyingKeyDecode)));
        assert_eq!(
            res.err().map(EligibilityReject::reason),
            Some("verifying_key_decode")
        );
    }

    #[test]
    fn is_eligible_happy_path_returns_decoded_verifying_key() {
        // Sanity check: when all four predicates pass the function
        // returns the decoded verifying key (Ok) so the caller can
        // hand it to `verify_with_timestamp` without re-decoding.
        let rec = fixture_record(true, 0, u64::MAX, known_good_verifying_key());
        let now = 1_700_000_000;
        let res = is_eligible(&rec, now);
        assert!(res.is_ok());
        if let Ok(vk) = res {
            assert_eq!(vk.to_bytes(), known_good_verifying_key());
        }
    }

    /* ========================================================================== */
    /*    Class 6 admin-credential header matrix                                  */
    /*    Mirrors provii-verifier/src/security/status_auth.rs 8-scenario tests       */
    /* ========================================================================== */

    /// 1. Bearer credential resolves verbatim.
    #[test]
    fn admin_bearer_returns_credential() {
        assert_eq!(
            resolve_admin_credential(Some("Bearer admin-token-abc")),
            Some("admin-token-abc".to_string())
        );
    }

    /// 2. Lowercase bearer accepted per RFC 9110 §11.1.
    #[test]
    fn admin_bearer_lowercase_scheme() {
        assert_eq!(
            resolve_admin_credential(Some("bearer admin-token-abc")),
            Some("admin-token-abc".to_string())
        );
    }

    /// 3. Authorization with extra whitespace after scheme is tolerated.
    #[test]
    fn admin_bearer_extra_whitespace() {
        assert_eq!(
            resolve_admin_credential(Some("Bearer   admin-token-abc")),
            Some("admin-token-abc".to_string())
        );
    }

    /// 4. `Authorization: Basic ...` is not a bearer credential.
    #[test]
    fn admin_authorization_basic_scheme_rejected() {
        assert_eq!(resolve_admin_credential(Some("Basic dXNlcjpwYXNz")), None);
    }

    /// 5. Missing Authorization header yields None.
    #[test]
    fn admin_missing_authorization_rejected() {
        assert_eq!(resolve_admin_credential(None), None);
    }

    /// 6. `Authorization: Bearer ` with empty credential yields None.
    #[test]
    fn admin_bearer_empty_credential_rejected() {
        assert_eq!(resolve_admin_credential(Some("Bearer ")), None);
    }

    /* ========================================================================== */
    /*    RotateAttestationKeyRequest body-shape tests                            */
    /* ========================================================================== */

    /// The minimal valid body has only `new_kid`. JSON shape stability
    /// matters because rotation tooling marshals this by hand.
    #[test]
    fn rotate_attestation_request_minimal_body_parses() {
        let body = r#"{"new_kid":"provii:2026-05"}"#;
        let parsed: RotateAttestationKeyRequest =
            serde_json::from_str(body).expect("body should parse"); // nosemgrep: expect-on-external-input
        assert_eq!(parsed.new_kid, "provii:2026-05");
    }

    /// Missing `new_kid` is a hard parse error (not a default-empty
    /// fallback). Without this, a body of `{}` would silently fall
    /// through and trigger the validate_identifier branch with an
    /// empty string. Better to surface the bad input at the JSON
    /// layer.
    #[test]
    fn rotate_attestation_request_missing_kid_rejected() {
        let body = r#"{}"#;
        let result: std::result::Result<RotateAttestationKeyRequest, _> =
            serde_json::from_str(body);
        assert!(result.is_err(), "missing new_kid must fail to deserialise");
    }

    /// Unknown fields are silently ignored on this body. The Ed25519
    /// rotation surface follows the same forward-compat policy as
    /// `BlindIssuanceRequest`: future tooling additions should not
    /// break existing operators on a deploy lag.
    #[test]
    fn rotate_attestation_request_ignores_unknown_fields() {
        let body = r#"{"new_kid":"provii:2026-05","reason":"manual rotate","ttl_days":365}"#;
        let parsed: RotateAttestationKeyRequest =
            serde_json::from_str(body).expect("unknown fields should be ignored"); // nosemgrep: expect-on-external-input
        assert_eq!(parsed.new_kid, "provii:2026-05");
    }
}

/// Admin endpoint to rotate signing keys
/// SECURITY: Requires super_admin role
pub async fn rotate_signing_key(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let env = ctx.env.clone();
    let client_ip = crate::audit::get_client_ip(&req);

    // SECURITY FIX: Enforce admin authentication (CWE-306, OWASP ASVS 4.0 V4)
    // Class 6 internal API key: the canonical admin-credential shape is
    // `Authorization: Bearer <token>`.
    let admin_api_key = match extract_admin_credential(req.headers()) {
        Some(k) => k,
        None => {
            crate::audit::audit_log(
                &env,
                "authentication_failed",
                &client_ip,
                "Missing or empty admin credential on key rotation endpoint",
                &serde_json::json!({"reason": "missing_admin_key", "endpoint": "/admin/keys/rotate"}),
            )
            .await;
            return ApiError::Unauthorized("Authentication failed".into()).to_response();
        }
    };

    // Lockout-protected admin auth (replaces bare verify_admin_api_key)
    let admin_slot =
        match authenticate_admin(&env, &admin_api_key, &client_ip, "/admin/keys/rotate").await? {
            AdminAuthOutcome::Deny(resp) => return Ok(resp),
            AdminAuthOutcome::Allow(slot) => slot,
        };

    // Require and validate nonce to prevent replay attacks.
    // Mandatory nonce consumed via NonceDO (atomic check-and-set).
    let admin_nonce = match req.headers().get("X-Nonce").ok().flatten() {
        Some(n) => n,
        None => {
            crate::audit::audit_log(
                &env,
                "authentication_failed",
                &client_ip,
                "Missing X-Nonce header on key rotation endpoint",
                &serde_json::json!({"reason": "missing_nonce", "endpoint": "/admin/keys/rotate"}),
            )
            .await;
            return ApiError::Unauthorized("Authentication failed".into()).to_response();
        }
    };

    match crate::storage::validate_and_consume_nonce(&env, &admin_nonce).await {
        Ok(true) => {} // Nonce is fresh
        Ok(false) => {
            crate::audit::audit_log(
                &env,
                "replay_attempt",
                &client_ip,
                "Nonce reuse detected on key rotation endpoint",
                &serde_json::json!({"reason": "nonce_reuse", "endpoint": "/admin/keys/rotate"}),
            )
            .await;
            return ApiError::Unauthorized("Authentication failed".into()).to_response();
        }
        Err(e) => {
            crate::log_error!("[Admin] Nonce validation failed for key rotation: {:?}", e,);
            return ApiError::ServiceUnavailable(
                "Authentication infrastructure unavailable".into(),
            )
            .to_response();
        }
    }

    // SECURITY: Rate limiting on admin key rotation (R-2)
    // SECURITY : Fail closed, return 503 when rate limiting infrastructure is unavailable
    let rl_quota = {
        let (rl_kv, cfg_kv) = match resolve_rate_limit_kvs(&env) {
            Ok(pair) => pair,
            Err(resp) => return resp,
        };
        let result =
            crate::rate_limiting::check_quota(&rl_kv, &cfg_kv, "admin", "key_rotate", 10).await;
        if !result.allowed {
            crate::log!(
                "[RateLimit] Exceeded for admin endpoint=key_rotate count={}/{}",
                result.current_count,
                result.limit
            );
            crate::audit::audit_log_with_actor(
                &env,
                "rate_limit_exceeded",
                &client_ip,
                "Rate limit exceeded for key rotation",
                &serde_json::json!({"endpoint": "key_rotate", "count": result.current_count, "limit": result.limit}),
                Some(&client_ip),
                Some(crate::audit::Outcome::Denied),
            ).await;
            return crate::rate_limiting::rate_limit_or_unavailable_response(&result);
        }
        result
    };

    crate::log!("[Admin] Key rotation requested");

    let key_manager = crate::key_rotation::KeyRotationManager::new(&env);

    // Check current key health
    let health = match key_manager.check_key_health().await {
        Ok(h) => h,
        Err(e) => {
            crate::log_error!("Failed to check key health: {:?}", e);
            crate::audit::audit_log(
                &env,
                "internal_error",
                &client_ip,
                "Failed to check signing key health",
                &serde_json::json!({"endpoint": "/admin/keys/rotate", "error": format!("{}", e)}),
            )
            .await;
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    if health.is_critical() {
        console_warn!("CRITICAL key health issues detected before rotation");
    }

    // INV-IA-002: Acquire DO lock to prevent concurrent key rotations.
    // Without this, two overlapping rotation requests could both read the
    // current key version, generate new keys with the same version+1, and
    // the last writer wins, silently dropping the other key.
    let lock_key = "signing_key_rotation";
    let lock_token = match crate::resource_lock::acquire_resource_lock(&env, lock_key).await {
        Ok(token) => token,
        Err(e) => {
            crate::log_error!("Failed to acquire key rotation lock: {:?}", e);
            return ApiError::ServiceUnavailable("Key rotation temporarily unavailable".into())
                .to_response();
        }
    };

    // Perform rotation
    let new_key = match key_manager.rotate_signing_key().await {
        Ok(key) => {
            crate::resource_lock::release_resource_lock(&env, lock_key, &lock_token).await;
            key
        }
        Err(e) => {
            crate::resource_lock::release_resource_lock(&env, lock_key, &lock_token).await;
            crate::log_error!("Key rotation failed: {:?}", e);
            crate::audit::audit_log(
                &env,
                "internal_error",
                &client_ip,
                "Signing key rotation failed",
                &serde_json::json!({"endpoint": "/admin/keys/rotate", "error": format!("{}", e)}),
            )
            .await;
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    crate::log!(
        "[Admin] Key rotation successful: version={}, expires_at={}",
        new_key.version,
        new_key.expires_at
    );

    // Audit the successful key rotation from the admin endpoint.
    // The key_rotation module already logs "signing_key_rotated" for the
    // cryptographic operation itself; this captures the admin-level success.
    crate::audit::audit_log_detailed(
        &env,
        "signing_key_rotated",
        &client_ip,
        "Admin-initiated signing key rotation completed successfully",
        &serde_json::json!({
            "new_version": new_key.version,
            "new_key_id": new_key.key_id,
            "expires_at": new_key.expires_at,
            "days_until_expiration": new_key.days_until_expiration(),
            "endpoint": "/admin/keys/rotate",
        }),
        crate::audit::DetailedAuditFields {
            event_category: provii_audit::EventCategory::KeyAccess,
            actor_id: "admin",
            outcome: Some(crate::audit::Outcome::Success),
            severity: Some(provii_audit::Severity::Critical),
        },
    )
    .await;

    // P3-17: Set JWKS rotation flag so the next JWKS response bypasses cache.
    // The flag has a 60s KV TTL, after which normal caching resumes.
    if let Ok(config_kv) = env.kv(crate::bindings::ISSUER_CONFIG) {
        let now_str = chrono::Utc::now().timestamp().to_string();
        let put_result = config_kv
            .put("jwks:rotated_at", &now_str)
            .map(|builder| builder.expiration_ttl(60));
        match put_result {
            Ok(builder) => {
                if let Err(e) = builder.execute().await {
                    crate::log_error!("[Key Rotation] Failed to set jwks:rotated_at flag: {:?}", e);
                }
            }
            Err(e) => {
                crate::log_error!(
                    "[Key Rotation] Failed to create jwks:rotated_at put: {:?}",
                    e
                );
            }
        }
    }

    let response_data = serde_json::json!({
        "success": true,
        "version": new_key.version,
        "key_id": new_key.key_id,
        "created_at": new_key.created_at,
        "expires_at": new_key.expires_at,
        "days_until_expiration": new_key.days_until_expiration(),
    });

    // OWASP ASVS V14.2.2: Prevent caching of sensitive key metadata
    let mut resp = add_anti_caching_headers(Response::from_json(&response_data)?)?;
    let _ = crate::rate_limiting::apply_rate_limit_headers(&mut resp, &rl_quota);

    // emit secret_version structured log + x-secret-version
    // response header.
    log_admin_secret_version(&env, admin_slot, "/v1/admin/keys/rotate").await;
    let admin_fp = admin_key_fingerprint_for_slot(&env, admin_slot).await;
    resp.headers_mut().set("x-secret-version", &admin_fp)?;
    Ok(resp)
}

/// Admin endpoint to check signing key health.
///
/// SECURITY: Requires super_admin role.
///
/// X-Nonce is intentionally omitted from this endpoint. This is a
/// read-only GET returning operational metadata (key status, expiry
/// timestamps, version numbers). Replay of a captured response returns
/// only stale data and cannot mutate state. The endpoint is already
/// protected by admin auth, rate limiting (60/window), and per-IP
/// account lockout, so adding X-Nonce would increase DX overhead with
/// zero security benefit.
pub async fn check_key_health(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let env = ctx.env.clone();
    let client_ip = crate::audit::get_client_ip(&req);

    // SECURITY FIX: Enforce admin authentication (CWE-306, CWE-200)
    // Class 6 internal API key: canonical shape is
    // `Authorization: Bearer <token>`. Prevents enumeration of key
    // metadata by unauthorised parties.
    let admin_api_key = match extract_admin_credential(req.headers()) {
        Some(k) => k,
        None => {
            crate::audit::audit_log(
                &env,
                "authentication_failed",
                &client_ip,
                "Missing or empty admin credential on key health endpoint",
                &serde_json::json!({"reason": "missing_admin_key", "endpoint": "/admin/keys/health"}),
            )
            .await;
            return ApiError::Unauthorized("Authentication failed".into()).to_response();
        }
    };

    // Lockout-protected admin auth (replaces bare verify_admin_api_key)
    let admin_slot =
        match authenticate_admin(&env, &admin_api_key, &client_ip, "/admin/keys/health").await? {
            AdminAuthOutcome::Deny(resp) => return Ok(resp),
            AdminAuthOutcome::Allow(slot) => slot,
        };

    // SECURITY: Rate limiting on admin key health check (R-2)
    // SECURITY : Fail closed, return 503 when rate limiting infrastructure is unavailable
    let rl_quota = {
        let (rl_kv, cfg_kv) = match resolve_rate_limit_kvs(&env) {
            Ok(pair) => pair,
            Err(resp) => return resp,
        };
        let result =
            crate::rate_limiting::check_quota(&rl_kv, &cfg_kv, "admin", "key_health", 60).await;
        if !result.allowed {
            crate::log!(
                "[RateLimit] Exceeded for admin endpoint=key_health count={}/{}",
                result.current_count,
                result.limit
            );
            crate::audit::audit_log(
                &env,
                "rate_limit_exceeded",
                &client_ip,
                "Rate limit exceeded for key health check",
                &serde_json::json!({"endpoint": "key_health", "count": result.current_count, "limit": result.limit}),
            ).await;
            return crate::rate_limiting::rate_limit_or_unavailable_response(&result);
        }
        result
    };

    crate::log!("[Admin] Key health check requested");
    crate::audit::audit_log(
        &env,
        "admin_key_health_checked",
        &client_ip,
        "Admin key health check requested",
        &serde_json::json!({"endpoint": "/admin/keys/health"}),
    )
    .await;

    let key_manager = crate::key_rotation::KeyRotationManager::new(&env);

    let health = match key_manager.check_key_health().await {
        Ok(h) => h,
        Err(e) => {
            crate::log_error!("Failed to check key health: {:?}", e);
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    let all_keys = match key_manager.get_all_signing_keys().await {
        Ok(keys) => keys,
        Err(e) => {
            crate::log_error!("Failed to get signing keys: {:?}", e);
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    let response_data = serde_json::json!({
        "healthy": health.is_healthy(),
        "critical": health.is_critical(),
        "has_expired_active": health.has_expired_active,
        "has_expiring_soon": health.has_expiring_soon,
        "has_no_keys": health.has_no_keys,
        "has_no_active": health.has_no_active,
        "has_multiple_active": health.has_multiple_active,
        "days_until_expiration": health.days_until_expiration,
        "total_keys": all_keys.len(),
        "keys": all_keys.iter().map(|k| serde_json::json!({
            "version": k.version,
            "key_id": k.key_id,
            "status": format!("{:?}", k.status),
            "created_at": k.created_at,
            "expires_at": k.expires_at,
            "days_until_expiration": k.days_until_expiration(),
            "is_expired": k.is_expired(),
            "is_expiring_soon": k.is_expiring_soon(),
        })).collect::<Vec<_>>(),
    });

    // Add anti-caching headers for sensitive health data (OWASP ASVS V14.2.2)
    let response = Response::from_json(&response_data)?;
    let mut response = add_anti_caching_headers(response)?;
    let _ = crate::rate_limiting::apply_rate_limit_headers(&mut response, &rl_quota);

    // emit secret_version structured log + x-secret-version
    // response header.
    log_admin_secret_version(&env, admin_slot, "/v1/admin/keys/health").await;
    let admin_fp = admin_key_fingerprint_for_slot(&env, admin_slot).await;
    response.headers_mut().set("x-secret-version", &admin_fp)?;

    Ok(response)
}

/// Request body for the Ed25519 attestation key rotation admin endpoint.
///
/// `new_kid` selects which pre-loaded Ed25519 keypair becomes the active
/// attestation signer. Both the verifying record (in
/// `ISSUER_ED25519_KEYS`) and the encrypted signing record (in
/// `ISSUER_ED25519_SIGNING_KEYS`) must already exist for this kid;
/// loading new key material is an out-of-band tooling step.
#[derive(Debug, serde::Deserialize)]
pub struct RotateAttestationKeyRequest {
    /// Target `kid` to promote into `IssuerConfig.default_kid`. Must
    /// pass the same `validate_identifier` rules as request envelopes.
    pub new_kid: String,
}

/// Admin endpoint to rotate Ed25519 attestation signing keys.
///
/// Rotate Ed25519 attestation signing keys. `/v1/admin/keys/rotate` only
/// handles RedJubjub credential-signing keys. Ed25519 attestation keys
/// (used by `/v1/issuance/blind` and `/v1/attestation/create`) are
/// separately keyed in `ISSUER_ED25519_KEYS` / `ISSUER_ED25519_SIGNING_KEYS`
/// and selected via `IssuerConfig.default_kid`. Without this endpoint
/// `default_kid` and `previous_kid` cannot be advanced through the
/// API after operators load a fresh keypair, and trial-verify cannot
/// walk back to the prior kid during the overlap window.
///
/// Operation:
/// 1. Verify caller holds a valid admin credential (Class 6 shape).
/// 2. Consume the `X-Nonce` header against `NonceDO` to block replay.
/// 3. Acquire a DO resource lock so concurrent rotates serialise.
/// 4. Verify `new_kid` actually has both verifying and signing records
///    in the Ed25519 KV namespaces under this `issuer_id`. Refuses to
///    promote a kid that was never loaded.
/// 5. Read the current `IssuerConfig`, push `default_kid` to
///    `previous_kid`, set `default_kid = new_kid`, and write the
///    config back to KV in a single put.
/// 6. Audit-log the rotation with old + new kids.
///
/// Self-rotation (`new_kid == default_kid`) is rejected as a no-op
/// because it would silently clobber `previous_kid` and break the
/// trial-verify overlap window.
///
/// SECURITY: Requires super_admin role. Mirrors the auth, lockout,
/// rate-limit, nonce, and resource-lock surface of `rotate_signing_key`.
pub async fn rotate_attestation_key(
    mut req: Request,
    ctx: RouteContext<()>,
) -> worker::Result<Response> {
    let env = ctx.env.clone();
    let client_ip = crate::audit::get_client_ip(&req);

    // Class 6 admin credential extraction.
    let admin_api_key = match extract_admin_credential(req.headers()) {
        Some(k) => k,
        None => {
            crate::audit::audit_log(
                &env,
                "authentication_failed",
                &client_ip,
                "Missing or empty admin credential on attestation rotation endpoint",
                &serde_json::json!({
                    "reason": "missing_admin_key",
                    "endpoint": "/admin/attestation-keys/rotate",
                }),
            )
            .await;
            return ApiError::Unauthorized("Authentication failed".into()).to_response();
        }
    };

    // Lockout-protected admin auth.
    let admin_slot = match authenticate_admin(
        &env,
        &admin_api_key,
        &client_ip,
        "/admin/attestation-keys/rotate",
    )
    .await?
    {
        AdminAuthOutcome::Deny(resp) => return Ok(resp),
        AdminAuthOutcome::Allow(slot) => slot,
    };

    // Mandatory replay nonce.
    let admin_nonce = match req.headers().get("X-Nonce").ok().flatten() {
        Some(n) => n,
        None => {
            crate::audit::audit_log(
                &env,
                "authentication_failed",
                &client_ip,
                "Missing X-Nonce header on attestation rotation endpoint",
                &serde_json::json!({
                    "reason": "missing_nonce",
                    "endpoint": "/admin/attestation-keys/rotate",
                }),
            )
            .await;
            return ApiError::Unauthorized("Authentication failed".into()).to_response();
        }
    };

    match crate::storage::validate_and_consume_nonce(&env, &admin_nonce).await {
        Ok(true) => {}
        Ok(false) => {
            crate::audit::audit_log(
                &env,
                "replay_attempt",
                &client_ip,
                "Nonce reuse detected on attestation rotation endpoint",
                &serde_json::json!({
                    "reason": "nonce_reuse",
                    "endpoint": "/admin/attestation-keys/rotate",
                }),
            )
            .await;
            return ApiError::Unauthorized("Authentication failed".into()).to_response();
        }
        Err(e) => {
            crate::log_error!(
                "[Admin] Nonce validation failed for attestation rotation: {:?}",
                e,
            );
            return ApiError::ServiceUnavailable(
                "Authentication infrastructure unavailable".into(),
            )
            .to_response();
        }
    }

    // Rate limit using the same conservative budget as RedJubjub rotation
    // (10/hour). Attestation key rotation is exceptionally rare in practice;
    // a higher budget would only widen brute-force surface against the lock.
    let rl_quota = {
        let (rl_kv, cfg_kv) = match resolve_rate_limit_kvs(&env) {
            Ok(pair) => pair,
            Err(resp) => return resp,
        };
        let result = crate::rate_limiting::check_quota(
            &rl_kv,
            &cfg_kv,
            "admin",
            "attestation_key_rotate",
            10,
        )
        .await;
        if !result.allowed {
            crate::log!(
                "[RateLimit] Exceeded for admin endpoint=attestation_key_rotate count={}/{}",
                result.current_count,
                result.limit
            );
            crate::audit::audit_log(
                &env,
                "rate_limit_exceeded",
                &client_ip,
                "Rate limit exceeded for attestation key rotation",
                &serde_json::json!({
                    "endpoint": "attestation_key_rotate",
                    "count": result.current_count,
                    "limit": result.limit,
                }),
            )
            .await;
            return crate::rate_limiting::rate_limit_or_unavailable_response(&result);
        }
        result
    };

    // Parse + validate the body before grabbing the lock. Body parse
    // failures should not block another operator from progressing.
    let body: RotateAttestationKeyRequest = match req.json().await {
        Ok(b) => b,
        Err(e) => {
            crate::log_error!("Failed to parse attestation rotation request: {:?}", e);
            return ApiError::BadRequest("Invalid request format".into()).to_response();
        }
    };

    // Reuse storage::validate_identifier (also invoked inside
    // get_issuer_ed25519_key). Pre-validate here so a malformed kid
    // never makes it past the lock acquisition.
    if let Err(e) = storage::validate_identifier(&body.new_kid, "new_kid") {
        crate::log_error!(
            "Attestation rotation rejected: new_kid validation failed: {:?}",
            e,
        );
        return ApiError::BadRequest("Invalid new_kid format".into()).to_response();
    }

    // INV-IA-002 mirror: serialise concurrent rotations so two operators
    // cannot both read the current default_kid and clobber each other's
    // previous_kid. A separate lock key from the RedJubjub rotate path
    // because the two are independent surfaces.
    let lock_key = "attestation_key_rotation";
    let lock_token = match crate::resource_lock::acquire_resource_lock(&env, lock_key).await {
        Ok(token) => token,
        Err(e) => {
            crate::log_error!("Failed to acquire attestation rotation lock: {:?}", e);
            return ApiError::ServiceUnavailable(
                "Attestation key rotation temporarily unavailable".into(),
            )
            .to_response();
        }
    };

    // From here on, every early return must release the lock.
    let outcome = rotate_attestation_key_inner(&env, &client_ip, &body.new_kid).await;
    crate::resource_lock::release_resource_lock(&env, lock_key, &lock_token).await;

    let (old_kid, new_kid) = match outcome {
        AttestationRotateOutcome::Ok { old_kid, new_kid } => (old_kid, new_kid),
        AttestationRotateOutcome::Err(api_err) => return api_err.to_response(),
    };

    crate::audit::audit_log_detailed(
        &env,
        "attestation_signing_key_rotated",
        &client_ip,
        "Admin-initiated Ed25519 attestation key rotation completed successfully",
        &serde_json::json!({
            "old_kid": old_kid,
            "new_kid": new_kid,
            "endpoint": "/admin/attestation-keys/rotate",
        }),
        crate::audit::DetailedAuditFields {
            event_category: provii_audit::EventCategory::KeyAccess,
            actor_id: "admin",
            outcome: Some(crate::audit::Outcome::Success),
            severity: Some(provii_audit::Severity::Critical),
        },
    )
    .await;

    let response_data = serde_json::json!({
        "success": true,
        "old_default_kid": old_kid,
        "new_default_kid": new_kid,
        "previous_kid": old_kid,
    });

    let mut resp = add_anti_caching_headers(Response::from_json(&response_data)?)?;
    let _ = crate::rate_limiting::apply_rate_limit_headers(&mut resp, &rl_quota);

    log_admin_secret_version(&env, admin_slot, "/v1/admin/attestation-keys/rotate").await;
    let admin_fp = admin_key_fingerprint_for_slot(&env, admin_slot).await;
    resp.headers_mut().set("x-secret-version", &admin_fp)?;
    Ok(resp)
}

/// Outcome of [`rotate_attestation_key_inner`]. Either the rotation
/// succeeded with the `(old_kid, new_kid)` pair, or it failed with a
/// preformed [`ApiError`] the outer function will materialise into a
/// response after releasing the resource lock.
enum AttestationRotateOutcome {
    Ok { old_kid: String, new_kid: String },
    Err(ApiError),
}

/// Inner half of [`rotate_attestation_key`] that runs while the resource
/// lock is held. Returns the outcome enum so the outer function can
/// release the lock unconditionally before turning a failure into a
/// `worker::Result<Response>`.
async fn rotate_attestation_key_inner(
    env: &Env,
    client_ip: &str,
    new_kid: &str,
) -> AttestationRotateOutcome {
    // Re-read config under the lock so we serialise on the latest state.
    let mut config = match storage::get_issuer_config(env).await {
        Ok(c) => c,
        Err(e) => {
            crate::log_error!(
                "[Admin] Failed to load IssuerConfig for attestation rotation: {:?}",
                e,
            );
            return AttestationRotateOutcome::Err(ApiError::Internal(
                "Internal server error".into(),
            ));
        }
    };

    // Reject self-rotation: would silently overwrite previous_kid with
    // the current default_kid and collapse the trial-verify overlap.
    if config.default_kid == new_kid {
        crate::audit::audit_log(
            env,
            "attestation_rotation_rejected",
            client_ip,
            "Attestation rotation rejected: new_kid equals current default_kid",
            &serde_json::json!({
                "reason": "self_rotation",
                "default_kid": config.default_kid,
            }),
        )
        .await;
        return AttestationRotateOutcome::Err(ApiError::BadRequest(
            "new_kid is already the active default_kid".into(),
        ));
    }

    // Both verifying and signing records must already exist for the
    // target kid; the admin endpoint promotes pre-loaded material, it
    // does not generate new key bytes.
    match storage::get_issuer_ed25519_key(env, &config.issuer_id, new_kid).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            crate::audit::audit_log(
                env,
                "attestation_rotation_rejected",
                client_ip,
                "Attestation rotation rejected: verifying key not loaded for new_kid",
                &serde_json::json!({
                    "reason": "verifying_key_missing",
                    "new_kid": new_kid,
                }),
            )
            .await;
            return AttestationRotateOutcome::Err(ApiError::BadRequest(
                "new_kid has no verifying key loaded; load key material first".into(),
            ));
        }
        Err(e) => {
            crate::log_error!("[Admin] Verifying key lookup failed: {:?}", e);
            return AttestationRotateOutcome::Err(ApiError::Internal(
                "Internal server error".into(),
            ));
        }
    };
    match storage::get_issuer_ed25519_signing_key(env, &config.issuer_id, new_kid).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            crate::audit::audit_log(
                env,
                "attestation_rotation_rejected",
                client_ip,
                "Attestation rotation rejected: signing key not loaded for new_kid",
                &serde_json::json!({
                    "reason": "signing_key_missing",
                    "new_kid": new_kid,
                }),
            )
            .await;
            return AttestationRotateOutcome::Err(ApiError::BadRequest(
                "new_kid has no signing key loaded; load key material first".into(),
            ));
        }
        Err(e) => {
            crate::log_error!("[Admin] Signing key lookup failed: {:?}", e);
            return AttestationRotateOutcome::Err(ApiError::Internal(
                "Internal server error".into(),
            ));
        }
    };

    // Transactional swap. The single KV put writes both fields atomically;
    // the resource lock above is what serialises overlapping operators.
    let old_kid = config.default_kid.clone();
    config.previous_kid = Some(old_kid.clone());
    config.default_kid = new_kid.to_string();

    if let Err(e) = storage::put_issuer_config(env, &config).await {
        crate::log_error!("[Admin] Failed to persist IssuerConfig swap: {:?}", e);
        crate::audit::audit_log(
            env,
            "attestation_rotation_failed",
            client_ip,
            "Attestation rotation failed during config write",
            &serde_json::json!({"error": format!("{}", e)}),
        )
        .await;
        return AttestationRotateOutcome::Err(ApiError::Internal("Internal server error".into()));
    }

    AttestationRotateOutcome::Ok {
        old_kid,
        new_kid: new_kid.to_string(),
    }
}

// ============================================================================
// Blind Attestation Issuance (ASVS 5.0 / MASVS 2.0 Compliant)
// ============================================================================

/// Process a blind issuance request using a Provii-signed attestation.
///
/// # Protocol Flow
/// 1. Issuer authenticates (HMAC-SHA256 or Yubikey) and calls POST /v1/attestation/create
/// 2. Provii signs the attestation with its own Ed25519 key
/// 3. Issuer passes attestation to wallet via deep link
/// 4. User generates random r_bits locally (blinding factor)
/// 5. Wallet sends attestation + r_bits to Provii (this endpoint)
/// 6. Provii verifies attestation, computes commitment, signs credential with RedJubjub
///
/// # Security Properties
/// - Only attestations signed by this Provii instance are accepted (issuer_id must match config)
/// - Third-party Ed25519 keys are not supported; all attestation signing is internal
/// - Issuer cannot see commitment C or r_bits (privacy)
/// - User cannot lie about dob_days (Provii uses attested value)
/// - Replay protection via nonce tracking with TTL
/// - Timestamp freshness validation (max 1 hour attestation age)
///
/// # ASVS 5.0 Compliance
/// - V1.5.1: Cryptographic nonces for replay prevention
/// - V2.8.7: Constant-time comparisons for secrets
/// - V6.2.1: Ed25519 signature verification
/// - V8.1.1: Sensitive data not logged
pub async fn blind_issuance(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    use ed25519_dalek::VerifyingKey;
    use provii_crypto_commit::pedersen_commit_dob_validated;
    use provii_crypto_commons::attestation::DobAttestation;
    use zeroize::{Zeroize, Zeroizing};

    let handler_start = js_sys::Date::now();
    let mut phase_timings: Vec<(&str, f64)> = Vec::with_capacity(10);

    let env = ctx.env.clone();
    let client_ip = crate::audit::get_client_ip(&req);

    // Phase 1: IP rate limit
    let phase_start = js_sys::Date::now();

    // SECURITY: IP-based rate limit BEFORE parsing the body. This is the first
    // line of defence against DoS: reject high-volume senders before we spend
    // CPU on JSON parsing, base64 decoding, or crypto verification. The
    // per-issuer rate limit (below) still applies after we know the issuer_id.
    {
        let rl_kv = match env.kv("ISSUER_RATE_LIMITS") {
            Ok(kv) => kv,
            Err(e) => {
                crate::log_error!("[RateLimit] ISSUER_RATE_LIMITS KV unavailable: {:?}", e);
                return ApiError::ServiceUnavailable(
                    "Rate limiting infrastructure unavailable".into(),
                )
                .to_response();
            }
        };
        // Hash the IP before using it in the KV key so plaintext
        // addresses are never stored as KV key names.
        let hashed_ip = crate::audit::build_privacy_context(&env)
            .await
            .hash_ip(&client_ip)
            .unwrap_or_default();
        let ip_key = format!("blind_ip:{}", hashed_ip);
        let ip_limit: u32 = env
            .var("BLIND_IP_LIMIT_PER_HOUR")
            .ok()
            .and_then(|v| v.to_string().parse().ok())
            .unwrap_or(60);
        let result = crate::rate_limiting::check_blind_issuance(&rl_kv, &ip_key, ip_limit).await;
        if !result.allowed {
            crate::log!(
                "[RateLimit] IP rate limit exceeded for blind_issuance ip_hash={}",
                hashed_ip
            );
            return crate::rate_limiting::rate_limit_or_unavailable_response(&result);
        }
    }

    phase_timings.push(("rate_limit", js_sys::Date::now() - phase_start));

    // Phase 2: Body parse (JSON parse + base64 decode attestation)
    let phase_start = js_sys::Date::now();

    // Parse request body
    let data: BlindIssuanceRequest = match req.json().await {
        Ok(d) => d,
        Err(e) => {
            crate::log_error!("Failed to parse blind issuance request: {:?}", e);
            crate::audit::audit_log(
                &env,
                "blind_issuance_rejected",
                &client_ip,
                "Failed to parse blind issuance request body",
                &serde_json::json!({"reason": "json_parse_failure", "endpoint": "/v1/issuance/blind", "error": format!("{}", e)}),
            )
            .await;
            return ApiError::BadRequest("Invalid request format".into()).to_response();
        }
    };

    // Validate request schema
    if let Err(e) = data.validate() {
        crate::log_error!("Blind issuance request validation failed: {:?}", e);
        crate::audit::audit_log(
            &env,
            "blind_issuance_rejected",
            &client_ip,
            "Blind issuance request schema validation failed",
            &serde_json::json!({"reason": "schema_validation_failure", "endpoint": "/v1/issuance/blind", "error": format!("{}", e)}),
        )
        .await;
        return ApiError::BadRequest("Invalid request".into()).to_response();
    }

    // Decode attestation from base64
    let mut attestation_bytes = match URL_SAFE_NO_PAD.decode(&data.attestation) {
        Ok(bytes) => bytes,
        Err(e) => {
            crate::log_error!("Failed to decode attestation base64: {:?}", e);
            crate::audit::audit_log(
                &env,
                "blind_issuance_rejected",
                &client_ip,
                "Failed to decode attestation base64",
                &serde_json::json!({"reason": "attestation_base64_decode_failure", "endpoint": "/v1/issuance/blind", "error": format!("{}", e)}),
            )
            .await;
            return ApiError::BadRequest("Invalid attestation encoding".into()).to_response();
        }
    };

    // Deserialize attestation
    // `mut` so we can zeroize `dob_days` after commitment computation.
    let mut attestation: DobAttestation = match serde_json::from_slice(&attestation_bytes) {
        Ok(a) => a,
        Err(e) => {
            crate::log_error!("Failed to deserialize attestation: {:?}", e);
            crate::audit::audit_log(
                &env,
                "blind_issuance_rejected",
                &client_ip,
                "Failed to deserialize attestation",
                &serde_json::json!({"reason": "attestation_deserialization_failure", "endpoint": "/v1/issuance/blind", "error": format!("{}", e)}),
            )
            .await;
            return ApiError::BadRequest("Invalid attestation format".into()).to_response();
        }
    };

    // Zeroize intermediate buffer that contained serialized DOB.
    attestation_bytes.zeroize();

    phase_timings.push(("body_parse", js_sys::Date::now() - phase_start));

    // Phase 3: Issuer config (KV read)
    let phase_start = js_sys::Date::now();

    // Verify attestation was issued by this Provii instance.
    // Only attestations created via POST /v1/attestation/create (which requires
    // HMAC-SHA256 or Yubikey auth) are accepted. Third-party Ed25519 keys are
    // not supported, Provii signs all attestations internally.
    let config = match storage::get_issuer_config(&env).await {
        Ok(c) => c,
        Err(e) => {
            crate::log_error!("Failed to get issuer config: {:?}", e);
            crate::audit::audit_log(
                &env,
                "internal_error",
                &client_ip,
                "Failed to fetch issuer config from storage",
                &serde_json::json!({"endpoint": "/v1/issuance/blind", "error": format!("{}", e)}),
            )
            .await;
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    if attestation.issuer_id != config.issuer_id {
        crate::log_error!(
            "Attestation issuer_id mismatch: expected={}",
            config.issuer_id,
        );
        let _ = crate::audit::audit_log(
            &env,
            "blind_issuance_issuer_mismatch",
            &client_ip,
            "Attestation issuer ID does not match this instance",
            &serde_json::json!({
                "expected_issuer": config.issuer_id,
                "severity": "HIGH",
            }),
        )
        .await;
        return ApiError::Forbidden("Unknown or unregistered issuer".into()).to_response();
    }

    phase_timings.push(("issuer_config", js_sys::Date::now() - phase_start));

    // Phase 4: Per-issuer rate limit (KV check)
    let phase_start = js_sys::Date::now();

    // Rate limit by issuer_id to prevent abuse (per-issuer hourly KV counter)
    // SECURITY : Fail closed, return 503 when rate limiting infrastructure is unavailable
    let rl_quota = {
        let rl_kv = match env.kv("ISSUER_RATE_LIMITS") {
            Ok(kv) => kv,
            Err(e) => {
                crate::log_error!("[RateLimit] ISSUER_RATE_LIMITS KV unavailable: {:?}", e);
                return ApiError::ServiceUnavailable(
                    "Rate limiting infrastructure unavailable".into(),
                )
                .to_response();
            }
        };
        // SECURITY: Hash the issuer_id before using it as a rate-limit key
        // component to prevent attacker-controlled identifiers from colliding
        // with or evicting other issuers' rate-limit entries.
        let hashed_issuer_id = {
            use sha2::{Digest as _, Sha256};
            let digest = Sha256::digest(attestation.issuer_id.as_bytes());
            hex::encode(digest.get(..16).unwrap_or(&digest)) // 128-bit truncation, collision-resistant for rate limiting
        };
        // R13: because all blind traffic funnels through this single per-issuer
        // key, it hits Cloudflare KV's ~1-write/sec/key cap and undercounts
        // above ~3600/hr. Use the SHARDED counter (K sub-keys, summed on read)
        // so the per-key write rate drops to ~1/K while the aggregate ceiling is
        // unchanged. This is the ONLY caller of check_blind_issuance_sharded;
        // the per-IP DoS caps deliberately keep the unsharded
        // check_blind_issuance (their keys are already unique per IP).
        let result = crate::rate_limiting::check_blind_issuance_sharded(
            &rl_kv,
            &hashed_issuer_id,
            get_blind_issuance_limit(&env),
        )
        .await;
        if !result.allowed {
            crate::log!(
                "[RateLimit] Exceeded for issuer={} endpoint=blind_issuance count={}/{}",
                attestation.issuer_id,
                result.current_count,
                result.limit
            );
            // R8: offload the best-effort reject audit to wait_until so the
            // 429/503 returns before the AUDIT_QUEUE send. Inline fallback is
            // MANDATORY (take_worker_context is single-shot). audit_log swallows
            // errors so this can never become a 5xx.
            //
            // M4: a wait_until future can be silently dropped if Cloudflare
            // evicts the isolate before the background task runs (slow-isolate
            // loss), losing the audit event with no trace. Bracket the
            // scheduling with synchronous console logs carrying a correlation id
            // so a "scheduled" line with no matching "handed_off" line (or no
            // downstream queue delivery for that id) is detectable in logs.
            {
                let audit_env = env.clone();
                let audit_ip = client_ip.clone();
                let audit_issuer_id = attestation.issuer_id.clone();
                let audit_count = result.current_count;
                let audit_limit = result.limit;
                let audit_corr_id = uuid::Uuid::new_v4().to_string();
                let emit_corr_id = audit_corr_id.clone();
                let emit = move |env: Env, ip: String, issuer_id: String| async move {
                    crate::audit::audit_log(
                        &env,
                        "rate_limit_exceeded",
                        &ip,
                        "Rate limit exceeded for blind issuance",
                        &serde_json::json!({"endpoint": "blind_issuance", "issuer_id": issuer_id, "count": audit_count, "limit": audit_limit, "audit_corr_id": emit_corr_id}),
                    )
                    .await;
                };
                if let Some(ctx) = crate::take_worker_context() {
                    // Synchronous placeholder BEFORE handing the emit to the
                    // background runtime. Emitted inline so it survives isolate
                    // eviction even if the wait_until future never executes.
                    crate::log!(
                        "{{\"event\":\"audit_wait_until_scheduled\",\"audit_event\":\"rate_limit_exceeded\",\"endpoint\":\"blind_issuance\",\"audit_corr_id\":\"{}\"}}",
                        audit_corr_id
                    );
                    ctx.wait_until(emit(audit_env, audit_ip, audit_issuer_id));
                    // Confirm the scheduling call returned. A scheduled line with
                    // no handed_off line means scheduling itself faulted.
                    crate::log!(
                        "{{\"event\":\"audit_wait_until_handed_off\",\"audit_event\":\"rate_limit_exceeded\",\"endpoint\":\"blind_issuance\",\"audit_corr_id\":\"{}\"}}",
                        audit_corr_id
                    );
                } else {
                    // No worker context: emit inline (awaited), so there is no
                    // loss window. No placeholder needed on this path.
                    emit(audit_env, audit_ip, audit_issuer_id).await;
                }
            }
            return crate::rate_limiting::rate_limit_or_unavailable_response(&result);
        }
        result
    };

    phase_timings.push(("issuer_rate_limit", js_sys::Date::now() - phase_start));

    // H6: signing-KEK preflight. The signing key is decrypted with ISSUER_KEK
    // at the keypair-load phase below; if the KEK is missing/unreadable, that
    // load fails and issuance returns a generic 503 only AFTER the expensive
    // Ed25519 verify, nonce consume, commitment computation, and RedJubjub
    // signing have already run. Probe the KEK here (cached per-isolate; free on
    // a warm isolate) so the failure is returned EARLY with a descriptive 503
    // and a CRITICAL alert, before any of that wasted CPU. This never changes
    // the success path: a healthy KEK passes straight through.
    {
        let phase_start = js_sys::Date::now();
        let kek_ok = crate::kek::preflight_kek(&env).await;
        phase_timings.push(("kek_preflight", js_sys::Date::now() - phase_start));
        if !kek_ok {
            crate::log_error!(
                "CRITICAL: ISSUER_KEK preflight failed; rejecting blind issuance with 503"
            );
            // Audit the early reject. The kek_unavailable event (with the
            // specific reason) is emitted inside the KEK fetch path; this records
            // that issuance was refused as a consequence.
            crate::audit::audit_log(
                &env,
                "blind_issuance_rejected",
                &client_ip,
                "Signing key unavailable: ISSUER_KEK preflight failed",
                &serde_json::json!({
                    "reason": "kek_preflight_failed",
                    "endpoint": "/v1/issuance/blind",
                    "severity": "CRITICAL",
                }),
            )
            .await;
            return ApiError::ServiceUnavailable("Signing key unavailable".into()).to_response();
        }
    }

    // Phase 5: Ed25519 verifying key lookup (KV read)
    let phase_start = js_sys::Date::now();

    // Trial verify: the issuer signs attestations with its current
    // `default_kid` and verifies redemptions against the same key. During a
    // rotation overlap window an attestation signed under the prior key is
    // still in the wallet's possession, so the verify path tries
    // `default_kid` first and falls back to `previous_kid` when present.
    // The wallet is a passive carrier and never advertises which key
    // signed the attestation; the issuer alone owns the kid lifecycle.
    //
    // Each candidate is eligible only if the underlying record exists,
    // is active, and falls within its validity window. Candidates are
    // collected before nonce consume so the cheap-DoS-shield ordering
    // (consume nonce before any signature verification) is preserved.
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);

    let mut candidates: Vec<(&'static str, String, VerifyingKey, String)> = Vec::with_capacity(2);
    let mut last_eligibility_failure: Option<(&'static str, String)> = None;

    let candidate_slots = trial_verify_candidate_slots(&config);

    for (slot_label, kid) in &candidate_slots {
        let record = match storage::get_issuer_ed25519_key(&env, &attestation.issuer_id, kid).await
        {
            Ok(Some(rec)) => rec,
            Ok(None) => {
                last_eligibility_failure = Some((*slot_label, "key_record_missing".to_string()));
                continue;
            }
            Err(e) => {
                crate::log_error!("Failed to lookup issuer key ({}): {:?}", slot_label, e);
                crate::audit::audit_log(
                    &env,
                    "internal_error",
                    &client_ip,
                    "Failed to fetch issuer Ed25519 key from storage",
                    &serde_json::json!({"endpoint": "/v1/issuance/blind", "slot": *slot_label, "error": format!("{}", e)}),
                )
                .await;
                return ApiError::Internal("Internal server error".into()).to_response();
            }
        };

        // Eligibility check is a pure predicate (`is_eligible`) so it
        // can be unit-tested without a Worker `Env`.
        match is_eligible(&record, now) {
            Ok(vk) => {
                candidates.push((*slot_label, kid.clone(), vk, record.issuer_name.clone()));
            }
            Err(reject) => {
                if reject == EligibilityReject::VerifyingKeyDecode {
                    crate::log_error!("Invalid issuer verifying key for slot {}", slot_label);
                }
                last_eligibility_failure = Some((*slot_label, reject.reason().to_string()));
                continue;
            }
        }
    }

    if candidates.is_empty() {
        let (failed_slot, reason) =
            last_eligibility_failure.unwrap_or(("default_kid", "no_eligible_kid".to_string()));
        crate::log_error!(
            "No eligible issuer verifying key for issuer={} reason={} slot={}",
            attestation.issuer_id,
            reason,
            failed_slot
        );
        let _ = crate::audit::audit_log(
            &env,
            "blind_issuance_unknown_issuer",
            &client_ip,
            "No eligible issuer Ed25519 verifying key",
            &serde_json::json!({
                "issuer_id": attestation.issuer_id,
                "reason": reason,
                "slot": failed_slot,
                "severity": "MEDIUM",
            }),
        )
        .await;
        return ApiError::Forbidden("Unknown or unregistered issuer".into()).to_response();
    }

    phase_timings.push(("ed25519_key", js_sys::Date::now() - phase_start));

    // Consume nonce BEFORE Ed25519 verification. Nonce check is a
    // cheap DO lookup; Ed25519 verify is expensive CPU work. Checking the nonce
    // first prevents DoS amplification via replayed attestations that force
    // repeated Ed25519 computation.

    // Phase 6: Nonce consume (async DO call for replay prevention)
    let phase_start = js_sys::Date::now();

    // M3: per-issuer nonce-consumption tripwire (advisory, FAIL-OPEN).
    //
    // Nonce consumption runs for every attestation including replays and
    // attestations that later fail verify/issuance, so an abnormal nonce-burn
    // (mass replay / a misbehaving client) is a signal the authoritative
    // issuance cap does not see directly. This counter surfaces that signal at
    // a multiple of the issuance cap. It NEVER rejects: it is fail-open and
    // observe-and-alert only, because the request has already passed the
    // authoritative per-issuer issuance cap upstream and the nonce-replay DO
    // check below is the real boundary. Emitting a distinct audit event when
    // over the tripwire keeps it discoverable without harming legitimate
    // traffic during a KV brownout. Best-effort: a KV-binding error skips the
    // tripwire entirely (never blocks issuance).
    if let Ok(nonce_rl_kv) = env.kv("ISSUER_RATE_LIMITS") {
        let hashed_issuer_id = {
            use sha2::{Digest as _, Sha256};
            let digest = Sha256::digest(attestation.issuer_id.as_bytes());
            // 128-bit truncation, collision-resistant for rate limiting; keyed
            // identically to the issuance counter so a future second issuer
            // cannot collide.
            hex::encode(digest.get(..16).unwrap_or(&digest))
        };
        let nonce_limit = get_attestation_nonce_limit(&env);
        let nonce_rl = crate::rate_limiting::check_attestation_nonce_rate(
            &nonce_rl_kv,
            &hashed_issuer_id,
            nonce_limit,
        )
        .await;
        if nonce_rl.over_limit {
            crate::log!(
                "[RateLimit] nonce-consume tripwire EXCEEDED for issuer={} count={}/{} (advisory, not rejected)",
                attestation.issuer_id,
                nonce_rl.current_count,
                nonce_rl.limit
            );
            // Distinct audit event so this is filterable separately from the
            // hard issuance-cap rejections. Best-effort; never blocks issuance.
            crate::audit::audit_log(
                &env,
                "attestation_nonce_rate_exceeded",
                &client_ip,
                "Per-issuer attestation nonce-consumption tripwire exceeded (advisory)",
                &serde_json::json!({
                    "endpoint": "/v1/issuance/blind",
                    "scope": "issuer",
                    "issuer_id": attestation.issuer_id,
                    "count": nonce_rl.current_count,
                    "limit": nonce_rl.limit,
                    "enforced": false,
                    "severity": "MEDIUM",
                }),
            )
            .await;
        }
    }

    let nonce_hex = attestation.nonce_hex();
    match storage::validate_and_consume_attestation_nonce(&env, &nonce_hex).await {
        Ok(true) => {
            // Nonce is fresh, continue
        }
        Ok(false) => {
            // Replay attack detected - already logged in storage function
            crate::log_error!("Replay attack detected for attestation nonce");
            return ApiError::InvalidStateTransition("Attestation has already been used".into())
                .to_response();
        }
        Err(e) => {
            crate::log_error!("Failed to validate attestation nonce: {:?}", e);
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    }

    phase_timings.push(("nonce_consume", js_sys::Date::now() - phase_start));

    // Phase 7: Attestation verification (Ed25519 verify, sync CPU)
    let phase_start = js_sys::Date::now();

    // Trial verify: walk the candidate list (default_kid then optional
    // previous_kid) and accept on the first slot whose Ed25519 verify
    // succeeds. Each `verify_with_timestamp` call is constant-time on its
    // own; the loop only branches on the public Result discriminant, not
    // on intermediate signature state. The number of iterations is bounded
    // by the candidate slot list length (at most two), so an attacker who
    // submits a forged signature pays the same fixed cost regardless of
    // which slot would have matched.
    let mut verify_slot: Option<&'static str> = None;
    let mut verify_kid: Option<String> = None;
    let mut verify_issuer_name: Option<String> = None;
    let mut verify_vk_bytes: Option<[u8; 32]> = None;
    let mut last_verify_error: Option<String> = None;
    for (slot_label, kid, vk, issuer_name) in &candidates {
        match attestation.verify_with_timestamp(vk, now) {
            Ok(()) => {
                verify_slot = Some(*slot_label);
                verify_kid = Some(kid.clone());
                verify_issuer_name = Some(issuer_name.clone());
                verify_vk_bytes = Some(vk.to_bytes());
                break;
            }
            Err(e) => {
                last_verify_error = Some(format!("{:?}", e));
            }
        }
    }

    let Some(matched_slot) = verify_slot else {
        let err_detail = last_verify_error.unwrap_or_else(|| "no_candidates".to_string());
        crate::log_error!(
            "Attestation verification failed across all candidates: {}",
            err_detail
        );
        let _ = crate::audit::audit_log(
            &env,
            "blind_issuance_verification_failed",
            &client_ip,
            "Attestation signature verification failed",
            &serde_json::json!({
                "issuer_id": attestation.issuer_id,
                "error": err_detail,
                "candidate_slots": candidate_slots.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
                "severity": "HIGH",
            }),
        )
        .await;
        return ApiError::Forbidden("Attestation verification failed".into()).to_response();
    };

    let matched_kid = verify_kid.unwrap_or_default();
    let matched_issuer_name = verify_issuer_name.unwrap_or_default();

    phase_timings.push(("attestation_verify", js_sys::Date::now() - phase_start));

    // Phase 8: Commitment (Pedersen commitment computation, sync CPU)
    let phase_start = js_sys::Date::now();

    // Wrap r_bytes in Zeroizing so the blinding factor is cleared on drop.
    let r_bytes: Zeroizing<Vec<u8>> = match URL_SAFE_NO_PAD.decode(&data.r_bits) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) => {
            crate::log_error!("Failed to decode r_bits base64: {:?}", e);
            crate::audit::audit_log(
                &env,
                "blind_issuance_rejected",
                &client_ip,
                "Failed to decode r_bits base64",
                &serde_json::json!({"reason": "r_bits_base64_decode_failure", "endpoint": "/v1/issuance/blind", "error": format!("{}", e)}),
            )
            .await;
            return ApiError::BadRequest("Invalid r_bits encoding".into()).to_response();
        }
    };

    // Validate r_bits length (16-32 bytes = 128-256 bits)
    if r_bytes.len() < crate::types::MIN_R_BITS_BYTES
        || r_bytes.len() > crate::types::MAX_R_BITS_BYTES
    {
        crate::log_error!(
            "Invalid r_bits length: {} bytes (expected {}-{})",
            r_bytes.len(),
            crate::types::MIN_R_BITS_BYTES,
            crate::types::MAX_R_BITS_BYTES
        );
        crate::audit::audit_log(
            &env,
            "blind_issuance_rejected",
            &client_ip,
            "Invalid r_bits length",
            &serde_json::json!({
                "reason": "r_bits_length_invalid",
                "endpoint": "/v1/issuance/blind",
                "actual_bytes": r_bytes.len(),
                "min_bytes": crate::types::MIN_R_BITS_BYTES,
                "max_bytes": crate::types::MAX_R_BITS_BYTES,
            }),
        )
        .await;
        return ApiError::BadRequest("Invalid r_bits length".into()).to_response();
    }

    // Convert r_bytes to r_bits (boolean vector)
    // IMPORTANT: SDK packs bits MSB-first (bit 0 → bit 7 of byte), so we unpack the same way
    //
    // Wrap in Zeroizing so that early-return error paths (commitment
    // failure, format validation, bytes validation) automatically zeroize the
    // blinding factor bits on drop.
    let r_bits: Zeroizing<Vec<bool>> = Zeroizing::new(
        r_bytes
            .iter()
            .flat_map(|byte| (0..8u32).map(move |i| ((byte >> (7u32.saturating_sub(i))) & 1) == 1))
            .collect(),
    );

    // Compute Pedersen commitment using attested dob_days.
    // This is the key security property: Provii computes C using the attested value,
    // preventing the user from lying about their DOB.
    //
    // Use the validated variant which rejects low-entropy r_bits
    // (all-zero, all-one, fewer than 8 unique byte values). This is defence in
    // depth against buggy wallet CSPRNGs. A deliberately malicious wallet can
    // always destroy its own user's privacy by choosing known r_bits; the
    // server-side check cannot prevent that (accepted residual risk).
    let c_bytes = match pedersen_commit_dob_validated(attestation.dob_days, &r_bits) {
        Ok(bytes) => bytes,
        Err(e) => {
            crate::log_error!("Pedersen commitment failed (entropy or input): {:?}", e);
            crate::audit::audit_log(
                &env,
                "blind_issuance_rejected",
                &client_ip,
                "Pedersen commitment computation failed (entropy or input error)",
                &serde_json::json!({
                    "reason": "commitment_computation_failed",
                    "endpoint": "/v1/issuance/blind",
                }),
            )
            .await;
            return ApiError::BadRequest("Invalid randomness for commitment".into()).to_response();
        }
    };

    // dob_days (PII) is no longer needed after commitment computation.
    // Zeroize it immediately. The remaining fields (issuer_id, timestamp, nonce,
    // signature) are non-secret and used for audit logging below.
    attestation.dob_days.zeroize();

    // CIV-139: Validate the computed commitment is a valid Jubjub curve point
    // before signing. validate_commitment_format checks hex encoding and curve
    // membership; validate_commitment_bytes re-confirms the decoded bytes.
    let commitment_hex = hex::encode(c_bytes);
    let validated_bytes = match validation::validate_commitment_format(&commitment_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            crate::log_error!("Computed commitment failed format validation: {:?}", e);
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };
    if let Err(e) = validation::validate_commitment_bytes(&validated_bytes) {
        crate::log_error!("Computed commitment failed bytes validation: {:?}", e);
        return ApiError::Internal("Internal server error".into()).to_response();
    }

    crate::log!(
        "Computed commitment with {} bits of randomness",
        r_bits.len()
    );

    // r_bits is wrapped in Zeroizing and will be cleared
    // on drop (including early-return error paths). Explicit zeroize removed.
    drop(r_bits);

    phase_timings.push(("commitment", js_sys::Date::now() - phase_start));

    // Phase 9: Signing keypair (KV read + KEK decrypt from Secrets Store)
    let phase_start = js_sys::Date::now();

    // Use KeyRotationManager to enforce key status (Active) and
    // expiry checks. The raw storage::get_signing_keypair loads any key by
    // kid without status validation.
    let key_mgr = crate::key_rotation::KeyRotationManager::new(&env);
    let active_key = match key_mgr.get_active_signing_key().await {
        Ok(k) => k,
        Err(e) => {
            crate::log_error!("No active signing key available: {:?}", e);
            crate::audit::audit_log(
                &env,
                "blind_issuance_rejected",
                &client_ip,
                "No active signing key available for blind issuance",
                &serde_json::json!({
                    "reason": "no_active_signing_key",
                    "endpoint": "/v1/issuance/blind",
                    "error": format!("{}", e),
                }),
            )
            .await;
            return ApiError::Internal("Signing key unavailable".into()).to_response();
        }
    };

    // Load the actual key material by the key's VERSION, not key_id. The KV path
    // is `issuer:{issuer_kid}:key:{kid}` and records are stored under the version
    // (matching get_active_signing_key's load_key_record path). Admin-rotated
    // records have key_id="provii:{version}" != version, so passing key_id here
    // 404s the key (the original blind-issuance bug). version==key_id for
    // onboarded keys, so this is a no-op for those.
    let (mut sk, vk) = match storage::get_signing_keypair(&env, &active_key.version).await {
        Ok((sk, vk)) => (zeroize::Zeroizing::new(sk), vk),
        Err(e) => {
            crate::log_error!("Failed to get signing keypair for active key: {:?}", e);
            crate::audit::audit_log(
                &env,
                "internal_error",
                &client_ip,
                "Failed to fetch active signing keypair from storage",
                &serde_json::json!({
                    "endpoint": "/v1/issuance/blind",
                    "key_id": active_key.key_id,
                    "error": format!("{}", e),
                }),
            )
            .await;
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    // Take the inner Vec out of Zeroizing so no unprotected copy is created.
    // The now-empty Zeroizing<Vec<u8>> will zeroize its (empty) buffer on drop.
    let sk_vec = std::mem::take(&mut *sk);
    let signer = match crypto::RjSigner::new(active_key.key_id.clone(), sk_vec, vk) {
        Ok(s) => s,
        Err(e) => {
            crate::log_error!("Failed to create signer: {:?}", e);
            crate::audit::audit_log(
                &env,
                "internal_error",
                &client_ip,
                "Failed to create RedJubjub signer",
                &serde_json::json!({"endpoint": "/v1/issuance/blind", "error": format!("{}", e)}),
            )
            .await;
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    // Cap validity_days to issuer policy, same as session path.
    // Default to policy value (not the 36500-day hardcoded fallback).
    let requested_validity = data
        .validity_days
        .unwrap_or(config.default_policy.validity_days);
    let validity_days = requested_validity
        .min(config.default_policy.validity_days)
        .min(MAX_VALIDITY_DAYS);
    if validity_days == 0 {
        crate::audit::audit_log(
            &env,
            "blind_issuance_rejected",
            &client_ip,
            "Requested validity days is zero after policy cap",
            &serde_json::json!({
                "reason": "validity_zero",
                "endpoint": "/v1/issuance/blind",
                "requested": data.validity_days,
            }),
        )
        .await;
        return ApiError::BadRequest("Invalid validity period".into()).to_response();
    }
    let iat = now;
    let exp = now.saturating_add(u64::from(validity_days).saturating_mul(86400));

    // Get schema (use default if not specified)
    let schema_raw = data.schema.as_deref().unwrap_or("provii.age/0");
    if !is_ascii_identifier(schema_raw, MAX_SCHEMA_LENGTH) {
        crate::audit::audit_log(
            &env,
            "blind_issuance_rejected",
            &client_ip,
            "Invalid schema format in blind issuance",
            &serde_json::json!({"reason": "schema_format_invalid", "endpoint": "/v1/issuance/blind"}),
        )
        .await;
        return ApiError::BadRequest("Invalid schema format".into()).to_response();
    }

    // Validate schema URL against allowed domains (SSRF protection).
    let allowed_schema_domains = env
        .var("ALLOWED_SCHEMA_DOMAINS")
        .map(|v| v.to_string())
        .ok();
    let schema = match validation::validate_schema_url(
        schema_raw,
        allowed_schema_domains.as_deref(),
    ) {
        Ok(s) => s,
        Err(e) => {
            crate::log_error!("Schema URL validation failed in blind issuance: {:?}", e);
            crate::audit::audit_log(
                &env,
                "blind_issuance_rejected",
                &client_ip,
                "Schema URL validation failed in blind issuance",
                &serde_json::json!({"reason": "schema_url_invalid", "endpoint": "/v1/issuance/blind", "error": format!("{}", e)}),
            )
            .await;
            return ApiError::BadRequest("Invalid schema".into()).to_response();
        }
    };

    // If the issuer config defines a default schema, blind issuance
    // must use that schema. Arbitrary schema override is not permitted in the
    // blind path because there is no client-level allowed_schemas check.
    //
    // Note: PolicyConfig::default() sets schema to "provii.age/0", so this
    // check is active on all deployments unless the config explicitly clears it.
    // This is intentionally restrictive for blind issuance.
    if !config.default_policy.schema.is_empty() && schema != config.default_policy.schema {
        crate::log_error!(
            "Blind issuance schema override rejected: requested={} policy={}",
            schema,
            config.default_policy.schema
        );
        crate::audit::audit_log(
            &env,
            "blind_issuance_rejected",
            &client_ip,
            "Schema override not permitted in blind issuance",
            &serde_json::json!({
                "reason": "schema_override_rejected",
                "endpoint": "/v1/issuance/blind",
                "requested_schema": schema,
                "policy_schema": config.default_policy.schema,
            }),
        )
        .await;
        return ApiError::Forbidden("Schema not permitted for blind issuance".into()).to_response();
    }

    phase_timings.push(("signing_keypair", js_sys::Date::now() - phase_start));

    // Phase 10: RedJubjub sign + self-verify (sync CPU, the expensive crypto)
    let phase_start = js_sys::Date::now();

    // Sign the commitment with RedJubjub
    let credential = match crypto::sign_commitment(&signer, c_bytes, iat, exp, &schema) {
        Ok(header) => {
            // Audit the core signing operation (CredentialIssuance).
            crate::audit::audit_log_detailed(
                &env,
                "credential_signed",
                &client_ip,
                "Commitment signed with RedJubjub",
                &serde_json::json!({
                    "kid": header.kid,
                    "schema": schema,
                    "endpoint": "/v1/issuance/blind",
                }),
                crate::audit::DetailedAuditFields {
                    event_category: provii_audit::EventCategory::CredentialIssuance,
                    actor_id: &attestation.issuer_id,
                    outcome: Some(crate::audit::Outcome::Success),
                    severity: None,
                },
            )
            .await;
            header
        }
        Err(e) => {
            let err_str = format!("{}", e);
            let is_self_verify = err_str.contains("Self-verify failed");

            if is_self_verify {
                // Self-verification failure is a Critical SecurityEvent.
                crate::log_error!("CRITICAL: Self-verification failed after signing: {:?}", e);
                crate::audit::audit_log_detailed(
                    &env,
                    "self_verification_failed",
                    &client_ip,
                    "CRITICAL: Self-verification failed after RedJubjub signing",
                    &serde_json::json!({
                        "endpoint": "/v1/issuance/blind",
                        "kid": signer.kid,
                        "error": err_str,
                    }),
                    crate::audit::DetailedAuditFields {
                        event_category: provii_audit::EventCategory::SecurityEvent,
                        actor_id: &attestation.issuer_id,
                        outcome: Some(crate::audit::Outcome::Failure),
                        severity: Some(provii_audit::Severity::Critical),
                    },
                )
                .await;
            } else {
                crate::log_error!("Failed to sign commitment: {:?}", e);
                crate::audit::audit_log_detailed(
                    &env,
                    "credential_signed",
                    &client_ip,
                    "Failed to sign commitment with RedJubjub",
                    &serde_json::json!({
                        "endpoint": "/v1/issuance/blind",
                        "kid": signer.kid,
                        "error": err_str,
                    }),
                    crate::audit::DetailedAuditFields {
                        event_category: provii_audit::EventCategory::CredentialIssuance,
                        actor_id: &attestation.issuer_id,
                        outcome: Some(crate::audit::Outcome::Failure),
                        severity: None,
                    },
                )
                .await;
            }
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    phase_timings.push(("redjubjub_sign", js_sys::Date::now() - phase_start));

    // Emit structured performance log with per-phase timings
    let total_ms = js_sys::Date::now() - handler_start;
    let slow_phases: Vec<&str> = phase_timings
        .iter()
        .filter(|(_, ms)| *ms > 50.0)
        .map(|(name, _)| *name)
        .collect();
    let slow_phases_str = slow_phases.join(",");

    let phases_json = phase_timings
        .iter()
        .map(|(name, ms)| format!(r#""{}": {:.1}"#, name, ms))
        .collect::<Vec<_>>()
        .join(",");
    // Surface which kid slot satisfied the trial verify on
    // the success-path log line. The `secret_version` object carries
    // the 6-char fingerprint of the matched verifying key per
    // OBSERVABILITY.md §1; the role-key `ED25519_KEYS_PROD` is the
    // suffix-only form (the `service` log field already carries the
    // Worker name, so the `ISSUER_` binding-name prefix is dropped
    // per OBSERVABILITY.md §1). `secret_version_used` is the slot
    // label (`default_kid` or `previous_kid`) per Trial verify;
    // this mirrors the status-token precedent in
    // `health.rs::log_status_secret_version`.
    let matched_vk_fp = match verify_vk_bytes {
        Some(bytes) => crate::secret_fingerprint::fingerprint6(&bytes),
        None => "000000".to_string(),
    };
    crate::log!(
        r#"{{"type":"REQUEST_COMPLETE","service":"provii-issuer","route":"/v1/issuance/blind","duration_ms":{:.1},"phases":{{{}}},"slow":{},"secret_version":{{"ED25519_KEYS_PROD":"{}"}},"secret_version_used":"{}","matched_kid":"{}"}}"#,
        total_ms,
        phases_json,
        total_ms > 500.0,
        matched_vk_fp,
        matched_slot,
        matched_kid,
    );

    // Emit analytics event
    let environment = env
        .var("ENVIRONMENT")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    crate::analytics::Analytics::new(&env).blind_issuance(
        "/v1/issuance/blind",
        &environment,
        &attestation.issuer_id,
        total_ms,
        &phase_timings,
        &slow_phases_str,
        &credential.kid,
        "ok",
        "",
    );

    // Audit log successful issuance (without sensitive data)
    crate::audit::audit_log(
        &env,
        "blind_issuance_success",
        &client_ip,
        "Credential signed via blind issuance",
        &serde_json::json!({
            "issuer_id": attestation.issuer_id,
            "issuer_name": matched_issuer_name,
            "validity_days": validity_days,
            "schema": schema,
            "kid": credential.kid,
            "duration_ms": total_ms,
            // ASVS 5.0 V8.1.1: Do NOT log dob_days, r_bits, or commitment
        }),
    )
    .await;

    crate::log!(
        "Blind issuance completed for issuer={} schema={} kid={}",
        attestation.issuer_id,
        schema,
        credential.kid
    );

    // Return signed credential header
    let response = BlindIssuanceResponse { credential };

    // Add anti-caching headers for sensitive credential data
    let mut resp = add_anti_caching_headers(Response::from_json(&response)?)?;
    let _ = crate::rate_limiting::apply_rate_limit_headers(&mut resp, &rl_quota);

    // x-secret-version response header carrying the
    // 6-char fingerprint of the matched verifying-key (computed
    // earlier for the structured-log line). Class 7 kid-based
    // rotation surfaces the active kid's public key as the
    // public-safe rotation observable; the underlying signing key is
    // never exposed via this header.
    resp.headers_mut().set("x-secret-version", &matched_vk_fp)?;

    Ok(resp)
}

/// Creates a DOB attestation signed with the issuer's Ed25519 key.
///
/// # Endpoint
/// `POST /v1/attestation/create`
///
/// # Security (ASVS 5.0 / MASVS 2.0)
/// - Officer YubiKey authentication required
/// - Ed25519 signing key decrypted only in memory
/// - Signing key zeroized after use
/// - Attestation expires in 1 hour
/// - V2.1.4: Unique nonce per attestation
/// - V6.2.1: Ed25519 digital signature
/// - V8.1.1: Sensitive data not logged
///
/// # No schema allowlist
///
/// This endpoint intentionally has no schema allowlist. It produces a
/// `DobAttestation` (Ed25519 envelope over `dob_days`), which has no schema
/// concept. `CreateAttestationRequest` contains only `dob_days` and
/// `authorizer`, with `#[serde(deny_unknown_fields)]` rejecting extras.
/// Schema enforcement occurs in `blind_issuance`, which signs the Pedersen
/// commitment with a schema tag .
pub async fn create_attestation(
    mut req: Request,
    ctx: RouteContext<()>,
) -> worker::Result<Response> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::SigningKey;
    use provii_crypto_commons::attestation::DobAttestation;
    use zeroize::{Zeroize, Zeroizing};

    let handler_start = js_sys::Date::now();
    let mut phase_timings: Vec<(&str, f64)> = Vec::with_capacity(8);

    let env = ctx.env.clone();
    let client_ip = crate::audit::get_client_ip(&req);

    // Phase 0: Pre-auth IP rate limit
    //
    // SECURITY: Per-IP rate limit BEFORE any expensive work. Without this,
    // an unauthenticated attacker can flood POST /v1/attestation/create and
    // force the worker through JSON parsing, Argon2id API key verification
    // (~60ms CPU), YubiKey/client auth, nonce DO consumption, and timestamp
    // validation before the per-actor limit ever engages. The per-actor
    // limit cannot defend against this because `actor_id` is unknown until
    // auth completes.
    //
    // This mirrors the pre-body IP limit in blind_issuance (routes.rs:1704)
    // and generate_yubikey_challenge (routes.rs:327).
    let phase_start = js_sys::Date::now();
    {
        let rl_kv = match env.kv("ISSUER_RATE_LIMITS") {
            Ok(kv) => kv,
            Err(e) => {
                crate::log_error!("[RateLimit] ISSUER_RATE_LIMITS KV unavailable: {:?}", e);
                return ApiError::ServiceUnavailable(
                    "Rate limiting infrastructure unavailable".into(),
                )
                .to_response();
            }
        };
        // Hash the IP before using it in the KV key so plaintext
        // addresses are never stored as KV key names.
        let hashed_ip = crate::audit::build_privacy_context(&env)
            .await
            .hash_ip(&client_ip)
            .unwrap_or_default();
        let ip_key = format!("attestation_ip:{}", hashed_ip);
        let ip_limit: u32 = env
            .var("ATTESTATION_IP_LIMIT_PER_HOUR")
            .ok()
            .and_then(|v| v.to_string().parse().ok())
            .unwrap_or(60);
        let result = crate::rate_limiting::check_blind_issuance(&rl_kv, &ip_key, ip_limit).await;
        if !result.allowed {
            crate::log!(
                "[RateLimit] IP rate limit exceeded for create_attestation ip_hash={}",
                hashed_ip
            );
            // R8: offload the best-effort reject audit to wait_until so the
            // 429/503 returns before the AUDIT_QUEUE send. Inline fallback is
            // MANDATORY (take_worker_context is single-shot). audit_log swallows
            // errors so this can never become a 5xx.
            //
            // M4: bracket the wait_until scheduling with synchronous console
            // logs carrying a correlation id so a slow-isolate eviction that
            // drops the background future (losing the audit event) is
            // detectable: a "scheduled" line with no matching "handed_off" line
            // or no downstream queue delivery for that id.
            {
                let audit_env = env.clone();
                let audit_ip = client_ip.clone();
                let audit_count = result.current_count;
                let audit_limit = result.limit;
                let audit_corr_id = uuid::Uuid::new_v4().to_string();
                let emit_corr_id = audit_corr_id.clone();
                let emit = move |env: Env, ip: String| async move {
                    crate::audit::audit_log(
                        &env,
                        "rate_limit_exceeded",
                        &ip,
                        "Pre-auth IP rate limit exceeded for attestation creation",
                        &serde_json::json!({
                            "endpoint": "/v1/attestation/create",
                            "scope": "ip",
                            "count": audit_count,
                            "limit": audit_limit,
                            "audit_corr_id": emit_corr_id,
                        }),
                    )
                    .await;
                };
                if let Some(ctx) = crate::take_worker_context() {
                    // Synchronous placeholder BEFORE handing off, emitted inline
                    // so it survives isolate eviction even if the wait_until
                    // future never executes.
                    crate::log!(
                        "{{\"event\":\"audit_wait_until_scheduled\",\"audit_event\":\"rate_limit_exceeded\",\"endpoint\":\"/v1/attestation/create\",\"audit_corr_id\":\"{}\"}}",
                        audit_corr_id
                    );
                    ctx.wait_until(emit(audit_env, audit_ip));
                    // Confirm scheduling returned.
                    crate::log!(
                        "{{\"event\":\"audit_wait_until_handed_off\",\"audit_event\":\"rate_limit_exceeded\",\"endpoint\":\"/v1/attestation/create\",\"audit_corr_id\":\"{}\"}}",
                        audit_corr_id
                    );
                } else {
                    // No worker context: emit inline (awaited), no loss window.
                    emit(audit_env, audit_ip).await;
                }
            }
            return crate::rate_limiting::rate_limit_or_unavailable_response(&result);
        }
    }
    phase_timings.push(("ip_rate_limit", js_sys::Date::now() - phase_start));

    // Phase 1: Optional API key verification (prefix KV lookup + Argon2id)
    let phase_start = js_sys::Date::now();

    // H-35 (modified): X-API-Key is OPTIONAL on this endpoint to support both
    // authentication flows on a single path:
    //
    //   1. Client app flow (app-to-app issuance): sends X-API-Key header.
    //      Validated here as a cheap pre-body-parse gate to reject bad keys
    //      before spending CPU on Argon2id. The real auth is the HMAC in the
    //      authorizer body (format: "client").
    //
    //   2. Officer flow (in-person issuance): no X-API-Key header. Officers
    //      authenticate via YubiKey challenge-response in the authorizer body
    //      (format: "yubikey"). They have no API key by design.
    //
    // In both cases the authorizer HMAC/YubiKey check after body parsing is
    // the security boundary. The X-API-Key header is a DoS-mitigation
    // optimisation for the client flow, not the auth boundary itself.
    if let Some(api_key) = req.headers().get("X-API-Key").ok().flatten() {
        if api_key.is_empty() {
            crate::audit::audit_log(
                &env,
                "authentication_failed",
                &client_ip,
                "Empty X-API-Key header on attestation create",
                &serde_json::json!({"reason": "empty_api_key", "endpoint": "/v1/attestation/create"}),
            )
            .await;
            return ApiError::Forbidden("Forbidden".into()).to_response();
        }
        // Verify the API key when present (client app flow fast-path).
        if let Err(e) = crate::security::ClientAuthVerifier::verify_api_key(&env, &api_key).await {
            crate::log_error!("API key verification failed: {:?}", e);
            crate::audit::audit_log(
                &env,
                "authentication_failed",
                &client_ip,
                "API key verification failed on attestation create",
                &serde_json::json!({"reason": "invalid_api_key", "endpoint": "/v1/attestation/create"}),
            )
            .await;
            return ApiError::Forbidden("Forbidden".into()).to_response();
        }
    }
    // No X-API-Key header: proceed to body parsing. The authorizer HMAC or
    // YubiKey check below is the auth boundary for the officer flow.

    phase_timings.push(("api_key_auth", js_sys::Date::now() - phase_start));

    // Phase 2: Body parse
    let phase_start = js_sys::Date::now();

    // Parse request body
    let data: crate::types::CreateAttestationRequest = match req.json().await {
        Ok(d) => d,
        Err(e) => {
            crate::log_error!("Failed to parse create attestation request: {:?}", e);
            // emit attestation_create_rejected for body parse failures,
            // matching the behaviour of blind_issuance (routes.rs:1631). The
            // serde_json error message is bounded and contains no PII (it
            // describes JSON syntax, not the parsed value).
            crate::audit::audit_log(
                &env,
                "attestation_create_rejected",
                &client_ip,
                "Failed to parse create attestation request body",
                &serde_json::json!({
                    "reason": "parse_error",
                    "endpoint": "/v1/attestation/create",
                    "error": format!("{}", e),
                }),
            )
            .await;
            return ApiError::BadRequest("Invalid request body".into()).to_response();
        }
    };

    // SECURITY: Enforce serde_valid constraints on Authorizer fields (A-21).
    // Without this, constraints on key_id length, nonce format, hmac length etc.
    // defined via #[validate] attributes are silently bypassed.
    // serde_valid error messages may include field values (including
    // dob_days). Log a generic message; do NOT include `e` in the log output
    // or in the audit details payload.
    if let Err(_e) = data.validate() {
        crate::log_error!("Attestation request validation failed");
        // emit attestation_create_rejected for schema-validation
        // failures, matching blind_issuance (routes.rs:1644). We deliberately
        // omit the serde_valid error string from the audit details because it
        // can echo field values including `dob_days` (PII).
        crate::audit::audit_log(
            &env,
            "attestation_create_rejected",
            &client_ip,
            "Attestation request schema validation failed",
            &serde_json::json!({
                "reason": "schema_violation",
                "endpoint": "/v1/attestation/create",
            }),
        )
        .await;
        return ApiError::BadRequest("Invalid request".into()).to_response();
    }

    // Validate dob_days range (sanity check)
    // Negative values represent pre-1970 DOBs (e.g. -25000 ~ 1901)
    if data.dob_days < -25000 || data.dob_days > 36500 {
        return ApiError::BadRequest("Invalid dob_days: out of acceptable range".into())
            .to_response();
    }

    // Reject DOBs in the future (negative age).
    {
        #[allow(clippy::arithmetic_side_effects)]
        let now_days_i64 = chrono::Utc::now().timestamp() / 86400;
        let now_days = i32::try_from(now_days_i64).unwrap_or(i32::MAX);
        if data.dob_days > now_days {
            crate::audit::audit_log(
                &env,
                "attestation_child_rejected",
                &client_ip,
                "Attestation rejected: DOB is in the future",
                &serde_json::json!({
                    "reason": "future_dob",
                    "endpoint": "/v1/attestation/create",
                    "issuer_kid": data.authorizer.key_id,
                }),
            )
            .await;
            return ApiError::BadRequest("Date of birth cannot be in the future".into())
                .to_response();
        }
    }

    phase_timings.push(("body_parse", js_sys::Date::now() - phase_start));

    // Phase 3: Session auth (YubiKey or Client HMAC, includes nonce DO + KV + KEK decrypt)
    let phase_start = js_sys::Date::now();

    // Validate timestamp freshness
    if !validate_timestamp(data.authorizer.timestamp) {
        crate::audit::audit_log(
            &env,
            "authentication_failed",
            &client_ip,
            "Invalid or expired timestamp on attestation create",
            &serde_json::json!({"reason": "invalid_timestamp", "endpoint": "/v1/attestation/create", "format": data.authorizer.format}),
        )
        .await;
        return ApiError::Unauthorized("Invalid or expired timestamp".into()).to_response();
    }

    // Authenticate based on authorizer format
    let auth_handler = crate::session::AuthHandler::new(&env);
    let actor_id = match data.authorizer.format.as_str() {
        "yubikey" => {
            // Officer authentication using YubiKey
            match auth_handler
                .authenticate_yubikey(&data.authorizer, true, &client_ip, None)
                .await
            {
                Ok(id) => id,
                Err(e) => {
                    crate::log_error!("Officer authentication failed: {:?}", e);
                    crate::audit::audit_log(
                        &env,
                        "authentication_failed",
                        &client_ip,
                        "Officer YubiKey authentication failed on attestation create",
                        &serde_json::json!({"reason": "yubikey_auth_failed", "endpoint": "/v1/attestation/create"}),
                    )
                    .await;
                    return ApiError::Unauthorized("Authentication failed".into()).to_response();
                }
            }
        }
        "client" => {
            // Third-party issuer authentication using HMAC
            let canonical = crate::session::create_canonical_message_for_attestation(
                "POST",
                "/v1/attestation/create",
                data.authorizer.timestamp,
                data.dob_days,
                &data.authorizer,
            );

            match auth_handler
                .authenticate_client(&data.authorizer, &canonical, &client_ip)
                .await
            {
                Ok(client) => client.client_id.clone(),
                Err(e) => {
                    crate::log_error!("Client authentication failed: {:?}", e);
                    crate::audit::audit_log(
                        &env,
                        "authentication_failed",
                        &client_ip,
                        "Client HMAC authentication failed on attestation create",
                        &serde_json::json!({"reason": "client_auth_failed", "endpoint": "/v1/attestation/create"}),
                    )
                    .await;
                    return ApiError::Unauthorized("Authentication failed".into()).to_response();
                }
            }
        }
        _ => {
            return ApiError::BadRequest(
                "Invalid authorizer format: must be 'yubikey' or 'client'".into(),
            )
            .to_response();
        }
    };

    let auth_method = data.authorizer.format.clone();
    phase_timings.push(("session_auth", js_sys::Date::now() - phase_start));

    // ADV-IA-33-001 / AUD-IA-01-027: Child DOB guard for client (app-to-app)
    // auth. Officers (YubiKey) verify identity in person and must be allowed
    // to attest any DOB including minors. Client (automated) issuers must not
    // issue attestations for persons under 18.
    if auth_method == "client" {
        #[allow(clippy::arithmetic_side_effects)]
        // Division by the constant 86400 cannot overflow for any i64 timestamp.
        let now_days = {
            let now_days_i64 = chrono::Utc::now().timestamp() / 86400;
            i32::try_from(now_days_i64).unwrap_or(i32::MAX)
        };
        let age_days = now_days.saturating_sub(data.dob_days);
        // 18 years = 365.25 * 18 = 6574.5, rounded down to 6574
        if age_days < 6574 {
            crate::audit::audit_log(
                &env,
                "attestation_child_rejected",
                &client_ip,
                "Attestation rejected: minor DOB with client auth",
                &serde_json::json!({
                    "reason": "child_dob_client_auth",
                    "endpoint": "/v1/attestation/create",
                    "issuer_kid": data.authorizer.key_id,
                }),
            )
            .await;
            return ApiError::BadRequest(
                "Attestation rejected: client auth not permitted for minors".into(),
            )
            .to_response();
        }
    }

    // Phase 4: Per-customer rate limit
    let phase_start = js_sys::Date::now();

    // Rate limiting: per-customer hourly quota via KV counter
    // SECURITY : Fail closed, return 503 when rate limiting infrastructure is unavailable
    let rl_quota = {
        let (rl_kv, cfg_kv) = match resolve_rate_limit_kvs(&env) {
            Ok(pair) => pair,
            Err(resp) => return resp,
        };
        let result = crate::rate_limiting::check_quota(
            &rl_kv,
            &cfg_kv,
            &actor_id,
            "attestation",
            get_default_quota(&env),
        )
        .await;
        if !result.allowed {
            crate::log!(
                "[RateLimit] Exceeded for actor={} endpoint=attestation count={}/{}",
                actor_id,
                result.current_count,
                result.limit
            );
            // R8: offload the best-effort reject audit to wait_until so the
            // 429/503 returns before the AUDIT_QUEUE send. Inline fallback is
            // MANDATORY (take_worker_context is single-shot). audit_log swallows
            // errors so this can never become a 5xx. actor_id is cloned (not
            // moved) because the happy path below still uses it.
            {
                let audit_env = env.clone();
                let audit_ip = client_ip.clone();
                let audit_actor_id = actor_id.clone();
                let audit_count = result.current_count;
                let audit_limit = result.limit;
                let emit = move |env: Env, ip: String, actor_id: String| async move {
                    crate::audit::audit_log(
                        &env,
                        "rate_limit_exceeded",
                        &ip,
                        "Rate limit exceeded for attestation creation",
                        &serde_json::json!({"endpoint": "attestation", "actor_id": actor_id, "count": audit_count, "limit": audit_limit}),
                    )
                    .await;
                };
                if let Some(ctx) = crate::take_worker_context() {
                    ctx.wait_until(emit(audit_env, audit_ip, audit_actor_id));
                } else {
                    emit(audit_env, audit_ip, audit_actor_id).await;
                }
            }
            return crate::rate_limiting::rate_limit_or_unavailable_response(&result);
        }
        result
    };

    phase_timings.push(("rate_limit", js_sys::Date::now() - phase_start));

    // Phase 5: Issuer config + Ed25519 signing key + KEK decrypt
    let phase_start = js_sys::Date::now();

    // Get the issuer config to determine which issuer_id this officer belongs to
    let config = match storage::get_issuer_config(&env).await {
        Ok(c) => c,
        Err(e) => {
            crate::log_error!("Failed to get issuer config: {:?}", e);
            crate::audit::audit_log(
                &env,
                "internal_error",
                &client_ip,
                "Failed to fetch issuer config from storage",
                &serde_json::json!({"endpoint": "/v1/attestation/create", "error": format!("{}", e)}),
            )
            .await;
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    phase_timings.push(("issuer_config", js_sys::Date::now() - phase_start));

    // Phase 6: Ed25519 signing key retrieval + KEK decrypt
    let phase_start = js_sys::Date::now();

    // Sign side: always sign new attestations under the issuer's
    // current `default_kid`. The verify side (in `blind_issuance`) trial
    // verifies against `default_kid` first and falls back to
    // `previous_kid` so attestations signed under the prior key during a
    // rotation overlap window still redeem successfully.
    let signing_kid = config.default_kid.clone();

    // Get the issuer's Ed25519 signing key (encrypted) under (issuer_id, kid)
    let signing_key_record = match storage::get_issuer_ed25519_signing_key(
        &env,
        &config.issuer_id,
        &signing_kid,
    )
    .await
    {
        Ok(Some(key)) => key,
        Ok(None) => {
            crate::log_error!(
                "No Ed25519 signing key configured for (issuer={}, kid={})",
                config.issuer_id,
                signing_kid
            );
            crate::audit::audit_log(
                    &env,
                    "internal_error",
                    &client_ip,
                    "No Ed25519 signing key configured for issuer/kid",
                    &serde_json::json!({"endpoint": "/v1/attestation/create", "issuer_id": config.issuer_id, "kid": signing_kid}),
                )
                .await;
            return ApiError::Internal("Internal server error".into()).to_response();
        }
        Err(e) => {
            crate::log_error!("Failed to get Ed25519 signing key: {:?}", e);
            crate::audit::audit_log(
                    &env,
                    "internal_error",
                    &client_ip,
                    "Failed to fetch Ed25519 signing key from storage",
                    &serde_json::json!({"endpoint": "/v1/attestation/create", "error": format!("{}", e)}),
                )
                .await;
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    // Check key status
    if signing_key_record.status != crate::types::KeyStatus::Active {
        crate::log_error!(
            "Ed25519 signing key for issuer={} is not active (status={:?})",
            config.issuer_id,
            signing_key_record.status
        );
        return ApiError::Internal("Internal server error".into()).to_response();
    }

    // Get KEK pair (with rotation fallback) for decryption
    let kek_pair = match crate::kek::get_kek_pair(&env).await {
        Ok(p) => p,
        Err(e) => {
            crate::log_error!("Failed to get KEK pair: {:?}", e);
            crate::audit::audit_log(
                &env,
                "internal_error",
                &client_ip,
                "Failed to get KEK pair from Secrets Store",
                &serde_json::json!({"endpoint": "/v1/attestation/create", "error": format!("{}", e)}),
            )
            .await;
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    // Decrypt the signing key using envelope encryption (with KEK fallback)
    let signing_key_bytes = match crate::kek::decrypt_with_kek_fallback(
        &env,
        &kek_pair,
        &signing_key_record.signing_key,
        b"provii-issuer:ed25519-key:v1",
    )
    .await
    {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) => {
            crate::log_error!("Failed to decrypt Ed25519 signing key: {:?}", e);
            crate::audit::audit_log(
                &env,
                "internal_error",
                &client_ip,
                "Failed to decrypt Ed25519 signing key with KEK",
                &serde_json::json!({"endpoint": "/v1/attestation/create", "error": format!("{}", e)}),
            )
            .await;
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    // Convert to ed25519-dalek SigningKey
    if signing_key_bytes.len() != 32 {
        crate::log_error!(
            "Invalid Ed25519 signing key length: expected 32, got {}",
            signing_key_bytes.len()
        );
        return ApiError::Internal("Internal server error".into()).to_response();
    }

    // Wrap in Zeroizing so the temporary array is cleared on all paths
    // (including panics). SigningKey::from_bytes takes &[u8; 32] which
    // requires this intermediate copy (inherent to ed25519-dalek API).
    let key_array = Zeroizing::new({
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&signing_key_bytes);
        arr
    });
    let signing_key = SigningKey::from_bytes(&key_array);

    // capture the public verifying-key bytes for the
    // x-secret-version response header. Public-safe by definition;
    // captured here so the variable can outlive the drop(signing_key)
    // below.
    let signing_vk_bytes = signing_key.verifying_key().to_bytes();

    phase_timings.push(("signing_key", js_sys::Date::now() - phase_start));

    // Phase 7: Attestation creation and Ed25519 signing (sync CPU)
    let phase_start = js_sys::Date::now();

    // Create and sign the attestation
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);

    // Generate cryptographically secure random nonce (256 bits)
    let mut nonce = [0u8; 32];
    if let Err(e) = getrandom::getrandom(&mut nonce) {
        crate::log_error!("Nonce generation failed: {:?}", e);
        crate::audit::audit_log(
            &env,
            "internal_error",
            &client_ip,
            "Nonce generation failed",
            &serde_json::json!({"endpoint": "/v1/attestation/create", "error": format!("{}", e)}),
        )
        .await;
        return ApiError::Internal("Internal server error".into()).to_response();
    }

    // provii-crypto v0.2.0: DobAttestation::create returns Result;
    // FieldTooLong is the only failure mode (issuer_id > 255 bytes).
    // Config-validated issuer_id cannot exceed that, but we must still
    // return a proper error rather than panic.
    let mut attestation =
        match DobAttestation::create(data.dob_days, &config.issuer_id, now, nonce, &signing_key) {
            Ok(a) => a,
            Err(e) => {
                crate::log_error!("Failed to construct attestation: {:?}", e);
                return ApiError::Internal("Internal server error".into()).to_response();
            }
        };

    // Zeroize the signing key (done automatically by SigningKey's Drop, but be explicit)
    drop(signing_key);

    // Serialize and encode the attestation
    let mut attestation_json = match serde_json::to_vec(&attestation) {
        Ok(j) => j,
        Err(e) => {
            crate::log_error!("Failed to serialize attestation: {:?}", e);
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };
    let attestation_b64 = URL_SAFE_NO_PAD.encode(&attestation_json);

    // Zeroize both the struct field and the intermediate JSON
    // buffer that contained the serialized DOB.
    attestation.dob_days.zeroize();
    attestation_json.zeroize();

    phase_timings.push(("attestation_sign", js_sys::Date::now() - phase_start));

    // Emit structured performance log with per-phase timings
    let total_ms = js_sys::Date::now() - handler_start;
    let phases_json = phase_timings
        .iter()
        .map(|(name, ms)| format!(r#""{}": {:.1}"#, name, ms))
        .collect::<Vec<_>>()
        .join(",");
    crate::log!(
        r#"{{"type":"REQUEST_COMPLETE","service":"provii-issuer","route":"/v1/attestation/create","duration_ms":{:.1},"phases":{{{}}},"slow":{}}}"#,
        total_ms,
        phases_json,
        total_ms > 500.0
    );

    // Emit analytics event
    let environment = env
        .var("ENVIRONMENT")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    crate::analytics::Analytics::new(&env).attestation_created(
        "/v1/attestation/create",
        &environment,
        &config.issuer_id,
        total_ms,
        &phase_timings,
        &auth_method,
        "ok",
        "",
    );

    // Audit log successful attestation creation (without sensitive data)
    let _ = crate::audit::audit_log(
        &env,
        "attestation_created",
        &client_ip,
        "DOB attestation created and signed",
        &serde_json::json!({
            "issuer_id": config.issuer_id,
            "officer_id": if data.authorizer.format == "yubikey" { Some(actor_id.clone()) } else { None },
            "client_id": if data.authorizer.format == "client" { Some(actor_id.clone()) } else { None },
            "auth_method": data.authorizer.format,
            // ASVS 5.0 V8.1.1: Do NOT log dob_days
        }),
    )
    .await;

    crate::log!(
        "Attestation created by actor={} for issuer={}",
        actor_id,
        config.issuer_id
    );

    // Return the attestation
    let response = crate::types::CreateAttestationResponse {
        attestation: attestation_b64,
        expires_at: now.saturating_add(crate::types::ATTESTATION_MAX_AGE_SECONDS),
        issuer_id: config.issuer_id,
    };

    // Add anti-caching headers for sensitive attestation data
    let mut resp = add_anti_caching_headers(Response::from_json(&response)?.with_status(201))?;
    let _ = crate::rate_limiting::apply_rate_limit_headers(&mut resp, &rl_quota);

    // x-secret-version response header carrying the
    // 6-char fingerprint of the signing kid's verifying key. Class 7
    // kid-based rotation surfaces the active kid's public key as the
    // public-safe rotation observable; the underlying signing key is
    // never exposed via this header.
    let vk_fp = crate::secret_fingerprint::fingerprint6(&signing_vk_bytes);
    resp.headers_mut().set("x-secret-version", &vk_fp)?;

    // Emit secret_version structured log for the sign-side handler so
    // Grafana panels see the active kid's fingerprint on every
    // attestation issuance.
    crate::log!(
        r#"{{"type":"REQUEST_COMPLETE","service":"provii-issuer","route":"/v1/attestation/create","secret_version":{{"ED25519_KEYS_PROD":"{fp}"}},"secret_version_used":"default_kid","kid":"{kid}"}}"#,
        fp = vk_fp,
        kid = signing_kid,
    );

    Ok(resp)
}
