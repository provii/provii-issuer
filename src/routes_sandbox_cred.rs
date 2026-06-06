// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Sandbox credential mint for the issuer service.
//!
//! # Endpoints
//!
//!   - `POST /v1/register-test-issuer`, mint a per-developer sandbox
//!     Issuing Party credential (client_id + hmac_secret). Auth:
//!     `X-Docs-Hmac` over body under the shared `SANDBOX_API_KEY` (same
//!     secret as provii-verifier). The Issuing Party authenticates to
//!     `/v1/attestation/create` with these credentials; the Issuer signs
//!     every attestation server-side with its own keys. The Issuing
//!     Party never holds an Ed25519 signing key.
//!
//! # Lifetime
//!
//! 72-hour KV TTL on the cred record. Aligned with the provii-verifier side.
//!
//! # Production
//!
//! Returns 404 in production. The `cfg.environment` gate is enforced in
//! `lib.rs` at the route registration point, plus a defensive
//! double-check at the top of the handler (mirroring provii-verifier's
//! pattern).

use crate::error::ApiError;
use crate::storage;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::sync::OnceLock;
use worker::*;

// ---------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------

/// 72 hours in seconds. Matches provii-verifier's register-test-origin TTL
/// so a dev minting a verifier+issuer pair sees them expire together.
const TTL_SECONDS: u64 = 259_200;

/// Maximum body size for the mint endpoint. 4 KB is generous given the
/// body has two short string fields.
const MAX_BODY_BYTES: usize = 4 * 1024;

/// Per-IP rate limit on mint calls. 10/hour matches provii-verifier.
const RATE_LIMIT_PER_HOUR: u32 = 10;

/// Rate-limit key prefix in `ISSUER_RATE_LIMITS` KV. The shared
/// `check_blind_issuance` helper writes a single key under the supplied
/// identifier; we prefix to keep our keyspace separate from the blind
/// issuance counters that helper was originally built for.
const RATE_LIMIT_PREFIX: &str = "register_test_issuer";

/// Maximum length for the `issuer_label` body field. Same upper bound
/// as production issuer display names; the field is opaque to issuer-
/// api beyond storage.
const MAX_LABEL_LEN: usize = 64;

/// Maximum length for the `api_key` body field. Mirrors provii-verifier.
const MAX_API_KEY_LEN: usize = 256;

/// Encryption AAD for the per-cred HMAC secret. Must match the AAD used
/// by `get_client_by_id` when decrypting on the auth path. Any drift
/// here breaks every sandbox login with an AES-GCM tag mismatch and
/// the dev sees a generic 401.
const HMAC_SECRET_AAD: &[u8] = b"provii-issuer:session:v1";

// ---------------------------------------------------------------------
// SANDBOX_API_KEY caching
// ---------------------------------------------------------------------

/// Module-level OnceLock cache of the bytes of `SANDBOX_API_KEY`.
///
/// Cloudflare Workers isolates are short-lived (~30s typical) so this
/// cache amortises Secrets Store cost across the small burst of
/// requests an isolate handles. The first call fetches and `.set()`s;
/// subsequent calls hit cache.
///
/// On startup-fetch failure the cache stays unset, and `cached_or_none`
/// returns None so the caller takes the fail-closed 401 path. There is
/// no fallback to a default key; either the binding read succeeded or
/// the route rejects every request. This matches the provii-verifier
/// fail-closed semantics on `verify_or_reject_hmac_key`.
static SANDBOX_API_KEY_CACHE: OnceLock<Vec<u8>> = OnceLock::new();

/// Fetch the cached `SANDBOX_API_KEY` bytes, populating the cache from
/// the Secrets Store on first call.
///
/// Returns `None` if the binding is unavailable or the secret is empty,
/// in which case the caller MUST emit the 401 `docs_hmac_invalid`
/// envelope without consulting the body further.
async fn cached_or_load_sandbox_api_key(env: &Env) -> Option<&'static [u8]> {
    if let Some(cached) = SANDBOX_API_KEY_CACHE.get() {
        return Some(cached.as_slice());
    }

    // Cache miss. Read once from the Secrets Store and try to populate.
    let store = match env.secret_store("SANDBOX_API_KEY") {
        Ok(s) => s,
        Err(e) => {
            crate::log_error!(
                "[register-test-issuer] SANDBOX_API_KEY binding unavailable: {:?}",
                e
            );
            return None;
        }
    };
    let value = match store.get().await {
        Ok(Some(v)) if !v.is_empty() => v,
        Ok(_) => {
            crate::log_error!(
                "[register-test-issuer] SANDBOX_API_KEY secret missing or empty in Secrets Store"
            );
            return None;
        }
        Err(e) => {
            crate::log_error!(
                "[register-test-issuer] SANDBOX_API_KEY Secrets Store read failed: {:?}",
                e
            );
            return None;
        }
    };
    let bytes = value.into_bytes();
    // OnceLock::set returns Err if another caller raced us; we ignore
    // that branch and read whichever value won.
    let _ = SANDBOX_API_KEY_CACHE.set(bytes);
    SANDBOX_API_KEY_CACHE.get().map(|v| v.as_slice())
}

// ---------------------------------------------------------------------
// Request / response shapes
// ---------------------------------------------------------------------

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterTestIssuerRequest {
    /// Plaintext SANDBOX_API_KEY. Cross-checked against the same
    /// secret used to verify the X-Docs-Hmac envelope, in addition to
    /// the HMAC, mirroring provii-verifier's belt-and-braces pattern.
    api_key: String,
    /// Display name for the minted issuer (1-64 ASCII printable bytes,
    /// no nul). Surfaced in the response only; not used as a key.
    issuer_label: String,
}

/// JSON body returned on a successful mint.
#[derive(serde::Serialize)]
struct RegisterTestIssuerResponse {
    client_id: String,
    /// Base64url-encoded 32 random bytes. The plaintext leaves issuer-
    /// api exactly once; the stored copy is encrypted under the
    /// ISSUER_KEK with AAD `provii-issuer:session:v1`.
    hmac_secret: String,
    kid: String,
    issuer_label: String,
    expires_at: u64,
    minted_at: u64,
    base_url: String,
}

// ---------------------------------------------------------------------
// JSON envelope helpers
// ---------------------------------------------------------------------

fn json_error_response(status: u16, code: &str, message: &str) -> Result<Response> {
    let body = serde_json::json!({
        "error": message,
        "code": code,
    });
    let mut resp = Response::from_json(&body)?.with_status(status);
    resp.headers_mut()
        .set("Content-Type", "application/json; charset=utf-8")?;
    resp.headers_mut().set(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, private",
    )?;
    Ok(resp)
}

fn docs_hmac_401(detail: &str) -> Result<Response> {
    json_error_response(401, crate::security::DOCS_HMAC_REJECTION_CODE, detail)
}

fn bad_request(field: &str, message: &str) -> Result<Response> {
    let body = serde_json::json!({
        "error": message,
        "code": "BODY_SCHEMA_INVALID",
        "field": field,
    });
    let mut resp = Response::from_json(&body)?.with_status(400);
    resp.headers_mut()
        .set("Content-Type", "application/json; charset=utf-8")?;
    resp.headers_mut().set(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, private",
    )?;
    Ok(resp)
}

// ---------------------------------------------------------------------
// Body reading
// ---------------------------------------------------------------------

/// Read the request body up to `max_bytes`. Returns 413 if the body
/// exceeds the limit. We use `bytes()` because it returns the full
/// body buffered (Cloudflare Workers does not support streaming reads
/// with backpressure for our worker-rs version), and check the length
/// against the limit after the fact.
async fn read_limited_body(
    req: &mut Request,
    max_bytes: usize,
) -> std::result::Result<Vec<u8>, &'static str> {
    let bytes = req.bytes().await.map_err(|_| "body read failed")?;
    if bytes.len() > max_bytes {
        return Err("body too large");
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------
// Identifier validation
// ---------------------------------------------------------------------

/// Validate the issuer_label field. Permissive ASCII printable, no nul,
/// 1-64 bytes. Display only; we never use it as a KV key.
fn validate_issuer_label(label: &str) -> std::result::Result<(), &'static str> {
    if label.is_empty() {
        return Err("issuer_label is required");
    }
    if label.len() > MAX_LABEL_LEN {
        return Err("issuer_label exceeds 64 bytes");
    }
    for byte in label.as_bytes() {
        // Reject nul, control characters, and non-ASCII. The label is
        // purely cosmetic; keeping it printable ASCII removes surprises
        // when it's surfaced in JSON or logs.
        if !(0x20..=0x7E).contains(byte) {
            return Err("issuer_label contains non-printable or non-ASCII bytes");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// POST /v1/register-test-issuer
// ---------------------------------------------------------------------

/// Handler for `POST /v1/register-test-issuer`. See module docs.
pub async fn register_test_issuer(
    mut req: Request,
    ctx: RouteContext<()>,
) -> worker::Result<Response> {
    let env = ctx.env.clone();

    // Defensive double-check: even if the route registration has been
    // miswired in lib.rs, refuse to mint creds outside sandbox. Mirrors
    // provii-verifier's `register_test_verifier` sandbox guard.
    let environment = env
        .var("ENVIRONMENT")
        .map(|v| v.to_string())
        .unwrap_or_default();
    if environment != "sandbox" {
        return ApiError::NotFound("Not Found".into()).to_response();
    }

    let client_ip = crate::audit::get_client_ip(&req);

    // ---- 1. Read body before HMAC verify (HMAC is over the bytes) ----
    let body_bytes = match read_limited_body(&mut req, MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(reason) => {
            crate::log!(
                "[register-test-issuer] body read rejected: {} (ip={})",
                reason,
                client_ip
            );
            return json_error_response(413, "PAYLOAD_TOO_LARGE", "Request body too large");
        }
    };

    // ---- 2. Verify X-Docs-Hmac fail-closed on missing cached key ----
    //
    // Match the provii-verifier ordering: HMAC first, then JSON parse, so
    // an attacker-controlled body never reaches `serde_json::from_slice`
    // on an unauthenticated path.
    let cached_key = cached_or_load_sandbox_api_key(&env).await;
    let docs_hmac_key = match crate::security::verify_or_reject_hmac_key(cached_key) {
        Ok(k) => k,
        Err(_) => {
            crate::log_error!(
                "[register-test-issuer] SANDBOX_API_KEY not cached; failing closed on X-Docs-Hmac"
            );
            return docs_hmac_401(
                "X-Docs-Hmac signature is required for this endpoint and could not be verified (server-side key not provisioned)",
            );
        }
    };

    let hdrs = req.headers();
    let header_value = hdrs.get(crate::security::DOCS_HMAC_HEADER).ok().flatten();
    match crate::security::verify_docs_hmac(header_value.as_deref(), &body_bytes, docs_hmac_key) {
        crate::security::DocsHmacCheck::Ok => {}
        outcome => {
            // Public detail strings deliberately avoid leaking the
            // "docs gateway" phrase, mirroring provii-verifier's R4 NEW-R4-F.
            let detail = match outcome {
                crate::security::DocsHmacCheck::MissingHeader => {
                    "X-Docs-Hmac header is required for the docs sandbox proxy route"
                }
                crate::security::DocsHmacCheck::MalformedHeader => {
                    "X-Docs-Hmac header is not a valid hex-encoded HMAC-SHA256 tag"
                }
                crate::security::DocsHmacCheck::Mismatch => {
                    "X-Docs-Hmac signature did not verify against the request body"
                }
                crate::security::DocsHmacCheck::Ok => "ok",
            };
            crate::log!(
                "[register-test-issuer] X-Docs-Hmac verification failed: {:?} (ip={})",
                outcome,
                client_ip
            );
            return docs_hmac_401(detail);
        }
    }

    // ---- 3. Parse body ----
    let body: RegisterTestIssuerRequest = match serde_json::from_slice(&body_bytes) {
        Ok(b) => b,
        Err(e) => {
            crate::log!("[register-test-issuer] invalid JSON: {:?}", e);
            return bad_request(
                "body",
                "Request body could not be parsed as JSON or has unknown fields",
            );
        }
    };

    if body.api_key.len() > MAX_API_KEY_LEN {
        return bad_request("api_key", "api_key exceeds maximum length (256 bytes)");
    }
    if let Err(msg) = validate_issuer_label(&body.issuer_label) {
        return bad_request("issuer_label", msg);
    }

    // ---- 4. In-body api_key constant-time check against SANDBOX_API_KEY ----
    //
    // Mirrors provii-verifier's sandbox api_key comparison. Hash both sides
    // to fixed-length SHA-256 digests before ct_eq so the comparison
    // doesn't leak length information.
    {
        use sha2::{Digest as _, Sha256};
        use subtle::ConstantTimeEq as _;

        let supplied = Sha256::digest(body.api_key.as_bytes());
        let expected = Sha256::digest(docs_hmac_key);
        if !bool::from(supplied.as_slice().ct_eq(expected.as_slice())) {
            crate::log!(
                "[register-test-issuer] api_key body field did not match SANDBOX_API_KEY (ip={})",
                client_ip
            );
            return ApiError::Forbidden("Access denied".into()).to_response();
        }
    }

    // ---- 5. Per-IP rate limit (10/hour) ----
    //
    // Use the existing `check_blind_issuance` helper. It's the
    // structurally appropriate primitive on provii-issuer: KV counter with
    // 1-hour bucketing keyed by an arbitrary identifier. We pass a
    // prefixed IP key so our counters stay in their own keyspace, and
    // a fixed limit (the brief specifies 10/hour).
    let rl_kv = match env.kv("ISSUER_RATE_LIMITS") {
        Ok(kv) => kv,
        Err(e) => {
            crate::log_error!(
                "[register-test-issuer] ISSUER_RATE_LIMITS KV unavailable: {:?}",
                e
            );
            return ApiError::ServiceUnavailable("Rate limiting infrastructure unavailable".into())
                .to_response();
        }
    };
    // Hash the IP before using it in the KV key so plaintext
    // addresses are never stored as KV key names.
    let privacy_ctx = crate::audit::build_privacy_context(&env).await;
    let hashed_ip_for_rl = privacy_ctx.hash_ip(&client_ip).unwrap_or_default();
    let rate_key = format!("{}:{}", RATE_LIMIT_PREFIX, hashed_ip_for_rl);
    let rl =
        crate::rate_limiting::check_blind_issuance(&rl_kv, &rate_key, RATE_LIMIT_PER_HOUR).await;
    if !rl.allowed {
        crate::log!(
            "[register-test-issuer] rate limit exceeded for ip_prefix={}",
            hashed_ip_for_rl
        );
        return crate::rate_limiting::rate_limit_or_unavailable_response(&rl);
    }

    // ---- 6. Generate cred material ----
    //
    // hmac_secret: 32 bytes random, returned to caller and stored
    //              encrypted under ISSUER_KEK with AAD "sandbox-cred".
    // client_id:   "cl_iss_sandbox_<12 hex chars>" (random).
    // kid:         "iss_sbx_<8 hex chars>" (random, no user input).
    use zeroize::Zeroizing;

    let mut hmac_secret_raw = Zeroizing::new(vec![0u8; 32]);
    if let Err(e) = getrandom::getrandom(hmac_secret_raw.as_mut_slice()) {
        crate::log_error!(
            "[register-test-issuer] hmac_secret random generation failed: {}",
            e
        );
        return ApiError::Internal("Internal server error".into()).to_response();
    }
    let hmac_secret_b64 = Zeroizing::new(URL_SAFE_NO_PAD.encode(hmac_secret_raw.as_slice()));

    // 6 random bytes -> 12 hex chars for client_id.
    let mut client_suffix = [0u8; 6];
    if let Err(e) = getrandom::getrandom(&mut client_suffix) {
        crate::log_error!(
            "[register-test-issuer] client_id random generation failed: {}",
            e
        );
        return ApiError::Internal("Internal server error".into()).to_response();
    }
    let client_id = format!("cl_iss_sandbox_{}", hex::encode(client_suffix));

    // 4 random bytes -> 8 hex chars for kid.
    let mut kid_suffix = [0u8; 4];
    if let Err(e) = getrandom::getrandom(&mut kid_suffix) {
        crate::log_error!("[register-test-issuer] kid random generation failed: {}", e);
        return ApiError::Internal("Internal server error".into()).to_response();
    }
    let kid = format!("iss_sbx_{}", hex::encode(kid_suffix));

    // ---- 7. Encrypt the hmac_secret under ISSUER_KEK ----
    let kek_pair = match crate::kek::get_kek_pair(&env).await {
        Ok(k) => k,
        Err(e) => {
            crate::log_error!("[register-test-issuer] ISSUER_KEK unavailable: {:?}", e);
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };
    let hmac_secret_encrypted = match storage::encrypt_with_kek(
        &kek_pair.current,
        hmac_secret_raw.as_slice(),
        HMAC_SECRET_AAD,
    ) {
        Ok(c) => c,
        Err(e) => {
            crate::log_error!(
                "[register-test-issuer] hmac_secret encryption failed: {:?}",
                e
            );
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    // ---- 8. Persist as a production-shaped ClientRegistration ----
    //
    // The auth path (session.rs::authenticate_client) reads from
    // ISSUER_CLIENTS at `issuer:{global_kid}:client:{client_id}` and
    // expects the encrypted-HMAC ClientRegistration shape that
    // provii-management writes for production clients. Anything else fails
    // closed with a generic 401 and the dev sees no useful detail.
    let now_sec = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
    let expires_at = now_sec.saturating_add(TTL_SECONDS);

    let issuer_config = match storage::get_issuer_config(&env).await {
        Ok(c) => c,
        Err(e) => {
            crate::log_error!(
                "[register-test-issuer] failed to load issuer config: {:?}",
                e
            );
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };
    let issuer_kid = storage::extract_issuer_kid(&issuer_config.issuer_id).to_string();

    let client_record = crate::types::ClientRegistration {
        client_id: client_id.clone(),
        client_name: body.issuer_label.clone(),
        // X-API-Key is optional on /v1/attestation/create so this stays
        // empty; auth flows by HMAC alone for sandbox-minted creds.
        api_key_hash: Vec::new(),
        hmac_secret: hmac_secret_encrypted,
        // i64 conversion mirrors session.rs:218; saturate rather than wrap
        // if Date::now() overflows i64 sometime around year 292277.
        created_at: i64::try_from(now_sec).unwrap_or(i64::MAX),
        last_used: None,
        rate_limit: 1000,
        allowed_schemas: Vec::new(),
        max_validity_days: 365,
        active: true,
        encrypted: true,
        secret_status: crate::types::KeyStatus::Active,
        previous_hmac_secret: None,
        role: crate::types::Role::Issuer,
        kv_key: None,
    };

    let client_json = match serde_json::to_string(&client_record) {
        Ok(v) => v,
        Err(e) => {
            crate::log_error!(
                "[register-test-issuer] client record serialise failed: {:?}",
                e
            );
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    let clients_kv = match env.kv(crate::bindings::ISSUER_CLIENTS) {
        Ok(kv) => kv,
        Err(e) => {
            crate::log_error!(
                "[register-test-issuer] ISSUER_CLIENTS KV unavailable: {:?}",
                e
            );
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    };

    let client_key = format!("issuer:{}:client:{}", issuer_kid, client_id);
    match clients_kv.put(&client_key, &client_json) {
        Ok(builder) => {
            if let Err(e) = builder.expiration_ttl(TTL_SECONDS).execute().await {
                crate::log_error!("[register-test-issuer] client KV write failed: {:?}", e);
                return ApiError::Internal("Internal server error".into()).to_response();
            }
        }
        Err(e) => {
            crate::log_error!("[register-test-issuer] client KV builder failed: {:?}", e);
            return ApiError::Internal("Internal server error".into()).to_response();
        }
    }

    // Audit log the sandbox credential mint.
    crate::audit::audit_log(
        &env,
        "register_test_issuer",
        &client_ip,
        "Sandbox test issuer credential minted",
        &serde_json::json!({
            "client_id": client_id,
            "kid": kid,
            "action": "sandbox_credential_minted",
            "expires_at": expires_at,
        }),
    )
    .await;

    // Privacy hash of the minting IP, logged only.
    let minted_by_ip_hash = privacy_ctx.hash_ip(&client_ip).unwrap_or_default();
    crate::log!(
        "[register-test-issuer] minted client_id={} kid={} ip_hash={}",
        client_id,
        kid,
        minted_by_ip_hash
    );

    // ---- 9. Build response ----
    let base_url = env
        .var("API_BASE_URL")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "https://sandbox-issuer.provii.app".to_string());

    let response = RegisterTestIssuerResponse {
        client_id,
        // Clone the inner String out of Zeroizing for serialisation.
        // The original Zeroizing wrapper drops at scope end and clears
        // the bytes; the cloned copy lives on inside the response and
        // is freed when the response body is written.
        hmac_secret: (*hmac_secret_b64).clone(),
        kid,
        issuer_label: body.issuer_label,
        expires_at,
        minted_at: now_sec,
        base_url,
    };

    let resp = Response::from_json(&response)?.with_status(201);
    Ok(resp)
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

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
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn validate_issuer_label_accepts_typical_label() {
        assert!(validate_issuer_label("Acme Sandbox").is_ok());
        assert!(validate_issuer_label("Issuer-1").is_ok());
        // 64-byte boundary
        let max = "x".repeat(64);
        assert!(validate_issuer_label(&max).is_ok());
    }

    #[test]
    fn validate_issuer_label_rejects_empty() {
        assert!(validate_issuer_label("").is_err());
    }

    #[test]
    fn validate_issuer_label_rejects_too_long() {
        let over = "x".repeat(65);
        assert!(validate_issuer_label(&over).is_err());
    }

    #[test]
    fn validate_issuer_label_rejects_nul() {
        assert!(validate_issuer_label("a\0b").is_err());
    }

    #[test]
    fn validate_issuer_label_rejects_control_char() {
        assert!(validate_issuer_label("a\nb").is_err());
        assert!(validate_issuer_label("a\tb").is_err());
    }

    #[test]
    fn validate_issuer_label_rejects_non_ascii() {
        assert!(validate_issuer_label("Æ").is_err());
        assert!(validate_issuer_label("issuer-é").is_err());
    }

    #[test]
    fn deny_unknown_fields_on_request_body() {
        let extra = br#"{
            "api_key":"x",
            "issuer_label":"a",
            "ed25519_public_key":"x"
        }"#;
        let parsed: std::result::Result<RegisterTestIssuerRequest, _> =
            serde_json::from_slice(extra);
        assert!(parsed.is_err(), "extra fields must be rejected");
    }

    #[test]
    fn request_body_parses_minimal_valid_input() {
        let body = serde_json::json!({
            "api_key": "key",
            "issuer_label": "Acme",
        })
        .to_string();
        let parsed: RegisterTestIssuerRequest = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.api_key, "key");
        assert_eq!(parsed.issuer_label, "Acme");
    }
}
