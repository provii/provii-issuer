// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Shared KEK (Key Encryption Key) accessor with dual-key rotation support.
//!
//! Replaces the 11+ independent `env.secret_store("ISSUER_KEK")` fetch sites
//! with a single accessor that returns both current and previous KEK values.
//!
//! The decoded KEK pair is cached in a `thread_local` with a 5-minute TTL.
//! A single issuance request triggers 2-3 `get_kek_pair` calls, which
//! without caching produce 4-6 Secrets Store reads per request. With caching,
//! only the first call per 5-minute window hits the Secrets Store.
//!
//! Three specific KEK lifecycle events are emitted to the audit log:
//!
//! 1. `kek_unavailable`, `ISSUER_KEK` Secret Store binding/read failure or
//!    invalid (non-32-byte) decoded value. Severity Error.
//! 2. `kek_bad_encoding`, Optional `ISSUER_KEK_PREVIOUS` is present but has
//!    invalid base64url encoding and is being ignored. Severity Error.
//! 3. `kek_fallback_to_previous`, Decryption with the current KEK failed
//!    and the previous KEK succeeded. Indicates active key rotation.
//!    Severity Warning.
//!
//! These events are scoped to the three rare paths and intentionally do NOT
//! fire on the cache-hit path (which would produce per-request noise).

use crate::error::{ApiError, Result};
use crate::secret_cache::{self, CachedBytePair};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::cell::RefCell;
use worker::Env;
use zeroize::Zeroizing;

// Per-isolate cache for the decoded KEK pair.
thread_local! {
    static KEK_CACHE: RefCell<Option<CachedBytePair>> = const { RefCell::new(None) };
}

// H6: per-isolate cache of the KEK preflight result.
//
// `(available, checked_at_ms)`. A positive result is cached for the full
// `KEK_PREFLIGHT_OK_TTL_MS` (the KEK does not change within an isolate except
// via redeploy, which spins fresh isolates). A negative result is cached for
// only `KEK_PREFLIGHT_FAIL_TTL_MS` so recovery (Secrets Store blip clears, or a
// late-arriving binding) is detected within seconds rather than minutes,
// without re-probing the Secrets Store on every single request during an
// outage.
thread_local! {
    static KEK_PREFLIGHT: RefCell<Option<(bool, f64)>> = const { RefCell::new(None) };
}

/// Positive-result TTL for the KEK preflight cache (5 minutes), matching the
/// underlying decoded-KEK cache.
const KEK_PREFLIGHT_OK_TTL_MS: f64 = 300_000.0;

/// Negative-result TTL for the KEK preflight cache (30 seconds): short so a
/// recovered KEK is picked up quickly, long enough to avoid hammering the
/// Secrets Store on every request during a sustained outage.
const KEK_PREFLIGHT_FAIL_TTL_MS: f64 = 30_000.0;

/// Decide whether a cached preflight result is still fresh enough to serve.
///
/// Pure helper (no clock, no Worker runtime) so the asymmetric TTL policy is
/// unit-tested. `age_ms` is `now - checked_at`. A negative age (clock skew)
/// is treated as stale so a bogus future timestamp can never pin a result.
#[inline]
fn preflight_cache_hit(available: bool, age_ms: f64) -> bool {
    let ttl = if available {
        KEK_PREFLIGHT_OK_TTL_MS
    } else {
        KEK_PREFLIGHT_FAIL_TTL_MS
    };
    (0.0..ttl).contains(&age_ms)
}

/// Test-only reset for the KEK cache.
///
/// Mode B rotation drills hot-reload the underlying ISSUER_KEK and
/// ISSUER_KEK_PREVIOUS bindings without restarting the isolate. This
/// helper drops the cached decoded KEK pair so the next `get_kek_pair`
/// call observes the fresh values within the same test, without sleeping
/// past the 5-minute TTL. Mode B rotation drills call this to observe
/// fresh binding values without waiting for TTL expiry.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn reset_for_testing() {
    KEK_CACHE.with(|c| *c.borrow_mut() = None);
}

/// Test-only reset for the H6 KEK preflight cache.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn reset_preflight_for_testing() {
    KEK_PREFLIGHT.with(|c| *c.borrow_mut() = None);
}

/// Decoded KEK pair: current (required) and previous (optional, for rotation).
pub struct KekPair {
    pub current: Zeroizing<Vec<u8>>,
    pub previous: Option<Zeroizing<Vec<u8>>>,
}

/// Re-export the AES-GCM envelope primitives the KEK module operates
/// over. The `storage` module owns the implementation; re-exposing
/// them here keeps every KEK-related rotation test inside a single
/// publicly-reachable namespace and saves callers from depending on
/// `pub(crate)` internals.
pub use crate::storage::{decrypt_with_kek, encrypt_with_kek};

/// Fetch and decode the KEK pair from Secrets Store, with per-isolate caching.
///
/// `ISSUER_KEK` must be present and valid. `ISSUER_KEK_PREVIOUS` is optional
/// and only present during a key rotation window.
///
/// Returns cached values when available and within the 5-minute TTL.
/// On cache miss or expiry, fetches from the Secrets Store and updates the
/// cache before returning.
pub async fn get_kek_pair(env: &Env) -> Result<KekPair> {
    let (current, previous) =
        secret_cache::get_or_fetch_byte_pair(&KEK_CACHE, || fetch_kek_pair(env)).await?;

    Ok(KekPair { current, previous })
}

/// H6: cheap preflight that confirms the signing KEK (`ISSUER_KEK`) is present,
/// readable, and correctly encoded BEFORE the issuance hot path spends CPU on
/// commitment computation and keypair load.
///
/// Returns `true` when the KEK is usable, `false` otherwise. The result is
/// cached per-isolate (`KEK_PREFLIGHT`): a positive result for 5 minutes, a
/// negative result for 30 seconds (fast recovery, bounded re-probing). Because
/// it delegates to [`get_kek_pair`], a positive probe within the decoded-KEK
/// cache TTL is essentially free and does not add a Secrets Store read on warm
/// isolates.
///
/// On a FRESH negative probe (cache miss or expiry) this emits a `CRITICAL`
/// structured alert to `console_error` so external log monitors fire
/// immediately. This is distinct from, and complementary to, the
/// `kek_unavailable` audit event already emitted inside [`fetch_and_decode_kek`]
/// (which routes to the audit queue): the queue may itself be degraded during
/// an incident, so the console alert is the always-on signal. The alert is
/// emitted only on a fresh probe, never on a cached-negative hit, so a
/// sustained outage does not spam the log.
///
/// Conservatism: this NEVER makes a successful issuance fail. A missing KEK
/// already fails issuance at keypair load today (generic 503); the preflight
/// only surfaces that condition earlier, with a descriptive 503 and a CRITICAL
/// alert. The success path is unchanged.
pub async fn preflight_kek(env: &Env) -> bool {
    let now_ms = worker::js_sys::Date::now();

    // Fast path: serve a cached result while within its TTL.
    let cached = KEK_PREFLIGHT.with(|c| *c.borrow());
    if let Some((available, checked_at)) = cached {
        if preflight_cache_hit(available, now_ms - checked_at) {
            return available;
        }
    }

    // Fresh probe. get_kek_pair reuses the decoded-KEK cache, so a healthy
    // KEK costs nothing extra on a warm isolate.
    let available = get_kek_pair(env).await.is_ok();

    KEK_PREFLIGHT.with(|c| *c.borrow_mut() = Some((available, now_ms)));

    if !available {
        // CRITICAL alert on a fresh negative probe. console_error surfaces in
        // Cloudflare dashboard error filtering even when the audit queue is
        // degraded. No secret material is referenced.
        emit_kek_unavailable_alert();
    }

    available
}

/// Emit the H6 CRITICAL structured alert for an unavailable signing KEK.
///
/// Kept as a separate function so the message shape is consistent and so the
/// non-wasm test build compiles without the `console_error!` macro.
fn emit_kek_unavailable_alert() {
    #[cfg(target_arch = "wasm32")]
    worker::console_error!(
        "{{\"alert\":\"SIGNING_KEK_UNAVAILABLE\",\"severity\":\"critical\",\"service\":\"provii-issuer\",\"message\":\"ISSUER_KEK preflight failed: signing key encryption key is missing, unreadable, or invalid. Blind issuance is returning 503 until the KEK is restored. See kek_unavailable audit events for the specific reason.\"}}"
    );
}

/// Fetch both KEK values from the Secrets Store (uncached).
async fn fetch_kek_pair(env: &Env) -> Result<(Zeroizing<Vec<u8>>, Option<Zeroizing<Vec<u8>>>)> {
    let current = fetch_and_decode_kek(env, "ISSUER_KEK", true)
        .await?
        .ok_or_else(|| {
            ApiError::CryptoError("ISSUER_KEK secret not found in Secrets Store".to_string())
        })?;

    let previous = fetch_and_decode_kek(env, "ISSUER_KEK_PREVIOUS", false).await?;

    Ok((current, previous))
}

/// Fetch a single KEK binding, base64-decode it, and validate length.
///
/// When `required` is true, missing binding or missing secret is an error.
/// When `required` is false, missing binding or secret returns Ok(None).
///
/// Emits `kek_unavailable` when the required KEK is missing/unreadable
/// or has an invalid length, and `kek_bad_encoding` when the optional KEK has
/// invalid base64url encoding.
async fn fetch_and_decode_kek(
    env: &Env,
    binding: &str,
    required: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let store = match env.secret_store(binding) {
        Ok(s) => s,
        Err(e) => {
            if required {
                let msg = format!("{} Secret Store binding not configured: {:?}", binding, e);
                emit_kek_unavailable(env, binding, "binding_not_configured", &msg).await;
                return Err(ApiError::CryptoError(msg));
            }
            return Ok(None);
        }
    };

    let kek_b64 = match store.get().await {
        Ok(Some(v)) => Zeroizing::new(v),
        Ok(None) => {
            if required {
                let msg = format!("{} secret not found in Secrets Store", binding);
                emit_kek_unavailable(env, binding, "secret_not_found", &msg).await;
                return Err(ApiError::CryptoError(msg));
            }
            return Ok(None);
        }
        Err(e) => {
            if required {
                let msg = format!("Failed to get {} from Secrets Store: {:?}", binding, e);
                emit_kek_unavailable(env, binding, "secret_read_failure", &msg).await;
                return Err(ApiError::CryptoError(msg));
            }
            return Ok(None);
        }
    };

    let decoded = match URL_SAFE_NO_PAD.decode(kek_b64.as_bytes()) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) => {
            if required {
                let msg = format!("Invalid {} encoding: {}", binding, e);
                emit_kek_unavailable(env, binding, "invalid_encoding", &msg).await;
                return Err(ApiError::CryptoError(msg));
            }
            // Optional KEK with bad encoding (e.g. placeholder or standard base64
            // instead of base64url), treat as absent rather than failing the request.
            crate::log!("[KEK] Ignoring {} with invalid encoding: {}", binding, e);
            // Emit structured audit event for the ignored bad encoding.
            // Encoded length is the base64 string length; not secret material.
            let encoded_len = kek_b64.len();
            emit_kek_bad_encoding(env, binding, encoded_len, &e.to_string()).await;
            return Ok(None);
        }
    };

    if decoded.len() != 32 {
        let actual_len = decoded.len();
        if required {
            let msg = format!("{} must be 32 bytes, got {}", binding, actual_len);
            emit_kek_unavailable(env, binding, "invalid_length", &msg).await;
            return Err(ApiError::CryptoError(msg));
        }
        // Optional KEK with wrong length, ignore rather than fail.
        crate::log!(
            "[KEK] Ignoring {} with invalid length: {}",
            binding,
            actual_len
        );
        emit_kek_bad_encoding(env, binding, actual_len, "decoded length is not 32 bytes").await;
        return Ok(None);
    }

    Ok(Some(decoded))
}

/// Decrypt with current KEK, falling back to previous KEK if available.
///
/// This supports zero-downtime KEK rotation: data encrypted under the old KEK
/// can still be decrypted while the rotation window is open.
///
/// When the current KEK fails and the previous KEK succeeds, emits a
/// `kek_fallback_to_previous` audit event (Warning) so operators can correlate
/// fallback events with active key rotations. The audit call is best-effort;
/// it never blocks the decrypt result.
pub async fn decrypt_with_kek_fallback(
    env: &Env,
    kek_pair: &KekPair,
    nonce_and_ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    match crate::storage::decrypt_with_kek(&kek_pair.current, nonce_and_ciphertext, aad) {
        Ok(plaintext) => Ok(plaintext),
        Err(primary_err) => match &kek_pair.previous {
            Some(prev_kek) => {
                match crate::storage::decrypt_with_kek(prev_kek, nonce_and_ciphertext, aad) {
                    Ok(plaintext) => {
                        crate::log!(
                            "[KEK] Primary decrypt failed, previous KEK succeeded (rotation window)"
                        );
                        // Fallback succeeded; emit an audit event.
                        // Do NOT include the AAD or ciphertext (could be PII-bound).
                        // primary_err is a CryptoError (typically AEAD tag mismatch).
                        emit_kek_fallback_to_previous(env, &primary_err.to_string()).await;
                        Ok(plaintext)
                    }
                    Err(_) => Err(primary_err),
                }
            }
            None => Err(primary_err),
        },
    }
}

/// Emit a `kek_unavailable` audit event (Error severity).
///
/// `binding` is the Secrets Store binding name (e.g. `ISSUER_KEK`).
/// `reason` is a short machine-readable code.
/// `detail` is a sanitised human-readable error string. MUST NOT contain
/// secret material; the KEK bytes themselves never reach this path.
async fn emit_kek_unavailable(env: &Env, binding: &str, reason: &str, detail: &str) {
    crate::audit::audit_log(
        env,
        "kek_unavailable",
        "system",
        "KEK Secret Store read failed or returned invalid data",
        &serde_json::json!({
            "binding": binding,
            "reason": reason,
            "detail": detail,
        }),
    )
    .await;
}

/// Emit a `kek_bad_encoding` audit event (Error severity).
///
/// Fired when the optional `ISSUER_KEK_PREVIOUS` is present but has invalid
/// base64url encoding or wrong decoded length and is being silently ignored.
/// Lengths are not secret. The KEK bytes themselves never reach this path.
async fn emit_kek_bad_encoding(env: &Env, binding: &str, actual_len: usize, detail: &str) {
    crate::audit::audit_log(
        env,
        "kek_bad_encoding",
        "system",
        "KEK fetched with invalid encoding or length, ignoring",
        &serde_json::json!({
            "binding": binding,
            "expected_decoded_len": 32,
            "actual_len": actual_len,
            "detail": detail,
        }),
    )
    .await;
}

/// Emit a `kek_fallback_to_previous` audit event (Warning severity).
///
/// Fired when the current KEK fails to decrypt and the previous KEK succeeds.
/// `reason` is the sanitised primary-decrypt error (typically AEAD tag mismatch).
/// MUST NOT contain plaintext, AAD, or ciphertext.
async fn emit_kek_fallback_to_previous(env: &Env, reason: &str) {
    crate::audit::audit_log(
        env,
        "kek_fallback_to_previous",
        "system",
        "Decryption fell back from current KEK to previous KEK (rotation window)",
        &serde_json::json!({
            "reason": reason,
        }),
    )
    .await;
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_kek_pair_struct_sizes() {
        // Ensure KekPair can hold 32-byte keys
        let pair = super::KekPair {
            current: zeroize::Zeroizing::new(vec![0u8; 32]),
            previous: Some(zeroize::Zeroizing::new(vec![0u8; 32])),
        };
        assert_eq!(pair.current.len(), 32);
        assert_eq!(pair.previous.as_ref().map(|p| p.len()), Some(32));
    }

    #[test]
    fn test_kek_pair_no_previous() {
        let pair = super::KekPair {
            current: zeroize::Zeroizing::new(vec![0u8; 32]),
            previous: None,
        };
        assert!(pair.previous.is_none());
    }

    // ---- H6: KEK preflight cache policy --------------------------------------

    #[test]
    fn preflight_negative_ttl_shorter_than_positive() {
        // A failed probe must be re-checked sooner than a healthy one so
        // recovery is detected quickly.
        assert!(super::KEK_PREFLIGHT_FAIL_TTL_MS < super::KEK_PREFLIGHT_OK_TTL_MS);
        assert!(super::KEK_PREFLIGHT_FAIL_TTL_MS > 0.0);
    }

    #[test]
    fn preflight_cache_hit_positive_within_ttl() {
        // A healthy result is served right up to (but not at) its TTL.
        assert!(super::preflight_cache_hit(true, 0.0));
        assert!(super::preflight_cache_hit(
            true,
            super::KEK_PREFLIGHT_OK_TTL_MS - 1.0
        ));
        assert!(!super::preflight_cache_hit(
            true,
            super::KEK_PREFLIGHT_OK_TTL_MS
        ));
    }

    #[test]
    fn preflight_cache_hit_negative_expires_on_short_ttl() {
        // A negative result older than the FAIL ttl is stale (forces a
        // re-probe), even though it is younger than the OK ttl.
        let between = (super::KEK_PREFLIGHT_FAIL_TTL_MS + super::KEK_PREFLIGHT_OK_TTL_MS) / 2.0;
        assert!(super::preflight_cache_hit(
            false,
            super::KEK_PREFLIGHT_FAIL_TTL_MS - 1.0
        ));
        assert!(!super::preflight_cache_hit(false, between));
        assert!(!super::preflight_cache_hit(
            false,
            super::KEK_PREFLIGHT_FAIL_TTL_MS
        ));
    }

    #[test]
    fn preflight_cache_hit_negative_age_is_stale() {
        // Clock skew (a future checked_at) must not pin either result.
        assert!(!super::preflight_cache_hit(true, -1.0));
        assert!(!super::preflight_cache_hit(false, -1.0));
    }

    #[test]
    fn preflight_alert_emitter_does_not_panic_on_host() {
        // The CRITICAL alert emitter must be safe to call on the native test
        // target (the console_error! macro is wasm-only and compiled out).
        super::emit_kek_unavailable_alert();
    }
}
