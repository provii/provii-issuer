// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Client authentication helpers and log sanitisation.
//!
//! Submodule of `security`. Contains API-key verification via
//! Argon2id prefix index, alongside prefix rejection and docs-HMAC
//! verification controls.

use crate::error::{ApiError, Result};
use crate::storage;
use crate::types::ClientRegistration;
use worker::Env;

/// Number of leading characters used for the API key prefix index lookup.
///
/// Re-exported from `issuer_logic::redaction`.
const API_KEY_PREFIX_LENGTH: usize = issuer_logic::redaction::API_KEY_PREFIX_LENGTH;

/// DH-001: Truncate a session ID to the first 4 characters plus "..." for log output.
///
/// Delegates to `issuer_logic::redaction::redact_session_id`.
#[inline]
pub fn redact_session_id(session_id: &str) -> String {
    issuer_logic::redaction::redact_session_id(session_id)
}

/// Validates API-key based client authentication.
pub struct ClientAuthVerifier;

impl ClientAuthVerifier {
    /// Look up the client record by API key value.
    ///
    /// SECURITY: Uses Argon2id hash verification via the prefix index in
    /// RATE_LIMIT_CONFIG KV.  Looks up `key_prefix:{first8chars}` and verifies
    /// Argon2id against that single client (~60ms).
    ///
    /// If the prefix index infrastructure is unavailable (KV binding error,
    /// network failure), returns 503 Service Unavailable rather than falling
    /// back to an O(n) scan which would leak client count via timing.
    pub async fn verify_api_key(env: &Env, api_key: &str) -> Result<ClientRegistration> {
        crate::log!("[VERIFY] Starting API key verification");

        let clients_kv = env
            .kv("ISSUER_CLIENTS")
            .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

        // --- Stage 1: prefix index fast path ---
        if api_key.len() >= API_KEY_PREFIX_LENGTH {
            if let Ok(config_kv) = env.kv("RATE_LIMIT_CONFIG") {
                let prefix = api_key.get(..API_KEY_PREFIX_LENGTH).unwrap_or(api_key);
                let prefix_key = format!("key_prefix:{}", prefix);

                match config_kv.get(&prefix_key).text().await {
                    Ok(Some(client_id)) => {
                        // Log only client_id on prefix hit, not the prefix itself.
                        crate::log!("[VERIFY] Prefix index hit for client_id={}", client_id);
                        // Try to verify against this specific client
                        match Self::verify_single_client(env, &clients_kv, &client_id, api_key)
                            .await
                        {
                            Ok(client) => {
                                // Audit successful API key verification.
                                // SECURITY: Never log the actual API key.
                                crate::audit::audit_log(
                                    env,
                                    "api_key_verified",
                                    "unknown",
                                    "API key verification succeeded (prefix index)",
                                    &serde_json::json!({
                                        "client_id": client.client_id,
                                        "method": "prefix_index",
                                    }),
                                )
                                .await;
                                return Ok(client);
                            }
                            Err(_) => {
                                crate::log!(
                                    "[VERIFY] Prefix match but Argon2id failed for client {}",
                                    client_id
                                );
                                // Audit failed API key verification.
                                // SECURITY: Never log the actual API key.
                                crate::audit::audit_log(
                                    env,
                                    "api_key_rejected",
                                    "unknown",
                                    "API key verification failed (prefix match, Argon2id mismatch)",
                                    &serde_json::json!({
                                        "client_id": client_id,
                                        "method": "prefix_index",
                                        "reason": "argon2id_mismatch",
                                    }),
                                )
                                .await;
                                // Could be a prefix collision or stale index.
                                // Fall through to reject (don't scan all clients).
                                return Err(ApiError::Unauthorized("Invalid API key".to_string()));
                            }
                        }
                    }
                    Ok(None) => {
                        // Do not log any key prefix material on miss.
                        crate::log!("[VERIFY] Prefix index miss, rejecting");

                        // CIV-163: Perform dummy Argon2id verification to prevent
                        // timing oracle. Without this, prefix miss returns in ~1ms
                        // while prefix hit + Argon2id mismatch returns in ~62ms,
                        // allowing brute-force of the 8-char prefix.
                        //
                        // H-13: The dummy hash MUST use the same Argon2id parameters
                        // as real hashes (m=65536, t=3, p=4) so that verification
                        // time is indistinguishable from a real prefix-hit mismatch.
                        let dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
                        let _ = crate::hash::verify_api_key("dummy", dummy_hash);

                        // Audit failed API key verification (no prefix match).
                        // SECURITY: Never log the actual API key.
                        crate::audit::audit_log(
                            env,
                            "api_key_rejected",
                            "unknown",
                            "API key verification failed (no prefix index match)",
                            &serde_json::json!({
                                "method": "prefix_index",
                                "reason": "no_prefix_match",
                            }),
                        )
                        .await;
                        return Err(ApiError::Unauthorized("Invalid API key".to_string()));
                    }
                    Err(e) => {
                        crate::log!("[VERIFY] Prefix index KV read failed: {:?}", e);
                        // SECURITY: Do NOT fall back to O(n) scan. The prefix
                        // index is required infrastructure; if it is
                        // unavailable that is a 503, not an auth failure.
                        crate::audit::audit_log(
                            env,
                            "auth_infrastructure_failure",
                            "unknown",
                            "Prefix index KV read failed",
                            &serde_json::json!({
                                "component": "RATE_LIMIT_CONFIG",
                                "error": format!("{:?}", e),
                            }),
                        )
                        .await;
                        return Err(ApiError::ServiceUnavailable(
                            "Authentication infrastructure unavailable".to_string(),
                        ));
                    }
                }
            } else {
                crate::log!("[VERIFY] RATE_LIMIT_CONFIG KV binding unavailable");
                crate::audit::audit_log(
                    env,
                    "auth_infrastructure_failure",
                    "unknown",
                    "RATE_LIMIT_CONFIG KV binding unavailable",
                    &serde_json::json!({
                        "component": "RATE_LIMIT_CONFIG",
                    }),
                )
                .await;
                return Err(ApiError::ServiceUnavailable(
                    "Authentication infrastructure unavailable".to_string(),
                ));
            }
        }

        // API key too short for prefix lookup. Reject.
        Err(ApiError::Unauthorized("Invalid API key".to_string()))
    }

    /// Returns the number of characters used for the API key prefix index.
    pub fn prefix_length() -> usize {
        API_KEY_PREFIX_LENGTH
    }

    /// Verify an API key against a single known client (fast path).
    async fn verify_single_client(
        env: &Env,
        clients_kv: &worker::kv::KvStore,
        client_id: &str,
        api_key: &str,
    ) -> Result<ClientRegistration> {
        // Client KV keys may use different formats; try the client_id directly
        // and also the common pattern of "client:{client_id}"
        let candidates = [client_id.to_string(), format!("client:{}", client_id)];

        for kv_key in &candidates {
            if let Ok(Some(data)) = clients_kv.get(kv_key).text().await {
                match serde_json::from_str::<ClientRegistration>(&data) {
                    Ok(ref client) if !client.active && client.client_id == client_id => {
                        crate::log!(
                            "[VERIFY] Inactive client attempted authentication: {}",
                            client_id
                        );
                        return Err(ApiError::Unauthorized("Invalid API key".to_string()));
                    }
                    Ok(client) if client.active && client.client_id == client_id => {
                        match storage::decrypt_api_key_hash(env, &client.api_key_hash).await {
                            Ok(decrypted_hash_str) => {
                                if crate::hash::verify_api_key(api_key, &decrypted_hash_str) {
                                    crate::log!(
                                        "[SECURITY] API key verified for client: {}",
                                        client.client_id
                                    );
                                    let mut verified_client = client.clone();
                                    verified_client.kv_key = Some(kv_key.clone());
                                    if verified_client.encrypted {
                                        let kek_pair = crate::kek::get_kek_pair(env).await?;
                                        verified_client.hmac_secret =
                                            crate::kek::decrypt_with_kek_fallback(
                                                env,
                                                &kek_pair,
                                                &verified_client.hmac_secret,
                                                b"provii-issuer:session:v1",
                                            )
                                            .await?;
                                        // Validate decrypted HMAC secret is
                                        // the expected size for HMAC-SHA256 (32 bytes).
                                        if verified_client.hmac_secret.len() != 32 {
                                            crate::log!(
                                                "[SECURITY] Decrypted HMAC secret has unexpected length {} for client {}",
                                                verified_client.hmac_secret.len(),
                                                client_id
                                            );
                                            return Err(ApiError::CryptoError(
                                                "HMAC secret has invalid length after decryption"
                                                    .to_string(),
                                            ));
                                        }
                                        if let Some(ref prev) = verified_client.previous_hmac_secret
                                        {
                                            let decrypted_prev =
                                                crate::kek::decrypt_with_kek_fallback(
                                                    env,
                                                    &kek_pair,
                                                    prev,
                                                    b"provii-issuer:session:v1",
                                                )
                                                .await?;
                                            if decrypted_prev.len() != 32 {
                                                crate::log!(
                                                    "[SECURITY] Decrypted previous HMAC secret has unexpected length {} for client {}",
                                                    decrypted_prev.len(),
                                                    client_id
                                                );
                                                return Err(ApiError::CryptoError(
                                                    "Previous HMAC secret has invalid length after decryption".to_string(),
                                                ));
                                            }
                                            verified_client.previous_hmac_secret =
                                                Some(decrypted_prev);
                                        }
                                    }
                                    return Ok(verified_client);
                                }
                            }
                            Err(e) => {
                                crate::log!(
                                    "[VERIFY] Failed to decrypt api_key_hash for {}: {:?}",
                                    client_id,
                                    e
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Err(ApiError::Unauthorized("Invalid API key".to_string()))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    #[test]
    fn redact_session_id_normal() {
        let result = redact_session_id("a1b2c3d4-e5f6-7890");
        assert_eq!(result, "a1b2...");
    }

    #[test]
    fn redact_session_id_empty() {
        assert_eq!(redact_session_id(""), "***");
    }

    #[test]
    fn redact_session_id_one_char() {
        assert_eq!(redact_session_id("x"), "***");
    }

    #[test]
    fn redact_session_id_two_chars() {
        assert_eq!(redact_session_id("ab"), "***");
    }

    #[test]
    fn redact_session_id_three_chars() {
        assert_eq!(redact_session_id("abc"), "***");
    }

    #[test]
    fn redact_session_id_exactly_four() {
        assert_eq!(redact_session_id("abcd"), "abcd...");
    }

    #[test]
    fn redact_session_id_five_chars() {
        assert_eq!(redact_session_id("abcde"), "abcd...");
    }

    #[test]
    fn redact_session_id_full_uuid() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(redact_session_id(uuid), "550e...");
    }

    #[test]
    fn prefix_length_is_eight() {
        assert_eq!(ClientAuthVerifier::prefix_length(), 8);
    }

    #[test]
    fn api_key_prefix_length_constant() {
        assert_eq!(API_KEY_PREFIX_LENGTH, 8);
    }
}
