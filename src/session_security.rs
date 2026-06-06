// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Enhanced session security: CSPRNG IDs, client binding, limits, encryption.
//!
//! **NOT YET WIRED INTO PRODUCTION.** This module is excluded from the build
//! via the commented-out `pub mod session_security;` line in `lib.rs`. It will
//! be re-enabled when session management routes are implemented.
//!
//! This module implements HIGH priority security fixes:
//! - Task #19: 256-bit CSPRNG session IDs
//! - Task #20: Session binding to IP and User-Agent
//! - Task #21: Concurrent session limits
//! - Task #22: Session data encryption at rest

use crate::error::{ApiError, Result};
use crate::storage;
use crate::types::{ActorType, IssuanceSession};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use worker::{Env, Request};

/// Maximum concurrent sessions per user (officer or client).
const MAX_CONCURRENT_SESSIONS: u32 = 5;

/// Generate a cryptographically secure 256-bit session ID.
///
/// **Security Enhancement #19**: Uses Web Crypto API via Workers runtime
/// to generate high-entropy random IDs instead of UUID v4 (128-bit).
///
/// The ID is base64url-encoded for URL safety and stored as a String.
/// This provides ~256 bits of entropy, making session IDs unpredictable.
pub fn generate_secure_session_id() -> Result<String> {
    // Generate 32 bytes (256 bits) of cryptographically secure random data
    let mut bytes = [0u8; 32];

    // Use getrandom crate which uses Web Crypto API in WASM environment
    getrandom::getrandom(&mut bytes)
        .map_err(|e| ApiError::CryptoError(format!("Failed to generate session ID: {}", e)))?;

    // Encode as base64url for URL safety (no padding)
    let session_id = URL_SAFE_NO_PAD.encode(bytes);

    crate::log!("Generated secure 256-bit session ID (entropy: 256 bits)");

    Ok(session_id)
}

/// Extract client IP address from request headers.
/// Checks CF-Connecting-IP (Cloudflare) first, then falls back to X-Forwarded-For.
///
/// On Cloudflare Workers, CF-Connecting-IP is always set by the Cloudflare
/// proxy and cannot be spoofed by clients. The X-Forwarded-For fallback is purely
/// defensive for local development or non-Cloudflare test environments. In production,
/// the first branch always succeeds.
fn extract_client_ip(req: &Request) -> Option<String> {
    // Try Cloudflare's CF-Connecting-IP header first (most reliable)
    if let Ok(Some(ip)) = req.headers().get("CF-Connecting-IP") {
        return Some(ip);
    }

    // Fallback to X-Forwarded-For (take first IP)
    if let Ok(Some(forwarded)) = req.headers().get("X-Forwarded-For") {
        if let Some(first_ip) = forwarded.split(',').next() {
            return Some(first_ip.trim().to_string());
        }
    }

    None
}

/// Extract User-Agent from request headers.
/// Sanitizes CRLF characters to prevent log injection and potential header injection.
fn extract_user_agent(req: &Request) -> Option<String> {
    if let Ok(Some(ua)) = req.headers().get("User-Agent") {
        // Truncate to reasonable length to prevent DoS
        let truncated = if ua.len() <= 500 {
            ua
        } else {
            ua.chars().take(500).collect()
        };

        // OWASP ASVS 1.3.10: sanitise CRLF to prevent log injection (CWE-113)
        let sanitized = truncated.replace(['\r', '\n'], "");
        return Some(sanitized);
    }

    None
}

/// Session binding mode configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionBindingMode {
    /// Strict mode: Both IP and User-Agent must match (default).
    Strict,
    /// Relaxed mode: Log warnings but allow mismatches (for mobile/VPN scenarios).
    Relaxed,
}

impl SessionBindingMode {
    /// Get binding mode from environment variable.
    pub fn from_env(env: &Env) -> Self {
        match env.var("BIND_SESSIONS_TO_CLIENT") {
            Ok(val) => {
                let value = val.to_string().to_lowercase();
                if value == "false" || value == "relaxed" {
                    crate::log!("Session binding mode: Relaxed (warnings only)");
                    SessionBindingMode::Relaxed
                } else {
                    crate::log!("Session binding mode: Strict (enforced)");
                    SessionBindingMode::Strict
                }
            }
            Err(_) => {
                crate::log!("Session binding mode: Strict (default)");
                SessionBindingMode::Strict
            }
        }
    }
}

/// Client binding information extracted from request.
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientBinding {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

impl std::fmt::Debug for ClientBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientBinding")
            .field("ip", &self.ip.as_ref().map(|_| "[REDACTED]"))
            .field(
                "user_agent",
                &self.user_agent.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl ClientBinding {
    /// Extract client binding from request headers.
    pub fn from_request(req: &Request) -> Self {
        ClientBinding {
            ip: extract_client_ip(req),
            user_agent: extract_user_agent(req),
        }
    }

    /// Check if binding matches the session's stored binding, with audit logging.
    ///
    /// Session binding violations are audited as Critical SecurityEvents.
    /// Call this instead of [`matches`] when an `&Env` is available.
    ///
    /// All IP addresses in log messages and audit details are hashed
    /// via `PrivacyContext` before output.
    pub async fn matches_audited(
        &self,
        session: &IssuanceSession,
        mode: SessionBindingMode,
        env: &Env,
        client_ip: &str,
    ) -> bool {
        let privacy = crate::audit::build_privacy_context(env).await;
        let result = self.matches_with_privacy(session, mode, Some(&privacy));
        if !result && mode == SessionBindingMode::Strict {
            // Audit session binding violation as Critical SecurityEvent.
            // session.client_ip is already a HashedIp; hash the
            // incoming raw IP for comparison in the audit record.
            let expected_ip_hash = session.client_ip.as_ref().map(|h| h.as_str().to_string());
            let actual_ip_hash = self.ip.as_deref().map(|ip| privacy.hash_ip(ip).ok());

            // Determine UA mismatch by hashing the incoming raw UA
            // and comparing to the stored hash.
            let ua_mismatch = match (&self.user_agent, &session.user_agent) {
                (Some(req_ua), Some(sess_hash)) => {
                    privacy.hash_user_agent(req_ua) != sess_hash.as_str()
                }
                (None, None) => false,
                _ => true,
            };

            crate::audit::audit_log_detailed(
                env,
                "session_ownership_violation",
                client_ip,
                "Session binding violation detected (IP or User-Agent mismatch)",
                &serde_json::json!({
                    "session_id": crate::security::redact_session_id(&session.session_id),
                    "expected_ip_hash": expected_ip_hash,
                    "actual_ip_hash": actual_ip_hash,
                    "ua_mismatch": ua_mismatch,
                }),
                crate::audit::DetailedAuditFields {
                    event_category: provii_audit::EventCategory::SecurityEvent,
                    actor_id: session
                        .officer_id
                        .as_deref()
                        .or(session.client_id.as_deref())
                        .unwrap_or("unknown"),
                    outcome: Some(crate::audit::Outcome::Denied),
                    severity: Some(provii_audit::Severity::Critical),
                },
            )
            .await;
        }
        result
    }

    /// Check if binding matches the session's stored binding.
    ///
    /// **Security Enhancement #20**: Binds sessions to client characteristics
    /// to prevent session hijacking/fixation attacks.
    ///
    /// This convenience method delegates to [`matches_with_privacy`] without
    /// a `PrivacyContext`. IP addresses in log messages will be redacted.
    /// Prefer [`matches_audited`] when an `&Env` is available.
    pub fn matches(&self, session: &IssuanceSession, mode: SessionBindingMode) -> bool {
        self.matches_with_privacy(session, mode, None)
    }

    /// Check if binding matches the session's stored binding, with optional
    /// IP hashing for log messages.
    ///
    /// When a `PrivacyContext` is provided, IP addresses in log
    /// messages are hashed before output. When `None`, IPs are redacted as
    /// `[REDACTED]` to avoid leaking raw addresses.
    pub fn matches_with_privacy(
        &self,
        session: &IssuanceSession,
        mode: SessionBindingMode,
        privacy: Option<&provii_audit::PrivacyContext>,
    ) -> bool {
        use subtle::ConstantTimeEq;

        // session.client_ip is HashedIp. Hash the incoming raw IP
        // through PrivacyContext before comparison. Without a context we
        // cannot hash, so treat as mismatch when both values are present.
        //
        // Use constant-time comparison on the IP hash to prevent
        // timing side-channels that could leak session ownership.
        let ip_matches = match (&self.ip, &session.client_ip) {
            (Some(req_ip), Some(sess_hash)) => {
                if let Some(ctx) = privacy {
                    let req_hash = ctx.hash_ip(req_ip).unwrap_or_default();
                    bool::from(req_hash.as_bytes().ct_eq(sess_hash.as_str().as_bytes()))
                } else {
                    false // Cannot verify without PrivacyContext
                }
            }
            (None, None) => true, // Both missing - allow
            _ => false,           // Mismatch
        };

        // session.user_agent is now HashedUserAgent. Hash the
        // incoming raw UA through PrivacyContext and compare with constant-time
        // equality, mirroring the IP comparison pattern above.
        let ua_matches = match (&self.user_agent, &session.user_agent) {
            (Some(req_ua), Some(sess_hash)) => {
                if let Some(ctx) = privacy {
                    let req_hash = ctx.hash_user_agent(req_ua);
                    bool::from(req_hash.as_bytes().ct_eq(sess_hash.as_str().as_bytes()))
                } else {
                    false // Cannot verify without PrivacyContext
                }
            }
            (None, None) => true, // Both missing - allow
            _ => false,           // Mismatch
        };

        // Hash or redact IPs for log messages.
        // Session IP is already hashed; incoming IP needs hashing.
        let stored_hash = || -> String {
            session
                .client_ip
                .as_ref()
                .map(|h| h.as_str().to_string())
                .unwrap_or_else(|| "None".to_string())
        };
        let incoming_hash = || -> String {
            match (&self.ip, privacy) {
                (Some(raw), Some(ctx)) => ctx.hash_ip(raw).unwrap_or_default(),
                (Some(_), None) => "[REDACTED]".to_string(),
                (None, _) => "None".to_string(),
            }
        };

        match mode {
            SessionBindingMode::Strict => {
                if !ip_matches {
                    crate::log_error!(
                        "Session {} binding violation: IP mismatch (expected_hash: {}, got_hash: {})",
                        crate::security::redact_session_id(&session.session_id),
                        stored_hash(),
                        incoming_hash()
                    );
                }
                if !ua_matches {
                    crate::log_error!(
                        "Session {} binding violation: User-Agent mismatch",
                        crate::security::redact_session_id(&session.session_id)
                    );
                }
                ip_matches && ua_matches
            }
            SessionBindingMode::Relaxed => {
                if !ip_matches {
                    crate::log!(
                        "Session {} binding warning: IP changed (expected_hash: {}, got_hash: {})",
                        crate::security::redact_session_id(&session.session_id),
                        stored_hash(),
                        incoming_hash()
                    );
                }
                if !ua_matches {
                    crate::log!(
                        "Session {} binding warning: User-Agent changed",
                        crate::security::redact_session_id(&session.session_id)
                    );
                }
                true // Allow but log
            }
        }
    }
}

/// Active session tracking entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSessionEntry {
    pub session_id: String,
    pub created_at: i64,
}

/// Manage concurrent session limits per user.
///
/// **Security Enhancement #21**: Prevents resource exhaustion and
/// credential farming by limiting active sessions per user.
pub struct SessionLimitManager<'a> {
    env: &'a Env,
}

impl<'a> SessionLimitManager<'a> {
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }

    /// Get the KV key for tracking active sessions.
    fn get_active_sessions_key(&self, actor: &ActorType, actor_id: &str) -> String {
        match actor {
            ActorType::Officer => format!("active_sessions:officer:{}", actor_id),
            ActorType::Client => format!("active_sessions:client:{}", actor_id),
        }
    }

    /// Get list of active sessions for a user.
    pub async fn get_active_sessions(
        &self,
        actor: &ActorType,
        actor_id: &str,
    ) -> Result<Vec<ActiveSessionEntry>> {
        let kv = self
            .env
            .kv("ISSUER_SESSIONS")
            .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

        let key = self.get_active_sessions_key(actor, actor_id);

        match kv.get(&key).text().await {
            Ok(Some(data)) => {
                let sessions: Vec<ActiveSessionEntry> = serde_json::from_str(&data)?;
                Ok(sessions)
            }
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(ApiError::StorageError(format!(
                "Failed to get active sessions: {}",
                e
            ))),
        }
    }

    /// Add a new active session, enforcing the limit.
    ///
    /// If limit is exceeded, deletes the oldest session (LRU eviction).
    ///
    /// Session creation is serialised per actor via ResourceLockDO to
    /// prevent TOCTOU races where two concurrent requests both read a count
    /// below MAX_CONCURRENT_SESSIONS and both proceed to add sessions.
    pub async fn add_active_session(
        &self,
        actor: &ActorType,
        actor_id: &str,
        session_id: &str,
    ) -> Result<()> {
        let lock_key = format!(
            "session_limit:{}:{}",
            match actor {
                ActorType::Officer => "officer",
                ActorType::Client => "client",
            },
            actor_id
        );

        let lock_token = crate::resource_lock::acquire_resource_lock(self.env, &lock_key).await?;

        let result = self
            .add_active_session_inner(actor, actor_id, session_id)
            .await;

        crate::resource_lock::release_resource_lock(self.env, &lock_key, &lock_token).await;

        result
    }

    /// Inner implementation of session addition (runs under DO lock).
    async fn add_active_session_inner(
        &self,
        actor: &ActorType,
        actor_id: &str,
        session_id: &str,
    ) -> Result<()> {
        let mut sessions = self.get_active_sessions(actor, actor_id).await?;

        // Check if limit exceeded
        if sessions.len() >= MAX_CONCURRENT_SESSIONS as usize {
            // Sort by created_at (oldest first)
            sessions.sort_by_key(|s| s.created_at);

            // Evict oldest session
            if let Some(oldest) = sessions.first() {
                crate::log!(
                    "Session limit exceeded for {} {}: Evicting oldest session {}",
                    match actor {
                        ActorType::Officer => "officer",
                        ActorType::Client => "client",
                    },
                    actor_id,
                    crate::security::redact_session_id(&oldest.session_id)
                );

                // Delete the oldest session from KV (best-effort).
                // If the delete fails, the orphaned session will expire
                // via its KV TTL. We log a warning rather than propagating the error
                // to avoid blocking new session creation on cleanup failures.
                let session_key = format!("session:{}", oldest.session_id);
                let kv = self.env.kv("ISSUER_SESSIONS").map_err(|e| {
                    ApiError::StorageError(format!("Failed to get KV namespace: {}", e))
                })?;
                if let Err(e) = kv.delete(&session_key).await {
                    crate::log!(
                        "[SESSION] Failed to evict session {}; orphan will expire via TTL: {:?}",
                        crate::security::redact_session_id(&oldest.session_id),
                        e
                    );
                }

                // Remove from tracking list
                sessions.remove(0);
            }
        }

        // Add new session
        sessions.push(ActiveSessionEntry {
            session_id: session_id.to_string(),
            created_at: chrono::Utc::now().timestamp(),
        });

        // Store updated list
        let kv = self
            .env
            .kv("ISSUER_SESSIONS")
            .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

        let key = self.get_active_sessions_key(actor, actor_id);
        let value = serde_json::to_string(&sessions)?;

        kv.put(&key, value)
            .map_err(|e| ApiError::StorageError(format!("Failed to store active sessions: {}", e)))?
            .expiration_ttl(7200) // 2 hours (longer than session max lifetime)
            .execute()
            .await
            .map_err(|e| ApiError::StorageError(format!("Failed to execute KV put: {}", e)))?;

        crate::log!(
            "Added session {} to active sessions for {} {} (count: {})",
            crate::security::redact_session_id(session_id),
            match actor {
                ActorType::Officer => "officer",
                ActorType::Client => "client",
            },
            actor_id,
            sessions.len()
        );

        Ok(())
    }

    /// Remove all active sessions for a user. Used by the "revoke all
    /// sessions" endpoint to clear the tracking list in one operation
    /// rather than passing an empty session_id to `remove_active_session`.
    pub async fn clear_all_active_sessions(&self, actor: &ActorType, actor_id: &str) -> Result<()> {
        let kv = self
            .env
            .kv("ISSUER_SESSIONS")
            .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

        let key = self.get_active_sessions_key(actor, actor_id);
        kv.delete(&key).await.map_err(|e| {
            ApiError::StorageError(format!("Failed to delete active sessions key: {}", e))
        })?;

        crate::log!(
            "Cleared all active sessions for {} {}",
            match actor {
                ActorType::Officer => "officer",
                ActorType::Client => "client",
            },
            actor_id
        );

        Ok(())
    }

    /// Remove a session from active session tracking.
    pub async fn remove_active_session(
        &self,
        actor: &ActorType,
        actor_id: &str,
        session_id: &str,
    ) -> Result<()> {
        // KV-105: Guard against empty session_id. Filtering by "" would
        // retain every entry since no real session has an empty ID.
        if session_id.is_empty() {
            return Err(ApiError::BadRequest(
                "session_id must not be empty".to_string(),
            ));
        }

        let mut sessions = self.get_active_sessions(actor, actor_id).await?;

        // Remove the session
        sessions.retain(|s| s.session_id != session_id);

        // Store updated list
        let kv = self
            .env
            .kv("ISSUER_SESSIONS")
            .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

        let key = self.get_active_sessions_key(actor, actor_id);

        if sessions.is_empty() {
            // Delete the key if no sessions left
            kv.delete(&key).await.map_err(|e| {
                ApiError::StorageError(format!("Failed to delete active sessions: {}", e))
            })?;
        } else {
            let value = serde_json::to_string(&sessions)?;

            kv.put(&key, value)
                .map_err(|e| {
                    ApiError::StorageError(format!("Failed to store active sessions: {}", e))
                })?
                .expiration_ttl(7200)
                .execute()
                .await
                .map_err(|e| ApiError::StorageError(format!("Failed to execute KV put: {}", e)))?;
        }

        crate::log!(
            "Removed session {} from active sessions for {} {}",
            crate::security::redact_session_id(session_id),
            match actor {
                ActorType::Officer => "officer",
                ActorType::Client => "client",
            },
            actor_id
        );

        Ok(())
    }
}

/// Encrypt session data using AES-256-GCM with KEK from Secrets Store.
///
/// **Security Enhancement #22**: Encrypts session data at rest in KV
/// to protect against KV storage compromise.
///
/// Always encrypts with the current KEK.
pub async fn encrypt_session_data(env: &Env, session_json: &str) -> Result<Vec<u8>> {
    let kek_pair = crate::kek::get_kek_pair(env).await?;
    storage::encrypt_with_kek(
        &kek_pair.current,
        session_json.as_bytes(),
        b"provii-issuer:session:v1",
    )
}

/// Decrypt session data using AES-256-GCM with KEK from Secrets Store.
///
/// Tries the current KEK first, then falls back to the previous KEK
/// during a key rotation window.
pub async fn decrypt_session_data(env: &Env, encrypted_data: &[u8]) -> Result<String> {
    let kek_pair = crate::kek::get_kek_pair(env).await?;
    let decrypted = crate::kek::decrypt_with_kek_fallback(
        env,
        &kek_pair,
        encrypted_data,
        b"provii-issuer:session:v1",
    )
    .await?;

    String::from_utf8(decrypted)
        .map_err(|e| ApiError::CryptoError(format!("Invalid UTF-8 in session data: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secure_session_id_length(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let session_id = generate_secure_session_id()?;
        // 32 bytes base64url-encoded = 43 characters (no padding)
        assert_eq!(session_id.len(), 43);
        Ok(())
    }

    #[test]
    fn test_generate_secure_session_id_uniqueness(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut ids = std::collections::HashSet::new();
        for _ in 0..1000 {
            ids.insert(generate_secure_session_id()?);
        }
        // Should have 1000 unique IDs
        assert_eq!(ids.len(), 1000);
        Ok(())
    }

    #[test]
    fn test_generate_secure_session_id_base64url_safe(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let session_id = generate_secure_session_id()?;
        // Should only contain base64url characters (no +, /, =)
        assert!(session_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
        Ok(())
    }

    #[test]
    fn test_session_binding_mode_from_env_default() {
        // Test would need mocked Env
        // In production: Default is Strict
    }

    /// Build a test PrivacyContext with a fixed salt.
    fn test_privacy(
    ) -> std::result::Result<provii_audit::PrivacyContext, Box<dyn std::error::Error>> {
        Ok(provii_audit::PrivacyContext::new(
            b"test-salt-minimum-32-bytes-long!!".to_vec(),
        )?)
    }

    #[test]
    fn test_client_binding_matches_strict() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let ctx = test_privacy()?;
        // Store the hashed IP in the session.
        let hashed_ip = crate::types::HashedIp::new(ctx.hash_ip("192.168.1.1").unwrap_or_default());
        // Store the hashed UA in the session.
        let hashed_ua = crate::types::HashedUserAgent::new(ctx.hash_user_agent("Mozilla/5.0"));

        let session = IssuanceSession {
            session_id: "test-session-id".to_string(),
            created_at: 0,
            expires_at: 0,
            actor: ActorType::Officer,
            kid: "test".to_string(),
            schema: "test".to_string(),
            iat: 0,
            exp: 0,
            signatures_issued: 0,
            status: crate::types::SessionStatus::Authenticated,
            officer_id: Some("officer-1".to_string()),
            client_id: None,
            absolute_expiry: 0,
            client_ip: Some(hashed_ip),
            user_agent: Some(hashed_ua),
        };

        // Matching binding (raw IP and UA that hash to the same values)
        let binding = ClientBinding {
            ip: Some("192.168.1.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
        };

        assert!(binding.matches_with_privacy(&session, SessionBindingMode::Strict, Some(&ctx)));
        Ok(())
    }

    #[test]
    fn test_client_binding_mismatch_strict() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let ctx = test_privacy()?;
        let hashed_ip = crate::types::HashedIp::new(ctx.hash_ip("192.168.1.1").unwrap_or_default());
        let hashed_ua = crate::types::HashedUserAgent::new(ctx.hash_user_agent("Mozilla/5.0"));

        let session = IssuanceSession {
            session_id: "test-session-id".to_string(),
            created_at: 0,
            expires_at: 0,
            actor: ActorType::Officer,
            kid: "test".to_string(),
            schema: "test".to_string(),
            iat: 0,
            exp: 0,
            signatures_issued: 0,
            status: crate::types::SessionStatus::Authenticated,
            officer_id: Some("officer-1".to_string()),
            client_id: None,
            absolute_expiry: 0,
            client_ip: Some(hashed_ip),
            user_agent: Some(hashed_ua),
        };

        // Different IP
        let binding = ClientBinding {
            ip: Some("192.168.1.2".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
        };

        assert!(!binding.matches_with_privacy(&session, SessionBindingMode::Strict, Some(&ctx)));
        Ok(())
    }

    #[test]
    fn test_client_binding_mismatch_relaxed() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let ctx = test_privacy()?;
        let hashed_ip = crate::types::HashedIp::new(ctx.hash_ip("192.168.1.1").unwrap_or_default());
        let hashed_ua = crate::types::HashedUserAgent::new(ctx.hash_user_agent("Mozilla/5.0"));

        let session = IssuanceSession {
            session_id: "test-session-id".to_string(),
            created_at: 0,
            expires_at: 0,
            actor: ActorType::Officer,
            kid: "test".to_string(),
            schema: "test".to_string(),
            iat: 0,
            exp: 0,
            signatures_issued: 0,
            status: crate::types::SessionStatus::Authenticated,
            officer_id: Some("officer-1".to_string()),
            client_id: None,
            absolute_expiry: 0,
            client_ip: Some(hashed_ip),
            user_agent: Some(hashed_ua),
        };

        // Different IP but relaxed mode allows it
        let binding = ClientBinding {
            ip: Some("192.168.1.2".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
        };

        assert!(binding.matches_with_privacy(&session, SessionBindingMode::Relaxed, Some(&ctx)));
        Ok(())
    }
}
