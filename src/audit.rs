// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Audit logging module backed by the shared `provii-audit` crate (v0.5.0).
//!
//! Provides a per-request `audit_log()` function that constructs a
//! `provii_audit::AuditLogger` from the Worker environment bindings and
//! dispatches events to a Cloudflare Queue for async processing into D1.
//!
//! Uses `AuditParams` (named parameters) and `log_event_best_effort()`
//! from provii-audit v0.5.0. The raw client IP is hashed internally by
//! the logger via `PrivacyContext` before any output (console or sink).

use std::cell::RefCell;
use std::sync::{Arc, OnceLock};

#[cfg(target_arch = "wasm32")]
use provii_audit::sinks::queue::QueueAuditSink;
use provii_audit::sinks::AuditSink;
// Re-export Outcome so callers can construct typed outcome values.
pub use provii_audit::Outcome;
use provii_audit::{
    AuditLogger, AuditParams, Environment, EventCategory, PrivacyContext, Severity,
};
use worker::Env;

thread_local! {
    static CACHED_LOGGER: RefCell<Option<AuditLogger>> = const { RefCell::new(None) };
}

/// Retrieve the cached logger or build a fresh one from the environment.
///
/// The logger is cached per-isolate (thread_local) so that multiple
/// audit_log() calls within a single request reuse the same instance.
async fn get_or_build_logger(env: &Env) -> AuditLogger {
    let cached = CACHED_LOGGER.with(|c| c.borrow().clone());
    if let Some(logger) = cached {
        return logger;
    }
    let logger = build_logger(env).await;
    CACHED_LOGGER.with(|c| *c.borrow_mut() = Some(logger.clone()));
    logger
}

/// Per-isolate cache for the IP hash salt bytes.
///
/// `resolve_ip_hash_salt` reads from the Secrets Store on every call. Since
/// the salt does not change within a single Worker isolate lifetime, we cache
/// the resolved bytes in a `OnceLock` and reuse them for every subsequent
/// `build_logger` / `build_privacy_context` invocation.
static CACHED_IP_HASH_SALT: OnceLock<Vec<u8>> = OnceLock::new();

/// Construct a `PrivacyContext` with a hardcoded non-zero 32-byte salt.
///
/// This is the absolute last-resort fallback when both the Secrets Store
/// salt and an ephemeral `getrandom` salt have failed `PrivacyContext`
/// validation (which is mathematically impossible for 32-byte non-zero
/// input, but the type system cannot encode that guarantee).
///
/// The hardcoded salt `[0x01; 32]` provably satisfies both validation
/// checks in `PrivacyContext::new`: length >= 32 and not all zeros.
/// The `#[allow]` is scoped to this single function to keep the rest
/// of the crate under `deny(clippy::unwrap_used)`.
#[allow(clippy::unwrap_used)]
fn hardcoded_fallback_privacy_context() -> PrivacyContext {
    // SAFETY INVARIANT: vec![0x01; 32] is exactly 32 bytes and contains
    // no zero bytes. PrivacyContext::new rejects only (a) salt < 32 bytes
    // or (b) all-zero salt. Neither condition can hold here.
    PrivacyContext::new(vec![0x01; 32]).unwrap()
}

/// Generate a random 32-byte ephemeral salt for degraded-mode IP hashing.
///
/// Used when the Secrets Store binding is unavailable or the stored salt
/// is too short. IP hashes remain privacy-preserving but will not
/// correlate across cold starts.
fn generate_ephemeral_salt() -> Vec<u8> {
    let mut ephemeral = vec![0u8; 32];
    if getrandom::getrandom(&mut ephemeral).is_err() {
        // getrandom should never fail in a WASM/Workers environment, but
        // if it does, set a single non-zero byte so the salt passes the
        // all-zeros check. This is the absolute last resort.
        if let Some(first) = ephemeral.first_mut() {
            *first = 0x01;
        }
    }

    // Structured alert for degraded IP hashing.
    #[cfg(target_arch = "wasm32")]
    worker::console_log!(
        "{{\"alert\":\"DEGRADED_IP_HASH_SALT\",\"severity\":\"warning\",\"service\":\"provii-issuer\",\"message\":\"ISSUER_IP_HASH_SALT missing or too short. Using ephemeral random salt; IP hashes will not correlate across cold starts.\"}}"
    );

    ephemeral
}

/// Resolve the IP hash salt from the Worker environment.
///
/// Reads `ISSUER_IP_HASH_SALT` from the Secrets Store (async binding).
/// If the secret is missing or shorter than 32 bytes, generates a random
/// 32-byte ephemeral salt via `getrandom` and emits a structured warning
/// alert.
///
/// An ephemeral random salt means IP hashes are still privacy-preserving
/// (non-reversible) but will not correlate across cold starts. This is
/// acceptable as a degraded fallback; production MUST configure the real
/// salt for consistent audit correlation.
async fn resolve_ip_hash_salt(env: &Env) -> Vec<u8> {
    // Return cached salt if already resolved for this isolate.
    if let Some(cached) = CACHED_IP_HASH_SALT.get() {
        return cached.clone();
    }

    let salt = match env.secret_store("ISSUER_IP_HASH_SALT") {
        Ok(store) => match store.get().await {
            Ok(Some(val)) => {
                let bytes = val.into_bytes();
                if bytes.len() >= 32 {
                    bytes
                } else {
                    generate_ephemeral_salt()
                }
            }
            _ => generate_ephemeral_salt(),
        },
        Err(_) => generate_ephemeral_salt(),
    };

    // Cache for the lifetime of this isolate. If another call raced us,
    // the OnceLock guarantees only one value is stored; we return
    // whichever won.
    let _ = CACHED_IP_HASH_SALT.set(salt.clone());
    salt
}

/// Construct an `AuditLogger` from the Cloudflare Worker environment.
///
/// Reads the Queue binding and IP hash salt secret. Falls back gracefully
/// if bindings are absent (console-only logging).
///
/// ## Alerts
///
/// - If `AUDIT_QUEUE` binding is unavailable, emits a structured JSON
///   alert at `critical` severity so external log monitors can fire.
/// - If `ISSUER_IP_HASH_SALT` is missing or too short, an ephemeral
///   random salt is used. See [`resolve_ip_hash_salt`].
async fn build_logger(env: &Env) -> AuditLogger {
    let privacy = {
        let salt_bytes = resolve_ip_hash_salt(env).await;
        Arc::new(match PrivacyContext::new(salt_bytes) {
            Ok(ctx) => ctx,
            Err(_e) => {
                // Last-resort fallback: use an ephemeral salt so audit logging
                // never panics in library code.
                #[cfg(target_arch = "wasm32")]
                worker::console_log!(
                    "{{\"alert\":\"PRIVACY_CONTEXT_CREATION_FAILED\",\"severity\":\"error\",\"service\":\"provii-issuer\",\"message\":\"{}\"}}", _e
                );
                PrivacyContext::new(generate_ephemeral_salt())
                    .unwrap_or_else(|_| hardcoded_fallback_privacy_context())
            }
        })
    };

    // Build sink: Queue-based (replaces KV + DO composite).
    //
    // When the AUDIT_QUEUE binding is unavailable, ALL security
    // events degrade to console-only logging and are effectively lost for
    // post-incident analysis. The structured alert below is logged at error
    // level (via console_error! on WASM) so that external log monitors can
    // detect the outage. A metric counter is emitted via the analytics
    // engine if the binding is available.
    //
    // `QueueAuditSink::new` only exists on `wasm32` because the underlying
    // `worker::Queue` send pipeline is wasm-only. Native test builds reach
    // this code via `cargo test --target x86_64-...` and skip the sink
    // entirely; logger output degrades to console-only there, which is the
    // same fallback path the runtime already takes when the binding is
    // missing.
    #[cfg(target_arch = "wasm32")]
    let sink: Option<Arc<dyn AuditSink>> = match env.queue("AUDIT_QUEUE") {
        Ok(queue) => Some(Arc::new(QueueAuditSink::new(queue)) as Arc<dyn AuditSink>),
        Err(e) => {
            // Structured alert at ERROR level for audit
            // queue binding failure. console_error! ensures this is visible in
            // Cloudflare dashboard error filtering, not just informational logs.
            worker::console_error!(
                "{{\"alert\":\"AUDIT_QUEUE_BINDING_FAILURE\",\"severity\":\"critical\",\"service\":\"provii-issuer\",\"message\":\"Audit queue unavailable, falling back to console-only logging. ALL security audit events will be lost during this outage.\",\"error\":\"{}\"}}", e
            );

            // Emit metric counter for audit queue failures so the
            // degradation is visible in monitoring dashboards beyond log search.
            if let Ok(dataset) = env.analytics_engine("ISSUER_ANALYTICS") {
                let point = worker::AnalyticsEngineDataPointBuilder::new()
                    .indexes(["audit_queue_failure"])
                    .blobs(["AUDIT_QUEUE_BINDING_FAILURE"])
                    .doubles([1.0])
                    .build();
                let _ = dataset.write_data_point(&point);
            }

            None
        }
    };
    #[cfg(not(target_arch = "wasm32"))]
    let sink: Option<Arc<dyn AuditSink>> = {
        let _ = env;
        None
    };

    AuditLogger::new(sink, privacy, "provii-issuer")
}

/// Map an event type to a severity level for the audit log entry.
///
/// This mapping is intentionally conservative: unknown event types default
/// to `Info` rather than `Debug` so they are not silently de-prioritised.
fn classify_severity(event_type: &str) -> Severity {
    match event_type {
        // SECURITY: Key rotation is a Critical event. A compromised admin key
        // allows an attacker to rotate signing keys and issue fraudulent credentials.
        "replay_attempt" | "signing_key_rotated" | "signing_key_disabled" => Severity::Critical,
        // Self-verification failure after signing is Critical.
        "self_verification_failed" => Severity::Critical,
        // Invalid worker identity: potential spoofing or misconfiguration.
        "invalid_worker_identity" => Severity::Error,
        "account_locked" => Severity::Error,
        // KEK rotation failures are Error severity.
        "kek_rotation_start_failed" | "kek_rotation_complete_failed" => Severity::Error,
        // KEK availability/encoding failures are Error severity.
        "kek_unavailable" | "kek_bad_encoding" => Severity::Error,
        // Fallback to previous KEK indicates active key rotation.
        "kek_fallback_to_previous" => Severity::Warning,
        "authentication_failed"
        | "rate_limit_exceeded"
        | "issuance_start_failed"
        | "blind_issuance_failure"
        | "blind_issuance_rejected"
        | "attestation_create_rejected"
        | "attestation_child_rejected"
        // M3: per-issuer nonce-consumption tripwire (advisory, not enforced).
        | "attestation_nonce_rate_exceeded"
        | "internal_error"
        | "admin_auth_failed"
        | "blind_issuance_issuer_mismatch"
        | "blind_issuance_unknown_issuer"
        | "blind_issuance_verification_failed"
        | "session_ownership_violation" => Severity::Warning,
        // KEK rotation success events.
        "kek_rotation_started" | "kek_rotation_completed" => Severity::Info,
        // Credential signing success.
        "credential_signed" => Severity::Info,
        // KV access control log events.
        "kv_access" => Severity::Info,
        "issuer_config_accessed" => Severity::Info,
        _ => Severity::Info,
    }
}

/// Map an event type to an `EventCategory`.
///
/// This provides a coarse classification for filtering, alerting, and
/// compliance reporting. Defaults to `SecurityEvent` for unknown types.
fn classify_category(event_type: &str) -> EventCategory {
    match event_type {
        "authentication_failed" | "admin_auth_failed" => EventCategory::Authentication,
        "session_ownership_violation" => EventCategory::Authorization,
        // KEK rotation events are KeyAccess.
        // KEK availability/encoding/fallback events are KeyAccess.
        "signing_key_rotated"
        | "signing_key_disabled"
        | "kek_rotation_started"
        | "kek_rotation_completed"
        | "kek_rotation_start_failed"
        | "kek_rotation_complete_failed"
        | "kek_unavailable"
        | "kek_bad_encoding"
        | "kek_fallback_to_previous" => EventCategory::KeyAccess,
        // Credential signing events.
        "blind_issuance_failure"
        | "blind_issuance_rejected"
        | "blind_issuance_issuer_mismatch"
        | "blind_issuance_unknown_issuer"
        | "blind_issuance_verification_failed"
        | "issuance_start_failed"
        | "attestation_create_rejected"
        | "attestation_child_rejected"
        | "credential_signed" => EventCategory::CredentialIssuance,
        "issuer_config_accessed" | "admin_config_change" => EventCategory::AdminAction,
        // Self-verification failure is a SecurityEvent.
        // Invalid worker identity escalation is a SecurityEvent.
        "replay_attempt"
        | "rate_limit_exceeded"
        // M3: nonce-consumption tripwire is a volumetric security signal.
        | "attestation_nonce_rate_exceeded"
        | "account_locked"
        | "self_verification_failed"
        | "invalid_worker_identity" => EventCategory::SecurityEvent,
        // KV access control events.
        "kv_access" => EventCategory::Authorization,
        _ => EventCategory::SecurityEvent,
    }
}

/// Log an audit event via the shared `provii-audit` crate (v0.5.0).
///
/// Uses the per-isolate cached logger. Dispatches via
/// `log_event_best_effort()`, which logs errors to console without
/// propagating them to the caller.
///
/// # Arguments
///
/// * `env` - Cloudflare Worker environment.
/// * `event_type` - Event type string (e.g. `"credential_signed"`).
/// * `client_ip` - Raw client IP (hashed internally by the logger).
/// * `message` - Human-readable event description.
/// * `details` - Additional details as a JSON `Value` (serialised internally).
pub async fn audit_log(
    env: &Env,
    event_type: &str,
    client_ip: &str,
    message: &str,
    details: &serde_json::Value,
) {
    audit_log_with_actor(env, event_type, client_ip, message, details, None, None).await;
}

/// Log an audit event with optional actor identification and outcome.
///
/// Security-critical call sites (auth success/failure, rate limit events)
/// should pass explicit `actor_id` and `outcome` values. When `None`,
/// the fields default to empty strings in the underlying `AuditParams`.
pub async fn audit_log_with_actor(
    env: &Env,
    event_type: &str,
    client_ip: &str,
    message: &str,
    details: &serde_json::Value,
    actor_id: Option<&str>,
    outcome: Option<Outcome>,
) {
    let logger = get_or_build_logger(env).await;
    let severity = classify_severity(event_type);
    let category = classify_category(event_type);
    let details_str = serde_json::to_string(details).unwrap_or_default();

    let environment = parse_environment(env);

    let request_id = uuid::Uuid::new_v4().to_string();

    let params = AuditParams {
        event_type,
        severity,
        message,
        event_category: category,
        raw_ip: client_ip,
        details: &details_str,
        request_id: &request_id,
        environment,
        actor_id: actor_id.unwrap_or_default(),
        outcome,
        ..Default::default()
    };

    logger.log_event_best_effort(params).await;
}

/// Extra fields for [`audit_log_detailed`] that go beyond what
/// [`audit_log`] infers from the event type string.
pub struct DetailedAuditFields<'a> {
    /// Coarse event category for filtering and alerting.
    pub event_category: EventCategory,
    /// Identity of the actor (worker, issuer, officer, etc.).
    pub actor_id: &'a str,
    /// Outcome of the operation.
    pub outcome: Option<Outcome>,
    /// Optional severity override; defaults to `classify_severity`.
    pub severity: Option<Severity>,
}

/// Log an audit event with explicit category, actor, outcome, and severity.
///
/// Use this instead of `audit_log()` when the caller needs precise control
/// over event classification rather than relying on the `classify_*` mappings.
/// Fields follow the same `AuditParams` / `log_event_best_effort()` pattern.
pub async fn audit_log_detailed(
    env: &Env,
    event_type: &str,
    client_ip: &str,
    message: &str,
    details: &serde_json::Value,
    fields: DetailedAuditFields<'_>,
) {
    let logger = get_or_build_logger(env).await;
    let severity = fields
        .severity
        .unwrap_or_else(|| classify_severity(event_type));
    let details_str = serde_json::to_string(details).unwrap_or_default();

    let environment = parse_environment(env);

    let request_id = uuid::Uuid::new_v4().to_string();

    let params = AuditParams {
        event_type,
        severity,
        message,
        event_category: fields.event_category,
        raw_ip: client_ip,
        details: &details_str,
        request_id: &request_id,
        environment,
        actor_id: fields.actor_id,
        outcome: fields.outcome,
        ..Default::default()
    };

    logger.log_event_best_effort(params).await;
}

/// Parse the `ENVIRONMENT` variable into a typed `Environment` enum.
fn parse_environment(env: &Env) -> Environment {
    let env_str = env
        .var("ENVIRONMENT")
        .map(|v| v.to_string())
        .unwrap_or_default();
    if env_str == "production" {
        Environment::Production
    } else {
        Environment::Sandbox
    }
}

/// Build a `PrivacyContext` from the Worker environment's IP hash salt.
///
/// Reads `ISSUER_IP_HASH_SALT` from Secrets Store. Falls back to an
/// ephemeral random salt if the secret is missing (degraded mode, not
/// recommended for production). See [`resolve_ip_hash_salt`].
///
/// This is used by modules that need to hash IPs outside the audit logger
/// (e.g. metrics, session security logs) to ensure consistent hashing.
pub async fn build_privacy_context(env: &Env) -> PrivacyContext {
    let salt_bytes = resolve_ip_hash_salt(env).await;
    match PrivacyContext::new(salt_bytes) {
        Ok(ctx) => ctx,
        Err(_) => {
            // Fallback: use an ephemeral salt so callers never receive a panic.
            PrivacyContext::new(generate_ephemeral_salt())
                .unwrap_or_else(|_| hardcoded_fallback_privacy_context())
        }
    }
}

/// Extract the raw client IP from request headers.
///
/// Returns `"unknown"` if no IP header is present. The raw IP is hashed
/// by the audit logger before any output.
pub fn get_client_ip(req: &worker::Request) -> String {
    req.headers()
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_severity_critical_events() {
        assert_eq!(classify_severity("replay_attempt"), Severity::Critical);
        assert_eq!(classify_severity("signing_key_rotated"), Severity::Critical);
        assert_eq!(
            classify_severity("signing_key_disabled"),
            Severity::Critical
        );
        assert_eq!(
            classify_severity("self_verification_failed"),
            Severity::Critical
        );
    }

    #[test]
    fn classify_severity_warning_events() {
        assert_eq!(
            classify_severity("authentication_failed"),
            Severity::Warning
        );
        assert_eq!(classify_severity("rate_limit_exceeded"), Severity::Warning);
        assert_eq!(
            classify_severity("session_ownership_violation"),
            Severity::Warning
        );
    }

    #[test]
    fn classify_severity_error_events() {
        assert_eq!(classify_severity("account_locked"), Severity::Error);
        assert_eq!(
            classify_severity("kek_rotation_start_failed"),
            Severity::Error
        );
        assert_eq!(classify_severity("kek_unavailable"), Severity::Error);
        assert_eq!(
            classify_severity("invalid_worker_identity"),
            Severity::Error
        );
    }

    #[test]
    fn classify_severity_info_events() {
        assert_eq!(classify_severity("credential_signed"), Severity::Info);
        assert_eq!(classify_severity("kek_rotation_started"), Severity::Info);
        assert_eq!(classify_severity("kv_access"), Severity::Info);
    }

    #[test]
    fn classify_severity_unknown_defaults_to_info() {
        assert_eq!(classify_severity("some_unknown_event"), Severity::Info);
    }

    #[test]
    fn classify_nonce_tripwire_is_warning_security_event() {
        // M3: the advisory nonce-consumption tripwire must classify as a
        // Warning-severity SecurityEvent, not fall through to the Info default.
        assert_eq!(
            classify_severity("attestation_nonce_rate_exceeded"),
            Severity::Warning
        );
        assert_eq!(
            classify_category("attestation_nonce_rate_exceeded"),
            EventCategory::SecurityEvent
        );
    }

    #[test]
    fn classify_category_authentication_events() {
        assert_eq!(
            classify_category("authentication_failed"),
            EventCategory::Authentication
        );
        assert_eq!(
            classify_category("admin_auth_failed"),
            EventCategory::Authentication
        );
    }

    #[test]
    fn classify_category_key_access_events() {
        assert_eq!(
            classify_category("signing_key_rotated"),
            EventCategory::KeyAccess
        );
        assert_eq!(
            classify_category("kek_rotation_started"),
            EventCategory::KeyAccess
        );
        assert_eq!(
            classify_category("kek_unavailable"),
            EventCategory::KeyAccess
        );
    }

    #[test]
    fn classify_category_credential_issuance_events() {
        assert_eq!(
            classify_category("credential_signed"),
            EventCategory::CredentialIssuance
        );
        assert_eq!(
            classify_category("blind_issuance_failure"),
            EventCategory::CredentialIssuance
        );
    }

    #[test]
    fn classify_category_security_events() {
        assert_eq!(
            classify_category("replay_attempt"),
            EventCategory::SecurityEvent
        );
        assert_eq!(
            classify_category("account_locked"),
            EventCategory::SecurityEvent
        );
        assert_eq!(
            classify_category("self_verification_failed"),
            EventCategory::SecurityEvent
        );
    }

    #[test]
    fn classify_category_unknown_defaults_to_security_event() {
        assert_eq!(
            classify_category("unknown_event_type"),
            EventCategory::SecurityEvent
        );
    }
}
