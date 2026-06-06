// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Storage helpers for KV-backed issuer worker state.

use crate::bindings::{
    ISSUER_CHALLENGES, ISSUER_CLIENTS, ISSUER_CONFIG, ISSUER_KEYS, ISSUER_NONCE_DO,
    ISSUER_OFFICER_REGISTRY, ISSUER_RATE_LIMITS,
};
use crate::error::{ApiError, Result};
use crate::types::{ClientRegistration, IssuerConfig, OfficerRegistration, StoredChallenge};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use uuid::Uuid;
use worker::*;
use zeroize::Zeroizing;

/// Compute the remaining TTL in seconds as u64 from an `expires_at` timestamp.
/// Returns at least 1 to avoid zero-TTL KV writes.
///
/// Delegates to `issuer_logic::crypto::remaining_ttl_secs`.
#[inline]
fn remaining_ttl_secs(expires_at: i64) -> u64 {
    issuer_logic::crypto::remaining_ttl_secs(expires_at)
}

/// Maximum length for user-controlled identifiers to prevent DoS.
///
/// Re-exported from `issuer_logic::identifier`. Referenced in tests only.
#[cfg(test)]
pub(crate) const MAX_IDENTIFIER_LENGTH: usize = issuer_logic::identifier::MAX_IDENTIFIER_LENGTH;

/// TTL for nonces in seconds (5-minute window, aligned with provii-verifier)
const NONCE_TTL_SECONDS: u64 = 300;

/// Validate an identifier to prevent KV injection attacks.
///
/// Delegates to `issuer_logic::identifier::validate_identifier` and maps
/// the error type.
pub(crate) fn validate_identifier(id: &str, context: &str) -> Result<()> {
    issuer_logic::identifier::validate_identifier(id, context).map_err(ApiError::from)
}

/// Number of NonceDO shards for distributing load.
const NONCE_DO_SHARD_COUNT: usize = 25;

/// Atomically check-and-set a nonce via the NonceDO Durable Object.
///
/// Uses the single-writer guarantee of Durable Objects to eliminate the
/// TOCTOU race window present in KV-based check-then-set. Sharded across
/// 25 instances via consistent hashing of the nonce value.
///
/// Returns Ok(true) if the nonce was newly consumed, Ok(false) if already used.
async fn nonce_do_check_and_set(env: &Env, nonce: &str, ttl_seconds: u64) -> Result<bool> {
    let namespace = env.durable_object(ISSUER_NONCE_DO).map_err(|e| {
        ApiError::StorageError(format!(
            "Failed to get {} namespace: {}",
            ISSUER_NONCE_DO, e
        ))
    })?;

    // Shard by hashing the nonce value
    let shard_num = {
        // Deterministic hash for cross-isolate shard consistency.
        let h = crate::hash::deterministic_shard_hash(nonce);
        #[allow(clippy::cast_possible_truncation)]
        {
            (h as usize) % NONCE_DO_SHARD_COUNT
        }
    };
    let shard_name = format!("nonce-shard-{}", shard_num);

    // The shard name appears in this server-side error log only.
    // HTTP responses surface a generic "storage error" via ApiError::StorageError,
    // so the internal shard topology is not exposed to callers.
    let id = namespace.id_from_name(&shard_name).map_err(|e| {
        ApiError::StorageError(format!(
            "Failed to get DO ID for shard {}: {}",
            shard_name, e
        ))
    })?;

    let stub = id
        .get_stub()
        .map_err(|e| ApiError::StorageError(format!("Failed to get DO stub: {}", e)))?;

    let body = serde_json::json!({
        "nonce": nonce,
        "ttl_seconds": ttl_seconds
    });

    let body_str = serde_json::to_string(&body)
        .map_err(|e| ApiError::StorageError(format!("Failed to serialise nonce request: {}", e)))?;

    let headers = worker::Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| ApiError::StorageError(format!("Failed to set header: {}", e)))?;

    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_headers(headers)
        .with_body(Some(body_str.into()));

    let do_request = worker::Request::new_with_init("https://nonce-do/check-and-set", &init)
        .map_err(|e| ApiError::StorageError(format!("Failed to create DO request: {}", e)))?;

    let mut response = stub.fetch_with_request(do_request).await.map_err(|e| {
        crate::log_error!(
            "[NonceDO] DO request failed for shard {}: {}",
            shard_name,
            e
        );
        ApiError::StorageError(format!("Nonce DO request failed: {}", e))
    })?;

    match response.status_code() {
        200 => Ok(true),
        409 => Ok(false),
        status => {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(ApiError::StorageError(format!(
                "Nonce DO returned unexpected status {}: {}",
                status, error_text
            )))
        }
    }
}

/// Check if a nonce has been used and mark it as used if not.
/// Returns Ok(true) if nonce is valid and unused, Ok(false) if already used.
///
/// Uses NonceDO for atomic check-and-set (no TOCTOU race).
/// Requires 256-bit (64 hex chars) nonce entropy.
pub async fn validate_and_consume_nonce(env: &Env, nonce: &str) -> Result<bool> {
    // Pure format validation delegated to issuer-logic
    issuer_logic::identifier::validate_nonce_format(nonce).map_err(ApiError::from)?;

    nonce_do_check_and_set(env, nonce, NONCE_TTL_SECONDS).await
}

/// Record an authentication failure, returning the new failure count.
///
/// Wraps the read-increment-write in a ResourceLockDO mutex to
/// prevent concurrent requests from racing on the counter, which could
/// allow an attacker to bypass the lockout threshold.
pub async fn record_auth_failure(
    env: &Env,
    actor_type: &str, // "officer", "client", or "admin"
    actor_id: &str,
    lockout_threshold: u32,
) -> Result<u32> {
    validate_identifier(actor_id, "actor_id")?;
    issuer_logic::identifier::validate_actor_type(actor_type).map_err(ApiError::from)?;

    let lock_key = format!("auth_failure:{}:{}", actor_type, actor_id);
    let lock_token = crate::resource_lock::acquire_resource_lock(env, &lock_key).await?;

    let result = record_auth_failure_inner(env, actor_type, actor_id, lockout_threshold).await;

    crate::resource_lock::release_resource_lock(env, &lock_key, &lock_token).await;

    result
}

/// Inner implementation of auth failure recording (runs under DO lock).
///
/// `lockout_threshold` is the per-actor count at which the caller locks the
/// account (5 for officers, `MAX_ADMIN_FAILED_ATTEMPTS` for admins). It is used
/// ONLY to clamp a corrupt/over-large stored counter so a single corrupt KV
/// read cannot push `new_count` across the threshold and lock a victim (R5
/// FIX B). It never changes the normal increment path.
async fn record_auth_failure_inner(
    env: &Env,
    actor_type: &str,
    actor_id: &str,
    lockout_threshold: u32,
) -> Result<u32> {
    let kv = env
        .kv(ISSUER_RATE_LIMITS)
        .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

    let key = format!("lockout:{}:{}", actor_type, actor_id);

    // Get current count or default to 0
    let mut corrupt_counter_detected = false;
    let current_count: u32 = match kv.get(&key).text().await {
        Ok(Some(data)) => data.parse().unwrap_or_else(|_| {
            corrupt_counter_detected = true;
            crate::log_error!(
                "[SECURITY] Corrupted lockout counter for {}:{}; clamping below threshold",
                actor_type,
                actor_id
            );
            // R5 FIX B: a corrupt/over-large counter must NOT lock the victim.
            // The lock fires at new_count >= lockout_threshold and
            // new_count = current_count + 1, so clamp current_count to
            // (threshold - 2): new_count = threshold - 1, which is BELOW the
            // threshold (neither locks nor forgives accumulated real failures).
            // The previous "u32::MAX - 1" was arithmetically wrong: it gave
            // new_count = u32::MAX >= threshold and locked instantly.
            // threshold is >= 1 in practice (5 officer / admin); guard the
            // subtraction so a threshold of 0 or 1 still clamps to 0.
            lockout_threshold.saturating_sub(2)
        }),
        Ok(None) => 0,
        Err(e) => {
            return Err(ApiError::StorageError(format!(
                "Failed to get failure count: {}",
                e
            )))
        }
    };

    // Emit a high-severity audit event when a corrupt counter is detected: it
    // is a KV-integrity signal, and surfacing it lets operators distinguish a
    // genuine brute-force lockout from a corrupt-read clamp.
    if corrupt_counter_detected {
        let privacy = crate::audit::build_privacy_context(env).await;
        let hashed_actor_id = privacy.hash_ip(actor_id).unwrap_or_default();
        crate::audit::audit_log_detailed(
            env,
            "lockout_counter_corrupt",
            "system",
            "Corrupted lockout counter detected; clamped below lockout threshold",
            &serde_json::json!({
                "actor_type": actor_type,
                "actor_id_hash": hashed_actor_id,
                "lockout_threshold": lockout_threshold,
                "clamped_current_count": current_count,
            }),
            crate::audit::DetailedAuditFields {
                event_category: provii_audit::EventCategory::SecurityEvent,
                actor_id: actor_type,
                outcome: Some(crate::audit::Outcome::Denied),
                severity: Some(provii_audit::Severity::Critical),
            },
        )
        .await;
    }

    let new_count = current_count.saturating_add(1);

    // Store updated count with TTL (tracking window)
    const LOCKOUT_TRACKING_WINDOW: u64 = 3600; // 1 hour
    kv.put(&key, new_count.to_string())
        .map_err(|e| ApiError::StorageError(format!("Failed to store failure count: {}", e)))?
        .expiration_ttl(LOCKOUT_TRACKING_WINDOW)
        .execute()
        .await
        .map_err(|e| {
            ApiError::StorageError(format!("Failed to execute failure count put: {}", e))
        })?;

    Ok(new_count)
}

/// Check if an account is currently locked out.
pub async fn is_locked_out(env: &Env, actor_type: &str, actor_id: &str) -> Result<bool> {
    validate_identifier(actor_id, "actor_id")?;
    issuer_logic::identifier::validate_actor_type(actor_type).map_err(ApiError::from)?;

    let kv = env
        .kv(ISSUER_RATE_LIMITS)
        .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

    let key = format!("locked:{}:{}", actor_type, actor_id);

    match kv.get(&key).text().await {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(e) => {
            // R5 FIX A: fail OPEN to "not locked" on a KV READ error so a
            // transient KV blip cannot lock out (or 503/500) a legitimate
            // officer/admin who is not actually locked. This is bounded by the
            // per-IP attempt caps and is the READ path only; the lock-SET path
            // (record_auth_failure / lock_account) stays fail-CLOSED, so a real
            // brute-force attacker still locks at the threshold (no amnesty).
            crate::log_error!(
                "[SECURITY] Lockout-status KV read failed for {}:{}: {}; failing open (not-locked)",
                actor_type,
                actor_id,
                e
            );
            Ok(false)
        }
    }
}

/// Maximum lockout duration in seconds (24 hours). Prevents unbounded lockouts
/// from creating permanent denial of service.
const MAX_LOCKOUT_DURATION: u64 = 86400;

/// Lock an account for the specified duration.
///
/// `duration_seconds` is clamped to `MAX_LOCKOUT_DURATION` (24 hours)
/// to prevent permanent lockouts via unbounded duration values.
pub async fn lock_account(
    env: &Env,
    actor_type: &str,
    actor_id: &str,
    duration_seconds: u64,
) -> Result<()> {
    validate_identifier(actor_id, "actor_id")?;
    issuer_logic::identifier::validate_actor_type(actor_type).map_err(ApiError::from)?;

    // Clamp: minimum 1 second (zero would be a no-op lockout that KV
    // rejects), maximum MAX_LOCKOUT_DURATION to prevent permanent lockouts.
    let duration = duration_seconds.clamp(1, MAX_LOCKOUT_DURATION);

    let kv = env
        .kv(ISSUER_RATE_LIMITS)
        .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

    let key = format!("locked:{}:{}", actor_type, actor_id);
    let lockout_until = chrono::Utc::now()
        .timestamp()
        .saturating_add(i64::try_from(duration).unwrap_or(i64::MAX));

    kv.put(&key, lockout_until.to_string())
        .map_err(|e| ApiError::StorageError(format!("Failed to lock account: {}", e)))?
        .expiration_ttl(duration)
        .execute()
        .await
        .map_err(|e| ApiError::StorageError(format!("Failed to execute lockout put: {}", e)))?;

    // Hash actor_id via PrivacyContext before including in the
    // audit log to avoid persisting plaintext PII in console output.
    let privacy = crate::audit::build_privacy_context(env).await;
    let hashed_actor_id = privacy.hash_ip(actor_id).unwrap_or_default();

    // Log to audit trail
    crate::audit::audit_log(
        env,
        "account_locked",
        "system",
        "Account locked",
        &serde_json::json!({
            "actor_type": actor_type,
            "actor_id_hash": hashed_actor_id,
            "lockout_until": lockout_until,
            "duration_seconds": duration,
            "requested_duration_seconds": duration_seconds,
            "clamped": duration_seconds != duration
        }),
    )
    .await;

    Ok(())
}

/// Clear failed authentication attempts after successful authentication.
pub async fn clear_auth_failures(env: &Env, actor_type: &str, actor_id: &str) -> Result<()> {
    validate_identifier(actor_id, "actor_id")?;
    issuer_logic::identifier::validate_actor_type(actor_type).map_err(ApiError::from)?;

    let kv = env
        .kv(ISSUER_RATE_LIMITS)
        .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

    // Delete the failure count key.
    let counter_key = format!("lockout:{}:{}", actor_type, actor_id);
    kv.delete(&counter_key)
        .await
        .map_err(|e| ApiError::StorageError(format!("Failed to clear auth failures: {}", e)))?;

    // R5 FIX D (early self-unlock): also clear the lock flag, not just the
    // counter, so a falsely-locked officer/admin who later authenticates
    // successfully is released immediately rather than waiting out the full
    // lockout duration. This does NOT weaken the brute-force ceiling: clearing
    // only happens AFTER a successful authentication, which a real attacker who
    // tripped the lock cannot perform.
    let lock_key = format!("locked:{}:{}", actor_type, actor_id);
    kv.delete(&lock_key)
        .await
        .map_err(|e| ApiError::StorageError(format!("Failed to clear lock flag: {}", e)))?;

    Ok(())
}

/// Persist a new YubiKey challenge and return the stored record.
pub async fn create_challenge(
    env: &Env,
    officer_id: String,
    challenge: Vec<u8>,
    ttl_seconds: u64,
) -> Result<StoredChallenge> {
    validate_identifier(&officer_id, "officer_id")?;

    // Challenge IDs use UUID v4 (122 bits of entropy). This is
    // sufficient because challenges are short-lived (5 min TTL) and scoped to a
    // single officer. Session IDs use 256-bit CSPRNG because they are long-lived
    // bearer tokens with broader attack surface.
    let challenge_obj = StoredChallenge {
        challenge_id: Uuid::new_v4().to_string(),
        officer_id,
        challenge,
        created_at: chrono::Utc::now().timestamp(),
        expires_at: chrono::Utc::now()
            .timestamp()
            .saturating_add(i64::try_from(ttl_seconds).unwrap_or(i64::MAX)),
        used: false,
    };

    let kv = env
        .kv(ISSUER_CHALLENGES)
        .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

    let key = format!("challenge:{}", challenge_obj.challenge_id);
    let value = serde_json::to_string(&challenge_obj)?;

    kv.put(&key, value)
        .map_err(|e| ApiError::StorageError(format!("Failed to store challenge: {}", e)))?
        .expiration_ttl(ttl_seconds)
        .execute()
        .await
        .map_err(|e| ApiError::StorageError(format!("Failed to execute KV put: {}", e)))?;

    // Audit challenge creation.
    crate::audit::audit_log(
        env,
        "challenge_created",
        "system",
        "YubiKey challenge created",
        &serde_json::json!({
            "challenge_id": challenge_obj.challenge_id,
            "officer_id": challenge_obj.officer_id,
            "ttl_seconds": ttl_seconds,
        }),
    )
    .await;

    Ok(challenge_obj)
}

/// Look up a challenge by id and mark it as used if it is still valid.
///
/// Uses ResourceLockDO `/consume` for atomic one-time consumption,
/// eliminating the TOCTOU race between KV GET and KV PUT. The DO instance
/// keyed by `challenge:{challenge_id}` guarantees that at most one caller
/// succeeds in consuming a given challenge.
pub async fn get_and_consume_challenge(
    env: &Env,
    challenge_id: &str,
) -> Result<Option<StoredChallenge>> {
    validate_identifier(challenge_id, "challenge_id")?;

    // Atomically consume via ResourceLockDO. If this returns false, another
    // request already consumed the challenge (or the DO has seen it before).
    let consumed =
        crate::resource_lock::consume_resource_once(env, "challenge", challenge_id).await?;

    if !consumed {
        // Challenge was already consumed by another request. Fail closed.
        return Ok(None);
    }

    // We hold the atomic consumption guarantee. Now read the challenge data
    // from KV (which is the source of the challenge payload).
    let kv = env
        .kv(ISSUER_CHALLENGES)
        .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

    let key = format!("challenge:{}", challenge_id);
    let data = match kv.get(&key).text().await {
        Ok(Some(d)) => d,
        Ok(None) => return Ok(None),
        Err(e) => {
            return Err(ApiError::StorageError(format!(
                "Failed to get challenge: {}",
                e
            )))
        }
    };

    let mut challenge: StoredChallenge = serde_json::from_str(&data)?;
    if challenge.expires_at < chrono::Utc::now().timestamp() {
        let _ = kv.delete(&key).await;
        return Ok(None);
    }
    if challenge.used {
        // Belt-and-braces: KV also says used. The DO should have caught this.
        return Ok(None);
    }

    // Mark as used in KV for consistency (the DO is the authoritative guard).
    challenge.used = true;
    let remaining_ttl = remaining_ttl_secs(challenge.expires_at);

    kv.put(&key, serde_json::to_string(&challenge)?)
        .map_err(|e| ApiError::StorageError(format!("Failed to update challenge: {}", e)))?
        .expiration_ttl(remaining_ttl)
        .execute()
        .await
        .map_err(|e| ApiError::StorageError(format!("Failed to execute KV put: {}", e)))?;

    // Audit challenge consumption.
    crate::audit::audit_log(
        env,
        "challenge_consumed",
        "system",
        "YubiKey challenge consumed",
        &serde_json::json!({
            "challenge_id": challenge.challenge_id,
            "officer_id": challenge.officer_id,
        }),
    )
    .await;

    Ok(Some(challenge))
}

/// Decrypt data using AES-256-GCM with the key encryption key and associated data.
///
/// Delegates to `issuer_logic::crypto::decrypt_with_kek` and maps the error type.
pub fn decrypt_with_kek(kek: &[u8], encrypted_data: &[u8], purpose: &[u8]) -> Result<Vec<u8>> {
    issuer_logic::crypto::decrypt_with_kek(kek, encrypted_data, purpose).map_err(ApiError::from)
}

/// Decrypt the api_key_hash field from a ClientRegistration.
/// The admin-portal stores this as an encrypted Argon2id hash (byte array).
///
/// Uses KEK fallback to support key rotation: tries current KEK first,
/// then previous KEK if available.
pub async fn decrypt_api_key_hash(env: &Env, encrypted_hash: &[u8]) -> Result<Zeroizing<String>> {
    let kek_pair = crate::kek::get_kek_pair(env).await?;

    let decrypted_bytes = crate::kek::decrypt_with_kek_fallback(
        env,
        &kek_pair,
        encrypted_hash,
        b"provii-issuer:api-key-hash:v1",
    )
    .await?;

    // Convert to string (Argon2id PHC format or hex SHA-256).
    // Wrapped in Zeroizing so the decrypted hash is cleared from memory on drop.
    let result = Zeroizing::new(String::from_utf8(decrypted_bytes).map_err(|e| {
        crate::log_error!("Invalid UTF-8 in decrypted hash: {}", e);
        ApiError::CryptoError(format!("Invalid UTF-8 in decrypted hash: {}", e))
    })?);

    Ok(result)
}

/// Encrypt data using AES-256-GCM with the key encryption key and associated data.
///
/// Delegates to `issuer_logic::crypto::encrypt_with_kek` and maps the error type.
pub fn encrypt_with_kek(kek: &[u8], plaintext: &[u8], purpose: &[u8]) -> Result<Vec<u8>> {
    issuer_logic::crypto::encrypt_with_kek(kek, plaintext, purpose).map_err(ApiError::from)
}

/// Default status for signing key records that predate the rotation module.
fn default_key_status_active() -> crate::types::KeyStatus {
    crate::types::KeyStatus::Active
}

/// Load the RedJubjub signing keypair identified by the given key id.
/// The private key must be encrypted with KEK; unencrypted keys are rejected.
/// Only keys with status "active" and a non-expired valid_until are returned.
pub async fn get_signing_keypair(env: &Env, kid: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    validate_identifier(kid, "kid")?;

    let kv = env
        .kv(ISSUER_KEYS)
        .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

    // First, try the expected key format based on current issuer config
    let config = get_issuer_config(env).await?;
    let issuer_kid = extract_issuer_kid(&config.issuer_id);
    let key = format!("issuer:{}:key:{}", issuer_kid, kid);

    let keypair_json = match kv.get(&key).text().await {
        Ok(Some(data)) => data,
        Ok(None) => {
            return Err(ApiError::NotFound(format!(
                "Keypair not found for kid: {}",
                kid
            )));
        }
        Err(e) => {
            return Err(ApiError::StorageError(format!(
                "Failed to get keypair: {}",
                e
            )))
        }
    };

    let keypair_json = Zeroizing::new(keypair_json);

    // Accept BOTH stored shapes for the same RedJubjub key:
    //   - canonical onboarding record (provii-management issuer-manager.ts):
    //       { sk, vk, public_key, ... }
    //   - admin key-rotation record (key_rotation.rs store_encrypted_key):
    //       { private_key_encrypted, public_key, ... }
    // `vk` cannot serde-alias `public_key`: the onboarding record carries BOTH,
    // which serde rejects as a duplicate field. So `public_key` is a separate
    // optional and we prefer `vk`, falling back to `public_key`.
    #[derive(serde::Deserialize)]
    struct KeypairRecord {
        #[serde(alias = "private_key_encrypted")]
        sk: String,
        #[serde(default)]
        vk: Option<String>,
        #[serde(default)]
        public_key: Option<String>,
        #[serde(default)]
        encrypted: bool,
        #[serde(default)]
        version: Option<String>,
        #[serde(default = "default_key_status_active")]
        status: crate::types::KeyStatus,
        #[serde(default)]
        valid_until: u64,
    }

    let keypair: KeypairRecord = serde_json::from_str(&keypair_json)?;

    if keypair.status != crate::types::KeyStatus::Active {
        crate::log!(
            "[SECURITY] Signing key kid={} rejected: status={:?} (expected active)",
            kid,
            keypair.status
        );
        return Err(ApiError::CryptoError(format!(
            "Signing key is not active (status: {:?})",
            keypair.status
        )));
    }

    // Check expiry. valid_until == 0 means "no expiry".
    if keypair.valid_until != 0 {
        #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
        let now = chrono::Utc::now().timestamp() as u64;
        if now > keypair.valid_until {
            crate::log!(
                "[SECURITY] Signing key kid={} rejected: expired (valid_until={}, now={})",
                kid,
                keypair.valid_until,
                now
            );
            return Err(ApiError::CryptoError("Signing key has expired".to_string()));
        }
    }

    let sk_b64 = Zeroizing::new(keypair.sk);
    let vk_b64 = keypair.vk.or(keypair.public_key).ok_or_else(|| {
        ApiError::StorageError("signing keypair record missing vk/public_key".to_string())
    })?;

    let sk_encrypted = Zeroizing::new(URL_SAFE_NO_PAD.decode(sk_b64.as_bytes())?);
    let vk = URL_SAFE_NO_PAD.decode(vk_b64.as_bytes())?;

    // All signing keys must be encrypted. Reject unencrypted key material.
    if !keypair.encrypted {
        return Err(ApiError::CryptoError(
            "Unencrypted key material not supported".to_string(),
        ));
    }

    // KV-109: Construct AAD from the record's version field so that keys
    // encrypted with version-specific AAD (v2, v3, ...) decrypt correctly.
    // Records without a version field default to "v1".
    let version = keypair.version.as_deref().unwrap_or("v1");
    let aad = format!("provii-issuer:signing-key:{}", version);
    let kek_pair = crate::kek::get_kek_pair(env).await?;
    let sk = crate::kek::decrypt_with_kek_fallback(env, &kek_pair, &sk_encrypted, aad.as_bytes())
        .await?;

    Ok((sk, vk))
}

/// Load only the public verification key for a given kid, optionally
/// reusing a previously fetched `IssuerConfig` to avoid a redundant KV
/// read when the caller already has one (e.g. the JWKS handler).
pub async fn get_public_key_only_with_config(
    env: &Env,
    kid: &str,
    cached_config: Option<&IssuerConfig>,
) -> Result<Vec<u8>> {
    validate_identifier(kid, "kid")?;

    let kv = env
        .kv(ISSUER_KEYS)
        .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

    let owned_config;
    let config = match cached_config {
        Some(c) => c,
        None => {
            owned_config = get_issuer_config(env).await?;
            &owned_config
        }
    };
    let issuer_kid = extract_issuer_kid(&config.issuer_id);
    let key = format!("issuer:{}:key:{}", issuer_kid, kid);

    let keypair_json = match kv.get(&key).text().await {
        Ok(Some(data)) => data,
        Ok(None) => {
            return Err(ApiError::NotFound(format!(
                "Key not found for kid: {}",
                kid
            )));
        }
        Err(e) => return Err(ApiError::StorageError(format!("Failed to get key: {}", e))),
    };

    #[derive(serde::Deserialize)]
    struct VkOnly {
        vk: String,
    }

    let record: VkOnly = serde_json::from_str(&keypair_json)?;
    let vk = URL_SAFE_NO_PAD.decode(record.vk.as_bytes())?;
    Ok(vk)
}

pub async fn get_officer_by_id(env: &Env, officer_id: &str) -> Result<Option<OfficerRegistration>> {
    get_officer_by_id_with_config(env, officer_id, None).await
}

/// Load an officer record by ID, optionally reusing a previously fetched
/// `IssuerConfig` to avoid a redundant KV read when the caller already has
/// one.
pub async fn get_officer_by_id_with_config(
    env: &Env,
    officer_id: &str,
    cached_config: Option<&IssuerConfig>,
) -> Result<Option<OfficerRegistration>> {
    validate_identifier(officer_id, "officer_id")?;

    let kv = env
        .kv(ISSUER_OFFICER_REGISTRY)
        .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

    // Reuse caller-provided config or fetch from KV.
    let owned_config;
    let config = match cached_config {
        Some(c) => c,
        None => {
            owned_config = get_issuer_config(env).await?;
            &owned_config
        }
    };
    let issuer_kid = extract_issuer_kid(&config.issuer_id);
    let key = format!("issuer:{}:officer:{}", issuer_kid, officer_id);

    match kv.get(&key).text().await {
        Ok(Some(data)) => {
            let mut officer: OfficerRegistration = serde_json::from_str(&data)?;

            if !officer.active {
                return Ok(None);
            }

            // Decrypt HMAC secret (and previous_hmac_secret) if encrypted flag is set
            if officer.encrypted {
                let kek_pair = crate::kek::get_kek_pair(env).await?;
                officer.hmac_secret = crate::kek::decrypt_with_kek_fallback(
                    env,
                    &kek_pair,
                    &officer.hmac_secret,
                    b"provii-issuer:session:v1",
                )
                .await?;
                if let Some(ref prev_secret) = officer.previous_hmac_secret {
                    officer.previous_hmac_secret = Some(
                        crate::kek::decrypt_with_kek_fallback(
                            env,
                            &kek_pair,
                            prev_secret,
                            b"provii-issuer:session:v1",
                        )
                        .await?,
                    );
                }
            } else {
                crate::log_error!(
                    "CRITICAL: Officer HMAC secret for {} is stored in plaintext, rejecting",
                    officer_id
                );
                return Err(ApiError::CryptoError(
                    "Unencrypted HMAC secret not supported".to_string(),
                ));
            }

            Ok(Some(officer))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(ApiError::StorageError(format!(
            "Failed to get officer: {}",
            e
        ))),
    }
}

/// Update the last-used timestamp for the given officer entry.
pub async fn update_officer_last_used_by_id(env: &Env, officer_id: &str) -> Result<()> {
    validate_identifier(officer_id, "officer_id")?;

    let kv = env
        .kv(ISSUER_OFFICER_REGISTRY)
        .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

    // Get issuer_kid for scoped key
    let config = get_issuer_config(env).await?;
    let issuer_kid = extract_issuer_kid(&config.issuer_id);
    let key = format!("issuer:{}:officer:{}", issuer_kid, officer_id);

    let data = kv
        .get(&key)
        .text()
        .await
        .map_err(|e| ApiError::StorageError(format!("Failed to get officer: {}", e)))?
        .ok_or_else(|| ApiError::NotFound("Officer not found".to_string()))?;

    let mut officer: OfficerRegistration = serde_json::from_str(&data)?;
    officer.last_used = Some(chrono::Utc::now().timestamp());

    kv.put(&key, serde_json::to_string(&officer)?)
        .map_err(|e| ApiError::StorageError(format!("Failed to update officer: {}", e)))?
        .execute()
        .await
        .map_err(|e| ApiError::StorageError(format!("Failed to execute KV put: {}", e)))?;

    Ok(())
}

pub async fn get_client_by_id(env: &Env, client_id: &str) -> Result<Option<ClientRegistration>> {
    validate_identifier(client_id, "client_id")?;

    let kv = env
        .kv(ISSUER_CLIENTS)
        .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

    // First, try the expected key format based on current issuer config
    let config = get_issuer_config(env).await?;
    let issuer_kid = extract_issuer_kid(&config.issuer_id);
    let key = format!("issuer:{}:client:{}", issuer_kid, client_id);

    match kv.get(&key).text().await {
        Ok(Some(data)) => {
            let mut client: ClientRegistration = serde_json::from_str(&data)?;

            if !client.active {
                return Ok(None);
            }

            // Store the KV key so update_client_last_used can use it.
            // Moved rather than cloned; `key` is not referenced after this point.
            client.kv_key = Some(key);

            // Decrypt HMAC secret (and previous_hmac_secret) if encrypted flag is set
            if client.encrypted {
                let kek_pair = crate::kek::get_kek_pair(env).await?;
                client.hmac_secret = crate::kek::decrypt_with_kek_fallback(
                    env,
                    &kek_pair,
                    &client.hmac_secret,
                    b"provii-issuer:session:v1",
                )
                .await?;
                if let Some(ref prev_secret) = client.previous_hmac_secret {
                    client.previous_hmac_secret = Some(
                        crate::kek::decrypt_with_kek_fallback(
                            env,
                            &kek_pair,
                            prev_secret,
                            b"provii-issuer:session:v1",
                        )
                        .await?,
                    );
                }
            } else {
                crate::log_error!(
                    "CRITICAL: Client HMAC secret for {} is stored in plaintext, rejecting",
                    client.client_id
                );
                return Err(ApiError::CryptoError(
                    "Unencrypted HMAC secret not supported".to_string(),
                ));
            }

            Ok(Some(client))
        }
        // KV key enumeration fallback is not used. Iterating all client
        // keys when the expected key is not found creates a DoS
        // amplification vector. Clients must be stored under the
        // canonical key format.
        Ok(None) => Ok(None),
        Err(e) => Err(ApiError::StorageError(format!(
            "Failed to get client: {}",
            e
        ))),
    }
}

/// Update the last-used timestamp for a client and keep the API-key index in sync.
pub async fn update_client_last_used(env: &Env, client: &ClientRegistration) -> Result<()> {
    validate_identifier(&client.client_id, "client_id")?;

    let kv = env
        .kv(ISSUER_CLIENTS)
        .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

    // Use the KV key stored during authentication to avoid issuer_kid mismatch
    let key = client.kv_key.as_ref().ok_or_else(|| {
        ApiError::StorageError("Client KV key not set during authentication".to_string())
    })?;

    let data = kv
        .get(key)
        .text()
        .await
        .map_err(|e| ApiError::StorageError(format!("Failed to get client: {}", e)))?
        .ok_or_else(|| ApiError::NotFound("Client not found".to_string()))?;

    let mut client_data: ClientRegistration = serde_json::from_str(&data)?;
    client_data.last_used = Some(chrono::Utc::now().timestamp());

    kv.put(key, serde_json::to_string(&client_data)?)
        .map_err(|e| ApiError::StorageError(format!("Failed to update client: {}", e)))?
        .execute()
        .await
        .map_err(|e| ApiError::StorageError(format!("Failed to execute KV put: {}", e)))?;

    // Client lookup by API key iterates through all clients and decrypts/verifies each hash.

    Ok(())
}

/// Retrieve a challenge without consuming it, ignoring expired or used entries.
pub async fn get_challenge(env: &Env, challenge_id: &str) -> Result<Option<StoredChallenge>> {
    validate_identifier(challenge_id, "challenge_id")?;

    let kv = env
        .kv(ISSUER_CHALLENGES)
        .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

    let key = format!("challenge:{}", challenge_id);

    let data = match kv.get(&key).text().await {
        Ok(Some(d)) => d,
        Ok(None) => return Ok(None),
        Err(e) => {
            return Err(ApiError::StorageError(format!(
                "Failed to get challenge: {}",
                e
            )))
        }
    };

    let challenge: StoredChallenge = serde_json::from_str(&data)?;

    if challenge.expires_at < chrono::Utc::now().timestamp() {
        let _ = kv.delete(&key).await;
        return Ok(None);
    }
    if challenge.used {
        return Ok(None);
    }

    Ok(Some(challenge))
}

/// Extract issuer_kid from issuer_id (strip "did:provii:" prefix).
///
/// Delegates to `issuer_logic::identifier::extract_issuer_kid`.
pub fn extract_issuer_kid(issuer_id: &str) -> &str {
    issuer_logic::identifier::extract_issuer_kid(issuer_id)
}

/// Load issuer configuration from KV or fall back to environment defaults.
///
/// Lookup order:
/// 1. Try env var ISSUER_ID-based key lookup
/// 2. If not found, auto-discover by listing all configs in the namespace
/// 3. Only fall back to hardcoded defaults if nothing is found
pub async fn get_issuer_config(env: &Env) -> Result<IssuerConfig> {
    let kv = env
        .kv(ISSUER_CONFIG)
        .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

    // Get issuer_id from env to determine issuer_kid.
    // No hardcoded fallback. ISSUER_ID must be set in the environment.
    let issuer_id = match env.var("ISSUER_ID") {
        Ok(v) => v.to_string(),
        Err(_) => {
            crate::log_error!("[GET_ISSUER_CONFIG] ISSUER_ID environment variable not set");
            return Err(ApiError::StorageError(
                "ISSUER_ID environment variable is required but not set".to_string(),
            ));
        }
    };

    let issuer_kid = extract_issuer_kid(&issuer_id);
    let config_key = format!("issuer:{}:config", issuer_kid);

    // First, try the env var-based lookup
    if let Ok(Some(data)) = kv.get(&config_key).text().await {
        crate::log!(
            "[GET_ISSUER_CONFIG] Found config with env-based key: {}",
            config_key
        );
        return Ok(serde_json::from_str(&data)?);
    }

    // If not found, auto-discover by listing all configs.
    // SECURITY: This list() prefix scan reveals namespace key structure in
    // server-side logs. Key names contain issuer_kid values. The information
    // is not exposed to callers (only internal logging), but operators should
    // be aware that log aggregation will contain the namespace topology.
    crate::log!(
        "[GET_ISSUER_CONFIG] Config not found at {}, auto-discovering...",
        config_key
    );

    let list_result = kv
        .list()
        .execute()
        .await
        .map_err(|e| ApiError::StorageError(format!("Failed to list configs: {}", e)))?;

    if !list_result.list_complete {
        crate::log_error!(
            "[WARNING] Config namespace list truncated, list_complete=false. \
             Auto-discovery may miss the correct config."
        );
        // Fail closed: truncated results mean we cannot guarantee we found the
        // correct config. Return an error rather than silently using a partial result.
        return Err(ApiError::StorageError(
            "Config namespace list truncated; cannot auto-discover issuer config reliably"
                .to_string(),
        ));
    }

    crate::log!(
        "[GET_ISSUER_CONFIG] Found {} configs in namespace",
        list_result.keys.len()
    );

    // Look for any config key (format: issuer:*:config)
    for key_info in list_result.keys.iter() {
        if key_info.name.ends_with(":config") {
            if let Ok(Some(data)) = kv.get(&key_info.name).text().await {
                crate::log!(
                    "[GET_ISSUER_CONFIG] Auto-discovered config: {}",
                    key_info.name
                );
                return Ok(serde_json::from_str(&data)?);
            }
        }
    }

    // Fail closed when no issuer config is available. A hardcoded fallback
    // config with a stale gov.au domain not owned by Provii is not acceptable.
    // Missing config is a deployment error that must be surfaced, not silently
    // papered over with defaults.
    crate::log_error!(
        "[GET_ISSUER_CONFIG] No config found in KV or environment. Deployment is misconfigured."
    );
    Err(ApiError::StorageError(
        "Issuer configuration not found. Neither KV nor environment variables provide a valid config.".to_string(),
    ))
}

/// Persist an updated `IssuerConfig` to the canonical KV slot.
///
/// Used by the Ed25519 attestation key rotation admin endpoint to swap
/// `default_kid` and `previous_kid` atomically against a single KV
/// write. The caller is responsible for serialising rotations behind
/// `resource_lock::acquire_resource_lock` so two concurrent operators
/// cannot both read the current config and clobber each other's
/// `previous_kid`.
///
/// The KV key shape `issuer:{issuer_kid}:config` mirrors
/// [`get_issuer_config`]'s primary lookup. The auto-discovery list
/// fallback is intentionally not mirrored on the write path: writes
/// must always target the deterministic env-derived slot. Auto-discovery
/// only exists to ride out a misconfiguration window on read; writing
/// to a discovered slot would compound the misconfiguration.
pub async fn put_issuer_config(env: &Env, config: &IssuerConfig) -> Result<()> {
    let kv = env
        .kv(ISSUER_CONFIG)
        .map_err(|e| ApiError::StorageError(format!("Failed to get KV namespace: {}", e)))?;

    let issuer_id = match env.var("ISSUER_ID") {
        Ok(v) => v.to_string(),
        Err(_) => {
            crate::log_error!("[PUT_ISSUER_CONFIG] ISSUER_ID environment variable not set");
            return Err(ApiError::StorageError(
                "ISSUER_ID environment variable is required but not set".to_string(),
            ));
        }
    };

    let issuer_kid = extract_issuer_kid(&issuer_id);
    let config_key = format!("issuer:{}:config", issuer_kid);

    let body = serde_json::to_string(config)
        .map_err(|e| ApiError::StorageError(format!("Failed to serialise issuer config: {}", e)))?;

    kv.put(&config_key, body)
        .map_err(|e| ApiError::StorageError(format!("Failed to create put operation: {}", e)))?
        .execute()
        .await
        .map_err(|e| ApiError::StorageError(format!("Failed to write issuer config: {}", e)))?;

    Ok(())
}

// ============================================================================
// Blind Attestation Issuance Storage (ASVS 5.0 / MASVS 2.0 compliant)
// ============================================================================

/// TTL for attestation nonces in seconds (2 hours).
///
/// This is 2x the `ATTESTATION_MAX_AGE_SECONDS` (1 hour) safety margin.
/// The nonce must survive longer than the attestation validity window so that
/// replay attempts arriving just before attestation expiry can still be
/// rejected. Without the margin, a nonce could be garbage-collected while
/// a valid-but-replayed attestation is still within its freshness window.
const ATTESTATION_NONCE_TTL: u64 = 7200;

/// Get an Ed25519 verifying key for a registered attestation issuer
/// under the given `kid`.
///
/// # Security (ASVS 5.0)
/// - Validates `issuer_id` and `kid` formats to prevent injection
/// - Returns None for unregistered (issuer_id, kid) tuples (fail-closed)
/// - Checks key validity timestamps in the caller after lookup
///
/// # Rotation
/// KV layout is `issuer:{issuer_id}:{kid}`. During a rotation overlap
/// window the same `issuer_id` may carry several entries keyed by
/// distinct `kid` values, so in-flight attestations signed under the
/// outgoing keypair continue to verify until they expire. No migration
/// or backward-compatibility code; storage format changes discard old
/// data. Fresh KV namespaces are empty; any prior `issuer:{issuer_id}`
/// records (single-slot layout) are not retained.
///
/// `kid` is a non-secret public selector sourced from the inbound
/// request envelope, never derived locally. Tampering selects the
/// wrong verifying key, which then fails signature verification.
///
/// # Composite key decomposition is not supported
/// The KV key shape `issuer:{issuer_id}:{kid}` is a one-way string
/// formatter, not a parser. Callers must always reach this function
/// (or its `signing:` counterpart) with the `(issuer_id, kid)` tuple
/// already in hand from a request envelope or `IssuerConfig`. There
/// is no helper that splits a composite key back into its parts and
/// nothing in the codebase relies on doing so. Adding a splitter
/// would be unsafe because both `issuer_id` and `kid` may legitimately
/// contain `:` (DID-style identifiers, `provii:sandbox` kids, etc.),
/// so any naive `split(':')` rule would silently misroute traffic.
/// See also `IssuerEd25519Key` and `get_issuer_ed25519_signing_key`.
pub async fn get_issuer_ed25519_key(
    env: &Env,
    issuer_id: &str,
    kid: &str,
) -> Result<Option<crate::types::IssuerEd25519Key>> {
    validate_identifier(issuer_id, "issuer_id")?;
    validate_identifier(kid, "kid")?;

    let kv = env.kv(crate::bindings::ISSUER_ED25519_KEYS).map_err(|e| {
        ApiError::StorageError(format!("Failed to get ED25519_KEYS namespace: {}", e))
    })?;

    // Composite key is lookup-only. Decomposing back to (issuer_id, kid)
    // is not supported (see function-level docs).
    let key = format!("issuer:{}:{}", issuer_id, kid);

    match kv.get(&key).json().await {
        Ok(Some(issuer_key)) => Ok(Some(issuer_key)),
        Ok(None) => Ok(None),
        Err(e) => Err(ApiError::StorageError(format!(
            "Failed to get issuer key: {}",
            e
        ))),
    }
}

/// Validate and consume an attestation nonce for replay prevention.
///
/// Uses NonceDO for atomic check-and-set (no TOCTOU race).
/// The nonce key is prefixed with "attest:" to namespace it within the
/// same NonceDO shards used by auth nonces.
///
/// # Security (ASVS 5.0)
/// - Nonce must be exactly 64 hex characters (256 bits)
/// - Atomic check-and-consume via DO single-writer prevents race conditions
/// - TTL ensures nonces are eventually cleaned up
///
/// # Returns
/// - `Ok(true)` if nonce is valid and was consumed
/// - `Ok(false)` if nonce was already used (replay attack)
/// - `Err(...)` for validation failures
pub async fn validate_and_consume_attestation_nonce(env: &Env, nonce_hex: &str) -> Result<bool> {
    // Validate nonce format: must be 64 hex characters (256 bits)
    if nonce_hex.len() != 64 {
        return Err(ApiError::BadRequest(
            "Attestation nonce must be exactly 64 hex characters (256 bits)".to_string(),
        ));
    }

    if !nonce_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest(
            "Attestation nonce must be a hex string".to_string(),
        ));
    }

    // Prefix with "attest:" to separate from auth nonces in the same DO
    let prefixed_nonce = format!("attest:{}", nonce_hex);

    let result = nonce_do_check_and_set(env, &prefixed_nonce, ATTESTATION_NONCE_TTL).await?;

    if !result {
        // Nonce already used, audit log the replay detection
        crate::log!(
            "REPLAY ATTACK: Attestation nonce {} already used",
            nonce_hex.get(..16).unwrap_or(nonce_hex)
        );

        crate::audit::audit_log(
            env,
            "replay_attempt",
            "system",
            "Attestation replay detected",
            &serde_json::json!({
                "nonce_prefix": nonce_hex.get(..16).unwrap_or(nonce_hex),
                "severity": "HIGH",
                "description": "Duplicate attestation nonce detected - possible replay attack"
            }),
        )
        .await;
    }

    Ok(result)
}

/// Get an Ed25519 signing key for a registered attestation issuer
/// under the given `kid`.
///
/// # Security (ASVS 5.0)
/// - Validates `issuer_id` and `kid` formats to prevent injection
/// - Returns None for unregistered (issuer_id, kid) tuples (fail-closed)
/// - Signing key is encrypted at rest; caller must decrypt
/// - Access requires prior officer authentication
///
/// # Rotation
/// KV layout is `signing:{issuer_id}:{kid}`. During a rotation overlap
/// window the same `issuer_id` may carry several entries keyed by
/// distinct `kid` values. The active kid is sourced from
/// `IssuerConfig.default_kid` so the two records (verifying + signing)
/// remain coordinated. No migration or backward-compatibility code;
/// storage format changes discard old data. Fresh KV namespaces are
/// empty; prior `signing:{issuer_id}` records (single-slot layout) are
/// not retained.
pub async fn get_issuer_ed25519_signing_key(
    env: &Env,
    issuer_id: &str,
    kid: &str,
) -> Result<Option<crate::types::IssuerEd25519SigningKey>> {
    validate_identifier(issuer_id, "issuer_id")?;
    validate_identifier(kid, "kid")?;

    let kv = env
        .kv(crate::bindings::ISSUER_ED25519_SIGNING_KEYS)
        .map_err(|e| {
            ApiError::StorageError(format!(
                "Failed to get ED25519_SIGNING_KEYS namespace: {}",
                e
            ))
        })?;

    let key = format!("signing:{}:{}", issuer_id, kid);

    match kv.get(&key).json().await {
        Ok(Some(signing_key)) => {
            let record: crate::types::IssuerEd25519SigningKey = signing_key;
            if !record.encrypted {
                crate::log_error!(
                    "[SECURITY] Ed25519 signing key kid={} has encrypted=false, rejecting",
                    kid
                );
                return Err(ApiError::CryptoError(
                    "Unencrypted signing key material not supported".to_string(),
                ));
            }
            Ok(Some(record))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(ApiError::StorageError(format!(
            "Failed to get issuer signing key: {}",
            e
        ))),
    }
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
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::types::*;
    use uuid::Uuid;

    /* ========================================================================== */
    /*                    KEY FORMATTING TESTS                                   */
    /* ========================================================================== */

    #[test]
    fn test_challenge_key_format() {
        let challenge_id = "test-challenge-123";
        let expected = format!("challenge:{}", challenge_id);
        assert_eq!(expected, "challenge:test-challenge-123");
    }

    #[test]
    fn test_session_key_format() {
        let session_id = Uuid::new_v4();
        let expected = format!("session:{}", session_id);
        assert!(expected.starts_with("session:"));
        assert_eq!(expected.len(), "session:".len() + 36); // UUID is 36 chars
    }

    #[test]
    fn test_pickup_key_format() {
        let token = "ABCD1234EFGH5678";
        let expected = format!("pickup:{}", token);
        assert_eq!(expected, "pickup:ABCD1234EFGH5678");
    }

    #[test]
    fn test_keypair_key_format() {
        let issuer_kid = "test-issuer";
        let kid = "gov:2025-08";
        let expected = format!("issuer:{}:key:{}", issuer_kid, kid);
        assert_eq!(expected, "issuer:test-issuer:key:gov:2025-08");
    }

    #[test]
    fn test_officer_id_key_format() {
        let issuer_kid = "test-issuer";
        let officer_id = "officer-123";
        let expected = format!("issuer:{}:officer:{}", issuer_kid, officer_id);
        assert_eq!(expected, "issuer:test-issuer:officer:officer-123");
    }

    #[test]
    fn test_client_api_key_format() {
        let issuer_kid = "test-issuer";
        let api_key_hash = "abcd1234hash";
        let expected = format!("issuer:{}:client-api:{}", issuer_kid, api_key_hash);
        assert_eq!(expected, "issuer:test-issuer:client-api:abcd1234hash");
    }

    #[test]
    fn test_client_id_key_format() {
        let issuer_kid = "test-issuer";
        let client_id = "client-456";
        let expected = format!("issuer:{}:client:{}", issuer_kid, client_id);
        assert_eq!(expected, "issuer:test-issuer:client:client-456");
    }

    #[test]
    fn test_audit_key_format() {
        let timestamp = 1700000000;
        let uuid = Uuid::new_v4();
        let expected = format!("audit:{}:{}", timestamp, uuid);
        assert!(expected.starts_with("audit:1700000000:"));
    }

    /* ========================================================================== */
    /*    kid-keyed Ed25519 KV layout regression tests                            */
    /* ========================================================================== */
    //
    // The integration-style scenarios documented under
    // "INTEGRATION TEST DOCUMENTATION" (KV-backed put/get cycles) live in
    // the rotation drill workflow because they require a Workers runtime.
    // The unit tests here cover the layout invariant: keys derive
    // deterministically from `(issuer_id, kid)`, distinct kids map to
    // distinct keys, kid-format validation rejects injection-shaped
    // inputs.

    #[test]
    fn test_ed25519_verifying_key_format_includes_kid() {
        let issuer_id = "provii:issuer:production";
        let kid = "provii:2026-05";
        let expected = format!("issuer:{}:{}", issuer_id, kid);
        assert_eq!(expected, "issuer:provii:issuer:production:provii:2026-05");
        assert!(expected.starts_with("issuer:"));
        assert!(expected.contains(issuer_id));
        assert!(expected.ends_with(kid));
    }

    #[test]
    fn test_ed25519_signing_key_format_includes_kid() {
        let issuer_id = "provii:issuer:production";
        let kid = "provii:2026-05";
        let expected = format!("signing:{}:{}", issuer_id, kid);
        assert_eq!(expected, "signing:provii:issuer:production:provii:2026-05");
        assert!(expected.starts_with("signing:"));
        assert!(expected.contains(issuer_id));
        assert!(expected.ends_with(kid));
    }

    #[test]
    fn test_ed25519_distinct_kids_yield_distinct_keys() {
        // Rotation invariant: the same issuer_id under two different kids
        // must produce two different KV record keys, so the records
        // coexist during the rotation overlap window.
        let issuer_id = "provii:issuer:production";
        let kid_a = "provii:2026-05";
        let kid_b = "provii:2026-06";
        let key_a = format!("issuer:{}:{}", issuer_id, kid_a);
        let key_b = format!("issuer:{}:{}", issuer_id, kid_b);
        assert_ne!(key_a, key_b);

        let signing_a = format!("signing:{}:{}", issuer_id, kid_a);
        let signing_b = format!("signing:{}:{}", issuer_id, kid_b);
        assert_ne!(signing_a, signing_b);
    }

    #[test]
    fn test_ed25519_kid_validation_rejects_empty() {
        // get_issuer_ed25519_key validates kid via validate_identifier,
        // which rejects empty strings. Guards against an empty
        // default_kid (or previous_kid fallback) reaching KV verbatim.
        let result = validate_identifier("", "kid");
        assert!(result.is_err());
    }

    #[test]
    fn test_ed25519_kid_validation_rejects_injection_chars() {
        // Newline, NUL, space, and equals are all outside the permitted
        // alphabet. KV keys are assembled via `format!()`, so without
        // validation a maliciously crafted kid could still be passed
        // verbatim to Cloudflare KV.
        for bad in [
            "kid with space",
            "kid=injected",
            "kid\nwith-newline",
            "kid\0nul",
            "kid#frag",
        ] {
            let result = validate_identifier(bad, "kid");
            assert!(
                result.is_err(),
                "expected rejection for kid containing disallowed chars: {:?}",
                bad
            );
        }
    }

    #[test]
    fn test_ed25519_kid_validation_accepts_did_style() {
        // Issuer kids in the wild use colons, slashes, and hyphens
        // (e.g. `provii:2026-05`, `provii:sandbox`, `gov.au:2026-q2`).
        for good in [
            "provii:2026-05",
            "provii:sandbox",
            "gov.au:2026-q2",
            "did:web:example.com/keys/1",
            "k_underscore-hyphen.dot",
        ] {
            assert!(
                validate_identifier(good, "kid").is_ok(),
                "expected acceptance for kid: {:?}",
                good
            );
        }
    }

    #[test]
    fn test_ed25519_verifying_key_record_serdes_with_kid_field() {
        // Ensures the `kid` field on `IssuerEd25519Key` round-trips
        // through JSON unchanged. Necessary because lookup callers
        // observe `record.kid` in audit logs to confirm the selected
        // key matched the requested kid.
        let record = IssuerEd25519Key {
            issuer_id: "provii:issuer:production".to_string(),
            kid: "provii:2026-05".to_string(),
            issuer_name: "Provii Production".to_string(),
            verifying_key: [0xAB; 32],
            valid_from: 0,
            valid_until: u64::MAX,
            active: true,
            created_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"kid\":\"provii:2026-05\""));
        let decoded: IssuerEd25519Key = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.kid, "provii:2026-05");
        assert_eq!(decoded.issuer_id, "provii:issuer:production");
    }

    #[test]
    fn test_ed25519_verifying_key_record_default_kid_is_empty_for_missing_field() {
        // Forward-compat: records written before the kid field was added
        // deserialise with `kid = ""`. Lookup-by-empty-kid is rejected at
        // validate_identifier(""), so any such legacy record is
        // unreachable through the kid-keyed code path. This documents
        // the intentional fail-closed posture.
        let legacy_json = r#"{
            "issuer_id":"provii:issuer:production",
            "issuer_name":"Provii Production",
            "verifying_key":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "valid_from":0,
            "valid_until":18446744073709551615,
            "active":true,
            "created_at":1700000000
        }"#;
        let decoded: IssuerEd25519Key = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(decoded.kid, "");
        assert!(validate_identifier(&decoded.kid, "kid").is_err());
    }

    #[test]
    fn test_ed25519_signing_key_record_serdes_with_kid_field() {
        let record = IssuerEd25519SigningKey {
            issuer_id: "provii:issuer:production".to_string(),
            kid: "provii:2026-05".to_string(),
            signing_key: zeroize::Zeroizing::new(vec![0u8; 64]),
            encrypted: true,
            created_at: 1_700_000_000,
            status: KeyStatus::Active,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"kid\":\"provii:2026-05\""));
        let decoded: IssuerEd25519SigningKey = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.kid, "provii:2026-05");
        assert_eq!(decoded.issuer_id, "provii:issuer:production");
    }

    #[test]
    fn test_ed25519_rotation_simulation_keys_coexist() {
        // Simulates the lookup invariant during a rotation overlap
        // window. Two records (kid-A and kid-B) live under the same
        // issuer_id and must be addressable independently. This test
        // does not exercise actual KV; it asserts the key-format level
        // collision-free property that get_issuer_ed25519_key relies
        // on.
        let issuer_id = "provii:issuer:production";

        // Step 1: legacy single-slot records under the OLD layout would
        // have collided here (`issuer:{issuer_id}` regardless of kid).
        // With the kid suffix, two distinct kids produce two distinct
        // keys.
        let kid_a = "provii:2026-05";
        let kid_b = "provii:2026-06";

        let verify_key_a = format!("issuer:{}:{}", issuer_id, kid_a);
        let verify_key_b = format!("issuer:{}:{}", issuer_id, kid_b);
        let sign_key_a = format!("signing:{}:{}", issuer_id, kid_a);
        let sign_key_b = format!("signing:{}:{}", issuer_id, kid_b);

        // Distinct keys (rotation invariant)
        assert_ne!(verify_key_a, verify_key_b);
        assert_ne!(sign_key_a, sign_key_b);

        // Verify and sign namespaces stay separated even at identical kid
        assert_ne!(verify_key_a, sign_key_a);
        assert_ne!(verify_key_b, sign_key_b);

        // Step 2: tearing down kid-A leaves kid-B intact (operationally,
        // the rotation runbook deletes the legacy KV record after the
        // overlap window). This test cannot verify deletion against
        // real KV, but it confirms the key shape allows it.
        assert!(verify_key_b.contains(kid_b));
        assert!(!verify_key_b.contains(kid_a));
    }

    /* ========================================================================== */
    /*                    TTL CALCULATION TESTS                                  */
    /* ========================================================================== */

    #[test]
    fn test_remaining_ttl_calculation_positive() {
        let expires_at = 1700000300i64;
        let now = 1700000000i64;
        let remaining = (expires_at - now).max(1) as u64;
        assert_eq!(remaining, 300);
    }

    #[test]
    fn test_remaining_ttl_calculation_zero_becomes_one() {
        let expires_at = 1700000000i64;
        let now = 1700000000i64;
        let remaining = (expires_at - now).max(1) as u64;
        assert_eq!(remaining, 1);
    }

    #[test]
    fn test_remaining_ttl_calculation_negative_becomes_one() {
        let expires_at = 1700000000i64;
        let now = 1700000100i64;
        let remaining = (expires_at - now).max(1) as u64;
        assert_eq!(remaining, 1);
    }

    #[test]
    fn test_remaining_ttl_calculation_one_second() {
        let expires_at = 1700000001i64;
        let now = 1700000000i64;
        let remaining = (expires_at - now).max(1) as u64;
        assert_eq!(remaining, 1);
    }

    #[test]
    fn test_remaining_ttl_calculation_large_value() {
        let expires_at = 1700086400i64; // 24 hours later
        let now = 1700000000i64;
        let remaining = (expires_at - now).max(1) as u64;
        assert_eq!(remaining, 86400);
    }

    /* ========================================================================== */
    /*                    EXPIRY LOGIC TESTS                                     */
    /* ========================================================================== */

    #[test]
    fn test_expiry_check_not_expired() {
        let expires_at = 1700000300i64;
        let now = 1700000000i64;
        assert!(expires_at >= now);
    }

    #[test]
    fn test_expiry_check_expired() {
        let expires_at = 1700000000i64;
        let now = 1700000300i64;
        assert!(expires_at < now);
    }

    #[test]
    fn test_expiry_check_boundary_exact() {
        let expires_at = 1700000000i64;
        let now = 1700000000i64;
        // Exactly at expiry should NOT be expired (expires_at < now is false)
        assert!(expires_at >= now);
    }

    #[test]
    fn test_expiry_check_one_second_before() {
        let expires_at = 1700000001i64;
        let now = 1700000000i64;
        assert!(expires_at >= now);
    }

    #[test]
    fn test_expiry_check_one_second_after() {
        let expires_at = 1700000000i64;
        let now = 1700000001i64;
        assert!(expires_at < now);
    }

    /* ========================================================================== */
    /*                    CHALLENGE LIFECYCLE TESTS (LOGIC ONLY)                */
    /* ========================================================================== */

    #[test]
    fn test_stored_challenge_structure() {
        let challenge = StoredChallenge {
            challenge_id: "test-123".to_string(),
            officer_id: "officer-1".to_string(),
            challenge: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            created_at: 1700000000,
            expires_at: 1700000120,
            used: false,
        };

        assert_eq!(challenge.challenge_id, "test-123");
        assert_eq!(challenge.officer_id, "officer-1");
        assert_eq!(challenge.challenge.len(), 8);
        assert!(!challenge.used);
    }

    #[test]
    fn test_stored_challenge_serialization() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let challenge = StoredChallenge {
            challenge_id: "test-456".to_string(),
            officer_id: "officer-2".to_string(),
            challenge: vec![0xAB, 0xCD, 0xEF],
            created_at: 1700000000,
            expires_at: 1700000120,
            used: false,
        };

        let json = serde_json::to_string(&challenge)?;
        assert!(json.contains("\"challenge_id\""));
        assert!(json.contains("\"officer_id\""));
        assert!(json.contains("\"used\""));

        let deserialized: StoredChallenge = serde_json::from_str(&json)?;
        assert_eq!(deserialized.challenge_id, challenge.challenge_id);
        assert_eq!(deserialized.officer_id, challenge.officer_id);
        assert_eq!(deserialized.challenge, challenge.challenge);
        assert_eq!(deserialized.created_at, challenge.created_at);
        assert_eq!(deserialized.expires_at, challenge.expires_at);
        assert_eq!(deserialized.used, challenge.used);
        Ok(())
    }

    #[test]
    fn test_stored_challenge_mark_used() {
        let mut challenge = StoredChallenge {
            challenge_id: "test-789".to_string(),
            officer_id: "officer-3".to_string(),
            challenge: vec![0x01; 8],
            created_at: 1700000000,
            expires_at: 1700000120,
            used: false,
        };

        assert!(!challenge.used);
        challenge.used = true;
        assert!(challenge.used);
    }

    #[test]
    fn test_challenge_expiry_simulation() {
        let created_at = 1700000000i64;
        let ttl = 120;
        let expires_at = created_at + ttl;

        // Before expiry
        let check_time_1 = 1700000060i64;
        assert!(expires_at >= check_time_1);

        // At expiry
        let check_time_2 = 1700000120i64;
        assert!(expires_at >= check_time_2);

        // After expiry
        let check_time_3 = 1700000121i64;
        assert!(expires_at < check_time_3);
    }

    /* ========================================================================== */
    /*                    SESSION LIFECYCLE TESTS (LOGIC ONLY)                  */
    /* ========================================================================== */

    #[test]
    fn test_issuance_session_initial_state() {
        let session = IssuanceSession {
            session_id: "test-session-id".to_string(),
            created_at: 1700000000,
            expires_at: 1700000300,
            actor: ActorType::Officer,
            kid: "key-1".to_string(),
            schema: "provii.age/0".to_string(),
            iat: 1700000000,
            exp: 1731536000,
            signatures_issued: 0,
            officer_id: None,
            client_id: None,
            status: SessionStatus::Pending,
            absolute_expiry: 1700003600,
            client_ip: None,
            user_agent: None,
        };

        assert!(session.officer_id.is_none());
        assert!(session.client_id.is_none());
        assert_eq!(session.status, SessionStatus::Pending);
    }

    #[test]
    fn test_issuance_session_officer_binding() {
        let mut session = IssuanceSession {
            session_id: "test-session-id".to_string(),
            created_at: 1700000000,
            expires_at: 1700000300,
            actor: ActorType::Officer,
            kid: "key-1".to_string(),
            schema: "provii.age/0".to_string(),
            iat: 1700000000,
            exp: 1731536000,
            signatures_issued: 0,
            officer_id: None,
            client_id: None,
            status: SessionStatus::Pending,
            absolute_expiry: 0,
            client_ip: None,
            user_agent: None,
        };

        session.officer_id = Some("officer-123".to_string());
        session.status = SessionStatus::Authenticated;

        assert_eq!(session.officer_id, Some("officer-123".to_string()));
        assert_eq!(session.status, SessionStatus::Authenticated);
    }

    #[test]
    fn test_issuance_session_client_binding() {
        let mut session = IssuanceSession {
            session_id: "test-session-id".to_string(),
            created_at: 1700000000,
            expires_at: 1700000300,
            actor: ActorType::Client,
            kid: "key-1".to_string(),
            schema: "provii.age/0".to_string(),
            iat: 1700000000,
            exp: 1731536000,
            signatures_issued: 0,
            officer_id: None,
            client_id: None,
            status: SessionStatus::Pending,
            absolute_expiry: 0,
            client_ip: None,
            user_agent: None,
        };

        session.client_id = Some("client-456".to_string());
        session.status = SessionStatus::Authenticated;

        assert_eq!(session.client_id, Some("client-456".to_string()));
        assert_eq!(session.status, SessionStatus::Authenticated);
    }

    #[test]
    fn test_issuance_session_status_transitions() {
        let mut session = IssuanceSession {
            session_id: "test-session-id".to_string(),
            created_at: 1700000000,
            expires_at: 1700000300,
            actor: ActorType::Officer,
            kid: "key-1".to_string(),
            schema: "provii.age/0".to_string(),
            iat: 1700000000,
            exp: 1731536000,
            signatures_issued: 0,
            officer_id: Some("officer-123".to_string()),
            client_id: None,
            status: SessionStatus::Pending,
            absolute_expiry: 0,
            client_ip: None,
            user_agent: None,
        };

        // Pending → Authenticated
        session.status = SessionStatus::Authenticated;
        assert_eq!(session.status, SessionStatus::Authenticated);

        // Authenticated → Completed
        session.status = SessionStatus::Completed;
        assert_eq!(session.status, SessionStatus::Completed);
    }

    #[test]
    fn test_issuance_session_expired_status() {
        let mut session = IssuanceSession {
            session_id: "test-session-id".to_string(),
            created_at: 1700000000,
            expires_at: 1700000300,
            actor: ActorType::Officer,
            kid: "key-1".to_string(),
            schema: "provii.age/0".to_string(),
            iat: 1700000000,
            exp: 1731536000,
            signatures_issued: 0,
            officer_id: None,
            client_id: None,
            status: SessionStatus::Pending,
            absolute_expiry: 0,
            client_ip: None,
            user_agent: None,
        };

        session.status = SessionStatus::Expired;
        assert_eq!(session.status, SessionStatus::Expired);
    }

    #[test]
    fn test_session_serialization_roundtrip() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let session = IssuanceSession {
            session_id: "test-session-id".to_string(),
            created_at: 1700000000,
            expires_at: 1700000300,
            actor: ActorType::Officer,
            kid: "key-1".to_string(),
            schema: "provii.age/0".to_string(),
            iat: 1700000000,
            exp: 1731536000,
            signatures_issued: 0,
            officer_id: Some("officer-123".to_string()),
            client_id: None,
            status: SessionStatus::Authenticated,
            absolute_expiry: 0,
            client_ip: None,
            user_agent: None,
        };

        let json = serde_json::to_string(&session)?;
        let deserialized: IssuanceSession = serde_json::from_str(&json)?;

        assert_eq!(deserialized.session_id, session.session_id);
        assert_eq!(deserialized.created_at, session.created_at);
        assert_eq!(deserialized.expires_at, session.expires_at);
        assert_eq!(deserialized.actor, session.actor);
        assert_eq!(deserialized.kid, session.kid);
        assert_eq!(deserialized.schema, session.schema);
        assert_eq!(deserialized.officer_id, session.officer_id);
        assert_eq!(deserialized.client_id, session.client_id);
        assert_eq!(deserialized.status, session.status);
        Ok(())
    }

    /* ========================================================================== */
    /*                    ISSUER CONFIG TESTS (DEFAULT VALUES)                  */
    /* ========================================================================== */

    #[test]
    fn test_issuer_config_default_structure() {
        let config = IssuerConfig {
            issuer_id: "gov.au/homeaffairs".to_string(),
            rp_id: "issuer.provii.app".to_string(),
            default_kid: "gov:2025-08".to_string(),
            previous_kid: None,
            default_policy: PolicyConfig {
                schema: "provii.age/0".to_string(),
                validity_days: 3650,
                v: 2,
            },
        };

        assert_eq!(config.issuer_id, "gov.au/homeaffairs");
        assert_eq!(config.rp_id, "issuer.provii.app");
        assert_eq!(config.default_kid, "gov:2025-08");
        assert_eq!(config.previous_kid, None);
        assert_eq!(config.default_policy.schema, "provii.age/0");
        assert_eq!(config.default_policy.validity_days, 3650);
        assert_eq!(config.default_policy.v, 2);
    }

    #[test]
    fn test_issuer_config_serialization() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let config = IssuerConfig {
            issuer_id: "test.gov".to_string(),
            rp_id: "issuer.test.gov".to_string(),
            default_kid: "test-key-1".to_string(),
            previous_kid: None,
            default_policy: PolicyConfig {
                schema: "test.schema/1".to_string(),
                validity_days: 365,
                v: 1,
            },
        };

        let json = serde_json::to_string(&config)?;
        let deserialized: IssuerConfig = serde_json::from_str(&json)?;

        assert_eq!(deserialized.issuer_id, config.issuer_id);
        assert_eq!(deserialized.rp_id, config.rp_id);
        assert_eq!(deserialized.default_kid, config.default_kid);
        assert_eq!(
            deserialized.default_policy.schema,
            config.default_policy.schema
        );
        assert_eq!(
            deserialized.default_policy.validity_days,
            config.default_policy.validity_days
        );
        assert_eq!(deserialized.default_policy.v, config.default_policy.v);
        Ok(())
    }

    /* ========================================================================== */
    /*                    KEYPAIR STORAGE TESTS (LOGIC ONLY)                    */
    /* ========================================================================== */

    #[test]
    fn test_keypair_json_structure() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let sk = vec![0x01; 32];
        let vk = vec![0x02; 32];

        let sk_b64 = URL_SAFE_NO_PAD.encode(&sk);
        let vk_b64 = URL_SAFE_NO_PAD.encode(&vk);

        let keypair = serde_json::json!({
            "sk": sk_b64,
            "vk": vk_b64,
        });

        assert!(keypair["sk"].is_string());
        assert!(keypair["vk"].is_string());
        assert_eq!(keypair["sk"].as_str().ok_or("expected string")?, sk_b64);
        assert_eq!(keypair["vk"].as_str().ok_or("expected string")?, vk_b64);
        Ok(())
    }

    #[test]
    fn test_keypair_base64_decoding() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let original_sk = vec![0xAB; 32];
        let original_vk = vec![0xCD; 32];

        let sk_b64 = URL_SAFE_NO_PAD.encode(&original_sk);
        let vk_b64 = URL_SAFE_NO_PAD.encode(&original_vk);

        let decoded_sk = URL_SAFE_NO_PAD.decode(&sk_b64)?;
        let decoded_vk = URL_SAFE_NO_PAD.decode(&vk_b64)?;

        assert_eq!(decoded_sk, original_sk);
        assert_eq!(decoded_vk, original_vk);
        assert_eq!(decoded_sk.len(), 32);
        assert_eq!(decoded_vk.len(), 32);
        Ok(())
    }

    /* ========================================================================== */
    /*                    OFFICER/CLIENT REGISTRY TESTS (LOGIC ONLY)           */
    /* ========================================================================== */

    #[test]
    fn test_officer_registration_active_check() {
        let active_officer = OfficerRegistration {
            officer_id: "officer-1".to_string(),
            hmac_secret: vec![0x01; 32],
            active: true,
            created_at: 1700000000,
            last_used: None,
            encrypted: false,
            secret_status: crate::types::KeyStatus::Active,
            previous_hmac_secret: None,
            role: crate::types::Role::default(),
        };

        assert!(active_officer.active);

        let inactive_officer = OfficerRegistration {
            officer_id: "officer-2".to_string(),
            hmac_secret: vec![0x02; 32],
            active: false,
            created_at: 1700000000,
            last_used: None,
            encrypted: false,
            secret_status: crate::types::KeyStatus::Active,
            previous_hmac_secret: None,
            role: crate::types::Role::default(),
        };

        assert!(!inactive_officer.active);
    }

    #[test]
    fn test_officer_last_used_update() {
        let mut officer = OfficerRegistration {
            officer_id: "officer-3".to_string(),
            hmac_secret: vec![0x03; 32],
            active: true,
            created_at: 1700000000,
            last_used: None,
            encrypted: false,
            secret_status: crate::types::KeyStatus::Active,
            previous_hmac_secret: None,
            role: crate::types::Role::default(),
        };

        assert!(officer.last_used.is_none());

        officer.last_used = Some(1700001000);
        assert_eq!(officer.last_used, Some(1700001000));
    }

    #[test]
    fn test_client_registration_active_check() {
        let active_client = ClientRegistration {
            client_id: "client-1".to_string(),
            client_name: "Test Client".to_string(),
            api_key_hash: b"hash123".to_vec(),
            hmac_secret: vec![0x04; 32],
            allowed_schemas: vec!["provii.age/0".to_string()],
            rate_limit: 100,
            max_validity_days: 3650,
            active: true,
            created_at: 1700000000,
            last_used: None,
            encrypted: false,
            secret_status: crate::types::KeyStatus::Active,
            previous_hmac_secret: None,
            role: crate::types::Role::default(),
            kv_key: None,
        };

        assert!(active_client.active);

        let inactive_client = ClientRegistration {
            client_id: "client-2".to_string(),
            client_name: "Inactive Client".to_string(),
            api_key_hash: b"hash456".to_vec(),
            hmac_secret: vec![0x05; 32],
            allowed_schemas: vec![],
            rate_limit: 10,
            max_validity_days: 365,
            active: false,
            created_at: 1700000000,
            last_used: None,
            encrypted: false,
            secret_status: crate::types::KeyStatus::Active,
            previous_hmac_secret: None,
            role: crate::types::Role::default(),
            kv_key: None,
        };

        assert!(!inactive_client.active);
    }

    #[test]
    fn test_client_schema_allowlist() {
        let client = ClientRegistration {
            client_id: "client-3".to_string(),
            client_name: "Test Client".to_string(),
            api_key_hash: b"hash789".to_vec(),
            hmac_secret: vec![0x06; 32],
            allowed_schemas: vec!["provii.age/0".to_string(), "provii.identity/1".to_string()],
            rate_limit: 50,
            max_validity_days: 1825,
            active: true,
            created_at: 1700000000,
            last_used: None,
            encrypted: false,
            secret_status: crate::types::KeyStatus::Active,
            previous_hmac_secret: None,
            role: crate::types::Role::default(),
            kv_key: None,
        };

        assert_eq!(client.allowed_schemas.len(), 2);
        assert!(client.allowed_schemas.contains(&"provii.age/0".to_string()));
        assert!(client
            .allowed_schemas
            .contains(&"provii.identity/1".to_string()));
        assert!(!client
            .allowed_schemas
            .contains(&"provii.other/1".to_string()));
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                  */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        #[test]
        fn prop_ttl_calculation_always_positive(
            expires_at in 1700000000i64..1800000000i64,
            now in 1700000000i64..1750000000i64,
        ) {
            let remaining = (expires_at - now).max(1) as u64;
            assert!(remaining >= 1, "TTL should always be at least 1");
        }

        #[test]
        fn prop_ttl_calculation_monotonic(
            expires_at in 1700000000i64..1800000000i64,
            offset in 0i64..1000i64,
        ) {
            let now1 = expires_at - 1000;
            let now2 = now1 + offset;

            let ttl1 = (expires_at - now1).max(1) as u64;
            let ttl2 = (expires_at - now2).max(1) as u64;

            // As time progresses, TTL should decrease or stay at 1
            assert!(ttl2 <= ttl1, "TTL should be monotonically decreasing");
        }

        #[test]
        fn prop_expiry_check_consistency(
            expires_at in 1700000000i64..1800000000i64,
            now in 1700000000i64..1800000000i64,
        ) {
            let is_expired = expires_at < now;
            let is_not_expired = expires_at >= now;

            // These should be mutually exclusive
            assert!(is_expired != is_not_expired);
        }

        #[test]
        fn prop_challenge_serialization_roundtrip(
            challenge_id in "[a-zA-Z0-9\\-]{10,50}",
            officer_id in "[a-zA-Z0-9\\-]{5,30}",
            challenge_bytes in prop::collection::vec(any::<u8>(), 1..100),
        ) {
            let challenge = StoredChallenge {
                challenge_id: challenge_id.clone(),
                officer_id: officer_id.clone(),
                challenge: challenge_bytes.clone(),
                created_at: 1700000000,
                expires_at: 1700000120,
                used: false,
            };

            let json = serde_json::to_string(&challenge).unwrap();
            let deserialized: StoredChallenge = serde_json::from_str(&json).unwrap();

            assert_eq!(deserialized.challenge_id, challenge_id);
            assert_eq!(deserialized.officer_id, officer_id);
            assert_eq!(deserialized.challenge, challenge_bytes);
        }

        #[test]
        fn prop_session_serialization_roundtrip(
            kid in "[a-zA-Z0-9:\\-]{5,20}",
            schema in "[a-zA-Z0-9./]{5,30}",
        ) {
            let session = IssuanceSession {
                session_id: "test-session-id".to_string(),
                created_at: 1700000000,
                expires_at: 1700000300,
                actor: ActorType::Officer,
                kid: kid.clone(),
                schema: schema.clone(),
                iat: 1700000000,
                exp: 1731536000,
                signatures_issued: 0,
                officer_id: Some("officer-123".to_string()),
                client_id: None,
                status: SessionStatus::Authenticated,
                absolute_expiry: 0,
            client_ip: None,
            user_agent: None,
            };

            let json = serde_json::to_string(&session).unwrap();
            let deserialized: IssuanceSession = serde_json::from_str(&json).unwrap();

            assert_eq!(deserialized.kid, kid);
            assert_eq!(deserialized.schema, schema);
            assert_eq!(deserialized.actor, ActorType::Officer);
        }

        #[test]
        fn prop_keypair_base64_roundtrip(
            sk_bytes in prop::collection::vec(any::<u8>(), 32..=32),
            vk_bytes in prop::collection::vec(any::<u8>(), 32..=32),
        ) {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

            let sk_b64 = URL_SAFE_NO_PAD.encode(&sk_bytes);
            let vk_b64 = URL_SAFE_NO_PAD.encode(&vk_bytes);

            let sk_decoded = URL_SAFE_NO_PAD.decode(&sk_b64).unwrap();
            let vk_decoded = URL_SAFE_NO_PAD.decode(&vk_b64).unwrap();

            assert_eq!(sk_decoded, sk_bytes);
            assert_eq!(vk_decoded, vk_bytes);
            assert_eq!(sk_decoded.len(), 32);
            assert_eq!(vk_decoded.len(), 32);
        }

        #[test]
        fn prop_audit_ttl_constant(days in 1u64..365) {
            // Audit TTL should always be 90 days
            let expected_ttl = 90 * 24 * 3600;
            assert_eq!(expected_ttl, 7_776_000);
            // Verify relationship
            assert!(expected_ttl > days * 24 * 3600 || days >= 90);
        }

        #[test]
        fn prop_key_format_consistency(
            id in "[a-zA-Z0-9\\-]{5,30}",
        ) {
            let challenge_key = format!("challenge:{}", id);
            let session_key = format!("session:{}", id);
            let pickup_key = format!("pickup:{}", id);

            // All keys should have their prefix
            assert!(challenge_key.starts_with("challenge:"));
            assert!(session_key.starts_with("session:"));
            assert!(pickup_key.starts_with("pickup:"));

            // Suffix should match input
            assert!(challenge_key.ends_with(&id));
            assert!(session_key.ends_with(&id));
            assert!(pickup_key.ends_with(&id));
        }
    }

    /* ========================================================================== */
    /*                    ADDITIONAL EDGE CASE TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_ttl_calculation_negative_time() {
        // When now > expires_at, should still return minimum of 1
        let expires_at = 1700000000i64;
        let now = 1700001000i64; // 1000 seconds after expiry
        let remaining = (expires_at - now).max(1) as u64;
        assert_eq!(remaining, 1);
    }

    #[test]
    fn test_ttl_calculation_far_future() {
        // Very large TTL values should work correctly
        let expires_at = 2000000000i64;
        let now = 1700000000i64;
        let remaining = (expires_at - now).max(1) as u64;
        assert_eq!(remaining, 300000000);
    }

    #[test]
    fn test_stored_challenge_all_fields() {
        // Verify all fields are present and correct
        let challenge = StoredChallenge {
            challenge_id: "id-123".to_string(),
            officer_id: "off-456".to_string(),
            challenge: vec![1, 2, 3, 4, 5, 6, 7, 8],
            created_at: 1700000000,
            expires_at: 1700000120,
            used: false,
        };

        assert_eq!(challenge.challenge_id, "id-123");
        assert_eq!(challenge.officer_id, "off-456");
        assert_eq!(challenge.challenge, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(challenge.created_at, 1700000000);
        assert_eq!(challenge.expires_at, 1700000120);
        assert!(!challenge.used);
    }

    #[test]
    fn test_session_all_actor_types() {
        // Test both Officer and Client actor types
        let officer_session = IssuanceSession {
            session_id: "test-session-id".to_string(),
            created_at: 1700000000,
            expires_at: 1700000300,
            actor: ActorType::Officer,
            kid: "key-1".to_string(),
            schema: "provii.age/0".to_string(),
            iat: 1700000000,
            exp: 1731536000,
            signatures_issued: 0,
            officer_id: Some("officer-123".to_string()),
            client_id: None,
            status: SessionStatus::Authenticated,
            absolute_expiry: 0,
            client_ip: None,
            user_agent: None,
        };

        let client_session = IssuanceSession {
            session_id: "test-session-id".to_string(),
            created_at: 1700000000,
            expires_at: 1700000300,
            actor: ActorType::Client,
            kid: "key-1".to_string(),
            schema: "provii.age/0".to_string(),
            iat: 1700000000,
            exp: 1731536000,
            signatures_issued: 0,
            officer_id: None,
            client_id: Some("client-456".to_string()),
            status: SessionStatus::Authenticated,
            absolute_expiry: 0,
            client_ip: None,
            user_agent: None,
        };

        assert_eq!(officer_session.actor, ActorType::Officer);
        assert_eq!(client_session.actor, ActorType::Client);
    }

    #[test]
    fn test_session_all_status_types() {
        // Test all possible session statuses
        let statuses = vec![
            SessionStatus::Pending,
            SessionStatus::Authenticated,
            SessionStatus::Completed,
            SessionStatus::Expired,
        ];

        for status in statuses {
            let session = IssuanceSession {
                session_id: "test-session-id".to_string(),
                created_at: 1700000000,
                expires_at: 1700000300,
                actor: ActorType::Officer,
                kid: "key-1".to_string(),
                schema: "provii.age/0".to_string(),
                iat: 1700000000,
                exp: 1731536000,
                signatures_issued: 0,
                officer_id: None,
                client_id: None,
                status,
                absolute_expiry: 0,
                client_ip: None,
                user_agent: None,
            };

            // Verify status is set correctly
            assert_eq!(session.status, status);
        }
    }

    #[test]
    fn test_issuer_config_all_fields() {
        let config = IssuerConfig {
            issuer_id: "test-issuer".to_string(),
            rp_id: "test-rp".to_string(),
            default_kid: "test-kid".to_string(),
            previous_kid: Some("prior-kid".to_string()),
            default_policy: PolicyConfig {
                schema: "test-schema".to_string(),
                validity_days: 365,
                v: 1,
            },
        };

        assert_eq!(config.issuer_id, "test-issuer");
        assert_eq!(config.rp_id, "test-rp");
        assert_eq!(config.default_kid, "test-kid");
        assert_eq!(config.previous_kid.as_deref(), Some("prior-kid"));
        assert_eq!(config.default_policy.schema, "test-schema");
        assert_eq!(config.default_policy.validity_days, 365);
        assert_eq!(config.default_policy.v, 1);
    }

    #[test]
    fn test_officer_registration_serialization_roundtrip(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let officer = OfficerRegistration {
            officer_id: "off-123".to_string(),
            hmac_secret: vec![0xAA; 32],
            active: true,
            created_at: 1700000000,
            last_used: Some(1700001000),
            encrypted: false,
            secret_status: crate::types::KeyStatus::Active,
            previous_hmac_secret: None,
            role: crate::types::Role::default(),
        };

        let json = serde_json::to_string(&officer)?;
        let deserialized: OfficerRegistration = serde_json::from_str(&json)?;

        assert_eq!(deserialized.officer_id, officer.officer_id);
        assert_eq!(deserialized.hmac_secret, officer.hmac_secret);
        assert_eq!(deserialized.active, officer.active);
        assert_eq!(deserialized.created_at, officer.created_at);
        assert_eq!(deserialized.last_used, officer.last_used);
        Ok(())
    }

    #[test]
    fn test_client_registration_serialization_roundtrip(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let client = ClientRegistration {
            client_id: "cli-789".to_string(),
            client_name: "Test Client".to_string(),
            api_key_hash: b"hash-abc".to_vec(),
            hmac_secret: vec![0xBB; 32],
            allowed_schemas: vec!["schema1".to_string(), "schema2".to_string()],
            rate_limit: 100,
            max_validity_days: 365,
            active: true,
            created_at: 1700000000,
            last_used: None,
            encrypted: false,
            secret_status: crate::types::KeyStatus::Active,
            previous_hmac_secret: None,
            role: crate::types::Role::default(),
            kv_key: None,
        };

        let json = serde_json::to_string(&client)?;
        let deserialized: ClientRegistration = serde_json::from_str(&json)?;

        assert_eq!(deserialized.client_id, client.client_id);
        assert_eq!(deserialized.client_name, client.client_name);
        assert_eq!(deserialized.api_key_hash, client.api_key_hash);
        assert_eq!(deserialized.hmac_secret, client.hmac_secret);
        assert_eq!(deserialized.allowed_schemas, client.allowed_schemas);
        assert_eq!(deserialized.rate_limit, client.rate_limit);
        assert_eq!(deserialized.max_validity_days, client.max_validity_days);
        assert_eq!(deserialized.active, client.active);
        Ok(())
    }

    #[test]
    fn test_key_format_special_characters() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Test various special characters in key components
        let challenge_id = "chal-123_abc:def";
        let key = format!("challenge:{}", challenge_id);
        assert_eq!(key, "challenge:chal-123_abc:def");

        let session_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
        let key = format!("session:{}", session_id);
        assert_eq!(key, "session:550e8400-e29b-41d4-a716-446655440000");
        Ok(())
    }

    /* ========================================================================== */
    /*                    KEY ROTATION LOGIC TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_signing_keypair_structure() {
        use crate::types::{KeyStatus, SigningKeypair};

        let keypair = SigningKeypair {
            kid: "gov:2025-01".to_string(),
            sk: "encrypted_sk_data".to_string(),
            vk: "vk_data".to_string(),
            encrypted: true,
            status: KeyStatus::Active,
            created_at: 1700000000,
            deprecated_at: None,
            revoked_at: None,
        };

        assert_eq!(keypair.kid, "gov:2025-01");
        assert!(keypair.encrypted);
        assert_eq!(keypair.status, KeyStatus::Active);
        assert!(keypair.deprecated_at.is_none());
        assert!(keypair.revoked_at.is_none());
    }

    #[test]
    fn test_signing_keypair_deprecation() {
        use crate::types::{KeyStatus, SigningKeypair};

        let mut keypair = SigningKeypair {
            kid: "gov:2025-01".to_string(),
            sk: "sk_data".to_string(),
            vk: "vk_data".to_string(),
            encrypted: true,
            status: KeyStatus::Active,
            created_at: 1700000000,
            deprecated_at: None,
            revoked_at: None,
        };

        // Deprecate the key
        keypair.status = KeyStatus::Deprecated;
        keypair.deprecated_at = Some(1700001000);

        assert_eq!(keypair.status, KeyStatus::Deprecated);
        assert_eq!(keypair.deprecated_at, Some(1700001000));
        assert!(keypair.revoked_at.is_none());
    }

    #[test]
    fn test_signing_keypair_revocation() {
        use crate::types::{KeyStatus, SigningKeypair};

        let mut keypair = SigningKeypair {
            kid: "gov:2025-01".to_string(),
            sk: "sk_data".to_string(),
            vk: "vk_data".to_string(),
            encrypted: true,
            status: KeyStatus::Deprecated,
            created_at: 1700000000,
            deprecated_at: Some(1700001000),
            revoked_at: None,
        };

        // Revoke the key
        keypair.status = KeyStatus::Revoked;
        keypair.revoked_at = Some(1700002000);

        assert_eq!(keypair.status, KeyStatus::Revoked);
        assert_eq!(keypair.deprecated_at, Some(1700001000));
        assert_eq!(keypair.revoked_at, Some(1700002000));
    }

    #[test]
    fn test_signing_keypair_serialization() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::types::{KeyStatus, SigningKeypair};

        let keypair = SigningKeypair {
            kid: "gov:2025-01".to_string(),
            sk: "sk_data".to_string(),
            vk: "vk_data".to_string(),
            encrypted: true,
            status: KeyStatus::Active,
            created_at: 1700000000,
            deprecated_at: None,
            revoked_at: None,
        };

        let json = serde_json::to_string(&keypair)?;
        let decoded: SigningKeypair = serde_json::from_str(&json)?;

        assert_eq!(decoded.kid, keypair.kid);
        assert_eq!(decoded.sk, keypair.sk);
        assert_eq!(decoded.vk, keypair.vk);
        assert_eq!(decoded.encrypted, keypair.encrypted);
        assert_eq!(decoded.status, keypair.status);
        assert_eq!(decoded.created_at, keypair.created_at);
        Ok(())
    }

    #[test]
    fn test_key_status_serialization() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::types::KeyStatus;

        let active = KeyStatus::Active;
        let json = serde_json::to_string(&active)?;
        assert_eq!(json, r#""active""#);

        let deprecated = KeyStatus::Deprecated;
        let json = serde_json::to_string(&deprecated)?;
        assert_eq!(json, r#""deprecated""#);

        let revoked = KeyStatus::Revoked;
        let json = serde_json::to_string(&revoked)?;
        assert_eq!(json, r#""revoked""#);
        Ok(())
    }

    #[test]
    fn test_key_status_deserialization() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::types::KeyStatus;

        let active: KeyStatus = serde_json::from_str(r#""active""#)?;
        assert_eq!(active, KeyStatus::Active);

        let deprecated: KeyStatus = serde_json::from_str(r#""deprecated""#)?;
        assert_eq!(deprecated, KeyStatus::Deprecated);

        let revoked: KeyStatus = serde_json::from_str(r#""revoked""#)?;
        assert_eq!(revoked, KeyStatus::Revoked);
        Ok(())
    }

    #[test]
    fn test_officer_with_previous_secret() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::types::OfficerRegistration;

        let mut officer = OfficerRegistration {
            officer_id: "off-1".to_string(),
            hmac_secret: vec![0x01; 32],
            created_at: 1700000000,
            last_used: None,
            active: true,
            encrypted: true,
            secret_status: crate::types::KeyStatus::Active,
            previous_hmac_secret: None,
            role: crate::types::Role::default(),
        };

        // Simulate rotation
        officer.previous_hmac_secret = Some(officer.hmac_secret.clone());
        officer.hmac_secret = vec![0x02; 32];

        assert!(officer.previous_hmac_secret.is_some());
        assert_eq!(
            officer
                .previous_hmac_secret
                .as_ref()
                .ok_or("expected Some")?,
            &vec![0x01; 32]
        );
        assert_eq!(officer.hmac_secret, vec![0x02; 32]);
        Ok(())
    }

    #[test]
    fn test_client_with_previous_secret() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::types::ClientRegistration;

        let mut client = ClientRegistration {
            client_id: "client-1".to_string(),
            client_name: "Test".to_string(),
            api_key_hash: b"hash".to_vec(),
            hmac_secret: vec![0xAA; 32],
            created_at: 1700000000,
            last_used: None,
            rate_limit: 100,
            allowed_schemas: vec![],
            max_validity_days: 365,
            active: true,
            encrypted: true,
            secret_status: crate::types::KeyStatus::Active,
            previous_hmac_secret: None,
            role: crate::types::Role::default(),
            kv_key: None,
        };

        // Simulate rotation
        client.previous_hmac_secret = Some(client.hmac_secret.clone());
        client.hmac_secret = vec![0xBB; 32];

        assert!(client.previous_hmac_secret.is_some());
        assert_eq!(
            client
                .previous_hmac_secret
                .as_ref()
                .ok_or("expected Some")?,
            &vec![0xAA; 32]
        );
        assert_eq!(client.hmac_secret, vec![0xBB; 32]);
        Ok(())
    }

    #[test]
    fn test_encryption_decryption_roundtrip() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let kek = vec![0x42; 32];
        let plaintext = b"secret data to encrypt";
        let purpose = b"provii-issuer:session:v1";

        let encrypted = encrypt_with_kek(&kek, plaintext, purpose)?;
        assert!(encrypted.len() > plaintext.len()); // Should include nonce + tag

        let decrypted = decrypt_with_kek(&kek, &encrypted, purpose)?;
        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_encryption_different_nonces() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let kek = vec![0x42; 32];
        let plaintext = b"same plaintext";
        let purpose = b"provii-issuer:session:v1";

        let encrypted1 = encrypt_with_kek(&kek, plaintext, purpose)?;
        let encrypted2 = encrypt_with_kek(&kek, plaintext, purpose)?;

        // Different nonces should produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);

        // Both should decrypt to same plaintext
        let decrypted1 = decrypt_with_kek(&kek, &encrypted1, purpose)?;
        let decrypted2 = decrypt_with_kek(&kek, &encrypted2, purpose)?;
        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
        Ok(())
    }

    #[test]
    fn test_decryption_wrong_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let kek1 = vec![0x42; 32];
        let kek2 = vec![0x43; 32];
        let plaintext = b"secret data";
        let purpose = b"provii-issuer:session:v1";

        let encrypted = encrypt_with_kek(&kek1, plaintext, purpose)?;
        let result = decrypt_with_kek(&kek2, &encrypted, purpose);

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_decryption_wrong_purpose() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let kek = vec![0x42; 32];
        let plaintext = b"secret data";

        let encrypted = encrypt_with_kek(&kek, plaintext, b"provii-issuer:session:v1")?;
        let result = decrypt_with_kek(&kek, &encrypted, b"provii-issuer:signing-key:v1");

        assert!(
            result.is_err(),
            "Decryption with wrong purpose AAD must fail"
        );
        Ok(())
    }

    #[test]
    fn test_decryption_corrupted_data() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let kek = vec![0x42; 32];
        let plaintext = b"secret data";
        let purpose = b"provii-issuer:session:v1";

        let mut encrypted = encrypt_with_kek(&kek, plaintext, purpose)?;

        // Corrupt the ciphertext
        if encrypted.len() > 12 {
            encrypted[12] ^= 0xFF;
        }

        let result = decrypt_with_kek(&kek, &encrypted, purpose);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_decrypt_too_short() {
        let kek = vec![0x42; 32];
        let short_data = vec![0x01; 11]; // Less than 12 bytes (nonce size)

        let result = decrypt_with_kek(&kek, &short_data, b"provii-issuer:session:v1");
        assert!(result.is_err());
    }

    #[test]
    fn test_expiry_boundary_conditions() {
        // Test exact boundary at expiry time
        let expires_at = 1700000000i64;

        // One second before expiry - not expired
        let now_before = 1699999999i64;
        assert!(expires_at >= now_before);

        // Exactly at expiry - not expired (using >= comparison)
        let now_exact = 1700000000i64;
        assert!(expires_at >= now_exact);

        // One second after expiry - expired
        let now_after = 1700000001i64;
        assert!(expires_at < now_after);
    }

    /* ========================================================================== */
    /*                    INTEGRATION TEST DOCUMENTATION                        */
    /* ========================================================================== */

    /* The following functions require Cloudflare Workers KV mocking infrastructure
       and are not testable with standard unit tests. They should be tested in
       integration tests with either:
       1. A real Cloudflare Workers environment (wrangler dev)
       2. A mock KV implementation for testing
       3. E2E tests against deployed Workers

       Functions requiring integration testing:
       - create_challenge() - requires KV put with TTL
       - get_and_consume_challenge() - requires KV get/put
       - get_challenge() - requires KV get
       - create_session() - requires KV put with TTL
       - get_session() - requires KV get
       - update_session_auth() - requires KV get/put
       - update_session_status() - requires KV get/put
       - update_session_expiry() - requires KV get/put
       - increment_signing_count() - requires KV get
       - store_pickup() - requires KV put with TTL
       - consume_pickup() - requires KV get/delete
       - get_signing_keypair() - requires KV get
       - get_officer_by_id() - requires KV get
       - update_officer_last_used_by_id() - requires KV get/put
       - get_client_by_api_key_hash() - requires KV get
       - get_client_by_id() - requires KV get
       - update_client_last_used() - requires KV get/put (dual index)
       - get_issuer_config() - requires KV get and Env var access
       - audit_log() - dispatches to AUDIT_QUEUE

       Test scenarios needed for integration tests:
       1. Challenge lifecycle: create → get → consume → verify used
       2. Session lifecycle: create → get → update auth → update status → get again
       3. Pickup lifecycle: store → consume → verify deleted
       4. TTL expiration: create with TTL → wait → verify auto-deletion
       5. Concurrent operations: multiple consume attempts → only one succeeds
       6. Error cases: missing keys, expired items, serialization failures
       7. Dual-index consistency: client updates maintain both id and api_key_hash
    */

    fn test_kek() -> Vec<u8> {
        let mut kek = vec![0u8; 32];
        getrandom::getrandom(&mut kek).unwrap();
        kek
    }

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let kek = test_kek();
        let ct = encrypt_with_kek(&kek, b"provii-issuer secret", b"provii-issuer:test:v1").unwrap();
        let pt = decrypt_with_kek(&kek, &ct, b"provii-issuer:test:v1").unwrap();
        assert_eq!(pt, b"provii-issuer secret");
    }

    #[test]
    fn encrypt_produces_different_ciphertext_each_call() {
        let kek = test_kek();
        let ct1 = encrypt_with_kek(&kek, b"repeated", b"aad").unwrap();
        let ct2 = encrypt_with_kek(&kek, b"repeated", b"aad").unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn decrypt_with_wrong_kek_fails() {
        let ct = encrypt_with_kek(&test_kek(), b"secret", b"aad").unwrap();
        assert!(decrypt_with_kek(&test_kek(), &ct, b"aad").is_err());
    }

    #[test]
    fn decrypt_with_wrong_aad_fails() {
        let kek = test_kek();
        let ct = encrypt_with_kek(&kek, b"secret", b"A").unwrap();
        assert!(decrypt_with_kek(&kek, &ct, b"B").is_err());
    }

    #[test]
    fn decrypt_empty_ciphertext_fails() {
        assert!(decrypt_with_kek(&test_kek(), &[], b"aad").is_err());
    }

    #[test]
    fn decrypt_too_short_ciphertext_fails() {
        assert!(decrypt_with_kek(&test_kek(), &[0u8; 27], b"aad").is_err());
    }

    #[test]
    fn decrypt_corrupted_nonce_fails() {
        let kek = test_kek();
        let mut ct = encrypt_with_kek(&kek, b"data", b"aad").unwrap();
        ct[0] ^= 0xFF;
        assert!(decrypt_with_kek(&kek, &ct, b"aad").is_err());
    }

    #[test]
    fn decrypt_corrupted_tag_fails() {
        let kek = test_kek();
        let mut ct = encrypt_with_kek(&kek, b"data", b"aad").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        assert!(decrypt_with_kek(&kek, &ct, b"aad").is_err());
    }

    #[test]
    fn encrypt_empty_plaintext_roundtrips() {
        let kek = test_kek();
        let ct = encrypt_with_kek(&kek, b"", b"aad").unwrap();
        assert_eq!(ct.len(), 28);
        assert!(decrypt_with_kek(&kek, &ct, b"aad").unwrap().is_empty());
    }

    #[test]
    fn encrypt_with_invalid_kek_length_fails() {
        assert!(encrypt_with_kek(&[0u8; 16], b"data", b"aad").is_err());
    }

    #[test]
    fn encrypt_large_plaintext_roundtrips() {
        let kek = test_kek();
        let pt = vec![0xABu8; 4096];
        let ct = encrypt_with_kek(&kek, &pt, b"big").unwrap();
        assert_eq!(decrypt_with_kek(&kek, &ct, b"big").unwrap(), pt);
    }

    #[test]
    fn remaining_ttl_secs_future_expiry() {
        let far_future = chrono::Utc::now().timestamp() + 3600;
        let ttl = remaining_ttl_secs(far_future);
        assert!(ttl >= 3598 && ttl <= 3601);
    }

    #[test]
    fn remaining_ttl_secs_past_expiry_clamps_to_one() {
        assert_eq!(remaining_ttl_secs(chrono::Utc::now().timestamp() - 1000), 1);
    }

    #[test]
    fn extract_issuer_kid_strips_did_prefix() {
        assert_eq!(extract_issuer_kid("did:provii:prod-issuer"), "prod-issuer");
    }

    #[test]
    fn extract_issuer_kid_no_prefix_returns_full() {
        assert_eq!(extract_issuer_kid("bare-issuer-id"), "bare-issuer-id");
    }

    #[test]
    fn validate_identifier_accepts_at_sign() {
        assert!(validate_identifier("user@example.com", "email").is_ok());
    }

    #[test]
    fn validate_identifier_rejects_max_length_plus_one() {
        assert!(validate_identifier(&"a".repeat(MAX_IDENTIFIER_LENGTH + 1), "id").is_err());
    }

    #[test]
    fn validate_identifier_accepts_max_length() {
        assert!(validate_identifier(&"a".repeat(MAX_IDENTIFIER_LENGTH), "id").is_ok());
    }

    #[test]
    fn validate_identifier_rejects_tab() {
        assert!(validate_identifier("id\twith-tab", "id").is_err());
    }

    #[test]
    fn default_key_status_returns_active() {
        assert_eq!(default_key_status_active(), KeyStatus::Active);
    }

    #[test]
    fn nonce_ttl_is_five_minutes() {
        assert_eq!(NONCE_TTL_SECONDS, 300);
    }

    #[test]
    fn max_identifier_length_is_128() {
        assert_eq!(MAX_IDENTIFIER_LENGTH, 128);
    }
}
