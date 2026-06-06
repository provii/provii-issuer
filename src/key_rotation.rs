// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Key rotation management for RedJubjub signing keys.
//!
//! This module implements V1/V2/V3 versioned key rotation with expiration tracking.
//! CRITICAL: HMAC-SHA1 for YubiKey is preserved in session.rs (hardware limitation).

use crate::error::{ApiError, Result};
use crate::storage;
use crate::types::KeyStatus;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use worker::*;
use zeroize::{Zeroize, Zeroizing};

/// Versioned signing key with metadata
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct SigningKeyRecord {
    /// Key version (v1, v2, v3, etc.)
    pub version: String,
    /// Unique key identifier
    pub key_id: String,
    /// Base64-encoded encrypted private key (32 bytes RedJubjub)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_encrypted: Option<String>,
    /// Base64-encoded public key (32 bytes RedJubjub)
    pub public_key: String,
    /// Creation timestamp (Unix seconds)
    pub created_at: i64,
    /// Expiration timestamp (Unix seconds)
    pub expires_at: i64,
    /// Current key status
    pub status: KeyStatus,
    /// Whether the key is encrypted with KEK
    #[serde(default = "default_encrypted")]
    pub encrypted: bool,
}

fn default_encrypted() -> bool {
    true
}

impl SigningKeyRecord {
    /// Check if key is expired
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        now > self.expires_at
    }

    /// Check if key is expiring soon (within 30 days)
    pub fn is_expiring_soon(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        let thirty_days = 30 * 24 * 60 * 60;
        now > self.expires_at.saturating_sub(thirty_days) && now <= self.expires_at
    }

    /// Get days until expiration (negative if expired)
    pub fn days_until_expiration(&self) -> i64 {
        let now = chrono::Utc::now().timestamp();
        #[allow(clippy::arithmetic_side_effects)]
        // Division by the constant 86_400 (seconds per day) cannot overflow.
        {
            self.expires_at.saturating_sub(now) / 86_400
        }
    }
}

/// Manages key rotation for the issuer service
pub struct KeyRotationManager<'a> {
    env: &'a Env,
}

impl<'a> KeyRotationManager<'a> {
    /// Create a new key rotation manager
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }

    /// Get all signing keys (all versions, all statuses).
    ///
    /// KV-106: Discovers versions dynamically by listing KV keys with the
    /// issuer-scoped prefix instead of probing a hardcoded set.
    /// Handles pagination via cursor if the list is truncated.
    pub async fn get_all_signing_keys(&self) -> Result<Vec<SigningKeyRecord>> {
        let kv = self.env.kv(crate::bindings::ISSUER_KEYS)?;

        let config = storage::get_issuer_config(self.env).await?;
        let issuer_kid = storage::extract_issuer_kid(&config.issuer_id);
        let prefix = format!("issuer:{}:key:", issuer_kid);

        let mut all_key_names: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let mut builder = kv.list().prefix(prefix.clone());
            if let Some(ref c) = cursor {
                builder = builder.cursor(c.clone());
            }

            let list_result = builder.execute().await.map_err(|e| {
                ApiError::StorageError(format!("Failed to list signing keys: {}", e))
            })?;

            for key_info in list_result.keys.iter() {
                if let Some(version) = key_info.name.strip_prefix(&prefix) {
                    all_key_names.push(version.to_string());
                }
            }

            if list_result.list_complete {
                break;
            }
            cursor = list_result.cursor;
            if cursor.is_none() {
                break;
            }
        }

        let mut keys = Vec::new();
        for version in &all_key_names {
            if let Ok(Some(record)) = self.load_key_record(version).await {
                keys.push(record);
            }
        }

        Ok(keys)
    }

    /// Get active signing key (for signing new credentials)
    ///
    /// R13 (deferred): the audit proposed caching this active-key SELECTION
    /// per-isolate with a short TTL to avoid the `kv.list()` + N
    /// `load_key_record` fan-out on every blind issuance. It is DELIBERATELY NOT
    /// implemented, because it cannot be made rotation-safe in this tree without
    /// risking a signing-correctness regression:
    ///
    ///  * A pure short-TTL cache of the resolved record would keep returning a
    ///    `key_id` whose status has since flipped to Deprecated/Revoked/Disabled
    ///    (rotation at line ~228; revoke/disable via `KeyStatus` at
    ///    types.rs:429) for up to the TTL on a warm isolate, so a freshly
    ///    rotated-out or revoked key could still be selected and signed under -
    ///    exactly the bug the invariant forbids.
    ///  * The provably-safe variant (an explicit active-key pointer written to
    ///    KV on EVERY rotate AND revoke/disable, validated by the cache) does
    ///    not exist today and requires instrumenting a revocation surface that
    ///    is not localised to a single write path here; missing one path would
    ///    silently reintroduce the sign-with-revoked-key hazard.
    ///
    /// The current per-request re-derivation is fail-closed and always correct;
    /// the cache is a latency/cost optimisation gated on real key-version-count
    /// telemetry. Sharding the per-issuer counter (the R13 critical constraint)
    /// is handled separately and needs no cache. Revisit with the pointer design
    /// once the revoke/disable paths are consolidated.
    pub async fn get_active_signing_key(&self) -> Result<SigningKeyRecord> {
        let keys = self.get_all_signing_keys().await?;

        keys.into_iter()
            .find(|k| k.status == KeyStatus::Active && !k.is_expired())
            .ok_or_else(|| ApiError::CryptoError("No active signing key found".to_string()))
    }

    /// Load a specific key version
    async fn load_key_record(&self, version: &str) -> Result<Option<SigningKeyRecord>> {
        let kv = self.env.kv(crate::bindings::ISSUER_KEYS)?;

        // Get issuer_kid for scoped key
        let config = storage::get_issuer_config(self.env).await?;
        let issuer_kid = storage::extract_issuer_kid(&config.issuer_id);
        let key = format!("issuer:{}:key:{}", issuer_kid, version);

        let key_json = match kv.get(&key).text().await {
            Ok(Some(json)) => json,
            Ok(None) => return Ok(None),
            Err(e) => return Err(ApiError::StorageError(format!("Failed to get key: {}", e))),
        };

        let record: SigningKeyRecord = serde_json::from_str(&key_json)
            .map_err(|e| ApiError::StorageError(format!("Failed to parse key record: {}", e)))?;

        Ok(Some(record))
    }

    /// Generate and store a new signing key with rotation.
    ///
    /// AUD-IA-13-012: Acquires a ResourceLockDO mutex before reading
    /// existing keys and writing the new key. This prevents two concurrent
    /// admin requests from assigning the same version number. The lock is
    /// released in all code paths (success and error).
    pub async fn rotate_signing_key(&self) -> Result<SigningKeyRecord> {
        crate::log!("[Key Rotation] Starting key rotation");

        // Acquire distributed lock to prevent concurrent rotation races.
        let lock_key = "key-rotation:signing-key";
        let lock_token = crate::resource_lock::acquire_resource_lock(self.env, lock_key).await?;

        let result = self.rotate_signing_key_inner().await;

        // Always release the lock, even on error
        crate::resource_lock::release_resource_lock(self.env, lock_key, &lock_token).await;

        result
    }

    /// Inner rotation logic, called while holding the distributed lock.
    async fn rotate_signing_key_inner(&self) -> Result<SigningKeyRecord> {
        // Get current keys
        let existing_keys = self.get_all_signing_keys().await?;

        // Determine next version
        let next_version = self.calculate_next_version(&existing_keys);
        crate::log!("[Key Rotation] Next version: {}", next_version);

        // Generate new RedJubjub keypair
        let (private_key, public_key) = self.generate_redjubjub_keypair()?;

        let now = chrono::Utc::now().timestamp();
        let new_key = SigningKeyRecord {
            version: next_version.clone(),
            key_id: format!("provii:{}", next_version),
            private_key_encrypted: None, // Will be set during encryption
            public_key: URL_SAFE_NO_PAD.encode(public_key),
            created_at: now,
            expires_at: now.saturating_add(365 * 24 * 60 * 60), // 1 year expiration
            status: KeyStatus::Active,
            encrypted: true,
        };

        // Collect deprecated key info for audit trail BEFORE mutation
        let deprecated_keys: Vec<serde_json::Value> = existing_keys
            .iter()
            .filter(|k| k.status == KeyStatus::Active)
            .map(|k| {
                serde_json::json!({
                    "version": k.version,
                    "key_id": k.key_id,
                    "created_at": k.created_at,
                    "expires_at": k.expires_at,
                })
            })
            .collect();

        // ADV-IA-37-006: Deprecate old active keys BEFORE storing the new
        // key. If deprecation fails, old keys remain active (safe state).
        // If the subsequent new-key store fails after deprecation, the
        // system has no active key, which is detectable by
        // check_key_health and recoverable by re-running rotation.
        for mut old_key in existing_keys {
            if old_key.status == KeyStatus::Active {
                crate::log!("[Key Rotation] Deprecating key: {}", old_key.version);
                old_key.status = KeyStatus::Deprecated;
                self.save_key_metadata(&old_key).await?;
            }
        }

        // Encrypt and store the new key (now that old keys are deprecated)
        self.store_encrypted_key(&new_key, &*private_key).await?;

        // SECURITY: Full audit trail for key rotation.
        // Includes before-state (which keys were deprecated), new key details,
        // and actor identity for forensic investigation.
        crate::audit::audit_log(
            self.env,
            "signing_key_rotated",
            "system",
            "Signing key rotated to new version",
            &serde_json::json!({
                "new_version": new_key.version,
                "new_key_id": new_key.key_id,
                "expires_at": new_key.expires_at,
                "deprecated_keys": deprecated_keys,
                "deprecated_count": deprecated_keys.len(),
            }),
        )
        .await;

        crate::log!("[Key Rotation] Rotation complete: {}", new_key.version);
        Ok(new_key)
    }

    /// Calculate next version number
    fn calculate_next_version(&self, existing_keys: &[SigningKeyRecord]) -> String {
        next_version_from_keys(existing_keys)
    }

    /// Generate a new RedJubjub keypair.
    /// Returns (private_key, public_key) with the private key wrapped in Zeroizing.
    fn generate_redjubjub_keypair(&self) -> Result<(Zeroizing<[u8; 32]>, [u8; 32])> {
        let (sk, vk) = provii_crypto_sig_redjubjub::generate_keypair();

        // Upstream provii-crypto v0.2.0 returns sk wrapped in Zeroizing
        // already; rewrap through our own Zeroizing so the outer API
        // signature stays stable for downstream callers.
        Ok((Zeroizing::new(*sk), vk))
    }

    /// Store encrypted key in KV
    async fn store_encrypted_key(&self, key: &SigningKeyRecord, private_key: &[u8]) -> Result<()> {
        // Always encrypt with the current KEK
        let kek_pair = crate::kek::get_kek_pair(self.env).await?;

        // KV-109: Include version in AAD so ciphertext is bound to its
        // specific version slot and cannot be transplanted across versions.
        let aad = format!("provii-issuer:signing-key:{}", key.version);
        let encrypted_sk =
            storage::encrypt_with_kek(&kek_pair.current, private_key, aad.as_bytes())?;
        let encrypted_sk_b64 = URL_SAFE_NO_PAD.encode(&encrypted_sk);

        // Create full record
        let mut record = key.clone();
        record.private_key_encrypted = Some(encrypted_sk_b64);

        // Store in KV
        let kv = self.env.kv(crate::bindings::ISSUER_KEYS)?;
        let config = storage::get_issuer_config(self.env).await?;
        let issuer_kid = storage::extract_issuer_kid(&config.issuer_id);
        let key_name = format!("issuer:{}:key:{}", issuer_kid, record.version);
        // Zeroize the serialised record since it contains encrypted private key material
        let record_json = Zeroizing::new(serde_json::to_string(&record)?);

        kv.put(&key_name, record_json.as_str())
            .map_err(|e| ApiError::StorageError(format!("Failed to create put operation: {}", e)))?
            .execute()
            .await
            .map_err(|e| ApiError::StorageError(format!("Failed to store key: {}", e)))?;

        crate::log!("[Key Rotation] Stored encrypted key: {}", record.version);
        Ok(())
    }

    /// Save key metadata (status updates)
    async fn save_key_metadata(&self, key: &SigningKeyRecord) -> Result<()> {
        let kv = self.env.kv(crate::bindings::ISSUER_KEYS)?;
        let config = storage::get_issuer_config(self.env).await?;
        let issuer_kid = storage::extract_issuer_kid(&config.issuer_id);
        let key_name = format!("issuer:{}:key:{}", issuer_kid, key.version);
        let record_json = serde_json::to_string(key)?;

        kv.put(&key_name, record_json)
            .map_err(|e| ApiError::StorageError(format!("Failed to create put operation: {}", e)))?
            .execute()
            .await
            .map_err(|e| ApiError::StorageError(format!("Failed to update key: {}", e)))?;

        Ok(())
    }

    /// Check for expired or expiring keys and log warnings
    pub async fn check_key_health(&self) -> Result<KeyHealthStatus> {
        let keys = self.get_all_signing_keys().await?;
        let mut health = KeyHealthStatus::default();

        for key in &keys {
            if key.status != KeyStatus::Active {
                continue;
            }

            if key.is_expired() {
                crate::log_error!(
                    "CRITICAL: Active signing key expired: {} (expired {} days ago)",
                    key.version,
                    key.days_until_expiration().saturating_neg()
                );
                health.has_expired_active = true;
            } else if key.is_expiring_soon() {
                console_warn!(
                    "WARNING: Signing key expiring soon: {} ({} days remaining)",
                    key.version,
                    key.days_until_expiration()
                );
                health.has_expiring_soon = true;
                health.days_until_expiration = Some(key.days_until_expiration());
            }
        }

        if keys.is_empty() {
            crate::log_error!("CRITICAL: No signing keys found");
            health.has_no_keys = true;
        }

        let active_count = keys
            .iter()
            .filter(|k| k.status == KeyStatus::Active)
            .count();
        if active_count == 0 {
            crate::log_error!("CRITICAL: No active signing keys");
            health.has_no_active = true;
        } else if active_count > 1 {
            console_warn!("WARNING: Multiple active signing keys: {}", active_count);
            health.has_multiple_active = true;
        }

        // Audit critical key health conditions.
        if health.is_critical() {
            crate::audit::audit_log_detailed(
                self.env,
                "key_health_critical",
                "system",
                "Critical key health condition detected",
                &serde_json::json!({
                    "has_expired_active": health.has_expired_active,
                    "has_no_keys": health.has_no_keys,
                    "has_no_active": health.has_no_active,
                    "has_multiple_active": health.has_multiple_active,
                    "has_expiring_soon": health.has_expiring_soon,
                    "days_until_expiration": health.days_until_expiration,
                    "total_keys": keys.len(),
                    "active_keys": active_count,
                }),
                crate::audit::DetailedAuditFields {
                    event_category: provii_audit::EventCategory::KeyAccess,
                    actor_id: "system",
                    outcome: Some(crate::audit::Outcome::Failure),
                    severity: Some(provii_audit::Severity::Critical),
                },
            )
            .await;
        } else if health.has_expiring_soon {
            crate::audit::audit_log(
                self.env,
                "key_health_warning",
                "system",
                "Signing key expiring soon",
                &serde_json::json!({
                    "days_until_expiration": health.days_until_expiration,
                    "has_multiple_active": health.has_multiple_active,
                }),
            )
            .await;
        }

        Ok(health)
    }
}

/// Health status of signing keys
#[derive(Debug, Default)]
pub struct KeyHealthStatus {
    pub has_expired_active: bool,
    pub has_expiring_soon: bool,
    pub has_no_keys: bool,
    pub has_no_active: bool,
    pub has_multiple_active: bool,
    pub days_until_expiration: Option<i64>,
}

impl KeyHealthStatus {
    pub fn is_healthy(&self) -> bool {
        !self.has_expired_active
            && !self.has_no_keys
            && !self.has_no_active
            && !self.has_multiple_active
    }

    pub fn is_critical(&self) -> bool {
        self.has_expired_active || self.has_no_keys || self.has_no_active
    }
}

/// Pure function to calculate the next key version string from existing keys.
///
/// Extracted for testability (no `Env` dependency).
fn next_version_from_keys(existing_keys: &[SigningKeyRecord]) -> String {
    if existing_keys.is_empty() {
        return "v1".to_string();
    }

    // Extract version numbers
    let mut max_version: u32 = 0;
    for key in existing_keys {
        if let Some(num) = key.version.strip_prefix('v') {
            if let Ok(n) = num.parse::<u32>() {
                max_version = max_version.max(n);
            }
        }
    }

    format!("v{}", max_version.saturating_add(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_status_equality() {
        assert_eq!(KeyStatus::Active, KeyStatus::Active);
        assert_ne!(KeyStatus::Active, KeyStatus::Deprecated);
        assert_ne!(KeyStatus::Deprecated, KeyStatus::Disabled);
    }

    #[test]
    fn test_signing_key_expiration() {
        let now = chrono::Utc::now().timestamp();

        // Expired key
        let expired_key = SigningKeyRecord {
            version: "v1".to_string(),
            key_id: "test".to_string(),
            private_key_encrypted: None,
            public_key: "test".to_string(),
            created_at: now - 10000,
            expires_at: now - 100,
            status: KeyStatus::Active,
            encrypted: true,
        };
        assert!(expired_key.is_expired());
        assert!(!expired_key.is_expiring_soon());

        // Expiring soon (20 days)
        let expiring_key = SigningKeyRecord {
            version: "v2".to_string(),
            key_id: "test2".to_string(),
            private_key_encrypted: None,
            public_key: "test2".to_string(),
            created_at: now,
            expires_at: now + (20 * 24 * 60 * 60),
            status: KeyStatus::Active,
            encrypted: true,
        };
        assert!(!expiring_key.is_expired());
        assert!(expiring_key.is_expiring_soon());
        assert_eq!(expiring_key.days_until_expiration(), 20);

        // Valid key (100 days)
        let valid_key = SigningKeyRecord {
            version: "v3".to_string(),
            key_id: "test3".to_string(),
            private_key_encrypted: None,
            public_key: "test3".to_string(),
            created_at: now,
            expires_at: now + (100 * 24 * 60 * 60),
            status: KeyStatus::Active,
            encrypted: true,
        };
        assert!(!valid_key.is_expired());
        assert!(!valid_key.is_expiring_soon());
        assert_eq!(valid_key.days_until_expiration(), 100);
    }

    fn make_key(version: &str) -> SigningKeyRecord {
        SigningKeyRecord {
            version: version.to_string(),
            key_id: "test".to_string(),
            private_key_encrypted: None,
            public_key: "test".to_string(),
            created_at: 0,
            expires_at: i64::MAX,
            status: KeyStatus::Active,
            encrypted: true,
        }
    }

    #[test]
    fn next_version_empty_returns_v1() {
        assert_eq!(next_version_from_keys(&[]), "v1");
    }

    #[test]
    fn next_version_single_key() {
        let keys = vec![make_key("v1")];
        assert_eq!(next_version_from_keys(&keys), "v2");
    }

    #[test]
    fn next_version_non_sequential_picks_max() {
        let keys = vec![make_key("v1"), make_key("v5"), make_key("v2")];
        assert_eq!(next_version_from_keys(&keys), "v6");
    }

    #[test]
    fn next_version_ignores_unparseable_versions() {
        let keys = vec![make_key("v1"), make_key("invalid"), make_key("v3")];
        assert_eq!(next_version_from_keys(&keys), "v4");
    }

    #[test]
    fn next_version_saturates_at_u32_max() {
        let keys = vec![make_key(&format!("v{}", u32::MAX))];
        // saturating_add(1) on u32::MAX stays at u32::MAX
        assert_eq!(next_version_from_keys(&keys), format!("v{}", u32::MAX));
    }
}
