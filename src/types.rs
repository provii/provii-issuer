// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Shared request, response, and storage types for the issuer service.

use core::fmt;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_valid::Validate;
use zeroize::Zeroize;

/// Newtype enforcing that stored IP addresses are pre-hashed.
///
/// Raw IP addresses MUST be hashed via `PrivacyContext::hash_ip()` before
/// wrapping in this type. The inner string contains a hex-encoded
/// HMAC-SHA-256 hash, never a raw IP.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashedIp(String);

impl HashedIp {
    /// Wrap an already-hashed IP string.
    ///
    /// Validates that the value is exactly 64 lowercase hex characters
    /// (the output format of HMAC-SHA-256). Panics in debug builds if
    /// the format is invalid; in release builds an invalid value is
    /// accepted to avoid breaking hot paths, but this indicates a caller bug.
    pub fn new(hashed: String) -> Self {
        debug_assert!(
            hashed.len() == 64 && hashed.chars().all(|c| c.is_ascii_hexdigit()),
            "HashedIp::new called with non-HMAC-SHA-256 hex value (len={})",
            hashed.len()
        );
        Self(hashed)
    }

    /// Borrow the inner hash string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for HashedIp {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Newtype enforcing that stored User-Agents are pre-hashed.
///
/// Raw User-Agent strings MUST be hashed via `PrivacyContext::hash_user_agent()`
/// before wrapping in this type. The inner string contains a hex-encoded
/// HMAC-SHA-256 hash, never a raw User-Agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashedUserAgent(String);

impl HashedUserAgent {
    /// Wrap an already-hashed User-Agent string.
    ///
    /// Validates that the value is exactly 64 lowercase hex characters
    /// (the output format of HMAC-SHA-256). Panics in debug builds if
    /// the format is invalid; in release builds an invalid value is
    /// accepted to avoid breaking hot paths, but this indicates a caller bug.
    pub fn new(hashed: String) -> Self {
        debug_assert!(
            hashed.len() == 64 && hashed.chars().all(|c| c.is_ascii_hexdigit()),
            "HashedUserAgent::new called with non-HMAC-SHA-256 hex value (len={})",
            hashed.len()
        );
        Self(hashed)
    }

    /// Borrow the inner hash string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for HashedUserAgent {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Role-based access control roles for authorization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Role {
    /// Full administrative access to all operations
    Admin,
    /// Standard issuer permissions (default)
    #[default]
    Issuer,
    /// Read-only access to sessions and audit logs
    Viewer,
}

impl Role {
    /// Check if this role has permission to generate challenges.
    pub fn can_generate_challenge(&self) -> bool {
        matches!(self, Role::Admin | Role::Issuer)
    }

    /// Check if this role has permission to issue credentials.
    pub fn can_issue_credential(&self) -> bool {
        matches!(self, Role::Admin | Role::Issuer)
    }

    /// Check if this role has permission to sign commitments.
    pub fn can_sign_commitment(&self) -> bool {
        matches!(self, Role::Admin | Role::Issuer)
    }

    /// Check if this role has permission to view sessions.
    pub fn can_view_sessions(&self) -> bool {
        matches!(self, Role::Admin | Role::Issuer | Role::Viewer)
    }

    /// Check if this role has permission to view audit logs.
    pub fn can_view_audit_logs(&self) -> bool {
        matches!(self, Role::Admin | Role::Issuer | Role::Viewer)
    }

    /// Check if this role has permission to manage keys.
    pub fn can_manage_keys(&self) -> bool {
        matches!(self, Role::Admin)
    }

    /// Check if this role has permission to manage users.
    pub fn can_manage_users(&self) -> bool {
        matches!(self, Role::Admin)
    }
}

// Validation size constants
pub const MAX_CREDENTIAL_SIZE: usize = 10_000; // 10KB
pub const MAX_AUDIT_DETAILS_SIZE: usize = 5_000; // 5KB
pub const MAX_COMMITMENT_SIZE: usize = 1_000; // 1KB
pub const MAX_SESSION_METADATA_SIZE: usize = 2_000; // 2KB
/// Maximum length for a schema URL value. Bounds a
/// possibly-fully-qualified URL, not a short identifier. Distinct from
/// the blind-issuance identifier cap `MAX_SCHEMA_LENGTH` defined in
/// `routes.rs` (128 chars), which applies to a different code path.
pub const MAX_SCHEMA_VALUE_URL_LENGTH: usize = 500;
pub const MAX_OFFICER_ID_LENGTH: usize = 128;
pub const MAX_CLIENT_ID_LENGTH: usize = 128;
pub const MAX_KID_LENGTH: usize = 64;
pub const MAX_ACTOR_LENGTH: usize = 32;
pub const MAX_FORMAT_LENGTH: usize = 32;
pub const MAX_KEY_ID_LENGTH: usize = 128;
pub const MAX_CHALLENGE_ID_LENGTH: usize = 64;
pub const MAX_HMAC_LENGTH: usize = 256;
pub const MAX_NONCE_LENGTH: usize = 128;
pub const MAX_SESSION_ID_LENGTH: usize = 64;
pub const MAX_BLOB_LENGTH: usize = 50_000; // 50KB for base64 encoded blobs
pub const MAX_TOKEN_LENGTH: usize = 64;
/// IV-207: Maximum number of allowed_schemas entries per client registration.
pub const MAX_ALLOWED_SCHEMAS: usize = 50;

fn validate_schema_url(schema: &Option<String>) -> Result<(), serde_valid::validation::Error> {
    if let Some(s) = schema {
        if s.is_empty() {
            return Err(serde_valid::validation::Error::Custom(
                "Schema cannot be empty".to_string(),
            ));
        }
        // Basic URL validation - will be enhanced in routes.rs
        if !s.chars().all(|c| c.is_ascii() && !c.is_control()) {
            return Err(serde_valid::validation::Error::Custom(
                "Schema contains invalid characters".to_string(),
            ));
        }
    }
    Ok(())
}

/// Enumerates the two supported session actors.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ActorType {
    Officer,
    Client,
}

/// Request body for provisioning a YubiKey challenge.
/// IV-205: deny_unknown_fields prevents unexpected fields in external input.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Validate)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    /// Officer identifier expecting to answer the challenge.
    #[validate(max_length = 128)]
    #[validate(custom(validate_identifier_format))]
    pub officer_id: String,
}

fn validate_identifier_format(id: &str) -> Result<(), serde_valid::validation::Error> {
    if id.is_empty() {
        return Err(serde_valid::validation::Error::Custom(
            "Identifier cannot be empty".to_string(),
        ));
    }
    // Only allow safe characters for identifiers
    if !id.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '-'
            || c == '_'
            || c == ':'
            || c == '.'
            || c == '/'
            || c == '@'
    }) {
        return Err(serde_valid::validation::Error::Custom(
            "Identifier contains invalid characters".to_string(),
        ));
    }
    Ok(())
}

/// Response payload containing the generated challenge material.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ChallengeResponse {
    /// Server-issued challenge identifier.
    pub challenge_id: String,
    /// Hex-encoded challenge bytes delivered to the client device.
    pub challenge: String,
    /// Absolute expiration timestamp for the challenge.
    pub expires_at: i64,
}

/// Standardized authentication envelope shared by officers and clients.
/// IV-205: deny_unknown_fields prevents unexpected fields in external input.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Validate)]
#[serde(deny_unknown_fields)]
pub struct Authorizer {
    /// Declares the authentication mechanism (`"yubikey"` or `"client"`).
    #[validate(max_length = 32)]
    #[validate(custom(validate_auth_format))]
    pub format: String,
    /// Identifier of the key used to produce the HMAC.
    #[serde(rename = "keyId")]
    #[validate(max_length = 128)]
    #[validate(custom(validate_identifier_format))]
    pub key_id: String,
    /// Challenge identifier required for YubiKey flows.
    #[serde(rename = "challengeId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(max_length = 64)]
    pub challenge_id: Option<String>,
    /// Unix timestamp in SECONDS included in the canonical message.
    /// Window 30 seconds (compared against provii-verifier's 300-second
    /// window in its own HMAC verification). See `validate_timestamp`
    /// in `session.rs` and `TIMESTAMP_WINDOW_SECONDS = 30`.
    pub timestamp: u64,
    /// Hex-encoded HMAC over the canonical payload.
    #[validate(max_length = 256)]
    pub hmac: String,
    /// Cryptographic nonce for replay protection (64 hex chars / 256 bits, mandatory).
    #[validate(min_length = 64)]
    #[validate(max_length = 64)]
    #[validate(custom(validate_hex_string))]
    pub nonce: String,
}

fn validate_auth_format(format: &str) -> Result<(), serde_valid::validation::Error> {
    if format != "yubikey" && format != "client" {
        return Err(serde_valid::validation::Error::Custom(
            "Format must be 'yubikey' or 'client'".to_string(),
        ));
    }
    Ok(())
}

fn validate_hex_string(s: &str) -> Result<(), serde_valid::validation::Error> {
    if s.is_empty() {
        return Err(serde_valid::validation::Error::Custom(
            "Hex string cannot be empty".to_string(),
        ));
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(serde_valid::validation::Error::Custom(
            "String must contain only hexadecimal characters".to_string(),
        ));
    }
    Ok(())
}

/// Public header returned after a commitment is signed.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignedCredentialHeader {
    /// Data structure version number.
    pub v: u8,
    /// Key identifier used to produce the signature.
    pub kid: String,
    #[serde(with = "base64_bytes")]
    #[schemars(with = "String")]
    // 32 raw bytes -> base64url(no-pad) length 43.
    #[schemars(extend(
        "minLength" = 43,
        "maxLength" = 43,
        "contentEncoding" = "base64url",
        "contentMediaType" = "application/octet-stream"
    ))]
    /// Issuer verification key material.
    pub issuer_vk: [u8; 32],
    #[serde(with = "base64_bytes_64")]
    #[schemars(with = "String")]
    // 64 raw bytes -> base64url(no-pad) length 86.
    #[schemars(extend(
        "minLength" = 86,
        "maxLength" = 86,
        "contentEncoding" = "base64url",
        "contentMediaType" = "application/octet-stream"
    ))]
    /// RedJubjub signature bytes.
    pub sig_rj: [u8; 64],
    #[serde(with = "base64_bytes")]
    #[schemars(with = "String")]
    // 32 raw bytes -> base64url(no-pad) length 43.
    #[schemars(extend(
        "minLength" = 43,
        "maxLength" = 43,
        "contentEncoding" = "base64url",
        "contentMediaType" = "application/octet-stream"
    ))]
    /// Commitment bytes included in the credential.
    pub c_bytes: [u8; 32],
    /// Credential issuance timestamp.
    pub iat: u64,
    /// Credential expiry timestamp.
    pub exp: u64,
    /// Schema identifier describing the credential contents.
    pub schema: String,
}

fn validate_base64_string(s: &str) -> Result<(), serde_valid::validation::Error> {
    if s.is_empty() {
        return Err(serde_valid::validation::Error::Custom(
            "Base64 string cannot be empty".to_string(),
        ));
    }
    // Check for valid base64url characters
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(serde_valid::validation::Error::Custom(
            "Invalid base64url encoding".to_string(),
        ));
    }
    Ok(())
}

/// Session record persisted in storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceSession {
    /// Unique identifier for the session (256-bit base64url-encoded).
    pub session_id: String,
    /// When the session was created.
    pub created_at: i64,
    /// When the session will expire without activity.
    pub expires_at: i64,
    /// The actor type that initiated the session.
    pub actor: ActorType,
    /// Signing key identifier associated with the session.
    pub kid: String,
    /// Credential schema selected for issuance.
    pub schema: String,
    /// Issued-at timestamp that will appear in the credential.
    pub iat: u64,
    /// Expiry timestamp that will appear in the credential.
    pub exp: u64,
    #[serde(default)]
    /// Number of signatures issued during this session.
    pub signatures_issued: u32,
    /// Lifecycle status of the session.
    pub status: SessionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Officer identifier bound after authentication.
    pub officer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Client identifier bound after authentication.
    pub client_id: Option<String>,
    #[serde(default)]
    /// Absolute expiration timestamp (cannot be extended)
    pub absolute_expiry: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Client IP hash for session binding (must be pre-hashed via PrivacyContext).
    pub client_ip: Option<HashedIp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Client User-Agent hash for session binding (must be pre-hashed
    /// via `PrivacyContext::hash_user_agent()`).
    pub user_agent: Option<HashedUserAgent>,
}

/// Possible lifecycle states for an issuance session.
///
/// `Completed` is defined in the state machine (Authenticated -> Completed)
/// but no production code path currently transitions to it. Retained for forward
/// compatibility with multi-step issuance flows where explicit completion tracking
/// is needed. Removing it would break the state machine invariant that authenticated
/// sessions have a terminal success state distinct from expiry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    #[default]
    Pending,
    Authenticated,
    Completed,
    Expired,
}

/// Lifecycle status for cryptographic keys and secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    /// Key is active and should be used for new operations
    #[default]
    Active,
    /// Key is deprecated but still valid for verification/decryption
    Deprecated,
    /// Key has been revoked and should not be used
    Revoked,
    /// Key is disabled and must not be used for any operation
    Disabled,
}

impl Zeroize for KeyStatus {
    fn zeroize(&mut self) {
        *self = KeyStatus::Disabled;
    }
}

/// Stored signing keypair with metadata for rotation support.
#[derive(Clone, Serialize, Deserialize)]
pub struct SigningKeypair {
    /// Key identifier
    pub kid: String,
    /// Encrypted signing key (base64url-encoded)
    pub sk: String,
    /// Verification key (base64url-encoded, public)
    pub vk: String,
    /// Whether the signing key is encrypted
    pub encrypted: bool,
    /// Key lifecycle status
    pub status: KeyStatus,
    /// Creation timestamp
    pub created_at: i64,
    /// Timestamp when key was deprecated (if applicable)
    pub deprecated_at: Option<i64>,
    /// Timestamp when key was revoked (if applicable)
    pub revoked_at: Option<i64>,
}

impl fmt::Debug for SigningKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKeypair")
            .field("kid", &self.kid)
            .field("sk", &"[REDACTED]")
            .field("vk", &self.vk)
            .field("encrypted", &self.encrypted)
            .field("status", &self.status)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl Drop for SigningKeypair {
    fn drop(&mut self) {
        self.sk.zeroize();
    }
}

/// Challenge state persisted while waiting for a YubiKey response.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredChallenge {
    /// Unique challenge identifier.
    pub challenge_id: String,
    /// Officer that owns the challenge.
    pub officer_id: String,
    /// Raw challenge bytes delivered to the officer.
    pub challenge: Vec<u8>,
    /// Creation timestamp.
    pub created_at: i64,
    /// Expiration timestamp.
    pub expires_at: i64,
    /// Tracks whether the challenge has already been consumed.
    pub used: bool,
}

impl fmt::Debug for StoredChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredChallenge")
            .field("challenge_id", &self.challenge_id)
            .field("officer_id", &self.officer_id)
            .field("challenge", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("used", &self.used)
            .finish()
    }
}

impl Drop for StoredChallenge {
    fn drop(&mut self) {
        self.challenge.zeroize();
    }
}

/// Minimum validity_days permitted by policy (1 day).
pub const MIN_POLICY_VALIDITY_DAYS: u32 = 1;

/// Maximum validity_days permitted by policy (36500 days ~ 100 years).
pub const MAX_POLICY_VALIDITY_DAYS: u32 = 36_500;

/// Captures the default issuance policy values.
///
/// This is stored config from a trusted source (provii-management writes
/// it to KV). `deny_unknown_fields` is intentionally omitted so that
/// stored config tolerates unknown fields during format evolution.
/// External API input types like `ChallengeRequest` use
/// `deny_unknown_fields` for untrusted input.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    /// Default credential schema (issuer config format).
    #[serde(default = "default_schema")]
    pub schema: String,
    /// Maximum validity duration permitted by policy.
    /// Clamped to `[MIN_POLICY_VALIDITY_DAYS, MAX_POLICY_VALIDITY_DAYS]` on access.
    #[serde(alias = "max_validity_days", default = "default_validity_days")]
    pub validity_days: u32,
    /// Policy version number.
    #[serde(default = "default_policy_version")]
    pub v: u8,
}

impl PolicyConfig {
    /// Return `validity_days` clamped to the permitted range.
    /// Protects against misconfiguration where a zero or unreasonable value
    /// was written to KV.
    pub fn effective_validity_days(&self) -> u32 {
        self.validity_days
            .clamp(MIN_POLICY_VALIDITY_DAYS, MAX_POLICY_VALIDITY_DAYS)
    }
}

fn default_schema() -> String {
    "provii.age/0".to_string()
}

fn default_validity_days() -> u32 {
    365
}

fn default_policy_version() -> u8 {
    2
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            schema: default_schema(),
            validity_days: default_validity_days(),
            v: default_policy_version(),
        }
    }
}

/// Container returned by JWKS endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    /// Collection of RedJubjub public keys.
    pub keys: Vec<Jwk>,
}

/// Individual JWKS entry describing a RedJubjub key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (`OKP`).
    pub kty: String,
    /// Curve label (`JUBJUB`).
    pub crv: String,
    /// Key identifier.
    pub kid: String,
    #[serde(rename = "use")]
    /// Intended key usage.
    pub use_: String,
    /// Algorithm hint.
    pub alg: String,
    /// Base64url-encoded public key bytes.
    pub x: String,
}

/// Stored officer metadata used for YubiKey authentication.
#[derive(Clone, Serialize, Deserialize)]
pub struct OfficerRegistration {
    /// Officer identifier registered with the system.
    pub officer_id: String,
    /// Symmetric key used for YubiKey challenge validation.
    pub hmac_secret: Vec<u8>,
    /// Creation timestamp.
    pub created_at: i64,
    /// When the officer last authenticated.
    pub last_used: Option<i64>,
    /// Whether the account is currently active.
    pub active: bool,
    /// Whether the HMAC secret is encrypted at rest using envelope encryption.
    #[serde(default)]
    pub encrypted: bool,
    /// HMAC secret status for rotation support.
    #[serde(default = "default_key_status")]
    pub secret_status: KeyStatus,
    /// Previous HMAC secret during rotation (encrypted if encrypted=true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hmac_secret: Option<Vec<u8>>,
    /// Role for RBAC (default: Issuer for backward compatibility).
    #[serde(default)]
    pub role: Role,
}

impl fmt::Debug for OfficerRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfficerRegistration")
            .field("officer_id", &self.officer_id)
            .field("hmac_secret", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("last_used", &self.last_used)
            .field("active", &self.active)
            .finish()
    }
}

impl Drop for OfficerRegistration {
    fn drop(&mut self) {
        self.hmac_secret.zeroize();
        if let Some(ref mut prev) = self.previous_hmac_secret {
            prev.zeroize();
        }
    }
}

/// Stored client metadata used for API authentication.
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientRegistration {
    /// Client identifier registered with the issuer.
    pub client_id: String,
    /// Human-readable client name.
    pub client_name: String,
    /// Argon2id hash of the API key (encrypted with KEK).
    /// Stored as Vec<u8> (encrypted bytes) by admin-portal.
    pub api_key_hash: Vec<u8>,
    /// Symmetric key used for HMAC validation.
    pub hmac_secret: Vec<u8>,
    /// Creation timestamp.
    pub created_at: i64,
    /// Last successful authentication timestamp.
    pub last_used: Option<i64>,
    /// Allowed requests per window.
    pub rate_limit: u32,
    /// Schemas this client may request.
    /// IV-207: Bounded to MAX_ALLOWED_SCHEMAS entries at the point of use.
    pub allowed_schemas: Vec<String>,
    /// Maximum credential validity the client may request.
    pub max_validity_days: u32,
    /// Whether the client is enabled.
    pub active: bool,
    /// Whether the HMAC secret is encrypted at rest using envelope encryption.
    #[serde(default)]
    pub encrypted: bool,
    /// HMAC secret status for rotation support.
    #[serde(default = "default_key_status")]
    pub secret_status: KeyStatus,
    /// Previous HMAC secret during rotation (encrypted if encrypted=true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hmac_secret: Option<Vec<u8>>,
    /// Role for RBAC (default: Issuer for backward compatibility).
    #[serde(default)]
    pub role: Role,
    /// KV key used to retrieve this client (not persisted, only used during authentication).
    #[serde(skip)]
    pub kv_key: Option<String>,
}

impl fmt::Debug for ClientRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientRegistration")
            .field("client_id", &self.client_id)
            .field("client_name", &self.client_name)
            .field("api_key_hash", &"[REDACTED]")
            .field("hmac_secret", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("last_used", &self.last_used)
            .field("rate_limit", &self.rate_limit)
            .field("allowed_schemas", &self.allowed_schemas)
            .field("max_validity_days", &self.max_validity_days)
            .field("active", &self.active)
            .finish()
    }
}

impl Drop for ClientRegistration {
    fn drop(&mut self) {
        self.hmac_secret.zeroize();
        self.api_key_hash.zeroize();
        if let Some(ref mut prev) = self.previous_hmac_secret {
            prev.zeroize();
        }
    }
}

/// Issuer-wide configuration loaded from KV or environment variables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerConfig {
    /// DID-style identifier for the issuer.
    pub issuer_id: String,
    /// Relying party identifier used in authentication challenges.
    pub rp_id: String,
    /// Default signing key identifier.
    pub default_kid: String,
    /// Previous kid retained during a rotation overlap window so the
    /// blind-issuance verify path can fall back when an attestation was
    /// signed under the prior key. Set when `default_kid` advances and
    /// cleared once the overlap window closes. Absent in steady state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_kid: Option<String>,
    /// Default issuance policy.
    pub default_policy: PolicyConfig,
}

/// Default key status for deserialization backwards compatibility.
fn default_key_status() -> KeyStatus {
    KeyStatus::Active
}

// ============================================================================
// Blind Attestation Issuance Types (ASVS 5.0 / MASVS 2.0 compliant)
// ============================================================================

/// Maximum r_bits length in bytes (256 bits = 32 bytes).
pub const MAX_R_BITS_BYTES: usize = 32;

/// Minimum r_bits length in bytes (128 bits = 16 bytes).
pub const MIN_R_BITS_BYTES: usize = 16;

/// Maximum attestation age in seconds (1 hour).
pub const ATTESTATION_MAX_AGE_SECONDS: u64 = 3600;

/// Request payload for blind issuance via Ed25519 attestation.
///
/// # Security (ASVS 5.0 / MASVS 2.0)
/// - Attestation signature verified against registered issuer key
/// - Nonce prevents replay attacks
/// - Timestamp validated for freshness
/// - r_bits validated for entropy requirements
///
/// `deny_unknown_fields` is intentionally NOT applied so that future
/// envelope fields can be added without a wire-format break. The IV-205
/// rationale (reject unexpected external input) is preserved at field
/// level via the `validate` attributes; an unknown top-level field is
/// safer dropped than rejected for forward compatibility during
/// rotation rollouts.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Validate)]
pub struct BlindIssuanceRequest {
    /// Base64url-encoded DobAttestation containing Ed25519 signature.
    #[validate(max_length = 1000)]
    #[validate(custom(validate_base64_string))]
    pub attestation: String,

    /// Base64url-encoded randomness bits (128-256 bits).
    /// User generates locally to ensure issuer cannot link identity to credential.
    #[validate(max_length = 64)]
    #[validate(custom(validate_base64_string))]
    pub r_bits: String,

    /// Optional schema override (defaults to "provii.age/0").
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(max_length = 500)]
    #[validate(custom(validate_schema_url))]
    pub schema: Option<String>,

    /// Requested validity duration in days (constrained by policy).
    /// Default is 100 years (36500 days) for lifetime credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(minimum = 1)]
    #[validate(maximum = 36500)]
    pub validity_days: Option<u32>,
}

/// Response payload for successful blind issuance.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BlindIssuanceResponse {
    /// The signed credential header containing the commitment and RedJubjub signature.
    pub credential: SignedCredentialHeader,
}

/// Stored Ed25519 verifying key for a trusted attestation issuer.
///
/// # Security (ASVS 5.0)
/// - Activation/expiry timestamps for key lifecycle management
/// - Audit trail via issuer_name for compliance
/// - Multi-keypair-per-issuer support: KV layout is `issuer:{issuer_id}:{kid}`,
///   so the same `issuer_id` may carry several entries during a key rotation
///   window. Lookups select by the `kid` provided in the request envelope.
///   No migration or backward-compatibility code; storage format changes
///   discard old data. Fresh KVs are empty; legacy `issuer:{issuer_id}`
///   records are not preserved.
///
/// # Composite key decomposition is not supported
/// The KV key `issuer:{issuer_id}:{kid}` is constructed by a one-way
/// formatter in `storage::get_issuer_ed25519_key` and its signing
/// counterpart. Callers must hold the `(issuer_id, kid)` tuple in
/// hand. There is no decomposer because both fields may contain `:`
/// in legitimate values (DID-style identifiers, `provii:sandbox`
/// kids, etc.), so a naive split would silently misroute traffic.
/// Lookup-by-tuple only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerEd25519Key {
    /// Issuer identifier (e.g., "dmv.ca.gov", "passport.usa.gov").
    pub issuer_id: String,

    /// Key identifier disambiguating multiple keypairs for the same `issuer_id`
    /// during rotation overlap windows. Required for kid-keyed KV layout.
    #[serde(default)]
    pub kid: String,

    /// Human-readable issuer name for audit logs.
    pub issuer_name: String,

    /// Ed25519 verifying key (32 bytes).
    ///
    /// This struct does not derive `JsonSchema` (internal KV storage
    /// only, not exposed via any API). If this type is wired into an
    /// admin/registry OpenAPI endpoint, add `JsonSchema` to the derive
    /// list, switch to `#[serde(with = "base64_bytes")]`, and apply
    /// schemars `extend(minLength=43, maxLength=43,
    /// contentEncoding="base64url")` annotations.
    pub verifying_key: [u8; 32],

    /// When this key became valid (Unix timestamp).
    pub valid_from: u64,

    /// When this key expires (Unix timestamp, 0 = no expiry).
    pub valid_until: u64,

    /// Whether this issuer is currently active.
    pub active: bool,

    /// Creation timestamp for audit.
    pub created_at: i64,
}

/// Request payload for creating a DOB attestation.
///
/// # Security (ASVS 5.0 / MASVS 2.0)
/// - Officer authentication via HMAC (same as existing issuance flow)
/// - Ed25519 signing key retrieved from secure storage
/// - Attestation signed with issuer-specific key
///
/// IV-205: deny_unknown_fields prevents unexpected fields in external input.
#[derive(Clone, Serialize, Deserialize, JsonSchema, Validate)]
#[serde(deny_unknown_fields)]
pub struct CreateAttestationRequest {
    /// Days since Unix epoch representing date of birth.
    /// Negative values represent dates before 1970-01-01 (e.g. -25000 ~ 1901).
    #[validate(minimum = -25000)]
    #[validate(maximum = 36500)]
    pub dob_days: i32,

    /// Authentication material (HMAC auth for officer).
    #[validate]
    pub authorizer: Authorizer,
}

/// Manual Debug impl redacts `dob_days` (PII, date of birth).
impl fmt::Debug for CreateAttestationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateAttestationRequest")
            .field("dob_days", &"[REDACTED]")
            .field("authorizer", &self.authorizer)
            .finish()
    }
}

/// Zeroize dob_days (PII) when CreateAttestationRequest is dropped.
/// Cannot derive ZeroizeOnDrop alongside Deserialize/Clone, so implement Drop manually.
impl Drop for CreateAttestationRequest {
    fn drop(&mut self) {
        self.dob_days.zeroize();
    }
}

/// Response payload for successful attestation creation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CreateAttestationResponse {
    /// Base64url-encoded DobAttestation containing Ed25519 signature.
    pub attestation: String,

    /// Unix timestamp when this attestation expires (1 hour from creation).
    pub expires_at: u64,

    /// Issuer identifier that signed this attestation.
    pub issuer_id: String,
}

/// Stored Ed25519 signing keypair for an attestation issuer.
///
/// # Security (ASVS 5.0)
/// - Signing key encrypted at rest with envelope encryption (KEK -> DEK -> key)
/// - Separate from verifying key storage for defence in depth
/// - Access requires officer authentication
/// - Multi-keypair-per-issuer support: KV layout is `signing:{issuer_id}:{kid}`,
///   so the same `issuer_id` may carry several entries during a key rotation
///   window. The active kid is sourced from `IssuerConfig.default_kid`.
/// - SK field wrapped in Zeroizing for automatic zeroing on drop.
#[derive(Clone, Serialize, Deserialize)]
pub struct IssuerEd25519SigningKey {
    /// Issuer identifier (must match verifying key registration).
    pub issuer_id: String,

    /// Key identifier disambiguating multiple signing keypairs for the same
    /// `issuer_id` during rotation overlap windows. Required for kid-keyed
    /// KV layout.
    #[serde(default)]
    pub kid: String,

    /// Ed25519 signing key (32 bytes, encrypted at rest).
    /// Wrapped in Zeroizing for defence-in-depth memory clearing.
    pub signing_key: zeroize::Zeroizing<Vec<u8>>,

    /// Whether the signing key is encrypted.
    pub encrypted: bool,

    /// Creation timestamp for audit.
    pub created_at: i64,

    /// Key lifecycle status.
    pub status: KeyStatus,
}

impl core::fmt::Debug for IssuerEd25519SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IssuerEd25519SigningKey")
            .field("issuer_id", &self.issuer_id)
            .field("kid", &self.kid)
            .field("signing_key", &"[REDACTED]")
            .field("encrypted", &self.encrypted)
            .field("created_at", &self.created_at)
            .field("status", &self.status)
            .finish()
    }
}

/// Base64 serialization helpers for fixed-size arrays.
mod base64_bytes {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        encoded.serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Base64 serialization helpers for 64-byte arrays.
mod base64_bytes_64 {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        encoded.serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
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
    clippy::panic,
    clippy::needless_update
)]
#[path = "types_tests.rs"]
mod tests;
