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
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    ROLE ENUM TESTS                                        */
    /* ========================================================================== */

    #[test]
    fn test_role_serialize_admin() -> Result<(), Box<dyn std::error::Error>> {
        let role = Role::Admin;
        let json = serde_json::to_string(&role)?;
        assert_eq!(json, r#""admin""#);
        Ok(())
    }

    #[test]
    fn test_role_serialize_issuer() -> Result<(), Box<dyn std::error::Error>> {
        let role = Role::Issuer;
        let json = serde_json::to_string(&role)?;
        assert_eq!(json, r#""issuer""#);
        Ok(())
    }

    #[test]
    fn test_role_serialize_viewer() -> Result<(), Box<dyn std::error::Error>> {
        let role = Role::Viewer;
        let json = serde_json::to_string(&role)?;
        assert_eq!(json, r#""viewer""#);
        Ok(())
    }

    #[test]
    fn test_role_deserialize_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        for (json_str, expected) in [
            (r#""admin""#, Role::Admin),
            (r#""issuer""#, Role::Issuer),
            (r#""viewer""#, Role::Viewer),
        ] {
            let decoded: Role = serde_json::from_str(json_str)?;
            assert_eq!(decoded, expected);
        }
        Ok(())
    }

    #[test]
    fn test_role_default_is_issuer() {
        assert_eq!(Role::default(), Role::Issuer);
    }

    /* ========================================================================== */
    /*                    KEYSTATUS ENUM TESTS                                   */
    /* ========================================================================== */

    #[test]
    fn test_key_status_serialize_all_variants() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(serde_json::to_string(&KeyStatus::Active)?, r#""active""#);
        assert_eq!(
            serde_json::to_string(&KeyStatus::Deprecated)?,
            r#""deprecated""#
        );
        assert_eq!(serde_json::to_string(&KeyStatus::Revoked)?, r#""revoked""#);
        assert_eq!(
            serde_json::to_string(&KeyStatus::Disabled)?,
            r#""disabled""#
        );
        Ok(())
    }

    #[test]
    fn test_key_status_deserialize_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        for status in [
            KeyStatus::Active,
            KeyStatus::Deprecated,
            KeyStatus::Revoked,
            KeyStatus::Disabled,
        ] {
            let json = serde_json::to_string(&status)?;
            let decoded: KeyStatus = serde_json::from_str(&json)?;
            assert_eq!(decoded, status);
        }
        Ok(())
    }

    #[test]
    fn test_key_status_default_is_active() {
        assert_eq!(KeyStatus::default(), KeyStatus::Active);
    }

    /* ========================================================================== */
    /*                    HASHED NEWTYPE TESTS                                   */
    /* ========================================================================== */

    #[test]
    fn test_hashed_ip_new_and_as_str() {
        let hex = "a".repeat(64);
        let hashed = HashedIp::new(hex.clone());
        assert_eq!(hashed.as_str(), hex.as_str());
    }

    #[test]
    fn test_hashed_ip_as_ref() {
        let hex = "b".repeat(64);
        let hashed = HashedIp::new(hex.clone());
        let r: &str = hashed.as_ref();
        assert_eq!(r, hex.as_str());
    }

    #[test]
    fn test_hashed_ip_serialize_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let hex = "c".repeat(64);
        let hashed = HashedIp::new(hex.clone());
        let json = serde_json::to_string(&hashed)?;
        let decoded: HashedIp = serde_json::from_str(&json)?;
        assert_eq!(decoded, hashed);
        Ok(())
    }

    #[test]
    fn test_hashed_user_agent_new_and_as_str() {
        let hex = "d".repeat(64);
        let hashed = HashedUserAgent::new(hex.clone());
        assert_eq!(hashed.as_str(), hex.as_str());
    }

    #[test]
    fn test_hashed_user_agent_serialize_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let hex = "e".repeat(64);
        let hashed = HashedUserAgent::new(hex.clone());
        let json = serde_json::to_string(&hashed)?;
        let decoded: HashedUserAgent = serde_json::from_str(&json)?;
        assert_eq!(decoded, hashed);
        Ok(())
    }

    /* ========================================================================== */
    /*                    DEBUG REDACTION TESTS                                  */
    /* ========================================================================== */

    #[test]
    fn test_signing_keypair_debug_redacts_sk() {
        let kp = SigningKeypair {
            kid: "test-kid".to_string(),
            sk: "super-secret-key-material".to_string(),
            vk: "public-vk".to_string(),
            encrypted: false,
            status: KeyStatus::Active,
            created_at: 1000,
            deprecated_at: None,
            revoked_at: None,
        };
        let debug = format!("{:?}", kp);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret-key-material"));
        assert!(debug.contains("test-kid"));
    }

    #[test]
    fn test_stored_challenge_debug_redacts_challenge() {
        let ch = StoredChallenge {
            challenge_id: "ch-debug".to_string(),
            officer_id: "off-debug".to_string(),
            challenge: vec![0xDE, 0xAD, 0xBE, 0xEF],
            created_at: 1000,
            expires_at: 2000,
            used: false,
        };
        let debug = format!("{:?}", ch);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("DEAD"));
        assert!(debug.contains("ch-debug"));
    }

    #[test]
    fn test_officer_registration_debug_redacts_secret() {
        let officer = OfficerRegistration {
            officer_id: "off-redact".to_string(),
            hmac_secret: vec![0x42; 32],
            created_at: 1000,
            last_used: None,
            active: true,
            encrypted: false,
            secret_status: KeyStatus::Active,
            previous_hmac_secret: None,
            role: Role::default(),
        };
        let debug = format!("{:?}", officer);
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("off-redact"));
    }

    #[test]
    fn test_client_registration_debug_redacts_secrets() {
        let client = ClientRegistration {
            client_id: "client-redact".to_string(),
            client_name: "Test".to_string(),
            api_key_hash: b"secret-hash".to_vec(),
            hmac_secret: vec![0x99; 32],
            created_at: 1000,
            last_used: None,
            rate_limit: 100,
            allowed_schemas: vec![],
            max_validity_days: 365,
            active: true,
            encrypted: false,
            secret_status: KeyStatus::Active,
            previous_hmac_secret: None,
            role: Role::default(),
            kv_key: None,
        };
        let debug = format!("{:?}", client);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret-hash"));
        assert!(debug.contains("client-redact"));
    }

    /* ========================================================================== */
    /*                    DROP / ZEROIZE BEHAVIOUR TESTS                         */
    /* ========================================================================== */

    #[test]
    fn test_signing_keypair_drop_impl_exists() {
        // Verify that SigningKeypair implements Drop (zeroize on drop).
        // We cannot use unsafe to inspect memory (crate forbids unsafe_code),
        // so we verify the Drop trait is triggered without panic.
        let kp = SigningKeypair {
            kid: "drop-test".to_string(),
            sk: "AAAA_secret_AAAA".to_string(),
            vk: "public".to_string(),
            encrypted: false,
            status: KeyStatus::Active,
            created_at: 0,
            deprecated_at: None,
            revoked_at: None,
        };
        drop(kp);
        // If Drop impl is broken this would panic or fail to compile.
    }

    #[test]
    fn test_key_status_zeroize_sets_disabled() {
        let mut status = KeyStatus::Active;
        status.zeroize();
        assert_eq!(status, KeyStatus::Disabled);
    }

    #[test]
    fn test_session_status_default_is_pending() {
        assert_eq!(SessionStatus::default(), SessionStatus::Pending);
    }

    /* ========================================================================== */
    /*                    POLICY CONFIG VALIDITY BOUNDS TESTS                    */
    /* ========================================================================== */

    #[test]
    fn test_policy_config_effective_validity_days_clamps_zero() {
        let policy = PolicyConfig {
            validity_days: 0,
            ..Default::default()
        };
        assert_eq!(policy.effective_validity_days(), MIN_POLICY_VALIDITY_DAYS);
    }

    #[test]
    fn test_policy_config_effective_validity_days_clamps_max() {
        let policy = PolicyConfig {
            validity_days: 100_000,
            ..Default::default()
        };
        assert_eq!(policy.effective_validity_days(), MAX_POLICY_VALIDITY_DAYS);
    }

    #[test]
    fn test_policy_config_effective_validity_days_normal() {
        let policy = PolicyConfig {
            validity_days: 365,
            ..Default::default()
        };
        assert_eq!(policy.effective_validity_days(), 365);
    }

    /* ========================================================================== */
    /*                    ACTORTYPE ENUM TESTS                                   */
    /* ========================================================================== */

    #[test]
    fn test_actor_type_officer_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let actor = ActorType::Officer;
        let json = serde_json::to_string(&actor)?;
        assert_eq!(json, r#""officer""#);
        Ok(())
    }

    #[test]
    fn test_actor_type_client_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let actor = ActorType::Client;
        let json = serde_json::to_string(&actor)?;
        assert_eq!(json, r#""client""#);
        Ok(())
    }

    #[test]
    fn test_actor_type_officer_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#""officer""#;
        let actor: ActorType = serde_json::from_str(json)?;
        assert_eq!(actor, ActorType::Officer);
        Ok(())
    }

    #[test]
    fn test_actor_type_client_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#""client""#;
        let actor: ActorType = serde_json::from_str(json)?;
        assert_eq!(actor, ActorType::Client);
        Ok(())
    }

    #[test]
    fn test_actor_type_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let officer = ActorType::Officer;
        let json = serde_json::to_string(&officer)?;
        let decoded: ActorType = serde_json::from_str(&json)?;
        assert_eq!(decoded, ActorType::Officer);

        let client = ActorType::Client;
        let json = serde_json::to_string(&client)?;
        let decoded: ActorType = serde_json::from_str(&json)?;
        assert_eq!(decoded, ActorType::Client);
        Ok(())
    }

    #[test]
    fn test_actor_type_clone() {
        let actor = ActorType::Officer;
        let cloned = actor.clone();
        assert_eq!(actor, cloned);
    }

    /* ========================================================================== */
    /*                    SESSIONSTATUS ENUM TESTS                               */
    /* ========================================================================== */

    #[test]
    fn test_session_status_pending() -> Result<(), Box<dyn std::error::Error>> {
        let status = SessionStatus::Pending;
        let json = serde_json::to_string(&status)?;
        assert_eq!(json, r#""pending""#);
        Ok(())
    }

    #[test]
    fn test_session_status_authenticated() -> Result<(), Box<dyn std::error::Error>> {
        let status = SessionStatus::Authenticated;
        let json = serde_json::to_string(&status)?;
        assert_eq!(json, r#""authenticated""#);
        Ok(())
    }

    #[test]
    fn test_session_status_completed() -> Result<(), Box<dyn std::error::Error>> {
        let status = SessionStatus::Completed;
        let json = serde_json::to_string(&status)?;
        assert_eq!(json, r#""completed""#);
        Ok(())
    }

    #[test]
    fn test_session_status_expired() -> Result<(), Box<dyn std::error::Error>> {
        let status = SessionStatus::Expired;
        let json = serde_json::to_string(&status)?;
        assert_eq!(json, r#""expired""#);
        Ok(())
    }

    #[test]
    fn test_session_status_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let pending: SessionStatus = serde_json::from_str(r#""pending""#)?;
        assert_eq!(pending, SessionStatus::Pending);

        let auth: SessionStatus = serde_json::from_str(r#""authenticated""#)?;
        assert_eq!(auth, SessionStatus::Authenticated);

        let done: SessionStatus = serde_json::from_str(r#""completed""#)?;
        assert_eq!(done, SessionStatus::Completed);

        let expired: SessionStatus = serde_json::from_str(r#""expired""#)?;
        assert_eq!(expired, SessionStatus::Expired);
        Ok(())
    }

    #[test]
    fn test_session_status_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        for status in [
            SessionStatus::Pending,
            SessionStatus::Authenticated,
            SessionStatus::Completed,
            SessionStatus::Expired,
        ] {
            let json = serde_json::to_string(&status)?;
            let decoded: SessionStatus = serde_json::from_str(&json)?;
            assert_eq!(status, decoded);
        }
        Ok(())
    }

    /* ========================================================================== */
    /*                    BASE64_BYTES MODULE TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_base64_bytes_serialize() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Serialize)]
        struct Test {
            #[serde(with = "base64_bytes")]
            data: [u8; 32],
        }
        let test = Test { data: [42u8; 32] };
        let json = serde_json::to_string(&test)?;
        assert!(json.contains("KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio"));
        Ok(())
    }

    #[test]
    fn test_base64_bytes_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Deserialize)]
        struct Test {
            #[serde(with = "base64_bytes")]
            data: [u8; 32],
        }
        let json = r#"{"data":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        let test: Test = serde_json::from_str(json)?;
        assert_eq!(test.data, [0u8; 32]);
        Ok(())
    }

    #[test]
    fn test_base64_bytes_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Serialize, Deserialize)]
        struct Test {
            #[serde(with = "base64_bytes")]
            data: [u8; 32],
        }
        let original = Test { data: [0xAB; 32] };
        let json = serde_json::to_string(&original)?;
        let decoded: Test = serde_json::from_str(&json)?;
        assert_eq!(original.data, decoded.data);
        Ok(())
    }

    #[test]
    fn test_base64_bytes_wrong_length() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Debug, Deserialize)]
        struct Test {
            #[serde(with = "base64_bytes")]
            #[allow(dead_code)]
            data: [u8; 32],
        }
        // 16 bytes encoded (too short)
        let json = r#"{"data":"AAAAAAAAAAAAAAAAAAAAAA"}"#;
        let result = serde_json::from_str::<Test>(json);
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .to_string()
            .contains("expected 32 bytes"));
        Ok(())
    }

    #[test]
    fn test_base64_bytes_invalid_base64() {
        #[derive(Deserialize)]
        struct Test {
            #[serde(with = "base64_bytes")]
            #[allow(dead_code)]
            data: [u8; 32],
        }
        let json = r#"{"data":"!!!invalid!!!"}"#;
        let result = serde_json::from_str::<Test>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_bytes_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Serialize, Deserialize)]
        struct Test {
            #[serde(with = "base64_bytes")]
            data: [u8; 32],
        }
        let test = Test { data: [0u8; 32] };
        let json = serde_json::to_string(&test)?;
        let decoded: Test = serde_json::from_str(&json)?;
        assert_eq!(decoded.data, [0u8; 32]);
        Ok(())
    }

    #[test]
    fn test_base64_bytes_all_ones() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Serialize, Deserialize)]
        struct Test {
            #[serde(with = "base64_bytes")]
            data: [u8; 32],
        }
        let test = Test { data: [0xFF; 32] };
        let json = serde_json::to_string(&test)?;
        let decoded: Test = serde_json::from_str(&json)?;
        assert_eq!(decoded.data, [0xFF; 32]);
        Ok(())
    }

    /* ========================================================================== */
    /*                    BASE64_BYTES_64 MODULE TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_base64_bytes_64_serialize() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Serialize)]
        struct Test {
            #[serde(with = "base64_bytes_64")]
            data: [u8; 64],
        }
        let test = Test { data: [42u8; 64] };
        let json = serde_json::to_string(&test)?;
        assert!(json.contains("data"));
        Ok(())
    }

    #[test]
    fn test_base64_bytes_64_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Deserialize)]
        struct Test {
            #[serde(with = "base64_bytes_64")]
            data: [u8; 64],
        }
        // Correct base64url encoding of 64 zero bytes (86 characters, no padding)
        let json = r#"{"data":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        let test: Test = serde_json::from_str(json)?;
        assert_eq!(test.data, [0u8; 64]);
        Ok(())
    }

    #[test]
    fn test_base64_bytes_64_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Serialize, Deserialize)]
        struct Test {
            #[serde(with = "base64_bytes_64")]
            data: [u8; 64],
        }
        let original = Test { data: [0xCD; 64] };
        let json = serde_json::to_string(&original)?;
        let decoded: Test = serde_json::from_str(&json)?;
        assert_eq!(original.data, decoded.data);
        Ok(())
    }

    #[test]
    fn test_base64_bytes_64_wrong_length() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Debug, Deserialize)]
        struct Test {
            #[serde(with = "base64_bytes_64")]
            #[allow(dead_code)]
            data: [u8; 64],
        }
        // 32 bytes encoded (too short)
        let json = r#"{"data":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        let result = serde_json::from_str::<Test>(json);
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .to_string()
            .contains("expected 64 bytes"));
        Ok(())
    }

    #[test]
    fn test_base64_bytes_64_invalid_base64() {
        #[derive(Deserialize)]
        struct Test {
            #[serde(with = "base64_bytes_64")]
            #[allow(dead_code)]
            data: [u8; 64],
        }
        let json = r#"{"data":"!!!invalid!!!"}"#;
        let result = serde_json::from_str::<Test>(json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    STRUCT SERIALIZATION TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_challenge_request_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let req = ChallengeRequest {
            officer_id: "officer-42".to_string(),
        };
        let json = serde_json::to_string(&req)?;
        assert!(json.contains("officer-42"));
        Ok(())
    }

    #[test]
    fn test_challenge_response_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let resp = ChallengeResponse {
            challenge_id: "ch-999".to_string(),
            challenge: "deadbeef".to_string(),
            expires_at: 5000,
        };
        let json = serde_json::to_string(&resp)?;
        let decoded: ChallengeResponse = serde_json::from_str(&json)?;
        assert_eq!(decoded.challenge_id, "ch-999");
        assert_eq!(decoded.challenge, "deadbeef");
        Ok(())
    }

    #[test]
    fn test_authorizer_with_challenge_id() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            format: "yubikey".to_string(),
            key_id: "yk-1".to_string(),
            challenge_id: Some("ch-456".to_string()),
            timestamp: 9999,
            hmac: "hmac-value".to_string(),
            nonce: "b".repeat(64),
        };
        let json = serde_json::to_string(&auth)?;
        assert!(json.contains("ch-456"));
        assert!(json.contains("keyId"));
        Ok(())
    }

    #[test]
    fn test_authorizer_without_challenge_id() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            format: "client".to_string(),
            key_id: "client-1".to_string(),
            challenge_id: None,
            timestamp: 1111,
            hmac: "abc".to_string(),
            nonce: "c".repeat(64),
        };
        let json = serde_json::to_string(&auth)?;
        // Should not include challenge_id when None
        assert!(!json.contains("challenge_id") || json.contains("null"));
        Ok(())
    }

    #[test]
    fn test_policy_config_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let policy = PolicyConfig {
            schema: "provii.id/age/v1".to_string(),
            validity_days: 730,
            v: 1,
        };
        let json = serde_json::to_string(&policy)?;
        let decoded: PolicyConfig = serde_json::from_str(&json)?;
        assert_eq!(decoded.schema, "provii.id/age/v1");
        assert_eq!(decoded.validity_days, 730);
        assert_eq!(decoded.v, 1);
        Ok(())
    }

    #[test]
    fn test_jwk_set_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let jwk = Jwk {
            kty: "OKP".to_string(),
            crv: "JUBJUB".to_string(),
            kid: "key-1".to_string(),
            use_: "sig".to_string(),
            alg: "RedJubjub".to_string(),
            x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        };
        let jwk_set = JwkSet { keys: vec![jwk] };
        let json = serde_json::to_string(&jwk_set)?;
        assert!(json.contains("OKP"));
        assert!(json.contains("JUBJUB"));
        assert!(json.contains("key-1"));
        Ok(())
    }

    #[test]
    fn test_officer_registration_active() -> Result<(), Box<dyn std::error::Error>> {
        let officer = OfficerRegistration {
            officer_id: "off-1".to_string(),
            hmac_secret: vec![1, 2, 3, 4],
            created_at: 1000,
            last_used: Some(2000),
            active: true,
            encrypted: false,
            secret_status: KeyStatus::Active,
            previous_hmac_secret: None,
            role: crate::types::Role::default(),
        };
        let json = serde_json::to_string(&officer)?;
        let decoded: OfficerRegistration = serde_json::from_str(&json)?;
        assert_eq!(decoded.officer_id, "off-1");
        assert!(decoded.active);
        assert_eq!(decoded.last_used, Some(2000));
        Ok(())
    }

    #[test]
    fn test_client_registration_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let client = ClientRegistration {
            client_id: "client-1".to_string(),
            client_name: "Test Client".to_string(),
            api_key_hash: b"hash123".to_vec(),
            hmac_secret: vec![5, 6, 7, 8],
            created_at: 5000,
            last_used: None,
            rate_limit: 100,
            allowed_schemas: vec!["provii.id/v1".to_string()],
            max_validity_days: 365,
            active: true,
            encrypted: false,
            secret_status: KeyStatus::Active,
            previous_hmac_secret: None,
            role: crate::types::Role::default(),
            kv_key: None,
        };
        let json = serde_json::to_string(&client)?;
        let decoded: ClientRegistration = serde_json::from_str(&json)?;
        assert_eq!(decoded.client_id, "client-1");
        assert_eq!(decoded.client_name, "Test Client");
        assert_eq!(decoded.rate_limit, 100);
        assert!(decoded.last_used.is_none());
        Ok(())
    }

    #[test]
    fn test_issuer_config_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let config = IssuerConfig {
            issuer_id: "did:provii:issuer".to_string(),
            rp_id: "provii.id".to_string(),
            default_kid: "key-default".to_string(),
            previous_kid: None,
            default_policy: PolicyConfig {
                schema: "provii.id/v1".to_string(),
                validity_days: 365,
                v: 1,
            },
        };
        let json = serde_json::to_string(&config)?;
        assert!(json.contains("did:provii:issuer"));
        assert!(json.contains("provii.id"));
        // None previous_kid is skipped on serialise so the wire shape
        // stays stable for steady-state configs that never rotated.
        assert!(!json.contains("previous_kid"));
        Ok(())
    }

    #[test]
    fn test_issuer_config_previous_kid_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let config = IssuerConfig {
            issuer_id: "did:provii:issuer".to_string(),
            rp_id: "provii.id".to_string(),
            default_kid: "v2".to_string(),
            previous_kid: Some("v1".to_string()),
            default_policy: PolicyConfig {
                schema: "provii.id/v1".to_string(),
                validity_days: 365,
                v: 1,
            },
        };
        let json = serde_json::to_string(&config)?;
        assert!(json.contains("\"previous_kid\":\"v1\""));
        let decoded: IssuerConfig = serde_json::from_str(&json)?;
        assert_eq!(decoded.default_kid, "v2");
        assert_eq!(decoded.previous_kid.as_deref(), Some("v1"));
        Ok(())
    }

    #[test]
    fn test_issuer_config_previous_kid_default_none() -> Result<(), Box<dyn std::error::Error>> {
        // Existing on-disk configs without `previous_kid` must decode
        // cleanly. Storage format change rules forbid migrations, so the
        // serde default is the only path for older records.
        let json = r#"{"issuer_id":"did:provii:issuer","rp_id":"provii.id","default_kid":"v1","default_policy":{"schema":"provii.id/v1","validity_days":365,"v":1}}"#;
        let decoded: IssuerConfig = serde_json::from_str(json)?;
        assert_eq!(decoded.previous_kid, None);
        Ok(())
    }

    #[test]
    fn test_issuance_session_with_officer() -> Result<(), Box<dyn std::error::Error>> {
        let session = IssuanceSession {
            session_id: "test-session-id".to_string(),
            created_at: 1000,
            expires_at: 2000,
            actor: ActorType::Officer,
            kid: "key-1".to_string(),
            schema: "provii.id/v1".to_string(),
            iat: 1000,
            exp: 3000,
            signatures_issued: 0,
            status: SessionStatus::Authenticated,
            officer_id: Some("off-1".to_string()),
            client_id: None,
            absolute_expiry: 4600, // 1 hour from creation
            client_ip: None,
            user_agent: None,
        };
        let json = serde_json::to_string(&session)?;
        let decoded: IssuanceSession = serde_json::from_str(&json)?;
        assert_eq!(decoded.actor, ActorType::Officer);
        assert_eq!(decoded.status, SessionStatus::Authenticated);
        assert!(decoded.officer_id.is_some());
        assert!(decoded.client_id.is_none());
        Ok(())
    }

    #[test]
    fn test_stored_challenge_unused() -> Result<(), Box<dyn std::error::Error>> {
        let challenge = StoredChallenge {
            challenge_id: "ch-1".to_string(),
            officer_id: "off-1".to_string(),
            challenge: vec![0xDE, 0xAD, 0xBE, 0xEF],
            created_at: 1000,
            expires_at: 2000,
            used: false,
        };
        let json = serde_json::to_string(&challenge)?;
        let decoded: StoredChallenge = serde_json::from_str(&json)?;
        assert_eq!(decoded.challenge_id, "ch-1");
        assert!(!decoded.used);
        assert_eq!(decoded.challenge, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        Ok(())
    }

    #[test]
    fn test_signed_credential_header_all_fields() -> Result<(), Box<dyn std::error::Error>> {
        let header = SignedCredentialHeader {
            v: 2,
            kid: "issuer-key".to_string(),
            issuer_vk: [0x99; 32],
            sig_rj: [0x88; 64],
            c_bytes: [0x77; 32],
            iat: 1700000000,
            exp: 1731536000,
            schema: "provii.id/age/v1".to_string(),
        };
        let json = serde_json::to_string(&header)?;
        let decoded: SignedCredentialHeader = serde_json::from_str(&json)?;

        assert_eq!(decoded.v, 2);
        assert_eq!(decoded.kid, "issuer-key");
        assert_eq!(decoded.issuer_vk, [0x99; 32]);
        assert_eq!(decoded.sig_rj, [0x88; 64]);
        assert_eq!(decoded.c_bytes, [0x77; 32]);
        assert_eq!(decoded.iat, 1700000000);
        assert_eq!(decoded.exp, 1731536000);
        assert_eq!(decoded.schema, "provii.id/age/v1");
        Ok(())
    }

    #[test]
    fn test_issuance_session_with_client() -> Result<(), Box<dyn std::error::Error>> {
        let session = IssuanceSession {
            session_id: "test-session-id".to_string(),
            created_at: 2000,
            expires_at: 3000,
            actor: ActorType::Client,
            kid: "key-2".to_string(),
            schema: "provii.id/v2".to_string(),
            iat: 2000,
            exp: 4000,
            signatures_issued: 0,
            status: SessionStatus::Completed,
            officer_id: None,
            client_id: Some("client-99".to_string()),
            absolute_expiry: 5600, // 1 hour from creation
            client_ip: None,
            user_agent: None,
        };
        let json = serde_json::to_string(&session)?;
        let decoded: IssuanceSession = serde_json::from_str(&json)?;
        assert_eq!(decoded.actor, ActorType::Client);
        assert_eq!(decoded.status, SessionStatus::Completed);
        assert!(decoded.officer_id.is_none());
        assert_eq!(decoded.client_id, Some("client-99".to_string()));
        Ok(())
    }

    #[test]
    fn test_stored_challenge_used() -> Result<(), Box<dyn std::error::Error>> {
        let challenge = StoredChallenge {
            challenge_id: "ch-2".to_string(),
            officer_id: "off-2".to_string(),
            challenge: vec![0x12, 0x34, 0x56, 0x78],
            created_at: 5000,
            expires_at: 6000,
            used: true,
        };
        let json = serde_json::to_string(&challenge)?;
        let decoded: StoredChallenge = serde_json::from_str(&json)?;
        assert_eq!(decoded.challenge_id, "ch-2");
        assert!(decoded.used);
        assert_eq!(decoded.challenge, vec![0x12, 0x34, 0x56, 0x78]);
        Ok(())
    }

    /* ========================================================================== */
    /*                    ROLE PERMISSION METHOD TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_admin_can_generate_challenge() {
        assert!(Role::Admin.can_generate_challenge());
    }

    #[test]
    fn test_issuer_can_generate_challenge() {
        assert!(Role::Issuer.can_generate_challenge());
    }

    #[test]
    fn test_viewer_cannot_generate_challenge() {
        assert!(!Role::Viewer.can_generate_challenge());
    }

    #[test]
    fn test_admin_can_issue_credential() {
        assert!(Role::Admin.can_issue_credential());
    }

    #[test]
    fn test_issuer_can_issue_credential() {
        assert!(Role::Issuer.can_issue_credential());
    }

    #[test]
    fn test_viewer_cannot_issue_credential() {
        assert!(!Role::Viewer.can_issue_credential());
    }

    #[test]
    fn test_admin_can_sign_commitment() {
        assert!(Role::Admin.can_sign_commitment());
    }

    #[test]
    fn test_viewer_cannot_sign_commitment() {
        assert!(!Role::Viewer.can_sign_commitment());
    }

    #[test]
    fn test_admin_can_view_sessions() {
        assert!(Role::Admin.can_view_sessions());
    }

    #[test]
    fn test_issuer_can_view_sessions() {
        assert!(Role::Issuer.can_view_sessions());
    }

    #[test]
    fn test_viewer_can_view_sessions() {
        assert!(Role::Viewer.can_view_sessions());
    }

    #[test]
    fn test_admin_can_view_audit_logs() {
        assert!(Role::Admin.can_view_audit_logs());
    }

    #[test]
    fn test_viewer_can_view_audit_logs() {
        assert!(Role::Viewer.can_view_audit_logs());
    }

    #[test]
    fn test_admin_can_manage_keys() {
        assert!(Role::Admin.can_manage_keys());
    }

    #[test]
    fn test_issuer_cannot_manage_keys() {
        assert!(!Role::Issuer.can_manage_keys());
    }

    #[test]
    fn test_viewer_cannot_manage_keys() {
        assert!(!Role::Viewer.can_manage_keys());
    }

    #[test]
    fn test_admin_can_manage_users() {
        assert!(Role::Admin.can_manage_users());
    }

    #[test]
    fn test_issuer_cannot_manage_users() {
        assert!(!Role::Issuer.can_manage_users());
    }

    #[test]
    fn test_viewer_cannot_manage_users() {
        assert!(!Role::Viewer.can_manage_users());
    }

    /* ========================================================================== */
    /*                    VALIDATION FUNCTION TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_validate_schema_url_none_is_ok() {
        assert!(validate_schema_url(&None).is_ok());
    }

    #[test]
    fn test_validate_schema_url_empty_is_err() {
        let result = validate_schema_url(&Some(String::new()));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_schema_url_valid() {
        let result = validate_schema_url(&Some("https://example.com/schema".to_string()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_schema_url_control_char_is_err() {
        let result = validate_schema_url(&Some("https://example.com/\x00bad".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_schema_url_non_ascii_is_err() {
        let result = validate_schema_url(&Some("https://example.com/\u{00e9}".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_identifier_format_valid() {
        assert!(validate_identifier_format("user-123_test:v1.0/path@host").is_ok());
    }

    #[test]
    fn test_validate_identifier_format_empty_is_err() {
        assert!(validate_identifier_format("").is_err());
    }

    #[test]
    fn test_validate_identifier_format_space_is_err() {
        assert!(validate_identifier_format("has space").is_err());
    }

    #[test]
    fn test_validate_identifier_format_special_chars_err() {
        assert!(validate_identifier_format("has<angle>brackets").is_err());
    }

    #[test]
    fn test_validate_auth_format_yubikey_ok() {
        assert!(validate_auth_format("yubikey").is_ok());
    }

    #[test]
    fn test_validate_auth_format_client_ok() {
        assert!(validate_auth_format("client").is_ok());
    }

    #[test]
    fn test_validate_auth_format_unknown_err() {
        assert!(validate_auth_format("password").is_err());
    }

    #[test]
    fn test_validate_hex_string_valid() {
        assert!(validate_hex_string("0123456789abcdefABCDEF").is_ok());
    }

    #[test]
    fn test_validate_hex_string_empty_err() {
        assert!(validate_hex_string("").is_err());
    }

    #[test]
    fn test_validate_hex_string_non_hex_err() {
        assert!(validate_hex_string("xyz123").is_err());
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: base64_bytes roundtrip is lossless for any 32-byte array
        #[test]
        fn prop_base64_bytes_roundtrip_is_lossless(
            data in prop::collection::vec(any::<u8>(), 32)
        ) {
            #[derive(Serialize, Deserialize)]
            struct Test {
                #[serde(with = "base64_bytes")]
                data: [u8; 32],
            }

            let mut arr = [0u8; 32];
            arr.copy_from_slice(&data);
            let original = Test { data: arr };

            let json = serde_json::to_string(&original)?;
            let decoded: Test = serde_json::from_str(&json)?;

            prop_assert_eq!(original.data, decoded.data);
        }

        /// Property: base64_bytes serialization has no padding
        #[test]
        fn prop_base64_bytes_no_padding(
            data in prop::collection::vec(any::<u8>(), 32)
        ) {
            #[derive(Serialize)]
            struct Test {
                #[serde(with = "base64_bytes")]
                data: [u8; 32],
            }

            let mut arr = [0u8; 32];
            arr.copy_from_slice(&data);
            let test = Test { data: arr };

            let json = serde_json::to_string(&test)?;
            // URL_SAFE_NO_PAD should never produce '=' padding
            prop_assert!(!json.contains('='));
        }

        /// Property: base64_bytes rejects wrong-length data
        #[test]
        fn prop_base64_bytes_rejects_wrong_length(
            len in 0usize..100usize
        ) {
            prop_assume!(len != 32); // Only test wrong lengths

            #[derive(Deserialize)]
            struct Test {
                #[allow(dead_code)] // Field is required for deserialisation type but not read.
                #[serde(with = "base64_bytes")]
                data: [u8; 32],
            }

            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            let bytes = vec![0u8; len];
            let encoded = URL_SAFE_NO_PAD.encode(&bytes);
            let json = format!(r#"{{"data":"{}"}}"#, encoded);

            let result = serde_json::from_str::<Test>(&json);
            prop_assert!(result.is_err());
        }

        /// Property: base64_bytes_64 roundtrip is lossless for any 64-byte array
        #[test]
        fn prop_base64_bytes_64_roundtrip_is_lossless(
            data in prop::collection::vec(any::<u8>(), 64)
        ) {
            #[derive(Serialize, Deserialize)]
            struct Test {
                #[serde(with = "base64_bytes_64")]
                data: [u8; 64],
            }

            let mut arr = [0u8; 64];
            arr.copy_from_slice(&data);
            let original = Test { data: arr };

            let json = serde_json::to_string(&original)?;
            let decoded: Test = serde_json::from_str(&json)?;

            prop_assert_eq!(original.data, decoded.data);
        }

        /// Property: base64_bytes_64 serialization has no padding
        #[test]
        fn prop_base64_bytes_64_no_padding(
            data in prop::collection::vec(any::<u8>(), 64)
        ) {
            #[derive(Serialize)]
            struct Test {
                #[serde(with = "base64_bytes_64")]
                data: [u8; 64],
            }

            let mut arr = [0u8; 64];
            arr.copy_from_slice(&data);
            let test = Test { data: arr };

            let json = serde_json::to_string(&test)?;
            // URL_SAFE_NO_PAD should never produce '=' padding
            prop_assert!(!json.contains('='));
        }

        /// Property: base64_bytes_64 rejects wrong-length data
        #[test]
        fn prop_base64_bytes_64_rejects_wrong_length(
            len in 0usize..150usize
        ) {
            prop_assume!(len != 64); // Only test wrong lengths

            #[derive(Deserialize)]
            struct Test {
                #[allow(dead_code)] // Field is required for deserialisation type but not read.
                #[serde(with = "base64_bytes_64")]
                data: [u8; 64],
            }

            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            let bytes = vec![0u8; len];
            let encoded = URL_SAFE_NO_PAD.encode(&bytes);
            let json = format!(r#"{{"data":"{}"}}"#, encoded);

            let result = serde_json::from_str::<Test>(&json);
            prop_assert!(result.is_err());
        }

        /// Property: ActorType serializes to lowercase strings
        #[test]
        fn prop_actor_type_serializes_lowercase(actor_is_officer: bool) {
            let actor = if actor_is_officer {
                ActorType::Officer
            } else {
                ActorType::Client
            };

            let json = serde_json::to_string(&actor)?;
            let expected = if actor_is_officer { r#""officer""# } else { r#""client""# };

            prop_assert_eq!(json, expected);
        }

        /// Property: ActorType roundtrip is lossless
        #[test]
        fn prop_actor_type_roundtrip(actor_is_officer: bool) {
            let actor = if actor_is_officer {
                ActorType::Officer
            } else {
                ActorType::Client
            };

            let json = serde_json::to_string(&actor)?;
            let decoded: ActorType = serde_json::from_str(&json)?;

            prop_assert_eq!(actor, decoded);
        }

        /// Property: SessionStatus serializes to lowercase strings
        #[test]
        fn prop_session_status_serializes_lowercase(status_idx: u8) {
            let status = match status_idx % 4 {
                0 => SessionStatus::Pending,
                1 => SessionStatus::Authenticated,
                2 => SessionStatus::Completed,
                _ => SessionStatus::Expired,
            };

            let json = serde_json::to_string(&status)?;
            let expected = match status_idx % 4 {
                0 => r#""pending""#,
                1 => r#""authenticated""#,
                2 => r#""completed""#,
                _ => r#""expired""#,
            };

            prop_assert_eq!(json, expected);
        }

        /// Property: SessionStatus roundtrip is lossless
        #[test]
        fn prop_session_status_roundtrip(status_idx: u8) {
            let status = match status_idx % 4 {
                0 => SessionStatus::Pending,
                1 => SessionStatus::Authenticated,
                2 => SessionStatus::Completed,
                _ => SessionStatus::Expired,
            };

            let json = serde_json::to_string(&status)?;
            let decoded: SessionStatus = serde_json::from_str(&json)?;

            prop_assert_eq!(status, decoded);
        }

        /// Property: ChallengeResponse roundtrip preserves all fields
        #[test]
        fn prop_challenge_response_roundtrip(
            challenge_id in "[a-z0-9\\-]{1,64}",
            challenge in "[a-f0-9]{1,128}",
            expires_at in any::<i64>()
        ) {
            let original = ChallengeResponse {
                challenge_id: challenge_id.clone(),
                challenge: challenge.clone(),
                expires_at,
            };

            let json = serde_json::to_string(&original)?;
            let decoded: ChallengeResponse = serde_json::from_str(&json)?;

            prop_assert_eq!(decoded.challenge_id, challenge_id);
            prop_assert_eq!(decoded.challenge, challenge);
            prop_assert_eq!(decoded.expires_at, expires_at);
        }

        /// Property: Authorizer preserves keyId camelCase field name
        #[test]
        fn prop_authorizer_camel_case_key_id(
            format in "[a-z]{1,10}",
            key_id in "[a-z0-9]{1,20}",
            timestamp in any::<u64>(),
            hmac in "[a-f0-9]{1,64}"
        ) {
            let auth = Authorizer {
                format,
                key_id,
                challenge_id: None,
                timestamp,
                hmac,
                nonce: "d".repeat(64),
            };

            let json = serde_json::to_string(&auth)?;
            // Verify camelCase field name
            prop_assert!(json.contains("keyId"));
            // Should not contain snake_case
            prop_assert!(!json.contains("key_id"));
        }

        /// Property: Authorizer roundtrip preserves all fields
        #[test]
        fn prop_authorizer_roundtrip(
            format in "[a-z]{1,10}",
            key_id in "[a-z0-9\\-]{1,20}",
            challenge_id in proptest::option::of("[a-z0-9\\-]{1,64}"),
            timestamp in any::<u64>(),
            hmac in "[a-f0-9]{1,128}"
        ) {
            let original = Authorizer {
                format: format.clone(),
                key_id: key_id.clone(),
                challenge_id: challenge_id.clone(),
                timestamp,
                hmac: hmac.clone(),
                nonce: "e".repeat(64),
            };

            let json = serde_json::to_string(&original)?;
            let decoded: Authorizer = serde_json::from_str(&json)?;

            prop_assert_eq!(decoded.format, format);
            prop_assert_eq!(decoded.key_id, key_id);
            prop_assert_eq!(decoded.challenge_id, challenge_id);
            prop_assert_eq!(decoded.timestamp, timestamp);
            prop_assert_eq!(decoded.hmac, hmac);
        }

        /// Property: PolicyConfig roundtrip preserves all fields
        #[test]
        fn prop_policy_config_roundtrip(
            schema in "[a-z0-9./]{1,50}",
            validity_days in any::<u32>(),
            v in any::<u8>()
        ) {
            let original = PolicyConfig {
                schema: schema.clone(),
                validity_days,
                v
            };

            let json = serde_json::to_string(&original)?;
            let decoded: PolicyConfig = serde_json::from_str(&json)?;

            prop_assert_eq!(decoded.schema, schema);
            prop_assert_eq!(decoded.validity_days, validity_days);
            prop_assert_eq!(decoded.v, v);
        }

        /// Property: Jwk roundtrip preserves all fields including "use" field
        #[test]
        fn prop_jwk_roundtrip(
            kty in "[A-Z]{1,10}",
            crv in "[A-Z]{1,10}",
            kid in "[a-z0-9\\-]{1,20}",
            use_ in "[a-z]{1,5}",
            alg in "[A-Za-z0-9]{1,20}",
            x in "[A-Za-z0-9_\\-]{1,86}"
        ) {
            let original = Jwk {
                kty: kty.clone(),
                crv: crv.clone(),
                kid: kid.clone(),
                use_: use_.clone(),
                alg: alg.clone(),
                x: x.clone(),
            };

            let json = serde_json::to_string(&original)?;
            let decoded: Jwk = serde_json::from_str(&json)?;

            prop_assert_eq!(decoded.kty, kty);
            prop_assert_eq!(decoded.crv, crv);
            prop_assert_eq!(decoded.kid, kid);
            prop_assert_eq!(decoded.use_, use_);
            prop_assert_eq!(decoded.alg, alg);
            prop_assert_eq!(decoded.x, x);
        }

        /// Property: JwkSet can serialize/deserialize with any number of keys
        #[test]
        fn prop_jwk_set_any_size(
            keys_count in 0usize..10
        ) {
            let keys: Vec<Jwk> = (0..keys_count)
                .map(|i| Jwk {
                    kty: "OKP".to_string(),
                    crv: "JUBJUB".to_string(),
                    kid: format!("key-{}", i),
                    use_: "sig".to_string(),
                    alg: "RedJubjub".to_string(),
                    x: "AAAA".to_string(),
                })
                .collect();

            let original = JwkSet { keys };
            let json = serde_json::to_string(&original)?;
            let decoded: JwkSet = serde_json::from_str(&json)?;

            prop_assert_eq!(decoded.keys.len(), keys_count);
        }
    }
}
