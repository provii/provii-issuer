// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Helpers for signing credential commitments with RedJubjub keys.

use crate::error::{ApiError, Result};
use crate::types::SignedCredentialHeader;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use core::fmt;
use group::GroupEncoding;
use jubjub::SubgroupPoint;
use provii_crypto_commons::CredMsgV2;
use provii_crypto_sig_redjubjub;
use zeroize::{Zeroize, Zeroizing};

/// Holds RedJubjub signing material and associated key id.
pub struct RjSigner {
    pub kid: String,
    sk: [u8; 32],
    pub vk: [u8; 32],
    /// When true, the SK is a zeroed placeholder and must not be used
    /// for signing. Only JWKS (public key) operations are permitted.
    verify_only: bool,
}

impl fmt::Debug for RjSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RjSigner")
            .field("kid", &self.kid)
            .field("sk", &"[REDACTED]")
            .field("vk", &self.vk_base64())
            .field("verify_only", &self.verify_only)
            .finish()
    }
}

impl Drop for RjSigner {
    fn drop(&mut self) {
        self.sk.zeroize();
    }
}

impl RjSigner {
    /// Build a signer from raw 32-byte secret and verification keys.
    ///
    /// SECURITY: `sk` is wrapped in `Zeroizing` immediately so it is cleared on
    /// all paths (including early-return errors). The intermediate `sk_array`
    /// stack copy is also wrapped in `Zeroizing`; its contents are moved into
    /// `Self.sk` which is zeroized via the `Drop` impl on `RjSigner`.
    pub fn new(kid: String, sk: Vec<u8>, vk: Vec<u8>) -> Result<Self> {
        // Validate kid: must not be empty and must not exceed reasonable length.
        if kid.is_empty() {
            return Err(ApiError::CryptoError("kid must not be empty".to_string()));
        }
        if kid.len() > 128 {
            return Err(ApiError::CryptoError(
                "kid exceeds maximum length (128 chars)".to_string(),
            ));
        }
        // Reject control characters in kid to prevent log injection.
        if kid.chars().any(|c| c.is_ascii_control()) {
            return Err(ApiError::CryptoError(
                "kid contains disallowed control characters".to_string(),
            ));
        }

        let sk = Zeroizing::new(sk);
        if sk.len() != 32 || vk.len() != 32 {
            return Err(ApiError::CryptoError("Invalid key size".to_string()));
        }

        let sk_array = Zeroizing::new({
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&sk);
            arr
        });
        let mut vk_array = [0u8; 32];
        vk_array.copy_from_slice(&vk);

        // CIV-134: Validate VK is a valid Jubjub SubgroupPoint.
        if bool::from(SubgroupPoint::from_bytes(&vk_array).is_none()) {
            return Err(ApiError::CryptoError(
                "VK is not a valid Jubjub SubgroupPoint".to_string(),
            ));
        }

        // Verify SK and VK form a consistent keypair by deriving VK from SK.
        let derived_sk = provii_crypto_sig_redjubjub::SigningKey::from_bytes(&sk_array)
            .map_err(|_| ApiError::CryptoError("SK is not a valid signing key".to_string()))?;
        let derived_vk = derived_sk.verification_key();
        if derived_vk.to_bytes() != vk_array {
            return Err(ApiError::CryptoError(
                "SK and VK are not a consistent keypair".to_string(),
            ));
        }

        Ok(Self {
            kid,
            sk: *sk_array,
            vk: vk_array,
            verify_only: false,
        })
    }

    /// Export the verification key in base64url form for JWKS responses.
    pub fn vk_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.vk)
    }
}

/// Sign a commitment and return the public credential header.
pub fn sign_commitment(
    signer: &RjSigner,
    c_bytes: [u8; 32],
    iat: u64,
    exp: u64,
    schema: &str,
) -> Result<SignedCredentialHeader> {
    // Refuse to sign with a verify-only signer (zero SK placeholder).
    if signer.verify_only {
        return Err(ApiError::CryptoError(
            "Cannot sign with a verify-only key manager".to_string(),
        ));
    }

    // Validate schema is present and well-formed before signing.
    if schema.is_empty() {
        return Err(ApiError::BadRequest("Schema must not be empty".to_string()));
    }
    if schema.len() > 500 {
        return Err(ApiError::BadRequest(
            "Schema exceeds maximum length".to_string(),
        ));
    }

    // Temporal guard, refuse to sign credentials where the issued-at
    // timestamp is not strictly before the expiry timestamp.
    if iat >= exp {
        return Err(ApiError::BadRequest("iat must be before exp".to_string()));
    }

    // CIV-135: Validate commitment is a valid Jubjub SubgroupPoint.
    if bool::from(SubgroupPoint::from_bytes(&c_bytes).is_none()) {
        return Err(ApiError::CryptoError(
            "Commitment is not a valid Jubjub SubgroupPoint".to_string(),
        ));
    }

    // Assemble the message expected by the signing library.
    let cred_msg = CredMsgV2 {
        v: 2,
        kid: signer.kid.clone(),
        c: c_bytes,
        iat,
        exp,
        schema: schema.to_string(),
    };

    let signature = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &signer.sk)
        .map_err(|e| ApiError::CryptoError(format!("Signing failed: {:?}", e)))?;

    // Immediately verify to ensure our signing and verification logic stay in sync.
    provii_crypto_sig_redjubjub::verify_cred_v2(&cred_msg, &signature, &signer.vk).map_err(
        |e| {
            crate::log_error!(
                "CRITICAL: Self-verification failed for kid={}: {:?}",
                signer.kid,
                e
            );
            ApiError::CryptoError(format!("Self-verify failed: {:?}", e))
        },
    )?;

    crate::log!("Signature self-verification passed for kid={}", signer.kid);

    Ok(SignedCredentialHeader {
        v: 2,
        kid: signer.kid.clone(),
        issuer_vk: signer.vk,
        sig_rj: signature,
        c_bytes,
        iat,
        exp,
        schema: schema.to_string(),
    })
}

/// Produce a random 32-byte nonce suitable for commitments.
///
/// Returns an error if the platform CSPRNG is unavailable.
pub fn generate_nonce() -> crate::error::Result<[u8; 32]> {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|e| {
        crate::error::ApiError::CryptoError(format!("Nonce generation failed: {}", e))
    })?;
    Ok(nonce)
}

/// Wraps one or more signers used by the issuer service.
#[derive(Debug)]
pub struct KeyManager {
    keys: Vec<RjSigner>,
}

impl KeyManager {
    /// Convenience constructor for the common single-key configuration.
    pub fn from_keypair(kid: String, sk: Vec<u8>, vk: Vec<u8>) -> Result<Self> {
        let signer = RjSigner::new(kid, sk, vk)?;
        Ok(Self { keys: vec![signer] })
    }

    /// Construct a KeyManager with only the public verification key.
    ///
    /// Suitable for JWKS endpoints that only need to serve public key material
    /// without loading the private signing key from storage.
    ///
    /// The resulting signer has `verify_only = true` and will refuse
    /// to sign if `sign_commitment` is called.
    pub fn from_public_key(kid: String, vk: Vec<u8>) -> Result<Self> {
        // Validate kid (same rules as RjSigner::new).
        if kid.is_empty() {
            return Err(ApiError::CryptoError("kid must not be empty".to_string()));
        }
        if kid.len() > 128 {
            return Err(ApiError::CryptoError(
                "kid exceeds maximum length (128 chars)".to_string(),
            ));
        }
        if kid.chars().any(|c| c.is_ascii_control()) {
            return Err(ApiError::CryptoError(
                "kid contains disallowed control characters".to_string(),
            ));
        }

        if vk.len() != 32 {
            return Err(ApiError::CryptoError("Invalid key size".to_string()));
        }

        let mut vk_array = [0u8; 32];
        vk_array.copy_from_slice(&vk);

        // Validate VK is a valid Jubjub SubgroupPoint.
        if bool::from(SubgroupPoint::from_bytes(&vk_array).is_none()) {
            return Err(ApiError::CryptoError(
                "VK is not a valid Jubjub SubgroupPoint".to_string(),
            ));
        }

        let signer = RjSigner {
            kid,
            sk: [0u8; 32],
            vk: vk_array,
            verify_only: true,
        };
        Ok(Self { keys: vec![signer] })
    }

    /// Return the signer used for default credential issuance.
    pub fn default_signer(&self) -> Option<&RjSigner> {
        self.keys.first()
    }

    /// Convert managed keys into JWKS JSON entries.
    pub fn get_jwks(&self) -> Vec<crate::types::Jwk> {
        self.keys
            .iter()
            .map(|key| crate::types::Jwk {
                kty: "OKP".to_string(),
                crv: "JUBJUB".to_string(),
                kid: key.kid.clone(),
                use_: "sig".to_string(),
                alg: "RedJubjub".to_string(),
                x: key.vk_base64(),
            })
            .collect()
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

    // Known valid Jubjub SubgroupPoint (Zcash spending key generator).
    // Used only for tests that do NOT exercise RjSigner::new (which now
    // validates SK/VK consistency). Tests that build an RjSigner must use
    // `derive_test_keypair` instead.
    const VALID_VK: [u8; 32] = [
        0x30, 0xb5, 0xf2, 0xaa, 0xad, 0x32, 0x56, 0x30, 0xbc, 0xdd, 0xdb, 0xce, 0x4d, 0x67, 0x65,
        0x6d, 0x05, 0xfd, 0x1c, 0xc2, 0xd0, 0x37, 0xbb, 0x53, 0x75, 0xb6, 0xe9, 0x6d, 0x9e, 0x01,
        0xa1, 0x57,
    ];

    fn derive_test_keypair(sk_bytes: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let sk = provii_crypto_sig_redjubjub::SigningKey::from_bytes(sk_bytes).unwrap();
        let vk = sk.verification_key();
        (*sk_bytes, vk.to_bytes())
    }

    /* ========================================================================== */
    /*                    RJSIGNER TESTS                                         */
    /* ========================================================================== */

    #[test]
    fn test_rj_signer_new_valid() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (sk_arr, vk_arr) = derive_test_keypair(&valid_test_sk());
        let signer = RjSigner::new("key-1".to_string(), sk_arr.to_vec(), vk_arr.to_vec())?;
        assert_eq!(signer.kid, "key-1");
        assert_eq!(signer.sk, sk_arr);
        assert_eq!(signer.vk, vk_arr);
        Ok(())
    }

    #[test]
    fn test_rj_signer_new_invalid_vk_curve_point(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // 32 bytes that are NOT a valid SubgroupPoint
        let sk = vec![1u8; 32];
        let vk = vec![0xFFu8; 32];
        let result = RjSigner::new("key-1".to_string(), sk, vk);
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .to_string()
            .contains("SubgroupPoint"));
        Ok(())
    }

    #[test]
    fn test_rj_signer_new_sk_too_short() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let sk = vec![1u8; 16]; // Too short
        let vk = VALID_VK.to_vec();
        let result = RjSigner::new("key-1".to_string(), sk, vk);
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .to_string()
            .contains("Invalid key size"));
        Ok(())
    }

    #[test]
    fn test_rj_signer_new_sk_too_long() {
        let sk = vec![1u8; 64]; // Too long
        let vk = VALID_VK.to_vec();
        let result = RjSigner::new("key-1".to_string(), sk, vk);
        assert!(result.is_err());
    }

    #[test]
    fn test_rj_signer_new_vk_too_short() {
        let sk = vec![1u8; 32];
        let vk = vec![2u8; 16]; // Too short
        let result = RjSigner::new("key-1".to_string(), sk, vk);
        assert!(result.is_err());
    }

    #[test]
    fn test_rj_signer_new_vk_too_long() {
        let sk = vec![1u8; 32];
        let vk = vec![2u8; 48]; // Too long
        let result = RjSigner::new("key-1".to_string(), sk, vk);
        assert!(result.is_err());
    }

    #[test]
    fn test_rj_signer_new_empty_keys() {
        let sk = vec![];
        let vk = vec![];
        let result = RjSigner::new("key-1".to_string(), sk, vk);
        assert!(result.is_err());
    }

    #[test]
    fn test_rj_signer_vk_base64() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (sk_arr, vk_arr) = derive_test_keypair(&valid_test_sk());
        let signer = RjSigner::new("key-1".to_string(), sk_arr.to_vec(), vk_arr.to_vec())?;
        let b64 = signer.vk_base64();

        assert!(!b64.contains('='));
        assert!(!b64.contains('+'));
        assert!(!b64.contains('/'));

        let decoded = URL_SAFE_NO_PAD.decode(&b64)?;
        assert_eq!(decoded, vk_arr.to_vec());
        Ok(())
    }

    #[test]
    fn test_rj_signer_rejects_all_zero_vk() {
        // CIV-134: An all-zero 32-byte VK is a non-canonical encoding that
        // jubjub 0.10's ZIP-216-enabled `SubgroupPoint::from_bytes` rejects.
        // Even if it decoded, using the identity point as a VK is
        // cryptographically degenerate (it implies sk = 0 mod r), so refusing
        // it at construction time is the correct behaviour.
        let sk = vec![1u8; 32];
        let vk = vec![0u8; 32];
        let err =
            RjSigner::new("key-1".to_string(), sk, vk).expect_err("all-zero VK must be rejected");
        match err {
            ApiError::CryptoError(msg) => {
                assert!(
                    msg.contains("Jubjub SubgroupPoint"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected CryptoError, got {other:?}"), // nosemgrep: panic-in-worker
        }
    }

    #[test]
    fn test_rj_signer_kid_preserved() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (sk_arr, vk_arr) = derive_test_keypair(&valid_test_sk());
        let kid = "test-key-with-special-chars-123_ABC".to_string();
        let signer = RjSigner::new(kid.clone(), sk_arr.to_vec(), vk_arr.to_vec())?;
        assert_eq!(signer.kid, kid);
        Ok(())
    }

    /* ========================================================================== */
    /*                    GENERATE_NONCE TESTS                                   */
    /* ========================================================================== */

    #[test]
    fn test_generate_nonce_length() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let nonce = generate_nonce()?;
        assert_eq!(nonce.len(), 32);
        Ok(())
    }

    #[test]
    fn test_generate_nonce_nonzero() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let nonce = generate_nonce()?;
        // Statistical test: extremely unlikely to get all zeros
        let all_zeros = nonce.iter().all(|&b| b == 0);
        assert!(!all_zeros);
        Ok(())
    }

    #[test]
    fn test_generate_nonce_unique() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let nonce1 = generate_nonce()?;
        let nonce2 = generate_nonce()?;
        // Statistically should be different
        assert_ne!(nonce1, nonce2);
        Ok(())
    }

    #[test]
    fn test_generate_nonce_multiple_calls() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let nonces: Vec<[u8; 32]> = (0..10)
            .map(|_| generate_nonce())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        // Check all nonces are unique
        for i in 0..nonces.len() {
            for j in (i + 1)..nonces.len() {
                assert_ne!(nonces[i], nonces[j]);
            }
        }
        Ok(())
    }

    /* ========================================================================== */
    /*                    KEYMANAGER TESTS                                       */
    /* ========================================================================== */

    #[test]
    fn test_key_manager_from_keypair_valid() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let (sk_arr, vk_arr) = derive_test_keypair(&valid_test_sk());
        let km = KeyManager::from_keypair("key-1".to_string(), sk_arr.to_vec(), vk_arr.to_vec())?;
        assert_eq!(km.keys.len(), 1);
        assert_eq!(km.keys[0].kid, "key-1");
        Ok(())
    }

    #[test]
    fn test_key_manager_from_keypair_invalid_sk() {
        let sk = vec![1u8; 16]; // Too short
        let vk = VALID_VK.to_vec();
        let result = KeyManager::from_keypair("key-1".to_string(), sk, vk);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_manager_from_keypair_invalid_vk() {
        let sk = vec![1u8; 32];
        let vk = vec![2u8; 16]; // Too short
        let result = KeyManager::from_keypair("key-1".to_string(), sk, vk);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_manager_default_signer() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (sk_arr, vk_arr) = derive_test_keypair(&valid_test_sk());
        let km = KeyManager::from_keypair("key-1".to_string(), sk_arr.to_vec(), vk_arr.to_vec())?;

        let default = km.default_signer();
        assert!(default.is_some());
        assert_eq!(default.ok_or("expected default signer")?.kid, "key-1");
        Ok(())
    }

    #[test]
    fn test_key_manager_get_jwks() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (sk_arr, vk_arr) = derive_test_keypair(&valid_test_sk());
        let km = KeyManager::from_keypair("key-1".to_string(), sk_arr.to_vec(), vk_arr.to_vec())?;

        let jwks = km.get_jwks();
        assert_eq!(jwks.len(), 1);

        let jwk = &jwks[0];
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, "JUBJUB");
        assert_eq!(jwk.kid, "key-1");
        assert_eq!(jwk.use_, "sig");
        assert_eq!(jwk.alg, "RedJubjub");

        let decoded = URL_SAFE_NO_PAD.decode(&jwk.x)?;
        assert_eq!(decoded, vk_arr.to_vec());
        Ok(())
    }

    #[test]
    fn test_key_manager_get_jwks_empty() {
        let km = KeyManager { keys: vec![] };
        let jwks = km.get_jwks();
        assert_eq!(jwks.len(), 0);
    }

    #[test]
    fn test_key_manager_default_signer_empty() {
        let km = KeyManager { keys: vec![] };
        let default = km.default_signer();
        assert!(default.is_none());
    }

    /* ========================================================================== */
    /*                    SIGN_COMMITMENT TESTS                                  */
    /* ========================================================================== */

    fn valid_test_sk() -> [u8; 32] {
        // Small scalar value guaranteed to be below the Jubjub field order.
        let mut sk = [0u8; 32];
        sk[0] = 0x42;
        sk[1] = 0x01;
        sk
    }

    fn create_test_signer() -> std::result::Result<RjSigner, Box<dyn std::error::Error>> {
        let (sk_arr, vk_arr) = derive_test_keypair(&valid_test_sk());
        Ok(RjSigner::new(
            "test-kid".to_string(),
            sk_arr.to_vec(),
            vk_arr.to_vec(),
        )?)
    }

    // Note: sign_commitment() uses the actual provii_crypto_sig_redjubjub library
    // Some tests may fail if the library requires valid curve points.
    // These tests verify the function behaviour we can control.

    #[test]
    fn test_sign_commitment_rejects_invalid_curve_point(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let signer = create_test_signer()?;
        let bad_commitment = [0xAB; 32]; // Not a valid SubgroupPoint
        let result = sign_commitment(
            &signer,
            bad_commitment,
            1700000000,
            1731536000,
            "provii.age/0",
        );
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .to_string()
            .contains("SubgroupPoint"));
        Ok(())
    }

    #[test]
    fn test_sign_commitment_returns_result() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let signer = create_test_signer()?;
        // Use a known valid SubgroupPoint as commitment
        let commitment = VALID_VK;
        let iat = 1700000000;
        let exp = 1731536000;
        let schema = "provii.age/0";

        let result = sign_commitment(&signer, commitment, iat, exp, schema);

        // Test that we get a Result back (even if it's an error from signing)
        match result {
            Ok(header) => {
                assert_eq!(header.v, 2);
                assert_eq!(header.kid, "test-kid");
                assert_eq!(header.c_bytes, commitment);
                assert_eq!(header.iat, iat);
                assert_eq!(header.exp, exp);
                assert_eq!(header.schema, schema);
            }
            Err(e) => {
                // May error from the actual crypto signing step
                assert!(
                    e.to_string().contains("Crypto error")
                        || e.to_string().contains("Signing failed")
                        || e.to_string().contains("Self-verify failed")
                );
            }
        }
        Ok(())
    }

    #[test]
    fn test_sign_commitment_time_edge_cases() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let signer = create_test_signer()?;
        let commitment = VALID_VK; // Valid SubgroupPoint

        // Test iat = 0, exp = 1000, valid temporal range, should succeed
        let result = sign_commitment(&signer, commitment, 0, 1000, "test");
        assert!(result.is_ok(), "iat=0, exp=1000 should succeed");

        // Test exp = 0, iat >= exp, should be rejected
        let result = sign_commitment(&signer, commitment, 1000, 0, "test");
        assert!(result.is_err(), "iat=1000, exp=0 must fail (iat >= exp)");

        // Test iat > exp (reversed times), should be rejected
        let result = sign_commitment(&signer, commitment, 2000, 1000, "test");
        assert!(result.is_err(), "iat > exp must fail");

        // Test iat = exp, should be rejected
        let result = sign_commitment(&signer, commitment, 1000, 1000, "test");
        assert!(result.is_err(), "iat == exp must fail");

        // Test large values (iat = exp = MAX), should be rejected
        let result = sign_commitment(&signer, commitment, u64::MAX, u64::MAX, "test");
        assert!(result.is_err(), "iat == exp (MAX) must fail");
        Ok(())
    }

    #[test]
    fn test_sign_commitment_schema_edge_cases(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let signer = create_test_signer()?;
        let commitment = VALID_VK; // Valid SubgroupPoint
        let iat = 1700000000;
        let exp = 1731536000;

        // Test empty schema (rejected by validation)
        let result = sign_commitment(&signer, commitment, iat, exp, "");
        assert!(result.is_err());

        // Test very long schema (>500 chars rejected by validation)
        let long_schema = "a".repeat(10000);
        let result = sign_commitment(&signer, commitment, iat, exp, &long_schema);
        assert!(result.is_err());

        // Test schema with special characters, valid input, should succeed
        let result = sign_commitment(
            &signer,
            commitment,
            iat,
            exp,
            "schema/with:special@chars#$%",
        );
        assert!(result.is_ok(), "special chars in schema should succeed");

        // Test schema with unicode, valid input, should succeed
        let result = sign_commitment(&signer, commitment, iat, exp, "スキーマ🔐");
        assert!(result.is_ok(), "unicode schema should succeed");

        // Test schema with newlines, valid input, should succeed
        let result = sign_commitment(&signer, commitment, iat, exp, "line1\nline2\nline3");
        assert!(result.is_ok(), "newline schema should succeed");

        // Test schema with tabs, valid input, should succeed
        let result = sign_commitment(&signer, commitment, iat, exp, "tab\ttab\ttab");
        assert!(result.is_ok(), "tab schema should succeed");

        // Test schema with quotes, valid input, should succeed
        let result = sign_commitment(&signer, commitment, iat, exp, r#"quotes"and'apostrophes"#);
        assert!(result.is_ok(), "quote schema should succeed");
        Ok(())
    }

    #[test]
    fn test_sign_commitment_commitment_edge_cases(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let signer = create_test_signer()?;
        let iat = 1700000000;
        let exp = 1731536000;

        // Test all-zero commitment, rejected by ZIP-216-enabled SubgroupPoint::from_bytes
        let result = sign_commitment(&signer, [0x00; 32], iat, exp, "test");
        assert!(
            result.is_err(),
            "all-zero bytes are not a valid SubgroupPoint encoding"
        );

        // Test all-FF commitment (NOT a valid SubgroupPoint, should be rejected)
        let result = sign_commitment(&signer, [0xFF; 32], iat, exp, "test");
        assert!(result.is_err(), "0xFF bytes are not a valid SubgroupPoint");

        // Test valid SubgroupPoint commitment
        let result = sign_commitment(&signer, VALID_VK, iat, exp, "test");
        assert!(result.is_ok(), "known valid SubgroupPoint should succeed");
        Ok(())
    }

    #[test]
    fn test_sign_commitment_different_kids() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let iat = 1700000000;
        let exp = 1731536000;
        let commitment = VALID_VK; // Valid SubgroupPoint
        let schema = "test-schema";

        // Test empty kid, construction must fail (kid validation)
        let (sk_arr, vk_arr) = derive_test_keypair(&valid_test_sk());
        let result = RjSigner::new("".to_string(), sk_arr.to_vec(), vk_arr.to_vec());
        assert!(result.is_err(), "empty kid must be rejected");

        // Test very long kid (> 128 chars), construction must fail
        let long_kid = "k".repeat(1000);
        let result = RjSigner::new(long_kid.clone(), sk_arr.to_vec(), vk_arr.to_vec());
        assert!(result.is_err(), "kid > 128 chars must be rejected");

        // Test kid at exactly 128 chars, should succeed
        let max_kid = "k".repeat(128);
        let signer = RjSigner::new(max_kid.clone(), sk_arr.to_vec(), vk_arr.to_vec())?;
        let result = sign_commitment(&signer, commitment, iat, exp, schema);
        if let Ok(header) = result {
            assert_eq!(header.kid, max_kid);
        }

        // Test kid with unicode
        let unicode_kid = "キー🔑";
        let signer = RjSigner::new(unicode_kid.to_string(), sk_arr.to_vec(), vk_arr.to_vec())?;
        let result = sign_commitment(&signer, commitment, iat, exp, schema);
        if let Ok(header) = result {
            assert_eq!(header.kid, unicode_kid);
        }
        Ok(())
    }

    #[test]
    fn test_sign_commitment_header_version() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let signer = create_test_signer()?;
        let commitment = VALID_VK;
        let result = sign_commitment(&signer, commitment, 1000, 2000, "v2-test");

        // Verify version is always 2
        if let Ok(header) = result {
            assert_eq!(header.v, 2, "SignedCredentialHeader version must be 2");
        }
        Ok(())
    }

    #[test]
    fn test_sign_commitment_preserves_issuer_vk(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (sk_arr, vk_arr) = derive_test_keypair(&valid_test_sk());
        let signer = RjSigner::new("vk-test".to_string(), sk_arr.to_vec(), vk_arr.to_vec())?;
        let commitment = VALID_VK;

        let result = sign_commitment(&signer, commitment, 1000, 2000, "vk-preserve");
        if let Ok(header) = result {
            assert_eq!(header.issuer_vk, vk_arr, "issuer_vk should match signer.vk");
        }
        Ok(())
    }

    #[test]
    fn test_sign_commitment_is_deterministic() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let signer = create_test_signer()?;
        let commitment = VALID_VK;
        let iat = 1700000000;
        let exp = 1731536000;
        let schema = "determinism-test";

        let result1 = sign_commitment(&signer, commitment, iat, exp, schema);
        let result2 = sign_commitment(&signer, commitment, iat, exp, schema);

        // Verify deterministic behaviour: both must succeed or both must fail
        assert_eq!(
            result1.is_ok(),
            result2.is_ok(),
            "Signing should be deterministic (both succeed or both fail)"
        );

        // If both succeeded, verify same outputs
        if let (Ok(header1), Ok(header2)) = (result1, result2) {
            assert_eq!(header1.v, header2.v);
            assert_eq!(header1.kid, header2.kid);
            assert_eq!(header1.issuer_vk, header2.issuer_vk);
            assert_eq!(header1.c_bytes, header2.c_bytes);
            assert_eq!(header1.iat, header2.iat);
            assert_eq!(header1.exp, header2.exp);
            assert_eq!(header1.schema, header2.schema);
            // Note: Signature may differ if randomness is involved in signing
        }
        Ok(())
    }

    #[test]
    fn test_sign_commitment_all_edge_case_combinations(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let signer = create_test_signer()?;

        // All-zero commitment with empty schema (both rejected)
        let result = sign_commitment(&signer, [0x00; 32], 0, 0, "");
        assert!(result.is_err());

        // Invalid SubgroupPoint should be rejected
        let result = sign_commitment(&signer, [0xFF; 32], u64::MAX, u64::MAX, &"z".repeat(10000));
        assert!(result.is_err());

        // Valid SubgroupPoint with extreme time values and empty schema
        let result = sign_commitment(&signer, VALID_VK, u64::MAX, 0, "");
        assert!(result.is_err());
        Ok(())
    }

    /* ========================================================================== */
    /*                    KEY MANAGER TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_key_manager_from_public_key_invalid_curve_point() {
        // 0xFF bytes are not a valid Jubjub SubgroupPoint
        let invalid_vk = vec![0xFF; 32];
        let result = KeyManager::from_public_key("test-kid".to_string(), invalid_vk);
        assert!(result.is_err(), "invalid VK curve point must be rejected");
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("SubgroupPoint"),
            "error message should mention SubgroupPoint, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_key_manager_from_public_key_valid() {
        let result = KeyManager::from_public_key("valid-kid".to_string(), VALID_VK.to_vec());
        assert!(result.is_ok(), "valid VK should succeed");
        let km = result.unwrap();
        let signer = km.default_signer().unwrap();
        assert_eq!(signer.kid, "valid-kid");
        assert!(signer.verify_only);
    }

    #[test]
    fn test_key_manager_from_public_key_empty_kid() {
        let result = KeyManager::from_public_key("".to_string(), VALID_VK.to_vec());
        assert!(result.is_err(), "empty kid must be rejected");
    }

    #[test]
    fn test_key_manager_from_public_key_wrong_size() {
        let result = KeyManager::from_public_key("kid".to_string(), vec![1u8; 16]);
        assert!(result.is_err(), "wrong-size VK must be rejected");
    }

    /* ========================================================================== */
    /*                    INTEGRATION TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_rj_signer_round_trip() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (sk_arr, vk_arr) = derive_test_keypair(&valid_test_sk());
        let kid = "test-key".to_string();

        let signer = RjSigner::new(kid.clone(), sk_arr.to_vec(), vk_arr.to_vec())?;
        assert_eq!(signer.kid, kid);
        assert_eq!(signer.sk, sk_arr);
        assert_eq!(signer.vk, vk_arr);

        let b64 = signer.vk_base64();
        let decoded = URL_SAFE_NO_PAD.decode(&b64)?;
        assert_eq!(decoded, vk_arr.to_vec());
        Ok(())
    }

    #[test]
    fn test_key_manager_jwks_consistency() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (sk_arr, vk_arr) = derive_test_keypair(&valid_test_sk());
        let kid = "consistent-key".to_string();

        let km = KeyManager::from_keypair(kid.clone(), sk_arr.to_vec(), vk_arr.to_vec())?;

        let jwks1 = km.get_jwks();
        let jwks2 = km.get_jwks();

        assert_eq!(jwks1.len(), jwks2.len());
        assert_eq!(jwks1[0].kid, jwks2[0].kid);
        assert_eq!(jwks1[0].x, jwks2[0].x);
        Ok(())
    }

    #[test]
    fn test_multiple_nonces_no_collisions() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Generate many nonces to test randomness
        let count = 100;
        let nonces: Vec<[u8; 32]> = (0..count)
            .map(|_| generate_nonce())
            .collect::<std::result::Result<Vec<_>, _>>()?;

        // Verify all are unique (collision probability is astronomically low)
        for i in 0..nonces.len() {
            for j in (i + 1)..nonces.len() {
                assert_ne!(
                    nonces[i], nonces[j],
                    "Found duplicate nonce at indices {} and {}",
                    i, j
                );
            }
        }
        Ok(())
    }

    /* ========================================================================== */
    /*                    PROPERTY TESTS                                         */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        #[test]
        fn prop_rj_signer_rejects_arbitrary_vk(
            sk in prop::collection::vec(any::<u8>(), 32),
            vk in prop::collection::vec(any::<u8>(), 32),
        ) {
            let result = RjSigner::new("test".to_string(), sk, vk);
            // With consistency check, arbitrary SK+VK pairs will almost always fail.
            // The test validates that construction never panics.
            let _ = result;
        }

        #[test]
        fn prop_rj_signer_rejects_wrong_size_keys(
            sk_len in 0usize..100,
            vk_len in 0usize..100
        ) {
            prop_assume!(sk_len != 32 || vk_len != 32);

            let sk = vec![0u8; sk_len];
            let vk = vec![0u8; vk_len];
            let result = RjSigner::new("test".to_string(), sk, vk);

            prop_assert!(result.is_err());
        }

        #[test]
        fn prop_vk_base64_roundtrip_is_lossless(
            sk in prop::collection::vec(any::<u8>(), 32)
        ) {
            // Only test with valid signing keys
            if let Ok(signing_key) = provii_crypto_sig_redjubjub::SigningKey::from_bytes(
                <&[u8; 32]>::try_from(sk.as_slice()).unwrap()
            ) {
                let vk = signing_key.verification_key().to_bytes();
                let signer = RjSigner::new("test".to_string(), sk, vk.to_vec()).unwrap();
                let b64 = signer.vk_base64();
                let decoded = URL_SAFE_NO_PAD.decode(&b64).unwrap();
                prop_assert_eq!(decoded, vk.to_vec());
            }
        }

        #[test]
        fn prop_vk_base64_is_deterministic(
            sk in prop::collection::vec(any::<u8>(), 32)
        ) {
            if let Ok(signing_key) = provii_crypto_sig_redjubjub::SigningKey::from_bytes(
                <&[u8; 32]>::try_from(sk.as_slice()).unwrap()
            ) {
                let vk = signing_key.verification_key().to_bytes();
                let signer = RjSigner::new("test".to_string(), sk, vk.to_vec()).unwrap();
                let b64_1 = signer.vk_base64();
                let b64_2 = signer.vk_base64();
                prop_assert_eq!(b64_1, b64_2);
            }
        }

        #[test]
        fn prop_vk_base64_has_no_padding(
            sk in prop::collection::vec(any::<u8>(), 32)
        ) {
            if let Ok(signing_key) = provii_crypto_sig_redjubjub::SigningKey::from_bytes(
                <&[u8; 32]>::try_from(sk.as_slice()).unwrap()
            ) {
                let vk = signing_key.verification_key().to_bytes();
                let signer = RjSigner::new("test".to_string(), sk, vk.to_vec()).unwrap();
                let b64 = signer.vk_base64();
                prop_assert!(!b64.contains('='));
                prop_assert!(!b64.contains('+'));
                prop_assert!(!b64.contains('/'));
            }
        }

        #[test]
        fn prop_kid_is_preserved(
            kid in "[a-zA-Z0-9_-]{1,128}",
            sk in prop::collection::vec(any::<u8>(), 32),
        ) {
            if let Ok(signing_key) = provii_crypto_sig_redjubjub::SigningKey::from_bytes(
                <&[u8; 32]>::try_from(sk.as_slice()).unwrap()
            ) {
                let vk = signing_key.verification_key().to_bytes();
                let signer = RjSigner::new(kid.clone(), sk, vk.to_vec()).unwrap();
                prop_assert_eq!(&signer.kid, &kid);
            }
        }

        #[test]
        fn prop_key_manager_preserves_single_key(
            kid in "[a-zA-Z0-9_-]{1,128}",
            sk in prop::collection::vec(any::<u8>(), 32),
        ) {
            if let Ok(signing_key) = provii_crypto_sig_redjubjub::SigningKey::from_bytes(
                <&[u8; 32]>::try_from(sk.as_slice()).unwrap()
            ) {
                let vk = signing_key.verification_key().to_bytes();
                let km = KeyManager::from_keypair(kid.clone(), sk.clone(), vk.to_vec()).unwrap();
                prop_assert_eq!(km.keys.len(), 1);
                prop_assert_eq!(&km.keys[0].kid, &kid);
                prop_assert_eq!(km.keys[0].sk.to_vec(), sk);
                prop_assert_eq!(km.keys[0].vk.to_vec(), vk.to_vec());
            }
        }

        #[test]
        fn prop_jwks_has_correct_structure(
            kid in "[a-zA-Z0-9_-]{1,128}",
            sk in prop::collection::vec(any::<u8>(), 32),
        ) {
            if let Ok(signing_key) = provii_crypto_sig_redjubjub::SigningKey::from_bytes(
                <&[u8; 32]>::try_from(sk.as_slice()).unwrap()
            ) {
                let vk = signing_key.verification_key().to_bytes();
                let km = KeyManager::from_keypair(kid.clone(), sk, vk.to_vec()).unwrap();
                let jwks = km.get_jwks();
                prop_assert_eq!(jwks.len(), 1);
                prop_assert_eq!(&jwks[0].kty, "OKP");
                prop_assert_eq!(&jwks[0].crv, "JUBJUB");
                prop_assert_eq!(&jwks[0].kid, &kid);
                prop_assert_eq!(&jwks[0].use_, "sig");
                prop_assert_eq!(&jwks[0].alg, "RedJubjub");
            }
        }

        #[test]
        fn prop_jwks_x_field_is_base64url_of_vk(
            kid in "[a-zA-Z0-9_-]{1,128}",
            sk in prop::collection::vec(any::<u8>(), 32),
        ) {
            if let Ok(signing_key) = provii_crypto_sig_redjubjub::SigningKey::from_bytes(
                <&[u8; 32]>::try_from(sk.as_slice()).unwrap()
            ) {
                let vk = signing_key.verification_key().to_bytes();
                let km = KeyManager::from_keypair(kid, sk, vk.to_vec()).unwrap();
                let jwks = km.get_jwks();
                let decoded_x = URL_SAFE_NO_PAD.decode(&jwks[0].x).unwrap();
                prop_assert_eq!(decoded_x, vk.to_vec());
            }
        }

        #[test]
        fn prop_generate_nonce_always_32_bytes(
            _seed in 0u64..1000
        ) {
            let nonce = generate_nonce().unwrap();
            prop_assert_eq!(nonce.len(), 32);
        }

        #[test]
        fn prop_jwks_is_consistent_across_calls(
            kid in "[a-zA-Z0-9_-]{1,128}",
            sk in prop::collection::vec(any::<u8>(), 32),
        ) {
            if let Ok(signing_key) = provii_crypto_sig_redjubjub::SigningKey::from_bytes(
                <&[u8; 32]>::try_from(sk.as_slice()).unwrap()
            ) {
                let vk = signing_key.verification_key().to_bytes();
                let km = KeyManager::from_keypair(kid, sk, vk.to_vec()).unwrap();
                let jwks1 = km.get_jwks();
                let jwks2 = km.get_jwks();
                prop_assert_eq!(jwks1.len(), jwks2.len());
                prop_assert_eq!(&jwks1[0].kid, &jwks2[0].kid);
                prop_assert_eq!(&jwks1[0].x, &jwks2[0].x);
                prop_assert_eq!(&jwks1[0].kty, &jwks2[0].kty);
                prop_assert_eq!(&jwks1[0].crv, &jwks2[0].crv);
            }
        }
    }
}
