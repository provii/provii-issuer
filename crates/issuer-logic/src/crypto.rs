// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! AES-256-GCM envelope encryption/decryption with AAD.
//!
//! Extracted from `storage.rs` in the Worker crate. These are the functions
//! that protect signing keys, HMAC secrets, and session data at rest.
//!
//! AAD labels (`purpose`) MUST be preserved byte-for-byte across extraction.
//! Known labels in production:
//!   - `b"provii-issuer:session:v1"` (session data, HMAC secrets)
//!   - `b"provii-issuer:api-key-hash:v1"` (API key hashes)
//!   - `b"provii-issuer:signing-key:v1"` (and v2, v3... per rotation)

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroizing;

use crate::error::{LogicError, Result};

/// Encrypt `plaintext` using AES-256-GCM with `kek` and `purpose` as AAD.
///
/// Output format: `nonce (12 bytes) || ciphertext+tag`.
pub fn encrypt_with_kek(kek: &[u8], plaintext: &[u8], purpose: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(kek)
        .map_err(|e| LogicError::CryptoError(format!("Invalid KEK: {}", e)))?;

    // Generate random nonce using getrandom (CSPRNG).
    // Wrapped in Zeroizing for defence-in-depth. AES-GCM nonces
    // are not secret, but zeroising ephemeral cryptographic material is
    // consistent with the project-wide policy.
    let mut nonce_bytes = Zeroizing::new([0u8; 12]);
    getrandom::getrandom(&mut *nonce_bytes)
        .map_err(|e| LogicError::CryptoError(format!("Nonce generation failed: {}", e)))?;
    let nonce = Nonce::from_slice(&*nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: purpose,
            },
        )
        .map_err(|e| LogicError::CryptoError(format!("Encryption failed: {}", e)))?;

    // Format: nonce (12 bytes) || ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt `encrypted_data` using AES-256-GCM with `kek` and `purpose` as AAD.
///
/// Expected input format: `nonce (12 bytes) || ciphertext+tag`.
pub fn decrypt_with_kek(kek: &[u8], encrypted_data: &[u8], purpose: &[u8]) -> Result<Vec<u8>> {
    // AES-256-GCM minimum: 12 bytes nonce + 16 bytes auth tag = 28 bytes.
    // Any shorter input cannot be valid ciphertext.
    if encrypted_data.len() < 28 {
        return Err(LogicError::CryptoError(
            "Encrypted data too short (minimum 28 bytes: nonce + tag)".to_string(),
        ));
    }

    // Format: nonce (12 bytes) || ciphertext (rest)
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(kek)
        .map_err(|e| LogicError::CryptoError(format!("Invalid KEK: {}", e)))?;

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: purpose,
            },
        )
        .map_err(|e| LogicError::CryptoError(format!("Decryption failed: {}", e)))
}

/// Compute remaining TTL in seconds from an `expires_at` timestamp.
/// Returns at least 1 to avoid zero-TTL KV writes.
#[inline]
pub fn remaining_ttl_secs(expires_at: i64) -> u64 {
    let diff = expires_at
        .saturating_sub(chrono::Utc::now().timestamp())
        .max(1);
    // diff is >= 1 (positive), so the u64 conversion is lossless.
    #[allow(clippy::cast_sign_loss)]
    let r = diff as u64;
    r
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let kek = [0xABu8; 32];
        let plaintext = b"secret signing key material";
        let purpose = b"provii-issuer:session:v1";

        let encrypted = encrypt_with_kek(&kek, plaintext, purpose).unwrap();
        let decrypted = decrypt_with_kek(&kek, &encrypted, purpose).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_kek_fails() {
        let kek = [0xABu8; 32];
        let wrong_kek = [0xCDu8; 32];
        let plaintext = b"secret";
        let purpose = b"provii-issuer:session:v1";

        let encrypted = encrypt_with_kek(&kek, plaintext, purpose).unwrap();
        let result = decrypt_with_kek(&wrong_kek, &encrypted, purpose);

        assert!(result.is_err());
    }

    #[test]
    fn wrong_purpose_fails() {
        let kek = [0xABu8; 32];
        let plaintext = b"secret";
        let purpose_a = b"provii-issuer:session:v1";
        let purpose_b = b"provii-issuer:api-key-hash:v1";

        let encrypted = encrypt_with_kek(&kek, plaintext, purpose_a).unwrap();
        let result = decrypt_with_kek(&kek, &encrypted, purpose_b);

        assert!(result.is_err());
    }

    #[test]
    fn too_short_input_rejected() {
        let kek = [0xABu8; 32];
        let purpose = b"provii-issuer:session:v1";

        // 27 bytes: below the 28-byte minimum
        let short = vec![0u8; 27];
        let result = decrypt_with_kek(&kek, &short, purpose);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn invalid_kek_length_rejected() {
        let bad_kek = [0xABu8; 16]; // 128 bits, not 256
        let plaintext = b"secret";
        let purpose = b"provii-issuer:session:v1";

        let result = encrypt_with_kek(&bad_kek, plaintext, purpose);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid KEK"));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let kek = [0xABu8; 32];
        let plaintext = b"secret";
        let purpose = b"provii-issuer:session:v1";

        let mut encrypted = encrypt_with_kek(&kek, plaintext, purpose).unwrap();
        // Flip a byte in the ciphertext portion (after the 12-byte nonce)
        let last = encrypted.len().saturating_sub(1);
        encrypted[last] ^= 0xFF;

        let result = decrypt_with_kek(&kek, &encrypted, purpose);
        assert!(result.is_err());
    }

    #[test]
    fn nonce_uniqueness() {
        let kek = [0xABu8; 32];
        let plaintext = b"same plaintext";
        let purpose = b"provii-issuer:session:v1";

        let enc1 = encrypt_with_kek(&kek, plaintext, purpose).unwrap();
        let enc2 = encrypt_with_kek(&kek, plaintext, purpose).unwrap();

        // Same plaintext + key produces different ciphertext (random nonce)
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let kek = [0xABu8; 32];
        let plaintext = b"";
        let purpose = b"provii-issuer:session:v1";

        let encrypted = encrypt_with_kek(&kek, plaintext, purpose).unwrap();
        let decrypted = decrypt_with_kek(&kek, &encrypted, purpose).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn remaining_ttl_secs_future_expiry() {
        // An expiry 100 seconds in the future
        let future = chrono::Utc::now().timestamp().saturating_add(100);
        let ttl = remaining_ttl_secs(future);
        // Should be approximately 100 (might be 99 due to timing)
        assert!(ttl >= 99 && ttl <= 101);
    }

    #[test]
    fn remaining_ttl_secs_past_expiry() {
        // An expiry 100 seconds in the past
        let past = chrono::Utc::now().timestamp().saturating_sub(100);
        let ttl = remaining_ttl_secs(past);
        // Clamped to minimum of 1
        assert_eq!(ttl, 1);
    }

    #[test]
    fn remaining_ttl_secs_at_epoch() {
        // Epoch (0) is always in the past
        let ttl = remaining_ttl_secs(0);
        assert_eq!(ttl, 1);
    }

    #[test]
    fn aad_domain_separation_labels_preserved() {
        // Regression guard: the known AAD labels must decrypt correctly
        let kek = [0x42u8; 32];

        let labels: &[&[u8]] = &[
            b"provii-issuer:session:v1",
            b"provii-issuer:api-key-hash:v1",
            b"provii-issuer:signing-key:v1",
            b"provii-issuer:signing-key:v2",
        ];

        for label in labels {
            let plaintext = b"test-payload";
            let encrypted = encrypt_with_kek(&kek, plaintext, label).unwrap();
            let decrypted = decrypt_with_kek(&kek, &encrypted, label).unwrap();
            assert_eq!(
                decrypted, plaintext,
                "Roundtrip failed for label {:?}",
                label
            );
        }
    }
}
