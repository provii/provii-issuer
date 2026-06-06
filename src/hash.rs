// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! API key hashing utilities with Argon2id support.
//!
//! SECURITY: This module implements secure password hashing for API keys using Argon2id
//! (CWE-916, ASVS V2.4.1).
//!
//! Uses Argon2id with 64 MiB memory cost (OWASP ASVS L3) for brute-force resistance.
#![forbid(unsafe_code)]

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use zeroize::Zeroizing;

/// Create Argon2id instance with enhanced security parameters.
///
/// Memory cost: 64 MiB (OWASP ASVS L3 recommendation).
///
/// Parameters:
/// - Memory: 64 MiB (65536 KiB) - OWASP ASVS L3 recommendation
/// - Iterations: 3 (default)
/// - Parallelism: 4 (default)
/// - Output length: 32 bytes (256 bits)
///
/// Performance: ~60ms per verification on Cloudflare Workers.
///
/// Trade-off justification:
/// - API key verification happens infrequently (session establishment)
/// - 60ms is acceptable latency for authentication operations
/// - Significantly increases attacker's cost for brute-force attacks
///
/// Returns `None` only if the hardcoded constants are rejected by the Argon2
/// library (should never happen with the values used here).
fn create_argon2_verifier() -> Option<Argon2<'static>> {
    // OWASP ASVS Level 3 recommended parameters
    let params = Params::new(
        65536,    // m_cost: 64 MiB (65536 KiB)
        3,        // t_cost: 3 iterations
        4,        // p_cost: 4 parallel threads
        Some(32), // output length: 32 bytes
    )
    .ok()?;

    Some(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Computes an Argon2id hash for a plaintext API key or token.
///
/// SECURITY: Uses Argon2id with OWASP ASVS L3 compliant parameters (CWE-916,
/// ASVS V2.4.1). The plaintext byte copy made internally is wrapped in
/// `Zeroizing` so it is scrubbed from memory after hashing. Callers MUST
/// ensure their own backing `String` is zeroised after use (or wrapped in
/// `Zeroizing<String>`).
///
/// Parameters (aligned with provii-verifier):
/// - Memory: 64 MiB (65536 KiB)
/// - Iterations: 3
/// - Parallelism: 4
/// - Output length: 32 bytes (256 bits)
/// - Salt: 128-bit cryptographically secure random per key
///
/// # Returns
/// PHC-formatted hash string including algorithm, version, parameters, salt,
/// and hash.
///
/// # Errors
/// Returns error if hashing fails (e.g. invalid parameters, RNG failure).
pub fn hash_api_key(api_key: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = match create_argon2_verifier() {
        Some(a) => a,
        None => return Err(argon2::password_hash::Error::Algorithm),
    };

    let api_key_bytes = Zeroizing::new(api_key.as_bytes().to_vec());
    let hash = argon2.hash_password(&api_key_bytes, &salt)?;
    Ok(hash.to_string())
}

/// Verifies an API key against a stored Argon2id hash.
///
/// SECURITY: Uses Argon2id with constant-time comparison and 64 MiB memory cost.
///
/// # Arguments
/// * `api_key` - The plaintext API key to verify.
///   SECURITY: Caller-owned `&str`; the borrow cannot be zeroized by this function.
///   Callers MUST ensure the backing `String` is zeroized after use.
/// * `stored_hash` - The stored Argon2id hash (PHC format)
///
/// # Returns
/// `true` if the API key matches the hash, `false` otherwise.
/// Returns `false` on any internal error (param construction, hash parsing).
///
/// # Zeroization
/// // ACCEPT: Argon2 crate internals allocate working memory that cannot be
/// // zeroized from caller code (upstream limitation).
pub fn verify_api_key(api_key: &str, stored_hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(stored_hash) {
        Ok(h) => h,
        Err(_) => {
            return false;
        }
    };

    let argon2 = match create_argon2_verifier() {
        Some(a) => a,
        None => {
            return false;
        }
    };

    argon2
        .verify_password(api_key.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Deterministic FNV-1a hash for shard index computation.
///
/// `DefaultHasher` uses `SipHash` with random per-process seeds,
/// producing different shard indices across Worker isolates. This function
/// uses FNV-1a with fixed constants, guaranteeing identical output for
/// identical input regardless of isolate identity or restart.
///
/// NOT for cryptographic use. Shard distribution only.
pub(crate) fn deterministic_shard_hash(input: &str) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_api_key_produces_argon2id() {
        let phc = hash_api_key("test-key-123").expect("hash must succeed");
        assert!(phc.starts_with("$argon2id$"));
    }

    #[test]
    fn test_hash_api_key_different_salts() {
        let h1 = hash_api_key("same-key").expect("hash must succeed");
        let h2 = hash_api_key("same-key").expect("hash must succeed");
        // Random salt produces distinct hashes for identical input.
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_api_key_roundtrip() {
        let key = "test-secret-key";
        let phc = hash_api_key(key).expect("hash must succeed");
        assert!(verify_api_key(key, &phc));
    }

    #[test]
    fn test_hash_api_key_wrong_key_rejects() {
        let phc = hash_api_key("correct-key").expect("hash must succeed");
        assert!(!verify_api_key("wrong-key", &phc));
    }

    #[test]
    fn test_hash_api_key_parameters() {
        use argon2::password_hash::PasswordHash;

        let phc = hash_api_key("param-test").expect("hash must succeed");
        let parsed = PasswordHash::new(&phc).expect("parse must succeed");
        assert_eq!(parsed.algorithm.as_str(), "argon2id");
        let params = parsed.params;
        assert_eq!(params.get("m").unwrap().as_str(), "65536");
        assert_eq!(params.get("t").unwrap().as_str(), "3");
        assert_eq!(params.get("p").unwrap().as_str(), "4");
    }

    #[test]
    fn test_verify_invalid_hash_format() {
        let result = verify_api_key("test_key", "invalid_hash");
        assert!(!result);
    }

    #[test]
    fn deterministic_shard_hash_is_stable() {
        // Same input always produces same output.
        assert_eq!(
            deterministic_shard_hash("nonce-abc-123"),
            deterministic_shard_hash("nonce-abc-123")
        );
        // Different inputs produce different outputs.
        assert_ne!(deterministic_shard_hash("a"), deterministic_shard_hash("b"));
        // Pinned value: prevents accidental algorithm changes across releases.
        assert_eq!(deterministic_shard_hash("test"), 0xf9e6e6ef197c2b25);
    }
}
