// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Public-safe hex fingerprints for rotation observability.
//!
//! Extracted from `secret_fingerprint.rs` in the Worker crate. Both the
//! logic crate and the Worker crate re-export these identical functions.
//!
//! Per `OBSERVABILITY.md` section 1, every rotation-capable secret slot is
//! identified on logs and on the `x-secret-version` response header by
//! the first 6 hex characters of `lowercase(hex(sha256(value)))`. The
//! literal string `"000000"` is the reserved sentinel for "no value".
//!
//! SECURITY: A 6-char prefix carries 24 bits of entropy. It is one-way
//! derived from the secret value but is NOT itself secret. It is logged
//! per request and returned as a response header. Do not treat it as
//! confidential. Do not use it as a comparison primitive.
//!
//! Constant-time comparison is intentionally NOT applied. Fingerprints
//! are public-safe and never used to authorise a request.
#![forbid(unsafe_code)]

/// 6-char hex fingerprint of a secret-shaped value.
/// Returns the `"000000"` sentinel for empty input.
pub fn fingerprint6(value: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    if value.is_empty() {
        return "000000".to_string();
    }
    let digest = Sha256::digest(value);
    hex::encode(digest.as_slice().get(..3).unwrap_or(&[0u8, 0u8, 0u8]))
}

/// Full 8-char hex fingerprint for rotation-drill identification.
pub fn fingerprint8(value: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    if value.is_empty() {
        return "00000000".to_string();
    }
    let digest = Sha256::digest(value);
    hex::encode(digest.as_slice().get(..4).unwrap_or(&[0u8, 0u8, 0u8, 0u8]))
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint6_empty_returns_sentinel() {
        assert_eq!(fingerprint6(b""), "000000");
    }

    #[test]
    fn fingerprint6_known_shape() {
        let fp = fingerprint6(b"any-secret-value");
        assert_eq!(fp.len(), 6);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(fp.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn fingerprint6_distinct_inputs() {
        let fp_a = fingerprint6(b"secret-current");
        let fp_b = fingerprint6(b"secret-previous");
        assert_ne!(fp_a, fp_b);
    }

    #[test]
    fn fingerprint6_deterministic() {
        assert_eq!(
            fingerprint6(b"identical-value"),
            fingerprint6(b"identical-value")
        );
    }

    #[test]
    fn fingerprint8_empty_returns_sentinel() {
        assert_eq!(fingerprint8(b""), "00000000");
    }

    #[test]
    fn fingerprint8_known_shape() {
        let fp = fingerprint8(b"any-secret-value");
        assert_eq!(fp.len(), 8);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint8_extends_fingerprint6() {
        let v = b"correlation-test";
        let fp6 = fingerprint6(v);
        let fp8 = fingerprint8(v);
        assert_eq!(fp8.get(..6), Some(fp6.as_str()));
    }
}
