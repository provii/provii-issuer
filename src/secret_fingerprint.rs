// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Public-safe 6-char hex fingerprints for rotation observability.
//!
//! Delegates to `issuer_logic::secret_fingerprint`. This thin wrapper
//! exists so existing `use crate::secret_fingerprint::fingerprint6` paths
//! resolve unchanged.
#![forbid(unsafe_code)]

pub use issuer_logic::secret_fingerprint::{fingerprint6, fingerprint8};

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint6_delegates_correctly() {
        assert_eq!(fingerprint6(b""), "000000");
        let fp = fingerprint6(b"test-value");
        assert_eq!(fp.len(), 6);
    }

    #[test]
    fn fingerprint8_delegates_correctly() {
        assert_eq!(fingerprint8(b""), "00000000");
        let fp = fingerprint8(b"test-value");
        assert_eq!(fp.len(), 8);
    }

    #[test]
    fn fp8_extends_fp6() {
        let v = b"correlation-test";
        let fp6 = fingerprint6(v);
        let fp8 = fingerprint8(v);
        assert_eq!(fp8.get(..6), Some(fp6.as_str()));
    }
}
