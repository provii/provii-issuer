// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

// Duplicated from provii-verifier. Extract to a shared crate when a second consumer exists.

//! Docs-gateway HMAC verification for sandbox credential mint paths.
//!
//! The docs-sandbox gateway signs every outbound request body with its
//! shared `SANDBOX_API_KEY` and sends the tag in the `X-Docs-Hmac`
//! header. This module recomputes the same tag and constant-time
//! compares it, giving the upstream route an independent authentication
//! layer that is neither the existing IP rate limit nor the KV feature
//! gate nor the service binding itself. Defence in depth.
//!
//! # Why this, not just a service binding?
//!
//! A service binding forwards the request from one worker to another
//! inside the Cloudflare runtime. It is strong against public-internet
//! attackers but does not protect against:
//!
//!   - A compromised gateway worker (bug, supply-chain, or misconfig).
//!   - A future refactor that accidentally exposes the upstream route on
//!     a public hostname.
//!   - A sandbox credential minted by a rogue caller replayed against
//!     the upstream before the gateway's own rate limit trips.
//!
//! The HMAC is verified against a secret that only the legitimate
//! gateway and upstream hold. The tag is computed over the full request
//! body, so an attacker who learns the secret still cannot tamper with
//! bodies in transit without invalidating the tag.
//!
//! # Contract
//!
//! - Header: `X-Docs-Hmac`, hex-encoded HMAC-SHA-256 of the request
//!   body.
//! - Key: UTF-8 bytes of `SANDBOX_API_KEY` (Secrets Store binding,
//!   same secret_name on provii-issuer and provii-verifier so the docs
//!   gateway holds a single key).
//! - Comparison: `hmac::Mac::verify_slice`, which performs a
//!   constant-time check internally. No hand-rolled byte comparison.
//! - Rejection status: 401, body `{"error":"docs_hmac_invalid","code":"docs_hmac_invalid"}`.
//!
//! # Scope
//!
//! The module is environment-agnostic. Route handlers gate the check on
//! `ENVIRONMENT == "sandbox"` and on the presence of a cached secret,
//! so verification runs on sandbox builds only. Production callers
//! never reach these routes (the route is gated on the environment var
//! and returns 404 otherwise).

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Header the docs gateway writes the hex tag into.
pub const DOCS_HMAC_HEADER: &str = "X-Docs-Hmac";

/// Stable error code returned on any verification failure.
///
/// The string is used as both the HTTP body's `error` field and `code`
/// field; the gateway integration test asserts against it verbatim.
pub const DOCS_HMAC_REJECTION_CODE: &str = "docs_hmac_invalid";

/// Outcome of a verification attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum DocsHmacCheck {
    /// Header present and the recomputed tag matched. Continue to the
    /// handler.
    Ok,
    /// Header missing. The request carried no tag at all.
    MissingHeader,
    /// Header present but the hex decode failed. Treated the same as a
    /// mismatch upstream; exposed separately so tests can distinguish
    /// a decode error from a wrong-key signature without reading logs.
    MalformedHeader,
    /// Header present, decoded, but the tag did not match the
    /// recomputed HMAC of the request body under the supplied key.
    Mismatch,
}

/// Fail-closed pre-check for routes that gate on a cached HMAC key.
///
/// Route handlers read the shared secret from a cached startup value
/// (a module-level OnceLock on provii-issuer, AppState on provii-verifier).
/// If that cache is empty, the Secrets Store read failed during cold
/// start and the route has no way to verify an inbound signature. This
/// helper returns `Ok(bytes)` when the cache is populated and
/// `Err(MissingHeader)` when it is not. Callers translate the error
/// into the stable 401 response whose body field `error` is
/// `DOCS_HMAC_REJECTION_CODE`. The variant is reused deliberately so
/// upstream logs record the same rejection code a caller would see for
/// any other un-authenticated call; distinguishing a startup failure
/// from an attacker-sourced one is not useful to a downstream log
/// consumer and widens the enum's surface for no gain.
///
/// The name encodes the fail-closed semantics: either the key is
/// verified as present-and-non-empty and returned for the caller to
/// use, or the request is rejected with the shared HMAC failure code.
/// No third path. Any future caller MUST NOT fall back to a default
/// key or skip verification on Err.
pub fn verify_or_reject_hmac_key(cached: Option<&[u8]>) -> Result<&[u8], DocsHmacCheck> {
    match cached {
        Some(k) if !k.is_empty() => Ok(k),
        _ => Err(DocsHmacCheck::MissingHeader),
    }
}

/// Recompute the HMAC over `body` using `key` and compare constant-time
/// against the hex-decoded `header_value`.
///
/// The body is NOT normalised; byte-identical framing on signer and
/// verifier sides is mandatory.
///
/// # Returns
///
/// `DocsHmacCheck::Ok` on success, one of the three failure variants
/// otherwise.
pub fn verify_docs_hmac(header_value: Option<&str>, body: &[u8], key: &[u8]) -> DocsHmacCheck {
    // Empty header string is treated identically to a missing header
    // so a client that emits `X-Docs-Hmac: ` (ambiguous) still fails
    // closed at the same gate.
    let header = match header_value {
        Some(h) if !h.is_empty() => h,
        _ => return DocsHmacCheck::MissingHeader,
    };

    let supplied_tag = match hex::decode(header) {
        Ok(bytes) => bytes,
        Err(_) => return DocsHmacCheck::MalformedHeader,
    };

    // Mac::new_from_slice accepts any length key (HMAC spec pads/hashes
    // internally). We still guard against an empty key to prevent the
    // route from running against an unconfigured binding.
    if key.is_empty() {
        return DocsHmacCheck::Mismatch;
    }

    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return DocsHmacCheck::Mismatch,
    };
    mac.update(body);

    // verify_slice runs a constant-time comparison internally. We do not
    // compute-then-compare ourselves; the RustCrypto team's
    // implementation is the reference we lean on for timing resistance.
    match mac.verify_slice(&supplied_tag) {
        Ok(()) => DocsHmacCheck::Ok,
        Err(_) => DocsHmacCheck::Mismatch,
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used
)]
mod tests {
    use super::*;

    fn compute_tag_hex(key: &[u8], body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn accepts_matching_hex_tag() {
        let key = b"SANDBOX_API_KEY";
        let body = br#"{"issuer_label":"Acme"}"#;
        let tag = compute_tag_hex(key, body);
        assert_eq!(verify_docs_hmac(Some(&tag), body, key), DocsHmacCheck::Ok);
    }

    #[test]
    fn rejects_missing_header() {
        let key = b"SANDBOX_API_KEY";
        let body = b"{}";
        assert_eq!(
            verify_docs_hmac(None, body, key),
            DocsHmacCheck::MissingHeader
        );
    }

    #[test]
    fn rejects_empty_header_value() {
        let key = b"SANDBOX_API_KEY";
        let body = b"{}";
        assert_eq!(
            verify_docs_hmac(Some(""), body, key),
            DocsHmacCheck::MissingHeader
        );
    }

    #[test]
    fn rejects_non_hex_header() {
        let key = b"SANDBOX_API_KEY";
        let body = b"{}";
        assert_eq!(
            verify_docs_hmac(Some("not-hex-at-all!"), body, key),
            DocsHmacCheck::MalformedHeader
        );
    }

    #[test]
    fn rejects_odd_length_hex() {
        let key = b"SANDBOX_API_KEY";
        let body = b"{}";
        assert_eq!(
            verify_docs_hmac(Some("abc"), body, key),
            DocsHmacCheck::MalformedHeader
        );
    }

    #[test]
    fn rejects_wrong_key_tag() {
        let body = b"{}";
        let tag = compute_tag_hex(b"WRONG_KEY", body);
        assert_eq!(
            verify_docs_hmac(Some(&tag), body, b"RIGHT_KEY"),
            DocsHmacCheck::Mismatch
        );
    }

    #[test]
    fn rejects_tampered_body() {
        let key = b"SANDBOX_API_KEY";
        let tag = compute_tag_hex(key, b"{\"issuer_label\":\"a\"}");
        // Same key, different body. Tag no longer matches.
        assert_eq!(
            verify_docs_hmac(Some(&tag), b"{\"issuer_label\":\"b\"}", key),
            DocsHmacCheck::Mismatch
        );
    }

    #[test]
    fn rejects_truncated_tag() {
        let key = b"SANDBOX_API_KEY";
        let body = b"{}";
        let mut tag = compute_tag_hex(key, body);
        tag.truncate(20);
        assert_eq!(
            verify_docs_hmac(Some(&tag), body, key),
            DocsHmacCheck::Mismatch
        );
    }

    #[test]
    fn rejects_empty_key() {
        let body = b"{}";
        let tag = compute_tag_hex(b"any", body);
        assert_eq!(
            verify_docs_hmac(Some(&tag), body, b""),
            DocsHmacCheck::Mismatch
        );
    }

    #[test]
    fn verify_or_reject_hmac_key_rejects_none() {
        assert_eq!(
            verify_or_reject_hmac_key(None).unwrap_err(),
            DocsHmacCheck::MissingHeader
        );
    }

    #[test]
    fn verify_or_reject_hmac_key_rejects_empty_slice() {
        assert_eq!(
            verify_or_reject_hmac_key(Some(&[])).unwrap_err(),
            DocsHmacCheck::MissingHeader
        );
    }

    #[test]
    fn verify_or_reject_hmac_key_accepts_populated() {
        let key = b"secret";
        assert_eq!(verify_or_reject_hmac_key(Some(key)).unwrap(), key);
    }

    #[test]
    fn tag_is_body_bound() {
        // Any body change, no matter how small, invalidates the tag.
        let key = b"k";
        let a = b"{\"x\":1}";
        let b = b"{\"x\":2}";
        let tag_a = compute_tag_hex(key, a);
        assert_eq!(verify_docs_hmac(Some(&tag_a), a, key), DocsHmacCheck::Ok);
        assert_eq!(
            verify_docs_hmac(Some(&tag_a), b, key),
            DocsHmacCheck::Mismatch
        );
    }
}
