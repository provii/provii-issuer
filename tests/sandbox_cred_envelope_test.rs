// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Envelope-level tests for the sandbox credential mint endpoint.
//!
//! These exercise the HMAC verification + body-shape contract that the
//! docs gateway depends on, without spinning up the Cloudflare Workers
//! runtime. The full route handler (KV writes, KEK encryption, rate
//! limit, request parsing) requires the wasm32 worker harness; the
//! cases below are the parts we can prove correct natively.
//!
//! For the cases that genuinely need the runtime (404 in production,
//! 429 rate limit, JWKS happy path against KV), the wrangler integration
//! suite under e2e/ in the credential-paths plan picks them up. The
//! native suite here closes the loop on the verification primitives.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use provii_issuer_worker::security::{
    verify_docs_hmac, verify_or_reject_hmac_key, DocsHmacCheck, DOCS_HMAC_HEADER,
    DOCS_HMAC_REJECTION_CODE,
};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute the hex tag the docs gateway emits for a given body and key.
fn sign_body(key: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// A valid Ed25519 public key in base64url form, for inclusion in
/// representative request bodies.
fn fresh_pubkey_b64() -> String {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes())
}

#[test]
fn happy_path_tag_verifies_against_body() {
    let key = b"GATEWAY_KEY";
    let body = serde_json::json!({
        "api_key": "GATEWAY_KEY",
        "issuer_label": "Acme Sandbox",
        "ed25519_public_key": fresh_pubkey_b64(),
    })
    .to_string();
    let tag = sign_body(key, body.as_bytes());

    assert_eq!(
        verify_docs_hmac(Some(&tag), body.as_bytes(), key),
        DocsHmacCheck::Ok
    );
}

#[test]
fn missing_header_yields_missing_header_outcome() {
    let key = b"GATEWAY_KEY";
    let body = b"{}";
    assert_eq!(
        verify_docs_hmac(None, body, key),
        DocsHmacCheck::MissingHeader
    );
}

#[test]
fn empty_header_value_treated_as_missing() {
    let key = b"GATEWAY_KEY";
    let body = b"{}";
    assert_eq!(
        verify_docs_hmac(Some(""), body, key),
        DocsHmacCheck::MissingHeader
    );
}

#[test]
fn malformed_hex_header_yields_malformed_outcome() {
    let key = b"GATEWAY_KEY";
    let body = b"{}";
    assert_eq!(
        verify_docs_hmac(Some("zzzz-not-hex"), body, key),
        DocsHmacCheck::MalformedHeader
    );
}

#[test]
fn wrong_key_signature_yields_mismatch_outcome() {
    let body = b"{}";
    let bad_tag = sign_body(b"WRONG_KEY", body);
    assert_eq!(
        verify_docs_hmac(Some(&bad_tag), body, b"RIGHT_KEY"),
        DocsHmacCheck::Mismatch
    );
}

#[test]
fn tampered_body_invalidates_tag() {
    let key = b"GATEWAY_KEY";
    let body_a = b"{\"api_key\":\"a\"}";
    let body_b = b"{\"api_key\":\"b\"}";
    let tag = sign_body(key, body_a);
    assert_eq!(
        verify_docs_hmac(Some(&tag), body_b, key),
        DocsHmacCheck::Mismatch
    );
}

#[test]
fn fail_closed_when_cached_key_absent() {
    // The route is required to short-circuit to 401 docs_hmac_invalid
    // when the cached SANDBOX_API_KEY is not populated.
    assert_eq!(
        verify_or_reject_hmac_key(None).unwrap_err(),
        DocsHmacCheck::MissingHeader
    );
    assert_eq!(
        verify_or_reject_hmac_key(Some(&[])).unwrap_err(),
        DocsHmacCheck::MissingHeader
    );
}

#[test]
fn fail_closed_passes_through_when_cached_key_populated() {
    let key = b"populated";
    assert_eq!(verify_or_reject_hmac_key(Some(key)).unwrap(), key);
}

#[test]
fn rejection_code_is_stable_string() {
    // The docs gateway integration test asserts against this string
    // verbatim. Bumping it is a breaking change.
    assert_eq!(DOCS_HMAC_REJECTION_CODE, "docs_hmac_invalid");
}

#[test]
fn header_name_is_stable_string() {
    assert_eq!(DOCS_HMAC_HEADER, "X-Docs-Hmac");
}

#[test]
fn truncated_tag_yields_mismatch_not_malformed() {
    // The tag is even-length hex, so truncation to even hex stays
    // valid hex but mismatches the recomputed MAC. A test for the
    // "almost-valid" bit-flipped tag class.
    let key = b"GATEWAY_KEY";
    let body = b"{}";
    let mut tag = sign_body(key, body);
    tag.truncate(40); // Still valid hex, half the length.
    assert_eq!(
        verify_docs_hmac(Some(&tag), body, key),
        DocsHmacCheck::Mismatch
    );
}
