// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Cross-service golden-vector tests for the canonical HMAC signing message
//! contract.
//!
//! Mirrors `provii-verifier/tests/security/canonical_message_test.rs`. The
//! fixture file is byte-identical to the copy in
//! `provii-verifier/tests/fixtures/` and
//! `provii-demos/demo-web-provii-agegate/test/docs/`. A diff script (added in
//! provii-demos) catches drift between the three.
//!
//! provii-issuer carries a canonical-message constructor in `session.rs`
//! for the attestation flow, producing the 5-section envelope
//! `{ts}:{method}:{path}:{body}:{nonce}`. This file:
//!
//! 1. Drives `create_canonical_message_for_attestation` with synthesised
//!    `Authorizer` + `dob_days` inputs and asserts equality with
//!    `issuer_post_attestation_create`.
//! 2. Walks every fixture vector that publishes
//!    `expected_canonical_bytes_hex` and verifies the published
//!    `expected_hmac_hex_with_known_key` matches HMAC-SHA-256 over those
//!    bytes with the published key. This guards the wire envelope and
//!    the published key-message-tag mapping independent of any
//!    constructor.
//! 3. Walks the attestation vectors and asserts the provii-crypto
//!    `DobAttestation::compute_message_bytes` framing matches.

#![allow(
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

use hmac::{Hmac, Mac};
use provii_crypto_commons::attestation::DobAttestation;
use provii_issuer_worker::session::create_canonical_message_for_attestation;
use provii_issuer_worker::types::Authorizer;
use serde::Deserialize;
use sha2::Sha256;
use wasm_bindgen_test::wasm_bindgen_test;

type HmacSha256 = Hmac<Sha256>;

const FIXTURE_BYTES: &str = include_str!("fixtures/canonical_message_vectors.json");

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    hmac_key_hex: String,
    vectors: Vec<Vector>,
    attestation_vectors: Vec<AttestationVector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    test_name: String,
    #[serde(default)]
    service_origin: String,
    inputs: VectorInputs,
    #[serde(default)]
    expected_canonical_bytes_hex: Option<String>,
    expected_hmac_hex_with_known_key: String,
}

#[derive(Debug, Deserialize)]
struct VectorInputs {
    timestamp: u64,
    method: String,
    path: String,
    #[serde(default)]
    body: Option<String>,
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct AttestationVector {
    test_name: String,
    constructor: String,
    inputs: AttestationInputs,
    expected_message_bytes_hex: String,
}

#[derive(Debug, Deserialize)]
struct AttestationInputs {
    dob_days: i32,
    issuer_id: String,
    timestamp: u64,
    nonce_hex: String,
    session_id: Option<String>,
    client_id: Option<String>,
}

fn load_fixture() -> Fixture {
    serde_json::from_str(FIXTURE_BYTES).expect("fixture JSON must parse")
}

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex must decode")
}

fn compute_hmac(key: &[u8], msg: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    hex::encode(mac.finalize().into_bytes())
}

#[wasm_bindgen_test]
fn fixture_schema_locked_at_v1() {
    let fixture = load_fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.hmac_key_hex.len(), 64);
}

/// Drive the provii-issuer `create_canonical_message_for_attestation`
/// constructor with the same inputs the fixture documents.
/// the constructor returns `Zeroizing<String>` so dob_days does not sit
/// in the heap after the comparison. We dereference once, compare, and
/// drop.
#[wasm_bindgen_test]
fn issuer_attestation_constructor_matches_fixture() {
    let fixture = load_fixture();
    let v = fixture
        .vectors
        .iter()
        .find(|v| v.test_name == "issuer_post_attestation_create")
        .expect("fixture must include issuer_post_attestation_create");

    let authorizer = Authorizer {
        format: "client".to_string(),
        key_id: "client-001".to_string(),
        challenge_id: None,
        timestamp: v.inputs.timestamp,
        hmac: "0".repeat(64),
        nonce: v.inputs.nonce.clone(),
    };

    let canonical = create_canonical_message_for_attestation(
        &v.inputs.method,
        &v.inputs.path,
        v.inputs.timestamp,
        7300,
        &authorizer,
    );
    let canonical_bytes = canonical.as_bytes();

    let expected = hex_decode(
        v.expected_canonical_bytes_hex
            .as_ref()
            .expect("issuer_post_attestation_create has expected bytes"),
    );
    assert_eq!(
        canonical_bytes,
        expected.as_slice(),
        "issuer create_canonical_message_for_attestation drifted from fixture"
    );

    let key = hex_decode(&fixture.hmac_key_hex);
    let actual_hmac = compute_hmac(&key, canonical_bytes);
    assert_eq!(actual_hmac, v.expected_hmac_hex_with_known_key);
}

/// Walk every fixture vector that publishes
/// `expected_canonical_bytes_hex` and prove HMAC-SHA-256 with the
/// published key recomputes `expected_hmac_hex_with_known_key`. This
/// guards the published key-message-tag mapping itself, catching typos
/// in the fixture or drift in the HMAC implementation.
#[wasm_bindgen_test]
fn every_published_canonical_bytes_round_trips_hmac() {
    let fixture = load_fixture();
    let key = hex_decode(&fixture.hmac_key_hex);
    let mut checked = 0;
    for v in &fixture.vectors {
        if let Some(hex_bytes) = &v.expected_canonical_bytes_hex {
            let bytes = hex_decode(hex_bytes);
            let actual_hmac = compute_hmac(&key, &bytes);
            assert_eq!(
                actual_hmac, v.expected_hmac_hex_with_known_key,
                "fixture round-trip failure for {}",
                v.test_name
            );
            // For vectors that also expose `body`, sanity-check that the
            // documented body appears as a contiguous substring of the
            // canonical bytes. Catches accidental escaping mistakes in
            // the fixture without coupling to the exact 5-section format.
            if let Some(body) = &v.inputs.body {
                let body_bytes = body.as_bytes();
                let canonical_text = std::str::from_utf8(&bytes).unwrap_or("");
                assert!(
                    canonical_text.contains(body),
                    "body bytes not found inside canonical bytes for {} (body len={}, canonical len={})",
                    v.test_name,
                    body_bytes.len(),
                    bytes.len()
                );
            }
            checked += 1;
        }
        // Echo the path/timestamp/method are non-empty to catch obviously
        // malformed fixtures.
        assert!(
            !v.inputs.method.is_empty() && !v.inputs.path.is_empty() && v.inputs.timestamp > 0,
            "fixture vector {} has empty mandatory inputs",
            v.test_name
        );
        assert!(!v.service_origin.is_empty());
    }
    assert!(
        checked >= 6,
        "expected at least 6 byte-string vectors (verifier x2, shared x3, issuer x2 minus 1kb), got {checked}"
    );
}

/// Lock the provii-crypto attestation framing (Blake2s-256, length-
/// prefixed strings, little-endian dob_days/timestamp). Drift here
/// invalidates every Ed25519 attestation already signed by an issuer.
#[wasm_bindgen_test]
fn attestation_compute_message_bytes_matches_fixture() {
    let fixture = load_fixture();
    for av in &fixture.attestation_vectors {
        assert_eq!(av.constructor, "DobAttestation::compute_message_bytes");
        let nonce_bytes = hex_decode(&av.inputs.nonce_hex);
        assert_eq!(nonce_bytes.len(), 32);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&nonce_bytes);

        let session = av.inputs.session_id.as_deref();
        let client = av.inputs.client_id.as_deref();

        let actual = DobAttestation::compute_message_bytes(
            av.inputs.dob_days,
            &av.inputs.issuer_id,
            av.inputs.timestamp,
            &nonce,
            session,
            client,
        )
        .expect("fixture inputs must be in-range");
        let expected = hex_decode(&av.expected_message_bytes_hex);
        assert_eq!(
            actual.as_slice(),
            expected.as_slice(),
            "attestation vector {} drifted",
            av.test_name
        );
    }
}
