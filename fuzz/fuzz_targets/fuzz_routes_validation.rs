// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

#![no_main]

use libfuzzer_sys::fuzz_target;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use provii_issuer_worker::types::{
    ChallengeRequest, Authorizer, BlindIssuanceRequest, CreateAttestationRequest,
    ActorType, SessionStatus, SignedCredentialHeader,
};
use provii_issuer_worker::session::validate_timestamp;

fn is_ascii_identifier(s: &str, max_len: usize) -> bool {
    if s.is_empty() || s.len() > max_len {
        return false;
    }

    if s.trim() != s {
        return false;
    }

    // Production rejects spaces in identifiers; match that behaviour
    s.chars().all(|c| c.is_ascii() && !c.is_control() && c != ' ')
}

fuzz_target!(|data: &[u8]| {
    // Test 1: is_ascii_identifier with arbitrary strings
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = is_ascii_identifier(s, 64);
        let _ = is_ascii_identifier(s, 128);
        let _ = is_ascii_identifier(s, 1);
        let _ = is_ascii_identifier(s, usize::MAX);

        if s.is_empty() {
            assert!(!is_ascii_identifier(s, 64), "Empty string should be invalid");
        }

        if s.len() > 64 {
            assert!(!is_ascii_identifier(s, 64), "String exceeding max_len should be invalid");
        }

        let result1 = is_ascii_identifier(s, 64);
        let result2 = is_ascii_identifier(s, 64);
        assert_eq!(result1, result2, "Function should be deterministic");
    }

    // Test 2: Deserialize into production types
    let _ = serde_json::from_slice::<ChallengeRequest>(data);
    let _ = serde_json::from_slice::<Authorizer>(data);
    let _ = serde_json::from_slice::<BlindIssuanceRequest>(data);
    let _ = serde_json::from_slice::<CreateAttestationRequest>(data);

    // Test 3: Base64Bytes32 deserialization via production type
    if data.len() >= 4 {
        let json_attempt = format!(r#"{{"data":"{}"}}"#, String::from_utf8_lossy(data));
        let _ = serde_json::from_str::<SignedCredentialHeader>(&json_attempt);
    }

    // Test 4: Base64Bytes64 deserialization
    if data.len() >= 8 {
        let b64 = URL_SAFE_NO_PAD.encode(data);
        let json = format!(r#"{{"nonce":"{}"}}"#, b64);
        let _ = serde_json::from_str::<ChallengeRequest>(&json);
    }

    // Test 5: UUID parsing (for session IDs, request IDs)
    if data.len() >= 16 {
        let uuid_str = format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            data[0], data[1], data[2], data[3],
            data[4], data[5],
            data[6], data[7],
            data[8], data[9],
            data[10], data[11], data[12], data[13], data[14], data[15]
        );
        let _ = uuid::Uuid::parse_str(&uuid_str);
    }

    // Test 6: validate_timestamp with fuzz-derived values
    if data.len() >= 8 {
        let ts = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let _ = validate_timestamp(ts);
    }

    // Test 7: Type serialization roundtrips
    if let Ok(req) = serde_json::from_slice::<ChallengeRequest>(data) {
        if let Ok(json) = serde_json::to_string(&req) {
            let roundtrip = serde_json::from_str::<ChallengeRequest>(&json);
            assert!(roundtrip.is_ok(), "ChallengeRequest roundtrip must succeed");
        }
    }

    if let Ok(auth) = serde_json::from_slice::<Authorizer>(data) {
        if let Ok(json) = serde_json::to_string(&auth) {
            let roundtrip = serde_json::from_str::<Authorizer>(&json);
            assert!(roundtrip.is_ok(), "Authorizer roundtrip must succeed");
        }
    }

    // Test 8: ActorType and SessionStatus roundtrips
    if data.len() >= 2 {
        let actor = if data[0] % 2 == 0 { ActorType::Officer } else { ActorType::Client };
        let actor_json = serde_json::to_string(&actor).unwrap();
        let decoded: ActorType = serde_json::from_str(&actor_json).unwrap();
        assert_eq!(decoded, actor);

        let status = match data[1] % 4 {
            0 => SessionStatus::Pending,
            1 => SessionStatus::Authenticated,
            2 => SessionStatus::Completed,
            _ => SessionStatus::Expired,
        };
        let status_json = serde_json::to_string(&status).unwrap();
        let decoded_status: SessionStatus = serde_json::from_str(&status_json).unwrap();
        assert_eq!(decoded_status, status);
    }
});
