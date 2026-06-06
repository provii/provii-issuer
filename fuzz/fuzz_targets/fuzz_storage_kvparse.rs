// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_issuer_worker::types::*;

fuzz_target!(|data: &[u8]| {
    // Test 1: Fuzz IssuanceSession deserialization
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<IssuanceSession>(s);
    }
    let _ = serde_json::from_slice::<IssuanceSession>(data);

    // Test 2: Fuzz StoredChallenge deserialization
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<StoredChallenge>(s);
    }
    let _ = serde_json::from_slice::<StoredChallenge>(data);

    // Test 3: Fuzz BlindIssuanceRequest deserialization
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<BlindIssuanceRequest>(s);
    }
    let _ = serde_json::from_slice::<BlindIssuanceRequest>(data);

    // Test 4: Fuzz ChallengeRequest deserialization
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<ChallengeRequest>(s);
    }
    let _ = serde_json::from_slice::<ChallengeRequest>(data);

    // Test 5: Fuzz CreateAttestationRequest deserialization
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<CreateAttestationRequest>(s);
    }
    let _ = serde_json::from_slice::<CreateAttestationRequest>(data);

    // Test 6: Fuzz CreateAttestationResponse deserialization
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<CreateAttestationResponse>(s);
    }
    let _ = serde_json::from_slice::<CreateAttestationResponse>(data);

    // Test 7: Fuzz OfficerRegistration deserialization
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<OfficerRegistration>(s);
    }
    let _ = serde_json::from_slice::<OfficerRegistration>(data);

    // Test 8: Fuzz ClientRegistration deserialization
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<ClientRegistration>(s);
    }
    let _ = serde_json::from_slice::<ClientRegistration>(data);

    // Test 9: Fuzz Authorizer deserialization
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<Authorizer>(s);
    }
    let _ = serde_json::from_slice::<Authorizer>(data);

    // Test 10: Fuzz SignedCredentialHeader deserialization
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<SignedCredentialHeader>(s);
    }
    let _ = serde_json::from_slice::<SignedCredentialHeader>(data);

    // Test 11: Roundtrip tests with proper error handling
    if let Ok(session) = serde_json::from_slice::<IssuanceSession>(data) {
        if let Ok(serialized) = serde_json::to_string(&session) {
            if let Ok(roundtrip) = serde_json::from_str::<IssuanceSession>(&serialized) {
                assert_eq!(roundtrip.session_id, session.session_id);
                assert_eq!(roundtrip.actor, session.actor);
                assert_eq!(roundtrip.status, session.status);
            }
        }
    }

    if let Ok(challenge) = serde_json::from_slice::<StoredChallenge>(data) {
        if let Ok(serialized) = serde_json::to_string(&challenge) {
            if let Ok(roundtrip) = serde_json::from_str::<StoredChallenge>(&serialized) {
                assert_eq!(roundtrip.challenge_id, challenge.challenge_id);
                assert_eq!(roundtrip.officer_id, challenge.officer_id);
            }
        }
    }

    if let Ok(blind_req) = serde_json::from_slice::<BlindIssuanceRequest>(data) {
        if let Ok(serialized) = serde_json::to_string(&blind_req) {
            let _ = serde_json::from_str::<BlindIssuanceRequest>(&serialized);
        }
    }

    if let Ok(header) = serde_json::from_slice::<SignedCredentialHeader>(data) {
        if let Ok(serialized) = serde_json::to_string(&header) {
            if let Ok(roundtrip) = serde_json::from_str::<SignedCredentialHeader>(&serialized) {
                assert_eq!(roundtrip.v, header.v);
                assert_eq!(roundtrip.kid, header.kid);
                assert_eq!(roundtrip.schema, header.schema);
            }
        }
    }
});
