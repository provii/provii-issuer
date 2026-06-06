// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_issuer_worker::types::*;
use provii_issuer_worker::session::validate_timestamp;

fuzz_target!(|data: &[u8]| {
    if data.len() < 38 {
        return;
    }

    let actor_byte = data[0];
    let actor = if actor_byte % 2 == 0 {
        ActorType::Officer
    } else {
        ActorType::Client
    };

    let status_byte = data[1] % 4;
    let status = match status_byte {
        0 => SessionStatus::Authenticated,
        1 => SessionStatus::Pending,
        2 => SessionStatus::Expired,
        3 => SessionStatus::Completed,
        _ => SessionStatus::Authenticated,
    };

    let officer_id = if data[2] > 127 {
        Some(format!("officer-{}", data[3]))
    } else {
        None
    };

    let client_id = if data[4] > 127 {
        Some(format!("client-{}", data[5]))
    } else {
        None
    };

    let created_at = i64::from_le_bytes([
        data[6], data[7], data[8], data[9],
        data[10], data[11], data[12], data[13],
    ]);
    let expires_at = i64::from_le_bytes([
        data[14], data[15], data[16], data[17],
        data[18], data[19], data.get(20).copied().unwrap_or(0), data.get(21).copied().unwrap_or(0),
    ]);

    let session = IssuanceSession {
        session_id: uuid::Uuid::new_v4().to_string(),
        created_at,
        expires_at,
        actor: actor.clone(),
        kid: String::from_utf8_lossy(&data[22..std::cmp::min(38, data.len())]).to_string(),
        schema: String::from_utf8_lossy(&data[38..std::cmp::min(54, data.len())]).to_string(),
        iat: u64::from_le_bytes([
            data.get(54).copied().unwrap_or(0),
            data.get(55).copied().unwrap_or(0),
            data.get(56).copied().unwrap_or(0),
            data.get(57).copied().unwrap_or(0),
            data.get(58).copied().unwrap_or(0),
            data.get(59).copied().unwrap_or(0),
            data.get(60).copied().unwrap_or(0),
            data.get(61).copied().unwrap_or(0),
        ]),
        exp: u64::from_le_bytes([
            data.get(62).copied().unwrap_or(0),
            data.get(63).copied().unwrap_or(0),
            data.get(64).copied().unwrap_or(0),
            data.get(65).copied().unwrap_or(0),
            data.get(66).copied().unwrap_or(0),
            data.get(67).copied().unwrap_or(0),
            data.get(68).copied().unwrap_or(0),
            data.get(69).copied().unwrap_or(0),
        ]),
        signatures_issued: 0,
        status,
        officer_id: officer_id.clone(),
        client_id: client_id.clone(),
        absolute_expiry: expires_at.saturating_add(3600),
        client_ip: None,
        user_agent: None,
    };

    // Test 1: validate_timestamp with session timestamps
    let _ = validate_timestamp(session.iat);
    let _ = validate_timestamp(session.exp);
    // Use unsigned_abs() to avoid wrapping negative i64 into unreachable u64 values
    let _ = validate_timestamp(session.created_at.unsigned_abs());
    let _ = validate_timestamp(session.expires_at.unsigned_abs());

    // Test 2: Session serialization roundtrip
    if let Ok(json) = serde_json::to_string(&session) {
        if let Ok(deserialized) = serde_json::from_str::<IssuanceSession>(&json) {
            assert_eq!(deserialized.session_id, session.session_id);
            assert_eq!(deserialized.actor, session.actor);
            assert_eq!(deserialized.status, session.status);
            assert_eq!(deserialized.officer_id, session.officer_id);
            assert_eq!(deserialized.client_id, session.client_id);
        }
    }

    // Test 3: ActorType serialization roundtrip
    let actor_json = serde_json::to_string(&actor).unwrap();
    let decoded_actor: ActorType = serde_json::from_str(&actor_json).unwrap();
    assert_eq!(decoded_actor, actor);

    // Test 4: SessionStatus serialization roundtrip
    let status_json = serde_json::to_string(&session.status).unwrap();
    let decoded_status: SessionStatus = serde_json::from_str(&status_json).unwrap();
    assert_eq!(decoded_status, session.status);

    // Test 5: Fuzz validate_timestamp with boundary values
    if data.len() >= 16 {
        let ts1 = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let ts2 = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        let _ = validate_timestamp(ts1);
        let _ = validate_timestamp(ts2);
        let _ = validate_timestamp(0);
        let _ = validate_timestamp(u64::MAX);
    }

    // Test 6: IssuanceSession deserialization from fuzz data
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<IssuanceSession>(s);
    }
    let _ = serde_json::from_slice::<IssuanceSession>(data);
});
