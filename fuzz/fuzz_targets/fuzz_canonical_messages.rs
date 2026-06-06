// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_issuer_worker::types::*;

// Import the canonical message creation functions
// These are public in the session module

fuzz_target!(|data: &[u8]| {
    // Need at least 4 bytes for method extraction; remaining tests gate on their own lengths
    if data.len() < 4 {
        return;
    }

    // Split the input data into parts for different fields
    let method_bytes = &data[0..std::cmp::min(4, data.len())];
    let path_bytes = &data[4..std::cmp::min(8, data.len())];
    let timestamp = u64::from_le_bytes([
        data.get(8).copied().unwrap_or(0),
        data.get(9).copied().unwrap_or(0),
        data.get(10).copied().unwrap_or(0),
        data.get(11).copied().unwrap_or(0),
        data.get(12).copied().unwrap_or(0),
        data.get(13).copied().unwrap_or(0),
        data.get(14).copied().unwrap_or(0),
        data.get(15).copied().unwrap_or(0),
    ]);

    // Try to construct valid UTF-8 strings for method and path
    let method = std::str::from_utf8(method_bytes).unwrap_or("POST");
    let path = std::str::from_utf8(path_bytes).unwrap_or("/v1/start");

    // Test 1: Fuzz create_canonical_message_for_attestation
    if data.len() >= 64 {
        let dob_days_bytes = [
            data.get(32).copied().unwrap_or(0),
            data.get(33).copied().unwrap_or(0),
            data.get(34).copied().unwrap_or(0),
            data.get(35).copied().unwrap_or(0),
        ];
        let dob_days = i32::from_le_bytes(dob_days_bytes);

        let format_byte = data.get(36).copied().unwrap_or(0);
        let auth_format = match format_byte % 3 {
            0 => "yubikey",
            1 => "client",
            _ => "unknown",
        };

        let key_id_start = 37;
        let key_id_end = std::cmp::min(key_id_start + 16, data.len());
        let key_id = if key_id_end > key_id_start {
            String::from_utf8_lossy(&data[key_id_start..key_id_end]).to_string()
        } else {
            "default-key".to_string()
        };

        let auth_timestamp = u64::from_le_bytes([
            data.get(53).copied().unwrap_or(0),
            data.get(54).copied().unwrap_or(0),
            data.get(55).copied().unwrap_or(0),
            data.get(56).copied().unwrap_or(0),
            data.get(57).copied().unwrap_or(0),
            data.get(58).copied().unwrap_or(0),
            data.get(59).copied().unwrap_or(0),
            data.get(60).copied().unwrap_or(0),
        ]);

        let hmac = hex::encode(&data[61..std::cmp::min(93, data.len())]);

        let nonce = hex::encode(&data[37..std::cmp::min(69, data.len())]);
        let nonce = format!("{:0<64}", nonce);

        let authorizer = Authorizer {
            format: auth_format.to_string(),
            key_id: key_id.clone(),
            timestamp: auth_timestamp,
            hmac,
            challenge_id: None,
            nonce,
        };

        // This should never panic, always produce a string
        let canonical = provii_issuer_worker::session::create_canonical_message_for_attestation(
            method,
            path,
            timestamp,
            dob_days,
            &authorizer,
        );

        // Invariants:
        // 1. Result must be non-empty
        assert!(!canonical.is_empty(), "Canonical message must not be empty");
        // 2. Must contain structural separators (the function joins fields with delimiters)
        assert!(canonical.len() > method.len(), "Canonical message must include more than just the method");

        // 2. Should be deterministic
        let canonical2 = provii_issuer_worker::session::create_canonical_message_for_attestation(
            method,
            path,
            timestamp,
            dob_days,
            &authorizer,
        );
        assert_eq!(canonical, canonical2, "Canonical message should be deterministic");

        // 3. Different dob_days should produce different messages
        let different_dob = dob_days.wrapping_add(1);
        let canonical_different = provii_issuer_worker::session::create_canonical_message_for_attestation(
            method,
            path,
            timestamp,
            different_dob,
            &authorizer,
        );
        assert_ne!(canonical, canonical_different, "Different dob_days should produce different canonical messages");
    }

    // Test 2: Fuzz timestamp validation
    let _ = provii_issuer_worker::session::validate_timestamp(timestamp);
    let _ = provii_issuer_worker::session::validate_timestamp(0);
    let _ = provii_issuer_worker::session::validate_timestamp(u64::MAX);
});
