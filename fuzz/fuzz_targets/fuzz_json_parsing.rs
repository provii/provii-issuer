// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json;
use provii_issuer_worker::types::{
    ChallengeRequest, Authorizer, BlindIssuanceRequest, CreateAttestationRequest,
    SignedCredentialHeader,
};

fuzz_target!(|data: &[u8]| {
    // Test 1: Deserialize into production types directly
    let _ = serde_json::from_slice::<ChallengeRequest>(data);
    let _ = serde_json::from_slice::<Authorizer>(data);
    let _ = serde_json::from_slice::<BlindIssuanceRequest>(data);
    let _ = serde_json::from_slice::<CreateAttestationRequest>(data);
    let _ = serde_json::from_slice::<SignedCredentialHeader>(data);

    // Test 2: String-based deserialization into production types
    if let Ok(json_str) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<ChallengeRequest>(json_str);
        let _ = serde_json::from_str::<Authorizer>(json_str);
        let _ = serde_json::from_str::<BlindIssuanceRequest>(json_str);
        let _ = serde_json::from_str::<CreateAttestationRequest>(json_str);
        let _ = serde_json::from_str::<SignedCredentialHeader>(json_str);
    }

    // Test 3: deny_unknown_fields enforcement on ChallengeRequest
    {
        let with_extra = r#"{"officer_id":"test","unexpected_field":"value"}"#;
        let result = serde_json::from_str::<ChallengeRequest>(with_extra);
        assert!(result.is_err(), "ChallengeRequest must reject unknown fields");

        let with_nested_extra = r#"{"officer_id":"test","nested":{"deep":"value"}}"#;
        let result = serde_json::from_str::<ChallengeRequest>(with_nested_extra);
        assert!(result.is_err(), "ChallengeRequest must reject unknown nested fields");
    }

    // Test 4: deny_unknown_fields enforcement on Authorizer
    {
        let with_extra = r#"{"format":"client","keyId":"k1","timestamp":1000,"hmac":"aa","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","extra":"bad"}"#;
        let result = serde_json::from_str::<Authorizer>(with_extra);
        assert!(result.is_err(), "Authorizer must reject unknown fields");
    }

    // Test 5: deny_unknown_fields enforcement on CreateAttestationRequest
    {
        let nonce_hex = "a".repeat(64);
        let with_extra = format!(
            r#"{{"dob_days":100,"authorizer":{{"format":"client","keyId":"k1","timestamp":1000,"hmac":"aa","nonce":"{}"}},"extra_field":"bad"}}"#,
            nonce_hex
        );
        let result = serde_json::from_str::<CreateAttestationRequest>(&with_extra);
        assert!(result.is_err(), "CreateAttestationRequest must reject unknown fields");
    }

    // Test 6: Fuzz-generated extra fields for deny_unknown_fields testing
    if let Ok(json_str) = std::str::from_utf8(data) {
        if json_str.len() > 5 {
            // Use proper JSON construction to avoid template injection
            let field_name: String = json_str[..json_str.len().min(20)]
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !field_name.is_empty() {
                let mut map = serde_json::Map::new();
                map.insert("officer_id".to_string(), serde_json::Value::String("test".to_string()));
                map.insert(format!("fuzz_{}", field_name), serde_json::Value::String("injected".to_string()));
                let injected = serde_json::to_string(&map).unwrap();
                let result = serde_json::from_str::<ChallengeRequest>(&injected);
                assert!(result.is_err(), "ChallengeRequest must reject fuzz-injected fields");
            }
        }
    }

    // Test 7: Oversize input testing (1MB+ payloads)
    if data.len() >= 8 {
        let repeat_count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let repeat_count = repeat_count.min(1_100_000).max(1_048_576);
        let oversize_payload = "A".repeat(repeat_count);
        let oversize_json = format!(r#"{{"officer_id":"{}"}}"#, oversize_payload);
        let result = serde_json::from_str::<ChallengeRequest>(&oversize_json);
        // Should either fail or succeed gracefully (no panic, no OOM crash)
        let _ = result;

        let oversize_raw = vec![b'a'; repeat_count];
        let _ = serde_json::from_slice::<ChallengeRequest>(&oversize_raw);
        let _ = serde_json::from_slice::<Authorizer>(&oversize_raw);
    }

    // Test 8: Roundtrip serialization of valid types
    if let Ok(challenge) = serde_json::from_slice::<ChallengeRequest>(data) {
        if let Ok(json) = serde_json::to_string(&challenge) {
            let _ = serde_json::from_str::<ChallengeRequest>(&json);
        }
    }

    if let Ok(authorizer) = serde_json::from_slice::<Authorizer>(data) {
        if let Ok(json) = serde_json::to_string(&authorizer) {
            let _ = serde_json::from_str::<Authorizer>(&json);
        }
    }

    if let Ok(header) = serde_json::from_slice::<SignedCredentialHeader>(data) {
        if let Ok(json) = serde_json::to_string(&header) {
            let _ = serde_json::from_str::<SignedCredentialHeader>(&json);
        }
    }

    // Test 9: Malformed JSON patterns
    let malformed_patterns = vec![
        br#"{"keys":null}"#.as_slice(),
        br#"{"keys":{}}"#,
        br#"{"keys":"not an array"}"#,
        br#"{"actor":null}"#,
        br#"{"actor":123}"#,
        br#"{{{{{}}"#,
        br#"[[[[[}"#,
        br#"}"#,
        br#"]"#,
        b"",
    ];

    for pattern in malformed_patterns {
        let _ = serde_json::from_slice::<ChallengeRequest>(pattern);
        let _ = serde_json::from_slice::<Authorizer>(pattern);
        let _ = serde_json::from_slice::<BlindIssuanceRequest>(pattern);
        let _ = serde_json::from_slice::<CreateAttestationRequest>(pattern);
    }

    // Test 10: Number edge cases in timestamp fields
    let number_tests = vec![
        r#"{"format":"client","keyId":"k","timestamp":0,"hmac":"a","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#,
        r#"{"format":"client","keyId":"k","timestamp":18446744073709551615,"hmac":"a","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#,
        r#"{"format":"client","keyId":"k","timestamp":-1,"hmac":"a","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#,
        r#"{"format":"client","keyId":"k","timestamp":1.5,"hmac":"a","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#,
    ];

    for test in number_tests {
        let _ = serde_json::from_str::<Authorizer>(test);
    }

    // Test 11: Deeply nested structures (JSON parsing DoS depth-limit testing)
    if data.len() > 5 {
        let depth = (data[0] as usize).min(50);
        let open = "{\"a\":".repeat(depth);
        let close = "}".repeat(depth);
        let nested = format!("{}\"leaf\"{}", open, close);
        let _ = serde_json::from_str::<ChallengeRequest>(&nested);

        // Also test extreme nesting depths (128+) to probe stack overflow limits
        let extreme_depth = ((data[0] as usize) << 2).min(512);
        let open_extreme = "[".repeat(extreme_depth);
        let close_extreme = "]".repeat(extreme_depth);
        let nested_arrays = format!("{}1{}", open_extreme, close_extreme);
        let _ = serde_json::from_str::<ChallengeRequest>(&nested_arrays);

        // Nested objects with fuzz-derived keys
        if data.len() > 6 {
            let obj_depth = (data[1] as usize).min(128);
            let open_obj = "{\"x\":".repeat(obj_depth);
            let close_obj = "}".repeat(obj_depth);
            let nested_obj = format!("{}null{}", open_obj, close_obj);
            let _ = serde_json::from_str::<Authorizer>(&nested_obj);
        }
    }

    // Test 12: Truncated JSON
    if let Ok(utf8_str) = std::str::from_utf8(data) {
        for i in 0..utf8_str.len().min(50) {
            if !utf8_str.is_char_boundary(i) {
                continue;
            }
            let truncated = &utf8_str[..i];
            let _ = serde_json::from_str::<ChallengeRequest>(truncated);
            let _ = serde_json::from_str::<Authorizer>(truncated);
        }
    }

    // Test 13: Null/missing fields with fuzz-derived field names
    // (Static null checks moved to unit tests; fuzz targets should exercise variable input)
    if let Ok(s) = std::str::from_utf8(data) {
        let field_name: String = s.chars()
            .take(16)
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        if !field_name.is_empty() {
            let null_json = format!(r#"{{"{}"  :null}}"#, field_name);
            let _ = serde_json::from_str::<ChallengeRequest>(&null_json);
            let _ = serde_json::from_str::<Authorizer>(&null_json);
            let _ = serde_json::from_str::<CreateAttestationRequest>(&null_json);
        }
    }

    // Test 14: SignedCredentialHeader with base64 data
    if data.len() >= 32 {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let b64_data = URL_SAFE_NO_PAD.encode(&data[..32]);

        let credential_json = format!(
            r#"{{"v":2,"kid":"test","issuer_vk":"{}","sig_rj":"{}","c_bytes":"{}","iat":1000,"exp":2000,"schema":"provii.id/v1"}}"#,
            b64_data,
            URL_SAFE_NO_PAD.encode(&[0u8; 64]),
            b64_data
        );
        let _ = serde_json::from_str::<SignedCredentialHeader>(&credential_json);
    }
});
