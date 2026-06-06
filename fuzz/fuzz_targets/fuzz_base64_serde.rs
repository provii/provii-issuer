// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

#![no_main]

use libfuzzer_sys::fuzz_target;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

// TODO: The production base64_bytes and base64_bytes_64 modules in types.rs are
// mod (private). They cannot be imported directly from the fuzz target. This local
// copy must be kept in sync with src/types.rs manually. If the production modules
// are made pub(crate) or re-exported, replace this with a direct import.

// Local copy of production serde helpers (src/types.rs base64_bytes, base64_bytes_64)
#[derive(Serialize, Deserialize, Debug)]
struct Test32 {
    #[serde(with = "base64_bytes")]
    data: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
struct Test64 {
    #[serde(with = "base64_bytes_64")]
    data: [u8; 64],
}

mod base64_bytes {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        encoded.serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

mod base64_bytes_64 {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        encoded.serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

fuzz_target!(|data: &[u8]| {
    // Test 1: Direct base64url encoding/decoding
    if data.len() >= 32 {
        let test_data = &data[..32];
        let encoded = URL_SAFE_NO_PAD.encode(test_data);

        // Verify no padding
        assert!(!encoded.contains('='), "URL_SAFE_NO_PAD must not include padding");

        // Verify URL-safe alphabet
        for ch in encoded.chars() {
            assert!(
                ch.is_alphanumeric() || ch == '-' || ch == '_',
                "Invalid URL-safe character: {}",
                ch
            );
        }

        // Test roundtrip
        if let Ok(decoded) = URL_SAFE_NO_PAD.decode(&encoded) {
            assert_eq!(decoded, test_data, "Base64url roundtrip must be lossless");
        }
    }

    // Test 2: Serialize/deserialize 32-byte arrays
    if data.len() >= 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data[..32]);

        let test = Test32 { data: arr };
        if let Ok(json) = serde_json::to_string(&test) {
            // Verify JSON contains base64url-encoded data
            assert!(json.contains("data"));

            // Test deserialization
            if let Ok(decoded) = serde_json::from_str::<Test32>(&json) {
                assert_eq!(decoded.data, arr, "Serialization roundtrip must be lossless");
            }
        }
    }

    // Test 3: Serialize/deserialize 64-byte arrays
    if data.len() >= 64 {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&data[..64]);

        let test = Test64 { data: arr };
        if let Ok(json) = serde_json::to_string(&test) {
            assert!(json.contains("data"));

            if let Ok(decoded) = serde_json::from_str::<Test64>(&json) {
                assert_eq!(decoded.data, arr, "Serialization roundtrip must be lossless");
            }
        }
    }

    // Test 4: Invalid base64url strings
    if let Ok(invalid_str) = std::str::from_utf8(data) {
        // Try to decode potentially invalid base64url
        let _ = URL_SAFE_NO_PAD.decode(invalid_str);

        // Try to deserialize as Test32
        let json = format!(r#"{{"data":"{}"}}"#, invalid_str);
        let _ = serde_json::from_str::<Test32>(&json);
    }

    // Test 5: Wrong-length base64url strings
    if data.len() >= 16 {
        let short_data = &data[..16];
        let encoded = URL_SAFE_NO_PAD.encode(short_data);

        // This should fail for Test32 (expects 32 bytes)
        let json = format!(r#"{{"data":"{}"}}"#, encoded);
        let result = serde_json::from_str::<Test32>(&json);
        assert!(result.is_err(), "Wrong-length data should be rejected");
    }

    // Test 6: Base64url with padding (should fail)
    let padded_tests = vec!["AAAA==", "AAAA=", "AA==", "A==="];
    for padded in padded_tests {
        let result = URL_SAFE_NO_PAD.decode(padded);
        assert!(result.is_err(), "Padding should be rejected by NO_PAD variant");
    }

    // Test 7: Standard base64 characters (should fail for URL_SAFE)
    let standard_chars = vec!["AAAA+BBB", "AAAA/BBB", "AAAA+/=="];
    for chars in standard_chars {
        let result = URL_SAFE_NO_PAD.decode(chars);
        assert!(result.is_err(), "Standard base64 characters should be rejected");
    }

    // Test 8: All-zeros arrays
    let zeros_32 = Test32 { data: [0u8; 32] };
    if let Ok(json) = serde_json::to_string(&zeros_32) {
        if let Ok(decoded) = serde_json::from_str::<Test32>(&json) {
            assert_eq!(decoded.data, [0u8; 32]);
        }
    }

    let zeros_64 = Test64 { data: [0u8; 64] };
    if let Ok(json) = serde_json::to_string(&zeros_64) {
        if let Ok(decoded) = serde_json::from_str::<Test64>(&json) {
            assert_eq!(decoded.data, [0u8; 64]);
        }
    }

    // Test 9: All-ones arrays
    let ones_32 = Test32 { data: [0xFFu8; 32] };
    if let Ok(json) = serde_json::to_string(&ones_32) {
        if let Ok(decoded) = serde_json::from_str::<Test32>(&json) {
            assert_eq!(decoded.data, [0xFFu8; 32]);
        }
    }

    // Test 10: Mixed valid/invalid base64url
    if data.len() >= 64 {
        let half = data.len() / 2;
        let valid_b64 = URL_SAFE_NO_PAD.encode(&data[..half]);
        let invalid_part = String::from_utf8_lossy(&data[half..]);
        let mixed = format!("{}{}", valid_b64, invalid_part);

        let _ = URL_SAFE_NO_PAD.decode(&mixed);
    }

    // Test 11: Empty strings
    let result = URL_SAFE_NO_PAD.decode("");
    assert!(result.is_ok(), "Empty string should decode to empty bytes");
    assert_eq!(result.unwrap().len(), 0);

    // Test 12: Single-character base64url
    let single_chars = vec!["A", "B", "Z", "0", "9", "-", "_"];
    for ch in single_chars {
        let _ = URL_SAFE_NO_PAD.decode(ch);
    }

    // Test 13: Base64url determinism
    if data.len() >= 32 {
        let test_data = &data[..32];
        let encoded1 = URL_SAFE_NO_PAD.encode(test_data);
        let encoded2 = URL_SAFE_NO_PAD.encode(test_data);
        assert_eq!(encoded1, encoded2, "Encoding must be deterministic");
    }

    // Test 14: JSON with extra fields (should be ignored)
    if data.len() >= 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data[..32]);
        let encoded = URL_SAFE_NO_PAD.encode(&arr);

        let json_with_extra = format!(
            r#"{{"data":"{}","extra_field":"ignored","another":123}}"#,
            encoded
        );
        if let Ok(decoded) = serde_json::from_str::<Test32>(&json_with_extra) {
            assert_eq!(decoded.data, arr);
        }
    }

    // Test 15: Null bytes in base64url
    let with_null = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                         16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
    let encoded = URL_SAFE_NO_PAD.encode(&with_null);
    if let Ok(decoded) = URL_SAFE_NO_PAD.decode(&encoded) {
        assert_eq!(decoded, with_null);
    }

    // Test 16: Control characters in base64url (should fail)
    let with_control = "AAAA\nBBBB";
    let result = URL_SAFE_NO_PAD.decode(with_control);
    assert!(result.is_err(), "Control characters should be rejected");

    // Test 17: Unicode in base64url (should fail)
    let with_unicode = "AAAA🔐BBBB";
    let result = URL_SAFE_NO_PAD.decode(with_unicode);
    assert!(result.is_err(), "Unicode should be rejected");

    // Test 18: Case sensitivity
    if data.len() >= 32 {
        let lowercase = "abcdefghijklmnopqrstuvwxyzabcdef".as_bytes();
        let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF".as_bytes();

        let enc_lower = URL_SAFE_NO_PAD.encode(lowercase);
        let enc_upper = URL_SAFE_NO_PAD.encode(uppercase);

        // Encodings should be different
        assert_ne!(enc_lower, enc_upper, "Base64 is case-sensitive");
    }

    // Test 19: Whitespace handling (should fail)
    let with_spaces = "AAAA BBBB";
    let result = URL_SAFE_NO_PAD.decode(with_spaces);
    assert!(result.is_err(), "Whitespace should be rejected");

    // Test 20: Very long base64url strings
    if data.len() >= 1024 {
        let encoded = URL_SAFE_NO_PAD.encode(&data[..1024]);
        if let Ok(decoded) = URL_SAFE_NO_PAD.decode(&encoded) {
            assert_eq!(decoded.len(), 1024);
            assert_eq!(decoded, &data[..1024]);
        }
    }
});
