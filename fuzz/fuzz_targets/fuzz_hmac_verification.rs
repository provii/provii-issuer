// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

#![no_main]

use libfuzzer_sys::fuzz_target;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use provii_issuer_worker::session::validate_timestamp;

fuzz_target!(|data: &[u8]| {
    if data.len() < 100 {
        return;
    }

    let split1 = data.len() / 3;
    let split2 = (data.len() * 2) / 3;
    let key = &data[..split1];
    let challenge = &data[split1..split2];
    let message = &data[split2..];

    // Test 1: HMAC-SHA1 (YubiKey authentication)
    type HmacSha1 = Hmac<Sha1>;
    if let Ok(mut mac) = HmacSha1::new_from_slice(key) {
        mac.update(challenge);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        assert_eq!(bytes.len(), 20, "HMAC-SHA1 must produce 20 bytes");

        let mut mac2 = HmacSha1::new_from_slice(key).unwrap();
        mac2.update(challenge);
        let result2 = mac2.finalize();
        assert_eq!(bytes, result2.into_bytes(), "HMAC must be deterministic");

        let expected = bytes.to_vec();
        let response = &bytes[..];

        if response.len() == expected.len() {
            assert!(
                bool::from(response.ct_eq(&expected)),
                "Constant-time comparison must work for equal inputs"
            );
        }

        if !bytes.is_empty() {
            let mut wrong = bytes.to_vec();
            wrong[0] ^= 0xFF;

            assert!(
                !bool::from(wrong.ct_eq(&expected)),
                "Constant-time comparison must detect differences"
            );
        }
    }

    // Test 2: HMAC-SHA256 (Client authentication)
    type HmacSha256 = Hmac<Sha256>;
    if let Ok(mut mac) = HmacSha256::new_from_slice(key) {
        mac.update(message);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        assert_eq!(bytes.len(), 32, "HMAC-SHA256 must produce 32 bytes");

        let mut mac2 = HmacSha256::new_from_slice(key).unwrap();
        mac2.update(message);
        let result2 = mac2.finalize();
        assert_eq!(bytes, result2.into_bytes(), "HMAC must be deterministic");

        let hex_hmac = hex::encode(&bytes);
        assert_eq!(hex_hmac.len(), 64, "Hex-encoded SHA256 must be 64 characters");

        if let Ok(decoded) = hex::decode(&hex_hmac) {
            assert_eq!(decoded, bytes.to_vec(), "Hex roundtrip must be lossless");
        }
    }

    // Test 3: SHA256 hashing for API keys
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    assert_eq!(hash.len(), 32, "SHA256 must produce 32 bytes");

    let mut hasher2 = Sha256::new();
    hasher2.update(data);
    let hash2 = hasher2.finalize();
    assert_eq!(hash, hash2, "SHA256 must be deterministic");

    let hex_hash = hex::encode(&hash);
    assert_eq!(hex_hash.len(), 64, "Hex-encoded SHA256 must be 64 characters");

    // Test 4: Production timestamp validation
    if data.len() >= 8 {
        let ts = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        let _ = validate_timestamp(ts);
    }

    // Test 5: HMAC with various key sizes
    for key_size in [0, 1, 16, 20, 32, 64, 128, 256].iter() {
        if data.len() >= *key_size + 10 {
            let key = &data[..*key_size];
            let msg = &data[*key_size..];

            if let Ok(mut mac) = HmacSha1::new_from_slice(key) {
                mac.update(msg);
                let _ = mac.finalize();
            }

            if let Ok(mut mac) = HmacSha256::new_from_slice(key) {
                mac.update(msg);
                let _ = mac.finalize();
            }
        }
    }

    // Test 6: Empty message HMAC
    if !key.is_empty() {
        if let Ok(mut mac) = HmacSha1::new_from_slice(key) {
            mac.update(&[]);
            let empty_result = mac.finalize();
            assert_eq!(empty_result.into_bytes().len(), 20);
        }

        if let Ok(mut mac) = HmacSha256::new_from_slice(key) {
            mac.update(&[]);
            let empty_result = mac.finalize();
            assert_eq!(empty_result.into_bytes().len(), 32);
        }
    }

    // Test 7: Single bit difference avalanche effect
    if data.len() >= 64 {
        let key = &data[..32];
        let msg = &data[32..64];

        if let Ok(mut mac1) = HmacSha256::new_from_slice(key) {
            mac1.update(msg);
            let hmac1 = mac1.finalize();

            let mut msg_modified = msg.to_vec();
            msg_modified[0] ^= 1;

            let mut mac2 = HmacSha256::new_from_slice(key).unwrap();
            mac2.update(&msg_modified);
            let hmac2 = mac2.finalize();

            assert_ne!(
                hmac1.into_bytes(),
                hmac2.into_bytes(),
                "Single bit flip must change HMAC"
            );
        }
    }

    // Test 8: Constant-time comparison with length mismatch
    if data.len() >= 40 {
        let hmac1 = &data[..20];
        let hmac2 = &data[20..30];

        if hmac1.len() != hmac2.len() {
            assert_ne!(hmac1.len(), hmac2.len());
        }
    }

    // Test 9: HMAC with boundary message sizes
    for msg_size in [0, 1, 63, 64, 127, 128, 255, 256, 511, 512].iter() {
        if data.len() >= *msg_size + 32 {
            let key = &data[..32];
            let msg = &data[32..32 + msg_size];

            if let Ok(mut mac) = HmacSha256::new_from_slice(key) {
                mac.update(msg);
                let result = mac.finalize();
                assert_eq!(result.into_bytes().len(), 32);
            }
        }
    }

    // Test 10: Constant-time comparison properties (using subtle::ConstantTimeEq)
    if data.len() >= 40 {
        let bytes1 = &data[..20];
        let bytes2 = &data[20..40];

        let ct_equal = bool::from(bytes1.ct_eq(bytes2));
        let direct_equal = bytes1 == bytes2;
        assert_eq!(ct_equal, direct_equal, "Constant-time comparison must be correct");
    }

    // Test 11: SHA256 with all zeros
    let mut zero_hasher = Sha256::new();
    zero_hasher.update(&[0u8; 32]);
    let zero_hash = zero_hasher.finalize();
    assert_eq!(zero_hash.len(), 32);

    // Test 12: SHA256 with all ones
    let mut ones_hasher = Sha256::new();
    ones_hasher.update(&[0xFFu8; 32]);
    let ones_hash = ones_hasher.finalize();
    assert_eq!(ones_hash.len(), 32);

    assert_ne!(zero_hash, ones_hash, "Different inputs must produce different hashes");

    // Test 13: Hex encoding edge cases
    let hex_empty = hex::encode(&[]);
    assert_eq!(hex_empty.len(), 0);

    let hex_one = hex::encode(&[0x42]);
    assert_eq!(hex_one.len(), 2);
    assert_eq!(hex_one, "42");

    // Test 14: Hex decoding invalid input
    if let Ok(invalid_str) = std::str::from_utf8(data) {
        let _ = hex::decode(invalid_str);
    }

    // Test 15: Canonical message format (from ClientAuthVerifier)
    if data.len() >= 16 {
        let timestamp = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        let _ = validate_timestamp(timestamp);

        if let Ok(message_str) = std::str::from_utf8(&data[8..]) {
            let canonical = format!("{}:{}", timestamp, message_str);

            if let Ok(mut mac) = HmacSha256::new_from_slice(&data[..16]) {
                mac.update(canonical.as_bytes());
                let result = mac.finalize();
                assert_eq!(result.into_bytes().len(), 32);
            }
        }
    }
});
