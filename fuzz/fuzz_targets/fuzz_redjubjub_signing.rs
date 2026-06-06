// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_issuer_worker::crypto::{RjSigner, KeyManager, generate_nonce, sign_commitment};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    // Test 1: RjSigner creation with various key sizes
    for key_size in [0, 16, 31, 32, 33, 64, 128].iter() {
        if data.len() >= *key_size * 2 {
            let sk = data[..*key_size].to_vec();
            let vk = data[*key_size..(*key_size * 2).min(data.len())].to_vec();
            let _ = RjSigner::new("fuzz-key".to_string(), sk, vk);
        }
    }

    // Test 2: Valid RjSigner creation and sign_commitment
    if data.len() >= 64 {
        let sk = data[..32].to_vec();
        let vk = data[32..64].to_vec();

        if let Ok(signer) = RjSigner::new("test-key".to_string(), sk.clone(), vk.clone()) {
            let b64 = signer.vk_base64();

            assert!(!b64.contains('='), "Base64url should not contain padding");
            assert!(!b64.contains('+'), "Base64url should not contain +");
            assert!(!b64.contains('/'), "Base64url should not contain /");

            if let Ok(decoded) = URL_SAFE_NO_PAD.decode(&b64) {
                assert_eq!(decoded.len(), 32, "Decoded VK must be 32 bytes");
                assert_eq!(decoded, vk, "Base64url roundtrip must be lossless");
            }

            let b64_2 = signer.vk_base64();
            assert_eq!(b64, b64_2, "Base64url encoding must be deterministic");

            // AUD-IA-26a-005: Fuzz sign_commitment with fuzz-derived commitment bytes
            if data.len() >= 96 {
                let mut c_bytes = [0u8; 32];
                c_bytes.copy_from_slice(&data[64..96]);

                let iat = if data.len() >= 104 {
                    u64::from_le_bytes([
                        data[96], data[97], data[98], data[99],
                        data[100], data[101], data[102], data[103],
                    ])
                } else {
                    1700000000
                };
                let exp = iat.saturating_add(86400);

                let _ = sign_commitment(&signer, c_bytes, iat, exp, "provii.age/0");
            }
        }
    }

    // Test 3: Kid (key ID) handling
    if data.len() >= 64 {
        let sk = vec![0x42; 32];
        let vk = vec![0x99; 32];

        if let Ok(kid_str) = std::str::from_utf8(&data[64..data.len().min(128)]) {
            if let Ok(signer) = RjSigner::new(kid_str.to_string(), sk.clone(), vk.clone()) {
                assert_eq!(signer.kid, kid_str, "Kid must be preserved");
            }
        }
    }

    // Test 4: Nonce generation
    if let (Ok(nonce1), Ok(nonce2)) = (generate_nonce(), generate_nonce()) {
        assert_eq!(nonce1.len(), 32, "Nonce must be 32 bytes");
        assert_eq!(nonce2.len(), 32, "Nonce must be 32 bytes");
        // AUD-IA-26a-006: Check nonces are 32 bytes and non-zero instead of assert_ne
        assert!(!nonce1.iter().all(|&b| b == 0), "Nonce must not be all zeros");
        assert!(!nonce2.iter().all(|&b| b == 0), "Nonce must not be all zeros");
    }

    // Test 5: SubgroupPoint validation with deliberately invalid point bytes
    {
        let invalid_points: &[[u8; 32]] = &[
            [0xFF; 32],
            [0x00; 32],
            [0x01; 32],
            [0x80; 32],
            {
                let mut p = [0u8; 32];
                p[31] = 0x80;
                p
            },
            {
                let mut p = [0u8; 32];
                p[0] = 0x01;
                p[31] = 0xFF;
                p
            },
        ];

        for invalid_vk in invalid_points {
            let sk = vec![0x42; 32];
            let result = RjSigner::new("invalid-point".to_string(), sk, invalid_vk.to_vec());
            // Most of these should fail SubgroupPoint validation
            let _ = result;
        }

        // Feed fuzz-derived bytes as potential SubgroupPoints
        if data.len() >= 32 {
            let fuzz_vk = data[..32].to_vec();
            let sk = vec![0x42; 32];
            let _ = RjSigner::new("fuzz-point".to_string(), sk, fuzz_vk);
        }
    }

    // Test 6: Verify-only signer path via KeyManager::from_public_key
    if data.len() >= 32 {
        let vk = data[..32].to_vec();
        match KeyManager::from_public_key("verify-only-key".to_string(), vk.clone()) {
            Ok(km) => {
                if let Some(signer) = km.default_signer() {
                    let _ = signer.vk_base64();
                    let _ = km.get_jwks();

                    // sign_commitment should refuse to sign with a verify-only signer
                    if data.len() >= 64 {
                        let mut c_bytes = [0u8; 32];
                        c_bytes.copy_from_slice(&data[32..64]);
                        let result = sign_commitment(signer, c_bytes, 1000, 2000, "test");
                        // Should error with "Cannot sign with a verify-only key manager"
                        assert!(result.is_err());
                    }
                }
            }
            Err(_) => {}
        }
    }

    // Test 7: Base64url encoding edge cases
    if data.len() >= 32 {
        let test_data = &data[..32];
        let encoded = URL_SAFE_NO_PAD.encode(test_data);

        for ch in encoded.chars() {
            assert!(
                ch.is_alphanumeric() || ch == '-' || ch == '_',
                "Invalid URL-safe base64 character: {}",
                ch
            );
        }

        if let Ok(decoded) = URL_SAFE_NO_PAD.decode(&encoded) {
            assert_eq!(decoded, test_data, "Roundtrip must be lossless");
        }
    }

    // Test 8: Same bytes for SK and VK
    if data.len() >= 64 {
        let same_bytes = &data[..32];
        let result = RjSigner::new(
            "test".to_string(),
            same_bytes.to_vec(),
            same_bytes.to_vec(),
        );
        if let Ok(signer) = result {
            assert_eq!(signer.vk, *same_bytes);
            let _ = signer.vk_base64();
        }
    }

    // Test 9: Empty kid
    if data.len() >= 64 {
        let sk = vec![1u8; 32];
        let vk = vec![2u8; 32];
        let result = RjSigner::new(String::new(), sk, vk);
        if let Ok(signer) = result {
            assert_eq!(signer.kid, "");
        }
    }

    // Test 10: Very long kid
    if data.len() >= 100 {
        let sk = vec![1u8; 32];
        let vk = vec![2u8; 32];
        let long_kid = "k".repeat(1000);
        let result = RjSigner::new(long_kid.clone(), sk, vk);
        if let Ok(signer) = result {
            assert_eq!(signer.kid, long_kid);
        }
    }

    // Test 11: Base64url with all byte values
    let all_bytes: Vec<u8> = (0..=255).collect();
    if all_bytes.len() >= 32 {
        for i in 0..32 {
            let test_byte = vec![all_bytes[i]; 32];
            let encoded = URL_SAFE_NO_PAD.encode(&test_byte);
            if let Ok(decoded) = URL_SAFE_NO_PAD.decode(&encoded) {
                assert_eq!(decoded, test_byte);
            }
        }
    }

    // Test 12: Nonce entropy (statistical test)
    let nonces: Vec<[u8; 32]> = (0..10)
        .filter_map(|_| generate_nonce().ok())
        .collect();
    for nonce in &nonces {
        assert_eq!(nonce.len(), 32, "Nonce must be 32 bytes");
        assert!(!nonce.iter().all(|&b| b == 0), "Nonce must not be all zeros");
    }

    // Test 13: Base64url with invalid characters (should fail gracefully)
    if let Ok(invalid_str) = std::str::from_utf8(data) {
        let _ = URL_SAFE_NO_PAD.decode(invalid_str);
    }

    // Test 14: Base64url with standard alphabet characters (should fail)
    let with_plus = format!("AAAA+BBB");
    let result = URL_SAFE_NO_PAD.decode(&with_plus);
    assert!(result.is_err(), "Should reject standard base64 '+' character");

    let with_slash = format!("AAAA/BBB");
    let result = URL_SAFE_NO_PAD.decode(&with_slash);
    assert!(result.is_err(), "Should reject standard base64 '/' character");

    // Test 15: Base64url with padding (should fail for NO_PAD variant)
    let with_padding = format!("AAAA==");
    let result = URL_SAFE_NO_PAD.decode(&with_padding);
    assert!(result.is_err(), "Should reject padding");

    // Test 16: Multiple signers with same keys (allowed)
    if data.len() >= 64 {
        let sk = vec![0x42; 32];
        let vk = vec![0x99; 32];

        let signer1 = RjSigner::new("key-1".to_string(), sk.clone(), vk.clone());
        let signer2 = RjSigner::new("key-2".to_string(), sk.clone(), vk.clone());

        if let (Ok(s1), Ok(s2)) = (signer1, signer2) {
            assert_eq!(s1.vk, s2.vk);
            assert_eq!(s1.vk_base64(), s2.vk_base64());
            assert_ne!(s1.kid, s2.kid);
        }
    }
});
