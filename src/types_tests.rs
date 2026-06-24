// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Unit and property tests for `types.rs`. Relocated verbatim from the
//! inline `#[cfg(test)] mod tests` module; wired back in via
//! `#[path = "types_tests.rs"] mod tests;` so the production type surface
//! in `types.rs` stays byte-unchanged.

use super::*;

/* ========================================================================== */
/*                    ROLE ENUM TESTS                                        */
/* ========================================================================== */

#[test]
fn test_role_serialize_admin() -> Result<(), Box<dyn std::error::Error>> {
    let role = Role::Admin;
    let json = serde_json::to_string(&role)?;
    assert_eq!(json, r#""admin""#);
    Ok(())
}

#[test]
fn test_role_serialize_issuer() -> Result<(), Box<dyn std::error::Error>> {
    let role = Role::Issuer;
    let json = serde_json::to_string(&role)?;
    assert_eq!(json, r#""issuer""#);
    Ok(())
}

#[test]
fn test_role_serialize_viewer() -> Result<(), Box<dyn std::error::Error>> {
    let role = Role::Viewer;
    let json = serde_json::to_string(&role)?;
    assert_eq!(json, r#""viewer""#);
    Ok(())
}

#[test]
fn test_role_deserialize_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    for (json_str, expected) in [
        (r#""admin""#, Role::Admin),
        (r#""issuer""#, Role::Issuer),
        (r#""viewer""#, Role::Viewer),
    ] {
        let decoded: Role = serde_json::from_str(json_str)?;
        assert_eq!(decoded, expected);
    }
    Ok(())
}

#[test]
fn test_role_default_is_issuer() {
    assert_eq!(Role::default(), Role::Issuer);
}

/* ========================================================================== */
/*                    KEYSTATUS ENUM TESTS                                   */
/* ========================================================================== */

#[test]
fn test_key_status_serialize_all_variants() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(serde_json::to_string(&KeyStatus::Active)?, r#""active""#);
    assert_eq!(
        serde_json::to_string(&KeyStatus::Deprecated)?,
        r#""deprecated""#
    );
    assert_eq!(serde_json::to_string(&KeyStatus::Revoked)?, r#""revoked""#);
    assert_eq!(
        serde_json::to_string(&KeyStatus::Disabled)?,
        r#""disabled""#
    );
    Ok(())
}

#[test]
fn test_key_status_deserialize_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    for status in [
        KeyStatus::Active,
        KeyStatus::Deprecated,
        KeyStatus::Revoked,
        KeyStatus::Disabled,
    ] {
        let json = serde_json::to_string(&status)?;
        let decoded: KeyStatus = serde_json::from_str(&json)?;
        assert_eq!(decoded, status);
    }
    Ok(())
}

#[test]
fn test_key_status_default_is_active() {
    assert_eq!(KeyStatus::default(), KeyStatus::Active);
}

/* ========================================================================== */
/*                    HASHED NEWTYPE TESTS                                   */
/* ========================================================================== */

#[test]
fn test_hashed_ip_new_and_as_str() {
    let hex = "a".repeat(64);
    let hashed = HashedIp::new(hex.clone());
    assert_eq!(hashed.as_str(), hex.as_str());
}

#[test]
fn test_hashed_ip_as_ref() {
    let hex = "b".repeat(64);
    let hashed = HashedIp::new(hex.clone());
    let r: &str = hashed.as_ref();
    assert_eq!(r, hex.as_str());
}

#[test]
fn test_hashed_ip_serialize_deserialize() -> Result<(), Box<dyn std::error::Error>> {
    let hex = "c".repeat(64);
    let hashed = HashedIp::new(hex.clone());
    let json = serde_json::to_string(&hashed)?;
    let decoded: HashedIp = serde_json::from_str(&json)?;
    assert_eq!(decoded, hashed);
    Ok(())
}

#[test]
fn test_hashed_user_agent_new_and_as_str() {
    let hex = "d".repeat(64);
    let hashed = HashedUserAgent::new(hex.clone());
    assert_eq!(hashed.as_str(), hex.as_str());
}

#[test]
fn test_hashed_user_agent_serialize_deserialize() -> Result<(), Box<dyn std::error::Error>> {
    let hex = "e".repeat(64);
    let hashed = HashedUserAgent::new(hex.clone());
    let json = serde_json::to_string(&hashed)?;
    let decoded: HashedUserAgent = serde_json::from_str(&json)?;
    assert_eq!(decoded, hashed);
    Ok(())
}

/* ========================================================================== */
/*                    DEBUG REDACTION TESTS                                  */
/* ========================================================================== */

#[test]
fn test_signing_keypair_debug_redacts_sk() {
    let kp = SigningKeypair {
        kid: "test-kid".to_string(),
        sk: "super-secret-key-material".to_string(),
        vk: "public-vk".to_string(),
        encrypted: false,
        status: KeyStatus::Active,
        created_at: 1000,
        deprecated_at: None,
        revoked_at: None,
    };
    let debug = format!("{:?}", kp);
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("super-secret-key-material"));
    assert!(debug.contains("test-kid"));
}

#[test]
fn test_stored_challenge_debug_redacts_challenge() {
    let ch = StoredChallenge {
        challenge_id: "ch-debug".to_string(),
        officer_id: "off-debug".to_string(),
        challenge: vec![0xDE, 0xAD, 0xBE, 0xEF],
        created_at: 1000,
        expires_at: 2000,
        used: false,
    };
    let debug = format!("{:?}", ch);
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("DEAD"));
    assert!(debug.contains("ch-debug"));
}

#[test]
fn test_officer_registration_debug_redacts_secret() {
    let officer = OfficerRegistration {
        officer_id: "off-redact".to_string(),
        hmac_secret: vec![0x42; 32],
        created_at: 1000,
        last_used: None,
        active: true,
        encrypted: false,
        secret_status: KeyStatus::Active,
        previous_hmac_secret: None,
        role: Role::default(),
    };
    let debug = format!("{:?}", officer);
    assert!(debug.contains("[REDACTED]"));
    assert!(debug.contains("off-redact"));
}

#[test]
fn test_client_registration_debug_redacts_secrets() {
    let client = ClientRegistration {
        client_id: "client-redact".to_string(),
        client_name: "Test".to_string(),
        api_key_hash: b"secret-hash".to_vec(),
        hmac_secret: vec![0x99; 32],
        created_at: 1000,
        last_used: None,
        rate_limit: 100,
        allowed_schemas: vec![],
        max_validity_days: 365,
        active: true,
        encrypted: false,
        secret_status: KeyStatus::Active,
        previous_hmac_secret: None,
        role: Role::default(),
        kv_key: None,
    };
    let debug = format!("{:?}", client);
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("secret-hash"));
    assert!(debug.contains("client-redact"));
}

/* ========================================================================== */
/*                    DROP / ZEROIZE BEHAVIOUR TESTS                         */
/* ========================================================================== */

#[test]
fn test_signing_keypair_drop_impl_exists() {
    // Verify that SigningKeypair implements Drop (zeroize on drop).
    // We cannot use unsafe to inspect memory (crate forbids unsafe_code),
    // so we verify the Drop trait is triggered without panic.
    let kp = SigningKeypair {
        kid: "drop-test".to_string(),
        sk: "AAAA_secret_AAAA".to_string(),
        vk: "public".to_string(),
        encrypted: false,
        status: KeyStatus::Active,
        created_at: 0,
        deprecated_at: None,
        revoked_at: None,
    };
    drop(kp);
    // If Drop impl is broken this would panic or fail to compile.
}

#[test]
fn test_key_status_zeroize_sets_disabled() {
    let mut status = KeyStatus::Active;
    status.zeroize();
    assert_eq!(status, KeyStatus::Disabled);
}

#[test]
fn test_session_status_default_is_pending() {
    assert_eq!(SessionStatus::default(), SessionStatus::Pending);
}

/* ========================================================================== */
/*                    POLICY CONFIG VALIDITY BOUNDS TESTS                    */
/* ========================================================================== */

#[test]
fn test_policy_config_effective_validity_days_clamps_zero() {
    let policy = PolicyConfig {
        validity_days: 0,
        ..Default::default()
    };
    assert_eq!(policy.effective_validity_days(), MIN_POLICY_VALIDITY_DAYS);
}

#[test]
fn test_policy_config_effective_validity_days_clamps_max() {
    let policy = PolicyConfig {
        validity_days: 100_000,
        ..Default::default()
    };
    assert_eq!(policy.effective_validity_days(), MAX_POLICY_VALIDITY_DAYS);
}

#[test]
fn test_policy_config_effective_validity_days_normal() {
    let policy = PolicyConfig {
        validity_days: 365,
        ..Default::default()
    };
    assert_eq!(policy.effective_validity_days(), 365);
}

/* ========================================================================== */
/*                    ACTORTYPE ENUM TESTS                                   */
/* ========================================================================== */

#[test]
fn test_actor_type_officer_serialize() -> Result<(), Box<dyn std::error::Error>> {
    let actor = ActorType::Officer;
    let json = serde_json::to_string(&actor)?;
    assert_eq!(json, r#""officer""#);
    Ok(())
}

#[test]
fn test_actor_type_client_serialize() -> Result<(), Box<dyn std::error::Error>> {
    let actor = ActorType::Client;
    let json = serde_json::to_string(&actor)?;
    assert_eq!(json, r#""client""#);
    Ok(())
}

#[test]
fn test_actor_type_officer_deserialize() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#""officer""#;
    let actor: ActorType = serde_json::from_str(json)?;
    assert_eq!(actor, ActorType::Officer);
    Ok(())
}

#[test]
fn test_actor_type_client_deserialize() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#""client""#;
    let actor: ActorType = serde_json::from_str(json)?;
    assert_eq!(actor, ActorType::Client);
    Ok(())
}

#[test]
fn test_actor_type_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let officer = ActorType::Officer;
    let json = serde_json::to_string(&officer)?;
    let decoded: ActorType = serde_json::from_str(&json)?;
    assert_eq!(decoded, ActorType::Officer);

    let client = ActorType::Client;
    let json = serde_json::to_string(&client)?;
    let decoded: ActorType = serde_json::from_str(&json)?;
    assert_eq!(decoded, ActorType::Client);
    Ok(())
}

#[test]
fn test_actor_type_clone() {
    let actor = ActorType::Officer;
    let cloned = actor.clone();
    assert_eq!(actor, cloned);
}

/* ========================================================================== */
/*                    SESSIONSTATUS ENUM TESTS                               */
/* ========================================================================== */

#[test]
fn test_session_status_pending() -> Result<(), Box<dyn std::error::Error>> {
    let status = SessionStatus::Pending;
    let json = serde_json::to_string(&status)?;
    assert_eq!(json, r#""pending""#);
    Ok(())
}

#[test]
fn test_session_status_authenticated() -> Result<(), Box<dyn std::error::Error>> {
    let status = SessionStatus::Authenticated;
    let json = serde_json::to_string(&status)?;
    assert_eq!(json, r#""authenticated""#);
    Ok(())
}

#[test]
fn test_session_status_completed() -> Result<(), Box<dyn std::error::Error>> {
    let status = SessionStatus::Completed;
    let json = serde_json::to_string(&status)?;
    assert_eq!(json, r#""completed""#);
    Ok(())
}

#[test]
fn test_session_status_expired() -> Result<(), Box<dyn std::error::Error>> {
    let status = SessionStatus::Expired;
    let json = serde_json::to_string(&status)?;
    assert_eq!(json, r#""expired""#);
    Ok(())
}

#[test]
fn test_session_status_deserialize() -> Result<(), Box<dyn std::error::Error>> {
    let pending: SessionStatus = serde_json::from_str(r#""pending""#)?;
    assert_eq!(pending, SessionStatus::Pending);

    let auth: SessionStatus = serde_json::from_str(r#""authenticated""#)?;
    assert_eq!(auth, SessionStatus::Authenticated);

    let done: SessionStatus = serde_json::from_str(r#""completed""#)?;
    assert_eq!(done, SessionStatus::Completed);

    let expired: SessionStatus = serde_json::from_str(r#""expired""#)?;
    assert_eq!(expired, SessionStatus::Expired);
    Ok(())
}

#[test]
fn test_session_status_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    for status in [
        SessionStatus::Pending,
        SessionStatus::Authenticated,
        SessionStatus::Completed,
        SessionStatus::Expired,
    ] {
        let json = serde_json::to_string(&status)?;
        let decoded: SessionStatus = serde_json::from_str(&json)?;
        assert_eq!(status, decoded);
    }
    Ok(())
}

/* ========================================================================== */
/*                    BASE64_BYTES MODULE TESTS                              */
/* ========================================================================== */

#[test]
fn test_base64_bytes_serialize() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Serialize)]
    struct Test {
        #[serde(with = "base64_bytes")]
        data: [u8; 32],
    }
    let test = Test { data: [42u8; 32] };
    let json = serde_json::to_string(&test)?;
    assert!(json.contains("KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio"));
    Ok(())
}

#[test]
fn test_base64_bytes_deserialize() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Deserialize)]
    struct Test {
        #[serde(with = "base64_bytes")]
        data: [u8; 32],
    }
    let json = r#"{"data":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
    let test: Test = serde_json::from_str(json)?;
    assert_eq!(test.data, [0u8; 32]);
    Ok(())
}

#[test]
fn test_base64_bytes_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Serialize, Deserialize)]
    struct Test {
        #[serde(with = "base64_bytes")]
        data: [u8; 32],
    }
    let original = Test { data: [0xAB; 32] };
    let json = serde_json::to_string(&original)?;
    let decoded: Test = serde_json::from_str(&json)?;
    assert_eq!(original.data, decoded.data);
    Ok(())
}

#[test]
fn test_base64_bytes_wrong_length() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Debug, Deserialize)]
    struct Test {
        #[serde(with = "base64_bytes")]
        #[allow(dead_code)]
        data: [u8; 32],
    }
    // 16 bytes encoded (too short)
    let json = r#"{"data":"AAAAAAAAAAAAAAAAAAAAAA"}"#;
    let result = serde_json::from_str::<Test>(json);
    assert!(result.is_err());
    assert!(result
        .err()
        .ok_or("expected error")?
        .to_string()
        .contains("expected 32 bytes"));
    Ok(())
}

#[test]
fn test_base64_bytes_invalid_base64() {
    #[derive(Deserialize)]
    struct Test {
        #[serde(with = "base64_bytes")]
        #[allow(dead_code)]
        data: [u8; 32],
    }
    let json = r#"{"data":"!!!invalid!!!"}"#;
    let result = serde_json::from_str::<Test>(json);
    assert!(result.is_err());
}

#[test]
fn test_base64_bytes_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Serialize, Deserialize)]
    struct Test {
        #[serde(with = "base64_bytes")]
        data: [u8; 32],
    }
    let test = Test { data: [0u8; 32] };
    let json = serde_json::to_string(&test)?;
    let decoded: Test = serde_json::from_str(&json)?;
    assert_eq!(decoded.data, [0u8; 32]);
    Ok(())
}

#[test]
fn test_base64_bytes_all_ones() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Serialize, Deserialize)]
    struct Test {
        #[serde(with = "base64_bytes")]
        data: [u8; 32],
    }
    let test = Test { data: [0xFF; 32] };
    let json = serde_json::to_string(&test)?;
    let decoded: Test = serde_json::from_str(&json)?;
    assert_eq!(decoded.data, [0xFF; 32]);
    Ok(())
}

/* ========================================================================== */
/*                    BASE64_BYTES_64 MODULE TESTS                           */
/* ========================================================================== */

#[test]
fn test_base64_bytes_64_serialize() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Serialize)]
    struct Test {
        #[serde(with = "base64_bytes_64")]
        data: [u8; 64],
    }
    let test = Test { data: [42u8; 64] };
    let json = serde_json::to_string(&test)?;
    assert!(json.contains("data"));
    Ok(())
}

#[test]
fn test_base64_bytes_64_deserialize() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Deserialize)]
    struct Test {
        #[serde(with = "base64_bytes_64")]
        data: [u8; 64],
    }
    // Correct base64url encoding of 64 zero bytes (86 characters, no padding)
    let json = r#"{"data":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
    let test: Test = serde_json::from_str(json)?;
    assert_eq!(test.data, [0u8; 64]);
    Ok(())
}

#[test]
fn test_base64_bytes_64_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Serialize, Deserialize)]
    struct Test {
        #[serde(with = "base64_bytes_64")]
        data: [u8; 64],
    }
    let original = Test { data: [0xCD; 64] };
    let json = serde_json::to_string(&original)?;
    let decoded: Test = serde_json::from_str(&json)?;
    assert_eq!(original.data, decoded.data);
    Ok(())
}

#[test]
fn test_base64_bytes_64_wrong_length() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Debug, Deserialize)]
    struct Test {
        #[serde(with = "base64_bytes_64")]
        #[allow(dead_code)]
        data: [u8; 64],
    }
    // 32 bytes encoded (too short)
    let json = r#"{"data":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
    let result = serde_json::from_str::<Test>(json);
    assert!(result.is_err());
    assert!(result
        .err()
        .ok_or("expected error")?
        .to_string()
        .contains("expected 64 bytes"));
    Ok(())
}

#[test]
fn test_base64_bytes_64_invalid_base64() {
    #[derive(Deserialize)]
    struct Test {
        #[serde(with = "base64_bytes_64")]
        #[allow(dead_code)]
        data: [u8; 64],
    }
    let json = r#"{"data":"!!!invalid!!!"}"#;
    let result = serde_json::from_str::<Test>(json);
    assert!(result.is_err());
}

/* ========================================================================== */
/*                    STRUCT SERIALIZATION TESTS                             */
/* ========================================================================== */

#[test]
fn test_challenge_request_serialize() -> Result<(), Box<dyn std::error::Error>> {
    let req = ChallengeRequest {
        officer_id: "officer-42".to_string(),
    };
    let json = serde_json::to_string(&req)?;
    assert!(json.contains("officer-42"));
    Ok(())
}

#[test]
fn test_challenge_response_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let resp = ChallengeResponse {
        challenge_id: "ch-999".to_string(),
        challenge: "deadbeef".to_string(),
        expires_at: 5000,
    };
    let json = serde_json::to_string(&resp)?;
    let decoded: ChallengeResponse = serde_json::from_str(&json)?;
    assert_eq!(decoded.challenge_id, "ch-999");
    assert_eq!(decoded.challenge, "deadbeef");
    Ok(())
}

#[test]
fn test_authorizer_with_challenge_id() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "yubikey".to_string(),
        key_id: "yk-1".to_string(),
        challenge_id: Some("ch-456".to_string()),
        timestamp: 9999,
        hmac: "hmac-value".to_string(),
        nonce: "b".repeat(64),
    };
    let json = serde_json::to_string(&auth)?;
    assert!(json.contains("ch-456"));
    assert!(json.contains("keyId"));
    Ok(())
}

#[test]
fn test_authorizer_without_challenge_id() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "client-1".to_string(),
        challenge_id: None,
        timestamp: 1111,
        hmac: "abc".to_string(),
        nonce: "c".repeat(64),
    };
    let json = serde_json::to_string(&auth)?;
    // Should not include challenge_id when None
    assert!(!json.contains("challenge_id") || json.contains("null"));
    Ok(())
}

#[test]
fn test_policy_config_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let policy = PolicyConfig {
        schema: "provii.id/age/v1".to_string(),
        validity_days: 730,
        v: 1,
    };
    let json = serde_json::to_string(&policy)?;
    let decoded: PolicyConfig = serde_json::from_str(&json)?;
    assert_eq!(decoded.schema, "provii.id/age/v1");
    assert_eq!(decoded.validity_days, 730);
    assert_eq!(decoded.v, 1);
    Ok(())
}

#[test]
fn test_jwk_set_serialize() -> Result<(), Box<dyn std::error::Error>> {
    let jwk = Jwk {
        kty: "OKP".to_string(),
        crv: "JUBJUB".to_string(),
        kid: "key-1".to_string(),
        use_: "sig".to_string(),
        alg: "RedJubjub".to_string(),
        x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    };
    let jwk_set = JwkSet { keys: vec![jwk] };
    let json = serde_json::to_string(&jwk_set)?;
    assert!(json.contains("OKP"));
    assert!(json.contains("JUBJUB"));
    assert!(json.contains("key-1"));
    Ok(())
}

#[test]
fn test_officer_registration_active() -> Result<(), Box<dyn std::error::Error>> {
    let officer = OfficerRegistration {
        officer_id: "off-1".to_string(),
        hmac_secret: vec![1, 2, 3, 4],
        created_at: 1000,
        last_used: Some(2000),
        active: true,
        encrypted: false,
        secret_status: KeyStatus::Active,
        previous_hmac_secret: None,
        role: crate::types::Role::default(),
    };
    let json = serde_json::to_string(&officer)?;
    let decoded: OfficerRegistration = serde_json::from_str(&json)?;
    assert_eq!(decoded.officer_id, "off-1");
    assert!(decoded.active);
    assert_eq!(decoded.last_used, Some(2000));
    Ok(())
}

#[test]
fn test_client_registration_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let client = ClientRegistration {
        client_id: "client-1".to_string(),
        client_name: "Test Client".to_string(),
        api_key_hash: b"hash123".to_vec(),
        hmac_secret: vec![5, 6, 7, 8],
        created_at: 5000,
        last_used: None,
        rate_limit: 100,
        allowed_schemas: vec!["provii.id/v1".to_string()],
        max_validity_days: 365,
        active: true,
        encrypted: false,
        secret_status: KeyStatus::Active,
        previous_hmac_secret: None,
        role: crate::types::Role::default(),
        kv_key: None,
    };
    let json = serde_json::to_string(&client)?;
    let decoded: ClientRegistration = serde_json::from_str(&json)?;
    assert_eq!(decoded.client_id, "client-1");
    assert_eq!(decoded.client_name, "Test Client");
    assert_eq!(decoded.rate_limit, 100);
    assert!(decoded.last_used.is_none());
    Ok(())
}

#[test]
fn test_issuer_config_serialize() -> Result<(), Box<dyn std::error::Error>> {
    let config = IssuerConfig {
        issuer_id: "did:provii:issuer".to_string(),
        rp_id: "provii.id".to_string(),
        default_kid: "key-default".to_string(),
        previous_kid: None,
        default_policy: PolicyConfig {
            schema: "provii.id/v1".to_string(),
            validity_days: 365,
            v: 1,
        },
    };
    let json = serde_json::to_string(&config)?;
    assert!(json.contains("did:provii:issuer"));
    assert!(json.contains("provii.id"));
    // None previous_kid is skipped on serialise so the wire shape
    // stays stable for steady-state configs that never rotated.
    assert!(!json.contains("previous_kid"));
    Ok(())
}

#[test]
fn test_issuer_config_previous_kid_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let config = IssuerConfig {
        issuer_id: "did:provii:issuer".to_string(),
        rp_id: "provii.id".to_string(),
        default_kid: "v2".to_string(),
        previous_kid: Some("v1".to_string()),
        default_policy: PolicyConfig {
            schema: "provii.id/v1".to_string(),
            validity_days: 365,
            v: 1,
        },
    };
    let json = serde_json::to_string(&config)?;
    assert!(json.contains("\"previous_kid\":\"v1\""));
    let decoded: IssuerConfig = serde_json::from_str(&json)?;
    assert_eq!(decoded.default_kid, "v2");
    assert_eq!(decoded.previous_kid.as_deref(), Some("v1"));
    Ok(())
}

#[test]
fn test_issuer_config_previous_kid_default_none() -> Result<(), Box<dyn std::error::Error>> {
    // Existing on-disk configs without `previous_kid` must decode
    // cleanly. Storage format change rules forbid migrations, so the
    // serde default is the only path for older records.
    let json = r#"{"issuer_id":"did:provii:issuer","rp_id":"provii.id","default_kid":"v1","default_policy":{"schema":"provii.id/v1","validity_days":365,"v":1}}"#;
    let decoded: IssuerConfig = serde_json::from_str(json)?;
    assert_eq!(decoded.previous_kid, None);
    Ok(())
}

#[test]
fn test_issuance_session_with_officer() -> Result<(), Box<dyn std::error::Error>> {
    let session = IssuanceSession {
        session_id: "test-session-id".to_string(),
        created_at: 1000,
        expires_at: 2000,
        actor: ActorType::Officer,
        kid: "key-1".to_string(),
        schema: "provii.id/v1".to_string(),
        iat: 1000,
        exp: 3000,
        signatures_issued: 0,
        status: SessionStatus::Authenticated,
        officer_id: Some("off-1".to_string()),
        client_id: None,
        absolute_expiry: 4600, // 1 hour from creation
        client_ip: None,
        user_agent: None,
    };
    let json = serde_json::to_string(&session)?;
    let decoded: IssuanceSession = serde_json::from_str(&json)?;
    assert_eq!(decoded.actor, ActorType::Officer);
    assert_eq!(decoded.status, SessionStatus::Authenticated);
    assert!(decoded.officer_id.is_some());
    assert!(decoded.client_id.is_none());
    Ok(())
}

#[test]
fn test_stored_challenge_unused() -> Result<(), Box<dyn std::error::Error>> {
    let challenge = StoredChallenge {
        challenge_id: "ch-1".to_string(),
        officer_id: "off-1".to_string(),
        challenge: vec![0xDE, 0xAD, 0xBE, 0xEF],
        created_at: 1000,
        expires_at: 2000,
        used: false,
    };
    let json = serde_json::to_string(&challenge)?;
    let decoded: StoredChallenge = serde_json::from_str(&json)?;
    assert_eq!(decoded.challenge_id, "ch-1");
    assert!(!decoded.used);
    assert_eq!(decoded.challenge, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    Ok(())
}

#[test]
fn test_signed_credential_header_all_fields() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "issuer-key".to_string(),
        issuer_vk: [0x99; 32],
        sig_rj: [0x88; 64],
        c_bytes: [0x77; 32],
        iat: 1700000000,
        exp: 1731536000,
        schema: "provii.id/age/v1".to_string(),
    };
    let json = serde_json::to_string(&header)?;
    let decoded: SignedCredentialHeader = serde_json::from_str(&json)?;

    assert_eq!(decoded.v, 2);
    assert_eq!(decoded.kid, "issuer-key");
    assert_eq!(decoded.issuer_vk, [0x99; 32]);
    assert_eq!(decoded.sig_rj, [0x88; 64]);
    assert_eq!(decoded.c_bytes, [0x77; 32]);
    assert_eq!(decoded.iat, 1700000000);
    assert_eq!(decoded.exp, 1731536000);
    assert_eq!(decoded.schema, "provii.id/age/v1");
    Ok(())
}

#[test]
fn test_issuance_session_with_client() -> Result<(), Box<dyn std::error::Error>> {
    let session = IssuanceSession {
        session_id: "test-session-id".to_string(),
        created_at: 2000,
        expires_at: 3000,
        actor: ActorType::Client,
        kid: "key-2".to_string(),
        schema: "provii.id/v2".to_string(),
        iat: 2000,
        exp: 4000,
        signatures_issued: 0,
        status: SessionStatus::Completed,
        officer_id: None,
        client_id: Some("client-99".to_string()),
        absolute_expiry: 5600, // 1 hour from creation
        client_ip: None,
        user_agent: None,
    };
    let json = serde_json::to_string(&session)?;
    let decoded: IssuanceSession = serde_json::from_str(&json)?;
    assert_eq!(decoded.actor, ActorType::Client);
    assert_eq!(decoded.status, SessionStatus::Completed);
    assert!(decoded.officer_id.is_none());
    assert_eq!(decoded.client_id, Some("client-99".to_string()));
    Ok(())
}

#[test]
fn test_stored_challenge_used() -> Result<(), Box<dyn std::error::Error>> {
    let challenge = StoredChallenge {
        challenge_id: "ch-2".to_string(),
        officer_id: "off-2".to_string(),
        challenge: vec![0x12, 0x34, 0x56, 0x78],
        created_at: 5000,
        expires_at: 6000,
        used: true,
    };
    let json = serde_json::to_string(&challenge)?;
    let decoded: StoredChallenge = serde_json::from_str(&json)?;
    assert_eq!(decoded.challenge_id, "ch-2");
    assert!(decoded.used);
    assert_eq!(decoded.challenge, vec![0x12, 0x34, 0x56, 0x78]);
    Ok(())
}

/* ========================================================================== */
/*                    ROLE PERMISSION METHOD TESTS                           */
/* ========================================================================== */

#[test]
fn test_admin_can_generate_challenge() {
    assert!(Role::Admin.can_generate_challenge());
}

#[test]
fn test_issuer_can_generate_challenge() {
    assert!(Role::Issuer.can_generate_challenge());
}

#[test]
fn test_viewer_cannot_generate_challenge() {
    assert!(!Role::Viewer.can_generate_challenge());
}

#[test]
fn test_admin_can_issue_credential() {
    assert!(Role::Admin.can_issue_credential());
}

#[test]
fn test_issuer_can_issue_credential() {
    assert!(Role::Issuer.can_issue_credential());
}

#[test]
fn test_viewer_cannot_issue_credential() {
    assert!(!Role::Viewer.can_issue_credential());
}

#[test]
fn test_admin_can_sign_commitment() {
    assert!(Role::Admin.can_sign_commitment());
}

#[test]
fn test_viewer_cannot_sign_commitment() {
    assert!(!Role::Viewer.can_sign_commitment());
}

#[test]
fn test_admin_can_view_sessions() {
    assert!(Role::Admin.can_view_sessions());
}

#[test]
fn test_issuer_can_view_sessions() {
    assert!(Role::Issuer.can_view_sessions());
}

#[test]
fn test_viewer_can_view_sessions() {
    assert!(Role::Viewer.can_view_sessions());
}

#[test]
fn test_admin_can_view_audit_logs() {
    assert!(Role::Admin.can_view_audit_logs());
}

#[test]
fn test_viewer_can_view_audit_logs() {
    assert!(Role::Viewer.can_view_audit_logs());
}

#[test]
fn test_admin_can_manage_keys() {
    assert!(Role::Admin.can_manage_keys());
}

#[test]
fn test_issuer_cannot_manage_keys() {
    assert!(!Role::Issuer.can_manage_keys());
}

#[test]
fn test_viewer_cannot_manage_keys() {
    assert!(!Role::Viewer.can_manage_keys());
}

#[test]
fn test_admin_can_manage_users() {
    assert!(Role::Admin.can_manage_users());
}

#[test]
fn test_issuer_cannot_manage_users() {
    assert!(!Role::Issuer.can_manage_users());
}

#[test]
fn test_viewer_cannot_manage_users() {
    assert!(!Role::Viewer.can_manage_users());
}

/* ========================================================================== */
/*                    VALIDATION FUNCTION TESTS                              */
/* ========================================================================== */

#[test]
fn test_validate_schema_url_none_is_ok() {
    assert!(validate_schema_url(&None).is_ok());
}

#[test]
fn test_validate_schema_url_empty_is_err() {
    let result = validate_schema_url(&Some(String::new()));
    assert!(result.is_err());
}

#[test]
fn test_validate_schema_url_valid() {
    let result = validate_schema_url(&Some("https://example.com/schema".to_string()));
    assert!(result.is_ok());
}

#[test]
fn test_validate_schema_url_control_char_is_err() {
    let result = validate_schema_url(&Some("https://example.com/\x00bad".to_string()));
    assert!(result.is_err());
}

#[test]
fn test_validate_schema_url_non_ascii_is_err() {
    let result = validate_schema_url(&Some("https://example.com/\u{00e9}".to_string()));
    assert!(result.is_err());
}

#[test]
fn test_validate_identifier_format_valid() {
    assert!(validate_identifier_format("user-123_test:v1.0/path@host").is_ok());
}

#[test]
fn test_validate_identifier_format_empty_is_err() {
    assert!(validate_identifier_format("").is_err());
}

#[test]
fn test_validate_identifier_format_space_is_err() {
    assert!(validate_identifier_format("has space").is_err());
}

#[test]
fn test_validate_identifier_format_special_chars_err() {
    assert!(validate_identifier_format("has<angle>brackets").is_err());
}

#[test]
fn test_validate_auth_format_yubikey_ok() {
    assert!(validate_auth_format("yubikey").is_ok());
}

#[test]
fn test_validate_auth_format_client_ok() {
    assert!(validate_auth_format("client").is_ok());
}

#[test]
fn test_validate_auth_format_unknown_err() {
    assert!(validate_auth_format("password").is_err());
}

#[test]
fn test_validate_hex_string_valid() {
    assert!(validate_hex_string("0123456789abcdefABCDEF").is_ok());
}

#[test]
fn test_validate_hex_string_empty_err() {
    assert!(validate_hex_string("").is_err());
}

#[test]
fn test_validate_hex_string_non_hex_err() {
    assert!(validate_hex_string("xyz123").is_err());
}

/* ========================================================================== */
/*                    PROPERTY-BASED TESTS                                   */
/* ========================================================================== */

#[cfg(not(target_arch = "wasm32"))]
use proptest::prelude::*;

#[cfg(not(target_arch = "wasm32"))]
proptest! {
    /// Property: base64_bytes roundtrip is lossless for any 32-byte array
    #[test]
    fn prop_base64_bytes_roundtrip_is_lossless(
        data in prop::collection::vec(any::<u8>(), 32)
    ) {
        #[derive(Serialize, Deserialize)]
        struct Test {
            #[serde(with = "base64_bytes")]
            data: [u8; 32],
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data);
        let original = Test { data: arr };

        let json = serde_json::to_string(&original)?;
        let decoded: Test = serde_json::from_str(&json)?;

        prop_assert_eq!(original.data, decoded.data);
    }

    /// Property: base64_bytes serialization has no padding
    #[test]
    fn prop_base64_bytes_no_padding(
        data in prop::collection::vec(any::<u8>(), 32)
    ) {
        #[derive(Serialize)]
        struct Test {
            #[serde(with = "base64_bytes")]
            data: [u8; 32],
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data);
        let test = Test { data: arr };

        let json = serde_json::to_string(&test)?;
        // URL_SAFE_NO_PAD should never produce '=' padding
        prop_assert!(!json.contains('='));
    }

    /// Property: base64_bytes rejects wrong-length data
    #[test]
    fn prop_base64_bytes_rejects_wrong_length(
        len in 0usize..100usize
    ) {
        prop_assume!(len != 32); // Only test wrong lengths

        #[derive(Deserialize)]
        struct Test {
            #[allow(dead_code)] // Field is required for deserialisation type but not read.
            #[serde(with = "base64_bytes")]
            data: [u8; 32],
        }

        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let bytes = vec![0u8; len];
        let encoded = URL_SAFE_NO_PAD.encode(&bytes);
        let json = format!(r#"{{"data":"{}"}}"#, encoded);

        let result = serde_json::from_str::<Test>(&json);
        prop_assert!(result.is_err());
    }

    /// Property: base64_bytes_64 roundtrip is lossless for any 64-byte array
    #[test]
    fn prop_base64_bytes_64_roundtrip_is_lossless(
        data in prop::collection::vec(any::<u8>(), 64)
    ) {
        #[derive(Serialize, Deserialize)]
        struct Test {
            #[serde(with = "base64_bytes_64")]
            data: [u8; 64],
        }

        let mut arr = [0u8; 64];
        arr.copy_from_slice(&data);
        let original = Test { data: arr };

        let json = serde_json::to_string(&original)?;
        let decoded: Test = serde_json::from_str(&json)?;

        prop_assert_eq!(original.data, decoded.data);
    }

    /// Property: base64_bytes_64 serialization has no padding
    #[test]
    fn prop_base64_bytes_64_no_padding(
        data in prop::collection::vec(any::<u8>(), 64)
    ) {
        #[derive(Serialize)]
        struct Test {
            #[serde(with = "base64_bytes_64")]
            data: [u8; 64],
        }

        let mut arr = [0u8; 64];
        arr.copy_from_slice(&data);
        let test = Test { data: arr };

        let json = serde_json::to_string(&test)?;
        // URL_SAFE_NO_PAD should never produce '=' padding
        prop_assert!(!json.contains('='));
    }

    /// Property: base64_bytes_64 rejects wrong-length data
    #[test]
    fn prop_base64_bytes_64_rejects_wrong_length(
        len in 0usize..150usize
    ) {
        prop_assume!(len != 64); // Only test wrong lengths

        #[derive(Deserialize)]
        struct Test {
            #[allow(dead_code)] // Field is required for deserialisation type but not read.
            #[serde(with = "base64_bytes_64")]
            data: [u8; 64],
        }

        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let bytes = vec![0u8; len];
        let encoded = URL_SAFE_NO_PAD.encode(&bytes);
        let json = format!(r#"{{"data":"{}"}}"#, encoded);

        let result = serde_json::from_str::<Test>(&json);
        prop_assert!(result.is_err());
    }

    /// Property: ActorType serializes to lowercase strings
    #[test]
    fn prop_actor_type_serializes_lowercase(actor_is_officer: bool) {
        let actor = if actor_is_officer {
            ActorType::Officer
        } else {
            ActorType::Client
        };

        let json = serde_json::to_string(&actor)?;
        let expected = if actor_is_officer { r#""officer""# } else { r#""client""# };

        prop_assert_eq!(json, expected);
    }

    /// Property: ActorType roundtrip is lossless
    #[test]
    fn prop_actor_type_roundtrip(actor_is_officer: bool) {
        let actor = if actor_is_officer {
            ActorType::Officer
        } else {
            ActorType::Client
        };

        let json = serde_json::to_string(&actor)?;
        let decoded: ActorType = serde_json::from_str(&json)?;

        prop_assert_eq!(actor, decoded);
    }

    /// Property: SessionStatus serializes to lowercase strings
    #[test]
    fn prop_session_status_serializes_lowercase(status_idx: u8) {
        let status = match status_idx % 4 {
            0 => SessionStatus::Pending,
            1 => SessionStatus::Authenticated,
            2 => SessionStatus::Completed,
            _ => SessionStatus::Expired,
        };

        let json = serde_json::to_string(&status)?;
        let expected = match status_idx % 4 {
            0 => r#""pending""#,
            1 => r#""authenticated""#,
            2 => r#""completed""#,
            _ => r#""expired""#,
        };

        prop_assert_eq!(json, expected);
    }

    /// Property: SessionStatus roundtrip is lossless
    #[test]
    fn prop_session_status_roundtrip(status_idx: u8) {
        let status = match status_idx % 4 {
            0 => SessionStatus::Pending,
            1 => SessionStatus::Authenticated,
            2 => SessionStatus::Completed,
            _ => SessionStatus::Expired,
        };

        let json = serde_json::to_string(&status)?;
        let decoded: SessionStatus = serde_json::from_str(&json)?;

        prop_assert_eq!(status, decoded);
    }

    /// Property: ChallengeResponse roundtrip preserves all fields
    #[test]
    fn prop_challenge_response_roundtrip(
        challenge_id in "[a-z0-9\\-]{1,64}",
        challenge in "[a-f0-9]{1,128}",
        expires_at in any::<i64>()
    ) {
        let original = ChallengeResponse {
            challenge_id: challenge_id.clone(),
            challenge: challenge.clone(),
            expires_at,
        };

        let json = serde_json::to_string(&original)?;
        let decoded: ChallengeResponse = serde_json::from_str(&json)?;

        prop_assert_eq!(decoded.challenge_id, challenge_id);
        prop_assert_eq!(decoded.challenge, challenge);
        prop_assert_eq!(decoded.expires_at, expires_at);
    }

    /// Property: Authorizer preserves keyId camelCase field name
    #[test]
    fn prop_authorizer_camel_case_key_id(
        format in "[a-z]{1,10}",
        key_id in "[a-z0-9]{1,20}",
        timestamp in any::<u64>(),
        hmac in "[a-f0-9]{1,64}"
    ) {
        let auth = Authorizer {
            format,
            key_id,
            challenge_id: None,
            timestamp,
            hmac,
            nonce: "d".repeat(64),
        };

        let json = serde_json::to_string(&auth)?;
        // Verify camelCase field name
        prop_assert!(json.contains("keyId"));
        // Should not contain snake_case
        prop_assert!(!json.contains("key_id"));
    }

    /// Property: Authorizer roundtrip preserves all fields
    #[test]
    fn prop_authorizer_roundtrip(
        format in "[a-z]{1,10}",
        key_id in "[a-z0-9\\-]{1,20}",
        challenge_id in proptest::option::of("[a-z0-9\\-]{1,64}"),
        timestamp in any::<u64>(),
        hmac in "[a-f0-9]{1,128}"
    ) {
        let original = Authorizer {
            format: format.clone(),
            key_id: key_id.clone(),
            challenge_id: challenge_id.clone(),
            timestamp,
            hmac: hmac.clone(),
            nonce: "e".repeat(64),
        };

        let json = serde_json::to_string(&original)?;
        let decoded: Authorizer = serde_json::from_str(&json)?;

        prop_assert_eq!(decoded.format, format);
        prop_assert_eq!(decoded.key_id, key_id);
        prop_assert_eq!(decoded.challenge_id, challenge_id);
        prop_assert_eq!(decoded.timestamp, timestamp);
        prop_assert_eq!(decoded.hmac, hmac);
    }

    /// Property: PolicyConfig roundtrip preserves all fields
    #[test]
    fn prop_policy_config_roundtrip(
        schema in "[a-z0-9./]{1,50}",
        validity_days in any::<u32>(),
        v in any::<u8>()
    ) {
        let original = PolicyConfig {
            schema: schema.clone(),
            validity_days,
            v
        };

        let json = serde_json::to_string(&original)?;
        let decoded: PolicyConfig = serde_json::from_str(&json)?;

        prop_assert_eq!(decoded.schema, schema);
        prop_assert_eq!(decoded.validity_days, validity_days);
        prop_assert_eq!(decoded.v, v);
    }

    /// Property: Jwk roundtrip preserves all fields including "use" field
    #[test]
    fn prop_jwk_roundtrip(
        kty in "[A-Z]{1,10}",
        crv in "[A-Z]{1,10}",
        kid in "[a-z0-9\\-]{1,20}",
        use_ in "[a-z]{1,5}",
        alg in "[A-Za-z0-9]{1,20}",
        x in "[A-Za-z0-9_\\-]{1,86}"
    ) {
        let original = Jwk {
            kty: kty.clone(),
            crv: crv.clone(),
            kid: kid.clone(),
            use_: use_.clone(),
            alg: alg.clone(),
            x: x.clone(),
        };

        let json = serde_json::to_string(&original)?;
        let decoded: Jwk = serde_json::from_str(&json)?;

        prop_assert_eq!(decoded.kty, kty);
        prop_assert_eq!(decoded.crv, crv);
        prop_assert_eq!(decoded.kid, kid);
        prop_assert_eq!(decoded.use_, use_);
        prop_assert_eq!(decoded.alg, alg);
        prop_assert_eq!(decoded.x, x);
    }

    /// Property: JwkSet can serialize/deserialize with any number of keys
    #[test]
    fn prop_jwk_set_any_size(
        keys_count in 0usize..10
    ) {
        let keys: Vec<Jwk> = (0..keys_count)
            .map(|i| Jwk {
                kty: "OKP".to_string(),
                crv: "JUBJUB".to_string(),
                kid: format!("key-{}", i),
                use_: "sig".to_string(),
                alg: "RedJubjub".to_string(),
                x: "AAAA".to_string(),
            })
            .collect();

        let original = JwkSet { keys };
        let json = serde_json::to_string(&original)?;
        let decoded: JwkSet = serde_json::from_str(&json)?;

        prop_assert_eq!(decoded.keys.len(), keys_count);
    }
}
