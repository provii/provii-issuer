// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Input validation for the issuer service.

use crate::error::{ApiError, Result};
use group::GroupEncoding;
use jubjub::SubgroupPoint;
use unicode_normalization::UnicodeNormalization;
use url::Url;

/// Default allowed schema domains if not specified in environment
const DEFAULT_ALLOWED_SCHEMA_DOMAINS: &[&str] = &["w3.org", "provii.app"];

/// Normalize text identifiers using NFC (Canonical Composition) to prevent homograph attacks
pub(crate) fn normalize_identifier(input: &str) -> String {
    input.nfc().collect()
}

/// Validate schema URL with whitelist and security checks.
/// Set `is_sandbox` to true to permit HTTP on localhost for local testing.
pub fn validate_schema_url(schema_url: &str, allowed_domains_env: Option<&str>) -> Result<String> {
    validate_schema_url_inner(schema_url, allowed_domains_env, false)
}

/// Variant that accepts an explicit sandbox flag for testing environments.
pub fn validate_schema_url_with_env(
    schema_url: &str,
    allowed_domains_env: Option<&str>,
    is_sandbox: bool,
) -> Result<String> {
    validate_schema_url_inner(schema_url, allowed_domains_env, is_sandbox)
}

fn validate_schema_url_inner(
    schema_url: &str,
    allowed_domains_env: Option<&str>,
    is_sandbox: bool,
) -> Result<String> {
    if schema_url.is_empty() {
        return Err(ApiError::BadRequest(
            "Schema URL cannot be empty".to_string(),
        ));
    }

    if schema_url.len() > crate::types::MAX_SCHEMA_VALUE_URL_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "Schema URL too long (max {} characters)",
            crate::types::MAX_SCHEMA_VALUE_URL_LENGTH
        )));
    }

    // Normalize the URL
    let normalized = normalize_identifier(schema_url);

    // Parse as URL to validate structure
    let parsed_url = match Url::parse(&normalized) {
        Ok(url) => url,
        Err(_) => {
            // If it's not a full URL, it might be a simple identifier like "provii.age/0"
            // Validate as identifier instead
            if normalized
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '/' || c == '-' || c == '_')
                && !normalized.contains("..")
            {
                return Ok(normalized);
            }
            return Err(ApiError::BadRequest(
                "Invalid schema URL format".to_string(),
            ));
        }
    };

    // Block dangerous schemes
    let scheme = parsed_url.scheme();
    if matches!(
        scheme,
        "javascript"
            | "file"
            | "data"
            | "blob"
            | "vbscript"
            | "ftp"
            | "gopher"
            | "telnet"
            | "ws"
            | "wss"
    ) {
        return Err(ApiError::BadRequest("URL scheme not allowed".to_string()));
    }

    // Enforce HTTPS for full URLs. HTTP localhost is only permitted in sandbox.
    if scheme == "http" {
        let is_localhost = parsed_url.host_str() == Some("localhost");
        if !is_localhost || !is_sandbox {
            return Err(ApiError::BadRequest(
                "Schema URLs must use HTTPS".to_string(),
            ));
        }
    }

    // Validate domain against whitelist
    if let Some(host) = parsed_url.host_str() {
        let allowed_domains: Vec<&str> = if let Some(env_domains) = allowed_domains_env {
            env_domains.split(',').map(|s| s.trim()).collect()
        } else {
            DEFAULT_ALLOWED_SCHEMA_DOMAINS.to_vec()
        };

        // Check if host matches or is subdomain of allowed domains
        let is_allowed = allowed_domains
            .iter()
            .any(|&allowed| host == allowed || host.ends_with(&format!(".{}", allowed)));

        if !is_allowed {
            crate::log!(
                "Schema URL domain not in whitelist (domain count: {})",
                allowed_domains.len()
            );
            return Err(ApiError::BadRequest(
                "Schema domain not in allowed list".to_string(),
            ));
        }
    }

    Ok(normalized)
}

/// Validate commitment format: exactly 64 hex characters (32 bytes)
pub fn validate_commitment_format(commitment_hex: &str) -> Result<[u8; 32]> {
    // Check length (64 hex chars = 32 bytes)
    if commitment_hex.len() != 64 {
        return Err(ApiError::BadRequest(
            "Commitment must be exactly 64 hex characters".to_string(),
        ));
    }

    // Decode hex to bytes (hex::decode validates hex characters internally)
    let bytes = match hex::decode(commitment_hex) {
        Ok(b) => b,
        Err(_) => {
            return Err(ApiError::BadRequest(
                "Commitment must contain only hexadecimal characters".to_string(),
            ))
        }
    };

    // Convert to fixed-size array
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&bytes);

    // Validate as curve point (basic check - not all zeros)
    if commitment.iter().all(|&b| b == 0) {
        return Err(ApiError::BadRequest(
            "Invalid commitment: all zeros".to_string(),
        ));
    }

    // CIV-139: Validate commitment is a valid Jubjub SubgroupPoint.
    if bool::from(SubgroupPoint::from_bytes(&commitment).is_none()) {
        return Err(ApiError::BadRequest(
            "Invalid commitment: not a valid curve point".to_string(),
        ));
    }

    Ok(commitment)
}

/// Validate commitment from base64url encoded bytes
pub fn validate_commitment_bytes(commitment: &[u8; 32]) -> Result<()> {
    // Basic sanity check - not all zeros
    if commitment.iter().all(|&b| b == 0) {
        return Err(ApiError::BadRequest(
            "Invalid commitment: all zeros".to_string(),
        ));
    }

    // CIV-139: Validate commitment is a valid Jubjub SubgroupPoint.
    if bool::from(SubgroupPoint::from_bytes(commitment).is_none()) {
        return Err(ApiError::BadRequest(
            "Invalid commitment: not a valid curve point".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_identifier_ascii() {
        let input = "test-officer-123";
        let result = normalize_identifier(input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_normalize_identifier_unicode() {
        // NFC normalization should compose characters
        let input = "e\u{0301}"; // e + combining acute accent
        let result = normalize_identifier(input);
        assert_eq!(result, "é"); // composed character
    }

    #[test]
    fn test_validate_schema_url_simple_identifier(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result = validate_schema_url("provii.age/0", None);
        assert!(result.is_ok());
        assert_eq!(result?, "provii.age/0");
        Ok(())
    }

    #[test]
    fn test_validate_schema_url_https() {
        let result = validate_schema_url("https://w3.org/2018/credentials/v1", None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_schema_url_http_blocked() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let result = validate_schema_url("http://example.com/schema", None);
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .to_string()
            .contains("HTTPS"));
        Ok(())
    }

    #[test]
    fn test_validate_schema_url_javascript_blocked(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result = validate_schema_url("javascript:alert(1)", None);
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .to_string()
            .contains("scheme not allowed"));
        Ok(())
    }

    #[test]
    fn test_validate_schema_url_file_blocked() {
        let result = validate_schema_url("file:///etc/passwd", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_schema_url_subdomain_allowed() {
        let result = validate_schema_url("https://schemas.provii.app/v1", None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_schema_url_not_in_whitelist(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result = validate_schema_url("https://evil.com/schema", None);
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .to_string()
            .contains("not in allowed list"));
        Ok(())
    }

    #[test]
    fn test_validate_schema_url_custom_whitelist() {
        let result = validate_schema_url(
            "https://custom.domain.com/schema",
            Some("custom.domain.com"),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_commitment_format_valid() {
        // Known valid Jubjub SubgroupPoint (spending key generator)
        let valid_bytes: [u8; 32] = [
            0x30, 0xb5, 0xf2, 0xaa, 0xad, 0x32, 0x56, 0x30, 0xbc, 0xdd, 0xdb, 0xce, 0x4d, 0x67,
            0x65, 0x6d, 0x05, 0xfd, 0x1c, 0xc2, 0xd0, 0x37, 0xbb, 0x53, 0x75, 0xb6, 0xe9, 0x6d,
            0x9e, 0x01, 0xa1, 0x57,
        ];
        let hex = hex::encode(valid_bytes);
        let result = validate_commitment_format(&hex);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_commitment_format_invalid_curve_point(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // 32 non-zero bytes that are NOT a valid SubgroupPoint
        let hex = "ff".repeat(32);
        let result = validate_commitment_format(&hex);
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .to_string()
            .contains("not a valid curve point"));
        Ok(())
    }

    #[test]
    fn test_validate_commitment_format_too_short(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let hex = "a".repeat(32);
        let result = validate_commitment_format(&hex);
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .to_string()
            .contains("64 hex"));
        Ok(())
    }

    #[test]
    fn test_validate_commitment_format_too_long() {
        let hex = "a".repeat(128);
        let result = validate_commitment_format(&hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_commitment_format_invalid_hex(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let hex = "g".repeat(64);
        let result = validate_commitment_format(&hex);
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .to_string()
            .contains("hexadecimal"));
        Ok(())
    }

    #[test]
    fn test_validate_commitment_format_all_zeros(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let hex = "0".repeat(64);
        let result = validate_commitment_format(&hex);
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .to_string()
            .contains("all zeros"));
        Ok(())
    }

    #[test]
    fn test_validate_commitment_bytes_valid() {
        // Known valid Jubjub SubgroupPoint (spending key generator)
        let commitment: [u8; 32] = [
            0x30, 0xb5, 0xf2, 0xaa, 0xad, 0x32, 0x56, 0x30, 0xbc, 0xdd, 0xdb, 0xce, 0x4d, 0x67,
            0x65, 0x6d, 0x05, 0xfd, 0x1c, 0xc2, 0xd0, 0x37, 0xbb, 0x53, 0x75, 0xb6, 0xe9, 0x6d,
            0x9e, 0x01, 0xa1, 0x57,
        ];
        let result = validate_commitment_bytes(&commitment);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_commitment_bytes_invalid_curve_point(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Non-zero bytes that are NOT a valid SubgroupPoint
        let commitment = [0xFFu8; 32];
        let result = validate_commitment_bytes(&commitment);
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .to_string()
            .contains("not a valid curve point"));
        Ok(())
    }

    #[test]
    fn test_validate_commitment_bytes_all_zeros() {
        let commitment = [0u8; 32];
        let result = validate_commitment_bytes(&commitment);
        assert!(result.is_err());
    }
}
