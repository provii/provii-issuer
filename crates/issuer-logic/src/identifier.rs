// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Identifier validation and key-format helpers.
//!
//! Extracted from `storage.rs` in the Worker crate.

use crate::error::{LogicError, Result};

/// Maximum length for user-controlled identifiers to prevent DoS.
pub const MAX_IDENTIFIER_LENGTH: usize = 128;

/// Validate an identifier to prevent KV injection attacks.
/// Allows: alphanumeric, hyphens, underscores, colons, periods, and forward slashes.
/// This covers UUIDs, email addresses, URLs, and other common identifier formats.
///
/// Forward slashes are intentionally permitted because DID-format
/// identifiers (e.g. `did:web:example.com/path`) contain path separators.
/// KV keys are assembled via `format!()` with a fixed prefix, so embedded
/// slashes cannot escape the key namespace.
pub fn validate_identifier(id: &str, context: &str) -> Result<()> {
    if id.is_empty() {
        return Err(LogicError::BadRequest(format!("Empty {}", context)));
    }

    if id.len() > MAX_IDENTIFIER_LENGTH {
        return Err(LogicError::BadRequest(format!(
            "{} too long (max {} characters)",
            context, MAX_IDENTIFIER_LENGTH
        )));
    }

    // Allow alphanumeric, hyphen, underscore, colon, period, forward slash, @ symbol
    // This covers: UUIDs, email addresses, URLs, key IDs, etc.
    if !id.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '-'
            || c == '_'
            || c == ':'
            || c == '.'
            || c == '/'
            || c == '@'
    }) {
        return Err(LogicError::BadRequest(format!(
            "Invalid {} format (contains disallowed characters)",
            context
        )));
    }

    Ok(())
}

/// Extract issuer_kid from issuer_id (strip "did:provii:" prefix).
pub fn extract_issuer_kid(issuer_id: &str) -> &str {
    issuer_id.strip_prefix("did:provii:").unwrap_or(issuer_id)
}

/// Validate nonce format: must be exactly 64 hex characters (256 bits).
///
/// Returns `Ok(())` if valid, `Err(...)` for validation failures.
/// The actual consumption (replay prevention) is handled by the Worker layer.
pub fn validate_nonce_format(nonce: &str) -> Result<()> {
    if nonce.len() != 64 {
        return Err(LogicError::BadRequest(
            "Nonce must be exactly 64 hex characters (256 bits)".to_string(),
        ));
    }

    if !nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(LogicError::BadRequest(
            "Nonce must be a hex string".to_string(),
        ));
    }

    Ok(())
}

/// Validate actor_type for lockout/rate-limit operations.
pub fn validate_actor_type(actor_type: &str) -> Result<()> {
    if actor_type != "officer" && actor_type != "client" && actor_type != "admin" {
        return Err(LogicError::BadRequest("Invalid actor_type".to_string()));
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    // === validate_identifier ===

    #[test]
    fn accepts_uuid() {
        assert!(validate_identifier("550e8400-e29b-41d4-a716-446655440000", "id").is_ok());
    }

    #[test]
    fn accepts_email() {
        assert!(validate_identifier("user@example.com", "email").is_ok());
    }

    #[test]
    fn accepts_did() {
        assert!(validate_identifier("did:web:example.com/path", "issuer_id").is_ok());
    }

    #[test]
    fn accepts_kid_with_colons() {
        assert!(validate_identifier("provii:2026-05", "kid").is_ok());
    }

    #[test]
    fn rejects_empty() {
        let err = validate_identifier("", "test").unwrap_err();
        assert!(err.to_string().contains("Empty test"));
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(129);
        let err = validate_identifier(&long, "test").unwrap_err();
        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn rejects_shell_injection() {
        let err = validate_identifier("id; rm -rf /", "test").unwrap_err();
        assert!(err.to_string().contains("disallowed characters"));
    }

    #[test]
    fn rejects_newline() {
        let err = validate_identifier("id\ninjection", "test").unwrap_err();
        assert!(err.to_string().contains("disallowed characters"));
    }

    #[test]
    fn rejects_null_byte() {
        let err = validate_identifier("id\x00null", "test").unwrap_err();
        assert!(err.to_string().contains("disallowed characters"));
    }

    #[test]
    fn accepts_exactly_max_length() {
        let exact = "a".repeat(MAX_IDENTIFIER_LENGTH);
        assert!(validate_identifier(&exact, "test").is_ok());
    }

    // === extract_issuer_kid ===

    #[test]
    fn strips_did_prefix() {
        assert_eq!(extract_issuer_kid("did:provii:test-issuer"), "test-issuer");
    }

    #[test]
    fn no_prefix_passthrough() {
        assert_eq!(extract_issuer_kid("bare-issuer"), "bare-issuer");
    }

    #[test]
    fn partial_prefix_passthrough() {
        assert_eq!(extract_issuer_kid("did:provii"), "did:provii");
    }

    #[test]
    fn empty_after_prefix() {
        assert_eq!(extract_issuer_kid("did:provii:"), "");
    }

    // === validate_nonce_format ===

    #[test]
    fn accepts_valid_nonce() {
        let nonce = "a".repeat(64);
        assert!(validate_nonce_format(&nonce).is_ok());
    }

    #[test]
    fn accepts_mixed_case_hex_nonce() {
        let nonce = "aAbBcCdDeEfF0123456789aAbBcCdDeEfF0123456789aAbBcCdDeEfF01234567";
        assert_eq!(nonce.len(), 64);
        // Contains uppercase hex, check if accepted
        // Our validator uses is_ascii_hexdigit which accepts a-f and A-F
        assert!(validate_nonce_format(nonce).is_ok());
    }

    #[test]
    fn rejects_short_nonce() {
        let nonce = "abcdef";
        let err = validate_nonce_format(nonce).unwrap_err();
        assert!(err.to_string().contains("64 hex characters"));
    }

    #[test]
    fn rejects_non_hex_nonce() {
        let nonce = "g".repeat(64); // 'g' is not hex
        let err = validate_nonce_format(&nonce).unwrap_err();
        assert!(err.to_string().contains("hex string"));
    }

    // === validate_actor_type ===

    #[test]
    fn accepts_officer() {
        assert!(validate_actor_type("officer").is_ok());
    }

    #[test]
    fn accepts_client() {
        assert!(validate_actor_type("client").is_ok());
    }

    #[test]
    fn accepts_admin() {
        assert!(validate_actor_type("admin").is_ok());
    }

    #[test]
    fn rejects_unknown_actor_type() {
        let err = validate_actor_type("hacker").unwrap_err();
        assert!(err.to_string().contains("Invalid actor_type"));
    }

    #[test]
    fn rejects_empty_actor_type() {
        assert!(validate_actor_type("").is_err());
    }
}
