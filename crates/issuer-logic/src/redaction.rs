// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Log sanitisation helpers.
//!
//! Extracted from `security/client_auth.rs` in the Worker crate.

/// DH-001: Truncate a session ID to the first 4 characters plus "..." for log output.
///
/// Session IDs are UUIDs. Logging them in full allows any log reader to
/// replay or hijack sessions. Four characters provide sufficient
/// entropy for correlating log lines within a single request context
/// without exposing the full token. Short inputs (fewer than 4 characters)
/// are replaced entirely with "***" to avoid leaking the complete value.
///
/// Matches the pattern used in provii-verifier (`security/log_sanitizer.rs`).
#[inline]
pub fn redact_session_id(session_id: &str) -> String {
    if session_id.len() < 4 {
        "***".to_string()
    } else {
        let prefix: String = session_id.chars().take(4).collect();
        format!("{}...", prefix)
    }
}

/// Number of leading characters used for the API key prefix index lookup.
/// Eight hex characters provide a 32-bit keyspace (4.3 billion values),
/// sufficient to avoid collisions at expected client counts while keeping
/// the KV key compact.
pub const API_KEY_PREFIX_LENGTH: usize = 8;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn redact_normal() {
        assert_eq!(redact_session_id("a1b2c3d4-e5f6-7890"), "a1b2...");
    }

    #[test]
    fn redact_empty() {
        assert_eq!(redact_session_id(""), "***");
    }

    #[test]
    fn redact_one_char() {
        assert_eq!(redact_session_id("x"), "***");
    }

    #[test]
    fn redact_two_chars() {
        assert_eq!(redact_session_id("ab"), "***");
    }

    #[test]
    fn redact_three_chars() {
        assert_eq!(redact_session_id("abc"), "***");
    }

    #[test]
    fn redact_exactly_four() {
        assert_eq!(redact_session_id("abcd"), "abcd...");
    }

    #[test]
    fn redact_five_chars() {
        assert_eq!(redact_session_id("abcde"), "abcd...");
    }

    #[test]
    fn redact_full_uuid() {
        assert_eq!(
            redact_session_id("550e8400-e29b-41d4-a716-446655440000"),
            "550e..."
        );
    }

    #[test]
    fn prefix_length_is_eight() {
        assert_eq!(API_KEY_PREFIX_LENGTH, 8);
    }
}
