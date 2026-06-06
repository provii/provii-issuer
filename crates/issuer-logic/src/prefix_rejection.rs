// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Sandbox-prefix rejection logic (pure, no Worker dependencies).
//!
//! Extracted from `security/prefix_rejection.rs`. The Worker-level entry
//! point (`check_request`) remains in the root crate and delegates to
//! [`check_request_inputs`] here.
//!
//! SECURITY: All comparisons here operate on non-secret identifier
//! prefixes. Constant-time comparison is neither required nor used.
//! Rejection short-circuits on the first hit to avoid needless work on
//! attacker-controlled input.

/// Prefixes that identify sandbox-only credentials.
///
/// Keep this list in sync with:
///
///   - `provii-verifier/src/security/prefix_rejection.rs`
///   - `provii-management/src/middleware/prefix-rejection.ts`
///   - `build.rs` (compile-time sentinel in sibling repos)
///   - the weekly CI bundle-grep workflow
///
/// All must agree on which prefixes are gated.
const SANDBOX_PREFIXES: &[&str] = &["mwallet-sbx-"];

/// Maximum length of an HTTP auth scheme token (RFC 9110 registered schemes
/// are all short: Bearer, Basic, Digest, HOBA, Mutual, Negotiate, etc.).
/// Anything longer than this is treated as credential material, not a scheme.
const MAX_AUTH_SCHEME_LENGTH: usize = 15;

/// Canonical rejection body. Shape matches the provii-verifier and
/// provii-management responses for cross-service symmetry.
pub const REJECTION_BODY: &str = r#"{"error":"Access denied","code":"prefix_not_permitted"}"#;

/// Outcome of a prefix scan.
#[derive(Debug, PartialEq, Eq)]
pub enum PrefixCheck {
    /// No sandbox-prefixed value observed. Request should continue.
    Allow,
    /// Sandbox-prefixed value observed. The `source` field describes
    /// where it was found; it is used only for structured diagnostics
    /// and never echoed in the 401 body.
    Reject { source: &'static str },
}

/// Inspect a request's URL and headers for sandbox-prefixed values.
///
/// Pure function, no side effects. Kept separate from the Worker-level
/// entry point so unit tests can exercise it without a Worker runtime.
///
/// Returns `PrefixCheck::Allow` when no sandbox prefix is observed.
pub fn check_request_inputs(
    path: &str,
    query: &str,
    header_iter: impl IntoIterator<Item = (String, String)>,
) -> PrefixCheck {
    // Path-segment scan.
    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }
        let decoded = percent_decode(segment);
        if matches_sandbox_prefix(decoded.as_str()) {
            return PrefixCheck::Reject { source: "path" };
        }
    }

    // Query-string scan.
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let decoded_key = percent_decode(key);
        if matches_sandbox_prefix(&decoded_key) {
            return PrefixCheck::Reject { source: "query" };
        }
        if !value.is_empty() {
            let decoded_value = percent_decode(value);
            if matches_sandbox_prefix(&decoded_value) {
                return PrefixCheck::Reject { source: "query" };
            }
        }
    }

    // Header scan. Case-insensitive header names, raw values.
    for (name, value) in header_iter {
        let lower = name.to_ascii_lowercase();
        let inspected = matches!(
            lower.as_str(),
            "x-client-id" | "x-api-key" | "authorization"
        );
        if inspected && matches_sandbox_prefix(&value) {
            return PrefixCheck::Reject { source: "header" };
        }
    }

    PrefixCheck::Allow
}

/// Return `true` if `value` begins with any configured sandbox prefix.
///
/// For `Authorization`-style values this helper strips a leading scheme
/// token (`Bearer `, `Basic `, etc.) before comparing.
fn matches_sandbox_prefix(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    if begins_with_any_prefix(value) {
        return true;
    }
    if let Some((scheme, rest)) = value.split_once(' ') {
        if scheme.len() <= MAX_AUTH_SCHEME_LENGTH && !scheme.is_empty() {
            let after = rest.trim_start();
            if begins_with_any_prefix(after) {
                return true;
            }
        }
    }
    false
}

/// Plain `str::starts_with` loop over the configured sandbox prefixes.
fn begins_with_any_prefix(candidate: &str) -> bool {
    for prefix in SANDBOX_PREFIXES {
        if candidate.starts_with(prefix) {
            return true;
        }
    }
    false
}

/// Best-effort percent-decode. Invalid sequences fall through as-is.
fn percent_decode(input: &str) -> String {
    if !input.contains('%') {
        return input.to_string();
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut iter = input.bytes().peekable();
    while let Some(b) = iter.next() {
        if b == b'%' {
            let next1 = iter.peek().copied();
            let hi = next1.and_then(hex_digit);
            if let Some(h) = hi {
                let raw_hi = next1.unwrap_or(b'%');
                iter.next();
                let next2 = iter.peek().copied();
                let lo = next2.and_then(hex_digit);
                if let Some(l) = lo {
                    iter.next();
                    out.push(h.saturating_mul(16).saturating_add(l));
                    continue;
                }
                out.push(b'%');
                out.push(raw_hi);
                continue;
            }
            out.push(b'%');
            continue;
        }
        out.push(b);
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.saturating_sub(b'0')),
        b'a'..=b'f' => Some(b.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(b.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
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

    #[test]
    fn allow_clean_request() {
        let result = check_request_inputs("/api/issue", "", vec![]);
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn reject_sandbox_prefix_in_path() {
        let result = check_request_inputs("/api/mwallet-sbx-abc123/issue", "", vec![]);
        assert_eq!(result, PrefixCheck::Reject { source: "path" });
    }

    #[test]
    fn reject_sandbox_prefix_in_query_value() {
        let result = check_request_inputs("/api/issue", "client_id=mwallet-sbx-xyz", vec![]);
        assert_eq!(result, PrefixCheck::Reject { source: "query" });
    }

    #[test]
    fn reject_sandbox_prefix_in_query_key() {
        let result = check_request_inputs("/api/issue", "mwallet-sbx-key=value", vec![]);
        assert_eq!(result, PrefixCheck::Reject { source: "query" });
    }

    #[test]
    fn reject_sandbox_prefix_in_header() {
        let headers = vec![("X-Client-Id".to_string(), "mwallet-sbx-abc".to_string())];
        let result = check_request_inputs("/api/issue", "", headers);
        assert_eq!(result, PrefixCheck::Reject { source: "header" });
    }

    #[test]
    fn reject_bearer_token_with_prefix() {
        let headers = vec![(
            "authorization".to_string(),
            "Bearer mwallet-sbx-token123".to_string(),
        )];
        let result = check_request_inputs("/api/issue", "", headers);
        assert_eq!(result, PrefixCheck::Reject { source: "header" });
    }

    #[test]
    fn allow_non_inspected_header() {
        let headers = vec![("x-custom".to_string(), "mwallet-sbx-ignored".to_string())];
        let result = check_request_inputs("/api/issue", "", headers);
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn percent_encoded_prefix_in_path() {
        // mwallet-sbx- with 's' encoded as %73
        let result = check_request_inputs("/api/mwallet-%73bx-abc123/issue", "", vec![]);
        assert_eq!(result, PrefixCheck::Reject { source: "path" });
    }

    #[test]
    fn malformed_percent_encoding_passthrough() {
        // %ZZ is not valid hex, falls through as literal
        let result = check_request_inputs("/api/%ZZnormal", "", vec![]);
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn empty_path_and_query() {
        let result = check_request_inputs("", "", vec![]);
        assert_eq!(result, PrefixCheck::Allow);
    }

    #[test]
    fn rejection_body_is_valid_json() {
        let parsed: serde_json::Value = serde_json::from_str(REJECTION_BODY).unwrap();
        assert_eq!(parsed["error"], "Access denied");
        assert_eq!(parsed["code"], "prefix_not_permitted");
    }
}
