// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! RFC 9110 `Authorization: Bearer` header parsing helpers.
//!
//! Every Class 6 internal API key (status tokens, admin keys, internal
//! service tokens) accepts its credential exclusively in the canonical
//! `Authorization: Bearer <token>` shape.
//!
//! This module hosts the parser the call sites share. Ported from
//! `provii-verifier/src/security/status_auth.rs::extract_bearer_token` so
//! both Workers parse the scheme literal identically.
//!
//! SECURITY: the helper consumes only the request `Authorization` header,
//! a public input. The shape check (scheme literal, single space
//! delimiter) is not secret-dependent and does not leak timing
//! information about the credential. Constant-time comparison of the
//! returned credential against the configured slot hashes is the
//! responsibility of the caller and lives in each call site's
//! `subtle::ConstantTimeEq` branch.

/// Strip a leading `Bearer ` scheme token from an `Authorization` header
/// value and return the trimmed credential, or `None` if the header is
/// missing the scheme, the credential is empty, or the header carries
/// any other scheme (`Basic`, etc.).
///
/// Comparison of the scheme literal is ASCII-case-insensitive per
/// RFC 9110 §11.1. The credential portion is returned verbatim with no
/// decoding so the constant-time verifier downstream sees the same bytes
/// the operator pasted into the `curl` invocation.
#[must_use]
pub fn extract_bearer_token(authorization: &str) -> Option<&str> {
    let (scheme, rest) = authorization.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let credential = rest.trim_ascii();
    if credential.is_empty() {
        return None;
    }
    Some(credential)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::extract_bearer_token;

    /// Canonical RFC 9110 shape: `Bearer <token>`.
    #[test]
    fn accepts_canonical_bearer() {
        assert_eq!(extract_bearer_token("Bearer abc"), Some("abc"));
    }

    /// Scheme comparison is ASCII-case-insensitive per RFC 9110 §11.1.
    /// Lowercase and uppercase variants must both resolve.
    #[test]
    fn accepts_lowercase_scheme() {
        assert_eq!(extract_bearer_token("bearer abc"), Some("abc"));
    }

    #[test]
    fn accepts_uppercase_scheme() {
        assert_eq!(extract_bearer_token("BEARER abc"), Some("abc"));
    }

    /// Multiple spaces between scheme and credential are tolerated; the
    /// credential is trimmed of leading whitespace so the verify path
    /// receives the exact bytes the operator typed.
    #[test]
    fn tolerates_extra_whitespace_after_scheme() {
        assert_eq!(extract_bearer_token("Bearer   abc"), Some("abc"));
    }

    /// `Basic` is RFC 9110 but not the scheme this Worker accepts. The
    /// helper rejects it without consulting any slot data so the caller
    /// cannot accidentally treat a base64-encoded user:pass pair as a
    /// bearer credential.
    #[test]
    fn rejects_basic_scheme() {
        assert_eq!(extract_bearer_token("Basic dXNlcjpwYXNz"), None);
    }

    /// Empty credential after the scheme is rejected; the verify path
    /// must never run against an empty string.
    #[test]
    fn rejects_empty_credential() {
        assert_eq!(extract_bearer_token("Bearer "), None);
    }

    /// Bare scheme with no separator is rejected.
    #[test]
    fn rejects_bare_scheme_token() {
        assert_eq!(extract_bearer_token("Bearer"), None);
    }

    /// Empty header value is rejected.
    #[test]
    fn rejects_empty_header() {
        assert_eq!(extract_bearer_token(""), None);
    }

    /// A bare token with no scheme is rejected.
    #[test]
    fn rejects_bare_token_no_scheme() {
        assert_eq!(extract_bearer_token("abc"), None);
    }

    /// Custom non-RFC schemes are rejected.
    #[test]
    fn rejects_unknown_scheme() {
        assert_eq!(extract_bearer_token("Token abc"), None);
    }
}
