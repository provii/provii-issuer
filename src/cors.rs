// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! CORS (Cross-Origin Resource Sharing) configuration with wildcard support.
//!
//! SECURITY: Implements OWASP CORS best practices:
//! - Wildcard patterns (*) supported for development
//! - Subdomain wildcards (https://*.example.com) supported
//! - Credentials never allowed with wildcard origins
//! - All origin matching is case-sensitive per spec
//!
//! Based on provii-verifier/src/config.rs implementation.

use url::Url;

/// Wrapper around a list of origin patterns with helper matching logic.
#[derive(Debug, Clone)]
pub struct AllowedOrigins {
    patterns: Vec<String>,
    /// SECURITY: Track if this list contains the global wildcard to prevent
    /// accidentally allowing credentials with wildcard origins
    contains_global_wildcard: bool,
}

impl AllowedOrigins {
    /// Parse a comma-separated list of origin patterns.
    ///
    /// Examples:
    /// - "https://example.com" - exact match
    /// - "https://*.example.com" - subdomain wildcard
    /// - "*" - allow all origins (development only)
    /// - "https://app.example.com,https://demo.example.com" - multiple origins
    pub fn new(raw: String) -> Self {
        let list: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // SECURITY: Check for global wildcard
        let contains_global_wildcard = list.iter().any(|p| p == "*");

        Self {
            patterns: list,
            contains_global_wildcard,
        }
    }

    /// SECURITY: Returns true if the origin matches any allowed pattern.
    /// Does NOT indicate whether credentials should be allowed.
    pub fn matches(&self, origin: &str) -> bool {
        let origin_url = match Url::parse(origin) {
            Ok(u) => u,
            Err(_) => return false,
        };

        self.patterns.iter().any(|pattern| {
            if pattern == "*" {
                return true;
            }

            if pattern.contains("://*.") {
                return self.matches_subdomain_wildcard(pattern, &origin_url);
            }

            if let Ok(pattern_url) = Url::parse(pattern) {
                return pattern_url.scheme() == origin_url.scheme()
                    && pattern_url.host() == origin_url.host()
                    && pattern_url.port_or_known_default() == origin_url.port_or_known_default();
            }

            false
        })
    }

    /// SECURITY: Returns true only if credentials should be allowed for this origin.
    /// Per OWASP guidelines: credentials MUST NOT be allowed with wildcard origins.
    ///
    /// When Access-Control-Allow-Credentials is true, Access-Control-Allow-Origin
    /// MUST be a specific origin (never "*" or contain wildcards).
    pub fn allows_credentials(&self, origin: &str) -> bool {
        // SECURITY: Never allow credentials with global wildcard
        if self.contains_global_wildcard {
            return false;
        }

        // SECURITY: Only allow credentials for exact origin matches (not subdomain wildcards)
        let origin_url = match Url::parse(origin) {
            Ok(u) => u,
            Err(_) => return false,
        };

        self.patterns.iter().any(|pattern| {
            // SECURITY: Skip wildcard patterns for credential checks
            if pattern == "*" || pattern.contains("://*.") {
                return false;
            }

            if let Ok(pattern_url) = Url::parse(pattern) {
                return pattern_url.scheme() == origin_url.scheme()
                    && pattern_url.host() == origin_url.host()
                    && pattern_url.port_or_known_default() == origin_url.port_or_known_default();
            }

            false
        })
    }

    fn matches_subdomain_wildcard(&self, pattern: &str, origin_url: &Url) -> bool {
        // Replace wildcard with dummy subdomain for parsing
        let pattern_url = match Url::parse(&pattern.replace("*.", "wildcard.")) {
            Ok(u) => u,
            Err(_) => return false,
        };

        if pattern_url.scheme() != origin_url.scheme() {
            return false;
        }

        if pattern_url.port_or_known_default() != origin_url.port_or_known_default() {
            return false;
        }

        // Extract domain from pattern (e.g., "example.com" from "https://*.example.com")
        let pattern_domain = match pattern_url
            .host_str()
            .and_then(|h| h.strip_prefix("wildcard."))
        {
            Some(d) if !d.is_empty() => d,
            _ => return false,
        };

        // CH-068: Match the bare domain exactly OR require a dot separator before
        // the pattern domain. Without the dot check, "evilprovii.app" would
        // match a pattern for "*.provii.app".
        let origin_host = origin_url.host_str().unwrap_or("");
        if origin_host == pattern_domain {
            return true;
        }
        // Check for ".{pattern_domain}" suffix without allocating.
        // The length guard guarantees the saturating_sub index is in bounds.
        let dot_offset = origin_host
            .len()
            .saturating_sub(pattern_domain.len().saturating_add(1));
        origin_host.len() > pattern_domain.len()
            && origin_host.ends_with(pattern_domain)
            && origin_host.as_bytes().get(dot_offset) == Some(&b'.')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let origins = AllowedOrigins::new("https://example.com".to_string());
        assert!(origins.matches("https://example.com"));
        assert!(!origins.matches("https://other.com"));
        assert!(!origins.matches("http://example.com")); // Different scheme
    }

    #[test]
    fn test_global_wildcard() {
        let origins = AllowedOrigins::new("*".to_string());
        assert!(origins.matches("https://example.com"));
        assert!(origins.matches("http://anything.com"));
        assert!(!origins.allows_credentials("https://example.com")); // SECURITY: No credentials with *
    }

    #[test]
    fn test_subdomain_wildcard() {
        let origins = AllowedOrigins::new("https://*.example.com".to_string());
        assert!(origins.matches("https://app.example.com"));
        assert!(origins.matches("https://demo.example.com"));
        assert!(origins.matches("https://example.com")); // Base domain matches
        assert!(!origins.matches("https://example.org"));
        assert!(!origins.matches("http://app.example.com")); // Different scheme
        assert!(!origins.allows_credentials("https://app.example.com")); // SECURITY: No credentials with wildcard
                                                                         // CH-068: Must NOT match domains that merely end with the pattern domain
                                                                         // without a dot separator (e.g., "evilexample.com" must not match "*.example.com")
        assert!(!origins.matches("https://evilexample.com"));
    }

    #[test]
    fn test_multiple_origins() {
        let origins =
            AllowedOrigins::new("https://app.example.com,https://demo.example.org".to_string());
        assert!(origins.matches("https://app.example.com"));
        assert!(origins.matches("https://demo.example.org"));
        assert!(!origins.matches("https://other.com"));
    }

    #[test]
    fn test_credentials_only_for_exact_match() {
        let origins = AllowedOrigins::new("https://app.example.com".to_string());
        assert!(origins.allows_credentials("https://app.example.com"));
        assert!(!origins.allows_credentials("https://other.com"));
    }

    #[test]
    fn test_no_credentials_with_wildcards() {
        let wildcard_origins = AllowedOrigins::new("*".to_string());
        assert!(!wildcard_origins.allows_credentials("https://example.com"));

        let subdomain_origins = AllowedOrigins::new("https://*.example.com".to_string());
        assert!(!subdomain_origins.allows_credentials("https://app.example.com"));
    }

    #[test]
    fn test_port_matching() {
        let origins = AllowedOrigins::new("https://example.com:8080".to_string());
        assert!(origins.matches("https://example.com:8080"));
        assert!(!origins.matches("https://example.com")); // Default port 443
        assert!(!origins.matches("https://example.com:9090"));
    }

    #[test]
    fn test_invalid_origins() {
        let origins = AllowedOrigins::new("https://example.com".to_string());
        assert!(!origins.matches("not-a-url"));
        assert!(!origins.matches(""));
    }
}
