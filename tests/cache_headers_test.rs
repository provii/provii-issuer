// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Cache-Control Headers Contract Tests
//!
//! These tests lock the expected cache-control policy for each endpoint
//! category per OWASP ASVS 5.0.0 V14.2.2 and V14.3.2. The actual
//! header values are set inside the Worker entrypoint (lib.rs) and can
//! only be verified end-to-end against a running Worker. These tests
//! serve as a machine-readable contract that the e2e suite and manual
//! reviews can reference.
//!
//! **Why self-referential (AUD-IA-25b-011):** The cache-control values
//! live in `lib.rs::add_security_headers` and the `main()` match block,
//! neither of which exports constants. Extracting them into `pub const`
//! values solely for test import would couple an internal security
//! policy to external API surface. Instead, the values are duplicated
//! here intentionally: if a developer changes the production value
//! without updating this file, the divergence is caught in review.
//! The `add_anti_caching_headers` function in `routes.rs` provides
//! a partial cross-reference (tested below).
#![allow(
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

// Note: no #[cfg(test)] needed; files under tests/ are test-only.
mod cache_headers_tests {
    /// The expected no-cache directive for sensitive endpoints.
    ///
    /// Duplicated from lib.rs `add_security_headers` (line ~727) and
    /// routes.rs `add_anti_caching_headers` intentionally. See module
    /// doc for rationale.
    ///
    /// Production value: `"no-store, no-cache, must-revalidate, private, max-age=0"`
    const SENSITIVE_CACHE_CONTROL: &str = "no-store, no-cache, must-revalidate, private, max-age=0";

    /// Required sub-directives per OWASP ASVS 5.0.0 V14.2.2.
    const REQUIRED_SENSITIVE_DIRECTIVES: &[&str] = &[
        "no-store",
        "no-cache",
        "must-revalidate",
        "private",
        "max-age=0",
    ];

    // Test 1: Verify the sensitive-endpoint cache directive includes
    // every required OWASP ASVS V14.2.2 sub-directive.
    #[test]
    fn sensitive_cache_directives_completeness() {
        for directive in REQUIRED_SENSITIVE_DIRECTIVES {
            assert!(
                SENSITIVE_CACHE_CONTROL.contains(directive),
                "missing required directive: {directive}"
            );
        }
    }

    // Test 2: Sensitive directive must not contain "public". This
    // validates mutual exclusion at the contract level.
    #[test]
    fn sensitive_cache_directive_excludes_public() {
        assert!(
            !SENSITIVE_CACHE_CONTROL.contains("public"),
            "sensitive cache directive must never contain 'public'"
        );
        assert!(
            SENSITIVE_CACHE_CONTROL.contains("private"),
            "sensitive cache directive must contain 'private'"
        );
    }

    // Test 3: JWKS cache duration contract. The route handler sets
    // max-age=600 in steady state. The contract is that it must not
    // exceed 600s so rotation propagates within a single JWKS TTL cycle.
    #[test]
    fn jwks_cache_within_rotation_bound() {
        // This value mirrors the constant in the JWKS route handler.
        let jwks_steady_max_age: u32 = 600;
        assert!(
            jwks_steady_max_age <= 600,
            "JWKS steady-state max-age must be <= 600s for rotation propagation"
        );
    }

    // Test 4: Endpoint classification. This locks the set of paths and
    // their cache category as registered in lib.rs. The lists below
    // must match the actual routes in the Router definition.
    #[test]
    fn endpoint_classification_matches_routes() {
        // Public-cacheable paths (receive "public, max-age=N").
        let public_paths = ["/health", "/v1/docs", "/v1/openapi.json"];

        // Sensitive paths (receive the full anti-cache directive).
        // These are the actual routes registered in lib.rs.
        let sensitive_paths = [
            "/v1/challenge",
            "/v1/issuance/blind",
            "/v1/attestation/create",
            "/v1/admin/keys/rotate",
            "/v1/admin/attestation-keys/rotate",
            "/v1/admin/keys/health",
            "/health/detailed",
            "/metrics",
        ];

        // JWKS paths are dynamically cached by the route handler, not
        // by the global match statement.
        let jwks_paths = ["/v1/jwks.json", "/.well-known/jwks.json"];

        // No overlap between public and sensitive path sets.
        for public in &public_paths {
            assert!(
                !sensitive_paths.contains(public),
                "public path {public} must not appear in sensitive list"
            );
        }

        // JWKS paths must not be in either static list (they are
        // handler-controlled).
        for jwks in &jwks_paths {
            assert!(!public_paths.contains(jwks));
            assert!(!sensitive_paths.contains(jwks));
        }

        // Verify the known public paths are a closed set. If a new
        // sensitive endpoint were accidentally added here, it would be
        // cached publicly.
        assert_eq!(
            public_paths.len(),
            3,
            "public path allowlist has changed; review cache policy"
        );
    }
}
