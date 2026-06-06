// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! provii-issuer security controls.
//!
//! This module hosts:
//!
//!   - `client_auth`: API-key verification via Argon2id prefix index.
//!   - `docs_hmac`: docs-gateway X-Docs-Hmac envelope verification for
//!     the sandbox credential mint route. Copied from provii-verifier,
//!     pending shared-crate extraction (see TODO at the top of
//!     `docs_hmac.rs`).
//!   - `header_parsing`: RFC 9110 `Authorization: Bearer` parser shared
//!     by every Class 6 token call site (status, admin, internal
//!     service). Ported from `provii-verifier/src/security/status_auth.rs`
//!     for Class 6 rotation compliance.
//!   - `prefix_rejection`: edge-level refusal of sandbox-prefixed
//!     identifiers on production deployments (mirroring
//!     `provii-verifier/src/security/prefix_rejection.rs`).

pub mod client_auth;
pub mod docs_hmac;
pub mod header_parsing;
pub mod prefix_rejection;

// Re-export the previous single-file API so the rest of the crate and
// external consumers keep working without a rename sweep. `ClientAuthVerifier`
// and `redact_session_id` were both public items of the old `security` module.
pub use client_auth::{redact_session_id, ClientAuthVerifier};
pub use docs_hmac::{
    verify_docs_hmac, verify_or_reject_hmac_key, DocsHmacCheck, DOCS_HMAC_HEADER,
    DOCS_HMAC_REJECTION_CODE,
};
pub use header_parsing::extract_bearer_token;
pub use prefix_rejection::check_request as check_prefix_rejection;
