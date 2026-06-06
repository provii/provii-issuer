// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Security Enhancement Tests
//!
//! The `session_security` module is not yet wired into any production
//! route handler (gated out of lib.rs compilation). All tests that
//! previously lived here exercised stdlib `String::replace` and
//! `str::contains` against CRLF patterns, providing zero coverage of
//! production code. They have been removed per audit finding
//! AUD-IA-25a-001 / AUD-IA-25a-003 / ADV-IA-31-013.
//!
//! Re-enable and write meaningful tests when the `session_security`
//! module is activated in lib.rs and its functions become importable.
//!
//! When that happens, tests should:
//! - Import and call `session_security::extract_user_agent` directly
//! - Import and call `session_security::generate_secure_session_id`
//! - Validate actual production sanitisation behaviour, not reimplementations
