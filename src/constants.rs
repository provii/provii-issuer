// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Shared security constants for admin lockout policy.
//!
//! Both the partner-traffic admin surface (`routes.rs`) and the
//! rotation-drill admin surface (`internal_admin.rs`) enforce the same
//! brute-force lockout policy. These constants are the single source of
//! truth so the two surfaces cannot drift.

/// Maximum number of failed admin auth attempts before lockout.
pub(crate) const MAX_ADMIN_FAILED_ATTEMPTS: u32 = 5;

/// Duration of the admin lockout window in seconds (30 minutes).
pub(crate) const ADMIN_LOCKOUT_DURATION_SECONDS: u64 = 1800;
