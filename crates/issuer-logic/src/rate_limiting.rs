// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Pure rate-limiting helpers (no KV, no Worker runtime).
//!
//! Extracted from `rate_limiting.rs` in the Worker crate.

use std::collections::HashMap;

/// Convert a chrono timestamp (i64 seconds since epoch) to u64, clamping
/// negative values to 0.
#[inline]
pub fn timestamp_as_u64(ts: i64) -> u64 {
    u64::try_from(ts).unwrap_or(0)
}

/// Unix timestamp (seconds) at which the current rate limit window resets.
pub fn reset_timestamp() -> u64 {
    #[allow(clippy::arithmetic_side_effects)]
    // Division and multiplication by the constant 3600 cannot overflow for
    // any realistic Unix timestamp.
    let now_secs = timestamp_as_u64(chrono::Utc::now().timestamp()) / 3600 * 3600;
    now_secs.saturating_add(3600)
}

/// Parse a tier limits JSON string into a `HashMap<endpoint, limit>`.
///
/// Accepts two formats:
/// 1. Nested: `{ "limits": { "endpoint": limit }, "tier_id": "..." }`
/// 2. Flat: `{ "endpoint": limit }`
pub fn parse_tier_limits(json: &str) -> HashMap<String, u32> {
    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(json) {
        if let Some(limits) = obj.get("limits") {
            if let Ok(map) = serde_json::from_value::<HashMap<String, u32>>(limits.clone()) {
                return map;
            }
        }
    }
    // Fallback: flat { "endpoint_name": limit, ... }
    serde_json::from_str::<HashMap<String, u32>>(json).unwrap_or_default()
}

/// M3: derive the per-issuer attestation-nonce-consumption tripwire limit from
/// the blind-issuance cap.
///
/// The tripwire is set at `issuance_cap * multiplier`, where `multiplier` is
/// clamped to the `2..=3` band defined by the hardening scope. `saturating_mul`
/// keeps the product within `u32` for any input. This is a WIDER bound than the
/// authoritative issuance cap: a legitimate issuer hits the issuance cap first,
/// so the tripwire only fires on abnormal nonce-burn.
#[inline]
pub fn nonce_limit_from_issuance_cap(issuance_cap: u32, multiplier: u32) -> u32 {
    issuance_cap.saturating_mul(multiplier.clamp(2, 3))
}

/// M3: tripwire boundary check. Returns `true` when the post-increment count is
/// at or above the limit. A `limit` of `0` is treated as "disabled" (never
/// over), so a misconfiguration that zeroes the cap cannot spam advisory audit
/// events for every request.
#[inline]
pub fn nonce_over_limit(count_after_increment: u32, limit: u32) -> bool {
    limit != 0 && count_after_increment >= limit
}

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
    fn timestamp_as_u64_positive() {
        assert_eq!(timestamp_as_u64(100), 100);
    }

    #[test]
    fn timestamp_as_u64_zero() {
        assert_eq!(timestamp_as_u64(0), 0);
    }

    #[test]
    fn timestamp_as_u64_negative_clamps() {
        assert_eq!(timestamp_as_u64(-1), 0);
        assert_eq!(timestamp_as_u64(i64::MIN), 0);
    }

    #[test]
    fn timestamp_as_u64_max() {
        assert_eq!(timestamp_as_u64(i64::MAX), i64::MAX as u64);
    }

    #[test]
    fn reset_timestamp_is_future() {
        let now = timestamp_as_u64(chrono::Utc::now().timestamp());
        let reset = reset_timestamp();
        assert!(reset > now);
    }

    #[test]
    fn reset_timestamp_is_hour_aligned() {
        let reset = reset_timestamp();
        assert_eq!(reset % 3600, 0);
    }

    #[test]
    fn reset_timestamp_within_one_hour() {
        let now = timestamp_as_u64(chrono::Utc::now().timestamp());
        let reset = reset_timestamp();
        assert!(reset.saturating_sub(now) <= 3600);
    }

    #[test]
    fn parse_tier_limits_nested_format() {
        let json = r#"{"tier_id":"pro","limits":{"issue":1000,"verify":5000}}"#;
        let limits = parse_tier_limits(json);
        assert_eq!(limits.get("issue"), Some(&1000));
        assert_eq!(limits.get("verify"), Some(&5000));
    }

    #[test]
    fn parse_tier_limits_flat_format() {
        let json = r#"{"issue":500,"verify":2000}"#;
        let limits = parse_tier_limits(json);
        assert_eq!(limits.get("issue"), Some(&500));
        assert_eq!(limits.get("verify"), Some(&2000));
    }

    #[test]
    fn parse_tier_limits_invalid_json() {
        let limits = parse_tier_limits("not json at all");
        assert!(limits.is_empty());
    }

    #[test]
    fn parse_tier_limits_empty_object() {
        let limits = parse_tier_limits("{}");
        assert!(limits.is_empty());
    }

    #[test]
    fn parse_tier_limits_nested_with_extra_fields() {
        let json = r#"{"tier_id":"enterprise","name":"Enterprise","limits":{"issue":10000},"created_at":"2026-01-01"}"#;
        let limits = parse_tier_limits(json);
        assert_eq!(limits.get("issue"), Some(&10000));
        assert_eq!(limits.len(), 1);
    }

    // ---- M3: nonce-consumption tripwire helpers ------------------------------

    #[test]
    fn nonce_limit_default_multiplier_is_3x() {
        // Prod issuance cap 1000 -> tripwire 3000.
        assert_eq!(nonce_limit_from_issuance_cap(1000, 3), 3000);
        // Sandbox issuance cap 5000 -> tripwire 15000.
        assert_eq!(nonce_limit_from_issuance_cap(5000, 3), 15000);
    }

    #[test]
    fn nonce_limit_multiplier_clamped_to_2_3_band() {
        // Below the band clamps up to 2x (never below the issuance cap so the
        // tripwire stays wider than the authoritative cap).
        assert_eq!(nonce_limit_from_issuance_cap(1000, 0), 2000);
        assert_eq!(nonce_limit_from_issuance_cap(1000, 1), 2000);
        // Above the band clamps down to 3x.
        assert_eq!(nonce_limit_from_issuance_cap(1000, 4), 3000);
        assert_eq!(nonce_limit_from_issuance_cap(1000, u32::MAX), 3000);
    }

    #[test]
    fn nonce_limit_saturates_not_overflows() {
        // A huge configured cap must not panic on multiply.
        assert_eq!(nonce_limit_from_issuance_cap(u32::MAX, 3), u32::MAX);
    }

    #[test]
    fn nonce_over_limit_boundary() {
        // Exactly at the limit is over (>=), one below is not.
        assert!(!nonce_over_limit(2999, 3000));
        assert!(nonce_over_limit(3000, 3000));
        assert!(nonce_over_limit(3001, 3000));
    }

    #[test]
    fn nonce_over_limit_zero_limit_is_disabled() {
        // A zeroed cap must never report over-limit (no advisory-event spam).
        assert!(!nonce_over_limit(0, 0));
        assert!(!nonce_over_limit(1_000_000, 0));
    }
}
