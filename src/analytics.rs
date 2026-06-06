// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Analytics helpers for emitting structured events to Cloudflare Analytics Engine.
//!
//! Provides [`Analytics`], a thin wrapper that enforces a consistent positional
//! schema across all issuer event types. Each event is written as a data point
//! with positional blobs (string fields) and doubles (numeric fields) so
//! downstream dashboards can rely on stable column ordering.
//!
//! Blob schema (positional):
//!   blob1  = event_type
//!   blob2  = route
//!   blob3  = environment ("production" or "sandbox")
//!   blob4  = issuer_id (issuer identifier or "system")
//!   blob5  = error_code (error reason or "")
//!   blob6  = auth_method ("yubikey", "hmac", "api_key", or "")
//!   blob7  = result ("ok" or "error")
//!   blob8  = slow_phases (comma-separated phase names >50ms)
//!   blob9  = key_id (signing key ID or "")
//!   blob10 = reserved (always empty)
//!
//! Double schema (positional):
//!   double1  = count (always 1.0)
//!   double2  = duration_ms (total request duration)
//!   double3  = phase1_ms
//!   double4  = phase2_ms
//!   double5  = phase3_ms
//!   double6  = phase4_ms
//!   double7  = phase5_ms
//!   double8  = phase6_ms
//!   double9  = worker_age_ms
//!   double10 = request_count
//!   double11 = phase7_ms  (overflow)
//!   double12 = phase8_ms  (overflow)
//!   double13 = phase9_ms  (overflow)
//!   double14 = phase10_ms (overflow)

use worker::{AnalyticsEngineDataPointBuilder, Env};

const BINDING: &str = "ISSUER_ANALYTICS";

/// Wrapper around the Cloudflare Analytics Engine binding that enforces
/// a consistent schema for events emitted by the issuer API.
pub struct Analytics {
    env: Env,
}

impl Analytics {
    /// Creates a new `Analytics` instance from the given worker environment.
    pub fn new(env: &Env) -> Self {
        Self { env: env.clone() }
    }

    /// Writes a single analytics event using the shared positional schema.
    ///
    /// Silently drops the event if the binding is unavailable or the write
    /// fails. Analytics must never cause a request to fail.
    #[allow(clippy::too_many_arguments)]
    fn write_event(
        &self,
        index: &str,
        event_type: &str,
        route: &str,
        environment: &str,
        issuer_id: &str,
        error_code: &str,
        auth_method: &str,
        result: &str,
        slow_phases: &str,
        key_id: &str,
        count: f64,
        duration_ms: f64,
        phases: &[f64; 6],
        worker_age_ms: f64,
        request_count: f64,
        overflow_phases: &[f64; 4],
    ) {
        let dataset = match self.env.analytics_engine(BINDING) {
            Ok(d) => d,
            Err(_) => return,
        };

        let blobs = vec![
            event_type.to_string(),  // blob1
            route.to_string(),       // blob2
            environment.to_string(), // blob3
            issuer_id.to_string(),   // blob4
            error_code.to_string(),  // blob5
            auth_method.to_string(), // blob6
            result.to_string(),      // blob7
            slow_phases.to_string(), // blob8
            key_id.to_string(),      // blob9
            String::new(),           // blob10 reserved
        ];

        let doubles = vec![
            count,              // double1
            duration_ms,        // double2
            phases[0],          // double3:  phase1_ms
            phases[1],          // double4:  phase2_ms
            phases[2],          // double5:  phase3_ms
            phases[3],          // double6:  phase4_ms
            phases[4],          // double7:  phase5_ms
            phases[5],          // double8:  phase6_ms
            worker_age_ms,      // double9
            request_count,      // double10
            overflow_phases[0], // double11: phase7_ms
            overflow_phases[1], // double12: phase8_ms
            overflow_phases[2], // double13: phase9_ms
            overflow_phases[3], // double14: phase10_ms
        ];

        let point = AnalyticsEngineDataPointBuilder::new()
            .indexes([index])
            .blobs(blobs)
            .doubles(doubles)
            .build();

        let _ = dataset.write_data_point(&point);
    }

    /// Converts a slice of named phase timings into the two fixed-size arrays
    /// expected by `write_event`: six primary phases (double3..double8) and
    /// four overflow phases (double11..double14). Phases beyond the tenth are
    /// silently dropped.
    fn phases_to_arrays(phases: &[(&str, f64)]) -> ([f64; 6], [f64; 4]) {
        let mut primary = [0.0_f64; 6];
        let mut overflow = [0.0_f64; 4];
        for (i, (_name, ms)) in phases.iter().enumerate() {
            if let Some(slot) = primary.get_mut(i) {
                *slot = *ms;
            } else if let Some(slot) = overflow.get_mut(i.saturating_sub(6)) {
                *slot = *ms;
            } else {
                break;
            }
        }
        (primary, overflow)
    }

    // ── Public event methods ───────────────────────────────────────────

    /// Records a blind issuance event (credential issuance with blinded signatures).
    #[allow(clippy::too_many_arguments)]
    pub fn blind_issuance(
        &self,
        route: &str,
        environment: &str,
        issuer_id: &str,
        duration_ms: f64,
        phases: &[(&str, f64)],
        slow_phases: &str,
        key_id: &str,
        result: &str,
        error_code: &str,
    ) {
        let (primary, overflow) = Self::phases_to_arrays(phases);
        self.write_event(
            issuer_id,
            "blind_issuance",
            route,
            environment,
            issuer_id,
            error_code,
            "",
            result,
            slow_phases,
            key_id,
            1.0,
            duration_ms,
            &primary,
            0.0,
            0.0,
            &overflow,
        );
    }

    /// Records an attestation creation event.
    #[allow(clippy::too_many_arguments)]
    pub fn attestation_created(
        &self,
        route: &str,
        environment: &str,
        issuer_id: &str,
        duration_ms: f64,
        phases: &[(&str, f64)],
        auth_method: &str,
        result: &str,
        error_code: &str,
    ) {
        let (primary, overflow) = Self::phases_to_arrays(phases);
        self.write_event(
            issuer_id,
            "attestation_created",
            route,
            environment,
            issuer_id,
            error_code,
            auth_method,
            result,
            "",
            "",
            1.0,
            duration_ms,
            &primary,
            0.0,
            0.0,
            &overflow,
        );
    }

    /// Records a cold start event with initialisation timing.
    pub fn cold_start(&self, environment: &str, init_ms: f64) {
        self.write_event(
            "cold_start",
            "cold_start",
            "",
            environment,
            "system",
            "",
            "",
            "ok",
            "",
            "",
            1.0,
            init_ms,
            &[0.0; 6],
            0.0,
            0.0,
            &[0.0; 4],
        );
    }

    /// Records a warm request event for worker lifetime tracking.
    pub fn warm_request(&self, environment: &str, worker_age_ms: f64, request_count: u64) {
        self.write_event(
            "warm_request",
            "warm_request",
            "",
            environment,
            "system",
            "",
            "",
            "ok",
            "",
            "",
            1.0,
            0.0,
            &[0.0; 6],
            worker_age_ms,
            request_count as f64,
            &[0.0; 4],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phases_to_arrays_empty_input() {
        let (primary, overflow) = Analytics::phases_to_arrays(&[]);
        assert_eq!(primary, [0.0; 6]);
        assert_eq!(overflow, [0.0; 4]);
    }

    #[test]
    fn phases_to_arrays_fills_primary_first() {
        let phases = [
            ("auth", 10.0),
            ("parse", 20.0),
            ("sign", 30.0),
            ("store", 40.0),
            ("respond", 50.0),
            ("cleanup", 60.0),
        ];
        let (primary, overflow) = Analytics::phases_to_arrays(&phases);
        assert_eq!(primary, [10.0, 20.0, 30.0, 40.0, 50.0, 60.0]);
        assert_eq!(overflow, [0.0; 4]);
    }

    #[test]
    fn phases_to_arrays_overflow_after_six() {
        let phases = [
            ("a", 1.0),
            ("b", 2.0),
            ("c", 3.0),
            ("d", 4.0),
            ("e", 5.0),
            ("f", 6.0),
            ("g", 7.0),
            ("h", 8.0),
            ("i", 9.0),
            ("j", 10.0),
        ];
        let (primary, overflow) = Analytics::phases_to_arrays(&phases);
        assert_eq!(primary, [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        assert_eq!(overflow, [7.0, 8.0, 9.0, 10.0]);
    }

    #[test]
    fn phases_to_arrays_drops_beyond_ten() {
        let phases: Vec<(&str, f64)> = (0..15).map(|i| ("x", i as f64)).collect();
        let (primary, overflow) = Analytics::phases_to_arrays(&phases);
        assert_eq!(primary, [0.0, 1.0, 2.0, 3.0, 4.0, 5.0]);
        assert_eq!(overflow, [6.0, 7.0, 8.0, 9.0]);
    }

    #[test]
    fn phases_to_arrays_partial_primary() {
        let phases = [("auth", 15.5), ("parse", 22.3)];
        let (primary, overflow) = Analytics::phases_to_arrays(&phases);
        assert_eq!(primary[0], 15.5);
        assert_eq!(primary[1], 22.3);
        assert_eq!(primary[2], 0.0);
        assert_eq!(overflow, [0.0; 4]);
    }
}
