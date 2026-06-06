// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Pure business logic for the provii-issuer Worker.
//!
//! This crate contains functions that do NOT depend on the Cloudflare Workers
//! runtime (`worker`, `js_sys`, `wasm-bindgen`). They are host-testable under
//! native `cargo test` and contribute to measured coverage.
//!
//! The Worker handler files delegate to this crate for all security-critical
//! logic that can be expressed without I/O bindings.
#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod identifier;
pub mod prefix_rejection;
pub mod rate_limiting;
pub mod redaction;
pub mod secret_fingerprint;
