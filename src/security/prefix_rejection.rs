// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Sandbox-prefix rejection for the provii-issuer edge.
//!
//! The pure logic lives in `issuer_logic::prefix_rejection`. This module
//! provides the Worker-specific entry point that pulls inputs from a
//! `worker::Request` and returns a Worker `Response`.

use worker::{Env, Headers, Request, Response, Result as WorkerResult};

// Re-export the pure types so existing callers (`check_request_inputs`,
// `PrefixCheck`) resolve without changing their imports.
pub use issuer_logic::prefix_rejection::{check_request_inputs, PrefixCheck, REJECTION_BODY};

/// Build a 401 `prefix_not_permitted` response.
pub fn rejection_response() -> WorkerResult<Response> {
    let body = REJECTION_BODY.as_bytes().to_vec();
    let mut response = Response::from_bytes(body)?.with_status(401);
    let headers = response.headers_mut();
    headers.set("Content-Type", "application/json; charset=utf-8")?;
    headers.set("Cache-Control", "no-store")?;
    Ok(response)
}

/// Convenience wrapper around [`check_request_inputs`] that pulls the
/// inputs straight off a Worker `Request`, logs a structured rejection
/// event, and returns a fully-formed 401 `Response` when a sandbox
/// prefix is observed.
///
/// Production environments trigger the check. Sandbox deployments
/// (`env.var("ENVIRONMENT")? == "sandbox"`) are a no-op.
pub fn check_request(req: &Request, env: &Env) -> WorkerResult<Option<Response>> {
    let environment = env
        .var("ENVIRONMENT")
        .map(|v| v.to_string())
        .unwrap_or_default();
    if environment == "sandbox" {
        return Ok(None);
    }

    let url = match req.url() {
        Ok(u) => u,
        Err(_) => {
            return Ok(None);
        }
    };
    let path = url.path().to_string();
    let query = url.query().unwrap_or("").to_string();

    let headers = collect_header_pairs(req.headers());

    match check_request_inputs(&path, &query, headers) {
        PrefixCheck::Allow => Ok(None),
        PrefixCheck::Reject { source } => {
            let truncated_path: String = path.chars().take(120).collect();
            crate::log!(
                "[SECURITY] Sandbox-prefixed {} on production surface: path={}",
                source,
                truncated_path
            );
            rejection_response().map(Some)
        }
    }
}

/// Materialise the headers we care about into owned `(name, value)`
/// pairs. Keeping this separate from `check_request_inputs` means the
/// pure function stays Worker-agnostic and unit-testable.
fn collect_header_pairs(headers: &Headers) -> Vec<(String, String)> {
    const INSPECTED: &[&str] = &["x-client-id", "x-api-key", "authorization"];
    let mut out = Vec::with_capacity(INSPECTED.len());
    for name in INSPECTED {
        if let Ok(Some(value)) = headers.get(name) {
            out.push(((*name).to_string(), value));
        }
    }
    out
}
