// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Sec-Fetch-* header validation for defence-in-depth against CSRF and XSRF attacks.
//!
//! Validates Sec-Fetch-Site, Sec-Fetch-Mode, and Sec-Fetch-Dest headers sent by
//! modern browsers. Non-browser clients (mobile apps, API clients) that omit these
//! headers are allowed through; the protection fires only when a browser sends
//! headers that indicate a cross-site or otherwise suspicious request context.
//!
//! Two validation modes are provided:
//!
//! * **Standard** (`validate_fetch_metadata`): Used for public API routes. Missing
//!   headers are allowed (non-browser clients). `no-cors` mode is rejected because
//!   API endpoints always require CORS headers (CH-078). `navigate` mode is rejected
//!   on API routes but allowed on docs routes (which are exempted at the call site).
//!
//! * **Strict** (`validate_fetch_metadata_strict`): Used for internal service-to-service
//!   routes (e.g. `/_internal/version`). Missing headers are rejected. Only
//!   `cors` and `same-origin` modes are allowed. Returns generic errors to avoid
//!   revealing the existence of internal endpoints (CH-079). The previous
//!   `/v1/issuers/{kid}/config` and `/v1/royalty/` families were removed; royalty
//!   accounting moved to credit-management and the issuer-config lookup is no
//!   longer required by provii-verifier.
//!
//! Reference: <https://w3c.github.io/fetch-metadata/>

use crate::error::ApiError;
use crate::logging;

/// Validate Sec-Fetch-* headers for public API routes.
///
/// Call this early in request processing, before routing.
///
/// # Behaviour
///
/// * Missing headers are allowed (older browsers, non-browser clients).
/// * `Sec-Fetch-Site: cross-site` is rejected (potential CSRF).
/// * `Sec-Fetch-Mode: websocket | navigate | no-cors` is rejected.
/// * `Sec-Fetch-Dest` values other than `empty` and `document` are blocked.
///
/// # Returns
///
/// * `Ok(())` when the request should proceed.
/// * `Err(ApiError::Forbidden)` when fetch metadata indicates a disallowed context.
pub fn validate_fetch_metadata(
    headers: &worker::Headers,
    request_id: &str,
) -> Result<(), ApiError> {
    validate_sec_fetch_site(headers, request_id, false)?;
    validate_sec_fetch_mode(headers, request_id, false)?;
    validate_sec_fetch_dest(headers, request_id, false)?;
    Ok(())
}

/// Validate Sec-Fetch-* headers with strict policy for internal routes.
///
/// Unlike the standard validator, this rejects requests with missing headers
/// (browsers always send them; legitimate service-to-service callers do not
/// go through browser fetch). Returns `ApiError::Forbidden`; the caller maps
/// this to a 404 response to avoid revealing that the internal endpoint exists.
///
/// # Behaviour
///
/// * Missing headers are rejected (only server-to-server callers expected).
/// * `Sec-Fetch-Site: cross-site` is rejected.
/// * Only `cors` and `same-origin` modes are allowed.
/// * `navigate`, `no-cors`, and `websocket` are all rejected.
pub fn validate_fetch_metadata_strict(
    headers: &worker::Headers,
    request_id: &str,
) -> Result<(), ApiError> {
    validate_sec_fetch_site(headers, request_id, true)?;
    validate_sec_fetch_mode(headers, request_id, true)?;
    validate_sec_fetch_dest(headers, request_id, true)?;
    Ok(())
}

/// Reject `cross-site`; allow `same-origin`, `same-site`, `none`, or missing
/// (unless strict mode is enabled).
fn validate_sec_fetch_site(
    headers: &worker::Headers,
    request_id: &str,
    strict: bool,
) -> Result<(), ApiError> {
    match headers.get("Sec-Fetch-Site") {
        Ok(Some(site)) => match site.to_lowercase().as_str() {
            "same-origin" | "same-site" | "none" => Ok(()),
            "cross-site" => {
                logging::log_security_event(
                    "sec_fetch_site_violation",
                    logging::LogLevel::Warn,
                    Some(request_id.to_string()),
                    serde_json::json!({
                        "header": "Sec-Fetch-Site",
                        "value": site,
                        "action": "blocked",
                        "strict": strict,
                    }),
                );
                Err(ApiError::Forbidden(
                    "Cross-site requests not allowed".to_string(),
                ))
            }
            other => {
                logging::log_security_event(
                    "sec_fetch_site_violation",
                    logging::LogLevel::Warn,
                    Some(request_id.to_string()),
                    serde_json::json!({
                        "header": "Sec-Fetch-Site",
                        "value": other,
                        "action": "blocked",
                        "strict": strict,
                    }),
                );
                Err(ApiError::Forbidden(
                    "Invalid Sec-Fetch-Site value".to_string(),
                ))
            }
        },
        Ok(None) => {
            if strict {
                // CH-079: Internal routes reject missing headers. Browsers always
                // send Sec-Fetch-* headers, so a missing header on an internal route
                // is suspicious. Return Forbidden (caller maps to 404).
                logging::log_security_event(
                    "sec_fetch_missing_strict",
                    logging::LogLevel::Warn,
                    Some(request_id.to_string()),
                    serde_json::json!({
                        "header": "Sec-Fetch-Site",
                        "action": "blocked",
                    }),
                );
                Err(ApiError::Forbidden(
                    "Missing required security headers".to_string(),
                ))
            } else {
                // Missing header: non-browser client or older browser. Allow.
                Ok(())
            }
        }
        Err(_) => {
            // Header read error. Allow in standard mode, block in strict mode.
            logging::log_security_event(
                "sec_fetch_header_read_error",
                logging::LogLevel::Warn,
                Some(request_id.to_string()),
                serde_json::json!({
                    "header": "Sec-Fetch-Site",
                }),
            );
            if strict {
                Err(ApiError::Forbidden(
                    "Security header validation failed".to_string(),
                ))
            } else {
                Ok(())
            }
        }
    }
}

/// Validate Sec-Fetch-Mode.
///
/// Standard mode: reject `websocket`, `navigate`, and `no-cors`. Allow `cors`
/// and `same-origin`. Missing headers are allowed.
///
/// Strict mode: reject everything except `cors` and `same-origin`. Missing
/// headers are rejected.
///
/// CH-078: `no-cors` is now rejected on API routes. The `no-cors` mode strips
/// response headers and is used for opaque requests (e.g., `<img>` tags). API
/// endpoints always require full CORS headers, so `no-cors` is unexpected and
/// potentially indicates an attack vector (e.g., DNS rebinding with opaque
/// fetch). `navigate` is allowed only for docs routes, which are exempted from
/// Sec-Fetch validation entirely at the call site in `lib.rs`.
fn validate_sec_fetch_mode(
    headers: &worker::Headers,
    request_id: &str,
    strict: bool,
) -> Result<(), ApiError> {
    match headers.get("Sec-Fetch-Mode") {
        Ok(Some(mode)) => match mode.to_lowercase().as_str() {
            "cors" | "same-origin" => Ok(()),
            "no-cors" => {
                // CH-078: Reject no-cors on all API routes. Opaque fetch mode
                // is never legitimate for JSON API endpoints.
                logging::log_security_event(
                    "sec_fetch_mode_violation",
                    logging::LogLevel::Warn,
                    Some(request_id.to_string()),
                    serde_json::json!({
                        "header": "Sec-Fetch-Mode",
                        "value": mode,
                        "action": "blocked",
                        "strict": strict,
                    }),
                );
                Err(ApiError::Forbidden(
                    "Opaque fetch mode not allowed on API endpoints".to_string(),
                ))
            }
            "websocket" => {
                logging::log_security_event(
                    "sec_fetch_mode_violation",
                    logging::LogLevel::Warn,
                    Some(request_id.to_string()),
                    serde_json::json!({
                        "header": "Sec-Fetch-Mode",
                        "value": mode,
                        "action": "blocked",
                        "strict": strict,
                    }),
                );
                Err(ApiError::Forbidden(
                    "WebSocket requests not allowed".to_string(),
                ))
            }
            "navigate" => {
                logging::log_security_event(
                    "sec_fetch_mode_violation",
                    logging::LogLevel::Warn,
                    Some(request_id.to_string()),
                    serde_json::json!({
                        "header": "Sec-Fetch-Mode",
                        "value": mode,
                        "action": "blocked",
                        "strict": strict,
                    }),
                );
                Err(ApiError::Forbidden(
                    "Navigation requests not allowed on API endpoints".to_string(),
                ))
            }
            other => {
                logging::log_security_event(
                    "sec_fetch_mode_violation",
                    logging::LogLevel::Warn,
                    Some(request_id.to_string()),
                    serde_json::json!({
                        "header": "Sec-Fetch-Mode",
                        "value": other,
                        "action": "blocked",
                        "strict": strict,
                    }),
                );
                Err(ApiError::Forbidden(
                    "Invalid Sec-Fetch-Mode value".to_string(),
                ))
            }
        },
        Ok(None) => {
            if strict {
                logging::log_security_event(
                    "sec_fetch_missing_strict",
                    logging::LogLevel::Warn,
                    Some(request_id.to_string()),
                    serde_json::json!({
                        "header": "Sec-Fetch-Mode",
                        "action": "blocked",
                    }),
                );
                Err(ApiError::Forbidden(
                    "Missing required security headers".to_string(),
                ))
            } else {
                Ok(())
            }
        }
        Err(_) => {
            logging::log_security_event(
                "sec_fetch_header_read_error",
                logging::LogLevel::Warn,
                Some(request_id.to_string()),
                serde_json::json!({
                    "header": "Sec-Fetch-Mode",
                }),
            );
            if strict {
                Err(ApiError::Forbidden(
                    "Security header validation failed".to_string(),
                ))
            } else {
                Ok(())
            }
        }
    }
}

/// Validate Sec-Fetch-Dest header.
///
/// Standard mode: allow `empty` and `document`. Reject all other values.
/// Missing headers are allowed (non-browser clients).
///
/// Strict mode: reject missing headers and only allow `empty`.
fn validate_sec_fetch_dest(
    headers: &worker::Headers,
    request_id: &str,
    strict: bool,
) -> Result<(), ApiError> {
    match headers.get("Sec-Fetch-Dest") {
        Ok(Some(dest)) => {
            let lower = dest.to_lowercase();
            let allowed = if strict {
                // Strict: only "empty" is valid for service-to-service API calls
                lower == "empty"
            } else {
                // Standard: "empty" (fetch/XHR) and "document" (navigation) are valid
                lower == "empty" || lower == "document"
            };
            if allowed {
                Ok(())
            } else {
                logging::log_security_event(
                    "sec_fetch_dest_violation",
                    logging::LogLevel::Warn,
                    Some(request_id.to_string()),
                    serde_json::json!({
                        "header": "Sec-Fetch-Dest",
                        "value": dest,
                        "action": "blocked",
                        "strict": strict,
                    }),
                );
                Err(ApiError::Forbidden(
                    "Invalid Sec-Fetch-Dest value".to_string(),
                ))
            }
        }
        Ok(None) => {
            if strict {
                logging::log_security_event(
                    "sec_fetch_missing_strict",
                    logging::LogLevel::Warn,
                    Some(request_id.to_string()),
                    serde_json::json!({
                        "header": "Sec-Fetch-Dest",
                        "action": "blocked",
                    }),
                );
                Err(ApiError::Forbidden(
                    "Missing required security headers".to_string(),
                ))
            } else {
                Ok(())
            }
        }
        Err(_) => {
            logging::log_security_event(
                "sec_fetch_header_read_error",
                logging::LogLevel::Warn,
                Some(request_id.to_string()),
                serde_json::json!({
                    "header": "Sec-Fetch-Dest",
                }),
            );
            if strict {
                Err(ApiError::Forbidden(
                    "Security header validation failed".to_string(),
                ))
            } else {
                Ok(())
            }
        }
    }
}

// Unit tests are limited because all validation functions require `worker::Headers`
// which is only available on the wasm32 target (Cloudflare Workers runtime).
// Integration-level tests covering Sec-Fetch validation are exercised via
// wrangler dev / miniflare in the CI pipeline.
