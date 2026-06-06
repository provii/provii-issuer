// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Cloudflare Worker entrypoint for the issuer service.
#![recursion_limit = "512"]
#![forbid(unsafe_code)]

use crate::error::ApiError;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use worker::*;

// Thread-local storage for the worker `Context`, used to schedule fire-and-forget
// background work via `ctx.wait_until()`. Workers are single-threaded, so a
// `RefCell` is sufficient. The context is set at the start of each request in
// `main` (before `router.run`) and consumed (taken) by handlers that need
// background dispatch. Ported verbatim from provii-verifier/src/lib.rs (R8).
thread_local! {
    static WORKER_CTX: RefCell<Option<worker::Context>> = const { RefCell::new(None) };
}

/// Store the worker `Context` for the current request so route handlers can
/// schedule background work via `wait_until()`.
pub fn set_worker_context(ctx: worker::Context) {
    WORKER_CTX.with(|cell| {
        *cell.borrow_mut() = Some(ctx);
    });
}

/// Take the stored worker `Context`, leaving `None` in its place. Returns
/// `None` if no context has been set or it was already consumed. This is
/// single-shot per request: only the first taker receives the context, so
/// every call site MUST provide an inline fallback when `None` is returned.
pub fn take_worker_context() -> Option<worker::Context> {
    WORKER_CTX.with(|cell| cell.borrow_mut().take())
}

// Cold start detection and performance monitoring.
//
// These statics track worker instance lifecycle. A "cold start" occurs when
// Cloudflare spins up a new isolate. Cold starts are expensive due to WASM
// compilation, crypto library initialisation, Secrets Store fetches, and KV
// binding resolution.

/// Whether this worker instance has handled its first request.
/// `false` indicates a cold start. `true` indicates warm.
static WORKER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Timestamp (ms since epoch) when this worker instance was first initialised.
static WORKER_INIT_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

/// Counter for total requests handled by this worker instance.
static WORKER_REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);

/// Returns true if this is the first request to this worker instance (cold start).
/// After the first call, subsequent calls return false.
fn is_cold_start() -> bool {
    !WORKER_INITIALIZED.swap(true, Ordering::AcqRel)
}

/// Records the worker initialisation timestamp. Call once during cold start.
fn record_worker_init_time(now_ms: f64) {
    WORKER_INIT_TIMESTAMP.store(f64_to_u64(now_ms), Ordering::Release);
}

/// Returns the timestamp when this worker instance was initialised.
fn get_worker_init_timestamp() -> u64 {
    WORKER_INIT_TIMESTAMP.load(Ordering::Acquire)
}

/// Increments and returns the request count for this worker instance.
fn increment_request_count() -> u64 {
    #[allow(clippy::arithmetic_side_effects)]
    // SAFETY RATIONALE: AtomicU64::fetch_add wraps on overflow, which is
    // acceptable for a request counter. The subsequent + 1 cannot overflow
    // because fetch_add returns the *previous* value; u64::MAX + 1 wraps to
    // 0, and we add 1 via saturating_add.
    WORKER_REQUEST_COUNT
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1)
}

/// Convert an f64 (e.g. from `js_sys::Date::now()`) to u64, clamping
/// negative and NaN values to 0 and values above `u64::MAX` to `u64::MAX`.
#[inline]
fn f64_to_u64(v: f64) -> u64 {
    if v.is_nan() || v < 0.0 {
        0
    } else if v > u64::MAX as f64 {
        u64::MAX
    } else {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let r = v as u64;
        r
    }
}

/// Compute the elapsed milliseconds between `start` and the current
/// `js_sys::Date::now()` value, returning the result as `u64`.
#[inline]
fn elapsed_ms(start: f64) -> u64 {
    #[allow(clippy::arithmetic_side_effects)]
    let diff = js_sys::Date::now() - start;
    f64_to_u64(diff)
}

/// Conditional console_log macro that works on both wasm32 and native targets.
/// On wasm32, uses worker::console_log! which calls JavaScript console.log.
/// On native targets (for tests), uses eprintln! for output.
#[cfg(target_arch = "wasm32")]
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        worker::console_log!($($arg)*)
    };
}

#[cfg(not(target_arch = "wasm32"))]
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        eprintln!($($arg)*)
    };
}

/// Conditional console_error macro that works on both wasm32 and native targets.
/// On wasm32, uses worker::console_error! which calls JavaScript console.error.
/// On native targets (for tests), uses eprintln! for output.
#[cfg(target_arch = "wasm32")]
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        worker::console_error!($($arg)*)
    };
}

#[cfg(not(target_arch = "wasm32"))]
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        eprintln!("[ERROR] {}", format!($($arg)*))
    };
}

pub mod analytics;
pub mod audit;
mod bindings;
pub(crate) mod constants;
mod cors;
pub mod crypto;
pub mod durable_objects;
pub use durable_objects::NonceDO;
pub use durable_objects::ResourceLockDO;
pub mod error;
mod fetch_metadata;
pub(crate) mod hash;
mod health;
/// Rotation-drill admin endpoints (`/_internal/replay-saved-pre-rotation-token`,
/// `/_internal/test-fixtures` GET + DELETE). Backs the verify-rotation
/// soak checks and the cleanup-test-fixtures CLI.
mod internal_admin;
mod internal_version;
pub mod kek;
pub mod key_rotation;
pub mod logging;
mod openapi;
pub mod rate_limiting;
pub(crate) mod resource_lock;
mod routes;
mod routes_sandbox_cred;
pub(crate) mod secret_cache;
pub mod secret_fingerprint;
pub mod security;
pub mod session;
// session_security: not yet wired into any production route handler.
// The module exists for future session management (CSPRNG IDs, client
// binding, concurrent session limits, session data encryption). Kept on
// disk but gated out of the build to avoid dead-code surface area.
// pub mod session_security;
pub mod ssrf_protection;
pub(crate) mod storage;
pub mod types;
pub mod validation;

/// Generate a cryptographically secure CSP nonce for inline scripts.
///
/// Returns a base64-encoded 16-byte (128-bit) random value suitable for
/// `script-src 'nonce-...'` and `style-src 'nonce-...'` CSP directives.
///
/// If the CSPRNG fails (should never happen on Cloudflare Workers), returns a
/// fixed nonce that will not match any inline script, causing the browser to
/// block all inline execution. This is fail-safe: no scripts run rather than
/// all scripts running.
fn generate_csp_nonce() -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        // CSPRNG failure is unrecoverable. Return None so the caller
        // can surface a 500 instead of serving a page with a predictable nonce.
        return String::new();
    }
    STANDARD.encode(bytes)
}

/// Apply baseline security headers to a response. Used for early-return error
/// paths (413, 411, 415, 403, 429, 503) that fire before the full
/// `add_security_headers` closure is available (CH-076).
///
/// This does NOT include CORS headers. Callers that need CORS on pre-routing
/// error responses (e.g. rate limit 429) should follow up with
/// `add_cors_headers_early`. Covers all defensive headers that
/// browsers rely on: HSTS, CSP, X-Content-Type-Options, etc.
fn add_base_security_headers(resp: &mut Response, request_id: &str, req_path: &str) -> Result<()> {
    let headers = resp.headers_mut();

    headers.set("X-Request-ID", request_id)?;
    headers.set("X-Content-Type-Options", "nosniff")?;
    headers.set("X-Frame-Options", "DENY")?;
    headers.set("Referrer-Policy", "strict-origin-when-cross-origin")?;
    headers.set(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains; preload",
    )?;
    headers.set(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; upgrade-insecure-requests",
    )?;
    headers.set(
        "Permissions-Policy",
        "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), \
         camera=(), cross-origin-isolated=(), display-capture=(), \
         document-domain=(), encrypted-media=(), execution-while-not-rendered=(), \
         execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), \
         gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), \
         midi=(), navigation-override=(), payment=(), picture-in-picture=(), \
         publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), \
         usb=(), web-share=(), xr-spatial-tracking=()",
    )?;
    headers.set("Cross-Origin-Embedder-Policy", "require-corp")?;
    headers.set("Cross-Origin-Opener-Policy", "same-origin")?;
    headers.set("Cross-Origin-Resource-Policy", "same-origin")?;
    headers.set("X-Permitted-Cross-Domain-Policies", "none")?;

    // Anti-caching on error responses
    if !matches!(
        req_path,
        "/health" | "/v1/jwks.json" | "/.well-known/jwks.json" | "/v1/docs" | "/v1/openapi.json"
    ) {
        headers.set(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, private, max-age=0",
        )?;
        headers.set("Pragma", "no-cache")?;
        headers.set("Expires", "0")?;
    }

    Ok(())
}

/// Apply CORS headers to an early-return error response (pre-routing).
///
/// Mirrors the CORS logic in the post-routing `add_security_headers` closure so
/// that browsers making cross-origin requests can read pre-routing error
/// responses (429, 503) instead of seeing an opaque CORS failure.
///
/// Only applies headers when the request targets a `/v1/` or
/// `/.well-known/jwks.json` path with a non-empty, allowlisted Origin.
/// Internal routes are excluded, matching the post-routing behaviour.
fn add_cors_headers_early(
    resp: &mut Response,
    req_path: &str,
    request_origin: &str,
    allowed_origins: &cors::AllowedOrigins,
) -> Result<()> {
    let is_internal = req_path.starts_with("/_internal/");
    if is_internal {
        return Ok(());
    }
    if !(req_path.starts_with("/v1/") || req_path == "/.well-known/jwks.json") {
        return Ok(());
    }
    if request_origin.is_empty() {
        return Ok(());
    }
    if !allowed_origins.matches(request_origin) {
        return Ok(());
    }

    let headers = resp.headers_mut();
    headers.set("Access-Control-Allow-Origin", request_origin)?;
    headers.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")?;
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")?;
    headers.set("Vary", "Origin")?;

    if allowed_origins.allows_credentials(request_origin) {
        headers.set("Access-Control-Allow-Credentials", "true")?;
    }

    Ok(())
}

/// Defence in depth for `/_internal/*` routes.
///
/// Service-binding traffic from sibling Workers reaches the dispatcher
/// without `CF-Connecting-IP`. Public-internet traffic always carries
/// the header (the Cloudflare edge sets it). Rejecting any request that
/// presents the header blocks an external attacker who possesses a valid
/// internal bearer token from reaching the surface, even before the
/// existing dual-slot `INTERNAL_VERSION_SERVICE_TOKEN` auth runs.
///
/// Returns `Some(401_response)` when external traffic is detected; the
/// caller forwards the response unchanged. Returns `None` when the
/// request looks like service-binding traffic and the existing auth
/// path should run.
///
/// The check applies in both production and sandbox: the `/_internal/*`
/// surface is service-binding-only in every environment, so an external
/// connecting-IP is unauthorised regardless of `ENVIRONMENT`. Mirrors
/// the provii-audit-consumer `internal_version_unauthorised` rejection
/// log shape so the SIEM can pivot across Workers on one event name.
fn reject_external_internal_traffic(headers: &Headers, role_tag: &str) -> Option<Response> {
    let connecting_ip = headers
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .unwrap_or_default();
    if connecting_ip.is_empty() {
        return None;
    }
    logging::log_security_event(
        "internal_route_unauthorised",
        logging::LogLevel::Warn,
        None,
        serde_json::json!({
            "service": "provii-issuer",
            "role_tag": role_tag,
            "reason": "external_traffic",
        }),
    );
    // Build the 401 response inline. ApiError::Unauthorized pulls the
    // standard sanitised body shape. If the response builder itself
    // fails we fall through to a static 401; the failure path is
    // unreachable on the live worker target.
    match ApiError::Unauthorized("Unauthorized".into()).to_response() {
        Ok(r) => Some(r),
        Err(_) => Response::error("Unauthorized", 401).ok(),
    }
}

#[event(fetch)]
/// Wire up the HTTP router and attach security headers for every response.
pub async fn main(req: Request, env: Env, ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    // R8: store the worker Context in a thread-local so reject-path audit emits
    // (and any handler reached via router.run) can offload best-effort audit
    // writes to ctx.wait_until(), returning the 4xx/429 before the AUDIT_QUEUE
    // send round-trip. Single-shot: every taker MUST keep an inline fallback.
    set_worker_context(ctx);

    // Capture request start time for response duration logging.
    // js_sys::Date::now() returns milliseconds since epoch as f64.
    let start_ms = js_sys::Date::now();

    // Cold start detection and request counting
    let is_cold = is_cold_start();
    let request_num = increment_request_count();

    if is_cold {
        record_worker_init_time(start_ms);
    }

    // Generate unique request ID for correlation
    let request_id = uuid::Uuid::new_v4().to_string();
    let request_id_for_error = request_id.clone(); // Clone for error handler

    let req_path = req.path();
    let req_method = req.method();

    logging::log_request(req_method.as_ref(), &req_path, &request_id);

    // Global body size limit: reject requests over 1 MB before routing (P2-15).
    // IV-208: Require Content-Length on mutating methods to prevent chunked
    // transfer encoding from bypassing the size check entirely. Cloudflare's
    // edge always sets Content-Length for buffered bodies, but we enforce the
    // header as a defence in depth measure.
    const MAX_BODY_SIZE: u64 = 1_048_576;
    if matches!(
        req_method,
        worker::Method::Post | worker::Method::Put | worker::Method::Patch
    ) {
        match req.headers().get("Content-Length").ok().flatten() {
            Some(len) => {
                match len.parse::<u64>() {
                    Ok(size) if size > MAX_BODY_SIZE => {
                        let mut resp =
                            ApiError::PayloadTooLarge("Request body too large".to_string())
                                .to_response()
                                .map_err(|_| {
                                    worker::Error::RustError("Internal server error".to_string())
                                })?;
                        add_base_security_headers(&mut resp, &request_id, &req_path)?;
                        let duration_ms = elapsed_ms(start_ms);
                        logging::log_response(resp.status_code(), &request_id, Some(duration_ms));
                        return Ok(resp);
                    }
                    Ok(_) => { /* valid Content-Length within limit */ }
                    Err(_) => {
                        // Content-Length header present but not a valid
                        // integer. Reject with 400 to prevent bypassing body
                        // size enforcement.
                        let mut resp = ApiError::BadRequest("Invalid request format".to_string())
                            .to_response()
                            .map_err(|_| {
                                worker::Error::RustError("Internal server error".to_string())
                            })?;
                        add_base_security_headers(&mut resp, &request_id, &req_path)?;
                        let duration_ms = elapsed_ms(start_ms);
                        logging::log_response(resp.status_code(), &request_id, Some(duration_ms));
                        return Ok(resp);
                    }
                }
            }
            None => {
                // IV-208: Missing Content-Length on a mutating request. Reject
                // with 411 Length Required to prevent unbounded body reads.
                let mut resp =
                    ApiError::LengthRequired("Content-Length header is required".to_string())
                        .to_response()
                        .map_err(|_| {
                            worker::Error::RustError("Internal server error".to_string())
                        })?;
                add_base_security_headers(&mut resp, &request_id, &req_path)?;
                let duration_ms = elapsed_ms(start_ms);
                logging::log_response(resp.status_code(), &request_id, Some(duration_ms));
                return Ok(resp);
            }
        }

        // IV-209, IV-202: Enforce Content-Type: application/json on mutating
        // requests. Reject non-JSON content types with 415 Unsupported Media
        // Type. This prevents form-encoded or multipart payloads from reaching
        // route handlers that expect JSON.
        let content_type = req
            .headers()
            .get("Content-Type")
            .ok()
            .flatten()
            .unwrap_or_default();
        if !content_type
            .to_ascii_lowercase()
            .starts_with("application/json")
        {
            let mut resp =
                ApiError::UnsupportedMediaType("Content-Type must be application/json".into())
                    .to_response()
                    .map_err(|_| worker::Error::RustError("Internal server error".to_string()))?;
            add_base_security_headers(&mut resp, &request_id, &req_path)?;
            let duration_ms = elapsed_ms(start_ms);
            logging::log_response(resp.status_code(), &request_id, Some(duration_ms));
            return Ok(resp);
        }
    }

    // Parse allowed CORS origins and the request Origin header early so they
    // are available for pre-routing error responses (rate limit 429, fail-closed
    // 503) as well as the post-routing add_security_headers closure. Without
    // CORS headers on pre-routing rejections, browsers cannot distinguish a 429
    // from a network error on cross-origin requests.
    let allowed_origins_str = env
        .var("ALLOWED_ORIGINS")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| {
            log_error!("ALLOWED_ORIGINS not set; using hardcoded fallback. Configure in wrangler.toml [vars].");
            "https://playground.provii.app,https://app.provii.app".to_string()
        });
    let allowed_origins = cors::AllowedOrigins::new(allowed_origins_str);

    let request_origin = req
        .headers()
        .get("Origin")
        .ok()
        .flatten()
        .unwrap_or_default();

    // Reject sandbox-prefixed identifiers on production.
    // Runs before rate-limiting so that probing with sandbox credentials
    // does not consume the per-IP budget. In sandbox this is a no-op.
    // Mirrors provii-verifier and provii-management prefix rejection so all
    // services reject the same identifier shapes with the same body.
    match crate::security::check_prefix_rejection(&req, &env) {
        Ok(Some(mut resp)) => {
            add_base_security_headers(&mut resp, &request_id, &req_path)?;
            let duration_ms = elapsed_ms(start_ms);
            logging::log_response(resp.status_code(), &request_id, Some(duration_ms));
            return Ok(resp);
        }
        Ok(None) => {}
        Err(e) => {
            // Response construction failed (OOM on the Workers runtime).
            // Let the existing router 500 paths surface the error rather
            // than emit a misleading 401.
            log_error!(
                "[SECURITY] prefix rejection check failed to construct response: {:?}",
                e
            );
        }
    }

    // Global per-IP rate limit. POST/PUT/PATCH: 120/hour.
    // GET: 600/hour (5x multiplier). Placed after Content-Type validation but
    // before Sec-Fetch checks. Uses check_blind_issuance() with the IP as key.
    // Fails closed when KV is unavailable. GET endpoints have their own
    // (higher) rate limit to prevent resource exhaustion.
    {
        let is_mutating = matches!(
            req_method,
            worker::Method::Post | worker::Method::Put | worker::Method::Patch
        );
        // 120/hour for mutating requests, 600/hour for GET.
        // R10: config-driven via env vars with UNCHANGED prod defaults. A
        // fat-fingered 0 (or non-positive) falls back to the default via
        // filter(|v| *v >= 1), mirroring the R5 clamp pattern, so the cap can
        // never be relaxed to a deny-first-request (count>=0) or fail-open
        // value through misconfiguration.
        let ip_rate_limit: u32 = if is_mutating {
            env.var("GLOBAL_IP_MUTATING_LIMIT_PER_HOUR")
                .ok()
                .and_then(|v| v.to_string().parse::<u32>().ok())
                .filter(|v| *v >= 1)
                .unwrap_or(120)
        } else {
            env.var("GLOBAL_IP_GET_LIMIT_PER_HOUR")
                .ok()
                .and_then(|v| v.to_string().parse::<u32>().ok())
                .filter(|v| *v >= 1)
                .unwrap_or(600)
        };
        let rate_key_prefix = if is_mutating {
            "global_post"
        } else {
            "global_get"
        };
        // CF-Connecting-IP is always present on requests reaching
        // Cloudflare Workers through the standard Cloudflare proxy. The only
        // scenario where it is absent is direct Worker invocation via service
        // bindings (server-to-server), which bypass the global IP rate limiter
        // anyway. The "unknown" fallback is a defensive default; in practice it
        // is never reached for external traffic. If it were, all such requests
        // would share a single rate limit bucket, which is fail-safe (over-
        // limiting rather than under-limiting).
        let rate_limit_ip = req
            .headers()
            .get("CF-Connecting-IP")
            .ok()
            .flatten()
            .unwrap_or_else(|| "unknown".to_string());
        // Hash the IP before using it in the KV key so plaintext
        // addresses are never stored as KV key names.
        let privacy_ctx = crate::audit::build_privacy_context(&env).await;
        let hashed_rate_ip = privacy_ctx.hash_ip(&rate_limit_ip).unwrap_or_default();
        let rate_key = format!("{}:{}", rate_key_prefix, hashed_rate_ip);
        match env.kv("ISSUER_RATE_LIMITS") {
            Ok(rl_kv) => {
                let rl =
                    rate_limiting::check_blind_issuance(&rl_kv, &rate_key, ip_rate_limit).await;
                if !rl.allowed {
                    log!(
                        "[RateLimit] Global IP rate limit exceeded for ip_hash={}",
                        hashed_rate_ip
                    );
                    // R8: offload the best-effort audit emit to wait_until so
                    // the 429/503 returns before the AUDIT_QUEUE send. The
                    // closure is 'static, so clone env and own every captured
                    // string. Inline fallback is MANDATORY because
                    // take_worker_context is single-shot (only the first taker
                    // per request gets the context). audit_log is best-effort
                    // (errors swallowed) so this cannot turn into a 5xx.
                    {
                        let audit_env = env.clone();
                        let audit_ip = rate_limit_ip.clone();
                        let audit_request_id = request_id.clone();
                        let audit_path = req_path.clone();
                        let audit_count = rl.current_count;
                        let audit_limit = rl.limit;
                        let emit = move |env: Env, ip: String, request_id: String, path: String| async move {
                            crate::audit::audit_log(
                                &env,
                                "global_ip_rate_limit",
                                &ip,
                                "Global per-IP rate limit exceeded",
                                &serde_json::json!({
                                    "request_id": request_id,
                                    "path": path,
                                    "count": audit_count,
                                    "limit": audit_limit,
                                }),
                            )
                            .await;
                        };
                        if let Some(ctx) = crate::take_worker_context() {
                            ctx.wait_until(emit(audit_env, audit_ip, audit_request_id, audit_path));
                        } else {
                            emit(audit_env, audit_ip, audit_request_id, audit_path).await;
                        }
                    }
                    let mut resp = rate_limiting::rate_limit_or_unavailable_response(&rl)?;
                    add_base_security_headers(&mut resp, &request_id, &req_path)?;
                    add_cors_headers_early(
                        &mut resp,
                        &req_path,
                        &request_origin,
                        &allowed_origins,
                    )?;
                    let duration_ms = elapsed_ms(start_ms);
                    logging::log_response(resp.status_code(), &request_id, Some(duration_ms));
                    return Ok(resp);
                }
            }
            Err(e) => {
                // Fail closed. This is the only pre-auth defence against
                // volumetric abuse; allowing requests through when KV is down
                // defeats the rate limiter entirely.
                log!(
                    "[RateLimit] ISSUER_RATE_LIMITS KV unavailable for global IP check, rejecting (fail-closed): {:?}",
                    e
                );
                let mut resp =
                    ApiError::ServiceUnavailable("Rate limiting infrastructure unavailable".into())
                        .to_response()?;
                add_base_security_headers(&mut resp, &request_id, &req_path)?;
                add_cors_headers_early(&mut resp, &req_path, &request_origin, &allowed_origins)?;
                let duration_ms = elapsed_ms(start_ms);
                logging::log_response(resp.status_code(), &request_id, Some(duration_ms));
                return Ok(resp);
            }
        }
    }

    // Sec-Fetch-* validation: block cross-site / websocket / navigate requests from browsers.
    // Must run before routing so that violations never reach business logic.
    // Exempt /v1/docs (browser navigation expected) and /v1/openapi.json (P2-13).
    let is_docs_route = matches!(req_path.as_str(), "/v1/docs" | "/v1/openapi.json");
    // `/_internal/version` is an internal-only
    // route. Strict Sec-Fetch validation rejects missing headers, no CORS
    // is applied, and Sec-Fetch rejection returns 404 so the existence of
    // the route is not advertised to unauthenticated callers.
    //
    // Service binding traffic from other Cloudflare Workers
    // includes Sec-Fetch-Site: same-origin and Sec-Fetch-Mode: cors, so
    // strict validation does not block server-to-server calls routed
    // through the Workers runtime.
    let is_internal_route = req_path.starts_with("/_internal/");
    if let Err(e) = if is_docs_route {
        Ok(())
    } else if is_internal_route {
        fetch_metadata::validate_fetch_metadata_strict(req.headers(), &request_id)
    } else {
        fetch_metadata::validate_fetch_metadata(req.headers(), &request_id)
    } {
        // Persist Sec-Fetch-* rejection to durable audit trail (the console
        // log inside fetch_metadata.rs alone is ephemeral).
        crate::audit::audit_log(
            &env,
            "fetch_metadata_rejected",
            &req.headers()
                .get("CF-Connecting-IP")
                .ok()
                .flatten()
                .unwrap_or_else(|| "unknown".to_string()),
            "Request blocked by Sec-Fetch-* policy",
            &serde_json::json!({
                "request_id": request_id,
                "path": req_path,
                "error": e.to_string(),
            }),
        )
        .await;
        // For internal routes, return 404 to avoid revealing endpoint existence.
        let mut resp = if is_internal_route {
            ApiError::NotFound("Not Found".to_string()).to_response()?
        } else {
            e.to_response()?
        };
        add_base_security_headers(&mut resp, &request_id, &req_path)?;
        let duration_ms = elapsed_ms(start_ms);
        logging::log_response(resp.status_code(), &request_id, Some(duration_ms));
        return Ok(resp);
    }

    // CH-074: Generate CSP nonce for docs page (replace 'unsafe-inline' with nonce-based CSP).
    // The nonce is generated once and shared between the HTML template (via docs_nonce_for_html)
    // and the CSP header (via csp_nonce). Both must match for the browser to allow execution.
    let csp_nonce = if req_path == "/v1/docs" {
        let nonce = generate_csp_nonce();
        // If CSPRNG failed, generate_csp_nonce returns an empty string.
        // Return 500 rather than serving the page with a predictable nonce.
        if nonce.is_empty() {
            crate::log_error!("CSPRNG failure: cannot generate CSP nonce");
            let mut resp = ApiError::Internal("Internal server error".into())
                .to_response()
                .map_err(|_| worker::Error::RustError("Internal server error".to_string()))?;
            add_base_security_headers(&mut resp, &request_id, &req_path)?;
            let duration_ms = elapsed_ms(start_ms);
            logging::log_response(resp.status_code(), &request_id, Some(duration_ms));
            return Ok(resp);
        }
        Some(nonce)
    } else {
        None
    };
    let docs_nonce_for_html = csp_nonce.clone();

    let add_security_headers = |mut resp: Response| -> Result<Response> {
        let headers = resp.headers_mut();

        // Request tracking
        headers.set("X-Request-ID", &request_id)?;

        // SECURITY: X-API-Version header removed to prevent server fingerprinting.
        // API version is available at /v1/openapi.json for legitimate consumers.

        // Security headers
        headers.set("X-Content-Type-Options", "nosniff")?;
        headers.set("X-Frame-Options", "DENY")?;
        // CH-072: X-XSS-Protection removed. The header is deprecated and can
        // introduce XSS vulnerabilities in older browsers via its block-mode
        // behaviour. Modern browsers ignore it entirely. CSP is the correct
        // mitigation.

        // CH-071: strict-origin-when-cross-origin is the recommended default for
        // API services that may be embedded in cross-origin flows (wallet deep
        // links, CORS preflight). no-referrer breaks legitimate Referer-based
        // logging and analytics without meaningfully improving security given
        // that all traffic is HTTPS with HSTS.
        headers.set("Referrer-Policy", "strict-origin-when-cross-origin")?;

        headers.set(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload",
        )?;

        // Content-Security-Policy (OWASP ASVS Level 3)
        // Strict CSP to prevent XSS attacks and unauthorised resource loading
        let csp = if let Some(ref nonce) = csp_nonce {
            // CH-074: Nonce-based CSP for Swagger UI (replaces 'unsafe-inline')
            // OWASP ASVS 5.0.0 V3 Level 2: Subresource Integrity enabled
            // SRI hashes ensure CDN resources haven't been tampered with
            format!(
                "default-src 'none'; \
                 script-src 'nonce-{}' https://cdn.jsdelivr.net; \
                 style-src 'nonce-{}' https://cdn.jsdelivr.net; \
                 img-src 'self' data: https://cdn.jsdelivr.net; \
                 font-src https://cdn.jsdelivr.net; \
                 connect-src 'self'; \
                 frame-ancestors 'none'; \
                 base-uri 'self'; \
                 form-action 'none'; \
                 upgrade-insecure-requests",
                nonce, nonce
            )
        } else {
            // Strict CSP for API endpoints (no inline scripts, no external resources)
            "default-src 'none'; \
             frame-ancestors 'none'; \
             base-uri 'none'; \
             form-action 'none'; \
             upgrade-insecure-requests"
                .to_string()
        };
        headers.set("Content-Security-Policy", &csp)?;

        // Strict Permissions-Policy (OWASP ASVS recommendation)
        // Disable all sensitive browser features to minimise attack surface
        headers.set(
            "Permissions-Policy",
            "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), \
             camera=(), cross-origin-isolated=(), display-capture=(), \
             document-domain=(), encrypted-media=(), execution-while-not-rendered=(), \
             execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), \
             gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), \
             midi=(), navigation-override=(), payment=(), picture-in-picture=(), \
             publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), \
             usb=(), web-share=(), xr-spatial-tracking=()",
        )?;
        headers.set("Cross-Origin-Embedder-Policy", "require-corp")?;
        headers.set("Cross-Origin-Opener-Policy", "same-origin")?;
        headers.set("Cross-Origin-Resource-Policy", "same-origin")?;
        headers.set("X-Permitted-Cross-Domain-Policies", "none")?;

        // OWASP ASVS 5.0.0 V14.2.2, V14.3.2: Cache-Control Headers
        // Prevent sensitive data from being cached by browsers or proxies
        // Endpoint-specific caching policies:
        // - Public endpoints (/health, /v1/docs) allow caching
        // - JWKS cache is controlled by the route handler (P3-17: dynamic after rotation)
        // - All credential/session/proof endpoints enforce no-cache
        let cache_control = match req_path.as_str() {
            "/health" => Some("public, max-age=30"),
            // P3-17: JWKS Cache-Control is set by the route handler itself,
            // which dynamically chooses no-cache after key rotation or
            // max-age=600 otherwise. Do not override here.
            "/v1/jwks.json" | "/.well-known/jwks.json" => None,
            "/v1/docs" => Some("public, max-age=3600"),
            "/v1/openapi.json" => Some("public, max-age=3600"),
            _ => Some("no-store, no-cache, must-revalidate, private, max-age=0"),
        };
        if let Some(cc) = cache_control {
            headers.set("Cache-Control", cc)?;
        }

        // Additional anti-caching headers for sensitive endpoints (OWASP ASVS 5.0.0 V14.2.2)
        if !matches!(
            req_path.as_str(),
            "/health"
                | "/v1/jwks.json"
                | "/.well-known/jwks.json"
                | "/v1/docs"
                | "/v1/openapi.json"
        ) {
            headers.set("Pragma", "no-cache")?;
            headers.set("Expires", "0")?;
        }

        // CORS: Only allow origins from the allowlist (with wildcard support)
        // CORS with subdomain wildcard matching (https://*.provii.app)
        // Also covers /.well-known/jwks.json which needs cross-origin access for key discovery
        //
        // SB-039: internal routes are service-to-service only. CORS
        // headers are unnecessary and undesirable on internal paths.
        if !is_internal_route
            && (req_path.starts_with("/v1/") || req_path == "/.well-known/jwks.json")
            && !request_origin.is_empty()
        {
            if allowed_origins.matches(&request_origin) {
                headers.set("Access-Control-Allow-Origin", &request_origin)?;
                headers.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")?;
                headers.set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")?;
                headers.set("Vary", "Origin")?;

                // SECURITY: Only allow credentials for exact matches (not wildcards)
                if allowed_origins.allows_credentials(&request_origin) {
                    headers.set("Access-Control-Allow-Credentials", "true")?;
                }
            } else {
                logging::log_security_event(
                    "cors_violation",
                    logging::LogLevel::Warn,
                    Some(request_id.clone()),
                    serde_json::json!({"origin": request_origin}),
                );
            }
        }

        // Log response status and duration for observability.
        let duration_ms = elapsed_ms(start_ms);
        logging::log_response(resp.status_code(), &request_id, Some(duration_ms));

        Ok(resp)
    };

    // OWASP ASVS 5.0.0 V4.1.4 Level 2: Handle OPTIONS explicitly with Allow header
    // CH-066: 204 No Content for preflight (no body needed)
    if req_method == Method::Options {
        let mut resp = Response::empty()?.with_status(204);

        // Determine allowed methods based on the path
        let allowed_methods = match req_path.as_str() {
            "/health" => "GET, OPTIONS",
            "/health/detailed" | "/metrics" => "GET, OPTIONS",
            "/v1/openapi.json" | "/v1/docs" => "GET, OPTIONS",
            "/v1/challenge"
            | "/v1/issuance/blind"
            | "/v1/attestation/create"
            | "/v1/admin/keys/rotate"
            | "/v1/admin/attestation-keys/rotate" => "POST, OPTIONS",
            "/v1/jwks.json" | "/.well-known/jwks.json" => "GET, OPTIONS",
            "/v1/admin/keys/health" => "GET, OPTIONS",
            "/_internal/version" => "GET, OPTIONS",
            // Internal routes are service-binding-only surfaces. Browser
            // preflight never reaches them, so only the bare method is
            // advertised here. No CORS preflight support is intentional.
            "/_internal/replay-saved-pre-rotation-token" => "POST, OPTIONS",
            "/_internal/test-fixtures" => "GET, OPTIONS",
            _ if req_path.starts_with("/_internal/test-fixtures/") => "DELETE, OPTIONS",
            "/v1/register-test-issuer" => {
                // Sandbox-only route. Advertise POST only if environment is sandbox.
                let is_sandbox = env
                    .var("ENVIRONMENT")
                    .map(|v| v.to_string())
                    .unwrap_or_default()
                    == "sandbox";
                if is_sandbox {
                    "POST, OPTIONS"
                } else {
                    "OPTIONS"
                }
            }
            _ => "OPTIONS",
        };

        resp.headers_mut().set("Allow", allowed_methods)?;
        // CH-067: Tell browsers to cache preflight results for 2 hours
        resp.headers_mut().set("Access-Control-Max-Age", "7200")?;

        logging::log_security_event(
            "http_options_request",
            logging::LogLevel::Debug,
            Some(request_id.clone()),
            serde_json::json!({
                "path": req_path,
                "allowed_methods": allowed_methods,
            }),
        );

        return add_security_headers(resp);
    }

    let router = Router::new()
        .get_async("/health", |_req, ctx| async move {
            match health::health_check(&ctx.env).await {
                Ok(health_response) => Response::from_json(&health_response),
                Err(e) => {
                    logging::log_error(format!("Health check failed: {:?}", e)).log();
                    ApiError::Internal("Health check failed".into()).to_response()
                }
            }
        })
        // SECURITY: Detailed health check with full subsystem probes (requires STATUS_API_TOKEN).
        .get_async("/health/detailed", |req, ctx| async move {
            // dual-slot accept + secret_version_used log.
            let slot = match health::authenticate_status_request(req.headers(), &ctx.env).await {
                Ok(slot) => slot,
                Err(e) => return e.to_response(),
            };
            health::log_status_secret_version(&ctx.env, slot, "/health/detailed").await;
            // x-secret-version response header carrying the
            // 6-char fingerprint of the matched slot.
            let fp = health::status_secret_version_header(&ctx.env, slot).await;

            let mut resp = match health::health_check_detailed(&ctx.env).await {
                Ok(health_response) => Response::from_json(&health_response)?,
                Err(e) => {
                    logging::log_error(format!("Detailed health check failed: {:?}", e)).log();
                    return ApiError::Internal("Health check failed".into()).to_response();
                }
            };
            resp.headers_mut().set("x-secret-version", &fp)?;
            Ok(resp)
        })
        // SECURITY: Metrics endpoint (requires STATUS_API_TOKEN).
        // Returns the same detailed health data as /health/detailed for monitoring tools.
        .get_async("/metrics", |req, ctx| async move {
            // dual-slot accept + secret_version_used log.
            let slot = match health::authenticate_status_request(req.headers(), &ctx.env).await {
                Ok(slot) => slot,
                Err(e) => return e.to_response(),
            };
            health::log_status_secret_version(&ctx.env, slot, "/metrics").await;
            let fp = health::status_secret_version_header(&ctx.env, slot).await;

            let mut resp = match health::health_check_detailed(&ctx.env).await {
                Ok(health_response) => Response::from_json(&health_response)?,
                Err(e) => {
                    logging::log_error(format!("Metrics check failed: {:?}", e)).log();
                    return ApiError::Internal("Metrics unavailable".into()).to_response();
                }
            };
            resp.headers_mut().set("x-secret-version", &fp)?;
            Ok(resp)
        })
        .get_async("/v1/openapi.json", |_req, ctx| async move {
            // Read the API version from environment or use a default
            let version = ctx
                .var("API_VERSION")
                .map(|v| v.to_string())
                .unwrap_or_else(|_| "1.0.0".to_string());

            // Construct the base URL from the request or environment
            let base_url = ctx
                .var("API_BASE_URL")
                .map(|v| v.to_string())
                .unwrap_or_else(|_| "https://issuer.provii.app".to_string());

            // Generate and return the specification document
            openapi::serve_openapi_json(&version, &base_url)
        })
        .get_async("/v1/docs", move |_req, _ctx| {
            let nonce_val = docs_nonce_for_html.clone();
            async move {
            // Serve Swagger UI HTML page with Subresource Integrity (SRI)
            // OWASP ASVS 5.0.0 V3 Level 2: Protect against CDN compromise
            // Swagger UI v5.18.2 pinned via SRI hashes.
            //
            // CH-074: Generate a per-request CSP nonce to replace 'unsafe-inline'.
            // The nonce is embedded in the inline <script> and <style> tags and
            // must match the nonce in the Content-Security-Policy header (set by
            // add_security_headers via csp_nonce).
            let nonce = match nonce_val.as_deref() {
                Some(n) if !n.is_empty() => n,
                _ => {
                    // Unreachable: the outer main() returns 500 if CSPRNG fails.
                    // Defensive: reject rather than serve with a predictable nonce.
                    return Response::error("Internal Server Error", 500);
                }
            };
            let html = format!(
                r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Provii Issuer API Documentation</title>
    <link rel="stylesheet"
          type="text/css"
          href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.18.2/swagger-ui.css"
          integrity="sha384-++DMKo1369T5pxDNqojF1F91bYxYiT1N7b1M15a7oCzEodfljztKlApQoH6eQSKI"
          crossorigin="anonymous" />
    <style nonce="{}">
        body {{ margin: 0; padding: 0; }}
        .swagger-ui .topbar {{ display: none; }}
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.18.2/swagger-ui-bundle.js"
            integrity="sha384-bBdB196maIUakX6v2F6J0XcjddQfaENm8kASsYfqTKCZua9xlYNh1AdtL18PGr0D"
            crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.18.2/swagger-ui-standalone-preset.js"
            integrity="sha384-Se2dMItBjKehkhvdy8ZDK8Qbj8wWIgvme6DMtaefAPiGI75QN4jG8LS/eFfkUxi2"
            crossorigin="anonymous"></script>
    <script nonce="{}">
        window.onload = function() {{
            window.ui = SwaggerUIBundle({{
                url: '/v1/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                layout: 'StandaloneLayout',
                defaultModelsExpandDepth: 1,
                defaultModelExpandDepth: 1,
                docExpansion: 'list',
                filter: true,
                syntaxHighlight: {{
                    activate: true,
                    theme: 'monokai'
                }}
            }});
        }}
    </script>
</body>
</html>"#,
                nonce, nonce
            );

            let mut response = Response::from_html(&html)?;
            response
                .headers_mut()
                .set("Content-Type", "text/html; charset=utf-8")?;
            // Cache-Control set in add_security_headers
            Ok(response)
        }})
        // The officer flow uses YubiKey HMAC-SHA1 challenge-response for authentication.
        .post_async("/v1/challenge", routes::generate_yubikey_challenge)
        .post_async("/v1/issuance/blind", routes::blind_issuance)
        .post_async("/v1/attestation/create", routes::create_attestation)
        .get_async("/v1/jwks.json", |_req, _ctx| async move {
            // P3-13: 301 redirect to canonical /.well-known/jwks.json location.
            let mut resp = Response::empty()?.with_status(301);
            resp.headers_mut().set("Location", "/.well-known/jwks.json")?;
            resp.headers_mut().set("Cache-Control", "public, max-age=86400")?;
            Ok(resp)
        })
        .get_async("/.well-known/jwks.json", routes::jwks)
        .post_async("/v1/admin/keys/rotate", routes::rotate_signing_key)
        // Ed25519 attestation key rotation. Promotes a pre-loaded kid into
        // IssuerConfig.default_kid and pushes the outgoing kid into
        // previous_kid in a single transactional KV write so trial-verify
        // keeps both keys in scope during the overlap window.
        .post_async(
            "/v1/admin/attestation-keys/rotate",
            routes::rotate_attestation_key,
        )
        .get_async("/v1/admin/keys/health", routes::check_key_health)
        // Rotation-drill propagation endpoint. Auth via
        // `Authorization: Bearer <token>`.
        .get_async("/_internal/version", |req, ctx| async move {
            // Defence in depth: reject any request carrying CF-Connecting-IP
            // before the existing `INTERNAL_VERSION_SERVICE_TOKEN` auth
            // runs. /_internal/* is a service-binding-only surface, so an
            // external connecting-IP is unauthorised regardless of token
            // validity. See `reject_external_internal_traffic`.
            if let Some(resp) = reject_external_internal_traffic(req.headers(), "internal_version") {
                return Ok(resp);
            }
            match internal_version::handle_internal_version(req.headers(), &ctx.env).await {
                Ok(resp) => Ok(resp),
                Err(e) => e.to_response(),
            }
        })
        // Rotation drill admin endpoints. Class 6: 10/hour cap +
        // 5-attempt lockout, dual-slot bearer
        // (INTERNAL_VERSION_SERVICE_TOKEN), mandatory X-Nonce consumed
        // through NonceDO so a captured request cannot replay within
        // the dedupe TTL.
        .post_async(
            "/_internal/replay-saved-pre-rotation-token",
            |req, ctx| async move {
                if let Some(resp) =
                    reject_external_internal_traffic(req.headers(), "admin-replay-token")
                {
                    return Ok(resp);
                }
                let env = ctx.env.clone();
                internal_admin::replay_pre_rotation_token(req, &env).await
            },
        )
        .get_async("/_internal/test-fixtures", |req, ctx| async move {
            if let Some(resp) =
                reject_external_internal_traffic(req.headers(), "admin-fixture-manifest")
            {
                return Ok(resp);
            }
            let env = ctx.env.clone();
            internal_admin::test_fixtures_manifest(req, &env).await
        })
        .delete_async("/_internal/test-fixtures/:class", |req, ctx| async move {
            if let Some(resp) =
                reject_external_internal_traffic(req.headers(), "admin-fixture-delete")
            {
                return Ok(resp);
            }
            let class = ctx.param("class").map(String::from).unwrap_or_default();
            let env = ctx.env.clone();
            internal_admin::delete_test_fixtures(req, &env, &class).await
        });

    // Sandbox credential mint. Only registered in sandbox deployments.
    // Production falls through to the 404 catchall below.
    let env_for_gate = env
        .var("ENVIRONMENT")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let router = if env_for_gate == "sandbox" {
        router.post_async(
            "/v1/register-test-issuer",
            routes_sandbox_cred::register_test_issuer,
        )
    } else {
        router
    };

    let router = router
        .get("/*catchall", |_, _| {
            ApiError::NotFound("Not Found".into()).to_response()
        })
        .or_else_any_method("/*catchall", |_, _| {
            ApiError::NotFound("Not Found".into()).to_response()
        });

    // OWASP ASVS 5.0.0 V4.1.4 Level 2: Pre-validate HTTP method before routing
    // Check if the request method is supported for the path
    //
    // /v1/register-test-issuer is sandbox-only. On production deployments
    // it falls through to the 404 catchall (the route is not registered
    // above).
    let is_sandbox_env = env_for_gate == "sandbox";
    let allowed_methods_for_path = match req_path.as_str() {
        "/health" | "/health/detailed" | "/metrics" => vec![Method::Get],
        "/v1/openapi.json" | "/v1/docs" => vec![Method::Get],
        "/v1/challenge"
        | "/v1/issuance/blind"
        | "/v1/attestation/create"
        | "/v1/admin/keys/rotate"
        | "/v1/admin/attestation-keys/rotate" => vec![Method::Post],
        "/v1/jwks.json" | "/.well-known/jwks.json" | "/v1/admin/keys/health" => vec![Method::Get],
        "/v1/register-test-issuer" if is_sandbox_env => vec![Method::Post],
        "/_internal/version" => vec![Method::Get],
        "/_internal/replay-saved-pre-rotation-token" => vec![Method::Post],
        "/_internal/test-fixtures" => vec![Method::Get],
        _ if req_path.starts_with("/_internal/test-fixtures/") => vec![Method::Delete],
        _ => vec![], // Unknown path - will be handled by 404 catchall
    };

    // If path is known but method is not allowed, return 405
    if !allowed_methods_for_path.is_empty() && !allowed_methods_for_path.contains(&req_method) {
        let allowed_str = allowed_methods_for_path
            .iter()
            .map(|m| m.to_string().to_uppercase())
            .collect::<Vec<_>>()
            .join(", ");

        logging::log_security_event(
            "http_method_not_allowed",
            logging::LogLevel::Warn,
            Some(request_id.clone()),
            serde_json::json!({
                "method": req_method.to_string(),
                "path": req_path,
                "allowed_methods": allowed_str,
                "security_note": "Potential scanning or attack attempt",
            }),
        );

        let body = serde_json::json!({
            "error": "Method not allowed",
            "code": "METHOD_NOT_ALLOWED",
        });
        let mut resp = Response::from_json(&body)?.with_status(405);
        resp.headers_mut().set("Allow", &allowed_str)?;
        resp.headers_mut()
            .set("Content-Type", "application/json; charset=utf-8")?;
        return add_security_headers(resp);
    }

    // Capture environment name and clone env for post-response analytics.
    // Must happen before `env` is moved into router.run().
    let environment = env
        .var("ENVIRONMENT")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let analytics_env = env.clone();

    let result = match router.run(req, env).await {
        Ok(resp) => add_security_headers(resp),
        Err(e) => {
            logging::log_error(format!("Router error: {:?}", e))
                .with_request_id(request_id_for_error)
                .log();
            let resp = ApiError::Internal("Internal Server Error".into()).to_response()?;
            add_security_headers(resp)
        }
    };

    // Request-level timing and analytics (runs after response is fully constructed)
    let total_ms = elapsed_ms(start_ms);
    let status = result.as_ref().map(|r| r.status_code()).unwrap_or(500);

    console_log!(
        r#"{{"type":"REQUEST_COMPLETE","service":"provii-issuer","route":"{}","status":{},"duration_ms":{},"cold_start":{}}}"#,
        req_path,
        status,
        total_ms,
        is_cold
    );

    if is_cold {
        #[allow(clippy::cast_precision_loss)]
        analytics::Analytics::new(&analytics_env).cold_start(&environment, total_ms as f64);
    }

    // Emit warm request analytics every 100th request for worker lifetime tracking
    #[allow(clippy::arithmetic_side_effects)]
    if request_num % 100 == 0 {
        let worker_init_ts = get_worker_init_timestamp();
        let worker_age_ms = if worker_init_ts > 0 {
            f64_to_u64(start_ms).saturating_sub(worker_init_ts) as f64
        } else {
            0.0
        };
        analytics::Analytics::new(&analytics_env).warm_request(
            &environment,
            worker_age_ms,
            request_num,
        );
    }

    result
}

// ==================== Scheduled Event Handler ====================

/// Scheduled event handler for cron triggers (per-minute warmup).
#[event(scheduled)]
pub async fn handle_cron(event: worker::ScheduledEvent, env: Env, _ctx: worker::ScheduleContext) {
    let cron = event.cron();
    console_log!("[CRON] Triggered: {}", cron);

    match cron.as_str() {
        "* * * * *" => {
            // P3-12: Keep worker warm by performing a lightweight health check every
            // minute. Sandbox workers go cold within ~60s of inactivity, causing
            // multi-second cold start chains for issuance flows.
            console_log!("[CRON] Warmup: running lightweight health check");
            match health::health_check(&env).await {
                Ok(resp) => {
                    console_log!(
                        "[CRON] Warmup OK: status={:?}, timestamp={}",
                        resp.status,
                        resp.timestamp
                    );
                }
                Err(e) => {
                    console_log!("[CRON] Warmup health check failed: {:?}", e);
                }
            }
        }
        other => {
            console_log!("[CRON] ERROR: unhandled cron schedule: {}", other);
        }
    }
}

#[cfg(test)]
#[allow(
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
mod tests {
    use super::*;

    // f64_to_u64 tests

    #[test]
    fn f64_to_u64_positive_integer() {
        assert_eq!(f64_to_u64(42.0), 42);
    }

    #[test]
    fn f64_to_u64_zero() {
        assert_eq!(f64_to_u64(0.0), 0);
    }

    #[test]
    fn f64_to_u64_negative_returns_zero() {
        assert_eq!(f64_to_u64(-1.0), 0);
        assert_eq!(f64_to_u64(-999.0), 0);
    }

    #[test]
    fn f64_to_u64_nan_returns_zero() {
        assert_eq!(f64_to_u64(f64::NAN), 0);
    }

    #[test]
    fn f64_to_u64_infinity_returns_max() {
        assert_eq!(f64_to_u64(f64::INFINITY), u64::MAX);
    }

    #[test]
    fn f64_to_u64_neg_infinity_returns_zero() {
        assert_eq!(f64_to_u64(f64::NEG_INFINITY), 0);
    }

    #[test]
    fn f64_to_u64_large_value_clamps() {
        assert_eq!(f64_to_u64(1e30), u64::MAX);
    }

    #[test]
    fn f64_to_u64_fractional_truncates() {
        assert_eq!(f64_to_u64(3.9), 3);
        assert_eq!(f64_to_u64(0.1), 0);
    }

    #[test]
    fn f64_to_u64_typical_timestamp() {
        // A typical Date.now() value
        let ts = 1717200000000.0;
        assert_eq!(f64_to_u64(ts), 1717200000000);
    }

    // is_cold_start tests

    #[test]
    fn is_cold_start_returns_true_then_false() {
        // Reset the atomic for this test
        WORKER_INITIALIZED.store(false, Ordering::SeqCst);
        assert!(is_cold_start());
        assert!(!is_cold_start());
        assert!(!is_cold_start());
    }

    // record_worker_init_time / get_worker_init_timestamp tests

    #[test]
    fn record_and_get_init_timestamp() {
        record_worker_init_time(1234567890.0);
        assert_eq!(get_worker_init_timestamp(), 1234567890);
    }

    #[test]
    fn record_init_time_nan_stores_zero() {
        record_worker_init_time(f64::NAN);
        assert_eq!(get_worker_init_timestamp(), 0);
    }

    #[test]
    fn record_init_time_negative_stores_zero() {
        record_worker_init_time(-100.0);
        assert_eq!(get_worker_init_timestamp(), 0);
    }

    // increment_request_count tests

    #[test]
    fn increment_request_count_increases() {
        WORKER_REQUEST_COUNT.store(0, Ordering::SeqCst);
        let first = increment_request_count();
        assert_eq!(first, 1);
        let second = increment_request_count();
        assert_eq!(second, 2);
    }

    // redact_session_id tests (from security::client_auth)

    #[test]
    fn redact_session_id_normal_uuid() {
        let id = "a1b2c3d4-e5f6-7890-abcd-ef0123456789";
        assert_eq!(crate::security::redact_session_id(id), "a1b2...");
    }

    #[test]
    fn redact_session_id_short_input() {
        assert_eq!(crate::security::redact_session_id("ab"), "***");
        assert_eq!(crate::security::redact_session_id(""), "***");
        assert_eq!(crate::security::redact_session_id("abc"), "***");
    }

    #[test]
    fn redact_session_id_exact_four_chars() {
        assert_eq!(crate::security::redact_session_id("abcd"), "abcd...");
    }

    #[test]
    fn redact_session_id_unicode() {
        // Unicode characters should each count as one char
        assert_eq!(crate::security::redact_session_id("abcde"), "abcd...");
    }

    // ---- R14: rate-limit config presence assertion --------------------------
    //
    // Every rate-limit env var the code READS must be PRESENT in wrangler.toml,
    // otherwise the var silently falls back to its in-code default and the
    // operator's intended (e.g. relaxed sandbox) limit never applies - config
    // drift that is invisible at deploy time.
    //
    // This is DELIBERATELY a #[cfg(test)] assertion, NEVER a runtime panic in
    // the #[event(fetch)]/main handler: a runtime panic on benign config drift
    // would brick the Worker and 5xx every paying customer - the exact
    // self-inflicted outage this whole remediation effort is avoiding. Failing
    // CI is the correct place to catch a missing var.

    /// The complete set of rate-limit env vars the issuer code reads via
    /// `env.var(...)`. Keep in sync with the `.var("…_LIMIT_…"/"…_QUOTA_…")`
    /// reads in src/ (grep guard below references this list).
    const RATE_LIMIT_ENV_VARS: &[&str] = &[
        "ATTESTATION_IP_LIMIT_PER_HOUR",
        "BLIND_IP_LIMIT_PER_HOUR",
        "BLIND_ISSUANCE_LIMIT_PER_HOUR",
        "CHALLENGE_IP_LIMIT_PER_HOUR",
        "DEFAULT_QUOTA_PER_HOUR",
        "GLOBAL_IP_GET_LIMIT_PER_HOUR",
        "GLOBAL_IP_MUTATING_LIMIT_PER_HOUR",
    ];

    /// Extract the lines belonging to a single TOML table header (e.g.
    /// `[vars]` or `[env.sandbox.vars]`) - i.e. every line after the header up
    /// to the next table header. `header` includes the brackets (e.g.
    /// `"[vars]"`); the match is exact on the (comment- and whitespace-trimmed)
    /// line so `[vars]` does not also match a different `[varsomething]` table.
    fn toml_table_body(toml: &str, header: &str) -> String {
        let mut in_block = false;
        let mut body = String::new();
        for line in toml.lines() {
            let trimmed = line.trim();
            // A table-header line begins with '[' and (after stripping any
            // trailing inline comment) ends with ']'.
            let is_header_line = trimmed.starts_with('[') && {
                let before_comment = trimmed.split('#').next().unwrap_or("").trim();
                before_comment.ends_with(']')
            };
            if is_header_line {
                let before_comment = trimmed.split('#').next().unwrap_or("").trim();
                in_block = before_comment == header;
                continue;
            }
            if in_block {
                body.push_str(line);
                body.push('\n');
            }
        }
        body
    }

    /// Assert every var in `RATE_LIMIT_ENV_VARS` has an assignment in `body`.
    fn assert_vars_present(body: &str, table_name: &str) {
        for var in RATE_LIMIT_ENV_VARS {
            // A real assignment looks like `VAR = "…"`; a mere mention inside a
            // comment line (starting with '#') must not count.
            let present = body.lines().any(|l| {
                let t = l.trim_start();
                !t.starts_with('#') && t.starts_with(var) && {
                    let rest = t[var.len()..].trim_start();
                    rest.starts_with('=')
                }
            });
            assert!(
                present,
                "rate-limit env var {} is read by the code but is MISSING from \
                 wrangler.toml [{}]; it would silently fall back to its in-code \
                 default. Add it to [{}].",
                var, table_name, table_name
            );
        }
    }

    #[test]
    fn every_rate_limit_var_present_in_both_wrangler_blocks() {
        // Read the deployed config relative to the crate manifest so the test
        // is independent of the working directory.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let toml = std::fs::read_to_string(format!("{}/wrangler.toml", manifest_dir))
            .expect("wrangler.toml must be readable next to Cargo.toml");

        let prod = toml_table_body(&toml, "[vars]");
        assert!(
            !prod.trim().is_empty(),
            "could not locate [vars] block in wrangler.toml"
        );
        assert_vars_present(&prod, "vars");

        let sandbox = toml_table_body(&toml, "[env.sandbox.vars]");
        assert!(
            !sandbox.trim().is_empty(),
            "could not locate [env.sandbox.vars] block in wrangler.toml"
        );
        assert_vars_present(&sandbox, "env.sandbox.vars");
    }

    #[test]
    fn dead_max_vars_stay_deleted_from_wrangler() {
        // R14 deleted three vars that have ZERO src references. Guard against
        // their reintroduction as misleading dead config (they imply enforcement
        // surfaces that do not exist).
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let toml = std::fs::read_to_string(format!("{}/wrangler.toml", manifest_dir))
            .expect("wrangler.toml must be readable next to Cargo.toml");
        for dead in [
            "MAX_CHALLENGES_PER_OFFICER_PER_HOUR",
            "MAX_SESSIONS_PER_CLIENT_PER_HOUR",
            "MAX_CREDENTIALS_PER_SESSION",
        ] {
            // Only flag a real assignment, not a mention in the explanatory
            // comment that records why they were removed.
            let assigned = toml.lines().any(|l| {
                let t = l.trim_start();
                !t.starts_with('#') && t.starts_with(dead) && {
                    let rest = t[dead.len()..].trim_start();
                    rest.starts_with('=')
                }
            });
            assert!(
                !assigned,
                "dead var {} was reintroduced into wrangler.toml; it has zero \
                 src references and must not be re-added (R14).",
                dead
            );
        }
    }
}
