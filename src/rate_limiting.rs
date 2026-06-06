// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Simple KV-counter-based rate limiting.
//!
//! Replaces the shared-rate-limit Durable Object system with direct KV
//! reads and writes.  All limits are configurable via wrangler.toml env
//! vars or RATE_LIMIT_CONFIG KV tier data (managed through the admin
//! portal).  Fail-closed: if a KV read fails the request is rejected
//! (fail-closed policy).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};

use worker::kv::KvStore;
use worker::Response;

// ---------------------------------------------------------------------------
// Per-operation timeout (R2)
// ---------------------------------------------------------------------------
//
// Cloudflare Workers have no native per-operation timeout. A stalled KV read
// on the shared rate-limit namespace would otherwise block the issuer hot path
// until the 30s global CPU limit kills the isolate. This ports the verifier's
// `with_timeout` combinator (provii-verifier/src/utils/timeout.rs) so the
// volumetric counter's get/put are bounded. A read timeout maps to the same
// fail-closed path as a KV read error (R1: 503 + short Retry-After).

/// KV read timeout for the volumetric counter (10x p99 headroom).
const KV_READ_TIMEOUT_MS: u32 = 500;
/// KV write timeout for the volumetric counter (best-effort put).
const KV_WRITE_TIMEOUT_MS: u32 = 1000;

/// Race an async operation against a JS `setTimeout` deadline.
///
/// On wasm32 (the deployed target) this builds a `js_sys::Promise` resolving
/// after `timeout_ms` and races it against `fut` with `futures::future::select`.
/// On non-wasm32 (host tests) it runs without a timer. Returns `Err(())` on
/// timeout; the underlying future is dropped (cancelled).
async fn with_timeout<T, F>(timeout_ms: u32, fut: F) -> Result<T, ()>
where
    F: std::future::Future<Output = T>,
{
    #[cfg(target_arch = "wasm32")]
    {
        use futures::future::Either;
        use wasm_bindgen::JsCast;

        let timer_promise = js_sys::Promise::new(&mut |resolve, _| {
            let global = js_sys::global();
            let set_timeout = match js_sys::Reflect::get(&global, &"setTimeout".into()) {
                Ok(val) => val,
                Err(_) => {
                    // setTimeout unavailable (should not happen in Workers):
                    // resolve immediately so the operation runs without a cap.
                    resolve.call0(&wasm_bindgen::JsValue::NULL).ok();
                    return;
                }
            };
            let set_timeout_fn = match set_timeout.dyn_into::<js_sys::Function>() {
                Ok(f) => f,
                Err(_) => {
                    resolve.call0(&wasm_bindgen::JsValue::NULL).ok();
                    return;
                }
            };
            // timeout_ms (max 1000) always fits in i32.
            #[allow(clippy::cast_possible_wrap)]
            let delay: i32 = timeout_ms as i32;
            let _ = set_timeout_fn.call2(&global, &resolve, &delay.into());
        });

        let timer_future = wasm_bindgen_futures::JsFuture::from(timer_promise);

        futures::pin_mut!(fut);
        futures::pin_mut!(timer_future);

        match futures::future::select(fut, timer_future).await {
            Either::Left((result, _)) => Ok(result),
            Either::Right((_, _)) => Err(()),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = timeout_ms;
        Ok(fut.await)
    }
}

/// Convert a chrono timestamp (i64 seconds since epoch) to u64, clamping
/// negative values to 0.
///
/// Delegates to `issuer_logic::rate_limiting::timestamp_as_u64`.
#[inline]
fn timestamp_as_u64(ts: i64) -> u64 {
    issuer_logic::rate_limiting::timestamp_as_u64(ts)
}

/// Unix timestamp (seconds) at which the current rate limit window resets.
///
/// Delegates to `issuer_logic::rate_limiting::reset_timestamp`.
fn reset_timestamp() -> u64 {
    issuer_logic::rate_limiting::reset_timestamp()
}

// ---------------------------------------------------------------------------
// Tier cache (Pattern C), cached per-isolate for 60 seconds
// ---------------------------------------------------------------------------

struct TierCache {
    limits: HashMap<String, u32>,
    fetched_at: u64,
}

static TIER_CACHE: OnceLock<RwLock<HashMap<String, TierCache>>> = OnceLock::new();

fn tier_cache() -> &'static RwLock<HashMap<String, TierCache>> {
    TIER_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Parse tier limits JSON.
///
/// Delegates to `issuer_logic::rate_limiting::parse_tier_limits`.
fn parse_tier_limits(json: &str) -> HashMap<String, u32> {
    issuer_logic::rate_limiting::parse_tier_limits(json)
}

/// Look up the per-hour quota for `client_id` on `endpoint`.
///
/// Reads `rate_limits/clients/{client_id}` → tier_id, then
/// `rate_limits/tiers/{tier_id}` → `{ endpoint: limit }`.
/// Falls back to `default_limit` on any miss or error.
async fn get_customer_limit(
    kv: &KvStore,
    client_id: &str,
    endpoint: &str,
    default_limit: u32,
    now_secs: u64,
) -> u32 {
    // Check in-memory cache first
    if let Ok(cache) = tier_cache().read() {
        if let Some(entry) = cache.get(client_id) {
            if now_secs.saturating_sub(entry.fetched_at) < 60 {
                return entry.limits.get(endpoint).copied().unwrap_or(default_limit);
            }
        }
    }

    // Cache miss: read from KV
    let tier_id = match kv
        .get(&format!("rate_limits/clients/{}", client_id))
        .text()
        .await
    {
        Ok(Some(t)) => t,
        Ok(None) => return default_limit,
        Err(_e) => {
            // KV read failure. Fall back to permissive default to avoid
            // false lockouts during transient KV outages. This is intentional: a
            // brief period of elevated limits is preferable to rejecting legitimate
            // traffic from paying customers.
            crate::log!("[RATE_LIMIT] KV read failed for client tier lookup (client={}); using default_limit={}", client_id, default_limit);
            return default_limit;
        }
    };

    let limits = match kv
        .get(&format!("rate_limits/tiers/{}", tier_id))
        .text()
        .await
    {
        Ok(Some(json)) => parse_tier_limits(&json),
        Ok(None) => {
            crate::log!(
                "[RATE_LIMIT] Tier '{}' not found in KV for client={}; using default_limit={}",
                tier_id,
                client_id,
                default_limit
            );
            HashMap::new()
        }
        Err(_e) => {
            crate::log!(
                "[RATE_LIMIT] KV read failed for tier '{}' (client={}); using default_limit={}",
                tier_id,
                client_id,
                default_limit
            );
            HashMap::new()
        }
    };

    let result = limits.get(endpoint).copied().unwrap_or(default_limit);

    // Update cache
    if let Ok(mut cache) = tier_cache().write() {
        cache.insert(
            client_id.to_string(),
            TierCache {
                limits,
                fetched_at: now_secs,
            },
        );
    }

    result
}

// ---------------------------------------------------------------------------
// KV counter (Pattern B), non-atomic, acceptable at Provii's scale
// ---------------------------------------------------------------------------

/// Increment a KV counter and return `(allowed, current_count, limit)`.
///
/// Returns `(true, count, limit)` if the request is within quota,
/// `(false, count, limit)` if over quota. On KV read errors the request
/// is denied (fail-closed) to prevent unlimited traffic during KV outages.
///
/// ## Known limitation: non-atomic read-check-write
///
/// Cloudflare KV does not support atomic compare-and-swap (CAS). The counter
/// is implemented as read-then-write, so concurrent requests that arrive within
/// the same KV propagation window (~60s for global consistency) may all read
/// the same counter value and each increment from the same base. In the worst
/// case a burst of N concurrent requests could allow up to N-1 extra requests
/// beyond the limit.
///
/// This is a best-effort rate limiter, not a hard quota enforcer. At Provii's
/// request volume the practical impact is negligible. A Durable Object based
/// counter would provide true atomicity but adds latency and cost for every
/// rate-limited request, which is not justified for the current traffic profile.
/// The fail-closed behaviour on KV read errors (below) ensures that KV outages
/// do not degrade into unlimited traffic.
///
/// The fourth tuple element is `read_failed`: it is `true` ONLY when the
/// counter READ failed (KV error or timeout). It never changes the admit/reject
/// decision (a read failure is still rejected, fail-closed); it only lets the
/// call site emit a 503 + short Retry-After instead of a 429 (R1/R2).
async fn check_kv_counter(
    kv: &KvStore,
    key: &str,
    limit: u32,
    ttl_secs: u64,
) -> (bool, u32, u32, bool) {
    // R2: bound the read so a slow shared-namespace KV cannot hang the hot
    // path. A timeout is treated identically to a KV read error: fail-closed
    // with read_failed=true (routes into R1's 503 + short Retry-After path).
    let read = with_timeout(KV_READ_TIMEOUT_MS, kv.get(key).text()).await;
    let count: u32 = match read {
        Ok(Ok(Some(s))) => s.parse().unwrap_or(0),
        Ok(Ok(None)) => 0,
        Ok(Err(_)) => {
            // Fail closed on KV read errors
            crate::log_error!(
                "[RateLimit] KV read failed for key={}; rejecting request (fail-closed)",
                key
            );
            return (false, 0, limit, true);
        }
        Err(()) => {
            // Fail closed on KV read timeout (R2)
            crate::log_error!(
                "[RateLimit] KV read timed out after {}ms for key={}; rejecting request (fail-closed)",
                KV_READ_TIMEOUT_MS,
                key
            );
            return (false, 0, limit, true);
        }
    };

    if count >= limit {
        return (false, count, limit, false);
    }

    // Increment (best-effort, non-atomic). The write path already fails open
    // (errors swallowed); a write timeout is treated the same way and never
    // sets read_failed (R2: only the read maps to the 503 path).
    let next = count.saturating_add(1);
    if let Ok(put) = kv.put(key, next.to_string()) {
        let _ = with_timeout(KV_WRITE_TIMEOUT_MS, put.expiration_ttl(ttl_secs).execute()).await;
    }

    (true, next, limit, false)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Result of a rate limit check, carrying enough context for logging and
/// Retry-After header generation.
pub struct RateLimitResult {
    pub allowed: bool,
    pub current_count: u32,
    pub limit: u32,
    pub retry_after_secs: u32,
    /// `true` ONLY when the underlying counter READ failed (KV error or
    /// timeout). Lets the call site return 503 + short Retry-After instead of
    /// a 429, distinguishing infrastructure failure from a genuine quota
    /// breach. Never affects `allowed` (a read failure stays fail-closed).
    pub read_failed: bool,
}

/// Check per-customer hourly quota (post-auth, tier-based).
///
/// `client_id` is the authenticated identity (officer ID, client ID, etc.).
/// `endpoint` is a short label like `"challenge"` or `"issuance"`.
pub async fn check_quota(
    rate_limit_kv: &KvStore,
    config_kv: &KvStore,
    client_id: &str,
    endpoint: &str,
    default_limit: u32,
) -> RateLimitResult {
    #[allow(clippy::arithmetic_side_effects)]
    // Division and multiplication by the constant 3600 cannot overflow.
    let now_secs = timestamp_as_u64(chrono::Utc::now().timestamp()) / 3600 * 3600;
    let hour_ts = now_secs;

    let limit = get_customer_limit(config_kv, client_id, endpoint, default_limit, now_secs).await;

    // Use pipe delimiter between variable components to prevent key collision
    // if client_id or endpoint ever contains ':'
    let key = format!("quota:{}|{}|{}", client_id, endpoint, hour_ts);
    let (allowed, current_count, limit, read_failed) =
        check_kv_counter(rate_limit_kv, &key, limit, 7200).await;

    // Seconds remaining in the current hour
    let now_actual = timestamp_as_u64(chrono::Utc::now().timestamp());
    let retry_after =
        u32::try_from(hour_ts.saturating_add(3600).saturating_sub(now_actual)).unwrap_or(u32::MAX);

    RateLimitResult {
        allowed,
        current_count,
        limit,
        retry_after_secs: retry_after,
        read_failed,
    }
}

/// Check per-issuer hourly limit for blind issuance (unauthenticated).
///
/// Uses `ISSUER_RATE_LIMITS` KV.  Limit comes from env var
/// `BLIND_ISSUANCE_LIMIT_PER_HOUR`.
pub async fn check_blind_issuance(
    rate_limit_kv: &KvStore,
    issuer_id: &str,
    limit: u32,
) -> RateLimitResult {
    #[allow(clippy::arithmetic_side_effects)]
    // Division and multiplication by the constant 3600 cannot overflow.
    let now_secs = timestamp_as_u64(chrono::Utc::now().timestamp()) / 3600 * 3600;
    let hour_ts = now_secs;

    let key = format!("blind:{}|{}", issuer_id, hour_ts);
    let (allowed, current_count, limit, read_failed) =
        check_kv_counter(rate_limit_kv, &key, limit, 7200).await;

    let now_actual = timestamp_as_u64(chrono::Utc::now().timestamp());
    let retry_after =
        u32::try_from(hour_ts.saturating_add(3600).saturating_sub(now_actual)).unwrap_or(u32::MAX);

    RateLimitResult {
        allowed,
        current_count,
        limit,
        retry_after_secs: retry_after,
        read_failed,
    }
}

// ---------------------------------------------------------------------------
// M3: per-issuer attestation-nonce-consumption tripwire (FAIL-OPEN)
// ---------------------------------------------------------------------------
//
// Nonce consumption runs for EVERY attestation before the expensive Ed25519
// verify, including replays and attestations that later fail verify/issuance.
// This counter is a WIDER tripwire (set at a multiple of the issuance cap) that
// surfaces abnormal nonce-burn. It is deliberately NOT a hard quota:
//
//   * FAIL-OPEN on read error/timeout. Unlike the volumetric counters
//     (`check_kv_counter`, fail-closed), a read failure here returns
//     `over_limit = false` so a transient KV brownout NEVER converts into a
//     customer-facing denial on a path the authoritative per-issuer issuance
//     cap has ALREADY gated upstream. Failing this secondary tripwire closed
//     would harm paying customers with zero security benefit.
//   * Observe-and-alert. The caller emits a distinct audit event when
//     `over_limit` is true and continues; it does NOT reject the request. The
//     real security boundary on this path is the nonce-replay DO check, which
//     runs regardless.
//
// Single-key (NOT sharded): "lightweight" per the hardening scope. At the prod
// issuance cap (1000/hr) the tripwire (~3000/hr) stays under Cloudflare KV's
// ~1-write/sec/key (~3600/hr) coalescing threshold, so the single key counts
// accurately in prod. Above that threshold the single key undercounts, which
// for a tripwire is the fail-SAFE direction (it errs toward NOT firing, i.e.
// toward NOT impacting traffic). The sharded primitive is reserved for the
// authoritative issuance cap where accuracy is load-bearing.

/// Result of the attestation-nonce tripwire check. This counter NEVER denies a
/// request; `over_limit` is purely an observability signal for the caller to
/// emit a distinct audit event.
pub struct NonceRateResult {
    /// `true` when the per-issuer hourly nonce-consume count is at or above the
    /// tripwire limit. Advisory only.
    pub over_limit: bool,
    /// Aggregate count after this consumption (best-effort; `0` if the read
    /// failed, in which case `over_limit` is forced `false`).
    pub current_count: u32,
    /// The tripwire limit that was compared against.
    pub limit: u32,
}

/// M3: increment and check the per-issuer attestation-nonce-consumption
/// tripwire. FAIL-OPEN: a KV read error or timeout returns
/// `over_limit = false` (never denies). Uses a distinct `nonce:` key namespace
/// in `ISSUER_RATE_LIMITS` so it never collides with the `blind:` issuance
/// counters.
///
/// `hashed_issuer_id` MUST already be the SHA-256-truncated issuer id (the
/// caller hashes it), matching the issuance counter's keying.
pub async fn check_attestation_nonce_rate(
    rate_limit_kv: &KvStore,
    hashed_issuer_id: &str,
    limit: u32,
) -> NonceRateResult {
    #[allow(clippy::arithmetic_side_effects)]
    // Division and multiplication by the constant 3600 cannot overflow.
    let now_secs = timestamp_as_u64(chrono::Utc::now().timestamp()) / 3600 * 3600;
    let hour_ts = now_secs;

    let key = format!("nonce:{}|{}", hashed_issuer_id, hour_ts);

    // Bounded read (reuse the Wave 1/R2 primitive's timeout). On read failure we
    // do NOT increment and we report over_limit=false (fail-open).
    let read = with_timeout(KV_READ_TIMEOUT_MS, rate_limit_kv.get(&key).text()).await;
    let count: u32 = match read {
        Ok(Ok(Some(s))) => s.parse().unwrap_or(0),
        Ok(Ok(None)) => 0,
        Ok(Err(_)) => {
            crate::log!(
                "[RateLimit] nonce tripwire read failed for key={}; failing OPEN (advisory counter)",
                key
            );
            return NonceRateResult {
                over_limit: false,
                current_count: 0,
                limit,
            };
        }
        Err(()) => {
            crate::log!(
                "[RateLimit] nonce tripwire read timed out after {}ms for key={}; failing OPEN (advisory counter)",
                KV_READ_TIMEOUT_MS,
                key
            );
            return NonceRateResult {
                over_limit: false,
                current_count: 0,
                limit,
            };
        }
    };

    // Best-effort, non-atomic increment (same semantics as check_kv_counter's
    // write path: errors and write timeouts are swallowed and never affect the
    // result).
    let next = count.saturating_add(1);
    if let Ok(put) = rate_limit_kv.put(&key, next.to_string()) {
        let _ = with_timeout(KV_WRITE_TIMEOUT_MS, put.expiration_ttl(7200).execute()).await;
    }

    NonceRateResult {
        // Boundary check (incl. limit==0 disabled handling) lives in
        // issuer_logic so it is unit-tested without a Worker runtime.
        over_limit: issuer_logic::rate_limiting::nonce_over_limit(next, limit),
        current_count: next,
        limit,
    }
}

// ---------------------------------------------------------------------------
// Sharded per-issuer blind-issuance counter (R13)
// ---------------------------------------------------------------------------
//
// PROBLEM: `attestation.issuer_id` is pinned to the single `config.issuer_id`,
// so EVERY blind issuance funnels its counter write through ONE KV key
// (`blind:{hashed_issuer_id}|{hour}`). Cloudflare KV enforces a hard
// ~1-write/sec/key cap, so above ~3600 issuances/hour the single hot key
// silently coalesces writes and UNDERCOUNTS, letting the per-issuer ceiling
// leak (`BLIND_ISSUANCE_LIMIT_PER_HOUR`, prod 1000 / sandbox 5000).
//
// FIX: spread the counter across `K` sub-keys
// `blind:{hashed_issuer_id}:{shard}|{hour}`. Each request increments exactly
// ONE shard but the READ SUMS all `K` shards to enforce the *aggregate*
// ceiling, so the per-key write rate drops to ~1/K of the issuance rate while
// the bound is still the same total.
//
// CRITICAL: this is a SEPARATE function from `check_blind_issuance`. The shared
// `check_blind_issuance` helper has SIX callers, four of which are per-IP DoS
// caps (challenge_ip, blind_ip, attestation_ip, the global gate) plus the
// per-IP auth-fail counter and the sandbox-cred counter. Those keys are already
// unique per source IP, so sharding them would give ZERO write-rate benefit
// while multiplying their non-atomic N-1 over-admit race by K - weakening the
// pre-auth volumetric net. This function is therefore called ONLY from the
// single per-issuer site (`routes.rs`); `check_blind_issuance` is left
// untouched for the per-IP callers.
//
// TRADE-OFF (read = K gets): the summation read fans out to `K` sequential KV
// gets, so per-issuance read latency and KV read-units grow ~Kx for this one
// counter (an admitted request additionally re-reads its one chosen shard
// inside the increment primitive, so K+1 gets + 1 put; a rejected request does
// K gets and no put). `K` is therefore kept modest (8). At prod 1000/hr that is
// ~9000 reads/hr on this counter (negligible), and the per-key write rate at the
// leak threshold (3600/hr) falls to ~450/hr/key = ~0.125 writes/sec/key,
// comfortably under the ~1/sec/key cap. Race slack: the non-atomic
// read-then-write race is per shard,
// so the worst-case aggregate over-admit is bounded by ~K-1 concurrent
// in-flight increments (one per shard) instead of the limit - well under 1% of
// even the prod 1000 ceiling. The TTL and fail-closed-on-read policy are
// inherited verbatim from `check_kv_counter` (Wave 1/R2: `read_failed` set on
// any read error or timeout). A single shard's read failure fails the WHOLE
// check closed (the aggregate cannot be trusted), preserving the cash-equivalent
// minting bound.

/// Number of sub-keys the per-issuer blind-issuance counter is sharded across.
///
/// Chosen modestly: large enough that the per-key write rate stays well under
/// Cloudflare KV's ~1-write/sec/key cap at the undercount threshold, small
/// enough that the read fan-out (K sequential gets) stays cheap. See the module
/// comment above for the read=K-gets trade-off and the race-slack bound.
const BLIND_SHARD_COUNT: u32 = 8;

/// Per-isolate round-robin shard selector for the sharded blind counter.
///
/// `Math.random` is unavailable in the Workers runtime, so the shard index is
/// derived from a process-wide monotonic counter (mirrors `WORKER_REQUEST_COUNT`
/// in `lib.rs`). Round-robin spreads writes across shards deterministically
/// within an isolate but non-deterministically across the fleet, which is
/// strictly better than random for evening out the per-key write rate. The
/// counter is per-isolate and resets on cold start; that is fine because shard
/// *balance* - not a globally consistent index - is all that matters.
static BLIND_SHARD_CURSOR: AtomicU64 = AtomicU64::new(0);

/// Pick the next blind-counter shard index in `[0, BLIND_SHARD_COUNT)`.
// `BLIND_SHARD_COUNT` is a non-zero compile-time constant, so the `%` can never
// divide by zero; the wrapping `fetch_add` is intentional for a round-robin cursor.
#[allow(clippy::cast_possible_truncation, clippy::arithmetic_side_effects)]
fn next_blind_shard() -> u32 {
    // `fetch_add` wraps on overflow (acceptable for a round-robin cursor); the
    // modulo keeps the result in range regardless.
    (BLIND_SHARD_CURSOR.fetch_add(1, Ordering::Relaxed) % u64::from(BLIND_SHARD_COUNT)) as u32
}

/// Check the per-issuer hourly blind-issuance limit using a SHARDED counter.
///
/// Increments one of `BLIND_SHARD_COUNT` sub-keys
/// (`blind:{hashed_issuer_id}:{shard}|{hour}`) and SUMS all shards on read to
/// enforce the aggregate `limit`. This is the per-issuer counter ONLY; the
/// shared [`check_blind_issuance`] helper (used by the per-IP DoS caps) is
/// deliberately NOT sharded - see the module comment above.
///
/// `hashed_issuer_id` MUST already be the SHA-256-truncated issuer id (the
/// caller hashes it), so a future second issuer cannot collide shards.
///
/// Fail-closed: if ANY shard's read fails (KV error or timeout) the whole check
/// returns `allowed=false` with `read_failed=true`, because the aggregate count
/// cannot be trusted. This routes into R1's 503 + short Retry-After path exactly
/// like the unsharded counter.
pub async fn check_blind_issuance_sharded(
    rate_limit_kv: &KvStore,
    hashed_issuer_id: &str,
    limit: u32,
) -> RateLimitResult {
    #[allow(clippy::arithmetic_side_effects)]
    // Division and multiplication by the constant 3600 cannot overflow.
    let now_secs = timestamp_as_u64(chrono::Utc::now().timestamp()) / 3600 * 3600;
    let hour_ts = now_secs;

    let now_actual = timestamp_as_u64(chrono::Utc::now().timestamp());
    let retry_after =
        u32::try_from(hour_ts.saturating_add(3600).saturating_sub(now_actual)).unwrap_or(u32::MAX);

    // 1. Read and SUM all shards to obtain the current aggregate. A read
    //    failure on ANY shard fails the whole check closed: an untrusted
    //    partial sum must never be allowed to admit a cash-equivalent mint.
    let mut aggregate: u32 = 0;
    for shard in 0..BLIND_SHARD_COUNT {
        let key = format!("blind:{}:{}|{}", hashed_issuer_id, shard, hour_ts);
        // Reuse the Wave 1/R2 read primitive: bounded read, fail-closed +
        // read_failed=true on error/timeout. `limit` is irrelevant for the
        // read-only summation pass (we never use this call's `allowed`), so we
        // pass `u32::MAX` to suppress its internal over-limit early-return and
        // always obtain the shard's count.
        let (_allowed, shard_count, _limit, read_failed) =
            check_kv_counter_read_only(rate_limit_kv, &key).await;
        if read_failed {
            return RateLimitResult {
                allowed: false,
                current_count: aggregate,
                limit,
                retry_after_secs: READ_FAILURE_RETRY_AFTER_SECS,
                read_failed: true,
            };
        }
        aggregate = aggregate.saturating_add(shard_count);
    }

    // 2. Enforce the aggregate ceiling BEFORE writing.
    if aggregate >= limit {
        return RateLimitResult {
            allowed: false,
            current_count: aggregate,
            limit,
            retry_after_secs: retry_after,
            read_failed: false,
        };
    }

    // 3. Admit: increment exactly ONE shard (round-robin). The write is
    //    best-effort and non-atomic, identical to the unsharded counter; a
    //    write error/timeout is swallowed and never sets read_failed.
    let shard = next_blind_shard();
    let key = format!("blind:{}:{}|{}", hashed_issuer_id, shard, hour_ts);
    let (_allowed, _count, _limit, _read_failed) =
        check_kv_counter(rate_limit_kv, &key, u32::MAX, 7200).await;

    RateLimitResult {
        // The aggregate was below `limit`, so this request is admitted. Report
        // the aggregate-after-this-request as `current_count` for the headers.
        allowed: true,
        current_count: aggregate.saturating_add(1),
        limit,
        retry_after_secs: retry_after,
        read_failed: false,
    }
}

/// Read a KV counter WITHOUT incrementing it, reusing the same bounded-read /
/// fail-closed / `read_failed` semantics as [`check_kv_counter`].
///
/// Returns `(allowed_unused, current_count, limit_unused, read_failed)`. Used by
/// [`check_blind_issuance_sharded`] to sum shards on read without mutating them.
async fn check_kv_counter_read_only(kv: &KvStore, key: &str) -> (bool, u32, u32, bool) {
    let read = with_timeout(KV_READ_TIMEOUT_MS, kv.get(key).text()).await;
    match read {
        Ok(Ok(Some(s))) => (true, s.parse().unwrap_or(0), 0, false),
        Ok(Ok(None)) => (true, 0, 0, false),
        Ok(Err(_)) => {
            crate::log_error!(
                "[RateLimit] KV read failed for shard key={}; failing check closed (fail-closed)",
                key
            );
            (false, 0, 0, true)
        }
        Err(()) => {
            crate::log_error!(
                "[RateLimit] KV read timed out after {}ms for shard key={}; failing check closed (fail-closed)",
                KV_READ_TIMEOUT_MS,
                key
            );
            (false, 0, 0, true)
        }
    }
}

/// Set `X-RateLimit-*` headers on a response.
///
/// Adds:
/// - `X-RateLimit-Limit`     - max requests in the window
/// - `X-RateLimit-Remaining` - requests left in the window
/// - `X-RateLimit-Reset`     - Unix timestamp when the window resets
pub fn apply_rate_limit_headers(
    resp: &mut Response,
    result: &RateLimitResult,
) -> worker::Result<()> {
    let remaining = result.limit.saturating_sub(result.current_count);
    let reset = reset_timestamp();
    let h = resp.headers_mut();
    h.set("X-RateLimit-Limit", &result.limit.to_string())?;
    h.set("X-RateLimit-Remaining", &remaining.to_string())?;
    h.set("X-RateLimit-Reset", &reset.to_string())?;
    Ok(())
}

/// Build a 429 response with Retry-After and X-RateLimit-* headers.
pub fn rate_limit_response(result: &RateLimitResult) -> worker::Result<Response> {
    let body = serde_json::json!({
        "error": "Rate limit exceeded",
        "code": "RATE_LIMIT_EXCEEDED",
    });
    let mut resp = Response::from_json(&body)?;
    let headers = resp.headers_mut();
    headers.set("Content-Type", "application/json; charset=utf-8")?;
    headers.set("Retry-After", &result.retry_after_secs.to_string())?;
    // X-RateLimit-* headers (remaining is 0 since we're rate-limited)
    headers.set("X-RateLimit-Limit", &result.limit.to_string())?;
    headers.set("X-RateLimit-Remaining", "0")?;
    headers.set("X-RateLimit-Reset", &reset_timestamp().to_string())?;
    // Override status to 429
    Ok(resp.with_status(429))
}

/// Short Retry-After (seconds) advertised when a counter READ failed, so a
/// self-throttling SDK retries quickly after a transient KV blip rather than
/// backing off for up to an hour as it would for a genuine quota breach.
const READ_FAILURE_RETRY_AFTER_SECS: u32 = 5;

/// Build a 503 response with a short Retry-After, used when the counter READ
/// failed (KV error or timeout). The body is deliberately distinct from the
/// 429 quota body so a KV brownout is observable as infrastructure failure
/// rather than masquerading as a customer quota breach (R1/R2).
fn service_unavailable_on_read_failure() -> worker::Result<Response> {
    let body = serde_json::json!({
        "error": "Service temporarily unavailable",
        "code": "SERVICE_UNAVAILABLE",
    });
    let mut resp = Response::from_json(&body)?;
    let headers = resp.headers_mut();
    headers.set("Content-Type", "application/json; charset=utf-8")?;
    headers.set("Retry-After", &READ_FAILURE_RETRY_AFTER_SECS.to_string())?;
    headers.set(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, private",
    )?;
    Ok(resp.with_status(503))
}

/// Shared response builder for a denied volumetric check.
///
/// Returns 503 + short Retry-After when the counter READ failed (R1/R2), and
/// the existing 429 quota response otherwise. The admit/reject decision is made
/// upstream (`!result.allowed`); this only chooses the error code and
/// Retry-After header - it never changes whether the request is rejected.
pub fn rate_limit_or_unavailable_response(result: &RateLimitResult) -> worker::Result<Response> {
    if result.read_failed {
        service_unavailable_on_read_failure()
    } else {
        rate_limit_response(result)
    }
}

#[cfg(test)]
#[allow(clippy::cast_sign_loss)]
mod tests {
    use super::*;

    #[test]
    fn parse_tier_limits_nested_format() {
        let json = r#"{"tier_id":"gold","limits":{"challenge":500,"issuance":1000}}"#;
        let limits = parse_tier_limits(json);
        assert_eq!(limits.get("challenge"), Some(&500));
        assert_eq!(limits.get("issuance"), Some(&1000));
        assert_eq!(limits.len(), 2);
    }

    #[test]
    fn parse_tier_limits_flat_format() {
        let json = r#"{"challenge":200,"issuance":400}"#;
        let limits = parse_tier_limits(json);
        assert_eq!(limits.get("challenge"), Some(&200));
        assert_eq!(limits.get("issuance"), Some(&400));
    }

    #[test]
    fn parse_tier_limits_invalid_json_returns_empty() {
        let limits = parse_tier_limits("not json at all");
        assert!(limits.is_empty());
    }

    #[test]
    fn parse_tier_limits_empty_object_returns_empty() {
        let limits = parse_tier_limits("{}");
        assert!(limits.is_empty());
    }

    #[test]
    fn timestamp_as_u64_positive_values() {
        assert_eq!(timestamp_as_u64(0), 0);
        assert_eq!(timestamp_as_u64(1_700_000_000), 1_700_000_000);
    }

    #[test]
    fn timestamp_as_u64_negative_clamps_to_zero() {
        assert_eq!(timestamp_as_u64(-1), 0);
        assert_eq!(timestamp_as_u64(i64::MIN), 0);
    }

    #[test]
    fn reset_timestamp_is_future_and_hour_aligned() {
        let now_secs = chrono::Utc::now().timestamp() as u64;
        let reset = reset_timestamp();
        assert!(reset > now_secs);
        assert!(reset <= now_secs + 3600);
        assert_eq!(reset % 3600, 0);
    }

    // ---- R13: sharded blind-issuance counter --------------------------------

    #[test]
    fn blind_shard_index_always_in_range() {
        // Whatever the cursor value, the selected shard must be a valid index.
        for _ in 0..(BLIND_SHARD_COUNT as usize * 4 + 3) {
            let s = next_blind_shard();
            assert!(s < BLIND_SHARD_COUNT, "shard {} out of range", s);
        }
    }

    #[test]
    fn blind_shard_round_robin_covers_every_shard() {
        // Over one full cycle, round-robin selection must touch every shard
        // exactly once (so the per-key write rate is evenly ~1/K).
        let start = BLIND_SHARD_CURSOR.load(Ordering::Relaxed);
        let mut seen = vec![false; BLIND_SHARD_COUNT as usize];
        for _ in 0..BLIND_SHARD_COUNT {
            seen[next_blind_shard() as usize] = true;
        }
        assert!(
            seen.iter().all(|&b| b),
            "round-robin did not cover every shard within one cycle (start cursor={})",
            start
        );
    }

    #[test]
    fn blind_shard_count_is_modest_and_nonzero() {
        // Guards the read=K-gets trade-off documented above: K must be >=2 to
        // shard at all, and small enough that the read fan-out stays cheap.
        assert!(BLIND_SHARD_COUNT >= 2);
        assert!(BLIND_SHARD_COUNT <= 16);
    }
}
