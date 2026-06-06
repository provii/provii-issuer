// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Per-isolate caching for Secrets Store values with a TTL.
//!
//! Cloudflare Workers Secrets Store reads are surprisingly expensive
//! (cross-context IPC on every call). Since secrets rotate at most
//! once per deployment, caching them for a few minutes within a single
//! isolate avoids redundant reads without meaningfully delaying
//! rotation propagation.
//!
//! Each cache slot is a `thread_local! { RefCell<Option<CachedEntry>> }`.
//! The generic helper `get_or_fetch` checks the TTL, clones a hit, or
//! runs the async `fetch` closure on a miss and stores the result.
#![forbid(unsafe_code)]

use std::cell::RefCell;
use worker::js_sys::Date;
use zeroize::Zeroizing;

/// A cached secret that stores only the Argon2id PHC hash string and
/// a 6-char public-safe fingerprint. The plaintext is never retained
/// in cache storage; it is zeroised immediately after hashing.
///
/// SECURITY: Argon2id-at-cache-time means a memory dump of the isolate
/// reveals only the one-way hash, not the recoverable plaintext. This
/// is strictly stronger than the previous SHA-256+ct_eq pattern, which
/// cached the plaintext wrapped in `Zeroizing<String>`.
pub struct CachedHashedSecret {
    /// Argon2id PHC-formatted hash, or `None` if the binding was absent,
    /// empty, or the hash operation failed. `None` is still cached so a
    /// misconfigured slot does not produce a Secrets Store read on every
    /// request inside the TTL window.
    pub argon2_hash: Option<String>,
    /// 6-char public-safe fingerprint of the plaintext token. Carries
    /// the `"000000"` sentinel when the slot is unbound.
    pub fingerprint: String,
    fetched_at_ms: f64,
}

/// A pair of cached byte vectors (current + optional previous) with a
/// fetch timestamp. Used for the KEK pair which stores raw decoded bytes
/// rather than strings.
pub struct CachedBytePair {
    pub current: Zeroizing<Vec<u8>>,
    pub previous: Option<Zeroizing<Vec<u8>>>,
    fetched_at_ms: f64,
}

/// Cache TTL: 5 minutes. After this period the next access re-fetches
/// from the Secrets Store. Short enough that a secret rotation
/// propagates within minutes; long enough to avoid hundreds of
/// redundant reads per isolate lifetime.
const CACHE_TTL_MS: f64 = 300_000.0;

/// Return a cached Argon2id hash + fingerprint for a secret, refreshing
/// from the Secrets Store on cache miss or TTL expiry.
///
/// On a cache miss the `fetch` closure retrieves the plaintext token from
/// the Secrets Store. The plaintext is immediately:
/// 1. Fingerprinted (6-char SHA-256 prefix for observability).
/// 2. Hashed with Argon2id (production parameters, random salt).
/// 3. Zeroised from memory.
///
/// Only the PHC hash string and fingerprint are stored in the cache.
/// A memory dump of the isolate therefore reveals no recoverable
/// plaintext, closing finding F-06.
///
/// SECURITY: The plaintext is wrapped in `Zeroizing<String>` and dropped
/// before the cache entry is written. The Argon2id PHC string is a
/// public hash, not secret material.
///
/// # Errors
///
/// Propagates any error from the `fetch` closure. An Argon2id hashing
/// failure is treated as a negative cache entry (hash = `None`) so the
/// auth path rejects rather than retrying on every request.
pub async fn get_or_fetch_hashed<F, Fut, E>(
    cache: &'static std::thread::LocalKey<RefCell<Option<CachedHashedSecret>>>,
    fetch: F,
) -> Result<(Option<String>, String), E>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<String, E>>,
{
    let now = Date::now();

    // Check for a valid cached entry.
    let hit = cache.with(|cell| {
        let borrow = cell.borrow();
        if let Some(entry) = borrow.as_ref() {
            let age = now - entry.fetched_at_ms;
            if (0.0..CACHE_TTL_MS).contains(&age) {
                return Some((entry.argon2_hash.clone(), entry.fingerprint.clone()));
            }
        }
        None
    });

    if let Some(pair) = hit {
        return Ok(pair);
    }

    // Cache miss or expired. Fetch the plaintext, hash it, store only
    // the hash + fingerprint.
    let fresh = fetch().await?;
    let zeroized = Zeroizing::new(fresh);

    let fingerprint = crate::secret_fingerprint::fingerprint6(zeroized.as_bytes());
    let argon2_hash = crate::hash::hash_api_key(&zeroized).ok();

    // The `zeroized` binding drops here, scrubbing the plaintext.

    cache.with(|cell| {
        *cell.borrow_mut() = Some(CachedHashedSecret {
            argon2_hash: argon2_hash.clone(),
            fingerprint: fingerprint.clone(),
            fetched_at_ms: now,
        });
    });

    Ok((argon2_hash, fingerprint))
}

/// Return a cached byte-pair if the TTL has not expired, otherwise run
/// `fetch` to obtain fresh values, store them, and return them.
///
/// # Errors
///
/// Propagates any error from the `fetch` closure.
pub async fn get_or_fetch_byte_pair<F, Fut, E>(
    cache: &'static std::thread::LocalKey<RefCell<Option<CachedBytePair>>>,
    fetch: F,
) -> Result<(Zeroizing<Vec<u8>>, Option<Zeroizing<Vec<u8>>>), E>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(Zeroizing<Vec<u8>>, Option<Zeroizing<Vec<u8>>>), E>>,
{
    let now = Date::now();

    // Check for a valid cached entry.
    let hit = cache.with(|cell| {
        let borrow = cell.borrow();
        if let Some(entry) = borrow.as_ref() {
            let age = now - entry.fetched_at_ms;
            if (0.0..CACHE_TTL_MS).contains(&age) {
                return Some((entry.current.clone(), entry.previous.clone()));
            }
        }
        None
    });

    if let Some(pair) = hit {
        return Ok(pair);
    }

    // Cache miss or expired. Fetch fresh values.
    let (current, previous) = fetch().await?;

    cache.with(|cell| {
        *cell.borrow_mut() = Some(CachedBytePair {
            current: current.clone(),
            previous: previous.clone(),
            fetched_at_ms: now,
        });
    });

    Ok((current, previous))
}

/// Test-only aggregator that flushes every secret-derived cache in the
/// crate. Mode B rotation drills call this during `hot_reload` between
/// rotation steps so the next request observes the freshly-mutated
/// MockSecret binding without sleeping past the 5-minute TTL.
///
/// Covers the thread_local cache slots in this crate:
///
/// - `kek::KEK_CACHE` (decoded ISSUER_KEK pair)
/// - `health::STATUS_TOKEN_CACHE` and `STATUS_TOKEN_PREV_CACHE`
/// - `routes::ADMIN_KEY_CACHE` and `ADMIN_KEY_PREV_CACHE`
///
/// Each per-module reset is itself `#[cfg(test)]`, so this aggregator and
/// the helpers it calls compile out of release builds.
#[cfg(test)]
#[allow(dead_code)]
pub fn reset_all_secret_caches_for_testing() {
    crate::kek::reset_for_testing();
    crate::health::reset_for_testing();
    crate::routes::reset_for_testing();
}
