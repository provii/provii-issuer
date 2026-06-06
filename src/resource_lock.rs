// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Helper functions for interacting with the ResourceLockDO Durable Object.
//!
//! Provides `acquire_resource_lock` and `release_resource_lock` for mutex-style
//! locking, plus `consume_resource_once` for one-time atomic consumption.
//!
//! All functions fail CLOSED: if the DO is unreachable or returns an unexpected
//! status, the caller receives an error rather than proceeding unlocked.

use crate::bindings;
use crate::durable_objects::resource_lock::{
    self, AcquireLockRequest, AcquireLockResponse, ConsumeResourceRequest, ConsumeResourceResponse,
    ReleaseLockRequest,
};
use crate::error::{ApiError, Result};
use worker::Env;

/// Default lock TTL in seconds (used when callers do not specify one).
/// Server-side cap is enforced by `MAX_LOCK_TTL_SECONDS` in the DO module.
const DEFAULT_LOCK_TTL_SECONDS: u64 = resource_lock::MAX_LOCK_TTL_SECONDS as u64;

/// Obtain a DO stub for the given resource key.
///
/// Shards across RESOURCE_LOCK_SHARD_COUNT instances via consistent hashing
/// to spread load.
fn get_stub(env: &Env, resource_key: &str) -> Result<worker::Stub> {
    let namespace = env
        .durable_object(bindings::RESOURCE_LOCK_DO)
        .map_err(|e| {
            ApiError::StorageError(format!(
                "Failed to get {} namespace: {}",
                bindings::RESOURCE_LOCK_DO,
                e
            ))
        })?;

    let shard_num = resource_lock::shard_index(resource_key);
    let shard_name = format!("lock-shard-{}", shard_num);

    let id = namespace.id_from_name(&shard_name).map_err(|e| {
        ApiError::StorageError(format!(
            "Failed to get DO ID for shard {}: {}",
            shard_name, e
        ))
    })?;

    id.get_stub()
        .map_err(|e| ApiError::StorageError(format!("Failed to get DO stub: {}", e)))
}

/// Build a POST request to the given path with a JSON body.
fn build_do_request(path: &str, body: &impl serde::Serialize) -> Result<worker::Request> {
    let body_str = serde_json::to_string(body)
        .map_err(|e| ApiError::StorageError(format!("Failed to serialise DO request: {}", e)))?;

    let headers = worker::Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| ApiError::StorageError(format!("Failed to set header: {}", e)))?;

    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_headers(headers)
        .with_body(Some(body_str.into()));

    let url = format!("https://resource-lock-do{}", path);
    worker::Request::new_with_init(&url, &init)
        .map_err(|e| ApiError::StorageError(format!("Failed to create DO request: {}", e)))
}

/// Generate a random lock token using CSPRNG.
fn generate_lock_token() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| ApiError::CryptoError(format!("Failed to generate lock token: {}", e)))?;
    Ok(hex::encode(bytes))
}

/// Acquire a mutex-style lock on the given resource key.
///
/// Returns the lock token on success. The caller MUST release the lock using
/// `release_resource_lock` with the returned token in all code paths (success
/// and error).
///
/// Fails CLOSED: returns `Err` if the DO is unreachable or the lock is
/// already held.
pub async fn acquire_resource_lock(env: &Env, resource_key: &str) -> Result<String> {
    acquire_resource_lock_with_ttl(env, resource_key, DEFAULT_LOCK_TTL_SECONDS).await
}

/// Acquire a mutex-style lock with a specific TTL.
///
/// TTL is capped server-side at 30 seconds regardless of the value passed here.
pub async fn acquire_resource_lock_with_ttl(
    env: &Env,
    resource_key: &str,
    ttl_seconds: u64,
) -> Result<String> {
    let stub = get_stub(env, resource_key)?;
    let lock_token = generate_lock_token()?;

    let body = AcquireLockRequest {
        lock_token: lock_token.clone(),
        ttl_seconds,
        resource_key: resource_key.to_string(),
    };

    let do_request = build_do_request("/acquire", &body)?;

    let mut response = stub.fetch_with_request(do_request).await.map_err(|e| {
        crate::log_error!("[ResourceLock] acquire failed for {}: {}", resource_key, e);
        ApiError::StorageError(format!("Resource lock acquire failed: {}", e))
    })?;

    if response.status_code() != 200 {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(ApiError::StorageError(format!(
            "Resource lock acquire returned status {}: {}",
            response.status_code(),
            error_text
        )));
    }

    let resp: AcquireLockResponse = response
        .json()
        .await
        .map_err(|e| ApiError::StorageError(format!("Failed to parse acquire response: {}", e)))?;

    if !resp.acquired {
        return Err(ApiError::Conflict(format!(
            "Resource lock contention on {}: {}",
            resource_key, resp.reason
        )));
    }

    crate::log!("[ResourceLock] acquired lock on {}", resource_key);
    Ok(lock_token)
}

/// Release a previously acquired lock.
///
/// Best-effort: logs a warning on failure but does not return an error,
/// because the lock has a TTL and will expire regardless. This prevents
/// release failures from masking the original operation's result.
pub async fn release_resource_lock(env: &Env, resource_key: &str, lock_token: &str) {
    let stub = match get_stub(env, resource_key) {
        Ok(s) => s,
        Err(e) => {
            crate::log_error!(
                "[ResourceLock] failed to get stub for release on {}: {}",
                resource_key,
                e
            );
            return;
        }
    };

    let body = ReleaseLockRequest {
        lock_token: lock_token.to_string(),
        resource_key: resource_key.to_string(),
    };

    let do_request = match build_do_request("/release", &body) {
        Ok(r) => r,
        Err(e) => {
            crate::log_error!(
                "[ResourceLock] failed to build release request for {}: {}",
                resource_key,
                e
            );
            return;
        }
    };

    match stub.fetch_with_request(do_request).await {
        Ok(mut resp) => {
            if resp.status_code() != 200 {
                let text = resp.text().await.unwrap_or_default();
                crate::log_error!(
                    "[ResourceLock] release returned {} for {}: {}",
                    resp.status_code(),
                    resource_key,
                    text
                );
            } else {
                crate::log!("[ResourceLock] released lock on {}", resource_key);
            }
        }
        Err(e) => {
            crate::log_error!(
                "[ResourceLock] release request failed for {}: {}",
                resource_key,
                e
            );
        }
    }
}

/// Atomically consume a one-time resource via the ResourceLockDO.
///
/// Returns `Ok(true)` if this was the first (and only) consumption,
/// `Ok(false)` if the resource was already consumed.
/// Returns `Err` if the DO is unreachable.
pub async fn consume_resource_once(
    env: &Env,
    resource_type: &str,
    resource_id: &str,
) -> Result<bool> {
    let resource_key = format!("{}:{}", resource_type, resource_id);
    let stub = get_stub(env, &resource_key)?;

    let body = ConsumeResourceRequest {
        resource_type: resource_type.to_string(),
        resource_id: resource_id.to_string(),
        metadata: None,
    };

    let do_request = build_do_request("/consume", &body)?;

    let mut response = stub.fetch_with_request(do_request).await.map_err(|e| {
        crate::log_error!(
            "[ResourceLock] consume failed for {}:{}: {}",
            resource_type,
            resource_id,
            e
        );
        ApiError::StorageError(format!("Resource consume failed: {}", e))
    })?;

    if response.status_code() != 200 {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(ApiError::StorageError(format!(
            "Resource consume returned status {}: {}",
            response.status_code(),
            error_text
        )));
    }

    let resp: ConsumeResourceResponse = response
        .json()
        .await
        .map_err(|e| ApiError::StorageError(format!("Failed to parse consume response: {}", e)))?;

    Ok(resp.allowed)
}
