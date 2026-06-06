// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Centralized KV namespace binding names.
//!
//! These constants define the binding names used to access KV namespaces.
//! The actual namespace IDs are configured in wrangler.toml.
//!
//! ## Production Environment
//! Uses PRODUCTION_ISSUER_* namespace titles with these bindings.
//!
//! ## Sandbox Environment
//! The sandbox deployment uses this repo as a submodule and can override
//! these constants to use SANDBOX_ISSUER_* namespaces instead.

/// KV namespace for active issuance sessions.
pub const ISSUER_SESSIONS: &str = "ISSUER_SESSIONS";

/// KV namespace for officer registry (YubiKey mappings).
pub const ISSUER_OFFICER_REGISTRY: &str = "ISSUER_OFFICER_REGISTRY";

/// KV namespace for signing keypairs.
pub const ISSUER_KEYS: &str = "ISSUER_KEYS";

/// KV namespace for issuer configuration.
pub const ISSUER_CONFIG: &str = "ISSUER_CONFIG";

/// KV namespace for rate limiting counters.
pub const ISSUER_RATE_LIMITS: &str = "ISSUER_RATE_LIMITS";

/// KV namespace for registered API clients.
pub const ISSUER_CLIENTS: &str = "ISSUER_CLIENTS";

/// KV namespace for YubiKey authentication challenges.
pub const ISSUER_CHALLENGES: &str = "ISSUER_CHALLENGES";

/// KV namespace for trusted issuer Ed25519 public keys (blind attestation).
pub const ISSUER_ED25519_KEYS: &str = "ISSUER_ED25519_KEYS";

/// KV namespace for issuer Ed25519 signing keys (encrypted, for attestation creation).
pub const ISSUER_ED25519_SIGNING_KEYS: &str = "ISSUER_ED25519_SIGNING_KEYS";

// --- Durable Object binding names ---

/// DO binding for the ResourceLockDO (atomic resource consumption and mutual exclusion).
pub const RESOURCE_LOCK_DO: &str = "RESOURCE_LOCK";

/// DO binding for the NonceDO (atomic nonce check-and-set for replay prevention).
pub const ISSUER_NONCE_DO: &str = "ISSUER_NONCE_DO";
