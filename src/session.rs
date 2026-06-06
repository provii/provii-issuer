//! Session orchestration and authentication helpers for the issuer worker.

use crate::error::{ApiError, Result};
use crate::storage;
use crate::types::*;
use worker::Env;
use zeroize::Zeroizing;

pub(crate) const CHALLENGE_TTL_SECONDS: u64 = 120;
pub(crate) const AUTH_FAILURE_MESSAGE: &str = "Authentication failed";
const TIMESTAMP_WINDOW_SECONDS: i64 = 30; // 30-second window for replay protection

// Account lockout protection configuration
const MAX_FAILED_ATTEMPTS: u32 = 5;
const LOCKOUT_DURATION_SECONDS: u64 = 900; // 15 minutes

// R6 per-IP failed-attempt cap configuration.
//
// Net-new counter (NOT a re-key) that preserves the brute-force ceiling the
// now-IP-scoped officer lock would otherwise drop. The officer lock is keyed on
// (hashed officer_id, hashed source IP); an attacker rotating source IPs gets a
// FRESH per-(officer,IP) lock bucket per IP, so the per-officer lock alone no
// longer bounds a roaming attacker. This per-IP attempt cap is what throttles
// that attacker: it counts EVERY officer bad-HMAC failure from a source IP
// (across all officer_ids) and rejects once the cap is exceeded for the hour.
const AUTHFAIL_IP_LIMIT_PER_HOUR: u32 = 50;

/// Number of hex chars retained from each 64-char `hash_ip` output when
/// composing the officer-lockout composite actor id. 32 hex chars = 128 bits,
/// matching the existing issuer_id rate-limit-key truncation precedent
/// (`routes.rs`, `Sha256::digest(...).get(..16)`). Two 32-char hashes joined by
/// a ':' give a 65-char composite, comfortably under
/// `issuer_logic::identifier::MAX_IDENTIFIER_LENGTH` (128) so the composite
/// passes `validate_identifier` inside every storage primitive. A full
/// 64+1+64=129-char composite would EXCEED that limit and make every officer
/// lockout READ/SET return BadRequest - silently dropping the brute-force
/// ceiling AND 503-ing the legitimate officer. The truncation is therefore
/// load-bearing, not cosmetic.
const LOCKOUT_HASH_HEX_LEN: usize = 32;

/// Compose the officer-lockout composite actor id used by ALL FIVE officer
/// lockout sites (the two `is_locked_out` READs, the `record_auth_failure` SET,
/// the `lock_account` SET, and the `clear_auth_failures` clear).
///
/// Shape: `"{hash(officer_id)[..32]}:{hash(source_ip)[..32]}"`.
///
/// CONSISTENCY IS CRITICAL: the lock-SET path and both READ paths MUST use the
/// identical shape, or a roaming officer (NAT/mobile IP change between the
/// challenge READ and the attestation READ) is evaluated against a different
/// bucket and the lock is silently neutered (errs toward admitting a legitimate
/// officer). Routing every site through this one helper guarantees that.
///
/// `source_ip` is the edge-set, unspoofable `CF-Connecting-IP` value. Both
/// components are HMAC-SHA-256 hashed (via the audit `PrivacyContext`) so no
/// plaintext officer_id or IP is ever stored as a KV key name.
pub(crate) async fn officer_lockout_actor_id(
    env: &Env,
    officer_id: &str,
    source_ip: &str,
) -> String {
    let privacy = crate::audit::build_privacy_context(env).await;
    let officer_hash = privacy.hash_ip(officer_id).unwrap_or_default();
    let ip_hash = privacy.hash_ip(source_ip).unwrap_or_default();
    // Truncate each hash to 128 bits of hex so the composite fits within
    // MAX_IDENTIFIER_LENGTH and passes validate_identifier. `get(..N)` is safe
    // for both the normal 64-char hash and the empty-string fallback (returns
    // None -> falls back to the whole, still-short slice).
    let officer_trunc = officer_hash
        .get(..LOCKOUT_HASH_HEX_LEN)
        .unwrap_or(officer_hash.as_str());
    let ip_trunc = ip_hash
        .get(..LOCKOUT_HASH_HEX_LEN)
        .unwrap_or(ip_hash.as_str());
    format!("{}:{}", officer_trunc, ip_trunc)
}

/// Record a per-IP officer auth-failure against the hourly `authfail_ip:` cap
/// and return `true` if the cap is now EXCEEDED (i.e. this source IP should be
/// throttled). Net-new (R6): distinct key prefix from every existing counter
/// (`challenge_ip:`, `attestation_ip:`, `blind_ip:`, `global_post`,
/// `global_get`) so there is no bucket collision. Incremented ONLY on a genuine
/// officer bad-HMAC failure. Uses the shared `check_kv_counter` via
/// `check_blind_issuance` (fail-closed on KV read error), so a KV brownout
/// during a flood still throttles rather than admitting unbounded guesses.
///
/// On any inability to obtain the KV namespace this returns `false` (does not
/// itself reject): the per-(officer,IP) lock and the fail-closed
/// `record_auth_failure` SET remain the primary controls; this cap is the
/// supplementary roaming-attacker throttle.
async fn record_authfail_ip_and_check(env: &Env, source_ip: &str) -> bool {
    let kv = match env.kv(crate::bindings::ISSUER_RATE_LIMITS) {
        Ok(kv) => kv,
        Err(e) => {
            crate::log_error!(
                "[R6] authfail_ip KV namespace unavailable: {:?}; skipping per-IP cap",
                e
            );
            return false;
        }
    };
    let privacy = crate::audit::build_privacy_context(env).await;
    let ip_hash = privacy.hash_ip(source_ip).unwrap_or_default();
    let ip_key = format!("authfail_ip:{}", ip_hash);
    // check_blind_issuance increments the hourly counter and reports allowed
    // while count < limit; `!allowed` means the per-IP cap is exceeded.
    let result =
        crate::rate_limiting::check_blind_issuance(&kv, &ip_key, AUTHFAIL_IP_LIMIT_PER_HOUR).await;
    !result.allowed
}

/// READ-ONLY check of the per-IP officer auth-failure cap. Returns `true` when
/// the `authfail_ip:` hourly counter for `source_ip` already meets/exceeds
/// `AUTHFAIL_IP_LIMIT_PER_HOUR`. This NEVER increments the counter, so it is
/// safe to call from the unauthenticated `/v1/challenge` path, which the spec
/// requires to stay strictly read-only on lockout (it must not feed the failure
/// counter). Only the genuine bad-HMAC failure path
/// (`record_officer_failure_and_reject` -> `record_authfail_ip_and_check`)
/// increments the counter.
///
/// Fail-OPEN to `false` (not throttled) on any KV namespace/read error,
/// mirroring R5 FIX A for the lockout-status READ: a transient KV blip must not
/// throttle a legitimate officer whose source IP has not actually exceeded the
/// cap. The fail-CLOSED increment in `record_authfail_ip_and_check` still
/// bounds a real attacker.
pub(crate) async fn authfail_ip_exceeded(env: &Env, source_ip: &str) -> bool {
    let kv = match env.kv(crate::bindings::ISSUER_RATE_LIMITS) {
        Ok(kv) => kv,
        Err(e) => {
            crate::log_error!(
                "[R6] authfail_ip KV namespace unavailable for read-only check: {:?}; failing open",
                e
            );
            return false;
        }
    };
    let privacy = crate::audit::build_privacy_context(env).await;
    let ip_hash = privacy.hash_ip(source_ip).unwrap_or_default();
    let ip_key = format!("authfail_ip:{}", ip_hash);
    match kv.get(&ip_key).text().await {
        Ok(Some(s)) => s.parse::<u32>().unwrap_or(0) >= AUTHFAIL_IP_LIMIT_PER_HOUR,
        Ok(None) => false,
        Err(e) => {
            crate::log_error!(
                "[R6] authfail_ip read failed: {:?}; failing open (not throttled)",
                e
            );
            false
        }
    }
}

pub struct AuthHandler<'a> {
    env: &'a Env,
}

impl<'a> AuthHandler<'a> {
    /// Construct a handler that validates credentials using the given environment.
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }

    /// Validate an officer's YubiKey response against the stored challenge.
    ///
    /// When the caller already holds an `IssuerConfig`, pass it via
    /// `cached_config` to skip the redundant KV read inside
    /// `get_officer_by_id`.
    pub async fn authenticate_yubikey(
        &self,
        authorizer: &Authorizer,
        consume_challenge: bool,
        client_ip: &str,
        cached_config: Option<&IssuerConfig>,
    ) -> Result<String> {
        // Check for account lockout BEFORE any authentication attempt.
        // R6: the officer lock is keyed on the (hashed officer_id, hashed
        // source IP) composite, NOT the raw officer_id, so an attacker who
        // names a victim officer_id can no longer lock that officer across all
        // source IPs. This READ MUST use the identical composite shape as the
        // SET path (record_officer_failure_and_reject) and the other READ
        // (generate_yubikey_challenge), or a roaming officer is mis-evaluated.
        let lockout_actor = officer_lockout_actor_id(self.env, &authorizer.key_id, client_ip).await;
        if storage::is_locked_out(self.env, "officer", &lockout_actor).await? {
            self.audit_auth_failure(
                "yubikey",
                &authorizer.key_id,
                "Account locked out",
                client_ip,
            )
            .await;
            return Err(ApiError::Unauthorized(AUTH_FAILURE_MESSAGE.into()));
        }

        // R6: read-only per-IP throttle. If this source IP has already exceeded
        // the hourly officer auth-failure cap, fast-fail BEFORE the expensive
        // HMAC verification. This throttles a roaming attacker (who gets a fresh
        // per-(officer,IP) lock bucket per rotated IP) without locking any
        // single victim officer. Read-only: it never increments the counter, so
        // a legitimate officer is never penalised merely by being checked.
        if authfail_ip_exceeded(self.env, client_ip).await {
            self.audit_auth_failure(
                "yubikey",
                &authorizer.key_id,
                "Per-IP auth-failure cap exceeded",
                client_ip,
            )
            .await;
            return Err(ApiError::Unauthorized(AUTH_FAILURE_MESSAGE.into()));
        }

        let challenge_id = authorizer
            .challenge_id
            .as_ref()
            .ok_or_else(|| ApiError::BadRequest("Challenge ID required for Yubikey".into()))?;

        // Validate nonce (mandatory for replay protection)
        if !storage::validate_and_consume_nonce(self.env, &authorizer.nonce).await? {
            self.audit_auth_failure(
                "yubikey",
                &authorizer.key_id,
                "Nonce reuse detected",
                client_ip,
            )
            .await;
            return Err(ApiError::Unauthorized("Nonce already used".into()));
        }

        let stored_challenge = if consume_challenge {
            storage::get_and_consume_challenge(self.env, challenge_id).await?
        } else {
            storage::get_challenge(self.env, challenge_id).await?
        }
        .ok_or_else(|| ApiError::Unauthorized("Invalid or expired challenge".into()))?;

        if stored_challenge.officer_id != authorizer.key_id {
            return Err(ApiError::Unauthorized(
                "Challenge not valid for this officer".into(),
            ));
        }

        let officer =
            storage::get_officer_by_id_with_config(self.env, &authorizer.key_id, cached_config)
                .await?
                .ok_or_else(|| ApiError::NotFound("Officer not found".into()))?;

        if !officer.active {
            return Err(ApiError::Forbidden("Officer account inactive".into()));
        }

        use hmac::{Hmac, Mac};
        use sha1::Sha1; // YubiKeys only support HMAC-SHA1 in challenge-response mode

        // Wrap decoded HMAC tag in Zeroizing so it is cleared on drop.
        let provided_hmac: Zeroizing<Vec<u8>> = match hex::decode(&authorizer.hmac) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(_) => {
                return self
                    .record_officer_failure_and_reject(&authorizer.key_id, client_ip)
                    .await;
            }
        };

        // YubiKeys only support HMAC-SHA1 in challenge-response mode (hardware limitation).
        // During key rotation, try the current secret first, then fall back to
        // previous_hmac_secret if present. Uses hmac::Mac::verify_slice for
        // constant-time comparison.
        let hmac_valid = {
            let mut mac = Hmac::<Sha1>::new_from_slice(&officer.hmac_secret)
                .map_err(|e| ApiError::CryptoError(format!("HMAC error: {}", e)))?;
            mac.update(&stored_challenge.challenge);

            if mac.verify_slice(&provided_hmac).is_ok() {
                true
            } else if let Some(ref prev_secret) = officer.previous_hmac_secret {
                // Rotation window: try previous HMAC secret
                let mut prev_mac = Hmac::<Sha1>::new_from_slice(prev_secret).map_err(|e| {
                    ApiError::CryptoError(format!("HMAC error (previous key): {}", e))
                })?;
                prev_mac.update(&stored_challenge.challenge);
                prev_mac.verify_slice(&provided_hmac).is_ok()
            } else {
                false
            }
        };

        if !hmac_valid {
            return self
                .record_officer_failure_and_reject(&authorizer.key_id, client_ip)
                .await;
        }

        // Audit successful YubiKey authentication
        crate::audit::audit_log_with_actor(
            self.env,
            "authentication_success",
            client_ip,
            "Officer authenticated via YubiKey challenge-response",
            &serde_json::json!({
                "auth_type": "yubikey",
                "challenge_id": challenge_id,
            }),
            Some(&authorizer.key_id),
            Some(crate::audit::Outcome::Success),
        )
        .await;

        // Clear failed authentication attempts on successful auth.
        // R6: clear the SAME composite (hashed officer_id, hashed source IP)
        // bucket that the SET path writes; `lockout_actor` was composed above
        // from this officer_id + this request's source IP. Clearing the raw
        // officer_id key here would leave the composite counter/lock intact and
        // neuter the early self-unlock (R5 FIX D) for the re-keyed bucket.
        if let Err(e) = storage::clear_auth_failures(self.env, "officer", &lockout_actor).await {
            crate::log_error!(
                "Failed to clear auth failures for officer {}: {:?}",
                authorizer.key_id,
                e
            );
        }

        if consume_challenge {
            self.audit_event(
                "challenge_consumed",
                Some(&authorizer.key_id),
                None,
                serde_json::json!({"challenge_id": challenge_id}),
                client_ip,
            )
            .await;
        }

        storage::update_officer_last_used_by_id(self.env, &authorizer.key_id).await?;

        Ok(authorizer.key_id.clone())
    }

    /// Validate a client HMAC using the API key header and request payload.
    pub async fn authenticate_client(
        &self,
        authorizer: &Authorizer,
        canonical_message: &str,
        client_ip: &str,
    ) -> Result<ClientRegistration> {
        // NOTE: Account lockout is NOT enforced for client API keys because:
        // 1. They are shared credentials used by all users of a mobile app
        // 2. Lockout would enable trivial DoS attacks on legitimate users
        // 3. Rate limiting provides sufficient protection against brute force

        if authorizer.challenge_id.is_some() {
            return Err(ApiError::BadRequest(
                "Challenge ID not allowed for client auth".into(),
            ));
        }

        // Validate nonce (mandatory for replay protection)
        if !storage::validate_and_consume_nonce(self.env, &authorizer.nonce).await? {
            self.audit_auth_failure(
                "client",
                &authorizer.key_id,
                "Nonce reuse detected",
                client_ip,
            )
            .await;
            return Err(ApiError::Unauthorized("Nonce already used".into()));
        }

        // Look up client by key_id from the authorizer
        crate::log!("[AUTH] Looking up client by key_id: {}", authorizer.key_id);
        let client = match storage::get_client_by_id(self.env, &authorizer.key_id).await {
            Ok(Some(client)) => {
                crate::log!("[AUTH] Found client: {}", client.client_id);
                client
            }
            Ok(None) => {
                crate::log!("[AUTH] ERROR: Client not found: {}", authorizer.key_id);
                self.audit_auth_failure(
                    "client",
                    &authorizer.key_id,
                    "Invalid credentials",
                    client_ip,
                )
                .await;
                return Err(ApiError::Unauthorized(AUTH_FAILURE_MESSAGE.into()));
            }
            Err(e) => {
                crate::log!("[AUTH] ERROR: Failed to look up client: {:?}", e);
                return Err(ApiError::Unauthorized(AUTH_FAILURE_MESSAGE.into()));
            }
        };

        type HmacSha256 = hmac::Hmac<sha2::Sha256>;
        use hmac::Mac;

        // Wrap decoded HMAC tag in Zeroizing so it is cleared on drop.
        let provided_hmac: Zeroizing<Vec<u8>> = match hex::decode(&authorizer.hmac) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(_) => {
                self.audit_auth_failure(
                    "client",
                    &client.client_id,
                    "Invalid credentials",
                    client_ip,
                )
                .await;
                return Err(ApiError::Unauthorized(AUTH_FAILURE_MESSAGE.into()));
            }
        };

        // During key rotation, try the current HMAC secret first,
        // then fall back to previous_hmac_secret if present. This mirrors the
        // YubiKey path and enables zero-downtime key rotation for clients.
        let hmac_valid = {
            let mut mac = HmacSha256::new_from_slice(&client.hmac_secret)
                .map_err(|e| ApiError::CryptoError(format!("HMAC error: {}", e)))?;
            mac.update(canonical_message.as_bytes());

            if mac.verify_slice(&provided_hmac).is_ok() {
                true
            } else if let Some(ref prev_secret) = client.previous_hmac_secret {
                // Rotation window: try previous HMAC secret
                let mut prev_mac = HmacSha256::new_from_slice(prev_secret).map_err(|e| {
                    ApiError::CryptoError(format!("HMAC error (previous key): {}", e))
                })?;
                prev_mac.update(canonical_message.as_bytes());
                prev_mac.verify_slice(&provided_hmac).is_ok()
            } else {
                false
            }
        };

        if !hmac_valid {
            // NOTE: Account lockout disabled for API keys - it's a DoS vector.
            // Rate limiting provides sufficient protection against brute force.
            self.audit_auth_failure(
                "client",
                &client.client_id,
                "Invalid credentials",
                client_ip,
            )
            .await;
            return Err(ApiError::Unauthorized(AUTH_FAILURE_MESSAGE.into()));
        }

        // Audit successful client HMAC authentication
        crate::audit::audit_log_with_actor(
            self.env,
            "authentication_success",
            client_ip,
            "Client authenticated via HMAC-SHA256",
            &serde_json::json!({
                "auth_type": "client",
            }),
            Some(&client.client_id),
            Some(crate::audit::Outcome::Success),
        )
        .await;

        storage::update_client_last_used(self.env, &client).await?;

        Ok(client)
    }

    /// Fire-and-forget helper for recording audit events without blocking the caller.
    async fn audit_event(
        &self,
        event_type: &str,
        officer_id: Option<&str>,
        client_id: Option<&str>,
        details: serde_json::Value,
        client_ip: &str,
    ) {
        let mut merged = details.clone();
        if let Some(obj) = merged.as_object_mut() {
            if let Some(oid) = officer_id {
                obj.insert("officer_id".to_string(), serde_json::json!(oid));
            }
            if let Some(cid) = client_id {
                obj.insert("client_id".to_string(), serde_json::json!(cid));
            }
        }
        let _ = crate::audit::audit_log(self.env, event_type, client_ip, event_type, &merged).await;
    }

    /// Emit a structured audit trail for failed authentication attempts.
    async fn audit_auth_failure(&self, auth_type: &str, id: &str, reason: &str, client_ip: &str) {
        self.audit_event(
            "authentication_failed",
            if auth_type == "yubikey" {
                Some(id)
            } else {
                None
            },
            if auth_type == "client" {
                Some(id)
            } else {
                None
            },
            serde_json::json!({ "reason": reason, "auth_type": auth_type }),
            client_ip,
        )
        .await;
    }

    /// Record a failed officer authentication attempt, enforce lockout, and
    /// return the appropriate error. Consolidates the repeated
    /// record-failure / check-threshold / lock-account / audit pattern.
    ///
    /// Always returns `Err`; the generic `T` allows the caller to use this
    /// in any `Result<T>` position via `return self.record_officer_failure_and_reject(...)`.
    async fn record_officer_failure_and_reject<T>(
        &self,
        officer_id: &str,
        client_ip: &str,
    ) -> Result<T> {
        // R6: net-new per-IP failed-attempt cap. Increment ONCE per genuine
        // officer bad-HMAC failure and note whether this source IP has now
        // exceeded the hourly ceiling. This is the throttle that preserves the
        // brute-force bound now that the lock is per-(officer,IP): an attacker
        // rotating IPs gets a fresh per-officer lock bucket per IP, so without
        // this cap a roaming attacker could guess unbounded. Counted only here,
        // never on the read-only /v1/challenge path.
        let ip_cap_exceeded = record_authfail_ip_and_check(self.env, client_ip).await;

        // R6: lock/track on the (hashed officer_id, hashed source IP) composite
        // so naming a victim officer_id can no longer lock that officer across
        // all IPs. The SET (record_auth_failure) and the lock_account SET below
        // MUST use the identical composite the READ paths use.
        let lockout_actor = officer_lockout_actor_id(self.env, officer_id, client_ip).await;

        let failure_count = match storage::record_auth_failure(
            self.env,
            "officer",
            &lockout_actor,
            MAX_FAILED_ATTEMPTS,
        )
        .await
        {
            Ok(count) => count,
            Err(e) => {
                // Fail closed. Unknown failure count means we
                // cannot guarantee the lockout threshold is enforced.
                crate::log_error!(
                        "record_auth_failure storage error for officer {}: {:?}; rejecting (fail-closed)",
                        officer_id,
                        e,
                    );
                self.audit_auth_failure(
                    "yubikey",
                    officer_id,
                    "Auth rejected: lockout storage unavailable",
                    client_ip,
                )
                .await;
                return Err(ApiError::ServiceUnavailable(
                    "Authentication infrastructure unavailable".into(),
                ));
            }
        };

        if failure_count >= MAX_FAILED_ATTEMPTS {
            if let Err(e) = storage::lock_account(
                self.env,
                "officer",
                &lockout_actor,
                LOCKOUT_DURATION_SECONDS,
            )
            .await
            {
                crate::log_error!("Failed to lock account {}: {:?}", officer_id, e);
            }
            // Audit account lockout as Critical SecurityEvent. R6: include the
            // hashed source IP so operators can see the lock is now scoped to a
            // single (officer, IP) and correlate credential-stuffing sources.
            let privacy = crate::audit::build_privacy_context(self.env).await;
            let actor_ip_hash = privacy.hash_ip(client_ip).unwrap_or_default();
            crate::audit::audit_log_detailed(
                self.env,
                "account_locked",
                client_ip,
                "Officer account locked after repeated authentication failures",
                &serde_json::json!({
                    "officer_id": officer_id,
                    "actor_ip_hash": actor_ip_hash,
                    "failure_count": failure_count,
                    "lockout_duration_seconds": LOCKOUT_DURATION_SECONDS,
                }),
                crate::audit::DetailedAuditFields {
                    event_category: provii_audit::EventCategory::SecurityEvent,
                    actor_id: officer_id,
                    outcome: Some(crate::audit::Outcome::Denied),
                    severity: Some(provii_audit::Severity::Critical),
                },
            )
            .await;
        }

        // R6: when the per-IP cap is exceeded, surface a Critical audit signal
        // for the throttled source IP. The admit/deny outcome is unchanged (a
        // bad HMAC is still a 401 below); this only records that the roaming
        // attacker's IP has crossed the hourly attempt ceiling. The cap is then
        // enforced fast-fail on subsequent requests via the read-only
        // `authfail_ip_exceeded` check at the lockout entry points.
        if ip_cap_exceeded {
            let privacy = crate::audit::build_privacy_context(self.env).await;
            let actor_ip_hash = privacy.hash_ip(client_ip).unwrap_or_default();
            crate::audit::audit_log_detailed(
                self.env,
                "officer_auth_ip_throttled",
                client_ip,
                "Per-IP officer authentication-failure cap exceeded",
                &serde_json::json!({
                    "actor_ip_hash": actor_ip_hash,
                    "limit_per_hour": AUTHFAIL_IP_LIMIT_PER_HOUR,
                }),
                crate::audit::DetailedAuditFields {
                    event_category: provii_audit::EventCategory::SecurityEvent,
                    actor_id: "officer",
                    outcome: Some(crate::audit::Outcome::Denied),
                    severity: Some(provii_audit::Severity::Critical),
                },
            )
            .await;
        }

        self.audit_auth_failure("yubikey", officer_id, "Invalid credentials", client_ip)
            .await;
        Err(ApiError::Unauthorized(AUTH_FAILURE_MESSAGE.into()))
    }
}

/// Ensure request timestamps are recent enough to mitigate replay attacks.
///
/// The `timestamp` argument is a Unix timestamp in **seconds**, matching
/// what `chrono::Utc::now().timestamp()` returns. The window is
/// `TIMESTAMP_WINDOW_SECONDS = 30` seconds either side of "now".
///
/// This is intentionally tighter than `provii-verifier`, which uses a
/// 300-second window for its own HMAC canonical message. The unit (seconds)
/// is identical across both APIs; only the window width differs. Callers
/// supplying milliseconds will be rejected as far-future timestamps.
pub fn validate_timestamp(timestamp: u64) -> bool {
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
    let diff = now.abs_diff(timestamp);

    if diff > TIMESTAMP_WINDOW_SECONDS as u64 {
        crate::log!(
            "Timestamp validation failed: diff={} seconds (max={})",
            diff,
            TIMESTAMP_WINDOW_SECONDS
        );
        return false;
    }

    true
}

/// PROTOCOL CONTRACT: Canonical message for attestation HMAC verification.
///
/// Format: `"{timestamp}:{method}:{path}:{json_payload}:{nonce}"`
///
/// The `json_payload` component uses manual `format!()` for deterministic
/// field order. `serde_json` has implementation-defined field order that
/// could diverge across versions, silently breaking HMAC verification.
///
/// Fields included in `json_payload` (in this exact order):
///
/// 1. `dob_days` (i32, days since Unix epoch)
/// 2. `authorizer.format` ("yubikey" or "client")
/// 3. `authorizer.key_id` (authenticating key identifier)
/// 4. `authorizer.timestamp` (u64)
///
/// Excluded fields: `authorizer.hmac` (it is the HMAC output itself),
/// `authorizer.nonce` (already present as a top-level component in the
/// canonical form), `authorizer.challenge_id` (optional, not part of the
/// protocol contract).
///
/// Cross-references for implementations that must produce byte-identical
/// output for the same inputs:
///
/// - Rust: this function
/// - iOS: `provii-mobile/ios/.../Core/Services/HmacSigner.swift`
/// - Android: `provii-mobile/android/.../network/HmacSigner.kt`
///
/// WARNING: any change to this format breaks HMAC verification for all
/// deployed mobile clients. All implementations (Rust, Swift, Kotlin)
/// must produce byte-identical output for the same inputs.
///
/// Returns `Zeroizing<String>` because the canonical message
/// contains plaintext `dob_days` (PII). The wrapper ensures the heap
/// allocation is zeroed when it goes out of scope.
///
/// See also: [`CANONICAL_MESSAGE_VERSION`].
pub const CANONICAL_MESSAGE_VERSION: u8 = 1;

pub fn create_canonical_message_for_attestation(
    method: &str,
    path: &str,
    timestamp: u64,
    dob_days: i32,
    authorizer: &Authorizer,
) -> Zeroizing<String> {
    // Manually construct JSON to guarantee exact field ordering matching mobile app.
    let format_json = serde_json::to_string(&authorizer.format).unwrap_or_default();
    let key_id_json = serde_json::to_string(&authorizer.key_id).unwrap_or_default();

    let payload_json = format!(
        r#"{{"dob_days":{},"authorizer":{{"format":{},"key_id":{},"timestamp":{}}}}}"#,
        dob_days, format_json, key_id_json, authorizer.timestamp
    );

    Zeroizing::new(format!(
        "{}:{}:{}:{}:{}",
        timestamp, method, path, payload_json, authorizer.nonce
    ))
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

    /* ========================================================================== */
    /*                    VALIDATE_TIMESTAMP TESTS (REPLAY ATTACK PREVENTION)   */
    /* ========================================================================== */

    #[test]
    fn test_validate_timestamp_current() {
        let now = chrono::Utc::now().timestamp() as u64;
        assert!(validate_timestamp(now));
    }

    #[test]
    fn test_validate_timestamp_30_seconds_future() {
        // Allows up to 30 seconds in the future for clock skew
        let now = chrono::Utc::now().timestamp() as u64;
        let future = now + 30;
        assert!(validate_timestamp(future));
    }

    #[test]
    fn test_validate_timestamp_31_seconds_future_rejected() {
        // Rejects more than 30 seconds in the future
        let now = chrono::Utc::now().timestamp() as u64;
        let future = now + 31;
        assert!(!validate_timestamp(future));
    }

    #[test]
    fn test_validate_timestamp_30_seconds_past() {
        // Allows up to 30 seconds in the past (TIMESTAMP_WINDOW_SECONDS)
        let now = chrono::Utc::now().timestamp() as u64;
        let past = now.saturating_sub(30);
        assert!(validate_timestamp(past));
    }

    #[test]
    fn test_validate_timestamp_31_seconds_past_rejected() {
        // Rejects more than 30 seconds in the past
        let now = chrono::Utc::now().timestamp() as u64;
        let past = now.saturating_sub(31);
        assert!(!validate_timestamp(past));
    }

    #[test]
    fn test_validate_timestamp_far_future() {
        let now = chrono::Utc::now().timestamp() as u64;
        let far_future = now + 3600; // 1 hour in future
        assert!(!validate_timestamp(far_future));
    }

    #[test]
    fn test_validate_timestamp_far_past() {
        let now = chrono::Utc::now().timestamp() as u64;
        let far_past = now.saturating_sub(3600); // 1 hour in past
        assert!(!validate_timestamp(far_past));
    }

    #[test]
    fn test_validate_timestamp_boundary_future() {
        // Test exact boundary
        let now = chrono::Utc::now().timestamp() as u64;
        let boundary = now + 30;
        assert!(validate_timestamp(boundary));
    }

    #[test]
    fn test_validate_timestamp_boundary_past() {
        // Test exact boundary (30 seconds = TIMESTAMP_WINDOW_SECONDS)
        let now = chrono::Utc::now().timestamp() as u64;
        let boundary = now.saturating_sub(30);
        assert!(validate_timestamp(boundary));
    }

    #[test]
    fn test_validate_timestamp_zero() {
        // Epoch start should be rejected
        assert!(!validate_timestamp(0));
    }

    /* ========================================================================== */
    /*                    CONSTANTS VALIDATION TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_challenge_ttl_value() {
        assert_eq!(CHALLENGE_TTL_SECONDS, 120); // 2 minutes
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_challenge_ttl_bounds() {
        assert!(
            CHALLENGE_TTL_SECONDS >= 30 && CHALLENGE_TTL_SECONDS <= 600,
            "Challenge TTL should be between 30 seconds and 10 minutes"
        );
    }
}
