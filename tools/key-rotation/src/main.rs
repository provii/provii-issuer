// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

// tools/key-rotation/src/main.rs
//! Admin CLI tool for rotating cryptographic keys and secrets in the Provii issuer.
//!
//! This tool provides secure key rotation functionality with:
//! - Zero-downtime signing key rotation
//! - Graceful HMAC secret rotation with transition periods
//! - KEK rotation with re-encryption of all envelope-encrypted data
//! - Full audit logging
//! - Dry-run mode for testing

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Parser, Subcommand};
use provii_crypto_sig_redjubjub::generate_keypair;
use rand::thread_rng;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "key-rotation")]
#[command(about = "Issuer service key rotation tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Cloudflare account ID
    #[arg(long, env = "CLOUDFLARE_ACCOUNT_ID")]
    account_id: String,

    /// Cloudflare API token (env only, never pass as CLI arg)
    #[arg(env = "CLOUDFLARE_API_TOKEN", hide = true)]
    api_token: Zeroizing<String>,

    /// KV namespace ID for keys
    #[arg(long, env = "KV_KEYS_NAMESPACE_ID")]
    kv_keys_id: String,

    /// KV namespace ID for officers
    #[arg(long, env = "KV_OFFICERS_NAMESPACE_ID")]
    kv_officers_id: String,

    /// KV namespace ID for clients
    #[arg(long, env = "KV_CLIENTS_NAMESPACE_ID")]
    kv_clients_id: String,

    /// KV namespace ID for Ed25519 signing keys
    #[arg(long, env = "KV_ED25519_SIGNING_KEYS_NAMESPACE_ID", default_value = "")]
    kv_ed25519_signing_keys_id: String,

    /// KV namespace ID for sessions (optional, sessions are TTL-bound)
    #[arg(long, env = "KV_SESSIONS_NAMESPACE_ID", default_value = "")]
    kv_sessions_id: String,

    /// Operator ID (for audit logging)
    #[arg(long, env = "OPERATOR_ID", default_value = "admin")]
    operator: String,

    /// Current KEK (base64url) for encrypting new secrets before storage.
    /// Required for rotate-signing-key, rotate-officer-hmac, and
    /// rotate-client-hmac commands. Without this, the worker will reject
    /// the stored key material as unencrypted.
    #[arg(env = "ISSUER_KEK", hide = true, default_value = "")]
    kek: Zeroizing<String>,

    /// Enable dry-run mode (no changes)
    #[arg(long)]
    dry_run: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Rotate a signing keypair (always generates new keypair)
    RotateSigningKey {
        /// Old key ID to deprecate
        #[arg(long)]
        old_kid: String,

        /// New key ID to create
        #[arg(long)]
        new_kid: String,
    },

    /// Rotate an officer's HMAC secret (always generates new secret)
    RotateOfficerHmac {
        /// Officer ID
        #[arg(long)]
        officer_id: String,
    },

    /// Finalize officer HMAC rotation (remove old secret)
    FinalizeOfficerHmac {
        /// Officer ID
        #[arg(long)]
        officer_id: String,
    },

    /// Rotate a client's HMAC secret (always generates new secret)
    RotateClientHmac {
        /// Client ID
        #[arg(long)]
        client_id: String,
    },

    /// Finalize client HMAC rotation (remove old secret)
    FinalizeClientHmac {
        /// Client ID
        #[arg(long)]
        client_id: String,
    },

    /// Rotate the Key Encryption Key (KEK) and re-encrypt all envelope-encrypted data
    RotateKek {
        /// Old KEK (base64url, env only)
        #[arg(env = "ISSUER_KEK_OLD", hide = true)]
        old_kek: Zeroizing<String>,

        /// New KEK (base64url, env only, if not generating)
        #[arg(env = "ISSUER_KEK_NEW", hide = true, default_value = "")]
        new_kek: Zeroizing<String>,

        /// Generate new KEK automatically (32 bytes)
        #[arg(long)]
        generate: bool,

        /// Only verify that all entries decrypt with the new KEK (no writes)
        #[arg(long)]
        verify_only: bool,

        /// Also re-encrypt sessions (ephemeral, normally unnecessary)
        #[arg(long)]
        include_sessions: bool,

        /// Skip interactive confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Verify KEK rotation status: report how many entries decrypt with current vs previous KEK
    VerifyRotation {
        /// Current KEK (base64url, env only)
        #[arg(env = "ISSUER_KEK", hide = true)]
        current_kek: Zeroizing<String>,

        /// Previous KEK (base64url, env only, optional)
        #[arg(env = "ISSUER_KEK_PREVIOUS", hide = true, default_value = "")]
        previous_kek: Zeroizing<String>,

        /// Also check sessions
        #[arg(long)]
        include_sessions: bool,
    },

    /// List all signing keys with their status
    ListSigningKeys,

    /// Show officer HMAC status
    ShowOfficer {
        /// Officer ID
        #[arg(long)]
        officer_id: String,
    },

    /// Show client HMAC status
    ShowClient {
        /// Client ID
        #[arg(long)]
        client_id: String,
    },
}

// ── Encrypted data categories ───────────────────────────────────────────────

/// Describes how a given field within a KV entry is encrypted, including its
/// JSON path and the AAD string used for AES-256-GCM binding.
#[derive(Debug, Clone)]
struct EncryptedField {
    /// JSON pointer path to the field (e.g. "hmac_secret")
    json_key: &'static str,
    /// AAD used during encrypt/decrypt
    aad: AadSource,
    /// Whether the field is optional (e.g. previous_hmac_secret)
    optional: bool,
}

#[derive(Debug, Clone)]
enum AadSource {
    /// Fixed AAD string
    Fixed(&'static [u8]),
    /// AAD derived from the record's "version" field: "provii-issuer:signing-key:{version}"
    SigningKeyVersion,
}

/// Describes a KV namespace that contains KEK-encrypted entries.
#[derive(Debug)]
struct EncryptedNamespace {
    label: &'static str,
    namespace_id_fn: fn(&Cli) -> &str,
    /// Key prefix filter (only process keys starting with this)
    key_prefix: &'static str,
    /// Fields within each JSON record that are encrypted
    fields: Vec<EncryptedField>,
    /// Whether the record has an "encrypted" boolean flag that must be true
    requires_encrypted_flag: bool,
}

fn get_kv_keys_id(cli: &Cli) -> &str {
    &cli.kv_keys_id
}
fn get_kv_officers_id(cli: &Cli) -> &str {
    &cli.kv_officers_id
}
fn get_kv_clients_id(cli: &Cli) -> &str {
    &cli.kv_clients_id
}
fn get_kv_ed25519_signing_keys_id(cli: &Cli) -> &str {
    &cli.kv_ed25519_signing_keys_id
}
fn get_kv_sessions_id(cli: &Cli) -> &str {
    &cli.kv_sessions_id
}

/// Build the list of namespaces that contain KEK-encrypted data.
fn encrypted_namespaces(include_sessions: bool) -> Vec<EncryptedNamespace> {
    let mut ns = vec![
        // RedJubjub signing keys: "sk" field encrypted with version-specific AAD
        EncryptedNamespace {
            label: "RedJubjub Signing Keys (ISSUER_KEYS)",
            namespace_id_fn: get_kv_keys_id,
            key_prefix: "issuer:",
            fields: vec![EncryptedField {
                json_key: "sk",
                aad: AadSource::SigningKeyVersion,
                optional: false,
            }],
            requires_encrypted_flag: true,
        },
        // Officer registrations: hmac_secret and previous_hmac_secret
        EncryptedNamespace {
            label: "Officer Registrations (ISSUER_OFFICER_REGISTRY)",
            namespace_id_fn: get_kv_officers_id,
            key_prefix: "issuer:",
            fields: vec![
                EncryptedField {
                    json_key: "hmac_secret",
                    aad: AadSource::Fixed(b"provii-issuer:session:v1"),
                    optional: false,
                },
                EncryptedField {
                    json_key: "previous_hmac_secret",
                    aad: AadSource::Fixed(b"provii-issuer:session:v1"),
                    optional: true,
                },
            ],
            requires_encrypted_flag: true,
        },
        // Client registrations: hmac_secret, previous_hmac_secret, and api_key_hash
        EncryptedNamespace {
            label: "Client Registrations (ISSUER_CLIENTS)",
            namespace_id_fn: get_kv_clients_id,
            key_prefix: "issuer:",
            fields: vec![
                EncryptedField {
                    json_key: "hmac_secret",
                    aad: AadSource::Fixed(b"provii-issuer:session:v1"),
                    optional: false,
                },
                EncryptedField {
                    json_key: "previous_hmac_secret",
                    aad: AadSource::Fixed(b"provii-issuer:session:v1"),
                    optional: true,
                },
                EncryptedField {
                    json_key: "api_key_hash",
                    aad: AadSource::Fixed(b"provii-issuer:api-key-hash:v1"),
                    optional: false,
                },
            ],
            requires_encrypted_flag: true,
        },
    ];

    // Ed25519 signing keys (separate namespace, may not be configured)
    ns.push(EncryptedNamespace {
        label: "Ed25519 Signing Keys (ISSUER_ED25519_SIGNING_KEYS)",
        namespace_id_fn: get_kv_ed25519_signing_keys_id,
        key_prefix: "signing:",
        fields: vec![EncryptedField {
            json_key: "signing_key",
            aad: AadSource::Fixed(b"provii-issuer:ed25519-key:v1"),
            optional: false,
        }],
        requires_encrypted_flag: true,
    });

    if include_sessions {
        // Sessions are stored as base64url(nonce||ciphertext), not as JSON with
        // individual encrypted fields. They get special handling.
        ns.push(EncryptedNamespace {
            label: "Sessions (ISSUER_SESSIONS)",
            namespace_id_fn: get_kv_sessions_id,
            key_prefix: "session:",
            fields: vec![], // Whole-blob encryption, handled separately
            requires_encrypted_flag: false,
        });
    }

    ns
}

// ── HTTP client builder ────────────────────────────────────────────────────

/// Build a reqwest Client with sensible defaults: 30s timeout, TLS 1.2 minimum.
fn build_http_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()
        .context("Failed to build HTTP client")
}

// ── Input validation ──────────────────────────────────────────────────────

/// Validate an identifier parameter (kid, officer_id, client_id).
/// Must be non-empty, at most 128 characters, and contain only ASCII
/// alphanumeric characters, hyphens, underscores, or dots.
fn validate_identifier(name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        anyhow::bail!("{} must not be empty", name);
    }
    if value.len() > 128 {
        anyhow::bail!("{} must be at most 128 characters (got {})", name, value.len());
    }
    if !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        anyhow::bail!(
            "{} contains invalid characters (allowed: ASCII alphanumeric, hyphen, underscore, dot)",
            name
        );
    }
    Ok(())
}

// ── Standalone AES-256-GCM encrypt/decrypt (no worker dependency) ───────────

/// Decrypt AES-256-GCM: input is nonce (12 bytes) || ciphertext+tag.
/// Returns the plaintext wrapped in Zeroizing to ensure it is cleared from memory.
fn aes_gcm_decrypt(kek: &[u8], data: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < 12 {
        anyhow::bail!("encrypted data too short ({} bytes, need >= 12)", data.len());
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(kek)
        .map_err(|e| anyhow::anyhow!("invalid KEK: {}", e))?;

    let plaintext = cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {}", e))?;

    Ok(Zeroizing::new(plaintext))
}

/// Encrypt AES-256-GCM: output is nonce (12 bytes) || ciphertext+tag.
fn aes_gcm_encrypt(kek: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(kek)
        .map_err(|e| anyhow::anyhow!("invalid KEK: {}", e))?;

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| anyhow::anyhow!("nonce generation failed: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {}", e))?;

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

// ── KV API helpers ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct KvListResponse {
    result: Vec<KvKeyInfo>,
    result_info: KvListResultInfo,
    success: bool,
}

#[derive(Deserialize)]
struct KvKeyInfo {
    name: String,
}

#[derive(Deserialize)]
struct KvListResultInfo {
    cursor: String,
    count: u64,
}

/// List all keys in a KV namespace, handling pagination.
async fn list_kv_keys(client: &Client, cli: &Cli, namespace_id: &str) -> Result<Vec<String>> {
    let mut all_keys = Vec::new();
    let mut cursor: Option<String> = None;

    loop {
        let mut url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/storage/kv/namespaces/{}/keys",
            cli.account_id, namespace_id
        );

        if let Some(ref c) = cursor {
            url.push_str(&format!("?cursor={}", urlencoding::encode(c)));
        }

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", cli.api_token.as_str()))
            .send()
            .await?
            .error_for_status()?;

        let body: KvListResponse = response.json().await?;

        if !body.success {
            anyhow::bail!("KV list API returned success=false");
        }

        for key_info in &body.result {
            all_keys.push(key_info.name.clone());
        }

        // If count is 0 or cursor is empty, we've reached the end
        if body.result_info.count == 0 || body.result_info.cursor.is_empty() {
            break;
        }

        cursor = Some(body.result_info.cursor);
    }

    Ok(all_keys)
}

/// Read a raw KV value by namespace ID (not by key-prefix routing).
async fn get_kv_value_by_ns(
    client: &Client,
    cli: &Cli,
    namespace_id: &str,
    key: &str,
) -> Result<Option<String>> {
    let url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/storage/kv/namespaces/{}/values/{}",
        cli.account_id, namespace_id, urlencoding::encode(key)
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", cli.api_token.as_str()))
        .send()
        .await?;

    if response.status().as_u16() == 404 {
        return Ok(None);
    }

    let value = response.error_for_status()?.text().await?;
    Ok(Some(value))
}

/// Write a raw KV value by namespace ID.
async fn put_kv_value_by_ns(
    client: &Client,
    cli: &Cli,
    namespace_id: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    let url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/storage/kv/namespaces/{}/values/{}",
        cli.account_id, namespace_id, urlencoding::encode(key)
    );

    client
        .put(&url)
        .header("Authorization", format!("Bearer {}", cli.api_token.as_str()))
        .body(value.to_string())
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Validate identifier parameters early
    match &cli.command {
        Commands::RotateSigningKey { old_kid, new_kid } => {
            validate_identifier("old_kid", old_kid)?;
            validate_identifier("new_kid", new_kid)?;
        }
        Commands::RotateOfficerHmac { officer_id }
        | Commands::FinalizeOfficerHmac { officer_id }
        | Commands::ShowOfficer { officer_id } => {
            validate_identifier("officer_id", officer_id)?;
        }
        Commands::RotateClientHmac { client_id }
        | Commands::FinalizeClientHmac { client_id }
        | Commands::ShowClient { client_id } => {
            validate_identifier("client_id", client_id)?;
        }
        _ => {}
    }

    println!("Issuer Service Key Rotation Tool");
    println!("Operator: {}", cli.operator);
    if cli.dry_run {
        println!("  DRY RUN MODE - No changes will be made");
    }
    println!();

    match &cli.command {
        Commands::RotateSigningKey {
            old_kid,
            new_kid,
        } => {
            rotate_signing_key(&cli, old_kid, new_kid).await?
        }
        Commands::RotateOfficerHmac {
            officer_id,
        } => rotate_officer_hmac(&cli, officer_id).await?,
        Commands::FinalizeOfficerHmac { officer_id } => {
            finalize_officer_hmac(&cli, officer_id).await?
        }
        Commands::RotateClientHmac {
            client_id,
        } => rotate_client_hmac(&cli, client_id).await?,
        Commands::FinalizeClientHmac { client_id } => {
            finalize_client_hmac(&cli, client_id).await?
        }
        Commands::RotateKek {
            old_kek,
            new_kek,
            generate,
            verify_only,
            include_sessions,
            yes,
        } => {
            rotate_kek(&cli, old_kek, *generate, new_kek, *verify_only, *include_sessions, *yes).await?
        }
        Commands::VerifyRotation {
            current_kek,
            previous_kek,
            include_sessions,
        } => {
            let prev = if previous_kek.is_empty() { None } else { Some(previous_kek.as_str()) };
            verify_rotation(&cli, current_kek, prev, *include_sessions).await?
        }
        Commands::ListSigningKeys => list_signing_keys(&cli).await?,
        Commands::ShowOfficer { officer_id } => show_officer(&cli, officer_id).await?,
        Commands::ShowClient { client_id } => show_client(&cli, client_id).await?,
    }

    Ok(())
}

async fn rotate_signing_key(
    cli: &Cli,
    old_kid: &str,
    new_kid: &str,
) -> Result<()> {
    println!("Rotating signing keypair: {} -> {}", old_kid, new_kid);

    println!("Generating new RedJubjub keypair...");
    let (sk, vk) = generate_keypair();
    println!("  Generated new keypair");
    println!("  VK: {}", URL_SAFE_NO_PAD.encode(vk));
    let (sk_bytes, vk_bytes) = (Zeroizing::new(sk.to_vec()), vk.to_vec());

    if cli.dry_run {
        println!("  DRY RUN: Would rotate signing keypair");
        return Ok(());
    }

    // Encrypt the signing key with the KEK before storing. The worker's
    // get_signing_keypair rejects unencrypted keys, so we must encrypt here.
    if cli.kek.is_empty() {
        anyhow::bail!(
            "KEK is required for signing key rotation. Set ISSUER_KEK env var. \
             The worker rejects unencrypted key material."
        );
    }
    let kek_bytes = URL_SAFE_NO_PAD
        .decode(cli.kek.as_bytes())
        .context("Failed to decode KEK from base64url")?;
    if kek_bytes.len() != 32 {
        anyhow::bail!("KEK must be exactly 32 bytes, got {}", kek_bytes.len());
    }

    let client = build_http_client()?;

    // AUD-IA-04-008: TOCTOU mitigation. The rotation steps are:
    //   1. Load old key (verify it exists)
    //   2. Store new key as "active"
    //   3. Deprecate old key
    // If step 3 fails, the system has two active keys, which is
    // detectable (the worker logs a warning for multiple active keys)
    // and recoverable by re-running the tool. This ordering is safer
    // than deprecate-first because a failure after deprecation but
    // before storing the new key leaves zero active keys (outage).
    //
    // WARNING: This tool is run manually by an operator. Concurrent
    // invocations are not safe (no distributed lock). Ensure only one
    // operator runs rotation at a time. Use --dry-run first to verify
    // the pre-rotation state.

    // Step 1: Load and verify old key exists
    println!("Loading old keypair: {}", old_kid);
    let old_key_name = format!("rj:keypair:{}", old_kid);
    let old_key_data = get_kv_value(&client, cli, &old_key_name).await?;

    let mut old_keypair: serde_json::Value = if let Some(data) = old_key_data {
        serde_json::from_str(&data)?
    } else {
        anyhow::bail!("Old keypair not found: {}", old_kid);
    };

    // Step 2: Encrypt and store the new key first
    // AAD matches the format used by the worker: "provii-issuer:signing-key:v1".
    println!("Encrypting and storing new key...");
    let sk_encrypted = aes_gcm_encrypt(&kek_bytes, &*sk_bytes, b"provii-issuer:signing-key:v1")
        .context("Failed to encrypt signing key with KEK")?;

    let new_keypair = json!({
        "kid": new_kid,
        "sk": URL_SAFE_NO_PAD.encode(&sk_encrypted),
        "vk": URL_SAFE_NO_PAD.encode(&vk_bytes),
        "encrypted": true,
        "version": "v1",
        "status": "active",
        "created_at": chrono::Utc::now().timestamp(),
        "deprecated_at": null,
        "revoked_at": null
    });

    let new_key_json = Zeroizing::new(new_keypair.to_string());
    let new_key_name = format!("rj:keypair:{}", new_kid);
    put_kv_value(&client, cli, &new_key_name, &new_key_json).await?;

    // Step 3: Deprecate the old key (after new key is safely stored)
    old_keypair["status"] = json!("deprecated");
    old_keypair["deprecated_at"] = json!(chrono::Utc::now().timestamp());

    println!("Storing deprecated old key...");
    put_kv_value(&client, cli, &old_key_name, &old_keypair.to_string()).await?;

    println!("  Signing keypair rotated successfully");
    println!("  Old key ({}) marked as deprecated", old_kid);
    println!("  New key ({}) is now active", new_kid);
    println!();
    println!("IMPORTANT: Update DEFAULT_KID environment variable to: {}", new_kid);

    Ok(())
}

async fn rotate_officer_hmac(
    cli: &Cli,
    officer_id: &str,
) -> Result<()> {
    println!("Rotating HMAC secret for officer: {}", officer_id);

    println!("Generating new HMAC secret (32 bytes)...");
    let mut secret = vec![0u8; 32];
    use rand::RngCore;
    thread_rng().fill_bytes(&mut secret);
    println!("  Generated new HMAC secret (redacted)");
    let secret_bytes = Zeroizing::new(secret);

    if secret_bytes.len() != 32 {
        anyhow::bail!("HMAC secret must be exactly 32 bytes");
    }

    if cli.dry_run {
        println!("  DRY RUN: Would rotate officer HMAC secret");
        return Ok(());
    }

    // Encrypt HMAC secret with KEK before storing. The worker rejects
    // unencrypted secrets.
    if cli.kek.is_empty() {
        anyhow::bail!(
            "KEK is required for officer HMAC rotation. Set ISSUER_KEK env var. \
             The worker rejects unencrypted secret material."
        );
    }
    let kek_bytes = URL_SAFE_NO_PAD
        .decode(cli.kek.as_bytes())
        .context("Failed to decode KEK from base64url")?;
    if kek_bytes.len() != 32 {
        anyhow::bail!("KEK must be exactly 32 bytes, got {}", kek_bytes.len());
    }

    let client = build_http_client()?;
    let key = format!("officer:id:{}", officer_id);

    println!("Loading officer record...");
    let officer_data = get_kv_value(&client, cli, &key).await?
        .context("Officer not found")?;

    let mut officer: serde_json::Value = serde_json::from_str(&officer_data)?;

    // Encrypt the new HMAC secret with KEK using the same AAD the worker
    // expects: "provii-issuer:session:v1".
    let encrypted_secret = aes_gcm_encrypt(&kek_bytes, &*secret_bytes, b"provii-issuer:session:v1")
        .context("Failed to encrypt officer HMAC secret with KEK")?;

    // Store current secret as previous
    officer["previous_hmac_secret"] = officer["hmac_secret"].clone();
    officer["hmac_secret"] = json!(URL_SAFE_NO_PAD.encode(&encrypted_secret));
    officer["encrypted"] = json!(true);
    officer["secret_status"] = json!("active");

    let officer_json = Zeroizing::new(officer.to_string());
    println!("Updating officer record...");
    put_kv_value(&client, cli, &key, &officer_json).await?;

    println!("  Officer HMAC secret rotated successfully (encrypted with KEK)");
    println!("  Both old and new secrets are now valid");
    println!("  Run 'finalize-officer-hmac' to remove the old secret");

    Ok(())
}

async fn finalize_officer_hmac(cli: &Cli, officer_id: &str) -> Result<()> {
    println!("Finalizing HMAC rotation for officer: {}", officer_id);

    if cli.dry_run {
        println!("  DRY RUN: Would finalize officer HMAC rotation");
        return Ok(());
    }

    let client = build_http_client()?;
    let key = format!("officer:id:{}", officer_id);

    println!("Loading officer record...");
    let officer_data = get_kv_value(&client, cli, &key).await?
        .context("Officer not found")?;

    let mut officer: serde_json::Value = serde_json::from_str(&officer_data)?;

    // Remove previous secret
    officer["previous_hmac_secret"] = json!(null);

    println!("Updating officer record...");
    put_kv_value(&client, cli, &key, &officer.to_string()).await?;

    println!("  Officer HMAC rotation finalized");
    println!("  Only the new secret is now valid");

    Ok(())
}

async fn rotate_client_hmac(
    cli: &Cli,
    client_id: &str,
) -> Result<()> {
    println!("Rotating HMAC secret for client: {}", client_id);

    println!("Generating new HMAC secret (32 bytes)...");
    let mut secret = vec![0u8; 32];
    use rand::RngCore;
    thread_rng().fill_bytes(&mut secret);
    println!("  Generated new HMAC secret (redacted)");
    let secret_bytes = Zeroizing::new(secret);

    if secret_bytes.len() != 32 {
        anyhow::bail!("HMAC secret must be exactly 32 bytes");
    }

    if cli.dry_run {
        println!("  DRY RUN: Would rotate client HMAC secret");
        return Ok(());
    }

    // Encrypt HMAC secret with KEK before storing. The worker rejects
    // unencrypted secrets.
    if cli.kek.is_empty() {
        anyhow::bail!(
            "KEK is required for client HMAC rotation. Set ISSUER_KEK env var. \
             The worker rejects unencrypted secret material."
        );
    }
    let kek_bytes = URL_SAFE_NO_PAD
        .decode(cli.kek.as_bytes())
        .context("Failed to decode KEK from base64url")?;
    if kek_bytes.len() != 32 {
        anyhow::bail!("KEK must be exactly 32 bytes, got {}", kek_bytes.len());
    }

    let client = build_http_client()?;
    let key_id = format!("client:id:{}", client_id);

    println!("Loading client record...");
    let client_data = get_kv_value(&client, cli, &key_id).await?
        .context("Client not found")?;

    let mut client_rec: serde_json::Value = serde_json::from_str(&client_data)?;

    // Encrypt the new HMAC secret with KEK using the same AAD the worker
    // expects: "provii-issuer:session:v1".
    let encrypted_secret = aes_gcm_encrypt(&kek_bytes, &*secret_bytes, b"provii-issuer:session:v1")
        .context("Failed to encrypt client HMAC secret with KEK")?;

    // Store current secret as previous
    client_rec["previous_hmac_secret"] = client_rec["hmac_secret"].clone();
    client_rec["hmac_secret"] = json!(URL_SAFE_NO_PAD.encode(&encrypted_secret));
    client_rec["encrypted"] = json!(true);
    client_rec["secret_status"] = json!("active");

    let api_key_hash = client_rec["api_key_hash"].as_str()
        .context("Missing api_key_hash")?
        .to_string();

    let client_json = Zeroizing::new(client_rec.to_string());
    println!("Updating client record...");
    put_kv_value(&client, cli, &key_id, &client_json).await?;

    // Update API key index, write only the client_id mapping, NOT the full
    // record which contains encrypted secrets. The index exists solely to
    // look up the canonical client:id:{id} key by api_key_hash.
    let key_api = format!("client:api:{}", api_key_hash);
    let index_value = json!({"client_id": client_id}).to_string();
    put_kv_value(&client, cli, &key_api, &index_value).await?;

    println!("  Client HMAC secret rotated successfully (encrypted with KEK)");
    println!("  Both old and new secrets are now valid");
    println!("  Run 'finalize-client-hmac' to remove the old secret");

    Ok(())
}

async fn finalize_client_hmac(cli: &Cli, client_id: &str) -> Result<()> {
    println!("Finalizing HMAC rotation for client: {}", client_id);

    if cli.dry_run {
        println!("  DRY RUN: Would finalize client HMAC rotation");
        return Ok(());
    }

    let client = build_http_client()?;
    let key_id = format!("client:id:{}", client_id);

    println!("Loading client record...");
    let client_data = get_kv_value(&client, cli, &key_id).await?
        .context("Client not found")?;

    let mut client_rec: serde_json::Value = serde_json::from_str(&client_data)?;

    // Remove previous secret
    client_rec["previous_hmac_secret"] = json!(null);

    let api_key_hash = client_rec["api_key_hash"].as_str()
        .context("Missing api_key_hash")?;

    println!("Updating client record...");
    put_kv_value(&client, cli, &key_id, &client_rec.to_string()).await?;

    // Update API key index, write only the client_id mapping, NOT the full
    // record which contains secrets. The index is a lookup pointer only.
    let key_api = format!("client:api:{}", api_key_hash);
    let index_value = json!({"client_id": client_id}).to_string();
    put_kv_value(&client, cli, &key_api, &index_value).await?;

    println!("  Client HMAC rotation finalized");
    println!("  Only the new secret is now valid");

    Ok(())
}

// ── KEK rotation: the core of this tool ─────────────────────────────────────

async fn rotate_kek(
    cli: &Cli,
    old_kek_b64: &Zeroizing<String>,
    generate: bool,
    new_kek_b64: &Zeroizing<String>,
    verify_only: bool,
    include_sessions: bool,
    skip_confirm: bool,
) -> Result<()> {
    if verify_only {
        println!("KEK Rotation VERIFY-ONLY mode");
    } else {
        println!("Rotating Key Encryption Key (KEK)");
        println!("WARNING: This is a critical operation that re-encrypts all secrets.");

        if !skip_confirm {
            println!();
            println!("This will re-encrypt ALL envelope-encrypted data with a new KEK.");
            println!("Type 'yes' to proceed:");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)
                .context("Failed to read confirmation from stdin")?;
            if input.trim() != "yes" {
                println!("Aborted.");
                return Ok(());
            }
        }
    }

    // Decode old KEK
    let old_kek = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(old_kek_b64.as_bytes())
            .context("Failed to decode old KEK (ISSUER_KEK_OLD)")?,
    );
    if old_kek.len() != 32 {
        anyhow::bail!("Old KEK must be exactly 32 bytes, got {}", old_kek.len());
    }

    // Obtain or generate new KEK
    let new_kek = Zeroizing::new(if generate {
        println!("Generating new KEK (32 bytes)...");
        let mut kek = vec![0u8; 32];
        use rand::RngCore;
        thread_rng().fill_bytes(&mut kek);
        println!("  Generated new KEK (redacted)");
        kek
    } else {
        if new_kek_b64.is_empty() {
            anyhow::bail!("ISSUER_KEK_NEW env var required when not using --generate");
        }
        URL_SAFE_NO_PAD
            .decode(new_kek_b64.as_bytes())
            .context("Failed to decode new KEK from ISSUER_KEK_NEW")?
    });
    if new_kek.len() != 32 {
        anyhow::bail!("New KEK must be exactly 32 bytes, got {}", new_kek.len());
    }

    if cli.dry_run && !verify_only {
        println!("  DRY RUN: Would re-encrypt all secrets with new KEK");
        println!("  Namespaces that would be processed:");
        for ns in &encrypted_namespaces(include_sessions) {
            println!("    - {}", ns.label);
        }
        return Ok(());
    }

    let http = build_http_client()?;
    let namespaces = encrypted_namespaces(include_sessions);

    let mut total_processed: u64 = 0;
    let mut total_re_encrypted: u64 = 0;
    let mut total_skipped: u64 = 0;
    let mut total_failed: u64 = 0;
    let mut failed_entries: Vec<String> = Vec::new();

    for ns in &namespaces {
        let ns_id = (ns.namespace_id_fn)(cli);
        if ns_id.is_empty() {
            println!("[SKIP] {} (namespace ID not configured)", ns.label);
            continue;
        }

        println!("\n[{}]", ns.label);
        println!("  Listing keys in namespace {}...", ns_id);

        let all_keys = list_kv_keys(&http, cli, ns_id).await?;

        let filtered_keys: Vec<&String> = all_keys
            .iter()
            .filter(|k| k.starts_with(ns.key_prefix))
            .collect();

        println!("  Found {} keys ({} matching prefix \"{}\")",
                 all_keys.len(), filtered_keys.len(), ns.key_prefix);

        // Sessions use whole-blob encryption, not JSON field encryption
        let is_session_ns = ns.label.contains("Sessions");

        // AUD-IA-04-009: Two-phase re-encryption. Phase 1 re-encrypts all
        // entries in memory. If ANY entry fails decryption or re-encryption,
        // we abort before writing anything, leaving KV in a consistent
        // old-KEK state. Phase 2 writes all successfully re-encrypted
        // entries only after the entire namespace passes Phase 1.
        //
        // RECOVERY: If a partial failure *does* occur during the Phase 2
        // write (network error mid-batch), the operator should:
        //   1. Set ISSUER_KEK_PREVIOUS to the old KEK
        //   2. Deploy the worker (it will try both KEKs on decrypt)
        //   3. Re-run this tool with --verify-only to identify which
        //      entries are on which KEK
        //   4. Re-run without --verify-only to complete re-encryption

        // Phase 1: Read and re-encrypt all entries in memory
        struct StagedEntry {
            kv_key: String,
            new_value: Zeroizing<String>,
            fields_processed: u32,
        }
        let mut staged_writes: Vec<StagedEntry> = Vec::new();
        let mut ns_failed = false;

        for (idx, kv_key) in filtered_keys.iter().enumerate() {
            total_processed = total_processed.saturating_add(1);
            let progress = format!("[{}/{}]", idx.saturating_add(1), filtered_keys.len());

            let raw_value = match get_kv_value_by_ns(&http, cli, ns_id, kv_key).await? {
                Some(v) => v,
                None => {
                    println!("  {} {} - not found (deleted concurrently?), skipping", progress, kv_key);
                    total_skipped = total_skipped.saturating_add(1);
                    continue;
                }
            };

            if is_session_ns {
                // Session: the entire value is base64url(nonce||ciphertext)
                match re_encrypt_session_blob(
                    &old_kek, &new_kek, &raw_value, verify_only,
                ) {
                    Ok(new_blob) => {
                        if verify_only {
                            println!("  {} {} - OK (decrypts with new KEK)", progress, kv_key);
                        } else if let Some(blob) = new_blob {
                            staged_writes.push(StagedEntry {
                                kv_key: kv_key.to_string(),
                                new_value: Zeroizing::new(blob),
                                fields_processed: 1,
                            });
                            println!("  {} {} - re-encrypted (staged)", progress, kv_key);
                        }
                    }
                    Err(e) => {
                        eprintln!("  {} {} - FAILED: {}", progress, kv_key, e);
                        total_failed = total_failed.saturating_add(1);
                        failed_entries.push(format!("{}:{}", ns.label, kv_key));
                        ns_failed = true;
                    }
                }
                continue;
            }

            // JSON record with individually encrypted fields
            let mut record: serde_json::Value = match serde_json::from_str(&raw_value) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("  {} {} - FAILED: invalid JSON: {}", progress, kv_key, e);
                    total_failed = total_failed.saturating_add(1);
                    failed_entries.push(format!("{}:{}", ns.label, kv_key));
                    ns_failed = true;
                    continue;
                }
            };

            // Check encrypted flag if required
            if ns.requires_encrypted_flag {
                let encrypted = record.get("encrypted").and_then(|v| v.as_bool()).unwrap_or(false);
                if !encrypted {
                    println!("  {} {} - skipped (encrypted=false, plaintext record)", progress, kv_key);
                    total_skipped = total_skipped.saturating_add(1);
                    continue;
                }
            }

            let mut any_failed = false;
            let mut fields_processed = 0u32;

            for field in &ns.fields {
                let aad_bytes: Vec<u8> = match &field.aad {
                    AadSource::Fixed(b) => b.to_vec(),
                    AadSource::SigningKeyVersion => {
                        let version = record
                            .get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("v1");
                        format!("provii-issuer:signing-key:{}", version).into_bytes()
                    }
                };

                // Read the field value. It might be stored as a JSON array of
                // u8 (serde Vec<u8> default) or as a base64url string.
                let field_val = record.get(field.json_key);
                let encrypted_bytes: Option<Vec<u8>> = match field_val {
                    None | Some(serde_json::Value::Null) => {
                        if field.optional {
                            None
                        } else {
                            eprintln!("    field \"{}\" missing (required)", field.json_key);
                            any_failed = true;
                            continue;
                        }
                    }
                    Some(serde_json::Value::String(s)) => {
                        // Base64url encoded (e.g. signing key "sk" field)
                        match URL_SAFE_NO_PAD.decode(s.as_bytes()) {
                            Ok(b) => Some(b),
                            Err(e) => {
                                eprintln!("    field \"{}\" base64 decode failed: {}", field.json_key, e);
                                any_failed = true;
                                continue;
                            }
                        }
                    }
                    Some(serde_json::Value::Array(arr)) => {
                        // JSON array of u8 (serde default for Vec<u8>)
                        let bytes: Result<Vec<u8>, _> = arr
                            .iter()
                            .map(|v| {
                                v.as_u64()
                                    .and_then(|n| u8::try_from(n).ok())
                                    .ok_or_else(|| anyhow::anyhow!("non-u8 value in array"))
                            })
                            .collect();
                        match bytes {
                            Ok(b) => Some(b),
                            Err(e) => {
                                eprintln!("    field \"{}\" array parse failed: {}", field.json_key, e);
                                any_failed = true;
                                continue;
                            }
                        }
                    }
                    Some(other) => {
                        eprintln!("    field \"{}\" has unexpected type: {}", field.json_key, other);
                        any_failed = true;
                        continue;
                    }
                };

                let encrypted_bytes = match encrypted_bytes {
                    Some(b) => b,
                    None => continue, // optional field not present
                };

                if verify_only {
                    // Just try to decrypt with new KEK
                    match aes_gcm_decrypt(&new_kek, &encrypted_bytes, &aad_bytes) {
                        Ok(_) => {
                            fields_processed = fields_processed.saturating_add(1);
                        }
                        Err(e) => {
                            eprintln!("    field \"{}\" VERIFY FAILED (does not decrypt with new KEK): {}",
                                     field.json_key, e);
                            any_failed = true;
                        }
                    }
                } else {
                    // Decrypt with old KEK, re-encrypt with new KEK
                    let plaintext = match aes_gcm_decrypt(&old_kek, &encrypted_bytes, &aad_bytes) {
                        Ok(pt) => pt,
                        Err(e) => {
                            eprintln!("    field \"{}\" decrypt failed: {}", field.json_key, e);
                            any_failed = true;
                            continue;
                        }
                    };

                    let new_ciphertext = aes_gcm_encrypt(&new_kek, &plaintext, &aad_bytes)?;

                    // Write back in the same format as the original
                    match field_val {
                        Some(serde_json::Value::String(_)) => {
                            record[field.json_key] =
                                json!(URL_SAFE_NO_PAD.encode(&new_ciphertext));
                        }
                        Some(serde_json::Value::Array(_)) => {
                            let arr: Vec<serde_json::Value> = new_ciphertext
                                .iter()
                                .map(|&b| json!(b))
                                .collect();
                            record[field.json_key] = serde_json::Value::Array(arr);
                        }
                        _ => {
                            // Should not reach here (we handled all cases above)
                            record[field.json_key] =
                                json!(URL_SAFE_NO_PAD.encode(&new_ciphertext));
                        }
                    }

                    fields_processed = fields_processed.saturating_add(1);
                }
            }

            if any_failed {
                total_failed = total_failed.saturating_add(1);
                failed_entries.push(format!("{}:{}", ns.label, kv_key));
                eprintln!("  {} {} - PARTIAL FAILURE ({} fields ok)", progress, kv_key, fields_processed);
                ns_failed = true;
            } else if verify_only {
                println!("  {} {} - OK ({} fields verified)", progress, kv_key, fields_processed);
            } else {
                // Stage the re-encrypted record (do not write yet)
                staged_writes.push(StagedEntry {
                    kv_key: kv_key.to_string(),
                    new_value: Zeroizing::new(record.to_string()),
                    fields_processed,
                });
                println!("  {} {} - re-encrypted (staged, {} fields)", progress, kv_key, fields_processed);
            }
        }

        // Phase 2: Write all staged entries only if no failures in this namespace
        if ns_failed && !verify_only {
            eprintln!("  [{}] ABORTING WRITES: {} entries were staged but not written because one or more entries failed re-encryption.",
                     ns.label, staged_writes.len());
            eprintln!("  Fix the failing entries and re-run. No data in this namespace was modified.");
        } else if !verify_only {
            for staged in &staged_writes {
                if !cli.dry_run {
                    put_kv_value_by_ns(&http, cli, ns_id, &staged.kv_key, &staged.new_value).await?;
                }
                total_re_encrypted = total_re_encrypted.saturating_add(1);
                println!("  [WRITE] {} - committed ({} fields)", staged.kv_key, staged.fields_processed);
            }
        }
    }

    // Summary
    println!("\n--- Summary ---");
    println!("  Total entries processed: {}", total_processed);
    if verify_only {
        println!("  Verified OK:            {}", total_processed.saturating_sub(total_failed).saturating_sub(total_skipped));
        println!("  Skipped:                {}", total_skipped);
        println!("  Failed verification:    {}", total_failed);
    } else {
        println!("  Re-encrypted:           {}", total_re_encrypted);
        println!("  Skipped:                {}", total_skipped);
        println!("  Failed:                 {}", total_failed);
    }

    if !failed_entries.is_empty() {
        eprintln!("\nFailed entries:");
        for entry in &failed_entries {
            eprintln!("  - {}", entry);
        }
    }

    if !verify_only && total_failed == 0 {
        println!("\nRe-encryption complete. Next steps:");
        println!("  1. Update ISSUER_KEK in Secrets Store to the new value");
        println!("  2. Set ISSUER_KEK_PREVIOUS to the old KEK value");
        println!("  3. Deploy the worker");
        println!("  4. Run this tool again with --verify-only to confirm");
        println!("  5. After confirming, remove ISSUER_KEK_PREVIOUS from Secrets Store");
    }

    if total_failed > 0 {
        anyhow::bail!("{} entries failed to process. See errors above.", total_failed);
    }

    Ok(())
}

/// Re-encrypt a session blob (base64url-encoded nonce||ciphertext).
/// Returns Ok(Some(new_base64)) if re-encrypted, Ok(None) if verify-only succeeded.
fn re_encrypt_session_blob(
    old_kek: &[u8],
    new_kek: &[u8],
    raw_value: &str,
    verify_only: bool,
) -> Result<Option<String>> {
    let encrypted_bytes = URL_SAFE_NO_PAD
        .decode(raw_value.as_bytes())
        .context("session value is not valid base64url")?;

    let aad = b"provii-issuer:session:v1";

    if verify_only {
        aes_gcm_decrypt(new_kek, &encrypted_bytes, aad)
            .context("session does not decrypt with new KEK")?;
        return Ok(None);
    }

    let plaintext = aes_gcm_decrypt(old_kek, &encrypted_bytes, aad)
        .context("session decrypt with old KEK failed")?;

    let new_encrypted = aes_gcm_encrypt(new_kek, &plaintext, aad)?;
    Ok(Some(URL_SAFE_NO_PAD.encode(&new_encrypted)))
}

// ── VerifyRotation command ──────────────────────────────────────────────────

async fn verify_rotation(
    cli: &Cli,
    current_kek_b64: &Zeroizing<String>,
    previous_kek_b64: Option<&str>,
    include_sessions: bool,
) -> Result<()> {
    println!("Verifying KEK rotation status");
    println!("  Checking which KEK each entry decrypts with.\n");

    let current_kek = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(current_kek_b64.as_bytes())
            .context("Failed to decode current KEK")?,
    );
    if current_kek.len() != 32 {
        anyhow::bail!("Current KEK must be 32 bytes");
    }

    let previous_kek: Option<Zeroizing<Vec<u8>>> = match previous_kek_b64 {
        Some(b64) => {
            let decoded = Zeroizing::new(
                URL_SAFE_NO_PAD
                    .decode(b64.as_bytes())
                    .context("Failed to decode previous KEK")?,
            );
            if decoded.len() != 32 {
                anyhow::bail!("Previous KEK must be 32 bytes");
            }
            Some(decoded)
        }
        None => {
            println!("  No previous KEK provided. Only checking current KEK.\n");
            None
        }
    };

    let http = build_http_client()?;
    let namespaces = encrypted_namespaces(include_sessions);

    let mut total_current: u64 = 0;
    let mut total_previous: u64 = 0;
    let mut total_neither: u64 = 0;
    let mut total_skipped: u64 = 0;

    for ns in &namespaces {
        let ns_id = (ns.namespace_id_fn)(cli);
        if ns_id.is_empty() {
            println!("[SKIP] {} (namespace ID not configured)", ns.label);
            continue;
        }

        println!("[{}]", ns.label);

        let all_keys = list_kv_keys(&http, cli, ns_id).await?;
        let filtered_keys: Vec<&String> = all_keys
            .iter()
            .filter(|k| k.starts_with(ns.key_prefix))
            .collect();

        let is_session_ns = ns.label.contains("Sessions");

        for kv_key in &filtered_keys {
            let raw_value = match get_kv_value_by_ns(&http, cli, ns_id, kv_key).await? {
                Some(v) => v,
                None => {
                    total_skipped = total_skipped.saturating_add(1);
                    continue;
                }
            };

            if is_session_ns {
                let encrypted_bytes = match URL_SAFE_NO_PAD.decode(raw_value.as_bytes()) {
                    Ok(b) => b,
                    Err(_) => {
                        total_skipped = total_skipped.saturating_add(1);
                        continue;
                    }
                };
                let aad = b"provii-issuer:session:v1";

                if aes_gcm_decrypt(&current_kek, &encrypted_bytes, aad).is_ok() {
                    total_current = total_current.saturating_add(1);
                } else if let Some(ref prev) = previous_kek {
                    if aes_gcm_decrypt(prev, &encrypted_bytes, aad).is_ok() {
                        total_previous = total_previous.saturating_add(1);
                        println!("  {} - decrypts with PREVIOUS KEK", kv_key);
                    } else {
                        total_neither = total_neither.saturating_add(1);
                        eprintln!("  {} - FAILS with both KEKs", kv_key);
                    }
                } else {
                    total_neither = total_neither.saturating_add(1);
                    eprintln!("  {} - FAILS with current KEK", kv_key);
                }
                continue;
            }

            // JSON record
            let record: serde_json::Value = match serde_json::from_str(&raw_value) {
                Ok(v) => v,
                Err(_) => {
                    total_skipped = total_skipped.saturating_add(1);
                    continue;
                }
            };

            if ns.requires_encrypted_flag {
                let encrypted = record.get("encrypted").and_then(|v| v.as_bool()).unwrap_or(false);
                if !encrypted {
                    total_skipped = total_skipped.saturating_add(1);
                    continue;
                }
            }

            // Try the first non-optional field to determine which KEK works
            let mut entry_result = EntryDecryptResult::Skipped;

            for field in &ns.fields {
                let aad_bytes: Vec<u8> = match &field.aad {
                    AadSource::Fixed(b) => b.to_vec(),
                    AadSource::SigningKeyVersion => {
                        let version = record
                            .get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("v1");
                        format!("provii-issuer:signing-key:{}", version).into_bytes()
                    }
                };

                let encrypted_bytes = match extract_bytes_from_json(record.get(field.json_key)) {
                    Some(b) => b,
                    None => {
                        if field.optional {
                            continue;
                        }
                        entry_result = EntryDecryptResult::Neither;
                        break;
                    }
                };

                if aes_gcm_decrypt(&current_kek, &encrypted_bytes, &aad_bytes).is_ok() {
                    entry_result = EntryDecryptResult::Current;
                    break;
                } else if let Some(ref prev) = previous_kek {
                    if aes_gcm_decrypt(prev, &encrypted_bytes, &aad_bytes).is_ok() {
                        entry_result = EntryDecryptResult::Previous;
                        break;
                    }
                }

                entry_result = EntryDecryptResult::Neither;
                break;
            }

            match entry_result {
                EntryDecryptResult::Current => {
                    total_current = total_current.saturating_add(1);
                }
                EntryDecryptResult::Previous => {
                    total_previous = total_previous.saturating_add(1);
                    println!("  {} - decrypts with PREVIOUS KEK", kv_key);
                }
                EntryDecryptResult::Neither => {
                    total_neither = total_neither.saturating_add(1);
                    eprintln!("  {} - FAILS with all KEKs", kv_key);
                }
                EntryDecryptResult::Skipped => {
                    total_skipped = total_skipped.saturating_add(1);
                }
            }
        }
    }

    println!("\n--- Verification Summary ---");
    println!("  Decrypt with current KEK:  {}", total_current);
    println!("  Decrypt with previous KEK: {}", total_previous);
    println!("  Failed both KEKs:          {}", total_neither);
    println!("  Skipped (unencrypted/etc): {}", total_skipped);

    if total_previous > 0 {
        println!("\nWARNING: {} entries still encrypted with the previous KEK.", total_previous);
        println!("  Run 'rotate-kek' to re-encrypt them, or keep ISSUER_KEK_PREVIOUS active.");
    }

    if total_neither > 0 {
        eprintln!("\nERROR: {} entries cannot be decrypted with any known KEK.", total_neither);
        anyhow::bail!("Undecryptable entries found");
    }

    if total_previous == 0 && total_neither == 0 {
        println!("\nAll entries decrypt with the current KEK. Safe to remove ISSUER_KEK_PREVIOUS.");
    }

    Ok(())
}

enum EntryDecryptResult {
    Current,
    Previous,
    Neither,
    Skipped,
}

/// Extract encrypted bytes from a JSON value, handling both base64url strings
/// and u8 arrays (serde's default Vec<u8> representation).
fn extract_bytes_from_json(val: Option<&serde_json::Value>) -> Option<Vec<u8>> {
    match val {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => URL_SAFE_NO_PAD.decode(s.as_bytes()).ok(),
        Some(serde_json::Value::Array(arr)) => {
            let bytes: Option<Vec<u8>> = arr
                .iter()
                .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            bytes
        }
        _ => None,
    }
}

// ── ListSigningKeys ─────────────────────────────────────────────────────────

async fn list_signing_keys(cli: &Cli) -> Result<()> {
    println!("Listing all signing keys\n");

    let http = build_http_client()?;
    let all_keys = list_kv_keys(&http, cli, &cli.kv_keys_id).await?;

    if all_keys.is_empty() {
        println!("  No keys found in namespace {}", cli.kv_keys_id);
        return Ok(());
    }

    println!("{:<50} {:<12} {:<10} {:<10}", "KV Key", "Status", "Encrypted", "Version");
    println!("{}", "-".repeat(86));

    for kv_key in &all_keys {
        let raw = match get_kv_value_by_ns(&http, cli, &cli.kv_keys_id, kv_key).await? {
            Some(v) => v,
            None => continue,
        };

        let record: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(_) => {
                println!("{:<50} INVALID JSON", kv_key);
                continue;
            }
        };

        let status = record.get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let encrypted = record.get("encrypted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let version = record.get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("-");

        println!("{:<50} {:<12} {:<10} {:<10}", kv_key, status, encrypted, version);
    }

    Ok(())
}

async fn show_officer(cli: &Cli, officer_id: &str) -> Result<()> {
    println!("Officer: {}", officer_id);

    let client = build_http_client()?;
    let key = format!("officer:id:{}", officer_id);

    let officer_data = get_kv_value(&client, cli, &key).await?
        .context("Officer not found")?;

    let officer: serde_json::Value = serde_json::from_str(&officer_data)?;

    println!();
    println!("Status: {}", officer["active"].as_bool().unwrap_or(false));
    println!("Created: {}", officer["created_at"].as_i64().unwrap_or(0));
    println!("Encrypted: {}", officer["encrypted"].as_bool().unwrap_or(false));
    println!("Secret Status: {}", officer["secret_status"].as_str().unwrap_or("active"));
    println!("Has Previous Secret: {}", !officer["previous_hmac_secret"].is_null());

    Ok(())
}

async fn show_client(cli: &Cli, client_id: &str) -> Result<()> {
    println!("Client: {}", client_id);

    let client = build_http_client()?;
    let key = format!("client:id:{}", client_id);

    let client_data = get_kv_value(&client, cli, &key).await?
        .context("Client not found")?;

    let client_rec: serde_json::Value = serde_json::from_str(&client_data)?;

    println!();
    println!("Name: {}", client_rec["client_name"].as_str().unwrap_or(""));
    println!("Status: {}", client_rec["active"].as_bool().unwrap_or(false));
    println!("Created: {}", client_rec["created_at"].as_i64().unwrap_or(0));
    println!("Encrypted: {}", client_rec["encrypted"].as_bool().unwrap_or(false));
    println!("Secret Status: {}", client_rec["secret_status"].as_str().unwrap_or("active"));
    println!("Has Previous Secret: {}", !client_rec["previous_hmac_secret"].is_null());
    println!("Rate Limit: {}", client_rec["rate_limit"].as_u64().unwrap_or(0));

    Ok(())
}

// ── Helper functions for KV operations (legacy key-prefix routing) ──────────

async fn get_kv_value(client: &Client, cli: &Cli, key: &str) -> Result<Option<String>> {
    let namespace_id = determine_namespace(cli, key)?;
    get_kv_value_by_ns(client, cli, namespace_id, key).await
}

async fn put_kv_value(client: &Client, cli: &Cli, key: &str, value: &str) -> Result<()> {
    let namespace_id = determine_namespace(cli, key)?;
    put_kv_value_by_ns(client, cli, namespace_id, key, value).await
}

fn determine_namespace<'a>(cli: &'a Cli, key: &str) -> Result<&'a str> {
    if key.starts_with("rj:keypair:") {
        Ok(&cli.kv_keys_id)
    } else if key.starts_with("officer:") {
        Ok(&cli.kv_officers_id)
    } else if key.starts_with("client:") {
        Ok(&cli.kv_clients_id)
    } else {
        anyhow::bail!("Unable to determine namespace for key: {}", key)
    }
}
