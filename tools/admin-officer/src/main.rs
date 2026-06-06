// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// KV Namespace ID for officer registry
    /// Must be set via --namespace-id or KV_NAMESPACE_ID environment variable
    /// Find your namespace ID: wrangler kv:namespace list
    #[arg(long, env = "KV_NAMESPACE_ID")]
    namespace_id: Option<String>,

    /// Cloudflare Account ID
    /// Must be set via --account-id or CF_ACCOUNT_ID environment variable
    /// Find at: https://dash.cloudflare.com/ → Account ID in sidebar
    #[arg(long, env = "CF_ACCOUNT_ID")]
    account_id: Option<String>,

    /// Cloudflare API Token (env only, never pass as CLI arg)
    #[arg(env = "CF_API_TOKEN", hide = true)]
    api_token: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register a new officer with auto-generated HMAC secret
    Register {
        /// Officer ID (e.g., "OFFICER123")
        #[arg(long)]
        officer_id: String,
    },
    
    /// Generate Yubikey configuration commands
    GenerateYubikeyConfig {
        /// Officer ID to configure
        #[arg(long)]
        officer_id: String,
    },
    
    /// Test HMAC authentication
    TestAuth {
        /// Officer ID
        #[arg(long)]
        officer_id: String,
        
        /// Challenge to test (base64url)
        #[arg(long)]
        challenge: Option<String>,
    },
    
    /// List all officers
    List,
    
    /// Deactivate an officer
    Deactivate {
        /// Officer ID to deactivate
        #[arg(long)]
        officer_id: String,
    },
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct OfficerRegistration {
    #[zeroize(skip)]
    officer_id: String,
    hmac_secret: Vec<u8>,  // 20 bytes for HMAC-SHA1
    #[zeroize(skip)]
    created_at: i64,
    #[zeroize(skip)]
    last_used: Option<i64>,
    #[zeroize(skip)]
    active: bool,
}

impl fmt::Debug for OfficerRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfficerRegistration")
            .field("officer_id", &self.officer_id)
            .field("hmac_secret", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("last_used", &self.last_used)
            .field("active", &self.active)
            .finish()
    }
}

/// Build a reqwest Client with sensible defaults: 30s timeout, TLS 1.2 minimum.
fn build_http_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {}", e))
}

/// Validate an identifier parameter (officer_id).
/// Must be non-empty, at most 128 characters, and contain only ASCII
/// alphanumeric characters, hyphens, underscores, or dots.
fn validate_identifier(name: &str, value: &str) -> anyhow::Result<()> {
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Validate officer_id parameters early
    match &cli.command {
        Commands::Register { officer_id }
        | Commands::GenerateYubikeyConfig { officer_id }
        | Commands::TestAuth { officer_id, .. }
        | Commands::Deactivate { officer_id } => {
            validate_identifier("officer_id", officer_id)?;
        }
        Commands::List => {}
    }

    // Validate required credentials for operations that need them
    let needs_api_token = !matches!(cli.command, Commands::TestAuth { .. });

    if needs_api_token {
        if cli.api_token.is_none() {
            anyhow::bail!(
                "API token is required. Set CF_API_TOKEN environment variable.\n\
                 Create token at: https://dash.cloudflare.com/profile/api-tokens"
            );
        }
        if cli.account_id.is_none() {
            anyhow::bail!(
                "Cloudflare Account ID is required. Set CF_ACCOUNT_ID environment variable or use --account-id.\n\
                 Find at: https://dash.cloudflare.com/ → Account ID in sidebar"
            );
        }
        if cli.namespace_id.is_none() {
            anyhow::bail!(
                "KV Namespace ID is required. Set KV_NAMESPACE_ID environment variable or use --namespace-id.\n\
                 Find your namespace IDs with: wrangler kv:namespace list\n\
                 Use the ID for KV_OFFICER_REGISTRY (e.g., SANDBOX_ISSUER_OFFICER_REGISTRY or PRODUCTION_ISSUER_OFFICER_REGISTRY)"
            );
        }
    }
    
    match &cli.command {  // <-- Note the & here
        Commands::Register { officer_id } => {
            let mut secret_bytes = vec![0u8; 20];
            rand::thread_rng().fill_bytes(&mut secret_bytes);
            let hmac_secret = Zeroizing::new(secret_bytes);

            if hmac_secret.len() != 20 {
                anyhow::bail!("HMAC secret must be exactly 20 bytes for SHA1");
            }

            let officer = OfficerRegistration {
                officer_id: officer_id.clone(),
                hmac_secret: hmac_secret.to_vec(),
                created_at: chrono::Utc::now().timestamp(),
                last_used: None,
                active: true,
            };

            // Store by officer ID (not credential ID like WebAuthn)
            let key = format!("officer:id:{}", officer_id);
            let value = Zeroizing::new(serde_json::to_string(&officer)?);

            put_kv(&cli, &key, &value).await?;

            println!("✅ Officer registered successfully!");
            println!("   Officer ID: {}", officer_id);
            println!("   HMAC Secret: (stored in KV, retrieve via wrangler)");
            println!();
            println!("📝 Next steps:");
            println!("   1. Program this secret into the officer's Yubikey slot 2");
            println!("   2. Run: cargo run -- generate-yubikey-config --officer-id {}", officer_id);
        }
        
        Commands::GenerateYubikeyConfig { officer_id } => {
            let key = format!("officer:id:{}", officer_id);

            if let Some(data) = get_kv(&cli, &key).await? {
                let _officer: OfficerRegistration = serde_json::from_str(&data)?;
                println!("🔑 Yubikey Configuration for {}", officer_id);
                println!("{}", "=".repeat(50));
                println!();
                println!("Using ykman CLI tool:");
                println!("----------------------");
                println!("# Retrieve the HMAC secret hex from KV:");
                println!("# wrangler kv key get --namespace-id=<KEYS_NS> \"officer:id:{}\" --remote | jq -r .hmac_secret", officer_id);
                println!("# Then program it:");
                println!("# ykman otp chalresp 2 <SECRET_HEX>");
                println!();
                println!("# Verify configuration:");
                println!("ykman otp info");
                println!();
                println!("Using Yubikey Personalization Tool:");
                println!("------------------------------------");
                println!("1. Open Yubikey Personalization Tool");
                println!("2. Select 'Challenge-Response' mode");
                println!("3. Select 'HMAC-SHA1' mode");
                println!("4. Select 'Configuration Slot 2'");
                println!("5. Retrieve the secret hex from KV (see command above)");
                println!("6. Enable 'Require user input (button press)'");
                println!("7. Click 'Write Configuration'");
            } else {
                println!("❌ Officer not found: {}", officer_id);
            }
        }
        
        Commands::TestAuth { officer_id, challenge } => {
            let key = format!("officer:id:{}", officer_id);
            
            if let Some(data) = get_kv(&cli, &key).await? {
                let officer: OfficerRegistration = serde_json::from_str(&data)?;
                
                // Generate or use provided challenge
                let challenge_bytes = if let Some(c) = challenge {
                    URL_SAFE_NO_PAD.decode(c)?
                } else {
                    let mut bytes = vec![0u8; 32];
                    rand::thread_rng().fill_bytes(&mut bytes);
                    bytes
                };
                
                // Calculate expected HMAC response
                use hmac::{Hmac, Mac};
                use sha1::Sha1;
                type HmacSha1 = Hmac<Sha1>;
                
                let mut mac = HmacSha1::new_from_slice(&officer.hmac_secret)?;
                mac.update(&challenge_bytes);
                let expected = mac.finalize().into_bytes();
                
                let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge_bytes);
                let challenge_hex = hex::encode(&challenge_bytes);
                let expected_b64 = URL_SAFE_NO_PAD.encode(expected.as_slice());
                let expected_hex = hex::encode(expected.as_slice());
                
                println!("🧪 HMAC Authentication Test for {}", officer_id);
                println!("{}", "=".repeat(50));
                println!();
                println!("Challenge (base64url): {}", challenge_b64);
                println!("Challenge (hex):       {}", challenge_hex);
                println!();
                println!("Expected Response (base64url): {}", expected_b64);
                println!("Expected Response (hex):       {}", expected_hex);
                println!();
                println!("Test with Yubikey:");
                println!("------------------");
                println!("# Using hex challenge directly:");
                println!("echo -n '{}' | ykchalresp -2 -x -i-", challenge_hex);
                println!();
                println!("# Should output: {}", expected_hex);
                println!();
                println!("Test with curl:");
                println!("---------------");
                println!("# First, get the Yubikey response:");
                println!("RESPONSE=$(echo -n '{}' | ykchalresp -2 -x -i-)", challenge_hex);
                println!();
                println!("# Convert hex to base64url:");
                println!("RESPONSE_B64=$(echo -n $RESPONSE | xxd -r -p | base64 -w0 | tr '/+' '_-' | tr -d '=')\n");
                println!("# Send to issuer:");
                println!("curl -X POST https://issuer.provii.app/v1/auth/hmac \\");
                println!("  -H 'Content-Type: application/json' \\");
                println!("  -d '{{");
                println!("    \"officer_id\": \"{}\",", officer_id);
                println!("    \"challenge\": \"{}\",", challenge_b64);
                println!("    \"response\": \"'$RESPONSE_B64'\"");
                println!("  }}'");
                println!();
                println!("# Or as a one-liner with the expected response for testing:");
                println!("curl -X POST https://issuer.provii.app/v1/auth/hmac \\");
                println!("  -H 'Content-Type: application/json' \\");
                println!("  -d '{{\"officer_id\":\"{}\",\"challenge\":\"{}\",\"response\":\"{}\"}}'", 
                    officer_id, challenge_b64, expected_b64);
            } else {
                println!("❌ Officer not found: {}", officer_id);
            }
        }
        
        Commands::List => {
            let keys = list_kv_keys(&cli, "officer:id:").await?;
            println!("Registered Officers (HMAC):");
            println!("--------------------------");
            
            for key in keys {
                if let Some(officer_data) = get_kv(&cli, &key).await? {
                    let reg: OfficerRegistration = serde_json::from_str(&officer_data)?;
                    println!("• {} ({})", 
                        reg.officer_id, 
                        if reg.active { "active" } else { "inactive" }
                    );
                    println!("  Created: {}", 
                        chrono::DateTime::from_timestamp(reg.created_at, 0)
                            .map(|dt| dt.format("%Y-%m-%d").to_string())
                            .unwrap_or_default()
                    );
                    if let Some(last_used) = reg.last_used {
                        println!("  Last used: {}", 
                            chrono::DateTime::from_timestamp(last_used, 0)
                                .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                                .unwrap_or_default()
                        );
                    }
                    println!();
                }
            }
        }
        
        Commands::Deactivate { officer_id } => {
            let key = format!("officer:id:{}", officer_id);

            if let Some(data) = get_kv(&cli, &key).await? {
                let mut record: serde_json::Value = serde_json::from_str(&data)?;
                record["active"] = serde_json::Value::Bool(false);

                let value = serde_json::to_string(&record)?;
                put_kv(&cli, &key, &value).await?;

                println!("Officer deactivated: {}", officer_id);
            } else {
                println!("Officer not found: {}", officer_id);
            }
        }
    }
    
    Ok(())
}

async fn put_kv(cli: &Cli, key: &str, value: &str) -> anyhow::Result<()> {
    let api_token = cli.api_token.as_ref()
        .ok_or_else(|| anyhow::anyhow!("API token required"))?;
    let account_id = cli.account_id.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Account ID required"))?;
    let namespace_id = cli.namespace_id.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Namespace ID required"))?;

    let client = build_http_client()?;
    let url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/storage/kv/namespaces/{}/values/{}",
        account_id, namespace_id, urlencoding::encode(key)
    );
    
    let response = client
        .put(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .header("Content-Type", "text/plain")
        .body(value.to_string())
        .send()
        .await?;
    
    if !response.status().is_success() {
        let error = response.text().await?;
        anyhow::bail!("Failed to store in KV: {}", error);
    }
    
    Ok(())
}

async fn get_kv(cli: &Cli, key: &str) -> anyhow::Result<Option<String>> {
    let api_token = cli.api_token.as_ref()
        .ok_or_else(|| anyhow::anyhow!("API token required"))?;
    let account_id = cli.account_id.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Account ID required"))?;
    let namespace_id = cli.namespace_id.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Namespace ID required"))?;

    let client = build_http_client()?;
    let url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/storage/kv/namespaces/{}/values/{}",
        account_id, namespace_id, urlencoding::encode(key)
    );
    
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await?;
    
    if response.status() == 404 {
        return Ok(None);
    }
    
    if !response.status().is_success() {
        let error = response.text().await?;
        anyhow::bail!("Failed to get from KV: {}", error);
    }
    
    Ok(Some(response.text().await?))
}

async fn list_kv_keys(cli: &Cli, prefix: &str) -> anyhow::Result<Vec<String>> {
    let api_token = cli.api_token.as_ref()
        .ok_or_else(|| anyhow::anyhow!("API token required"))?;
    let account_id = cli.account_id.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Account ID required"))?;
    let namespace_id = cli.namespace_id.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Namespace ID required"))?;

    let client = build_http_client()?;

    #[derive(Deserialize)]
    struct ListResponse {
        result: Vec<KeyInfo>,
        result_info: Option<ResultInfo>,
    }

    #[derive(Deserialize)]
    struct ResultInfo {
        cursor: String,
    }

    #[derive(Deserialize)]
    struct KeyInfo {
        name: String,
    }

    let mut all_keys = Vec::new();
    let mut cursor: Option<String> = None;

    loop {
        let mut url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/storage/kv/namespaces/{}/keys?prefix={}",
            account_id, namespace_id, urlencoding::encode(prefix)
        );

        if let Some(ref c) = cursor {
            url.push_str(&format!("&cursor={}", urlencoding::encode(c)));
        }

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_token))
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            anyhow::bail!("Failed to list KV keys: {}", error);
        }

        let data: ListResponse = response.json().await?;
        let count = data.result.len();
        all_keys.extend(data.result.into_iter().map(|k| k.name));

        // If no results or cursor is empty/absent, we have reached the end
        let next_cursor = data.result_info.map(|ri| ri.cursor).unwrap_or_default();
        if count == 0 || next_cursor.is_empty() {
            break;
        }

        cursor = Some(next_cursor);
    }

    Ok(all_keys)
}