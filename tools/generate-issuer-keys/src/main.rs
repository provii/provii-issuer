// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

// tools/generate-issuer-keys/src/main.rs
use provii_crypto_sig_redjubjub::generate_keypair;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::env;
use zeroize::Zeroizing;

fn main() {
    let (raw_sk, vk) = generate_keypair();
    let _sk = Zeroizing::new(raw_sk); // kept for zeroize-on-drop
    let vk_b64 = URL_SAFE_NO_PAD.encode(vk);

    println!("Generated RedJubjub Keypair\n");
    println!("VK: {}", vk_b64);

    println!("\n=== Store in KV with this command ===");
    println!("\nUsing wrangler CLI:");
    println!("-------------------");

    // Try to read namespace ID from environment, but don't require it
    match env::var("KV_KEYS_ID") {
        Ok(namespace_id) => {
            println!("npx wrangler kv key put --remote --namespace-id={} \"rj:keypair:provii:2026-05\" '{{\"sk\":\"<SK_REDACTED>\",\"vk\":\"{}\"}}'",
                namespace_id, vk_b64);
            println!("\nNote: Replace <SK_REDACTED> with the SK value from your secure key ceremony records.");
        }
        Err(_) => {
            println!("npx wrangler kv key put --remote --namespace-id=<YOUR_KV_KEYS_NAMESPACE_ID> \"rj:keypair:provii:2026-05\" '{{\"sk\":\"<SK_REDACTED>\",\"vk\":\"{}\"}}'",
                vk_b64);
            println!("\nNote: Replace <SK_REDACTED> with the SK value from your secure key ceremony records.");
            println!("      Set KV_KEYS_ID environment variable to auto-fill the namespace ID.");
            println!("      Find your namespace ID with: wrangler kv:namespace list --remote");
            println!("      Use the ID for KV_KEYS (e.g., SANDBOX_ISSUER_KEYS or PRODUCTION_ISSUER_KEYS)");
        }
    }

    println!("\n=== SECURITY NOTICE ===");
    println!("The SK has been generated in memory but is NOT printed.");
    println!("Use your secure key ceremony process to capture and store it.");
    println!("- Store it securely in Cloudflare KV immediately");
    println!("- Do NOT commit it to version control");
    println!("- Do NOT share it via insecure channels");
}