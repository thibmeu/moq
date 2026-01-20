//! End-to-end Privacy Pass authentication flow example.
//!
//! This demonstrates the complete flow:
//! 1. Get challenge from relay's /challenge endpoint
//! 2. Request token from issuer using the challenge
//! 3. Show how the token would be included in SETUP
//!
//! Usage:
//!   cargo run -p moq-privacypass --example e2e_flow -- <relay_url>
//!
//! Example:
//!   cargo run -p moq-privacypass --example e2e_flow -- http://127.0.0.1:8080

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use moq_privacypass::{IssuerClient, Operation, Scope};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    challenge: String,
    token_key: String,
    issuer: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let relay_url = if args.len() >= 2 {
        args[1].clone()
    } else {
        eprintln!("Usage: {} <relay_url>", args[0]);
        eprintln!("Example: {} http://127.0.0.1:8080", args[0]);
        eprintln!("\nMake sure moq-relay is running with --pp-enabled");
        std::process::exit(1);
    };

    let namespace = "test/room";
    let operation = "subscribe";

    println!("=== Privacy Pass E2E Flow ===\n");

    // Step 1: Get challenge from relay
    println!("Step 1: Get challenge from relay");
    println!("  GET {}/challenge?path={}&op={}", relay_url, namespace, operation);

    let client = reqwest::Client::new();
    let challenge_url = format!("{}/challenge?path={}&op={}", relay_url, namespace, operation);
    let resp: ChallengeResponse = client.get(&challenge_url).send().await?.json().await?;

    println!("  Issuer: {}", resp.issuer);
    println!("  Challenge: {}...", &resp.challenge[..40.min(resp.challenge.len())]);
    println!();

    // Step 2: Request token from issuer
    println!("Step 2: Request token from issuer");
    let mut issuer_client = IssuerClient::with_issuer(&resp.issuer);

    // Fetch the issuer key (or use the one from challenge response)
    println!("  Fetching issuer key...");
    issuer_client.fetch_issuer_key().await?;

    // Create scope matching the challenge
    let scope = Scope::exact(Operation::Subscribe, namespace);
    println!("  Scope: {}", scope);

    // Request token
    println!("  Requesting token...");
    let token = issuer_client.request_token(&scope).await?;
    let token_bytes = token.encode()?;

    println!("  Got token: {} bytes", token_bytes.len());
    println!();

    // Step 3: Show how to use the token
    println!("Step 3: Connect with token in SETUP AuthorizationToken parameter");
    println!();
    println!("  In Rust (moq-lite), use Session::connect_with_auth:");
    println!("  ```rust");
    println!("  let token_bytes: Vec<u8> = /* from step 2 */;");
    println!("  let session = Session::connect_with_auth(");
    println!("      transport,");
    println!("      publish,");
    println!("      subscribe,");
    println!("      Some(token_bytes),");
    println!("  ).await?;");
    println!("  ```");
    println!();
    println!("  The relay will:");
    println!("  - Extract AuthorizationToken from SETUP parameters");
    println!("  - Verify the Privacy Pass token");
    println!("  - Accept or reject (0x2 Unauthorized) the session");
    println!();

    // Show the raw token for debugging
    println!("=== Token (for debugging) ===");
    println!("Hex (first 64 bytes): {}", hex::encode(&token_bytes[..64.min(token_bytes.len())]));
    println!("Base64url: {}", URL_SAFE_NO_PAD.encode(&token_bytes));

    Ok(())
}
