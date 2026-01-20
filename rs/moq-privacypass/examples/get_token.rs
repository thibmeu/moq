//! Example: Get a Privacy Pass token from an issuer.
//!
//! Usage:
//!   cargo run -p moq-privacypass --example get_token -- <operation> <namespace>
//!
//! Example:
//!   cargo run -p moq-privacypass --example get_token -- subscribe test/room

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use moq_privacypass::{IssuerClient, Operation, Scope};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let (operation, namespace) = if args.len() >= 3 {
        let op = match args[1].as_str() {
            "subscribe" => Operation::Subscribe,
            "publish" => Operation::Publish,
            "announce" => Operation::Announce,
            "fetch" => Operation::Fetch,
            other => {
                eprintln!("Unknown operation: {}. Use: subscribe, publish, announce, fetch", other);
                std::process::exit(1);
            }
        };
        (op, args[2].clone())
    } else {
        eprintln!("Usage: {} <operation> <namespace>", args[0]);
        eprintln!("Example: {} subscribe test/room", args[0]);
        std::process::exit(1);
    };

    println!("=== Privacy Pass Token Acquisition ===\n");

    // Create client for demo issuer
    let mut client = IssuerClient::new();
    println!("Issuer: {}", client.issuer_name());

    // Create scope
    let scope = Scope::exact(operation, &namespace);
    println!("Scope: {}\n", scope);

    // Fetch issuer key
    println!("Fetching issuer public key...");
    let _key = client.fetch_issuer_key().await?;
    println!("Got issuer key\n");

    // Request token
    println!("Requesting token from issuer...");
    let token = client.request_token(&scope).await?;
    println!("Got token!\n");

    // Encode token for use in SETUP AuthorizationToken
    let token_bytes = token.encode()?;
    let token_b64 = URL_SAFE_NO_PAD.encode(&token_bytes);

    println!("=== Token Details ===");
    println!("Token size: {} bytes", token_bytes.len());
    println!("\nToken (hex, first 64 bytes):");
    println!("{}", hex::encode(&token_bytes[..64.min(token_bytes.len())]));
    println!("\nToken (base64url, for debugging):\n{}\n", token_b64);

    println!("=== How to use ===");
    println!("Include this token in SETUP message's AuthorizationToken parameter (id=3)");
    println!("The token bytes should be sent as-is (not base64 encoded) in the parameter value.");

    Ok(())
}
