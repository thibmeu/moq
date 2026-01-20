//! Complete Privacy Pass authentication client example.
//!
//! Demonstrates the full flow:
//! 1. Get challenge from relay's /challenge endpoint
//! 2. Request token from issuer
//! 3. Connect with token in SETUP AuthorizationToken parameter
//! 4. Establish a working MoQ session
//!
//! Usage:
//!   cargo run -p moq-native --example pp_client -- <http_url> <quic_url> <namespace>
//!
//! Example:
//!   cargo run -p moq-native --example pp_client -- http://localhost:9080 https://localhost:9443 test/room
//!
//! Requirements:
//!   - moq-relay running with --pp-enabled and --web-http-listen
//!   - For local dev, use --tls-disable-verify or --tls-generate=localhost

use moq_privacypass::{IssuerClient, Operation, Scope};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ChallengeResponse {
	challenge: String,
	#[allow(dead_code)]
	token_key: String,
	issuer: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	moq_native::Log::new(tracing::Level::DEBUG).init();

	let args: Vec<String> = std::env::args().collect();
	if args.len() < 4 {
		eprintln!("Usage: {} <http_url> <quic_url> <namespace>", args[0]);
		eprintln!("Example: {} http://localhost:9080 http://localhost:9443 test/room", args[0]);
		eprintln!();
		eprintln!("Start relay with:");
		eprintln!("  cargo run -p moq-relay -- --pp-enabled --auth-public=\"\" \\");
		eprintln!("    --tls-generate=localhost --web-http-listen=127.0.0.1:9080 \\");
		eprintln!("    --server-bind=127.0.0.1:9443");
		std::process::exit(1);
	}

	let http_base = &args[1];
	let quic_base = &args[2];
	let namespace = &args[3];

	let moq_url = format!("{}/{}", quic_base, namespace);

	tracing::info!("Privacy Pass MoQ Client");
	tracing::info!("  HTTP endpoint: {}", http_base);
	tracing::info!("  MoQ endpoint:  {}", moq_url);
	tracing::info!("  Namespace:     {}", namespace);

	// Step 1: Get challenge from relay
	tracing::info!("Step 1: Get challenge from relay");

	let http_client = reqwest::Client::new();
	let challenge_url = format!("{}/challenge?path={}&op=subscribe", http_base, namespace);
	tracing::debug!("  GET {}", challenge_url);

	let resp: ChallengeResponse = http_client
		.get(&challenge_url)
		.send()
		.await?
		.error_for_status()?
		.json()
		.await?;

	tracing::info!("  Issuer: {}", resp.issuer);
	tracing::debug!("  Challenge: {}...", &resp.challenge[..40.min(resp.challenge.len())]);

	// Step 2: Request token from issuer
	tracing::info!("Step 2: Request token from issuer ({})", resp.issuer);

	let mut issuer_client = IssuerClient::with_issuer(&resp.issuer);
	issuer_client.fetch_issuer_key().await?;

	let scope = Scope::exact(Operation::Subscribe, namespace);
	tracing::debug!("  Scope: {}", scope);

	let token = issuer_client.request_token(&scope).await?;
	let token_bytes = token.encode()?;
	tracing::info!("  Got token: {} bytes", token_bytes.len());

	// Step 3: Connect to relay with token
	tracing::info!("Step 3: Connect to relay with Privacy Pass token");

	let mut config = moq_native::ClientConfig::default();
	config.tls.disable_verify = Some(true); // For local dev with self-signed certs
	let client = config.init()?;

	let origin = moq_lite::Origin::produce();
	let moq_url = url::Url::parse(&moq_url)?;

	let session = client
		.connect_with_auth(moq_url.clone(), origin.consumer, None, Some(token_bytes))
		.await?;

	tracing::info!("Connected! Session established with Privacy Pass auth");
	tracing::info!("  URL: {}", moq_url);

	// Keep session alive briefly to demonstrate it's working
	tokio::select! {
		_ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {
			tracing::info!("Session stayed alive for 5 seconds, closing...");
		}
		res = session.closed() => {
			if let Err(e) = res {
				tracing::warn!("Session closed: {}", e);
			}
		}
	}

	tracing::info!("Done!");
	Ok(())
}
