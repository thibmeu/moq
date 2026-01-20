//! Complete Privacy Pass authentication client example.
//!
//! Demonstrates the full flow per draft-ietf-moq-privacy-pass-auth-01:
//! 1. Connect without token
//! 2. Get rejected with 0x2 Unauthorized + TokenChallenge
//! 3. Parse challenge to get issuer name
//! 4. Request token from issuer
//! 5. Reconnect with token in SETUP AuthorizationToken parameter
//!
//! Usage:
//!   cargo run -p moq-native --example pp_client -- <moq_url>
//!
//! Example:
//!   cargo run -p moq-native --example pp_client -- https://localhost:4443/test/room
//!
//! Requirements:
//!   - moq-relay running with --pp-enabled and --auth-public=""
//!   - For local dev, use --tls-generate=localhost

use moq_privacypass::{IssuerClient, Operation, Scope, parse_challenge_from_reason};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	moq_native::Log::new(tracing::Level::DEBUG).init();

	let args: Vec<String> = std::env::args().collect();
	if args.len() < 2 {
		eprintln!("Usage: {} <moq_url>", args[0]);
		eprintln!("Example: {} https://localhost:4443/test/room", args[0]);
		eprintln!();
		eprintln!("Start relay with:");
		eprintln!("  cargo run -p moq-relay -- --pp-enabled --auth-public=\"\" \\");
		eprintln!("    --tls-generate=localhost --server-bind=127.0.0.1:4443");
		std::process::exit(1);
	}

	let moq_url = url::Url::parse(&args[1])?;
	let namespace = moq_url.path().trim_start_matches('/');

	tracing::info!("Privacy Pass MoQ Client");
	tracing::info!("  URL: {}", moq_url);
	tracing::info!("  Namespace: {}", namespace);

	// Create client with TLS verification disabled for local dev
	let mut config = moq_native::ClientConfig::default();
	config.tls.disable_verify = Some(true);
	let client = config.init()?;

	// Step 1: Try to connect without token - expect rejection with challenge
	tracing::info!("Step 1: Connect without token (expect rejection)");

	let origin = moq_lite::Origin::produce();
	let connect_result = client
		.connect_with_auth(moq_url.clone(), origin.consumer, None, None)
		.await;

	// Step 2: Parse the TokenChallenge from the rejection
	let (challenge, issuer) = match connect_result {
		Ok(_) => {
			tracing::warn!("Connection succeeded without token - Privacy Pass may not be enabled");
			return Ok(());
		}
		Err(err) => {
			let err_str = err.to_string();
			tracing::debug!("Connection rejected: {}", err_str);

			// Try to parse challenge from the error
			// The error should contain "pp:<base64>" in the reason
			if let Some(start) = err_str.find("pp:") {
				// Extract the pp:... portion
				let reason = &err_str[start..];
				// Find end (space, quote, or end of string)
				let end = reason.find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
					.unwrap_or(reason.len());
				let challenge_str = &reason[..end];

				match parse_challenge_from_reason(challenge_str) {
					Ok((challenge, issuer)) => {
						tracing::info!("  Got TokenChallenge from issuer: {}", issuer);
						(challenge, issuer)
					}
					Err(e) => {
						anyhow::bail!("Failed to parse challenge: {} (reason: {})", e, challenge_str);
					}
				}
			} else {
				anyhow::bail!("Connection rejected without TokenChallenge: {}", err_str);
			}
		}
	};

	// Step 3: Request token from issuer
	tracing::info!("Step 2: Request token from issuer ({})", issuer);

	let mut issuer_client = IssuerClient::with_issuer(&issuer);
	issuer_client.fetch_issuer_key().await?;

	// Build scope from the challenge's origin_info
	let scope = Scope::exact(Operation::Subscribe, namespace);
	tracing::debug!("  Scope: {}", scope);
	tracing::debug!("  Challenge issuer: {}", challenge.issuer_name());

	let token = issuer_client.request_token(&scope).await?;
	let token_bytes = token.encode()?;
	tracing::info!("  Got token: {} bytes", token_bytes.len());

	// Step 4: Reconnect with token
	tracing::info!("Step 3: Reconnect with Privacy Pass token");

	let origin = moq_lite::Origin::produce();
	let session = client
		.connect_with_auth(moq_url.clone(), origin.consumer, None, Some(token_bytes))
		.await?;

	tracing::info!("Connected! Session established with Privacy Pass auth");

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
