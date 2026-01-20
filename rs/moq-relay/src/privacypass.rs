//! Privacy Pass authentication for MoQ relay.
//!
//! Provides TokenChallenge endpoint and token verification.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use moq_privacypass::{Operation, PrivateTokenAuth, Scope, Verifier, build_challenge, serialize_challenge};
use privacypass::public_tokens::PublicKey;
use privacypass::public_tokens::server::serialize_public_key;
use serde::{Deserialize, Serialize};

use crate::AuthError;

/// Privacy Pass configuration.
#[derive(clap::Args, Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PrivacyPassConfig {
	/// Enable Privacy Pass authentication.
	#[arg(long = "pp-enabled", env = "MOQ_PP_ENABLED")]
	pub enabled: bool,

	/// Privacy Pass issuer URL (default: Cloudflare test endpoint).
	#[arg(long = "pp-issuer", env = "MOQ_PP_ISSUER")]
	pub issuer: Option<String>,

	/// Path to issuer public key file (SPKI format, base64).
	/// If not provided, key will be fetched from issuer's well-known directory.
	#[arg(long = "pp-issuer-key", env = "MOQ_PP_ISSUER_KEY")]
	pub issuer_key: Option<String>,
}

impl PrivacyPassConfig {
	/// Initialize Privacy Pass authentication.
	pub async fn init(self) -> anyhow::Result<Option<PrivacyPassAuth>> {
		if !self.enabled {
			return Ok(None);
		}

		let issuer_name = self
			.issuer
			.unwrap_or_else(|| moq_privacypass::DEFAULT_ISSUER.to_string());

		// Load or fetch the issuer public key
		let public_key = if let Some(key_path) = self.issuer_key {
			// Load from file
			let key_data =
				std::fs::read_to_string(&key_path).map_err(|e| anyhow::anyhow!("failed to read issuer key: {e}"))?;
			let key_bytes = URL_SAFE_NO_PAD
				.decode(key_data.trim())
				.map_err(|e| anyhow::anyhow!("invalid base64 key: {e}"))?;
			PublicKey::from_spki(&key_bytes, None).map_err(|e| anyhow::anyhow!("invalid SPKI key: {e}"))?
		} else {
			// Fetch from issuer
			let mut client = moq_privacypass::IssuerClient::with_issuer(&issuer_name);
			client
				.fetch_issuer_key()
				.await
				.map_err(|e| anyhow::anyhow!("failed to fetch issuer key: {e}"))?
		};

		let verifier = Verifier::new(issuer_name.clone(), public_key.clone());

		Ok(Some(PrivacyPassAuth {
			issuer_name,
			public_key,
			verifier: Arc::new(verifier),
		}))
	}
}

/// Privacy Pass authentication state.
#[derive(Clone)]
pub struct PrivacyPassAuth {
	issuer_name: String,
	public_key: PublicKey,
	verifier: Arc<Verifier>,
}

impl PrivacyPassAuth {
	/// Get the issuer name.
	pub fn issuer_name(&self) -> &str {
		&self.issuer_name
	}

	/// Build a challenge for the given scope.
	///
	/// Returns (challenge_bytes, token_key_bytes) for the WWW-Authenticate header.
	pub fn build_challenge(&self, scope: &Scope) -> (Vec<u8>, Vec<u8>) {
		let challenge = build_challenge(&self.issuer_name, scope, None);
		let challenge_bytes = serialize_challenge(&challenge).unwrap_or_default();
		let key_bytes = serialize_public_key(&self.public_key);
		(challenge_bytes, key_bytes)
	}

	/// Build a challenge response for the HTTP endpoint.
	pub fn challenge_response(&self, operation: Operation, namespace: &str) -> ChallengeResponse {
		let scope = Scope::exact(operation, namespace);
		let (challenge, token_key) = self.build_challenge(&scope);

		ChallengeResponse {
			challenge: URL_SAFE_NO_PAD.encode(&challenge),
			token_key: URL_SAFE_NO_PAD.encode(&token_key),
			issuer: self.issuer_name.clone(),
		}
	}

	/// Verify a Privacy Pass token.
	///
	/// Returns the authorized scope on success.
	pub async fn verify(
		&self,
		token_bytes: &[u8],
		operation: Operation,
		namespace: &str,
		track: Option<&str>,
	) -> Result<Scope, AuthError> {
		let token = PrivateTokenAuth::decode_token_only(token_bytes).map_err(|_| AuthError::DecodeFailed)?;

		self.verifier
			.verify(&token, operation, namespace, track)
			.await
			.map_err(|e| {
				tracing::debug!("Privacy Pass verification failed: {e}");
				AuthError::DecodeFailed
			})
	}
}

/// Response from the /challenge endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
	/// Base64-encoded TokenChallenge.
	pub challenge: String,
	/// Base64-encoded issuer public key (SPKI format).
	pub token_key: String,
	/// Issuer hostname.
	pub issuer: String,
}

/// Query parameters for the /challenge endpoint.
#[derive(Debug, Deserialize)]
pub struct ChallengeParams {
	/// Path/namespace for the challenge.
	pub path: String,
	/// Operation type.
	#[serde(default = "default_operation")]
	pub op: String,
}

fn default_operation() -> String {
	"subscribe".to_string()
}

impl ChallengeParams {
	/// Parse the operation from the query parameter.
	pub fn operation(&self) -> Result<Operation, AuthError> {
		self.op.parse().map_err(|_| AuthError::DecodeFailed)
	}
}
