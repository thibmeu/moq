//! Client-side token acquisition.
//!
//! Handles fetching issuer keys and requesting tokens from Privacy Pass issuers.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use privacypass::auth::authenticate::TokenChallenge;
use privacypass::public_tokens::server::serialize_public_key;
use privacypass::public_tokens::{PublicKey, PublicToken, TokenRequest, TokenResponse};
use privacypass::{Deserialize, Serialize};
use rand::rngs::OsRng;
use serde::Deserialize as SerdeDeserialize;

use crate::{DEFAULT_ISSUER, Error, ISSUER_DIRECTORY_PATH, PrivateTokenAuth, Scope, build_challenge};

/// Response from the issuer's well-known directory.
#[derive(Debug, SerdeDeserialize)]
pub struct IssuerDirectory {
	/// URI for token requests (relative to issuer).
	#[serde(rename = "issuer-request-uri")]
	pub issuer_request_uri: String,
	/// Available token keys.
	#[serde(rename = "token-keys")]
	pub token_keys: Vec<TokenKeyInfo>,
}

/// Information about a token key from the issuer directory.
#[derive(Debug, SerdeDeserialize)]
pub struct TokenKeyInfo {
	/// Token type (should be 2 for public tokens).
	#[serde(rename = "token-type")]
	pub token_type: u16,
	/// Base64-encoded public key (SPKI format).
	#[serde(rename = "token-key")]
	pub token_key: String,
	/// Optional "not before" timestamp.
	#[serde(rename = "not-before")]
	pub not_before: Option<u64>,
}

/// Client for acquiring Privacy Pass tokens.
pub struct IssuerClient {
	http: reqwest::Client,
	issuer_url: String,
	directory: Option<IssuerDirectory>,
	public_key: Option<PublicKey>,
}

impl IssuerClient {
	/// Create a new client for the default Cloudflare issuer.
	pub fn new() -> Self {
		Self::with_issuer(DEFAULT_ISSUER)
	}

	/// Create a new client for a custom issuer.
	pub fn with_issuer(issuer: &str) -> Self {
		Self {
			http: reqwest::Client::new(),
			issuer_url: format!("https://{issuer}"),
			directory: None,
			public_key: None,
		}
	}

	/// Get the issuer hostname.
	pub fn issuer_name(&self) -> &str {
		self.issuer_url.strip_prefix("https://").unwrap_or(&self.issuer_url)
	}

	/// Fetch the issuer's public key from the well-known directory.
	pub async fn fetch_issuer_key(&mut self) -> crate::Result<PublicKey> {
		if let Some(ref key) = self.public_key {
			return Ok(key.clone());
		}

		let directory = self.fetch_directory().await?;

		// Find a type 2 (public) token key
		let key_info = directory
			.token_keys
			.iter()
			.find(|k| k.token_type == 2)
			.ok_or(Error::NoTokenKeys)?;

		let key_bytes = URL_SAFE_NO_PAD
			.decode(&key_info.token_key)
			.or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&key_info.token_key))
			.map_err(|e| Error::DecodeFailed(format!("invalid base64 key: {e}")))?;

		let public_key = PublicKey::from_spki(&key_bytes, None)
			.map_err(|e| Error::DecodeFailed(format!("invalid SPKI key: {e}")))?;

		self.public_key = Some(public_key.clone());
		Ok(public_key)
	}

	/// Fetch the issuer directory.
	async fn fetch_directory(&mut self) -> crate::Result<&IssuerDirectory> {
		if self.directory.is_some() {
			return Ok(self.directory.as_ref().unwrap());
		}

		let url = format!("{}{}", self.issuer_url, ISSUER_DIRECTORY_PATH);
		let resp = self.http.get(&url).send().await?;

		if !resp.status().is_success() {
			return Err(Error::IssuerError(format!("directory fetch failed: {}", resp.status())));
		}

		let directory: IssuerDirectory = resp.json().await?;
		self.directory = Some(directory);
		Ok(self.directory.as_ref().unwrap())
	}

	/// Request a token for the given scope.
	///
	/// This performs the full token acquisition flow:
	/// 1. Fetch issuer key if not cached
	/// 2. Build a TokenChallenge for the scope
	/// 3. Create a blinded token request
	/// 4. Send request to issuer
	/// 5. Unblind the response to get a valid token
	pub async fn request_token(&mut self, scope: &Scope) -> crate::Result<PrivateTokenAuth> {
		let public_key = self.fetch_issuer_key().await?;
		let directory = self.directory.as_ref().ok_or(Error::NoTokenKeys)?;

		// Build challenge
		let challenge = build_challenge(self.issuer_name(), scope, None);

		// Create token request using the TokenRequest::new API
		let (token_request, token_state) =
			TokenRequest::new(&mut OsRng, public_key, &challenge).map_err(|e| Error::PrivacyPass(e.to_string()))?;

		// Send request to issuer
		let request_url = format!("{}{}", self.issuer_url, directory.issuer_request_uri);
		let request_bytes = token_request
			.tls_serialize_detached()
			.map_err(|e| Error::EncodeFailed(e.to_string()))?;

		let resp = self
			.http
			.post(&request_url)
			.header("Content-Type", "application/private-token-request")
			.body(request_bytes)
			.send()
			.await?;

		if !resp.status().is_success() {
			return Err(Error::IssuerError(format!("token request failed: {}", resp.status())));
		}

		let response_bytes = resp.bytes().await?;
		let token_response: TokenResponse = TokenResponse::tls_deserialize(&mut response_bytes.as_ref())
			.map_err(|e| Error::DecodeFailed(format!("invalid token response: {e}")))?;

		// Finalize token
		let token: PublicToken = token_response
			.issue_token(&token_state)
			.map_err(|e| Error::PrivacyPass(e.to_string()))?;

		Ok(PrivateTokenAuth::new(token))
	}

	/// Build a challenge for a scope without requesting a token.
	///
	/// Useful for relay's challenge endpoint.
	pub async fn build_challenge_for_scope(&mut self, scope: &Scope) -> crate::Result<(TokenChallenge, Vec<u8>)> {
		let public_key = self.fetch_issuer_key().await?;
		let challenge = build_challenge(self.issuer_name(), scope, None);
		let key_bytes = serialize_public_key(&public_key);
		Ok((challenge, key_bytes))
	}
}

impl Default for IssuerClient {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_issuer_name() {
		let client = IssuerClient::new();
		assert_eq!(client.issuer_name(), DEFAULT_ISSUER);

		let client = IssuerClient::with_issuer("custom.example.com");
		assert_eq!(client.issuer_name(), "custom.example.com");
	}

	// Integration tests would go here but require network access
	// See tests/cloudflare.rs for integration tests
}
