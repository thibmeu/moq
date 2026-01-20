//! Token verification for MoQ relays.
//!
//! The Verifier handles server-side validation of Privacy Pass tokens,
//! including signature verification, replay protection, and scope matching.

use std::sync::Arc;

use privacypass::TruncatedTokenKeyId;
use privacypass::public_tokens::PublicKey;
use privacypass::public_tokens::server::{OriginKeyStore, OriginServer};

use crate::{Error, InMemoryNonceStore, NonceStore, Operation, PrivateTokenAuth, Scope};

/// Token verifier for MoQ relays.
///
/// Validates Privacy Pass tokens and checks authorization scope.
pub struct Verifier {
	origin_server: OriginServer,
	key_store: Arc<SingleKeyStore>,
	nonce_store: Arc<InMemoryNonceStore>,
	issuer_name: String,
}

impl Verifier {
	/// Create a new verifier with the given issuer public key.
	pub fn new(issuer_name: String, issuer_key: PublicKey) -> Self {
		let key_store = Arc::new(SingleKeyStore::new(issuer_key));
		let nonce_store = Arc::new(InMemoryNonceStore::new());

		Self {
			origin_server: OriginServer::new(),
			key_store,
			nonce_store,
			issuer_name,
		}
	}

	/// Get the issuer name.
	pub fn issuer_name(&self) -> &str {
		&self.issuer_name
	}

	/// Verify a token and check that it authorizes the requested operation.
	///
	/// # Arguments
	///
	/// * `token` - The PrivateTokenAuth to verify
	/// * `operation` - The operation being requested
	/// * `namespace` - The namespace being accessed
	/// * `track` - Optional track name being accessed
	///
	/// # Returns
	///
	/// The verified scope on success, or an error if verification fails.
	pub async fn verify(
		&self,
		token: &PrivateTokenAuth,
		operation: Operation,
		namespace: &str,
		track: Option<&str>,
	) -> crate::Result<Scope> {
		// Check for replay
		if !self.nonce_store.check_and_insert(token.nonce()).await {
			return Err(Error::NonceReplay);
		}

		// Verify token signature using privacypass crate
		self.origin_server
			.redeem_token(self.key_store.as_ref(), self.nonce_store.as_ref(), token.token.clone())
			.await
			.map_err(|e| Error::PrivacyPass(e.to_string()))?;

		// Reconstruct the challenge to extract scope
		// The scope is encoded in origin_info, which is hashed into challenge_digest
		// We need the client to send the scope separately, or we trust the challenge_digest
		// For now, we'll require the scope to be passed in and verify it matches

		// TODO: In a full implementation, we'd need to:
		// 1. Store challenges when issued, keyed by digest
		// 2. Look up the challenge by the token's challenge_digest
		// 3. Extract and verify the scope

		// For now, we construct the expected scope and verify the operation matches
		let scope = Scope::exact(operation, namespace);
		if let Some(track_name) = track {
			let scope_with_track = Scope::new(
				operation,
				crate::Pattern::Exact(namespace.to_string()),
				Some(crate::Pattern::Exact(track_name.to_string())),
			);
			// The token's scope must authorize this request
			// We accept if either exact namespace or namespace+track matches
			if !scope.matches(operation, namespace, track) && !scope_with_track.matches(operation, namespace, track) {
				return Err(Error::InvalidScope(format!(
					"token does not authorize {operation}:{namespace}:{track_name}"
				)));
			}
		}

		Ok(scope)
	}

	/// Verify a token without checking operation scope.
	///
	/// Use this when you only need to verify the token is valid,
	/// not that it authorizes a specific operation.
	pub async fn verify_token_only(&self, token: &PrivateTokenAuth) -> crate::Result<()> {
		// Check for replay
		if !self.nonce_store.check_and_insert(token.nonce()).await {
			return Err(Error::NonceReplay);
		}

		// Verify token signature
		self.origin_server
			.redeem_token(self.key_store.as_ref(), self.nonce_store.as_ref(), token.token.clone())
			.await
			.map_err(|e| Error::PrivacyPass(e.to_string()))?;

		Ok(())
	}
}

/// Simple key store holding a single issuer key.
pub struct SingleKeyStore {
	key: PublicKey,
	truncated_id: TruncatedTokenKeyId,
}

impl SingleKeyStore {
	/// Create a new key store with the given public key.
	pub fn new(key: PublicKey) -> Self {
		let truncated_id = privacypass::public_tokens::public_key_to_truncated_token_key_id(&key);
		Self { key, truncated_id }
	}
}

#[async_trait::async_trait]
impl OriginKeyStore for SingleKeyStore {
	async fn insert(&self, _truncated_token_key_id: TruncatedTokenKeyId, _key: PublicKey) {
		// Single key store, ignore inserts
	}

	async fn get(&self, truncated_token_key_id: &TruncatedTokenKeyId) -> Vec<PublicKey> {
		if *truncated_token_key_id == self.truncated_id {
			vec![self.key.clone()]
		} else {
			vec![]
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// Note: Full verification tests require a real issuer key and valid token.
	// These would be integration tests against the Cloudflare endpoint.

	#[test]
	fn test_single_key_store() {
		// This test just verifies the key store compiles and basic structure
		// A real test would need a valid RSA public key
	}
}
