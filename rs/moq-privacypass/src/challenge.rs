//! TokenChallenge construction for MoQ.
//!
//! Wraps the Privacy Pass TokenChallenge with MoQ-specific origin_info encoding.

use privacypass::TokenType;
use privacypass::auth::authenticate::TokenChallenge;

use crate::Scope;

/// Build a TokenChallenge for MoQ authorization.
///
/// The challenge encodes the MoQ scope in the `origin_info` field using the format:
/// `operation:namespace[:track]`
///
/// # Arguments
///
/// * `issuer_name` - The issuer hostname (e.g., "pp-issuer-production.research.cloudflare.com")
/// * `scope` - The MoQ authorization scope
/// * `redemption_context` - Optional 32-byte context for binding tokens to specific sessions
pub fn build_challenge(issuer_name: &str, scope: &Scope, redemption_context: Option<[u8; 32]>) -> TokenChallenge {
	let origin_info = scope.to_origin_info();

	TokenChallenge::new(
		TokenType::Public, // 0x0002
		issuer_name,
		redemption_context,
		&[origin_info],
	)
}

/// Compute the SHA-256 digest of a TokenChallenge.
///
/// This is used as the `challenge_digest` field in the token.
pub fn challenge_digest(challenge: &TokenChallenge) -> crate::Result<[u8; 32]> {
	challenge
		.digest()
		.map_err(|e| crate::Error::EncodeFailed(e.to_string()))
}

/// Serialize a TokenChallenge to bytes.
pub fn serialize_challenge(challenge: &TokenChallenge) -> crate::Result<Vec<u8>> {
	challenge
		.serialize()
		.map_err(|e| crate::Error::EncodeFailed(e.to_string()))
}

/// Deserialize a TokenChallenge from bytes.
pub fn deserialize_challenge(bytes: &[u8]) -> crate::Result<TokenChallenge> {
	TokenChallenge::deserialize(bytes).map_err(|e| crate::Error::DecodeFailed(e.to_string()))
}

/// Extract the scope from a TokenChallenge's origin_info.
pub fn extract_scope(challenge: &TokenChallenge) -> crate::Result<Scope> {
	let origin_info = challenge.origin_info();
	if origin_info.is_empty() {
		return Err(crate::Error::InvalidScope("empty origin_info".to_string()));
	}
	origin_info[0].parse()
}

/// Verify that a challenge digest matches the expected challenge.
pub fn verify_digest(challenge: &TokenChallenge, digest: &[u8; 32]) -> crate::Result<bool> {
	let expected = challenge_digest(challenge)?;
	Ok(expected == *digest)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{Operation, Pattern};

	#[test]
	fn test_build_challenge() {
		let scope = Scope::new(Operation::Subscribe, Pattern::Prefix("room/".to_string()), None);

		let challenge = build_challenge("test-issuer.example.com", &scope, None);

		assert_eq!(challenge.token_type(), TokenType::Public);
		assert_eq!(challenge.issuer_name(), "test-issuer.example.com");
		assert_eq!(challenge.origin_info(), vec!["subscribe:room/*"]);
		assert!(challenge.redemption_context().is_none());
	}

	#[test]
	fn test_build_challenge_with_context() {
		let scope = Scope::exact(Operation::Publish, "room/123");
		let context = [0x42u8; 32];

		let challenge = build_challenge("issuer.example.com", &scope, Some(context));

		assert_eq!(challenge.redemption_context(), Some(context));
	}

	#[test]
	fn test_challenge_roundtrip() {
		let scope = Scope::parse("subscribe:sports/*:video*").unwrap();
		let challenge = build_challenge("issuer.example.com", &scope, None);

		let bytes = serialize_challenge(&challenge).unwrap();
		let decoded = deserialize_challenge(&bytes).unwrap();

		assert_eq!(decoded.issuer_name(), challenge.issuer_name());
		assert_eq!(decoded.origin_info(), challenge.origin_info());
	}

	#[test]
	fn test_extract_scope() {
		let scope = Scope::parse("publish:room/123:audio").unwrap();
		let challenge = build_challenge("issuer.example.com", &scope, None);

		let extracted = extract_scope(&challenge).unwrap();
		assert_eq!(extracted, scope);
	}

	#[test]
	fn test_challenge_digest() {
		let scope = Scope::exact(Operation::Subscribe, "test");
		let challenge = build_challenge("issuer.example.com", &scope, None);

		let digest = challenge_digest(&challenge).unwrap();
		assert_eq!(digest.len(), 32);

		// Digest should be deterministic
		let digest2 = challenge_digest(&challenge).unwrap();
		assert_eq!(digest, digest2);
	}

	#[test]
	fn test_verify_digest() {
		let scope = Scope::exact(Operation::Subscribe, "test");
		let challenge = build_challenge("issuer.example.com", &scope, None);
		let digest = challenge_digest(&challenge).unwrap();

		assert!(verify_digest(&challenge, &digest).unwrap());

		let wrong_digest = [0u8; 32];
		assert!(!verify_digest(&challenge, &wrong_digest).unwrap());
	}
}
