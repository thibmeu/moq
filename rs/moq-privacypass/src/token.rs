//! PrivateTokenAuth wire format for MoQ.
//!
//! Implements the token encoding specified in draft-ietf-moq-privacy-pass-auth-01:
//!
//! ```text
//! struct {
//!     uint8_t auth_scheme = 0x01;  // Privacy Pass
//!     opaque token_data<1..2^16-1>;
//! } PrivateTokenAuth;
//! ```
//!
//! The token_data contains a Privacy Pass token (RFC 9577 §2.2):
//!
//! ```text
//! struct {
//!     uint16_t token_type = 0x0002;
//!     uint8_t nonce[32];
//!     uint8_t challenge_digest[32];
//!     uint8_t token_key_id[32];
//!     uint8_t authenticator[Nk];  // 256 bytes for RSA-2048
//! } Token;
//! ```

use bytes::{Buf, BufMut};
use privacypass::public_tokens::PublicToken;
use privacypass::{Deserialize, Serialize, TokenType};

use crate::Error;

/// Auth scheme identifier for Privacy Pass (from draft-ietf-moq-privacy-pass-auth-01).
pub const AUTH_SCHEME_PRIVACY_PASS: u8 = 0x01;

/// Token type for publicly verifiable tokens (Blind RSA 2048-bit).
pub const TOKEN_TYPE_PUBLIC: u16 = 0x0002;

/// Size of the authenticator for RSA-2048 (Nk = 256 bytes).
pub const AUTHENTICATOR_SIZE: usize = 256;

/// Total size of a public token: 2 + 32 + 32 + 32 + 256 = 354 bytes.
pub const PUBLIC_TOKEN_SIZE: usize = 2 + 32 + 32 + 32 + AUTHENTICATOR_SIZE;

/// PrivateTokenAuth wrapper for MoQ authorization.
///
/// This wraps a Privacy Pass token with the MoQ-specific auth scheme prefix.
#[derive(Debug, Clone)]
pub struct PrivateTokenAuth {
	/// The underlying Privacy Pass token.
	pub token: PublicToken,
}

impl PrivateTokenAuth {
	/// Create a new PrivateTokenAuth from a PublicToken.
	pub fn new(token: PublicToken) -> Self {
		Self { token }
	}

	/// Get the token's nonce.
	pub fn nonce(&self) -> [u8; 32] {
		self.token.nonce()
	}

	/// Get the token's challenge digest.
	pub fn challenge_digest(&self) -> &[u8; 32] {
		self.token.challenge_digest()
	}

	/// Get the token's key ID.
	pub fn token_key_id(&self) -> &[u8; 32] {
		self.token.token_key_id()
	}

	/// Encode to bytes for transmission.
	///
	/// Format:
	/// - auth_scheme: u8 (0x01)
	/// - token_len: u16 (big-endian)
	/// - token_data: [u8; token_len]
	pub fn encode(&self) -> crate::Result<Vec<u8>> {
		let token_bytes = self
			.token
			.tls_serialize_detached()
			.map_err(|e| Error::EncodeFailed(e.to_string()))?;

		let mut buf = Vec::with_capacity(1 + 2 + token_bytes.len());
		buf.put_u8(AUTH_SCHEME_PRIVACY_PASS);
		buf.put_u16(token_bytes.len() as u16);
		buf.put_slice(&token_bytes);

		Ok(buf)
	}

	/// Decode from bytes.
	pub fn decode(mut bytes: &[u8]) -> crate::Result<Self> {
		if bytes.remaining() < 3 {
			return Err(Error::DecodeFailed("buffer too short".to_string()));
		}

		let scheme = bytes.get_u8();
		if scheme != AUTH_SCHEME_PRIVACY_PASS {
			return Err(Error::DecodeFailed(format!("invalid auth scheme: {scheme:#04x}")));
		}

		let token_len = bytes.get_u16() as usize;
		if bytes.remaining() < token_len {
			return Err(Error::DecodeFailed(format!(
				"token length mismatch: expected {token_len}, got {}",
				bytes.remaining()
			)));
		}

		let token_bytes = &bytes[..token_len];
		let token =
			PublicToken::tls_deserialize(&mut &token_bytes[..]).map_err(|e| Error::DecodeFailed(e.to_string()))?;

		// Verify token type
		if token.token_type() != TokenType::Public {
			return Err(Error::InvalidTokenType(token.token_type() as u16));
		}

		Ok(Self { token })
	}

	/// Decode from bytes without the auth scheme prefix.
	///
	/// Use this when the token is already extracted from the AuthorizationToken parameter.
	pub fn decode_token_only(bytes: &[u8]) -> crate::Result<Self> {
		let token = PublicToken::tls_deserialize(&mut &bytes[..]).map_err(|e| Error::DecodeFailed(e.to_string()))?;

		if token.token_type() != TokenType::Public {
			return Err(Error::InvalidTokenType(token.token_type() as u16));
		}

		Ok(Self { token })
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use generic_array::GenericArray;
	use privacypass::TokenType;
	use typenum::U256;

	fn create_test_token() -> PublicToken {
		let nonce = [0x11u8; 32];
		let challenge_digest = [0x22u8; 32];
		let token_key_id = [0x33u8; 32];
		let authenticator = [0x44u8; 256];

		privacypass::auth::authorize::Token::<U256>::new(
			TokenType::Public,
			nonce,
			challenge_digest,
			token_key_id,
			*GenericArray::from_slice(&authenticator),
		)
	}

	#[test]
	fn test_encode_decode_roundtrip() {
		let token = create_test_token();
		let auth = PrivateTokenAuth::new(token);

		let encoded = auth.encode().unwrap();
		let decoded = PrivateTokenAuth::decode(&encoded).unwrap();

		assert_eq!(decoded.nonce(), auth.nonce());
		assert_eq!(decoded.challenge_digest(), auth.challenge_digest());
		assert_eq!(decoded.token_key_id(), auth.token_key_id());
	}

	#[test]
	fn test_encode_format() {
		let token = create_test_token();
		let auth = PrivateTokenAuth::new(token);
		let encoded = auth.encode().unwrap();

		// Check auth scheme
		assert_eq!(encoded[0], AUTH_SCHEME_PRIVACY_PASS);

		// Check length (big-endian u16)
		let len = u16::from_be_bytes([encoded[1], encoded[2]]) as usize;
		assert_eq!(len, PUBLIC_TOKEN_SIZE);
		assert_eq!(encoded.len(), 3 + PUBLIC_TOKEN_SIZE);
	}

	#[test]
	fn test_decode_invalid_scheme() {
		let mut bytes = vec![0x99, 0x00, 0x10]; // Invalid scheme
		bytes.extend_from_slice(&[0u8; 16]);

		let result = PrivateTokenAuth::decode(&bytes);
		assert!(matches!(result, Err(Error::DecodeFailed(_))));
	}

	#[test]
	fn test_decode_token_only() {
		let token = create_test_token();
		let token_bytes = token.tls_serialize_detached().unwrap();

		let decoded = PrivateTokenAuth::decode_token_only(&token_bytes).unwrap();
		assert_eq!(decoded.nonce(), token.nonce());
	}

	#[test]
	fn test_token_accessors() {
		let token = create_test_token();
		let auth = PrivateTokenAuth::new(token);

		assert_eq!(auth.nonce(), [0x11u8; 32]);
		assert_eq!(auth.challenge_digest(), &[0x22u8; 32]);
		assert_eq!(auth.token_key_id(), &[0x33u8; 32]);
	}
}
