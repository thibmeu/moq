//! Error types for Privacy Pass operations.

use thiserror::Error;

/// Errors from Privacy Pass operations.
#[derive(Debug, Error)]
pub enum Error {
	/// Failed to parse scope string.
	#[error("invalid scope: {0}")]
	InvalidScope(String),

	/// Token type mismatch.
	#[error("invalid token type: expected 0x0002, got {0:#06x}")]
	InvalidTokenType(u16),

	/// Token signature verification failed.
	#[error("token signature invalid")]
	InvalidSignature,

	/// Token nonce was already used (replay attack).
	#[error("token nonce already used")]
	NonceReplay,

	/// Challenge digest mismatch.
	#[error("challenge digest mismatch")]
	ChallengeMismatch,

	/// Token key ID not found.
	#[error("unknown token key ID")]
	UnknownKeyId,

	/// Failed to decode token.
	#[error("token decode failed: {0}")]
	DecodeFailed(String),

	/// Failed to encode token.
	#[error("token encode failed: {0}")]
	EncodeFailed(String),

	/// HTTP request failed.
	#[cfg(feature = "client")]
	#[error("HTTP request failed: {0}")]
	HttpError(#[from] reqwest::Error),

	/// Issuer returned an error.
	#[error("issuer error: {0}")]
	IssuerError(String),

	/// No token keys available from issuer.
	#[error("no token keys available")]
	NoTokenKeys,

	/// Privacy Pass library error.
	#[error("privacypass error: {0}")]
	PrivacyPass(String),
}

/// Result type for Privacy Pass operations.
pub type Result<T> = std::result::Result<T, Error>;
