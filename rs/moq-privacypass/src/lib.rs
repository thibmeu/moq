//! Privacy Pass authentication for Media over QUIC (MoQ).
//!
//! Implements [draft-ietf-moq-privacy-pass-auth-01](https://www.ietf.org/archive/id/draft-ietf-moq-privacy-pass-auth-01.txt)
//! using publicly verifiable tokens (type 0x0002, Blind RSA 2048-bit).
//!
//! # Overview
//!
//! Privacy Pass provides privacy-preserving authorization through unlinkable tokens.
//! Clients obtain tokens from an issuer after attestation, then present them to
//! relays for authorization without revealing their identity.
//!
//! # Components
//!
//! - [`Scope`]: MoQ-specific authorization scope (operation + namespace + track)
//! - [`Challenge`]: TokenChallenge construction for MoQ
//! - [`Token`]: Wire format for PrivateTokenAuth
//! - [`Verifier`]: Server-side token verification
//! - [`NonceStore`]: Replay protection interface
//!
//! # Example Flow
//!
//! ```text
//! Client                     Relay                        Issuer
//!    |                         |                            |
//!    |-- GET /challenge ------>|                            |
//!    |<-- TokenChallenge ------|                            |
//!    |                         |                            |
//!    |-- POST /token-request ---------------------->|
//!    |<-- TokenResponse -------------------------|
//!    |                         |                            |
//!    |-- SETUP + Token ------->|                            |
//!    |                    [verify]                          |
//!    |<-- SETUP_OK ------------|                            |
//! ```

mod challenge;
#[cfg(feature = "client")]
mod client;
mod error;
mod nonce;
mod scope;
mod token;
mod verifier;

pub use challenge::*;
#[cfg(feature = "client")]
pub use client::*;
pub use error::*;
pub use nonce::*;
pub use scope::*;
pub use token::*;
pub use verifier::*;

/// Default Privacy Pass issuer (Cloudflare demo endpoint - no attestation required).
pub const DEFAULT_ISSUER: &str = "demo-pat.issuer.cloudflare.com";

/// Well-known path for issuer directory.
pub const ISSUER_DIRECTORY_PATH: &str = "/.well-known/private-token-issuer-directory";

/// Privacy Pass challenge prefix in rejection reasons.
pub const CHALLENGE_PREFIX: &str = "pp:";

/// Parse a Privacy Pass TokenChallenge from a QUIC close reason.
///
/// The reason format is: `pp:<base64url(challenge)>`
///
/// Returns the parsed TokenChallenge and the issuer name for acquiring a token.
pub fn parse_challenge_from_reason(reason: &str) -> Result<(privacypass::auth::authenticate::TokenChallenge, String)> {
	let encoded = reason.strip_prefix(CHALLENGE_PREFIX).ok_or_else(|| {
		Error::DecodeFailed("reason does not contain Privacy Pass challenge".to_string())
	})?;

	use base64::Engine;
	let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
		.decode(encoded)
		.map_err(|e| Error::DecodeFailed(format!("invalid base64: {e}")))?;

	let challenge = deserialize_challenge(&bytes)?;
	let issuer = challenge.issuer_name().to_string();

	Ok((challenge, issuer))
}
