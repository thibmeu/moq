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

/// Default Privacy Pass issuer (Cloudflare test endpoint).
pub const DEFAULT_ISSUER: &str = "pp-issuer-production.research.cloudflare.com";

/// Well-known path for issuer directory.
pub const ISSUER_DIRECTORY_PATH: &str = "/.well-known/private-token-issuer-directory";
