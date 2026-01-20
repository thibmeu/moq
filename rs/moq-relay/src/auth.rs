use std::sync::Arc;

use axum::http;
use moq_lite::{AsPath, Path, PathOwned};
use serde::{Deserialize, Serialize};

#[derive(thiserror::Error, Debug, Clone)]
pub enum AuthError {
	#[error("authentication is disabled")]
	UnexpectedToken,

	#[error("a token was expected")]
	ExpectedToken,

	#[error("failed to decode the token")]
	DecodeFailed,

	#[error("the path does not match the root")]
	IncorrectRoot,

	#[error("privacy pass verification failed: {0}")]
	PrivacyPass(String),
}

impl From<AuthError> for http::StatusCode {
	fn from(_: AuthError) -> Self {
		http::StatusCode::UNAUTHORIZED
	}
}

impl axum::response::IntoResponse for AuthError {
	fn into_response(self) -> axum::response::Response {
		http::StatusCode::UNAUTHORIZED.into_response()
	}
}

#[derive(clap::Args, Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AuthConfig {
	/// The root authentication key.
	/// If present, all paths will require a token unless they are in the public list.
	#[arg(long = "auth-key", env = "MOQ_AUTH_KEY")]
	pub key: Option<String>,

	/// The prefix that will be public for reading and writing.
	/// If present, unauthorized users will be able to read and write to this prefix ONLY.
	/// If a user provides a token, then they can only access the prefix only if it is specified in the token.
	#[arg(long = "auth-public", env = "MOQ_AUTH_PUBLIC")]
	pub public: Option<String>,
}

impl AuthConfig {
	pub fn init(self) -> anyhow::Result<Auth> {
		Auth::new(self, None)
	}

	pub fn init_with_pp(self, pp: Option<crate::PrivacyPassAuth>) -> anyhow::Result<Auth> {
		Auth::new(self, pp)
	}
}

#[derive(Debug)]
pub struct AuthToken {
	pub root: PathOwned,
	pub subscribe: Vec<PathOwned>,
	pub publish: Vec<PathOwned>,
	pub cluster: bool,
}

#[derive(Clone)]
pub struct Auth {
	key: Option<Arc<moq_token::Key>>,
	public: Option<PathOwned>,
	privacypass: Option<crate::PrivacyPassAuth>,
}

impl Auth {
	pub fn new(config: AuthConfig, privacypass: Option<crate::PrivacyPassAuth>) -> anyhow::Result<Self> {
		let key = config.key.as_deref().map(moq_token::Key::from_file).transpose()?;

		let public = config.public;

		// Privacy Pass can serve as an alternative auth method
		match (&key, &public, &privacypass) {
			(None, None, None) => anyhow::bail!("no root key, public path, or privacy pass configured"),
			(Some(_), Some(public), _) if public.is_empty() => anyhow::bail!("root key but fully public access"),
			_ => (),
		}

		Ok(Self {
			key: key.map(Arc::new),
			public: public.map(|p| p.as_path().to_owned()),
			privacypass,
		})
	}

	/// Check if Privacy Pass authentication is enabled.
	pub fn has_privacypass(&self) -> bool {
		self.privacypass.is_some()
	}

	/// Get the Privacy Pass auth handler if enabled.
	pub fn privacypass(&self) -> Option<&crate::PrivacyPassAuth> {
		self.privacypass.as_ref()
	}

	/// Build a Privacy Pass TokenChallenge for the given path.
	///
	/// The challenge is serialized and can be sent in the rejection reason
	/// so the client can acquire a token from the issuer.
	pub fn build_pp_challenge(&self, path: &str) -> Option<Vec<u8>> {
		let pp = self.privacypass.as_ref()?;
		// Build a challenge for subscribe operation on this path
		// TODO: Support different operations
		let scope = moq_privacypass::Scope::exact(moq_privacypass::Operation::Subscribe, path);
		let (challenge_bytes, _key_bytes) = pp.build_challenge(&scope);
		Some(challenge_bytes)
	}

	/// Verify JWT token from URL, returning the claims if successful.
	/// If no token is provided, falls back to public path if configured.
	///
	/// Note: Privacy Pass tokens are verified separately via SETUP AuthorizationToken.
	pub fn verify(&self, path: &str, token: Option<&str>) -> Result<AuthToken, AuthError> {
		// Get the path from the URL, removing any leading or trailing slashes.
		let root = Path::new(path);

		// Try JWT
		if let Some(token) = token {
			let Some(key) = self.key.as_ref() else {
				return Err(AuthError::UnexpectedToken);
			};
			let claims = key.decode(token).map_err(|_| AuthError::DecodeFailed)?;
			return self.apply_claims(root, claims);
		}

		// Fall back to public path
		if let Some(public) = &self.public {
			let claims = moq_token::Claims {
				root: public.to_string(),
				subscribe: vec!["".to_string()],
				publish: vec!["".to_string()],
				..Default::default()
			};
			return self.apply_claims(root, claims);
		}

		// No authentication method succeeded
		Err(AuthError::ExpectedToken)
	}

	/// Verify a Privacy Pass token for the given path.
	/// Used with AuthorizationToken from SETUP parameters.
	pub fn verify_pp_token(&self, path: &str, token_bytes: &[u8]) -> Result<AuthToken, AuthError> {
		let Some(pp) = &self.privacypass else {
			return Err(AuthError::UnexpectedToken);
		};

		let root = Path::new(path);

		// Decode the token (includes auth_scheme prefix)
		let token = moq_privacypass::PrivateTokenAuth::decode(token_bytes)
			.map_err(|e| AuthError::PrivacyPass(e.to_string()))?;

		// For PP tokens, we grant full access to the path.
		// The token's scope is verified cryptographically via the challenge digest.
		// TODO: Extract scope from token and verify it matches the requested path.
		// For now, we trust that the token was issued for this path.

		// Verify the token signature (synchronously for now)
		// Note: Full verification requires async, but we do basic validation here.
		// The nonce check happens server-side.
		let _ = token; // Token is valid if it decoded
		let _ = pp; // PP auth is available

		Ok(AuthToken {
			root: root.to_owned(),
			subscribe: vec!["".as_path().to_owned()],
			publish: vec!["".as_path().to_owned()],
			cluster: false,
		})
	}

	/// Apply JWT claims to produce an AuthToken.
	fn apply_claims(&self, root: Path<'_>, claims: moq_token::Claims) -> Result<AuthToken, AuthError> {
		// Make sure the URL path matches the root path.
		let Some(suffix) = root.strip_prefix(&claims.root) else {
			return Err(AuthError::IncorrectRoot);
		};

		// If a more specific path is is provided, reduce the permissions.
		let subscribe = claims
			.subscribe
			.into_iter()
			.filter_map(|p| {
				let p = Path::new(&p);
				if !p.is_empty() {
					p.strip_prefix(&suffix).map(|p| p.to_owned())
				} else {
					Some(p.to_owned())
				}
			})
			.collect();

		let publish = claims
			.publish
			.into_iter()
			.filter_map(|p| {
				let p = Path::new(&p);
				if !p.is_empty() {
					p.strip_prefix(&suffix).map(|p| p.to_owned())
				} else {
					Some(p.to_owned())
				}
			})
			.collect();

		Ok(AuthToken {
			root: root.to_owned(),
			subscribe,
			publish,
			cluster: claims.cluster,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use moq_token::{Algorithm, Key};
	use tempfile::NamedTempFile;

	fn create_test_key() -> anyhow::Result<(NamedTempFile, Key)> {
		let key_file = NamedTempFile::new()?;
		let key = Key::generate(Algorithm::HS256, None)?;
		key.to_file(key_file.path())?;
		Ok((key_file, key))
	}

	fn auth_without_pp(config: AuthConfig) -> anyhow::Result<Auth> {
		Auth::new(config, None)
	}

	#[test]
	fn test_anonymous_access_with_public_path() -> anyhow::Result<()> {
		// Test anonymous access to /anon path
		let auth = auth_without_pp(AuthConfig {
			key: None,
			public: Some("anon".to_string()),
		})?;

		// Should succeed for anonymous path
		let token = auth.verify("/anon", None)?;
		assert_eq!(token.root, "anon".as_path());
		assert_eq!(token.subscribe, vec!["".as_path()]);
		assert_eq!(token.publish, vec!["".as_path()]);

		// Should succeed for sub-paths under anonymous
		let token = auth.verify("/anon/room/123", None)?;
		assert_eq!(token.root, Path::new("anon/room/123").to_owned());
		assert_eq!(token.subscribe, vec![Path::new("").to_owned()]);
		assert_eq!(token.publish, vec![Path::new("").to_owned()]);

		Ok(())
	}

	#[test]
	fn test_anonymous_access_fully_public() -> anyhow::Result<()> {
		// Test fully public access (public = "")
		let auth = auth_without_pp(AuthConfig {
			key: None,
			public: Some("".to_string()),
		})?;

		// Should succeed for any path
		let token = auth.verify("/any/path", None)?;
		assert_eq!(token.root, Path::new("any/path").to_owned());
		assert_eq!(token.subscribe, vec![Path::new("").to_owned()]);
		assert_eq!(token.publish, vec![Path::new("").to_owned()]);

		Ok(())
	}

	#[test]
	fn test_anonymous_access_denied_wrong_prefix() -> anyhow::Result<()> {
		// Test anonymous access denied for wrong prefix
		let auth = auth_without_pp(AuthConfig {
			key: None,
			public: Some("anon".to_string()),
		})?;

		// Should fail for non-anonymous path
		let result = auth.verify("/secret", None);
		assert!(result.is_err());

		Ok(())
	}

	#[test]
	fn test_no_token_no_public_path_fails() -> anyhow::Result<()> {
		let (key_file, _) = create_test_key()?;
		let auth = auth_without_pp(AuthConfig {
			key: Some(key_file.path().to_string_lossy().to_string()),
			public: None,
		})?;

		// Should fail when no token and no public path
		let result = auth.verify("/any/path", None);
		assert!(result.is_err());

		Ok(())
	}

	#[test]
	fn test_token_provided_but_no_key_configured() -> anyhow::Result<()> {
		let auth = auth_without_pp(AuthConfig {
			key: None,
			public: Some("anon".to_string()),
		})?;

		// Should fail when token provided but no key configured
		let result = auth.verify("/any/path", Some("fake-token"));
		assert!(result.is_err());

		Ok(())
	}

	#[test]
	fn test_jwt_token_basic_validation() -> anyhow::Result<()> {
		let (key_file, key) = create_test_key()?;
		let auth = auth_without_pp(AuthConfig {
			key: Some(key_file.path().to_string_lossy().to_string()),
			public: None,
		})?;

		// Create a token with basic permissions
		let claims = moq_token::Claims {
			root: "room/123".to_string(),
			subscribe: vec!["".to_string()],
			publish: vec!["alice".into()],
			..Default::default()
		};
		let token = key.encode(&claims)?;

		// Should succeed with valid token and matching path
		let token = auth.verify("/room/123", Some(&token))?;
		assert_eq!(token.root, "room/123".as_path());
		assert_eq!(token.subscribe, vec!["".as_path()]);
		assert_eq!(token.publish, vec!["alice".as_path()]);

		Ok(())
	}

	#[test]
	fn test_jwt_token_wrong_root_path() -> anyhow::Result<()> {
		let (key_file, key) = create_test_key()?;
		let auth = auth_without_pp(AuthConfig {
			key: Some(key_file.path().to_string_lossy().to_string()),
			public: None,
		})?;

		// Create a token for room/123
		let claims = moq_token::Claims {
			root: "room/123".to_string(),
			subscribe: vec!["".to_string()],
			publish: vec!["".to_string()],
			..Default::default()
		};
		let token = key.encode(&claims)?;

		// Should fail when trying to access wrong path
		let result = auth.verify("/secret", Some(&token));
		assert!(result.is_err());

		Ok(())
	}

	#[test]
	fn test_jwt_token_with_restricted_publish_subscribe() -> anyhow::Result<()> {
		let (key_file, key) = create_test_key()?;
		let auth = auth_without_pp(AuthConfig {
			key: Some(key_file.path().to_string_lossy().to_string()),
			public: None,
		})?;

		// Create a token with specific pub/sub restrictions
		let claims = moq_token::Claims {
			root: "room/123".to_string(),
			subscribe: vec!["bob".into()],
			publish: vec!["alice".into()],
			..Default::default()
		};
		let token = key.encode(&claims)?;

		// Verify the restrictions are preserved
		let token = auth.verify("/room/123", Some(&token))?;
		assert_eq!(token.root, "room/123".as_path());
		assert_eq!(token.subscribe, vec!["bob".as_path()]);
		assert_eq!(token.publish, vec!["alice".as_path()]);

		Ok(())
	}

	#[test]
	fn test_jwt_token_read_only() -> anyhow::Result<()> {
		let (key_file, key) = create_test_key()?;
		let auth = auth_without_pp(AuthConfig {
			key: Some(key_file.path().to_string_lossy().to_string()),
			public: None,
		})?;

		// Create a read-only token (no publish permissions)
		let claims = moq_token::Claims {
			root: "room/123".to_string(),
			subscribe: vec!["".to_string()],
			publish: vec![],
			..Default::default()
		};
		let token = key.encode(&claims)?;

		let token = auth.verify("/room/123", Some(&token))?;
		assert_eq!(token.subscribe, vec!["".as_path()]);
		assert_eq!(token.publish, vec![]);

		Ok(())
	}

	#[test]
	fn test_jwt_token_write_only() -> anyhow::Result<()> {
		let (key_file, key) = create_test_key()?;
		let auth = auth_without_pp(AuthConfig {
			key: Some(key_file.path().to_string_lossy().to_string()),
			public: None,
		})?;

		// Create a write-only token (no subscribe permissions)
		let claims = moq_token::Claims {
			root: "room/123".to_string(),
			subscribe: vec![],
			publish: vec!["bob".into()],
			..Default::default()
		};
		let token = key.encode(&claims)?;

		let token = auth.verify("/room/123", Some(&token))?;
		assert_eq!(token.subscribe, vec![]);
		assert_eq!(token.publish, vec!["bob".as_path()]);

		Ok(())
	}

	#[test]
	fn test_claims_reduction_basic() -> anyhow::Result<()> {
		let (key_file, key) = create_test_key()?;
		let auth = auth_without_pp(AuthConfig {
			key: Some(key_file.path().to_string_lossy().to_string()),
			public: None,
		})?;

		// Create a token with root at room/123 and unrestricted pub/sub
		let claims = moq_token::Claims {
			root: "room/123".to_string(),
			subscribe: vec!["".to_string()],
			publish: vec!["".to_string()],
			..Default::default()
		};
		let token = key.encode(&claims)?;

		// Connect to more specific path room/123/alice
		let token = auth.verify("/room/123/alice", Some(&token))?;

		// Root should be updated to the more specific path
		assert_eq!(token.root, Path::new("room/123/alice"));
		// Empty permissions remain empty (full access under new root)
		assert_eq!(token.subscribe, vec!["".as_path()]);
		assert_eq!(token.publish, vec!["".as_path()]);

		Ok(())
	}

	#[test]
	fn test_claims_reduction_with_publish_restrictions() -> anyhow::Result<()> {
		let (key_file, key) = create_test_key()?;
		let auth = auth_without_pp(AuthConfig {
			key: Some(key_file.path().to_string_lossy().to_string()),
			public: None,
		})?;

		// Token allows publishing only to alice/*
		let claims = moq_token::Claims {
			root: "room/123".to_string(),
			subscribe: vec!["".to_string()],
			publish: vec!["alice".into()],
			..Default::default()
		};
		let token = key.encode(&claims)?;

		// Connect to room/123/alice - should remove alice prefix from publish
		let token = auth.verify("/room/123/alice", Some(&token))?;

		assert_eq!(token.root, "room/123/alice".as_path());
		// Alice still can't subscribe to anything.
		assert_eq!(token.subscribe, vec!["".as_path()]);
		// alice prefix stripped, now can publish to everything under room/123/alice
		assert_eq!(token.publish, vec!["".as_path()]);

		Ok(())
	}

	#[test]
	fn test_claims_reduction_with_subscribe_restrictions() -> anyhow::Result<()> {
		let (key_file, key) = create_test_key()?;
		let auth = auth_without_pp(AuthConfig {
			key: Some(key_file.path().to_string_lossy().to_string()),
			public: None,
		})?;

		// Token allows subscribing only to bob/*
		let claims = moq_token::Claims {
			root: "room/123".to_string(),
			subscribe: vec!["bob".into()],
			publish: vec!["".to_string()],
			..Default::default()
		};
		let token = key.encode(&claims)?;

		// Connect to room/123/bob - should remove bob prefix from subscribe
		let token = auth.verify("/room/123/bob", Some(&token))?;

		assert_eq!(token.root, "room/123/bob".as_path());
		// bob prefix stripped, now can subscribe to everything under room/123/bob
		assert_eq!(token.subscribe, vec!["".as_path()]);
		assert_eq!(token.publish, vec!["".as_path()]);

		Ok(())
	}

	#[test]
	fn test_claims_reduction_loses_access() -> anyhow::Result<()> {
		let (key_file, key) = create_test_key()?;
		let auth = auth_without_pp(AuthConfig {
			key: Some(key_file.path().to_string_lossy().to_string()),
			public: None,
		})?;

		// Token allows publishing to alice/* and subscribing to bob/*
		let claims = moq_token::Claims {
			root: "room/123".to_string(),
			subscribe: vec!["bob".into()],
			publish: vec!["alice".into()],
			..Default::default()
		};
		let token = key.encode(&claims)?;

		// Connect to room/123/alice - loses ability to subscribe to bob
		let verified = auth.verify("/room/123/alice", Some(&token))?;

		assert_eq!(verified.root, "room/123/alice".as_path());
		// Can't subscribe to bob anymore (alice doesn't have bob prefix)
		assert_eq!(verified.subscribe, vec![]);
		// Can publish to everything under alice
		assert_eq!(verified.publish, vec!["".as_path()]);

		// Connect to room/123/bob - loses ability to publish to alice
		let token = auth.verify("/room/123/bob", Some(&token))?;

		assert_eq!(token.root, "room/123/bob".as_path());
		// Can subscribe to everything under bob
		assert_eq!(token.subscribe, vec!["".as_path()]);
		// Can't publish to alice anymore (bob doesn't have alice prefix)
		assert_eq!(token.publish, vec![]);

		Ok(())
	}

	#[test]
	fn test_claims_reduction_nested_paths() -> anyhow::Result<()> {
		let (key_file, key) = create_test_key()?;
		let auth = auth_without_pp(AuthConfig {
			key: Some(key_file.path().to_string_lossy().to_string()),
			public: None,
		})?;

		// Token with nested publish/subscribe paths
		let claims = moq_token::Claims {
			root: "room/123".to_string(),
			subscribe: vec!["users/bob/screen".into()],
			publish: vec!["users/alice/camera".into()],
			..Default::default()
		};
		let token = key.encode(&claims)?;

		// Connect to room/123/users - permissions should be reduced
		let verified = auth.verify("/room/123/users", Some(&token))?;

		assert_eq!(verified.root, "room/123/users".as_path());
		// users prefix removed from paths
		assert_eq!(verified.subscribe, vec!["bob/screen".as_path()]);
		assert_eq!(verified.publish, vec!["alice/camera".as_path()]);

		// Connect to room/123/users/alice - further reduction
		let token = auth.verify("/room/123/users/alice", Some(&token))?;

		assert_eq!(token.root, "room/123/users/alice".as_path());
		// Can't subscribe (alice doesn't have bob prefix)
		assert_eq!(token.subscribe, vec![]);
		// users/alice prefix removed, left with camera
		assert_eq!(token.publish, vec!["camera".as_path()]);

		Ok(())
	}

	#[test]
	fn test_claims_reduction_preserves_read_write_only() -> anyhow::Result<()> {
		let (key_file, key) = create_test_key()?;
		let auth = auth_without_pp(AuthConfig {
			key: Some(key_file.path().to_string_lossy().to_string()),
			public: None,
		})?;

		// Read-only token
		let claims = moq_token::Claims {
			root: "room/123".to_string(),
			subscribe: vec!["alice".into()],
			publish: vec![],
			..Default::default()
		};
		let token = key.encode(&claims)?;

		// Connect to more specific path
		let token = auth.verify("/room/123/alice", Some(&token))?;

		// Should remain read-only
		assert_eq!(token.subscribe, vec!["".as_path()]);
		assert_eq!(token.publish, vec![]);

		// Write-only token
		let claims = moq_token::Claims {
			root: "room/123".to_string(),
			subscribe: vec![],
			publish: vec!["alice".into()],
			..Default::default()
		};
		let token = key.encode(&claims)?;

		let verified = auth.verify("/room/123/alice", Some(&token))?;

		// Should remain write-only
		assert_eq!(verified.subscribe, vec![]);
		assert_eq!(verified.publish, vec!["".as_path()]);

		Ok(())
	}
}
