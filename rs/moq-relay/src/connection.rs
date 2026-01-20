use crate::{Auth, AuthError, AuthToken, Cluster};

use moq_native::Request;

/// MoQ session termination error code for Unauthorized.
const ERROR_UNAUTHORIZED: u32 = 0x2;

pub struct Connection {
	pub id: u64,
	pub request: Request,
	pub cluster: Cluster,
	pub auth: Auth,
}

impl Connection {
	#[tracing::instrument("conn", skip_all, fields(id = self.id))]
	pub async fn run(self) -> anyhow::Result<()> {
		// Extract path and JWT from URL (if present)
		let (path, jwt) = match self.request.url() {
			Some(url) => {
				let path = url.path().to_string();
				let jwt = url.query_pairs().find(|(k, _)| k == "jwt").map(|(_, v)| v.to_string());
				(path, jwt)
			}
			None => (String::new(), None),
		};

		// Try JWT auth first (pre-SETUP, from URL)
		if let Ok(token) = self.auth.verify(&path, jwt.as_deref()) {
			// JWT auth succeeded - use simple accept path
			let publish = self.cluster.publisher(&token);
			let subscribe = self.cluster.subscriber(&token);

			log_accepted(&token, &publish, &subscribe);

			if publish.is_none() && subscribe.is_none() {
				anyhow::bail!("invalid session; no allowed paths");
			}

			// Accept the connection.
			// NOTE: subscribe and publish seem backwards because of how relays work.
			// We publish the tracks the client is allowed to subscribe to.
			// We subscribe to the tracks the client is allowed to publish.
			let session = self.request.accept(subscribe, publish).await?;
			return session.closed().await.map_err(Into::into);
		}

		// No JWT - need to check SETUP AuthorizationToken for Privacy Pass
		// Use two-phase accept to inspect SETUP parameters
		let pending = match self.request.accept_setup().await {
			Ok(pending) => pending,
			Err(err) => {
				tracing::debug!(%err, "failed to accept setup");
				return Err(err);
			}
		};

		// Check for AuthorizationToken (Privacy Pass)
		let token = if let Some(auth_token) = pending.authorization_token() {
			// Verify Privacy Pass token
			match self.auth.verify_pp_token(&path, &auth_token) {
				Ok(token) => token,
				Err(err) => {
					tracing::debug!(%err, "Privacy Pass token verification failed");
					// Reject with challenge so client can get a new token
					if let Some(challenge) = self.auth.build_pp_challenge(&path) {
						pending.reject_with_challenge(ERROR_UNAUTHORIZED, &challenge);
					} else {
						pending.reject(ERROR_UNAUTHORIZED, "invalid authorization token");
					}
					return Err(err.into());
				}
			}
		} else if self.auth.has_privacypass() {
			// Privacy Pass is enabled but no token provided
			// Reject with TokenChallenge so client can acquire a token from the issuer
			tracing::debug!("no authorization token, sending TokenChallenge");
			if let Some(challenge) = self.auth.build_pp_challenge(&path) {
				pending.reject_with_challenge(ERROR_UNAUTHORIZED, &challenge);
			} else {
				pending.reject(ERROR_UNAUTHORIZED, "authorization required");
			}
			return Err(AuthError::ExpectedToken.into());
		} else {
			// No PP configured and no JWT - this shouldn't happen if auth is configured
			tracing::debug!("no authorization method available");
			pending.reject(ERROR_UNAUTHORIZED, "authorization required");
			return Err(AuthError::ExpectedToken.into());
		};

		// Complete the handshake with the verified token
		let publish = self.cluster.publisher(&token);
		let subscribe = self.cluster.subscriber(&token);

		log_accepted(&token, &publish, &subscribe);

		if publish.is_none() && subscribe.is_none() {
			pending.reject(ERROR_UNAUTHORIZED, "no allowed paths");
			anyhow::bail!("invalid session; no allowed paths");
		}

		// Complete the handshake
		let session = pending.accept(subscribe, publish).await?;

		// Wait until the session is closed.
		session.closed().await.map_err(Into::into)
	}
}

fn log_accepted(
	token: &AuthToken,
	publish: &Option<moq_lite::OriginProducer>,
	subscribe: &Option<moq_lite::OriginConsumer>,
) {
	match (publish, subscribe) {
		(Some(publish), Some(subscribe)) => {
			tracing::info!(
				root = %token.root,
				publish = %publish.allowed().map(|p| p.as_str()).collect::<Vec<_>>().join(","),
				subscribe = %subscribe.allowed().map(|p| p.as_str()).collect::<Vec<_>>().join(","),
				"session accepted"
			);
		}
		(Some(publish), None) => {
			tracing::info!(
				root = %token.root,
				publish = %publish.allowed().map(|p| p.as_str()).collect::<Vec<_>>().join(","),
				"publisher accepted"
			);
		}
		(None, Some(subscribe)) => {
			tracing::info!(
				root = %token.root,
				subscribe = %subscribe.allowed().map(|p| p.as_str()).collect::<Vec<_>>().join(","),
				"subscriber accepted"
			);
		}
		_ => {}
	}
}
