use std::{future::Future, pin::Pin, sync::Arc};

use bytes::Bytes;

use crate::{
	Error, OriginConsumer, OriginProducer,
	coding::{self, Decode, Encode, Stream},
	ietf, lite, setup,
};

/// A MoQ transport session, wrapping a WebTransport connection.
///
/// Created via:
/// - [`Session::connect`] for clients.
/// - [`Session::accept`] for servers.
pub struct Session {
	session: Arc<dyn SessionInner>,
}

/// The versions of MoQ that are supported by this implementation.
///
/// Ordered by preference, with the client's preference taking priority.
pub const VERSIONS: [coding::Version; 3] = [
	lite::Version::Draft02.coding(),
	lite::Version::Draft01.coding(),
	ietf::Version::Draft14.coding(),
];

/// The ALPN strings for supported versions.
pub const ALPNS: [&str; 2] = [lite::ALPN, ietf::ALPN];

impl Session {
	fn new<S: web_transport_trait::Session>(session: S) -> Self {
		Self {
			session: Arc::new(session),
		}
	}

	/// Perform the MoQ handshake as a client, negotiating the version.
	///
	/// Publishing is performed with [OriginConsumer] and subscribing with [OriginProducer].
	/// The connection remains active until the session is closed.
	pub async fn connect<S: web_transport_trait::Session>(
		session: S,
		publish: impl Into<Option<OriginConsumer>>,
		subscribe: impl Into<Option<OriginProducer>>,
	) -> Result<Self, Error> {
		Self::connect_with_auth(session, publish, subscribe, None).await
	}

	/// Perform the MoQ handshake as a client with optional authorization token.
	///
	/// The `auth_token` is included in the SETUP message's AuthorizationToken parameter.
	/// This is used for Privacy Pass authentication.
	pub async fn connect_with_auth<S: web_transport_trait::Session>(
		session: S,
		publish: impl Into<Option<OriginConsumer>>,
		subscribe: impl Into<Option<OriginProducer>>,
		auth_token: Option<Vec<u8>>,
	) -> Result<Self, Error> {
		let mut stream = Stream::open(&session, setup::ServerKind::Ietf14).await?;

		let mut parameters = ietf::Parameters::default();
		parameters.set_varint(ietf::ParameterVarInt::MaxRequestId, u32::MAX as u64);
		parameters.set_bytes(ietf::ParameterBytes::Implementation, b"moq-lite-rs".to_vec());
		if let Some(token) = auth_token {
			parameters.set_bytes(ietf::ParameterBytes::AuthorizationToken, token);
		}
		let parameters = parameters.encode_bytes(());

		let client = setup::Client {
			// Unfortunately, we have to pick a single draft range to support.
			// moq-lite can support this handshake.
			kind: setup::ClientKind::Ietf14,
			versions: VERSIONS.into(),
			parameters,
		};

		// TODO pretty print the parameters.
		tracing::trace!(?client, "sending client setup");
		stream.writer.encode(&client).await?;

		let mut server: setup::Server = stream.reader.decode().await?;
		tracing::trace!(?server, "received server setup");

		if let Ok(version) = lite::Version::try_from(server.version) {
			let stream = stream.with_version(version);
			lite::start(session.clone(), stream, publish.into(), subscribe.into(), version).await?;
		} else if let Ok(version) = ietf::Version::try_from(server.version) {
			// Decode the parameters to get the initial request ID.
			let parameters = ietf::Parameters::decode(&mut server.parameters, version)?;
			let request_id_max =
				ietf::RequestId(parameters.get_varint(ietf::ParameterVarInt::MaxRequestId).unwrap_or(0));

			let stream = stream.with_version(version);
			ietf::start(
				session.clone(),
				stream,
				request_id_max,
				true,
				publish.into(),
				subscribe.into(),
				version,
			)
			.await?;
		} else {
			// unreachable, but just in case
			return Err(Error::Version(client.versions, [server.version].into()));
		}

		tracing::debug!(version = ?server.version, "connected");

		Ok(Self::new(session))
	}

	/// Perform the MoQ handshake as a server.
	///
	/// Publishing is performed with [OriginConsumer] and subscribing with [OriginProducer].
	/// The connection remains active until the session is closed.
	pub async fn accept<S: web_transport_trait::Session>(
		session: S,
		publish: impl Into<Option<OriginConsumer>>,
		subscribe: impl Into<Option<OriginProducer>>,
	) -> Result<Self, Error> {
		// Accept with an initial version; we'll switch to the negotiated version later
		let mut stream = Stream::accept(&session, ()).await?;
		let client: setup::Client = stream.reader.decode().await?;
		tracing::trace!(?client, "received client setup");

		// Choose the version to use
		let version = client
			.versions
			.iter()
			.find(|v| VERSIONS.contains(v))
			.copied()
			.ok_or_else(|| Error::Version(client.versions.clone(), VERSIONS.into()))?;

		// Only encode parameters if we're using the IETF draft because it has max_request_id
		let parameters = if ietf::Version::try_from(version).is_ok() && client.kind == setup::ClientKind::Ietf14 {
			let mut parameters = ietf::Parameters::default();
			parameters.set_varint(ietf::ParameterVarInt::MaxRequestId, u32::MAX as u64);
			parameters.set_bytes(ietf::ParameterBytes::Implementation, b"moq-lite-rs".to_vec());
			parameters.encode_bytes(())
		} else {
			lite::Parameters::default().encode_bytes(())
		};

		let mut server = setup::Server { version, parameters };
		tracing::trace!(?server, "sending server setup");

		let mut stream = stream.with_version(client.kind.reply());
		stream.writer.encode(&server).await?;

		if let Ok(version) = lite::Version::try_from(version) {
			let stream = stream.with_version(version);
			lite::start(session.clone(), stream, publish.into(), subscribe.into(), version).await?;
		} else if let Ok(version) = ietf::Version::try_from(version) {
			// Decode the parameters to get the initial request ID.
			let parameters = ietf::Parameters::decode(&mut server.parameters, version)?;
			let request_id_max =
				ietf::RequestId(parameters.get_varint(ietf::ParameterVarInt::MaxRequestId).unwrap_or(0));

			let stream = stream.with_version(version);
			ietf::start(
				session.clone(),
				stream,
				request_id_max,
				false,
				publish.into(),
				subscribe.into(),
				version,
			)
			.await?;
		} else {
			// unreachable, but just in case
			return Err(Error::Version(client.versions, VERSIONS.into()));
		}

		tracing::debug!(?version, "connected");

		Ok(Self::new(session))
	}

	/// Close the underlying transport session.
	pub fn close(self, err: Error) {
		self.session.close(err.to_code(), err.to_string().as_ref());
	}

	/// Block until the transport session is closed.
	// TODO Remove the Result the next time we make a breaking change.
	pub async fn closed(&self) -> Result<(), Error> {
		let err = self.session.closed().await;
		Err(Error::Transport(err))
	}

	/// Accept a connection and parse CLIENT_SETUP, but don't complete handshake yet.
	///
	/// This allows inspecting SETUP parameters (e.g., AuthorizationToken) before
	/// deciding to accept or reject the session.
	///
	/// Use [`PendingSession::accept`] to complete the handshake or
	/// [`PendingSession::reject`] to terminate with an error.
	pub async fn accept_setup<S: web_transport_trait::Session>(session: S) -> Result<PendingSession<S>, Error> {
		// Accept with an initial version; we'll switch to the negotiated version later
		let stream = Stream::accept(&session, ()).await?;
		let mut stream = stream;
		let client: setup::Client = stream.reader.decode().await?;
		tracing::trace!(?client, "received client setup");

		// Choose the version to use
		let version = client
			.versions
			.iter()
			.find(|v| VERSIONS.contains(v))
			.copied()
			.ok_or_else(|| Error::Version(client.versions.clone(), VERSIONS.into()))?;

		Ok(PendingSession {
			session,
			stream,
			client,
			version,
		})
	}
}

/// A pending session after CLIENT_SETUP has been received but before SERVER_SETUP is sent.
///
/// This allows inspecting SETUP parameters before completing the handshake.
pub struct PendingSession<S: web_transport_trait::Session> {
	session: S,
	stream: Stream<S, ()>,
	client: setup::Client,
	version: coding::Version,
}

impl<S: web_transport_trait::Session> PendingSession<S> {
	/// Get the negotiated protocol version.
	pub fn version(&self) -> coding::Version {
		self.version
	}

	/// Get the raw CLIENT_SETUP parameters as bytes.
	///
	/// These can be decoded using [`ietf::Parameters`] or [`lite::Parameters`]
	/// depending on the negotiated version.
	pub fn parameters(&self) -> &Bytes {
		&self.client.parameters
	}

	/// Get the AuthorizationToken from SETUP parameters, if present.
	///
	/// This is a convenience method for Privacy Pass authentication.
	pub fn authorization_token(&self) -> Option<Bytes> {
		// Try to decode as IETF parameters first (more common)
		if let Ok(params) = ietf::Parameters::decode(&mut self.client.parameters.clone(), ()) {
			if let Some(token) = params.get_bytes(ietf::ParameterBytes::AuthorizationToken) {
				return Some(Bytes::copy_from_slice(token));
			}
		}
		None
	}

	/// Complete the handshake and accept the session.
	pub async fn accept(
		self,
		publish: impl Into<Option<OriginConsumer>>,
		subscribe: impl Into<Option<OriginProducer>>,
	) -> Result<Session, Error> {
		// Only encode parameters if we're using the IETF draft because it has max_request_id
		let parameters =
			if ietf::Version::try_from(self.version).is_ok() && self.client.kind == setup::ClientKind::Ietf14 {
				let mut parameters = ietf::Parameters::default();
				parameters.set_varint(ietf::ParameterVarInt::MaxRequestId, u32::MAX as u64);
				parameters.set_bytes(ietf::ParameterBytes::Implementation, b"moq-lite-rs".to_vec());
				parameters.encode_bytes(())
			} else {
				lite::Parameters::default().encode_bytes(())
			};

		let mut server = setup::Server {
			version: self.version,
			parameters,
		};
		tracing::trace!(?server, "sending server setup");

		let mut stream = self.stream.with_version(self.client.kind.reply());
		stream.writer.encode(&server).await?;

		if let Ok(version) = lite::Version::try_from(self.version) {
			let stream = stream.with_version(version);
			lite::start(self.session.clone(), stream, publish.into(), subscribe.into(), version).await?;
		} else if let Ok(version) = ietf::Version::try_from(self.version) {
			// Decode the parameters to get the initial request ID.
			let parameters = ietf::Parameters::decode(&mut server.parameters, version)?;
			let request_id_max =
				ietf::RequestId(parameters.get_varint(ietf::ParameterVarInt::MaxRequestId).unwrap_or(0));

			let stream = stream.with_version(version);
			ietf::start(
				self.session.clone(),
				stream,
				request_id_max,
				false,
				publish.into(),
				subscribe.into(),
				version,
			)
			.await?;
		} else {
			// unreachable, but just in case
			return Err(Error::Version(self.client.versions, VERSIONS.into()));
		}

		tracing::debug!(version = ?self.version, "connected");

		Ok(Session::new(self.session))
	}

	/// Reject the session with an error code.
	///
	/// Common codes:
	/// - `0x2` (Unauthorized): Authentication required or failed
	pub fn reject(self, code: u32, reason: &str) {
		self.session.close(code, reason);
	}
}

// We use a wrapper type that is dyn-compatible to remove the generic bounds from Session.
trait SessionInner: Send + Sync {
	fn close(&self, code: u32, reason: &str);
	fn closed(&self) -> Pin<Box<dyn Future<Output = Arc<dyn crate::error::SendSyncError>> + Send + '_>>;
}

impl<S: web_transport_trait::Session> SessionInner for S {
	fn close(&self, code: u32, reason: &str) {
		S::close(self, code, reason);
	}

	fn closed(&self) -> Pin<Box<dyn Future<Output = Arc<dyn crate::error::SendSyncError>> + Send + '_>> {
		Box::pin(async move { Arc::new(S::closed(self).await) as Arc<dyn crate::error::SendSyncError> })
	}
}
