//! MoQ authorization scope.
//!
//! Encodes operation type, namespace pattern, and optional track pattern
//! as specified in draft-ietf-moq-privacy-pass-auth-01.
//!
//! Format: `operation:namespace-pattern[:track-pattern]`
//!
//! Examples:
//! - `subscribe:sports.example.com/live/*`
//! - `publish:meetings.example.com/meeting/m123/audio/opus48000`
//! - `fetch:vod.example.com/movies/action*`

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::Error;

/// MoQ operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
	/// Subscribe to tracks.
	Subscribe,
	/// Fetch content.
	Fetch,
	/// Publish content.
	Publish,
	/// Announce broadcasts.
	Announce,
}

impl fmt::Display for Operation {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Subscribe => write!(f, "subscribe"),
			Self::Fetch => write!(f, "fetch"),
			Self::Publish => write!(f, "publish"),
			Self::Announce => write!(f, "announce"),
		}
	}
}

impl std::str::FromStr for Operation {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"subscribe" => Ok(Self::Subscribe),
			"fetch" => Ok(Self::Fetch),
			"publish" => Ok(Self::Publish),
			"announce" => Ok(Self::Announce),
			_ => Err(Error::InvalidScope(format!("unknown operation: {s}"))),
		}
	}
}

/// Pattern for matching namespaces or track names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Pattern {
	/// Exact match required.
	Exact(String),
	/// Prefix match (pattern ends with `*`).
	Prefix(String),
}

impl Pattern {
	/// Parse a pattern string.
	pub fn parse(s: &str) -> Self {
		if let Some(prefix) = s.strip_suffix('*') {
			Self::Prefix(prefix.to_string())
		} else {
			Self::Exact(s.to_string())
		}
	}

	/// Check if the pattern matches the given value.
	pub fn matches(&self, value: &str) -> bool {
		match self {
			Self::Exact(expected) => value == expected,
			Self::Prefix(prefix) => value.starts_with(prefix),
		}
	}
}

impl fmt::Display for Pattern {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Exact(s) => write!(f, "{s}"),
			Self::Prefix(s) => write!(f, "{s}*"),
		}
	}
}

/// MoQ authorization scope.
///
/// Specifies what operation is authorized on which namespace/track.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
	/// The operation being authorized.
	pub operation: Operation,
	/// Namespace pattern (exact or prefix match).
	pub namespace: Pattern,
	/// Optional track name pattern.
	pub track: Option<Pattern>,
}

impl Scope {
	/// Create a new scope.
	pub fn new(operation: Operation, namespace: Pattern, track: Option<Pattern>) -> Self {
		Self {
			operation,
			namespace,
			track,
		}
	}

	/// Create scope for subscribing to a namespace prefix.
	pub fn subscribe_prefix(namespace: &str) -> Self {
		Self::new(Operation::Subscribe, Pattern::Prefix(namespace.to_string()), None)
	}

	/// Create scope for publishing to a namespace prefix.
	pub fn publish_prefix(namespace: &str) -> Self {
		Self::new(Operation::Publish, Pattern::Prefix(namespace.to_string()), None)
	}

	/// Create scope for exact namespace match.
	pub fn exact(operation: Operation, namespace: &str) -> Self {
		Self::new(operation, Pattern::Exact(namespace.to_string()), None)
	}

	/// Parse from origin_info string format.
	///
	/// Format: `operation:namespace[:track]`
	pub fn parse(s: &str) -> crate::Result<Self> {
		let mut parts = s.splitn(3, ':');

		let operation = parts
			.next()
			.ok_or_else(|| Error::InvalidScope("missing operation".to_string()))?
			.parse()?;

		let namespace = parts
			.next()
			.ok_or_else(|| Error::InvalidScope("missing namespace".to_string()))?;
		let namespace = Pattern::parse(namespace);

		let track = parts.next().map(Pattern::parse);

		Ok(Self {
			operation,
			namespace,
			track,
		})
	}

	/// Encode as origin_info string.
	pub fn to_origin_info(&self) -> String {
		match &self.track {
			Some(track) => format!("{}:{}:{}", self.operation, self.namespace, track),
			None => format!("{}:{}", self.operation, self.namespace),
		}
	}

	/// Check if this scope authorizes the given operation.
	pub fn matches(&self, operation: Operation, namespace: &str, track: Option<&str>) -> bool {
		if self.operation != operation {
			return false;
		}

		if !self.namespace.matches(namespace) {
			return false;
		}

		match (&self.track, track) {
			(Some(pattern), Some(name)) => pattern.matches(name),
			(Some(_), None) => false, // Scope requires track but none provided
			(None, _) => true,        // Scope doesn't restrict track
		}
	}
}

impl fmt::Display for Scope {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.to_origin_info())
	}
}

impl std::str::FromStr for Scope {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Self::parse(s)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_operation_parse() {
		assert_eq!("subscribe".parse::<Operation>().unwrap(), Operation::Subscribe);
		assert_eq!("PUBLISH".parse::<Operation>().unwrap(), Operation::Publish);
		assert_eq!("Fetch".parse::<Operation>().unwrap(), Operation::Fetch);
		assert_eq!("announce".parse::<Operation>().unwrap(), Operation::Announce);
		assert!("invalid".parse::<Operation>().is_err());
	}

	#[test]
	fn test_pattern_exact() {
		let p = Pattern::parse("foo/bar");
		assert!(p.matches("foo/bar"));
		assert!(!p.matches("foo/bar/baz"));
		assert!(!p.matches("foo"));
		assert_eq!(p.to_string(), "foo/bar");
	}

	#[test]
	fn test_pattern_prefix() {
		let p = Pattern::parse("foo/bar/*");
		assert!(p.matches("foo/bar/"));
		assert!(p.matches("foo/bar/baz"));
		assert!(p.matches("foo/bar/baz/qux"));
		assert!(!p.matches("foo/bar"));
		assert!(!p.matches("foo/barbaz"));
		assert_eq!(p.to_string(), "foo/bar/*");
	}

	#[test]
	fn test_scope_parse() {
		let s = Scope::parse("subscribe:sports.example.com/live/*").unwrap();
		assert_eq!(s.operation, Operation::Subscribe);
		assert_eq!(s.namespace, Pattern::Prefix("sports.example.com/live/".to_string()));
		assert!(s.track.is_none());

		let s = Scope::parse("publish:room/123:audio").unwrap();
		assert_eq!(s.operation, Operation::Publish);
		assert_eq!(s.namespace, Pattern::Exact("room/123".to_string()));
		assert_eq!(s.track, Some(Pattern::Exact("audio".to_string())));
	}

	#[test]
	fn test_scope_roundtrip() {
		let original = "subscribe:foo/bar/*:video*";
		let scope = Scope::parse(original).unwrap();
		assert_eq!(scope.to_origin_info(), original);
	}

	#[test]
	fn test_scope_matches() {
		let scope = Scope::parse("subscribe:room/*").unwrap();

		assert!(scope.matches(Operation::Subscribe, "room/123", None));
		assert!(scope.matches(Operation::Subscribe, "room/123", Some("video")));
		assert!(!scope.matches(Operation::Publish, "room/123", None));
		assert!(!scope.matches(Operation::Subscribe, "other/123", None));
	}

	#[test]
	fn test_scope_matches_track() {
		let scope = Scope::parse("subscribe:room/123:video*").unwrap();

		assert!(scope.matches(Operation::Subscribe, "room/123", Some("video")));
		assert!(scope.matches(Operation::Subscribe, "room/123", Some("video-high")));
		assert!(!scope.matches(Operation::Subscribe, "room/123", Some("audio")));
		assert!(!scope.matches(Operation::Subscribe, "room/123", None));
	}
}
