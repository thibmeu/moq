//! Nonce storage for replay protection.
//!
//! Privacy Pass tokens include a unique nonce that must only be used once.
//! The NonceStore trait provides an interface for tracking used nonces.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

/// Nonce type (32 bytes).
pub type Nonce = [u8; 32];

/// Interface for nonce storage to prevent token replay.
///
/// Implementations must be thread-safe and should persist nonces
/// for at least the token validity period.
#[async_trait]
pub trait NonceStore: Send + Sync {
	/// Check if a nonce has been used.
	async fn exists(&self, nonce: &Nonce) -> bool;

	/// Record a nonce as used.
	///
	/// Returns true if the nonce was newly inserted, false if it already existed.
	async fn insert(&self, nonce: Nonce) -> bool;

	/// Check and insert atomically.
	///
	/// Returns true if the nonce was newly inserted, false if it already existed.
	async fn check_and_insert(&self, nonce: Nonce) -> bool {
		if self.exists(&nonce).await {
			false
		} else {
			self.insert(nonce).await
		}
	}
}

/// In-memory nonce store.
///
/// Simple implementation suitable for single-node deployments.
/// For distributed deployments, use a Redis-backed implementation.
#[derive(Debug, Default)]
pub struct InMemoryNonceStore {
	nonces: Arc<RwLock<HashSet<Nonce>>>,
}

impl InMemoryNonceStore {
	/// Create a new empty nonce store.
	pub fn new() -> Self {
		Self::default()
	}

	/// Get the number of stored nonces.
	pub async fn len(&self) -> usize {
		self.nonces.read().await.len()
	}

	/// Check if the store is empty.
	pub async fn is_empty(&self) -> bool {
		self.nonces.read().await.is_empty()
	}

	/// Clear all stored nonces.
	pub async fn clear(&self) {
		self.nonces.write().await.clear();
	}
}

#[async_trait]
impl NonceStore for InMemoryNonceStore {
	async fn exists(&self, nonce: &Nonce) -> bool {
		self.nonces.read().await.contains(nonce)
	}

	async fn insert(&self, nonce: Nonce) -> bool {
		self.nonces.write().await.insert(nonce)
	}

	async fn check_and_insert(&self, nonce: Nonce) -> bool {
		// Atomic check-and-insert with write lock
		self.nonces.write().await.insert(nonce)
	}
}

// Also implement the privacypass crate's NonceStore trait
#[async_trait]
impl privacypass::NonceStore for InMemoryNonceStore {
	async fn exists(&self, nonce: &Nonce) -> bool {
		self.nonces.read().await.contains(nonce)
	}

	async fn insert(&self, nonce: Nonce) {
		self.nonces.write().await.insert(nonce);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn test_insert_and_exists() {
		let store = InMemoryNonceStore::new();
		let nonce = [0x42u8; 32];

		assert!(!store.exists(&nonce).await);
		assert!(store.insert(nonce).await);
		assert!(store.exists(&nonce).await);
		assert!(!store.insert(nonce).await); // Already exists
	}

	#[tokio::test]
	async fn test_check_and_insert() {
		let store = InMemoryNonceStore::new();
		let nonce = [0x42u8; 32];

		assert!(store.check_and_insert(nonce).await);
		assert!(!store.check_and_insert(nonce).await);
	}

	#[tokio::test]
	async fn test_multiple_nonces() {
		let store = InMemoryNonceStore::new();

		for i in 0..10u8 {
			let nonce = [i; 32];
			assert!(store.insert(nonce).await);
		}

		assert_eq!(store.len().await, 10);

		for i in 0..10u8 {
			let nonce = [i; 32];
			assert!(store.exists(&nonce).await);
		}
	}

	#[tokio::test]
	async fn test_clear() {
		let store = InMemoryNonceStore::new();
		let nonce = [0x42u8; 32];

		store.insert(nonce).await;
		assert!(!store.is_empty().await);

		store.clear().await;
		assert!(store.is_empty().await);
		assert!(!store.exists(&nonce).await);
	}
}
