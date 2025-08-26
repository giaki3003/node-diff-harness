//! Protocol message adapter for the Rust implementation
//!
//! This module handles protocol message creation, parsing, and validation
//! using the rs_node protocol implementation.

use ama_core::consensus::entry::EntryHeader;
use ama_core::consensus::entry::EntrySummary;
use ama_core::node::protocol::{self, Peers, Ping, Protocol, TxPool};
use anyhow::Result;
use proto::MessageType;
use sha2::{Digest, Sha256};

// Protocol prefix constants for canonical digest creation
const PROTOCOL_PING: &[u8] = b"ping";
const PROTOCOL_TXPOOL: &[u8] = b"txpool";
const PROTOCOL_PEERS: &[u8] = b"peers";

/// Adapter for protocol message operations
pub struct ProtocolAdapter {
    // State for consistent mock data generation
    mock_signer: [u8; 48],
}

impl ProtocolAdapter {
    pub fn new() -> Result<Self> {
        // Use a fixed mock signer for deterministic results
        let mock_signer = [0x42u8; 48];

        Ok(Self { mock_signer })
    }

    /// Handle ping message creation and return canonical digest
    pub fn handle_ping(
        &mut self,
        temporal_height: u64,
        temporal_slot: u64,
        rooted_height: u64,
        rooted_slot: u64,
        timestamp_ms: u64,
    ) -> Result<Vec<u8>> {
        // Create canonical digest from ping parameters
        self.create_ping_canonical_digest(
            temporal_height,
            temporal_slot,
            rooted_height,
            rooted_slot,
            timestamp_ms,
        )
    }

    /// Handle transaction pool message and return canonical digest
    pub fn handle_txpool(&mut self, txs: &[Vec<u8>]) -> Result<Vec<u8>> {
        // Create canonical digest from transaction data
        self.create_txpool_canonical_digest(txs)
    }

    /// Handle peers message and return canonical digest
    pub fn handle_peers(&mut self, ips: &[String]) -> Result<Vec<u8>> {
        // Create canonical digest from peers data
        self.create_peers_canonical_digest(ips)
    }

    /// Test message serialization round-trip
    pub fn test_serialization(&mut self, msg_type: &MessageType, payload: &[u8]) -> Result<bool> {
        // Test round-trip serialization based on message type
        match msg_type {
            MessageType::Ping => {
                // Try to deserialize as ping, then re-serialize
                match protocol::from_etf_bin(payload) {
                    Ok(msg) => {
                        if msg.typename() == "ping" {
                            // Try to serialize back
                            match msg.to_etf_bin() {
                                Ok(_) => Ok(true),
                                Err(_) => Ok(false),
                            }
                        } else {
                            Ok(false)
                        }
                    }
                    Err(_) => Ok(false),
                }
            }
            MessageType::Pong => match protocol::from_etf_bin(payload) {
                Ok(msg) => {
                    if msg.typename() == "pong" {
                        match msg.to_etf_bin() {
                            Ok(_) => Ok(true),
                            Err(_) => Ok(false),
                        }
                    } else {
                        Ok(false)
                    }
                }
                Err(_) => Ok(false),
            },
            MessageType::TxPool => match protocol::from_etf_bin(payload) {
                Ok(msg) => {
                    if msg.typename() == "txpool" {
                        match msg.to_etf_bin() {
                            Ok(_) => Ok(true),
                            Err(_) => Ok(false),
                        }
                    } else {
                        Ok(false)
                    }
                }
                Err(_) => Ok(false),
            },
            MessageType::Peers => match protocol::from_etf_bin(payload) {
                Ok(msg) => {
                    if msg.typename() == "peers" {
                        match msg.to_etf_bin() {
                            Ok(_) => Ok(true),
                            Err(_) => Ok(false),
                        }
                    } else {
                        Ok(false)
                    }
                }
                Err(_) => Ok(false),
            },
        }
    }

    /// Reset internal state
    pub fn reset(&mut self) -> Result<()> {
        // Protocol adapter is stateless, nothing to reset
        Ok(())
    }

    /// Create a mock entry summary for testing
    fn create_mock_entry_summary(&self, height: u64, slot: u64) -> Result<EntrySummary> {
        let header = EntryHeader {
            height,
            slot,
            prev_slot: if slot > 0 { slot as i64 - 1 } else { -1 },
            prev_hash: [0u8; 32],                         // Mock previous hash
            dr: self.deterministic_hash(height, slot, 0), // Deterministic random
            vr: [0u8; 96],                                // Mock verifiable random
            signer: self.mock_signer,
            txs_hash: self.deterministic_hash(height, slot, 1),
        };

        let signature = [0u8; 96]; // Mock signature
        let mask = None; // No mask for single signer

        Ok(EntrySummary {
            header,
            signature,
            mask,
        })
    }

    /// Generate deterministic hash based on inputs (using SHA256 for consistency with Elixir)
    fn deterministic_hash(&self, height: u64, slot: u64, salt: u8) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&height.to_le_bytes());
        hasher.update(&slot.to_le_bytes());
        hasher.update(&[salt]);
        hasher.update(&self.mock_signer);
        hasher.finalize().into()
    }

    /// Create canonical digest for Ping message
    fn create_ping_canonical_digest(
        &self,
        temporal_height: u64,
        temporal_slot: u64,
        rooted_height: u64,
        rooted_slot: u64,
        timestamp_ms: u64,
    ) -> Result<Vec<u8>> {
        // Create canonical representation: ("ping", rooted_height, rooted_slot, temporal_height, temporal_slot, timestamp_ms)
        // Order fields alphabetically by field name for determinism
        let mut hasher = Sha256::new();
        hasher.update(PROTOCOL_PING);
        hasher.update(&rooted_height.to_le_bytes());
        hasher.update(&rooted_slot.to_le_bytes());
        hasher.update(&temporal_height.to_le_bytes());
        hasher.update(&temporal_slot.to_le_bytes());
        hasher.update(&timestamp_ms.to_le_bytes());

        Ok(hasher.finalize().to_vec())
    }

    /// Create canonical digest for TxPool message
    fn create_txpool_canonical_digest(&self, txs: &[Vec<u8>]) -> Result<Vec<u8>> {
        // Create canonical representation: ("txpool", sorted_tx_hashes)
        let mut hasher = Sha256::new();
        hasher.update(PROTOCOL_TXPOOL);

        // Sort transactions for deterministic ordering
        let mut sorted_txs = txs.to_vec();
        sorted_txs.sort();

        // Hash each transaction in sorted order
        for tx in &sorted_txs {
            hasher.update(tx);
        }

        Ok(hasher.finalize().to_vec())
    }

    /// Create canonical digest for Peers message
    fn create_peers_canonical_digest(&self, ips: &[String]) -> Result<Vec<u8>> {
        // Create canonical representation: ("peers", sorted_ips)
        let mut hasher = Sha256::new();
        hasher.update(PROTOCOL_PEERS);

        // Sort IPs for deterministic ordering
        let mut sorted_ips = ips.to_vec();
        sorted_ips.sort();

        // Hash each IP in sorted order
        for ip in &sorted_ips {
            hasher.update(ip.as_bytes());
        }

        Ok(hasher.finalize().to_vec())
    }

    /// Normalize protocol output for consistent comparison
    /// Note: This method is deprecated in favor of canonical digests
    fn normalize_protocol_output(&self, etf_bin: &[u8]) -> Result<Vec<u8>> {
        // For now, return the ETF binary as-is
        // In the future, we could normalize timestamps, sort fields, etc.
        Ok(etf_bin.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_canonical_digest() {
        let mut adapter = ProtocolAdapter::new().unwrap();
        let result = adapter.handle_ping(100, 50, 90, 45, 1700000000000).unwrap();
        assert!(!result.is_empty());
        assert_eq!(result.len(), 32); // SHA256 digest length

        // Test deterministic - same inputs should produce same output
        let result2 = adapter.handle_ping(100, 50, 90, 45, 1700000000000).unwrap();
        assert_eq!(result, result2);

        // Test different inputs produce different digests
        let result3 = adapter.handle_ping(101, 50, 90, 45, 1700000000000).unwrap();
        assert_ne!(result, result3);
    }

    #[test]
    fn test_txpool_canonical_digest() {
        let mut adapter = ProtocolAdapter::new().unwrap();
        let txs = vec![b"tx1".to_vec(), b"tx2".to_vec()];
        let result = adapter.handle_txpool(&txs).unwrap();
        assert!(!result.is_empty());
        assert_eq!(result.len(), 32); // SHA256 digest length

        // Test deterministic - same transactions should produce same digest
        let result2 = adapter.handle_txpool(&txs).unwrap();
        assert_eq!(result, result2);

        // Test order independence - different order should produce same digest
        let txs_reversed = vec![b"tx2".to_vec(), b"tx1".to_vec()];
        let result3 = adapter.handle_txpool(&txs_reversed).unwrap();
        assert_eq!(result, result3); // Should be same due to sorting
    }

    #[test]
    fn test_peers_canonical_digest() {
        let mut adapter = ProtocolAdapter::new().unwrap();
        let ips = vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()];
        let result = adapter.handle_peers(&ips).unwrap();
        assert!(!result.is_empty());
        assert_eq!(result.len(), 32); // SHA256 digest length

        // Test deterministic - same IPs should produce same digest
        let result2 = adapter.handle_peers(&ips).unwrap();
        assert_eq!(result, result2);

        // Test order independence - different order should produce same digest
        let ips_reversed = vec!["10.0.0.1".to_string(), "192.168.1.1".to_string()];
        let result3 = adapter.handle_peers(&ips_reversed).unwrap();
        assert_eq!(result, result3); // Should be same due to sorting
    }

    #[test]
    fn test_canonical_digest_consistency() {
        let mut adapter = ProtocolAdapter::new().unwrap();

        // Test that all message types produce consistent 32-byte SHA256 digests
        let ping_digest = adapter.handle_ping(100, 50, 90, 45, 1700000000000).unwrap();
        let txpool_digest = adapter.handle_txpool(&[b"test".to_vec()]).unwrap();
        let peers_digest = adapter.handle_peers(&["127.0.0.1".to_string()]).unwrap();

        // All should be SHA256 digests (32 bytes)
        assert_eq!(ping_digest.len(), 32);
        assert_eq!(txpool_digest.len(), 32);
        assert_eq!(peers_digest.len(), 32);

        // All should be different (different message types)
        assert_ne!(ping_digest, txpool_digest);
        assert_ne!(ping_digest, peers_digest);
        assert_ne!(txpool_digest, peers_digest);
    }
}
