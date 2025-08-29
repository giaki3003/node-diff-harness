//! Protocol message adapter for the Rust implementation
//!
//! This module handles protocol message creation, parsing, and validation
//! using the rs_node protocol implementation.

use ama_core::consensus::entry::EntryHeader;
use ama_core::consensus::entry::EntrySummary;
use ama_core::node::protocol;
use anyhow::Result;
use proto::MessageType;
use sha2::{Digest, Sha256};
use crate::tx_adapter::TxAdapter;

// Protocol prefix constants for canonical digest creation
const PROTOCOL_PING: &[u8] = b"ping";
const PROTOCOL_TXPOOL: &[u8] = b"txpool";
const PROTOCOL_PEERS: &[u8] = b"peers";

/// Adapter for protocol message operations
pub struct ProtocolAdapter {
    // State for consistent mock data generation
    mock_signer: [u8; 48],
    // Protected transaction validator
    tx_adapter: TxAdapter,
}

impl ProtocolAdapter {
    pub fn new() -> Result<Self> {
        // Use a fixed mock signer for deterministic results
        let mock_signer = [0x42u8; 48];
        let tx_adapter = TxAdapter::new()?;

        Ok(Self { mock_signer, tx_adapter })
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

    /// Test message deserialization
    pub fn test_serialization(&mut self, msg_type: &MessageType, payload: &[u8]) -> Result<bool> {
        // Test deserialization success based on message type
        match msg_type {
            MessageType::Ping => {
                match protocol::from_etf_bin(payload) {
                    Ok(msg) => Ok(msg.typename() == "ping"),
                    Err(_) => Ok(false),
                }
            }
            MessageType::Pong => {
                match protocol::from_etf_bin(payload) {
                    Ok(msg) => Ok(msg.typename() == "pong"),
                    Err(_) => Ok(false),
                }
            }
            MessageType::TxPool => {
                match protocol::from_etf_bin(payload) {
                    Ok(msg) => Ok(msg.typename() == "txpool"),
                    Err(_) => Ok(false),
                }
            }
            // TODO: Re-enable PeersV2 once Rust implementation supports peers_v2 operations
            MessageType::PeersV2 => {
                // For now, always return false since Rust doesn't support PeersV2 yet
                Ok(false)
            }
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
        // Build the exact byte sequence we hash to make debugging easy
        let mut bytes = Vec::with_capacity(4 + 8 * 5);
        bytes.extend_from_slice(PROTOCOL_PING);
        bytes.extend_from_slice(&rooted_height.to_le_bytes());
        bytes.extend_from_slice(&rooted_slot.to_le_bytes());
        bytes.extend_from_slice(&temporal_height.to_le_bytes());
        bytes.extend_from_slice(&temporal_slot.to_le_bytes());
        bytes.extend_from_slice(&timestamp_ms.to_le_bytes());

        // Optional debugging: print the exact bytes and digest when FUZZ_DEBUG=1
        let debug_enabled = std::env::var("FUZZ_DEBUG")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if debug_enabled {
            eprintln!(
                "[RUST] Ping hash input hex: {}",
                hex::encode(&bytes)
            );
        }

        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize().to_vec();

        if debug_enabled {
            eprintln!(
                "[RUST] Ping digest hex: {}",
                hex::encode(&digest)
            );
        }

        Ok(digest)
    }

    /// Create canonical digest for TxPool message with prevalidation filter
    fn create_txpool_canonical_digest(&mut self, txs: &[Vec<u8>]) -> Result<Vec<u8>> {
        // Create canonical representation: ("txpool", sorted_valid_txs)
        let mut hasher = Sha256::new();
        hasher.update(PROTOCOL_TXPOOL);

        // Filter only transactions that pass protected tx validation
        let mut valid_txs: Vec<Vec<u8>> = Vec::with_capacity(txs.len());
        for tx_bytes in txs {
            // Use protected transaction validation that guards against malicious varints
            match self.tx_adapter.validate_transaction(tx_bytes, false) {
                Ok(1) => {
                    // Valid transaction (code 1 means success)
                    valid_txs.push(tx_bytes.clone());
                }
                Ok(_) | Err(_) => {
                    // Invalid transaction or error - skip it
                }
            }
        }

        // Sort valid transactions for deterministic ordering
        valid_txs.sort();

        // Hash each valid transaction in sorted order
        for tx in &valid_txs {
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

    #[test]
    fn test_txpool_excludes_invalid_zero() {
        let mut adapter = ProtocolAdapter::new().unwrap();

        // A clearly invalid tx (all zeros) should be filtered out
        let zero_tx = vec![0u8; 64];
        let digest = adapter.handle_txpool(&[zero_tx]).unwrap();

        // Expected digest is SHA256 over just the "txpool" prefix, since no valid tx remains
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"txpool");
        let expected = hasher.finalize().to_vec();

        assert_eq!(digest, expected);
    }

    #[test]
    fn test_debug_ping_bytes() {
        let mut adapter = ProtocolAdapter::new().unwrap();
        
        // Test the exact failing case from fuzzer
        let temporal_height = 1u64;
        let temporal_slot = 1u64;
        let rooted_height = 1u64;
        let rooted_slot = 1u64;
        let timestamp_ms = 1600000000000u64;
        
        // Manually build what should be hashed
        let mut debug_bytes = Vec::new();
        debug_bytes.extend_from_slice(PROTOCOL_PING);
        debug_bytes.extend_from_slice(&rooted_height.to_le_bytes());
        debug_bytes.extend_from_slice(&rooted_slot.to_le_bytes());
        debug_bytes.extend_from_slice(&temporal_height.to_le_bytes());
        debug_bytes.extend_from_slice(&temporal_slot.to_le_bytes());
        debug_bytes.extend_from_slice(&timestamp_ms.to_le_bytes());
        
        println!("Debug: Rust ping hash input bytes: {:?}", debug_bytes);
        println!("Debug: Rust ping hash input hex: {}", hex::encode(&debug_bytes));
        
        // Compute expected hash manually
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&debug_bytes);
        let expected_digest = hasher.finalize().to_vec();
        println!("Debug: Expected Rust digest: {}", hex::encode(&expected_digest));
        
        // Test actual function
        let result = adapter.handle_ping(temporal_height, temporal_slot, rooted_height, rooted_slot, timestamp_ms).unwrap();
        println!("Debug: Actual Rust digest: {}", hex::encode(&result));
        
        assert_eq!(result, expected_digest);
    }

    #[test]
    fn test_debug_trace_digest() {
        let mut adapter = ProtocolAdapter::new().unwrap();
        
        // Test the exact failing case from fuzzer
        let temporal_height = 1u64;
        let temporal_slot = 1u64;
        let rooted_height = 1u64;
        let rooted_slot = 1u64;
        let timestamp_ms = 1600000000000u64;
        
        // Get the ping digest
        let ping_digest = adapter.handle_ping(temporal_height, temporal_slot, rooted_height, rooted_slot, timestamp_ms).unwrap();
        println!("Debug: Ping digest: {}", hex::encode(&ping_digest));
        
        // Now compute the overall trace digest as the trace execution would
        let messages_count = 1u32;
        let mut trace_digest_bytes = Vec::new();
        trace_digest_bytes.extend_from_slice(b"protocol:");
        trace_digest_bytes.extend_from_slice(&messages_count.to_le_bytes());
        trace_digest_bytes.extend_from_slice(&ping_digest);
        
        println!("Debug: Trace digest input bytes: {:?}", trace_digest_bytes);
        println!("Debug: Trace digest input hex: {}", hex::encode(&trace_digest_bytes));
        
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&trace_digest_bytes);
        let trace_digest = hasher.finalize().to_vec();
        println!("Debug: Final trace digest: {}", hex::encode(&trace_digest));
        
        // This should match what the replay tool produces
        let expected_replay_digest = hex::decode("ced85bc10b1fb74b0ea7df00ae9effda1daeba1c45eff568e7787463a09b4da1").unwrap();
        assert_eq!(trace_digest, expected_replay_digest);
    }
}
