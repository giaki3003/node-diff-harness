//! Trace format for differential fuzzing between Elixir and Rust implementations
//!
//! This module defines the binary trace format used by the fuzzer to generate
//! reproducible test cases that can be executed on both implementations.

use arbitrary::{Arbitrary, Result, Unstructured};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// Maximum size limits to prevent resource exhaustion during fuzzing
// Realistic limits for internal data structures (not operation count)
const MAX_TXS: usize = 50;         // Maximum transactions per TxPool message
const MAX_IPS: usize = 100;        // Maximum ANRs per PeersV2 message  
const MAX_TX_SIZE: usize = 10_000; // Maximum transaction size in bytes

/// A complete trace containing a sequence of operations to test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    /// Random seed for deterministic execution
    pub seed: u64,
    /// Sequence of operations to execute
    pub ops: Vec<Operation>,
}

/// Individual operations that can be tested
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    /// Test ping message creation and parsing
    Ping {
        /// Mock temporal summary data (simplified for fuzzing)
        temporal_height: u64,
        temporal_slot: u64,
        /// Mock rooted summary data  
        rooted_height: u64,
        rooted_slot: u64,
        /// Timestamp override (0 = use current time)
        timestamp_ms: u64,
    },

    /// Test transaction pool message handling
    TxPool {
        /// List of raw transaction binaries to include
        txs: Vec<Vec<u8>>,
    },

    /// Test legacy peer list message handling (Rust implementation only)
    /// TODO: DEPRECATED - Remove this once both implementations standardize on PeersV2
    Peers {
        /// List of IP addresses as strings
        ips: Vec<String>,
    },

    /// Test modern peer list message handling (Elixir implementation)  
    /// TODO: Rust implementation needs PeersV2 support for complete differential testing
    PeersV2 {
        /// List of ANR (Address Name Records) for peers
        /// For now, we'll use simplified format until Rust implements PeersV2
        anrs: Vec<String>, // Simplified - real format would be more complex
    },

    /// Test individual transaction validation
    ProcessTx {
        /// Raw transaction binary to validate
        tx_data: Vec<u8>,
        /// Whether this is for a special meeting block
        is_special_meeting: bool,
    },

    /// Test protocol message round-trip serialization
    SerializeMessage {
        /// Type of message to serialize/deserialize
        msg_type: MessageType,
        /// Raw payload data for the message
        payload: Vec<u8>,
    },
}

/// Types of protocol messages for serialization testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Ping,
    Pong,
    TxPool,
    PeersV2, // Use modern PeersV2 instead of deprecated Peers
}

impl Arbitrary<'_> for Trace {
    fn arbitrary(u: &mut Unstructured<'_>) -> Result<Self> {
        let seed = u.arbitrary::<u64>()?;

        // CONSTRAINT: Single operation per trace to match real UDP network behavior
        // Real networks: 1 UDP packet = 1 protocol message = 1 operation
        // Complexity comes from internal data structures (multiple txs, multiple ANRs, etc.)
        let operation = Operation::arbitrary(u)?;
        
        Ok(Trace { seed, ops: vec![operation] })
    }
}

impl Arbitrary<'_> for Operation {
    fn arbitrary(u: &mut Unstructured<'_>) -> Result<Self> {
        match u.int_in_range(0..=3)? {
            0 => Ok(Operation::Ping {
                // Realistic chain heights (avoid zero which can crash oracle)
                temporal_height: u.int_in_range(1..=1_000_000)?,
                temporal_slot: u.int_in_range(1..=10_000)?,
                rooted_height: u.int_in_range(1..=1_000_000)?,
                rooted_slot: u.int_in_range(1..=10_000)?,
                // Realistic Unix timestamps (2020-2030 range)
                timestamp_ms: u.int_in_range(1_600_000_000_000..=1_900_000_000_000)?,
            }),

            1 => {
                // TxPool: Realistic batching (1-50 transactions per UDP message)
                let num_txs = u.int_in_range(1..=MAX_TXS)?;
                let mut txs = Vec::with_capacity(num_txs);
                for _ in 0..num_txs {
                    // Realistic transaction sizes (32 bytes minimum for basic tx)
                    let tx_size = u.int_in_range(32..=MAX_TX_SIZE)?;
                    let tx_data: Vec<u8> = (0..tx_size)
                        .map(|_| u.arbitrary())
                        .collect::<Result<Vec<_>>>()?;
                    txs.push(tx_data);
                }
                Ok(Operation::TxPool { txs })
            }

            // TODO: Re-enable PeersV2 once Rust implementation supports peers_v2 operations
            // 2 => {
            //     // PeersV2: Modern peer discovery (1-100 ANRs per UDP message)
            //     let num_anrs = u.int_in_range(1..=MAX_IPS)?; // Reuse MAX_IPS for ANR limit
            //     let mut anrs = Vec::with_capacity(num_anrs);
            //     for _ in 0..num_anrs {
            //         // Generate realistic ANR strings (simplified format for now)
            //         let anr = format!(
            //             "anr://{}:{}/{}",
            //             u.int_in_range(1..=255)?,
            //             u.int_in_range(1024..=65535)?, // Realistic port range
            //             u.int_in_range(1000..=9999)?   // Node ID
            //         );
            //         anrs.push(anr);
            //     }
            //     Ok(Operation::PeersV2 { anrs })
            // }

            2 => {
                // ProcessTx: Single transaction processing
                let tx_size = u.int_in_range(32..=MAX_TX_SIZE)?; // Minimum 32 bytes
                let tx_data: Vec<u8> = (0..tx_size)
                    .map(|_| u.arbitrary())
                    .collect::<Result<Vec<_>>>()?;
                Ok(Operation::ProcessTx {
                    tx_data,
                    is_special_meeting: u.arbitrary()?,
                })
            }

            3 => {
                // SerializeMessage: Single message serialization test
                let msg_type = u.arbitrary::<MessageType>()?;
                let payload_size = u.int_in_range(0..=1000)?;
                let payload: Vec<u8> = (0..payload_size)
                    .map(|_| u.arbitrary())
                    .collect::<Result<Vec<_>>>()?;
                Ok(Operation::SerializeMessage { msg_type, payload })
            }

            _ => unreachable!(),
        }
    }
}


impl Arbitrary<'_> for MessageType {
    fn arbitrary(u: &mut Unstructured<'_>) -> Result<Self> {
        match u.int_in_range(0..=2)? {
            0 => Ok(MessageType::Ping),
            1 => Ok(MessageType::Pong),
            2 => Ok(MessageType::TxPool),
            // TODO: Re-enable PeersV2 once Rust implementation supports peers_v2
            // 3 => Ok(MessageType::PeersV2),
            _ => unreachable!(),
        }
    }
}

impl Trace {
    /// Serialize trace to binary format for storage/transmission
    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Deserialize trace from binary format  
    pub fn from_bytes(data: &[u8]) -> io::Result<Self> {
        bincode::deserialize(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Write trace to a writer in binary format
    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let data = self.to_bytes()?;
        writer.write_all(&data)?;
        Ok(())
    }

    /// Read trace from a reader in binary format
    pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Self::from_bytes(&data)
    }

    /// Create a simple trace with a single operation for testing
    pub fn single_op(seed: u64, op: Operation) -> Self {
        Self {
            seed,
            ops: vec![op],
        }
    }

    /// Create a trace that tests basic protocol operations
    pub fn basic_protocol_test() -> Self {
        Self {
            seed: 12345,
            ops: vec![
                Operation::Ping {
                    temporal_height: 100,
                    temporal_slot: 50,
                    rooted_height: 90,
                    rooted_slot: 45,
                    timestamp_ms: 1700000000000, // Fixed timestamp
                },
                Operation::TxPool {
                    txs: vec![b"simple_tx_1".to_vec(), b"simple_tx_2".to_vec()],
                },
                Operation::Peers {
                    ips: vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()],
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_serialization() {
        let trace = Trace::basic_protocol_test();
        let bytes = trace.to_bytes().expect("should serialize");
        let deserialized = Trace::from_bytes(&bytes).expect("should deserialize");

        assert_eq!(trace.seed, deserialized.seed);
        assert_eq!(trace.ops.len(), deserialized.ops.len());
    }

    #[test]
    fn test_arbitrary_trace_generation() {
        use arbitrary::Unstructured;

        let data = [0u8; 1000];
        let mut u = Unstructured::new(&data);
        let trace = Trace::arbitrary(&mut u).expect("should generate trace");

        assert!(!trace.ops.is_empty());
        assert!(trace.ops.len() <= MAX_OPS);
    }

    #[test]
    fn test_operation_limits() {
        use arbitrary::Unstructured;

        let data = [0xffu8; 10000]; // Use 0xff to trigger max values
        let mut u = Unstructured::new(&data);

        for _ in 0..100 {
            if let Ok(op) = Operation::arbitrary(&mut u) {
                match op {
                    Operation::TxPool { txs } => {
                        assert!(txs.len() <= MAX_TXS);
                        for tx in txs {
                            assert!(tx.len() <= MAX_TX_SIZE);
                        }
                    }
                    Operation::Peers { ips } => {
                        assert!(ips.len() <= MAX_IPS);
                    }
                    Operation::ProcessTx { tx_data, .. } => {
                        assert!(tx_data.len() <= MAX_TX_SIZE);
                    }
                    _ => {} // Other operations don't have collection limits
                }
            }
        }
    }
}
