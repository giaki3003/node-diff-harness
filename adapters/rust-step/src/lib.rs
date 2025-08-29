//! Rust adapter for executing traces on the rs_node implementation
//!
//! This adapter provides a clean interface for running traces against the Rust
//! implementation of the Amadeus node, normalizing results for comparison with
//! the Elixir implementation.

use anyhow::Result;
use proto::{ExecutionMetrics, ExecutionResult, Operation, Trace, TraceExecutor, MessageType};
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use std::time::Instant;

pub mod normalizer;
pub mod protocol_adapter;
pub mod tx_adapter;

use normalizer::Normalizer;
use protocol_adapter::ProtocolAdapter;
use tx_adapter::TxAdapter;

/// Main executor for running traces on the Rust implementation
pub struct RustStepExecutor {
    protocol_adapter: ProtocolAdapter,
    tx_adapter: TxAdapter,
    normalizer: Normalizer,
    rng: rand_chacha::ChaCha8Rng,
}

impl RustStepExecutor {
    /// Create a new executor instance
    pub fn new() -> Result<Self> {
        Ok(Self {
            protocol_adapter: ProtocolAdapter::new()?,
            tx_adapter: TxAdapter::new()?,
            normalizer: Normalizer::new(),
            rng: rand_chacha::ChaCha8Rng::from_entropy(),
        })
    }

    /// Initialize with a specific seed for deterministic execution
    pub fn with_seed(seed: u64) -> Result<Self> {
        use rand::SeedableRng;

        Ok(Self {
            protocol_adapter: ProtocolAdapter::new()?,
            tx_adapter: TxAdapter::new()?,
            normalizer: Normalizer::new(),
            rng: rand_chacha::ChaCha8Rng::seed_from_u64(seed),
        })
    }

    /// Execute a single operation and return partial results
    fn execute_operation(&mut self, op: &Operation) -> Result<OperationResult> {
        match op {
            Operation::Ping {
                temporal_height,
                temporal_slot,
                rooted_height,
                rooted_slot,
                timestamp_ms,
            } => {
                let result = self.protocol_adapter.handle_ping(
                    *temporal_height,
                    *temporal_slot,
                    *rooted_height,
                    *rooted_slot,
                    *timestamp_ms,
                )?;
                Ok(OperationResult::Protocol {
                    data: result,
                    messages_count: 1,
                })
            }

            Operation::TxPool { txs } => {
                let result = self.protocol_adapter.handle_txpool(txs)?;
                Ok(OperationResult::Protocol {
                    data: result,
                    messages_count: 1,
                })
            }

            Operation::Peers { ips } => {
                let result = self.protocol_adapter.handle_peers(ips)?;
                Ok(OperationResult::Protocol {
                    data: result,
                    messages_count: 1,
                })
            }

            Operation::PeersV2 { anrs: _ } => {
                // TODO: PeersV2 protocol not implemented in rs_node
                Err(anyhow::anyhow!(
                    "PeersV2 not supported - protocol version mismatch"
                ))
            }

            Operation::ProcessTx {
                tx_data,
                is_special_meeting,
            } => {
                let result = self
                    .tx_adapter
                    .validate_transaction(tx_data, *is_special_meeting)?;
                Ok(OperationResult::Transaction {
                    validation_result: result,
                })
            }

            Operation::SerializeMessage { msg_type, payload } => {
                // Exclude empty Ping serialization from affecting the digest (mirror Elixir)
                if matches!(msg_type, MessageType::Ping) && payload.is_empty() {
                    Ok(OperationResult::Noop)
                } else {
                    let result = self
                        .protocol_adapter
                        .test_serialization(msg_type, payload)?;
                    Ok(OperationResult::Serialization { success: result })
                }
            }
        }
    }

    /// Compute normalized digest from operation results
    fn compute_digest(&self, results: &[OperationResult]) -> Vec<u8> {
        // Build the exact byte stream we will hash so we can debug it if needed
        let debug_enabled = std::env::var("FUZZ_DEBUG")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let mut input_bytes: Vec<u8> = Vec::new();

        for result in results {
            match result {
                OperationResult::Protocol {
                    data,
                    messages_count,
                } => {
                    input_bytes.extend_from_slice(b"protocol:");
                    input_bytes.extend_from_slice(&messages_count.to_le_bytes());
                    input_bytes.extend_from_slice(data);
                }
                OperationResult::Transaction { validation_result } => {
                    input_bytes.extend_from_slice(b"tx:");
                    input_bytes.extend_from_slice(&validation_result.to_le_bytes());
                }
                OperationResult::Serialization { success } => {
                    input_bytes.extend_from_slice(b"serialize:");
                    input_bytes.push(if *success { 1u8 } else { 0u8 });
                }
                OperationResult::Noop => {
                    // Intentionally omitted from digest
                }
            }
        }

        if debug_enabled {
            eprintln!("[RUST] Trace digest input bytes: {:?}", &input_bytes);
        }

        let mut hasher = Sha256::new();
        hasher.update(&input_bytes);
        let digest = hasher.finalize().to_vec();

        if debug_enabled {
            eprintln!("[RUST] Final trace digest bytes: {:?}", &digest);
        }

        digest
    }
}

impl Default for RustStepExecutor {
    fn default() -> Self {
        Self::new().expect("Failed to create default RustStepExecutor")
    }
}

impl TraceExecutor for RustStepExecutor {
    type Error = anyhow::Error;

    fn execute_trace(&mut self, trace: &Trace) -> Result<ExecutionResult> {
        let start_time = Instant::now();

        // Set deterministic seed
        use rand::SeedableRng;
        self.rng = rand_chacha::ChaCha8Rng::seed_from_u64(trace.seed);

        let mut results = Vec::new();
        let mut ops_executed = 0;
        let mut messages_processed = 0;
        let mut transactions_processed = 0;

        // Execute each operation
        for op in &trace.ops {
            match self.execute_operation(op) {
                Ok(result) => {
                    // Update metrics based on non-noop results
                    match &result {
                        OperationResult::Protocol { messages_count, .. } => {
                            messages_processed += messages_count;
                        }
                        OperationResult::Transaction { .. } => {
                            transactions_processed += 1;
                        }
                        OperationResult::Noop => {
                            // skip metrics and ops count
                        }
                        _ => {}
                    }
                    let is_noop = matches!(result, OperationResult::Noop);
                    results.push(result);
                    if !is_noop {
                        ops_executed += 1;
                    }
                }
                Err(e) => {
                    // Log error but continue execution for partial results
                    tracing::warn!("Operation failed: {}", e);
                    return Ok(ExecutionResult::error(
                        format!("Operation {} failed: {}", ops_executed, e),
                        ops_executed,
                    ));
                }
            }
        }

        let duration = start_time.elapsed();
        let digest = self.compute_digest(&results);

        let metrics = ExecutionMetrics {
            duration_us: duration.as_micros() as u64,
            memory_bytes: None, // Could be implemented with memory profiling
            messages_processed,
            transactions_processed,
        };

        Ok(ExecutionResult::success(digest, ops_executed).with_metrics(metrics))
    }

    fn reset(&mut self) -> Result<()> {
        // Reset internal state of adapters
        self.protocol_adapter.reset()?;
        self.tx_adapter.reset()?;
        Ok(())
    }
}

/// Internal result types for different operation categories  
#[derive(Debug)]
enum OperationResult {
    Protocol {
        data: Vec<u8>,
        messages_count: u32,
    },
    Transaction {
        validation_result: u32, // 0 = invalid, 1 = valid, 2 = error
    },
    Serialization {
        success: bool,
    },
    Noop,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::{Operation, Trace};

    #[tokio::test]
    async fn test_basic_execution() {
        let mut executor = RustStepExecutor::with_seed(12345).unwrap();
        let trace = Trace::basic_protocol_test();

        let result = executor.execute_trace(&trace).unwrap();
        assert!(result.is_success());
        assert_eq!(result.ops_executed, trace.ops.len());
        assert!(!result.digest.is_empty());
    }

    #[tokio::test]
    async fn test_deterministic_execution() {
        let trace = Trace::basic_protocol_test();

        let mut executor1 = RustStepExecutor::with_seed(12345).unwrap();
        let result1 = executor1.execute_trace(&trace).unwrap();

        let mut executor2 = RustStepExecutor::with_seed(12345).unwrap();
        let result2 = executor2.execute_trace(&trace).unwrap();

        assert_eq!(result1.digest, result2.digest);
    }

    #[tokio::test]
    async fn test_different_seeds_same_digest() {
        let trace = Trace::basic_protocol_test();

        let mut executor1 = RustStepExecutor::with_seed(12345).unwrap();
        let result1 = executor1.execute_trace(&trace).unwrap();

        let mut executor2 = RustStepExecutor::with_seed(67890).unwrap();
        let result2 = executor2.execute_trace(&trace).unwrap();

        // With canonical digests, same trace should produce same digest regardless of seed
        // This is correct behavior for differential fuzzing
        assert_eq!(result1.digest, result2.digest);
        assert_eq!(result1.ops_executed, result2.ops_executed);
        assert!(result1.is_success() && result2.is_success());
    }
}
