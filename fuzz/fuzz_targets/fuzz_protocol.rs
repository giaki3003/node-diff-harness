#![no_main]

//! Differential fuzzing target for protocol message handling
//!
//! This target generates arbitrary traces and executes them on both
//! the Rust and Elixir implementations, comparing the results.

use anyhow::{Context, Result};
use libfuzzer_sys::fuzz_target;
use proto::{Trace, TraceExecutor};
use rust_step::RustStepExecutor;
use std::sync::OnceLock;

mod elixir_oracle;
use elixir_oracle::ElixirOraclePool;

/// Global Elixir oracle pool (persistent child processes)
static ORACLE_POOL: OnceLock<ElixirOraclePool> = OnceLock::new();

fuzz_target!(|trace: Trace| {
    // Initialize tracing (only once)
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    if let Err(e) = fuzz_trace(trace) {
        // Log error but don't panic the fuzzer
        eprintln!("Fuzzing error: {}", e);
    }
});

fn fuzz_trace(trace: Trace) -> Result<()> {
    // Get or initialize the Elixir oracle pool
    let pool = ORACLE_POOL.get_or_init(|| {
        let pool_size = elixir_oracle::default_pool_size();
        ElixirOraclePool::new(pool_size).expect("Failed to initialize Elixir oracle pool")
    });

    // Execute trace on Rust implementation
    let mut rust_executor =
        RustStepExecutor::with_seed(trace.seed).context("Failed to create Rust executor")?;

    let rust_result = rust_executor
        .execute_trace(&trace)
        .context("Rust execution failed")?;

    // Execute trace on Elixir implementation using pool
    let elixir_result = pool
        .execute_trace(&trace)
        .context("Elixir execution failed")?;

    // Compare normalized results
    compare_results(&trace, &rust_result, &elixir_result)?;

    Ok(())
}

fn compare_results(
    trace: &Trace,
    rust_result: &proto::ExecutionResult,
    elixir_result: &proto::ExecutionResult,
) -> Result<()> {
    // First, check if both succeeded or both failed in the same way
    match (rust_result.is_success(), elixir_result.is_success()) {
        (true, true) => {
            // Both succeeded - compare digests
            if rust_result.digest != elixir_result.digest {
                panic!(
                    "DIFFERENTIAL BUG FOUND!\n\
                       Trace seed: {}\n\
                       Rust digest: {:?}\n\
                       Elixir digest: {:?}\n\
                       Operations executed - Rust: {}, Elixir: {}\n\
                       Trace: {:?}",
                    trace.seed,
                    hex::encode(&rust_result.digest),
                    hex::encode(&elixir_result.digest),
                    rust_result.ops_executed,
                    elixir_result.ops_executed,
                    trace
                );
            }
        }
        (false, false) => {
            // Both failed - this is expected for many invalid inputs
            // We could compare error types here if needed
            if rust_result.ops_executed != elixir_result.ops_executed {
                // Different number of operations before failure - potential bug
                panic!(
                    "DIFFERENTIAL FAILURE POINT!\n\
                       Trace seed: {}\n\
                       Rust failed after {} ops: {:?}\n\
                       Elixir failed after {} ops: {:?}\n\
                       Trace: {:?}",
                    trace.seed,
                    rust_result.ops_executed,
                    rust_result.get_error(),
                    elixir_result.ops_executed,
                    elixir_result.get_error(),
                    trace
                );
            }
        }
        (true, false) => {
            // Rust succeeded but Elixir failed
            panic!(
                "DIFFERENTIAL SUCCESS/FAILURE!\n\
                   Trace seed: {}\n\
                   Rust succeeded: {} ops, digest: {:?}\n\
                   Elixir failed: {} ops, error: {:?}\n\
                   Trace: {:?}",
                trace.seed,
                rust_result.ops_executed,
                hex::encode(&rust_result.digest),
                elixir_result.ops_executed,
                elixir_result.get_error(),
                trace
            );
        }
        (false, true) => {
            // Elixir succeeded but Rust failed
            panic!(
                "DIFFERENTIAL FAILURE/SUCCESS!\n\
                   Trace seed: {}\n\
                   Rust failed: {} ops, error: {:?}\n\
                   Elixir succeeded: {} ops, digest: {:?}\n\
                   Trace: {:?}",
                trace.seed,
                rust_result.ops_executed,
                rust_result.get_error(),
                elixir_result.ops_executed,
                hex::encode(&elixir_result.digest),
                trace
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_protocol_trace() {
        let trace = Trace::basic_protocol_test();
        fuzz_trace(trace).expect("Basic trace should not crash");
    }

    #[test]
    fn test_empty_trace() {
        let trace = Trace {
            seed: 12345,
            ops: vec![],
        };
        fuzz_trace(trace).expect("Empty trace should not crash");
    }
}
