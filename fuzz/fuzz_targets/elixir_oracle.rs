//! Elixir oracle process manager
//!
//! This module manages a persistent Elixir child process that executes
//! traces and returns results for comparison with the Rust implementation.

use anyhow::{Context, Result};
use proto::{ExecutionResult, Trace};
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

pub struct ElixirOracle {
    child: Child,
    restart_count: u32,
}

impl ElixirOracle {
    /// Create a new Elixir oracle with a child process
    pub fn new() -> Result<Self> {
        let child =
            Self::spawn_elixir_process().context("Failed to spawn Elixir oracle process")?;

        Ok(Self {
            child,
            restart_count: 0,
        })
    }

    /// Execute a trace on the Elixir implementation
    pub fn execute_trace(&mut self, trace: &Trace) -> Result<ExecutionResult> {
        // Try to execute, restart process if needed
        match self.execute_trace_inner(trace) {
            Ok(result) => Ok(result),
            Err(e) => {
                // Try to restart the process once
                if self.restart_count < 3 {
                    eprintln!(
                        "Elixir oracle failed ({}), restarting: {}",
                        self.restart_count + 1,
                        e
                    );
                    self.restart()?;
                    self.execute_trace_inner(trace)
                        .context("Failed even after restart")
                } else {
                    Err(e).context("Too many restart attempts")
                }
            }
        }
    }

    fn execute_trace_inner(&mut self, trace: &Trace) -> Result<ExecutionResult> {
        // Serialize trace to JSON (simple format for now)
        let trace_json = serde_json::to_vec(trace).context("Failed to serialize trace")?;

        // Send length-prefixed trace
        let length = trace_json.len() as u32;
        let stdin = self
            .child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No stdin"))?;

        stdin
            .write_all(&length.to_be_bytes())
            .context("Failed to write length")?;
        stdin
            .write_all(&trace_json)
            .context("Failed to write trace")?;
        stdin.flush().context("Failed to flush stdin")?;

        // Read length-prefixed response
        let stdout = self
            .child
            .stdout
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No stdout"))?;

        let mut length_buf = [0u8; 4];
        stdout
            .read_exact(&mut length_buf)
            .context("Failed to read response length")?;

        let response_length = u32::from_be_bytes(length_buf);

        if response_length == 0 {
            // Error response
            return Ok(ExecutionResult::error("Elixir oracle error".to_string(), 0));
        }

        let mut response_buf = vec![0u8; response_length as usize];
        stdout
            .read_exact(&mut response_buf)
            .context("Failed to read response data")?;

        // Parse response (simple binary format)
        self.parse_elixir_response(&response_buf)
    }

    fn parse_elixir_response(&self, response_data: &[u8]) -> Result<ExecutionResult> {
        // Parse binary format from Elixir oracle with backwards compatibility:
        // Legacy (36 bytes): [ops_executed: 4 bytes] + [digest: 32 bytes]
        // Extended (52 bytes): [ops_executed: 4 bytes] + [digest: 32 bytes] + 
        //                     [duration_us: 8 bytes] + [messages: 4 bytes] + [txs: 4 bytes]
        
        if response_data.len() < 36 {
            return Ok(ExecutionResult::error(
                format!(
                    "Invalid response format: expected at least 36 bytes, got {}",
                    response_data.len()
                ),
                0,
            ));
        }

        // Extract ops_executed (first 4 bytes, big-endian) 
        let ops_executed = u32::from_be_bytes([
            response_data[0],
            response_data[1], 
            response_data[2],
            response_data[3]
        ]) as usize;

        // Extract digest (next 32 bytes)
        let digest = response_data[4..36].to_vec();

        if digest.len() != 32 {
            return Ok(ExecutionResult::error(
                format!(
                    "Invalid digest length: expected 32 bytes, got {}",
                    digest.len()
                ),
                ops_executed,
            ));
        }

        let mut result = ExecutionResult::success(digest, ops_executed);

        // Check if extended format with metrics (52 bytes total)
        if response_data.len() >= 52 {
            // Extract additional metrics
            let duration_us = u64::from_be_bytes([
                response_data[36], response_data[37], response_data[38], response_data[39],
                response_data[40], response_data[41], response_data[42], response_data[43]
            ]);

            let messages_processed = u32::from_be_bytes([
                response_data[44], response_data[45], response_data[46], response_data[47]
            ]);

            let transactions_processed = u32::from_be_bytes([
                response_data[48], response_data[49], response_data[50], response_data[51]
            ]);

            let metrics = proto::ExecutionMetrics {
                duration_us,
                memory_bytes: None,
                messages_processed,
                transactions_processed,
            };

            result = result.with_metrics(metrics);
        }

        Ok(result)
    }


    fn restart(&mut self) -> Result<()> {
        // Kill old process
        let _ = self.child.kill();
        let _ = self.child.wait();

        // Start new process
        self.child = Self::spawn_elixir_process().context("Failed to restart Elixir process")?;
        self.restart_count += 1;

        Ok(())
    }

    fn spawn_elixir_process() -> Result<Child> {
        // Try to find the Elixir runner escript
        let escript_paths = [
            "../adapters/elixir-runner/elixir_runner",
            "./adapters/elixir-runner/elixir_runner",
            "../../adapters/elixir-runner/elixir_runner",
            "../../../adapters/elixir-runner/elixir_runner",
        ];

        let mut last_error = None;

        for escript_path in &escript_paths {
            match Command::new(escript_path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .env("LC_ALL", "C")         // Force C locale for binary I/O
                .env("LANG", "C")           // Force C language for binary I/O  
                .env("ERL_AFLAGS", "-noshell +A4 +K true") // Elixir/Erlang flags for binary I/O
                .spawn()
            {
                Ok(child) => {
                    eprintln!("Started Elixir oracle: {}", escript_path);

                    // Give it a moment to start up
                    std::thread::sleep(Duration::from_millis(100));

                    return Ok(child);
                }
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }

        Err(anyhow::anyhow!(
            "Failed to start Elixir oracle: {:?}",
            last_error
        ))
    }
}

impl Drop for ElixirOracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
