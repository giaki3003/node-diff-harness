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

        // Parse response (Erlang term format)
        self.parse_elixir_response(&response_buf)
    }

    fn parse_elixir_response(&self, response_data: &[u8]) -> Result<ExecutionResult> {
        // For now, just create a minimal response
        // In production, we'd properly deserialize the Erlang term format

        // Try to deserialize as Erlang term
        match self.try_parse_etf(response_data) {
            Ok(result) => Ok(result),
            Err(_) => {
                // Fallback: create digest from raw response
                let digest = blake3::hash(response_data).as_bytes().to_vec();
                Ok(ExecutionResult::success(digest, 1))
            }
        }
    }

    fn try_parse_etf(&self, data: &[u8]) -> Result<ExecutionResult> {
        // This is a simplified parser - in production we'd use a proper ETF library
        // or implement bincode deserialization in Elixir

        // For now, just hash the data to create a consistent digest
        let digest = blake3::hash(data).as_bytes().to_vec();

        // Try to extract basic info (this is very naive parsing)
        let ops_executed = if data.len() > 8 {
            u32::from_be_bytes([data[4], data[5], data[6], data[7]]) % 100
        } else {
            1
        };

        Ok(ExecutionResult::success(digest, ops_executed as usize))
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
