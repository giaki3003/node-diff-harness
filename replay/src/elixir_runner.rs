//! Elixir runner for the replay tool
//!
//! This module manages communication with the Elixir oracle process
//! for replaying traces in the replay tool.

use anyhow::{Context, Result};
use proto::{ExecutionResult, Trace};
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::time::{timeout, Duration};

pub struct ElixirRunner {
    child: Child,
}

impl ElixirRunner {
    pub async fn new() -> Result<Self> {
        let child = Self::spawn_elixir_process()
            .await
            .context("Failed to spawn Elixir process")?;

        Ok(Self { child })
    }

    pub async fn execute_trace(&mut self, trace: &Trace) -> Result<ExecutionResult> {
        // Convert trace to JSON for communication
        let trace_json = serde_json::to_vec(trace).context("Failed to serialize trace to JSON")?;

        // Send length-prefixed trace
        let length = trace_json.len() as u32;

        if let Some(stdin) = &mut self.child.stdin {
            stdin
                .write_all(&length.to_be_bytes())
                .await
                .context("Failed to write trace length")?;
            stdin
                .write_all(&trace_json)
                .await
                .context("Failed to write trace data")?;
            stdin.flush().await.context("Failed to flush stdin")?;
        } else {
            anyhow::bail!("Elixir process has no stdin");
        }

        // Read response with timeout
        let response = timeout(Duration::from_secs(30), self.read_response())
            .await
            .context("Timeout waiting for Elixir response")??;

        self.parse_response(&response)
    }

    async fn read_response(&mut self) -> Result<Vec<u8>> {
        if let Some(stdout) = &mut self.child.stdout {
            // Read length
            let mut length_buf = [0u8; 4];
            stdout
                .read_exact(&mut length_buf)
                .await
                .context("Failed to read response length")?;

            let response_length = u32::from_be_bytes(length_buf);

            if response_length == 0 {
                return Ok(vec![]); // Error response
            }

            // Read response data
            let mut response_buf = vec![0u8; response_length as usize];
            stdout
                .read_exact(&mut response_buf)
                .await
                .context("Failed to read response data")?;

            Ok(response_buf)
        } else {
            anyhow::bail!("Elixir process has no stdout");
        }
    }

    fn parse_response(&self, response: &[u8]) -> Result<ExecutionResult> {
        if response.is_empty() {
            return Ok(ExecutionResult::error(
                "Elixir execution failed".to_string(),
                0,
            ));
        }

        // Parse binary format from Elixir oracle with backwards compatibility:
        // Legacy (36 bytes): [ops_executed: 4 bytes] + [digest: 32 bytes]
        // Extended (52 bytes): [ops_executed: 4 bytes] + [digest: 32 bytes] + 
        //                     [duration_us: 8 bytes] + [messages: 4 bytes] + [txs: 4 bytes]
        if response.len() < 36 {
            return Ok(ExecutionResult::error(
                format!(
                    "Invalid response format: expected at least 36 bytes, got {}",
                    response.len()
                ),
                0,
            ));
        }

        // Extract ops_executed (first 4 bytes, big-endian)
        let ops_executed =
            u32::from_be_bytes([response[0], response[1], response[2], response[3]]) as usize;

        // Extract digest (next 32 bytes)
        let digest = response[4..36].to_vec();

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
        if response.len() >= 52 {
            // Extract additional metrics
            let duration_us = u64::from_be_bytes([
                response[36], response[37], response[38], response[39],
                response[40], response[41], response[42], response[43]
            ]);

            let messages_processed = u32::from_be_bytes([
                response[44], response[45], response[46], response[47]
            ]);

            let transactions_processed = u32::from_be_bytes([
                response[48], response[49], response[50], response[51]
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

    async fn spawn_elixir_process() -> Result<Child> {
        // Try to find the Elixir runner escript
        let possible_paths = [
            "./adapters/elixir-runner/elixir_runner",
            "../adapters/elixir-runner/elixir_runner",
            "../../adapters/elixir-runner/elixir_runner",
            "./elixir_runner",
        ];

        let mut last_error = None;

        for path in &possible_paths {
            match Command::new(path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .env("LC_ALL", "C")         // Force C locale for binary I/O
                .env("LANG", "C")           // Force C language for binary I/O  
                .env("ERL_AFLAGS", "-noshell +A4 +K true") // Elixir/Erlang flags for binary I/O
                .spawn()
            {
                Ok(child) => {
                    println!("✅ Started Elixir oracle: {}", path);

                    // Give it a moment to start
                    tokio::time::sleep(Duration::from_millis(200)).await;

                    return Ok(child);
                }
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }

        Err(anyhow::anyhow!(
            "Could not find Elixir runner. Tried paths: {:?}. Last error: {:?}",
            possible_paths,
            last_error
        ))
    }
}

impl Drop for ElixirRunner {
    fn drop(&mut self) {
        // Kill the child process
        let _ = self.child.start_kill();
    }
}
