//! Elixir runner for the replay tool
//!
//! This module manages communication with the Elixir oracle process
//! for replaying traces in the replay tool.

use anyhow::{Context, Result};
use proto::{ExecutionResult, Trace};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Stdio;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::time::{timeout, Duration};
use nix::unistd::{pipe, dup2, close};
use std::os::fd::{AsRawFd, IntoRawFd};

pub struct ElixirRunner {
    child: Child,
    result_reader: TokioFile, // NEW: read replies from FD 3 pipe
}

impl ElixirRunner {
    pub async fn new() -> Result<Self> {
        let (child, result_reader) = Self::spawn_elixir_process()
            .await
            .context("Failed to spawn Elixir process")?;

        Ok(Self { child, result_reader })
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
        // Read length from FD 3 pipe
        let mut length_buf = [0u8; 4];
        self.result_reader
            .read_exact(&mut length_buf)
            .await
            .context("Failed to read response length from FD 3")?;

        let response_length = u32::from_be_bytes(length_buf);

        if response_length == 0 {
            return Ok(vec![]); // Error response
        }

        // Read response data from FD 3 pipe
        let mut response_buf = vec![0u8; response_length as usize];
        self.result_reader
            .read_exact(&mut response_buf)
            .await
            .context("Failed to read response data from FD 3")?;

        Ok(response_buf)
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

    async fn spawn_elixir_process() -> Result<(Child, TokioFile)> {
        // Create a pipe for FD 3 communication
        let (read_fd, write_fd) = pipe().context("Failed to create pipe for FD 3")?;
        let write_raw = write_fd.as_raw_fd();

        // Use mix run instead of escript for full NIF support
        let possible_dirs = [
            "./adapters/elixir-runner/",
            "../adapters/elixir-runner/",
            "../../adapters/elixir-runner/",
            "./",
        ];

        let mut last_error = None;

        for dir in &possible_dirs {
            let mut cmd = Command::new("mix");
            unsafe {
                cmd.args(&["run", "--no-compile", "--no-halt", "-e", "ElixirRunner.CLI.main([])"])
                    .current_dir(dir)
                    .env("AMA_RESULT_FD", "3")
                    .env("MIX_ENV", "prod")  // Use prod to load precompiled NIFs consistently
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())   // logs won't matter now
                    .stderr(Stdio::inherit())   // Enable to see mix output for debugging
                    .pre_exec(move || {
                        // SAFETY: we are in the child just before exec
                        // make write_raw become FD 3
                        match dup2(write_raw, 3) {
                            Ok(_) => {},
                            Err(e) => return Err(std::io::Error::from_raw_os_error(e as i32)),
                        }
                        let _ = close(write_raw);
                        Ok(())
                    })
            };

            match cmd.spawn() {
                Ok(child) => {
                    println!("✅ Started Elixir oracle: mix run in {}", dir);

                    // Close the write end in the parent process (consume the OwnedFd)
                    drop(write_fd);

                    // Convert read_fd to a TokioFile
                    let reader = unsafe { std::fs::File::from_raw_fd(read_fd.into_raw_fd()) };
                    let result_reader = TokioFile::from_std(reader);

                    // Give it a moment to start
                    tokio::time::sleep(Duration::from_millis(200)).await;

                    return Ok((child, result_reader));
                }
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }

        // If we get here, all paths failed - clean up the pipe (consume the OwnedFds)
        drop(read_fd);
        drop(write_fd);

        Err(anyhow::anyhow!(
            "Could not start Elixir runner. Tried dirs: {:?}. Last error: {:?}",
            possible_dirs,
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
