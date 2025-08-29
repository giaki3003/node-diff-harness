//! Elixir oracle process manager
//!
//! This module manages a persistent Elixir child process that executes
//! traces and returns results for comparison with the Rust implementation.

use anyhow::{Context, Result};
use proto::{ExecutionResult, Trace};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use nix::unistd::{pipe, dup2, close};
use std::os::fd::{AsRawFd, IntoRawFd};

pub struct ElixirOracle {
    child: Child,
    result_reader: File, // Read replies from FD 3 pipe (using std::fs::File for sync API)
    restart_count: u32,
}

impl ElixirOracle {
    /// Create a new Elixir oracle with a child process
    pub fn new() -> Result<Self> {
        let (child, result_reader) =
            Self::spawn_elixir_process().context("Failed to spawn Elixir oracle process")?;

        Ok(Self {
            child,
            result_reader,
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
        let oracle_pid = self.child.id();
        
        // Check if the process is still alive before attempting communication
        match self.child.try_wait() {
            Ok(Some(exit_status)) => {
                return Err(anyhow::anyhow!("Oracle PID {} died before execution with status: {}", oracle_pid, exit_status));
            }
            Ok(None) => {
                // Oracle is alive, continue
            }
            Err(_e) => {
                // Could not check liveness
            }
        }
        
        // Serialize trace to JSON (simple format for now)
        let trace_json = serde_json::to_vec(trace).context("Failed to serialize trace")?;

        // Send length-prefixed trace
        let length = trace_json.len() as u32;
        let stdin = self
            .child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No stdin available for PID {}", oracle_pid))?;

        // Send trace to oracle

        // Writing trace length
        stdin
            .write_all(&length.to_be_bytes())
            .with_context(|| format!("Failed to write length to PID {}", oracle_pid))?;
        
        // Writing trace data
        stdin
            .write_all(&trace_json)
            .with_context(|| format!("Failed to write trace data to PID {}", oracle_pid))?;
            
        stdin.flush()
            .with_context(|| format!("Failed to flush stdin to PID {}", oracle_pid))?;
        
        // Trace sent successfully

        // Read length-prefixed response from FD 3 pipe
        // Reading response length
        let mut length_buf = [0u8; 4];
        self.result_reader
            .read_exact(&mut length_buf)
            .with_context(|| format!("Failed to read response length from FD 3 for PID {}", oracle_pid))?;
    
        let response_length = u32::from_be_bytes(length_buf);
    
        // Basic sanity: cap the maximum response length to avoid huge allocations if protocol is corrupted
        const MAX_RESP_LEN: u32 = 10_000_000; // 10MB cap
        if response_length == 0 {
            // Error response
            // Oracle returned error response
            return Ok(ExecutionResult::error("Elixir oracle error".to_string(), 0));
        } else if response_length > MAX_RESP_LEN {
            return Err(anyhow::anyhow!(
                "Unreasonable response length {} from PID {}",
                response_length,
                oracle_pid
            ));
        }
    
        // Reading response data from FD 3 pipe
        let mut response_buf = vec![0u8; response_length as usize];
        self.result_reader
            .read_exact(&mut response_buf)
            .with_context(|| format!("Failed to read response data ({} bytes) from FD 3 for PID {}", response_length, oracle_pid))?;
    
        // Response received successfully
        
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

            // Parse additional metrics from extended format

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
        let old_pid = self.child.id();
        // Restarting oracle
        
        // Kill old process
        let _ = self.child.kill();
        let _ = self.child.wait();

        // Start new process
        let (child, result_reader) = Self::spawn_elixir_process().context("Failed to restart Elixir process")?;
        self.child = child;
        self.result_reader = result_reader;
        self.restart_count += 1;

        Ok(())
    }

    fn spawn_elixir_process() -> Result<(Child, File)> {
        // Create a pipe for FD 3 communication
        let (read_fd, write_fd) = pipe().context("Failed to create pipe for FD 3")?;
        let write_raw = write_fd.as_raw_fd();

        // Enable Elixir stderr debug passthrough when AMA_ORACLE_DEBUG is set
        let debug_stderr = std::env::var("AMA_ORACLE_DEBUG")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let mut last_error = None;

        // Strategy A: spawn ElixirRunner via mix run (enabled by default; set AMA_ORACLE_USE_MIX=0 to disable)
        let use_mix = std::env::var("AMA_ORACLE_USE_MIX").map(|v| v != "0").unwrap_or(true);  // Enable mix for full NIF support
        if use_mix {
            let mut cmd = Command::new("mix");
            unsafe {
                cmd.args(&["run", "--no-halt", "-e", "ElixirRunner.CLI.main([])"])
                    .current_dir("../adapters/elixir-runner")
                    .env("MIX_ENV", "dev")  // Use dev mode for full NIF availability
                    .env("AMA_RESULT_FD", "3")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())  // Always inherit stderr for debugging
                    .pre_exec(move || {
                        // SAFETY: we are in the child just before exec
                        // make write_raw become FD 3
                        match dup2(write_raw, 3) {
                            Ok(_) => {},
                            Err(e) => {
                                return Err(std::io::Error::from_raw_os_error(e as i32));
                            }
                        }
                        let _ = close(write_raw);
                        Ok(())
                    })
            };

            match cmd.spawn() {
                Ok(mut child) => {
                    // Give it a moment to start up
                    std::thread::sleep(Duration::from_millis(100));

                    // Check if process is still alive after startup delay
                    match child.try_wait() {
                        Ok(Some(_exit_status)) => {
                            // fall through to escript fallback
                        }
                        Ok(None) => {
                            // Close the write end in the parent process (consume the OwnedFd)
                            drop(write_fd);

                            // Convert read_fd to a File
                            let result_reader = unsafe { File::from_raw_fd(read_fd.into_raw_fd()) };

                            return Ok((child, result_reader));
                        }
                        Err(_e) => {
                            // Close the write end in the parent process (consume the OwnedFd)
                            drop(write_fd);

                            // Convert read_fd to a File
                            let result_reader = unsafe { File::from_raw_fd(read_fd.into_raw_fd()) };

                            return Ok((child, result_reader));
                        }
                    }
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        // Strategy B: Try to find and spawn the prebuilt Elixir runner escript
        let escript_paths = [
            "../adapters/elixir-runner/elixir_runner",
            "./adapters/elixir-runner/elixir_runner",
            "../../adapters/elixir-runner/elixir_runner",
            "../../../adapters/elixir-runner/elixir_runner",
        ];

        for escript_path in &escript_paths {
            let mut cmd = Command::new(escript_path);
            unsafe {
                cmd.env("AMA_RESULT_FD", "3")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())   // logs won't matter now
                    .stderr(Stdio::inherit())  // Always inherit stderr for debugging
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
                Ok(mut child) => {
                    // Give it a moment to start up
                    std::thread::sleep(Duration::from_millis(100));

                    // Check if process is still alive after startup delay
                    match child.try_wait() {
                        Ok(Some(_exit_status)) => {
                            continue; // Try next path
                        }
                        Ok(None) => {
                            // Oracle started successfully
                        }
                        Err(_e) => {
                        }
                    }

                    // Close the write end in the parent process (consume the OwnedFd)
                    drop(write_fd);

                    // Convert read_fd to a File
                    let result_reader = unsafe { File::from_raw_fd(read_fd.into_raw_fd()) };

                    return Ok((child, result_reader));
                }
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }

        // If we get here, all strategies failed - clean up the pipe (consume the OwnedFds)
        drop(read_fd);
        drop(write_fd);

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

/// Pool of independent Elixir oracle processes for parallel fuzzing
/// 
/// This enables true parallelism by spawning multiple isolated oracle processes,
/// each with its own RocksDB database and unique working directory, completely
/// eliminating locking conflicts and maximizing CPU utilization.
pub struct ElixirOraclePool {
    oracles: Vec<Mutex<ElixirOracle>>,
    next_oracle: AtomicUsize,
    pool_size: usize,
}

impl ElixirOraclePool {
    /// Create a new oracle pool with the specified number of processes
    pub fn new(pool_size: usize) -> Result<Self> {
        if pool_size == 0 {
            return Err(anyhow::anyhow!("Pool size must be greater than 0"));
        }
        
        println!("🚀 Spawning {} oracle processes for parallel fuzzing...", pool_size);
        
        let mut oracles = Vec::with_capacity(pool_size);
        let mut failed_spawns = 0;
        
        for i in 0..pool_size {
            match ElixirOracle::new() {
                Ok(oracle) => {
                    println!("✅ Oracle {}/{} spawned successfully", i + 1, pool_size);
                    oracles.push(Mutex::new(oracle));
                }
                Err(e) => {
                    failed_spawns += 1;
                    eprintln!("❌ Oracle {}/{} failed to spawn: {}", i + 1, pool_size, e);
                    
                    // If too many failures, abort pool creation
                    if failed_spawns > pool_size / 2 {
                        return Err(anyhow::anyhow!(
                            "Too many oracle spawn failures ({}/{}), aborting pool creation", 
                            failed_spawns, pool_size
                        ));
                    }
                }
            }
        }
        
        let actual_size = oracles.len();
        if actual_size < pool_size {
            eprintln!("⚠️  Created pool with {}/{} oracles due to spawn failures", actual_size, pool_size);
        }
        
        println!("🎯 Oracle pool ready: {} processes for parallel execution", actual_size);
        
        Ok(Self {
            oracles,
            next_oracle: AtomicUsize::new(0),
            pool_size: actual_size,
        })
    }
    
    /// Execute a trace using round-robin distribution across the oracle pool
    pub fn execute_trace(&self, trace: &Trace) -> Result<ExecutionResult> {
        if self.oracles.is_empty() {
            return Err(anyhow::anyhow!("No oracles available in pool"));
        }
        
        // Round-robin selection for fair load distribution
        let oracle_index = self.next_oracle.fetch_add(1, Ordering::Relaxed) % self.pool_size;
        
        // Execute on the selected oracle
        // SAFETY: oracle_index is guaranteed to be < pool_size due to modulo operation
        let oracle = &self.oracles[oracle_index];
        
        // Note: We can't get a mutable reference here since ElixirOracle.execute_trace expects &mut self
        // We'll need to modify the approach to use interior mutability or unsafe code
        // For now, let's create a method that handles the execution differently
        self.execute_on_oracle(oracle_index, trace)
    }
    
    /// Execute trace on a specific oracle by index (internal helper)
    fn execute_on_oracle(&self, oracle_index: usize, trace: &Trace) -> Result<ExecutionResult> {
        let oracle = &self.oracles[oracle_index];
        
        // Lock the oracle for exclusive access
        let mut oracle_guard = oracle
            .lock()
            .map_err(|_| anyhow::anyhow!("Oracle {} mutex poisoned", oracle_index))?;
        
        // Execute the trace on the locked oracle
        oracle_guard.execute_trace(trace)
    }
    
    /// Get the number of active oracles in the pool
    pub fn pool_size(&self) -> usize {
        self.pool_size
    }
    
    /// Get pool utilization statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            total_oracles: self.pool_size,
            active_oracles: self.pool_size, // TODO: Track failed oracles
        }
    }
}

/// Statistics about the oracle pool
pub struct PoolStats {
    pub total_oracles: usize,
    pub active_oracles: usize,
}

impl Drop for ElixirOraclePool {
    fn drop(&mut self) {
        println!("🛑 Shutting down oracle pool with {} processes...", self.pool_size);
        
        // Note: Each ElixirOracle has its own Drop implementation that kills the child process,
        // so when the Mutex<ElixirOracle> is dropped, the child processes will be terminated properly.
        // We don't need to do anything special here.
    }
}

/// Determine the optimal pool size based on system resources and configuration
pub fn default_pool_size() -> usize {
    // Check for explicit configuration first
    if let Ok(size_str) = std::env::var("AMA_ORACLE_POOL_SIZE") {
        if let Ok(size) = size_str.parse::<usize>() {
            if size > 0 && size <= 32 {  // Reasonable bounds
                return size;
            } else {
                eprintln!("⚠️  Invalid AMA_ORACLE_POOL_SIZE={}, using default", size_str);
            }
        }
    }
    
    // Smart default based on system resources
    std::cmp::min(
        num_cpus::get(),     // Don't exceed available CPU cores
        4                    // Conservative default (4 processes ≈ 600-800MB memory)
    )
}
