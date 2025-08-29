//! Protocol definitions and trace formats for differential fuzzing
//!
//! This crate defines the data structures and binary formats used to
//! communicate test cases between the fuzzer and both implementations.

pub mod trace;

pub use trace::{MessageType, Operation, Trace};

/// Result of executing a trace on an implementation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    /// Normalized digest of the final state
    pub digest: Vec<u8>,
    /// Number of operations executed successfully  
    pub ops_executed: usize,
    /// Any error that occurred during execution
    pub error: Option<String>,
    /// Performance metrics (optional)
    pub metrics: Option<ExecutionMetrics>,
}

/// Performance and execution metrics
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionMetrics {
    /// Execution time in microseconds
    pub duration_us: u64,
    /// Memory usage in bytes (if available)
    pub memory_bytes: Option<u64>,
    /// Number of protocol messages processed
    pub messages_processed: u32,
    /// Number of transactions validated
    pub transactions_processed: u32,
}

impl ExecutionResult {
    /// Create a successful result
    pub fn success(digest: Vec<u8>, ops_executed: usize) -> Self {
        Self {
            digest,
            ops_executed,
            error: None,
            metrics: None,
        }
    }

    /// Create an error result
    pub fn error(error: String, ops_executed: usize) -> Self {
        Self {
            digest: Vec::new(),
            ops_executed,
            error: Some(error),
            metrics: None,
        }
    }

    /// Add performance metrics
    pub fn with_metrics(mut self, metrics: ExecutionMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Check if execution was successful
    pub fn is_success(&self) -> bool {
        self.error.is_none()
    }

    /// Get execution error if any
    pub fn get_error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

/// Canonical error taxonomy for consistent cross-implementation error classification
/// 
/// This enum defines semantic error categories that both Rust and Elixir implementations
/// can map their native errors to, enabling meaningful differential testing comparison.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CanonErr {
    /// Successful operation
    Ok           = 1,
    /// Resource limits exceeded (size, memory, etc.)
    TooLarge     = 122,
    /// Generic parsing/deserialization failure (VanillaSer, ETF, etc.)
    Decode       = 123,
    /// Unexpected EOF or insufficient data
    Truncated    = 124,
    /// Integer/varint overflow
    Overflow     = 125,
    /// Negative length or invalid sign bit
    NegativeLen  = 126,
    /// Container nesting exceeded limits
    DepthExceeded = 127,
    /// Unrecognized type tag or format
    UnknownTag   = 128,
}

impl From<CanonErr> for u32 {
    fn from(c: CanonErr) -> u32 {
        c as u32
    }
}

impl From<CanonErr> for u16 {
    fn from(c: CanonErr) -> u16 {
        c as u16
    }
}

impl CanonErr {
    /// Get the canonical error code as u32 (for compatibility with existing adapters)
    pub fn code(self) -> u32 {
        self.into()
    }

    /// Check if this represents a successful operation
    pub fn is_success(self) -> bool {
        matches!(self, CanonErr::Ok)
    }

    /// Check if this represents a failure
    pub fn is_error(self) -> bool {
        !self.is_success()
    }
}

/// Trait for implementations that can execute traces
pub trait TraceExecutor {
    type Error;

    /// Execute a trace and return the normalized result
    fn execute_trace(&mut self, trace: &Trace) -> Result<ExecutionResult, Self::Error>;

    /// Reset the executor state (useful for stateful implementations)
    fn reset(&mut self) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_result() {
        let result = ExecutionResult::success(vec![1, 2, 3], 5);
        assert!(result.is_success());
        assert_eq!(result.ops_executed, 5);
        assert_eq!(result.digest, vec![1, 2, 3]);

        let error_result = ExecutionResult::error("test error".to_string(), 2);
        assert!(!error_result.is_success());
        assert_eq!(error_result.get_error(), Some("test error"));
    }
}
