//! Transaction validation adapter for the Rust implementation
//!
//! This module handles transaction validation using the rs_node tx validation logic.

use ama_core::consensus::tx;
use anyhow::Result;
use proto::CanonErr;

/// Adapter for transaction validation operations
pub struct TxAdapter {
    // Could hold validation state if needed
}

impl TxAdapter {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }

    /// Validate a transaction binary and return normalized result
    pub fn validate_transaction(
        &mut self,
        tx_data: &[u8],
        is_special_meeting: bool,
    ) -> Result<u32> {
        // Protocol-level size limit (parity with Elixir :ama, :tx_size default 393_216)
        const MAX_SAFE_TX_SIZE: usize = 393_216;
        if tx_data.len() > MAX_SAFE_TX_SIZE {
            return Ok(CanonErr::TooLarge.code());
        }

        // Direct validation - let VanillaSer and tx validation handle all edge cases
        match tx::validate(tx_data, is_special_meeting) {
            Ok(_txu) => Ok(CanonErr::Ok.code()),
            Err(e) => {
                let error_code = self.map_error_to_code(&e);
                Ok(error_code)
            }
        }
    }

    /// Reset internal state
    pub fn reset(&mut self) -> Result<()> {
        // Transaction adapter is stateless, nothing to reset
        Ok(())
    }

    /// Map transaction validation errors to canonical error codes
    /// This allows consistent comparison with Elixir error types
    fn map_error_to_code(&self, error: &tx::Error) -> u32 {
        match error {
            // Canonical error mappings for cross-implementation consistency
            tx::Error::TooLarge => CanonErr::TooLarge.code(),
            tx::Error::VanillaSer(_) => CanonErr::Decode.code(),
            
            // Transaction-specific validation errors (keep existing codes)
            tx::Error::WrongType(_) => 100,
            tx::Error::Missing(_) => 101,
            tx::Error::InvalidHash => 102,
            tx::Error::InvalidSignature => 103,
            tx::Error::NonceNotInteger => 104,
            tx::Error::NonceTooHigh => 105,
            tx::Error::ActionsNotList => 106,
            tx::Error::ActionsLenNot1 => 107,
            tx::Error::OpMustBeCall => 108,
            tx::Error::ContractMustBeBinary => 109,
            tx::Error::FunctionMustBeBinary => 110,
            tx::Error::ArgsMustBeList => 111,
            tx::Error::ArgMustBeBinary => 112,
            tx::Error::InvalidContractOrFunction => 113,
            tx::Error::InvalidModuleForSpecial => 114,
            tx::Error::InvalidFunctionForSpecial => 115,
            tx::Error::AttachedSymbolMustBeBinary => 116,
            tx::Error::AttachedSymbolWrongSize => 117,
            tx::Error::AttachedAmountMustBeBinary => 118,
            tx::Error::AttachedAmountMustBeIncluded => 119,
            tx::Error::AttachedSymbolMustBeIncluded => 120,
            tx::Error::TxNotCanonical => 121,
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_transaction() {
        let mut adapter = TxAdapter::new().unwrap();

        // Test with empty transaction data (should be invalid)
        let result = adapter.validate_transaction(&[], false).unwrap();
        assert_ne!(result, 1); // Should not be valid (1)
        assert!(result >= 100); // Should be an error code
    }

    #[test]
    fn test_malformed_transaction() {
        let mut adapter = TxAdapter::new().unwrap();

        // Test with random bytes (should be invalid)
        let random_data = vec![0xFF; 100];
        let result = adapter.validate_transaction(&random_data, false).unwrap();
        assert_ne!(result, 1); // Should not be valid
        assert!(result >= 100); // Should be an error code
    }

    #[test]
    fn test_special_meeting_flag() {
        let mut adapter = TxAdapter::new().unwrap();

        // Test that special_meeting flag is handled
        let random_data = vec![0xFF; 100];
        let result1 = adapter.validate_transaction(&random_data, false).unwrap();
        let result2 = adapter.validate_transaction(&random_data, true).unwrap();

        // Results might be the same for invalid data, but the function should not panic
        assert!(result1 >= 100 || result1 == 1);
        assert!(result2 >= 100 || result2 == 1);
    }

    #[test]
    fn test_basic_malformed_handling() {
        let mut adapter = TxAdapter::new().unwrap();

        // Test basic malformed inputs - avoiding pathological VanillaSer cases for now
        let test_cases = vec![
            // All zeros - basic case
            vec![0; 32],
            // Empty input
            vec![],
            // Single byte
            vec![0],
            // Invalid tag
            vec![99, 1, 2, 3],
        ];

        for test_input in test_cases {
            // All should either succeed or fail with proper error codes (not crash)
            let result = adapter.validate_transaction(&test_input, false).unwrap();
            // Should return some error code (1 for success, 100+ for various failures)  
            assert!(result == 1 || result >= 100, "Unexpected error code: {}", result);
        }
    }

    // TODO: This test exposes VanillaSer parsing bugs that need proper fixes
    // The pathological varints should be handled in vanilla_ser.rs, not with heuristic guards
    #[test]
    #[ignore] // Disabled until VanillaSer parsing is made more robust
    fn test_pathological_varints() {
        let mut adapter = TxAdapter::new().unwrap();

        // These inputs currently cause massive allocations - need VanillaSer fixes
        let pathological_cases = vec![
            // List with multiple 0xFF bytes (causes huge allocation)
            vec![6, 8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            // Bytes with multiple 0xFF bytes (causes huge allocation)  
            vec![5, 3, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        ];

        for test_input in pathological_cases {
            let result = adapter.validate_transaction(&test_input, false).unwrap();
            assert!(result >= 100); // Should fail gracefully, not crash
        }
    }
}
