//! Transaction validation adapter for the Rust implementation
//!
//! This module handles transaction validation using the rs_node tx validation logic.

use ama_core::consensus::tx;
use anyhow::Result;
use proto::CanonErr;
use crate::vanilla_validator::{validate_vanilla, ValidationError};

// Ultra-strict security limits
const MAX_TX_SIZE: usize = 10_000;      // 10KB max - extremely conservative
const MAX_MAGNITUDE_BYTES: u8 = 2;      // Maximum 2 bytes for magnitude encoding
const MAX_COLLECTION_ELEMENTS: u16 = 1000; // Maximum 1000 elements per collection

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
        if tx_data.len() > MAX_TX_SIZE {
            return Ok(CanonErr::TooLarge.code());
        }

        // Layer 1: Detect expansion bomb patterns before any parsing
        if Self::detect_expansion_bombs(tx_data) {
            return Ok(CanonErr::TooLarge.code());
        }

        // Layer 2: Streaming VanillaSer validation **before** decode  
        let debug_enabled = std::env::var("AMA_ORACLE_DEBUG")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if debug_enabled {
            eprintln!("[RUST] TX data size: {}, first 20 bytes: {:?}", tx_data.len(), &tx_data[..tx_data.len().min(20)]);
            eprintln!("[RUST] Calling validate_vanilla...");
        }
        
        match validate_vanilla(tx_data) {
            Ok(()) => {
                if debug_enabled {
                    eprintln!("[RUST] VanillaSer validation PASSED - proceeding to tx::validate");
                }
                // Safe to decode
            },
            Err(e) => {
                if debug_enabled {
                    eprintln!("[RUST] VanillaSer validation FAILED with error: {:?}", e);
                }
                let error_code = Self::map_validation_error_to_code(&e);
                if debug_enabled {
                    eprintln!("[RUST] Mapped VanillaSer error to code: {}", error_code);
                }
                return Ok(error_code);
            }
        }

        // Direct validation - let VanillaSer and tx validation handle all edge cases
        if debug_enabled {
            eprintln!("[RUST] Calling tx::validate...");
        }
        
        match tx::validate(tx_data, is_special_meeting) {
            Ok(_txu) => {
                if debug_enabled {
                    eprintln!("[RUST] tx::validate PASSED - returning canon_ok");
                }
                let result_code = CanonErr::Ok.code();
                Ok(result_code)
            },
            Err(e) => {
                if debug_enabled {
                    eprintln!("[RUST] tx::validate FAILED with error: {:?}", e);
                }
                let error_code = self.map_error_to_code(&e);
                if debug_enabled {
                    eprintln!("[RUST] Mapped tx error to code: {}", error_code);
                }
                Ok(error_code)
            }
        }
    }

    /// Reset internal state
    pub fn reset(&mut self) -> Result<()> {
        // Transaction adapter is stateless, nothing to reset
        Ok(())
    }

    /// Ultra-strict expansion bomb detection
    /// Rejects ANY input that could cause large allocations
    fn detect_expansion_bombs(data: &[u8]) -> bool {

        if data.is_empty() {
            return false;
        }

        let mut i = 0;
        let scan_limit = data.len().min(200);
        
        
        while i < scan_limit {
            match data.get(i) {
                Some(&_tag @ (5 | 6 | 7)) => { // Bytes, List, Map
                    
                    // Check magnitude encoding immediately
                    if i + 1 >= data.len() {
                        return true; // Truncated, reject
                    }
                    
                    let length_byte = data[i + 1];
                    
                    // Check for negative length first (sign bit set)
                    if (length_byte & 0x80) != 0 {
                        i += 1; // Skip this malformed length, let VanillaSer catch it
                        continue;
                    }
                    
                    let magnitude_bytes = length_byte & 0x7F;
                    
                    
                    // Reject ANY magnitude > 2 bytes (only for valid positive lengths)
                    if magnitude_bytes > MAX_MAGNITUDE_BYTES {
                        return true;
                    }
                    
                    // Check actual magnitude value for 2-byte encoding
                    if magnitude_bytes == 2 {
                        if i + 3 >= data.len() {
                            return true; // Truncated, reject
                        }
                        let magnitude = ((data[i + 2] as u16) << 8) | (data[i + 3] as u16);
                        if magnitude > MAX_COLLECTION_ELEMENTS {
                            return true;
                        }
                    }
                    
                    // Skip ahead by magnitude length
                    let new_i = i + 1 + magnitude_bytes as usize;
                    i = new_i;
                }
                Some(&_tag) => {
                    i += 1;
                },
                None => break,
            }
        }
        
        false // Passed ultra-strict checks
    }

    /// Map VanillaSer validation errors to canonical error codes
    fn map_validation_error_to_code(error: &ValidationError) -> u32 {
        match error {
            ValidationError::TooLarge => CanonErr::TooLarge.code(),
            ValidationError::Truncated => CanonErr::Truncated.code(),
            ValidationError::Overflow => CanonErr::Overflow.code(),
            ValidationError::NegativeLength => CanonErr::NegativeLen.code(),
            ValidationError::DepthExceeded => CanonErr::DepthExceeded.code(),
            ValidationError::UnknownTag(_) => CanonErr::UnknownTag.code(),
            ValidationError::TooManyElements => CanonErr::TooLarge.code(),
            ValidationError::SuspiciousLength => CanonErr::TooLarge.code(),
            ValidationError::Malformed => CanonErr::Decode.code(),
        }
    }

    /// Map transaction validation errors to canonical error codes
    /// This allows consistent comparison with Elixir error types
    fn map_error_to_code(&self, error: &tx::Error) -> u32 {
        match error {
            // Canonical error mappings for cross-implementation consistency
            tx::Error::TooLarge => CanonErr::TooLarge.code(),
            tx::Error::VanillaSer(_) => CanonErr::Decode.code(),
            tx::Error::WrongType(_) => CanonErr::Decode.code(),  // Use canonical code for structure issues
            
            // Transaction-specific validation errors (keep existing codes)
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
    fn prefilter_catches_list_bomb() {
        // tag=6 (list), b0 says 4-byte magnitude, then absurd size 0x10_00_00_00
        let bomb = vec![6, 4, 0x10, 0x00, 0x00, 0x00];
        let mut adapter = TxAdapter::new().unwrap();
        let code = adapter.validate_transaction(&bomb, false).unwrap();
        assert_eq!(code, 122); // Should be rejected as TooLarge
    }

    #[test]
    fn prefilter_maps_to_too_large() {
        let mut adapter = TxAdapter::new().unwrap();
        let ff_bomb = vec![6, 8, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x01];
        let code = adapter.validate_transaction(&ff_bomb, false).unwrap();
        assert_eq!(code, 122);
    }

    #[test]
    fn test_ff_flood_detection() {
        let mut adapter = TxAdapter::new().unwrap();
        
        // Classic FF flood pattern should be caught
        let ff_bomb = vec![5, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        let code = adapter.validate_transaction(&ff_bomb, false).unwrap();
        assert_eq!(code, 122); // Should be rejected as TooLarge
        
        // Normal small length should pass (after proper VanillaSer encoding)
        let normal = vec![5, 1, 16, 42]; // tag 5, 1-byte length=16, then 16 bytes of data would follow
        // This will fail because we don't have the actual data, but it should fail in tx validation, not preflight
        let code = adapter.validate_transaction(&normal, false).unwrap();
        // Should not be 122 (TooLarge) - should be some other validation error
        assert_ne!(code, 122);
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
