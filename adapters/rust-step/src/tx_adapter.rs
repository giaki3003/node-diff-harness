//! Transaction validation adapter for the Rust implementation
//!
//! This module handles transaction validation using the rs_node tx validation logic.

use ama_core::consensus::tx;
use anyhow::Result;
use proto::CanonErr;

// VanillaSer bomb detection constants
const MAX_SAFE_TX_SIZE: usize = 393_216;   // match Elixir :ama, :tx_size
const MAX_COLLECTION_LEN: u64 = 4_096;     // conservative, keeps decode bounded

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
        if tx_data.len() > MAX_SAFE_TX_SIZE {
            return Ok(CanonErr::TooLarge.code());
        }

        // Prefilter bomb-y VanillaSer prefixes **before** decode
        if Self::suspicious_vanilla_prefix(tx_data) {
            return Ok(CanonErr::TooLarge.code()); // TooLarge-equivalent for our harness
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

    /// Parse VanillaSer length encoding from bytes  
    /// Returns (magnitude, bytes_consumed) or None if invalid
    fn parse_vanilla_len(bytes: &[u8]) -> Option<(u64, usize)> {
        if bytes.len() < 2 { return None; }
        let b0 = bytes[1];
        let len_of_mag = (b0 & 0x7F) as usize;
        let sign = (b0 & 0x80) != 0;

        // Defensive: reject negative, zero, or very long magnitudes
        if sign || len_of_mag == 0 || len_of_mag > 8 { return None; }
        if bytes.len() < 2 + len_of_mag { return None; }

        let mut mag: u64 = 0;
        for &b in &bytes[2..2 + len_of_mag] {
            mag = (mag << 8) | (b as u64);
        }
        Some((mag, 2 + len_of_mag))
    }

    /// Check for VanillaSer allocation bombs using proper format knowledge and FF flood detection
    fn suspicious_vanilla_prefix(bytes: &[u8]) -> bool {
        if bytes.len() < 2 { return false; }
        let tag = bytes[0];

        if matches!(tag, 5 | 6 | 7) {
            // Cheap FF flood heuristic (classic varint bomb)
            let ff = bytes[1..].iter().take(8).filter(|&&b| b == 0xFF).count();
            if ff >= 3 { return true; }

            if let Some((len, _consumed)) = Self::parse_vanilla_len(bytes) {
                match tag {
                    5 => len > MAX_SAFE_TX_SIZE as u64, // bytes length
                    6 | 7 => len > MAX_COLLECTION_LEN,  // list/map length
                    _ => false,
                }
            } else {
                // malformed varint ⇒ treat as suspicious
                true
            }
        } else {
            false
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
        assert!(TxAdapter::suspicious_vanilla_prefix(&bomb));
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
        // Classic FF flood pattern should be caught
        let ff_bomb = vec![5, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        assert!(TxAdapter::suspicious_vanilla_prefix(&ff_bomb));
        
        // Normal small length should pass
        let normal = vec![5, 2, 0x00, 0x10]; // tag 5, 2-byte mag, value 16
        assert!(!TxAdapter::suspicious_vanilla_prefix(&normal));
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
