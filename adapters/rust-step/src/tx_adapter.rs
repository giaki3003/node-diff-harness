//! Transaction validation adapter for the Rust implementation
//!
//! This module handles transaction validation using the rs_node tx validation logic.

use ama_core::consensus::tx;
use anyhow::Result;

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
        // Hard prelimits to protect against pathological allocations during decode
        // 1) Absolute size guard (parity with Elixir :ama, :tx_size default 393_216)
        const MAX_SAFE_TX_SIZE: usize = 393_216;
        if tx_data.len() > MAX_SAFE_TX_SIZE {
            return Ok(122); // TooLarge
        }

        // 2) Quick structure sanity: avoid inputs with excessive repetition of high bytes
        // Zero bytes are valid (common in padding), but high bytes (0xF0+) with 90%+ repetition
        // are more likely to be malicious varint attacks
        if tx_data.len() >= 64 {
            let first = tx_data[0];
            let identical = tx_data.iter().filter(|b| **b == first).count();
            if identical * 10 >= tx_data.len() * 9 && first >= 0xF0 {
                return Ok(122); // treat as too-large/suspicious to avoid decode
            }
        }

        // 3) Guard against malicious VanillaSer varints that imply huge allocations
        if self.suspicious_vanilla_prefix(tx_data) {
            return Ok(122); // TooLarge-equivalent prefilter
        }

        // 4) Attempt normal validation
        match tx::validate(tx_data, is_special_meeting) {
            Ok(_txu) => Ok(1),
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

    /// Map transaction validation errors to consistent error codes
    /// This allows comparison with Elixir error types
    fn map_error_to_code(&self, error: &tx::Error) -> u32 {
        // Map each error variant to a unique code
        match error {
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
            tx::Error::TooLarge => 122,
            tx::Error::VanillaSer(_) => 123,
        }
    }

    /// Detect egregious length-prefixed allocations in VanillaSer prefix using aggressive heuristics.
    /// Since parsing VanillaSer varints correctly is complex, use multiple heuristics to catch
    /// patterns that are likely to cause massive allocations.
    fn suspicious_vanilla_prefix(&self, bytes: &[u8]) -> bool {
        if bytes.len() < 2 {
            return false;
        }

        let tag = bytes[0];

        // Heuristic 1: Reject any tag 5, 6, or 7 followed by multiple 0xFF bytes
        // This catches many malicious varint patterns
        if matches!(tag, 5 | 6 | 7) && bytes.len() >= 8 {
            let mut ff_count = 0;
            for &byte in &bytes[1..8] {
                if byte == 0xFF {
                    ff_count += 1;
                    if ff_count >= 3 {
                        return true; // Multiple 0xFF bytes = likely massive number
                    }
                } else if byte == 0x00 {
                    break; // Zero byte might terminate the varint
                }
            }
        }

        // Heuristic 2: Conservative varint parsing with very low limits        
        let b0 = bytes[1];
        if b0 == 0 {
            return false; // Zero length is fine
        }
        
        let len_of_mag = (b0 & 0x7F) as usize;
        let sign_bit = (b0 & 0x80) != 0;
        
        // Be extremely conservative: any magnitude > 3 bytes can encode huge numbers
        if len_of_mag > 3 {
            return true;
        }
        
        // Negative lengths are invalid
        if sign_bit {
            return true;
        }
        
        if bytes.len() < 2 + len_of_mag {
            return false; // Can't parse, don't block
        }
        
        // Parse the magnitude with overflow protection
        let mut mag: u64 = 0;
        for &byte in &bytes[2..2 + len_of_mag] {
            if mag > (u64::MAX >> 8) {
                return true; // Would overflow
            }
            mag = (mag << 8) | (byte as u64);
        }
        
        // Use very conservative limits
        match tag {
            5 => mag > 100_000, // Bytes: 100KB max
            6 | 7 => mag > 1_000, // List/Map: 1000 elements max
            _ => false,
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
    fn test_malicious_varint_protection() {
        let mut adapter = TxAdapter::new().unwrap();

        // Test the specific failing case from the fuzzer
        let fuzzer_crash = vec![
            6, 2, 6, 6, 6, 6, 255, 255, 255, 255, 255, 255, 0, 84, 208, 142, 0, 251, 247, 142, 142, 250
        ];
        assert!(adapter.suspicious_vanilla_prefix(&fuzzer_crash));
        let result = adapter.validate_transaction(&fuzzer_crash, false).unwrap();
        assert_eq!(result, 122);

        // Test malicious List (tag 6) with multiple 0xFF bytes  
        let malicious_list = vec![6, 8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(adapter.suspicious_vanilla_prefix(&malicious_list));
        let result = adapter.validate_transaction(&malicious_list, false).unwrap();
        assert_eq!(result, 122);

        // Test malicious Bytes (tag 5) with multiple 0xFF bytes
        let malicious_bytes = vec![5, 3, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(adapter.suspicious_vanilla_prefix(&malicious_bytes));
        let result = adapter.validate_transaction(&malicious_bytes, false).unwrap();
        assert_eq!(result, 122);

        // Test edge case: magnitude length > 3 bytes
        let huge_magnitude = vec![6, 4, 0x10, 0x20, 0x30, 0x40]; // 4-byte magnitude
        assert!(adapter.suspicious_vanilla_prefix(&huge_magnitude));
        let result = adapter.validate_transaction(&huge_magnitude, false).unwrap();
        assert_eq!(result, 122);

        // Test reasonable sizes should not be flagged
        let reasonable = vec![6, 2, 0x00, 0x10, 0, 0, 0, 0]; // List with length 16
        assert!(!adapter.suspicious_vanilla_prefix(&reasonable));
        
        let small_list = vec![6, 1, 0x05, 0, 0, 0, 0, 0]; // List with length 5
        assert!(!adapter.suspicious_vanilla_prefix(&small_list));

        // Test that all-zero transactions are now allowed (fix for differential bug)
        let all_zeros = vec![0; 64];
        let result = adapter.validate_transaction(&all_zeros, false).unwrap();
        assert_ne!(result, 122); // Should not be rejected as "too large"
        
        // Test that high-byte repetition is still caught
        let high_byte_repetition = vec![0xFF; 64];
        let result = adapter.validate_transaction(&high_byte_repetition, false).unwrap();
        assert_eq!(result, 122); // Should be rejected
    }
}
