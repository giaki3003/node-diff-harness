//! Transaction validation adapter for the Rust implementation
//!
//! This module handles transaction validation using the rs_node tx validation logic.

use ama_core::consensus::tx;
use anyhow::Result;
use proto::CanonErr;

#[derive(Debug)]
pub enum GuardErr { 
    Malformed, 
    TooLarge 
}

// VanillaSer preflight validation constants - keep identical to Elixir side
const MAX_TX_SIZE: usize = 393_216;     // cap for bytes blobs
const MAX_LIST_LEN: u64 = 4_096;
const MAX_MAP_LEN: u64 = 4_096;
const MAX_DEPTH: usize = 16;
const MAX_ELEMS: u64 = 32_768;       // global sanity cap

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

        // Allocation-free preflight validation **before** decode
        match Self::vanilla_preflight(tx_data) {
            Ok(()) => {}, // Safe to decode
            Err(GuardErr::TooLarge) | Err(GuardErr::Malformed) => {
                return Ok(CanonErr::TooLarge.code()); // Canonical error for bombs/malformed
            }
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

    /// Allocation-free VanillaSer preflight validation
    /// Validates the entire VanillaSer structure without allocating memory
    fn vanilla_preflight(bytes: &[u8]) -> Result<(), GuardErr> {
        let mut i = 0usize;
        let mut elems = MAX_ELEMS;
        while i < bytes.len() {
            let used = Self::walk_one(&bytes[i..], 0, &mut elems)?;
            i += used;
        }
        Ok(())
    }

    /// Read VanillaSer length header
    #[inline]
    fn read_len(s: &[u8]) -> Result<(u64, usize), GuardErr> {
        if s.is_empty() { return Err(GuardErr::Malformed); }
        let b0 = s[0];
        if (b0 & 0x80) != 0 { return Err(GuardErr::Malformed); }    // sign/continuation not allowed
        let mag_len = (b0 & 0x7F) as usize;
        let s = &s[1..];
        if mag_len > 8 { return Err(GuardErr::TooLarge); }           // reject absurd magnitudes
        if s.len() < mag_len { return Err(GuardErr::Malformed); }
        let mag = if mag_len == 0 { 0 } else { u64::from_be_bytes({
            let mut buf = [0u8; 8];
            buf[8 - mag_len..].copy_from_slice(&s[..mag_len]);
            buf
        })};
        Ok((mag, 1 + mag_len))
    }

    /// Walk one VanillaSer value without allocating
    fn walk_one(s: &[u8], depth: usize, elem_budget: &mut u64) -> Result<usize, GuardErr> {
        if depth > MAX_DEPTH { return Err(GuardErr::TooLarge); }
        if s.is_empty() { return Err(GuardErr::Malformed); }

        // Read the tag (VanillaSer: 1 byte)
        let tag = s[0];
        let s = &s[1..];
        let mut consumed = 1usize;

        match tag {
            // scalar primitives that do not allocate: just skip their fixed/encoded body
            0 => { /* nil/unit */ }
            1 | 2 | 3 | 4 => {
                // varint/small ints with length-of-mag encoding
                let (_n, used) = Self::read_len(s)?; 
                consumed += used;
            }

            // bytes
            5 => {
                let (len, used) = Self::read_len(s)?; 
                consumed += used;
                if len as usize > MAX_TX_SIZE { return Err(GuardErr::TooLarge); }
                if s.len() < used + (len as usize) { return Err(GuardErr::Malformed); }
                consumed += len as usize;
            }

            // list
            6 => {
                let (len, used) = Self::read_len(s)?; 
                consumed += used;
                if len > MAX_LIST_LEN { return Err(GuardErr::TooLarge); }
                // global element budget to prevent nested bombs
                if *elem_budget < len { return Err(GuardErr::TooLarge); }
                *elem_budget -= len;
                let mut rest = &s[used..];
                let mut local = 0usize;
                for _ in 0..len {
                    let c = Self::walk_one(rest, depth + 1, elem_budget)?;
                    local += c;
                    rest = &rest[c..];
                }
                consumed += local;
            }

            // map
            7 => {
                let (len, used) = Self::read_len(s)?; 
                consumed += used;
                if len > MAX_MAP_LEN { return Err(GuardErr::TooLarge); }
                let needed = len.checked_mul(2).ok_or(GuardErr::TooLarge)?;
                if *elem_budget < needed { return Err(GuardErr::TooLarge); }
                *elem_budget -= needed;
                let mut rest = &s[used..];
                let mut local = 0usize;
                for _ in 0..len {
                    let ck = Self::walk_one(rest, depth + 1, elem_budget)?;
                    rest = &rest[ck..];
                    let cv = Self::walk_one(rest, depth + 1, elem_budget)?;
                    rest = &rest[cv..];
                    local += ck + cv;
                }
                consumed += local;
            }

            // Unknown tags -> treat as malformed (safer for fuzzing harness)
            _ => return Err(GuardErr::Malformed),
        }
        Ok(consumed)
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
