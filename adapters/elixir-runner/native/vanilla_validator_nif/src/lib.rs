//! VanillaSer Validation NIF
//!
//! Perform only the pre-decode streaming VanillaSer checks here.
//! Elixir will run its own TX validation logic after this passes.

use rustler::{Atom, Binary};

/// Validation error types - matches the Rust ValidationError enum
#[derive(Debug)]
pub enum ValidationError {
    TooLarge,
    Truncated,
    Overflow,
    NegativeLength,
    DepthExceeded,
    UnknownTag(u8),
    TooManyElements,
    SuspiciousLength,
    Malformed,
}

// Define atoms for error types to match Elixir expectations
mod atoms {
    rustler::atoms! {
        ok,
        error,
        too_large,
        truncated,
        overflow,
        negative_length,
        depth_exceeded,
        unknown_tag,
        too_many_elements,
        suspicious_length,
        malformed,
    }
}



// Expansion bomb detection constants - must match tx_adapter.rs exactly
const MAX_MAGNITUDE_BYTES: u8 = 2;
const MAX_COLLECTION_ELEMENTS: u16 = 1000;

/// Streaming VanillaSer validator that validates without allocating
/// EXACT COPY of VanillaValidator from rust-step/src/vanilla_validator.rs
#[allow(dead_code)]
pub struct VanillaValidator {
    depth: usize,
    element_count: usize,
    max_elements: usize,
    max_bytes: usize,
}

impl VanillaValidator {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            depth: 0,
            element_count: 0,
            max_elements: 32_768,
            max_bytes,
        }
    }

    /// Validate the entire stream without allocating - EXACT COPY
    pub fn validate(&mut self, data: &[u8]) -> Result<(), ValidationError> {
        let mut pos = 0;
        let mut elem_budget = self.max_elements;
        
        while pos < data.len() {
            let consumed = self.validate_value(&data[pos..], 0, &mut elem_budget)?;
            pos += consumed;
        }
        
        Ok(())
    }

    fn validate_value(&self, data: &[u8], depth: usize, elem_budget: &mut usize) -> Result<usize, ValidationError> {
        if depth > 16 {
            return Err(ValidationError::DepthExceeded);
        }
        
        if data.is_empty() {
            return Err(ValidationError::Truncated);
        }
        
        let tag = data[0];
        let mut consumed = 1;
        
        match tag {
            0 => Ok(consumed), // nil
            
            1..=4 => {
                // Integer with magnitude - magnitude represents the integer value, not length to skip
                let (_integer_value, header_size) = self.read_length_header(&data[consumed..])?;
                
                // For integers, header_size already includes the tag byte offset and magnitude bytes
                // We just need to account for the header_size which includes all the magnitude bytes
                consumed += header_size;
                
                Ok(consumed)
            }
            
            5 => {
                // Binary data - apply length limit for allocation safety
                let (data_len, header_size) = self.read_length_header_with_limit(&data[consumed..], 393_216)?;
                consumed += header_size;
                
                if consumed + data_len > data.len() {
                    return Err(ValidationError::Truncated);
                }
                
                consumed += data_len;
                Ok(consumed)
            }
            
            6 => {
                // List - apply count limit
                let (list_len, header_size) = self.read_length_header_with_limit(&data[consumed..], 4_096)?;
                consumed += header_size;
                
                // Check element budget
                if *elem_budget < list_len {
                    return Err(ValidationError::TooManyElements);
                }
                
                *elem_budget -= list_len;
                
                // Validate each element WITHOUT allocating a Vec
                for _ in 0..list_len {
                    let element_consumed = self.validate_value(&data[consumed..], depth + 1, elem_budget)?;
                    consumed += element_consumed;
                }
                
                Ok(consumed)
            }
            
            7 => {
                // Map - apply count limit
                let (map_len, header_size) = self.read_length_header_with_limit(&data[consumed..], 4_096)?;
                consumed += header_size;
                
                let pairs = map_len.checked_mul(2).ok_or(ValidationError::Overflow)?;
                if *elem_budget < pairs {
                    return Err(ValidationError::TooManyElements);
                }
                
                *elem_budget -= pairs;
                
                // Validate key-value pairs
                for _ in 0..map_len {
                    let key_consumed = self.validate_value(&data[consumed..], depth + 1, elem_budget)?;
                    consumed += key_consumed;
                    let value_consumed = self.validate_value(&data[consumed..], depth + 1, elem_budget)?;
                    consumed += value_consumed;
                }
                
                Ok(consumed)
            }
            
            _ => Err(ValidationError::UnknownTag(tag))
        }
    }

    fn read_length_header(&self, data: &[u8]) -> Result<(usize, usize), ValidationError> {
        if data.is_empty() {
            return Err(ValidationError::Truncated);
        }
        
        let b0 = data[0];
        
        if (b0 & 0x80) != 0 {
            return Err(ValidationError::NegativeLength);
        }
        
        let mag_bytes = (b0 & 0x7F) as usize;
        
        // Critical: Reject suspiciously large magnitude byte counts
        if mag_bytes > 4 {
            // No legitimate length needs more than 4 bytes (2^32)
            return Err(ValidationError::SuspiciousLength);
        }
        
        let total_header_size = 1 + mag_bytes;
        
        if data.len() < total_header_size {
            return Err(ValidationError::Truncated);
        }
        
        // Read magnitude bytes
        let mut magnitude = 0u64;
        for i in 0..mag_bytes {
            let byte = data[1 + i];
            
            // Detect overflow BEFORE it happens
            if magnitude > (u64::MAX >> 8) {
                return Err(ValidationError::Overflow);
            }
            
            magnitude = (magnitude << 8) | (byte as u64);
        }
        
        Ok((magnitude as usize, total_header_size))
    }

    fn read_length_header_with_limit(&self, data: &[u8], max_value: usize) -> Result<(usize, usize), ValidationError> {
        let (magnitude, header_size) = self.read_length_header(data)?;
        
        // Apply limit check only when needed (for lengths that will be used for allocation/skipping)
        if magnitude > max_value {
            return Err(ValidationError::TooLarge);
        }
        
        Ok((magnitude, header_size))
    }
}

/// Convenience function for validating VanillaSer data from a byte slice - EXACT COPY
pub fn validate_vanilla(data: &[u8]) -> Result<(), ValidationError> {
    let mut validator = VanillaValidator::new(data.len());
    validator.validate(data)
}



/// Ultra-strict expansion bomb detection - exact copy from tx_adapter.rs
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
                
                // Skip this tag
                i += 1;
            },
            _ => i += 1,
        }
    }
    
    false
}


/// NIF: Pre-decode validation only. Returns {:ok, :ok} or {:error, reason_atom}
#[rustler::nif]
fn validate_vanilla_ser(data: Binary) -> Result<Atom, Atom> {
    // Layer 1: Detect expansion bomb patterns before any parsing
    if detect_expansion_bombs(&data) {
        return Err(atoms::too_large());
    }

    // Layer 2: Streaming VanillaSer validation
    match validate_vanilla(&data) {
        Ok(()) => Ok(atoms::ok()),
        Err(e) => Err(map_validation_error_to_atom(&e)),
    }
}

fn map_validation_error_to_atom(error: &ValidationError) -> Atom {
    match error {
        ValidationError::TooLarge => atoms::too_large(),
        ValidationError::Truncated => atoms::truncated(),
        ValidationError::Overflow => atoms::overflow(),
        ValidationError::NegativeLength => atoms::negative_length(),
        ValidationError::DepthExceeded => atoms::depth_exceeded(),
        ValidationError::UnknownTag(_) => atoms::unknown_tag(),
        ValidationError::TooManyElements => atoms::too_many_elements(),
        ValidationError::SuspiciousLength => atoms::suspicious_length(),
        ValidationError::Malformed => atoms::malformed(),
    }
}

/// Map validation errors to canonical codes (copied from tx_adapter.rs)
fn map_validation_error_to_code(error: &ValidationError) -> u32 {
    match error {
        ValidationError::TooLarge => 122,      // CanonErr::TooLarge
        ValidationError::Truncated => 124,    // CanonErr::Truncated  
        ValidationError::Overflow => 125,     // CanonErr::Overflow
        ValidationError::NegativeLength => 126, // CanonErr::NegativeLen
        ValidationError::DepthExceeded => 127, // CanonErr::DepthExceeded
        ValidationError::UnknownTag(_) => 128, // CanonErr::UnknownTag
        ValidationError::TooManyElements => 122, // CanonErr::TooLarge
        ValidationError::SuspiciousLength => 122, // CanonErr::TooLarge
        ValidationError::Malformed => 123,    // CanonErr::Decode
    }
}

// Register all #[nif] functions for the Elixir module
rustler::init!("Elixir.VanillaValidatorNif");
