//! Result normalizer for consistent comparison between implementations
//!
//! This module handles normalizing results from different operations to ensure
//! meaningful comparison between Rust and Elixir implementations.

use sha2::{Digest, Sha256};

/// Normalizer for execution results
pub struct Normalizer {
    // Future: could hold normalization configuration
}

impl Normalizer {
    pub fn new() -> Self {
        Self {}
    }

    /// Normalize binary data for comparison
    pub fn normalize_binary(&self, data: &[u8]) -> Vec<u8> {
        // For now, just return the data as-is
        // Future enhancements could include:
        // - Sorting map keys in ETF data
        // - Normalizing timestamps to fixed values
        // - Canonicalizing floating-point representations
        data.to_vec()
    }

    /// Normalize protocol message output
    pub fn normalize_protocol_message(&self, etf_data: &[u8]) -> Vec<u8> {
        // Hash the ETF data to create a stable digest
        // This abstracts away internal representation differences
        let mut hasher = Sha256::new();
        hasher.update(b"protocol:");
        hasher.update(etf_data);
        hasher.finalize().to_vec()
    }

    /// Normalize transaction validation result
    pub fn normalize_tx_result(&self, result_code: u32) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"tx_result:");
        hasher.update(&result_code.to_le_bytes());
        hasher.finalize().to_vec()
    }

    /// Normalize error messages for comparison
    pub fn normalize_error(&self, error: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"error:");

        // Normalize common error message variations
        let normalized_error = self.normalize_error_message(error);
        hasher.update(normalized_error.as_bytes());

        hasher.finalize().to_vec()
    }

    /// Normalize error message text to handle implementation differences
    fn normalize_error_message(&self, error: &str) -> String {
        let lower = error.to_lowercase();

        // Map common error patterns to canonical forms
        if lower.contains("signature") && lower.contains("invalid") {
            "invalid_signature".to_string()
        } else if lower.contains("hash") && lower.contains("invalid") {
            "invalid_hash".to_string()
        } else if lower.contains("nonce") {
            if lower.contains("integer") {
                "nonce_not_integer".to_string()
            } else if lower.contains("high") || lower.contains("too") {
                "nonce_too_high".to_string()
            } else {
                "nonce_error".to_string()
            }
        } else if lower.contains("action") {
            if lower.contains("list") {
                "actions_must_be_list".to_string()
            } else if lower.contains("length") || lower.contains("1") {
                "actions_length_must_be_1".to_string()
            } else {
                "actions_error".to_string()
            }
        } else if lower.contains("canonical") {
            "tx_not_canonical".to_string()
        } else if lower.contains("too") && lower.contains("large") {
            "too_large".to_string()
        } else {
            // Return a hash of the original error for unknown patterns
            let hash = Sha256::digest(error.as_bytes());
            format!(
                "unknown_error_{:08x}",
                hash[0..4].iter().fold(0u32, |acc, &b| acc << 8 | b as u32)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_normalization() {
        let normalizer = Normalizer::new();
        let data = b"test data";
        let normalized = normalizer.normalize_binary(data);
        assert_eq!(normalized, data.to_vec());
    }

    #[test]
    fn test_protocol_message_normalization() {
        let normalizer = Normalizer::new();
        let data1 = b"some etf data";
        let data2 = b"some etf data";
        let data3 = b"different etf data";

        let norm1 = normalizer.normalize_protocol_message(data1);
        let norm2 = normalizer.normalize_protocol_message(data2);
        let norm3 = normalizer.normalize_protocol_message(data3);

        assert_eq!(norm1, norm2); // Same data should normalize to same result
        assert_ne!(norm1, norm3); // Different data should normalize differently
    }

    #[test]
    fn test_tx_result_normalization() {
        let normalizer = Normalizer::new();

        let valid_result = normalizer.normalize_tx_result(1);
        let invalid_result = normalizer.normalize_tx_result(102);

        assert_ne!(valid_result, invalid_result);
        assert_eq!(valid_result, normalizer.normalize_tx_result(1)); // Deterministic
    }

    #[test]
    fn test_error_normalization() {
        let normalizer = Normalizer::new();

        // Test canonical error mappings
        assert_eq!(
            normalizer.normalize_error_message("Invalid signature detected"),
            "invalid_signature"
        );
        assert_eq!(
            normalizer.normalize_error_message("INVALID HASH"),
            "invalid_hash"
        );
        assert_eq!(
            normalizer.normalize_error_message("nonce not integer"),
            "nonce_not_integer"
        );
        assert_eq!(
            normalizer.normalize_error_message("nonce too high"),
            "nonce_too_high"
        );

        // Test unknown error handling
        let unknown = normalizer.normalize_error_message("some weird error");
        assert!(unknown.starts_with("unknown_error_"));
    }

    #[test]
    fn test_error_hash_consistency() {
        let normalizer = Normalizer::new();

        let error1 = normalizer.normalize_error("invalid signature");
        let error2 = normalizer.normalize_error("Invalid Signature");
        let error3 = normalizer.normalize_error("signature is invalid");

        // All should normalize to the same canonical form
        assert_eq!(error1, error2);
        assert_eq!(error2, error3);
    }
}
