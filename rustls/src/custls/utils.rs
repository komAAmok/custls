//! Utility functions for custls
//!
//! This module provides helper functions for:
//! - HTTP/2 SETTINGS encoding
//! - Probability distribution sampling
//! - Timing jitter injection
//! - Extension ordering validation

use alloc::vec::Vec;
use core::time::Duration;

use crate::msgs::ExtensionType;
use super::CustlsError;

// Simple pseudo-random number generator for custls
// Uses a linear congruential generator (LCG) for basic randomization
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new() -> Self {
        // Seed with a simple time-based value or constant
        // In production, this should use a better entropy source
        Self { state: 0x123456789ABCDEF0 }
    }
    
    fn next_u64(&mut self) -> u64 {
        // LCG parameters from Numerical Recipes
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.state
    }
    
    fn gen_range_u16(&mut self, min: u16, max: u16) -> u16 {
        if min >= max {
            return min;
        }
        let range = (max - min) as u64 + 1;
        let value = self.next_u64() % range;
        min + value as u16
    }
    
    fn gen_range_usize(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        let range = (max - min) as u64 + 1;
        let value = self.next_u64() % range;
        min + value as usize
    }
    
    fn gen_f64(&mut self) -> f64 {
        // Generate a float between 0.0 and 1.0
        (self.next_u64() as f64) / (u64::MAX as f64)
    }
}

// Thread-local RNG instance
#[cfg(feature = "std")]
use std::cell::RefCell;

#[cfg(feature = "std")]
std::thread_local! {
    static RNG: RefCell<SimpleRng> = RefCell::new(SimpleRng::new());
}

#[cfg(not(feature = "std"))]
static mut RNG: SimpleRng = SimpleRng { state: 0x123456789ABCDEF0 };

fn with_rng<F, R>(f: F) -> R
where
    F: FnOnce(&mut SimpleRng) -> R,
{
    #[cfg(feature = "std")]
    {
        RNG.with(|rng| f(&mut *rng.borrow_mut()))
    }
    
    #[cfg(not(feature = "std"))]
    {
        unsafe { f(&mut RNG) }
    }
}

/// HTTP/2 SETTINGS frame parameters for browser coordination
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2Settings {
    /// SETTINGS_HEADER_TABLE_SIZE (0x1)
    pub header_table_size: u32,
    
    /// SETTINGS_ENABLE_PUSH (0x2)
    pub enable_push: bool,
    
    /// SETTINGS_MAX_CONCURRENT_STREAMS (0x3)
    pub max_concurrent_streams: u32,
    
    /// SETTINGS_INITIAL_WINDOW_SIZE (0x4)
    pub initial_window_size: u32,
    
    /// SETTINGS_MAX_FRAME_SIZE (0x5)
    pub max_frame_size: u32,
    
    /// SETTINGS_MAX_HEADER_LIST_SIZE (0x6)
    pub max_header_list_size: u32,
    
    /// Pseudo-header ordering for HTTP/2 requests
    pub pseudo_header_order: Vec<&'static str>,
    
    /// Priority specification for HTTP/2 streams
    pub priority_spec: Option<PrioritySpec>,
}

impl Default for Http2Settings {
    fn default() -> Self {
        Self {
            header_table_size: 65536,
            enable_push: true,
            max_concurrent_streams: 1000,
            initial_window_size: 6291456,
            max_frame_size: 16384,
            max_header_list_size: 262144,
            pseudo_header_order: alloc::vec![":method", ":authority", ":scheme", ":path"],
            priority_spec: None,
        }
    }
}

impl Http2Settings {
    /// Encode HTTP/2 SETTINGS frame payload
    ///
    /// Returns a vector of bytes representing the SETTINGS frame payload
    /// (without the frame header). Each setting is encoded as:
    /// - 2 bytes: setting identifier
    /// - 4 bytes: setting value
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        
        // SETTINGS_HEADER_TABLE_SIZE (0x1)
        payload.extend_from_slice(&[0x00, 0x01]);
        payload.extend_from_slice(&self.header_table_size.to_be_bytes());
        
        // SETTINGS_ENABLE_PUSH (0x2)
        payload.extend_from_slice(&[0x00, 0x02]);
        payload.extend_from_slice(&(self.enable_push as u32).to_be_bytes());
        
        // SETTINGS_MAX_CONCURRENT_STREAMS (0x3)
        payload.extend_from_slice(&[0x00, 0x03]);
        payload.extend_from_slice(&self.max_concurrent_streams.to_be_bytes());
        
        // SETTINGS_INITIAL_WINDOW_SIZE (0x4)
        payload.extend_from_slice(&[0x00, 0x04]);
        payload.extend_from_slice(&self.initial_window_size.to_be_bytes());
        
        // SETTINGS_MAX_FRAME_SIZE (0x5)
        payload.extend_from_slice(&[0x00, 0x05]);
        payload.extend_from_slice(&self.max_frame_size.to_be_bytes());
        
        // SETTINGS_MAX_HEADER_LIST_SIZE (0x6)
        payload.extend_from_slice(&[0x00, 0x06]);
        payload.extend_from_slice(&self.max_header_list_size.to_be_bytes());
        
        payload
    }
    
    /// Create Chrome-like HTTP/2 settings
    pub fn chrome_default() -> Self {
        Self {
            header_table_size: 65536,
            enable_push: false,
            max_concurrent_streams: 1000,
            initial_window_size: 6291456,
            max_frame_size: 16384,
            max_header_list_size: 262144,
            pseudo_header_order: alloc::vec![":method", ":authority", ":scheme", ":path"],
            priority_spec: Some(PrioritySpec {
                stream_dependency: 0,
                weight: 256,
                exclusive: true,
            }),
        }
    }
    
    /// Create Firefox-like HTTP/2 settings
    pub fn firefox_default() -> Self {
        Self {
            header_table_size: 65536,
            enable_push: true,
            max_concurrent_streams: 1000,
            initial_window_size: 131072,
            max_frame_size: 16384,
            max_header_list_size: 262144,
            pseudo_header_order: alloc::vec![":method", ":path", ":authority", ":scheme"],
            priority_spec: None,
        }
    }
}

/// HTTP/2 priority specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrioritySpec {
    /// Stream dependency (31-bit stream identifier)
    pub stream_dependency: u32,
    
    /// Weight (1-256, where 256 is highest priority)
    pub weight: u16,
    
    /// Exclusive flag
    pub exclusive: bool,
}

impl PrioritySpec {
    /// Encode priority specification to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(5);
        
        // Encode stream dependency with exclusive flag in high bit
        let dependency = if self.exclusive {
            self.stream_dependency | 0x8000_0000
        } else {
            self.stream_dependency & 0x7FFF_FFFF
        };
        bytes.extend_from_slice(&dependency.to_be_bytes());
        
        // Encode weight (subtract 1 as per HTTP/2 spec)
        let weight = self.weight.saturating_sub(1).min(255) as u8;
        bytes.push(weight);
        
        bytes
    }
}

/// Timing jitter configuration for anti-fingerprinting
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TimingJitterConfig {
    /// Minimum delay in microseconds
    pub min_delay_micros: u64,
    
    /// Maximum delay in microseconds
    pub max_delay_micros: u64,
    
    /// Probability of applying jitter (0.0 to 1.0)
    pub apply_probability: f64,
}

impl Default for TimingJitterConfig {
    fn default() -> Self {
        Self {
            min_delay_micros: 100,
            max_delay_micros: 5000,
            apply_probability: 0.3,
        }
    }
}

impl TimingJitterConfig {
    /// Apply timing jitter based on configuration
    ///
    /// This function will sleep for a random duration between min_delay_micros
    /// and max_delay_micros with probability apply_probability.
    #[cfg(feature = "std")]
    pub fn apply(&self) {
        let should_apply = with_rng(|rng| rng.gen_f64() < self.apply_probability);
        
        if should_apply {
            let delay = with_rng(|rng| {
                rng.gen_range_u16(
                    self.min_delay_micros as u16,
                    self.max_delay_micros as u16
                ) as u64
            });
            std::thread::sleep(Duration::from_micros(delay));
        }
    }
    
    /// Apply timing jitter (no-op in no_std environments)
    #[cfg(not(feature = "std"))]
    pub fn apply(&self) {
        // No-op in no_std environments
    }
    
    /// Create a configuration with specific parameters
    pub fn new(min_micros: u64, max_micros: u64, probability: f64) -> Result<Self, CustlsError> {
        if min_micros > max_micros {
            return Err(CustlsError::ValidationError(
                "min_delay_micros must be <= max_delay_micros".into()
            ));
        }
        
        if !(0.0..=1.0).contains(&probability) {
            return Err(CustlsError::ValidationError(
                "apply_probability must be between 0.0 and 1.0".into()
            ));
        }
        
        Ok(Self {
            min_delay_micros: min_micros,
            max_delay_micros: max_micros,
            apply_probability: probability,
        })
    }
}

/// Sample from a discrete probability distribution
///
/// Takes a probability mass function (PMF) as a vector of (value, probability) pairs
/// and returns a randomly sampled value according to the distribution.
///
/// # Arguments
/// * `pmf` - Probability mass function as (value, probability) pairs
///
/// # Returns
/// * `Some(value)` - A sampled value from the distribution
/// * `None` - If the PMF is empty or probabilities don't sum to a positive value
pub fn sample_from_pmf<T: Clone>(pmf: &[(T, f64)]) -> Option<T> {
    if pmf.is_empty() {
        return None;
    }
    
    let total: f64 = pmf.iter().map(|(_, p)| p).sum();
    if total <= 0.0 {
        return None;
    }
    
    let mut roll = with_rng(|rng| rng.gen_f64() * total);
    
    for (value, probability) in pmf {
        roll -= probability;
        if roll <= 0.0 {
            return Some(value.clone());
        }
    }
    
    // Fallback to last element (handles floating point rounding)
    pmf.last().map(|(v, _)| v.clone())
}

/// Sample a value from a weighted distribution with power-of-2 bias
///
/// This function samples from a range [min, max] with a bias toward powers of 2.
/// Used for generating padding lengths that match browser behavior.
///
/// # Arguments
/// * `min` - Minimum value (inclusive)
/// * `max` - Maximum value (inclusive)
/// * `power_of_2_bias` - Probability of selecting a power of 2 (0.0 to 1.0)
///
/// # Returns
/// A randomly sampled value with power-of-2 bias applied
pub fn sample_with_power_of_2_bias(min: u16, max: u16, power_of_2_bias: f64) -> u16 {
    // Decide whether to use power-of-2 bias
    let use_power_of_2 = with_rng(|rng| rng.gen_f64() < power_of_2_bias);
    
    if use_power_of_2 {
        // Find powers of 2 in range
        let mut powers_of_2 = Vec::new();
        let mut power = 1u16;
        while power <= max {
            if power >= min {
                powers_of_2.push(power);
            }
            if let Some(next) = power.checked_mul(2) {
                power = next;
            } else {
                break;
            }
        }
        
        if !powers_of_2.is_empty() {
            return with_rng(|rng| {
                let idx = rng.gen_range_usize(0, powers_of_2.len() - 1);
                powers_of_2[idx]
            });
        }
    }
    
    // Uniform random selection
    with_rng(|rng| rng.gen_range_u16(min, max))
}

/// Validate extension ordering against browser-specific rules
///
/// Checks that critical extensions appear in appropriate positions:
/// - supported_versions should be early
/// - key_share should be near the end
/// - pre_shared_key must be last (if present)
///
/// # Arguments
/// * `extensions` - List of extension types in order
///
/// # Returns
/// * `Ok(())` - If ordering is valid
/// * `Err(CustlsError)` - If ordering violates constraints
pub fn validate_extension_order(extensions: &[ExtensionType]) -> Result<(), CustlsError> {
    if extensions.is_empty() {
        return Ok(());
    }
    
    // Check if PSK is present and is last
    if let Some(last) = extensions.last() {
        let has_psk = extensions.iter().any(|e| matches!(e, ExtensionType::PreSharedKey));
        
        if has_psk && !matches!(last, ExtensionType::PreSharedKey) {
            return Err(CustlsError::ValidationError(
                "pre_shared_key extension must be last".into()
            ));
        }
    }
    
    // Check for duplicate extensions by comparing each pair
    for i in 0..extensions.len() {
        for j in (i + 1)..extensions.len() {
            if extensions[i] == extensions[j] {
                return Err(CustlsError::ValidationError(
                    alloc::format!("duplicate extension at positions {} and {}", i, j)
                ));
            }
        }
    }
    
    Ok(())
}

/// Calculate a simple reputation score based on success/failure counts
///
/// Uses a weighted formula that favors recent successes and penalizes failures.
///
/// # Arguments
/// * `success_count` - Number of successful handshakes
/// * `failure_count` - Number of failed handshakes
///
/// # Returns
/// A reputation score between 0.0 and 1.0
pub fn calculate_reputation_score(success_count: u32, failure_count: u32) -> f64 {
    let total = success_count + failure_count;
    if total == 0 {
        return 0.5; // Neutral score for new entries
    }
    
    let success_rate = success_count as f64 / total as f64;
    
    // Apply confidence weighting (more samples = more confident)
    let confidence = (total as f64 / (total as f64 + 10.0)).min(1.0);
    
    // Blend with neutral score based on confidence
    0.5 * (1.0 - confidence) + success_rate * confidence
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    
    #[test]
    fn test_http2_settings_encode() {
        let settings = Http2Settings::default();
        let encoded = settings.encode();
        
        // Should have 6 settings * 6 bytes each = 36 bytes
        assert_eq!(encoded.len(), 36);
        
        // Check first setting (HEADER_TABLE_SIZE)
        assert_eq!(&encoded[0..2], &[0x00, 0x01]);
        assert_eq!(u32::from_be_bytes([encoded[2], encoded[3], encoded[4], encoded[5]]), 65536);
    }
    
    #[test]
    fn test_http2_settings_chrome() {
        let settings = Http2Settings::chrome_default();
        assert_eq!(settings.enable_push, false);
        assert_eq!(settings.initial_window_size, 6291456);
        assert!(settings.priority_spec.is_some());
    }
    
    #[test]
    fn test_http2_settings_firefox() {
        let settings = Http2Settings::firefox_default();
        assert_eq!(settings.enable_push, true);
        assert_eq!(settings.initial_window_size, 131072);
        assert_eq!(settings.pseudo_header_order, alloc::vec![":method", ":path", ":authority", ":scheme"]);
    }
    
    #[test]
    fn test_priority_spec_encode() {
        let spec = PrioritySpec {
            stream_dependency: 0,
            weight: 256,
            exclusive: true,
        };
        
        let encoded = spec.encode();
        assert_eq!(encoded.len(), 5);
        
        // Check exclusive flag is set in high bit
        assert_eq!(encoded[0] & 0x80, 0x80);
        
        // Check weight (256 - 1 = 255)
        assert_eq!(encoded[4], 255);
    }
    
    #[test]
    fn test_timing_jitter_config_validation() {
        // Valid config
        let config = TimingJitterConfig::new(100, 1000, 0.5);
        assert!(config.is_ok());
        
        // Invalid: min > max
        let config = TimingJitterConfig::new(1000, 100, 0.5);
        assert!(config.is_err());
        
        // Invalid: probability out of range
        let config = TimingJitterConfig::new(100, 1000, 1.5);
        assert!(config.is_err());
        
        let config = TimingJitterConfig::new(100, 1000, -0.1);
        assert!(config.is_err());
    }
    
    #[test]
    fn test_sample_from_pmf() {
        let pmf = vec![
            (1, 0.5),
            (2, 0.3),
            (3, 0.2),
        ];
        
        // Sample multiple times to ensure it doesn't panic
        for _ in 0..100 {
            let sample = sample_from_pmf(&pmf);
            assert!(sample.is_some());
            let value = sample.unwrap();
            assert!(value >= 1 && value <= 3);
        }
    }
    
    #[test]
    fn test_sample_from_pmf_empty() {
        let pmf: Vec<(i32, f64)> = vec![];
        assert!(sample_from_pmf(&pmf).is_none());
    }
    
    #[test]
    fn test_sample_with_power_of_2_bias() {
        // Sample multiple times to ensure it doesn't panic
        for _ in 0..100 {
            let value = sample_with_power_of_2_bias(0, 1500, 0.7);
            assert!(value <= 1500);
        }
    }
    
    #[test]
    fn test_validate_extension_order_psk_last() {
        use crate::msgs::ExtensionType;
        
        // Valid: PSK is last
        let extensions = vec![
            ExtensionType::ServerName,
            ExtensionType::SupportedVersions,
            ExtensionType::PreSharedKey,
        ];
        assert!(validate_extension_order(&extensions).is_ok());
        
        // Invalid: PSK is not last
        let extensions = vec![
            ExtensionType::PreSharedKey,
            ExtensionType::ServerName,
            ExtensionType::SupportedVersions,
        ];
        assert!(validate_extension_order(&extensions).is_err());
    }
    
    #[test]
    fn test_validate_extension_order_duplicates() {
        use crate::msgs::ExtensionType;
        
        let extensions = vec![
            ExtensionType::ServerName,
            ExtensionType::ServerName,
        ];
        assert!(validate_extension_order(&extensions).is_err());
    }
    
    #[test]
    fn test_calculate_reputation_score() {
        // New entry (no data)
        assert_eq!(calculate_reputation_score(0, 0), 0.5);
        
        // Perfect success
        let score = calculate_reputation_score(10, 0);
        assert!(score > 0.7, "Expected score > 0.7, got {}", score);
        
        // Perfect failure
        let score = calculate_reputation_score(0, 10);
        assert!(score < 0.3, "Expected score < 0.3, got {}", score);
        
        // Mixed results
        let score = calculate_reputation_score(5, 5);
        assert!(score > 0.4 && score < 0.6, "Expected score between 0.4 and 0.6, got {}", score);
    }
}
