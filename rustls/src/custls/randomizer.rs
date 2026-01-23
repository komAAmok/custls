//! Browser-style randomization engine for ClientHello generation
//!
//! This module provides the `BrowserRandomizer` struct, which applies non-uniform
//! randomization to ClientHello components to match real browser behavior patterns.
//!
//! ## Design Philosophy
//!
//! Real browsers don't use uniform random distributions. They exhibit specific patterns:
//! - Extension ordering follows grouped constraints (critical, standard, optional)
//! - GREASE values appear in preferred positions (Chrome: front third)
//! - Padding lengths favor powers of 2 and common browser values
//! - Extension combinations must pass naturalness filtering
//!
//! ## Randomization Levels
//!
//! - **None**: No randomization, use template exactly
//! - **Light**: Small browser-style perturbations (mainstream variation)
//! - **Medium**: Moderate variation within browser norms
//! - **High**: Maximum variation within naturalness constraints
//!
//! ## Usage
//!
//! ```rust,ignore
//! use rustls::custls::randomizer::BrowserRandomizer;
//! use rustls::custls::RandomizationLevel;
//!
//! let mut randomizer = BrowserRandomizer::new(
//!     RandomizationLevel::Light,
//!     NaturalnessFilter::default(),
//! );
//!
//! // Shuffle extensions with grouped constraints
//! randomizer.shuffle_extensions(&mut extensions, &template)?;
//!
//! // Inject GREASE values
//! randomizer.inject_grease(&mut cipher_suites, &mut extensions, &template)?;
//!
//! // Generate padding length
//! let padding_len = randomizer.generate_padding_len(&template);
//! ```

use alloc::vec::Vec;

use crate::custls::{RandomizationLevel, ClientExtension};
use crate::crypto::CipherSuite;
use crate::custls::templates::{TemplateData, NaturalnessFilter};
use crate::error::Error as RustlsError;

// Simple pseudo-random number generator for custls
// This is a placeholder until rand crate is added as a dependency
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new() -> Self {
        // Use a simple seed - in production this would use system entropy
        Self { state: 0x123456789ABCDEF0 }
    }
    
    fn next_u64(&mut self) -> u64 {
        // Simple xorshift64 PRNG
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
    
    fn gen_range(&mut self, min: u16, max: u16) -> u16 {
        if min >= max {
            return min;
        }
        let range = (max - min) as u64 + 1;
        let random = self.next_u64();
        min + (random % range) as u16
    }
    
    fn gen_f64(&mut self) -> f64 {
        // Generate a random f64 between 0.0 and 1.0
        let random = self.next_u64();
        (random as f64) / (u64::MAX as f64)
    }
    
    fn choose<'a, T>(&mut self, slice: &'a [T]) -> Option<&'a T> {
        if slice.is_empty() {
            return None;
        }
        let index = (self.next_u64() as usize) % slice.len();
        slice.get(index)
    }
}

/// Browser-style randomization engine
///
/// This struct provides methods for applying non-uniform randomization to ClientHello
/// components, matching real browser behavior patterns. It maintains an RNG and
/// naturalness filter for validating randomization results.
pub struct BrowserRandomizer {
    /// Randomization intensity level
    level: RandomizationLevel,
    
    /// Random number generator
    rng: SimpleRng,
    
    /// Naturalness filter for validating extension combinations
    naturalness_filter: NaturalnessFilter,
}

impl BrowserRandomizer {
    /// Create a new BrowserRandomizer with the specified randomization level
    ///
    /// # Parameters
    ///
    /// - `level`: Randomization intensity level
    /// - `naturalness_filter`: Filter for validating extension combinations
    ///
    /// # Returns
    ///
    /// A new `BrowserRandomizer` instance
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let randomizer = BrowserRandomizer::new(
    ///     RandomizationLevel::Light,
    ///     NaturalnessFilter::default(),
    /// );
    /// ```
    pub fn new(level: RandomizationLevel, naturalness_filter: NaturalnessFilter) -> Self {
        Self {
            level,
            rng: SimpleRng::new(),
            naturalness_filter,
        }
    }
    
    /// Get the current randomization level
    pub fn level(&self) -> RandomizationLevel {
        self.level
    }
    
    /// Get a reference to the naturalness filter
    pub fn naturalness_filter(&self) -> &NaturalnessFilter {
        &self.naturalness_filter
    }
    
    /// Shuffle extensions with grouped constraints
    ///
    /// This method applies browser-style extension shuffling that respects grouped
    /// constraints. Extensions are categorized into:
    /// - **Critical**: Must maintain specific positions (supported_versions, key_share, pre_shared_key)
    /// - **Standard**: Common extensions that can be shuffled within their group
    /// - **Optional**: Less common extensions that can be shuffled more freely
    ///
    /// # Constraints
    ///
    /// - PSK (pre_shared_key) extension MUST always appear last when present
    /// - Critical extensions maintain browser-appropriate positions
    /// - Shuffling respects template-specific ordering preferences
    /// - Result is validated against naturalness filter
    ///
    /// # Parameters
    ///
    /// - `extensions`: Mutable reference to extension list to shuffle
    /// - `template`: Browser template providing ordering preferences
    ///
    /// # Returns
    ///
    /// - `Ok(())` if shuffling succeeded and passed naturalness filter
    /// - `Err(error)` if shuffling failed or result was unnatural
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut extensions = vec![/* ... */];
    /// randomizer.shuffle_extensions(&mut extensions, &chrome_130())?;
    /// // Extensions are now shuffled with grouped constraints
    /// ```
    pub fn shuffle_extensions(
        &mut self,
        _extensions: &mut Vec<ClientExtension>,
        _template: &TemplateData,
    ) -> Result<(), RustlsError> {
        // If no randomization, return immediately
        if self.level == RandomizationLevel::None {
            return Ok(());
        }
        
        // TODO: Once ClientExtension has real implementation with extension_type() method:
        // 1. Separate PSK extension if present (must be last)
        // 2. Group remaining extensions into critical, standard, optional
        // 3. Shuffle within groups based on randomization level
        // 4. Reassemble: critical + standard + optional + PSK (if present)
        // 5. Validate against naturalness filter
        // 6. Retry if unnatural (up to 3 attempts)
        
        // For now, with placeholder types, we can't actually shuffle
        // This will be implemented once ClientExtension integration is complete
        
        // Placeholder implementation that does nothing
        // This ensures the API is correct even though functionality is deferred
        Ok(())
    }
    
    /// Inject GREASE values into cipher suites and extensions
    ///
    /// GREASE (Generate Random Extensions And Sustain Extensibility) is defined in RFC 8701.
    /// This method injects GREASE values following browser-specific patterns.
    ///
    /// # Browser Patterns
    ///
    /// - **Chrome**: Prefers GREASE in front third of cipher suite list (positions 0.0-0.33)
    /// - **Firefox**: Distributes GREASE more evenly (positions 0.0, 0.25, 0.5, 0.75)
    /// - **Safari**: Conservative GREASE usage (80% probability)
    ///
    /// # Parameters
    ///
    /// - `cipher_suites`: Mutable reference to cipher suite list
    /// - `extensions`: Mutable reference to extension list
    /// - `template`: Browser template providing GREASE pattern
    /// - `previous_grease_values`: Previously used GREASE values to avoid
    ///
    /// # Returns
    ///
    /// - `Ok(grease_values)` - Vector of GREASE values that were injected
    /// - `Err(error)` if injection failed
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut cipher_suites = vec![/* ... */];
    /// let mut extensions = vec![/* ... */];
    /// let previous = vec![0x0a0a, 0x1a1a];
    /// let used = randomizer.inject_grease(&mut cipher_suites, &mut extensions, &chrome_130(), &previous)?;
    /// // GREASE values are now injected following Chrome's pattern, avoiding previous values
    /// ```
    pub fn inject_grease(
        &mut self,
        _cipher_suites: &mut Vec<CipherSuite>,
        _extensions: &mut Vec<ClientExtension>,
        template: &TemplateData,
        previous_grease_values: &[u16],
    ) -> Result<Vec<u16>, RustlsError> {
        // If no randomization, return immediately
        if self.level == RandomizationLevel::None {
            return Ok(Vec::new());
        }
        
        let grease_pattern = &template.grease_pattern;
        let mut used_grease_values = Vec::new();
        
        // Inject GREASE cipher suites based on probability
        if self.rng.gen_f64() < grease_pattern.cipher_suite_probability {
            // Select a GREASE value that hasn't been used recently
            if let Some(grease_value) = self.select_unused_grease(
                &grease_pattern.grease_values,
                previous_grease_values
            ) {
                used_grease_values.push(grease_value);
                
                // Select a position based on template's preferred positions
                let _position = if !grease_pattern.cipher_suite_positions.is_empty() {
                    let normalized_pos = self.rng.choose(&grease_pattern.cipher_suite_positions)
                        .copied()
                        .unwrap_or(0.0);
                    
                    // Convert normalized position (0.0-1.0) to actual index
                    // let max_index = cipher_suites.len();
                    // (normalized_pos * max_index as f64) as usize
                    (normalized_pos * 10.0) as usize  // Placeholder
                } else {
                    0
                };
                
                // TODO: Once CipherSuite has real implementation:
                // Create GREASE cipher suite and insert at position
                // For now, this is a placeholder
                
                // Placeholder: would insert GREASE cipher suite here
                // cipher_suites.insert(position.min(cipher_suites.len()), grease_cipher_suite);
            }
        }
        
        // Inject GREASE extensions based on probability
        if self.rng.gen_f64() < grease_pattern.extension_probability {
            // Select a different GREASE value for extensions (avoid reusing the same one)
            let avoid_values: Vec<u16> = previous_grease_values.iter()
                .chain(used_grease_values.iter())
                .copied()
                .collect();
            
            if let Some(grease_value) = self.select_unused_grease(
                &grease_pattern.grease_values,
                &avoid_values
            ) {
                used_grease_values.push(grease_value);
                
                // Select a position based on template's preferred positions
                let _position = if !grease_pattern.extension_positions.is_empty() {
                    let normalized_pos = self.rng.choose(&grease_pattern.extension_positions)
                        .copied()
                        .unwrap_or(0.0);
                    
                    // Convert normalized position (0.0-1.0) to actual index
                    // let max_index = extensions.len();
                    // (normalized_pos * max_index as f64) as usize
                    (normalized_pos * 10.0) as usize  // Placeholder
                } else {
                    0
                };
                
                // TODO: Once ClientExtension has real implementation:
                // Create GREASE extension and insert at position
                // For now, this is a placeholder
                
                // Placeholder: would insert GREASE extension here
                // extensions.insert(position.min(extensions.len()), grease_extension);
            }
        }
        
        Ok(used_grease_values)
    }
    
    /// Generate padding length from template's distribution
    ///
    /// This method samples a padding length from the template's padding distribution,
    /// which is based on real browser behavior. Real browsers favor:
    /// - Powers of 2 (0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024)
    /// - Common browser lengths (0, 128, 256, 384, 512 for Chrome)
    /// - Staying under 1500 bytes to avoid fragmentation
    ///
    /// # Sampling Strategy
    ///
    /// 1. First, try to sample from the template's PMF (probability mass function)
    /// 2. If PMF sampling fails or randomization level is high, generate a random length
    /// 3. Apply power-of-2 bias based on template configuration
    /// 4. Clamp to template's min/max range
    /// 5. Avoid recently used padding lengths to ensure variation
    ///
    /// # Parameters
    ///
    /// - `template`: Browser template providing padding distribution
    /// - `previous_padding_lengths`: Previously used padding lengths to avoid
    ///
    /// # Returns
    ///
    /// A padding length in bytes (u16)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let previous = vec![128, 256];
    /// let padding_len = randomizer.generate_padding_len(&chrome_130(), &previous);
    /// // padding_len is likely 0, 384, or 512 (avoiding 128 and 256)
    /// ```
    pub fn generate_padding_len(&mut self, template: &TemplateData, previous_padding_lengths: &[u16]) -> u16 {
        // If no randomization, use first PMF entry or 0
        if self.level == RandomizationLevel::None {
            return template.padding_distribution.pmf
                .first()
                .map(|(len, _)| *len)
                .unwrap_or(0);
        }
        
        let dist = &template.padding_distribution;
        
        // Decide whether to sample from PMF or generate random
        let use_pmf = match self.level {
            RandomizationLevel::None => true,
            RandomizationLevel::Light => self.rng.gen_f64() < 0.9,  // 90% use PMF
            RandomizationLevel::Medium => self.rng.gen_f64() < 0.7, // 70% use PMF
            RandomizationLevel::High => self.rng.gen_f64() < 0.5,   // 50% use PMF
        };
        
        // Try to find a length that hasn't been used recently
        let max_attempts = 5;
        for _ in 0..max_attempts {
            let length = if use_pmf && !dist.pmf.is_empty() {
                // Sample from PMF using cumulative distribution
                let random_value = self.rng.gen_f64();
                let mut cumulative = 0.0;
                let mut selected_len = dist.pmf.first().map(|(len, _)| *len).unwrap_or(0);
                
                for (len, prob) in &dist.pmf {
                    cumulative += prob;
                    if random_value <= cumulative {
                        selected_len = *len;
                        break;
                    }
                }
                
                selected_len
            } else {
                // Generate random length within range
                let range = dist.max_length - dist.min_length;
                if range == 0 {
                    dist.min_length
                } else {
                    let random_len = dist.min_length + self.rng.gen_range(0, range);
                    
                    // Apply power-of-2 bias
                    if self.rng.gen_f64() < dist.power_of_2_bias {
                        // Find nearest power of 2
                        self.nearest_power_of_2(random_len, dist.min_length, dist.max_length)
                    } else {
                        random_len
                    }
                }
            };
            
            // Clamp to valid range
            let clamped = length.clamp(dist.min_length, dist.max_length);
            
            // Check if this length was recently used
            if !previous_padding_lengths.contains(&clamped) {
                return clamped;
            }
        }
        
        // If we couldn't find an unused length after max_attempts, just return a random one
        // This ensures we don't get stuck if all common lengths have been used
        let range = dist.max_length - dist.min_length;
        if range == 0 {
            dist.min_length
        } else {
            let random_len = dist.min_length + self.rng.gen_range(0, range);
            random_len.clamp(dist.min_length, dist.max_length)
        }
    }
    
    /// Find the nearest power of 2 to the given value, within the specified range
    ///
    /// Powers of 2 considered: 0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048
    fn nearest_power_of_2(&self, value: u16, min: u16, max: u16) -> u16 {
        const POWERS_OF_2: [u16; 13] = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048];
        
        // Filter powers within range
        let valid_powers: Vec<u16> = POWERS_OF_2
            .iter()
            .copied()
            .filter(|&p| p >= min && p <= max)
            .collect();
        
        if valid_powers.is_empty() {
            return value.clamp(min, max);
        }
        
        // Find nearest power
        valid_powers
            .iter()
            .min_by_key(|&&p| {
                let diff = if p > value {
                    p - value
                } else {
                    value - p
                };
                diff
            })
            .copied()
            .unwrap_or(value)
    }
    
    /// Select a GREASE value that hasn't been used recently
    ///
    /// This method selects a GREASE value from the available pool, avoiding
    /// values that were recently used for the same target. This ensures variation
    /// across connections to prevent static fingerprint repetition.
    ///
    /// # Parameters
    ///
    /// - `available_values`: Pool of GREASE values to choose from
    /// - `previous_values`: GREASE values that were recently used (to avoid)
    ///
    /// # Returns
    ///
    /// A GREASE value that hasn't been used recently, or a random value if all
    /// have been used.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let grease_values = vec![0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a];
    /// let previous = vec![0x0a0a, 0x1a1a];
    /// let new_value = randomizer.select_unused_grease(&grease_values, &previous);
    /// // new_value will be 0x2a2a or 0x3a3a (not 0x0a0a or 0x1a1a)
    /// ```
    pub fn select_unused_grease(&mut self, available_values: &[u16], previous_values: &[u16]) -> Option<u16> {
        if available_values.is_empty() {
            return None;
        }
        
        // Filter out recently used values
        let unused: Vec<u16> = available_values
            .iter()
            .copied()
            .filter(|v| !previous_values.contains(v))
            .collect();
        
        // If we have unused values, select from them
        if !unused.is_empty() {
            return self.rng.choose(&unused).copied();
        }
        
        // If all values have been used, select randomly from all available
        // This ensures we still vary even if we've cycled through all values
        self.rng.choose(available_values).copied()
    }
}

#[cfg(test)]
#[path = "randomizer_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "randomizer_properties.rs"]
mod properties;
