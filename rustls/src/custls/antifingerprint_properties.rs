//! Property-based tests for anti-fingerprinting features
//!
//! This module contains property tests that validate anti-fingerprinting behavior:
//! - GREASE value variation across connections
//! - Padding length variation across connections
//! - Timing jitter application
//!
//! These tests use proptest to verify that the system exhibits the required
//! variation properties across many randomly generated inputs.

#[cfg(test)]
mod tests {
    use super::super::*;
    use proptest::prelude::*;
    use alloc::vec::Vec;
    use alloc::string::ToString;
    
    use crate::custls::state::{FingerprintManager, TargetKey, ClientHelloConfig};
    use crate::custls::randomizer::BrowserRandomizer;
    use crate::custls::templates::{NaturalnessFilter, chrome_130};
    use crate::custls::{RandomizationLevel, BrowserTemplate};
    
    // Feature: custls, Property 15: GREASE Value Variation
    //
    // For any two handshakes to the same target, the GREASE values (cipher suites
    // and extensions) SHALL differ, preventing static fingerprint repetition.
    //
    // Validates: Requirements 9.3, 10.1
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        #[test]
        fn grease_value_variation_across_connections(
            num_connections in 2usize..10,
            seed in any::<u64>(),
        ) {
            // Create a fingerprint manager to track GREASE values
            let mut manager = FingerprintManager::new(100);
            let target = TargetKey::new("example.com".to_string(), 443);
            
            // Create a randomizer
            let naturalness_filter = NaturalnessFilter::default();
            let mut randomizer = BrowserRandomizer::new(
                RandomizationLevel::Light,
                naturalness_filter,
            );
            
            // Get template
            let template = chrome_130();
            
            // Track GREASE values across multiple connections
            let mut all_grease_values = Vec::new();
            
            for i in 0..num_connections {
                // Get previous GREASE values for this target
                let previous = manager.get_previous_grease_values(&target);
                
                // Inject GREASE values
                let mut cipher_suites = Vec::new();
                let mut extensions = Vec::new();
                
                let used_grease = randomizer.inject_grease(
                    &mut cipher_suites,
                    &mut extensions,
                    &template,
                    previous,
                ).expect("GREASE injection should succeed");
                
                // Track the GREASE values
                for &grease_value in &used_grease {
                    manager.track_grease_value(&target, grease_value);
                    all_grease_values.push((i, grease_value));
                }
            }
            
            // Property: GREASE values should vary across connections
            // Check that we don't use the same GREASE value for consecutive connections
            if all_grease_values.len() >= 2 {
                let mut has_variation = false;
                
                for window in all_grease_values.windows(2) {
                    if window[0].1 != window[1].1 {
                        has_variation = true;
                        break;
                    }
                }
                
                // At least some variation should occur across connections
                // (unless all GREASE values are the same by chance, which is unlikely)
                prop_assert!(
                    has_variation || all_grease_values.len() < 2,
                    "GREASE values should vary across connections"
                );
            }
        }
        
        #[test]
        fn grease_selection_avoids_recent_values(
            available_values in prop::collection::vec(any::<u16>(), 5..20),
            previous_values in prop::collection::vec(any::<u16>(), 1..5),
        ) {
            // Create a randomizer
            let naturalness_filter = NaturalnessFilter::default();
            let mut randomizer = BrowserRandomizer::new(
                RandomizationLevel::Light,
                naturalness_filter,
            );
            
            // Select a GREASE value
            if let Some(selected) = randomizer.select_unused_grease(&available_values, &previous_values) {
                // Property: Selected value should not be in previous_values
                // (unless all available values are in previous_values)
                let unused_available: Vec<u16> = available_values
                    .iter()
                    .copied()
                    .filter(|v| !previous_values.contains(v))
                    .collect();
                
                if !unused_available.is_empty() {
                    prop_assert!(
                        !previous_values.contains(&selected),
                        "Selected GREASE value should not be in recent history when unused values are available"
                    );
                }
            }
        }
        
        #[test]
        fn padding_length_variation_across_connections(
            num_connections in 2usize..10,
        ) {
            // Create a fingerprint manager to track padding lengths
            let mut manager = FingerprintManager::new(100);
            let target = TargetKey::new("example.com".to_string(), 443);
            
            // Create a randomizer
            let naturalness_filter = NaturalnessFilter::default();
            let mut randomizer = BrowserRandomizer::new(
                RandomizationLevel::Light,
                naturalness_filter,
            );
            
            // Get template
            let template = chrome_130();
            
            // Track padding lengths across multiple connections
            let mut all_padding_lengths = Vec::new();
            
            for _ in 0..num_connections {
                // Get previous padding lengths for this target
                let previous = manager.get_previous_padding_lengths(&target);
                
                // Generate padding length
                let padding_len = randomizer.generate_padding_len(&template, previous);
                
                // Track the padding length
                manager.track_padding_length(&target, padding_len);
                all_padding_lengths.push(padding_len);
            }
            
            // Property: Padding lengths should vary across connections
            // Check that we don't use the same padding length for all connections
            if all_padding_lengths.len() >= 2 {
                let first = all_padding_lengths[0];
                let has_variation = all_padding_lengths.iter().any(|&len| len != first);
                
                // At least some variation should occur across connections
                // (unless the template has very limited padding options)
                prop_assert!(
                    has_variation || template.padding_distribution.pmf.len() <= 1,
                    "Padding lengths should vary across connections when multiple options are available"
                );
            }
        }
        
        #[test]
        fn timing_jitter_config_validation(
            min_micros in 0u64..10000,
            max_micros in 0u64..10000,
            probability in -1.0f64..2.0,
        ) {
            use crate::custls::utils::TimingJitterConfig;
            
            let result = TimingJitterConfig::new(min_micros, max_micros, probability);
            
            // Property: Config should be valid only if:
            // 1. min_micros <= max_micros
            // 2. 0.0 <= probability <= 1.0
            let should_be_valid = min_micros <= max_micros && (0.0..=1.0).contains(&probability);
            
            prop_assert_eq!(
                result.is_ok(),
                should_be_valid,
                "TimingJitterConfig validation should match expected criteria"
            );
        }
    }
}


// Unit tests for anti-fingerprinting features
#[cfg(test)]
mod unit_tests {
    use super::super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use alloc::string::ToString;
    
    use crate::custls::state::{FingerprintManager, TargetKey};
    use crate::custls::randomizer::BrowserRandomizer;
    use crate::custls::templates::{NaturalnessFilter, chrome_130};
    use crate::custls::{RandomizationLevel, CustlsConfig};
    use crate::custls::utils::TimingJitterConfig;
    
    #[test]
    fn test_grease_tracking_in_cache() {
        let mut manager = FingerprintManager::new(100);
        let target = TargetKey::new("example.com".to_string(), 443);
        
        // Create a cache entry first by recording a result
        let config = crate::custls::state::ClientHelloConfig {
            template: crate::custls::BrowserTemplate::Chrome130,
            cipher_suites: Vec::new(),
            extension_order: Vec::new(),
            extension_data: alloc::collections::BTreeMap::new(),
            grease_cipher_positions: Vec::new(),
            grease_extension_positions: Vec::new(),
            padding_length: 0,
            random_seed: 0,
            supported_groups: Vec::new(),
            signature_algorithms: Vec::new(),
        };
        manager.record_result(&target, config, true);
        
        // Track some GREASE values
        manager.track_grease_value(&target, 0x0a0a);
        manager.track_grease_value(&target, 0x1a1a);
        manager.track_grease_value(&target, 0x2a2a);
        
        // Verify they're tracked
        let previous = manager.get_previous_grease_values(&target);
        assert_eq!(previous.len(), 3);
        assert!(previous.contains(&0x0a0a));
        assert!(previous.contains(&0x1a1a));
        assert!(previous.contains(&0x2a2a));
    }
    
    #[test]
    fn test_grease_tracking_limit() {
        let mut manager = FingerprintManager::new(100);
        let target = TargetKey::new("example.com".to_string(), 443);
        
        // Create a cache entry first
        let config = crate::custls::state::ClientHelloConfig {
            template: crate::custls::BrowserTemplate::Chrome130,
            cipher_suites: Vec::new(),
            extension_order: Vec::new(),
            extension_data: alloc::collections::BTreeMap::new(),
            grease_cipher_positions: Vec::new(),
            grease_extension_positions: Vec::new(),
            padding_length: 0,
            random_seed: 0,
            supported_groups: Vec::new(),
            signature_algorithms: Vec::new(),
        };
        manager.record_result(&target, config, true);
        
        // Track more than 10 GREASE values
        for i in 0..15 {
            manager.track_grease_value(&target, i as u16);
        }
        
        // Should only keep the most recent 10
        let previous = manager.get_previous_grease_values(&target);
        assert_eq!(previous.len(), 10);
        
        // Should have values 5-14 (most recent 10)
        for i in 5..15 {
            assert!(previous.contains(&(i as u16)));
        }
        
        // Should not have values 0-4 (oldest)
        for i in 0..5 {
            assert!(!previous.contains(&(i as u16)));
        }
    }
    
    #[test]
    fn test_padding_tracking_in_cache() {
        let mut manager = FingerprintManager::new(100);
        let target = TargetKey::new("example.com".to_string(), 443);
        
        // Create a cache entry first
        let config = crate::custls::state::ClientHelloConfig {
            template: crate::custls::BrowserTemplate::Chrome130,
            cipher_suites: Vec::new(),
            extension_order: Vec::new(),
            extension_data: alloc::collections::BTreeMap::new(),
            grease_cipher_positions: Vec::new(),
            grease_extension_positions: Vec::new(),
            padding_length: 0,
            random_seed: 0,
            supported_groups: Vec::new(),
            signature_algorithms: Vec::new(),
        };
        manager.record_result(&target, config, true);
        
        // Track some padding lengths
        manager.track_padding_length(&target, 128);
        manager.track_padding_length(&target, 256);
        manager.track_padding_length(&target, 384);
        
        // Verify they're tracked
        let previous = manager.get_previous_padding_lengths(&target);
        assert_eq!(previous.len(), 3);
        assert!(previous.contains(&128));
        assert!(previous.contains(&256));
        assert!(previous.contains(&384));
    }
    
    #[test]
    fn test_padding_tracking_limit() {
        let mut manager = FingerprintManager::new(100);
        let target = TargetKey::new("example.com".to_string(), 443);
        
        // Create a cache entry first
        let config = crate::custls::state::ClientHelloConfig {
            template: crate::custls::BrowserTemplate::Chrome130,
            cipher_suites: Vec::new(),
            extension_order: Vec::new(),
            extension_data: alloc::collections::BTreeMap::new(),
            grease_cipher_positions: Vec::new(),
            grease_extension_positions: Vec::new(),
            padding_length: 0,
            random_seed: 0,
            supported_groups: Vec::new(),
            signature_algorithms: Vec::new(),
        };
        manager.record_result(&target, config, true);
        
        // Track more than 10 padding lengths
        for i in 0..15 {
            manager.track_padding_length(&target, i * 64);
        }
        
        // Should only keep the most recent 10
        let previous = manager.get_previous_padding_lengths(&target);
        assert_eq!(previous.len(), 10);
        
        // Should have values from 5*64 to 14*64 (most recent 10)
        for i in 5..15 {
            assert!(previous.contains(&(i * 64)));
        }
        
        // Should not have values 0*64 to 4*64 (oldest)
        for i in 0..5 {
            assert!(!previous.contains(&(i * 64)));
        }
    }
    
    #[test]
    fn test_select_unused_grease_prefers_unused() {
        let naturalness_filter = NaturalnessFilter::default();
        let mut randomizer = BrowserRandomizer::new(
            RandomizationLevel::Light,
            naturalness_filter,
        );
        
        let available = vec![0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a];
        let previous = vec![0x0a0a, 0x1a1a];
        
        // Select multiple times and verify we get unused values
        for _ in 0..10 {
            if let Some(selected) = randomizer.select_unused_grease(&available, &previous) {
                // Should be one of the unused values
                assert!(selected == 0x2a2a || selected == 0x3a3a || selected == 0x4a4a);
            }
        }
    }
    
    #[test]
    fn test_select_unused_grease_handles_all_used() {
        let naturalness_filter = NaturalnessFilter::default();
        let mut randomizer = BrowserRandomizer::new(
            RandomizationLevel::Light,
            naturalness_filter,
        );
        
        let available = vec![0x0a0a, 0x1a1a, 0x2a2a];
        let previous = vec![0x0a0a, 0x1a1a, 0x2a2a]; // All values used
        
        // Should still return a value (cycles through)
        let selected = randomizer.select_unused_grease(&available, &previous);
        assert!(selected.is_some());
        assert!(available.contains(&selected.unwrap()));
    }
    
    #[test]
    fn test_padding_variation_avoids_recent() {
        let naturalness_filter = NaturalnessFilter::default();
        let mut randomizer = BrowserRandomizer::new(
            RandomizationLevel::Medium,
            naturalness_filter,
        );
        
        let template = chrome_130();
        let previous = vec![128, 256, 384];
        
        // Generate multiple padding lengths
        let mut generated = Vec::new();
        for _ in 0..10 {
            let len = randomizer.generate_padding_len(&template, &previous);
            generated.push(len);
        }
        
        // At least some should be different from previous values
        let has_new_values = generated.iter().any(|&len| !previous.contains(&len));
        assert!(has_new_values, "Should generate some new padding lengths");
    }
    
    #[test]
    fn test_timing_jitter_config_builder() {
        let config = CustlsConfig::builder()
            .with_timing_jitter(TimingJitterConfig::new(100, 1000, 0.5).unwrap())
            .build();
        
        assert!(config.timing_jitter.is_some());
        let jitter = config.timing_jitter.unwrap();
        assert_eq!(jitter.min_delay_micros, 100);
        assert_eq!(jitter.max_delay_micros, 1000);
        assert_eq!(jitter.apply_probability, 0.5);
    }
    
    #[test]
    fn test_timing_jitter_validation() {
        // Valid config
        assert!(TimingJitterConfig::new(100, 1000, 0.5).is_ok());
        
        // Invalid: min > max
        assert!(TimingJitterConfig::new(1000, 100, 0.5).is_err());
        
        // Invalid: probability < 0
        assert!(TimingJitterConfig::new(100, 1000, -0.1).is_err());
        
        // Invalid: probability > 1
        assert!(TimingJitterConfig::new(100, 1000, 1.5).is_err());
        
        // Edge cases: valid
        assert!(TimingJitterConfig::new(0, 0, 0.0).is_ok());
        assert!(TimingJitterConfig::new(0, 0, 1.0).is_ok());
        assert!(TimingJitterConfig::new(100, 100, 0.5).is_ok());
    }
    
    #[test]
    fn test_grease_variation_across_multiple_connections() {
        let mut manager = FingerprintManager::new(100);
        let target = TargetKey::new("example.com".to_string(), 443);
        
        let naturalness_filter = NaturalnessFilter::default();
        let mut randomizer = BrowserRandomizer::new(
            RandomizationLevel::Light,
            naturalness_filter,
        );
        
        let template = chrome_130();
        
        // Simulate 5 connections
        let mut all_grease = Vec::new();
        for _ in 0..5 {
            let previous = manager.get_previous_grease_values(&target);
            
            let mut cipher_suites = Vec::new();
            let mut extensions = Vec::new();
            
            let used = randomizer.inject_grease(
                &mut cipher_suites,
                &mut extensions,
                &template,
                previous,
            ).unwrap();
            
            for &grease in &used {
                manager.track_grease_value(&target, grease);
                all_grease.push(grease);
            }
        }
        
        // Should have some GREASE values (may be empty if probability is low)
        // But if we have values, they should show variation
        if all_grease.len() >= 2 {
            let first = all_grease[0];
            let has_variation = all_grease.iter().any(|&g| g != first);
            // Note: Due to randomness, this might not always be true,
            // but with 5 connections it's very likely
            assert!(has_variation || all_grease.len() < 2);
        }
    }
    
    #[test]
    fn test_padding_variation_across_multiple_connections() {
        let mut manager = FingerprintManager::new(100);
        let target = TargetKey::new("example.com".to_string(), 443);
        
        let naturalness_filter = NaturalnessFilter::default();
        let mut randomizer = BrowserRandomizer::new(
            RandomizationLevel::Medium,
            naturalness_filter,
        );
        
        let template = chrome_130();
        
        // Simulate 5 connections
        let mut all_padding = Vec::new();
        for _ in 0..5 {
            let previous = manager.get_previous_padding_lengths(&target);
            let len = randomizer.generate_padding_len(&template, previous);
            manager.track_padding_length(&target, len);
            all_padding.push(len);
        }
        
        // Should have 5 padding lengths
        assert_eq!(all_padding.len(), 5);
        
        // Should show some variation (unless template has very limited options)
        let first = all_padding[0];
        let has_variation = all_padding.iter().any(|&len| len != first);
        assert!(has_variation || template.padding_distribution.pmf.len() <= 1);
    }
}
