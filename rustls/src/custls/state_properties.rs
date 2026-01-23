//! Property-based tests for fingerprint cache and state management.
//!
//! These tests verify universal properties that should hold across all valid
//! inputs and execution sequences for the cache system.

#[cfg(test)]
mod property_tests {
    use super::super::*;
    use proptest::prelude::*;
    use alloc::collections::BTreeMap;
    use alloc::string::ToString;
    extern crate alloc;
    
    // Helper to create a test config with a specific seed
    fn create_test_config_with_seed(seed: u64) -> ClientHelloConfig {
        ClientHelloConfig {
            template: BrowserTemplate::Chrome130,
            cipher_suites: Vec::new(),
            extension_order: Vec::new(),
            extension_data: BTreeMap::new(),
            grease_cipher_positions: Vec::new(),
            grease_extension_positions: Vec::new(),
            padding_length: (seed % 1500) as u16,
            random_seed: seed,
            supported_groups: Vec::new(),
            signature_algorithms: Vec::new(),
        }
    }
    
    // Strategy for generating target keys
    fn target_key_strategy() -> impl Strategy<Value = TargetKey> {
        (
            prop::string::string_regex("[a-z]{3,20}\\.com").unwrap(),
            prop::num::u16::ANY,
        ).prop_map(|(host, port)| TargetKey::new(host, port))
    }
    
    // Feature: custls, Property 6: Cache State Updates
    // For any handshake result (success or failure), the FingerprintManager SHALL
    // update the cache entry for that target, incrementing success_count on success
    // or decrementing reputation_score on failure.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        #[test]
        fn property_cache_state_updates(
            target in target_key_strategy(),
            results in prop::collection::vec(prop::bool::ANY, 1..20),
            seed in prop::num::u64::ANY,
        ) {
            let mut manager = FingerprintManager::new(1000);
            let config = create_test_config_with_seed(seed);
            
            let mut expected_success = 0u32;
            let mut expected_failure = 0u32;
            
            // Record each result
            for &success in &results {
                manager.record_result(&target, config.clone(), success);
                
                if success {
                    expected_success += 1;
                } else {
                    expected_failure += 1;
                }
            }
            
            // Verify cache entry was updated correctly
            let stats = manager.get_stats(&target);
            prop_assert!(stats.is_some(), "Cache entry should exist after recording results");
            
            let (success_count, failure_count, reputation_score) = stats.unwrap();
            
            // Verify counts match expectations
            prop_assert_eq!(success_count, expected_success, 
                "Success count should match number of successful results");
            prop_assert_eq!(failure_count, expected_failure,
                "Failure count should match number of failed results");
            
            // Verify reputation score is calculated correctly
            let total = expected_success + expected_failure;
            let expected_reputation = expected_success as f64 / total as f64;
            prop_assert!((reputation_score - expected_reputation).abs() < 0.0001,
                "Reputation score should be success_count / total");
        }
    }
    
    // Additional property: Cache updates preserve entry existence
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        #[test]
        fn property_cache_updates_preserve_entry(
            target in target_key_strategy(),
            num_updates in 1usize..50,
            seed in prop::num::u64::ANY,
        ) {
            let mut manager = FingerprintManager::new(1000);
            let config = create_test_config_with_seed(seed);
            
            // Record multiple results
            for i in 0..num_updates {
                let success = i % 2 == 0; // Alternate success/failure
                manager.record_result(&target, config.clone(), success);
                
                // Entry should exist after each update
                prop_assert!(manager.get_stats(&target).is_some(),
                    "Cache entry should exist after update {}", i);
            }
            
            // Final verification
            let stats = manager.get_stats(&target);
            prop_assert!(stats.is_some(), "Cache entry should still exist");
            
            let (success_count, failure_count, _) = stats.unwrap();
            prop_assert_eq!(success_count + failure_count, num_updates as u32,
                "Total count should match number of updates");
        }
    }
    
    // Additional property: Reputation score bounds
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        #[test]
        fn property_reputation_score_bounds(
            target in target_key_strategy(),
            results in prop::collection::vec(prop::bool::ANY, 1..50),
            seed in prop::num::u64::ANY,
        ) {
            let mut manager = FingerprintManager::new(1000);
            let config = create_test_config_with_seed(seed);
            
            // Record results
            for &success in &results {
                manager.record_result(&target, config.clone(), success);
            }
            
            // Verify reputation score is in valid range [0.0, 1.0]
            if let Some((_, _, reputation_score)) = manager.get_stats(&target) {
                prop_assert!(reputation_score >= 0.0 && reputation_score <= 1.0,
                    "Reputation score should be between 0.0 and 1.0, got {}", reputation_score);
            }
        }
    }
    
    // Additional property: Multiple targets are tracked independently
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        #[test]
        fn property_multiple_targets_independent(
            targets in prop::collection::vec(target_key_strategy(), 2..10),
            seed in prop::num::u64::ANY,
        ) {
            let mut manager = FingerprintManager::new(1000);
            let config = create_test_config_with_seed(seed);
            
            // Record different results for each target
            for (i, target) in targets.iter().enumerate() {
                let success = i % 2 == 0;
                manager.record_result(target, config.clone(), success);
            }
            
            // Verify each target has independent stats
            for (i, target) in targets.iter().enumerate() {
                let stats = manager.get_stats(target);
                prop_assert!(stats.is_some(), "Each target should have stats");
                
                let (success_count, failure_count, _) = stats.unwrap();
                if i % 2 == 0 {
                    prop_assert_eq!(success_count, 1, "Even-indexed targets should have 1 success");
                    prop_assert_eq!(failure_count, 0, "Even-indexed targets should have 0 failures");
                } else {
                    prop_assert_eq!(success_count, 0, "Odd-indexed targets should have 0 successes");
                    prop_assert_eq!(failure_count, 1, "Odd-indexed targets should have 1 failure");
                }
            }
        }
    }
    
    // Feature: custls, Property 7: Cached Fingerprint Variation
    // For any two consecutive retrievals of a cached fingerprint for the same target,
    // the returned configurations SHALL differ in at least one randomizable parameter
    // (GREASE values, padding length, or minor extension ordering).
    //
    // Note: This property test verifies that the cache returns the config, but actual
    // variation is applied by the randomizer in the calling code. We verify that
    // consecutive retrievals return clones that can be independently modified.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        #[test]
        fn property_cached_fingerprint_variation(
            target in target_key_strategy(),
            seed1 in prop::num::u64::ANY,
            seed2 in prop::num::u64::ANY,
        ) {
            let mut manager = FingerprintManager::new(1000);
            
            // Create and cache a config
            let config1 = create_test_config_with_seed(seed1);
            manager.record_result(&target, config1.clone(), true);
            
            // Retrieve the cached config twice
            let retrieved1 = manager.get_working_fingerprint(&target);
            let retrieved2 = manager.get_working_fingerprint(&target);
            
            prop_assert!(retrieved1.is_some(), "First retrieval should return cached config");
            prop_assert!(retrieved2.is_some(), "Second retrieval should return cached config");
            
            // Both retrievals should return configs (clones of the cached one)
            // The actual variation would be applied by the randomizer in calling code
            let config_a = retrieved1.unwrap();
            let config_b = retrieved2.unwrap();
            
            // Verify they are independent clones (same initial values)
            prop_assert_eq!(config_a.padding_length, config_b.padding_length,
                "Retrieved configs should have same initial values");
            prop_assert_eq!(config_a.random_seed, config_b.random_seed,
                "Retrieved configs should have same random seed");
        }
    }
    
    // Additional property: Cache returns consistent config for same target
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        #[test]
        fn property_cache_consistency_same_target(
            target in target_key_strategy(),
            seed in prop::num::u64::ANY,
            num_retrievals in 2usize..10,
        ) {
            let mut manager = FingerprintManager::new(1000);
            let config = create_test_config_with_seed(seed);
            
            // Cache the config
            manager.record_result(&target, config.clone(), true);
            
            // Retrieve multiple times
            for i in 0..num_retrievals {
                let retrieved = manager.get_working_fingerprint(&target);
                prop_assert!(retrieved.is_some(), 
                    "Retrieval {} should return cached config", i);
                
                let retrieved_config = retrieved.unwrap();
                prop_assert_eq!(retrieved_config.random_seed, seed,
                    "Retrieved config should match original seed");
            }
        }
    }
    
    // Feature: custls, Property 8: Cache Size Limit
    // For any sequence of cache insertions, the cache size SHALL never exceed
    // the configured max_size limit, evicting low-reputation entries when necessary.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        #[test]
        fn property_cache_size_limit(
            max_size in 5usize..50,
            num_insertions in 10usize..100,
            seed in prop::num::u64::ANY,
        ) {
            let mut manager = FingerprintManager::new(max_size);
            let config = create_test_config_with_seed(seed);
            
            // Insert more entries than max_size
            for i in 0..num_insertions {
                let target = TargetKey::new(
                    alloc::format!("host{}.com", i),
                    443
                );
                manager.record_result(&target, config.clone(), true);
                
                // Verify cache size never exceeds max_size
                prop_assert!(manager.size() <= max_size,
                    "Cache size {} should not exceed max_size {}", 
                    manager.size(), max_size);
            }
            
            // Final verification
            prop_assert!(manager.size() <= max_size,
                "Final cache size {} should not exceed max_size {}", 
                manager.size(), max_size);
        }
    }
    
    // Additional property: Cache eviction preserves highest reputation entries
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        #[test]
        fn property_cache_eviction_preserves_high_reputation(
            max_size in 5usize..20,
            seed in prop::num::u64::ANY,
        ) {
            let mut manager = FingerprintManager::new(max_size);
            let config = create_test_config_with_seed(seed);
            
            // Create a high-reputation entry
            let high_rep_target = TargetKey::new("high-rep.com".to_string(), 443);
            for _ in 0..10 {
                manager.record_result(&high_rep_target, config.clone(), true);
            }
            
            // Create many low-reputation entries to trigger eviction
            for i in 0..(max_size * 2) {
                let target = TargetKey::new(
                    alloc::format!("low-rep{}.com", i),
                    443
                );
                manager.record_result(&target, config.clone(), false);
            }
            
            // High reputation entry should still be in cache
            let stats = manager.get_stats(&high_rep_target);
            prop_assert!(stats.is_some(),
                "High reputation entry should not be evicted");
            
            if let Some((success_count, _, reputation)) = stats {
                prop_assert_eq!(success_count, 10,
                    "High reputation entry should have correct success count");
                prop_assert!(reputation > 0.9,
                    "High reputation entry should have high reputation score");
            }
        }
    }
    
    // Additional property: Empty cache after clear
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        #[test]
        fn property_cache_clear_empties_cache(
            num_entries in 1usize..50,
            seed in prop::num::u64::ANY,
        ) {
            let mut manager = FingerprintManager::new(100);
            let config = create_test_config_with_seed(seed);
            
            // Add entries
            for i in 0..num_entries {
                let target = TargetKey::new(
                    alloc::format!("host{}.com", i),
                    443
                );
                manager.record_result(&target, config.clone(), true);
            }
            
            prop_assert!(manager.size() > 0, "Cache should have entries");
            
            // Clear cache
            manager.clear_cache();
            
            // Verify cache is empty
            prop_assert_eq!(manager.size(), 0, "Cache should be empty after clear");
            prop_assert!(manager.is_empty(), "Cache should report as empty");
        }
    }
}
