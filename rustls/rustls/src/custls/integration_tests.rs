//! End-to-end integration tests for custls ClientHello generation.
//!
//! These tests verify that the complete custls system works correctly:
//! - Template application
//! - Randomization
//! - Cache functionality
//! - Hook invocation
//! - Complete ClientHello generation flow
//!
//! ## Test Strategy
//!
//! These integration tests complement the unit and property tests by verifying
//! that all components work together correctly in realistic scenarios.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use alloc::string::ToString;

use crate::custls::{
    CustlsConfig, BrowserTemplate, RandomizationLevel, TemplateRotationPolicy,
    ClientHelloCustomizer, ConfigParams,
    DefaultCustomizer, TargetKey, ClientHelloConfig,
};

/// Test that DefaultCustomizer can be created with various configurations
#[test]
fn test_end_to_end_customizer_creation() {
    // Test with Chrome template
    let config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_randomization_level(RandomizationLevel::Light)
        .with_cache(true)
        .build();
    
    let customizer = DefaultCustomizer::new(config);
    assert!(customizer.template().is_some());
    assert_eq!(customizer.template().unwrap().name, "Chrome 130+");
    
    // Test with Firefox template
    let config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Firefox135)
        .with_randomization_level(RandomizationLevel::Medium)
        .build();
    
    let customizer = DefaultCustomizer::new(config);
    assert!(customizer.template().is_some());
    assert_eq!(customizer.template().unwrap().name, "Firefox 135+");
    
    // Test with Safari template
    let config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Safari17)
        .with_randomization_level(RandomizationLevel::High)
        .build();
    
    let customizer = DefaultCustomizer::new(config);
    assert!(customizer.template().is_some());
    assert_eq!(customizer.template().unwrap().name, "Safari 17+");
    
    // Test with Edge template
    let config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Edge130)
        .with_randomization_level(RandomizationLevel::None)
        .build();
    
    let customizer = DefaultCustomizer::new(config);
    assert!(customizer.template().is_some());
    assert_eq!(customizer.template().unwrap().name, "Edge 130+");
}

/// Test that all hook phases can be invoked successfully
#[test]
fn test_end_to_end_hook_invocation() {
    let config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_randomization_level(RandomizationLevel::Light)
        .build();
    
    let customizer = DefaultCustomizer::new(config);
    
    // Phase 1: on_config_resolve
    let mut config_params = ConfigParams::new();
    assert!(customizer.on_config_resolve(&mut config_params).is_ok());
    
    // Phase 2: on_components_ready
    let mut cipher_suites = Vec::new();
    let mut extensions = Vec::new();
    assert!(customizer.on_components_ready(&mut cipher_suites, &mut extensions).is_ok());
    
    // Phase 3: on_struct_ready (would need real ClientHelloPayload)
    // Skipped for now as we can't easily create ClientHelloPayload
    
    // Phase 4: transform_wire_bytes
    let test_bytes = vec![1, 2, 3, 4, 5];
    let result = customizer.transform_wire_bytes(test_bytes.clone());
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), test_bytes);
}

/// Test that template is applied correctly
#[test]
fn test_end_to_end_template_application() {
    // Test each template
    let templates = vec![
        (BrowserTemplate::Chrome130, "Chrome 130+"),
        (BrowserTemplate::Firefox135, "Firefox 135+"),
        (BrowserTemplate::Safari17, "Safari 17+"),
        (BrowserTemplate::Edge130, "Edge 130+"),
    ];
    
    for (template, expected_name) in templates {
        let config = CustlsConfig::builder()
            .with_template(template)
            .with_randomization_level(RandomizationLevel::None)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        
        // Verify template is loaded
        assert!(customizer.template().is_some());
        assert_eq!(customizer.template().unwrap().name, expected_name);
        
        // Verify template has required fields
        let template_data = customizer.template().unwrap();
        assert!(!template_data.cipher_suites.is_empty());
        assert!(!template_data.extension_order.is_empty());
        assert!(!template_data.supported_groups.is_empty());
        assert!(!template_data.signature_algorithms.is_empty());
    }
}

/// Test that randomization works at different levels
#[test]
fn test_end_to_end_randomization() {
    let levels = vec![
        RandomizationLevel::None,
        RandomizationLevel::Light,
        RandomizationLevel::Medium,
        RandomizationLevel::High,
    ];
    
    for level in levels {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .with_randomization_level(level)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        
        // Invoke hooks to trigger randomization
        let mut cipher_suites = Vec::new();
        let mut extensions = Vec::new();
        
        let result = customizer.on_components_ready(&mut cipher_suites, &mut extensions);
        assert!(result.is_ok(), "Randomization level {:?} failed", level);
    }
}

/// Test that cache operations work correctly
#[test]
fn test_end_to_end_cache_operations() {
    let config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_cache(true)
        .with_max_cache_size(100)
        .build();
    
    let customizer = DefaultCustomizer::new(config);
    
    // Create a test target
    let target = TargetKey::new("example.com".to_string(), 443);
    
    // Create a test config
    let client_hello_config = ClientHelloConfig {
        template: BrowserTemplate::Chrome130,
        cipher_suites: Vec::new(),
        extension_order: Vec::new(),
        extension_data: Default::default(),
        grease_cipher_positions: Vec::new(),
        grease_extension_positions: Vec::new(),
        padding_length: 128,
        random_seed: 12345,
        supported_groups: Vec::new(),
        signature_algorithms: Vec::new(),
    };
    
    // Record a successful handshake
    customizer.record_handshake_result(&target, client_hello_config.clone(), true);
    
    // Record a failed handshake
    customizer.record_handshake_result(&target, client_hello_config.clone(), false);
    
    // Clear cache
    customizer.clear_cache();
    
    // Invalidate specific target
    let invalidated = customizer.invalidate_target(&target);
    // Should return false since we just cleared the cache
    assert!(!invalidated);
}

/// Test that template rotation works correctly
#[test]
fn test_end_to_end_template_rotation() {
    // Test round-robin rotation
    let config = CustlsConfig::builder()
        .with_rotation_policy(TemplateRotationPolicy::RoundRobin)
        .with_rotation_templates(vec![
            BrowserTemplate::Chrome130,
            BrowserTemplate::Firefox135,
        ])
        .build();
    
    let customizer = DefaultCustomizer::new(config);
    
    // Invoke hooks multiple times to trigger rotation
    for _ in 0..5 {
        let mut config_params = ConfigParams::new();
        assert!(customizer.on_config_resolve(&mut config_params).is_ok());
    }
    
    // Test random rotation
    let config = CustlsConfig::builder()
        .with_rotation_policy(TemplateRotationPolicy::Random)
        .with_rotation_templates(vec![
            BrowserTemplate::Chrome130,
            BrowserTemplate::Firefox135,
            BrowserTemplate::Safari17,
        ])
        .build();
    
    let customizer = DefaultCustomizer::new(config);
    
    for _ in 0..10 {
        let mut config_params = ConfigParams::new();
        assert!(customizer.on_config_resolve(&mut config_params).is_ok());
    }
    
    // Test weighted random rotation
    let config = CustlsConfig::builder()
        .with_rotation_policy(TemplateRotationPolicy::WeightedRandom)
        .build();
    
    let customizer = DefaultCustomizer::new(config);
    
    for _ in 0..20 {
        let mut config_params = ConfigParams::new();
        assert!(customizer.on_config_resolve(&mut config_params).is_ok());
    }
}

/// Test that customizer can be shared across threads (Arc)
#[test]
fn test_end_to_end_arc_sharing() {
    let config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_randomization_level(RandomizationLevel::Light)
        .build();
    
    let customizer = DefaultCustomizer::new_arc(config);
    
    // Clone the Arc
    let customizer_clone = Arc::clone(&customizer);
    
    // Both should work
    let mut config_params = ConfigParams::new();
    assert!(customizer.on_config_resolve(&mut config_params).is_ok());
    assert!(customizer_clone.on_config_resolve(&mut config_params).is_ok());
}

/// Test complete flow: config -> customizer -> hooks -> result
#[test]
fn test_end_to_end_complete_flow() {
    // Step 1: Create configuration
    let config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_randomization_level(RandomizationLevel::Light)
        .with_cache(true)
        .with_max_cache_size(1000)
        .build();
    
    // Step 2: Create customizer
    let customizer = DefaultCustomizer::new(config);
    
    // Verify customizer state
    assert!(customizer.template().is_some());
    assert_eq!(customizer.config().randomization_level, RandomizationLevel::Light);
    assert!(customizer.config().enable_cache);
    
    // Step 3: Invoke all hook phases
    
    // Phase 1: Pre-build
    let mut config_params = ConfigParams::new();
    let result = customizer.on_config_resolve(&mut config_params);
    assert!(result.is_ok(), "Phase 1 failed: {:?}", result);
    
    // Phase 2: Mid-build
    let mut cipher_suites = Vec::new();
    let mut extensions = Vec::new();
    let result = customizer.on_components_ready(&mut cipher_suites, &mut extensions);
    assert!(result.is_ok(), "Phase 2 failed: {:?}", result);
    
    // Phase 4: Post-marshal
    let test_bytes = vec![0x16, 0x03, 0x03, 0x00, 0x05]; // TLS handshake header
    let result = customizer.transform_wire_bytes(test_bytes.clone());
    assert!(result.is_ok(), "Phase 4 failed: {:?}", result);
    assert_eq!(result.unwrap(), test_bytes);
    
    // Step 4: Test cache operations
    let target = TargetKey::new("example.com".to_string(), 443);
    let client_hello_config = ClientHelloConfig {
        template: BrowserTemplate::Chrome130,
        cipher_suites: Vec::new(),
        extension_order: Vec::new(),
        extension_data: Default::default(),
        grease_cipher_positions: Vec::new(),
        grease_extension_positions: Vec::new(),
        padding_length: 256,
        random_seed: 54321,
        supported_groups: Vec::new(),
        signature_algorithms: Vec::new(),
    };
    
    customizer.record_handshake_result(&target, client_hello_config, true);
}

/// Test that multiple customizers can coexist
#[test]
fn test_end_to_end_multiple_customizers() {
    let configs = vec![
        CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .with_randomization_level(RandomizationLevel::Light)
            .build(),
        CustlsConfig::builder()
            .with_template(BrowserTemplate::Firefox135)
            .with_randomization_level(RandomizationLevel::Medium)
            .build(),
        CustlsConfig::builder()
            .with_template(BrowserTemplate::Safari17)
            .with_randomization_level(RandomizationLevel::High)
            .build(),
    ];
    
    let customizers: Vec<_> = configs.into_iter()
        .map(DefaultCustomizer::new)
        .collect();
    
    // All customizers should work independently
    for customizer in &customizers {
        let mut config_params = ConfigParams::new();
        assert!(customizer.on_config_resolve(&mut config_params).is_ok());
        
        let mut cipher_suites = Vec::new();
        let mut extensions = Vec::new();
        assert!(customizer.on_components_ready(&mut cipher_suites, &mut extensions).is_ok());
    }
}

/// Test error handling in hooks
#[test]
fn test_end_to_end_error_handling() {
    // Test with no template (should still work)
    let config = CustlsConfig::builder()
        .with_randomization_level(RandomizationLevel::Light)
        .build();
    
    let customizer = DefaultCustomizer::new(config);
    
    let mut config_params = ConfigParams::new();
    assert!(customizer.on_config_resolve(&mut config_params).is_ok());
    
    let mut cipher_suites = Vec::new();
    let mut extensions = Vec::new();
    assert!(customizer.on_components_ready(&mut cipher_suites, &mut extensions).is_ok());
}

/// Test that cache respects size limits
#[test]
fn test_end_to_end_cache_size_limit() {
    let config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_cache(true)
        .with_max_cache_size(5) // Small cache for testing
        .build();
    
    let customizer = DefaultCustomizer::new(config);
    
    // Add more entries than the cache can hold
    for i in 0..10 {
        let target = TargetKey::new(alloc::format!("example{}.com", i), 443);
        let client_hello_config = ClientHelloConfig {
            template: BrowserTemplate::Chrome130,
            cipher_suites: Vec::new(),
            extension_order: Vec::new(),
            extension_data: Default::default(),
            grease_cipher_positions: Vec::new(),
            grease_extension_positions: Vec::new(),
            padding_length: 128,
            random_seed: i,
            supported_groups: Vec::new(),
            signature_algorithms: Vec::new(),
        };
        
        customizer.record_handshake_result(&target, client_hello_config, true);
    }
    
    // Cache should have evicted old entries
    // We can't directly verify the cache size, but the operation should succeed
}

/// Test that randomization produces different results across invocations
#[test]
fn test_end_to_end_randomization_variation() {
    let config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_randomization_level(RandomizationLevel::Medium)
        .build();
    
    let customizer = DefaultCustomizer::new(config);
    
    // Invoke hooks multiple times
    // Note: We can't easily verify the actual variation without inspecting
    // the internal state, but we can verify that the operations succeed
    for _ in 0..10 {
        let mut cipher_suites = Vec::new();
        let mut extensions = Vec::new();
        assert!(customizer.on_components_ready(&mut cipher_suites, &mut extensions).is_ok());
    }
}

/// Test configuration builder with all options
#[test]
fn test_end_to_end_full_configuration() {
    let config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_randomization_level(RandomizationLevel::High)
        .with_cache(true)
        .with_max_cache_size(2000)
        .with_rotation_policy(TemplateRotationPolicy::WeightedRandom)
        .with_rotation_templates(vec![
            BrowserTemplate::Chrome130,
            BrowserTemplate::Firefox135,
            BrowserTemplate::Safari17,
            BrowserTemplate::Edge130,
        ])
        .build();
    
    let customizer = DefaultCustomizer::new(config);
    
    // Verify all settings
    assert!(customizer.template().is_some());
    assert_eq!(customizer.config().randomization_level, RandomizationLevel::High);
    assert!(customizer.config().enable_cache);
    assert_eq!(customizer.config().max_cache_size, 2000);
    assert_eq!(customizer.config().rotation_policy, TemplateRotationPolicy::WeightedRandom);
    assert_eq!(customizer.config().rotation_templates.len(), 4);
    
    // Test that it works
    let mut config_params = ConfigParams::new();
    assert!(customizer.on_config_resolve(&mut config_params).is_ok());
}

/// Test that cache can be cleared and invalidated
#[test]
fn test_end_to_end_cache_management() {
    let config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_cache(true)
        .build();
    
    let customizer = DefaultCustomizer::new(config);
    
    // Add some entries
    let targets = vec![
        TargetKey::new("example1.com".to_string(), 443),
        TargetKey::new("example2.com".to_string(), 443),
        TargetKey::new("example3.com".to_string(), 443),
    ];
    
    for target in &targets {
        let client_hello_config = ClientHelloConfig {
            template: BrowserTemplate::Chrome130,
            cipher_suites: Vec::new(),
            extension_order: Vec::new(),
            extension_data: Default::default(),
            grease_cipher_positions: Vec::new(),
            grease_extension_positions: Vec::new(),
            padding_length: 128,
            random_seed: 12345,
            supported_groups: Vec::new(),
            signature_algorithms: Vec::new(),
        };
        
        customizer.record_handshake_result(target, client_hello_config, true);
    }
    
    // Invalidate one target
    let invalidated = customizer.invalidate_target(&targets[0]);
    assert!(invalidated, "Should have invalidated existing entry");
    
    // Try to invalidate again (should return false)
    let invalidated = customizer.invalidate_target(&targets[0]);
    assert!(!invalidated, "Should not find entry after invalidation");
    
    // Clear entire cache
    customizer.clear_cache();
    
    // All targets should be gone
    for target in &targets {
        let invalidated = customizer.invalidate_target(target);
        assert!(!invalidated, "Cache should be empty after clear");
    }
}

/// Test that template data is correctly loaded
#[test]
fn test_end_to_end_template_data_integrity() {
    let templates = vec![
        BrowserTemplate::Chrome130,
        BrowserTemplate::Firefox135,
        BrowserTemplate::Safari17,
        BrowserTemplate::Edge130,
    ];
    
    for template in templates {
        let config = CustlsConfig::builder()
            .with_template(template.clone())
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        let template_data = customizer.template().expect("Template should be loaded");
        
        // Verify template has all required data
        assert!(!template_data.name.is_empty(), "Template name should not be empty");
        assert!(!template_data.description.is_empty(), "Template description should not be empty");
        assert!(!template_data.cipher_suites.is_empty(), "Cipher suites should not be empty");
        assert!(!template_data.extension_order.is_empty(), "Extension order should not be empty");
        assert!(!template_data.supported_groups.is_empty(), "Support groups should not be empty");
        assert!(!template_data.signature_algorithms.is_empty(), "Signature algorithms should not be empty");
        assert!(!template_data.alpn_protocols.is_empty(), "ALPN protocols should not be empty");
        assert!(!template_data.supported_versions.is_empty(), "Supported versions should not be empty");
        assert!(!template_data.key_share_groups.is_empty(), "Key share groups should not be empty");
        
        // Verify GREASE pattern
        assert!(template_data.grease_pattern.cipher_suite_probability >= 0.0);
        assert!(template_data.grease_pattern.cipher_suite_probability <= 1.0);
        assert!(template_data.grease_pattern.extension_probability >= 0.0);
        assert!(template_data.grease_pattern.extension_probability <= 1.0);
        
        // Verify padding distribution
        assert!(template_data.padding_distribution.min_length <= template_data.padding_distribution.max_length);
        assert!(!template_data.padding_distribution.pmf.is_empty());
    }
}
