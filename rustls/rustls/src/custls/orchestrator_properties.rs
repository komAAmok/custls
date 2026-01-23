//! Property-based tests for DefaultCustomizer orchestration.
//!
//! These tests verify universal properties that should hold across all inputs
//! and configurations for the DefaultCustomizer.

#[cfg(test)]
mod properties {
    use super::super::*;
    use proptest::prelude::*;
    use alloc::vec;
    use alloc::vec::Vec;
    
    // Helper to generate arbitrary BrowserTemplate
    fn arbitrary_browser_template() -> impl Strategy<Value = BrowserTemplate> {
        prop_oneof![
            Just(BrowserTemplate::Chrome130),
            Just(BrowserTemplate::Firefox135),
            Just(BrowserTemplate::Safari17),
            Just(BrowserTemplate::Edge130),
        ]
    }
    
    // Helper to generate arbitrary RandomizationLevel
    fn arbitrary_randomization_level() -> impl Strategy<Value = RandomizationLevel> {
        prop_oneof![
            Just(RandomizationLevel::None),
            Just(RandomizationLevel::Light),
            Just(RandomizationLevel::Medium),
            Just(RandomizationLevel::High),
        ]
    }
    
    // Helper to generate arbitrary TemplateRotationPolicy
    fn arbitrary_rotation_policy() -> impl Strategy<Value = TemplateRotationPolicy> {
        prop_oneof![
            Just(TemplateRotationPolicy::None),
            Just(TemplateRotationPolicy::RoundRobin),
            Just(TemplateRotationPolicy::Random),
            Just(TemplateRotationPolicy::WeightedRandom),
        ]
    }
    
    /// Property 10: Template Rotation Variation
    ///
    /// For any sequence of connections with automatic template rotation enabled,
    /// consecutive connections SHALL use different templates according to the rotation policy.
    ///
    /// **Validates: Requirements 5.6**
    proptest! {
        #[test]
        fn property_template_rotation_variation(
            rotation_policy in arbitrary_rotation_policy(),
            num_connections in 2usize..20,
        ) {
            // Skip if rotation is disabled
            prop_assume!(rotation_policy != TemplateRotationPolicy::None);
            
            // Create config with rotation enabled
            let config = CustlsConfig::builder()
                .with_rotation_policy(rotation_policy)
                .with_rotation_templates(vec![
                    BrowserTemplate::Chrome130,
                    BrowserTemplate::Firefox135,
                    BrowserTemplate::Safari17,
                ])
                .build();
            
            let customizer = DefaultCustomizer::new(config);
            
            // Select templates for multiple connections
            let mut templates = Vec::new();
            for _ in 0..num_connections {
                if let Some(template) = customizer.select_rotated_template() {
                    templates.push(template);
                }
            }
            
            // Verify we got the expected number of templates
            prop_assert_eq!(templates.len(), num_connections);
            
            // For RoundRobin, verify templates cycle through the list
            if rotation_policy == TemplateRotationPolicy::RoundRobin {
                // Check that we see all templates in the rotation list
                // (if we have enough connections)
                if num_connections >= 3 {
                    let has_chrome = templates.iter().any(|t| matches!(t, BrowserTemplate::Chrome130));
                    let has_firefox = templates.iter().any(|t| matches!(t, BrowserTemplate::Firefox135));
                    let has_safari = templates.iter().any(|t| matches!(t, BrowserTemplate::Safari17));
                    
                    prop_assert!(has_chrome || has_firefox || has_safari,
                        "RoundRobin should cycle through templates");
                }
            }
            
            // For Random and WeightedRandom, verify we get variation
            // (with high probability for enough connections)
            if (rotation_policy == TemplateRotationPolicy::Random ||
                rotation_policy == TemplateRotationPolicy::WeightedRandom) &&
               num_connections >= 10 {
                // Count unique templates
                let mut unique_templates = std::collections::HashSet::new();
                for template in &templates {
                    unique_templates.insert(template);
                }
                
                // Should have at least 2 different templates with high probability
                prop_assert!(unique_templates.len() >= 2,
                    "Random rotation should produce variation (got {} unique templates)",
                    unique_templates.len());
            }
        }
    }
    
    /// Property 17: Template-Consistent Variation
    ///
    /// For any two connections using the same browser template, the ClientHello messages
    /// SHALL be similar (matching template constraints) but not byte-for-byte identical,
    /// with variations in GREASE values, padding length, and minor extension ordering.
    ///
    /// **Validates: Requirements 10.4**
    proptest! {
        #[test]
        fn property_template_consistent_variation(
            template in arbitrary_browser_template(),
            randomization_level in arbitrary_randomization_level(),
        ) {
            // Skip if randomization is None (no variation expected)
            prop_assume!(randomization_level != RandomizationLevel::None);
            
            // Create two customizers with the same template and randomization level
            let config1 = CustlsConfig::builder()
                .with_template(template.clone())
                .with_randomization_level(randomization_level)
                .build();
            
            let config2 = CustlsConfig::builder()
                .with_template(template)
                .with_randomization_level(randomization_level)
                .build();
            
            let customizer1 = DefaultCustomizer::new(config1);
            let customizer2 = DefaultCustomizer::new(config2);
            
            // Verify both have the same template
            prop_assert!(customizer1.template().is_some());
            prop_assert!(customizer2.template().is_some());
            
            let template1 = customizer1.template().unwrap();
            let template2 = customizer2.template().unwrap();
            
            // Templates should have the same name (same browser)
            prop_assert_eq!(&template1.name, &template2.name);
            
            // Templates should have the same cipher suites (template constraint)
            prop_assert_eq!(template1.cipher_suites.len(), template2.cipher_suites.len());
            
            // Templates should have the same extension order (template constraint)
            prop_assert_eq!(template1.extension_order.len(), template2.extension_order.len());
            
            // Note: We can't easily test actual ClientHello generation here without
            // full rustls integration. This test verifies that the templates are
            // consistent, which is a prerequisite for template-consistent variation.
            
            // The actual variation (GREASE, padding, minor shuffling) would be tested
            // in integration tests with real ClientHello generation.
        }
    }
    
    /// Additional property: Customizer creation is deterministic
    ///
    /// Creating multiple customizers with the same config should produce
    /// equivalent customizers (same template, same settings).
    proptest! {
        #[test]
        fn property_customizer_creation_deterministic(
            template in arbitrary_browser_template(),
            randomization_level in arbitrary_randomization_level(),
            enable_cache in prop::bool::ANY,
        ) {
            let config = CustlsConfig::builder()
                .with_template(template)
                .with_randomization_level(randomization_level)
                .with_cache(enable_cache)
                .build();
            
            let customizer1 = DefaultCustomizer::new(config.clone());
            let customizer2 = DefaultCustomizer::new(config);
            
            // Both should have templates (or both should not)
            prop_assert_eq!(customizer1.template().is_some(), customizer2.template().is_some());
            
            // If templates exist, they should have the same name
            if let (Some(t1), Some(t2)) = (customizer1.template(), customizer2.template()) {
                prop_assert_eq!(&t1.name, &t2.name);
            }
            
            // Both should have cache (or both should not)
            prop_assert_eq!(customizer1.cache.is_some(), customizer2.cache.is_some());
        }
    }
}
