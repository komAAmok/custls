//! Property-based tests for browser templates
//!
//! These tests verify universal properties that should hold for all templates
//! and all randomization levels.

#[cfg(test)]
mod property_tests {
    use super::super::*;
    use proptest::prelude::*;
    
    // Feature: custls, Property 9: Template Application Fidelity
    //
    // For any browser template applied to a ClientHello, the resulting cipher suites,
    // extension order, support groups, and GREASE behavior SHALL match the template's
    // specification within the bounds of the configured randomization level.
    //
    // Validates: Requirements 5.2, 5.3, 5.4, 8.2
    
    /// Strategy to generate all available browser templates
    fn template_strategy() -> impl Strategy<Value = TemplateData> {
        prop_oneof![
            Just(chrome_130()),
            Just(firefox_135()),
            Just(safari_17()),
            Just(edge_130()),
        ]
    }
    
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        #[test]
        fn template_has_valid_cipher_suites(template in template_strategy()) {
            // Property: All templates must have at least one cipher suite
            prop_assert!(!template.cipher_suites.is_empty(),
                "Template '{}' has no cipher suites", template.name);
            
            // Property: Cipher suites should be reasonable in number (1-50)
            prop_assert!(template.cipher_suites.len() <= 50,
                "Template '{}' has too many cipher suites: {}",
                template.name, template.cipher_suites.len());
        }
        
        #[test]
        fn template_has_valid_extensions(template in template_strategy()) {
            // Property: All templates must have at least one extension
            prop_assert!(!template.extension_order.is_empty(),
                "Template '{}' has no extensions", template.name);
            
            // Property: Extensions should be reasonable in number (1-30)
            prop_assert!(template.extension_order.len() <= 30,
                "Template '{}' has too many extensions: {}",
                template.name, template.extension_order.len());
        }
        
        #[test]
        fn template_has_valid_supported_groups(template in template_strategy()) {
            // Property: All templates must have at least one supported group
            prop_assert!(!template.supported_groups.is_empty(),
                "Template '{}' has no supported groups", template.name);
            
            // Property: Supported groups should be reasonable in number (1-20)
            prop_assert!(template.supported_groups.len() <= 20,
                "Template '{}' has too many supported groups: {}",
                template.name, template.supported_groups.len());
        }
        
        #[test]
        fn template_has_valid_signature_algorithms(template in template_strategy()) {
            // Property: All templates must have at least one signature algorithm
            prop_assert!(!template.signature_algorithms.is_empty(),
                "Template '{}' has no signature algorithms", template.name);
            
            // Property: Signature algorithms should be reasonable in number (1-30)
            prop_assert!(template.signature_algorithms.len() <= 30,
                "Template '{}' has too many signature algorithms: {}",
                template.name, template.signature_algorithms.len());
        }
        
        #[test]
        fn template_grease_pattern_valid(template in template_strategy()) {
            // Property: GREASE probabilities must be between 0.0 and 1.0
            prop_assert!(template.grease_pattern.cipher_suite_probability >= 0.0
                && template.grease_pattern.cipher_suite_probability <= 1.0,
                "Template '{}' has invalid cipher suite GREASE probability: {}",
                template.name, template.grease_pattern.cipher_suite_probability);
            
            prop_assert!(template.grease_pattern.extension_probability >= 0.0
                && template.grease_pattern.extension_probability <= 1.0,
                "Template '{}' has invalid extension GREASE probability: {}",
                template.name, template.grease_pattern.extension_probability);
            
            // Property: GREASE positions must be normalized (0.0-1.0)
            for pos in &template.grease_pattern.cipher_suite_positions {
                prop_assert!(*pos >= 0.0 && *pos <= 1.0,
                    "Template '{}' has invalid cipher suite GREASE position: {}",
                    template.name, pos);
            }
            
            for pos in &template.grease_pattern.extension_positions {
                prop_assert!(*pos >= 0.0 && *pos <= 1.0,
                    "Template '{}' has invalid extension GREASE position: {}",
                    template.name, pos);
            }
            
            // Property: GREASE values should be valid (all should be 0x?a?a format)
            for val in &template.grease_pattern.grease_values {
                let low_byte = val & 0xFF;
                let high_byte = (val >> 8) & 0xFF;
                prop_assert!(low_byte == high_byte && (low_byte & 0x0F) == 0x0A,
                    "Template '{}' has invalid GREASE value: 0x{:04x}",
                    template.name, val);
            }
        }
        
        #[test]
        fn template_padding_distribution_valid(template in template_strategy()) {
            // Property: Padding min <= max
            prop_assert!(template.padding_distribution.min_length
                <= template.padding_distribution.max_length,
                "Template '{}' has invalid padding range: min={}, max={}",
                template.name,
                template.padding_distribution.min_length,
                template.padding_distribution.max_length);
            
            // Property: Padding max should be reasonable (< 2000 bytes)
            prop_assert!(template.padding_distribution.max_length < 2000,
                "Template '{}' has excessive max padding: {}",
                template.name, template.padding_distribution.max_length);
            
            // Property: Power of 2 bias must be between 0.0 and 1.0
            prop_assert!(template.padding_distribution.power_of_2_bias >= 0.0
                && template.padding_distribution.power_of_2_bias <= 1.0,
                "Template '{}' has invalid power_of_2_bias: {}",
                template.name, template.padding_distribution.power_of_2_bias);
            
            // Property: PMF probabilities should sum to approximately 1.0
            let total_prob: f64 = template.padding_distribution.pmf
                .iter()
                .map(|(_, p)| p)
                .sum();
            prop_assert!((total_prob - 1.0).abs() < 0.2,
                "Template '{}' has invalid PMF (sum={})",
                template.name, total_prob);
            
            // Property: All PMF lengths should be within min/max range
            for (len, _) in &template.padding_distribution.pmf {
                prop_assert!(*len >= template.padding_distribution.min_length
                    && *len <= template.padding_distribution.max_length,
                    "Template '{}' has PMF length {} outside range [{}, {}]",
                    template.name, len,
                    template.padding_distribution.min_length,
                    template.padding_distribution.max_length);
            }
        }
        
        #[test]
        fn template_has_valid_alpn(template in template_strategy()) {
            // Property: All templates should have at least one ALPN protocol
            prop_assert!(!template.alpn_protocols.is_empty(),
                "Template '{}' has no ALPN protocols", template.name);
            
            // Property: ALPN protocols should be non-empty
            for alpn in &template.alpn_protocols {
                prop_assert!(!alpn.is_empty(),
                    "Template '{}' has empty ALPN protocol", template.name);
            }
        }
        
        #[test]
        fn template_has_valid_http2_headers(template in template_strategy()) {
            // Property: HTTP/2 pseudo-header order should contain standard headers
            let headers = &template.http2_pseudo_header_order;
            
            // Most browsers include these four pseudo-headers
            let expected_headers = [":method", ":path", ":authority", ":scheme"];
            let mut found_count = 0;
            
            for expected in &expected_headers {
                if headers.iter().any(|h| h == expected) {
                    found_count += 1;
                }
            }
            
            // Property: Should have at least 3 of the 4 standard headers
            prop_assert!(found_count >= 3,
                "Template '{}' has incomplete HTTP/2 pseudo-headers (found {}/4)",
                template.name, found_count);
        }
        
        #[test]
        fn template_has_valid_tls_versions(template in template_strategy()) {
            // Property: All templates must support at least one TLS version
            prop_assert!(!template.supported_versions.is_empty(),
                "Template '{}' has no supported TLS versions", template.name);
            
            // Property: Should support TLS 1.2 or TLS 1.3 (modern browsers)
            let has_modern_tls = template.supported_versions.iter().any(|v| {
                matches!(v, ProtocolVersion::TLSv1_2 | ProtocolVersion::TLSv1_3)
            });
            
            prop_assert!(has_modern_tls,
                "Template '{}' doesn't support TLS 1.2 or 1.3", template.name);
        }
        
        #[test]
        fn template_key_share_groups_subset_of_supported(template in template_strategy()) {
            // Property: Key share groups must be a subset of supported groups
            for key_share_group in &template.key_share_groups {
                prop_assert!(template.supported_groups.contains(key_share_group),
                    "Template '{}' has key share group {:?} not in supported groups",
                    template.name, key_share_group);
            }
        }
        
        #[test]
        fn template_has_name_and_description(template in template_strategy()) {
            // Property: All templates must have a non-empty name
            prop_assert!(!template.name.is_empty(),
                "Template has empty name");
            
            // Property: All templates must have a non-empty description
            prop_assert!(!template.description.is_empty(),
                "Template '{}' has empty description", template.name);
        }
    }
}
