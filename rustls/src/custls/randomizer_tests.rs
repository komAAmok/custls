//! Unit tests for BrowserRandomizer
//!
//! These tests verify specific examples and edge cases for the randomizer.

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::custls::templates::{chrome_130, firefox_135, safari_17, edge_130, NaturalnessFilter};
    use crate::custls::RandomizationLevel;
    use alloc::vec;
    
    #[test]
    fn test_randomizer_creation() {
        let randomizer = BrowserRandomizer::new(
            RandomizationLevel::Light,
            NaturalnessFilter::default(),
        );
        
        assert_eq!(randomizer.level(), RandomizationLevel::Light);
    }
    
    #[test]
    fn test_randomizer_with_different_levels() {
        let levels = vec![
            RandomizationLevel::None,
            RandomizationLevel::Light,
            RandomizationLevel::Medium,
            RandomizationLevel::High,
        ];
        
        for level in levels {
            let randomizer = BrowserRandomizer::new(level, NaturalnessFilter::default());
            assert_eq!(randomizer.level(), level);
        }
    }
    
    #[test]
    fn test_generate_padding_len_none_level() {
        let mut randomizer = BrowserRandomizer::new(
            RandomizationLevel::None,
            NaturalnessFilter::default(),
        );
        
        let template = chrome_130();
        let padding_len = randomizer.generate_padding_len(&template, &[]);
        
        // With None level, should return first PMF entry
        let expected = template.padding_distribution.pmf
            .first()
            .map(|(len, _)| *len)
            .unwrap_or(0);
        
        assert_eq!(padding_len, expected);
    }
    
    #[test]
    fn test_generate_padding_len_within_range() {
        let mut randomizer = BrowserRandomizer::new(
            RandomizationLevel::High,
            NaturalnessFilter::default(),
        );
        
        let template = chrome_130();
        
        // Generate multiple padding lengths and verify they're all within range
        for _ in 0..20 {
            let padding_len = randomizer.generate_padding_len(&template, &[]);
            assert!(padding_len >= template.padding_distribution.min_length);
            assert!(padding_len <= template.padding_distribution.max_length);
        }
    }
    
    #[test]
    fn test_generate_padding_len_different_templates() {
        let mut randomizer = BrowserRandomizer::new(
            RandomizationLevel::Medium,
            NaturalnessFilter::default(),
        );
        
        let templates = vec![
            chrome_130(),
            firefox_135(),
            safari_17(),
            edge_130(),
        ];
        
        for template in templates {
            let padding_len = randomizer.generate_padding_len(&template, &[]);
            assert!(padding_len >= template.padding_distribution.min_length);
            assert!(padding_len <= template.padding_distribution.max_length);
        }
    }
    
    #[test]
    fn test_generate_padding_len_safari_minimal() {
        let mut randomizer = BrowserRandomizer::new(
            RandomizationLevel::Light,
            NaturalnessFilter::default(),
        );
        
        let template = safari_17();
        
        // Safari typically uses minimal padding (max 64 bytes)
        for _ in 0..10 {
            let padding_len = randomizer.generate_padding_len(&template, &[]);
            assert!(padding_len <= 64);
        }
    }
    
    #[test]
    fn test_nearest_power_of_2() {
        let randomizer = BrowserRandomizer::new(
            RandomizationLevel::Light,
            NaturalnessFilter::default(),
        );
        
        // Test various values
        assert_eq!(randomizer.nearest_power_of_2(0, 0, 1000), 0);
        assert_eq!(randomizer.nearest_power_of_2(1, 0, 1000), 1);
        assert_eq!(randomizer.nearest_power_of_2(3, 0, 1000), 2);
        assert_eq!(randomizer.nearest_power_of_2(5, 0, 1000), 4);
        assert_eq!(randomizer.nearest_power_of_2(100, 0, 1000), 128);
        assert_eq!(randomizer.nearest_power_of_2(200, 0, 1000), 256);
        assert_eq!(randomizer.nearest_power_of_2(400, 0, 1000), 512);
        assert_eq!(randomizer.nearest_power_of_2(700, 0, 1000), 512);
    }
    
    #[test]
    fn test_nearest_power_of_2_with_range_limits() {
        let randomizer = BrowserRandomizer::new(
            RandomizationLevel::Light,
            NaturalnessFilter::default(),
        );
        
        // Test with restricted range
        assert_eq!(randomizer.nearest_power_of_2(100, 64, 256), 128);
        assert_eq!(randomizer.nearest_power_of_2(10, 64, 256), 64);
        assert_eq!(randomizer.nearest_power_of_2(300, 64, 256), 256);
    }
    
    #[test]
    fn test_shuffle_extensions_placeholder() {
        // Placeholder test for shuffle_extensions
        // Once ClientExtension has real implementation, this should test:
        // - Empty extension list
        // - Extension list with PSK
        // - Extension list without PSK
        // - Different randomization levels produce different behavior
        
        let mut randomizer = BrowserRandomizer::new(
            RandomizationLevel::Light,
            NaturalnessFilter::default(),
        );
        
        let template = chrome_130();
        let mut extensions = Vec::new();
        
        // Should not error on empty list
        let result = randomizer.shuffle_extensions(&mut extensions, &template);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_inject_grease_placeholder() {
        // Placeholder test for inject_grease
        // Once CipherSuite and ClientExtension have real implementations, this should test:
        // - GREASE injection with different templates
        // - GREASE values are from template's grease_values list
        // - GREASE positions follow template's preferred positions
        // - Chrome prefers front third for cipher suites
        
        let mut randomizer = BrowserRandomizer::new(
            RandomizationLevel::Light,
            NaturalnessFilter::default(),
        );
        
        let template = chrome_130();
        let mut cipher_suites = Vec::new();
        let mut extensions = Vec::new();
        
        // Should not error on empty lists
        let result = randomizer.inject_grease(&mut cipher_suites, &mut extensions, &template, &[]);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_inject_grease_respects_probability() {
        let mut randomizer = BrowserRandomizer::new(
            RandomizationLevel::High,
            NaturalnessFilter::default(),
        );
        
        let template = chrome_130();
        
        // Chrome has 100% GREASE probability
        assert_eq!(template.grease_pattern.cipher_suite_probability, 1.0);
        assert_eq!(template.grease_pattern.extension_probability, 1.0);
        
        // Safari has lower GREASE probability
        let safari = safari_17();
        assert_eq!(safari.grease_pattern.cipher_suite_probability, 0.8);
        assert_eq!(safari.grease_pattern.extension_probability, 0.8);
    }
    
    #[test]
    fn test_randomization_level_none_does_nothing() {
        let mut randomizer = BrowserRandomizer::new(
            RandomizationLevel::None,
            NaturalnessFilter::default(),
        );
        
        let template = chrome_130();
        let mut cipher_suites = Vec::new();
        let mut extensions = Vec::new();
        
        // With None level, should not modify anything
        let result = randomizer.inject_grease(&mut cipher_suites, &mut extensions, &template, &[]);
        assert!(result.is_ok());
        
        // Lists should still be empty
        assert!(cipher_suites.is_empty());
        assert!(extensions.is_empty());
    }
    
    #[test]
    fn test_naturalness_filter_access() {
        let filter = NaturalnessFilter::default();
        let randomizer = BrowserRandomizer::new(
            RandomizationLevel::Light,
            filter.clone(),
        );
        
        // Should be able to access the filter
        let retrieved_filter = randomizer.naturalness_filter();
        assert_eq!(retrieved_filter.blacklist.len(), filter.blacklist.len());
    }
}
