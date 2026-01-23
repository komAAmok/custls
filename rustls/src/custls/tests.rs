//! Unit tests for custls core types

use super::*;
use alloc::format;
use alloc::vec;

#[test]
fn test_custls_error_display() {
    let hook_err = CustlsError::HookError("test hook error".into());
    assert_eq!(format!("{}", hook_err), "Hook error: test hook error");
    
    let rand_err = CustlsError::RandomizationError("test randomization error".into());
    assert_eq!(format!("{}", rand_err), "Randomization error: test randomization error");
    
    let ext_err = CustlsError::ExtensionError("test extension error".into());
    assert_eq!(format!("{}", ext_err), "Extension error: test extension error");
    
    let template_err = CustlsError::TemplateError("test template error".into());
    assert_eq!(format!("{}", template_err), "Template error: test template error");
    
    let cache_err = CustlsError::CacheError("test cache error".into());
    assert_eq!(format!("{}", cache_err), "Cache error: test cache error");
    
    let validation_err = CustlsError::ValidationError("test validation error".into());
    assert_eq!(format!("{}", validation_err), "Validation error: test validation error");
}

#[test]
fn test_custls_error_to_rustls_error() {
    let custls_err = CustlsError::HookError("test error".into());
    let rustls_err: RustlsError = custls_err.into();
    
    match rustls_err {
        RustlsError::General(msg) => {
            assert!(msg.contains("custls error"));
            assert!(msg.contains("Hook error"));
            assert!(msg.contains("test error"));
        }
        _ => panic!("Expected General error variant"),
    }
}

#[test]
fn test_randomization_level_default() {
    let level = RandomizationLevel::default();
    assert_eq!(level, RandomizationLevel::Light);
}

#[test]
fn test_randomization_level_equality() {
    assert_eq!(RandomizationLevel::None, RandomizationLevel::None);
    assert_eq!(RandomizationLevel::Light, RandomizationLevel::Light);
    assert_eq!(RandomizationLevel::Medium, RandomizationLevel::Medium);
    assert_eq!(RandomizationLevel::High, RandomizationLevel::High);
    
    assert_ne!(RandomizationLevel::None, RandomizationLevel::Light);
    assert_ne!(RandomizationLevel::Light, RandomizationLevel::Medium);
    assert_ne!(RandomizationLevel::Medium, RandomizationLevel::High);
}

#[test]
fn test_browser_template_variants() {
    let chrome = BrowserTemplate::Chrome130;
    let firefox = BrowserTemplate::Firefox135;
    let safari = BrowserTemplate::Safari17;
    let edge = BrowserTemplate::Edge130;
    
    // Test that variants can be created
    assert!(matches!(chrome, BrowserTemplate::Chrome130));
    assert!(matches!(firefox, BrowserTemplate::Firefox135));
    assert!(matches!(safari, BrowserTemplate::Safari17));
    assert!(matches!(edge, BrowserTemplate::Edge130));
}

#[test]
fn test_browser_template_custom() {
    let custom_template = CustomTemplate {
        name: "TestBrowser".into(),
        description: "A test browser template".into(),
    };
    
    let template = BrowserTemplate::Custom(Box::new(custom_template.clone()));
    
    match template {
        BrowserTemplate::Custom(t) => {
            assert_eq!(t.name, "TestBrowser");
            assert_eq!(t.description, "A test browser template");
        }
        _ => panic!("Expected Custom variant"),
    }
}

#[test]
fn test_custls_config_default() {
    let config = CustlsConfig::default();
    
    assert!(config.template.is_none());
    assert_eq!(config.randomization_level, RandomizationLevel::Light);
    assert!(config.enable_cache);
    assert_eq!(config.max_cache_size, 1000);
}

#[test]
fn test_custls_config_builder_default() {
    let config = CustlsConfig::builder().build();
    
    assert!(config.template.is_none());
    assert_eq!(config.randomization_level, RandomizationLevel::Light);
    assert!(config.enable_cache);
    assert_eq!(config.max_cache_size, 1000);
}

#[test]
fn test_custls_config_builder_with_template() {
    let config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .build();
    
    assert!(config.template.is_some());
    assert!(matches!(config.template.unwrap(), BrowserTemplate::Chrome130));
}

#[test]
fn test_custls_config_builder_with_randomization_level() {
    let config = CustlsConfig::builder()
        .with_randomization_level(RandomizationLevel::High)
        .build();
    
    assert_eq!(config.randomization_level, RandomizationLevel::High);
}

#[test]
fn test_custls_config_builder_with_cache_disabled() {
    let config = CustlsConfig::builder()
        .with_cache(false)
        .build();
    
    assert!(!config.enable_cache);
}

#[test]
fn test_custls_config_builder_with_max_cache_size() {
    let config = CustlsConfig::builder()
        .with_max_cache_size(500)
        .build();
    
    assert_eq!(config.max_cache_size, 500);
}

#[test]
fn test_custls_config_builder_chaining() {
    let config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Firefox135)
        .with_randomization_level(RandomizationLevel::Medium)
        .with_cache(true)
        .with_max_cache_size(2000)
        .build();
    
    assert!(config.template.is_some());
    assert!(matches!(config.template.unwrap(), BrowserTemplate::Firefox135));
    assert_eq!(config.randomization_level, RandomizationLevel::Medium);
    assert!(config.enable_cache);
    assert_eq!(config.max_cache_size, 2000);
}

#[test]
fn test_custls_config_builder_new() {
    let builder = CustlsConfigBuilder::new();
    let config = builder.build();
    
    assert!(config.template.is_none());
    assert_eq!(config.randomization_level, RandomizationLevel::Light);
    assert!(config.enable_cache);
    assert_eq!(config.max_cache_size, 1000);
}

#[test]
fn test_custls_config_builder_multiple_builds() {
    let builder = CustlsConfig::builder()
        .with_template(BrowserTemplate::Safari17)
        .with_randomization_level(RandomizationLevel::None);
    
    let config1 = builder.clone().build();
    let config2 = builder.build();
    
    // Both configs should have the same settings
    assert!(matches!(config1.template.as_ref().unwrap(), BrowserTemplate::Safari17));
    assert!(matches!(config2.template.as_ref().unwrap(), BrowserTemplate::Safari17));
    assert_eq!(config1.randomization_level, RandomizationLevel::None);
    assert_eq!(config2.randomization_level, RandomizationLevel::None);
}

#[test]
fn test_browser_template_equality() {
    let chrome1 = BrowserTemplate::Chrome130;
    let chrome2 = BrowserTemplate::Chrome130;
    let firefox = BrowserTemplate::Firefox135;
    
    assert_eq!(chrome1, chrome2);
    assert_ne!(chrome1, firefox);
}

#[test]
fn test_custom_template_equality() {
    let custom1 = CustomTemplate {
        name: "Test".into(),
        description: "Test template".into(),
    };
    
    let custom2 = CustomTemplate {
        name: "Test".into(),
        description: "Test template".into(),
    };
    
    let custom3 = CustomTemplate {
        name: "Different".into(),
        description: "Test template".into(),
    };
    
    assert_eq!(custom1, custom2);
    assert_ne!(custom1, custom3);
}

#[test]
fn test_custls_error_clone() {
    let err1 = CustlsError::HookError("test".into());
    let err2 = err1.clone();
    
    assert_eq!(format!("{}", err1), format!("{}", err2));
}

#[test]
fn test_randomization_level_copy() {
    let level1 = RandomizationLevel::Medium;
    let level2 = level1; // Copy
    
    assert_eq!(level1, level2);
}
