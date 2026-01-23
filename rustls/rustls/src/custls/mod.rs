//! # custls - Browser-Level TLS ClientHello Fingerprint Simulation
//!
//! custls is a minimal-invasive extension to rustls that provides sophisticated
//! ClientHello customization capabilities for browser fingerprint simulation.
//!
//! ## Overview
//!
//! This module provides:
//! - Multi-phase hook system for ClientHello customization
//! - Browser simulation templates (Chrome, Firefox, Safari, Edge)
//! - Non-uniform randomization matching real browser behavior
//! - Working fingerprint cache with reputation tracking
//! - Missing TLS extension implementations
//!
//! ## Design Philosophy
//!
//! custls maintains minimal invasiveness: all customization logic is isolated
//! in this module with only strategic "probe points" inserted into rustls's
//! native flow. This facilitates easy upstream rebasing while providing
//! powerful customization capabilities.
//!
//! ## Security
//!
//! custls preserves all rustls security guarantees:
//! - Zero unsafe code
//! - RFC 8446 downgrade protection
//! - Certificate validation unchanged
//! - Constant-time cryptographic operations maintained

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::error::Error as RustlsError;

/// Core error type for custls operations
#[derive(Debug, Clone)]
pub enum CustlsError {
    /// Error occurred during hook execution
    HookError(String),
    
    /// Error occurred during randomization
    RandomizationError(String),
    
    /// Error occurred with extension handling
    ExtensionError(String),
    
    /// Error occurred with template handling
    TemplateError(String),
    
    /// Error occurred with cache operations
    CacheError(String),
    
    /// Error occurred during validation
    ValidationError(String),
}

impl fmt::Display for CustlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CustlsError::HookError(msg) => write!(f, "Hook error: {}", msg),
            CustlsError::RandomizationError(msg) => write!(f, "Randomization error: {}", msg),
            CustlsError::ExtensionError(msg) => write!(f, "Extension error: {}", msg),
            CustlsError::TemplateError(msg) => write!(f, "Template error: {}", msg),
            CustlsError::CacheError(msg) => write!(f, "Cache error: {}", msg),
            CustlsError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CustlsError {}

/// Convert CustlsError to rustls::Error for seamless integration
impl From<CustlsError> for RustlsError {
    fn from(e: CustlsError) -> Self {
        RustlsError::General(alloc::format!("custls error: {}", e))
    }
}

/// Randomization intensity level for ClientHello generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomizationLevel {
    /// No randomization, use template exactly
    None,
    
    /// Small browser-style perturbations (mainstream variation)
    Light,
    
    /// Moderate variation within browser norms
    Medium,
    
    /// Maximum variation within naturalness constraints
    High,
}

impl Default for RandomizationLevel {
    fn default() -> Self {
        RandomizationLevel::Light
    }
}

/// Template rotation policy for automatic template selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateRotationPolicy {
    /// No rotation, use the same template for all connections
    None,
    
    /// Round-robin rotation through all templates
    RoundRobin,
    
    /// Random selection from all templates
    Random,
    
    /// Weighted random selection (prefer more common browsers)
    WeightedRandom,
}

/// Browser template presets for fingerprint simulation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BrowserTemplate {
    /// Chrome 130+ template
    Chrome130,
    
    /// Firefox 135+ template
    Firefox135,
    
    /// Safari 17+ template
    Safari17,
    
    /// Edge 130+ template
    Edge130,
    
    /// Custom user-defined template
    Custom(Box<CustomTemplate>),
}

/// Custom template definition for advanced users
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CustomTemplate {
    /// Template name for identification
    pub name: String,
    
    /// Template description
    pub description: String,
    
    // Note: Full template data structures will be defined in templates.rs
    // This is a placeholder for the public API
}

/// Main configuration for custls customization
#[derive(Clone, Debug)]
pub struct CustlsConfig {
    /// Browser template to simulate (optional)
    pub template: Option<BrowserTemplate>,
    
    /// Randomization intensity level
    pub randomization_level: RandomizationLevel,
    
    /// Enable working fingerprint cache
    pub enable_cache: bool,
    
    /// Maximum cache size (number of entries)
    pub max_cache_size: usize,
    
    /// Template rotation policy
    pub rotation_policy: TemplateRotationPolicy,
    
    /// Templates to rotate through (if rotation is enabled)
    pub rotation_templates: Vec<BrowserTemplate>,
    
    /// Timing jitter configuration for anti-fingerprinting (optional)
    pub timing_jitter: Option<TimingJitterConfig>,
}

impl Default for CustlsConfig {
    fn default() -> Self {
        Self {
            template: None,
            randomization_level: RandomizationLevel::Light,
            enable_cache: true,
            max_cache_size: 1000,
            rotation_policy: TemplateRotationPolicy::None,
            rotation_templates: Vec::new(),
            timing_jitter: None,
        }
    }
}

impl CustlsConfig {
    /// Create a new builder for CustlsConfig
    pub fn builder() -> CustlsConfigBuilder {
        CustlsConfigBuilder::default()
    }
}

/// Builder for CustlsConfig
#[derive(Clone)]
pub struct CustlsConfigBuilder {
    template: Option<BrowserTemplate>,
    randomization_level: RandomizationLevel,
    enable_cache: bool,
    max_cache_size: usize,
    rotation_policy: TemplateRotationPolicy,
    rotation_templates: Vec<BrowserTemplate>,
    timing_jitter: Option<TimingJitterConfig>,
}

impl Default for CustlsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CustlsConfigBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        Self {
            template: None,
            randomization_level: RandomizationLevel::Light,
            enable_cache: true,
            max_cache_size: 1000,
            rotation_policy: TemplateRotationPolicy::None,
            rotation_templates: Vec::new(),
            timing_jitter: None,
        }
    }
    
    /// Set the browser template to use
    pub fn with_template(mut self, template: BrowserTemplate) -> Self {
        self.template = Some(template);
        self
    }
    
    /// Set the randomization level
    pub fn with_randomization_level(mut self, level: RandomizationLevel) -> Self {
        self.randomization_level = level;
        self
    }
    
    /// Enable or disable the fingerprint cache
    pub fn with_cache(mut self, enable: bool) -> Self {
        self.enable_cache = enable;
        self
    }
    
    /// Set the maximum cache size
    pub fn with_max_cache_size(mut self, size: usize) -> Self {
        self.max_cache_size = size;
        self
    }
    
    /// Set the timing jitter configuration
    pub fn with_timing_jitter(mut self, config: TimingJitterConfig) -> Self {
        self.timing_jitter = Some(config);
        self
    }
    
    /// Set the template rotation policy
    pub fn with_rotation_policy(mut self, policy: TemplateRotationPolicy) -> Self {
        self.rotation_policy = policy;
        self
    }
    
    /// Set the templates to rotate through
    ///
    /// This is only used when rotation_policy is not None.
    /// If not set, defaults to all built-in templates.
    pub fn with_rotation_templates(mut self, templates: Vec<BrowserTemplate>) -> Self {
        self.rotation_templates = templates;
        self
    }
    
    /// Build the CustlsConfig
    pub fn build(self) -> CustlsConfig {
        CustlsConfig {
            template: self.template,
            randomization_level: self.randomization_level,
            enable_cache: self.enable_cache,
            max_cache_size: self.max_cache_size,
            rotation_policy: self.rotation_policy,
            rotation_templates: self.rotation_templates,
            timing_jitter: self.timing_jitter,
        }
    }
}

// Submodules
pub mod hooks;
pub mod extensions;
pub mod templates;
pub mod randomizer;
pub mod state;
pub mod utils;
pub mod orchestrator;
pub mod security;

#[cfg(test)]
pub mod browser_validation;

#[cfg(test)]
pub mod real_server_tests;

// Re-export key types from hooks module
pub use hooks::{ClientHelloCustomizer, ConfigParams, ClientExtension};

// Re-export extension types
pub use extensions::{
    ApplicationSettingsExtension,
    DelegatedCredentialExtension,
    CompressCertificateExtension,
    PaddingExtension,
    StatusRequestExtension,
    SignedCertificateTimestampExtension,
};

// Re-export template types
pub use templates::{
    TemplateData,
    GreasePattern,
    PaddingDistribution,
    NaturalnessFilter,
    ExtensionSet,
};

// Re-export state types
pub use state::{
    FingerprintManager,
    TargetKey,
    ClientHelloConfig,
    FingerprintEntry,
};

// Re-export utility types
pub use utils::{
    Http2Settings,
    PrioritySpec,
    TimingJitterConfig,
    sample_from_pmf,
    sample_with_power_of_2_bias,
    validate_extension_order,
    calculate_reputation_score,
};

// Re-export orchestrator types
pub use orchestrator::DefaultCustomizer;

// Re-export security types
pub use security::{
    validate_downgrade_protection,
    SessionId,
    SessionState,
    SessionStateTracker,
    TLS12_DOWNGRADE_CANARY,
    TLS11_DOWNGRADE_CANARY,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod integration_tests;

#[cfg(test)]
mod antifingerprint_properties;

#[cfg(test)]
mod examples_tests;

#[cfg(test)]
mod config_tests {
    use super::*;
    use alloc::format;
    use alloc::vec;
    use alloc::string::ToString;
    
    #[test]
    fn test_custls_config_default() {
        let config = CustlsConfig::default();
        
        assert!(config.template.is_none());
        assert_eq!(config.randomization_level, RandomizationLevel::Light);
        assert!(config.enable_cache);
        assert_eq!(config.max_cache_size, 1000);
        assert_eq!(config.rotation_policy, TemplateRotationPolicy::None);
        assert!(config.rotation_templates.is_empty());
    }
    
    #[test]
    fn test_custls_config_builder_default() {
        let config = CustlsConfig::builder().build();
        
        assert!(config.template.is_none());
        assert_eq!(config.randomization_level, RandomizationLevel::Light);
        assert!(config.enable_cache);
        assert_eq!(config.max_cache_size, 1000);
        assert_eq!(config.rotation_policy, TemplateRotationPolicy::None);
    }
    
    #[test]
    fn test_custls_config_builder_with_template() {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .build();
        
        assert!(matches!(config.template, Some(BrowserTemplate::Chrome130)));
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
    fn test_custls_config_builder_with_rotation_policy() {
        let config = CustlsConfig::builder()
            .with_rotation_policy(TemplateRotationPolicy::RoundRobin)
            .build();
        
        assert_eq!(config.rotation_policy, TemplateRotationPolicy::RoundRobin);
    }
    
    #[test]
    fn test_custls_config_builder_with_rotation_templates() {
        let templates = vec![
            BrowserTemplate::Chrome130,
            BrowserTemplate::Firefox135,
        ];
        
        let config = CustlsConfig::builder()
            .with_rotation_templates(templates.clone())
            .build();
        
        assert_eq!(config.rotation_templates.len(), 2);
    }
    
    #[test]
    fn test_custls_config_builder_chaining() {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .with_randomization_level(RandomizationLevel::Medium)
            .with_cache(true)
            .with_max_cache_size(2000)
            .with_rotation_policy(TemplateRotationPolicy::Random)
            .build();
        
        assert!(matches!(config.template, Some(BrowserTemplate::Chrome130)));
        assert_eq!(config.randomization_level, RandomizationLevel::Medium);
        assert!(config.enable_cache);
        assert_eq!(config.max_cache_size, 2000);
        assert_eq!(config.rotation_policy, TemplateRotationPolicy::Random);
    }
    
    #[test]
    fn test_randomization_level_default() {
        assert_eq!(RandomizationLevel::default(), RandomizationLevel::Light);
    }
    
    #[test]
    fn test_randomization_level_equality() {
        assert_eq!(RandomizationLevel::None, RandomizationLevel::None);
        assert_eq!(RandomizationLevel::Light, RandomizationLevel::Light);
        assert_eq!(RandomizationLevel::Medium, RandomizationLevel::Medium);
        assert_eq!(RandomizationLevel::High, RandomizationLevel::High);
        
        assert_ne!(RandomizationLevel::None, RandomizationLevel::Light);
        assert_ne!(RandomizationLevel::Light, RandomizationLevel::Medium);
    }
    
    #[test]
    fn test_template_rotation_policy_equality() {
        assert_eq!(TemplateRotationPolicy::None, TemplateRotationPolicy::None);
        assert_eq!(TemplateRotationPolicy::RoundRobin, TemplateRotationPolicy::RoundRobin);
        assert_eq!(TemplateRotationPolicy::Random, TemplateRotationPolicy::Random);
        assert_eq!(TemplateRotationPolicy::WeightedRandom, TemplateRotationPolicy::WeightedRandom);
        
        assert_ne!(TemplateRotationPolicy::None, TemplateRotationPolicy::RoundRobin);
        assert_ne!(TemplateRotationPolicy::Random, TemplateRotationPolicy::WeightedRandom);
    }
    
    #[test]
    fn test_browser_template_equality() {
        assert_eq!(BrowserTemplate::Chrome130, BrowserTemplate::Chrome130);
        assert_eq!(BrowserTemplate::Firefox135, BrowserTemplate::Firefox135);
        assert_eq!(BrowserTemplate::Safari17, BrowserTemplate::Safari17);
        assert_eq!(BrowserTemplate::Edge130, BrowserTemplate::Edge130);
        
        assert_ne!(BrowserTemplate::Chrome130, BrowserTemplate::Firefox135);
        assert_ne!(BrowserTemplate::Safari17, BrowserTemplate::Edge130);
    }
    
    #[test]
    fn test_custls_error_display() {
        let error = CustlsError::HookError("test error".to_string());
        assert_eq!(format!("{}", error), "Hook error: test error");
        
        let error = CustlsError::RandomizationError("random error".to_string());
        assert_eq!(format!("{}", error), "Randomization error: random error");
        
        let error = CustlsError::ExtensionError("ext error".to_string());
        assert_eq!(format!("{}", error), "Extension error: ext error");
        
        let error = CustlsError::TemplateError("template error".to_string());
        assert_eq!(format!("{}", error), "Template error: template error");
        
        let error = CustlsError::CacheError("cache error".to_string());
        assert_eq!(format!("{}", error), "Cache error: cache error");
        
        let error = CustlsError::ValidationError("validation error".to_string());
        assert_eq!(format!("{}", error), "Validation error: validation error");
    }
    
    #[test]
    fn test_custls_error_to_rustls_error() {
        let custls_error = CustlsError::HookError("test".to_string());
        let rustls_error: RustlsError = custls_error.into();
        
        match rustls_error {
            RustlsError::General(msg) => {
                assert!(msg.contains("custls error"));
                assert!(msg.contains("Hook error"));
            }
            _ => panic!("Expected General error"),
        }
    }
}

