//! High-level orchestration for custls ClientHello customization.
//!
//! This module provides the `DefaultCustomizer` struct, which implements the
//! `ClientHelloCustomizer` trait and orchestrates template application,
//! randomization, caching, and GREASE injection.
//!
//! ## Design
//!
//! The DefaultCustomizer integrates all custls components:
//! - **Templates**: Provide browser-specific configuration
//! - **Randomizer**: Apply non-uniform variation
//! - **Cache**: Reuse working fingerprints with small variations
//! - **Extensions**: Add missing browser extensions
//!
//! ## Hook Phases
//!
//! - **Phase 1 (on_config_resolve)**: Select template, query cache
//! - **Phase 2 (on_components_ready)**: Apply randomization, inject GREASE
//! - **Phase 3 (on_struct_ready)**: Add padding extension
//! - **Phase 4 (transform_wire_bytes)**: Final byte-level adjustments (if needed)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use rustls::custls::{CustlsConfig, BrowserTemplate, RandomizationLevel};
//! use rustls::custls::orchestrator::DefaultCustomizer;
//!
//! let config = CustlsConfig::builder()
//!     .with_template(BrowserTemplate::Chrome130)
//!     .with_randomization_level(RandomizationLevel::Light)
//!     .with_cache(true)
//!     .build();
//!
//! let customizer = DefaultCustomizer::new(config);
//! // Use customizer with rustls ClientConfig
//! ```

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "std")]
use std::sync::Mutex;

use crate::error::Error as RustlsError;
use crate::custls::{
    CustlsConfig, BrowserTemplate, RandomizationLevel, TemplateRotationPolicy,
    ClientHelloCustomizer, ConfigParams, ClientExtension,
};
use crate::crypto::CipherSuite;
use crate::custls::templates::{TemplateData, NaturalnessFilter, chrome_130, firefox_135, safari_17, edge_130};
use crate::custls::randomizer::BrowserRandomizer;
use crate::custls::state::{FingerprintManager, TargetKey, ClientHelloConfig};
use crate::custls::extensions::PaddingExtension;
use crate::custls::security::{SessionStateTracker, SessionId};

/// Default implementation of ClientHelloCustomizer that orchestrates all custls components.
///
/// This struct integrates template application, randomization, caching, and extension
/// injection to provide a complete browser fingerprint simulation solution.
///
/// ## Thread Safety
///
/// DefaultCustomizer uses interior mutability (Mutex) for the randomizer and cache
/// to allow modification during hook callbacks while maintaining Send + Sync.
pub struct DefaultCustomizer {
    /// Configuration for customization behavior
    config: CustlsConfig,
    
    /// Browser template data (resolved from config.template)
    template: Option<TemplateData>,
    
    /// Randomizer for applying variations (wrapped in Mutex for interior mutability)
    #[cfg(feature = "std")]
    randomizer: Mutex<BrowserRandomizer>,
    
    /// Randomizer for applying variations (no_std version - not thread-safe)
    #[cfg(not(feature = "std"))]
    randomizer: core::cell::RefCell<BrowserRandomizer>,
    
    /// Fingerprint cache manager (wrapped in Mutex for interior mutability)
    #[cfg(feature = "std")]
    cache: Option<Mutex<FingerprintManager>>,
    
    /// Fingerprint cache manager (no_std version - not thread-safe)
    #[cfg(not(feature = "std"))]
    cache: Option<core::cell::RefCell<FingerprintManager>>,
    
    /// Connection counter for template rotation
    #[cfg(feature = "std")]
    connection_counter: Mutex<usize>,
    
    /// Connection counter for template rotation (no_std version)
    #[cfg(not(feature = "std"))]
    connection_counter: core::cell::RefCell<usize>,
    
    /// Session state tracker for maintaining fingerprint consistency within sessions
    #[cfg(feature = "std")]
    session_tracker: Option<Mutex<SessionStateTracker>>,
    
    /// Session state tracker (no_std version)
    #[cfg(not(feature = "std"))]
    session_tracker: Option<core::cell::RefCell<SessionStateTracker>>,
}

impl DefaultCustomizer {
    /// Create a new DefaultCustomizer with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration specifying template, randomization level, and cache settings
    ///
    /// # Returns
    ///
    /// A new `DefaultCustomizer` instance ready to use as a ClientHelloCustomizer.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = CustlsConfig::builder()
    ///     .with_template(BrowserTemplate::Chrome130)
    ///     .with_randomization_level(RandomizationLevel::Light)
    ///     .build();
    ///
    /// let customizer = DefaultCustomizer::new(config);
    /// ```
    pub fn new(config: CustlsConfig) -> Self {
        // Resolve template from config
        let template = config.template.as_ref().map(|t| Self::resolve_template(t));
        
        // Create naturalness filter (for now, use default)
        let naturalness_filter = NaturalnessFilter::default();
        
        // Create randomizer
        let randomizer = BrowserRandomizer::new(
            config.randomization_level,
            naturalness_filter,
        );
        
        // Create cache if enabled
        let cache = if config.enable_cache {
            Some(FingerprintManager::new(config.max_cache_size))
        } else {
            None
        };
        
        // Create session tracker if cache is enabled
        // Session tracking is tied to caching for consistency
        let session_tracker = if config.enable_cache {
            Some(SessionStateTracker::new(config.max_cache_size))
        } else {
            None
        };
        
        Self {
            config,
            template,
            #[cfg(feature = "std")]
            randomizer: Mutex::new(randomizer),
            #[cfg(not(feature = "std"))]
            randomizer: core::cell::RefCell::new(randomizer),
            #[cfg(feature = "std")]
            cache: cache.map(Mutex::new),
            #[cfg(not(feature = "std"))]
            cache: cache.map(core::cell::RefCell::new),
            #[cfg(feature = "std")]
            connection_counter: Mutex::new(0),
            #[cfg(not(feature = "std"))]
            connection_counter: core::cell::RefCell::new(0),
            #[cfg(feature = "std")]
            session_tracker: session_tracker.map(Mutex::new),
            #[cfg(not(feature = "std"))]
            session_tracker: session_tracker.map(core::cell::RefCell::new),
        }
    }
    
    /// Create a new DefaultCustomizer wrapped in Arc for sharing.
    ///
    /// This is a convenience method for creating a customizer that can be
    /// shared across multiple connections.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration specifying template, randomization level, and cache settings
    ///
    /// # Returns
    ///
    /// An `Arc<DefaultCustomizer>` ready to use with rustls ClientConfig.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let customizer = DefaultCustomizer::new_arc(config);
    /// // Use with rustls: client_config.custls_customizer = Some(customizer);
    /// ```
    pub fn new_arc(config: CustlsConfig) -> Arc<Self> {
        Arc::new(Self::new(config))
    }
    
    /// Resolve a BrowserTemplate enum to TemplateData.
    ///
    /// # Arguments
    ///
    /// * `template` - The browser template to resolve
    ///
    /// # Returns
    ///
    /// The corresponding `TemplateData` structure.
    fn resolve_template(template: &BrowserTemplate) -> TemplateData {
        match template {
            BrowserTemplate::Chrome130 => chrome_130(),
            BrowserTemplate::Firefox135 => firefox_135(),
            BrowserTemplate::Safari17 => safari_17(),
            BrowserTemplate::Edge130 => edge_130(),
            BrowserTemplate::Custom(_custom) => {
                // TODO: Once CustomTemplate has full implementation, convert it to TemplateData
                // For now, fall back to Chrome
                chrome_130()
            }
        }
    }
    
    /// Get the current configuration.
    pub fn config(&self) -> &CustlsConfig {
        &self.config
    }
    
    /// Get the current template (if any).
    pub fn template(&self) -> Option<&TemplateData> {
        self.template.as_ref()
    }
    
    /// Select the next template based on rotation policy.
    ///
    /// This method is called internally to select a template when rotation is enabled.
    /// It updates the connection counter and returns the appropriate template.
    ///
    /// # Returns
    ///
    /// The selected `BrowserTemplate`, or `None` if no rotation templates are configured.
    #[cfg(feature = "std")]
    fn select_rotated_template(&self) -> Option<BrowserTemplate> {
        // If rotation is disabled, return the configured template
        if self.config.rotation_policy == TemplateRotationPolicy::None {
            return self.config.template.clone();
        }
        
        // Get rotation templates (use defaults if not specified)
        let templates = if self.config.rotation_templates.is_empty() {
            vec![
                BrowserTemplate::Chrome130,
                BrowserTemplate::Firefox135,
                BrowserTemplate::Safari17,
                BrowserTemplate::Edge130,
            ]
        } else {
            self.config.rotation_templates.clone()
        };
        
        if templates.is_empty() {
            return None;
        }
        
        // Increment connection counter
        let counter = {
            let mut counter_guard = self.connection_counter.lock().ok()?;
            let current = *counter_guard;
            *counter_guard = current.wrapping_add(1);
            current
        };
        
        // Select template based on policy
        match self.config.rotation_policy {
            TemplateRotationPolicy::None => self.config.template.clone(),
            
            TemplateRotationPolicy::RoundRobin => {
                let index = counter % templates.len();
                Some(templates[index].clone())
            }
            
            TemplateRotationPolicy::Random => {
                // Simple pseudo-random selection based on counter
                let index = (counter * 2654435761) % templates.len();
                Some(templates[index].clone())
            }
            
            TemplateRotationPolicy::WeightedRandom => {
                // Weighted selection: Chrome 40%, Firefox 25%, Safari 20%, Edge 15%
                // This is a simplified implementation
                let weight = (counter * 2654435761) % 100;
                
                let index = if weight < 40 {
                    // Chrome (40%)
                    templates.iter().position(|t| matches!(t, BrowserTemplate::Chrome130))
                        .unwrap_or(0)
                } else if weight < 65 {
                    // Firefox (25%)
                    templates.iter().position(|t| matches!(t, BrowserTemplate::Firefox135))
                        .unwrap_or(1 % templates.len())
                } else if weight < 85 {
                    // Safari (20%)
                    templates.iter().position(|t| matches!(t, BrowserTemplate::Safari17))
                        .unwrap_or(2 % templates.len())
                } else {
                    // Edge (15%)
                    templates.iter().position(|t| matches!(t, BrowserTemplate::Edge130))
                        .unwrap_or(3 % templates.len())
                };
                
                Some(templates[index].clone())
            }
        }
    }
    
    /// Select the next template based on rotation policy (no_std version).
    #[cfg(not(feature = "std"))]
    fn select_rotated_template(&self) -> Option<BrowserTemplate> {
        // If rotation is disabled, return the configured template
        if self.config.rotation_policy == TemplateRotationPolicy::None {
            return self.config.template.clone();
        }
        
        // Get rotation templates (use defaults if not specified)
        let templates = if self.config.rotation_templates.is_empty() {
            vec![
                BrowserTemplate::Chrome130,
                BrowserTemplate::Firefox135,
                BrowserTemplate::Safari17,
                BrowserTemplate::Edge130,
            ]
        } else {
            self.config.rotation_templates.clone()
        };
        
        if templates.is_empty() {
            return None;
        }
        
        // Increment connection counter
        let counter = {
            let mut counter_ref = self.connection_counter.borrow_mut();
            let current = *counter_ref;
            *counter_ref = current.wrapping_add(1);
            current
        };
        
        // Select template based on policy (same logic as std version)
        match self.config.rotation_policy {
            TemplateRotationPolicy::None => self.config.template.clone(),
            
            TemplateRotationPolicy::RoundRobin => {
                let index = counter % templates.len();
                Some(templates[index].clone())
            }
            
            TemplateRotationPolicy::Random => {
                let index = (counter * 2654435761) % templates.len();
                Some(templates[index].clone())
            }
            
            TemplateRotationPolicy::WeightedRandom => {
                let weight = (counter * 2654435761) % 100;
                
                let index = if weight < 40 {
                    templates.iter().position(|t| matches!(t, BrowserTemplate::Chrome130))
                        .unwrap_or(0)
                } else if weight < 65 {
                    templates.iter().position(|t| matches!(t, BrowserTemplate::Firefox135))
                        .unwrap_or(1 % templates.len())
                } else if weight < 85 {
                    templates.iter().position(|t| matches!(t, BrowserTemplate::Safari17))
                        .unwrap_or(2 % templates.len())
                } else {
                    templates.iter().position(|t| matches!(t, BrowserTemplate::Edge130))
                        .unwrap_or(3 % templates.len())
                };
                
                Some(templates[index].clone())
            }
        }
    }
    
    /// Record a handshake result in the cache.
    ///
    /// This method should be called after a handshake completes to update
    /// the cache with success/failure information.
    ///
    /// # Arguments
    ///
    /// * `target` - The target that was connected to
    /// * `config` - The ClientHello configuration that was used
    /// * `success` - Whether the handshake succeeded
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // After successful handshake
    /// customizer.record_handshake_result(&target, config, true);
    /// ```
    #[cfg(feature = "std")]
    pub fn record_handshake_result(
        &self,
        target: &TargetKey,
        config: ClientHelloConfig,
        success: bool,
    ) {
        if let Some(cache) = &self.cache {
            if let Ok(mut cache_guard) = cache.lock() {
                cache_guard.record_result(target, config, success);
            }
        }
    }
    
    /// Record a handshake result in the cache (no_std version).
    #[cfg(not(feature = "std"))]
    pub fn record_handshake_result(
        &self,
        target: &TargetKey,
        config: ClientHelloConfig,
        success: bool,
    ) {
        if let Some(cache) = &self.cache {
            cache.borrow_mut().record_result(target, config, success);
        }
    }
    
    /// Clear the fingerprint cache.
    ///
    /// This removes all cached fingerprints, forcing fresh generation
    /// for all future connections.
    #[cfg(feature = "std")]
    pub fn clear_cache(&self) {
        if let Some(cache) = &self.cache {
            if let Ok(mut cache_guard) = cache.lock() {
                cache_guard.clear_cache();
            }
        }
    }
    
    /// Clear the fingerprint cache (no_std version).
    #[cfg(not(feature = "std"))]
    pub fn clear_cache(&self) {
        if let Some(cache) = &self.cache {
            cache.borrow_mut().clear_cache();
        }
    }
    
    /// Invalidate cache entry for a specific target.
    ///
    /// # Arguments
    ///
    /// * `target` - The target to invalidate
    ///
    /// # Returns
    ///
    /// `true` if an entry was removed, `false` if no entry existed
    #[cfg(feature = "std")]
    pub fn invalidate_target(&self, target: &TargetKey) -> bool {
        if let Some(cache) = &self.cache {
            if let Ok(mut cache_guard) = cache.lock() {
                return cache_guard.invalidate_target(target);
            }
        }
        false
    }
    
    /// Invalidate cache entry for a specific target (no_std version).
    #[cfg(not(feature = "std"))]
    pub fn invalidate_target(&self, target: &TargetKey) -> bool {
        if let Some(cache) = &self.cache {
            return cache.borrow_mut().invalidate_target(target);
        }
        false
    }
    
    /// Record a session with its configuration.
    ///
    /// This should be called when a new session is established to track
    /// the ClientHello configuration used for that session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session identifier
    /// * `config` - The ClientHello configuration used
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// customizer.record_session(&session_id, config);
    /// ```
    #[cfg(feature = "std")]
    pub fn record_session(&self, session_id: &SessionId, config: ClientHelloConfig) {
        if let Some(tracker) = &self.session_tracker {
            if let Ok(mut tracker_guard) = tracker.lock() {
                tracker_guard.record_session(session_id, config);
            }
        }
    }
    
    /// Record a session with its configuration (no_std version).
    #[cfg(not(feature = "std"))]
    pub fn record_session(&self, session_id: &SessionId, config: ClientHelloConfig) {
        if let Some(tracker) = &self.session_tracker {
            tracker.borrow_mut().record_session(session_id, config);
        }
    }
    
    /// Get the configuration for a session.
    ///
    /// Returns the ClientHello configuration that should be used for this session
    /// to maintain consistency during resumption.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session identifier
    ///
    /// # Returns
    ///
    /// `Some(config)` if the session is tracked, `None` otherwise.
    #[cfg(feature = "std")]
    pub fn get_session_config(&self, session_id: &SessionId) -> Option<ClientHelloConfig> {
        if let Some(tracker) = &self.session_tracker {
            if let Ok(tracker_guard) = tracker.lock() {
                return tracker_guard.get_session_config(session_id).cloned();
            }
        }
        None
    }
    
    /// Get the configuration for a session (no_std version).
    #[cfg(not(feature = "std"))]
    pub fn get_session_config(&self, session_id: &SessionId) -> Option<ClientHelloConfig> {
        if let Some(tracker) = &self.session_tracker {
            return tracker.borrow().get_session_config(session_id).cloned();
        }
        None
    }
    
    /// Mark a session as established.
    ///
    /// This should be called after a successful handshake.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session identifier
    #[cfg(feature = "std")]
    pub fn mark_session_established(&self, session_id: &SessionId) {
        if let Some(tracker) = &self.session_tracker {
            if let Ok(mut tracker_guard) = tracker.lock() {
                tracker_guard.mark_established(session_id);
            }
        }
    }
    
    /// Mark a session as established (no_std version).
    #[cfg(not(feature = "std"))]
    pub fn mark_session_established(&self, session_id: &SessionId) {
        if let Some(tracker) = &self.session_tracker {
            tracker.borrow_mut().mark_established(session_id);
        }
    }
    
    /// Record a session ticket.
    ///
    /// This should be called when a NewSessionTicket message is received.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session identifier
    /// * `ticket` - The session ticket bytes
    #[cfg(feature = "std")]
    pub fn record_session_ticket(&self, session_id: &SessionId, ticket: Vec<u8>) {
        if let Some(tracker) = &self.session_tracker {
            if let Ok(mut tracker_guard) = tracker.lock() {
                tracker_guard.record_ticket(session_id, ticket);
            }
        }
    }
    
    /// Record a session ticket (no_std version).
    #[cfg(not(feature = "std"))]
    pub fn record_session_ticket(&self, session_id: &SessionId, ticket: Vec<u8>) {
        if let Some(tracker) = &self.session_tracker {
            tracker.borrow_mut().record_ticket(session_id, ticket);
        }
    }
    
    /// Record a session resumption.
    ///
    /// This should be called when resuming a session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session identifier
    #[cfg(feature = "std")]
    pub fn record_session_resumption(&self, session_id: &SessionId) {
        if let Some(tracker) = &self.session_tracker {
            if let Ok(mut tracker_guard) = tracker.lock() {
                tracker_guard.record_resumption(session_id);
            }
        }
    }
    
    /// Record a session resumption (no_std version).
    #[cfg(not(feature = "std"))]
    pub fn record_session_resumption(&self, session_id: &SessionId) {
        if let Some(tracker) = &self.session_tracker {
            tracker.borrow_mut().record_resumption(session_id);
        }
    }
}

impl fmt::Debug for DefaultCustomizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefaultCustomizer")
            .field("config", &self.config)
            .field("template", &self.template.as_ref().map(|t| &t.name))
            .field("cache_enabled", &self.cache.is_some())
            .finish()
    }
}

impl ClientHelloCustomizer for DefaultCustomizer {
    /// Phase 1: Pre-build configuration hook.
    ///
    /// In this phase, we:
    /// - Select template based on rotation policy (if enabled)
    /// - Query the cache for working fingerprints (if enabled)
    /// - Initialize per-connection state
    ///
    /// # Note
    ///
    /// Cache lookup requires knowing the target (host, port), which is not
    /// currently available in ConfigParams. This will be added in future
    /// rustls integration work. For now, this phase handles template rotation.
    fn on_config_resolve(&self, _config: &mut ConfigParams) -> Result<(), RustlsError> {
        // Apply timing jitter if configured
        if let Some(ref jitter_config) = self.config.timing_jitter {
            jitter_config.apply();
        }
        
        // If rotation is enabled, select the next template
        // Note: This updates the connection counter but doesn't change self.template
        // because self is immutable. In a real implementation, we would need to
        // store the selected template in ConfigParams or use a different approach.
        
        // For now, just call select_rotated_template to increment the counter
        // The actual template selection will happen in on_components_ready
        if self.config.rotation_policy != TemplateRotationPolicy::None {
            let _ = self.select_rotated_template();
        }
        
        // TODO: Once ConfigParams includes target information:
        // 1. Extract target (host, port) from config
        // 2. Query cache for working fingerprint
        // 3. If found, prepare to apply cached config with small variation
        // 4. If not found, proceed with template-based generation
        
        Ok(())
    }
    
    /// Phase 2: Mid-build component modification hook.
    ///
    /// In this phase, we:
    /// - Apply template configuration to cipher suites and extensions
    /// - Apply randomization based on configured level
    /// - Inject GREASE values following browser patterns
    /// - Shuffle extensions with grouped constraints
    ///
    /// This is the main customization phase where most fingerprint shaping occurs.
    fn on_components_ready(
        &self,
        cipher_suites: &mut Vec<CipherSuite>,
        extensions: &mut Vec<ClientExtension>,
    ) -> Result<(), RustlsError> {
        // Apply timing jitter if configured
        if let Some(ref jitter_config) = self.config.timing_jitter {
            jitter_config.apply();
        }
        
        // Select template (either fixed or rotated)
        let template_enum = if self.config.rotation_policy != TemplateRotationPolicy::None {
            self.select_rotated_template()
        } else {
            self.config.template.clone()
        };
        
        // Resolve template to TemplateData
        let template = match template_enum {
            Some(t) => Self::resolve_template(&t),
            None => {
                // If no template, use the pre-resolved one from construction
                match &self.template {
                    Some(t) => t.clone(),
                    None => return Ok(()), // No template, skip customization
                }
            }
        };
        
        // Get mutable access to randomizer
        #[cfg(feature = "std")]
        let mut randomizer = self.randomizer.lock()
            .map_err(|e| RustlsError::General(alloc::format!("Failed to lock randomizer: {}", e)))?;
        
        #[cfg(not(feature = "std"))]
        let mut randomizer = self.randomizer.borrow_mut();
        
        // Apply randomization if level is not None
        if randomizer.level() != RandomizationLevel::None {
            // Shuffle extensions with grouped constraints
            randomizer.shuffle_extensions(extensions, &template)?;
            
            // Inject GREASE values (no previous values tracking yet - will be added with cache integration)
            let _ = randomizer.inject_grease(cipher_suites, extensions, &template, &[])?;
        }
        
        // TODO: Once cipher_suites and extensions have real implementations:
        // - Apply template cipher suite ordering
        // - Apply template extension ordering
        // - Validate against naturalness filter
        
        Ok(())
    }
    
    /// Phase 3: Pre-marshal structure modification hook.
    ///
    /// In this phase, we:
    /// - Add padding extension with generated length
    /// - Perform final validation of ClientHello structure
    /// - Make any final adjustments before serialization
    fn on_struct_ready(&self, _payload: &mut crate::msgs::ClientHelloPayload) -> Result<(), RustlsError> {
        // Apply timing jitter if configured
        if let Some(ref jitter_config) = self.config.timing_jitter {
            jitter_config.apply();
        }
        
        // Select template (either fixed or rotated)
        let template_enum = if self.config.rotation_policy != TemplateRotationPolicy::None {
            self.select_rotated_template()
        } else {
            self.config.template.clone()
        };
        
        // Resolve template to TemplateData
        let template = match template_enum {
            Some(t) => Self::resolve_template(&t),
            None => {
                // If no template, use the pre-resolved one from construction
                match &self.template {
                    Some(t) => t.clone(),
                    None => return Ok(()), // No template, skip customization
                }
            }
        };
        
        // Get mutable access to randomizer
        #[cfg(feature = "std")]
        let mut randomizer = self.randomizer.lock()
            .map_err(|e| RustlsError::General(alloc::format!("Failed to lock randomizer: {}", e)))?;
        
        #[cfg(not(feature = "std"))]
        let mut randomizer = self.randomizer.borrow_mut();
        
        // Generate padding length from template distribution (no previous values tracking yet)
        let padding_len = randomizer.generate_padding_len(&template, &[]);
        
        // TODO: Once ClientHelloPayload has real implementation:
        // - Create PaddingExtension with generated length
        // - Add to payload.extensions
        // - Validate final structure
        
        // For now, just create the padding extension to validate the API
        let _padding_ext = PaddingExtension::new(padding_len);
        
        Ok(())
    }
    
    /// Phase 4: Post-marshal byte transformation hook.
    ///
    /// In this phase, we could apply byte-level transformations if needed.
    /// For most use cases, the default implementation (no transformation) is sufficient.
    ///
    /// Future enhancements might include:
    /// - Timing-dependent byte modifications
    /// - Additional obfuscation techniques
    /// - Final size adjustments
    fn transform_wire_bytes(&self, bytes: Vec<u8>) -> Result<Vec<u8>, RustlsError> {
        // Apply timing jitter if configured
        if let Some(ref jitter_config) = self.config.timing_jitter {
            jitter_config.apply();
        }
        
        // Default implementation: no transformation
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    
    #[test]
    fn test_default_customizer_creation() {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .with_randomization_level(RandomizationLevel::Light)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        
        assert!(customizer.template().is_some());
        assert_eq!(customizer.template().unwrap().name, "Chrome 130+");
    }
    
    #[test]
    fn test_default_customizer_no_template() {
        let config = CustlsConfig::builder()
            .with_randomization_level(RandomizationLevel::None)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        
        assert!(customizer.template().is_none());
    }
    
    #[test]
    fn test_default_customizer_with_cache() {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .with_cache(true)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        
        assert!(customizer.cache.is_some());
    }
    
    #[test]
    fn test_default_customizer_without_cache() {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .with_cache(false)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        
        assert!(customizer.cache.is_none());
    }
    
    #[test]
    fn test_resolve_template_chrome() {
        let template = DefaultCustomizer::resolve_template(&BrowserTemplate::Chrome130);
        assert_eq!(template.name, "Chrome 130+");
    }
    
    #[test]
    fn test_resolve_template_firefox() {
        let template = DefaultCustomizer::resolve_template(&BrowserTemplate::Firefox135);
        assert_eq!(template.name, "Firefox 135+");
    }
    
    #[test]
    fn test_resolve_template_safari() {
        let template = DefaultCustomizer::resolve_template(&BrowserTemplate::Safari17);
        assert_eq!(template.name, "Safari 17+");
    }
    
    #[test]
    fn test_resolve_template_edge() {
        let template = DefaultCustomizer::resolve_template(&BrowserTemplate::Edge130);
        assert_eq!(template.name, "Edge 130+");
    }
    
    #[test]
    fn test_default_customizer_arc() {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .build();
        
        let customizer = DefaultCustomizer::new_arc(config);
        
        assert!(customizer.template().is_some());
    }
    
    #[test]
    fn test_cache_operations() {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .with_cache(true)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        
        // Test clear cache
        customizer.clear_cache();
        
        // Test invalidate target
        let target = TargetKey::new("example.com".to_string(), 443);
        assert!(!customizer.invalidate_target(&target)); // Should return false (no entry)
    }
    
    #[test]
    fn test_hook_on_config_resolve() {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        let mut config_params = ConfigParams::new();
        
        // Should succeed (currently a no-op)
        assert!(customizer.on_config_resolve(&mut config_params).is_ok());
    }
    
    #[test]
    fn test_hook_on_components_ready() {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .with_randomization_level(RandomizationLevel::Light)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        let mut cipher_suites = Vec::new();
        let mut extensions = Vec::new();
        
        // Should succeed
        assert!(customizer.on_components_ready(&mut cipher_suites, &mut extensions).is_ok());
    }
    
    #[test]
    fn test_hook_on_struct_ready() {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        
        // Note: We can't easily create a ClientHelloPayload for testing
        // since it doesn't have a public constructor. This test would need
        // integration with actual rustls ClientHello generation.
        // For now, we just verify the customizer was created successfully.
        assert!(customizer.template().is_some());
    }
    
    #[test]
    fn test_hook_transform_wire_bytes() {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        let bytes = vec![1, 2, 3, 4, 5];
        
        // Should return unchanged bytes
        let result = customizer.transform_wire_bytes(bytes.clone()).unwrap();
        assert_eq!(result, bytes);
    }
    
    #[test]
    fn test_no_template_skips_customization() {
        let config = CustlsConfig::builder()
            .with_randomization_level(RandomizationLevel::High)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        let mut cipher_suites = Vec::new();
        let mut extensions = Vec::new();
        
        // Should succeed but do nothing (no template)
        assert!(customizer.on_components_ready(&mut cipher_suites, &mut extensions).is_ok());
    }
    
    #[test]
    fn test_randomization_none_skips_variation() {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .with_randomization_level(RandomizationLevel::None)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        let mut cipher_suites = Vec::new();
        let mut extensions = Vec::new();
        
        // Should succeed but skip randomization
        assert!(customizer.on_components_ready(&mut cipher_suites, &mut extensions).is_ok());
    }
    
    #[test]
    fn test_template_rotation_round_robin() {
        let config = CustlsConfig::builder()
            .with_rotation_policy(TemplateRotationPolicy::RoundRobin)
            .with_rotation_templates(vec![
                BrowserTemplate::Chrome130,
                BrowserTemplate::Firefox135,
            ])
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        
        // First selection should be Chrome
        let template1 = customizer.select_rotated_template();
        assert!(matches!(template1, Some(BrowserTemplate::Chrome130)));
        
        // Second selection should be Firefox
        let template2 = customizer.select_rotated_template();
        assert!(matches!(template2, Some(BrowserTemplate::Firefox135)));
        
        // Third selection should wrap back to Chrome
        let template3 = customizer.select_rotated_template();
        assert!(matches!(template3, Some(BrowserTemplate::Chrome130)));
    }
    
    #[test]
    fn test_template_rotation_random() {
        let config = CustlsConfig::builder()
            .with_rotation_policy(TemplateRotationPolicy::Random)
            .with_rotation_templates(vec![
                BrowserTemplate::Chrome130,
                BrowserTemplate::Firefox135,
                BrowserTemplate::Safari17,
            ])
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        
        // Select multiple templates - should get different ones
        let mut templates = Vec::new();
        for _ in 0..10 {
            templates.push(customizer.select_rotated_template());
        }
        
        // Should have at least 2 different templates (very high probability)
        let unique_count = templates.iter()
            .filter_map(|t| t.as_ref())
            .collect::<std::collections::HashSet<_>>()
            .len();
        
        assert!(unique_count >= 2, "Expected at least 2 different templates, got {}", unique_count);
    }
    
    #[test]
    fn test_template_rotation_weighted_random() {
        let config = CustlsConfig::builder()
            .with_rotation_policy(TemplateRotationPolicy::WeightedRandom)
            .build(); // Uses default templates
        
        let customizer = DefaultCustomizer::new(config);
        
        // Select many templates and count occurrences
        let mut chrome_count = 0;
        let mut firefox_count = 0;
        let mut safari_count = 0;
        let mut edge_count = 0;
        
        for _ in 0..100 {
            match customizer.select_rotated_template() {
                Some(BrowserTemplate::Chrome130) => chrome_count += 1,
                Some(BrowserTemplate::Firefox135) => firefox_count += 1,
                Some(BrowserTemplate::Safari17) => safari_count += 1,
                Some(BrowserTemplate::Edge130) => edge_count += 1,
                _ => {}
            }
        }
        
        // Chrome should be most common (40% weight)
        assert!(chrome_count > firefox_count);
        assert!(chrome_count > safari_count);
        assert!(chrome_count > edge_count);
        
        // All templates should appear at least once
        assert!(chrome_count > 0);
        assert!(firefox_count > 0);
        assert!(safari_count > 0);
        assert!(edge_count > 0);
    }
    
    #[test]
    fn test_template_rotation_none() {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .with_rotation_policy(TemplateRotationPolicy::None)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        
        // Should always return the same template
        for _ in 0..10 {
            let template = customizer.select_rotated_template();
            assert!(matches!(template, Some(BrowserTemplate::Chrome130)));
        }
    }
    
    #[test]
    fn test_template_rotation_with_empty_list() {
        let config = CustlsConfig::builder()
            .with_rotation_policy(TemplateRotationPolicy::RoundRobin)
            .with_rotation_templates(Vec::new()) // Empty list
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        
        // Should use default templates
        let template = customizer.select_rotated_template();
        assert!(template.is_some());
    }
    
    #[test]
    fn test_rotation_increments_counter() {
        let config = CustlsConfig::builder()
            .with_rotation_policy(TemplateRotationPolicy::RoundRobin)
            .with_rotation_templates(vec![
                BrowserTemplate::Chrome130,
                BrowserTemplate::Firefox135,
            ])
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        
        // Call on_config_resolve multiple times
        let mut config_params = ConfigParams::new();
        for _ in 0..5 {
            assert!(customizer.on_config_resolve(&mut config_params).is_ok());
        }
        
        // Counter should have been incremented
        // We can't directly check the counter, but we can verify rotation works
        let template = customizer.select_rotated_template();
        assert!(template.is_some());
    }
    
    #[test]
    fn test_session_management() {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .with_cache(true)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        let session_id = SessionId::new(vec![1, 2, 3, 4]);
        let mut hello_config = ClientHelloConfig {
            template: BrowserTemplate::Chrome130,
            cipher_suites: Vec::new(),
            extension_order: Vec::new(),
            extension_data: alloc::collections::BTreeMap::new(),
            grease_cipher_positions: Vec::new(),
            grease_extension_positions: Vec::new(),
            padding_length: 256,
            random_seed: 12345,
            supported_groups: Vec::new(),
            signature_algorithms: Vec::new(),
        };
        
        // Record session
        customizer.record_session(&session_id, hello_config.clone());
        
        // Get session config
        let retrieved = customizer.get_session_config(&session_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().padding_length, 256);
        
        // Mark established
        customizer.mark_session_established(&session_id);
        
        // Record ticket
        let ticket = vec![10, 20, 30, 40];
        customizer.record_session_ticket(&session_id, ticket);
        
        // Record resumption
        customizer.record_session_resumption(&session_id);
    }
    
    #[test]
    fn test_session_management_without_cache() {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .with_cache(false)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        let session_id = SessionId::new(vec![1, 2, 3, 4]);
        let hello_config = ClientHelloConfig {
            template: BrowserTemplate::Chrome130,
            cipher_suites: Vec::new(),
            extension_order: Vec::new(),
            extension_data: alloc::collections::BTreeMap::new(),
            grease_cipher_positions: Vec::new(),
            grease_extension_positions: Vec::new(),
            padding_length: 256,
            random_seed: 12345,
            supported_groups: Vec::new(),
            signature_algorithms: Vec::new(),
        };
        
        // Record session (should be no-op without cache)
        customizer.record_session(&session_id, hello_config);
        
        // Get session config (should return None)
        let retrieved = customizer.get_session_config(&session_id);
        assert!(retrieved.is_none());
    }
    
    #[test]
    fn test_session_consistency_during_resumption() {
        let config = CustlsConfig::builder()
            .with_template(BrowserTemplate::Chrome130)
            .with_cache(true)
            .build();
        
        let customizer = DefaultCustomizer::new(config);
        let session_id = SessionId::new(vec![5, 6, 7, 8]);
        let hello_config = ClientHelloConfig {
            template: BrowserTemplate::Chrome130,
            cipher_suites: Vec::new(),
            extension_order: Vec::new(),
            extension_data: alloc::collections::BTreeMap::new(),
            grease_cipher_positions: Vec::new(),
            grease_extension_positions: Vec::new(),
            padding_length: 512,
            random_seed: 99999,
            supported_groups: Vec::new(),
            signature_algorithms: Vec::new(),
        };
        
        // Record initial session
        customizer.record_session(&session_id, hello_config);
        
        // Get config for resumption
        let config1 = customizer.get_session_config(&session_id).unwrap();
        
        // Record resumption
        customizer.record_session_resumption(&session_id);
        
        // Get config again - should be consistent
        let config2 = customizer.get_session_config(&session_id).unwrap();
        
        assert_eq!(config1.padding_length, config2.padding_length);
        assert_eq!(config1.random_seed, config2.random_seed);
    }
}


#[cfg(test)]
#[path = "orchestrator_properties.rs"]
mod properties;
