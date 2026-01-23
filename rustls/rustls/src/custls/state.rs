//! Fingerprint cache and state management for custls.
//!
//! This module implements the working fingerprint cache that tracks successful
//! ClientHello configurations per target and applies small variations to avoid
//! exact repetition while maintaining behavioral consistency.
//!
//! ## Design Philosophy
//!
//! The cache serves two purposes:
//! 1. **Performance**: Reuse working configurations instead of generating from scratch
//! 2. **Behavioral consistency**: Maintain similar fingerprints to the same target
//!    while applying small variations to avoid static mimicry detection
//!
//! ## Cache Strategy
//!
//! - Indexed by (host, port) target
//! - Tracks success/failure counts and reputation scores
//! - LRU eviction with reputation weighting
//! - Small random variations applied on retrieval
//! - Size-limited to prevent unbounded growth
//!
//! ## Usage
//!
//! ```rust,ignore
//! use rustls::custls::state::FingerprintManager;
//!
//! let mut manager = FingerprintManager::new(1000);
//! 
//! // Record successful handshake
//! manager.record_result(&target, config, true);
//! 
//! // Retrieve working fingerprint with variation
//! if let Some(config) = manager.get_working_fingerprint(&target, &mut randomizer) {
//!     // Use config for new connection
//! }
//! ```

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::time::Instant;

use crate::crypto::{CipherSuite, SignatureScheme};
use crate::crypto::kx::NamedGroup;
use crate::msgs::ExtensionType;

use super::BrowserTemplate;

/// Key for identifying a target server.
///
/// Fingerprints are cached per target to maintain behavioral consistency
/// when connecting to the same server multiple times.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TargetKey {
    /// Target hostname
    pub host: String,
    
    /// Target port
    pub port: u16,
}

impl TargetKey {
    /// Create a new target key
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }
}

/// Cached ClientHello configuration snapshot.
///
/// This structure captures the complete state of a ClientHello configuration
/// that can be reused (with small variations) for future connections to the
/// same target.
#[derive(Debug, Clone)]
pub struct ClientHelloConfig {
    /// Browser template used
    pub template: BrowserTemplate,
    
    /// Cipher suites in order
    pub cipher_suites: Vec<CipherSuite>,
    
    /// Extension types in order
    pub extension_order: Vec<ExtensionType>,
    
    /// Extension data (type -> encoded bytes)
    pub extension_data: BTreeMap<ExtensionType, Vec<u8>>,
    
    /// GREASE positions in cipher suite list
    pub grease_cipher_positions: Vec<usize>,
    
    /// GREASE positions in extension list
    pub grease_extension_positions: Vec<usize>,
    
    /// Padding length used
    pub padding_length: u16,
    
    /// Random seed for reproducible small variations
    pub random_seed: u64,
    
    /// Supported groups (curves) in order
    pub supported_groups: Vec<NamedGroup>,
    
    /// Signature algorithms in order
    pub signature_algorithms: Vec<SignatureScheme>,
}

/// Cache entry for a working fingerprint.
///
/// Tracks the configuration along with success/failure statistics and
/// reputation scoring for eviction policy.
#[derive(Debug, Clone)]
pub struct FingerprintEntry {
    /// The cached configuration
    pub config: ClientHelloConfig,
    
    /// Number of successful handshakes with this fingerprint
    pub success_count: u32,
    
    /// Number of failed handshakes with this fingerprint
    pub failure_count: u32,
    
    /// Reputation score (0.0 to 1.0)
    ///
    /// Calculated as: success_count / (success_count + failure_count)
    /// Used for eviction policy - low reputation entries are evicted first.
    pub reputation_score: f64,
    
    /// Last time this entry was used
    #[cfg(feature = "std")]
    pub last_used: Instant,
    
    /// Last time this entry was used (duration since epoch for no_std)
    #[cfg(not(feature = "std"))]
    pub last_used: Duration,
    
    /// Previously used GREASE values for this target
    /// Tracks up to 10 most recent GREASE values to ensure variation
    pub previous_grease_values: Vec<u16>,
    
    /// Previously used padding lengths for this target
    /// Tracks up to 10 most recent padding lengths to ensure variation
    pub previous_padding_lengths: Vec<u16>,
}

impl FingerprintEntry {
    /// Create a new fingerprint entry
    #[cfg(feature = "std")]
    pub fn new(config: ClientHelloConfig) -> Self {
        Self {
            config,
            success_count: 0,
            failure_count: 0,
            reputation_score: 0.5, // Start with neutral reputation
            last_used: Instant::now(),
            previous_grease_values: Vec::new(),
            previous_padding_lengths: Vec::new(),
        }
    }
    
    /// Create a new fingerprint entry (no_std version)
    #[cfg(not(feature = "std"))]
    pub fn new(config: ClientHelloConfig) -> Self {
        Self {
            config,
            success_count: 0,
            failure_count: 0,
            reputation_score: 0.5,
            last_used: Duration::from_secs(0),
            previous_grease_values: Vec::new(),
            previous_padding_lengths: Vec::new(),
        }
    }
    
    /// Update reputation score based on success/failure counts
    pub fn update_reputation(&mut self) {
        let total = self.success_count + self.failure_count;
        if total > 0 {
            self.reputation_score = self.success_count as f64 / total as f64;
        } else {
            self.reputation_score = 0.5; // Neutral if no data
        }
    }
    
    /// Update last used timestamp
    #[cfg(feature = "std")]
    pub fn touch(&mut self) {
        self.last_used = Instant::now();
    }
    
    /// Update last used timestamp (no_std version)
    #[cfg(not(feature = "std"))]
    pub fn touch(&mut self) {
        // In no_std, we can't get current time easily
        // This is a placeholder - real implementation would need a time provider
        self.last_used = Duration::from_secs(0);
    }
    
    /// Track a GREASE value that was used
    ///
    /// Adds the GREASE value to the history, keeping only the most recent 10 values.
    /// This allows us to ensure variation across connections.
    pub fn track_grease_value(&mut self, grease_value: u16) {
        self.previous_grease_values.push(grease_value);
        
        // Keep only the most recent 10 values
        if self.previous_grease_values.len() > 10 {
            self.previous_grease_values.remove(0);
        }
    }
    
    /// Check if a GREASE value was recently used
    ///
    /// Returns true if the value appears in the recent history.
    pub fn was_grease_used(&self, grease_value: u16) -> bool {
        self.previous_grease_values.contains(&grease_value)
    }
    
    /// Get all previously used GREASE values
    pub fn get_previous_grease_values(&self) -> &[u16] {
        &self.previous_grease_values
    }
    
    /// Track a padding length that was used
    ///
    /// Adds the padding length to the history, keeping only the most recent 10 values.
    /// This allows us to ensure variation across connections.
    pub fn track_padding_length(&mut self, padding_length: u16) {
        self.previous_padding_lengths.push(padding_length);
        
        // Keep only the most recent 10 values
        if self.previous_padding_lengths.len() > 10 {
            self.previous_padding_lengths.remove(0);
        }
    }
    
    /// Check if a padding length was recently used
    ///
    /// Returns true if the value appears in the recent history.
    pub fn was_padding_used(&self, padding_length: u16) -> bool {
        self.previous_padding_lengths.contains(&padding_length)
    }
    
    /// Get all previously used padding lengths
    pub fn get_previous_padding_lengths(&self) -> &[u16] {
        &self.previous_padding_lengths
    }
}

/// Fingerprint cache manager.
///
/// Manages a cache of working ClientHello configurations indexed by target.
/// Implements LRU eviction with reputation weighting to maintain cache size limits.
///
/// ## Thread Safety
///
/// FingerprintManager is not thread-safe by default. If you need to share it
/// across threads, wrap it in a Mutex or RwLock.
pub struct FingerprintManager {
    /// Cache storage: target -> fingerprint entry
    cache: BTreeMap<TargetKey, FingerprintEntry>,
    
    /// Maximum number of cache entries
    max_size: usize,
}

impl FingerprintManager {
    /// Create a new fingerprint manager with specified maximum cache size.
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum number of cache entries. When this limit is reached,
    ///   entries with the lowest reputation scores are evicted.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let manager = FingerprintManager::new(1000);
    /// ```
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: BTreeMap::new(),
            max_size,
        }
    }
    
    /// Get the current cache size
    pub fn size(&self) -> usize {
        self.cache.len()
    }
    
    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
    
    /// Get the maximum cache size
    pub fn max_size(&self) -> usize {
        self.max_size
    }
    
    /// Clear all cache entries
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
    
    /// Invalidate cache entry for a specific target
    ///
    /// # Arguments
    ///
    /// * `target` - The target to invalidate
    ///
    /// # Returns
    ///
    /// `true` if an entry was removed, `false` if no entry existed
    pub fn invalidate_target(&mut self, target: &TargetKey) -> bool {
        self.cache.remove(target).is_some()
    }
    
    /// Insert or update a cache entry
    ///
    /// If the cache is full, evicts the lowest reputation entry before inserting.
    ///
    /// # Arguments
    ///
    /// * `target` - The target key
    /// * `config` - The ClientHello configuration to cache
    #[allow(dead_code)]
    fn insert(&mut self, target: TargetKey, config: ClientHelloConfig) {
        // If cache is full, evict lowest reputation entry
        if self.cache.len() >= self.max_size && !self.cache.contains_key(&target) {
            self.evict_lowest_reputation();
        }
        
        // Insert or update entry
        let entry = FingerprintEntry::new(config);
        self.cache.insert(target, entry);
    }
    
    /// Evict the entry with the lowest reputation score.
    ///
    /// If multiple entries have the same lowest reputation, evicts the least
    /// recently used one (LRU policy).
    #[allow(dead_code)]
    fn evict_lowest_reputation(&mut self) {
        if self.cache.is_empty() {
            return;
        }
        
        // Find entry with lowest reputation score
        // If tied, prefer least recently used
        let mut lowest_key: Option<TargetKey> = None;
        let mut lowest_score = f64::MAX;
        
        #[cfg(feature = "std")]
        let mut oldest_time = Instant::now();
        
        #[cfg(not(feature = "std"))]
        let mut oldest_time = Duration::from_secs(u64::MAX);
        
        for (key, entry) in &self.cache {
            #[cfg(feature = "std")]
            let is_older = entry.last_used < oldest_time;
            
            #[cfg(not(feature = "std"))]
            let is_older = entry.last_used < oldest_time;
            
            if entry.reputation_score < lowest_score || 
               (entry.reputation_score == lowest_score && is_older) {
                lowest_score = entry.reputation_score;
                lowest_key = Some(key.clone());
                oldest_time = entry.last_used;
            }
        }
        
        // Remove the lowest reputation entry
        if let Some(key) = lowest_key {
            self.cache.remove(&key);
        }
    }
    
    /// Get a working fingerprint for the target with small random variation.
    ///
    /// This method looks up a cached fingerprint for the target and returns it
    /// with small random variations applied. The variations are template-consistent
    /// and designed to avoid exact repetition while maintaining behavioral similarity.
    ///
    /// # Arguments
    ///
    /// * `target` - The target to look up
    ///
    /// # Returns
    ///
    /// `Some(config)` if a cached fingerprint exists, `None` otherwise.
    /// The returned config has small variations applied.
    ///
    /// # Note
    ///
    /// This method updates the `last_used` timestamp for the cache entry.
    pub fn get_working_fingerprint(
        &mut self,
        target: &TargetKey,
    ) -> Option<ClientHelloConfig> {
        // Look up cached entry
        if let Some(entry) = self.cache.get_mut(target) {
            // Update last used timestamp
            entry.touch();
            
            // Clone the config for variation
            // Note: Actual variation logic will be applied by the randomizer
            // in the calling code. We just return the cached config here.
            Some(entry.config.clone())
        } else {
            None
        }
    }
    
    /// Record the result of a handshake attempt.
    ///
    /// Updates the cache entry's success/failure counts and recalculates the
    /// reputation score. If no entry exists for the target, creates a new one.
    ///
    /// # Arguments
    ///
    /// * `target` - The target that was connected to
    /// * `config` - The ClientHello configuration that was used
    /// * `success` - Whether the handshake succeeded
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // After successful handshake
    /// manager.record_result(&target, config, true);
    ///
    /// // After failed handshake
    /// manager.record_result(&target, config, false);
    /// ```
    pub fn record_result(
        &mut self,
        target: &TargetKey,
        config: ClientHelloConfig,
        success: bool,
    ) {
        // Check if entry exists
        let entry_exists = self.cache.contains_key(target);
        
        // If entry doesn't exist and cache is full, evict first
        if !entry_exists && self.cache.len() >= self.max_size {
            self.evict_lowest_reputation();
        }
        
        // Get or create entry
        let entry = self.cache.entry(target.clone())
            .or_insert_with(|| FingerprintEntry::new(config.clone()));
        
        // Update counts
        if success {
            entry.success_count += 1;
        } else {
            entry.failure_count += 1;
        }
        
        // Update reputation score
        entry.update_reputation();
        
        // Update last used timestamp
        entry.touch();
        
        // Update config if it's different (e.g., after variation)
        entry.config = config;
    }
    
    /// Get cache statistics for a specific target
    ///
    /// # Arguments
    ///
    /// * `target` - The target to query
    ///
    /// # Returns
    ///
    /// `Some((success_count, failure_count, reputation_score))` if entry exists,
    /// `None` otherwise.
    pub fn get_stats(&self, target: &TargetKey) -> Option<(u32, u32, f64)> {
        self.cache.get(target).map(|entry| {
            (entry.success_count, entry.failure_count, entry.reputation_score)
        })
    }
    
    /// Get all cached targets
    ///
    /// Returns a vector of all target keys currently in the cache.
    pub fn get_all_targets(&self) -> Vec<TargetKey> {
        self.cache.keys().cloned().collect()
    }
    
    /// Get previously used GREASE values for a target
    ///
    /// Returns a slice of GREASE values that were recently used for this target.
    /// This allows the randomizer to avoid repeating the same GREASE values.
    ///
    /// # Arguments
    ///
    /// * `target` - The target to query
    ///
    /// # Returns
    ///
    /// A slice of previously used GREASE values (up to 10 most recent)
    pub fn get_previous_grease_values(&self, target: &TargetKey) -> &[u16] {
        self.cache
            .get(target)
            .map(|entry| entry.get_previous_grease_values())
            .unwrap_or(&[])
    }
    
    /// Track a GREASE value for a target
    ///
    /// Records that a specific GREASE value was used for this target.
    /// This helps ensure variation across connections.
    ///
    /// # Arguments
    ///
    /// * `target` - The target that was connected to
    /// * `grease_value` - The GREASE value that was used
    pub fn track_grease_value(&mut self, target: &TargetKey, grease_value: u16) {
        if let Some(entry) = self.cache.get_mut(target) {
            entry.track_grease_value(grease_value);
        }
    }
    
    /// Get previously used padding lengths for a target
    ///
    /// Returns a slice of padding lengths that were recently used for this target.
    /// This allows the randomizer to vary padding lengths across connections.
    ///
    /// # Arguments
    ///
    /// * `target` - The target to query
    ///
    /// # Returns
    ///
    /// A slice of previously used padding lengths (up to 10 most recent)
    pub fn get_previous_padding_lengths(&self, target: &TargetKey) -> &[u16] {
        self.cache
            .get(target)
            .map(|entry| entry.get_previous_padding_lengths())
            .unwrap_or(&[])
    }
    
    /// Track a padding length for a target
    ///
    /// Records that a specific padding length was used for this target.
    /// This helps ensure variation across connections.
    ///
    /// # Arguments
    ///
    /// * `target` - The target that was connected to
    /// * `padding_length` - The padding length that was used
    pub fn track_padding_length(&mut self, target: &TargetKey, padding_length: u16) {
        if let Some(entry) = self.cache.get_mut(target) {
            entry.track_padding_length(padding_length);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    
    // Helper function to create a test config
    fn create_test_config() -> ClientHelloConfig {
        ClientHelloConfig {
            template: BrowserTemplate::Chrome130,
            cipher_suites: Vec::new(),
            extension_order: Vec::new(),
            extension_data: BTreeMap::new(),
            grease_cipher_positions: Vec::new(),
            grease_extension_positions: Vec::new(),
            padding_length: 0,
            random_seed: 0,
            supported_groups: Vec::new(),
            signature_algorithms: Vec::new(),
        }
    }
    
    #[test]
    fn test_target_key_creation() {
        let key = TargetKey::new("example.com".to_string(), 443);
        assert_eq!(key.host, "example.com");
        assert_eq!(key.port, 443);
    }
    
    #[test]
    fn test_fingerprint_entry_reputation() {
        let config = create_test_config();
        let mut entry = FingerprintEntry::new(config);
        
        // Initial reputation should be neutral
        assert_eq!(entry.reputation_score, 0.5);
        
        // After successes, reputation should increase
        entry.success_count = 10;
        entry.failure_count = 0;
        entry.update_reputation();
        assert_eq!(entry.reputation_score, 1.0);
        
        // After failures, reputation should decrease
        entry.success_count = 5;
        entry.failure_count = 5;
        entry.update_reputation();
        assert_eq!(entry.reputation_score, 0.5);
        
        // More failures than successes
        entry.success_count = 2;
        entry.failure_count = 8;
        entry.update_reputation();
        assert_eq!(entry.reputation_score, 0.2);
    }
    
    #[test]
    fn test_fingerprint_manager_creation() {
        let manager = FingerprintManager::new(100);
        assert_eq!(manager.max_size(), 100);
        assert_eq!(manager.size(), 0);
        assert!(manager.is_empty());
    }
    
    #[test]
    fn test_cache_clear() {
        let mut manager = FingerprintManager::new(100);
        let target = TargetKey::new("example.com".to_string(), 443);
        let config = create_test_config();
        
        manager.record_result(&target, config, true);
        assert_eq!(manager.size(), 1);
        
        manager.clear_cache();
        assert_eq!(manager.size(), 0);
        assert!(manager.is_empty());
    }
    
    #[test]
    fn test_cache_invalidate_target() {
        let mut manager = FingerprintManager::new(100);
        let target1 = TargetKey::new("example.com".to_string(), 443);
        let target2 = TargetKey::new("test.com".to_string(), 443);
        let config = create_test_config();
        
        manager.record_result(&target1, config.clone(), true);
        manager.record_result(&target2, config, true);
        assert_eq!(manager.size(), 2);
        
        assert!(manager.invalidate_target(&target1));
        assert_eq!(manager.size(), 1);
        
        assert!(!manager.invalidate_target(&target1)); // Already removed
        assert_eq!(manager.size(), 1);
    }
    
    #[test]
    fn test_cache_insertion_and_lookup() {
        let mut manager = FingerprintManager::new(100);
        let target = TargetKey::new("example.com".to_string(), 443);
        let mut config = create_test_config();
        config.padding_length = 256;
        
        // Record result
        manager.record_result(&target, config.clone(), true);
        
        // Lookup should return the config
        let retrieved = manager.get_working_fingerprint(&target);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().padding_length, 256);
    }
    
    #[test]
    fn test_reputation_score_calculation() {
        let mut manager = FingerprintManager::new(100);
        let target = TargetKey::new("example.com".to_string(), 443);
        let config = create_test_config();
        
        // All successes
        for _ in 0..10 {
            manager.record_result(&target, config.clone(), true);
        }
        let stats = manager.get_stats(&target).unwrap();
        assert_eq!(stats.0, 10); // success_count
        assert_eq!(stats.1, 0);  // failure_count
        assert_eq!(stats.2, 1.0); // reputation_score
        
        // Add some failures
        for _ in 0..5 {
            manager.record_result(&target, config.clone(), false);
        }
        let stats = manager.get_stats(&target).unwrap();
        assert_eq!(stats.0, 10); // success_count
        assert_eq!(stats.1, 5);  // failure_count
        assert!((stats.2 - 0.666).abs() < 0.01); // reputation_score ~= 10/15
    }
    
    #[test]
    fn test_cache_eviction_policy() {
        let mut manager = FingerprintManager::new(3);
        let config = create_test_config();
        
        // Create entries with different reputations
        let target1 = TargetKey::new("high-rep.com".to_string(), 443);
        let target2 = TargetKey::new("medium-rep.com".to_string(), 443);
        let target3 = TargetKey::new("low-rep.com".to_string(), 443);
        
        // High reputation (10 successes)
        for _ in 0..10 {
            manager.record_result(&target1, config.clone(), true);
        }
        
        // Medium reputation (5 successes, 5 failures)
        for _ in 0..5 {
            manager.record_result(&target2, config.clone(), true);
        }
        for _ in 0..5 {
            manager.record_result(&target2, config.clone(), false);
        }
        
        // Low reputation (0 successes, 10 failures)
        for _ in 0..10 {
            manager.record_result(&target3, config.clone(), false);
        }
        
        assert_eq!(manager.size(), 3);
        
        // Add a new entry, should evict low-rep
        let target4 = TargetKey::new("new.com".to_string(), 443);
        manager.record_result(&target4, config.clone(), true);
        
        assert_eq!(manager.size(), 3);
        assert!(manager.get_stats(&target1).is_some()); // High rep should remain
        assert!(manager.get_stats(&target2).is_some()); // Medium rep should remain
        assert!(manager.get_stats(&target3).is_none()); // Low rep should be evicted
        assert!(manager.get_stats(&target4).is_some()); // New entry should be present
    }
    
    #[test]
    fn test_manual_invalidation() {
        let mut manager = FingerprintManager::new(100);
        let target1 = TargetKey::new("example.com".to_string(), 443);
        let target2 = TargetKey::new("test.com".to_string(), 443);
        let config = create_test_config();
        
        manager.record_result(&target1, config.clone(), true);
        manager.record_result(&target2, config, true);
        assert_eq!(manager.size(), 2);
        
        // Invalidate specific target
        assert!(manager.invalidate_target(&target1));
        assert_eq!(manager.size(), 1);
        assert!(manager.get_stats(&target1).is_none());
        assert!(manager.get_stats(&target2).is_some());
        
        // Clear all
        manager.clear_cache();
        assert_eq!(manager.size(), 0);
        assert!(manager.get_stats(&target2).is_none());
    }
    
    #[test]
    fn test_get_all_targets() {
        let mut manager = FingerprintManager::new(100);
        let config = create_test_config();
        
        let target1 = TargetKey::new("example.com".to_string(), 443);
        let target2 = TargetKey::new("test.com".to_string(), 443);
        let target3 = TargetKey::new("demo.com".to_string(), 443);
        
        manager.record_result(&target1, config.clone(), true);
        manager.record_result(&target2, config.clone(), true);
        manager.record_result(&target3, config, true);
        
        let targets = manager.get_all_targets();
        assert_eq!(targets.len(), 3);
        assert!(targets.contains(&target1));
        assert!(targets.contains(&target2));
        assert!(targets.contains(&target3));
    }
    
    #[test]
    fn test_cache_updates_existing_entry() {
        let mut manager = FingerprintManager::new(100);
        let target = TargetKey::new("example.com".to_string(), 443);
        let mut config1 = create_test_config();
        config1.padding_length = 100;
        
        // Initial record
        manager.record_result(&target, config1, true);
        assert_eq!(manager.size(), 1);
        
        // Update with different config
        let mut config2 = create_test_config();
        config2.padding_length = 200;
        manager.record_result(&target, config2, true);
        
        // Should still have only 1 entry
        assert_eq!(manager.size(), 1);
        
        // Config should be updated
        let retrieved = manager.get_working_fingerprint(&target).unwrap();
        assert_eq!(retrieved.padding_length, 200);
        
        // Stats should reflect both results
        let stats = manager.get_stats(&target).unwrap();
        assert_eq!(stats.0, 2); // 2 successes
    }
    
    #[test]
    fn test_empty_cache_operations() {
        let mut manager = FingerprintManager::new(100);
        
        assert!(manager.is_empty());
        assert_eq!(manager.size(), 0);
        
        let target = TargetKey::new("example.com".to_string(), 443);
        assert!(manager.get_working_fingerprint(&target).is_none());
        assert!(manager.get_stats(&target).is_none());
        assert!(!manager.invalidate_target(&target));
        
        let targets = manager.get_all_targets();
        assert!(targets.is_empty());
    }
}

#[cfg(test)]
#[path = "state_properties.rs"]
mod state_properties;
