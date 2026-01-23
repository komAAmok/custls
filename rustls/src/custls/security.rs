//! Security features for custls.
//!
//! This module implements security-critical features that must be preserved
//! even when customizing ClientHello fingerprints:
//!
//! - RFC 8446 downgrade protection with canary validation
//! - Session ticket reuse and management
//! - Per-session state consistency
//!
//! ## Design Philosophy
//!
//! custls maintains all rustls security guarantees. This module ensures that
//! fingerprint customization does not compromise connection security.
//!
//! ## Downgrade Protection
//!
//! RFC 8446 Section 4.1.3 defines downgrade protection canaries that servers
//! must include in ServerHello.random when negotiating older protocol versions.
//! This prevents active attackers from forcing protocol downgrades.
//!
//! TLS 1.3 servers negotiating TLS 1.2 MUST set the last 8 bytes of
//! ServerHello.random to:
//! ```text
//! 44 4F 57 4E 47 52 44 01  ("DOWNGRD\x01")
//! ```
//!
//! TLS 1.3 servers negotiating TLS 1.1 or below MUST set the last 8 bytes to:
//! ```text
//! 44 4F 57 4E 47 52 44 00  ("DOWNGRD\x00")
//! ```
//!
//! ## Session Tickets
//!
//! Session tickets enable abbreviated handshakes by caching session state.
//! custls ensures that:
//! - Tickets are correctly stored and reused
//! - Fingerprint consistency is maintained during resumption
//! - Session state is tracked per connection
//!
//! ## Usage
//!
//! ```rust,ignore
//! use rustls::custls::security::{validate_downgrade_protection, SessionStateTracker};
//!
//! // Validate ServerHello for downgrade attacks
//! validate_downgrade_protection(&server_hello_random, expected_version)?;
//!
//! // Track session state
//! let mut tracker = SessionStateTracker::new();
//! tracker.record_session(&session_id, config);
//! ```

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::error::Error as RustlsError;
use crate::enums::ProtocolVersion;

use super::state::ClientHelloConfig;

/// RFC 8446 downgrade protection canary for TLS 1.2
///
/// When a TLS 1.3 server negotiates TLS 1.2, it MUST set the last 8 bytes
/// of ServerHello.random to this value.
pub const TLS12_DOWNGRADE_CANARY: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];

/// RFC 8446 downgrade protection canary for TLS 1.1 and below
///
/// When a TLS 1.3 server negotiates TLS 1.1 or below, it MUST set the last
/// 8 bytes of ServerHello.random to this value.
pub const TLS11_DOWNGRADE_CANARY: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];

/// Validate ServerHello.random for downgrade attack detection.
///
/// This function checks if the server is attempting a protocol downgrade attack
/// by examining the downgrade canary in ServerHello.random.
///
/// # Arguments
///
/// * `server_random` - The 32-byte random value from ServerHello
/// * `expected_version` - The protocol version we expect to negotiate
/// * `negotiated_version` - The protocol version the server selected
///
/// # Returns
///
/// `Ok(())` if no downgrade attack is detected, `Err` if a downgrade is detected.
///
/// # Errors
///
/// Returns `RustlsError::PeerMisbehaved` if:
/// - TLS 1.2 downgrade canary is present when expecting TLS 1.3
/// - TLS 1.1 downgrade canary is present when expecting TLS 1.3
///
/// # Examples
///
/// ```rust,ignore
/// let server_random = &server_hello.random;
/// validate_downgrade_protection(
///     server_random,
///     ProtocolVersion::TLSv1_3,
///     ProtocolVersion::TLSv1_2,
/// )?;
/// ```
pub fn validate_downgrade_protection(
    server_random: &[u8],
    expected_version: ProtocolVersion,
    negotiated_version: ProtocolVersion,
) -> Result<(), RustlsError> {
    // Only check if we expected TLS 1.3 but got something older
    if expected_version != ProtocolVersion::TLSv1_3 {
        return Ok(());
    }
    
    // Server random must be exactly 32 bytes
    if server_random.len() != 32 {
        return Err(RustlsError::PeerMisbehaved(
            crate::error::PeerMisbehaved::IllegalTlsInnerPlaintext,
        ));
    }
    
    // Extract last 8 bytes
    let last_8_bytes = &server_random[24..32];
    
    // Check for TLS 1.2 downgrade canary
    if negotiated_version == ProtocolVersion::TLSv1_2 {
        if last_8_bytes == TLS12_DOWNGRADE_CANARY {
            return Err(RustlsError::PeerMisbehaved(
                crate::error::PeerMisbehaved::AttemptedDowngradeToTls12WhenTls13IsSupported,
            ));
        }
    }
    
    // Check for TLS 1.1 or below downgrade canary
    if negotiated_version == ProtocolVersion::TLSv1_1 || 
       negotiated_version == ProtocolVersion::TLSv1_0 {
        if last_8_bytes == TLS11_DOWNGRADE_CANARY {
            return Err(RustlsError::PeerMisbehaved(
                crate::error::PeerMisbehaved::AttemptedDowngradeToTls12WhenTls13IsSupported,
            ));
        }
    }
    
    Ok(())
}

/// Session identifier for tracking session state.
///
/// Sessions are identified by a unique session ID assigned by the server
/// or derived from the session ticket.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub Vec<u8>);

impl SessionId {
    /// Create a new session ID from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    
    /// Create an empty session ID
    pub fn empty() -> Self {
        Self(Vec::new())
    }
    
    /// Check if the session ID is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    
    /// Get the session ID bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Session state entry tracking fingerprint configuration per session.
///
/// This structure maintains the ClientHello configuration used for a session
/// to ensure consistency during session resumption and within a session.
#[derive(Debug, Clone)]
pub struct SessionState {
    /// The ClientHello configuration used for this session
    pub config: ClientHelloConfig,
    
    /// Session ticket (if any)
    pub ticket: Option<Vec<u8>>,
    
    /// Whether this session has been successfully established
    pub established: bool,
    
    /// Number of times this session has been resumed
    pub resume_count: u32,
}

impl SessionState {
    /// Create a new session state
    pub fn new(config: ClientHelloConfig) -> Self {
        Self {
            config,
            ticket: None,
            established: false,
            resume_count: 0,
        }
    }
    
    /// Mark the session as established
    pub fn mark_established(&mut self) {
        self.established = true;
    }
    
    /// Record a session ticket
    pub fn set_ticket(&mut self, ticket: Vec<u8>) {
        self.ticket = Some(ticket);
    }
    
    /// Increment the resume count
    pub fn increment_resume_count(&mut self) {
        self.resume_count += 1;
    }
}

/// Session state tracker for managing per-session fingerprint consistency.
///
/// This tracker ensures that:
/// - The same ClientHello configuration is used within a session
/// - Session tickets are correctly associated with configurations
/// - Variations are applied across sessions, not within sessions
///
/// ## Thread Safety
///
/// SessionStateTracker is not thread-safe by default. If you need to share it
/// across threads, wrap it in a Mutex or RwLock.
pub struct SessionStateTracker {
    /// Map of session ID to session state
    sessions: BTreeMap<SessionId, SessionState>,
    
    /// Maximum number of tracked sessions
    max_sessions: usize,
}

impl SessionStateTracker {
    /// Create a new session state tracker.
    ///
    /// # Arguments
    ///
    /// * `max_sessions` - Maximum number of sessions to track. When this limit
    ///   is reached, the oldest sessions are evicted.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let tracker = SessionStateTracker::new(1000);
    /// ```
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: BTreeMap::new(),
            max_sessions,
        }
    }
    
    /// Get the current number of tracked sessions
    pub fn size(&self) -> usize {
        self.sessions.len()
    }
    
    /// Check if the tracker is empty
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
    
    /// Record a new session with its configuration.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session identifier
    /// * `config` - The ClientHello configuration used for this session
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// tracker.record_session(&session_id, config);
    /// ```
    pub fn record_session(&mut self, session_id: &SessionId, config: ClientHelloConfig) {
        // Evict oldest session if at capacity
        if self.sessions.len() >= self.max_sessions && !self.sessions.contains_key(session_id) {
            // Remove the first (oldest) entry
            if let Some(first_key) = self.sessions.keys().next().cloned() {
                self.sessions.remove(&first_key);
            }
        }
        
        // Insert or update session state
        let state = SessionState::new(config);
        self.sessions.insert(session_id.clone(), state);
    }
    
    /// Get the configuration for a session.
    ///
    /// Returns the ClientHello configuration that should be used for this session
    /// to maintain consistency.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session identifier
    ///
    /// # Returns
    ///
    /// `Some(config)` if the session is tracked, `None` otherwise.
    pub fn get_session_config(&self, session_id: &SessionId) -> Option<&ClientHelloConfig> {
        self.sessions.get(session_id).map(|state| &state.config)
    }
    
    /// Mark a session as established.
    ///
    /// This should be called after a successful handshake.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session identifier
    pub fn mark_established(&mut self, session_id: &SessionId) {
        if let Some(state) = self.sessions.get_mut(session_id) {
            state.mark_established();
        }
    }
    
    /// Record a session ticket for a session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session identifier
    /// * `ticket` - The session ticket bytes
    pub fn record_ticket(&mut self, session_id: &SessionId, ticket: Vec<u8>) {
        if let Some(state) = self.sessions.get_mut(session_id) {
            state.set_ticket(ticket);
        }
    }
    
    /// Record a session resumption.
    ///
    /// This increments the resume count for the session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session identifier
    pub fn record_resumption(&mut self, session_id: &SessionId) {
        if let Some(state) = self.sessions.get_mut(session_id) {
            state.increment_resume_count();
        }
    }
    
    /// Get session statistics.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session identifier
    ///
    /// # Returns
    ///
    /// `Some((established, resume_count, has_ticket))` if the session exists,
    /// `None` otherwise.
    pub fn get_session_stats(&self, session_id: &SessionId) -> Option<(bool, u32, bool)> {
        self.sessions.get(session_id).map(|state| {
            (state.established, state.resume_count, state.ticket.is_some())
        })
    }
    
    /// Clear all tracked sessions
    pub fn clear(&mut self) {
        self.sessions.clear();
    }
    
    /// Remove a specific session
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session identifier to remove
    ///
    /// # Returns
    ///
    /// `true` if a session was removed, `false` if no session existed
    pub fn remove_session(&mut self, session_id: &SessionId) -> bool {
        self.sessions.remove(session_id).is_some()
    }
    
    /// Get all tracked session IDs
    pub fn get_all_sessions(&self) -> Vec<SessionId> {
        self.sessions.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use crate::custls::BrowserTemplate;
    use alloc::collections::BTreeMap;
    
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
    fn test_downgrade_canary_constants() {
        // Verify the canary values match RFC 8446
        assert_eq!(TLS12_DOWNGRADE_CANARY, [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01]);
        assert_eq!(TLS11_DOWNGRADE_CANARY, [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00]);
        
        // Verify they spell "DOWNGRD" with version suffix
        assert_eq!(&TLS12_DOWNGRADE_CANARY[0..7], b"DOWNGRD");
        assert_eq!(&TLS11_DOWNGRADE_CANARY[0..7], b"DOWNGRD");
    }
    
    #[test]
    fn test_validate_downgrade_protection_no_downgrade() {
        // Normal random without canary
        let server_random = [0u8; 32];
        
        let result = validate_downgrade_protection(
            &server_random,
            ProtocolVersion::TLSv1_3,
            ProtocolVersion::TLSv1_3,
        );
        
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_validate_downgrade_protection_tls12_canary_detected() {
        // Server random with TLS 1.2 downgrade canary
        let mut server_random = [0u8; 32];
        server_random[24..32].copy_from_slice(&TLS12_DOWNGRADE_CANARY);
        
        let result = validate_downgrade_protection(
            &server_random,
            ProtocolVersion::TLSv1_3,
            ProtocolVersion::TLSv1_2,
        );
        
        assert!(result.is_err());
        match result {
            Err(RustlsError::PeerMisbehaved(
                crate::error::PeerMisbehaved::AttemptedDowngradeToTls12WhenTls13IsSupported
            )) => {}
            _ => panic!("Expected AttemptedDowngradeToTls12WhenTls13IsSupported error"),
        }
    }
    
    #[test]
    fn test_validate_downgrade_protection_tls11_canary_detected() {
        // Server random with TLS 1.1 downgrade canary
        let mut server_random = [0u8; 32];
        server_random[24..32].copy_from_slice(&TLS11_DOWNGRADE_CANARY);
        
        let result = validate_downgrade_protection(
            &server_random,
            ProtocolVersion::TLSv1_3,
            ProtocolVersion::TLSv1_1,
        );
        
        assert!(result.is_err());
        match result {
            Err(RustlsError::PeerMisbehaved(
                crate::error::PeerMisbehaved::AttemptedDowngradeToTls12WhenTls13IsSupported
            )) => {}
            _ => panic!("Expected AttemptedDowngradeToTls12WhenTls13IsSupported error"),
        }
    }
    
    #[test]
    fn test_validate_downgrade_protection_not_expecting_tls13() {
        // If we're not expecting TLS 1.3, no check is performed
        let mut server_random = [0u8; 32];
        server_random[24..32].copy_from_slice(&TLS12_DOWNGRADE_CANARY);
        
        let result = validate_downgrade_protection(
            &server_random,
            ProtocolVersion::TLSv1_2,
            ProtocolVersion::TLSv1_2,
        );
        
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_validate_downgrade_protection_invalid_random_length() {
        let server_random = [0u8; 16]; // Wrong length
        
        let result = validate_downgrade_protection(
            &server_random,
            ProtocolVersion::TLSv1_3,
            ProtocolVersion::TLSv1_2,
        );
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_session_id_creation() {
        let id = SessionId::new(vec![1, 2, 3, 4]);
        assert_eq!(id.as_bytes(), &[1, 2, 3, 4]);
        assert!(!id.is_empty());
    }
    
    #[test]
    fn test_session_id_empty() {
        let id = SessionId::empty();
        assert!(id.is_empty());
        assert_eq!(id.as_bytes().len(), 0);
    }
    
    #[test]
    fn test_session_state_creation() {
        let config = create_test_config();
        let state = SessionState::new(config);
        
        assert!(!state.established);
        assert_eq!(state.resume_count, 0);
        assert!(state.ticket.is_none());
    }
    
    #[test]
    fn test_session_state_mark_established() {
        let config = create_test_config();
        let mut state = SessionState::new(config);
        
        state.mark_established();
        assert!(state.established);
    }
    
    #[test]
    fn test_session_state_set_ticket() {
        let config = create_test_config();
        let mut state = SessionState::new(config);
        
        let ticket = vec![1, 2, 3, 4, 5];
        state.set_ticket(ticket.clone());
        
        assert_eq!(state.ticket, Some(ticket));
    }
    
    #[test]
    fn test_session_state_increment_resume_count() {
        let config = create_test_config();
        let mut state = SessionState::new(config);
        
        assert_eq!(state.resume_count, 0);
        
        state.increment_resume_count();
        assert_eq!(state.resume_count, 1);
        
        state.increment_resume_count();
        assert_eq!(state.resume_count, 2);
    }
    
    #[test]
    fn test_session_state_tracker_creation() {
        let tracker = SessionStateTracker::new(100);
        assert_eq!(tracker.size(), 0);
        assert!(tracker.is_empty());
    }
    
    #[test]
    fn test_session_state_tracker_record_session() {
        let mut tracker = SessionStateTracker::new(100);
        let session_id = SessionId::new(vec![1, 2, 3]);
        let config = create_test_config();
        
        tracker.record_session(&session_id, config);
        
        assert_eq!(tracker.size(), 1);
        assert!(!tracker.is_empty());
        assert!(tracker.get_session_config(&session_id).is_some());
    }
    
    #[test]
    fn test_session_state_tracker_get_session_config() {
        let mut tracker = SessionStateTracker::new(100);
        let session_id = SessionId::new(vec![1, 2, 3]);
        let mut config = create_test_config();
        config.padding_length = 256;
        
        tracker.record_session(&session_id, config);
        
        let retrieved = tracker.get_session_config(&session_id).unwrap();
        assert_eq!(retrieved.padding_length, 256);
    }
    
    #[test]
    fn test_session_state_tracker_mark_established() {
        let mut tracker = SessionStateTracker::new(100);
        let session_id = SessionId::new(vec![1, 2, 3]);
        let config = create_test_config();
        
        tracker.record_session(&session_id, config);
        tracker.mark_established(&session_id);
        
        let stats = tracker.get_session_stats(&session_id).unwrap();
        assert!(stats.0); // established
    }
    
    #[test]
    fn test_session_state_tracker_record_ticket() {
        let mut tracker = SessionStateTracker::new(100);
        let session_id = SessionId::new(vec![1, 2, 3]);
        let config = create_test_config();
        let ticket = vec![10, 20, 30];
        
        tracker.record_session(&session_id, config);
        tracker.record_ticket(&session_id, ticket);
        
        let stats = tracker.get_session_stats(&session_id).unwrap();
        assert!(stats.2); // has_ticket
    }
    
    #[test]
    fn test_session_state_tracker_record_resumption() {
        let mut tracker = SessionStateTracker::new(100);
        let session_id = SessionId::new(vec![1, 2, 3]);
        let config = create_test_config();
        
        tracker.record_session(&session_id, config);
        tracker.record_resumption(&session_id);
        tracker.record_resumption(&session_id);
        
        let stats = tracker.get_session_stats(&session_id).unwrap();
        assert_eq!(stats.1, 2); // resume_count
    }
    
    #[test]
    fn test_session_state_tracker_eviction() {
        let mut tracker = SessionStateTracker::new(3);
        let config = create_test_config();
        
        let session1 = SessionId::new(vec![1]);
        let session2 = SessionId::new(vec![2]);
        let session3 = SessionId::new(vec![3]);
        let session4 = SessionId::new(vec![4]);
        
        tracker.record_session(&session1, config.clone());
        tracker.record_session(&session2, config.clone());
        tracker.record_session(&session3, config.clone());
        
        assert_eq!(tracker.size(), 3);
        
        // Adding a 4th session should evict the oldest (session1)
        tracker.record_session(&session4, config);
        
        assert_eq!(tracker.size(), 3);
        assert!(tracker.get_session_config(&session1).is_none());
        assert!(tracker.get_session_config(&session2).is_some());
        assert!(tracker.get_session_config(&session3).is_some());
        assert!(tracker.get_session_config(&session4).is_some());
    }
    
    #[test]
    fn test_session_state_tracker_clear() {
        let mut tracker = SessionStateTracker::new(100);
        let config = create_test_config();
        
        tracker.record_session(&SessionId::new(vec![1]), config.clone());
        tracker.record_session(&SessionId::new(vec![2]), config);
        
        assert_eq!(tracker.size(), 2);
        
        tracker.clear();
        
        assert_eq!(tracker.size(), 0);
        assert!(tracker.is_empty());
    }
    
    #[test]
    fn test_session_state_tracker_remove_session() {
        let mut tracker = SessionStateTracker::new(100);
        let session_id = SessionId::new(vec![1, 2, 3]);
        let config = create_test_config();
        
        tracker.record_session(&session_id, config);
        assert_eq!(tracker.size(), 1);
        
        assert!(tracker.remove_session(&session_id));
        assert_eq!(tracker.size(), 0);
        
        assert!(!tracker.remove_session(&session_id)); // Already removed
    }
    
    #[test]
    fn test_session_state_tracker_get_all_sessions() {
        let mut tracker = SessionStateTracker::new(100);
        let config = create_test_config();
        
        let session1 = SessionId::new(vec![1]);
        let session2 = SessionId::new(vec![2]);
        let session3 = SessionId::new(vec![3]);
        
        tracker.record_session(&session1, config.clone());
        tracker.record_session(&session2, config.clone());
        tracker.record_session(&session3, config);
        
        let sessions = tracker.get_all_sessions();
        assert_eq!(sessions.len(), 3);
        assert!(sessions.contains(&session1));
        assert!(sessions.contains(&session2));
        assert!(sessions.contains(&session3));
    }
    
    #[test]
    fn test_session_state_consistency() {
        let mut tracker = SessionStateTracker::new(100);
        let session_id = SessionId::new(vec![1, 2, 3]);
        let mut config = create_test_config();
        config.padding_length = 512;
        
        // Record session
        tracker.record_session(&session_id, config);
        
        // Get config multiple times - should be consistent
        let config1 = tracker.get_session_config(&session_id).unwrap();
        let config2 = tracker.get_session_config(&session_id).unwrap();
        
        assert_eq!(config1.padding_length, config2.padding_length);
        assert_eq!(config1.padding_length, 512);
    }
}


#[cfg(test)]
#[path = "security_properties.rs"]
mod properties;
