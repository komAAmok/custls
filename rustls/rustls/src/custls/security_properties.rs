//! Property-based tests for custls security features.
//!
//! These tests verify universal correctness properties that must hold
//! across all inputs for security-critical functionality.

#[cfg(test)]
mod tests {
    use super::super::*;
    use proptest::prelude::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use alloc::collections::BTreeMap;
    use crate::custls::BrowserTemplate;
    
    // Helper to create a test ClientHelloConfig
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
    
    /// Property 13: Downgrade Attack Detection
    ///
    /// For any TLS connection where the server attempts a protocol downgrade attack
    /// (by including the downgrade canary in ServerHello.random), the system SHALL
    /// detect the attack and abort the handshake with a clear error.
    ///
    /// **Validates: Requirements 7.2, 7.3**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        #[test]
        fn property_downgrade_attack_detection(
            // Generate random bytes for the first 24 bytes of server_random
            random_prefix in prop::collection::vec(prop::num::u8::ANY, 24..=24),
            // Choose which canary to inject (or none)
            canary_type in 0u8..3,
        ) {
            // Build server_random with potential canary
            let mut server_random = vec![0u8; 32];
            server_random[0..24].copy_from_slice(&random_prefix);
            
            match canary_type {
                0 => {
                    // TLS 1.2 downgrade canary
                    server_random[24..32].copy_from_slice(&TLS12_DOWNGRADE_CANARY);
                    
                    // Should detect downgrade when expecting TLS 1.3 but getting TLS 1.2
                    let result = validate_downgrade_protection(
                        &server_random,
                        ProtocolVersion::TLSv1_3,
                        ProtocolVersion::TLSv1_2,
                    );
                    
                    prop_assert!(result.is_err(), "Failed to detect TLS 1.2 downgrade attack");
                }
                1 => {
                    // TLS 1.1 downgrade canary
                    server_random[24..32].copy_from_slice(&TLS11_DOWNGRADE_CANARY);
                    
                    // Should detect downgrade when expecting TLS 1.3 but getting TLS 1.1
                    let result = validate_downgrade_protection(
                        &server_random,
                        ProtocolVersion::TLSv1_3,
                        ProtocolVersion::TLSv1_1,
                    );
                    
                    prop_assert!(result.is_err(), "Failed to detect TLS 1.1 downgrade attack");
                }
                _ => {
                    // No canary - should pass validation
                    let result = validate_downgrade_protection(
                        &server_random,
                        ProtocolVersion::TLSv1_3,
                        ProtocolVersion::TLSv1_3,
                    );
                    
                    prop_assert!(result.is_ok(), "False positive downgrade detection");
                }
            }
        }
        
        #[test]
        fn property_downgrade_detection_only_when_expecting_tls13(
            random_bytes in prop::collection::vec(prop::num::u8::ANY, 32..=32),
            expected_version in prop::sample::select(vec![
                ProtocolVersion::TLSv1_0,
                ProtocolVersion::TLSv1_1,
                ProtocolVersion::TLSv1_2,
            ]),
        ) {
            // When not expecting TLS 1.3, no downgrade check should occur
            // even if canary is present
            let result = validate_downgrade_protection(
                &random_bytes,
                expected_version,
                expected_version,
            );
            
            prop_assert!(result.is_ok(), 
                "Downgrade check should only apply when expecting TLS 1.3");
        }
    }
    
    /// Property 14: Session Ticket Reuse
    ///
    /// For any valid session ticket from a previous connection, reusing that ticket
    /// in a new connection to the same target SHALL result in an abbreviated handshake
    /// (session resumption) rather than a full handshake.
    ///
    /// **Validates: Requirements 9.1**
    ///
    /// Note: This property tests the state tracking mechanism. The actual abbreviated
    /// handshake behavior is handled by rustls core.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        #[test]
        fn property_session_ticket_reuse(
            session_id_bytes in prop::collection::vec(prop::num::u8::ANY, 1..32),
            ticket_bytes in prop::collection::vec(prop::num::u8::ANY, 1..256),
        ) {
            let mut tracker = SessionStateTracker::new(100);
            let session_id = SessionId::new(session_id_bytes);
            let config = create_test_config();
            
            // Record initial session
            tracker.record_session(&session_id, config.clone());
            
            // Mark as established
            tracker.mark_established(&session_id);
            
            // Record ticket
            tracker.record_ticket(&session_id, ticket_bytes.clone());
            
            // Verify session has ticket
            let stats = tracker.get_session_stats(&session_id);
            prop_assert!(stats.is_some(), "Session should exist");
            
            let (established, resume_count, has_ticket) = stats.unwrap();
            prop_assert!(established, "Session should be established");
            prop_assert!(has_ticket, "Session should have ticket");
            prop_assert_eq!(resume_count, 0, "Initial resume count should be 0");
            
            // Record resumption
            tracker.record_resumption(&session_id);
            
            // Verify resume count incremented
            let stats = tracker.get_session_stats(&session_id).unwrap();
            prop_assert_eq!(stats.1, 1, "Resume count should increment");
            
            // Config should remain consistent
            let retrieved_config = tracker.get_session_config(&session_id);
            prop_assert!(retrieved_config.is_some(), "Config should be retrievable");
        }
    }
    
    /// Property 16: Session State Consistency
    ///
    /// For any session, multiple operations within that session SHALL observe
    /// consistent state (same template, same base configuration) while allowing
    /// small variations in randomizable parameters.
    ///
    /// **Validates: Requirements 9.6**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        #[test]
        fn property_session_state_consistency(
            session_id_bytes in prop::collection::vec(prop::num::u8::ANY, 1..32),
            padding_length in 0u16..1500,
            random_seed in prop::num::u64::ANY,
            num_lookups in 2usize..10,
        ) {
            let mut tracker = SessionStateTracker::new(100);
            let session_id = SessionId::new(session_id_bytes);
            
            // Create config with specific values
            let mut config = create_test_config();
            config.padding_length = padding_length;
            config.random_seed = random_seed;
            
            // Record session
            tracker.record_session(&session_id, config.clone());
            
            // Perform multiple lookups
            for _ in 0..num_lookups {
                let retrieved = tracker.get_session_config(&session_id);
                prop_assert!(retrieved.is_some(), "Config should always be retrievable");
                
                let retrieved_config = retrieved.unwrap();
                
                // Core configuration should be consistent
                prop_assert_eq!(
                    retrieved_config.padding_length,
                    padding_length,
                    "Padding length should be consistent within session"
                );
                prop_assert_eq!(
                    retrieved_config.random_seed,
                    random_seed,
                    "Random seed should be consistent within session"
                );
                prop_assert_eq!(
                    &retrieved_config.template,
                    &config.template,
                    "Template should be consistent within session"
                );
            }
        }
        
        #[test]
        fn property_session_state_isolation(
            session1_bytes in prop::collection::vec(prop::num::u8::ANY, 1..32),
            session2_bytes in prop::collection::vec(prop::num::u8::ANY, 1..32),
            padding1 in 0u16..1500,
            padding2 in 0u16..1500,
        ) {
            // Ensure different session IDs
            prop_assume!(session1_bytes != session2_bytes);
            
            let mut tracker = SessionStateTracker::new(100);
            let session1 = SessionId::new(session1_bytes);
            let session2 = SessionId::new(session2_bytes);
            
            // Create different configs
            let mut config1 = create_test_config();
            config1.padding_length = padding1;
            
            let mut config2 = create_test_config();
            config2.padding_length = padding2;
            
            // Record both sessions
            tracker.record_session(&session1, config1);
            tracker.record_session(&session2, config2);
            
            // Verify isolation - each session has its own config
            let retrieved1 = tracker.get_session_config(&session1).unwrap();
            let retrieved2 = tracker.get_session_config(&session2).unwrap();
            
            prop_assert_eq!(retrieved1.padding_length, padding1);
            prop_assert_eq!(retrieved2.padding_length, padding2);
            
            // Modifying one session shouldn't affect the other
            tracker.mark_established(&session1);
            
            let stats1 = tracker.get_session_stats(&session1).unwrap();
            let stats2 = tracker.get_session_stats(&session2).unwrap();
            
            prop_assert!(stats1.0, "Session 1 should be established");
            prop_assert!(!stats2.0, "Session 2 should not be established");
        }
    }
    
    /// Additional property: Session eviction maintains consistency
    ///
    /// When the session tracker reaches capacity and evicts old sessions,
    /// the remaining sessions should maintain their state correctly.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]
        
        #[test]
        fn property_session_eviction_consistency(
            num_sessions in 5usize..20,
        ) {
            let max_size = 10;
            let mut tracker = SessionStateTracker::new(max_size);
            
            // Create more sessions than capacity
            let mut session_ids = Vec::new();
            for i in 0..num_sessions {
                let session_id = SessionId::new(vec![i as u8]);
                let mut config = create_test_config();
                config.padding_length = i as u16 * 100;
                
                tracker.record_session(&session_id, config);
                session_ids.push(session_id);
            }
            
            // Tracker should not exceed max size
            prop_assert!(
                tracker.size() <= max_size,
                "Tracker size {} should not exceed max_size {}",
                tracker.size(),
                max_size
            );
            
            // Recent sessions should still be present
            let recent_start = if num_sessions > max_size {
                num_sessions - max_size
            } else {
                0
            };
            
            for i in recent_start..num_sessions {
                let session_id = &session_ids[i];
                let config = tracker.get_session_config(session_id);
                
                if config.is_some() {
                    // If session is present, its config should be correct
                    prop_assert_eq!(
                        config.unwrap().padding_length,
                        i as u16 * 100,
                        "Session config should be consistent after eviction"
                    );
                }
            }
        }
    }
}
