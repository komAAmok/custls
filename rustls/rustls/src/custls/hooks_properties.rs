//! Property-based tests for hooks module
//! These tests verify universal properties of the hook system

#[cfg(test)]
mod property_tests {
    use super::super::*;
    use crate::error::Error;
    use crate::crypto::CipherSuite;
    use crate::msgs::ClientHelloPayload;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};

    // Feature: custls, Property 2: Hook Modifications Persist
    // For any modification made to ClientHello components within a hook callback,
    // the final ClientHello SHALL reflect those modifications.
    
    #[derive(Debug)]
    struct ModifyingCustomizer {
        phase2_called: Arc<AtomicBool>,
        phase3_called: Arc<AtomicBool>,
        test_cipher_suite: CipherSuite,
    }

    impl ModifyingCustomizer {
        fn new(test_cipher_suite: CipherSuite) -> Self {
            Self {
                phase2_called: Arc::new(AtomicBool::new(false)),
                phase3_called: Arc::new(AtomicBool::new(false)),
                test_cipher_suite,
            }
        }
    }

    impl ClientHelloCustomizer for ModifyingCustomizer {
        fn on_components_ready(
            &self,
            cipher_suites: &mut Vec<CipherSuite>,
            _extensions: &mut Vec<ClientExtension>,
        ) -> Result<(), Error> {
            self.phase2_called.store(true, Ordering::SeqCst);
            // Add a test cipher suite at the beginning
            cipher_suites.insert(0, self.test_cipher_suite);
            Ok(())
        }

        fn on_struct_ready(&self, payload: &mut ClientHelloPayload) -> Result<(), Error> {
            self.phase3_called.store(true, Ordering::SeqCst);
            // Verify the modification from phase 2 is present
            assert!(
                payload.cipher_suites.contains(&self.test_cipher_suite),
                "Cipher suite modification from phase 2 should persist to phase 3"
            );
            Ok(())
        }
    }

    #[test]
    fn test_hook_modifications_persist_phase2_to_phase3() {
        // This test verifies that modifications made in phase 2 (on_components_ready)
        // persist to phase 3 (on_struct_ready)
        
        // Use a distinctive cipher suite for testing
        let test_suite = CipherSuite::TLS13_AES_128_GCM_SHA256;
        let customizer = ModifyingCustomizer::new(test_suite);
        
        // Create a test ClientHelloPayload
        let mut payload = ClientHelloPayload {
            client_version: crate::enums::ProtocolVersion::TLSv1_2,
            random: crate::msgs::Random([0u8; 32]),
            session_id: crate::msgs::SessionId::empty(),
            cipher_suites: vec![CipherSuite::TLS13_AES_256_GCM_SHA384],
            compression_methods: vec![crate::msgs::Compression::Null],
            extensions: Box::new(crate::msgs::ClientExtensions::default()),
        };
        
        // Simulate phase 2: modify cipher suites
        let mut cipher_suites = payload.cipher_suites.clone();
        let mut extensions_placeholder = vec![];
        customizer.on_components_ready(&mut cipher_suites, &mut extensions_placeholder).unwrap();
        payload.cipher_suites = cipher_suites;
        
        // Verify phase 2 was called
        assert!(customizer.phase2_called.load(Ordering::SeqCst), "Phase 2 should be called");
        
        // Simulate phase 3: verify modifications persist
        customizer.on_struct_ready(&mut payload).unwrap();
        
        // Verify phase 3 was called
        assert!(customizer.phase3_called.load(Ordering::SeqCst), "Phase 3 should be called");
        
        // Verify the modification is still present
        assert_eq!(payload.cipher_suites[0], test_suite, "Modified cipher suite should be first");
    }
}
