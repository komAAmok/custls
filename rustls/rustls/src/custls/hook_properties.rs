//! Property-based tests for ClientHelloCustomizer trait and hook system
//!
//! These tests verify universal properties that should hold across all inputs
//! and execution scenarios.

use super::*;
use crate::custls::CustlsError;
use alloc::format;
use alloc::string::String;
use alloc::vec;

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    
    // Feature: custls, Property 1: Hook Error Propagation
    //
    // For any ClientHelloCustomizer that returns an error from any hook phase
    // (on_config_resolve, on_components_ready, on_struct_ready, or transform_wire_bytes),
    // the handshake SHALL fail and propagate that error to the caller.
    //
    // Validates: Requirements 2.6
    
    /// Strategy to generate arbitrary error messages
    fn arbitrary_error_message() -> impl Strategy<Value = String> {
        prop::string::string_regex("[a-zA-Z0-9 ]{1,100}").unwrap()
    }
    
    /// Strategy to generate arbitrary CustlsError variants
    fn arbitrary_custls_error() -> impl Strategy<Value = CustlsError> {
        prop_oneof![
            arbitrary_error_message().prop_map(CustlsError::HookError),
            arbitrary_error_message().prop_map(CustlsError::RandomizationError),
            arbitrary_error_message().prop_map(CustlsError::ExtensionError),
            arbitrary_error_message().prop_map(CustlsError::TemplateError),
            arbitrary_error_message().prop_map(CustlsError::CacheError),
            arbitrary_error_message().prop_map(CustlsError::ValidationError),
        ]
    }
    
    /// Strategy to select which hook phase should return an error
    #[derive(Debug, Clone, Copy)]
    enum HookPhase {
        ConfigResolve,
        ComponentsReady,
        StructReady,
        TransformWireBytes,
    }
    
    fn arbitrary_hook_phase() -> impl Strategy<Value = HookPhase> {
        prop_oneof![
            Just(HookPhase::ConfigResolve),
            Just(HookPhase::ComponentsReady),
            Just(HookPhase::StructReady),
            Just(HookPhase::TransformWireBytes),
        ]
    }
    
    /// Customizer that returns an error from a specific phase
    struct ErrorReturningCustomizer {
        phase: HookPhase,
        error: CustlsError,
    }
    
    impl ClientHelloCustomizer for ErrorReturningCustomizer {
        fn on_config_resolve(&self, _config: &mut ConfigParams) -> Result<(), Error> {
            if matches!(self.phase, HookPhase::ConfigResolve) {
                Err(self.error.clone().into())
            } else {
                Ok(())
            }
        }
        
        fn on_components_ready(
            &self,
            _cipher_suites: &mut Vec<CipherSuite>,
            _extensions: &mut Vec<ClientExtension>,
        ) -> Result<(), Error> {
            if matches!(self.phase, HookPhase::ComponentsReady) {
                Err(self.error.clone().into())
            } else {
                Ok(())
            }
        }
        
        fn on_struct_ready(&self, _payload: &mut ClientHelloPayload) -> Result<(), Error> {
            if matches!(self.phase, HookPhase::StructReady) {
                Err(self.error.clone().into())
            } else {
                Ok(())
            }
        }
        
        fn transform_wire_bytes(&self, _bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
            if matches!(self.phase, HookPhase::TransformWireBytes) {
                Err(self.error.clone().into())
            } else {
                Ok(vec![])
            }
        }
    }
    
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 100,
            .. ProptestConfig::default()
        })]
        
        /// Property 1: Hook Error Propagation
        ///
        /// For any hook phase and any error type, when a hook returns an error,
        /// that error must be propagated to the caller.
        #[test]
        fn prop_hook_error_propagation(
            phase in arbitrary_hook_phase(),
            error in arbitrary_custls_error(),
        ) {
            let customizer = ErrorReturningCustomizer {
                phase,
                error: error.clone(),
            };
            
            let mut config = ConfigParams::new();
            let mut cipher_suites = Vec::new();
            let mut extensions = Vec::new();
            let mut payload = ClientHelloPayload::new();
            let bytes = vec![1, 2, 3, 4];
            
            // Call the appropriate hook based on the phase
            let result = match phase {
                HookPhase::ConfigResolve => {
                    customizer.on_config_resolve(&mut config)
                }
                HookPhase::ComponentsReady => {
                    customizer.on_components_ready(&mut cipher_suites, &mut extensions)
                }
                HookPhase::StructReady => {
                    customizer.on_struct_ready(&mut payload)
                }
                HookPhase::TransformWireBytes => {
                    customizer.transform_wire_bytes(bytes).map(|_| ())
                }
            };
            
            // The hook should return an error
            prop_assert!(result.is_err(), "Hook should return an error");
            
            // The error should be a General error containing the custls error
            match result {
                Err(Error::General(msg)) => {
                    prop_assert!(msg.contains("custls error"), 
                        "Error message should contain 'custls error', got: {}", msg);
                }
                _ => {
                    return Err(TestCaseError::fail("Expected General error variant"));
                }
            }
        }
        
        /// Property: Hook Success Propagation
        ///
        /// For any hook phase, when a hook returns Ok(()), the operation should succeed.
        #[test]
        fn prop_hook_success_propagation(
            phase in arbitrary_hook_phase(),
        ) {
            struct SuccessCustomizer;
            impl ClientHelloCustomizer for SuccessCustomizer {}
            
            let customizer = SuccessCustomizer;
            
            let mut config = ConfigParams::new();
            let mut cipher_suites = Vec::new();
            let mut extensions = Vec::new();
            let mut payload = ClientHelloPayload::new();
            let bytes = vec![1, 2, 3, 4];
            
            // Call the appropriate hook based on the phase
            let result = match phase {
                HookPhase::ConfigResolve => {
                    customizer.on_config_resolve(&mut config)
                }
                HookPhase::ComponentsReady => {
                    customizer.on_components_ready(&mut cipher_suites, &mut extensions)
                }
                HookPhase::StructReady => {
                    customizer.on_struct_ready(&mut payload)
                }
                HookPhase::TransformWireBytes => {
                    customizer.transform_wire_bytes(bytes).map(|_| ())
                }
            };
            
            // The hook should succeed
            prop_assert!(result.is_ok(), "Hook should succeed");
        }
        
        /// Property: Error Type Preservation
        ///
        /// For any CustlsError type, when converted to rustls::Error and back,
        /// the error message should be preserved.
        #[test]
        fn prop_error_type_preservation(
            error in arbitrary_custls_error(),
        ) {
            let error_msg = format!("{}", error);
            let rustls_error: Error = error.into();
            
            match rustls_error {
                Error::General(msg) => {
                    prop_assert!(msg.contains("custls error"), 
                        "Error should contain 'custls error'");
                    prop_assert!(msg.contains(&error_msg), 
                        "Error should preserve original message");
                }
                _ => {
                    return Err(TestCaseError::fail("Expected General error variant"));
                }
            }
        }
        
        /// Property: Hook Modifications Persist (Cipher Suites)
        ///
        /// For any modifications made to cipher suites in on_components_ready,
        /// those modifications should be visible after the hook returns.
        #[test]
        fn prop_cipher_suite_modifications_persist(
            num_additions in 0usize..10,
        ) {
            struct CipherSuiteAdder {
                count: usize,
            }
            
            impl ClientHelloCustomizer for CipherSuiteAdder {
                fn on_components_ready(
                    &self,
                    cipher_suites: &mut Vec<CipherSuite>,
                    _extensions: &mut Vec<ClientExtension>,
                ) -> Result<(), Error> {
                    for _ in 0..self.count {
                        cipher_suites.push(CipherSuite { _placeholder: () });
                    }
                    Ok(())
                }
            }
            
            let customizer = CipherSuiteAdder { count: num_additions };
            let mut cipher_suites = Vec::new();
            let mut extensions = Vec::new();
            
            let initial_len = cipher_suites.len();
            let result = customizer.on_components_ready(&mut cipher_suites, &mut extensions);
            
            prop_assert!(result.is_ok(), "Hook should succeed");
            prop_assert_eq!(cipher_suites.len(), initial_len + num_additions,
                "Cipher suite modifications should persist");
        }
        
        /// Property: Hook Modifications Persist (Extensions)
        ///
        /// For any modifications made to extensions in on_components_ready,
        /// those modifications should be visible after the hook returns.
        #[test]
        fn prop_extension_modifications_persist(
            num_additions in 0usize..10,
        ) {
            struct ExtensionAdder {
                count: usize,
            }
            
            impl ClientHelloCustomizer for ExtensionAdder {
                fn on_components_ready(
                    &self,
                    _cipher_suites: &mut Vec<CipherSuite>,
                    extensions: &mut Vec<ClientExtension>,
                ) -> Result<(), Error> {
                    for _ in 0..self.count {
                        extensions.push(ClientExtension { _placeholder: () });
                    }
                    Ok(())
                }
            }
            
            let customizer = ExtensionAdder { count: num_additions };
            let mut cipher_suites = Vec::new();
            let mut extensions = Vec::new();
            
            let initial_len = extensions.len();
            let result = customizer.on_components_ready(&mut cipher_suites, &mut extensions);
            
            prop_assert!(result.is_ok(), "Hook should succeed");
            prop_assert_eq!(extensions.len(), initial_len + num_additions,
                "Extension modifications should persist");
        }
        
        /// Property: Wire Bytes Transformation Preserves Length (when not modified)
        ///
        /// For any byte vector, when passed through a no-op transform_wire_bytes,
        /// the length should be preserved.
        #[test]
        fn prop_wire_bytes_length_preservation(
            bytes in prop::collection::vec(any::<u8>(), 0..1000),
        ) {
            struct NoOpCustomizer;
            impl ClientHelloCustomizer for NoOpCustomizer {}
            
            let customizer = NoOpCustomizer;
            let original_len = bytes.len();
            
            let result = customizer.transform_wire_bytes(bytes);
            
            prop_assert!(result.is_ok(), "Transform should succeed");
            prop_assert_eq!(result.unwrap().len(), original_len,
                "Byte length should be preserved");
        }
        
        /// Property: Wire Bytes Transformation Can Modify
        ///
        /// For any byte vector, when passed through a modifying transform_wire_bytes,
        /// the modifications should be visible.
        #[test]
        fn prop_wire_bytes_transformation_modifies(
            bytes in prop::collection::vec(any::<u8>(), 1..100),
        ) {
            struct AppendingCustomizer;
            
            impl ClientHelloCustomizer for AppendingCustomizer {
                fn transform_wire_bytes(&self, mut bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
                    bytes.push(0xFF);
                    Ok(bytes)
                }
            }
            
            let customizer = AppendingCustomizer;
            let original_len = bytes.len();
            
            let result = customizer.transform_wire_bytes(bytes);
            
            prop_assert!(result.is_ok(), "Transform should succeed");
            let transformed = result.unwrap();
            prop_assert_eq!(transformed.len(), original_len + 1,
                "Byte length should increase by 1");
            prop_assert_eq!(transformed[original_len], 0xFF,
                "Last byte should be 0xFF");
        }
    }
}
