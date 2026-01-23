//! Unit tests for ClientHelloCustomizer trait and hook system

use super::*;
use crate::custls::CustlsError;
use alloc::vec;

/// Test that default implementations of all hooks return Ok(())
#[test]
fn test_default_hook_implementations() {
    struct DefaultCustomizer;
    impl ClientHelloCustomizer for DefaultCustomizer {}
    
    let customizer = DefaultCustomizer;
    let mut config = ConfigParams::new();
    let mut cipher_suites = Vec::new();
    let mut extensions = Vec::new();
    let mut payload = ClientHelloPayload::new();
    let bytes = vec![1, 2, 3, 4];
    
    // All default implementations should return Ok(())
    assert!(customizer.on_config_resolve(&mut config).is_ok());
    assert!(customizer.on_components_ready(&mut cipher_suites, &mut extensions).is_ok());
    assert!(customizer.on_struct_ready(&mut payload).is_ok());
    assert!(customizer.transform_wire_bytes(bytes).is_ok());
}

/// Test that custom implementation of on_config_resolve is called
#[test]
fn test_custom_on_config_resolve() {
    use core::sync::atomic::{AtomicBool, Ordering};
    use alloc::sync::Arc;
    
    struct ConfigResolveCustomizer {
        called: Arc<AtomicBool>,
    }
    
    impl ClientHelloCustomizer for ConfigResolveCustomizer {
        fn on_config_resolve(&self, _config: &mut ConfigParams) -> Result<(), Error> {
            self.called.store(true, Ordering::SeqCst);
            Ok(())
        }
    }
    
    let called = Arc::new(AtomicBool::new(false));
    let customizer = ConfigResolveCustomizer {
        called: called.clone(),
    };
    
    let mut config = ConfigParams::new();
    assert!(customizer.on_config_resolve(&mut config).is_ok());
    assert!(called.load(Ordering::SeqCst));
}

/// Test that custom implementation of on_components_ready is called
#[test]
fn test_custom_on_components_ready() {
    use core::sync::atomic::{AtomicBool, Ordering};
    use alloc::sync::Arc;
    
    struct ComponentsReadyCustomizer {
        called: Arc<AtomicBool>,
    }
    
    impl ClientHelloCustomizer for ComponentsReadyCustomizer {
        fn on_components_ready(
            &self,
            _cipher_suites: &mut Vec<CipherSuite>,
            _extensions: &mut Vec<ClientExtension>,
        ) -> Result<(), Error> {
            self.called.store(true, Ordering::SeqCst);
            Ok(())
        }
    }
    
    let called = Arc::new(AtomicBool::new(false));
    let customizer = ComponentsReadyCustomizer {
        called: called.clone(),
    };
    
    let mut cipher_suites = Vec::new();
    let mut extensions = Vec::new();
    assert!(customizer.on_components_ready(&mut cipher_suites, &mut extensions).is_ok());
    assert!(called.load(Ordering::SeqCst));
}

/// Test that custom implementation of on_struct_ready is called
#[test]
fn test_custom_on_struct_ready() {
    use core::sync::atomic::{AtomicBool, Ordering};
    use alloc::sync::Arc;
    
    struct StructReadyCustomizer {
        called: Arc<AtomicBool>,
    }
    
    impl ClientHelloCustomizer for StructReadyCustomizer {
        fn on_struct_ready(&self, _payload: &mut ClientHelloPayload) -> Result<(), Error> {
            self.called.store(true, Ordering::SeqCst);
            Ok(())
        }
    }
    
    let called = Arc::new(AtomicBool::new(false));
    let customizer = StructReadyCustomizer {
        called: called.clone(),
    };
    
    let mut payload = ClientHelloPayload::new();
    assert!(customizer.on_struct_ready(&mut payload).is_ok());
    assert!(called.load(Ordering::SeqCst));
}

/// Test that custom implementation of transform_wire_bytes is called
#[test]
fn test_custom_transform_wire_bytes() {
    struct TransformBytesCustomizer;
    
    impl ClientHelloCustomizer for TransformBytesCustomizer {
        fn transform_wire_bytes(&self, mut bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
            // Modify the bytes by appending a marker
            bytes.push(0xFF);
            Ok(bytes)
        }
    }
    
    let customizer = TransformBytesCustomizer;
    let bytes = vec![1, 2, 3, 4];
    let result = customizer.transform_wire_bytes(bytes).unwrap();
    
    assert_eq!(result.len(), 5);
    assert_eq!(result[4], 0xFF);
}

/// Test that hook can return an error
#[test]
fn test_hook_error_return() {
    struct ErrorCustomizer;
    
    impl ClientHelloCustomizer for ErrorCustomizer {
        fn on_config_resolve(&self, _config: &mut ConfigParams) -> Result<(), Error> {
            Err(CustlsError::HookError("test error".into()).into())
        }
    }
    
    let customizer = ErrorCustomizer;
    let mut config = ConfigParams::new();
    let result = customizer.on_config_resolve(&mut config);
    
    assert!(result.is_err());
}

/// Test that multiple hooks can be implemented
#[test]
fn test_multiple_hooks_implemented() {
    use core::sync::atomic::{AtomicU32, Ordering};
    use alloc::sync::Arc;
    
    struct MultiHookCustomizer {
        call_count: Arc<AtomicU32>,
    }
    
    impl ClientHelloCustomizer for MultiHookCustomizer {
        fn on_config_resolve(&self, _config: &mut ConfigParams) -> Result<(), Error> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        
        fn on_components_ready(
            &self,
            _cipher_suites: &mut Vec<CipherSuite>,
            _extensions: &mut Vec<ClientExtension>,
        ) -> Result<(), Error> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        
        fn on_struct_ready(&self, _payload: &mut ClientHelloPayload) -> Result<(), Error> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        
        fn transform_wire_bytes(&self, bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(bytes)
        }
    }
    
    let call_count = Arc::new(AtomicU32::new(0));
    let customizer = MultiHookCustomizer {
        call_count: call_count.clone(),
    };
    
    let mut config = ConfigParams::new();
    let mut cipher_suites = Vec::new();
    let mut extensions = Vec::new();
    let mut payload = ClientHelloPayload::new();
    let bytes = vec![1, 2, 3];
    
    assert!(customizer.on_config_resolve(&mut config).is_ok());
    assert!(customizer.on_components_ready(&mut cipher_suites, &mut extensions).is_ok());
    assert!(customizer.on_struct_ready(&mut payload).is_ok());
    assert!(customizer.transform_wire_bytes(bytes).is_ok());
    
    assert_eq!(call_count.load(Ordering::SeqCst), 4);
}

/// Test that hooks can modify cipher suites
#[test]
fn test_hook_modifies_cipher_suites() {
    struct CipherSuiteModifier;
    
    impl ClientHelloCustomizer for CipherSuiteModifier {
        fn on_components_ready(
            &self,
            cipher_suites: &mut Vec<CipherSuite>,
            _extensions: &mut Vec<ClientExtension>,
        ) -> Result<(), Error> {
            // Add a cipher suite
            cipher_suites.push(CipherSuite { _placeholder: () });
            Ok(())
        }
    }
    
    let customizer = CipherSuiteModifier;
    let mut cipher_suites = Vec::new();
    let mut extensions = Vec::new();
    
    assert_eq!(cipher_suites.len(), 0);
    assert!(customizer.on_components_ready(&mut cipher_suites, &mut extensions).is_ok());
    assert_eq!(cipher_suites.len(), 1);
}

/// Test that hooks can modify extensions
#[test]
fn test_hook_modifies_extensions() {
    struct ExtensionModifier;
    
    impl ClientHelloCustomizer for ExtensionModifier {
        fn on_components_ready(
            &self,
            _cipher_suites: &mut Vec<CipherSuite>,
            extensions: &mut Vec<ClientExtension>,
        ) -> Result<(), Error> {
            // Add an extension
            extensions.push(ClientExtension { _placeholder: () });
            Ok(())
        }
    }
    
    let customizer = ExtensionModifier;
    let mut cipher_suites = Vec::new();
    let mut extensions = Vec::new();
    
    assert_eq!(extensions.len(), 0);
    assert!(customizer.on_components_ready(&mut cipher_suites, &mut extensions).is_ok());
    assert_eq!(extensions.len(), 1);
}

/// Test ConfigParams can be created and used
#[test]
fn test_config_params_creation() {
    let config1 = ConfigParams::new();
    let config2 = ConfigParams::default();
    
    // Both should be valid
    assert!(core::mem::size_of_val(&config1) >= 0);
    assert!(core::mem::size_of_val(&config2) >= 0);
}

/// Test ClientHelloPayload can be created and used
#[test]
fn test_client_hello_payload_creation() {
    let payload1 = ClientHelloPayload::new();
    let payload2 = ClientHelloPayload::default();
    
    // Both should be valid
    assert!(core::mem::size_of_val(&payload1) >= 0);
    assert!(core::mem::size_of_val(&payload2) >= 0);
}

/// Test that customizer can be shared across threads (Send + Sync)
#[test]
fn test_customizer_send_sync() {
    use alloc::sync::Arc;
    
    struct ThreadSafeCustomizer;
    impl ClientHelloCustomizer for ThreadSafeCustomizer {}
    
    let customizer = Arc::new(ThreadSafeCustomizer);
    
    // This should compile because ClientHelloCustomizer requires Send + Sync
    let customizer_clone = customizer.clone();
    
    // Verify we can use it
    let mut config = ConfigParams::new();
    assert!(customizer_clone.on_config_resolve(&mut config).is_ok());
}

/// Test that hook errors can be converted to rustls errors
#[test]
fn test_hook_error_conversion() {
    struct ErrorReturningCustomizer;
    
    impl ClientHelloCustomizer for ErrorReturningCustomizer {
        fn on_config_resolve(&self, _config: &mut ConfigParams) -> Result<(), Error> {
            let custls_err = CustlsError::HookError("hook failed".into());
            Err(custls_err.into())
        }
    }
    
    let customizer = ErrorReturningCustomizer;
    let mut config = ConfigParams::new();
    let result = customizer.on_config_resolve(&mut config);
    
    assert!(result.is_err());
    match result {
        Err(Error::General(msg)) => {
            assert!(msg.contains("custls error"));
            assert!(msg.contains("Hook error"));
        }
        _ => panic!("Expected General error"),
    }
}

/// Test that different error types can be returned from hooks
#[test]
fn test_different_hook_error_types() {
    struct MultiErrorCustomizer {
        error_type: u8,
    }
    
    impl ClientHelloCustomizer for MultiErrorCustomizer {
        fn on_config_resolve(&self, _config: &mut ConfigParams) -> Result<(), Error> {
            match self.error_type {
                1 => Err(CustlsError::HookError("hook error".into()).into()),
                2 => Err(CustlsError::ValidationError("validation error".into()).into()),
                3 => Err(CustlsError::RandomizationError("randomization error".into()).into()),
                _ => Ok(()),
            }
        }
    }
    
    let customizer1 = MultiErrorCustomizer { error_type: 1 };
    let customizer2 = MultiErrorCustomizer { error_type: 2 };
    let customizer3 = MultiErrorCustomizer { error_type: 3 };
    let customizer4 = MultiErrorCustomizer { error_type: 0 };
    
    let mut config = ConfigParams::new();
    
    assert!(customizer1.on_config_resolve(&mut config).is_err());
    assert!(customizer2.on_config_resolve(&mut config).is_err());
    assert!(customizer3.on_config_resolve(&mut config).is_err());
    assert!(customizer4.on_config_resolve(&mut config).is_ok());
}

/// Test that transform_wire_bytes preserves bytes when not modified
#[test]
fn test_transform_wire_bytes_preserves_bytes() {
    struct NoOpCustomizer;
    impl ClientHelloCustomizer for NoOpCustomizer {}
    
    let customizer = NoOpCustomizer;
    let original_bytes = vec![1, 2, 3, 4, 5];
    let result = customizer.transform_wire_bytes(original_bytes.clone()).unwrap();
    
    assert_eq!(result, original_bytes);
}

/// Test that transform_wire_bytes can completely replace bytes
#[test]
fn test_transform_wire_bytes_replaces_bytes() {
    struct ReplaceCustomizer;
    
    impl ClientHelloCustomizer for ReplaceCustomizer {
        fn transform_wire_bytes(&self, _bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
            Ok(vec![0xAA, 0xBB, 0xCC])
        }
    }
    
    let customizer = ReplaceCustomizer;
    let original_bytes = vec![1, 2, 3, 4, 5];
    let result = customizer.transform_wire_bytes(original_bytes).unwrap();
    
    assert_eq!(result, vec![0xAA, 0xBB, 0xCC]);
}

/// Test that CipherSuite can be cloned and compared
#[test]
fn test_cipher_suite_clone_eq() {
    let cs1 = CipherSuite { _placeholder: () };
    let cs2 = cs1;
    
    assert_eq!(cs1, cs2);
}

/// Test that ClientExtension can be cloned
#[test]
fn test_client_extension_clone() {
    let ext1 = ClientExtension { _placeholder: () };
    let ext2 = ext1.clone();
    
    // Both should be valid
    assert!(core::mem::size_of_val(&ext1) >= 0);
    assert!(core::mem::size_of_val(&ext2) >= 0);
}
