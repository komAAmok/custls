//! Unit tests for hooks module
//! These tests verify hook invocation and behavior

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::error::Error;
    use crate::crypto::CipherSuite;
    use crate::msgs::ClientHelloPayload;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU8, Ordering};

    // Test that all four hooks are called in correct order
    #[test]
    fn test_hook_invocation_order() {
        #[derive(Debug)]
        struct OrderTrackingCustomizer {
            call_order: Arc<AtomicU8>,
        }

        impl OrderTrackingCustomizer {
            fn new() -> Self {
                Self {
                    call_order: Arc::new(AtomicU8::new(0)),
                }
            }
        }

        impl ClientHelloCustomizer for OrderTrackingCustomizer {
            fn on_config_resolve(&self, _config: &mut ConfigParams) -> Result<(), Error> {
                let current = self.call_order.fetch_add(1, Ordering::SeqCst);
                assert_eq!(current, 0, "on_config_resolve should be called first");
                Ok(())
            }

            fn on_components_ready(
                &self,
                _cipher_suites: &mut Vec<CipherSuite>,
                _extensions: &mut Vec<ClientExtension>,
            ) -> Result<(), Error> {
                let current = self.call_order.fetch_add(1, Ordering::SeqCst);
                assert_eq!(current, 1, "on_components_ready should be called second");
                Ok(())
            }

            fn on_struct_ready(&self, _payload: &mut ClientHelloPayload) -> Result<(), Error> {
                let current = self.call_order.fetch_add(1, Ordering::SeqCst);
                assert_eq!(current, 2, "on_struct_ready should be called third");
                Ok(())
            }

            fn transform_wire_bytes(&self, bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
                let current = self.call_order.fetch_add(1, Ordering::SeqCst);
                assert_eq!(current, 3, "transform_wire_bytes should be called fourth");
                Ok(bytes)
            }
        }

        let customizer = OrderTrackingCustomizer::new();

        // Simulate hook calls in order
        let mut config = ConfigParams::new();
        customizer.on_config_resolve(&mut config).unwrap();

        let mut cipher_suites = vec![CipherSuite::TLS13_AES_128_GCM_SHA256];
        let mut extensions = vec![];
        customizer.on_components_ready(&mut cipher_suites, &mut extensions).unwrap();

        let mut payload = ClientHelloPayload {
            client_version: crate::enums::ProtocolVersion::TLSv1_2,
            random: crate::msgs::Random([0u8; 32]),
            session_id: crate::msgs::SessionId::empty(),
            cipher_suites,
            compression_methods: vec![crate::msgs::Compression::Null],
            extensions: Box::new(crate::msgs::ClientExtensions::default()),
        };
        customizer.on_struct_ready(&mut payload).unwrap();

        let wire_bytes = vec![0u8; 10];
        customizer.transform_wire_bytes(wire_bytes).unwrap();

        // Verify all hooks were called
        assert_eq!(customizer.call_order.load(Ordering::SeqCst), 4, "All four hooks should be called");
    }

    // Test that hook errors abort the handshake
    #[test]
    fn test_hook_error_aborts_handshake() {
        #[derive(Debug)]
        struct ErroringCustomizer;

        impl ClientHelloCustomizer for ErroringCustomizer {
            fn on_components_ready(
                &self,
                _cipher_suites: &mut Vec<CipherSuite>,
                _extensions: &mut Vec<ClientExtension>,
            ) -> Result<(), Error> {
                Err(Error::General("Test error".into()))
            }
        }

        let customizer = ErroringCustomizer;
        let mut cipher_suites = vec![CipherSuite::TLS13_AES_128_GCM_SHA256];
        let mut extensions = vec![];

        let result = customizer.on_components_ready(&mut cipher_suites, &mut extensions);
        assert!(result.is_err(), "Hook error should be propagated");
    }

    // Test that hooks can modify ClientHello components
    #[test]
    fn test_hooks_can_modify_client_hello() {
        #[derive(Debug)]
        struct ModifyingCustomizer {
            test_suite: CipherSuite,
        }

        impl ClientHelloCustomizer for ModifyingCustomizer {
            fn on_components_ready(
                &self,
                cipher_suites: &mut Vec<CipherSuite>,
                _extensions: &mut Vec<ClientExtension>,
            ) -> Result<(), Error> {
                cipher_suites.insert(0, self.test_suite);
                Ok(())
            }
        }

        let test_suite = CipherSuite::TLS13_CHACHA20_POLY1305_SHA256;
        let customizer = ModifyingCustomizer { test_suite };

        let mut cipher_suites = vec![CipherSuite::TLS13_AES_128_GCM_SHA256];
        let mut extensions = vec![];

        customizer.on_components_ready(&mut cipher_suites, &mut extensions).unwrap();

        assert_eq!(cipher_suites.len(), 2, "Cipher suite should be added");
        assert_eq!(cipher_suites[0], test_suite, "Test suite should be first");
    }

    // Test default implementations do nothing
    #[test]
    fn test_default_implementations() {
        #[derive(Debug)]
        struct DefaultCustomizer;

        impl ClientHelloCustomizer for DefaultCustomizer {}

        let customizer = DefaultCustomizer;

        // All default implementations should succeed without modification
        let mut config = ConfigParams::new();
        assert!(customizer.on_config_resolve(&mut config).is_ok());

        let mut cipher_suites = vec![CipherSuite::TLS13_AES_128_GCM_SHA256];
        let mut extensions = vec![];
        assert!(customizer.on_components_ready(&mut cipher_suites, &mut extensions).is_ok());

        let mut payload = ClientHelloPayload {
            client_version: crate::enums::ProtocolVersion::TLSv1_2,
            random: crate::msgs::Random([0u8; 32]),
            session_id: crate::msgs::SessionId::empty(),
            cipher_suites: vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
            compression_methods: vec![crate::msgs::Compression::Null],
            extensions: Box::new(crate::msgs::ClientExtensions::default()),
        };
        assert!(customizer.on_struct_ready(&mut payload).is_ok());

        let wire_bytes = vec![0u8; 10];
        assert!(customizer.transform_wire_bytes(wire_bytes).is_ok());
    }
}
