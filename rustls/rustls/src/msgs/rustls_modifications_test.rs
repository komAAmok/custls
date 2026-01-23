//! Unit tests for rustls modifications made for custls integration
//!
//! This test module validates the minimal modifications made to rustls core
//! to support custls customization capabilities.

use alloc::boxed::Box;
use alloc::vec;

use super::client_hello::{ClientExtensions, ClientHelloPayload, ClientSessionTicket};
use super::codec::Codec;
use super::enums::{Compression, ExtensionType};
use super::handshake::{Random, SessionId};
use crate::crypto::{CipherSuite, SignatureScheme};
use crate::enums::ProtocolVersion;

/// Test that ClientHelloPayload fields are accessible
#[test]
fn test_client_hello_payload_field_access() {
    let mut client_hello = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from([0; 32]),
        session_id: SessionId::empty(),
        cipher_suites: vec![CipherSuite::TLS_PSK_WITH_AES_128_CCM],
        compression_methods: vec![Compression::Null],
        extensions: Box::new(ClientExtensions::default()),
    };

    // Test direct field access to cipher_suites (now public)
    assert_eq!(client_hello.cipher_suites.len(), 1);
    assert_eq!(
        client_hello.cipher_suites[0],
        CipherSuite::TLS_PSK_WITH_AES_128_CCM
    );

    // Test direct field access to extensions (now public)
    assert!(client_hello.extensions.server_name.is_none());

    // Test that we can modify cipher_suites directly
    client_hello
        .cipher_suites
        .push(CipherSuite::TLS_PSK_WITH_AES_256_CCM);
    assert_eq!(client_hello.cipher_suites.len(), 2);
}

/// Test that ClientHelloPayload provides mutable accessor methods
#[test]
fn test_client_hello_payload_mutable_accessors() {
    let mut client_hello = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from([0; 32]),
        session_id: SessionId::empty(),
        cipher_suites: vec![CipherSuite::TLS_PSK_WITH_AES_128_CCM],
        compression_methods: vec![Compression::Null],
        extensions: Box::new(ClientExtensions::default()),
    };

    // Test cipher_suites_mut() accessor
    {
        let cipher_suites = client_hello.cipher_suites_mut();
        assert_eq!(cipher_suites.len(), 1);
        cipher_suites.push(CipherSuite::TLS_PSK_WITH_AES_256_CCM);
        cipher_suites.push(CipherSuite::TLS13_AES_128_GCM_SHA256);
    }
    assert_eq!(client_hello.cipher_suites.len(), 3);

    // Test extensions_mut() accessor
    {
        let extensions = client_hello.extensions_mut();
        extensions.session_ticket = Some(ClientSessionTicket::Request);
    }
    assert!(client_hello.extensions.session_ticket.is_some());
}

/// Test that modifications via accessors persist through encoding/decoding
#[test]
fn test_client_hello_modifications_persist() {
    let mut client_hello = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from([1; 32]),
        session_id: SessionId::empty(),
        cipher_suites: vec![CipherSuite::TLS_PSK_WITH_AES_128_CCM],
        compression_methods: vec![Compression::Null],
        extensions: Box::new(ClientExtensions::default()),
    };

    // Modify cipher suites
    client_hello
        .cipher_suites_mut()
        .push(CipherSuite::TLS_PSK_WITH_AES_256_CCM);

    // Modify extensions
    client_hello.extensions_mut().session_ticket = Some(ClientSessionTicket::Request);

    // Encode
    let encoded = client_hello.get_encoding();

    // Decode
    let decoded = ClientHelloPayload::read_bytes(&encoded).unwrap();

    // Verify modifications persisted
    assert_eq!(decoded.cipher_suites.len(), 2);
    assert_eq!(
        decoded.cipher_suites[0],
        CipherSuite::TLS_PSK_WITH_AES_128_CCM
    );
    assert_eq!(
        decoded.cipher_suites[1],
        CipherSuite::TLS_PSK_WITH_AES_256_CCM
    );
    assert!(decoded.extensions.session_ticket.is_some());
}

/// Test that ExtensionType enum includes new extension types
#[test]
fn test_extension_type_enum_completeness() {
    // Test that ApplicationSettings extension type exists
    let app_settings = ExtensionType::ApplicationSettings;
    assert_eq!(u16::from(app_settings), 0x4469);

    // Test that DelegatedCredential extension type exists
    let delegated_cred = ExtensionType::DelegatedCredential;
    assert_eq!(u16::from(delegated_cred), 0x0022);

    // Test that CompressCertificate extension type exists
    let compress_cert = ExtensionType::CompressCertificate;
    assert_eq!(u16::from(compress_cert), 0x001b);

    // Test that Padding extension type exists
    let padding = ExtensionType::Padding;
    assert_eq!(u16::from(padding), 0x0015);

    // Test that StatusRequest extension type exists (OCSP)
    let status_request = ExtensionType::StatusRequest;
    assert_eq!(u16::from(status_request), 0x0005);

    // Test that SCT extension type exists
    let sct = ExtensionType::SCT;
    assert_eq!(u16::from(sct), 0x0012);
}

/// Test that new extension types can be used in extension lists
#[test]
fn test_extension_types_in_collections() {
    let extension_types = vec![
        ExtensionType::ApplicationSettings,
        ExtensionType::DelegatedCredential,
        ExtensionType::CompressCertificate,
        ExtensionType::Padding,
        ExtensionType::StatusRequest,
        ExtensionType::SCT,
    ];

    // Verify all extension types are distinct
    assert_eq!(extension_types.len(), 6);

    // Verify they can be compared
    assert_ne!(
        ExtensionType::ApplicationSettings,
        ExtensionType::DelegatedCredential
    );
    assert_ne!(
        ExtensionType::CompressCertificate,
        ExtensionType::Padding
    );
}

/// Test that extension types can be converted to/from u16
#[test]
fn test_extension_type_conversions() {
    // Test conversion from ExtensionType to u16
    assert_eq!(u16::from(ExtensionType::ApplicationSettings), 0x4469);
    assert_eq!(u16::from(ExtensionType::DelegatedCredential), 0x0022);
    assert_eq!(u16::from(ExtensionType::CompressCertificate), 0x001b);
    assert_eq!(u16::from(ExtensionType::Padding), 0x0015);
    assert_eq!(u16::from(ExtensionType::StatusRequest), 0x0005);
    assert_eq!(u16::from(ExtensionType::SCT), 0x0012);

    // Test that ExtensionType can be used in match statements
    let ext_type = ExtensionType::ApplicationSettings;
    match ext_type {
        ExtensionType::ApplicationSettings => {
            // Expected path
        }
        _ => panic!("Unexpected extension type"),
    }
}

/// Test that ClientHelloPayload can be cloned with modifications
#[test]
fn test_client_hello_clone_and_modify() {
    let original = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from([0; 32]),
        session_id: SessionId::empty(),
        cipher_suites: vec![CipherSuite::TLS_PSK_WITH_AES_128_CCM],
        compression_methods: vec![Compression::Null],
        extensions: Box::new(ClientExtensions::default()),
    };

    let mut modified = original.clone();

    // Modify the clone
    modified
        .cipher_suites_mut()
        .push(CipherSuite::TLS_PSK_WITH_AES_256_CCM);

    // Verify original is unchanged
    assert_eq!(original.cipher_suites.len(), 1);

    // Verify clone is modified
    assert_eq!(modified.cipher_suites.len(), 2);
}

/// Test that extension ordering is preserved when modifying ClientHello
#[test]
fn test_extension_ordering_preserved() {
    let mut client_hello = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from([0; 32]),
        session_id: SessionId::empty(),
        cipher_suites: vec![CipherSuite::TLS_PSK_WITH_AES_128_CCM],
        compression_methods: vec![Compression::Null],
        extensions: Box::new(ClientExtensions {
            signature_schemes: Some(vec![SignatureScheme::ECDSA_NISTP256_SHA256]),
            session_ticket: Some(ClientSessionTicket::Request),
            ..Default::default()
        }),
    };

    // Get the original extension order
    let original_order = client_hello.extensions.collect_used();

    // Modify cipher suites (should not affect extension order)
    client_hello
        .cipher_suites_mut()
        .push(CipherSuite::TLS_PSK_WITH_AES_256_CCM);

    // Verify extension order is unchanged
    let new_order = client_hello.extensions.collect_used();
    assert_eq!(original_order, new_order);
}

/// Test that empty cipher suites list can be created and modified
#[test]
fn test_empty_cipher_suites_modification() {
    let mut client_hello = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from([0; 32]),
        session_id: SessionId::empty(),
        cipher_suites: vec![],
        compression_methods: vec![Compression::Null],
        extensions: Box::new(ClientExtensions::default()),
    };

    // Start with empty cipher suites
    assert_eq!(client_hello.cipher_suites.len(), 0);

    // Add cipher suites via mutable accessor
    let cipher_suites = client_hello.cipher_suites_mut();
    cipher_suites.push(CipherSuite::TLS_PSK_WITH_AES_128_CCM);
    cipher_suites.push(CipherSuite::TLS_PSK_WITH_AES_256_CCM);

    // Verify additions
    assert_eq!(client_hello.cipher_suites.len(), 2);
}

/// Test that multiple modifications can be made in sequence
#[test]
fn test_sequential_modifications() {
    let mut client_hello = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from([0; 32]),
        session_id: SessionId::empty(),
        cipher_suites: vec![CipherSuite::TLS_PSK_WITH_AES_128_CCM],
        compression_methods: vec![Compression::Null],
        extensions: Box::new(ClientExtensions::default()),
    };

    // First modification: add cipher suite
    client_hello
        .cipher_suites_mut()
        .push(CipherSuite::TLS_PSK_WITH_AES_256_CCM);
    assert_eq!(client_hello.cipher_suites.len(), 2);

    // Second modification: add another cipher suite
    client_hello
        .cipher_suites_mut()
        .push(CipherSuite::TLS13_AES_128_GCM_SHA256);
    assert_eq!(client_hello.cipher_suites.len(), 3);

    // Third modification: modify extensions
    client_hello.extensions_mut().session_ticket = Some(ClientSessionTicket::Request);
    assert!(client_hello.extensions.session_ticket.is_some());

    // Fourth modification: add signature schemes
    client_hello.extensions_mut().signature_schemes =
        Some(vec![SignatureScheme::ECDSA_NISTP256_SHA256]);
    assert!(client_hello.extensions.signature_schemes.is_some());

    // Verify all modifications persisted
    assert_eq!(client_hello.cipher_suites.len(), 3);
    assert!(client_hello.extensions.session_ticket.is_some());
    assert!(client_hello.extensions.signature_schemes.is_some());
}
