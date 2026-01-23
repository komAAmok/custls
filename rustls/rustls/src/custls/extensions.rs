//! Missing TLS extension implementations for custls
//!
//! This module provides implementations for TLS extensions that are commonly
//! used by modern browsers but are not fully supported in rustls. These
//! implementations focus on correct wire format encoding/decoding to enable
//! browser fingerprint simulation.
//!
//! Some extensions are "stub" implementations when aws-lc-rs lacks cryptographic
//! support - they encode and send correctly but may not provide full functionality.

use alloc::vec::Vec;
use core::fmt;

use crate::error::InvalidMessage;
use crate::internal::msgs::{Codec, Reader};
use crate::enums::CertificateCompressionAlgorithm;
use crate::crypto::SignatureScheme;

/// Application Settings Extension (0x001b)
///
/// This extension is used to negotiate application-layer settings,
/// particularly for HTTP/2 and HTTP/3. It's critical for matching
/// modern browser fingerprints.
///
/// Reference: draft-ietf-tls-application-settings
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationSettingsExtension {
    /// List of supported ALPN protocols with their settings
    pub protocols: Vec<Vec<u8>>,
}

impl ApplicationSettingsExtension {
    /// Create a new ApplicationSettingsExtension
    pub fn new(protocols: Vec<Vec<u8>>) -> Self {
        Self { protocols }
    }
    
    /// Create an empty ApplicationSettingsExtension
    pub fn empty() -> Self {
        Self {
            protocols: Vec::new(),
        }
    }
}

impl<'a> Codec<'a> for ApplicationSettingsExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // Encode as a length-prefixed list of protocols
        // Each protocol is length-prefixed
        let mut inner = Vec::new();
        for protocol in &self.protocols {
            // Protocol length (u8)
            inner.push(protocol.len() as u8);
            inner.extend_from_slice(protocol);
        }
        
        // Total length (u16)
        let len = inner.len() as u16;
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(&inner);
    }
    
    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        // Read total length
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;
        
        let mut protocols = Vec::new();
        while sub.any_left() {
            // Read protocol length
            let proto_len = u8::read(&mut sub)? as usize;
            // Read protocol bytes
            let proto_bytes = sub
                .take(proto_len)
                .ok_or(InvalidMessage::MissingData("application_settings protocol"))?;
            protocols.push(proto_bytes.to_vec());
        }
        
        Ok(Self { protocols })
    }
}

/// Delegated Credential Extension (0x0022)
///
/// This extension allows a server to delegate its credentials to another
/// entity. Used by some CDNs and modern browsers support it.
///
/// Reference: RFC 9345
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedCredentialExtension {
    /// Supported signature algorithms for delegated credentials
    pub signature_algorithms: Vec<SignatureScheme>,
}

impl DelegatedCredentialExtension {
    /// Create a new DelegatedCredentialExtension
    pub fn new(signature_algorithms: Vec<SignatureScheme>) -> Self {
        Self {
            signature_algorithms,
        }
    }
    
    /// Create an empty DelegatedCredentialExtension
    pub fn empty() -> Self {
        Self {
            signature_algorithms: Vec::new(),
        }
    }
}

impl<'a> Codec<'a> for DelegatedCredentialExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // Encode as a length-prefixed list of signature schemes
        let len = (self.signature_algorithms.len() * 2) as u16;
        bytes.extend_from_slice(&len.to_be_bytes());
        
        for scheme in &self.signature_algorithms {
            scheme.encode(bytes);
        }
    }
    
    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        // Read length
        let len = u16::read(r)? as usize;
        if len % 2 != 0 {
            return Err(InvalidMessage::TrailingData(
                "delegated_credential length must be even",
            ));
        }
        
        let mut sub = r.sub(len)?;
        let mut signature_algorithms = Vec::new();
        
        while sub.any_left() {
            signature_algorithms.push(SignatureScheme::read(&mut sub)?);
        }
        
        Ok(Self {
            signature_algorithms,
        })
    }
}

/// Compress Certificate Extension
///
/// This extension negotiates certificate compression algorithms to reduce
/// handshake size. Modern browsers commonly include this.
///
/// Reference: RFC 8879
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressCertificateExtension {
    /// Supported compression algorithms
    pub algorithms: Vec<CertificateCompressionAlgorithm>,
}

impl CompressCertificateExtension {
    /// Create a new CompressCertificateExtension
    pub fn new(algorithms: Vec<CertificateCompressionAlgorithm>) -> Self {
        Self { algorithms }
    }
    
    /// Create an empty CompressCertificateExtension
    pub fn empty() -> Self {
        Self {
            algorithms: Vec::new(),
        }
    }
}

impl<'a> Codec<'a> for CompressCertificateExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // Encode as a length-prefixed list of algorithms
        let len = (self.algorithms.len() * 2) as u8;
        bytes.push(len);
        
        for algorithm in &self.algorithms {
            algorithm.encode(bytes);
        }
    }
    
    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        // Read length
        let len = u8::read(r)? as usize;
        if len % 2 != 0 {
            return Err(InvalidMessage::TrailingData(
                "compress_certificate length must be even",
            ));
        }
        
        let mut sub = r.sub(len)?;
        let mut algorithms = Vec::new();
        
        while sub.any_left() {
            algorithms.push(CertificateCompressionAlgorithm::read(&mut sub)?);
        }
        
        Ok(Self { algorithms })
    }
}

/// Padding Extension (0x0015)
///
/// This extension adds padding to the ClientHello to reach a desired size.
/// The padding length is dynamically configurable and is a key component
/// of browser fingerprint simulation.
///
/// Reference: RFC 7685
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddingExtension {
    /// Length of padding in bytes
    pub length: u16,
}

impl PaddingExtension {
    /// Create a new PaddingExtension with specified length
    pub fn new(length: u16) -> Self {
        Self { length }
    }
    
    /// Create a PaddingExtension with zero length
    pub fn empty() -> Self {
        Self { length: 0 }
    }
}

impl<'a> Codec<'a> for PaddingExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // Padding is just zeros
        bytes.resize(bytes.len() + self.length as usize, 0);
    }
    
    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        // Read all remaining bytes as padding
        let padding_bytes = r.rest();
        Ok(Self {
            length: padding_bytes.len() as u16,
        })
    }
}

/// Status Request Extension (OCSP) (0x0005)
///
/// This extension requests OCSP stapling from the server. While rustls
/// has some OCSP support, this provides a complete implementation for
/// ClientHello generation.
///
/// Reference: RFC 6066
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusRequestExtension {
    /// Status type (1 = OCSP)
    pub status_type: u8,
    
    /// Responder ID list (empty for standard OCSP)
    pub responder_id_list: Vec<Vec<u8>>,
    
    /// Request extensions (empty for standard OCSP)
    pub request_extensions: Vec<u8>,
}

impl StatusRequestExtension {
    /// Create a new StatusRequestExtension for OCSP
    pub fn ocsp() -> Self {
        Self {
            status_type: 1, // OCSP
            responder_id_list: Vec::new(),
            request_extensions: Vec::new(),
        }
    }
    
    /// Create a custom StatusRequestExtension
    pub fn new(
        status_type: u8,
        responder_id_list: Vec<Vec<u8>>,
        request_extensions: Vec<u8>,
    ) -> Self {
        Self {
            status_type,
            responder_id_list,
            request_extensions,
        }
    }
}

impl<'a> Codec<'a> for StatusRequestExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // Status type
        bytes.push(self.status_type);
        
        // Responder ID list length (u16)
        let mut responder_data = Vec::new();
        for responder_id in &self.responder_id_list {
            // Each responder ID is length-prefixed (u16)
            let id_len = responder_id.len() as u16;
            responder_data.extend_from_slice(&id_len.to_be_bytes());
            responder_data.extend_from_slice(responder_id);
        }
        let responder_list_len = responder_data.len() as u16;
        bytes.extend_from_slice(&responder_list_len.to_be_bytes());
        bytes.extend_from_slice(&responder_data);
        
        // Request extensions length (u16)
        let ext_len = self.request_extensions.len() as u16;
        bytes.extend_from_slice(&ext_len.to_be_bytes());
        bytes.extend_from_slice(&self.request_extensions);
    }
    
    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        // Read status type
        let status_type = u8::read(r)?;
        
        // Read responder ID list
        let responder_list_len = u16::read(r)? as usize;
        let mut responder_sub = r.sub(responder_list_len)?;
        let mut responder_id_list = Vec::new();
        
        while responder_sub.any_left() {
            let id_len = u16::read(&mut responder_sub)? as usize;
            let id_bytes = responder_sub
                .take(id_len)
                .ok_or(InvalidMessage::MissingData("status_request responder_id"))?;
            responder_id_list.push(id_bytes.to_vec());
        }
        
        // Read request extensions
        let ext_len = u16::read(r)? as usize;
        let ext_bytes = r
            .take(ext_len)
            .ok_or(InvalidMessage::MissingData("status_request extensions"))?;
        let request_extensions = ext_bytes.to_vec();
        
        Ok(Self {
            status_type,
            responder_id_list,
            request_extensions,
        })
    }
}

/// Signed Certificate Timestamp Extension (0x0012)
///
/// This extension requests SCTs (Signed Certificate Timestamps) for
/// Certificate Transparency. Modern browsers include this for security.
///
/// Reference: RFC 6962
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCertificateTimestampExtension {
    // This extension has no data in ClientHello - it's just a flag
}

impl SignedCertificateTimestampExtension {
    /// Create a new SignedCertificateTimestampExtension
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for SignedCertificateTimestampExtension {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Codec<'a> for SignedCertificateTimestampExtension {
    fn encode(&self, _bytes: &mut Vec<u8>) {
        // No data to encode - extension presence is the signal
    }
    
    fn read(_r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        // No data to read
        Ok(Self {})
    }
}

impl fmt::Display for ApplicationSettingsExtension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ApplicationSettings({} protocols)",
            self.protocols.len()
        )
    }
}

impl fmt::Display for DelegatedCredentialExtension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DelegatedCredential({} algorithms)",
            self.signature_algorithms.len()
        )
    }
}

impl fmt::Display for CompressCertificateExtension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CompressCertificate({} algorithms)",
            self.algorithms.len()
        )
    }
}

impl fmt::Display for PaddingExtension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Padding({} bytes)", self.length)
    }
}

impl fmt::Display for StatusRequestExtension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StatusRequest(type={}, {} responders)",
            self.status_type,
            self.responder_id_list.len()
        )
    }
}

impl fmt::Display for SignedCertificateTimestampExtension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignedCertificateTimestamp")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    
    // ApplicationSettingsExtension tests
    
    #[test]
    fn test_application_settings_empty() {
        let ext = ApplicationSettingsExtension::empty();
        assert_eq!(ext.protocols.len(), 0);
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        // Should encode as length 0
        assert_eq!(bytes, vec![0, 0]);
        
        // Round-trip
        let mut reader = Reader::init(&bytes);
        let decoded = ApplicationSettingsExtension::read(&mut reader).unwrap();
        assert_eq!(ext, decoded);
    }
    
    #[test]
    fn test_application_settings_single_protocol() {
        let ext = ApplicationSettingsExtension::new(vec![b"h2".to_vec()]);
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        // Length (u16) + protocol length (u8) + protocol bytes
        assert_eq!(bytes.len(), 2 + 1 + 2);
        
        // Round-trip
        let mut reader = Reader::init(&bytes);
        let decoded = ApplicationSettingsExtension::read(&mut reader).unwrap();
        assert_eq!(ext, decoded);
    }
    
    #[test]
    fn test_application_settings_multiple_protocols() {
        let ext = ApplicationSettingsExtension::new(vec![
            b"h2".to_vec(),
            b"http/1.1".to_vec(),
        ]);
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        // Round-trip
        let mut reader = Reader::init(&bytes);
        let decoded = ApplicationSettingsExtension::read(&mut reader).unwrap();
        assert_eq!(ext, decoded);
    }
    
    // DelegatedCredentialExtension tests
    
    #[test]
    fn test_delegated_credential_empty() {
        let ext = DelegatedCredentialExtension::empty();
        assert_eq!(ext.signature_algorithms.len(), 0);
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        // Should encode as length 0
        assert_eq!(bytes, vec![0, 0]);
        
        // Round-trip
        let mut reader = Reader::init(&bytes);
        let decoded = DelegatedCredentialExtension::read(&mut reader).unwrap();
        assert_eq!(ext, decoded);
    }
    
    #[test]
    fn test_delegated_credential_single_algorithm() {
        let ext = DelegatedCredentialExtension::new(vec![SignatureScheme::ECDSA_NISTP256_SHA256]);
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        // Length (u16) + one signature scheme (u16)
        assert_eq!(bytes.len(), 2 + 2);
        
        // Round-trip
        let mut reader = Reader::init(&bytes);
        let decoded = DelegatedCredentialExtension::read(&mut reader).unwrap();
        assert_eq!(ext, decoded);
    }
    
    #[test]
    fn test_delegated_credential_multiple_algorithms() {
        let ext = DelegatedCredentialExtension::new(vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ED25519,
        ]);
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        // Round-trip
        let mut reader = Reader::init(&bytes);
        let decoded = DelegatedCredentialExtension::read(&mut reader).unwrap();
        assert_eq!(ext, decoded);
    }
    
    // CompressCertificateExtension tests
    
    #[test]
    fn test_compress_certificate_empty() {
        let ext = CompressCertificateExtension::empty();
        assert_eq!(ext.algorithms.len(), 0);
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        // Should encode as length 0
        assert_eq!(bytes, vec![0]);
        
        // Round-trip
        let mut reader = Reader::init(&bytes);
        let decoded = CompressCertificateExtension::read(&mut reader).unwrap();
        assert_eq!(ext, decoded);
    }
    
    #[test]
    fn test_compress_certificate_single_algorithm() {
        let ext = CompressCertificateExtension::new(vec![CertificateCompressionAlgorithm::Brotli]);
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        // Length (u8) + one algorithm (u16)
        assert_eq!(bytes.len(), 1 + 2);
        
        // Round-trip
        let mut reader = Reader::init(&bytes);
        let decoded = CompressCertificateExtension::read(&mut reader).unwrap();
        assert_eq!(ext, decoded);
    }
    
    #[test]
    fn test_compress_certificate_multiple_algorithms() {
        let ext = CompressCertificateExtension::new(vec![
            CertificateCompressionAlgorithm::Zlib,
            CertificateCompressionAlgorithm::Brotli,
            CertificateCompressionAlgorithm::Zstd,
        ]);
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        // Round-trip
        let mut reader = Reader::init(&bytes);
        let decoded = CompressCertificateExtension::read(&mut reader).unwrap();
        assert_eq!(ext, decoded);
    }
    
    // PaddingExtension tests
    
    #[test]
    fn test_padding_zero_length() {
        let ext = PaddingExtension::empty();
        assert_eq!(ext.length, 0);
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        // Should encode as empty
        assert_eq!(bytes.len(), 0);
    }
    
    #[test]
    fn test_padding_specific_length() {
        let ext = PaddingExtension::new(100);
        assert_eq!(ext.length, 100);
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        // Should encode as 100 zero bytes
        assert_eq!(bytes.len(), 100);
        assert!(bytes.iter().all(|&b| b == 0));
    }
    
    #[test]
    fn test_padding_maximum_length() {
        // Test with a large padding value (1500 bytes is common for TLS)
        let ext = PaddingExtension::new(1500);
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        assert_eq!(bytes.len(), 1500);
        assert!(bytes.iter().all(|&b| b == 0));
    }
    
    #[test]
    fn test_padding_decode() {
        let padding_data = vec![0u8; 256];
        let mut reader = Reader::init(&padding_data);
        let decoded = PaddingExtension::read(&mut reader).unwrap();
        
        assert_eq!(decoded.length, 256);
    }
    
    // StatusRequestExtension tests
    
    #[test]
    fn test_status_request_ocsp() {
        let ext = StatusRequestExtension::ocsp();
        assert_eq!(ext.status_type, 1);
        assert_eq!(ext.responder_id_list.len(), 0);
        assert_eq!(ext.request_extensions.len(), 0);
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        // Status type (1) + responder list length (0) + extensions length (0)
        assert_eq!(bytes, vec![1, 0, 0, 0, 0]);
        
        // Round-trip
        let mut reader = Reader::init(&bytes);
        let decoded = StatusRequestExtension::read(&mut reader).unwrap();
        assert_eq!(ext, decoded);
    }
    
    #[test]
    fn test_status_request_with_responders() {
        let ext = StatusRequestExtension::new(
            1,
            vec![b"responder1".to_vec(), b"responder2".to_vec()],
            vec![],
        );
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        // Round-trip
        let mut reader = Reader::init(&bytes);
        let decoded = StatusRequestExtension::read(&mut reader).unwrap();
        assert_eq!(ext, decoded);
    }
    
    #[test]
    fn test_status_request_with_extensions() {
        let ext = StatusRequestExtension::new(
            1,
            vec![],
            vec![1, 2, 3, 4, 5],
        );
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        // Round-trip
        let mut reader = Reader::init(&bytes);
        let decoded = StatusRequestExtension::read(&mut reader).unwrap();
        assert_eq!(ext, decoded);
    }
    
    // SignedCertificateTimestampExtension tests
    
    #[test]
    fn test_sct_extension() {
        let ext = SignedCertificateTimestampExtension::new();
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        // Should encode as empty
        assert_eq!(bytes.len(), 0);
        
        // Round-trip
        let mut reader = Reader::init(&bytes);
        let decoded = SignedCertificateTimestampExtension::read(&mut reader).unwrap();
        assert_eq!(ext, decoded);
    }
    
    #[test]
    fn test_sct_extension_default() {
        let ext = SignedCertificateTimestampExtension::default();
        
        let mut bytes = Vec::new();
        ext.encode(&mut bytes);
        
        assert_eq!(bytes.len(), 0);
    }
}


#[cfg(test)]
mod property_tests {
    use super::*;
    use alloc::vec;
    
    // Feature: custls, Property 12: Extension Stub Round-Trip
    // For any stub extension (application_settings, delegated_credential, compress_certificate,
    // status_request, signed_certificate_timestamp), encoding the extension to wire format
    // and then decoding SHALL produce an equivalent extension structure.
    
    #[cfg(feature = "std")]
    use proptest::prelude::*;
    
    #[cfg(feature = "std")]
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        
        #[test]
        fn application_settings_round_trip(
            protocols in prop::collection::vec(
                prop::collection::vec(prop::num::u8::ANY, 0..255),
                0..10
            )
        ) {
            let ext = ApplicationSettingsExtension::new(protocols);
            
            // Encode
            let mut bytes = Vec::new();
            ext.encode(&mut bytes);
            
            // Decode
            let mut reader = Reader::init(&bytes);
            let decoded = ApplicationSettingsExtension::read(&mut reader)
                .expect("Failed to decode ApplicationSettingsExtension");
            
            // Should be equivalent
            prop_assert_eq!(ext, decoded);
        }
        
        #[test]
        fn delegated_credential_round_trip(
            // Generate a vector of valid SignatureScheme values
            schemes in prop::collection::vec(
                prop::sample::select(vec![
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::RSA_PKCS1_SHA384,
                    SignatureScheme::RSA_PKCS1_SHA512,
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    SignatureScheme::ECDSA_NISTP521_SHA512,
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::RSA_PSS_SHA384,
                    SignatureScheme::RSA_PSS_SHA512,
                    SignatureScheme::ED25519,
                    SignatureScheme::ED448,
                ]),
                0..10
            )
        ) {
            let ext = DelegatedCredentialExtension::new(schemes);
            
            // Encode
            let mut bytes = Vec::new();
            ext.encode(&mut bytes);
            
            // Decode
            let mut reader = Reader::init(&bytes);
            let decoded = DelegatedCredentialExtension::read(&mut reader)
                .expect("Failed to decode DelegatedCredentialExtension");
            
            // Should be equivalent
            prop_assert_eq!(ext, decoded);
        }
        
        #[test]
        fn compress_certificate_round_trip(
            // Generate a vector of valid CertificateCompressionAlgorithm values
            algorithms in prop::collection::vec(
                prop::sample::select(vec![
                    CertificateCompressionAlgorithm::Zlib,
                    CertificateCompressionAlgorithm::Brotli,
                    CertificateCompressionAlgorithm::Zstd,
                ]),
                0..5
            )
        ) {
            let ext = CompressCertificateExtension::new(algorithms);
            
            // Encode
            let mut bytes = Vec::new();
            ext.encode(&mut bytes);
            
            // Decode
            let mut reader = Reader::init(&bytes);
            let decoded = CompressCertificateExtension::read(&mut reader)
                .expect("Failed to decode CompressCertificateExtension");
            
            // Should be equivalent
            prop_assert_eq!(ext, decoded);
        }
        
        #[test]
        fn status_request_round_trip(
            status_type in prop::num::u8::ANY,
            responder_ids in prop::collection::vec(
                prop::collection::vec(prop::num::u8::ANY, 0..100),
                0..5
            ),
            request_extensions in prop::collection::vec(prop::num::u8::ANY, 0..100)
        ) {
            let ext = StatusRequestExtension::new(status_type, responder_ids, request_extensions);
            
            // Encode
            let mut bytes = Vec::new();
            ext.encode(&mut bytes);
            
            // Decode
            let mut reader = Reader::init(&bytes);
            let decoded = StatusRequestExtension::read(&mut reader)
                .expect("Failed to decode StatusRequestExtension");
            
            // Should be equivalent
            prop_assert_eq!(ext, decoded);
        }
        
        #[test]
        fn sct_extension_round_trip(_dummy in prop::bool::ANY) {
            let ext = SignedCertificateTimestampExtension::new();
            
            // Encode
            let mut bytes = Vec::new();
            ext.encode(&mut bytes);
            
            // Decode
            let mut reader = Reader::init(&bytes);
            let decoded = SignedCertificateTimestampExtension::read(&mut reader)
                .expect("Failed to decode SignedCertificateTimestampExtension");
            
            // Should be equivalent (both are empty)
            prop_assert_eq!(ext, decoded);
        }
        
        // Feature: custls, Property 11: Padding Length Configuration
        // For any specified padding length, the PaddingExtension SHALL encode exactly
        // that many padding bytes in the wire format.
        #[test]
        fn padding_length_configuration(length in 0u16..1500) {
            let ext = PaddingExtension::new(length);
            
            // Encode
            let mut bytes = Vec::new();
            ext.encode(&mut bytes);
            
            // Should encode exactly 'length' bytes
            prop_assert_eq!(bytes.len(), length as usize);
            
            // All bytes should be zero
            prop_assert!(bytes.iter().all(|&b| b == 0));
        }
    }
}
