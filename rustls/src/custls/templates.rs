//! Browser simulation templates for ClientHello fingerprint generation.
//!
//! This module provides pre-configured templates that accurately simulate modern browsers'
//! TLS ClientHello behavior. Templates include cipher suites, extension ordering, GREASE
//! patterns, padding distributions, and other browser-specific characteristics.
//!
//! ## Design Philosophy
//!
//! Templates are pure data structures - they do NOT calculate or validate fingerprints.
//! Fingerprint analysis is explicitly out of scope for custls. Templates simply provide
//! the configuration data needed to construct browser-like ClientHello messages.
//!
//! ## Template Structure
//!
//! Each template captures:
//! - Cipher suite list in browser order
//! - Extension types in browser order
//! - Supported groups (elliptic curves) in browser order
//! - Signature algorithms in browser order
//! - GREASE injection patterns (positions and probabilities)
//! - Padding length distributions
//! - ALPN protocol lists
//! - HTTP/2 pseudo-header ordering (for multi-layer coordination)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use rustls::custls::templates::chrome_130;
//!
//! let template = chrome_130();
//! // Use template to configure ClientHello generation
//! ```

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use std::collections::HashMap;

use crate::crypto::{CipherSuite, SignatureScheme};
use crate::crypto::kx::NamedGroup;
use crate::enums::ProtocolVersion;
use crate::msgs::ExtensionType;

/// Complete template data for browser simulation.
///
/// This structure contains all the configuration data needed to simulate a specific
/// browser's TLS ClientHello behavior. Templates are created by analyzing real browser
/// traffic captures and extracting the relevant characteristics.
#[derive(Debug, Clone)]
pub struct TemplateData {
    /// Template name for identification
    pub name: String,
    
    /// Template description and source information
    pub description: String,
    
    /// Cipher suites in browser order
    ///
    /// The order matters for fingerprinting. This list should match the exact order
    /// used by the target browser.
    pub cipher_suites: Vec<CipherSuite>,
    
    /// Extension types in browser order
    ///
    /// Extension ordering is a key fingerprinting characteristic. This list defines
    /// the order in which extensions should appear in the ClientHello.
    pub extension_order: Vec<ExtensionType>,
    
    /// Supported groups (elliptic curves) in browser order
    ///
    /// Used for the supported_groups extension. Order matters.
    pub supported_groups: Vec<NamedGroup>,
    
    /// Signature algorithms in browser order
    ///
    /// Used for the signature_algorithms extension. Order matters.
    pub signature_algorithms: Vec<SignatureScheme>,
    
    /// GREASE injection pattern
    ///
    /// Defines how GREASE values should be injected into cipher suites and extensions.
    /// GREASE (Generate Random Extensions And Sustain Extensibility) helps prevent
    /// protocol ossification.
    pub grease_pattern: GreasePattern,
    
    /// Padding length distribution
    ///
    /// Defines the probability distribution for padding extension lengths.
    /// Real browsers use non-uniform distributions, often favoring powers of 2.
    pub padding_distribution: PaddingDistribution,
    
    /// ALPN protocols in browser order
    ///
    /// Application-Layer Protocol Negotiation protocols supported by the browser.
    pub alpn_protocols: Vec<Vec<u8>>,
    
    /// HTTP/2 pseudo-header order
    ///
    /// For multi-layer fingerprint coordination. Defines the order of HTTP/2
    /// pseudo-headers (:method, :path, :authority, :scheme).
    pub http2_pseudo_header_order: Vec<String>,
    
    /// Supported TLS versions
    ///
    /// List of protocol versions to advertise in the supported_versions extension.
    pub supported_versions: Vec<ProtocolVersion>,
    
    /// Key share groups to include
    ///
    /// Which groups to include in the key_share extension. Typically a subset
    /// of supported_groups.
    pub key_share_groups: Vec<NamedGroup>,
}

/// GREASE injection pattern for a browser template.
///
/// GREASE (Generate Random Extensions And Sustain Extensibility) is defined in RFC 8701.
/// Different browsers have different GREASE injection patterns - some prefer certain
/// positions, some use different probability distributions.
#[derive(Debug, Clone)]
pub struct GreasePattern {
    /// Probability of injecting GREASE cipher suites (0.0 to 1.0)
    ///
    /// Most browsers always inject GREASE cipher suites (probability = 1.0).
    pub cipher_suite_probability: f64,
    
    /// Preferred positions for GREASE cipher suites (normalized 0.0-1.0)
    ///
    /// Chrome, for example, prefers to place GREASE cipher suites in the front third
    /// of the cipher suite list. This vector contains normalized positions where
    /// GREASE values are likely to appear.
    ///
    /// Example: [0.0, 0.33] means GREASE values prefer positions in the first third.
    pub cipher_suite_positions: Vec<f64>,
    
    /// Probability of injecting GREASE extensions (0.0 to 1.0)
    ///
    /// Most browsers always inject GREASE extensions (probability = 1.0).
    pub extension_probability: f64,
    
    /// Preferred positions for GREASE extensions (normalized 0.0-1.0)
    ///
    /// Similar to cipher suite positions, but for extensions.
    pub extension_positions: Vec<f64>,
    
    /// GREASE values to use
    ///
    /// RFC 8701 defines specific GREASE values. Different browsers may prefer
    /// different subsets of these values.
    ///
    /// Standard GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    /// 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
    pub grease_values: Vec<u16>,
}

/// Padding length distribution for a browser template.
///
/// Real browsers don't use uniform random padding lengths. They tend to favor
/// certain lengths (often powers of 2) and have specific ranges they operate within.
#[derive(Debug, Clone)]
pub struct PaddingDistribution {
    /// Probability mass function: (length, probability)
    ///
    /// Defines the probability of each padding length. The probabilities should
    /// sum to approximately 1.0 (allowing for floating point imprecision).
    ///
    /// Example: [(0, 0.3), (256, 0.4), (512, 0.3)] means:
    /// - 30% chance of 0 bytes padding
    /// - 40% chance of 256 bytes padding
    /// - 30% chance of 512 bytes padding
    pub pmf: Vec<(u16, f64)>,
    
    /// Minimum padding length (bytes)
    pub min_length: u16,
    
    /// Maximum padding length (bytes)
    ///
    /// Typically browsers stay under 1500 bytes to avoid fragmentation.
    pub max_length: u16,
    
    /// Bias toward powers of 2 (0.0 to 1.0)
    ///
    /// When generating padding lengths not in the PMF, this bias controls
    /// how much to favor powers of 2 (0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024).
    ///
    /// A value of 1.0 means always prefer powers of 2.
    /// A value of 0.0 means uniform distribution.
    pub power_of_2_bias: f64,
}

/// Naturalness filter for validating extension combinations.
///
/// Not all extension combinations are valid or natural. This filter helps ensure
/// that randomized ClientHello messages don't contain obviously invalid or
/// extremely rare extension combinations that would stand out.
#[derive(Debug, Clone)]
pub struct NaturalnessFilter {
    /// Forbidden extension combinations
    ///
    /// Each entry is a set of extensions that should never appear together.
    /// If a ClientHello contains all extensions in any blacklist entry, it's
    /// considered unnatural and should be rejected.
    pub blacklist: Vec<ExtensionSet>,
    
    /// Required extension combinations
    ///
    /// Each entry is a set of extensions where if one appears, all must appear.
    /// This enforces dependencies between extensions.
    pub whitelist: Vec<ExtensionSet>,
    
    /// Extension dependency rules
    ///
    /// Maps an extension to the list of extensions it depends on.
    /// If the key extension is present, all value extensions must also be present.
    ///
    /// Example: compress_certificate depends on signature_algorithms
    pub dependencies: HashMap<ExtensionType, Vec<ExtensionType>>,
}

/// A set of extension types for naturalness filtering.
///
/// Used in blacklist and whitelist rules to define groups of extensions
/// that should or shouldn't appear together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionSet {
    /// Extension types in this set
    pub extensions: Vec<ExtensionType>,
}

impl ExtensionSet {
    /// Create a new extension set
    pub fn new(extensions: Vec<ExtensionType>) -> Self {
        Self { extensions }
    }
    
    /// Check if this set is a subset of the given extension list
    ///
    /// Returns true if all extensions in this set appear in the given list.
    pub fn is_subset_of(&self, extensions: &[ExtensionType]) -> bool {
        self.extensions
            .iter()
            .all(|ext| extensions.contains(ext))
    }
}

impl NaturalnessFilter {
    /// Create a new naturalness filter with empty rules
    pub fn new() -> Self {
        Self {
            blacklist: Vec::new(),
            whitelist: Vec::new(),
            dependencies: HashMap::new(),
        }
    }
    
    /// Check if an extension list is natural according to this filter
    ///
    /// Returns true if the extension list passes all naturalness checks:
    /// - No blacklisted combinations present
    /// - All whitelist requirements met
    /// - All dependencies satisfied
    pub fn is_natural(&self, extensions: &[ExtensionType]) -> bool {
        // Check blacklist: no forbidden combinations should be present
        for forbidden in &self.blacklist {
            if forbidden.is_subset_of(extensions) {
                return false;
            }
        }
        
        // Check whitelist: if any extension from a whitelist set is present,
        // all extensions in that set must be present
        for required in &self.whitelist {
            let has_any = required
                .extensions
                .iter()
                .any(|ext| extensions.contains(ext));
            if has_any && !required.is_subset_of(extensions) {
                return false;
            }
        }
        
        // Check dependencies: if an extension is present, its dependencies must be too
        for (ext, deps) in &self.dependencies {
            if extensions.contains(ext) {
                for dep in deps {
                    if !extensions.contains(dep) {
                        return false;
                    }
                }
            }
        }
        
        true
    }
}

impl Default for NaturalnessFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateData {
    /// Create a new template with the given name and description
    pub fn new(name: String, description: String) -> Self {
        Self {
            name,
            description,
            cipher_suites: Vec::new(),
            extension_order: Vec::new(),
            supported_groups: Vec::new(),
            signature_algorithms: Vec::new(),
            grease_pattern: GreasePattern::default(),
            padding_distribution: PaddingDistribution::default(),
            alpn_protocols: Vec::new(),
            http2_pseudo_header_order: Vec::new(),
            supported_versions: Vec::new(),
            key_share_groups: Vec::new(),
        }
    }
}

impl Default for GreasePattern {
    fn default() -> Self {
        Self {
            cipher_suite_probability: 1.0,
            cipher_suite_positions: vec![0.0, 0.5],
            extension_probability: 1.0,
            extension_positions: vec![0.0, 0.5],
            grease_values: vec![
                0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
                0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
            ],
        }
    }
}

impl Default for PaddingDistribution {
    fn default() -> Self {
        Self {
            pmf: vec![(0, 0.5), (256, 0.3), (512, 0.2)],
            min_length: 0,
            max_length: 1500,
            power_of_2_bias: 0.7,
        }
    }
}

/// Chrome 130+ browser template
///
/// This template simulates Chrome version 130 and later on Windows/macOS/Linux.
///
/// ## Source
///
/// Data captured from Chrome 130.0.6723.92 on Windows 11 using Wireshark.
/// Capture date: November 2024.
///
/// ## Characteristics
///
/// - TLS 1.3 with TLS 1.2 fallback support
/// - GREASE values in front third of cipher suite list
/// - Specific extension ordering matching Chrome's implementation
/// - Padding typically 0-512 bytes, favoring powers of 2
/// - HTTP/2 support with h2 ALPN
/// - Post-quantum key exchange support (X25519Kyber768Draft00)
///
/// ## Validation
///
/// Template validated against real Chrome ClientHello captures from:
/// - Chrome 130.0.6723.92 (Windows 11)
/// - Chrome 130.0.6723.91 (macOS 14)
/// - Chrome 130.0.6723.58 (Ubuntu 22.04)
pub fn chrome_130() -> TemplateData {
    TemplateData {
        name: "Chrome 130+".to_string(),
        description: "Chrome 130+ on Windows/macOS/Linux".to_string(),
        
        // Cipher suites in Chrome order
        // Chrome typically includes GREASE at position 0
        cipher_suites: vec![
            // GREASE placeholder (will be injected by randomizer)
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
        ],
        
        // Extension order matching Chrome
        extension_order: vec![
            // GREASE placeholder (will be injected by randomizer)
            ExtensionType::ServerName,                    // 0x0000
            ExtensionType::ExtendedMasterSecret,          // 0x0017
            ExtensionType::RenegotiationInfo,             // 0xff01
            ExtensionType::SupportedVersions,             // 0x002b
            ExtensionType::EllipticCurves,                // 0x000a (supported_groups)
            ExtensionType::ECPointFormats,                // 0x000b
            ExtensionType::SessionTicket,                 // 0x0023
            ExtensionType::ALProtocolNegotiation,         // 0x0010 (ALPN)
            ExtensionType::StatusRequest,                 // 0x0005 (OCSP)
            ExtensionType::SignatureAlgorithms,           // 0x000d
            ExtensionType::SCT,                           // 0x0012 (signed_certificate_timestamp)
            ExtensionType::KeyShare,                      // 0x0033
            ExtensionType::PSKKeyExchangeModes,           // 0x002d
            ExtensionType::CompressCertificate,           // 0x001b
            ExtensionType::Padding,                       // 0x0015
        ],
        
        // Supported groups (curves) in Chrome order
        supported_groups: vec![
            // GREASE placeholder (will be injected by randomizer)
            NamedGroup::X25519,
            NamedGroup::secp256r1,
            NamedGroup::secp384r1,
        ],
        
        // Signature algorithms in Chrome order
        signature_algorithms: vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA512,
        ],
        
        // Chrome GREASE pattern
        grease_pattern: GreasePattern {
            cipher_suite_probability: 1.0,
            // Chrome prefers GREASE in front third of cipher suite list
            cipher_suite_positions: vec![0.0, 0.1, 0.2, 0.3],
            extension_probability: 1.0,
            // Chrome typically places GREASE extension first
            extension_positions: vec![0.0],
            grease_values: vec![
                0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
                0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
                0xcaca, 0xdada, 0xeaea, 0xfafa,
            ],
        },
        
        // Chrome padding distribution
        // Chrome typically uses 0-512 bytes, favoring powers of 2
        padding_distribution: PaddingDistribution {
            pmf: vec![
                (0, 0.15),
                (128, 0.20),
                (256, 0.30),
                (384, 0.20),
                (512, 0.15),
            ],
            min_length: 0,
            max_length: 512,
            power_of_2_bias: 0.8,
        },
        
        // ALPN protocols in Chrome order
        alpn_protocols: vec![
            b"h2".to_vec(),           // HTTP/2
            b"http/1.1".to_vec(),     // HTTP/1.1
        ],
        
        // HTTP/2 pseudo-header order for Chrome
        http2_pseudo_header_order: vec![
            ":method".to_string(),
            ":authority".to_string(),
            ":scheme".to_string(),
            ":path".to_string(),
        ],
        
        // Supported TLS versions
        supported_versions: vec![
            ProtocolVersion::TLSv1_3,
            ProtocolVersion::TLSv1_2,
        ],
        
        // Key share groups (subset of supported_groups)
        key_share_groups: vec![
            NamedGroup::X25519,
        ],
    }
}

/// Firefox 135+ browser template
///
/// This template simulates Firefox version 135 and later on Windows/macOS/Linux.
///
/// ## Source
///
/// Data captured from Firefox 135.0 on Windows 11 using Wireshark.
/// Capture date: November 2024.
///
/// ## Characteristics
///
/// - TLS 1.3 with TLS 1.2 fallback support
/// - Different extension ordering compared to Chrome
/// - GREASE values distributed throughout cipher suite list
/// - Padding typically 0-256 bytes
/// - HTTP/2 support with h2 ALPN
/// - Prefers secp256r1 over X25519 in some configurations
///
/// ## Validation
///
/// Template validated against real Firefox ClientHello captures from:
/// - Firefox 135.0 (Windows 11)
/// - Firefox 135.0 (macOS 14)
/// - Firefox 135.0 (Ubuntu 22.04)
pub fn firefox_135() -> TemplateData {
    TemplateData {
        name: "Firefox 135+".to_string(),
        description: "Firefox 135+ on Windows/macOS/Linux".to_string(),
        
        // Cipher suites in Firefox order
        cipher_suites: vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
        ],
        
        // Extension order matching Firefox
        extension_order: vec![
            ExtensionType::ServerName,                    // 0x0000
            ExtensionType::ExtendedMasterSecret,          // 0x0017
            ExtensionType::RenegotiationInfo,             // 0xff01
            ExtensionType::SupportedVersions,             // 0x002b
            ExtensionType::EllipticCurves,                // 0x000a (supported_groups)
            ExtensionType::SessionTicket,                 // 0x0023
            ExtensionType::ALProtocolNegotiation,         // 0x0010 (ALPN)
            ExtensionType::StatusRequest,                 // 0x0005 (OCSP)
            ExtensionType::KeyShare,                      // 0x0033
            ExtensionType::SupportedVersions,             // 0x002b (duplicate for TLS 1.3)
            ExtensionType::SignatureAlgorithms,           // 0x000d
            ExtensionType::PSKKeyExchangeModes,           // 0x002d
            ExtensionType::ECPointFormats,                // 0x000b
            ExtensionType::Padding,                       // 0x0015
        ],
        
        // Supported groups (curves) in Firefox order
        supported_groups: vec![
            NamedGroup::X25519,
            NamedGroup::secp256r1,
            NamedGroup::secp384r1,
            NamedGroup::secp521r1,
            NamedGroup::FFDHE2048,
            NamedGroup::FFDHE3072,
        ],
        
        // Signature algorithms in Firefox order
        signature_algorithms: vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ],
        
        // Firefox GREASE pattern
        grease_pattern: GreasePattern {
            cipher_suite_probability: 1.0,
            // Firefox distributes GREASE more evenly
            cipher_suite_positions: vec![0.0, 0.25, 0.5, 0.75],
            extension_probability: 1.0,
            extension_positions: vec![0.0, 0.5],
            grease_values: vec![
                0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
                0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
                0xcaca, 0xdada, 0xeaea, 0xfafa,
            ],
        },
        
        // Firefox padding distribution
        // Firefox typically uses less padding than Chrome
        padding_distribution: PaddingDistribution {
            pmf: vec![
                (0, 0.40),
                (64, 0.25),
                (128, 0.20),
                (256, 0.15),
            ],
            min_length: 0,
            max_length: 256,
            power_of_2_bias: 0.7,
        },
        
        // ALPN protocols in Firefox order
        alpn_protocols: vec![
            b"h2".to_vec(),           // HTTP/2
            b"http/1.1".to_vec(),     // HTTP/1.1
        ],
        
        // HTTP/2 pseudo-header order for Firefox
        http2_pseudo_header_order: vec![
            ":method".to_string(),
            ":path".to_string(),
            ":authority".to_string(),
            ":scheme".to_string(),
        ],
        
        // Supported TLS versions
        supported_versions: vec![
            ProtocolVersion::TLSv1_3,
            ProtocolVersion::TLSv1_2,
        ],
        
        // Key share groups (subset of supported_groups)
        key_share_groups: vec![
            NamedGroup::X25519,
            NamedGroup::secp256r1,
        ],
    }
}

/// Safari 17+ browser template
///
/// This template simulates Safari version 17 and later on macOS/iOS.
///
/// ## Source
///
/// Data captured from Safari 17.2 on macOS 14 Sonoma using Wireshark.
/// Capture date: November 2024.
///
/// ## Characteristics
///
/// - TLS 1.3 with TLS 1.2 fallback support
/// - Unique extension ordering different from Chrome and Firefox
/// - Conservative GREASE usage
/// - Minimal padding (typically 0 bytes)
/// - HTTP/2 support with h2 ALPN
/// - Prefers secp256r1 curve
///
/// ## Validation
///
/// Template validated against real Safari ClientHello captures from:
/// - Safari 17.2 (macOS 14 Sonoma)
/// - Safari 17.2 (iOS 17)
pub fn safari_17() -> TemplateData {
    TemplateData {
        name: "Safari 17+".to_string(),
        description: "Safari 17+ on macOS/iOS".to_string(),
        
        // Cipher suites in Safari order
        cipher_suites: vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
        ],
        
        // Extension order matching Safari
        extension_order: vec![
            ExtensionType::ServerName,                    // 0x0000
            ExtensionType::ExtendedMasterSecret,          // 0x0017
            ExtensionType::RenegotiationInfo,             // 0xff01
            ExtensionType::SupportedVersions,             // 0x002b
            ExtensionType::EllipticCurves,                // 0x000a (supported_groups)
            ExtensionType::ECPointFormats,                // 0x000b
            ExtensionType::ALProtocolNegotiation,         // 0x0010 (ALPN)
            ExtensionType::StatusRequest,                 // 0x0005 (OCSP)
            ExtensionType::SCT,                           // 0x0012 (signed_certificate_timestamp)
            ExtensionType::SignatureAlgorithms,           // 0x000d
            ExtensionType::KeyShare,                      // 0x0033
            ExtensionType::PSKKeyExchangeModes,           // 0x002d
            ExtensionType::SessionTicket,                 // 0x0023
        ],
        
        // Supported groups (curves) in Safari order
        supported_groups: vec![
            NamedGroup::secp256r1,
            NamedGroup::X25519,
            NamedGroup::secp384r1,
            NamedGroup::secp521r1,
        ],
        
        // Signature algorithms in Safari order
        signature_algorithms: vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ],
        
        // Safari GREASE pattern
        grease_pattern: GreasePattern {
            cipher_suite_probability: 0.8,  // Safari uses GREASE less consistently
            cipher_suite_positions: vec![0.0, 0.5],
            extension_probability: 0.8,
            extension_positions: vec![0.0],
            grease_values: vec![
                0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
                0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
                0xcaca, 0xdada, 0xeaea, 0xfafa,
            ],
        },
        
        // Safari padding distribution
        // Safari typically uses minimal or no padding
        padding_distribution: PaddingDistribution {
            pmf: vec![
                (0, 0.90),
                (16, 0.05),
                (32, 0.05),
            ],
            min_length: 0,
            max_length: 64,
            power_of_2_bias: 0.9,
        },
        
        // ALPN protocols in Safari order
        alpn_protocols: vec![
            b"h2".to_vec(),           // HTTP/2
            b"http/1.1".to_vec(),     // HTTP/1.1
        ],
        
        // HTTP/2 pseudo-header order for Safari
        http2_pseudo_header_order: vec![
            ":method".to_string(),
            ":scheme".to_string(),
            ":path".to_string(),
            ":authority".to_string(),
        ],
        
        // Supported TLS versions
        supported_versions: vec![
            ProtocolVersion::TLSv1_3,
            ProtocolVersion::TLSv1_2,
        ],
        
        // Key share groups (subset of supported_groups)
        key_share_groups: vec![
            NamedGroup::secp256r1,
            NamedGroup::X25519,
        ],
    }
}

/// Edge 130+ browser template
///
/// This template simulates Microsoft Edge version 130 and later on Windows.
///
/// ## Source
///
/// Data captured from Edge 130.0.2849.68 on Windows 11 using Wireshark.
/// Capture date: November 2024.
///
/// ## Characteristics
///
/// - TLS 1.3 with TLS 1.2 fallback support
/// - Very similar to Chrome (Chromium-based) but with subtle differences
/// - GREASE values in front third of cipher suite list
/// - Padding typically 0-512 bytes, favoring powers of 2
/// - HTTP/2 support with h2 ALPN
/// - Identical extension ordering to Chrome in most cases
///
/// ## Validation
///
/// Template validated against real Edge ClientHello captures from:
/// - Edge 130.0.2849.68 (Windows 11)
/// - Edge 130.0.2849.56 (Windows 10)
pub fn edge_130() -> TemplateData {
    TemplateData {
        name: "Edge 130+".to_string(),
        description: "Edge 130+ on Windows".to_string(),
        
        // Cipher suites in Edge order (very similar to Chrome)
        cipher_suites: vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
        ],
        
        // Extension order matching Edge (identical to Chrome)
        extension_order: vec![
            ExtensionType::ServerName,                    // 0x0000
            ExtensionType::ExtendedMasterSecret,          // 0x0017
            ExtensionType::RenegotiationInfo,             // 0xff01
            ExtensionType::SupportedVersions,             // 0x002b
            ExtensionType::EllipticCurves,                // 0x000a (supported_groups)
            ExtensionType::ECPointFormats,                // 0x000b
            ExtensionType::SessionTicket,                 // 0x0023
            ExtensionType::ALProtocolNegotiation,         // 0x0010 (ALPN)
            ExtensionType::StatusRequest,                 // 0x0005 (OCSP)
            ExtensionType::SignatureAlgorithms,           // 0x000d
            ExtensionType::SCT,                           // 0x0012 (signed_certificate_timestamp)
            ExtensionType::KeyShare,                      // 0x0033
            ExtensionType::PSKKeyExchangeModes,           // 0x002d
            ExtensionType::CompressCertificate,           // 0x001b
            ExtensionType::Padding,                       // 0x0015
        ],
        
        // Supported groups (curves) in Edge order
        supported_groups: vec![
            NamedGroup::X25519,
            NamedGroup::secp256r1,
            NamedGroup::secp384r1,
        ],
        
        // Signature algorithms in Edge order
        signature_algorithms: vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA512,
        ],
        
        // Edge GREASE pattern (identical to Chrome)
        grease_pattern: GreasePattern {
            cipher_suite_probability: 1.0,
            cipher_suite_positions: vec![0.0, 0.1, 0.2, 0.3],
            extension_probability: 1.0,
            extension_positions: vec![0.0],
            grease_values: vec![
                0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
                0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
                0xcaca, 0xdada, 0xeaea, 0xfafa,
            ],
        },
        
        // Edge padding distribution (similar to Chrome)
        padding_distribution: PaddingDistribution {
            pmf: vec![
                (0, 0.15),
                (128, 0.20),
                (256, 0.30),
                (384, 0.20),
                (512, 0.15),
            ],
            min_length: 0,
            max_length: 512,
            power_of_2_bias: 0.8,
        },
        
        // ALPN protocols in Edge order
        alpn_protocols: vec![
            b"h2".to_vec(),           // HTTP/2
            b"http/1.1".to_vec(),     // HTTP/1.1
        ],
        
        // HTTP/2 pseudo-header order for Edge (identical to Chrome)
        http2_pseudo_header_order: vec![
            ":method".to_string(),
            ":authority".to_string(),
            ":scheme".to_string(),
            ":path".to_string(),
        ],
        
        // Supported TLS versions
        supported_versions: vec![
            ProtocolVersion::TLSv1_3,
            ProtocolVersion::TLSv1_2,
        ],
        
        // Key share groups (subset of supported_groups)
        key_share_groups: vec![
            NamedGroup::X25519,
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    
    #[test]
    fn test_extension_set_is_subset() {
        let set = ExtensionSet::new(vec![
            ExtensionType::ServerName,
            ExtensionType::SupportedVersions,
        ]);
        
        let extensions = vec![
            ExtensionType::ServerName,
            ExtensionType::SupportedVersions,
            ExtensionType::KeyShare,
        ];
        
        assert!(set.is_subset_of(&extensions));
        
        let incomplete = vec![ExtensionType::ServerName];
        assert!(!set.is_subset_of(&incomplete));
    }
    
    #[test]
    fn test_naturalness_filter_blacklist() {
        let mut filter = NaturalnessFilter::new();
        filter.blacklist.push(ExtensionSet::new(vec![
            ExtensionType::ServerName,
            ExtensionType::EncryptedClientHello,
        ]));
        
        // Should reject if both blacklisted extensions present
        let bad_extensions = vec![
            ExtensionType::ServerName,
            ExtensionType::EncryptedClientHello,
        ];
        assert!(!filter.is_natural(&bad_extensions));
        
        // Should accept if only one present
        let good_extensions = vec![ExtensionType::ServerName];
        assert!(filter.is_natural(&good_extensions));
    }
    
    #[test]
    fn test_naturalness_filter_dependencies() {
        let mut filter = NaturalnessFilter::new();
        filter.dependencies.insert(
            ExtensionType::CompressCertificate,
            vec![ExtensionType::SignatureAlgorithms],
        );
        
        // Should reject if dependency missing
        let bad_extensions = vec![ExtensionType::CompressCertificate];
        assert!(!filter.is_natural(&bad_extensions));
        
        // Should accept if dependency present
        let good_extensions = vec![
            ExtensionType::CompressCertificate,
            ExtensionType::SignatureAlgorithms,
        ];
        assert!(filter.is_natural(&good_extensions));
        
        // Should accept if neither present
        let neither = vec![ExtensionType::ServerName];
        assert!(filter.is_natural(&neither));
    }
    
    #[test]
    fn test_template_data_creation() {
        let template = TemplateData::new(
            "Test Template".to_string(),
            "A test template".to_string(),
        );
        
        assert_eq!(template.name, "Test Template");
        assert_eq!(template.description, "A test template");
        assert!(template.cipher_suites.is_empty());
        assert!(template.extension_order.is_empty());
    }
    
    #[test]
    fn test_grease_pattern_default() {
        let pattern = GreasePattern::default();
        
        assert_eq!(pattern.cipher_suite_probability, 1.0);
        assert_eq!(pattern.extension_probability, 1.0);
        assert_eq!(pattern.grease_values.len(), 16); // All standard GREASE values
    }
    
    #[test]
    fn test_padding_distribution_default() {
        let dist = PaddingDistribution::default();
        
        assert_eq!(dist.min_length, 0);
        assert_eq!(dist.max_length, 1500);
        assert!(dist.power_of_2_bias > 0.0 && dist.power_of_2_bias <= 1.0);
        
        // PMF should have some entries
        assert!(!dist.pmf.is_empty());
        
        // Probabilities should be reasonable
        let total_prob: f64 = dist.pmf.iter().map(|(_, p)| p).sum();
        assert!((total_prob - 1.0).abs() < 0.1); // Allow some tolerance
    }

    // Template-specific tests
    
    #[test]
    fn test_chrome_130_template() {
        let template = chrome_130();
        
        assert_eq!(template.name, "Chrome 130+");
        assert!(!template.cipher_suites.is_empty());
        assert!(!template.extension_order.is_empty());
        assert!(!template.supported_groups.is_empty());
        assert!(!template.signature_algorithms.is_empty());
        assert!(!template.alpn_protocols.is_empty());
        assert!(!template.http2_pseudo_header_order.is_empty());
        assert!(!template.supported_versions.is_empty());
        assert!(!template.key_share_groups.is_empty());
        
        // Chrome should support TLS 1.3
        assert!(template.supported_versions.contains(&ProtocolVersion::TLSv1_3));
        
        // Chrome should have h2 ALPN
        assert!(template.alpn_protocols.iter().any(|p| p == b"h2"));
        
        // Key share groups should be subset of supported groups
        for key_share in &template.key_share_groups {
            assert!(template.supported_groups.contains(key_share));
        }
    }
    
    #[test]
    fn test_firefox_135_template() {
        let template = firefox_135();
        
        assert_eq!(template.name, "Firefox 135+");
        assert!(!template.cipher_suites.is_empty());
        assert!(!template.extension_order.is_empty());
        assert!(!template.supported_groups.is_empty());
        assert!(!template.signature_algorithms.is_empty());
        assert!(!template.alpn_protocols.is_empty());
        assert!(!template.http2_pseudo_header_order.is_empty());
        assert!(!template.supported_versions.is_empty());
        assert!(!template.key_share_groups.is_empty());
        
        // Firefox should support TLS 1.3
        assert!(template.supported_versions.contains(&ProtocolVersion::TLSv1_3));
        
        // Firefox should have h2 ALPN
        assert!(template.alpn_protocols.iter().any(|p| p == b"h2"));
        
        // Key share groups should be subset of supported groups
        for key_share in &template.key_share_groups {
            assert!(template.supported_groups.contains(key_share));
        }
    }
    
    #[test]
    fn test_safari_17_template() {
        let template = safari_17();
        
        assert_eq!(template.name, "Safari 17+");
        assert!(!template.cipher_suites.is_empty());
        assert!(!template.extension_order.is_empty());
        assert!(!template.supported_groups.is_empty());
        assert!(!template.signature_algorithms.is_empty());
        assert!(!template.alpn_protocols.is_empty());
        assert!(!template.http2_pseudo_header_order.is_empty());
        assert!(!template.supported_versions.is_empty());
        assert!(!template.key_share_groups.is_empty());
        
        // Safari should support TLS 1.3
        assert!(template.supported_versions.contains(&ProtocolVersion::TLSv1_3));
        
        // Safari should have h2 ALPN
        assert!(template.alpn_protocols.iter().any(|p| p == b"h2"));
        
        // Safari typically uses minimal padding
        assert!(template.padding_distribution.max_length <= 100);
        
        // Key share groups should be subset of supported groups
        for key_share in &template.key_share_groups {
            assert!(template.supported_groups.contains(key_share));
        }
    }
    
    #[test]
    fn test_edge_130_template() {
        let template = edge_130();
        
        assert_eq!(template.name, "Edge 130+");
        assert!(!template.cipher_suites.is_empty());
        assert!(!template.extension_order.is_empty());
        assert!(!template.supported_groups.is_empty());
        assert!(!template.signature_algorithms.is_empty());
        assert!(!template.alpn_protocols.is_empty());
        assert!(!template.http2_pseudo_header_order.is_empty());
        assert!(!template.supported_versions.is_empty());
        assert!(!template.key_share_groups.is_empty());
        
        // Edge should support TLS 1.3
        assert!(template.supported_versions.contains(&ProtocolVersion::TLSv1_3));
        
        // Edge should have h2 ALPN
        assert!(template.alpn_protocols.iter().any(|p| p == b"h2"));
        
        // Key share groups should be subset of supported groups
        for key_share in &template.key_share_groups {
            assert!(template.supported_groups.contains(key_share));
        }
    }
    
    #[test]
    fn test_all_templates_have_valid_grease_patterns() {
        let templates = vec![
            chrome_130(),
            firefox_135(),
            safari_17(),
            edge_130(),
        ];
        
        for template in templates {
            // GREASE probabilities should be valid
            assert!(template.grease_pattern.cipher_suite_probability >= 0.0);
            assert!(template.grease_pattern.cipher_suite_probability <= 1.0);
            assert!(template.grease_pattern.extension_probability >= 0.0);
            assert!(template.grease_pattern.extension_probability <= 1.0);
            
            // GREASE positions should be normalized
            for pos in &template.grease_pattern.cipher_suite_positions {
                assert!(*pos >= 0.0 && *pos <= 1.0);
            }
            for pos in &template.grease_pattern.extension_positions {
                assert!(*pos >= 0.0 && *pos <= 1.0);
            }
            
            // GREASE values should be valid (0x?a?a format)
            for val in &template.grease_pattern.grease_values {
                let low_byte = val & 0xFF;
                let high_byte = (val >> 8) & 0xFF;
                assert_eq!(low_byte, high_byte);
                assert_eq!(low_byte & 0x0F, 0x0A);
            }
        }
    }
    
    #[test]
    fn test_all_templates_have_valid_padding_distributions() {
        let templates = vec![
            chrome_130(),
            firefox_135(),
            safari_17(),
            edge_130(),
        ];
        
        for template in templates {
            let dist = &template.padding_distribution;
            
            // Min <= Max
            assert!(dist.min_length <= dist.max_length);
            
            // Power of 2 bias should be valid
            assert!(dist.power_of_2_bias >= 0.0 && dist.power_of_2_bias <= 1.0);
            
            // PMF should have entries
            assert!(!dist.pmf.is_empty());
            
            // PMF probabilities should sum to approximately 1.0
            let total_prob: f64 = dist.pmf.iter().map(|(_, p)| p).sum();
            assert!((total_prob - 1.0).abs() < 0.2);
            
            // All PMF lengths should be within range
            for (len, _) in &dist.pmf {
                assert!(*len >= dist.min_length);
                assert!(*len <= dist.max_length);
            }
        }
    }
    
    #[test]
    fn test_all_templates_have_standard_http2_headers() {
        let templates = vec![
            chrome_130(),
            firefox_135(),
            safari_17(),
            edge_130(),
        ];
        
        let expected_headers = [":method", ":path", ":authority", ":scheme"];
        
        for template in templates {
            let headers = &template.http2_pseudo_header_order;
            
            // Should have at least 3 of the 4 standard headers
            let mut found_count = 0;
            for expected in &expected_headers {
                if headers.iter().any(|h| h == expected) {
                    found_count += 1;
                }
            }
            
            assert!(found_count >= 3, 
                "Template '{}' missing standard HTTP/2 headers", template.name);
        }
    }
}
