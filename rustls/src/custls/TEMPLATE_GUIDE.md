# Template Creation Guide

## Introduction

This guide explains how to capture browser fingerprints, create custom templates, and validate them for use with custls.

## Overview

A template in custls is a complete specification of a browser's TLS ClientHello characteristics:
- Cipher suite list and order
- Extension types and order
- Supported groups (curves)
- Signature algorithms
- GREASE injection patterns
- Padding length distribution
- ALPN protocols
- HTTP/2 settings

## Prerequisites

### Tools Required

1. **Wireshark** - For capturing TLS traffic
   - Download: https://www.wireshark.org/
   - Version 4.0+ recommended

2. **Browser** - The browser you want to simulate
   - Chrome, Firefox, Safari, or Edge
   - Latest version recommended

3. **Test Server** - A TLS server to connect to
   - Can use any HTTPS website
   - Cloudflare sites are good for testing (they use advanced fingerprinting)

### Knowledge Required

- Basic understanding of TLS handshake
- Familiarity with Wireshark
- Basic Rust programming

## Step 1: Capture Browser Traffic

### 1.1 Set Up Wireshark

1. Start Wireshark with administrator/root privileges
2. Select your network interface (usually Wi-Fi or Ethernet)
3. Apply display filter: `tls.handshake.type == 1`
   - This shows only ClientHello messages

### 1.2 Clear Browser State

Before capturing, clear browser state to get a fresh handshake:

**Chrome/Edge:**
```
Settings → Privacy and security → Clear browsing data
- Cookies and site data
- Cached images and files
```

**Firefox:**
```
Settings → Privacy & Security → Cookies and Site Data → Clear Data
```

**Safari:**
```
Safari → Clear History → All History
```

### 1.3 Capture ClientHello

1. Start Wireshark capture
2. In browser, navigate to: `https://www.cloudflare.com/`
3. Stop Wireshark capture after page loads
4. Find the ClientHello packet in Wireshark

### 1.4 Export Packet

1. Right-click on ClientHello packet
2. Select "Export Packet Bytes..."
3. Save as `browser_clienthello.bin`

## Step 2: Analyze ClientHello

### 2.1 Examine in Wireshark

Expand the ClientHello in Wireshark to see:

**Cipher Suites:**
```
Transport Layer Security
  TLSv1.3 Record Layer: Handshake Protocol: Client Hello
    Handshake Protocol: Client Hello
      Cipher Suites (XX suites)
        Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
        Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
        Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
        ...
```

**Extensions:**
```
Extension: server_name (len=XX)
Extension: extended_master_secret (len=0)
Extension: renegotiation_info (len=1)
Extension: supported_groups (len=XX)
Extension: ec_point_formats (len=XX)
Extension: session_ticket (len=0)
Extension: application_layer_protocol_negotiation (len=XX)
Extension: status_request (len=XX)
Extension: signature_algorithms (len=XX)
Extension: signed_certificate_timestamp (len=0)
Extension: key_share (len=XX)
Extension: psk_key_exchange_modes (len=XX)
Extension: supported_versions (len=XX)
Extension: compress_certificate (len=XX)
Extension: application_settings (len=XX)
Extension: padding (len=XX)
```

### 2.2 Record Key Information

Create a spreadsheet or text file with:

1. **Cipher Suites** (in order):
   ```
   0x1301 - TLS_AES_128_GCM_SHA256
   0x1302 - TLS_AES_256_GCM_SHA384
   0x1303 - TLS_CHACHA20_POLY1305_SHA256
   0xc02b - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
   ...
   ```

2. **Extension Order**:
   ```
   1. server_name (0x0000)
   2. extended_master_secret (0x0017)
   3. renegotiation_info (0xff01)
   4. supported_groups (0x000a)
   ...
   ```

3. **Supported Groups** (from supported_groups extension):
   ```
   0x001d - x25519
   0x0017 - secp256r1
   0x0018 - secp384r1
   ...
   ```

4. **Signature Algorithms** (from signature_algorithms extension):
   ```
   0x0403 - ecdsa_secp256r1_sha256
   0x0804 - rsa_pss_rsae_sha256
   0x0401 - rsa_pkcs1_sha256
   ...
   ```

5. **ALPN Protocols** (from ALPN extension):
   ```
   h2
   http/1.1
   ```

6. **Padding Length**:
   - Note the length of the padding extension
   - Capture multiple times to see variation

7. **GREASE Values**:
   - Note positions of GREASE values (0x?a?a pattern)
   - In cipher suites: position X
   - In extensions: position Y
   - In supported groups: position Z

### 2.3 Capture Multiple Samples

Repeat the capture process 10-20 times to observe:
- Padding length variation
- GREASE value positions
- Any other variations

Record statistics:
```
Padding lengths observed:
- 0 bytes: 5 times
- 128 bytes: 3 times
- 256 bytes: 7 times
- 512 bytes: 5 times

GREASE cipher suite positions:
- Position 0: 12 times
- Position 1: 8 times

GREASE extension positions:
- Position 0: 15 times
- Position 2: 5 times
```

## Step 3: Create Template Code

### 3.1 Template Structure

Create a new file `my_browser_template.rs`:

```rust
use crate::custls::templates::{TemplateData, GreasePattern, PaddingDistribution};
use crate::enums::{CipherSuite, NamedGroup, SignatureScheme, ProtocolVersion};
use alloc::vec;
use alloc::vec::Vec;

/// My Custom Browser Template
///
/// Captured from: [Browser Name] [Version] on [OS]
/// Date: [Capture Date]
/// Source: [Website used for capture]
pub fn my_browser_template() -> TemplateData {
    TemplateData {
        cipher_suites: cipher_suites(),
        extension_order: extension_order(),
        support_groups: support_groups(),
        signature_algorithms: signature_algorithms(),
        grease_pattern: grease_pattern(),
        padding_distribution: padding_distribution(),
        alpn_protocols: alpn_protocols(),
        http2_pseudo_header_order: http2_pseudo_header_order(),
        supported_versions: supported_versions(),
        key_share_groups: key_share_groups(),
    }
}

fn cipher_suites() -> Vec<CipherSuite> {
    vec![
        // Add cipher suites in exact order from capture
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        // ... more cipher suites
    ]
}

fn extension_order() -> Vec<ExtensionType> {
    vec![
        // Add extensions in exact order from capture
        ExtensionType::ServerName,
        ExtensionType::ExtendedMasterSecret,
        ExtensionType::RenegotiationInfo,
        ExtensionType::SupportedGroups,
        // ... more extensions
    ]
}

fn support_groups() -> Vec<NamedGroup> {
    vec![
        // Add supported groups in exact order
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
        // ... more groups
    ]
}

fn signature_algorithms() -> Vec<SignatureScheme> {
    vec![
        // Add signature algorithms in exact order
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
        // ... more algorithms
    ]
}

fn grease_pattern() -> GreasePattern {
    GreasePattern {
        // Probability of injecting GREASE cipher suite
        cipher_suite_probability: 1.0,
        
        // Preferred positions (0.0 = start, 1.0 = end)
        // Based on observed positions from captures
        cipher_suite_positions: vec![0.0, 0.1],
        
        // Probability of injecting GREASE extension
        extension_probability: 1.0,
        
        // Preferred extension positions
        extension_positions: vec![0.0, 0.15],
        
        // GREASE values to use (standard GREASE values)
        grease_values: vec![
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
            0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
            0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
            0xcaca, 0xdada, 0xeaea, 0xfafa,
        ],
    }
}

fn padding_distribution() -> PaddingDistribution {
    PaddingDistribution {
        // Probability mass function: (length, probability)
        // Based on observed padding lengths
        pmf: vec![
            (0, 0.25),      // 25% chance of 0 bytes
            (128, 0.15),    // 15% chance of 128 bytes
            (256, 0.35),    // 35% chance of 256 bytes
            (512, 0.25),    // 25% chance of 512 bytes
        ],
        min_length: 0,
        max_length: 1500,
        power_of_2_bias: 0.7,  // 70% bias toward powers of 2
    }
}

fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
    ]
}

fn http2_pseudo_header_order() -> Vec<String> {
    vec![
        ":method".to_string(),
        ":authority".to_string(),
        ":scheme".to_string(),
        ":path".to_string(),
    ]
}

fn supported_versions() -> Vec<ProtocolVersion> {
    vec![
        ProtocolVersion::TLSv1_3,
        ProtocolVersion::TLSv1_2,
    ]
}

fn key_share_groups() -> Vec<NamedGroup> {
    vec![
        NamedGroup::X25519,
        NamedGroup::secp256r1,
    ]
}
```

### 3.2 Add to Templates Module

Edit `templates.rs` to add your template:

```rust
// Add to the template factory functions
pub fn my_browser_template() -> TemplateData {
    my_browser_template::my_browser_template()
}

// Add module
mod my_browser_template;
```

### 3.3 Add to BrowserTemplate Enum

Edit `mod.rs` to add your template variant:

```rust
pub enum BrowserTemplate {
    Chrome130,
    Firefox135,
    Safari17,
    Edge130,
    MyBrowser,  // Add your template
    Custom(Box<CustomTemplate>),
}
```

## Step 4: Validate Template

### 4.1 Unit Test

Create a test to validate your template:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_my_browser_template_completeness() {
        let template = my_browser_template();
        
        // Validate cipher suites
        assert!(!template.cipher_suites.is_empty());
        assert!(template.cipher_suites.len() >= 10);
        
        // Validate extensions
        assert!(!template.extension_order.is_empty());
        assert!(template.extension_order.len() >= 10);
        
        // Validate supported groups
        assert!(!template.support_groups.is_empty());
        
        // Validate signature algorithms
        assert!(!template.signature_algorithms.is_empty());
        
        // Validate ALPN
        assert!(!template.alpn_protocols.is_empty());
        
        // Validate padding distribution
        assert!(!template.padding_distribution.pmf.is_empty());
        
        // Validate GREASE pattern
        assert!(!template.grease_pattern.grease_values.is_empty());
    }
    
    #[test]
    fn test_my_browser_template_cipher_suite_order() {
        let template = my_browser_template();
        
        // Validate first few cipher suites match capture
        assert_eq!(template.cipher_suites[0], CipherSuite::TLS13_AES_128_GCM_SHA256);
        assert_eq!(template.cipher_suites[1], CipherSuite::TLS13_AES_256_GCM_SHA384);
        // ... more assertions
    }
    
    #[test]
    fn test_my_browser_template_extension_order() {
        let template = my_browser_template();
        
        // Validate extension order matches capture
        assert_eq!(template.extension_order[0], ExtensionType::ServerName);
        assert_eq!(template.extension_order[1], ExtensionType::ExtendedMasterSecret);
        // ... more assertions
    }
}
```

### 4.2 Integration Test

Test with a real connection:

```rust
#[test]
fn test_my_browser_template_real_connection() {
    use rustls::custls::{CustlsConfig, BrowserTemplate, DefaultCustomizer};
    
    let config = CustlsConfig::builder()
        .with_template(BrowserTemplate::MyBrowser)
        .build();
    
    let customizer = DefaultCustomizer::new(config)
        .with_target("www.cloudflare.com".to_string(), 443);
    
    // Perform handshake and verify success
    // (Implementation depends on your test setup)
}
```

### 4.3 Compare with Real Browser

Capture a ClientHello generated by custls and compare with real browser:

1. Generate ClientHello with custls
2. Capture with Wireshark
3. Compare side-by-side with original browser capture

**Check:**
- ✅ Cipher suite order matches
- ✅ Extension order matches
- ✅ Supported groups match
- ✅ Signature algorithms match
- ✅ ALPN protocols match
- ✅ Padding length is within observed range
- ✅ GREASE positions are similar

## Step 5: Test Against Real Servers

### 5.1 Test with Cloudflare

Cloudflare uses advanced fingerprinting. Test your template:

```rust
use rustls::custls::{CustlsConfig, BrowserTemplate, DefaultCustomizer};

let config = CustlsConfig::builder()
    .with_template(BrowserTemplate::MyBrowser)
    .build();

let customizer = DefaultCustomizer::new(config)
    .with_target("www.cloudflare.com".to_string(), 443);

// Perform handshake
// Verify: No blocks, no challenges
```

### 5.2 Test with Akamai

Akamai also uses fingerprinting:

```rust
let customizer = DefaultCustomizer::new(config)
    .with_target("www.akamai.com".to_string(), 443);

// Perform handshake
// Verify: Successful connection
```

### 5.3 Test with Multiple Sites

Test with various sites that use different CDNs:
- Cloudflare sites
- Akamai sites
- Fastly sites
- AWS CloudFront sites

## Step 6: Document Your Template

### 6.1 Add Documentation Comments

```rust
/// My Custom Browser Template
///
/// # Source
/// - Browser: Chrome 131.0.6778.86
/// - OS: Windows 11 23H2
/// - Capture Date: 2024-01-15
/// - Capture Site: https://www.cloudflare.com/
///
/// # Characteristics
/// - 17 cipher suites
/// - 18 extensions
/// - 5 supported groups
/// - 9 signature algorithms
/// - GREASE at positions 0 and 2
/// - Padding: 0-512 bytes, favoring 256
///
/// # Validation
/// - Tested against Cloudflare: ✅
/// - Tested against Akamai: ✅
/// - Tested against AWS CloudFront: ✅
///
/// # Notes
/// - This template includes application_settings extension
/// - Padding distribution based on 20 samples
/// - GREASE pattern matches Chrome 131 behavior
pub fn my_browser_template() -> TemplateData {
    // ...
}
```

### 6.2 Create Validation Report

Create `MY_BROWSER_VALIDATION.md`:

```markdown
# My Browser Template Validation Report

## Capture Details
- Browser: Chrome 131.0.6778.86
- OS: Windows 11 23H2
- Date: 2024-01-15
- Samples: 20 captures

## Cipher Suites
Matches real browser: ✅
- 17 cipher suites in exact order
- GREASE at position 0 (100% of samples)

## Extensions
Matches real browser: ✅
- 18 extensions in exact order
- GREASE at position 0 (75%) or position 2 (25%)

## Padding Distribution
| Length | Observed | Template |
|--------|----------|----------|
| 0      | 25%      | 25%      |
| 128    | 15%      | 15%      |
| 256    | 35%      | 35%      |
| 512    | 25%      | 25%      |

## Real Server Tests
- Cloudflare: ✅ No blocks
- Akamai: ✅ No blocks
- AWS CloudFront: ✅ No blocks
- Fastly: ✅ No blocks

## Known Limitations
- None identified

## Maintenance
- Review quarterly for browser updates
- Re-capture if browser version changes significantly
```

## Advanced Topics

### Handling Browser Updates

Browsers update frequently. Monitor for changes:

1. **Set up alerts** for browser releases
2. **Re-capture** after major updates
3. **Compare** new captures with template
4. **Update template** if significant changes

### Multiple OS Variations

Browsers behave differently on different OSes:

1. Capture on Windows, macOS, Linux
2. Create OS-specific templates if needed
3. Or create a "universal" template that works on all

### Mobile Browsers

Mobile browsers have different characteristics:

1. Capture from iOS Safari, Android Chrome
2. Note differences in cipher suites, extensions
3. Create mobile-specific templates

### Handling ECH (Encrypted Client Hello)

If the browser uses ECH:

1. Capture both ECH and non-ECH handshakes
2. Note ECH extension characteristics
3. Template should support both modes

## Troubleshooting

### Issue: Template doesn't match browser

**Solution:** Re-capture with fresh browser state. Clear all cookies, cache, and site data.

### Issue: Handshakes failing with template

**Solution:** 
1. Verify cipher suites are supported by server
2. Check extension order (PSK must be last)
3. Reduce randomization level
4. Compare wire bytes with real browser

### Issue: Getting blocked by CDN

**Solution:**
1. Verify template matches browser exactly
2. Check HTTP/2 settings match
3. Ensure User-Agent header matches browser
4. Test with lower randomization level

### Issue: Padding length seems wrong

**Solution:**
1. Capture more samples (20-50)
2. Calculate actual distribution
3. Update padding_distribution PMF
4. Ensure power_of_2_bias is appropriate

## Best Practices

1. **Capture fresh**: Always clear browser state before capturing
2. **Multiple samples**: Capture 20+ samples to see variation
3. **Document source**: Record browser version, OS, date
4. **Test thoroughly**: Test against multiple real servers
5. **Keep updated**: Re-capture when browser updates
6. **Validate regularly**: Test template monthly
7. **Version control**: Track template changes over time

## Example: Complete Chrome 131 Template

See `templates/chrome_130.rs` for a complete, production-ready example.

## Resources

- **Wireshark Documentation**: https://www.wireshark.org/docs/
- **TLS 1.3 RFC**: https://datatracker.ietf.org/doc/html/rfc8446
- **GREASE RFC**: https://datatracker.ietf.org/doc/html/rfc8701
- **JA3 Fingerprinting**: https://github.com/salesforce/ja3
- **JA4 Fingerprinting**: https://github.com/FoxIO-LLC/ja4

## Support

For help with template creation:
- Open an issue on GitHub
- Check existing templates for examples
- Review the API documentation

## Contributing

To contribute your template:
1. Follow this guide to create and validate
2. Add comprehensive tests
3. Document thoroughly
4. Submit a pull request
5. Include validation report
