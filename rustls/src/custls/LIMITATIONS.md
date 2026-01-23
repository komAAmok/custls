# custls Limitations and Stub Implementations

## Overview

This document describes the current limitations of custls, stub implementations, and future work. Understanding these limitations helps set appropriate expectations and guides future development.

## Stub Extensions

Several TLS extensions are implemented as "stubs" - they encode and send correctly but lack full cryptographic functionality. This is intentional: the goal is ClientHello simulation, not full protocol implementation.

### 1. ApplicationSettings Extension (0x001b)

**Status:** Stub Implementation

**What Works:**
- ✅ Correct encoding in ClientHello
- ✅ Proper wire format
- ✅ Included in extension list
- ✅ Does not cause handshake failures

**What Doesn't Work:**
- ❌ No actual application settings negotiation
- ❌ Server responses are ignored
- ❌ No protocol-level functionality

**Impact:**
- **Low** - Most servers accept the extension and ignore it if not supported
- ClientHello appears authentic to fingerprinting systems
- Actual HTTP/2 settings negotiation happens at HTTP/2 layer

**Workaround:**
- Configure HTTP/2 settings at the HTTP/2 layer (e.g., in h2 crate)
- Use `Http2Settings` type for coordination

**Example:**
```rust
use rustls::custls::ApplicationSettingsExtension;

let ext = ApplicationSettingsExtension {
    protocols: vec![b"h2".to_vec()],
};
// Encodes correctly, but no negotiation happens
```

**Future Work:**
- Full implementation requires HTTP/2 integration
- Consider upstreaming to rustls if demand exists

---

### 2. DelegatedCredential Extension (0x0022)

**Status:** Stub Implementation

**What Works:**
- ✅ Correct encoding in ClientHello
- ✅ Proper wire format
- ✅ Signature algorithm list included

**What Doesn't Work:**
- ❌ No delegated credential verification
- ❌ Server delegated credentials are not processed
- ❌ No actual delegation support

**Impact:**
- **Low** - Delegated credentials are rarely used
- Extension presence is sufficient for fingerprint simulation
- Servers that don't support it ignore the extension

**Workaround:**
- None needed for fingerprint simulation
- For actual delegation, use rustls with delegation support (if available)

**Example:**
```rust
use rustls::custls::DelegatedCredentialExtension;

let ext = DelegatedCredentialExtension {
    signature_algorithms: vec![
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PSS_SHA256,
    ],
};
// Encodes correctly, but no verification happens
```

**Future Work:**
- Full implementation requires cryptographic provider support
- Low priority due to limited real-world usage

---

### 3. CompressCertificate Extension (0x001b)

**Status:** Stub Implementation

**What Works:**
- ✅ Correct encoding in ClientHello
- ✅ Compression algorithm list included
- ✅ Proper wire format

**What Doesn't Work:**
- ❌ No certificate decompression
- ❌ Compressed certificates from server are not processed
- ❌ No actual compression support

**Impact:**
- **Medium** - Certificate compression is increasingly common
- Extension presence is sufficient for fingerprint simulation
- Handshakes succeed (server sends uncompressed if client can't decompress)

**Workaround:**
- Server will send uncompressed certificates
- Handshake completes successfully
- Slightly larger handshake size

**Example:**
```rust
use rustls::custls::CompressCertificateExtension;

let ext = CompressCertificateExtension {
    algorithms: vec![
        CertificateCompressionAlgorithm::Brotli,
        CertificateCompressionAlgorithm::Zstd,
    ],
};
// Encodes correctly, but no decompression happens
```

**Future Work:**
- Implement decompression using brotli and zstd crates
- Medium priority for bandwidth savings

---

### 4. StatusRequest Extension (0x0005)

**Status:** Stub Implementation

**What Works:**
- ✅ Correct encoding in ClientHello
- ✅ OCSP responder list included
- ✅ Proper wire format

**What Doesn't Work:**
- ❌ No OCSP response processing
- ❌ Certificate revocation not checked via OCSP
- ❌ No actual OCSP support

**Impact:**
- **Low** - rustls has other revocation checking mechanisms
- Extension presence is sufficient for fingerprint simulation
- Certificate validation still works (via other methods)

**Workaround:**
- Use rustls's built-in certificate validation
- Consider CRL-based revocation checking if needed

**Example:**
```rust
use rustls::custls::StatusRequestExtension;

let ext = StatusRequestExtension {
    responder_id_list: vec![],
    request_extensions: vec![],
};
// Encodes correctly, but no OCSP processing happens
```

**Future Work:**
- Implement OCSP response processing
- Low priority (rustls has other validation methods)

---

### 5. SignedCertificateTimestamp Extension (0x0012)

**Status:** Stub Implementation

**What Works:**
- ✅ Correct encoding in ClientHello
- ✅ Proper wire format
- ✅ Extension presence

**What Doesn't Work:**
- ❌ No SCT verification
- ❌ Certificate Transparency not enforced
- ❌ No actual CT support

**Impact:**
- **Low** - CT is primarily for certificate authorities
- Extension presence is sufficient for fingerprint simulation
- Certificate validation still works

**Workaround:**
- None needed for most use cases
- For CT enforcement, use external tools

**Example:**
```rust
use rustls::custls::SignedCertificateTimestampExtension;

let ext = SignedCertificateTimestampExtension;
// Encodes correctly, but no verification happens
```

**Future Work:**
- Implement SCT verification
- Low priority for most users

---

## Functional Limitations

### 1. No Fingerprint Calculation

**Limitation:** custls does NOT calculate, parse, or validate fingerprints (JA3, JA4, Akamai, etc.)

**Rationale:**
- Fingerprint calculation is out of scope
- Focus is on ClientHello construction, not analysis
- Upper-layer applications should handle fingerprint analysis

**Impact:**
- Cannot verify that generated ClientHello matches target fingerprint
- Cannot import/export fingerprints
- Cannot compare fingerprints

**Workaround:**
- Use external tools for fingerprint calculation:
  - JA3: https://github.com/salesforce/ja3
  - JA4: https://github.com/FoxIO-LLC/ja4
- Capture and compare ClientHello wire bytes manually

**Example:**
```rust
// custls does NOT provide:
// let ja3 = calculate_ja3(&client_hello);  // ❌ Not available
// let ja4 = calculate_ja4(&client_hello);  // ❌ Not available

// Instead, use external tools or manual comparison
```

**Future Work:**
- Consider adding fingerprint calculation as optional feature
- Low priority (out of core scope)

---

### 2. Limited HTTP/2 Integration

**Limitation:** custls provides types for HTTP/2 coordination but does not implement HTTP/2 fingerprinting

**What Works:**
- ✅ `Http2Settings` type for configuration
- ✅ `PrioritySpec` type for priority frames
- ✅ Pseudo-header order specification

**What Doesn't Work:**
- ❌ No automatic HTTP/2 SETTINGS frame generation
- ❌ No HTTP/2 fingerprint simulation
- ❌ No coordination with HTTP/2 libraries

**Impact:**
- **Medium** - HTTP/2 fingerprinting is important for complete simulation
- TLS fingerprint is simulated, but HTTP/2 is separate
- Requires manual HTTP/2 configuration

**Workaround:**
- Configure HTTP/2 settings in your HTTP/2 library (e.g., h2, hyper)
- Use `Http2Settings` as a guide for configuration
- Manually coordinate TLS and HTTP/2 fingerprints

**Example:**
```rust
use rustls::custls::Http2Settings;

let http2_settings = Http2Settings {
    header_table_size: 65536,
    enable_push: false,
    max_concurrent_streams: 1000,
    initial_window_size: 6291456,
    max_frame_size: 16384,
    max_header_list_size: 262144,
    pseudo_header_order: vec![
        ":method".to_string(),
        ":authority".to_string(),
        ":scheme".to_string(),
        ":path".to_string(),
    ],
    priority_spec: None,
};

// Use these settings when configuring h2 or hyper
```

**Future Work:**
- Integration with h2 crate
- Automatic HTTP/2 fingerprint simulation
- Medium priority

---

### 3. No ECH (Encrypted Client Hello) Support

**Limitation:** custls hooks do not currently support ECH flows

**What Works:**
- ✅ Basic ClientHello customization
- ✅ Standard TLS 1.3 handshakes
- ✅ HelloRetryRequest flows

**What Doesn't Work:**
- ❌ ECH ClientHello customization
- ❌ ECH inner/outer ClientHello modification
- ❌ ECH-specific hooks

**Impact:**
- **Low** - ECH is not widely deployed yet
- Standard handshakes work fine
- ECH handshakes may not be customizable

**Workaround:**
- Disable ECH if customization is required
- Use standard ClientHello

**Future Work:**
- Add ECH-specific hooks
- Support inner/outer ClientHello customization
- Medium priority (as ECH adoption increases)

---

### 4. No Post-Quantum Hybrid Support

**Limitation:** custls does not provide special handling for post-quantum hybrid key exchange

**What Works:**
- ✅ Standard key exchange groups
- ✅ X25519, secp256r1, secp384r1, etc.

**What Doesn't Work:**
- ❌ No PQ hybrid group simulation
- ❌ No Kyber support
- ❌ No ML-KEM support

**Impact:**
- **Low** - PQ is not widely deployed yet
- Standard key exchange works fine
- Future-proofing concern

**Workaround:**
- Use standard key exchange groups
- Wait for browser adoption of PQ

**Future Work:**
- Add PQ hybrid group support
- Support Kyber/ML-KEM
- Low priority (waiting for standardization)

---

### 5. No QUIC Support

**Limitation:** custls is designed for TLS over TCP, not QUIC

**What Works:**
- ✅ TLS 1.3 over TCP
- ✅ Standard ClientHello customization

**What Doesn't Work:**
- ❌ QUIC ClientHello customization
- ❌ QUIC-specific extensions
- ❌ QUIC transport parameters

**Impact:**
- **Medium** - QUIC is increasingly important
- HTTP/3 uses QUIC
- Cannot simulate QUIC fingerprints

**Workaround:**
- Use TLS over TCP (HTTP/1.1, HTTP/2)
- Wait for QUIC support

**Future Work:**
- Add QUIC ClientHello customization
- Support QUIC transport parameters
- High priority for HTTP/3 support

---

## Template Limitations

### 1. Template Staleness

**Limitation:** Browser templates become outdated as browsers update

**Impact:**
- **Medium** - Browsers update frequently
- Templates may not match latest browser versions
- Fingerprinting systems may detect outdated templates

**Workaround:**
- Update templates regularly
- Capture new templates when browsers update
- Use template rotation to reduce detection

**Mitigation:**
- Quarterly template updates recommended
- Monitor browser release notes
- Re-capture templates after major updates

**Example:**
```rust
// Template may be outdated
let config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Chrome130)  // May not match Chrome 131+
    .build();

// Use rotation to reduce impact
let config = CustlsConfig::builder()
    .with_rotation_policy(TemplateRotationPolicy::WeightedRandom)
    .with_rotation_templates(vec![
        BrowserTemplate::Chrome130,
        BrowserTemplate::Firefox135,
        BrowserTemplate::Edge130,
    ])
    .build();
```

---

### 2. OS-Specific Variations

**Limitation:** Templates may not capture OS-specific browser variations

**Impact:**
- **Low** - Most browser characteristics are OS-independent
- Some subtle differences exist (e.g., cipher suite order)
- May be detectable by advanced fingerprinting

**Workaround:**
- Capture templates on target OS
- Create OS-specific templates if needed
- Use randomization to mask differences

**Example:**
```rust
// Template captured on Windows may differ from macOS
// Consider creating OS-specific templates:
// BrowserTemplate::Chrome130Windows
// BrowserTemplate::Chrome130MacOS
// BrowserTemplate::Chrome130Linux
```

---

### 3. Mobile Browser Support

**Limitation:** Limited mobile browser templates

**Impact:**
- **Medium** - Mobile traffic is significant
- Mobile browsers have different characteristics
- Cannot simulate mobile fingerprints well

**Workaround:**
- Capture mobile browser templates
- Create mobile-specific templates
- Use desktop templates as fallback

**Future Work:**
- Add iOS Safari templates
- Add Android Chrome templates
- Medium priority

---

## Performance Limitations

### 1. Randomization Overhead

**Limitation:** Randomization adds latency to ClientHello generation

**Impact:**
- **Low** - <10% overhead for light randomization
- <20% overhead for high randomization
- Acceptable for most use cases

**Workaround:**
- Use light randomization for performance
- Disable randomization in tests
- Use zero-overhead mode if needed

**Example:**
```rust
// For maximum performance
let config = CustlsConfig::builder()
    .with_randomization_level(RandomizationLevel::None)
    .with_cache(false)
    .build();
```

---

### 2. Cache Memory Usage

**Limitation:** Fingerprint cache consumes memory

**Impact:**
- **Low** - ~1KB per cached entry
- 1000 entries = ~1MB
- Acceptable for most applications

**Workaround:**
- Limit cache size
- Clear cache periodically
- Disable cache if memory is constrained

**Example:**
```rust
let config = CustlsConfig::builder()
    .with_cache(true)
    .with_max_cache_size(500)  // Limit to 500 entries
    .build();
```

---

## Security Limitations

### 1. No Additional Security Guarantees

**Limitation:** custls does not add security beyond rustls

**What custls Provides:**
- ✅ Preserves all rustls security guarantees
- ✅ Zero unsafe code
- ✅ RFC 8446 downgrade protection
- ✅ Certificate validation unchanged

**What custls Does NOT Provide:**
- ❌ No additional encryption
- ❌ No additional authentication
- ❌ No additional privacy (beyond fingerprint simulation)

**Impact:**
- **None** - custls is not a security enhancement
- Security is identical to rustls
- Focus is on fingerprint simulation, not security

---

### 2. Fingerprint Simulation is Not Anonymity

**Limitation:** Simulating a browser fingerprint does not provide anonymity

**Important:**
- Fingerprint simulation helps avoid detection
- Does NOT provide anonymity like Tor
- Other identifying information may still leak:
  - IP address
  - HTTP headers
  - Cookies
  - Timing patterns
  - Application behavior

**Workaround:**
- Use Tor or VPN for anonymity
- Coordinate TLS, HTTP, and application-level fingerprints
- Consider all identifying factors

---

## Known Issues

### 1. GREASE Value Collisions

**Issue:** GREASE values may occasionally collide with real values

**Impact:**
- **Very Low** - Extremely rare
- May cause confusion in debugging
- Does not affect handshake success

**Workaround:**
- Use standard GREASE values (0x?a?a pattern)
- Avoid custom GREASE values

---

### 2. Padding Length Limits

**Issue:** Padding extension has maximum length of 65535 bytes

**Impact:**
- **Very Low** - Browsers rarely use >1500 bytes
- May not match extreme edge cases
- Does not affect normal operation

**Workaround:**
- Use realistic padding lengths (0-1500 bytes)
- Follow browser distributions

---

### 3. Extension Order Constraints

**Issue:** Some extension orders are invalid per TLS spec

**Impact:**
- **Low** - Naturalness filter prevents most issues
- PSK must be last (enforced)
- Some combinations are blacklisted

**Workaround:**
- Use built-in templates (already validated)
- Test custom templates thoroughly
- Follow TLS specifications

---

## Future Work

### High Priority

1. **QUIC Support** - Enable QUIC ClientHello customization
2. **HTTP/2 Integration** - Automatic HTTP/2 fingerprint simulation
3. **Mobile Templates** - iOS Safari and Android Chrome templates

### Medium Priority

4. **ECH Support** - Encrypted Client Hello customization
5. **Certificate Compression** - Implement decompression
6. **Template Updates** - Quarterly browser template updates
7. **PQ Hybrid Support** - Post-quantum key exchange

### Low Priority

8. **Fingerprint Calculation** - Optional JA3/JA4 calculation
9. **OCSP Processing** - Full OCSP support
10. **SCT Verification** - Certificate Transparency support
11. **Delegated Credentials** - Full delegation support

---

## Reporting Issues

If you encounter limitations not documented here:

1. **Check existing issues:** https://github.com/rustls/rustls/issues
2. **Open new issue:** Tag with `custls` and `limitation`
3. **Provide details:**
   - What you're trying to do
   - What doesn't work
   - Expected behavior
   - Actual behavior
   - Workarounds attempted

---

## Contributing

Help address these limitations:

1. **Implement stub extensions:** Full functionality for stubs
2. **Create templates:** Capture and contribute browser templates
3. **Add tests:** Test edge cases and limitations
4. **Improve documentation:** Document workarounds and solutions

See [CONTRIBUTING.md](../../../CONTRIBUTING.md) for details.

---

## Summary

custls is designed for ClientHello fingerprint simulation, not full protocol implementation. Key limitations:

**Stub Extensions:**
- ApplicationSettings, DelegatedCredential, CompressCertificate, StatusRequest, SignedCertificateTimestamp
- Encode correctly but lack full functionality
- Sufficient for fingerprint simulation

**Functional Limitations:**
- No fingerprint calculation (out of scope)
- Limited HTTP/2 integration (manual configuration needed)
- No ECH support (future work)
- No QUIC support (future work)

**Template Limitations:**
- Templates become outdated (update regularly)
- Limited OS-specific variations (capture as needed)
- Limited mobile support (future work)

**Performance:**
- <10% overhead for light randomization
- Acceptable for most use cases
- Zero-overhead mode available

**Security:**
- Preserves all rustls security guarantees
- Does not add additional security
- Fingerprint simulation ≠ anonymity

Despite these limitations, custls provides powerful ClientHello customization for browser fingerprint simulation while maintaining rustls's security and performance characteristics.
