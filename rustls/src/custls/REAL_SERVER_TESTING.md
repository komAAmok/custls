# Real Server Testing Guide

This guide explains how to test custls against real TLS servers, including those with advanced fingerprinting systems.

## Overview

Testing against real servers validates that:
1. custls-generated ClientHello messages are accepted by production servers
2. Handshakes complete successfully with major CDN providers
3. Fingerprinting systems (Cloudflare, Akamai) don't block connections
4. Browser templates work in real-world scenarios

## Test Targets

### Cloudflare
- **URL**: https://www.cloudflare.com
- **Features**: Bot Management, TLS fingerprinting, JA3/JA4 analysis
- **Expected**: Successful handshake with all browser templates
- **Notes**: Cloudflare uses sophisticated fingerprinting; good test of template fidelity

### Akamai
- **URL**: https://www.akamai.com
- **Features**: Bot Manager, TLS fingerprinting, behavioral analysis
- **Expected**: Successful handshake with all browser templates
- **Notes**: Akamai has strict fingerprinting; tests naturalness filtering

### Google
- **URL**: https://www.google.com
- **Features**: Standard TLS 1.3, modern cipher suites
- **Expected**: Successful handshake with all templates
- **Notes**: Good baseline test for TLS 1.3 compatibility

### Amazon
- **URL**: https://www.amazon.com
- **Features**: AWS infrastructure, standard TLS
- **Expected**: Successful handshake with all templates
- **Notes**: Tests compatibility with AWS-hosted services

## Manual Testing

### Prerequisites
```bash
# Install rustls examples
cd rustls/examples
cargo build --release
```

### Test Procedure

1. **Test with vanilla rustls (baseline)**:
```bash
cargo run --release --bin simpleclient -- www.cloudflare.com
```

2. **Test with custls Chrome template**:
```rust
// In your test code
let config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Chrome130)
    .with_randomization_level(RandomizationLevel::Light)
    .build();

// Create ClientConfig with custls
// Perform handshake
```

3. **Test with each browser template**:
- Chrome 130
- Firefox 135
- Safari 17
- Edge 130

4. **Test with different randomization levels**:
- None (exact template)
- Light (small variations)
- Medium (moderate variations)
- High (maximum variations)

### Success Criteria

For each test:
- ✅ TLS handshake completes successfully
- ✅ No certificate validation errors
- ✅ HTTP response received (if applicable)
- ✅ No connection refused or timeout errors
- ✅ No fingerprinting-related blocks

## Automated Testing

### Integration Test Structure

```rust
#[cfg(feature = "real_server_tests")]
mod real_server_tests {
    use super::*;
    
    #[test]
    #[ignore] // Run with --ignored flag
    fn test_cloudflare_chrome_template() {
        // Test Cloudflare with Chrome template
    }
    
    #[test]
    #[ignore]
    fn test_akamai_firefox_template() {
        // Test Akamai with Firefox template
    }
    
    // ... more tests
}
```

### Running Automated Tests

```bash
# Run all real server tests (requires network)
cargo test --features real_server_tests -- --ignored --test-threads=1

# Run specific test
cargo test --features real_server_tests test_cloudflare_chrome_template -- --ignored
```

## Fingerprinting Analysis

### JA3 Fingerprint Comparison

1. **Capture JA3 from real browser**:
```bash
# Use ja3er.com or similar service
curl -v https://ja3er.com/json
```

2. **Capture JA3 from custls**:
```rust
// Generate ClientHello with custls
// Calculate JA3 hash
// Compare with real browser JA3
```

3. **Expected**: JA3 hashes should be similar (not identical due to randomization)

### JA4 Fingerprint Comparison

Similar process for JA4 fingerprints, which include:
- TLS version
- SNI
- Cipher suites
- Extensions
- Signature algorithms

## Troubleshooting

### Connection Refused
- **Cause**: Server blocking based on fingerprint
- **Solution**: Adjust template or randomization level
- **Check**: Verify GREASE values, extension order, padding

### Certificate Validation Errors
- **Cause**: Not related to custls (rustls core issue)
- **Solution**: Check root certificates, system time
- **Note**: custls doesn't modify certificate validation

### Timeout Errors
- **Cause**: Network issues or server overload
- **Solution**: Retry with backoff, check network connectivity
- **Note**: Not related to custls fingerprinting

### Handshake Failures
- **Cause**: Incompatible cipher suites or extensions
- **Solution**: Review template configuration
- **Check**: Ensure template matches target browser version

## Continuous Testing

### CI/CD Integration

```yaml
# .github/workflows/real-server-tests.yml
name: Real Server Tests

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly
  workflow_dispatch:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run real server tests
        run: cargo test --features real_server_tests -- --ignored
```

### Monitoring

Track success rates over time:
- Cloudflare: 95%+ success rate expected
- Akamai: 90%+ success rate expected
- Google: 99%+ success rate expected
- Amazon: 99%+ success rate expected

Lower success rates may indicate:
- Template needs updating (browser version changed)
- Fingerprinting systems evolved
- Network issues

## Security Considerations

### Rate Limiting
- Don't hammer servers with tests
- Use reasonable delays between requests
- Respect robots.txt and terms of service

### Privacy
- Don't send real user data in tests
- Use test accounts where applicable
- Clear cookies/session data between tests

### Legal
- Ensure testing complies with terms of service
- Don't attempt to bypass security measures maliciously
- Use for legitimate compatibility testing only

## Reporting Issues

If tests fail consistently:

1. **Document the failure**:
   - Server URL
   - Browser template used
   - Randomization level
   - Error message
   - Wireshark capture (if possible)

2. **Check for updates**:
   - Has the browser version changed?
   - Has the server's TLS configuration changed?
   - Are there new extensions or cipher suites?

3. **File an issue**:
   - Include all documentation
   - Provide reproduction steps
   - Suggest potential fixes

## Future Enhancements

- Automated JA3/JA4 comparison
- Fingerprint database for tracking changes
- Machine learning for template optimization
- Real-time monitoring dashboard
- A/B testing framework for templates

## References

- [JA3 Fingerprinting](https://github.com/salesforce/ja3)
- [JA4 Fingerprinting](https://github.com/FoxIO-LLC/ja4)
- [Cloudflare Bot Management](https://www.cloudflare.com/products/bot-management/)
- [Akamai Bot Manager](https://www.akamai.com/products/bot-manager)
- [TLS 1.3 RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)
