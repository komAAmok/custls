# Migration Guide: From Vanilla rustls to custls

## Introduction

This guide helps you migrate from vanilla rustls to custls, enabling browser-level TLS ClientHello fingerprint simulation in your application.

## Overview

custls is a minimal-invasive extension to rustls. Migration is straightforward:
- **No breaking changes** to existing rustls API
- **Opt-in customization** - works like vanilla rustls by default
- **Backward compatible** - existing code continues to work
- **Zero overhead** when customization is disabled

## Migration Levels

Choose your migration level based on your needs:

1. **Level 1: Drop-in Replacement** - Replace rustls with custls, no code changes
2. **Level 2: Basic Customization** - Add browser template simulation
3. **Level 3: Advanced Customization** - Use custom hooks and templates
4. **Level 4: Full Integration** - Integrate with HTTP/2 fingerprinting

## Level 1: Drop-in Replacement

### Step 1: Update Dependencies

**Before (vanilla rustls):**
```toml
[dependencies]
rustls = "0.23"
```

**After (custls):**
```toml
[dependencies]
rustls = { version = "0.23", features = ["custls"] }
```

### Step 2: Verify

Your existing code should work without changes:

```rust
// Existing code - no changes needed
use rustls::{ClientConfig, RootCertStore};

let mut root_store = RootCertStore::empty();
root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

let config = ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_no_client_auth();

// Works exactly as before
```

### Step 3: Test

```bash
cargo test
cargo run
```

**Result:** Your application works identically to vanilla rustls.

## Level 2: Basic Customization

### Step 1: Add custls Configuration

Add browser template simulation:

```rust
use rustls::{ClientConfig, RootCertStore};
use rustls::custls::{CustlsConfig, BrowserTemplate, RandomizationLevel};
use rustls::custls::DefaultCustomizer;

// Create custls configuration
let custls_config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Chrome130)
    .with_randomization_level(RandomizationLevel::Light)
    .with_cache(true)
    .build();

// Create customizer
let customizer = DefaultCustomizer::new(custls_config);

// Create rustls config as before
let mut root_store = RootCertStore::empty();
root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

let config = ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_no_client_auth();

// Note: Integration with ClientConfig is done through hooks
// The customizer is applied automatically during handshake
```

### Step 2: Set Target for Cache

For cache to work, set the target:

```rust
let customizer = DefaultCustomizer::new(custls_config)
    .with_target("example.com".to_string(), 443);
```

### Step 3: Test

```bash
cargo test
cargo run
```

**Result:** Your ClientHello now simulates Chrome 130+ with light randomization.

## Level 3: Advanced Customization

### Custom Hooks

Implement custom ClientHello modification logic:

**Before:**
```rust
// No customization possible
let config = ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_no_client_auth();
```

**After:**
```rust
use rustls::custls::{ClientHelloCustomizer, ConfigParams, ClientHelloPayload};
use rustls::Error;

struct MyCustomizer;

impl ClientHelloCustomizer for MyCustomizer {
    fn on_struct_ready(&self, payload: &mut ClientHelloPayload) -> Result<(), Error> {
        // Custom modification logic
        // Example: Add custom extension
        Ok(())
    }
}

// Use custom customizer
let customizer = MyCustomizer;
// Apply to ClientConfig (implementation depends on integration)
```

### Custom Templates

Create your own browser template:

**Before:**
```rust
// Limited to rustls defaults
```

**After:**
```rust
use rustls::custls::{BrowserTemplate, CustomTemplate};

let custom_template = CustomTemplate {
    name: "MyBrowser".to_string(),
    description: "Custom browser simulation".to_string(),
};

let custls_config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Custom(Box::new(custom_template)))
    .build();
```

See [TEMPLATE_GUIDE.md](TEMPLATE_GUIDE.md) for details on creating custom templates.

## Level 4: Full Integration

### HTTP/2 Coordination

Coordinate TLS and HTTP/2 fingerprints:

```rust
use rustls::custls::{Http2Settings, PrioritySpec};

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
    priority_spec: Some(PrioritySpec {
        stream_dependency: 0,
        weight: 255,
        exclusive: false,
    }),
};

// Use http2_settings when configuring HTTP/2 client
```

### Timing Jitter

Add timing jitter for anti-fingerprinting:

```rust
use rustls::custls::TimingJitterConfig;

let custls_config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Chrome130)
    .with_timing_jitter(TimingJitterConfig {
        min_delay_micros: 100,
        max_delay_micros: 5000,
        apply_probability: 0.3,
    })
    .build();
```

## Common Migration Patterns

### Pattern 1: Simple HTTPS Client

**Before:**
```rust
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

fn create_client_config() -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    )
}
```

**After:**
```rust
use rustls::{ClientConfig, RootCertStore};
use rustls::custls::{CustlsConfig, BrowserTemplate, DefaultCustomizer};
use std::sync::Arc;

fn create_client_config() -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    
    // Add custls configuration
    let custls_config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .build();
    
    let customizer = DefaultCustomizer::new(custls_config);
    
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    )
}
```

### Pattern 2: Web Scraper

**Before:**
```rust
use rustls::ClientConfig;
use reqwest::Client;

async fn create_scraper() -> Client {
    Client::builder()
        .use_rustls_tls()
        .build()
        .unwrap()
}
```

**After:**
```rust
use rustls::ClientConfig;
use rustls::custls::{CustlsConfig, BrowserTemplate, TemplateRotationPolicy};
use reqwest::Client;

async fn create_scraper() -> Client {
    // Rotate between browser templates for stealth
    let custls_config = CustlsConfig::builder()
        .with_rotation_policy(TemplateRotationPolicy::WeightedRandom)
        .with_rotation_templates(vec![
            BrowserTemplate::Chrome130,
            BrowserTemplate::Firefox135,
            BrowserTemplate::Edge130,
        ])
        .build();
    
    Client::builder()
        .use_rustls_tls()
        .build()
        .unwrap()
}
```

### Pattern 3: API Client

**Before:**
```rust
use rustls::ClientConfig;

fn create_api_client() -> ClientConfig {
    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}
```

**After:**
```rust
use rustls::ClientConfig;
use rustls::custls::{CustlsConfig, BrowserTemplate, RandomizationLevel};

fn create_api_client() -> ClientConfig {
    // Use consistent fingerprint for API
    let custls_config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_randomization_level(RandomizationLevel::None)  // No randomization
        .with_cache(true)  // Reuse working fingerprint
        .build();
    
    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}
```

### Pattern 4: Testing/Development

**Before:**
```rust
#[cfg(test)]
mod tests {
    use rustls::ClientConfig;
    
    #[test]
    fn test_connection() {
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        // ... test ...
    }
}
```

**After:**
```rust
#[cfg(test)]
mod tests {
    use rustls::ClientConfig;
    use rustls::custls::{CustlsConfig, RandomizationLevel};
    
    #[test]
    fn test_connection() {
        // Disable customization for faster tests
        let custls_config = CustlsConfig::builder()
            .with_randomization_level(RandomizationLevel::None)
            .with_cache(false)
            .build();
        
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        // ... test ...
    }
}
```

## API Differences

### No Breaking Changes

custls maintains full backward compatibility with rustls:

| rustls API | custls API | Notes |
|------------|------------|-------|
| `ClientConfig::builder()` | Same | No changes |
| `with_root_certificates()` | Same | No changes |
| `with_no_client_auth()` | Same | No changes |
| All existing methods | Same | No changes |

### New APIs

custls adds new APIs without breaking existing ones:

| API | Purpose |
|-----|---------|
| `CustlsConfig` | Configure customization |
| `BrowserTemplate` | Browser presets |
| `RandomizationLevel` | Control variation |
| `ClientHelloCustomizer` | Custom hooks |
| `DefaultCustomizer` | Built-in customizer |
| `FingerprintManager` | Cache management |

## Configuration Examples

### Example 1: Maximum Stealth

```rust
use rustls::custls::{
    CustlsConfig, BrowserTemplate, RandomizationLevel,
    TemplateRotationPolicy, TimingJitterConfig
};

let config = CustlsConfig::builder()
    .with_rotation_policy(TemplateRotationPolicy::WeightedRandom)
    .with_rotation_templates(vec![
        BrowserTemplate::Chrome130,
        BrowserTemplate::Firefox135,
        BrowserTemplate::Safari17,
        BrowserTemplate::Edge130,
    ])
    .with_randomization_level(RandomizationLevel::High)
    .with_cache(true)
    .with_timing_jitter(TimingJitterConfig {
        min_delay_micros: 100,
        max_delay_micros: 5000,
        apply_probability: 0.3,
    })
    .build();
```

### Example 2: Consistent Chrome

```rust
let config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Chrome130)
    .with_randomization_level(RandomizationLevel::Light)
    .with_cache(true)
    .build();
```

### Example 3: Zero Overhead

```rust
let config = CustlsConfig::builder()
    .with_randomization_level(RandomizationLevel::None)
    .with_cache(false)
    .build();
```

### Example 4: Custom Template

```rust
let custom = CustomTemplate {
    name: "MyBrowser".to_string(),
    description: "Custom browser".to_string(),
};

let config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Custom(Box::new(custom)))
    .build();
```

## Performance Considerations

### Overhead

custls introduces minimal overhead:

| Configuration | Overhead |
|---------------|----------|
| Zero-overhead mode | 0% |
| Light randomization | <10% |
| Medium randomization | <15% |
| High randomization | <20% |

### Optimization Tips

1. **Disable in tests:**
   ```rust
   #[cfg(not(test))]
   let custls_config = CustlsConfig::builder()
       .with_template(BrowserTemplate::Chrome130)
       .build();
   
   #[cfg(test)]
   let custls_config = CustlsConfig::builder()
       .with_randomization_level(RandomizationLevel::None)
       .build();
   ```

2. **Use cache:**
   ```rust
   .with_cache(true)  // Reuse working fingerprints
   ```

3. **Lower randomization:**
   ```rust
   .with_randomization_level(RandomizationLevel::Light)
   ```

## Error Handling

### Error Conversion

custls errors convert to rustls errors:

**Before:**
```rust
match result {
    Ok(conn) => { /* ... */ },
    Err(e) => eprintln!("rustls error: {:?}", e),
}
```

**After:**
```rust
use rustls::custls::CustlsError;

match result {
    Ok(conn) => { /* ... */ },
    Err(e) => {
        // custls errors are rustls::Error::General
        eprintln!("Error: {:?}", e);
    }
}
```

### Handling Customization Errors

```rust
use rustls::custls::{DefaultCustomizer, CustlsConfig};

let custls_config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Chrome130)
    .build();

match DefaultCustomizer::new(custls_config).with_target("example.com".to_string(), 443) {
    customizer => {
        // Use customizer
    }
}
```

## Testing

### Unit Tests

**Before:**
```rust
#[test]
fn test_tls_connection() {
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    // ... test ...
}
```

**After:**
```rust
#[test]
fn test_tls_connection() {
    let custls_config = CustlsConfig::builder()
        .with_randomization_level(RandomizationLevel::None)
        .build();
    
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    // ... test ...
}
```

### Integration Tests

Test with real servers:

```rust
#[tokio::test]
async fn test_cloudflare_connection() {
    let custls_config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .build();
    
    let customizer = DefaultCustomizer::new(custls_config)
        .with_target("www.cloudflare.com".to_string(), 443);
    
    // Perform connection
    // Verify: No blocks, no challenges
}
```

## Troubleshooting

### Issue: Build errors

**Symptom:** Compilation fails with custls

**Solution:**
```bash
# Install build dependencies
# Windows: Install NASM
# Linux: sudo apt-get install build-essential cmake
# macOS: xcode-select --install
```

### Issue: Handshakes failing

**Symptom:** Connections fail with custls enabled

**Solution:**
```rust
// Try lower randomization
.with_randomization_level(RandomizationLevel::Light)

// Or disable customization
.with_randomization_level(RandomizationLevel::None)
```

### Issue: Performance degradation

**Symptom:** Slower connection establishment

**Solution:**
```rust
// Use zero-overhead mode
.with_randomization_level(RandomizationLevel::None)
.with_cache(false)
```

### Issue: Cache not working

**Symptom:** Fingerprints not being reused

**Solution:**
```rust
// Ensure target is set
let customizer = DefaultCustomizer::new(custls_config)
    .with_target(host, port);  // Must set target

// Ensure cache is enabled
.with_cache(true)
```

## Rollback

If you need to rollback to vanilla rustls:

### Step 1: Update Dependencies

```toml
[dependencies]
rustls = "0.23"  # Remove custls feature
```

### Step 2: Remove custls Code

```rust
// Remove custls imports
// use rustls::custls::*;  // Remove

// Remove custls configuration
// let custls_config = ...;  // Remove
```

### Step 3: Test

```bash
cargo clean
cargo test
cargo run
```

## Best Practices

1. **Start simple:** Begin with Level 1 or 2 migration
2. **Test thoroughly:** Test with real servers
3. **Monitor performance:** Benchmark before and after
4. **Use appropriate randomization:** Light for most cases
5. **Enable cache:** Reuse working fingerprints
6. **Document configuration:** Note why you chose specific settings
7. **Update regularly:** Keep custls updated with upstream rustls

## Next Steps

After migration:

1. **Read the Quickstart:** [QUICKSTART.md](QUICKSTART.md)
2. **Explore examples:** Check `examples/` directory
3. **Create custom templates:** [TEMPLATE_GUIDE.md](TEMPLATE_GUIDE.md)
4. **Review API docs:** [API.md](API.md)
5. **Join community:** GitHub discussions

## Support

For migration help:
- GitHub Issues: Tag with `migration`
- Examples: `examples/` directory
- Documentation: [API.md](API.md)

## Conclusion

Migrating from vanilla rustls to custls is straightforward:
- **Level 1:** Zero code changes, drop-in replacement
- **Level 2:** Add browser simulation with minimal changes
- **Level 3:** Custom hooks and templates for advanced use
- **Level 4:** Full integration with HTTP/2 fingerprinting

Choose the level that fits your needs and migrate incrementally. custls maintains full backward compatibility, so you can adopt features at your own pace.
