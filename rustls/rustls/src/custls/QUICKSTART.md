# custls Quickstart Guide

## Introduction

custls is a minimal-invasive extension to rustls that provides browser-level TLS ClientHello fingerprint simulation. This guide will help you get started quickly.

## Installation

Add custls (rustls with custls module) to your `Cargo.toml`:

```toml
[dependencies]
rustls = { version = "0.23", features = ["custls"] }
```

## Basic Usage

### 1. Simple Browser Simulation

The simplest way to use custls is with a built-in browser template:

```rust
use rustls::custls::{CustlsConfig, BrowserTemplate, RandomizationLevel};
use rustls::custls::DefaultCustomizer;

// Create configuration
let config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Chrome130)
    .with_randomization_level(RandomizationLevel::Light)
    .build();

// Create customizer
let customizer = DefaultCustomizer::new(config)
    .with_target("example.com".to_string(), 443);

// Use with rustls ClientConfig
// (Integration with rustls ClientConfig is done through hooks)
```

### 2. Using Different Browser Templates

custls provides templates for major browsers:

```rust
use rustls::custls::BrowserTemplate;

// Chrome 130+
let chrome = BrowserTemplate::Chrome130;

// Firefox 135+
let firefox = BrowserTemplate::Firefox135;

// Safari 17+
let safari = BrowserTemplate::Safari17;

// Edge 130+
let edge = BrowserTemplate::Edge130;
```

### 3. Adjusting Randomization Level

Control how much variation is applied:

```rust
use rustls::custls::RandomizationLevel;

// No randomization - use template exactly
let none = RandomizationLevel::None;

// Light randomization - small browser-style perturbations (default)
let light = RandomizationLevel::Light;

// Medium randomization - moderate variation
let medium = RandomizationLevel::Medium;

// High randomization - maximum variation within naturalness constraints
let high = RandomizationLevel::High;
```

### 4. Enabling Fingerprint Cache

The cache stores working fingerprints for reuse:

```rust
let config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Chrome130)
    .with_cache(true)  // Enable cache (default)
    .with_max_cache_size(1000)  // Maximum 1000 entries
    .build();
```

### 5. Template Rotation

Automatically rotate between different browser templates:

```rust
use rustls::custls::TemplateRotationPolicy;

let config = CustlsConfig::builder()
    .with_rotation_policy(TemplateRotationPolicy::RoundRobin)
    .with_rotation_templates(vec![
        BrowserTemplate::Chrome130,
        BrowserTemplate::Firefox135,
        BrowserTemplate::Safari17,
    ])
    .build();
```

## Common Configuration Examples

### Example 1: Stealth Mode (Maximum Anti-Fingerprinting)

```rust
use rustls::custls::{CustlsConfig, BrowserTemplate, RandomizationLevel, TemplateRotationPolicy};
use rustls::custls::TimingJitterConfig;

let config = CustlsConfig::builder()
    .with_rotation_policy(TemplateRotationPolicy::WeightedRandom)
    .with_rotation_templates(vec![
        BrowserTemplate::Chrome130,
        BrowserTemplate::Firefox135,
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

### Example 2: Consistent Chrome Simulation

```rust
let config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Chrome130)
    .with_randomization_level(RandomizationLevel::Light)
    .with_cache(true)
    .build();
```

### Example 3: Zero-Overhead Mode

```rust
// Disable all customization for vanilla rustls behavior
let config = CustlsConfig::builder()
    .with_randomization_level(RandomizationLevel::None)
    .with_cache(false)
    .build();
```

### Example 4: Firefox with Medium Variation

```rust
let config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Firefox135)
    .with_randomization_level(RandomizationLevel::Medium)
    .with_cache(true)
    .with_max_cache_size(2000)
    .build();
```

## Working with the Cache

### Recording Handshake Results

The cache automatically tracks success/failure rates:

```rust
use rustls::custls::{FingerprintManager, TargetKey};

let mut manager = FingerprintManager::new(1000);
let target = TargetKey::new("example.com".to_string(), 443);

// After successful handshake
manager.record_result(&target, true);

// After failed handshake
manager.record_result(&target, false);
```

### Clearing the Cache

```rust
// Clear all cached fingerprints
manager.clear_cache();

// Invalidate specific target
manager.invalidate_target(&target);
```

## Custom Hooks

For advanced use cases, implement the `ClientHelloCustomizer` trait:

```rust
use rustls::custls::{ClientHelloCustomizer, ConfigParams, ClientHelloPayload};
use rustls::Error;

struct MyCustomizer;

impl ClientHelloCustomizer for MyCustomizer {
    fn on_config_resolve(&self, config: &mut ConfigParams) -> Result<(), Error> {
        // Phase 1: Modify configuration before ClientHello construction
        Ok(())
    }
    
    fn on_components_ready(
        &self,
        cipher_suites: &mut Vec<CipherSuite>,
        extensions: &mut Vec<ClientExtension>,
    ) -> Result<(), Error> {
        // Phase 2: Modify cipher suites and extensions during construction
        Ok(())
    }
    
    fn on_struct_ready(&self, payload: &mut ClientHelloPayload) -> Result<(), Error> {
        // Phase 3: Modify complete ClientHelloPayload before serialization
        Ok(())
    }
    
    fn transform_wire_bytes(&self, bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
        // Phase 4: Transform final wire bytes
        Ok(bytes)
    }
}
```

See [examples/custls_custom_hooks.rs](../../examples/custls_custom_hooks.rs) for a complete example.

## HTTP/2 Coordination

custls provides types for coordinating TLS and HTTP/2 fingerprints:

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
```

## Timing Jitter

Add timing jitter to prevent behavioral fingerprinting:

```rust
use rustls::custls::TimingJitterConfig;

let jitter = TimingJitterConfig {
    min_delay_micros: 100,      // Minimum 100 microseconds
    max_delay_micros: 5000,     // Maximum 5 milliseconds
    apply_probability: 0.3,     // Apply 30% of the time
};

let config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Chrome130)
    .with_timing_jitter(jitter)
    .build();
```

## Error Handling

custls errors convert to `rustls::Error`:

```rust
use rustls::custls::CustlsError;
use rustls::Error;

fn handle_custls_error(error: CustlsError) {
    let rustls_error: Error = error.into();
    eprintln!("Error: {:?}", rustls_error);
}
```

## Performance Considerations

custls is designed for minimal overhead:

- **Light randomization**: <10% overhead
- **Cache lookups**: <1ms
- **Randomization**: <5ms
- **Zero-overhead mode**: No performance impact

For maximum performance, use:
```rust
let config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Chrome130)
    .with_randomization_level(RandomizationLevel::None)
    .with_cache(false)
    .build();
```

## Security Notes

custls preserves all rustls security guarantees:

- ✅ Zero unsafe code
- ✅ RFC 8446 downgrade protection
- ✅ Certificate validation unchanged
- ✅ Constant-time cryptographic operations

**Important:** custls does NOT calculate or validate fingerprints (JA3, JA4, etc.). It only constructs ClientHello messages. Fingerprint analysis is the responsibility of upper-layer applications.

## Debugging

Enable logging to see custls operations:

```rust
// In your Cargo.toml
[dependencies]
rustls = { version = "0.23", features = ["custls", "logging"] }
env_logger = "0.11"

// In your code
env_logger::init();
```

## Next Steps

- **Custom Templates**: See [TEMPLATE_GUIDE.md](TEMPLATE_GUIDE.md) for creating custom templates
- **Advanced Hooks**: See [examples/custls_custom_hooks.rs](../../examples/custls_custom_hooks.rs)
- **Migration**: See [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) for migrating from vanilla rustls
- **API Reference**: See [API.md](API.md) for complete API documentation

## Examples

Complete working examples are available in the `examples/` directory:

- `custls_basic_usage.rs` - Basic template usage
- `custls_custom_hooks.rs` - Custom hook implementation
- `custls_custom_template.rs` - Custom template creation
- `custls_zero_overhead.rs` - Zero-overhead mode

Run an example:
```bash
cargo run --example custls_basic_usage
```

## Troubleshooting

### Build Errors

If you encounter build errors related to aws-lc-rs:

**Windows**: Install NASM
```bash
# Using Chocolatey
choco install nasm

# Or download from https://www.nasm.us/
```

**Linux**: Install build dependencies
```bash
# Ubuntu/Debian
sudo apt-get install build-essential cmake

# Fedora/RHEL
sudo dnf install gcc cmake
```

**macOS**: Install Xcode Command Line Tools
```bash
xcode-select --install
```

### Runtime Issues

**Issue**: Handshakes failing with customization enabled

**Solution**: Try reducing randomization level:
```rust
.with_randomization_level(RandomizationLevel::Light)
```

**Issue**: Cache not working as expected

**Solution**: Ensure you're recording results:
```rust
manager.record_result(&target, success);
```

## Support

For issues, questions, or contributions:
- GitHub Issues: [rustls/custls](https://github.com/rustls/rustls)
- Documentation: [API.md](API.md)
- Examples: `examples/` directory

## License

custls is part of rustls and follows the same licensing:
- Apache License 2.0
- ISC License
- MIT License
