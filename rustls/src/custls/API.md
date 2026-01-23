# custls API Documentation

## Overview

custls provides browser-level TLS ClientHello fingerprint simulation capabilities for rustls. This document describes all public types, functions, and their usage.

## Core Types

### CustlsConfig

Main configuration structure for custls customization.

```rust
pub struct CustlsConfig {
    pub template: Option<BrowserTemplate>,
    pub randomization_level: RandomizationLevel,
    pub enable_cache: bool,
    pub max_cache_size: usize,
    pub rotation_policy: TemplateRotationPolicy,
    pub rotation_templates: Vec<BrowserTemplate>,
    pub timing_jitter: Option<TimingJitterConfig>,
}
```

**Fields:**
- `template`: Browser template to simulate (optional)
- `randomization_level`: Intensity of randomization (None, Light, Medium, High)
- `enable_cache`: Enable working fingerprint cache
- `max_cache_size`: Maximum number of cached fingerprints
- `rotation_policy`: How to rotate templates across connections
- `rotation_templates`: Templates to rotate through
- `timing_jitter`: Timing jitter configuration for anti-fingerprinting

**Example:**
```rust
use rustls::custls::{CustlsConfig, BrowserTemplate, RandomizationLevel};

let config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Chrome130)
    .with_randomization_level(RandomizationLevel::Light)
    .with_cache(true)
    .build();
```

### CustlsConfigBuilder

Builder for constructing CustlsConfig instances.

**Methods:**
- `new()` - Create a new builder with default values
- `with_template(template: BrowserTemplate)` - Set the browser template
- `with_randomization_level(level: RandomizationLevel)` - Set randomization intensity
- `with_cache(enable: bool)` - Enable/disable fingerprint cache
- `with_max_cache_size(size: usize)` - Set maximum cache size
- `with_timing_jitter(config: TimingJitterConfig)` - Set timing jitter configuration
- `with_rotation_policy(policy: TemplateRotationPolicy)` - Set template rotation policy
- `with_rotation_templates(templates: Vec<BrowserTemplate>)` - Set templates to rotate
- `build()` - Build the final CustlsConfig

**Example:**
```rust
let config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Firefox135)
    .with_randomization_level(RandomizationLevel::Medium)
    .with_cache(true)
    .with_max_cache_size(2000)
    .build();
```

### BrowserTemplate

Enum representing browser presets for fingerprint simulation.

```rust
pub enum BrowserTemplate {
    Chrome130,
    Firefox135,
    Safari17,
    Edge130,
    Custom(Box<CustomTemplate>),
}
```

**Variants:**
- `Chrome130` - Chrome 130+ template
- `Firefox135` - Firefox 135+ template
- `Safari17` - Safari 17+ template
- `Edge130` - Edge 130+ template
- `Custom` - User-defined custom template

**Example:**
```rust
use rustls::custls::BrowserTemplate;

let chrome = BrowserTemplate::Chrome130;
let firefox = BrowserTemplate::Firefox135;
```

### RandomizationLevel

Enum controlling randomization intensity.

```rust
pub enum RandomizationLevel {
    None,
    Light,
    Medium,
    High,
}
```

**Variants:**
- `None` - No randomization, use template exactly
- `Light` - Small browser-style perturbations (default, mainstream variation)
- `Medium` - Moderate variation within browser norms
- `High` - Maximum variation within naturalness constraints

**Example:**
```rust
use rustls::custls::RandomizationLevel;

let level = RandomizationLevel::Light; // Default
```

### TemplateRotationPolicy

Enum controlling automatic template rotation.

```rust
pub enum TemplateRotationPolicy {
    None,
    RoundRobin,
    Random,
    WeightedRandom,
}
```

**Variants:**
- `None` - No rotation, use the same template for all connections
- `RoundRobin` - Rotate through templates in order
- `Random` - Random selection from all templates
- `WeightedRandom` - Weighted random selection (prefer more common browsers)

**Example:**
```rust
use rustls::custls::TemplateRotationPolicy;

let policy = TemplateRotationPolicy::RoundRobin;
```

### CustlsError

Error type for custls operations.

```rust
pub enum CustlsError {
    HookError(String),
    RandomizationError(String),
    ExtensionError(String),
    TemplateError(String),
    CacheError(String),
    ValidationError(String),
}
```

**Variants:**
- `HookError` - Error during hook execution
- `RandomizationError` - Error during randomization
- `ExtensionError` - Error with extension handling
- `TemplateError` - Error with template handling
- `CacheError` - Error with cache operations
- `ValidationError` - Error during validation

CustlsError automatically converts to `rustls::Error` for seamless integration.

## Hook System

### ClientHelloCustomizer

Trait for implementing custom ClientHello modification logic.

```rust
pub trait ClientHelloCustomizer: Send + Sync {
    fn on_config_resolve(&self, config: &mut ConfigParams) -> Result<(), Error>;
    fn on_components_ready(&self, cipher_suites: &mut Vec<CipherSuite>, 
                           extensions: &mut Vec<ClientExtension>) -> Result<(), Error>;
    fn on_struct_ready(&self, payload: &mut ClientHelloPayload) -> Result<(), Error>;
    fn transform_wire_bytes(&self, bytes: Vec<u8>) -> Result<Vec<u8>, Error>;
}
```

**Methods:**
- `on_config_resolve` - Phase 1: Modify configuration before ClientHello construction
- `on_components_ready` - Phase 2: Modify cipher suites and extensions during construction
- `on_struct_ready` - Phase 3: Modify complete ClientHelloPayload before serialization
- `transform_wire_bytes` - Phase 4: Transform final wire bytes

All methods have default implementations that return `Ok(())`.

**Example:**
```rust
use rustls::custls::{ClientHelloCustomizer, ConfigParams, ClientHelloPayload};
use rustls::Error;

struct MyCustomizer;

impl ClientHelloCustomizer for MyCustomizer {
    fn on_config_resolve(&self, config: &mut ConfigParams) -> Result<(), Error> {
        // Modify configuration
        Ok(())
    }
    
    fn on_struct_ready(&self, payload: &mut ClientHelloPayload) -> Result<(), Error> {
        // Modify ClientHello structure
        Ok(())
    }
}
```

### DefaultCustomizer

Built-in customizer that applies templates and randomization.

```rust
pub struct DefaultCustomizer {
    // Internal fields
}
```

**Methods:**
- `new(config: CustlsConfig)` - Create a new DefaultCustomizer with configuration
- `with_target(host: String, port: u16)` - Set the target for cache lookup

**Example:**
```rust
use rustls::custls::{DefaultCustomizer, CustlsConfig, BrowserTemplate};

let config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Chrome130)
    .build();

let customizer = DefaultCustomizer::new(config)
    .with_target("example.com".to_string(), 443);
```

## Extensions

custls provides implementations for TLS extensions that rustls doesn't natively support.

### ApplicationSettingsExtension

Application-Layer Protocol Settings extension (0x001b).

```rust
pub struct ApplicationSettingsExtension {
    pub protocols: Vec<Vec<u8>>,
}
```

### DelegatedCredentialExtension

Delegated Credential extension (0x0022).

```rust
pub struct DelegatedCredentialExtension {
    pub signature_algorithms: Vec<SignatureScheme>,
}
```

### CompressCertificateExtension

Compress Certificate extension.

```rust
pub struct CompressCertificateExtension {
    pub algorithms: Vec<CertificateCompressionAlgorithm>,
}
```

### PaddingExtension

Padding extension with configurable length.

```rust
pub struct PaddingExtension {
    pub length: u16,
}
```

**Example:**
```rust
use rustls::custls::PaddingExtension;

let padding = PaddingExtension { length: 256 };
```

### StatusRequestExtension

OCSP Status Request extension.

```rust
pub struct StatusRequestExtension {
    pub responder_id_list: Vec<Vec<u8>>,
    pub request_extensions: Vec<u8>,
}
```

### SignedCertificateTimestampExtension

Signed Certificate Timestamp extension.

```rust
pub struct SignedCertificateTimestampExtension;
```

## Templates

### TemplateData

Complete template data structure defining browser characteristics.

```rust
pub struct TemplateData {
    pub cipher_suites: Vec<CipherSuite>,
    pub extension_order: Vec<ExtensionType>,
    pub support_groups: Vec<NamedGroup>,
    pub signature_algorithms: Vec<SignatureScheme>,
    pub grease_pattern: GreasePattern,
    pub padding_distribution: PaddingDistribution,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub http2_pseudo_header_order: Vec<String>,
    pub supported_versions: Vec<ProtocolVersion>,
    pub key_share_groups: Vec<NamedGroup>,
}
```

**Factory Functions:**
- `chrome_130()` - Chrome 130+ template
- `firefox_135()` - Firefox 135+ template
- `safari_17()` - Safari 17+ template
- `edge_130()` - Edge 130+ template

**Example:**
```rust
use rustls::custls::templates::TemplateData;

let chrome_template = TemplateData::chrome_130();
```

### GreasePattern

Defines GREASE value injection behavior.

```rust
pub struct GreasePattern {
    pub cipher_suite_probability: f64,
    pub cipher_suite_positions: Vec<f64>,
    pub extension_probability: f64,
    pub extension_positions: Vec<f64>,
    pub grease_values: Vec<u16>,
}
```

### PaddingDistribution

Defines padding length sampling distribution.

```rust
pub struct PaddingDistribution {
    pub pmf: Vec<(u16, f64)>,
    pub min_length: u16,
    pub max_length: u16,
    pub power_of_2_bias: f64,
}
```

### NaturalnessFilter

Validates extension combinations for naturalness.

```rust
pub struct NaturalnessFilter {
    pub blacklist: Vec<ExtensionSet>,
    pub whitelist: Vec<ExtensionSet>,
    pub dependencies: HashMap<ExtensionType, Vec<ExtensionType>>,
}
```

**Methods:**
- `is_natural(&self, extensions: &[ClientExtension]) -> bool` - Check if extension combination is natural

## State Management

### FingerprintManager

Manages working fingerprint cache with reputation tracking.

```rust
pub struct FingerprintManager {
    // Internal fields
}
```

**Methods:**
- `new(max_size: usize)` - Create a new manager with maximum cache size
- `get_working_fingerprint(&mut self, target: &TargetKey, randomizer: &mut BrowserRandomizer) -> Option<ClientHelloConfig>` - Get cached fingerprint with variation
- `record_result(&mut self, target: &TargetKey, success: bool)` - Record handshake result
- `clear_cache(&mut self)` - Clear all cached fingerprints
- `invalidate_target(&mut self, target: &TargetKey)` - Invalidate specific target

**Example:**
```rust
use rustls::custls::{FingerprintManager, TargetKey};

let mut manager = FingerprintManager::new(1000);
let target = TargetKey::new("example.com".to_string(), 443);

// Record successful handshake
manager.record_result(&target, true);
```

### TargetKey

Identifies a connection target for caching.

```rust
pub struct TargetKey {
    pub host: String,
    pub port: u16,
}
```

**Methods:**
- `new(host: String, port: u16)` - Create a new target key

### ClientHelloConfig

Captured ClientHello configuration for caching.

```rust
pub struct ClientHelloConfig {
    pub template: BrowserTemplate,
    pub cipher_suites: Vec<CipherSuite>,
    pub extension_order: Vec<ExtensionType>,
    pub extension_data: HashMap<ExtensionType, Vec<u8>>,
    pub grease_positions: Vec<usize>,
    pub padding_length: u16,
    pub random_seed: u64,
}
```

### FingerprintEntry

Cache entry with reputation tracking.

```rust
pub struct FingerprintEntry {
    pub config: ClientHelloConfig,
    pub success_count: u32,
    pub failure_count: u32,
    pub last_used: Instant,
    pub reputation_score: f64,
}
```

## Utilities

### Http2Settings

HTTP/2 SETTINGS frame configuration.

```rust
pub struct Http2Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
    pub pseudo_header_order: Vec<String>,
    pub priority_spec: Option<PrioritySpec>,
}
```

### PrioritySpec

HTTP/2 priority specification.

```rust
pub struct PrioritySpec {
    pub stream_dependency: u32,
    pub weight: u8,
    pub exclusive: bool,
}
```

### TimingJitterConfig

Configuration for timing jitter injection.

```rust
pub struct TimingJitterConfig {
    pub min_delay_micros: u64,
    pub max_delay_micros: u64,
    pub apply_probability: f64,
}
```

**Example:**
```rust
use rustls::custls::TimingJitterConfig;

let jitter = TimingJitterConfig {
    min_delay_micros: 100,
    max_delay_micros: 5000,
    apply_probability: 0.3,
};
```

### Utility Functions

**sample_from_pmf**
```rust
pub fn sample_from_pmf(pmf: &[(u16, f64)], rng: &mut impl Rng) -> u16
```
Sample a value from a probability mass function.

**sample_with_power_of_2_bias**
```rust
pub fn sample_with_power_of_2_bias(min: u16, max: u16, bias: f64, rng: &mut impl Rng) -> u16
```
Sample a value with bias toward powers of 2.

**validate_extension_order**
```rust
pub fn validate_extension_order(extensions: &[ClientExtension]) -> Result<(), CustlsError>
```
Validate that extension order is protocol-compliant.

**calculate_reputation_score**
```rust
pub fn calculate_reputation_score(success_count: u32, failure_count: u32) -> f64
```
Calculate reputation score from success/failure counts.

## Security

### validate_downgrade_protection

```rust
pub fn validate_downgrade_protection(
    server_random: &[u8],
    negotiated_version: ProtocolVersion,
) -> Result<(), CustlsError>
```

Validate RFC 8446 downgrade protection canary.

**Example:**
```rust
use rustls::custls::security::validate_downgrade_protection;

validate_downgrade_protection(&server_random, ProtocolVersion::TLSv1_3)?;
```

### SessionStateTracker

Tracks session state for consistent fingerprinting.

```rust
pub struct SessionStateTracker {
    // Internal fields
}
```

**Methods:**
- `new()` - Create a new session state tracker
- `get_or_create_session(&mut self, session_id: &SessionId) -> &mut SessionState` - Get or create session state
- `record_handshake(&mut self, session_id: &SessionId, config: ClientHelloConfig)` - Record handshake configuration

## Constants

### Downgrade Canaries

```rust
pub const TLS12_DOWNGRADE_CANARY: &[u8] = &[0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];
pub const TLS11_DOWNGRADE_CANARY: &[u8] = &[0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];
```

## Feature Flags

custls respects rustls feature flags:
- `std` - Standard library support (enabled by default)
- `logging` - Logging support

## Thread Safety

All public types are `Send + Sync` where appropriate:
- `CustlsConfig` - `Clone + Send + Sync`
- `ClientHelloCustomizer` - `Send + Sync` (trait bound)
- `DefaultCustomizer` - `Send + Sync`
- `FingerprintManager` - `Send` (uses interior mutability)

## Error Handling

All custls errors convert to `rustls::Error` for seamless integration. Critical errors (hook failures, validation failures) abort the handshake. Non-critical errors (cache failures, GREASE failures) log warnings and continue with degraded functionality.

## Performance

custls is designed for minimal overhead:
- <10% overhead for ClientHello generation with light randomization
- <1ms cache lookups
- <5ms randomization
- Zero-overhead mode available (disable all customization)

## Security Guarantees

custls preserves all rustls security properties:
- Zero unsafe code
- RFC 8446 downgrade protection
- Certificate validation unchanged
- Constant-time cryptographic operations maintained
- No fingerprint calculation (out of scope)

## See Also

- [Quickstart Guide](QUICKSTART.md)
- [Template Creation Guide](TEMPLATE_GUIDE.md)
- [Rebase Guide](REBASE_GUIDE.md)
- [Migration Guide](MIGRATION_GUIDE.md)
- [Limitations](LIMITATIONS.md)
