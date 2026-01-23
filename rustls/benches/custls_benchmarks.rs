// Performance benchmarks for custls
// Requirements: 13.1, 13.2, 13.3, 13.5
//
// Note: These benchmarks measure the overhead of custls compared to vanilla rustls.
// Due to the complexity of setting up full ClientHello generation with internal types,
// some benchmarks measure proxy metrics (e.g., template access time as a proxy for
// randomization setup time).

use bencher::{benchmark_group, benchmark_main, Bencher};
use rustls::client::ClientConfig;
use rustls::custls::{
    BrowserTemplate, CustlsConfig, DefaultCustomizer, FingerprintManager, RandomizationLevel,
    TargetKey,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, RootCertStore};
use std::sync::Arc;

// Helper to create a basic ClientConfig
fn create_vanilla_config() -> Arc<ClientConfig> {
    let root_store = RootCertStore::empty();
    // Use ring as the default provider for benchmarks (available in workspace)
    let provider = Arc::new(rustls_ring::DEFAULT_PROVIDER);
    let config = ClientConfig::builder(provider)
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .expect("Failed to build config");
    Arc::new(config)
}

// Helper to create a custls-enabled ClientConfig
fn create_custls_config(
    template: BrowserTemplate,
    randomization: RandomizationLevel,
) -> Arc<ClientConfig> {
    let root_store = RootCertStore::empty();
    // Use ring as the default provider for benchmarks (available in workspace)
    let provider = Arc::new(rustls_ring::DEFAULT_PROVIDER);
    let mut config = ClientConfig::builder(provider)
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .expect("Failed to build config");

    // Apply custls configuration
    let custls_config = CustlsConfig::builder()
        .with_template(template)
        .with_randomization_level(randomization)
        .with_cache(false) // Disable cache for pure generation benchmarks
        .build();

    let customizer = DefaultCustomizer::new(custls_config);
    config.custls_customizer = Some(Arc::new(customizer));

    Arc::new(config)
}

// Benchmark 1: Vanilla rustls ClientHello generation (baseline)
fn bench_vanilla_client_hello(b: &mut Bencher) {
    let config = create_vanilla_config();
    let server_name = ServerName::try_from("example.com").unwrap();

    b.iter(|| {
        let _conn = ClientConnection::new(Arc::clone(&config), server_name.clone());
    });
}

// Benchmark 2: custls ClientHello generation with Chrome template, no randomization
fn bench_custls_chrome_no_randomization(b: &mut Bencher) {
    let config = create_custls_config(BrowserTemplate::Chrome130, RandomizationLevel::None);
    let server_name = ServerName::try_from("example.com").unwrap();

    b.iter(|| {
        let _conn = ClientConnection::new(Arc::clone(&config), server_name.clone());
    });
}

// Benchmark 3: custls ClientHello generation with Chrome template, light randomization
fn bench_custls_chrome_light_randomization(b: &mut Bencher) {
    let config = create_custls_config(BrowserTemplate::Chrome130, RandomizationLevel::Light);
    let server_name = ServerName::try_from("example.com").unwrap();

    b.iter(|| {
        let _conn = ClientConnection::new(Arc::clone(&config), server_name.clone());
    });
}

// Benchmark 4: custls ClientHello generation with Chrome template, medium randomization
fn bench_custls_chrome_medium_randomization(b: &mut Bencher) {
    let config = create_custls_config(BrowserTemplate::Chrome130, RandomizationLevel::Medium);
    let server_name = ServerName::try_from("example.com").unwrap();

    b.iter(|| {
        let _conn = ClientConnection::new(Arc::clone(&config), server_name.clone());
    });
}

// Benchmark 5: custls ClientHello generation with Chrome template, high randomization
fn bench_custls_chrome_high_randomization(b: &mut Bencher) {
    let config = create_custls_config(BrowserTemplate::Chrome130, RandomizationLevel::High);
    let server_name = ServerName::try_from("example.com").unwrap();

    b.iter(|| {
        let _conn = ClientConnection::new(Arc::clone(&config), server_name.clone());
    });
}

// Benchmark 6: Cache lookup time
fn bench_cache_lookup(b: &mut Bencher) {
    let mut manager = FingerprintManager::new(1000);
    let target = TargetKey {
        host: "example.com".to_string(),
        port: 443,
    };

    b.iter(|| {
        let _result = manager.get_working_fingerprint(&target);
    });
}

// Benchmark 7: Cache manager creation time
fn bench_cache_creation(b: &mut Bencher) {
    b.iter(|| {
        let _manager = FingerprintManager::new(1000);
    });
}

// Benchmark 8: Template data access time
fn bench_template_access(b: &mut Bencher) {
    use rustls::custls::templates;

    b.iter(|| {
        let _template_data = templates::chrome_130();
    });
}

// Benchmark 9: Hook invocation overhead (empty hooks)
fn bench_hook_invocation_overhead(b: &mut Bencher) {
    use rustls::custls::ClientHelloCustomizer;

    #[derive(Debug)]
    struct EmptyCustomizer;
    impl ClientHelloCustomizer for EmptyCustomizer {}

    let customizer = EmptyCustomizer;

    b.iter(|| {
        // Measure trait object overhead
        let _c = &customizer as &dyn ClientHelloCustomizer;
    });
}

// Benchmark 10: Template application time (all templates)
fn bench_all_templates(b: &mut Bencher) {
    use rustls::custls::templates;

    b.iter(|| {
        let _chrome = templates::chrome_130();
        let _firefox = templates::firefox_135();
        let _safari = templates::safari_17();
        let _edge = templates::edge_130();
    });
}

// Benchmark 11: Full custls pipeline (template + randomization + hooks)
fn bench_full_custls_pipeline(b: &mut Bencher) {
    let config = create_custls_config(BrowserTemplate::Chrome130, RandomizationLevel::Medium);
    let server_name = ServerName::try_from("example.com").unwrap();

    b.iter(|| {
        let _conn = ClientConnection::new(Arc::clone(&config), server_name.clone());
    });
}

// Benchmark 12: Cache-enabled custls (with cache hits)
fn bench_custls_with_cache(b: &mut Bencher) {
    let root_store = RootCertStore::empty();
    // Use ring as the default provider for benchmarks (available in workspace)
    let provider = Arc::new(rustls_ring::DEFAULT_PROVIDER);
    let mut config = ClientConfig::builder(provider)
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .expect("Failed to build config");

    let custls_config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_randomization_level(RandomizationLevel::Light)
        .with_cache(true)
        .build();

    let customizer = DefaultCustomizer::new(custls_config);
    config.custls_customizer = Some(Arc::new(customizer));
    let config = Arc::new(config);

    let server_name = ServerName::try_from("example.com").unwrap();

    // Warm up the cache
    for _ in 0..5 {
        let _conn = ClientConnection::new(Arc::clone(&config), server_name.clone());
    }

    b.iter(|| {
        let _conn = ClientConnection::new(Arc::clone(&config), server_name.clone());
    });
}

benchmark_group!(
    client_hello_generation,
    bench_vanilla_client_hello,
    bench_custls_chrome_no_randomization,
    bench_custls_chrome_light_randomization,
    bench_custls_chrome_medium_randomization,
    bench_custls_chrome_high_randomization,
    bench_full_custls_pipeline,
    bench_custls_with_cache
);

benchmark_group!(
    cache_operations,
    bench_cache_lookup,
    bench_cache_creation
);

benchmark_group!(
    template_operations,
    bench_template_access,
    bench_all_templates
);

benchmark_group!(
    hook_operations,
    bench_hook_invocation_overhead
);

benchmark_main!(
    client_hello_generation,
    cache_operations,
    template_operations,
    hook_operations
);
