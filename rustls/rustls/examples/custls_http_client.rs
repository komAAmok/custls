//! custls HTTP Client Integration Pattern
//!
//! This example shows the integration pattern for using custls with HTTP clients.
//! While this example doesn't use hyper directly (to avoid async complexity),
//! it demonstrates the exact same pattern you would use with hyper.

use std::sync::Arc;
use rustls::custls::{CustlsConfig, BrowserTemplate, RandomizationLevel, DefaultCustomizer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("custls HTTP Client Integration Pattern");
    println!("======================================\n");

    // ============================================================================
    // PART 1: Basic Integration Pattern (works with any HTTP client)
    // ============================================================================
    
    println!("PART 1: Basic Integration Pattern");
    println!("----------------------------------\n");
    
    // Step 1: Create custls configuration
    println!("Step 1: Create custls configuration");
    let custls_config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_randomization_level(RandomizationLevel::Light)
        .with_cache(true)
        .build();
    
    println!("  ✓ Template: Chrome 130");
    println!("  ✓ Randomization: Light");
    println!("  ✓ Cache: Enabled\n");

    // Step 2: Create customizer
    println!("Step 2: Create DefaultCustomizer");
    let customizer = Arc::new(DefaultCustomizer::new(custls_config));
    println!("  ✓ Customizer created\n");

    // Step 3: Show how to use with different HTTP clients
    println!("Step 3: Integration with HTTP Clients");
    println!("=====================================\n");

    // ============================================================================
    // HYPER Integration
    // ============================================================================
    
    println!("A. Hyper Integration");
    println!("-------------------");
    println!("```rust");
    println!("use hyper::Client;");
    println!("use hyper_rustls::HttpsConnectorBuilder;");
    println!("use rustls::ClientConfig;");
    println!();
    println!("// 1. Configure rustls with custls");
    println!("let mut tls_config = ClientConfig::builder()");
    println!("    .with_safe_defaults()");
    println!("    .with_native_roots()");
    println!("    .with_no_client_auth();");
    println!();
    println!("// 2. Attach custls customizer (implementation-specific)");
    println!("// tls_config.custls_customizer = Some(customizer);");
    println!();
    println!("// 3. Build HTTPS connector");
    println!("let https = HttpsConnectorBuilder::new()");
    println!("    .with_tls_config(tls_config)");
    println!("    .https_only()");
    println!("    .enable_http2()");
    println!("    .build();");
    println!();
    println!("// 4. Create hyper client");
    println!("let client = Client::builder().build::<_, hyper::Body>(https);");
    println!();
    println!("// 5. Make requests");
    println!("let res = client.get(\"https://example.com\".parse()?).await?;");
    println!("```\n");

    // ============================================================================
    // REQWEST Integration
    // ============================================================================
    
    println!("B. Reqwest Integration");
    println!("---------------------");
    println!("```rust");
    println!("use reqwest::Client;");
    println!("use rustls::ClientConfig;");
    println!();
    println!("// 1. Configure rustls with custls");
    println!("let mut tls_config = ClientConfig::builder()");
    println!("    .with_safe_defaults()");
    println!("    .with_native_roots()");
    println!("    .with_no_client_auth();");
    println!();
    println!("// 2. Attach custls customizer");
    println!("// tls_config.custls_customizer = Some(customizer);");
    println!();
    println!("// 3. Build reqwest client with custom TLS");
    println!("let client = Client::builder()");
    println!("    .use_preconfigured_tls(tls_config)");
    println!("    .build()?;");
    println!();
    println!("// 4. Make requests");
    println!("let res = client.get(\"https://example.com\").send().await?;");
    println!("```\n");

    // ============================================================================
    // PART 2: Advanced Patterns
    // ============================================================================
    
    println!("\nPART 2: Advanced Integration Patterns");
    println!("======================================\n");

    // Pattern 1: Multiple clients with different fingerprints
    println!("Pattern 1: Multiple Clients with Different Fingerprints");
    println!("-------------------------------------------------------");
    
    let chrome_config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_randomization_level(RandomizationLevel::Light)
        .build();
    
    let firefox_config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Firefox135)
        .with_randomization_level(RandomizationLevel::Medium)
        .build();
    
    let _chrome_customizer = Arc::new(DefaultCustomizer::new(chrome_config));
    let _firefox_customizer = Arc::new(DefaultCustomizer::new(firefox_config));
    
    println!("  ✓ Chrome client: Simulates Chrome 130");
    println!("  ✓ Firefox client: Simulates Firefox 135");
    println!("  → Use different clients for different targets\n");

    // Pattern 2: Template rotation
    println!("Pattern 2: Template Rotation");
    println!("----------------------------");
    println!("Rotate templates across requests to avoid detection:");
    println!("  1. Request 1: Chrome template");
    println!("  2. Request 2: Firefox template");
    println!("  3. Request 3: Safari template");
    println!("  4. Request 4: Back to Chrome");
    println!("  → Prevents behavioral clustering detection\n");

    // Pattern 3: Per-target configuration
    println!("Pattern 3: Per-Target Configuration");
    println!("-----------------------------------");
    println!("Configure different settings for different targets:");
    println!("  • Cloudflare sites: Chrome + Light randomization");
    println!("  • Akamai sites: Firefox + Medium randomization");
    println!("  • Other sites: Safari + High randomization");
    println!("  → Optimize for each target's detection system\n");

    // ============================================================================
    // PART 3: Best Practices
    // ============================================================================
    
    println!("\nPART 3: Best Practices");
    println!("======================\n");

    println!("1. Cache Management:");
    println!("   ✓ Enable caching for consistent fingerprints per target");
    println!("   ✓ Set appropriate cache size limits");
    println!("   ✓ Clear cache when changing strategies\n");

    println!("2. Randomization Levels:");
    println!("   ✓ Light: For most use cases (mainstream browser behavior)");
    println!("   ✓ Medium: For moderate anti-fingerprinting");
    println!("   ✓ High: For maximum variation (may be less natural)\n");

    println!("3. Template Selection:");
    println!("   ✓ Chrome: Most common, best for general use");
    println!("   ✓ Firefox: Unique fingerprint, good for diversity");
    println!("   ✓ Safari: macOS/iOS specific scenarios");
    println!("   ✓ Edge: Windows-specific scenarios\n");

    println!("4. HTTP Headers:");
    println!("   ✓ Match User-Agent to TLS fingerprint");
    println!("   ✓ Use browser-appropriate Accept headers");
    println!("   ✓ Include Accept-Language, Accept-Encoding");
    println!("   ✓ Maintain consistency across requests\n");

    println!("5. Connection Pooling:");
    println!("   ✓ Reuse connections when possible");
    println!("   ✓ Maintain fingerprint consistency per connection");
    println!("   ✓ Close connections when changing fingerprints\n");

    // ============================================================================
    // PART 4: Complete Example Code
    // ============================================================================
    
    println!("\nPART 4: Complete Example Code");
    println!("=============================\n");
    
    println!("```rust");
    println!("use std::sync::Arc;");
    println!("use hyper::{{Client, Request, Body}};");
    println!("use hyper_rustls::HttpsConnectorBuilder;");
    println!("use rustls::ClientConfig;");
    println!("use rustls::custls::{{");
    println!("    CustlsConfig, BrowserTemplate,");
    println!("    RandomizationLevel, DefaultCustomizer");
    println!("}};");
    println!();
    println!("#[tokio::main]");
    println!("async fn main() -> Result<(), Box<dyn std::error::Error>> {{");
    println!("    // Configure custls");
    println!("    let custls_config = CustlsConfig::builder()");
    println!("        .with_template(BrowserTemplate::Chrome130)");
    println!("        .with_randomization_level(RandomizationLevel::Light)");
    println!("        .with_cache(true)");
    println!("        .build();");
    println!();
    println!("    let customizer = Arc::new(DefaultCustomizer::new(custls_config));");
    println!();
    println!("    // Configure rustls");
    println!("    let mut tls_config = ClientConfig::builder()");
    println!("        .with_safe_defaults()");
    println!("        .with_native_roots()");
    println!("        .with_no_client_auth();");
    println!();
    println!("    // Attach customizer (implementation-specific API)");
    println!("    // tls_config.custls_customizer = Some(customizer);");
    println!();
    println!("    // Build hyper client");
    println!("    let https = HttpsConnectorBuilder::new()");
    println!("        .with_tls_config(tls_config)");
    println!("        .https_only()");
    println!("        .enable_http2()");
    println!("        .build();");
    println!();
    println!("    let client = Client::builder().build::<_, Body>(https);");
    println!();
    println!("    // Make request");
    println!("    let req = Request::builder()");
    println!("        .uri(\"https://example.com\")");
    println!("        .header(\"User-Agent\", \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\")");
    println!("        .body(Body::empty())?;");
    println!();
    println!("    let res = client.request(req).await?;");
    println!("    println!(\"Status: {{}}\", res.status());");
    println!();
    println!("    Ok(())");
    println!("}}");
    println!("```\n");

    println!("✓ Integration pattern example completed!");
    println!("\nNext Steps:");
    println!("  1. Add hyper and hyper-rustls to your Cargo.toml");
    println!("  2. Configure custls as shown above");
    println!("  3. Build your HTTP client with the custls-enabled TLS config");
    println!("  4. Make requests with browser-like fingerprints");
    println!("  5. Monitor success rates and adjust configuration as needed");

    Ok(())
}
