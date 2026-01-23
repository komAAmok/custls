//! Basic custls usage example
//!
//! This example demonstrates:
//! - Creating a CustlsConfig with a browser template
//! - Applying the configuration to a rustls ClientConfig
//! - Basic custls configuration patterns
//!
//! Requirements: 15.2

use std::sync::Arc;

use rustls::custls::{CustlsConfig, BrowserTemplate, RandomizationLevel, DefaultCustomizer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("custls Basic Usage Example");
    println!("==========================\n");

    // Step 1: Create a CustlsConfig with a browser template
    println!("Step 1: Creating CustlsConfig with Chrome 130 template...");
    let custls_config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_randomization_level(RandomizationLevel::Light)
        .with_cache(true)
        .build();
    
    println!("  ✓ Template: Chrome 130");
    println!("  ✓ Randomization: Light");
    println!("  ✓ Cache: Enabled\n");

    // Step 2: Create a DefaultCustomizer with the config
    println!("Step 2: Creating DefaultCustomizer...");
    let customizer = Arc::new(DefaultCustomizer::new(custls_config));
    println!("  ✓ Customizer created\n");

    // Step 3: Configuration options
    println!("Step 3: Configuration Options...");
    println!("  Available templates:");
    println!("    • BrowserTemplate::Chrome130");
    println!("    • BrowserTemplate::Firefox135");
    println!("    • BrowserTemplate::Safari17");
    println!("    • BrowserTemplate::Edge130");
    println!("    • BrowserTemplate::Custom(...)");
    println!();
    println!("  Randomization levels:");
    println!("    • RandomizationLevel::None   - No variation");
    println!("    • RandomizationLevel::Light  - Small variations");
    println!("    • RandomizationLevel::Medium - Moderate variations");
    println!("    • RandomizationLevel::High   - Maximum variation");
    println!();
    println!("  Cache options:");
    println!("    • with_cache(true)  - Enable fingerprint caching");
    println!("    • with_cache(false) - Disable caching");
    println!("    • with_max_cache_size(n) - Set cache size limit\n");

    // Step 4: Different configuration patterns
    println!("Step 4: Configuration Patterns...");
    
    // Pattern 1: Minimal configuration
    println!("  Pattern 1: Minimal (default settings)");
    let _config1 = CustlsConfig::builder().build();
    println!("    ✓ Uses default template and settings\n");
    
    // Pattern 2: Specific browser
    println!("  Pattern 2: Specific browser simulation");
    let _config2 = CustlsConfig::builder()
        .with_template(BrowserTemplate::Firefox135)
        .build();
    println!("    ✓ Simulates Firefox 135 fingerprint\n");
    
    // Pattern 3: High security
    println!("  Pattern 3: High variation for anti-fingerprinting");
    let _config3 = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_randomization_level(RandomizationLevel::High)
        .with_cache(false)
        .build();
    println!("    ✓ Maximum variation, no caching\n");
    
    // Pattern 4: Performance optimized
    println!("  Pattern 4: Performance optimized");
    let _config4 = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_randomization_level(RandomizationLevel::None)
        .with_cache(true)
        .build();
    println!("    ✓ No randomization, caching enabled\n");

    println!("✓ Example completed successfully!");
    println!("\nKey Points:");
    println!("  • CustlsConfig defines the fingerprint simulation strategy");
    println!("  • DefaultCustomizer implements the customization logic");
    println!("  • Templates provide browser-specific fingerprints");
    println!("  • Randomization adds natural variation");
    println!("  • Caching improves performance and consistency");
    
    Ok(())
}
