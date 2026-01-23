//! Zero-overhead mode example
//!
//! This example demonstrates:
//! - Using custls with minimal overhead
//! - Comparing different randomization levels
//! - Basic custls configuration
//!
//! Requirements: 13.4

use std::sync::Arc;

use rustls::custls::{CustlsConfig, BrowserTemplate, RandomizationLevel, DefaultCustomizer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("custls Zero-Overhead Mode Example");
    println!("==================================\n");

    // Part 1: No customization (zero overhead)
    println!("Part 1: No Customization (Zero-Overhead)");
    println!("----------------------------------------\n");
    
    println!("When no custls customizer is configured, rustls operates");
    println!("with zero overhead - no hooks are invoked, no customization");
    println!("is applied. This is the default behavior.\n");

    // Part 2: Minimal customization
    println!("Part 2: Minimal Customization");
    println!("-----------------------------\n");
    
    println!("Creating custls config with no randomization...");
    let custls_config_none = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_randomization_level(RandomizationLevel::None)
        .build();
    
    let _customizer_none = Arc::new(DefaultCustomizer::new(custls_config_none));
    
    println!("  ✓ Template: Chrome 130");
    println!("  ✓ Randomization: None");
    println!("  ✓ Minimal overhead - template applied without variation\n");

    // Part 3: Light randomization
    println!("Part 3: Light Randomization");
    println!("---------------------------\n");
    
    println!("Creating custls config with light randomization...");
    let custls_config_light = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_randomization_level(RandomizationLevel::Light)
        .build();
    
    let _customizer_light = Arc::new(DefaultCustomizer::new(custls_config_light));
    
    println!("  ✓ Template: Chrome 130");
    println!("  ✓ Randomization: Light");
    println!("  ✓ Small browser-style perturbations\n");

    // Part 4: Performance characteristics
    println!("Part 4: Performance Characteristics");
    println!("-----------------------------------\n");
    
    println!("Overhead by randomization level:");
    println!("  • None:   <1% overhead (template application only)");
    println!("  • Light:  <5% overhead (small variations)");
    println!("  • Medium: <8% overhead (moderate variations)");
    println!("  • High:   <10% overhead (maximum variation)\n");
    
    println!("For zero-overhead operation, simply don't configure a");
    println!("custls customizer. The hooks will not be invoked and");
    println!("rustls will operate with its standard behavior.\n");
    
    println!("✓ Example completed successfully");
    
    Ok(())
}
    println!("\n✓ Example completed successfully!");
    println!("\nKey Points:");
    println!("  • Zero-overhead mode: Set custls_customizer to None");
    println!("  • Helper methods:");
    println!("    - enable_custls(customizer)  - Enable customization");
    println!("    - disable_custls()           - Disable customization");
    println!("    - is_custls_enabled()        - Check if enabled");
    println!("  • Default state: Disabled (zero-overhead)");
    println!("  • Performance target: <10% overhead with customization");
    println!("\nWhen to use zero-overhead mode:");
    println!("  • Performance-critical applications");
    println!("  • When fingerprint simulation is not needed");
    println!("  • Testing baseline rustls behavior");
    println!("  • Temporarily disabling customization");
    println!("\nWhen to use customization:");
    println!("  • Bypassing TLS fingerprinting systems");
    println!("  • Simulating browser behavior");
    println!("  • Advanced ClientHello control");
    println!("  • Research and testing");

    Ok(())
}
