//! Custom template example
//!
//! This example demonstrates:
//! - Creating a custom browser template
//! - Using CustomTemplate for advanced fingerprint simulation
//! - Comparing built-in templates with custom templates
//!
//! Requirements: 15.3, 15.6

use rustls::custls::{
    CustlsConfig, BrowserTemplate, RandomizationLevel,
    CustomTemplate,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("custls Custom Template Example");
    println!("==============================\n");

    // Part 1: Using built-in templates
    println!("Part 1: Built-in Templates");
    println!("--------------------------\n");
    
    println!("Available built-in templates:");
    println!("  • Chrome 130+  - Most common browser, Chromium-based");
    println!("  • Firefox 135+ - Gecko-based, unique fingerprint");
    println!("  • Safari 17+   - WebKit-based, macOS/iOS");
    println!("  • Edge 130+    - Chromium-based, similar to Chrome\n");
    
    // Example with Chrome template
    println!("Example 1: Using Chrome 130 template");
    let _chrome_config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)
        .with_randomization_level(RandomizationLevel::Light)
        .build();
    
    println!("  ✓ Chrome 130 template configured");
    println!("  ✓ Will simulate Chrome browser fingerprint\n");
    
    // Example with Firefox template
    println!("Example 2: Using Firefox 135 template");
    let _firefox_config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Firefox135)
        .with_randomization_level(RandomizationLevel::Medium)
        .build();
    
    println!("  ✓ Firefox 135 template configured");
    println!("  ✓ Will simulate Firefox browser fingerprint\n");

    // Part 2: Creating a custom template
    println!("Part 2: Custom Templates");
    println!("------------------------\n");
    
    println!("Creating a custom template...");
    
    let custom_template = CustomTemplate {
        name: "MyCustomBrowser".to_string(),
        description: "A custom browser fingerprint for specialized use cases".to_string(),
    };
    
    println!("  ✓ Template name: {}", custom_template.name);
    println!("  ✓ Description: {}", custom_template.description);
    
    let _custom_config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Custom(Box::new(custom_template)))
        .with_randomization_level(RandomizationLevel::High)
        .build();
    
    println!("  ✓ Custom template configured\n");

    // Part 3: Template characteristics
    println!("Part 3: Template Characteristics");
    println!("--------------------------------\n");
    
    println!("Each template defines:");
    println!("  • Cipher suite list and order");
    println!("  • Extension types and order");
    println!("  • Supported groups (curves)");
    println!("  • Signature algorithms");
    println!("  • GREASE injection pattern");
    println!("  • Padding length distribution");
    println!("  • ALPN protocol list");
    println!("  • HTTP/2 pseudo-header order\n");

    // Part 4: Best practices
    println!("Part 4: Best Practices");
    println!("----------------------\n");
    
    println!("When creating custom templates:");
    println!("  1. Capture real browser ClientHello with Wireshark");
    println!("  2. Extract cipher suites, extensions, and order");
    println!("  3. Document the source browser and version");
    println!("  4. Test against real servers (Cloudflare, Akamai)");
    println!("  5. Validate with browser_validation module\n");
    
    println!("Note: Custom template implementation requires extending");
    println!("the internal template data structures. For most use cases,");
    println!("the built-in templates (Chrome, Firefox, Safari, Edge) are");
    println!("sufficient and provide accurate browser simulation.\n");
    
    println!("✓ Example completed successfully");
    
    Ok(())
}
