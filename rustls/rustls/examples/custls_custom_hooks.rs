//! Custom hooks example
//!
//! This example demonstrates:
//! - Implementing the ClientHelloCustomizer trait
//! - Understanding the four hook phases
//! - How hooks provide fine-grained control
//!
//! Requirements: 15.5

use std::sync::Arc;

use rustls::custls::ClientHelloCustomizer;

/// Custom hook implementation that demonstrates all four phases
#[derive(Debug)]
struct MyCustomHooks {
    name: String,
}

impl MyCustomHooks {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

impl ClientHelloCustomizer for MyCustomHooks {
    // Note: This example demonstrates the trait interface.
    // The actual hook methods have default implementations that do nothing.
    // In a real implementation, you would override the methods you need.
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("custls Custom Hooks Example");
    println!("===========================\n");

    // Step 1: Create custom hook implementation
    println!("Step 1: Creating custom hook implementation...");
    let _custom_hooks = Arc::new(MyCustomHooks::new("MyCustomHooks"));
    println!("  ✓ Custom hooks created\n");

    // Step 2: Demonstrate hook phases
    println!("Step 2: Hook Phases Overview...");
    println!("  Phase 1: on_config_resolve    - Pre-build configuration");
    println!("  Phase 2: on_components_ready  - Mid-build component modification");
    println!("  Phase 3: on_struct_ready      - Pre-marshal structure access");
    println!("  Phase 4: transform_wire_bytes - Post-marshal byte transformation\n");

    // Step 3: Show how hooks would be invoked
    println!("Step 3: Hook Invocation Flow...");
    println!("  When a ClientHello is generated with this customizer:");
    println!("  1. on_config_resolve is called first");
    println!("  2. on_components_ready is called during construction");
    println!("  3. on_struct_ready is called before marshaling");
    println!("  4. transform_wire_bytes is called after marshaling\n");

    // Step 4: Hook capabilities
    println!("Step 4: Hook Capabilities...");
    println!("  Phase 1 - Configuration:");
    println!("    • Modify high-level configuration parameters");
    println!("    • Select cipher suites and protocol versions");
    println!();
    println!("  Phase 2 - Components:");
    println!("    • Modify cipher suite list and order");
    println!("    • Add, remove, or reorder extensions");
    println!("    • Apply template-based modifications");
    println!();
    println!("  Phase 3 - Structure:");
    println!("    • Access complete ClientHelloPayload");
    println!("    • Perform final validation");
    println!("    • Make structural adjustments");
    println!();
    println!("  Phase 4 - Wire Bytes:");
    println!("    • Transform final serialized bytes");
    println!("    • Apply byte-level modifications");
    println!("    • Log or analyze wire format\n");

    // Step 5: Usage example
    println!("Step 5: Usage Example...");
    println!("  To use custom hooks:");
    println!("  ```rust");
    println!("  let customizer = Arc::new(MyCustomHooks::new(\"MyHooks\"));");
    println!("  // Configure with rustls ClientConfig");
    println!("  // Hooks will be invoked during TLS handshakes");
    println!("  ```\n");

    println!("✓ Example completed successfully");
    println!("\nNote: This example demonstrates the hook interface.");
    println!("The ClientHelloCustomizer trait provides default implementations");
    println!("for all hook methods. Override only the methods you need for your");
    println!("specific customization requirements.");
    
    Ok(())
}
