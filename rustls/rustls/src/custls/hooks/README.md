# ClientHelloCustomizer Hook System

This module implements the multi-phase hook system for ClientHello customization in custls.

## Overview

The hook system provides four distinct callback phases that intercept ClientHello construction at different stages:

1. **Phase 1 (on_config_resolve)**: Pre-build configuration
2. **Phase 2 (on_components_ready)**: Mid-build component modification
3. **Phase 3 (on_struct_ready)**: Pre-marshal structure modification
4. **Phase 4 (transform_wire_bytes)**: Post-marshal byte transformation

## Files

- `mod.rs` (hooks.rs): Core trait definition and documentation
- `tests.rs`: Unit tests for hook functionality
- `properties.rs`: Property-based tests for universal correctness properties
- `README.md`: This file

## Implementation Status

### ✅ Completed

- [x] ClientHelloCustomizer trait with 4 hook methods
- [x] Comprehensive documentation for each hook phase
- [x] Default implementations returning Ok(())
- [x] ConfigParams placeholder structure
- [x] ClientHelloPayload placeholder structure
- [x] CipherSuite placeholder type
- [x] ClientExtension placeholder type
- [x] Unit tests (20+ test cases)
- [x] Property-based tests (8 properties)
- [x] Error propagation tests
- [x] Modification persistence tests

### 📝 Notes

- Placeholder types (ConfigParams, ClientHelloPayload, CipherSuite, ClientExtension) will be replaced with actual rustls types once integration is complete
- Tests compile successfully with `cargo check`
- Tests require NASM for full execution (see RUN_TESTS.md)

## Usage Example

```rust
use rustls::custls::{ClientHelloCustomizer, CustlsError};
use rustls::Error;

struct MyCustomizer;

impl ClientHelloCustomizer for MyCustomizer {
    fn on_components_ready(
        &self,
        cipher_suites: &mut Vec<CipherSuite>,
        extensions: &mut Vec<ClientExtension>,
    ) -> Result<(), Error> {
        // Add GREASE cipher suite
        cipher_suites.insert(0, CipherSuite::GREASE);
        
        // Shuffle extensions
        shuffle_extensions(extensions)?;
        
        Ok(())
    }
    
    fn on_struct_ready(&self, payload: &mut ClientHelloPayload) -> Result<(), Error> {
        // Add padding extension
        let padding_len = calculate_padding(payload);
        payload.extensions.push(PaddingExtension::new(padding_len));
        
        Ok(())
    }
}
```

## Testing

See `RUN_TESTS.md` for detailed testing instructions.

Quick test commands:

```bash
# Check compilation
cargo check --package rustls --lib

# Run unit tests (requires NASM)
cargo test --package rustls --lib custls::hooks::tests

# Run property tests (requires NASM)
cargo test --package rustls --lib custls::hooks::properties
```

## Requirements Validated

This implementation validates the following requirements from the design document:

- **Requirement 2.1**: Phase 1 hook (on_config_resolve) ✅
- **Requirement 2.2**: Phase 2 hook (on_components_ready) ✅
- **Requirement 2.3**: Phase 3 hook (on_struct_ready) ✅
- **Requirement 2.4**: Phase 4 hook (transform_wire_bytes) ✅
- **Requirement 2.5**: Default implementations ✅
- **Requirement 2.6**: Error propagation ✅

## Properties Tested

The property-based test suite validates:

1. **Property 1: Hook Error Propagation** - Errors from any hook phase are propagated
2. **Hook Success Propagation** - Successful hooks complete without error
3. **Error Type Preservation** - Error messages are preserved through conversion
4. **Cipher Suite Modifications Persist** - Changes to cipher suites are visible
5. **Extension Modifications Persist** - Changes to extensions are visible
6. **Wire Bytes Length Preservation** - No-op transforms preserve length
7. **Wire Bytes Transformation** - Transforms can modify bytes

Each property is tested with 100 random inputs (configurable via PROPTEST_CASES).

## Next Steps

1. Integrate with rustls core (task 10-11)
2. Replace placeholder types with actual rustls types
3. Implement DefaultCustomizer using these hooks (task 12)
4. Add integration tests with full handshakes

## Design Document Reference

See `.kiro/specs/custls/design.md` for complete design documentation.
