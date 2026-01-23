# Rebase Guide for custls

## Introduction

This guide documents all modifications made to rustls core files to support custls, and provides a strategy for rebasing from upstream rustls.

## Design Philosophy

custls follows a **minimal-invasive** architecture:
- All customization logic is isolated in the `src/custls` module
- Only strategic "probe points" are inserted into rustls's native flow
- Total modifications to existing rustls files: **<100 lines across 5 files**
- No unsafe code introduced
- All modifications are clearly marked with comments

This design facilitates easy upstream rebasing with minimal merge conflicts.

## Modified Files

### 1. `src/lib.rs` (1 line)

**Location:** Module declarations section

**Modification:**
```rust
pub mod custls;
```

**Purpose:** Export the custls module as part of the rustls public API.

**Rebase Strategy:**
- This line should be added after other module declarations
- Very unlikely to conflict with upstream changes
- If conflict occurs, simply re-add the line

---

### 2. `src/msgs/client_hello.rs` (~30 lines)

**Location:** `ClientHelloPayload` struct definition

**Modification 1: Make fields public**
```rust
pub struct ClientHelloPayload {
    pub(crate) client_version: ProtocolVersion,
    pub(crate) random: Random,
    pub(crate) session_id: SessionId,
    pub cipher_suites: Vec<CipherSuite>,  // Changed from pub(crate) to pub
    pub(crate) compression_methods: Vec<Compression>,
    pub extensions: Box<ClientExtensions<'static>>,  // Changed from pub(crate) to pub
}
```

**Modification 2: Add accessor methods**
```rust
impl ClientHelloPayload {
    /// Get a mutable reference to the cipher suites list
    pub fn cipher_suites_mut(&mut self) -> &mut Vec<CipherSuite> {
        &mut self.cipher_suites
    }

    /// Get a mutable reference to the extensions
    pub fn extensions_mut(&mut self) -> &mut Box<ClientExtensions<'static>> {
        &mut self.extensions
    }
    
    // ... existing methods ...
}
```

**Purpose:** Allow custls hooks to modify cipher suites and extensions.

**Rebase Strategy:**
- These changes are additive and unlikely to conflict
- If `ClientHelloPayload` structure changes, update field visibility accordingly
- If new fields are added, consider whether they need custls access
- Accessor methods are standalone and won't conflict with other methods

**Conflict Resolution:**
1. Check if `ClientHelloPayload` structure changed
2. Ensure `cipher_suites` and `extensions` remain public
3. Ensure accessor methods are present
4. If fields were renamed, update accessor methods

---

### 3. `src/msgs/enums.rs` (~20 lines)

**Location:** `ExtensionType` enum

**Modification: Add missing extension types**
```rust
pub enum ExtensionType {
    // ... existing variants ...
    
    // custls additions for browser simulation
    ApplicationSettings = 0x001b,
    DelegatedCredential = 0x0022,
    CompressCertificate = 0x001b,
    StatusRequest = 0x0005,
    SignedCertificateTimestamp = 0x0012,
    
    // ... existing variants ...
}
```

**Purpose:** Support extensions commonly used by browsers but not natively supported by rustls.

**Rebase Strategy:**
- These are additive enum variants
- Unlikely to conflict unless upstream adds the same extensions
- If upstream adds these extensions, remove custls versions and use upstream

**Conflict Resolution:**
1. Check if upstream added any of these extension types
2. If yes, remove custls version and use upstream implementation
3. If no, re-add custls extension types
4. Ensure extension type values (hex codes) are correct

---

### 4. `src/client/client_conn.rs` (~20 lines)

**Location:** `make_client_hello()` function

**Modification: Insert hook invocation points**

```rust
fn make_client_hello(&mut self, ...) -> Result<...> {
    // Phase 1: Pre-build hook
    // custls: Allow customization before ClientHello construction
    #[cfg(feature = "custls")]
    if let Some(customizer) = &self.config.custls_customizer {
        let mut config_params = ConfigParams::default();
        customizer.on_config_resolve(&mut config_params)?;
    }
    
    // ... existing rustls logic to build cipher_suites and extensions ...
    
    // Phase 2: Mid-build hook
    // custls: Allow modification of cipher suites and extensions during construction
    #[cfg(feature = "custls")]
    if let Some(customizer) = &self.config.custls_customizer {
        customizer.on_components_ready(&mut cipher_suites, &mut extensions)?;
    }
    
    // ... construct ClientHelloPayload ...
    
    // Phase 3: Pre-marshal hook
    // custls: Allow modification of complete ClientHelloPayload before serialization
    #[cfg(feature = "custls")]
    if let Some(customizer) = &self.config.custls_customizer {
        customizer.on_struct_ready(&mut client_hello_payload)?;
    }
    
    // ... marshal to bytes ...
    
    // Phase 4: Post-marshal hook
    // custls: Allow transformation of final wire bytes
    #[cfg(feature = "custls")]
    if let Some(customizer) = &self.config.custls_customizer {
        wire_bytes = customizer.transform_wire_bytes(wire_bytes)?;
    }
    
    Ok(wire_bytes)
}
```

**Purpose:** Provide four-phase hook system for ClientHello customization.

**Rebase Strategy:**
- This is the most critical modification
- `make_client_hello()` may change significantly in upstream
- Hook insertions are marked with `// custls:` comments
- All hooks are guarded by `#[cfg(feature = "custls")]`

**Conflict Resolution:**
1. Locate the new `make_client_hello()` function
2. Identify the four key points:
   - **Phase 1**: Before any ClientHello construction begins
   - **Phase 2**: After cipher_suites and extensions vectors are created but before ClientHelloPayload
   - **Phase 3**: After ClientHelloPayload is constructed but before marshaling
   - **Phase 4**: After marshaling to wire bytes
3. Insert hook invocations at these points
4. Ensure error propagation works correctly
5. Test that all four hooks are invoked in order

**Testing After Rebase:**
```rust
// Run hook integration tests
cargo test --package rustls --lib custls::integration_tests::test_all_hooks_invoked
```

---

### 5. `src/client/tls13.rs` (~10 lines)

**Location:** `handle_hello_retry_request()` and ECH-related functions

**Modification: Ensure hooks trigger in special flows**

```rust
// In handle_hello_retry_request
fn handle_hello_retry_request(...) -> Result<...> {
    // ... existing logic ...
    
    // custls: Ensure hooks are invoked for retry ClientHello
    #[cfg(feature = "custls")]
    if let Some(customizer) = &self.config.custls_customizer {
        // Invoke hooks as in normal flow
    }
    
    // ... existing logic ...
}

// In ECH-related functions
// custls: Ensure hooks are invoked for ECH ClientHello
#[cfg(feature = "custls")]
// ... hook invocations ...
```

**Purpose:** Ensure custls hooks work correctly with HelloRetryRequest and ECH flows.

**Rebase Strategy:**
- These modifications are in TLS 1.3 specific code
- May need updates if HRR or ECH logic changes
- Less critical than main ClientHello flow

**Conflict Resolution:**
1. Check if HRR or ECH handling changed
2. Ensure hooks are invoked in these special flows
3. Test with HRR and ECH scenarios

---

## Rebase Procedure

### Step 1: Prepare

1. **Backup current custls branch:**
   ```bash
   git checkout custls
   git branch custls-backup-$(date +%Y%m%d)
   ```

2. **Fetch upstream:**
   ```bash
   git remote add upstream https://github.com/rustls/rustls.git
   git fetch upstream
   ```

3. **Review upstream changes:**
   ```bash
   git log upstream/main --oneline --since="2024-01-01"
   ```

4. **Identify potentially conflicting changes:**
   - Look for changes to `client_conn.rs`, `client_hello.rs`, `enums.rs`
   - Note any new features or refactorings

### Step 2: Create Rebase Branch

```bash
git checkout -b custls-rebase-$(date +%Y%m%d)
git rebase upstream/main
```

### Step 3: Resolve Conflicts

For each conflict:

1. **Identify the file:**
   ```bash
   git status
   ```

2. **Review the conflict:**
   ```bash
   git diff <file>
   ```

3. **Resolve using this guide:**
   - Refer to the "Modified Files" section above
   - Preserve custls modifications
   - Integrate upstream changes
   - Keep custls comments (`// custls:`)

4. **Mark as resolved:**
   ```bash
   git add <file>
   ```

5. **Continue rebase:**
   ```bash
   git rebase --continue
   ```

### Step 4: Verify Modifications

After rebase, verify all modifications are present:

```bash
# Check lib.rs
grep "pub mod custls" src/lib.rs

# Check client_hello.rs
grep "pub cipher_suites" src/msgs/client_hello.rs
grep "cipher_suites_mut" src/msgs/client_hello.rs

# Check enums.rs
grep "ApplicationSettings" src/msgs/enums.rs

# Check client_conn.rs
grep "custls:" src/client/client_conn.rs | wc -l
# Should show 4 (one for each hook phase)

# Check tls13.rs
grep "custls:" src/client/tls13.rs
```

### Step 5: Run Tests

```bash
# Run all custls tests
cargo test --package rustls --lib custls

# Run integration tests
cargo test --package rustls --lib custls::integration_tests

# Run property tests
cargo test --package rustls --lib custls::*_properties

# Run examples
cargo run --example custls_basic_usage
cargo run --example custls_custom_hooks
cargo run --example custls_custom_template
cargo run --example custls_zero_overhead
```

### Step 6: Validate Hook System

Run specific tests to ensure hooks work:

```bash
# Test all four hooks are invoked
cargo test --package rustls --lib test_all_hooks_invoked

# Test hook modifications persist
cargo test --package rustls --lib test_hook_modifications_persist

# Test hook errors propagate
cargo test --package rustls --lib test_hook_error_propagation
```

### Step 7: Performance Benchmarks

Ensure performance hasn't regressed:

```bash
# Run benchmarks
cargo bench --package rustls-bench

# Compare with pre-rebase benchmarks
# Ensure <10% overhead for ClientHello generation
```

### Step 8: Documentation

Update documentation if needed:

```bash
# Update REBASE_GUIDE.md with any new findings
# Update API.md if public API changed
# Update QUICKSTART.md if usage changed
```

### Step 9: Commit and Push

```bash
git commit -m "Rebase custls on upstream rustls $(git describe upstream/main)"
git push origin custls-rebase-$(date +%Y%m%d)
```

## Common Rebase Scenarios

### Scenario 1: ClientHello Structure Changed

**Symptom:** `ClientHelloPayload` has new fields or changed structure

**Resolution:**
1. Review new structure
2. Determine if new fields need custls access
3. Update field visibility if needed
4. Add accessor methods for new fields
5. Update custls code to handle new fields

**Example:**
```rust
// If upstream adds new field:
pub struct ClientHelloPayload {
    // ... existing fields ...
    pub new_field: NewType,  // Make public if custls needs access
}

// Add accessor if needed:
impl ClientHelloPayload {
    pub fn new_field_mut(&mut self) -> &mut NewType {
        &mut self.new_field
    }
}
```

### Scenario 2: make_client_hello() Refactored

**Symptom:** `make_client_hello()` function significantly changed or split

**Resolution:**
1. Identify the new structure
2. Find the four key hook insertion points
3. Re-insert hooks with proper error handling
4. Test thoroughly

**Example:**
```rust
// If split into multiple functions:
fn make_client_hello(&mut self) -> Result<...> {
    // Phase 1 hook
    #[cfg(feature = "custls")]
    self.invoke_phase1_hook()?;
    
    let (cipher_suites, extensions) = self.build_components()?;
    
    // Phase 2 hook
    #[cfg(feature = "custls")]
    self.invoke_phase2_hook(&mut cipher_suites, &mut extensions)?;
    
    // ... continue ...
}
```

### Scenario 3: New Extension Types Added

**Symptom:** Upstream added extension types that custls also added

**Resolution:**
1. Remove custls version of extension type
2. Use upstream implementation
3. Update custls extension implementations to use upstream types
4. Test that extensions still work

**Example:**
```rust
// Remove from custls enums.rs:
// ApplicationSettings = 0x001b,  // Now in upstream

// Update custls code to use upstream type:
use crate::enums::ExtensionType;
// ExtensionType::ApplicationSettings now available from upstream
```

### Scenario 4: TLS 1.3 Logic Changed

**Symptom:** HRR or ECH handling changed significantly

**Resolution:**
1. Review new TLS 1.3 logic
2. Ensure hooks are invoked in all ClientHello generation paths
3. Test with HRR scenarios
4. Test with ECH scenarios

### Scenario 5: Error Handling Changed

**Symptom:** Error types or propagation changed

**Resolution:**
1. Update custls error conversion
2. Ensure `CustlsError` converts to new rustls error types
3. Update hook error propagation
4. Test error paths

## Maintenance Strategy

### Regular Rebases

Rebase from upstream regularly to avoid large conflicts:

- **Monthly**: Check for upstream changes
- **Quarterly**: Perform rebase if changes are significant
- **Major releases**: Always rebase for major rustls releases

### Tracking Upstream

Monitor upstream rustls:

```bash
# Subscribe to rustls releases
# Watch: https://github.com/rustls/rustls/releases

# Monitor relevant files
git log upstream/main -- src/client/client_conn.rs
git log upstream/main -- src/msgs/client_hello.rs
git log upstream/main -- src/msgs/enums.rs
```

### Automated Testing

Set up CI to test after rebase:

```yaml
# .github/workflows/rebase-test.yml
name: Rebase Test
on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly
jobs:
  test-rebase:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Fetch upstream
        run: git fetch upstream
      - name: Test rebase
        run: |
          git rebase upstream/main
          cargo test --package rustls --lib custls
```

## Minimizing Future Conflicts

### Best Practices

1. **Keep modifications minimal**: Don't add unnecessary changes
2. **Use feature flags**: Guard all custls code with `#[cfg(feature = "custls")]`
3. **Comment clearly**: Mark all custls modifications with `// custls:`
4. **Isolate logic**: Keep all custls logic in the `custls` module
5. **Avoid refactoring**: Don't refactor rustls code, only add hooks

### Future-Proofing

Consider these strategies:

1. **Trait-based hooks**: If rustls adds official hook support, migrate to it
2. **Plugin system**: If rustls adds plugin system, migrate custls to plugin
3. **Upstream contribution**: Consider upstreaming hook system to rustls

## Troubleshooting

### Issue: Rebase conflicts in client_conn.rs

**Solution:**
1. Accept upstream changes
2. Manually re-insert four hook invocations
3. Test with `cargo test custls::integration_tests`

### Issue: Tests failing after rebase

**Solution:**
1. Check if rustls API changed
2. Update custls code to match new API
3. Run `cargo test --package rustls --lib custls` to identify failures
4. Fix one test at a time

### Issue: Performance regression after rebase

**Solution:**
1. Run benchmarks to identify bottleneck
2. Check if upstream changes affected hot paths
3. Optimize custls code if needed
4. Consider disabling features if overhead too high

### Issue: New rustls features conflict with custls

**Solution:**
1. Review new features
2. Determine if custls needs updates
3. Update custls to work with new features
4. Test thoroughly

## Rollback Procedure

If rebase fails catastrophically:

```bash
# Abort rebase
git rebase --abort

# Return to backup
git checkout custls-backup-$(date +%Y%m%d)

# Create new branch from backup
git checkout -b custls

# Force push if needed
git push -f origin custls
```

## Contact and Support

For rebase assistance:
- Open an issue on GitHub
- Tag with `rebase` label
- Include upstream commit hash
- Include conflict details

## Version History

| Date | Upstream Version | Custls Version | Notes |
|------|------------------|----------------|-------|
| 2024-01-15 | 0.23.0 | 1.0.0 | Initial custls implementation |
| TBD | TBD | TBD | Next rebase |

## Checklist

After each rebase, verify:

- [ ] All 5 files modified correctly
- [ ] All 4 hook phases present in client_conn.rs
- [ ] ClientHelloPayload fields public
- [ ] Extension types present in enums.rs
- [ ] All tests passing
- [ ] All examples working
- [ ] Performance benchmarks acceptable
- [ ] Documentation updated
- [ ] REBASE_GUIDE.md updated with findings

## Conclusion

custls's minimal-invasive design makes rebasing straightforward. By following this guide and maintaining regular rebases, custls can stay synchronized with upstream rustls with minimal effort.

The key is to:
1. Keep modifications minimal and well-documented
2. Test thoroughly after each rebase
3. Maintain clear separation between custls and rustls code
4. Rebase regularly to avoid large conflicts

With these practices, custls can evolve alongside rustls while maintaining its powerful customization capabilities.
