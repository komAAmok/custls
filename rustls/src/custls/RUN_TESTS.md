# Running custls Tests

This document explains how to run the custls test suite.

## Prerequisites

The rustls library requires a cryptographic provider. By default, it uses `aws-lc-rs` which requires:
- NASM assembler (for Windows)
- CMake
- C compiler

### Installing NASM on Windows

1. Download NASM from https://www.nasm.us/
2. Install and add to PATH
3. Or set `AWS_LC_SYS_PREBUILT_NASM` environment variable

Alternatively, you can use the `ring` provider which has fewer dependencies.

## Running Tests

### Unit Tests

Run all custls unit tests:

```bash
cargo test --package rustls --lib custls::hooks::tests
```

Run a specific unit test:

```bash
cargo test --package rustls --lib custls::hooks::tests::test_default_hook_implementations
```

### Property-Based Tests

Run all custls property tests (requires proptest):

```bash
cargo test --package rustls --lib custls::hooks::properties
```

Run a specific property test:

```bash
cargo test --package rustls --lib custls::hooks::properties::property_tests::prop_hook_error_propagation
```

### All custls Tests

Run all custls tests (unit + property):

```bash
cargo test --package rustls --lib custls
```

## Test Configuration

Property-based tests are configured to run 100 cases per property (as specified in the design document).

To increase the number of test cases:

```bash
PROPTEST_CASES=1000 cargo test --package rustls --lib custls::hooks::properties
```

## Verification Without Running

To verify that tests compile without running them:

```bash
cargo check --package rustls --lib
```

To build tests without running:

```bash
cargo test --package rustls --lib custls --no-run
```

## Troubleshooting

### NASM Not Found

If you see "NASM command not found or failed to execute":

1. Install NASM (see Prerequisites above)
2. Or use an alternative crypto provider
3. Or set `AWS_LC_SYS_PREBUILT_NASM=1` to use prebuilt binaries

### Build Failures

If tests fail to build:

1. Ensure you have the latest Rust toolchain: `rustup update`
2. Clean the build: `cargo clean`
3. Try building with verbose output: `cargo test --verbose`

## Test Coverage

The custls test suite includes:

- **Unit tests**: Concrete examples and edge cases
- **Property-based tests**: Universal properties across all inputs
- **Integration tests**: Full handshake scenarios (in separate test files)

Target coverage: 80% for custls module, 100% for critical paths.
