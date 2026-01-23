# Running Extension Tests

## Prerequisites

The tests require a crypto provider to be available. The default provider is `aws-lc-rs`, which requires NASM to be installed on Windows.

### Installing NASM on Windows

1. Download NASM from https://www.nasm.us/
2. Install it and add to PATH
3. Or set `AWS_LC_SYS_PREBUILT_NASM` environment variable

Alternatively, you can use the `ring` crypto provider if available in your workspace.

## Running Tests

### Unit Tests

```bash
cargo test --package rustls --lib custls::extensions::tests
```

### Property-Based Tests

```bash
cargo test --package rustls --lib custls::extensions::property_tests
```

### All Extension Tests

```bash
cargo test --package rustls --lib custls::extensions
```

## Test Coverage

### Unit Tests (Task 3.4)
- ApplicationSettingsExtension: empty, single protocol, multiple protocols
- DelegatedCredentialExtension: empty, single algorithm, multiple algorithms
- CompressCertificateExtension: empty, single algorithm, multiple algorithms
- PaddingExtension: zero length, specific length, maximum length, decode
- StatusRequestExtension: OCSP, with responders, with extensions
- SignedCertificateTimestampExtension: basic, default

### Property-Based Tests

#### Property 12: Extension Stub Round-Trip (Task 3.2)
- `application_settings_round_trip`: Tests encoding/decoding with arbitrary protocols
- `delegated_credential_round_trip`: Tests encoding/decoding with arbitrary signature schemes
- `compress_certificate_round_trip`: Tests encoding/decoding with arbitrary compression algorithms
- `status_request_round_trip`: Tests encoding/decoding with arbitrary status types and data
- `sct_extension_round_trip`: Tests encoding/decoding of empty extension

#### Property 11: Padding Length Configuration (Task 3.3)
- `padding_length_configuration`: Tests that padding extension encodes exactly the specified number of bytes (0-1500)

All property tests run with 100 iterations as specified in the design document.

## Expected Results

All tests should pass, demonstrating:
1. Correct encoding/decoding for all extension types
2. Round-trip property holds for all extensions
3. Padding length is exactly as configured
4. Edge cases (empty data, maximum length) are handled correctly
