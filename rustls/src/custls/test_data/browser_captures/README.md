# Browser Capture Test Data

This directory contains real browser ClientHello captures for validation testing.

## Directory Structure

```
browser_captures/
├── chrome_130/
│   ├── windows_clienthello.hex
│   ├── macos_clienthello.hex
│   ├── linux_clienthello.hex
│   └── analysis.json
├── firefox_135/
│   ├── windows_clienthello.hex
│   ├── macos_clienthello.hex
│   ├── linux_clienthello.hex
│   └── analysis.json
├── safari_17/
│   ├── macos_clienthello.hex
│   ├── ios_clienthello.hex
│   └── analysis.json
└── edge_130/
    ├── windows_clienthello.hex
    └── analysis.json
```

## Capture Instructions

See `BROWSER_CAPTURE_GUIDE.md` for detailed capture instructions.

## File Formats

**`.hex` files**: Raw ClientHello bytes in hexadecimal format (no spaces, newlines allowed)

**`analysis.json` files**: Structured analysis of the capture including:
- Cipher suites and order
- Extensions and order
- GREASE positions
- Padding length
- Key share groups
- Signature algorithms
- ALPN protocols

## Usage in Tests

The `browser_validation.rs` test module parses these captures and compares them
against custls template output to ensure fidelity.

## Updating Captures

When browser versions change significantly:
1. Capture new ClientHello messages
2. Update analysis.json files
3. Update template definitions if needed
4. Re-run validation tests

## Privacy Note

These captures should NOT contain:
- Real domain names (use example.com or test servers)
- Session tickets or resumption data
- Any personally identifiable information
