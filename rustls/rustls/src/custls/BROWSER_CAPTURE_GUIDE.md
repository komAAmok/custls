# Browser ClientHello Capture Guide

This guide explains how to capture real browser ClientHello messages for validation testing.

## Prerequisites

- Wireshark installed (https://www.wireshark.org/)
- Target browsers installed:
  - Chrome 130+
  - Firefox 135+
  - Safari 17+ (macOS/iOS only)
  - Edge 130+
- Test server with TLS enabled (e.g., https://example.com)

## Capture Process

### Step 1: Start Wireshark Capture

1. Open Wireshark
2. Select your network interface (usually Wi-Fi or Ethernet)
3. Start capture
4. Apply display filter: `tls.handshake.type == 1` (ClientHello only)

### Step 2: Trigger Browser Connection

For each browser:

1. Clear browser cache and cookies
2. Close all browser windows
3. Open a new browser window
4. Navigate to a TLS 1.3 enabled website (e.g., https://www.cloudflare.com)
5. Wait for page to load completely

### Step 3: Export ClientHello Data

1. In Wireshark, find the ClientHello packet
2. Expand: Transport Layer Security → TLSv1.3 Record Layer → Handshake Protocol: Client Hello
3. Right-click on "Client Hello" → Copy → Bytes → Hex Stream
4. Save to file: `captures/<browser>_<version>_clienthello.hex`

### Step 4: Extract Key Fields

For each capture, document:

**Cipher Suites:**
- Expand "Cipher Suites" in Wireshark
- Note the order and values
- Look for GREASE values (0x?A?A pattern)

**Extensions:**
- Expand "Extension: ..." for each extension
- Note the extension type and order
- Pay special attention to:
  - supported_versions
  - supported_groups
  - signature_algorithms
  - key_share
  - application_settings (0x001b)
  - compress_certificate
  - padding

**GREASE Values:**
- Note positions of GREASE cipher suites
- Note positions of GREASE extensions
- Document the pattern (e.g., "Chrome places GREASE in first position")

**Padding:**
- Find "Extension: padding"
- Note the padding length
- Capture multiple samples to determine distribution

## Capture Locations

Store captures in: `rustls/rustls/src/custls/test_data/browser_captures/`

Directory structure:
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

## Analysis Format

Each `analysis.json` should contain:

```json
{
  "browser": "Chrome",
  "version": "130.0.6723.92",
  "platform": "Windows 11",
  "capture_date": "2026-01-23",
  "tls_version": "1.3",
  "cipher_suites": [
    "0x1301",
    "0x1302",
    "0x1303"
  ],
  "grease_cipher_positions": [0],
  "extensions": [
    {"type": "0x0000", "name": "server_name"},
    {"type": "0x0017", "name": "extended_master_secret"},
    {"type": "0x002b", "name": "supported_versions"}
  ],
  "grease_extension_positions": [1, 5],
  "padding_length": 128,
  "key_share_groups": ["x25519", "secp256r1"],
  "signature_algorithms": [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256"
  ],
  "alpn_protocols": ["h2", "http/1.1"],
  "notes": "Captured from fresh browser install"
}
```

## Multiple Samples

Capture at least 5 samples per browser to understand:
- Padding length distribution
- GREASE value variation
- Extension ordering consistency
- Random field variation

## Validation Targets

Test against these known TLS fingerprinting services:
- https://www.cloudflare.com (Cloudflare Bot Management)
- https://www.akamai.com (Akamai Bot Manager)
- https://tls.peet.ws/api/all (TLS fingerprint analysis)
- https://ja3er.com/json (JA3 fingerprint)

## Security Considerations

- Use test accounts only
- Don't capture sensitive data
- Clear browser data between captures
- Use incognito/private mode when appropriate

## Automation

For automated capture, consider:
- Selenium WebDriver for browser automation
- tshark (CLI Wireshark) for packet capture
- Python scripts for parsing and analysis

Example tshark command:
```bash
tshark -i eth0 -Y "tls.handshake.type == 1" -T fields \
  -e tls.handshake.ciphersuite \
  -e tls.handshake.extension.type \
  -w chrome_capture.pcap
```

## Next Steps

After capturing:
1. Parse captures into structured data (see `browser_validation.rs`)
2. Compare with custls template output (task 20.2)
3. Test against real servers (task 20.3)
