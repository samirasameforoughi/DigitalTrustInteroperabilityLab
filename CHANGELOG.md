# Changelog

All notable changes to this project are documented in this file.

## [1.0.0] - 2026-08-11 — Initial Release

### Added
- Phase 1: System diagnostics, provider enumeration, certificate 
  store analysis
- Phase 2: Dynamic PKCS#11 DLL testing with 9 standard test cases
- Phase 3: Multi-provider signature engine with SHA-1/256/384/512 
  support
- Phase 3.5: PKCS#11 direct signing with PIN
- Cross-path signature determinism proof
- Signature history panel
- Award-grade HTML report generator
- In-app PIN dialog with SecureZeroMemory
- HP_HASHVAL injection for legacy CSP SHA-256 support
- Automatic DLL reload for vendor state recovery

### Interoperability Findings
- Token CSP (iPassCSPv1) operates independent of Smart Card Service
- Legacy Microsoft CSPs (Base/Enhanced/Strong) do not support SHA-256
- CryptoAPI and PKCS#11 produce byte-identical signatures with 
  same key

### Security
- No PIN persistence in memory
- No private key extraction
- No network activity
- No telemetry

## Roadmap

### [1.1.0] - Planned
- Cross-path automated comparison
- Provider Capability Matrix report section
- Signature verification via PKCS#11

### [2.0.0] - Planned
- OCSP live testing
- CRL fetching and analysis
- RFC 3161 timestamp support
