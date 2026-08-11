# Security Policy

## Reporting a Security Vulnerability

Digital Trust Interoperability Lab handles sensitive cryptographic 
operations. If you discover a security issue, please report it 
responsibly.

### How to Report

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email:  
📧 **samirasameforoughi@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested remediation (if any)

### Response Timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 7 days
- **Fix or mitigation:** as soon as possible based on severity

### Scope

Vulnerabilities we care about:
- Memory leaks of sensitive data (PIN, keys)
- Buffer overflows or memory corruption
- Improper handling of cryptographic material
- Incorrect verification logic

### Out of Scope

- Third-party PKCS#11 DLL vulnerabilities (report to vendor)
- Vulnerabilities in Windows CryptoAPI (report to Microsoft)
- Issues requiring physical access to the machine

## Security Design Principles

This tool is designed with the following security guarantees:

1. **No PIN persistence** — `SecureZeroMemory` used after every 
   PIN operation
2. **No private key extraction** — keys never leave the provider
3. **No network activity** — 100% offline operation
4. **No telemetry** — no data collection whatsoever
5. **Local-only reports** — no cloud upload
6. **Standard User privilege** — no elevated access required
