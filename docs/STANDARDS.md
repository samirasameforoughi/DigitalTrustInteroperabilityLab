# Standards Reference

## Overview

Digital Trust Interoperability Lab implements only **open, publicly 
documented standards**. This document details each standard used, 
its purpose, and how it is implemented.

---

## Standards Summary

| Standard | Version | Category | RFC/Spec |
|----------|---------|----------|----------|
| **X.509** | v3 | Certificate format | RFC 5280 |
| **PKCS#11** | v2.20+ | Token interface | OASIS |
| **PKCS#7 / CMS** | Current | Message syntax | RFC 5652 |
| **PKCS#1** | v2.1 | RSA signatures | RFC 8017 |
| **CryptoAPI** | Win32 | Windows API | Microsoft |
| **CNG / KSP** | Vista+ | Modern Windows | Microsoft |
| **FIPS 180-4** | Current | Hash algorithms | NIST |
| **OCSP** | Current | Revocation | RFC 6960 |
| **CRL** | Current | Revocation | RFC 5280 §5 |

---

## Detailed Standards

### Certificate Format & Path Validation

#### X.509 (RFC 5280)

Standard for public key certificate format.

**The tool implements:**

- Certificate parsing (`CertGetCertificateContextProperty`)
- Chain building (`CertGetCertificateChain`)
- Extension inspection:
  - KeyUsage
  - ExtendedKeyUsage (EKU)
  - BasicConstraints
  - Subject Key Identifier (SKI)
  - Authority Key Identifier (AKI)
  - CRL Distribution Points (CDP)
  - Authority Information Access (AIA)
- Validity period checking
- Serial number extraction
- Subject/Issuer parsing (RDN)
- Thumbprint calculation (SHA-1, SHA-256)

**Reference:** [RFC 5280](https://tools.ietf.org/html/rfc5280)

---

### Cryptographic Message Syntax

#### PKCS#7 / CMS (RFC 5652)

Message syntax for signed and encrypted data.

**The tool uses this for:**

- Understanding signature format
- Certificate chain packaging (future phases)

**Reference:** [RFC 5652](https://tools.ietf.org/html/rfc5652)

---

### Token & Smart Card Interface

#### PKCS#11 v2.20+

Standard interface for hardware cryptographic tokens.

**The tool implements 9 core test cases:**

| Code | Function | Purpose |
|------|----------|---------|
| P11-01 | `C_Initialize` | Library initialization |
| P11-02 | `C_GetInfo` | Library version/manufacturer |
| P11-03 | `C_GetSlotList` | Enumerate slots |
| P11-04 | `C_GetSlotInfo` | Slot capabilities |
| P11-05 | `C_GetTokenInfo` | Token identity |
| P11-06 | `C_OpenSession` | Session establishment |
| P11-07 | `C_GetMechanismList` | Supported algorithms |
| P11-08 | `C_FindObjects` (Cert) | Certificate discovery |
| P11-09 | `C_FindObjects` (Key) | Private key discovery |

**Additionally, for signing:**

- `C_Login` (with PIN)
- `C_SignInit`
- `C_Sign`
- `C_Logout`
- `C_FindObjectsInit`, `C_FindObjectsFinal`
- `C_CloseSession`
- `C_Finalize`

**Reference:** [OASIS PKCS#11](http://docs.oasis-open.org/pkcs11/)

---

### Signature Algorithms

#### PKCS#1 v2.1 (RFC 8017)

RSA cryptography standard. The tool uses:

- **RSA-PKCS#1 v1.5 padding** for signature operations
- **DigestInfo ASN.1 encoding** for hash algorithm identification

**ASN.1 DigestInfo prefixes** (hardcoded per RFC 3447 Appendix A.2.4):

```
SHA-1:   30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14
SHA-256: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
SHA-384: 30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30
SHA-512: 30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40
```

These prefixes are prepended to the hash value before RSA signing 
via PKCS#11's `CKM_RSA_PKCS` mechanism.

**Reference:** [RFC 8017](https://tools.ietf.org/html/rfc8017)

---

#### FIPS 180-4

Secure Hash Standard.

**The tool supports:**

- **SHA-1** (160-bit) — legacy compatibility
- **SHA-256** (256-bit) — recommended
- **SHA-384** (384-bit) — high security
- **SHA-512** (512-bit) — maximum security

**Implementation paths:**

- Legacy CSP (via `CryptCreateHash`)
- Modern CSP (via `CryptCreateHash` with SHA-2 ALG_IDs)
- CNG (via BCrypt algorithms)
- HP_HASHVAL injection (for legacy compatibility)

**Reference:** [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final)

---

### Windows Cryptographic APIs

#### CryptoAPI (CAPI)

Legacy Windows crypto interface (Windows 2000+).

**Used for:**

- CSP enumeration (`CryptEnumProviders`)
- Provider acquisition (`CryptAcquireContext`)
- Certificate operations
- Hash operations (`CryptCreateHash`, `CryptHashData`)
- Signing (`CryptSignHash`)
- Verification (`CryptVerifySignature`)

**Reference:** [Microsoft CryptoAPI Documentation](https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-portal)

---

#### CNG (Cryptography Next Generation)

Modern Windows crypto interface (Vista+).

**Used for:**

- KSP enumeration (`NCryptEnumProviders`)
- Modern algorithm support
- BCrypt hashing (`BCryptCreateHash`)
- CNG key operations (`NCryptOpenKey`, `NCryptSignHash`)

**Reference:** [Microsoft CNG Documentation](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)

---

### Certificate Revocation

#### OCSP (RFC 6960)

Online Certificate Status Protocol.

**The tool uses Windows' built-in OCSP support** via 
`CertGetCertificateChain` with revocation flags:

- `CERT_CHAIN_REVOCATION_CHECK_END_CERT`
- `CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY`

**Reference:** [RFC 6960](https://tools.ietf.org/html/rfc6960)

---

#### CRL (RFC 5280 Section 5)

Certificate Revocation Lists.

**Handled automatically by Windows chain building.**

**Reference:** [RFC 5280 §5](https://tools.ietf.org/html/rfc5280#section-5)

---

## Future Standards (Roadmap)

### Time-Stamp Protocol

**RFC 3161** — Internet X.509 PKI Time-Stamp Protocol

Planned for Phase 6. Will include:

- TSP client
- Verification of RFC 3161 timestamps
- CAdES / PAdES long-term signature support

**Reference:** [RFC 3161](https://tools.ietf.org/html/rfc3161)

---

### Post-Quantum Cryptography

**NIST PQC Standards** (once finalized)

Planned for Phase 8. Will include:

- CRYSTALS-Kyber (KEM)
- CRYSTALS-Dilithium (signatures)
- Falcon (signatures)
- SPHINCS+ (signatures)

---

## Compliance Verification

All standards used are:

- ✅ **Publicly documented** — IETF RFCs, OASIS, NIST FIPS
- ✅ **Vendor-neutral** — no proprietary extensions
- ✅ **Backward-compatible** — works on Windows 7 and later
- ✅ **Auditable** — full source code available

---

## Non-Standard Features (None)

Digital Trust Interoperability Lab uses **zero non-standard 
features**. This includes:

- ❌ No vendor-specific PKCS#11 extensions
- ❌ No Microsoft-proprietary APIs beyond documented CryptoAPI/CNG
- ❌ No undocumented Win32 APIs
- ❌ No registry hacks
- ❌ No kernel-mode code

This ensures the tool works uniformly across all vendors and Windows 
versions.

---

## Testing Against Standards

For each standard, the tool provides diagnostic evidence:

### X.509 Compliance Test

Any RFC 5280-compliant certificate is correctly parsed and 
displayed with all fields.

### PKCS#11 Compliance Test

Any PKCS#11 v2.20+ compliant library passes all 9 basic tests 
(P11-01 through P11-08 always pass; P11-09 may WARNING due to 
silent mode).

### RSA-PKCS#1 v1.5 Compliance Test

**Cross-Path Signature Determinism** proves that any two RSA-PKCS#1 
v1.5 compliant implementations produce byte-identical signatures 
given the same input and key.

---

## References

Full RFC and specification URLs:

| Standard | URL |
|----------|-----|
| RFC 5280 (X.509) | https://tools.ietf.org/html/rfc5280 |
| RFC 5652 (CMS) | https://tools.ietf.org/html/rfc5652 |
| RFC 6960 (OCSP) | https://tools.ietf.org/html/rfc6960 |
| RFC 8017 (PKCS#1 v2.2) | https://tools.ietf.org/html/rfc8017 |
| RFC 3161 (TSP) | https://tools.ietf.org/html/rfc3161 |
| FIPS 180-4 | https://csrc.nist.gov/publications/detail/fips/180/4/final |
| PKCS#11 v2.20 | http://docs.oasis-open.org/pkcs11/ |
| CryptoAPI Docs | https://learn.microsoft.com/en-us/windows/win32/seccrypto/ |
| CNG Docs | https://learn.microsoft.com/en-us/windows/win32/seccng/ |

---

**Digital Trust Interoperability Lab** — 100% Standards-Based
