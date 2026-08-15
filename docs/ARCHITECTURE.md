# Architecture Overview

## Design Philosophy

Digital Trust Interoperability Lab is built on five principles:

1. **Vendor Neutrality** — no proprietary code, no vendor-specific hard-coding
2. **Layer Isolation** — each cryptographic layer is tested independently
3. **Local-Only** — zero network transmission of any cryptographic material
4. **Standards Compliance** — all operations use published open standards
5. **Actionable Output** — every finding includes root cause + remediation

## System Overview

The application is a **Windows MFC dialog-based** desktop tool that 
performs comprehensive diagnostics across multiple layers of the PKI stack.

---

## Component Architecture

### Layer 1: User Interface (UI)

**Files:** `DiagnosticView.cpp`, `DigitalTrustLabDlg.cpp`

- MFC Dialog with 7 tabs
- Multi-threaded operation (all heavy work in background threads)
- Real-time console log via `PostMessage`
- Tab-based navigation:
  - Dashboard (overall status)
  - System Info
  - Crypto Providers (CSP + KSP)
  - Certificates
  - Console (log)
  - PKCS#11 Test
  - Signature Test

### Layer 2: Business Logic (Engines)

#### Diagnostic Engine

**File:** `Core/DiagnosticEngine.cpp`

Orchestrates system, provider, and certificate diagnostics.

Coordinates:
- SystemDiagnostic
- CryptoAPIAdapter
- CNGAdapter
- CertificateManager

#### Signature Engine

**File:** `Signature/SignatureEngine.cpp`

Multi-provider signature generation:
- CryptoAPI path (CSP)
- CNG path (KSP)
- HP_HASHVAL injection for legacy providers

#### Signature Verifier

**File:** `Signature/SignatureVerifier.cpp`

Cryptographic verification with certificate chain building.

#### PKCS#11 Loader

**File:** `PKCS11/PKCS11Loader.cpp`

Dynamic PKCS#11 DLL loading and testing:
- No compile-time dependency on any PKCS#11 library
- Direct `GetProcAddress` (no CK_FUNCTION_LIST struct)
- 9 standard test cases
- Login-enabled signing with PIN
- Automatic DLL reload for vendor state recovery

### Layer 3: Windows Crypto Abstractions

#### CryptoAPI Adapter

**File:** `Providers/CryptoAPIAdapter.cpp`

- Enumerates legacy CSPs via `CryptEnumProviders`
- Extracts capabilities (Sign, Encrypt, Hardware)
- Discovers supported algorithms

#### CNG Adapter

**File:** `Providers/CNGAdapter.cpp`

- Enumerates CNG KSPs via `NCryptEnumProviders`
- Tests provider availability
- Identifies hardware/software providers

#### Certificate Manager

**File:** `Certificate/CertificateManager.cpp`

- Scans 8 stores × 2 locations = 16 stores
- Analyzes each certificate:
  - Basic X.509 fields
  - Chain of trust
  - Private-key binding
  - Provider association
  - Token-backed vs software-backed

### Layer 4: Windows Native APIs

- **CryptoAPI (CAPI)** — legacy crypto (Windows 2000+)
- **CNG (Cryptography Next Generation)** — modern crypto (Vista+)
- **Certificate Store APIs** — X.509 handling
- **NCrypt** — CNG key operations

### Layer 5: Providers and Hardware

- **Legacy CSPs** (installed by vendor middleware)
- **CNG KSPs** (installed by vendor middleware)
- **PKCS#11 DLLs** (loaded dynamically)
- **Hardware tokens** (smart cards, USB tokens, HSMs)

---

## Data Flow

### Diagnostic Flow

```
User clicks [Run All Diagnostics]
    |
    v
DiagnosticEngine.RunAll()
    |
    +--> SystemInfo.Collect()
    +--> CryptoAPIAdapter.EnumerateProviders()
    +--> CNGAdapter.EnumerateProviders()
    +--> CertificateManager.EnumerateStores()
    |
    v
Results aggregated in DiagnosticResultSet
    |
    v
UI updated via PostMessage(WM_DIAG_COMPLETE)
    |
    v
Dashboard, System Info, Providers, Certificates tabs populated
```

### Signature Flow (CryptoAPI Path)

```
User clicks [Sign]
    |
    v
SignatureEngine.SignFile()
    |
    +--> Find certificate in store
    +--> CertGetCertificateContextProperty (get provider info)
    +--> CryptAcquireCertificatePrivateKey
    +--> CryptCreateHash + CryptHashData
    |       OR (for legacy CSP)
    |    Compute hash externally, then HP_HASHVAL inject
    +--> CryptSignHash (with PIN prompt from provider)
    +--> Reverse bytes (little-endian to big-endian)
    |
    v
Signature stored in SignatureResult
    |
    v
UI updated: Signature History + Result panel
```

### Signature Flow (PKCS#11 Path)

```
User clicks [Sign via PKCS#11]
    |
    v
Custom PIN dialog (in-memory template)
    |
    v
Background thread starts:
    |
    +--> PKCS11Loader.EnsureInitialized()
    |       (reload DLL if needed for vendor state recovery)
    +--> C_Login with PIN
    |       (PIN SecureZeroMemory'd after use)
    +--> FindFirstSigningKey()
    +--> Read file into memory
    +--> Compute SHA-256 hash externally
    +--> Build ASN.1 DigestInfo + Hash
    +--> C_SignInit + C_Sign (CKM_RSA_PKCS)
    +--> C_Logout
    |
    v
Signature stored in SignatureResult
    |
    v
UI updated
```

### Cross-Path Comparison

Both signatures should be **byte-identical** for RSA-PKCS#1 v1.5 
signing with the same key, file, and hash algorithm. This is proven 
empirically in the tool's output.

---

## Thread Safety

- All heavy operations run in **background threads**
- UI updates via `PostMessage` (never `SendMessage` from workers)
- No shared mutable state between threads without synchronization
- Thread lifecycle:
  - Created with `CreateThread`
  - Handle stored in view member
  - Waited on with `WaitForSingleObject` in destructor
  - Closed with `CloseHandle` after completion

---

## Memory Safety

- `SecureZeroMemory` for all PIN buffers
- No `strcpy` / `sprintf` — only `_sntprintf_s`, `_tcscpy_s`
- Explicit `LocalFree` for all `LocalAlloc` allocations
- RAII where possible (via MFC classes like `CString`, `CFile`)

---

## Error Handling

- Every Win32 API call is checked for error
- Errors logged with descriptive messages
- User-facing errors show:
  - Human-readable description
  - Error code (for support)
  - Suggested remediation

---

## Vendor-Neutral Design Details

### PKCS#11 Loader

Uses **direct `GetProcAddress`** instead of `CK_FUNCTION_LIST` 
struct to avoid layout compatibility issues with vendor DLLs.

This approach was chosen after crash reports from certain vendor 
DLLs that use non-standard struct layouts.

### Provider Detection

Never hard-codes vendor names. All provider identification is 
runtime-discovered from:

- `CryptEnumProviders` (CSPs)
- `NCryptEnumProviders` (KSPs)
- User selection (PKCS#11 DLLs)

### Certificate Store

Uses only standard Windows certificate store APIs. No registry 
hacks, no undocumented APIs.

---

## Build Configuration

| Setting | Value |
|---------|-------|
| **Compiler** | Visual C++ 2008 (VS 2008 SP1) |
| **Framework** | MFC (statically linked) |
| **Target** | Win32 (x86) |
| **CRT** | Multi-threaded static (`/MT` for Release) |
| **Character Set** | Unicode (UTF-16 internal) |
| **Optimization** | `/O2` for Release |
| **Debug info** | `/Zi` (both Debug and Release) |

---

## Distribution Model

- Single portable EXE
- No installer required
- No registry entries
- No dependency DLLs (statically linked CRT)
- Can be run from USB drive
- Uninstall = delete file

---

## Extension Points

The architecture supports future extensions:

1. **Additional adapters** — add new provider types
2. **Additional test cases** — extend PKCS#11 test suite
3. **Additional report formats** — JSON, XML, PDF
4. **Additional standards** — TSP, OCSP live testing
5. **Cross-machine mode** — export/import diagnostics

---

## Summary Diagram

```
+----------------------------------------------------------+
|                    USER INTERFACE (MFC)                  |
|  Dashboard | System | Providers | Certs | PKCS11 | Sign  |
+----------------------+-----------------------------------+
                       |
     +-----------------+-------------------+
     |                 |                   |
     v                 v                   v
+---------+     +-------------+      +-----------+
|Diagnos. |     |  Signature  |      |  PKCS#11  |
| Engine  |     |   Engine    |      |   Loader  |
+----+----+     +------+------+      +-----+-----+
     |                 |                   |
     v                 v                   v
+----------------------------+     +--------------+
| Windows CryptoAPI + CNG    |     | Vendor DLLs  |
| (Vendor-Neutral Layer)     |     +--------------+
+----+---------------+-------+            |
     |               |                    |
     v               v                    v
+---------+     +---------+          +---------+
| Legacy  |     |  CNG    |          | PKCS#11 |
|  CSPs   |     |  KSPs   |          | Vendor  |
+----+----+     +----+----+          +----+----+
     |               |                    |
     +---------------+--------------------+
                     |
                     v
        +--------------------------+
        |   HARDWARE TOKENS        |
        |   Smart Cards, USB, HSM  |
        +--------------------------+
```

---

**Digital Trust Interoperability Lab** — Vendor-Neutral by Design
