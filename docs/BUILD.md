# Build Instructions

## Requirements

### Development Environment

- **Visual C++ 2008** (Visual Studio 2008 with Service Pack 1)
  - Professional or Standard edition
  - Or: Visual Studio 2008 Express + Windows SDK
- **Windows SDK** (included with VS 2008)
- **MFC libraries** (part of VS 2008)

### Target System

- Windows 7 or later
- 32-bit or 64-bit (via WOW64)
- No runtime dependencies (statically linked CRT)

---

## Build Steps

### 1. Open the Solution

1. Launch Visual C++ 2008
2. **File → Open → Project/Solution**
3. Navigate to `source/DigitalTrustLab.sln`
4. Open

### 2. Configure Build Type

**For Release build (recommended for distribution):**

1. Toolbar: Select **Release** from configuration dropdown
2. Toolbar: Select **Win32** from platform dropdown

**For Debug build (for development):**

1. Configuration: **Debug**
2. Platform: **Win32**

### 3. Verify Settings

Right-click project → **Properties**

Verify these settings:

**C/C++ → Code Generation:**

- Runtime Library: **Multi-threaded (/MT)** for Release
  or **Multi-threaded Debug (/MTd)** for Debug
- This ensures no external Visual C++ runtime is needed

**General:**

- Character Set: **Use Unicode Character Set**
- Use of MFC: **Use MFC in a Static Library**

**Linker → System:**

- SubSystem: **Windows (/SUBSYSTEM:WINDOWS)**

### 4. Build

**Menu → Build → Rebuild Solution** (or `Ctrl+Alt+F7`)

Expected output:

```
1>------ Rebuild All started: Project: DigitalTrustLab ...
1>Compiling...
1>stdafx.cpp
1>DigitalTrustLab.cpp
1>DigitalTrustLabDlg.cpp
1>DiagnosticView.cpp
1>(... more files ...)
1>Linking...
1>Build succeeded.
========== Rebuild All: 1 succeeded, 0 failed, 0 skipped ==========
```

### 5. Locate the EXE

**Release build output:**

```
source/Release/DigitalTrustLab.exe
```

**Debug build output:**

```
source/Debug/DigitalTrustLab.exe
```

---

## Distribution

The output EXE is fully portable:

- ✅ No installer required
- ✅ No registry entries
- ✅ No dependency DLLs (statically linked CRT + MFC)
- ✅ Can be run from USB drive
- ✅ Single-file distribution

**File size:** approximately 2-3 MB (Release)

---

## Testing After Build

### Basic Test

1. Run `DigitalTrustLab.exe`
2. Click **[Run All Diagnostics]**
3. Verify all 4 diagnostic categories complete:
   - System Information
   - CryptoAPI / CSP Diagnostics
   - CNG / KSP Diagnostics
   - Certificate Store Analysis

### Advanced Test (with PKCS#11 token)

1. Connect a hardware token
2. Menu **PKCS#11 → Select DLL** → choose vendor's DLL
3. Menu **PKCS#11 → Run PKCS#11 Tests**
4. Verify all 9 tests complete

### Signature Test (requires PIN)

1. **Signature Test** tab
2. Select certificate + file
3. **[Sign]** → enter PIN → verify success
4. **[Sign via PKCS#11]** → enter PIN → verify success
5. **[Verify]** → verify success

### Report Test

1. Menu **Report → Generate HTML Report**
2. Save the HTML file
3. Open in browser
4. Verify:
   - Executive Summary
   - Signature Test Results
   - Standards Compliance table
   - All certificate data

---

## Troubleshooting Build Issues

### Error: "MFC libraries not found"

**Solution:** Reinstall Visual C++ 2008 with MFC option enabled.

### Error: "Cannot open include file: 'stdafx.h'"

**Solution:** Ensure the project is built via the Solution file, 
not individual files.

### Error: "unresolved external symbol"

**Solution:** Ensure MFC is set to **Use MFC in a Static Library** 
(not Shared DLL).

### Warning: "This project has been converted"

**Note:** If VS 2008 asks to convert the project, click Yes. This 
happens if the project was created in an older version.

---

## Compile-Time Constants

### Character Set

The project uses **Unicode** (`UNICODE` and `_UNICODE` defined).

### MFC Version

Uses MFC 9.0 (bundled with VS 2008).

### Target Windows Version

`_WIN32_WINNT=0x0501` (Windows XP or later) — provides maximum 
compatibility.

---

## Compiler Warnings

The project may produce warnings related to:

- Deprecated functions (safe to ignore, project uses `_s` variants)
- Signed/unsigned comparison (safe, all reviewed)
- Deprecated PKCS#11 mechanisms (safe, backward compatibility)

**No warnings should be treated as errors.**

---

## Dependencies

### Included with Windows

- Win32 API
- CryptoAPI (`crypt32.dll`, `advapi32.dll`)
- CNG (`ncrypt.dll`, `bcrypt.dll` — Vista+)
- Common Controls (`comctl32.dll`)

### Included with Visual Studio

- MFC libraries (statically linked)
- CRT libraries (statically linked)

### Optional (runtime)

- PKCS#11 DLL from any vendor (for token testing)

---

## Project Structure

```
source/
├── DigitalTrustLab.sln          (Solution file)
├── DigitalTrustLab.vcproj       (Project file, VS 2008)
├── stdafx.h                     (Precompiled header)
├── stdafx.cpp
├── DigitalTrustLab.cpp          (Application class)
├── DigitalTrustLab.h
├── DigitalTrustLabDlg.cpp       (Main dialog)
├── DigitalTrustLabDlg.h
├── DiagnosticView.cpp           (Multi-tab UI)
├── DiagnosticView.h
├── Resource.h                   (Resource IDs)
├── DigitalTrustLab.rc           (Resources)
├── res/                         (Icons, bitmaps)
│
├── Core/                        (Diagnostic engine)
│   ├── DiagnosticEngine.h
│   ├── DiagnosticEngine.cpp
│   ├── DiagnosticResult.h
│   └── SystemInfo.h
│
├── Certificate/                 (Cert management)
│   ├── CertificateInfo.h
│   ├── CertificateManager.h
│   └── CertificateManager.cpp
│
├── PKCS11/                      (PKCS#11 loader)
│   ├── PKCS11Types.h
│   ├── PKCS11Loader.h
│   └── PKCS11Loader.cpp
│
├── Providers/                   (Windows crypto)
│   ├── CryptoAPIAdapter.h
│   ├── CryptoAPIAdapter.cpp
│   ├── CNGAdapter.h
│   └── CNGAdapter.cpp
│
├── Signature/                   (Sign/verify)
│   ├── SignatureEngine.h
│   ├── SignatureEngine.cpp
│   ├── SignatureVerifier.h
│   └── SignatureVerifier.cpp
│
└── Utils/                       (Helpers)
    ├── Logger.h
    ├── Logger.cpp
    ├── ErrorHelper.h
    ├── ErrorHelper.cpp
    ├── StringHelper.h
    └── StringHelper.cpp
```

---

## Modifying the Code

### Coding Standards

- **C++03 only** — no C++11 features
- No `auto`, no lambdas, no `nullptr`, no range-for
- Use `CString` for strings
- Use `CArray` for arrays
- Use `_sntprintf_s` for string formatting
- Always check Win32 API return values

### Style

- Braces on new lines (Allman style)
- 4-space indentation
- Descriptive variable names
- `m_` prefix for member variables
- `strXxx` for CString, `nXxx` for int, `bXxx` for BOOL, etc.

### Testing After Modifications

Always:

1. Build both Debug and Release
2. Run All Diagnostics
3. Test PKCS#11 with a real DLL
4. Test signature roundtrip
5. Generate HTML report

---

## Support

For build issues, contact:

**Samira Same Foroughi**  
Email: samirasameforoughi@gmail.com  
GitHub: github.com/samirasameforoughi
