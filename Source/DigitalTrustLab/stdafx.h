
#pragma once

// Windows version targeting - XP SP3 and later
#ifndef WINVER
#define WINVER 0x0501
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#ifndef _WIN32_IE
#define _WIN32_IE 0x0600
#endif

#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN
#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS
#define _AFX_ALL_WARNINGS

// MFC core - MUST come before windows.h
#include <afxwin.h>
#include <afxext.h>
#include <afxcmn.h>
#include <afxmt.h>
#include <afxtempl.h>
#include <afxdlgs.h>

// Windows crypto
#include <wincrypt.h>
#include <wintrust.h>
#include <winsvc.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <ncrypt.h>

// Standard C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

// Libraries
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ncrypt.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Comctl32.lib")

// Compatibility definitions for older Windows SDK headers.
#ifndef szOID_OIWSEC_sha1
#define szOID_OIWSEC_sha1 "1.3.14.3.2.26"
#endif

#ifndef szOID_NIST_sha256
#define szOID_NIST_sha256 "2.16.840.1.101.3.4.2.1"
#endif

#ifndef szOID_RSA_RSA
#define szOID_RSA_RSA "1.2.840.113549.1.1.1"
#endif

#ifndef szOID_RSA_SHA1RSA
#define szOID_RSA_SHA1RSA "1.2.840.113549.1.1.5"
#endif

#ifndef szOID_RSA_SHA256RSA
#define szOID_RSA_SHA256RSA "1.2.840.113549.1.1.11"
#endif

#ifndef CALG_RSA_SIGN
#define CALG_RSA_SIGN ((ALG_ID)0x00002400)
#endif

#ifndef CALG_OID_INFO_CNG_ONLY
#define CALG_OID_INFO_CNG_ONLY ((ALG_ID)0xFFFFFFFF)
#endif

#ifndef CALG_OID_INFO_PARAMETERS
#define CALG_OID_INFO_PARAMETERS ((ALG_ID)0xFFFFFFFE)
#endif

#ifndef CRYPT_OID_INFO_OID_KEY
#define CRYPT_OID_INFO_OID_KEY 1
#endif

#ifndef CRYPT_OID_INFO_SIGN_KEY
#define CRYPT_OID_INFO_SIGN_KEY 4
#endif

#ifndef CRYPT_HASH_ALG_OID_GROUP_ID
#define CRYPT_HASH_ALG_OID_GROUP_ID 1
#endif

#ifndef CRYPT_PUBKEY_ALG_OID_GROUP_ID
#define CRYPT_PUBKEY_ALG_OID_GROUP_ID 3
#endif

#ifndef CRYPT_SIGN_ALG_OID_GROUP_ID
#define CRYPT_SIGN_ALG_OID_GROUP_ID 4
#endif

#ifndef CALG_SHA1
#define CALG_SHA1 ((ALG_ID)0x00008004)
#endif

#ifndef CALG_SHA_256
#define CALG_SHA_256 ((ALG_ID)0x0000800c)
#endif

#ifndef CRYPT_ACQUIRE_COMPARE_KEY_FLAG
#define CRYPT_ACQUIRE_COMPARE_KEY_FLAG 0x00000004
#endif

#ifndef CMSG_AUTHENTICATED_ATTRIBUTES_FLAG
#define CMSG_AUTHENTICATED_ATTRIBUTES_FLAG 0x00000008
#endif

// Visual styles
#ifdef _UNICODE
#if defined _M_IX86
#pragma comment(linker, \
    "/manifestdependency:\"type='win32' " \
    "name='Microsoft.Windows.Common-Controls' " \
    "version='6.0.0.0' " \
    "processorArchitecture='x86' " \
    "publicKeyToken='6595b64144ccf1df' " \
    "language='*'\"")
#elif defined _M_X64
#pragma comment(linker, \
    "/manifestdependency:\"type='win32' " \
    "name='Microsoft.Windows.Common-Controls' " \
    "version='6.0.0.0' " \
    "processorArchitecture='amd64' " \
    "publicKeyToken='6595b64144ccf1df' " \
    "language='*'\"")
#endif
#endif

// IMPORTANT: Do NOT include any project headers here
// Project headers (Logger.h, ErrorHelper.h, etc.) must NOT be in stdafx.h
// They include stdafx.h themselves, which would cause circular includes