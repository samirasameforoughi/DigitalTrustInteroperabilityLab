// Utils/ErrorHelper.h
// Windows error code translation
// Digital Trust Interoperability Lab - Phase 1
// DO NOT include stdafx.h here

#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <afx.h>

class CErrorHelper
{
public:
	// GetLastError() to string
	static CString GetLastErrorString(DWORD dwError = 0);

	// HRESULT to string
	static CString GetHResultString(HRESULT hr);

	// SECURITY_STATUS (NCrypt) to string
	static CString GetSecurityStatusString(SECURITY_STATUS ss);

	// Crypto-specific error descriptions
	static CString GetCryptoErrorDescription(DWORD dwError);

	// Certificate store error
	static CString GetCertStoreError(DWORD dwError);

	// Admin check
	static BOOL IsRunningAsAdmin();

	// Windows version string
	static CString GetWindowsVersionString();

	// DWORD to hex string
	static CString DwordToHex(DWORD dw);

	// Format diagnostic error
	static CString FormatDiagnosticError(
		DWORD dwCode,
		const CString& strSource,
		const CString& strContext);


	static CString GetWindowsVersionFromRegistry();
	static CString GetWindowsVersionFromAPI();
};