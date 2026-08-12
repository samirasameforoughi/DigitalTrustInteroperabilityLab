// Crypto/CryptoAPIAdapter.h
// Legacy CryptoAPI (CSP) enumeration and diagnostics

#pragma once
#include "../stdafx.h"
#include "../Core/DiagnosticResult.h"

struct CSPInfo
{
	CString     strName;
	DWORD       dwType;
	CString     strTypeDescription;
	CString     strVersion;       // from PP_VERSION
	CString     strContainer;     // default container (PP_CONTAINER)
	BOOL        bCanSign;
	BOOL        bCanEncrypt;
	BOOL        bHardware;        // CRYPT_IMPL_HARDWARE
	BOOL        bSoftware;        // CRYPT_IMPL_SOFTWARE
	BOOL        bRemovable;       // CRYPT_IMPL_REMOVABLE
	DWORD       dwEnumError;      // error during acquisition (0 = success)
	CString     strAlgorithms;    // comma-separated list
};

class CCryptoAPIAdapter
{
public:
	CCryptoAPIAdapter();
	~CCryptoAPIAdapter();

	// Enumerate all installed CSPs
	BOOL EnumerateProviders();

	// Run diagnostics on all CSPs
	BOOL RunDiagnostics();

	int  GetProviderCount() const;
	const CSPInfo* GetProvider(int nIndex) const;

	const CDiagnosticResult& GetDiagnosticResult() const;

	void Clear();


	void AnalyzeProvider(CSPInfo& info);
	void EnumerateAlgorithms(HCRYPTPROV hProv, CSPInfo& info);
	CString GetProviderVersion(HCRYPTPROV hProv);
	CString GetProviderContainer(HCRYPTPROV hProv);
	BOOL    CheckHardwareFlag(HCRYPTPROV hProv);

	CArray<CSPInfo, const CSPInfo&> m_providers;
	CDiagnosticResult               m_diagResult;
};