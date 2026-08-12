// Crypto/CNGAdapter.h
// CNG / KSP enumeration (Vista+)

#pragma once
#include "../stdafx.h"
#include "../Core/DiagnosticResult.h"

struct KSPInfo
{
	CString     strName;
	CString     strComment;
	DWORD       dwFlags;
	BOOL        bIsHardware;
	BOOL        bIsSoftware;
	BOOL        bIsRemovable;
	DWORD       dwEnumError;
	BOOL        bAvailable;    // Could we open it?
};

class CCNGAdapter
{
public:
	CCNGAdapter();
	~CCNGAdapter();

	// Returns TRUE if CNG is available on this OS
	BOOL IsCNGAvailable() const;

	// Enumerate KSPs (Vista+)
	BOOL EnumerateProviders();

	// Run diagnostics
	BOOL RunDiagnostics();

	int  GetProviderCount() const;
	const KSPInfo* GetProvider(int nIndex) const;

	const CDiagnosticResult& GetDiagnosticResult() const;

	void Clear();


	BOOL LoadNCryptFunctions();
	void UnloadNCrypt();

	// Dynamic function pointers (Vista+ only)
	HMODULE m_hNcrypt;

	typedef SECURITY_STATUS (WINAPI* PFN_NCryptEnumStorageProviders)(
		DWORD*, NCryptProviderName**, DWORD);
	typedef SECURITY_STATUS (WINAPI* PFN_NCryptFreeBufferList)(
		NCryptBufferDesc*);
	typedef SECURITY_STATUS (WINAPI* PFN_NCryptOpenStorageProvider)(
		NCRYPT_PROV_HANDLE*, LPCWSTR, DWORD);
	typedef SECURITY_STATUS (WINAPI* PFN_NCryptFreeObject)(NCRYPT_HANDLE);
	typedef SECURITY_STATUS (WINAPI* PFN_NCryptGetProperty)(
		NCRYPT_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD*, DWORD);

	PFN_NCryptEnumStorageProviders  m_pfnEnumStorageProviders;
	PFN_NCryptOpenStorageProvider   m_pfnOpenStorageProvider;
	PFN_NCryptFreeObject            m_pfnFreeObject;
	PFN_NCryptGetProperty           m_pfnGetProperty;

	// Note: NCryptFreeBufferList is available via NCryptFreeBuffer
	typedef SECURITY_STATUS (WINAPI* PFN_NCryptFreeBuffer)(PVOID);
	PFN_NCryptFreeBuffer m_pfnFreeBuffer;

	CArray<KSPInfo, const KSPInfo&> m_providers;
	CDiagnosticResult               m_diagResult;
	BOOL                            m_bCNGAvailable;
};