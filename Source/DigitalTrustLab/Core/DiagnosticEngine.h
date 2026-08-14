// Core/DiagnosticEngine.h
// Digital Trust Interoperability Lab - Phase 1

#pragma once

#include <windows.h>
#include <afx.h>
#include <winsvc.h>

#include "DiagnosticResult.h"

// IMPORTANT: Include CertificateInfo BEFORE CertificateManager
#include "../Certificate/CertificateInfo.h"
#include "../Certificate/CertificateManager.h"
#include "../Crypto/CryptoAPIAdapter.h"
#include "../Crypto/CNGAdapter.h"

// ============================================================
// SystemInfo - plain struct, no CObject
// ============================================================
struct SystemInfo
{
	CString strWindowsVersion;
	CString strArchitecture;
	CString strComputerName;
	CString strUserName;
	BOOL    bIsAdmin;
	CString strAdminStatus;

	BOOL    bSmartCardServiceRunning;
	CString strSmartCardServiceStatus;
	CString strCryptSvcStatus;
	CString strCertPropSvcStatus;

	SystemInfo()
		: bIsAdmin(FALSE)
		, bSmartCardServiceRunning(FALSE)
	{
	}
};

// Progress callback
typedef void (*DiagnosticProgressFunc)(
									   int nCurrent,
									   int nTotal,
									   const CString& strTask,
									   LPVOID pContext);

// ============================================================
// CDiagnosticEngine
// ============================================================
class CDiagnosticEngine
{
public:
	CDiagnosticEngine();
	~CDiagnosticEngine();

	BOOL Initialize();

	BOOL RunAll(
		DiagnosticProgressFunc pfnProgress = NULL,
		LPVOID pContext = NULL);

	BOOL RunSystemDiagnostic();
	BOOL RunCryptoAPIDiagnostic();
	BOOL RunCNGDiagnostic();
	BOOL RunCertificateDiagnostic();

	// Accessors
	const SystemInfo&           GetSystemInfo() const;
	const CDiagnosticResultSet& GetResultSet() const;
	const CCertificateManager&  GetCertificateManager() const;
	const CCryptoAPIAdapter&    GetCryptoAPIAdapter() const;
	const CCNGAdapter&          GetCNGAdapter() const;

	DiagnosticStatus GetOverallStatus() const;
	CString          GetOverallSummary() const;

	void Reset();


	// Use a different name to avoid conflict with Win32 GetSystemInfo()
	void CollectSystemInfo();

	CString QueryServiceStatus(const CString& strServiceName);
	BOOL    IsServiceRunning(const CString& strServiceName);

	SystemInfo              m_sysInfo;
	CDiagnosticResultSet    m_resultSet;
	CCertificateManager     m_certManager;
	CCryptoAPIAdapter       m_cryptoAPIAdapter;
	CCNGAdapter             m_cngAdapter;
	BOOL                    m_bInitialized;
};