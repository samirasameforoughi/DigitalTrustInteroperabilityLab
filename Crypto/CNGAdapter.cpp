// Crypto/CNGAdapter.cpp
// Digital Trust Interoperability Lab - Phase 1

#include "stdafx.h"
#include "CNGAdapter.h"
#include "../Utils/Logger.h"
#include "../Utils/ErrorHelper.h"

CCNGAdapter::CCNGAdapter()
: m_hNcrypt(NULL)
, m_pfnEnumStorageProviders(NULL)
, m_pfnOpenStorageProvider(NULL)
, m_pfnFreeObject(NULL)
, m_pfnGetProperty(NULL)
, m_pfnFreeBuffer(NULL)
, m_bCNGAvailable(FALSE)
{
	m_diagResult.m_strCheckName = _T("CNG / KSP Diagnostics");
	m_diagResult.m_strCategory  = _T("CNG");
}

CCNGAdapter::~CCNGAdapter()
{
	UnloadNCrypt();
	Clear();
}

BOOL CCNGAdapter::IsCNGAvailable() const
{
	return m_bCNGAvailable;
}

BOOL CCNGAdapter::LoadNCryptFunctions()
{
	if (m_hNcrypt != NULL)
		return TRUE;  // Already loaded

	m_hNcrypt = LoadLibrary(_T("ncrypt.dll"));
	if (m_hNcrypt == NULL)
	{
		CLogger::Instance().Warning(_T("CNGAdapter"),
			_T("ncrypt.dll not found - CNG/KSP not available (Windows XP?)"));
		m_bCNGAvailable = FALSE;
		return FALSE;
	}

	m_pfnEnumStorageProviders = (PFN_NCryptEnumStorageProviders)
		GetProcAddress(m_hNcrypt, "NCryptEnumStorageProviders");
	m_pfnOpenStorageProvider = (PFN_NCryptOpenStorageProvider)
		GetProcAddress(m_hNcrypt, "NCryptOpenStorageProvider");
	m_pfnFreeObject = (PFN_NCryptFreeObject)
		GetProcAddress(m_hNcrypt, "NCryptFreeObject");
	m_pfnGetProperty = (PFN_NCryptGetProperty)
		GetProcAddress(m_hNcrypt, "NCryptGetProperty");
	m_pfnFreeBuffer = (PFN_NCryptFreeBuffer)
		GetProcAddress(m_hNcrypt, "NCryptFreeBuffer");

	if (!m_pfnEnumStorageProviders ||
		!m_pfnOpenStorageProvider  ||
		!m_pfnFreeObject           ||
		!m_pfnFreeBuffer)
	{
		CLogger::Instance().Error(_T("CNGAdapter"),
			_T("Required NCrypt functions not found in ncrypt.dll"));
		UnloadNCrypt();
		m_bCNGAvailable = FALSE;
		return FALSE;
	}

	m_bCNGAvailable = TRUE;
	return TRUE;
}

void CCNGAdapter::UnloadNCrypt()
{
	m_pfnEnumStorageProviders = NULL;
	m_pfnOpenStorageProvider  = NULL;
	m_pfnFreeObject           = NULL;
	m_pfnGetProperty          = NULL;
	m_pfnFreeBuffer           = NULL;

	if (m_hNcrypt != NULL)
	{
		FreeLibrary(m_hNcrypt);
		m_hNcrypt = NULL;
	}
}

void CCNGAdapter::Clear()
{
	m_providers.RemoveAll();
}

int CCNGAdapter::GetProviderCount() const
{
	return (int)m_providers.GetSize();
}

const KSPInfo* CCNGAdapter::GetProvider(int nIndex) const
{
	if (nIndex < 0 || nIndex >= (int)m_providers.GetSize())
		return NULL;
	return &m_providers[nIndex];
}

const CDiagnosticResult& CCNGAdapter::GetDiagnosticResult() const
{
	return m_diagResult;
}

BOOL CCNGAdapter::EnumerateProviders()
{
	m_diagResult.MarkStart();
	Clear();

	if (!LoadNCryptFunctions())
	{
		m_diagResult.AddWarning(_T("CNGAdapter"),
			_T("CNG/KSP not available on this system"),
			_T("CNG requires Windows Vista or later."));
		m_diagResult.SetStatus(DIAG_STATUS_NOT_AVAILABLE);
		m_diagResult.MarkEnd();
		return FALSE;
	}

	CLogger::Instance().Info(_T("CNGAdapter"), _T("Enumerating KSP providers..."));

	DWORD dwCount = 0;
	NCryptProviderName* pProvNames = NULL;

	SECURITY_STATUS ss = m_pfnEnumStorageProviders(
		&dwCount,
		&pProvNames,
		0);

	if (ss != ERROR_SUCCESS || pProvNames == NULL)
	{
		CLogger::Instance().LogFmt(LOG_LEVEL_ERROR, _T("CNGAdapter"),
			_T("NCryptEnumStorageProviders failed: 0x%08X - %s"),
			(DWORD)ss,
			(LPCTSTR)CErrorHelper::GetSecurityStatusString(ss));

		m_diagResult.AddError(_T("CNGAdapter"),
			_T("NCryptEnumStorageProviders failed"),
			_T("CNG storage provider enumeration failed."),
			(DWORD)ss);
		m_diagResult.SetStatus(DIAG_STATUS_FAIL);
		m_diagResult.MarkEnd();
		return FALSE;
	}

	for (DWORD i = 0; i < dwCount; i++)
	{
		KSPInfo info;
		info.dwEnumError = 0;
		info.bAvailable  = FALSE;
		info.bIsHardware = FALSE;
		info.bIsSoftware = FALSE;
		info.bIsRemovable = FALSE;
		info.dwFlags = 0;

		if (pProvNames[i].pszName != NULL)
		{
			info.strName = CString(pProvNames[i].pszName);
		}

		if (pProvNames[i].pszComment != NULL)
		{
			info.strComment = CString(pProvNames[i].pszComment);
		}

		m_providers.Add(info);

		CLogger::Instance().LogFmt(LOG_LEVEL_INFO, _T("CNGAdapter"),
			_T("Found KSP: [%s]"), (LPCTSTR)info.strName);
	}

	// Free the provider name buffer
	if (pProvNames != NULL)
	{
		m_pfnFreeBuffer(pProvNames);
	}

	CLogger::Instance().LogFmt(LOG_LEVEL_INFO, _T("CNGAdapter"),
		_T("KSP enumeration complete. Found %lu provider(s)."), dwCount);

	m_diagResult.MarkEnd();
	return (dwCount > 0);
}

BOOL CCNGAdapter::RunDiagnostics()
{
	m_diagResult.MarkStart();

	if (!m_bCNGAvailable && !LoadNCryptFunctions())
	{
		m_diagResult.AddWarning(_T("CNGAdapter"),
			_T("CNG not available on this platform"),
			_T("Upgrade to Windows Vista or later to use CNG/KSP."));
		m_diagResult.SetStatus(DIAG_STATUS_NOT_AVAILABLE);
		m_diagResult.MarkEnd();
		return FALSE;
	}

	if (m_providers.GetSize() == 0)
	{
		EnumerateProviders();
	}

	if (m_providers.GetSize() == 0)
	{
		m_diagResult.AddError(_T("CNGAdapter"),
			_T("No KSP providers found"),
			_T("CNG key storage providers are not installed."),
			0);
		m_diagResult.SetStatus(DIAG_STATUS_FAIL);
		m_diagResult.MarkEnd();
		return FALSE;
	}

	// Try to open each KSP
	int nAvailable = 0;
	int nFailed    = 0;

	for (int i = 0; i < (int)m_providers.GetSize(); i++)
	{
		KSPInfo& info = m_providers[i];

		NCRYPT_PROV_HANDLE hProvider = NULL;
		SECURITY_STATUS ss = m_pfnOpenStorageProvider(
			&hProvider,
			(LPCWSTR)info.strName,
			0);

		if (ss == ERROR_SUCCESS && hProvider != NULL)
		{
			info.bAvailable = TRUE;
			nAvailable++;

			// Try to get impl type if GetProperty available
			if (m_pfnGetProperty != NULL)
			{
				DWORD dwImplType = 0;
				DWORD cbResult = 0;
				SECURITY_STATUS ssGet = m_pfnGetProperty(
					(NCRYPT_HANDLE)hProvider,
					NCRYPT_IMPL_TYPE_PROPERTY,
					(PBYTE)&dwImplType,
					sizeof(dwImplType),
					&cbResult,
					0);

				if (ssGet == ERROR_SUCCESS)
				{
					info.dwFlags      = dwImplType;
					info.bIsHardware  = (dwImplType & NCRYPT_IMPL_HARDWARE_FLAG)  ? TRUE : FALSE;
					info.bIsSoftware  = (dwImplType & NCRYPT_IMPL_SOFTWARE_FLAG)  ? TRUE : FALSE;
					info.bIsRemovable = (dwImplType & NCRYPT_IMPL_REMOVABLE_FLAG) ? TRUE : FALSE;
				}
			}

			CLogger::Instance().LogFmt(LOG_LEVEL_PASS, _T("CNGAdapter"),
				_T("KSP [%s]: AVAILABLE | HW:%s SW:%s Removable:%s"),
				(LPCTSTR)info.strName,
				info.bIsHardware  ? _T("YES") : _T("NO"),
				info.bIsSoftware  ? _T("YES") : _T("NO"),
				info.bIsRemovable ? _T("YES") : _T("NO"));

			m_pfnFreeObject((NCRYPT_HANDLE)hProvider);
		}
		else
		{
			info.bAvailable  = FALSE;
			info.dwEnumError = (DWORD)ss;
			nFailed++;

			CLogger::Instance().LogFmt(LOG_LEVEL_WARNING, _T("CNGAdapter"),
				_T("KSP [%s]: UNAVAILABLE (0x%08X - %s)"),
				(LPCTSTR)info.strName, (DWORD)ss,
				(LPCTSTR)CErrorHelper::GetSecurityStatusString(ss));
		}
	}

	TCHAR szBuf[256] = {0};
	_sntprintf_s(szBuf, 256, _TRUNCATE,
		_T("KSP Analysis: %d available, %d unavailable"),
		nAvailable, nFailed);

	if (nFailed > 0 && nAvailable == 0)
	{
		m_diagResult.AddError(_T("CNGAdapter"), CString(szBuf),
			_T("No KSP providers are accessible. Check CNG installation."), 0);
	}
	else if (nFailed > 0)
	{
		m_diagResult.AddWarning(_T("CNGAdapter"), CString(szBuf),
			_T("Some KSP providers are unavailable."));
	}
	else
	{
		m_diagResult.AddPass(_T("CNGAdapter"), CString(szBuf));
	}

	m_diagResult.RecalculateStatus();
	m_diagResult.MarkEnd();
	return TRUE;
}