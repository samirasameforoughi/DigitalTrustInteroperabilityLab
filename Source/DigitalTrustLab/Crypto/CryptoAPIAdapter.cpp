// Crypto/CryptoAPIAdapter.cpp
// Digital Trust Interoperability Lab - Phase 1

#include "stdafx.h"
#include "CryptoAPIAdapter.h"
#include "../Utils/Logger.h"
#include "../Utils/ErrorHelper.h"
#include "../Utils/StringHelper.h"

CCryptoAPIAdapter::CCryptoAPIAdapter()
{
	m_diagResult.m_strCheckName = _T("CryptoAPI / CSP Diagnostics");
	m_diagResult.m_strCategory  = _T("CryptoAPI");
}

CCryptoAPIAdapter::~CCryptoAPIAdapter()
{
	Clear();
}

void CCryptoAPIAdapter::Clear()
{
	m_providers.RemoveAll();
}

int CCryptoAPIAdapter::GetProviderCount() const
{
	return (int)m_providers.GetSize();
}

const CSPInfo* CCryptoAPIAdapter::GetProvider(int nIndex) const
{
	if (nIndex < 0 || nIndex >= (int)m_providers.GetSize())
		return NULL;
	return &m_providers[nIndex];
}

const CDiagnosticResult& CCryptoAPIAdapter::GetDiagnosticResult() const
{
	return m_diagResult;
}

BOOL CCryptoAPIAdapter::EnumerateProviders()
{
	m_diagResult.MarkStart();
	Clear();

	CLogger::Instance().Info(_T("CryptoAPIAdapter"), _T("Enumerating CSP providers..."));

	DWORD dwIndex = 0;
	DWORD dwType  = 0;
	DWORD cbName  = 0;

	// First pass: count and enumerate
	while (TRUE)
	{
		cbName = 0;
		// Get size of provider name
		BOOL bOK = CryptEnumProviders(dwIndex, NULL, 0, &dwType, NULL, &cbName);
		if (!bOK)
		{
			DWORD dwErr = GetLastError();
			if (dwErr == ERROR_NO_MORE_ITEMS)
				break;

			CLogger::Instance().LogFmt(LOG_LEVEL_ERROR, _T("CryptoAPIAdapter"),
				_T("CryptEnumProviders failed at index %lu: 0x%08X - %s"),
				dwIndex, dwErr,
				(LPCTSTR)CErrorHelper::GetLastErrorString(dwErr));
			break;
		}

		// Allocate and get name
		LPTSTR pszName = (LPTSTR)LocalAlloc(LPTR, cbName * sizeof(TCHAR));
		if (pszName == NULL)
		{
			CLogger::Instance().Error(_T("CryptoAPIAdapter"), _T("Memory allocation failed"));
			break;
		}

		bOK = CryptEnumProviders(dwIndex, NULL, 0, &dwType, pszName, &cbName);
		if (bOK)
		{
			CSPInfo info;
			info.strName = pszName;
			info.dwType  = dwType;
			info.strTypeDescription = CStringHelper::ProviderTypeToString(dwType);
			info.bCanSign    = FALSE;
			info.bCanEncrypt = FALSE;
			info.bHardware   = FALSE;
			info.bSoftware   = FALSE;
			info.bRemovable  = FALSE;
			info.dwEnumError = 0;

			m_providers.Add(info);

			CLogger::Instance().LogFmt(LOG_LEVEL_INFO, _T("CryptoAPIAdapter"),
				_T("Found CSP: [%s] Type: %s"),
				pszName,
				(LPCTSTR)info.strTypeDescription);
		}

		LocalFree(pszName);
		dwIndex++;
	}

	CLogger::Instance().LogFmt(LOG_LEVEL_INFO, _T("CryptoAPIAdapter"),
		_T("Enumeration complete. Found %d CSP provider(s)."),
		(int)m_providers.GetSize());

	m_diagResult.MarkEnd();
	return (m_providers.GetSize() > 0);
}

BOOL CCryptoAPIAdapter::RunDiagnostics()
{
	m_diagResult.MarkStart();

	if (m_providers.GetSize() == 0)
	{
		EnumerateProviders();
	}

	if (m_providers.GetSize() == 0)
	{
		m_diagResult.AddError(
			_T("CryptoAPIAdapter"),
			_T("No CryptoAPI CSP providers found on this system"),
			_T("CryptoAPI may not be properly installed."),
			GetLastError());
		m_diagResult.SetStatus(DIAG_STATUS_FAIL);
		m_diagResult.MarkEnd();
		return FALSE;
	}

	int nSuccessful = 0;
	int nFailed     = 0;

	for (int i = 0; i < (int)m_providers.GetSize(); i++)
	{
		CSPInfo& info = m_providers[i];
		AnalyzeProvider(info);

		if (info.dwEnumError == 0)
			nSuccessful++;
		else
			nFailed++;
	}

	TCHAR szBuf[256] = {0};
	_sntprintf_s(szBuf, 256, _TRUNCATE,
		_T("CSP Analysis: %d available, %d with acquisition errors"),
		nSuccessful, nFailed);

	if (nFailed > 0)
		m_diagResult.AddWarning(_T("CryptoAPIAdapter"), CString(szBuf),
		_T("Some providers returned errors during context acquisition. ")
		_T("This may indicate missing middleware or token hardware."));
	else
		m_diagResult.AddPass(_T("CryptoAPIAdapter"), CString(szBuf));

	// Check for Microsoft Base Provider (minimum requirement)
	BOOL bBaseFound = FALSE;
	for (int i = 0; i < (int)m_providers.GetSize(); i++)
	{
		if (m_providers[i].strName.Find(_T("Microsoft Base")) >= 0)
		{
			bBaseFound = TRUE;
			break;
		}
	}

	if (!bBaseFound)
	{
		m_diagResult.AddWarning(_T("CryptoAPIAdapter"),
			_T("Microsoft Base Cryptographic Provider not found"),
			_T("Core cryptographic functionality may be impaired."));
	}
	else
	{
		m_diagResult.AddPass(_T("CryptoAPIAdapter"),
			_T("Microsoft Base Cryptographic Provider is present"));
	}

	m_diagResult.RecalculateStatus();
	m_diagResult.MarkEnd();
	return TRUE;
}

void CCryptoAPIAdapter::AnalyzeProvider(CSPInfo& info)
{
	// Try to acquire a context
	// Use CRYPT_VERIFYCONTEXT for enumeration (no key container access)
	HCRYPTPROV hProv = NULL;
	BOOL bAcquired = CryptAcquireContext(
		&hProv,
		NULL,               // No container
		info.strName,
		info.dwType,
		CRYPT_VERIFYCONTEXT | CRYPT_SILENT
		);

	if (!bAcquired)
	{
		info.dwEnumError = GetLastError();
		CLogger::Instance().LogFmt(LOG_LEVEL_WARNING, _T("CryptoAPIAdapter"),
			_T("CryptAcquireContext(VERIFYCONTEXT) failed for [%s]: 0x%08X - %s"),
			(LPCTSTR)info.strName,
			info.dwEnumError,
			(LPCTSTR)CErrorHelper::GetCryptoErrorDescription(info.dwEnumError));
		return;
	}

	// Get version
	info.strVersion   = GetProviderVersion(hProv);
	info.bHardware    = CheckHardwareFlag(hProv);

	// Enumerate algorithms supported
	EnumerateAlgorithms(hProv, info);

	// Check sign capability (RSA or DSA signature alg)
	if (info.strAlgorithms.Find(_T("RSA")) >= 0 ||
		info.strAlgorithms.Find(_T("DSA")) >= 0 ||
		info.strAlgorithms.Find(_T("ECDSA")) >= 0)
	{
		info.bCanSign = TRUE;
	}

	if (info.strAlgorithms.Find(_T("RC2")) >= 0 ||
		info.strAlgorithms.Find(_T("AES")) >= 0 ||
		info.strAlgorithms.Find(_T("3DES")) >= 0)
	{
		info.bCanEncrypt = TRUE;
	}

	CLogger::Instance().LogFmt(LOG_LEVEL_PASS, _T("CryptoAPIAdapter"),
		_T("Provider [%s]: v%s | Sign:%s | Encrypt:%s | Hardware:%s"),
		(LPCTSTR)info.strName,
		(LPCTSTR)info.strVersion,
		info.bCanSign    ? _T("YES") : _T("NO"),
		info.bCanEncrypt ? _T("YES") : _T("NO"),
		info.bHardware   ? _T("YES") : _T("NO"));

	CryptReleaseContext(hProv, 0);
}

void CCryptoAPIAdapter::EnumerateAlgorithms(HCRYPTPROV hProv, CSPInfo& info)
{
	PROV_ENUMALGS algInfo;
	DWORD cbAlgInfo = sizeof(algInfo);
	BOOL bFirst = TRUE;
	CString strAlgList;

	while (TRUE)
	{
		ZeroMemory(&algInfo, sizeof(algInfo));
		cbAlgInfo = sizeof(algInfo);

		BOOL bOK = CryptGetProvParam(
			hProv,
			PP_ENUMALGS,
			(BYTE*)&algInfo,
			&cbAlgInfo,
			bFirst ? CRYPT_FIRST : CRYPT_NEXT
			);

		if (!bOK)
		{
			DWORD dwErr = GetLastError();
			if (dwErr == ERROR_NO_MORE_ITEMS)
				break;
			// Some providers don't support PP_ENUMALGS
			break;
		}

		bFirst = FALSE;

		// Get friendly name
		CString strAlgName;
		if (algInfo.szName[0] != '\0')
		{
#ifdef _UNICODE
			int nLen = MultiByteToWideChar(CP_ACP, 0, algInfo.szName, -1, NULL, 0);
			LPWSTR pBuf = strAlgName.GetBufferSetLength(nLen + 1);
			MultiByteToWideChar(CP_ACP, 0, algInfo.szName, -1, pBuf, nLen + 1);
			strAlgName.ReleaseBuffer();
#else
			strAlgName = algInfo.szName;
#endif
		}
		else
		{
			TCHAR szID[32] = {0};
			_sntprintf_s(szID, 32, _TRUNCATE, _T("ALG_%04X"), algInfo.aiAlgid);
			strAlgName = szID;
		}

		if (!strAlgList.IsEmpty()) strAlgList += _T(", ");
		strAlgList += strAlgName;
	}

	info.strAlgorithms = strAlgList;
}

CString CCryptoAPIAdapter::GetProviderVersion(HCRYPTPROV hProv)
{
	DWORD dwVersion = 0;
	DWORD cbVersion = sizeof(dwVersion);

	if (!CryptGetProvParam(hProv, PP_VERSION, (BYTE*)&dwVersion, &cbVersion, 0))
		return _T("(unknown)");

	TCHAR szBuf[32] = {0};
	_sntprintf_s(szBuf, 32, _TRUNCATE,
		_T("%d.%d"),
		HIWORD(dwVersion), LOWORD(dwVersion));
	return CString(szBuf);
}

CString CCryptoAPIAdapter::GetProviderContainer(HCRYPTPROV hProv)
{
	DWORD cbName = 0;
	if (!CryptGetProvParam(hProv, PP_CONTAINER, NULL, &cbName, 0))
		return _T("(unknown)");

	BYTE* pBuf = (BYTE*)LocalAlloc(LPTR, cbName + 2);
	if (!pBuf) return _T("(alloc fail)");

	CString strResult;
	if (CryptGetProvParam(hProv, PP_CONTAINER, pBuf, &cbName, 0))
	{
#ifdef _UNICODE
		int nLen = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)pBuf, -1, NULL, 0);
		LPWSTR pW = strResult.GetBufferSetLength(nLen + 1);
		MultiByteToWideChar(CP_ACP, 0, (LPCSTR)pBuf, -1, pW, nLen + 1);
		strResult.ReleaseBuffer();
#else
		strResult = (LPCSTR)pBuf;
#endif
	}

	LocalFree(pBuf);
	return strResult;
}

BOOL CCryptoAPIAdapter::CheckHardwareFlag(HCRYPTPROV hProv)
{
	DWORD dwImpType = 0;
	DWORD cbImpType = sizeof(dwImpType);

	if (!CryptGetProvParam(hProv, PP_IMPTYPE, (BYTE*)&dwImpType, &cbImpType, 0))
		return FALSE;

	return (dwImpType & CRYPT_IMPL_HARDWARE) ? TRUE : FALSE;
}