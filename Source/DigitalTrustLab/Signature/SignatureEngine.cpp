// Signature/SignatureEngine.cpp
// Digital Trust Interoperability Lab - Phase 3

#include "stdafx.h"
#include "SignatureEngine.h"
#include "../Utils/Logger.h"
#include "../Utils/ErrorHelper.h"
#include "../Utils/StringHelper.h"

// NCrypt dynamic loading
typedef SECURITY_STATUS (WINAPI* PFN_NCryptOpenStorageProvider)(
	NCRYPT_PROV_HANDLE*, LPCWSTR, DWORD);
typedef SECURITY_STATUS (WINAPI* PFN_NCryptOpenKey)(
	NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*, LPCWSTR, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI* PFN_NCryptSignHash)(
	NCRYPT_KEY_HANDLE, VOID*, PBYTE, DWORD,
	PBYTE, DWORD, DWORD*, DWORD);
typedef SECURITY_STATUS (WINAPI* PFN_NCryptFreeObject)(NCRYPT_HANDLE);

CSignatureEngine::CSignatureEngine()
{
	m_diagResult.m_strCheckName = _T("Signature Engine");
	m_diagResult.m_strCategory  = _T("Signature");
}

CSignatureEngine::~CSignatureEngine()
{
}

const CDiagnosticResult& CSignatureEngine::GetDiagnosticResult() const
{
	return m_diagResult;
}

// ============================================================
// SignFile
// ============================================================
BOOL CSignatureEngine::SignFile(
								const CString& strFilePath,
								PCCERT_CONTEXT pCertContext,
								SignHashAlgorithm hashAlg,
								SignatureResult& result)
{
	result.bSuccess = FALSE;

	// Read file
	CArray<BYTE, BYTE> buffer;
	if (!ReadFile(strFilePath, buffer))
	{
		result.strError = _T("Cannot read file: ") + strFilePath;
		CLogger::Instance().Error(_T("SignatureEngine"),
			result.strError);
		return FALSE;
	}

	if (buffer.GetSize() == 0)
	{
		result.strError = _T("File is empty");
		return FALSE;
	}

	CLogger::Instance().LogFmt(LOG_LEVEL_INFO, _T("SignatureEngine"),
		_T("Signing file: %s (%lu bytes) | Algorithm: %s"),
		(LPCTSTR)strFilePath,
		(unsigned long)buffer.GetSize(),
		(LPCTSTR)HashAlgorithmToString(hashAlg));

	return SignData(
		buffer.GetData(),
		(DWORD)buffer.GetSize(),
		pCertContext,
		hashAlg,
		result);
}

// ============================================================
// SignData - dispatches to CSP or CNG
// ============================================================
BOOL CSignatureEngine::SignData(
								const BYTE* pbData,
								DWORD cbData,
								PCCERT_CONTEXT pCertContext,
								SignHashAlgorithm hashAlg,
								SignatureResult& result)
{
	if (pCertContext == NULL)
	{
		result.strError = _T("No certificate context");
		return FALSE;
	}

	result.strCertSubject =
		CStringHelper::CertNameBlobToString(
		pCertContext->pCertInfo->Subject);

	// Get SHA-1 thumbprint for display
	BYTE rgbThumb[20] = {0};
	DWORD cbThumb = 20;
	if (CryptHashCertificate(0, CALG_SHA1, 0,
		pCertContext->pbCertEncoded,
		pCertContext->cbCertEncoded,
		rgbThumb, &cbThumb))
	{
		result.strCertThumbprint =
			CStringHelper::BinaryToHex(rgbThumb, cbThumb, FALSE);
	}

	result.strHashAlgorithm = HashAlgorithmToString(hashAlg);

	// Determine provider type
	DWORD cbData2 = 0;
	if (!CertGetCertificateContextProperty(
		pCertContext,
		CERT_KEY_PROV_INFO_PROP_ID,
		NULL, &cbData2) || cbData2 == 0)
	{
		result.strError =
			_T("Certificate has no key provider info. ")
			_T("Private key not associated.");
		CLogger::Instance().Error(_T("SignatureEngine"),
			result.strError);
		return FALSE;
	}

	CRYPT_KEY_PROV_INFO* pKeyProvInfo =
		(CRYPT_KEY_PROV_INFO*)LocalAlloc(LPTR, cbData2);
	if (!pKeyProvInfo)
	{
		result.strError = _T("Memory allocation failed");
		return FALSE;
	}

	BOOL bRet = FALSE;

	if (CertGetCertificateContextProperty(
		pCertContext,
		CERT_KEY_PROV_INFO_PROP_ID,
		pKeyProvInfo, &cbData2))
	{
		if (pKeyProvInfo->pwszProvName)
			result.strProviderName = pKeyProvInfo->pwszProvName;

		if (pKeyProvInfo->dwProvType == 0)
		{
			// CNG/KSP
			result.strProviderType = _T("CNG KSP");
			bRet = SignWithCNG(
				pbData, cbData, pCertContext, hashAlg, result);
		}
		else
		{
			// Legacy CSP
			result.strProviderType = _T("Legacy CSP");
			bRet = SignWithCSP(
				pbData, cbData, pCertContext, hashAlg, result);
		}
	}
	else
	{
		result.strError = CErrorHelper::GetCryptoErrorDescription(
			GetLastError());
	}

	LocalFree(pKeyProvInfo);
	return bRet;
}

// ============================================================
// SignWithCSP - Legacy CryptoAPI signing
// ============================================================
BOOL CSignatureEngine::SignWithCSP(
								   const BYTE* pbData,
								   DWORD cbData,
								   PCCERT_CONTEXT pCertContext,
								   SignHashAlgorithm hashAlg,
								   SignatureResult& result)
{
	DWORD dwStart = GetTickCount();

	// Acquire private key WITHOUT silent flag
	HCRYPTPROV hProv     = NULL;
	DWORD      dwKeySpec = 0;
	BOOL       bCallerFree = FALSE;

	DWORD dwAcquireFlags =
		CRYPT_ACQUIRE_USE_PROV_INFO_FLAG |
		CRYPT_ACQUIRE_COMPARE_KEY_FLAG;

	if (!CryptAcquireCertificatePrivateKey(
		pCertContext,
		dwAcquireFlags,
		NULL,
		&hProv,
		&dwKeySpec,
		&bCallerFree))
	{
		DWORD dwErr = GetLastError();

		if (dwErr == NTE_SILENT_CONTEXT)
		{
			// Try without compare flag
			dwAcquireFlags = CRYPT_ACQUIRE_USE_PROV_INFO_FLAG;
			if (!CryptAcquireCertificatePrivateKey(
				pCertContext, dwAcquireFlags,
				NULL, &hProv, &dwKeySpec, &bCallerFree))
			{
				dwErr = GetLastError();
				result.strError =
					CString(_T("CryptAcquireCertificatePrivateKey: ")) +
					CErrorHelper::GetCryptoErrorDescription(dwErr);
				CLogger::Instance().Error(_T("SignatureEngine"),
					result.strError);
				return FALSE;
			}
		}
		else
		{
			result.strError =
				CString(_T("CryptAcquireCertificatePrivateKey: ")) +
				CErrorHelper::GetCryptoErrorDescription(dwErr);
			CLogger::Instance().Error(_T("SignatureEngine"),
				result.strError);
			return FALSE;
		}
	}

	CLogger::Instance().LogFmt(LOG_LEVEL_INFO, _T("SignatureEngine"),
		_T("Provider acquired | KeySpec: %lu | Hash: %s"),
		dwKeySpec, (LPCTSTR)HashAlgorithmToString(hashAlg));

	ALG_ID hashAlgId = HashAlgorithmToCSPAlgId(hashAlg);
	HCRYPTHASH hHash = NULL;
	BOOL bSuccess    = FALSE;

	// ============================================================
	// STRATEGY: Try to create hash object from token CSP first.
	// If CSP doesn't support the hash (e.g. old CSP + SHA-256),
	// we compute the hash VALUE separately, then inject it via
	// HP_HASHVAL into a hash object of the SAME token CSP.
	// This way both hash and sign use the same hProv.
	// ============================================================

	if (CryptCreateHash(hProv, hashAlgId, 0, 0, &hHash) && hHash)
	{
		// Token CSP supports this hash directly
		CLogger::Instance().Info(_T("SignatureEngine"),
			_T("Token CSP supports hash algorithm directly."));

		if (!CryptHashData(hHash, pbData, cbData, 0))
		{
			DWORD dwErr = GetLastError();
			result.strError =
				CString(_T("CryptHashData failed: ")) +
				CErrorHelper::GetCryptoErrorDescription(dwErr);
			CryptDestroyHash(hHash);
			if (bCallerFree) CryptReleaseContext(hProv, 0);
			return FALSE;
		}
	}
	else
	{
		// --------------------------------------------------------
		// Token CSP does NOT support hash creation with this ALG_ID.
		// Solution:
		// 1. Compute hash value externally (RSA_AES or BCrypt)
		// 2. Create hash object on token CSP with same ALG_ID
		// 3. Set HP_HASHVAL to inject computed hash bytes
		// 4. Sign - both hash obj and key belong to same hProv
		// --------------------------------------------------------

		DWORD dwHashErr = GetLastError();
		CLogger::Instance().LogFmt(LOG_LEVEL_WARNING,
			_T("SignatureEngine"),
			_T("Token CSP hash creation failed (0x%08X). ")
			_T("Using HP_HASHVAL injection method."), dwHashErr);

		// Step 1: Compute hash value externally
		DWORD cbHashVal = 0;
		switch (hashAlg)
		{
		case HASH_SHA1:   cbHashVal = 20; break;
		case HASH_SHA256: cbHashVal = 32; break;
		case HASH_SHA384: cbHashVal = 48; break;
		case HASH_SHA512: cbHashVal = 64; break;
		default:          cbHashVal = 32; break;
		}

		BYTE* pbHashVal = (BYTE*)LocalAlloc(LPTR, cbHashVal);
		if (!pbHashVal)
		{
			result.strError = _T("Memory allocation failed");
			if (bCallerFree) CryptReleaseContext(hProv, 0);
			return FALSE;
		}

		BOOL bHashComputed = FALSE;

		// Try BCrypt first (Vista+)
		HMODULE hBcrypt = LoadLibrary(_T("bcrypt.dll"));
		if (hBcrypt)
		{
			typedef NTSTATUS (WINAPI* PFN_BCryptOpenAlg)(
				BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
			typedef NTSTATUS (WINAPI* PFN_BCryptCreateHash)(
				BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*,
				PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
			typedef NTSTATUS (WINAPI* PFN_BCryptHashData)(
				BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
			typedef NTSTATUS (WINAPI* PFN_BCryptFinishHash)(
				BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
			typedef NTSTATUS (WINAPI* PFN_BCryptDestroyHash)(
				BCRYPT_HASH_HANDLE);
			typedef NTSTATUS (WINAPI* PFN_BCryptCloseAlg)(
				BCRYPT_ALG_HANDLE, ULONG);

			PFN_BCryptOpenAlg    pfnOpen  = (PFN_BCryptOpenAlg)   GetProcAddress(hBcrypt, "BCryptOpenAlgorithmProvider");
			PFN_BCryptCreateHash pfnCH    = (PFN_BCryptCreateHash) GetProcAddress(hBcrypt, "BCryptCreateHash");
			PFN_BCryptHashData   pfnHD    = (PFN_BCryptHashData)   GetProcAddress(hBcrypt, "BCryptHashData");
			PFN_BCryptFinishHash pfnFH    = (PFN_BCryptFinishHash) GetProcAddress(hBcrypt, "BCryptFinishHash");
			PFN_BCryptDestroyHash pfnDH   = (PFN_BCryptDestroyHash)GetProcAddress(hBcrypt, "BCryptDestroyHash");
			PFN_BCryptCloseAlg   pfnClose = (PFN_BCryptCloseAlg)  GetProcAddress(hBcrypt, "BCryptCloseAlgorithmProvider");

			if (pfnOpen && pfnCH && pfnHD && pfnFH && pfnDH && pfnClose)
			{
				LPCWSTR pszAlg = HashAlgorithmToCNGAlgId(hashAlg);
				BCRYPT_ALG_HANDLE hAlg = NULL;

				if (pfnOpen(&hAlg, pszAlg, NULL, 0) == 0 && hAlg)
				{
					BCRYPT_HASH_HANDLE hBHash = NULL;
					if (pfnCH(hAlg, &hBHash, NULL, 0, NULL, 0, 0) == 0 && hBHash)
					{
						if (pfnHD(hBHash, (PUCHAR)pbData, cbData, 0) == 0)
						{
							if (pfnFH(hBHash, pbHashVal, cbHashVal, 0) == 0)
							{
								bHashComputed = TRUE;
								CLogger::Instance().Info(
									_T("SignatureEngine"),
									_T("Hash computed via BCrypt."));
							}
						}
						pfnDH(hBHash);
					}
					pfnClose(hAlg, 0);
				}
			}

			FreeLibrary(hBcrypt);
		}

		// Fallback: compute hash with Microsoft RSA_AES CSP
		if (!bHashComputed)
		{
			HCRYPTPROV hAuxProv = NULL;
			if (CryptAcquireContext(
				&hAuxProv, NULL, NULL,
				PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
			{
				HCRYPTHASH hAuxHash = NULL;
				if (CryptCreateHash(hAuxProv, hashAlgId, 0, 0, &hAuxHash) && hAuxHash)
				{
					if (CryptHashData(hAuxHash, pbData, cbData, 0))
					{
						DWORD cb = cbHashVal;
						if (CryptGetHashParam(hAuxHash, HP_HASHVAL, pbHashVal, &cb, 0))
						{
							bHashComputed = TRUE;
							CLogger::Instance().Info(
								_T("SignatureEngine"),
								_T("Hash computed via RSA_AES CSP."));
						}
					}
					CryptDestroyHash(hAuxHash);
				}
				CryptReleaseContext(hAuxProv, 0);
			}
		}

		if (!bHashComputed)
		{
			result.strError = _T("Cannot compute hash value.");
			LocalFree(pbHashVal);
			if (bCallerFree) CryptReleaseContext(hProv, 0);
			return FALSE;
		}

		// Step 2: Create hash object on TOKEN CSP (same hProv as key)
		// This time we DON'T hash data - we will inject hash value
		if (!CryptCreateHash(hProv, hashAlgId, 0, 0, &hHash) || !hHash)
		{
			// If token CSP truly cannot create this hash object at all,
			// we cannot use HP_HASHVAL injection.
			// Try CALG_SHA1 as fallback to at least confirm CSP works.
			DWORD dwErr = GetLastError();
			CLogger::Instance().LogFmt(LOG_LEVEL_ERROR,
				_T("SignatureEngine"),
				_T("Token CSP cannot create hash object for HP_HASHVAL: ")
				_T("0x%08X. Provider: %s"),
				dwErr, (LPCTSTR)result.strProviderName);

			result.strError.Format(
				_T("Provider '%s' does not support algorithm %s ")
				_T("(error 0x%08X).\r\n\r\n")
				_T("This is a provider limitation, not a data error.\r\n")
				_T("Recommendation: Use SHA-1 with this provider, ")
				_T("or use a SHA-256 capable provider."),
				(LPCTSTR)result.strProviderName,
				(LPCTSTR)HashAlgorithmToString(hashAlg),
				dwErr);

			LocalFree(pbHashVal);
			if (bCallerFree) CryptReleaseContext(hProv, 0);
			return FALSE;
		}

		// Step 3: Inject the pre-computed hash value into the hash object
		// HP_HASHVAL allows setting the hash directly without hashing data
		if (!CryptSetHashParam(hHash, HP_HASHVAL, pbHashVal, 0))
		{
			DWORD dwErr = GetLastError();
			CLogger::Instance().LogFmt(LOG_LEVEL_ERROR,
				_T("SignatureEngine"),
				_T("CryptSetHashParam(HP_HASHVAL) failed: 0x%08X"), dwErr);

			result.strError =
				CString(_T("Cannot inject hash value into token CSP: ")) +
				CErrorHelper::GetCryptoErrorDescription(dwErr);

			LocalFree(pbHashVal);
			CryptDestroyHash(hHash);
			if (bCallerFree) CryptReleaseContext(hProv, 0);
			return FALSE;
		}

		LocalFree(pbHashVal);

		CLogger::Instance().Info(_T("SignatureEngine"),
			_T("HP_HASHVAL injected into token hash object. Ready to sign."));
	}

	// ============================================================
	// Sign - at this point hHash belongs to hProv (token CSP)
	// ============================================================

	// Get signature size
	DWORD cbSig = 0;
	if (!CryptSignHash(hHash, dwKeySpec, NULL, 0, NULL, &cbSig))
	{
		DWORD dwErr = GetLastError();
		result.strError =
			CString(_T("CryptSignHash(size) failed: ")) +
			CErrorHelper::GetCryptoErrorDescription(dwErr);
		CLogger::Instance().LogFmt(LOG_LEVEL_ERROR,
			_T("SignatureEngine"),
			_T("CryptSignHash size failed: 0x%08X"), dwErr);
		CryptDestroyHash(hHash);
		if (bCallerFree) CryptReleaseContext(hProv, 0);
		return FALSE;
	}

	// Allocate and sign
	BYTE* pSigBuf = (BYTE*)LocalAlloc(LPTR, cbSig);
	if (!pSigBuf)
	{
		result.strError = _T("Memory allocation failed");
		CryptDestroyHash(hHash);
		if (bCallerFree) CryptReleaseContext(hProv, 0);
		return FALSE;
	}

	if (!CryptSignHash(hHash, dwKeySpec, NULL, 0, pSigBuf, &cbSig))
	{
		DWORD dwErr = GetLastError();
		result.strError =
			CString(_T("CryptSignHash failed: ")) +
			CErrorHelper::GetCryptoErrorDescription(dwErr);
		CLogger::Instance().LogFmt(LOG_LEVEL_ERROR,
			_T("SignatureEngine"),
			_T("CryptSignHash failed: 0x%08X"), dwErr);
		LocalFree(pSigBuf);
		CryptDestroyHash(hHash);
		if (bCallerFree) CryptReleaseContext(hProv, 0);
		return FALSE;
	}

	// Reverse bytes: CryptoAPI returns little-endian, standard is big-endian
	for (DWORD i = 0; i < cbSig / 2; i++)
	{
		BYTE tmp = pSigBuf[i];
		pSigBuf[i] = pSigBuf[cbSig - 1 - i];
		pSigBuf[cbSig - 1 - i] = tmp;
	}

	result.strSignatureHex =
		CStringHelper::BinaryToHex(pSigBuf, cbSig, FALSE);
	result.cbSignature  = cbSig;
	result.dwDurationMs = GetTickCount() - dwStart;
	result.bSuccess     = TRUE;

	CLogger::Instance().LogFmt(LOG_LEVEL_PASS, _T("SignatureEngine"),
		_T("CSP Sign SUCCESS | Provider: %s | Hash: %s | SigLen: %lu bytes"),
		(LPCTSTR)result.strProviderName,
		(LPCTSTR)result.strHashAlgorithm,
		cbSig);

	LocalFree(pSigBuf);
	CryptDestroyHash(hHash);
	if (bCallerFree) CryptReleaseContext(hProv, 0);

	return TRUE;
}
// ============================================================
// CheckProviderCapability
// ============================================================
BOOL CSignatureEngine::CheckProviderCapability(
	PCCERT_CONTEXT pCertContext,
	ProviderCapability& cap)
{
	if (pCertContext == NULL)
		return FALSE;

	DWORD cbData = 0;
	if (!CertGetCertificateContextProperty(
		pCertContext,
		CERT_KEY_PROV_INFO_PROP_ID,
		NULL, &cbData) || cbData == 0)
	{
		cap.strLimitationWarning =
			_T("No key provider info on certificate.");
		return FALSE;
	}

	CRYPT_KEY_PROV_INFO* pKPI =
		(CRYPT_KEY_PROV_INFO*)LocalAlloc(LPTR, cbData);
	if (!pKPI) return FALSE;

	if (!CertGetCertificateContextProperty(
		pCertContext,
		CERT_KEY_PROV_INFO_PROP_ID,
		pKPI, &cbData))
	{
		LocalFree(pKPI);
		return FALSE;
	}

	if (pKPI->pwszProvName)
		cap.strProviderName = pKPI->pwszProvName;
	if (pKPI->pwszContainerName)
		cap.strKeyContainerName = pKPI->pwszContainerName;

	cap.dwProvType = pKPI->dwProvType;
	cap.dwKeySpec  = pKPI->dwKeySpec;

	if (pKPI->dwProvType == 0)
	{
		// CNG KSP
		cap.bIsCNGKSP       = TRUE;
		cap.bIsLegacyCSP    = FALSE;
		cap.strProviderType = _T("CNG KSP");
		cap.bSupportsSHA1   = TRUE;
		cap.bSupportsSHA256 = TRUE;
		cap.bSupportsSHA384 = TRUE;
		cap.bSupportsSHA512 = TRUE;
		cap.bKeyAccessible  = TRUE;
		LocalFree(pKPI);
		return TRUE;
	}

	cap.bIsLegacyCSP    = TRUE;
	cap.bIsCNGKSP       = FALSE;
	cap.strProviderType = _T("Legacy CSP");

	HCRYPTPROV hProv = NULL;
	BOOL bAcquired = CryptAcquireContext(
		&hProv,
		pKPI->pwszContainerName,
		pKPI->pwszProvName,
		pKPI->dwProvType,
		CRYPT_SILENT);

	if (!bAcquired)
	{
		DWORD dwErr = GetLastError();
		if (dwErr == NTE_SILENT_CONTEXT)
		{
			bAcquired = CryptAcquireContext(
				&hProv, NULL,
				pKPI->pwszProvName,
				pKPI->dwProvType,
				CRYPT_VERIFYCONTEXT | CRYPT_SILENT);

			cap.bKeyAccessible = TRUE;
		}
		else
		{
			cap.bKeyAccessible = FALSE;
			cap.strLimitationWarning =
				_T("Cannot access private key.");
			LocalFree(pKPI);
			return FALSE;
		}
	}
	else
	{
		cap.bKeyAccessible = TRUE;
	}

	LocalFree(pKPI);

	if (hProv == NULL)
		return FALSE;

	const ALG_ID CALG_SHA256_VAL = (ALG_ID)0x0000800cUL;
	const ALG_ID CALG_SHA384_VAL = (ALG_ID)0x0000800dUL;
	const ALG_ID CALG_SHA512_VAL = (ALG_ID)0x0000800eUL;

	cap.bSupportsSHA1   = CheckCSPHashSupport(hProv, CALG_SHA1);
	cap.bSupportsSHA256 = CheckCSPHashSupport(hProv, CALG_SHA256_VAL);
	cap.bSupportsSHA384 = CheckCSPHashSupport(hProv, CALG_SHA384_VAL);
	cap.bSupportsSHA512 = CheckCSPHashSupport(hProv, CALG_SHA512_VAL);

	if (cap.bIsLegacyCSP && !cap.bSupportsSHA256)
	{
		cap.strLimitationWarning =
			_T("Legacy CSP does not support SHA-256+ hashing.\r\n")
			_T("Only SHA-1 signing is available.\r\n\r\n")
			_T("To use SHA-256, migrate the key to:\r\n")
			_T("- Microsoft Enhanced RSA and AES Cryptographic Provider\r\n")
			_T("- Or use a CNG KSP-backed certificate");
	}

	CryptReleaseContext(hProv, 0);
	return TRUE;
}

// ============================================================
// CheckCSPHashSupport
// ============================================================
BOOL CSignatureEngine::CheckCSPHashSupport(
	HCRYPTPROV hProv,
	ALG_ID algId)
{
	if (hProv == NULL) return FALSE;

	HCRYPTHASH hHash = NULL;
	BOOL bOK = CryptCreateHash(hProv, algId, 0, 0, &hHash);

	if (bOK && hHash != NULL)
	{
		CryptDestroyHash(hHash);
		return TRUE;
	}
	return FALSE;
}
// ============================================================
// SignWithCNG - CNG/KSP signing (Vista+)
// ============================================================
BOOL CSignatureEngine::SignWithCNG(
								   const BYTE* pbData,
								   DWORD cbData,
								   PCCERT_CONTEXT pCertContext,
								   SignHashAlgorithm hashAlg,
								   SignatureResult& result)
{
	DWORD dwStart = GetTickCount();

	// Load NCrypt dynamically (Vista+)
	HMODULE hNcrypt = LoadLibrary(_T("ncrypt.dll"));
	HMODULE hBcrypt = LoadLibrary(_T("bcrypt.dll"));

	if (hNcrypt == NULL)
	{
		result.strError =
			_T("CNG not available on this system (requires Vista+)");
		return FALSE;
	}

	typedef SECURITY_STATUS (WINAPI* PFN_NCryptOpenStorageProvider)(
		NCRYPT_PROV_HANDLE*, LPCWSTR, DWORD);
	typedef SECURITY_STATUS (WINAPI* PFN_NCryptOpenKey)(
		NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*,
		LPCWSTR, DWORD, DWORD);
	typedef SECURITY_STATUS (WINAPI* PFN_NCryptSignHash)(
		NCRYPT_KEY_HANDLE, VOID*, PBYTE, DWORD,
		PBYTE, DWORD, DWORD*, DWORD);
	typedef SECURITY_STATUS (WINAPI* PFN_NCryptFreeObject)(NCRYPT_HANDLE);
	typedef NTSTATUS        (WINAPI* PFN_BCryptCreateHash)(
		BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*,
		PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
	typedef NTSTATUS        (WINAPI* PFN_BCryptHashData)(
		BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
	typedef NTSTATUS        (WINAPI* PFN_BCryptFinishHash)(
		BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
	typedef NTSTATUS        (WINAPI* PFN_BCryptDestroyHash)(
		BCRYPT_HASH_HANDLE);
	typedef NTSTATUS        (WINAPI* PFN_BCryptOpenAlgorithmProvider)(
		BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
	typedef NTSTATUS        (WINAPI* PFN_BCryptCloseAlgorithmProvider)(
		BCRYPT_ALG_HANDLE, ULONG);
	typedef NTSTATUS        (WINAPI* PFN_BCryptGetProperty)(
		BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG);

	PFN_NCryptOpenStorageProvider pfnOpenProv =
		(PFN_NCryptOpenStorageProvider)GetProcAddress(
		hNcrypt, "NCryptOpenStorageProvider");
	PFN_NCryptOpenKey pfnOpenKey =
		(PFN_NCryptOpenKey)GetProcAddress(
		hNcrypt, "NCryptOpenKey");
	PFN_NCryptSignHash pfnSignHash =
		(PFN_NCryptSignHash)GetProcAddress(
		hNcrypt, "NCryptSignHash");
	PFN_NCryptFreeObject pfnFreeObj =
		(PFN_NCryptFreeObject)GetProcAddress(
		hNcrypt, "NCryptFreeObject");

	PFN_BCryptOpenAlgorithmProvider pfnBCryptOpenAlg =
		(PFN_BCryptOpenAlgorithmProvider)(hBcrypt ?
		GetProcAddress(hBcrypt, "BCryptOpenAlgorithmProvider") : NULL);
	PFN_BCryptCreateHash pfnBCryptCreateHash =
		(PFN_BCryptCreateHash)(hBcrypt ?
		GetProcAddress(hBcrypt, "BCryptCreateHash") : NULL);
	PFN_BCryptHashData pfnBCryptHashData =
		(PFN_BCryptHashData)(hBcrypt ?
		GetProcAddress(hBcrypt, "BCryptHashData") : NULL);
	PFN_BCryptFinishHash pfnBCryptFinishHash =
		(PFN_BCryptFinishHash)(hBcrypt ?
		GetProcAddress(hBcrypt, "BCryptFinishHash") : NULL);
	PFN_BCryptDestroyHash pfnBCryptDestroyHash =
		(PFN_BCryptDestroyHash)(hBcrypt ?
		GetProcAddress(hBcrypt, "BCryptDestroyHash") : NULL);
	PFN_BCryptCloseAlgorithmProvider pfnBCryptCloseAlg =
		(PFN_BCryptCloseAlgorithmProvider)(hBcrypt ?
		GetProcAddress(hBcrypt, "BCryptCloseAlgorithmProvider") : NULL);
	PFN_BCryptGetProperty pfnBCryptGetProp =
		(PFN_BCryptGetProperty)(hBcrypt ?
		GetProcAddress(hBcrypt, "BCryptGetProperty") : NULL);

	if (!pfnOpenProv || !pfnOpenKey ||
		!pfnSignHash || !pfnFreeObj)
	{
		result.strError = _T("NCrypt functions not found");
		if (hNcrypt) FreeLibrary(hNcrypt);
		if (hBcrypt) FreeLibrary(hBcrypt);
		return FALSE;
	}

	// Get provider info from certificate
	DWORD cbProvInfo = 0;
	CertGetCertificateContextProperty(
		pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cbProvInfo);

	CRYPT_KEY_PROV_INFO* pKPI =
		(CRYPT_KEY_PROV_INFO*)LocalAlloc(LPTR, cbProvInfo);
	if (!pKPI)
	{
		result.strError = _T("Memory allocation failed");
		FreeLibrary(hNcrypt);
		if (hBcrypt) FreeLibrary(hBcrypt);
		return FALSE;
	}

	CertGetCertificateContextProperty(
		pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pKPI, &cbProvInfo);

	// Open KSP
	NCRYPT_PROV_HANDLE hProv = 0;
	SECURITY_STATUS ss = pfnOpenProv(
		&hProv, pKPI->pwszProvName, 0);

	if (ss != ERROR_SUCCESS || hProv == 0)
	{
		result.strError =
			CString(_T("NCryptOpenStorageProvider failed: ")) +
			CErrorHelper::GetSecurityStatusString(ss);
		LocalFree(pKPI);
		FreeLibrary(hNcrypt);
		if (hBcrypt) FreeLibrary(hBcrypt);
		return FALSE;
	}

	// Open key
	NCRYPT_KEY_HANDLE hKey = 0;
	ss = pfnOpenKey(
		hProv, &hKey, pKPI->pwszContainerName,
		0, NCRYPT_SILENT_FLAG);

	if (ss == NTE_SILENT_CONTEXT)
	{
		result.strError =
			_T("CNG key requires user interaction (PIN). ")
			_T("Cannot sign in silent mode.");
		pfnFreeObj((NCRYPT_HANDLE)hProv);
		LocalFree(pKPI);
		FreeLibrary(hNcrypt);
		if (hBcrypt) FreeLibrary(hBcrypt);
		return FALSE;
	}

	if (ss != ERROR_SUCCESS || hKey == 0)
	{
		result.strError =
			CString(_T("NCryptOpenKey failed: ")) +
			CErrorHelper::GetSecurityStatusString(ss);
		pfnFreeObj((NCRYPT_HANDLE)hProv);
		LocalFree(pKPI);
		FreeLibrary(hNcrypt);
		if (hBcrypt) FreeLibrary(hBcrypt);
		return FALSE;
	}

	LocalFree(pKPI);

	// ---- Compute hash using BCrypt ----
	LPCWSTR pszHashAlg = HashAlgorithmToCNGAlgId(hashAlg);

	// Hash sizes
	DWORD cbHash = 0;
	switch (hashAlg)
	{
	case HASH_SHA1:   cbHash = 20; break;
	case HASH_SHA256: cbHash = 32; break;
	case HASH_SHA384: cbHash = 48; break;
	case HASH_SHA512: cbHash = 64; break;
	default:          cbHash = 32; break;
	}

	BYTE* pbHash = (BYTE*)LocalAlloc(LPTR, cbHash);
	BOOL bHashOK = FALSE;

	if (pbHash && pfnBCryptOpenAlg && pfnBCryptCreateHash &&
		pfnBCryptHashData && pfnBCryptFinishHash &&
		pfnBCryptDestroyHash && pfnBCryptCloseAlg)
	{
		BCRYPT_ALG_HANDLE hAlg = NULL;
		NTSTATUS nt = pfnBCryptOpenAlg(
			&hAlg, pszHashAlg, NULL, 0);

		if (nt == 0 && hAlg != NULL)
		{
			BCRYPT_HASH_HANDLE hHash = NULL;
			nt = pfnBCryptCreateHash(
				hAlg, &hHash, NULL, 0, NULL, 0, 0);

			if (nt == 0 && hHash != NULL)
			{
				nt = pfnBCryptHashData(
					hHash, (PUCHAR)pbData, cbData, 0);

				if (nt == 0)
					nt = pfnBCryptFinishHash(
					hHash, pbHash, cbHash, 0);

				if (nt == 0)
					bHashOK = TRUE;

				pfnBCryptDestroyHash(hHash);
			}

			pfnBCryptCloseAlg(hAlg, 0);
		}
	}

	if (!bHashOK || pbHash == NULL)
	{
		// Fallback: compute hash with CryptoAPI
		if (pbHash) LocalFree(pbHash);
		pbHash = (BYTE*)LocalAlloc(LPTR, cbHash);

		if (pbHash)
		{
			HCRYPTPROV hCAPIProv = NULL;
			CryptAcquireContext(
				&hCAPIProv, NULL, NULL,
				PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

			if (hCAPIProv)
			{
				ALG_ID capiAlg = HashAlgorithmToCSPAlgId(hashAlg);
				HCRYPTHASH hCAPIHash = NULL;

				if (CryptCreateHash(hCAPIProv, capiAlg, 0, 0, &hCAPIHash) &&
					hCAPIHash)
				{
					if (CryptHashData(hCAPIHash, pbData, cbData, 0))
					{
						DWORD cb = cbHash;
						if (CryptGetHashParam(
							hCAPIHash, HP_HASHVAL, pbHash, &cb, 0))
						{
							bHashOK = TRUE;
						}
					}
					CryptDestroyHash(hCAPIHash);
				}
				CryptReleaseContext(hCAPIProv, 0);
			}
		}
	}

	if (!bHashOK)
	{
		result.strError = _T("Hash computation failed");
		if (pbHash) LocalFree(pbHash);
		pfnFreeObj((NCRYPT_HANDLE)hKey);
		pfnFreeObj((NCRYPT_HANDLE)hProv);
		FreeLibrary(hNcrypt);
		if (hBcrypt) FreeLibrary(hBcrypt);
		return FALSE;
	}

	// ---- NCryptSignHash ----
	// Build BCRYPT_PKCS1_PADDING_INFO for RSA
	BCRYPT_PKCS1_PADDING_INFO pkcs1PaddingInfo;
	pkcs1PaddingInfo.pszAlgId = pszHashAlg;

	// Get signature size first
	DWORD cbSig = 0;
	ss = pfnSignHash(
		hKey,
		&pkcs1PaddingInfo,
		pbHash, cbHash,
		NULL, 0,
		&cbSig,
		BCRYPT_PAD_PKCS1);

	if (ss != ERROR_SUCCESS || cbSig == 0)
	{
		// Try without padding info (for some providers)
		ss = pfnSignHash(
			hKey,
			NULL,
			pbHash, cbHash,
			NULL, 0,
			&cbSig,
			0);
	}

	if (ss != ERROR_SUCCESS || cbSig == 0)
	{
		result.strError =
			CString(_T("NCryptSignHash(size) failed: ")) +
			CErrorHelper::GetSecurityStatusString(ss);
		LocalFree(pbHash);
		pfnFreeObj((NCRYPT_HANDLE)hKey);
		pfnFreeObj((NCRYPT_HANDLE)hProv);
		FreeLibrary(hNcrypt);
		if (hBcrypt) FreeLibrary(hBcrypt);
		return FALSE;
	}

	BYTE* pSigBuf = (BYTE*)LocalAlloc(LPTR, cbSig);
	if (!pSigBuf)
	{
		result.strError = _T("Memory allocation failed");
		LocalFree(pbHash);
		pfnFreeObj((NCRYPT_HANDLE)hKey);
		pfnFreeObj((NCRYPT_HANDLE)hProv);
		FreeLibrary(hNcrypt);
		if (hBcrypt) FreeLibrary(hBcrypt);
		return FALSE;
	}

	// Actual sign
	ss = pfnSignHash(
		hKey,
		&pkcs1PaddingInfo,
		pbHash, cbHash,
		pSigBuf, cbSig,
		&cbSig,
		BCRYPT_PAD_PKCS1);

	if (ss != ERROR_SUCCESS)
	{
		// Try without padding
		ZeroMemory(pSigBuf, cbSig);
		ss = pfnSignHash(
			hKey,
			NULL,
			pbHash, cbHash,
			pSigBuf, cbSig,
			&cbSig,
			0);
	}

	if (ss == ERROR_SUCCESS)
	{
		result.strSignatureHex =
			CStringHelper::BinaryToHex(pSigBuf, cbSig, FALSE);
		result.cbSignature = cbSig;
		result.dwDurationMs = GetTickCount() - dwStart;
		result.bSuccess = TRUE;

		CLogger::Instance().LogFmt(LOG_LEVEL_PASS,
			_T("SignatureEngine"),
			_T("CNG Sign SUCCESS | Provider: %s | Hash: %s | SigLen: %lu bytes"),
			(LPCTSTR)result.strProviderName,
			(LPCTSTR)result.strHashAlgorithm,
			cbSig);
	}
	else
	{
		result.strError =
			CString(_T("NCryptSignHash failed: ")) +
			CErrorHelper::GetSecurityStatusString(ss);

		CLogger::Instance().LogFmt(LOG_LEVEL_FAIL,
			_T("SignatureEngine"),
			_T("CNG Sign FAIL: %s"), (LPCTSTR)result.strError);
	}

	LocalFree(pSigBuf);
	LocalFree(pbHash);
	pfnFreeObj((NCRYPT_HANDLE)hKey);
	pfnFreeObj((NCRYPT_HANDLE)hProv);
	FreeLibrary(hNcrypt);
	if (hBcrypt) FreeLibrary(hBcrypt);

	return result.bSuccess;
}

// ============================================================
// HashDataCSP
// ============================================================
BOOL CSignatureEngine::HashDataCSP(
								   HCRYPTPROV hProv,
								   ALG_ID algId,
								   const BYTE* pbData,
								   DWORD cbData,
								   HCRYPTHASH& hHash)
{
	hHash = NULL;

	if (!CryptCreateHash(hProv, algId, 0, 0, &hHash))
	{
		DWORD dwErr = GetLastError();
		CLogger::Instance().LogFmt(LOG_LEVEL_ERROR,
			_T("SignatureEngine"),
			_T("CryptCreateHash failed: 0x%08X"), dwErr);
		return FALSE;
	}

	if (!CryptHashData(hHash, pbData, cbData, 0))
	{
		DWORD dwErr = GetLastError();
		CLogger::Instance().LogFmt(LOG_LEVEL_ERROR,
			_T("SignatureEngine"),
			_T("CryptHashData failed: 0x%08X"), dwErr);
		CryptDestroyHash(hHash);
		hHash = NULL;
		return FALSE;
	}

	return TRUE;
}

// ============================================================
// ReadFile
// ============================================================
BOOL CSignatureEngine::ReadFile(
								const CString& strPath,
								CArray<BYTE, BYTE>& buffer)
{
	buffer.RemoveAll();

	CFile file;
	CFileException ex;
	if (!file.Open(strPath,
		CFile::modeRead | CFile::shareDenyNone, &ex))
	{
		return FALSE;
	}

	ULONGLONG ullSize = file.GetLength();
	if (ullSize == 0 || ullSize > 100 * 1024 * 1024)
	{
		file.Close();
		return (ullSize == 0);
	}

	DWORD dwSize = (DWORD)ullSize;
	buffer.SetSize(dwSize);

	DWORD dwRead = file.Read(buffer.GetData(), dwSize);
	file.Close();

	if (dwRead != dwSize)
	{
		buffer.RemoveAll();
		return FALSE;
	}

	return TRUE;
}

// ============================================================
// Utility
// ============================================================
CString CSignatureEngine::HashAlgorithmToString(SignHashAlgorithm alg)
{
	switch (alg)
	{
	case HASH_SHA1:   return _T("SHA-1");
	case HASH_SHA256: return _T("SHA-256");
	case HASH_SHA384: return _T("SHA-384");
	case HASH_SHA512: return _T("SHA-512");
	default:          return _T("SHA-256");
	}
}

ALG_ID CSignatureEngine::HashAlgorithmToCSPAlgId(SignHashAlgorithm alg)
{
	//const ALG_ID CALG_SHA256_VALUE = (ALG_ID)0x0000800cUL;
	const ALG_ID CALG_SHA384_VALUE = (ALG_ID)0x0000800dUL;
	const ALG_ID CALG_SHA512_VALUE = (ALG_ID)0x0000800eUL;

	switch (alg)
	{
	case HASH_SHA1:   return CALG_SHA1;
	case HASH_SHA256: return CALG_SHA_256;
	case HASH_SHA384: return CALG_SHA384_VALUE;
	case HASH_SHA512: return CALG_SHA512_VALUE;
	default:          return CALG_SHA_256;
	}
}

LPCWSTR CSignatureEngine::HashAlgorithmToCNGAlgId(SignHashAlgorithm alg)
{
	switch (alg)
	{
	case HASH_SHA1:   return L"SHA1";
	case HASH_SHA256: return L"SHA256";
	case HASH_SHA384: return L"SHA384";
	case HASH_SHA512: return L"SHA512";
	default:          return L"SHA256";
	}
}