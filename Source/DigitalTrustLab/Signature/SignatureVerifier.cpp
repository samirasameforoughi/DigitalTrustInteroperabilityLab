// Signature/SignatureVerifier.cpp
// Digital Trust Interoperability Lab - Phase 3

#include "stdafx.h"
#include "SignatureVerifier.h"
#include "../Utils/Logger.h"
#include "../Utils/ErrorHelper.h"
#include "../Utils/StringHelper.h"

CSignatureVerifier::CSignatureVerifier()
{
	m_diagResult.m_strCheckName = _T("Signature Verifier");
	m_diagResult.m_strCategory  = _T("Verification");
}

CSignatureVerifier::~CSignatureVerifier() {}

const CDiagnosticResult& CSignatureVerifier::GetDiagnosticResult() const
{
	return m_diagResult;
}

// ============================================================
// VerifySignatureHex
// ============================================================
BOOL CSignatureVerifier::VerifySignatureHex(
	const BYTE* pbData,
	DWORD cbData,
	const CString& strSignatureHex,
	PCCERT_CONTEXT pSignerCert,
	SignHashAlgorithm hashAlg,
	VerificationResult& result)
{
	if (strSignatureHex.IsEmpty())
	{
		result.strError = _T("Empty signature hex string");
		return FALSE;
	}

	// Convert hex to bytes
	int nHexLen = strSignatureHex.GetLength();
	if (nHexLen % 2 != 0)
	{
		result.strError = _T("Invalid hex string length");
		return FALSE;
	}

	DWORD cbSig = nHexLen / 2;
	BYTE* pSig  = (BYTE*)LocalAlloc(LPTR, cbSig);
	if (!pSig)
	{
		result.strError = _T("Memory allocation failed");
		return FALSE;
	}

	for (DWORD i = 0; i < cbSig; i++)
	{
		TCHAR szByte[4] = {0};
		szByte[0] = strSignatureHex[i * 2];
		szByte[1] = strSignatureHex[i * 2 + 1];
		szByte[2] = 0;

		unsigned int val = 0;
#ifdef _UNICODE
		char szA[4] = {0};
		WideCharToMultiByte(CP_ACP, 0, szByte, -1, szA, 4, NULL, NULL);
		sscanf_s(szA, "%02X", &val);
#else
		sscanf_s(szByte, "%02X", &val);
#endif
		pSig[i] = (BYTE)val;
	}

	BOOL bOK = VerifySignature(
		pbData, cbData, pSig, cbSig,
		pSignerCert, hashAlg, result);

	LocalFree(pSig);
	return bOK;
}

// ============================================================
// VerifySignature
// ============================================================
BOOL CSignatureVerifier::VerifySignature(
	const BYTE* pbData,
	DWORD cbData,
	const BYTE* pbSignature,
	DWORD cbSignature,
	PCCERT_CONTEXT pSignerCert,
	SignHashAlgorithm hashAlg,
	VerificationResult& result)
{
	DWORD dwStart = GetTickCount();
	result.bSignatureValid = FALSE;

	if (pSignerCert == NULL)
	{
		result.strError = _T("No signer certificate");
		return FALSE;
	}

	// Get certificate info
	result.strSignerSubject = CStringHelper::CertNameBlobToString(
		pSignerCert->pCertInfo->Subject);
	result.strSignerIssuer = CStringHelper::CertNameBlobToString(
		pSignerCert->pCertInfo->Issuer);
	result.strCertValidFrom = CStringHelper::FileTimeToString(
		pSignerCert->pCertInfo->NotBefore);
	result.strCertValidTo = CStringHelper::FileTimeToString(
		pSignerCert->pCertInfo->NotAfter);

	// SHA-1 thumbprint
	BYTE rgbThumb[20] = {0};
	DWORD cbThumb = 20;
	if (CryptHashCertificate(0, CALG_SHA1, 0,
		pSignerCert->pbCertEncoded,
		pSignerCert->cbCertEncoded,
		rgbThumb, &cbThumb))
	{
		result.strSignerThumbprint =
			CStringHelper::BinaryToHex(rgbThumb, cbThumb, FALSE);
	}

	// Check certificate expiry
	FILETIME ftNow;
	SYSTEMTIME stNow;
	GetSystemTime(&stNow);
	SystemTimeToFileTime(&stNow, &ftNow);

	if (CompareFileTime(&ftNow, &pSignerCert->pCertInfo->NotBefore) < 0)
		result.strValidityStatus = _T("NOT YET VALID");
	else if (CompareFileTime(&ftNow, &pSignerCert->pCertInfo->NotAfter) > 0)
		result.strValidityStatus = _T("EXPIRED");
	else
		result.strValidityStatus = _T("VALID");

	result.bNotExpired =
		(result.strValidityStatus == _T("VALID")) ? TRUE : FALSE;
	result.bCertificateValid = result.bNotExpired;

	// ---- Cryptographic signature verification ----
	// Get public key from certificate
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY  hPubKey = NULL;

	// Use VERIFYCONTEXT provider for hashing
	CryptAcquireContext(
		&hProv, NULL, NULL,
		PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

	if (hProv == NULL)
	{
		// Try default provider
		CryptAcquireContext(
			&hProv, NULL, NULL,
			PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	}

	if (hProv == NULL)
	{
		result.strError = _T("Cannot acquire crypto provider for verification");
		return FALSE;
	}

	// Import the public key from the certificate
	if (!CryptImportPublicKeyInfo(
		hProv,
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		&pSignerCert->pCertInfo->SubjectPublicKeyInfo,
		&hPubKey))
	{
		DWORD dwErr = GetLastError();
		result.strError =
			CString(_T("CryptImportPublicKeyInfo failed: ")) +
			CErrorHelper::GetCryptoErrorDescription(dwErr);

		CLogger::Instance().LogFmt(LOG_LEVEL_ERROR,
			_T("SignatureVerifier"),
			_T("Import public key failed: 0x%08X"), dwErr);

		CryptReleaseContext(hProv, 0);
		return FALSE;
	}

	// Create hash of data
	//const ALG_ID CALG_SHA256_VALUE = (ALG_ID)0x0000800cUL;
	ALG_ID hashAlgId;

	switch (hashAlg)
	{
	case HASH_SHA1:   hashAlgId = CALG_SHA1;         break;
	case HASH_SHA256: hashAlgId = CALG_SHA_256;  break;
	case HASH_SHA384: hashAlgId = (ALG_ID)0x0000800dUL; break;
	case HASH_SHA512: hashAlgId = (ALG_ID)0x0000800eUL; break;
	default:          hashAlgId = CALG_SHA_256;  break;
	}

	HCRYPTHASH hHash = NULL;
	BOOL bVerified   = FALSE;

	if (CryptCreateHash(hProv, hashAlgId, 0, 0, &hHash) && hHash)
	{
		if (CryptHashData(hHash, pbData, cbData, 0))
		{
			// Verify needs big-endian signature
			// CryptoAPI VerifySignature expects little-endian
			// So we reverse the signature bytes
			BYTE* pSigLE = (BYTE*)LocalAlloc(LPTR, cbSignature);
			if (pSigLE)
			{
				for (DWORD i = 0; i < cbSignature; i++)
					pSigLE[i] = pbSignature[cbSignature - 1 - i];

				bVerified = CryptVerifySignature(
					hHash,
					pSigLE,
					cbSignature,
					hPubKey,
					NULL,
					0) ? TRUE : FALSE;

				if (!bVerified)
				{
					DWORD dwErr = GetLastError();
					// Try original order
					bVerified = CryptVerifySignature(
						hHash,
						pbSignature,
						cbSignature,
						hPubKey,
						NULL,
						0) ? TRUE : FALSE;

					if (!bVerified)
					{
						result.strError =
							CString(_T("Signature verification failed: ")) +
							CErrorHelper::GetCryptoErrorDescription(dwErr);
					}
				}

				LocalFree(pSigLE);
			}
		}
		CryptDestroyHash(hHash);
	}

	CryptDestroyKey(hPubKey);
	CryptReleaseContext(hProv, 0);

	result.bSignatureValid = bVerified;

	if (bVerified)
	{
		CLogger::Instance().LogFmt(LOG_LEVEL_PASS,
			_T("SignatureVerifier"),
			_T("Signature VALID | Signer: %s | Hash: %s"),
			(LPCTSTR)result.strSignerSubject,
			(LPCTSTR)CSignatureEngine::HashAlgorithmToString(hashAlg));
	}
	else
	{
		CLogger::Instance().LogFmt(LOG_LEVEL_FAIL,
			_T("SignatureVerifier"),
			_T("Signature INVALID | Signer: %s"),
			(LPCTSTR)result.strSignerSubject);
	}

	// Build certificate chain
	BuildCertChain(pSignerCert, result);

	result.dwDurationMs = GetTickCount() - dwStart;

	return result.bSignatureValid;
}

// ============================================================
// ValidateCertificate
// ============================================================
BOOL CSignatureVerifier::ValidateCertificate(
	PCCERT_CONTEXT pCertContext,
	VerificationResult& result)
{
	if (!pCertContext) return FALSE;

	result.strSignerSubject = CStringHelper::CertNameBlobToString(
		pCertContext->pCertInfo->Subject);
	result.strSignerIssuer = CStringHelper::CertNameBlobToString(
		pCertContext->pCertInfo->Issuer);

	// Check validity
	FILETIME ftNow;
	SYSTEMTIME stNow;
	GetSystemTime(&stNow);
	SystemTimeToFileTime(&stNow, &ftNow);

	if (CompareFileTime(&ftNow, &pCertContext->pCertInfo->NotAfter) > 0)
	{
		result.strValidityStatus = _T("EXPIRED");
		result.bNotExpired = FALSE;
	}
	else if (CompareFileTime(&ftNow, &pCertContext->pCertInfo->NotBefore) < 0)
	{
		result.strValidityStatus = _T("NOT YET VALID");
		result.bNotExpired = FALSE;
	}
	else
	{
		result.strValidityStatus = _T("VALID");
		result.bNotExpired = TRUE;
	}

	result.bCertificateValid = result.bNotExpired;

	BuildCertChain(pCertContext, result);

	return result.bCertificateValid && result.bChainValid;
}

// ============================================================
// BuildCertChain
// ============================================================
BOOL CSignatureVerifier::BuildCertChain(
										PCCERT_CONTEXT pCertContext,
										VerificationResult& result)
{
	result.bChainValid = FALSE;
	result.strChainStatus = _T("NOT CHECKED");

	CERT_CHAIN_PARA chainPara;
	ZeroMemory(&chainPara, sizeof(chainPara));
	chainPara.cbSize = sizeof(chainPara);

	// Only check online if not running in minimal mode
	DWORD dwFlags =
		CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY;

	PCCERT_CHAIN_CONTEXT pChainContext = NULL;

	BOOL bOK = CertGetCertificateChain(
		NULL,
		pCertContext,
		NULL,
		NULL,
		&chainPara,
		dwFlags,
		NULL,
		&pChainContext);

	if (!bOK || pChainContext == NULL)
	{
		DWORD dwErr = GetLastError();
		result.strChainStatus =
			CString(_T("Chain build failed: ")) +
			CErrorHelper::GetCertStoreError(dwErr);

		CLogger::Instance().LogFmt(LOG_LEVEL_WARNING,
			_T("SignatureVerifier"),
			_T("CertGetCertificateChain failed: 0x%08X"), dwErr);
		return FALSE;
	}

	// Check chain status
	DWORD dwErrorStatus = pChainContext->TrustStatus.dwErrorStatus;

	if (dwErrorStatus == CERT_TRUST_NO_ERROR)
	{
		result.bChainValid = TRUE;
		result.strChainStatus = _T("VALID");

		CLogger::Instance().Pass(_T("SignatureVerifier"),
			_T("Certificate chain: VALID"));
	}
	else
	{
		// Analyze specific errors
		CString strErrors;

		if (dwErrorStatus & CERT_TRUST_IS_NOT_TIME_VALID)
			strErrors += _T("EXPIRED; ");
		if (dwErrorStatus & CERT_TRUST_IS_REVOKED)
		{
			strErrors += _T("REVOKED; ");
			result.bRevoked = TRUE;
		}
		if (dwErrorStatus & CERT_TRUST_IS_NOT_SIGNATURE_VALID)
			strErrors += _T("INVALID_SIGNATURE; ");
		if (dwErrorStatus & CERT_TRUST_IS_NOT_VALID_FOR_USAGE)
			strErrors += _T("INVALID_USAGE; ");
		if (dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT)
			strErrors += _T("UNTRUSTED_ROOT; ");
		if (dwErrorStatus & CERT_TRUST_IS_PARTIAL_CHAIN)
			strErrors += _T("PARTIAL_CHAIN; ");
		if (dwErrorStatus & CERT_TRUST_REVOCATION_STATUS_UNKNOWN)
		{
			strErrors += _T("REVOCATION_UNKNOWN; ");
			result.bRevocationChecked = FALSE;
		}
		if (dwErrorStatus & CERT_TRUST_IS_OFFLINE_REVOCATION)
			strErrors += _T("REVOCATION_OFFLINE; ");

		if (strErrors.IsEmpty())
		{
			TCHAR szBuf[32] = {0};
			_sntprintf_s(szBuf, 32, _TRUNCATE,
				_T("0x%08X"), dwErrorStatus);
			strErrors = CString(szBuf);
		}

		result.strChainStatus = strErrors;
		result.bChainValid = FALSE;

		CLogger::Instance().LogFmt(LOG_LEVEL_WARNING,
			_T("SignatureVerifier"),
			_T("Chain status: %s"), (LPCTSTR)strErrors);
	}

	// Check revocation from chain info
	if (pChainContext->TrustStatus.dwInfoStatus &
		CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS)
	{
		result.bRevocationChecked = TRUE;
		result.bRevoked = ((dwErrorStatus & CERT_TRUST_IS_REVOKED) != 0);

		result.strRevocationStatus = result.bRevoked ?
			_T("REVOKED") : _T("GOOD");
	}
	else
	{
		result.strRevocationStatus = _T("NOT CHECKED");
	}

	CertFreeCertificateChain(pChainContext);
	return result.bChainValid;
}