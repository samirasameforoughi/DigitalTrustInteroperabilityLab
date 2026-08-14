// Utils/StringHelper.cpp
// Digital Trust Interoperability Lab - Phase 1
// ONLY CStringHelper implementations here
// Do NOT include ErrorHelper.cpp content here

#include "stdafx.h"
#include "StringHelper.h"

// ============================================================
CString CStringHelper::BinaryToHex(
								   const BYTE* pbData,
								   DWORD cbData,
								   BOOL bSpaces)
{
	if (pbData == NULL || cbData == 0)
		return _T("");

	CString strResult;
	TCHAR szByte[8] = {0};

	for (DWORD i = 0; i < cbData; i++)
	{
		_sntprintf_s(szByte, 8, _TRUNCATE,
			_T("%02X"), pbData[i]);
		strResult += szByte;

		if (bSpaces && i < cbData - 1)
			strResult += _T(" ");
	}

	return strResult;
}

// ============================================================
CString CStringHelper::BinaryToHexColon(
										const BYTE* pbData,
										DWORD cbData)
{
	if (pbData == NULL || cbData == 0)
		return _T("");

	CString strResult;
	TCHAR szByte[8] = {0};

	for (DWORD i = 0; i < cbData; i++)
	{
		_sntprintf_s(szByte, 8, _TRUNCATE,
			_T("%02X"), pbData[i]);
		strResult += szByte;

		if (i < cbData - 1)
			strResult += _T(":");
	}

	return strResult;
}

// ============================================================
CString CStringHelper::SerialNumberToString(
	const CRYPT_INTEGER_BLOB& blob)
{
	if (blob.pbData == NULL || blob.cbData == 0)
		return _T("(none)");

	// Serial number: bytes are little-endian, display big-endian
	CString strResult;
	TCHAR szByte[8] = {0};

	for (int i = (int)blob.cbData - 1; i >= 0; i--)
	{
		_sntprintf_s(szByte, 8, _TRUNCATE,
			_T("%02X"), blob.pbData[i]);
		strResult += szByte;

		if (i > 0)
			strResult += _T(" ");
	}

	return strResult;
}

// ============================================================
CString CStringHelper::CertNameBlobToString(
	const CERT_NAME_BLOB& nameBlob)
{
	DWORD dwSize = CertNameToStr(
		X509_ASN_ENCODING,
		const_cast<PCERT_NAME_BLOB>(&nameBlob),
		CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
		NULL,
		0);

	if (dwSize <= 1)
		return _T("(empty)");

	CString strResult;
	LPTSTR pszBuf = strResult.GetBufferSetLength((int)dwSize + 1);

	CertNameToStr(
		X509_ASN_ENCODING,
		const_cast<PCERT_NAME_BLOB>(&nameBlob),
		CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
		pszBuf,
		dwSize + 1);

	strResult.ReleaseBuffer();
	return strResult;
}

// ============================================================
CString CStringHelper::FileTimeToString(const FILETIME& ft)
{
	if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0)
		return _T("(not set)");

	SYSTEMTIME st;
	ZeroMemory(&st, sizeof(st));

	if (!FileTimeToSystemTime(&ft, &st))
		return _T("(invalid time)");

	TCHAR szBuf[128] = {0};
	_sntprintf_s(szBuf, 128, _TRUNCATE,
		_T("%04d-%02d-%02d %02d:%02d:%02d UTC"),
		st.wYear, st.wMonth, st.wDay,
		st.wHour, st.wMinute, st.wSecond);

	return CString(szBuf);
}

// ============================================================
CString CStringHelper::OidToAlgorithmName(LPCSTR pszOID)
{
	if (pszOID == NULL)
		return _T("(unknown)");

	// Signature algorithms
	if (strcmp(pszOID, szOID_RSA_SHA256RSA) == 0)
		return _T("SHA256withRSA");
	if (strcmp(pszOID, szOID_RSA_SHA384RSA) == 0)
		return _T("SHA384withRSA");
	if (strcmp(pszOID, szOID_RSA_SHA512RSA) == 0)
		return _T("SHA512withRSA");
	if (strcmp(pszOID, szOID_RSA_SHA1RSA) == 0)
		return _T("SHA1withRSA");
	if (strcmp(pszOID, szOID_RSA_MD5RSA) == 0)
		return _T("MD5withRSA");
	if (strcmp(pszOID, szOID_RSA_MD2RSA) == 0)
		return _T("MD2withRSA");

	// Public key
	if (strcmp(pszOID, szOID_RSA_RSA) == 0)
		return _T("RSA");
	if (strcmp(pszOID, "1.2.840.113549.1.1.1") == 0)
		return _T("RSA (PKCS#1)");
	if (strcmp(pszOID, szOID_X957_DSA) == 0)
		return _T("DSA");
	if (strcmp(pszOID, szOID_X957_SHA1DSA) == 0)
		return _T("SHA1withDSA");

	// EC
	if (strcmp(pszOID, "1.2.840.10045.4.3.2") == 0)
		return _T("SHA256withECDSA");
	if (strcmp(pszOID, "1.2.840.10045.4.3.3") == 0)
		return _T("SHA384withECDSA");
	if (strcmp(pszOID, "1.2.840.10045.4.3.4") == 0)
		return _T("SHA512withECDSA");
	if (strcmp(pszOID, "1.2.840.10045.2.1") == 0)
		return _T("EC Public Key");

	// Hash OIDs (by string value, not macro)
	if (strcmp(pszOID, "2.16.840.1.101.3.4.2.1") == 0)
		return _T("SHA-256");
	if (strcmp(pszOID, "2.16.840.1.101.3.4.2.2") == 0)
		return _T("SHA-384");
	if (strcmp(pszOID, "2.16.840.1.101.3.4.2.3") == 0)
		return _T("SHA-512");
	if (strcmp(pszOID, "1.3.14.3.2.26") == 0)
		return _T("SHA-1");
	if (strcmp(pszOID, "1.2.840.113549.2.5") == 0)
		return _T("MD5");
	if (strcmp(pszOID, "1.2.840.113549.2.2") == 0)
		return _T("MD2");

	// Return OID string as-is
#ifdef _UNICODE
	int nLen = MultiByteToWideChar(
		CP_ACP, 0, pszOID, -1, NULL, 0);
	if (nLen <= 0)
		return _T("(unknown)");

	CString strOID;
	LPWSTR pBuf = strOID.GetBufferSetLength(nLen + 1);
	MultiByteToWideChar(CP_ACP, 0, pszOID, -1, pBuf, nLen + 1);
	strOID.ReleaseBuffer();
	return strOID;
#else
	return CString(pszOID);
#endif
}

// ============================================================
CString CStringHelper::KeyUsageToString(DWORD dwKeyUsage)
{
	if (dwKeyUsage == 0)
		return _T("(none)");

	CString strResult;

	if (dwKeyUsage & CERT_DIGITAL_SIGNATURE_KEY_USAGE)
		strResult += _T("DigitalSignature ");
	if (dwKeyUsage & CERT_NON_REPUDIATION_KEY_USAGE)
		strResult += _T("NonRepudiation ");
	if (dwKeyUsage & CERT_KEY_ENCIPHERMENT_KEY_USAGE)
		strResult += _T("KeyEncipherment ");
	if (dwKeyUsage & CERT_DATA_ENCIPHERMENT_KEY_USAGE)
		strResult += _T("DataEncipherment ");
	if (dwKeyUsage & CERT_KEY_AGREEMENT_KEY_USAGE)
		strResult += _T("KeyAgreement ");
	if (dwKeyUsage & CERT_KEY_CERT_SIGN_KEY_USAGE)
		strResult += _T("KeyCertSign ");
	if (dwKeyUsage & CERT_OFFLINE_CRL_SIGN_KEY_USAGE)
		strResult += _T("CRLSign ");
	if (dwKeyUsage & CERT_ENCIPHER_ONLY_KEY_USAGE)
		strResult += _T("EncipherOnly ");

	strResult.TrimRight();
	return strResult.IsEmpty() ? _T("(none)") : strResult;
}

// ============================================================
CString CStringHelper::ProviderTypeToString(DWORD dwProvType)
{
	switch (dwProvType)
	{
	case PROV_RSA_FULL:      return _T("PROV_RSA_FULL (1)");
	case PROV_RSA_SIG:       return _T("PROV_RSA_SIG (2)");
	case PROV_DSS:           return _T("PROV_DSS (3)");
	case PROV_FORTEZZA:      return _T("PROV_FORTEZZA (4)");
	case PROV_MS_EXCHANGE:   return _T("PROV_MS_EXCHANGE (5)");
	case PROV_SSL:           return _T("PROV_SSL (6)");
	case PROV_RSA_SCHANNEL:  return _T("PROV_RSA_SCHANNEL (12)");
	case PROV_DSS_DH:        return _T("PROV_DSS_DH (13)");
	case PROV_EC_ECDSA_SIG:  return _T("PROV_EC_ECDSA_SIG (16)");
	case PROV_EC_ECNRA_SIG:  return _T("PROV_EC_ECNRA_SIG (17)");
	case PROV_EC_ECDSA_FULL: return _T("PROV_EC_ECDSA_FULL (18)");
	case PROV_EC_ECNRA_FULL: return _T("PROV_EC_ECNRA_FULL (19)");
	case 20:                 return _T("PROV_SPYRUS_LYNKs (20)");
	case PROV_RNG:           return _T("PROV_RNG (21)");
	case PROV_INTEL_SEC:     return _T("PROV_INTEL_SEC (22)");
	case PROV_REPLACE_OWF:   return _T("PROV_REPLACE_OWF (23)");
	case PROV_RSA_AES:       return _T("PROV_RSA_AES (24)");
	default:
		{
			TCHAR szBuf[32] = {0};
			_sntprintf_s(szBuf, 32, _TRUNCATE,
				_T("Unknown (%lu)"), (unsigned long)dwProvType);
			return CString(szBuf);
		}
	}
}

// ============================================================
CString CStringHelper::Trim(const CString& str)
{
	CString s(str);
	s.TrimLeft();
	s.TrimRight();
	return s;
}

// ============================================================
CString CStringHelper::FormatKeySize(DWORD dwBits)
{
	TCHAR szBuf[64] = {0};
	_sntprintf_s(szBuf, 64, _TRUNCATE,
		_T("%lu bits"), (unsigned long)dwBits);
	return CString(szBuf);
}

// ============================================================
CString CStringHelper::ValidityStatus(
									  const FILETIME& ftNotBefore,
									  const FILETIME& ftNotAfter)
{
	FILETIME ftNow;
	SYSTEMTIME stNow;
	GetSystemTime(&stNow);
	SystemTimeToFileTime(&stNow, &ftNow);

	if (CompareFileTime(&ftNow, &ftNotBefore) < 0)
		return _T("NOT YET VALID");

	if (CompareFileTime(&ftNow, &ftNotAfter) > 0)
		return _T("EXPIRED");

	return _T("VALID");
}