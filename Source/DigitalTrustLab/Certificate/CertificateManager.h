// Certificate/CertificateManager.h
// Digital Trust Interoperability Lab - Phase 1

#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <afx.h>
#include <afxtempl.h>

// CertificateInfo is now in its own header
#include "CertificateInfo.h"
#include "../Core/DiagnosticResult.h"

class CCertificateManager
{
public:
	CCertificateManager();
	~CCertificateManager();

	BOOL EnumerateCertificates();

	int GetCertificateCount() const;
	const CertificateInfo* GetCertificate(int nIndex) const;
	const CDiagnosticResult& GetDiagnosticResult() const;

	void Clear();

	BOOL EnumerateStore(
		const CString& strStoreName,
		const CString& strStoreLocation,
		DWORD dwFlags);

	static const int STORE_COUNT = 8;
	static LPCTSTR   s_szStoreNames[STORE_COUNT];


	void ResetDiagnosticResult();

	void AnalyzeCertificate(
		PCCERT_CONTEXT pCertContext,
		const CString& strStoreName,
		const CString& strStoreLocation,
		CertificateInfo& info);

	void ExtractSubjectIssuer(PCCERT_CONTEXT pCtx, CertificateInfo& info);
	void ExtractValidity(PCCERT_CONTEXT pCtx, CertificateInfo& info);
	void ExtractAlgorithms(PCCERT_CONTEXT pCtx, CertificateInfo& info);
	void ExtractThumbprints(PCCERT_CONTEXT pCtx, CertificateInfo& info);
	void ExtractKeyUsage(PCCERT_CONTEXT pCtx, CertificateInfo& info);
	void ExtractExtensions(PCCERT_CONTEXT pCtx, CertificateInfo& info);
	void DetectPrivateKey(PCCERT_CONTEXT pCtx, CertificateInfo& info);

	void DetectCSPPrivateKey(
		PCCERT_CONTEXT pCtx,
		CertificateInfo& info,
		const CRYPT_KEY_PROV_INFO* pKeyProvInfo);

	void DetectCNGPrivateKey(
		PCCERT_CONTEXT pCtx,
		CertificateInfo& info,
		const CRYPT_KEY_PROV_INFO* pKeyProvInfo);

	CString ExtractEKU(PCCERT_CONTEXT pCtx);
	CString ExtractCDPUrls(PCCERT_CONTEXT pCtx);
	CString ExtractAIAUrls(PCCERT_CONTEXT pCtx, BOOL bOCSP);
	CString ExtractCAIssuers(PCCERT_CONTEXT pCtx);
	CString ExtractAKI(PCCERT_CONTEXT pCtx);
	CString ExtractSKI(PCCERT_CONTEXT pCtx);

	CArray<CertificateInfo, const CertificateInfo&> m_certificates;
	CDiagnosticResult m_diagResult;
};