// Signature/SignatureVerifier.h
// Digital Trust Interoperability Lab - Phase 3

#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <afx.h>
#include "../Core/DiagnosticResult.h"
#include "SignatureEngine.h"

struct VerificationResult
{
	BOOL    bSignatureValid;
	BOOL    bCertificateValid;
	BOOL    bChainValid;
	BOOL    bNotExpired;
	BOOL    bRevocationChecked;
	BOOL    bRevoked;

	CString strSignerSubject;
	CString strSignerIssuer;
	CString strSignerThumbprint;
	CString strCertValidFrom;
	CString strCertValidTo;
	CString strValidityStatus;
	CString strChainStatus;
	CString strRevocationStatus;
	CString strError;

	DWORD   dwDurationMs;

	VerificationResult()
		: bSignatureValid(FALSE)
		, bCertificateValid(FALSE)
		, bChainValid(FALSE)
		, bNotExpired(FALSE)
		, bRevocationChecked(FALSE)
		, bRevoked(FALSE)
		, dwDurationMs(0)
	{}
};

class CSignatureVerifier
{
public:
	CSignatureVerifier();
	~CSignatureVerifier();

	// Verify raw signature against data
	BOOL VerifySignature(
		const BYTE* pbData,
		DWORD cbData,
		const BYTE* pbSignature,
		DWORD cbSignature,
		PCCERT_CONTEXT pSignerCert,
		SignHashAlgorithm hashAlg,
		VerificationResult& result);

	// Verify signature from hex strings
	BOOL VerifySignatureHex(
		const BYTE* pbData,
		DWORD cbData,
		const CString& strSignatureHex,
		PCCERT_CONTEXT pSignerCert,
		SignHashAlgorithm hashAlg,
		VerificationResult& result);

	// Validate certificate (chain + expiry)
	BOOL ValidateCertificate(
		PCCERT_CONTEXT pCertContext,
		VerificationResult& result);

	const CDiagnosticResult& GetDiagnosticResult() const;


	BOOL BuildCertChain(
		PCCERT_CONTEXT pCertContext,
		VerificationResult& result);

	CDiagnosticResult m_diagResult;
};