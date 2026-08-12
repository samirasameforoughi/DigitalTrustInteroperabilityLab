// Core/DiagnosticResult.h
// Digital Trust Interoperability Lab - Phase 1
// IMPORTANT: No stdafx.h include here - causes circular include

#pragma once

#include <windows.h>
#include <afx.h>
#include <afxtempl.h>

// ============================================================
// Enums
// ============================================================
enum DiagnosticSeverity
{
	DIAG_SEVERITY_NONE    = 0,
	DIAG_SEVERITY_INFO    = 1,
	DIAG_SEVERITY_WARNING = 2,
	DIAG_SEVERITY_ERROR   = 3,
	DIAG_SEVERITY_PASS    = 4,
	DIAG_SEVERITY_FAIL    = 5
};

enum DiagnosticStatus
{
	DIAG_STATUS_UNKNOWN       = 0,
	DIAG_STATUS_PASS          = 1,
	DIAG_STATUS_FAIL          = 2,
	DIAG_STATUS_WARNING       = 3,
	DIAG_STATUS_NOT_TESTED    = 4,
	DIAG_STATUS_NOT_AVAILABLE = 5,
	DIAG_STATUS_RUNNING       = 6
};

// ============================================================
// DiagnosticFinding - plain struct, NO CObject inheritance
// Must have explicit copy constructor and operator= for CArray
// ============================================================
struct DiagnosticFinding
{
	DiagnosticSeverity  severity;
	CString             strCode;
	CString             strSource;
	CString             strDescription;
	CString             strDetail;
	CString             strRecommendation;
	DWORD               dwErrorCode;

	DiagnosticFinding()
		: severity(DIAG_SEVERITY_NONE)
		, dwErrorCode(0)
	{
	}

	DiagnosticFinding(const DiagnosticFinding& o)
		: severity(o.severity)
		, strCode(o.strCode)
		, strSource(o.strSource)
		, strDescription(o.strDescription)
		, strDetail(o.strDetail)
		, strRecommendation(o.strRecommendation)
		, dwErrorCode(o.dwErrorCode)
	{
	}

	DiagnosticFinding& operator=(const DiagnosticFinding& o)
	{
		if (this != &o)
		{
			severity            = o.severity;
			strCode             = o.strCode;
			strSource           = o.strSource;
			strDescription      = o.strDescription;
			strDetail           = o.strDetail;
			strRecommendation   = o.strRecommendation;
			dwErrorCode         = o.dwErrorCode;
		}
		return *this;
	}
};

// ============================================================
// CDiagnosticResult
// MUST declare copy constructor and operator= explicitly
// because it contains CArray member
// ============================================================
class CDiagnosticResult
{
public:
	// --- Constructors / Destructor ---
	CDiagnosticResult();
	CDiagnosticResult(const CDiagnosticResult& other);
	CDiagnosticResult& operator=(const CDiagnosticResult& other);
	~CDiagnosticResult();

	// --- Identity ---
	CString             m_strCheckName;
	CString             m_strCategory;
	DiagnosticStatus    m_status;

	// --- Timing ---
	SYSTEMTIME          m_timeStart;
	SYSTEMTIME          m_timeEnd;
	DWORD               m_dwDurationMs;

	// --- Findings ---
	CArray<DiagnosticFinding, const DiagnosticFinding&> m_findings;

	// --- Summary ---
	CString             m_strSummary;

	// --- Methods ---
	void AddFinding(
		DiagnosticSeverity severity,
		const CString& strCode,
		const CString& strSource,
		const CString& strDesc,
		const CString& strDetail = CString(),
		const CString& strRec   = CString(),
		DWORD dwErr = 0);

	void AddPass(
		const CString& strSource,
		const CString& strDesc);

	void AddWarning(
		const CString& strSource,
		const CString& strDesc,
		const CString& strRec = CString());

	void AddError(
		const CString& strSource,
		const CString& strDesc,
		const CString& strRec = CString(),
		DWORD dwErr = 0);

	void SetStatus(DiagnosticStatus status);
	void RecalculateStatus();

	int GetFindingCount() const;
	int GetFindingCountBySeverity(DiagnosticSeverity sev) const;

	static CString StatusToString(DiagnosticStatus status);
	static CString SeverityToString(DiagnosticSeverity sev);

	void MarkStart();
	void MarkEnd();
};

// ============================================================
// CDiagnosticResultSet
// ============================================================
class CDiagnosticResultSet
{
public:
	CDiagnosticResultSet();
	~CDiagnosticResultSet();

	void AddResult(const CDiagnosticResult& result);
	int  GetResultCount() const;
	const CDiagnosticResult* GetResult(int nIndex) const;
	CDiagnosticResult* GetResultByCategory(const CString& strCategory);

	int GetTotalPass() const;
	int GetTotalFail() const;
	int GetTotalWarning() const;

	DiagnosticStatus GetOverallStatus() const;
	CString GetSummary() const;
	void Clear();

	SYSTEMTIME m_timeGenerated;


	CArray<CDiagnosticResult, const CDiagnosticResult&> m_results;
};