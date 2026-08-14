// Core/DiagnosticResult.cpp
#include "stdafx.h"
#include "DiagnosticResult.h"

// ============================================================
// CDiagnosticResult
// ============================================================

CDiagnosticResult::CDiagnosticResult()
: m_status(DIAG_STATUS_UNKNOWN)
, m_dwDurationMs(0)
{
	ZeroMemory(&m_timeStart, sizeof(m_timeStart));
	ZeroMemory(&m_timeEnd,   sizeof(m_timeEnd));
}

CDiagnosticResult::CDiagnosticResult(const CDiagnosticResult& other)
: m_strCheckName(other.m_strCheckName)
, m_strCategory(other.m_strCategory)
, m_status(other.m_status)
, m_timeStart(other.m_timeStart)
, m_timeEnd(other.m_timeEnd)
, m_dwDurationMs(other.m_dwDurationMs)
, m_strSummary(other.m_strSummary)
{
	// Copy findings array
	m_findings.RemoveAll();
	for (int i = 0; i < other.m_findings.GetSize(); i++)
		m_findings.Add(other.m_findings[i]);
}

CDiagnosticResult& CDiagnosticResult::operator=(
	const CDiagnosticResult& other)
{
	if (this != &other)
	{
		m_strCheckName  = other.m_strCheckName;
		m_strCategory   = other.m_strCategory;
		m_status        = other.m_status;
		m_timeStart     = other.m_timeStart;
		m_timeEnd       = other.m_timeEnd;
		m_dwDurationMs  = other.m_dwDurationMs;
		m_strSummary    = other.m_strSummary;

		m_findings.RemoveAll();
		for (int i = 0; i < other.m_findings.GetSize(); i++)
			m_findings.Add(other.m_findings[i]);
	}
	return *this;
}

CDiagnosticResult::~CDiagnosticResult()
{
	m_findings.RemoveAll();
}

void CDiagnosticResult::AddFinding(
								   DiagnosticSeverity severity,
								   const CString& strCode,
								   const CString& strSource,
								   const CString& strDesc,
								   const CString& strDetail,
								   const CString& strRec,
								   DWORD dwErr)
{
	DiagnosticFinding f;
	f.severity          = severity;
	f.strCode           = strCode;
	f.strSource         = strSource;
	f.strDescription    = strDesc;
	f.strDetail         = strDetail;
	f.strRecommendation = strRec;
	f.dwErrorCode       = dwErr;
	m_findings.Add(f);
}

void CDiagnosticResult::AddPass(
								const CString& strSource,
								const CString& strDesc)
{
	AddFinding(DIAG_SEVERITY_PASS,
		_T("PASS"), strSource, strDesc);
}

void CDiagnosticResult::AddWarning(
								   const CString& strSource,
								   const CString& strDesc,
								   const CString& strRec)
{
	AddFinding(DIAG_SEVERITY_WARNING,
		_T("WARNING"), strSource, strDesc,
		CString(), strRec);
}

void CDiagnosticResult::AddError(
								 const CString& strSource,
								 const CString& strDesc,
								 const CString& strRec,
								 DWORD dwErr)
{
	AddFinding(DIAG_SEVERITY_ERROR,
		_T("ERROR"), strSource, strDesc,
		CString(), strRec, dwErr);
}

void CDiagnosticResult::SetStatus(DiagnosticStatus status)
{
	m_status = status;
}

void CDiagnosticResult::RecalculateStatus()
{
	int nError   = GetFindingCountBySeverity(DIAG_SEVERITY_ERROR);
	int nFail    = GetFindingCountBySeverity(DIAG_SEVERITY_FAIL);
	int nWarning = GetFindingCountBySeverity(DIAG_SEVERITY_WARNING);
	int nPass    = GetFindingCountBySeverity(DIAG_SEVERITY_PASS);

	if (nError > 0 || nFail > 0)
		m_status = DIAG_STATUS_FAIL;
	else if (nWarning > 0)
		m_status = DIAG_STATUS_WARNING;
	else if (nPass > 0)
		m_status = DIAG_STATUS_PASS;
	else
		m_status = DIAG_STATUS_UNKNOWN;
}

int CDiagnosticResult::GetFindingCount() const
{
	return (int)m_findings.GetSize();
}

int CDiagnosticResult::GetFindingCountBySeverity(
	DiagnosticSeverity sev) const
{
	int n = 0;
	for (int i = 0; i < (int)m_findings.GetSize(); i++)
		if (m_findings[i].severity == sev) n++;
	return n;
}

CString CDiagnosticResult::StatusToString(DiagnosticStatus status)
{
	switch (status)
	{
	case DIAG_STATUS_PASS:          return _T("PASS");
	case DIAG_STATUS_FAIL:          return _T("FAIL");
	case DIAG_STATUS_WARNING:       return _T("WARNING");
	case DIAG_STATUS_NOT_TESTED:    return _T("NOT TESTED");
	case DIAG_STATUS_NOT_AVAILABLE: return _T("N/A");
	case DIAG_STATUS_RUNNING:       return _T("RUNNING...");
	default:                        return _T("UNKNOWN");
	}
}

CString CDiagnosticResult::SeverityToString(DiagnosticSeverity sev)
{
	switch (sev)
	{
	case DIAG_SEVERITY_INFO:    return _T("INFO");
	case DIAG_SEVERITY_WARNING: return _T("WARNING");
	case DIAG_SEVERITY_ERROR:   return _T("ERROR");
	case DIAG_SEVERITY_PASS:    return _T("PASS");
	case DIAG_SEVERITY_FAIL:    return _T("FAIL");
	default:                    return _T("NONE");
	}
}

void CDiagnosticResult::MarkStart()
{
	GetSystemTime(&m_timeStart);
}

void CDiagnosticResult::MarkEnd()
{
	GetSystemTime(&m_timeEnd);

	FILETIME ftStart, ftEnd;
	SystemTimeToFileTime(&m_timeStart, &ftStart);
	SystemTimeToFileTime(&m_timeEnd,   &ftEnd);

	ULARGE_INTEGER uStart, uEnd;
	uStart.LowPart  = ftStart.dwLowDateTime;
	uStart.HighPart = ftStart.dwHighDateTime;
	uEnd.LowPart    = ftEnd.dwLowDateTime;
	uEnd.HighPart   = ftEnd.dwHighDateTime;

	if (uEnd.QuadPart >= uStart.QuadPart)
		m_dwDurationMs = (DWORD)(
		(uEnd.QuadPart - uStart.QuadPart) / 10000);
	else
		m_dwDurationMs = 0;
}

// ============================================================
// CDiagnosticResultSet
// ============================================================

CDiagnosticResultSet::CDiagnosticResultSet()
{
	GetSystemTime(&m_timeGenerated);
}

CDiagnosticResultSet::~CDiagnosticResultSet()
{
	Clear();
}

void CDiagnosticResultSet::AddResult(const CDiagnosticResult& result)
{
	m_results.Add(result);
}

int CDiagnosticResultSet::GetResultCount() const
{
	return (int)m_results.GetSize();
}

const CDiagnosticResult* CDiagnosticResultSet::GetResult(
	int nIndex) const
{
	if (nIndex < 0 || nIndex >= (int)m_results.GetSize())
		return NULL;
	return &m_results[nIndex];
}

CDiagnosticResult* CDiagnosticResultSet::GetResultByCategory(
	const CString& strCategory)
{
	for (int i = 0; i < (int)m_results.GetSize(); i++)
	{
		if (m_results[i].m_strCategory == strCategory)
			return &m_results[i];
	}
	return NULL;
}

int CDiagnosticResultSet::GetTotalPass() const
{
	int n = 0;
	for (int i = 0; i < (int)m_results.GetSize(); i++)
		if (m_results[i].m_status == DIAG_STATUS_PASS) n++;
	return n;
}

int CDiagnosticResultSet::GetTotalFail() const
{
	int n = 0;
	for (int i = 0; i < (int)m_results.GetSize(); i++)
		if (m_results[i].m_status == DIAG_STATUS_FAIL) n++;
	return n;
}

int CDiagnosticResultSet::GetTotalWarning() const
{
	int n = 0;
	for (int i = 0; i < (int)m_results.GetSize(); i++)
		if (m_results[i].m_status == DIAG_STATUS_WARNING) n++;
	return n;
}

DiagnosticStatus CDiagnosticResultSet::GetOverallStatus() const
{
	if (GetTotalFail() > 0)    return DIAG_STATUS_FAIL;
	if (GetTotalWarning() > 0) return DIAG_STATUS_WARNING;
	if (GetTotalPass() > 0)    return DIAG_STATUS_PASS;
	return DIAG_STATUS_UNKNOWN;
}

CString CDiagnosticResultSet::GetSummary() const
{
	TCHAR szBuf[256] = {0};
	_sntprintf_s(szBuf, 256, _TRUNCATE,
		_T("Results: %d PASS | %d WARNING | %d FAIL | Overall: %s"),
		GetTotalPass(), GetTotalWarning(), GetTotalFail(),
		(LPCTSTR)CDiagnosticResult::StatusToString(
		GetOverallStatus()));
	return CString(szBuf);
}

void CDiagnosticResultSet::Clear()
{
	m_results.RemoveAll();
}