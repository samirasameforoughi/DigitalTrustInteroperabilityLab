// PKCS11/PKCS11Loader.h
// Digital Trust Interoperability Lab - Phase 2
// Uses direct GetProcAddress instead of CK_FUNCTION_LIST
// to avoid struct layout compatibility issues

#pragma once

#include <windows.h>
#include <afx.h>
#include <afxtempl.h>
#include "PKCS11Types.h"

enum PKCS11TestStatus
{
	P11_TEST_NOT_RUN   = 0,
	P11_TEST_PASS      = 1,
	P11_TEST_FAIL      = 2,
	P11_TEST_WARNING   = 3,
	P11_TEST_SKIPPED   = 4
};

struct PKCS11TestResult
{
	CString          strTestName;
	CString          strTestCode;
	PKCS11TestStatus status;
	CK_RV            rvResult;
	CString          strResultCode;
	CString          strDescription;
	CString          strDetail;
	DWORD            dwDurationMs;

	PKCS11TestResult()
		: status(P11_TEST_NOT_RUN)
		, rvResult(CKR_OK)
		, dwDurationMs(0)
	{}

	PKCS11TestResult(const PKCS11TestResult& o)
		: strTestName(o.strTestName)
		, strTestCode(o.strTestCode)
		, status(o.status)
		, rvResult(o.rvResult)
		, strResultCode(o.strResultCode)
		, strDescription(o.strDescription)
		, strDetail(o.strDetail)
		, dwDurationMs(o.dwDurationMs)
	{}

	PKCS11TestResult& operator=(const PKCS11TestResult& o)
	{
		if (this != &o)
		{
			strTestName   = o.strTestName;
			strTestCode   = o.strTestCode;
			status        = o.status;
			rvResult      = o.rvResult;
			strResultCode = o.strResultCode;
			strDescription = o.strDescription;
			strDetail     = o.strDetail;
			dwDurationMs  = o.dwDurationMs;
		}
		return *this;
	}
};

struct PKCS11SlotInfo
{
	CK_SLOT_ID  slotId;
	CString     strDescription;
	CString     strManufacturerID;
	BOOL        bTokenPresent;
	BOOL        bRemovableDevice;
	BOOL        bHWSlot;
	BOOL        bTokenInfoAvailable;
	CString     strTokenLabel;
	CString     strTokenManufacturerID;
	CString     strTokenModel;
	CString     strTokenSerialNumber;
	BOOL        bLoginRequired;
	BOOL        bTokenInitialized;
	BOOL        bUserPinLocked;

	PKCS11SlotInfo()
		: slotId(0)
		, bTokenPresent(FALSE)
		, bRemovableDevice(FALSE)
		, bHWSlot(FALSE)
		, bTokenInfoAvailable(FALSE)
		, bLoginRequired(FALSE)
		, bTokenInitialized(FALSE)
		, bUserPinLocked(FALSE)
	{}
};

class CPKCS11Loader
{
public:
	CPKCS11Loader();
	~CPKCS11Loader();

	BOOL LoadLibrary(const CString& strDllPath);
	void UnloadLibrary();
	BOOL IsLoaded() const;
	CString GetDllPath() const;

	BOOL RunTests(BOOL bSilentMode = TRUE);

	int GetTestCount() const;
	const PKCS11TestResult* GetTestResult(int nIndex) const;

	int GetSlotCount() const;
	const PKCS11SlotInfo* GetSlotInfo(int nIndex) const;

	int GetPassCount() const;
	int GetFailCount() const;
	int GetWarningCount() const;

	CString GetLibraryManufacturer() const;
	CString GetLibraryDescription() const;
	CString GetLibraryVersion() const;

	static CString RVToString(CK_RV rv);
	static CString TestStatusToString(PKCS11TestStatus status);

	void Clear();
	// ============================================================
	// Phase 3.5: PKCS#11 Signing Support
	// ============================================================

	// Ensure library is initialized (call before Login/Sign)
	BOOL EnsureInitialized();

	// Login with PIN (interactive - not silent)
	CK_RV Login(const CString& strPIN);

	// Logout
	CK_RV Logout();

	// Find first signing-capable private key
	// Returns object handle, or CK_INVALID_HANDLE on failure
	CK_OBJECT_HANDLE FindFirstSigningKey();

	// Sign raw data (pre-hashed by caller)
	// pbHash: pre-computed hash bytes
	// cbHash: hash length (20 for SHA-1, 32 for SHA-256, etc.)
	// hashAlg: which hash was used (for mechanism selection)
	// pbSignature: output buffer
	// pcbSignature: in/out - buffer size / actual signature size
	CK_RV SignHash(
		CK_OBJECT_HANDLE hKey,
		const BYTE* pbHash,
		DWORD cbHash,
		int nHashAlg,  // 0=SHA1, 1=SHA256, 2=SHA384, 3=SHA512
		BYTE* pbSignature,
		DWORD* pcbSignature);

	// Get token label (for UI display)
	CString GetTokenLabel() const;

	// Is user logged in?
	BOOL IsLoggedIn() const { return m_bLoggedIn; }

	// Session accessible?
	BOOL HasSession() const
	{ return (m_hSession != CK_INVALID_HANDLE); }


	// Individual tests

	// Individual tests
	BOOL TestInitialize();
	BOOL TestGetInfo();
	BOOL TestGetSlotList();
	BOOL TestGetSlotInfo();
	BOOL TestGetTokenInfo();
	BOOL TestOpenSession();
	BOOL TestGetMechanismList();
	BOOL TestFindCertificates();
	BOOL TestFindPrivateKeys();

	void AddTestResult(const PKCS11TestResult& result);
	CString TrimPKCS11String(const CK_BYTE* pBytes, int nLen) const;
	CString ByteArrayToString(const CK_BYTE* pBytes, int nLen) const;

	HMODULE m_hDll;
	CString m_strDllPath;
	BOOL    m_bInitialized;

	// ============================================================
	// Direct function pointers - loaded via GetProcAddress
	// This avoids CK_FUNCTION_LIST struct layout issues
	// ============================================================
	CK_C_Initialize_t       m_pfnInitialize;
	CK_C_Finalize_t         m_pfnFinalize;
	CK_C_GetInfo_t          m_pfnGetInfo;
	CK_C_GetFunctionList_t  m_pfnGetFunctionList;
	CK_C_GetSlotList_t      m_pfnGetSlotList;
	CK_C_GetSlotInfo_t      m_pfnGetSlotInfo;
	CK_C_GetTokenInfo_t     m_pfnGetTokenInfo;
	CK_C_GetMechanismList_t m_pfnGetMechanismList;
	CK_C_GetMechanismInfo_t m_pfnGetMechanismInfo;
	CK_C_OpenSession_t      m_pfnOpenSession;
	CK_C_CloseSession_t     m_pfnCloseSession;
	CK_C_CloseAllSessions_t m_pfnCloseAllSessions;
	CK_C_GetSessionInfo_t   m_pfnGetSessionInfo;
	CK_C_Login_t            m_pfnLogin;
	CK_C_Logout_t           m_pfnLogout;
	CK_C_FindObjectsInit_t  m_pfnFindObjectsInit;
	CK_C_FindObjects_t      m_pfnFindObjects;
	CK_C_FindObjectsFinal_t m_pfnFindObjectsFinal;
	CK_C_GetAttributeValue_t m_pfnGetAttributeValue;
	CK_C_SignInit_t         m_pfnSignInit;
	CK_C_Sign_t             m_pfnSign;
	BOOL m_bLoggedIn;
	CString m_strTokenLabel;

	// Cached info
	CK_INFO m_ckInfo;
	BOOL    m_bInfoValid;

	// Active slot/session
	CK_SLOT_ID          m_activeSlot;
	CK_SESSION_HANDLE   m_hSession;

	// Results
	CArray<PKCS11TestResult, const PKCS11TestResult&> m_testResults;
	CArray<PKCS11SlotInfo,   const PKCS11SlotInfo&>   m_slots;
};