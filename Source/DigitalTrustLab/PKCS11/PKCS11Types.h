// PKCS11/PKCS11Types.h
// Simplified and safe PKCS#11 types for VC++ 2008
// Compatible with standard PKCS#11 v2.20

#pragma once
#include <windows.h>

// ============================================================
// Calling convention - PKCS#11 standard uses __cdecl on Win32
// Some vendors use __stdcall - we handle both
// ============================================================
#ifndef CK_PTR
#define CK_PTR *
#endif

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

// ============================================================
// Basic Types
// ============================================================
typedef unsigned char   CK_BYTE;
typedef unsigned char   CK_BBOOL;
typedef unsigned char   CK_CHAR;
typedef unsigned char   CK_UTF8CHAR;
typedef unsigned long   CK_ULONG;
typedef long            CK_LONG;
typedef CK_ULONG        CK_FLAGS;
typedef CK_ULONG        CK_SLOT_ID;
typedef CK_ULONG        CK_SESSION_HANDLE;
typedef CK_ULONG        CK_OBJECT_HANDLE;
typedef CK_ULONG        CK_MECHANISM_TYPE;
typedef CK_ULONG        CK_ATTRIBUTE_TYPE;
typedef CK_ULONG        CK_KEY_TYPE;
typedef CK_ULONG        CK_OBJECT_CLASS;
typedef CK_ULONG        CK_RV;
typedef CK_ULONG        CK_USER_TYPE;
typedef CK_ULONG        CK_STATE;
typedef CK_ULONG        CK_CERTIFICATE_TYPE;

typedef CK_BYTE*            CK_BYTE_PTR;
typedef CK_CHAR*            CK_CHAR_PTR;
typedef CK_UTF8CHAR*        CK_UTF8CHAR_PTR;
typedef CK_ULONG*           CK_ULONG_PTR;
typedef void*               CK_VOID_PTR;
typedef CK_VOID_PTR*        CK_VOID_PTR_PTR;
typedef CK_SLOT_ID*         CK_SLOT_ID_PTR;
typedef CK_SESSION_HANDLE*  CK_SESSION_HANDLE_PTR;
typedef CK_OBJECT_HANDLE*   CK_OBJECT_HANDLE_PTR;
typedef CK_MECHANISM_TYPE*  CK_MECHANISM_TYPE_PTR;

#define CK_TRUE   1
#define CK_FALSE  0
#define CK_INVALID_HANDLE 0UL

// ============================================================
// Return Values
// ============================================================
#define CKR_OK                              0x00000000UL
#define CKR_CANCEL                          0x00000001UL
#define CKR_HOST_MEMORY                     0x00000002UL
#define CKR_SLOT_ID_INVALID                 0x00000003UL
#define CKR_GENERAL_ERROR                   0x00000005UL
#define CKR_FUNCTION_FAILED                 0x00000006UL
#define CKR_ARGUMENTS_BAD                   0x00000007UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED    0x00000191UL
#define CKR_CRYPTOKI_NOT_INITIALIZED        0x00000190UL
#define CKR_DEVICE_ERROR                    0x00000030UL
#define CKR_DEVICE_MEMORY                   0x00000031UL
#define CKR_DEVICE_REMOVED                  0x00000032UL
#define CKR_FUNCTION_NOT_SUPPORTED          0x00000054UL
#define CKR_MECHANISM_INVALID               0x00000070UL
#define CKR_OBJECT_HANDLE_INVALID           0x00000082UL
#define CKR_OPERATION_ACTIVE                0x00000090UL
#define CKR_OPERATION_NOT_INITIALIZED       0x00000091UL
#define CKR_PIN_INCORRECT                   0x000000A0UL
#define CKR_PIN_INVALID                     0x000000A1UL
#define CKR_PIN_LEN_RANGE                   0x000000A2UL
#define CKR_PIN_EXPIRED                     0x000000A3UL
#define CKR_PIN_LOCKED                      0x000000A4UL
#define CKR_SESSION_CLOSED                  0x000000B0UL
#define CKR_SESSION_COUNT                   0x000000B1UL
#define CKR_SESSION_HANDLE_INVALID          0x000000B3UL
#define CKR_SESSION_READ_ONLY               0x000000B5UL
#define CKR_SIGNATURE_INVALID               0x000000C0UL
#define CKR_TOKEN_NOT_PRESENT               0x000000E0UL
#define CKR_TOKEN_NOT_RECOGNIZED            0x000000E1UL
#define CKR_TOKEN_WRITE_PROTECTED           0x000000E2UL
#define CKR_USER_ALREADY_LOGGED_IN          0x00000100UL
#define CKR_USER_NOT_LOGGED_IN              0x00000101UL
#define CKR_USER_PIN_NOT_INITIALIZED        0x00000102UL
#define CKR_USER_TYPE_INVALID               0x00000103UL
#define CKR_BUFFER_TOO_SMALL                0x00000150UL
#define CKR_VENDOR_DEFINED                  0x80000000UL

// ============================================================
// Flags
// ============================================================
#define CKF_TOKEN_PRESENT               0x00000001UL
#define CKF_REMOVABLE_DEVICE            0x00000002UL
#define CKF_HW_SLOT                     0x00000004UL
#define CKF_RNG                         0x00000001UL
#define CKF_WRITE_PROTECTED             0x00000002UL
#define CKF_LOGIN_REQUIRED              0x00000004UL
#define CKF_USER_PIN_INITIALIZED        0x00000008UL
#define CKF_TOKEN_INITIALIZED           0x00000400UL
#define CKF_USER_PIN_LOCKED             0x00040000UL
#define CKF_USER_PIN_FINAL_TRY          0x00020000UL
#define CKF_RW_SESSION                  0x00000002UL
#define CKF_SERIAL_SESSION              0x00000004UL
#define CKF_SIGN                        0x00000800UL
#define CKF_HW                          0x00000001UL

// ============================================================
// User types
// ============================================================
#define CKU_SO                          0UL
#define CKU_USER                        1UL
#define CKU_CONTEXT_SPECIFIC            2UL

// ============================================================
// Object classes
// ============================================================
#define CKO_CERTIFICATE                 0x00000001UL
#define CKO_PUBLIC_KEY                  0x00000002UL
#define CKO_PRIVATE_KEY                 0x00000003UL
#define CKO_SECRET_KEY                  0x00000004UL

// ============================================================
// Attribute types
// ============================================================
#define CKA_CLASS                       0x00000000UL
#define CKA_TOKEN                       0x00000001UL
#define CKA_PRIVATE                     0x00000002UL
#define CKA_LABEL                       0x00000003UL
#define CKA_VALUE                       0x00000011UL
#define CKA_CERTIFICATE_TYPE            0x00000080UL
#define CKA_ISSUER                      0x00000081UL
#define CKA_SERIAL_NUMBER               0x00000082UL
#define CKA_KEY_TYPE                    0x00000100UL
#define CKA_SUBJECT                     0x00000101UL
#define CKA_ID                          0x00000102UL
#define CKA_SENSITIVE                   0x00000103UL
#define CKA_SIGN                        0x00000108UL
#define CKA_MODULUS                     0x00000120UL
#define CKA_MODULUS_BITS                0x00000121UL
#define CKA_PUBLIC_EXPONENT             0x00000122UL
#define CKA_EC_PARAMS                   0x00000180UL
#define CKA_EC_POINT                    0x00000181UL

// ============================================================
// Mechanism types
// ============================================================
#define CKM_RSA_PKCS                    0x00000001UL
#define CKM_SHA1_RSA_PKCS               0x00000006UL
#define CKM_SHA256_RSA_PKCS             0x00000040UL
#define CKM_SHA384_RSA_PKCS             0x00000041UL
#define CKM_SHA512_RSA_PKCS             0x00000042UL
#define CKM_ECDSA                       0x00001041UL
#define CKM_ECDSA_SHA1                  0x00001042UL
#define CKM_ECDSA_SHA256                0x00001043UL

// ============================================================
// Structures - MUST match PKCS#11 standard exactly
// Use pack(1) to avoid padding issues
// ============================================================

#pragma pack(push, 1)

typedef struct CK_VERSION
{
	CK_BYTE major;
	CK_BYTE minor;
} CK_VERSION;
typedef CK_VERSION* CK_VERSION_PTR;

typedef struct CK_INFO
{
	CK_VERSION  cryptokiVersion;
	CK_BYTE     manufacturerID[32];
	CK_FLAGS    flags;
	CK_BYTE     libraryDescription[32];
	CK_VERSION  libraryVersion;
} CK_INFO;
typedef CK_INFO* CK_INFO_PTR;

typedef struct CK_SLOT_INFO
{
	CK_BYTE     slotDescription[64];
	CK_BYTE     manufacturerID[32];
	CK_FLAGS    flags;
	CK_VERSION  hardwareVersion;
	CK_VERSION  firmwareVersion;
} CK_SLOT_INFO;
typedef CK_SLOT_INFO* CK_SLOT_INFO_PTR;

typedef struct CK_TOKEN_INFO
{
	CK_BYTE     label[32];
	CK_BYTE     manufacturerID[32];
	CK_BYTE     model[16];
	CK_BYTE     serialNumber[16];
	CK_FLAGS    flags;
	CK_ULONG    ulMaxSessionCount;
	CK_ULONG    ulSessionCount;
	CK_ULONG    ulMaxRwSessionCount;
	CK_ULONG    ulRwSessionCount;
	CK_ULONG    ulMaxPinLen;
	CK_ULONG    ulMinPinLen;
	CK_ULONG    ulTotalPublicMemory;
	CK_ULONG    ulFreePublicMemory;
	CK_ULONG    ulTotalPrivateMemory;
	CK_ULONG    ulFreePrivateMemory;
	CK_VERSION  hardwareVersion;
	CK_VERSION  firmwareVersion;
	CK_BYTE     utcTime[16];
} CK_TOKEN_INFO;
typedef CK_TOKEN_INFO* CK_TOKEN_INFO_PTR;

typedef struct CK_SESSION_INFO
{
	CK_SLOT_ID  slotID;
	CK_STATE    state;
	CK_FLAGS    flags;
	CK_ULONG    ulDeviceError;
} CK_SESSION_INFO;
typedef CK_SESSION_INFO* CK_SESSION_INFO_PTR;

typedef struct CK_ATTRIBUTE
{
	CK_ATTRIBUTE_TYPE   type;
	CK_VOID_PTR         pValue;
	CK_ULONG            ulValueLen;
} CK_ATTRIBUTE;
typedef CK_ATTRIBUTE* CK_ATTRIBUTE_PTR;

typedef struct CK_MECHANISM
{
	CK_MECHANISM_TYPE   mechanism;
	CK_VOID_PTR         pParameter;
	CK_ULONG            ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM* CK_MECHANISM_PTR;

typedef struct CK_MECHANISM_INFO
{
	CK_ULONG    ulMinKeySize;
	CK_ULONG    ulMaxKeySize;
	CK_FLAGS    flags;
} CK_MECHANISM_INFO;
typedef CK_MECHANISM_INFO* CK_MECHANISM_INFO_PTR;

#pragma pack(pop)

// ============================================================
// Function pointer types
// ============================================================
typedef CK_RV (*CK_C_Initialize_t)(CK_VOID_PTR);
typedef CK_RV (*CK_C_Finalize_t)(CK_VOID_PTR);
typedef CK_RV (*CK_C_GetInfo_t)(CK_INFO_PTR);
typedef CK_RV (*CK_C_GetSlotList_t)(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
typedef CK_RV (*CK_C_GetSlotInfo_t)(CK_SLOT_ID, CK_SLOT_INFO_PTR);
typedef CK_RV (*CK_C_GetTokenInfo_t)(CK_SLOT_ID, CK_TOKEN_INFO_PTR);
typedef CK_RV (*CK_C_GetMechanismList_t)(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);
typedef CK_RV (*CK_C_GetMechanismInfo_t)(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR);
typedef CK_RV (*CK_C_OpenSession_t)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_VOID_PTR, CK_SESSION_HANDLE_PTR);
typedef CK_RV (*CK_C_CloseSession_t)(CK_SESSION_HANDLE);
typedef CK_RV (*CK_C_CloseAllSessions_t)(CK_SLOT_ID);
typedef CK_RV (*CK_C_GetSessionInfo_t)(CK_SESSION_HANDLE, CK_SESSION_INFO_PTR);
typedef CK_RV (*CK_C_Login_t)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (*CK_C_Logout_t)(CK_SESSION_HANDLE);
typedef CK_RV (*CK_C_FindObjectsInit_t)(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
typedef CK_RV (*CK_C_FindObjects_t)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR);
typedef CK_RV (*CK_C_FindObjectsFinal_t)(CK_SESSION_HANDLE);
typedef CK_RV (*CK_C_GetAttributeValue_t)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
typedef CK_RV (*CK_C_SignInit_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (*CK_C_Sign_t)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);

// Forward declarations
struct CK_FUNCTION_LIST;
typedef struct CK_FUNCTION_LIST*  CK_FUNCTION_LIST_PTR;
typedef struct CK_FUNCTION_LIST** CK_FUNCTION_LIST_PTR_PTR;
typedef CK_RV (*CK_C_GetFunctionList_t)(CK_FUNCTION_LIST_PTR_PTR);