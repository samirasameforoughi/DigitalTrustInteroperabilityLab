//{{NO_DEPENDENCIES}}
// Microsoft Visual C++ generated include file.
// Used by DigitalTrustLab.rc
//
#define IDR_MAINFRAME					128
#define IDM_ABOUTBOX					0x0010
#define IDD_ABOUTBOX					100
#define IDS_ABOUTBOX					101
#define IDD_DIGITALTRUSTLAB_DIALOG				102







// Menus
#define IDR_MENU_MAIN                   129

// Icons
#define IDI_APP_ICON                    130
#define IDI_ICON_PASS                   131
#define IDI_ICON_FAIL                   132
#define IDI_ICON_WARN                   133
#define IDI_ICON_INFO                   134

// Dialogs
#define IDD_ABOUTBOX                    100
#define IDD_CERT_DETAIL                 101

// String Table
#define IDS_APP_TITLE                   1000
#define IDS_APP_VERSION                 1001
#define IDS_READY                       1002
#define IDS_RUNNING                     1003
#define IDS_DONE                        1004

// Menu Items - File
#define ID_FILE_EXIT                    40001

// Menu Items - Diagnostics
#define ID_DIAG_SYSTEM                  40010
#define ID_DIAG_PROVIDERS               40011
#define ID_DIAG_CERTIFICATES            40012
#define ID_DIAG_PRIVATEKEYS             40013
#define ID_DIAG_RUNALL                  40014
// Menu
#define ID_DIAG_PKCS11                  40015
#define ID_PKCS11_SELECT_DLL            40016
#define ID_PKCS11_RUN_TESTS             40017

// Menu Items - Report
#define ID_REPORT_HTML                  40020
#define ID_REPORT_TEXT                  40021
#define ID_REPORT_CLEARLOG              40022

#define ID_SIGN_SELECTFILE              40023
#define ID_SIGN_DOSIGN                  40024
#define ID_SIGN_VERIFY                  40025
#define ID_SIGN_DOSIGN_PKCS11           40026

// Menu Items - View
#define ID_VIEW_CLEARLOG                40030
#define ID_VIEW_SYSINFO                 40031
#define ID_VIEW_PROVIDERS               40032
#define ID_VIEW_CERTIFICATES            40033
#define ID_VIEW_DASHBOARD               40034
#define ID_VIEW_SIGNATURE               40035
#define ID_HELP_ABOUT                   40040
#define ID_HELP_STANDARDS               40041

// Controls
#define IDC_TAB_MAIN                    2000
#define IDC_LIST_PROVIDERS              2001
#define IDC_LIST_CERTIFICATES           2002
#define IDC_EDIT_CONSOLE                2003
#define IDC_LIST_SYSINFO                2004
#define IDC_LIST_CERTDETAIL             2005
#define IDC_EDIT_CERTDETAIL             2006
#define IDC_STATIC_DASHBOARD            2007
#define IDC_BTN_RUNALL                  2008
#define IDC_BTN_REPORT                  2009
#define IDC_BTN_CLEAR                   2010
#define IDC_LIST_PRIVATEKEYS            2011
#define IDC_PROGRESS                    2012


// Splitter
#define IDC_SPLITTER                    2020


// PKCS#11 Tab controls
#define IDC_LIST_PKCS11_TESTS           2030
#define IDC_EDIT_PKCS11_DETAIL          2031
#define IDC_BTN_SELECT_DLL              2032
#define IDC_BTN_RUN_PKCS11              2033
#define IDC_STATIC_DLL_PATH             2034
#define IDC_STATIC_DLL_LABEL            2035

// Signature controls
#define IDC_BTN_SELECT_FILE             2040
#define IDC_BTN_SIGN                    2041
#define IDC_BTN_VERIFY                  2042
#define IDC_STATIC_FILE_PATH            2043
#define IDC_COMBO_HASH_ALG              2044
#define IDC_EDIT_SIGNATURE_RESULT       2045
#define IDC_LIST_CERTS_FOR_SIGN         2046
#define IDC_STATIC_SIG_STATUS           2047
#define IDC_COMBO_PROVIDER              2048
#define IDC_STATIC_PROVIDER_LABEL       2049
// Phase B: Signature History + Provider Capability
#define IDC_LIST_SIGN_HISTORY           2050
#define IDC_BTN_TEST_ALL_PROVIDERS      2051
#define IDC_STATIC_HISTORY_LABEL        2052


// Phase B: Menu
#define ID_DIAG_PROVIDER_CAPABILITY     40050

// Phase 3.5: PKCS#11 direct signing
#define IDC_BTN_SIGN_PKCS11             2060
#define IDC_STATIC_PKCS11_STATUS        2061




// Status Bar Pane IDs
#define ID_STATUS_PANE_STATUS  0xE700
#define ID_STATUS_PANE_RESULT  0xE701
#define ID_STATUS_PANE_USER    0xE702

// Toolbar buttons
#define ID_TOOLBAR_RUNALL               41000
#define ID_TOOLBAR_REPORT               41001
#define ID_TOOLBAR_CLEAR                41002

// Timer
#define IDT_STATUS_TIMER                1

// WM_USER messages
#define WM_LOG_MESSAGE                  (WM_USER + 100)
#define WM_DIAG_COMPLETE                (WM_USER + 101)
#define WM_DIAG_PROGRESS                (WM_USER + 102)
#define WM_PKCS11_COMPLETE   (WM_USER + 103)
#define WM_SIGN_COMPLETE   (WM_USER + 104)
// Phase B: Message
#define WM_CAPABILITY_COMPLETE          (WM_USER + 105)
#define WM_PKCS11_SIGN_COMPLETE         (WM_USER + 106)

// Tab indices
#define TAB_DASHBOARD                   0
#define TAB_SYSINFO                     1
#define TAB_PROVIDERS                   2
#define TAB_CERTIFICATES                3
#define TAB_CONSOLE                     4
// Tab index
#define TAB_PKCS11                      5
// Signature Tab
#define TAB_SIGNATURE                   6
//
//// Next default values for new objects
////
#ifdef APSTUDIO_INVOKED
#ifndef APSTUDIO_READONLY_SYMBOLS
//
#define _APS_NEXT_RESOURCE_VALUE	129
#define _APS_NEXT_CONTROL_VALUE		1000
#define _APS_NEXT_SYMED_VALUE		101
#define _APS_NEXT_COMMAND_VALUE		32771
#endif
#endif
// Resource.h
// Resource identifiers for Digital Trust Interoperability Lab

