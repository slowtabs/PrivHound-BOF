#pragma once

/*
 * Beacon resolves external functions from symbols named MODULE$Function.
 * Define those names before the Windows SDK headers declare the functions so
 * both MinGW and MSVC emit BOF-compatible Dynamic Function Resolution imports.
 */
#ifdef BOF
#define CloseHandle                 KERNEL32$CloseHandle
#define CreateFileA                 KERNEL32$CreateFileA
#define FindClose                   KERNEL32$FindClose
#define FindFirstFileA              KERNEL32$FindFirstFileA
#define FindNextFileA               KERNEL32$FindNextFileA
#define GetComputerNameA            KERNEL32$GetComputerNameA
#define GetCurrentProcess           KERNEL32$GetCurrentProcess
#define GetCurrentThread            KERNEL32$GetCurrentThread
#define GetEnvironmentVariableA     KERNEL32$GetEnvironmentVariableA
#define GetFileAttributesA          KERNEL32$GetFileAttributesA
#define GetFileSize                 KERNEL32$GetFileSize
#define GetProcessHeap              KERNEL32$GetProcessHeap
#define GetWindowsDirectoryA        KERNEL32$GetWindowsDirectoryA
#define ExpandEnvironmentStringsA   KERNEL32$ExpandEnvironmentStringsA
#define HeapAlloc                   KERNEL32$HeapAlloc
#define HeapFree                    KERNEL32$HeapFree
#define LocalFree                   KERNEL32$LocalFree
#define ReadFile                    KERNEL32$ReadFile

#define CoCreateInstance            OLE32$CoCreateInstance
#define CoInitializeEx              OLE32$CoInitializeEx
#define CoSetProxyBlanket           OLE32$CoSetProxyBlanket
#define CoUninitialize              OLE32$CoUninitialize

#define SysAllocString              OLEAUT32$SysAllocString
#define SysFreeString               OLEAUT32$SysFreeString
#define VariantClear                OLEAUT32$VariantClear

#define AccessCheck                 ADVAPI32$AccessCheck
#define CloseServiceHandle          ADVAPI32$CloseServiceHandle
#define ConvertSidToStringSidA      ADVAPI32$ConvertSidToStringSidA
#define CredEnumerateA              ADVAPI32$CredEnumerateA
#define CredFree                    ADVAPI32$CredFree
#define CryptAcquireContextA        ADVAPI32$CryptAcquireContextA
#define CryptDecrypt               ADVAPI32$CryptDecrypt
#define CryptDestroyKey            ADVAPI32$CryptDestroyKey
#define CryptImportKey             ADVAPI32$CryptImportKey
#define CryptReleaseContext        ADVAPI32$CryptReleaseContext
#define DuplicateToken              ADVAPI32$DuplicateToken
#define EnumServicesStatusExA       ADVAPI32$EnumServicesStatusExA
#define GetNamedSecurityInfoA       ADVAPI32$GetNamedSecurityInfoA
#define GetTokenInformation         ADVAPI32$GetTokenInformation
#define GetUserNameA                ADVAPI32$GetUserNameA
#define LookupAccountSidA           ADVAPI32$LookupAccountSidA
#define LookupPrivilegeNameA        ADVAPI32$LookupPrivilegeNameA
#define LogonUserA                  ADVAPI32$LogonUserA
#define CheckTokenMembership        ADVAPI32$CheckTokenMembership
#define CreateWellKnownSid          ADVAPI32$CreateWellKnownSid
#define ImpersonateLoggedOnUser     ADVAPI32$ImpersonateLoggedOnUser
#define RevertToSelf                ADVAPI32$RevertToSelf
#define OpenProcessToken            ADVAPI32$OpenProcessToken
#define OpenThreadToken             ADVAPI32$OpenThreadToken
#define OpenSCManagerA              ADVAPI32$OpenSCManagerA
#define OpenServiceA                ADVAPI32$OpenServiceA
#define QueryServiceConfigA         ADVAPI32$QueryServiceConfigA
#define QueryServiceConfig2A        ADVAPI32$QueryServiceConfig2A
#define QueryServiceObjectSecurity  ADVAPI32$QueryServiceObjectSecurity
#define QueryServiceStatusEx        ADVAPI32$QueryServiceStatusEx
#define RegCloseKey                 ADVAPI32$RegCloseKey
#define RegEnumKeyExA               ADVAPI32$RegEnumKeyExA
#define RegEnumValueA               ADVAPI32$RegEnumValueA
#define RegOpenKeyExA               ADVAPI32$RegOpenKeyExA
#define RegQueryValueExA            ADVAPI32$RegQueryValueExA

#define RtlGetVersion               NTDLL$RtlGetVersion

#define NetUserEnum                 NETAPI32$NetUserEnum
#define NetApiBufferFree            NETAPI32$NetApiBufferFree

#define CryptStringToBinaryA        CRYPT32$CryptStringToBinaryA

#define WlanCloseHandle             WLANAPI$WlanCloseHandle
#define WlanEnumInterfaces          WLANAPI$WlanEnumInterfaces
#define WlanFreeMemory              WLANAPI$WlanFreeMemory
#define WlanGetProfile              WLANAPI$WlanGetProfile
#define WlanGetProfileList          WLANAPI$WlanGetProfileList
#define WlanOpenHandle              WLANAPI$WlanOpenHandle
#endif

#include <windows.h>
