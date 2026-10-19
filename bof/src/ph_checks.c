#include "ph_checks.h"

#include <aclapi.h>
#include <wincred.h>
#include <winsvc.h>
#include <wincrypt.h>
#include <wbemidl.h>
#include <oleauto.h>
#include <lm.h>
#include <wlanapi.h>

#ifdef BOF
/* lm.h lacks dllimport; address its Beacon DFR import-pointer symbols explicitly. */
extern NET_API_STATUS (WINAPI *__imp_NETAPI32$NetUserEnum)(LPCWSTR, DWORD, DWORD, LPBYTE *, DWORD, LPDWORD, LPDWORD, LPDWORD);
extern NET_API_STATUS (WINAPI *__imp_NETAPI32$NetApiBufferFree)(LPVOID);
#undef NetUserEnum
#undef NetApiBufferFree
#define NetUserEnum __imp_NETAPI32$NetUserEnum
#define NetApiBufferFree __imp_NETAPI32$NetApiBufferFree

extern DWORD (WINAPI *__imp_WLANAPI$WlanOpenHandle)(DWORD, PVOID, PDWORD, PHANDLE);
extern DWORD (WINAPI *__imp_WLANAPI$WlanCloseHandle)(HANDLE, PVOID);
extern DWORD (WINAPI *__imp_WLANAPI$WlanEnumInterfaces)(HANDLE, PVOID, PWLAN_INTERFACE_INFO_LIST *);
extern DWORD (WINAPI *__imp_WLANAPI$WlanGetProfile)(HANDLE, const GUID *, LPCWSTR, PVOID, LPWSTR *, DWORD *, DWORD *);
extern DWORD (WINAPI *__imp_WLANAPI$WlanGetProfileList)(HANDLE, const GUID *, PVOID, PWLAN_PROFILE_INFO_LIST *);
extern VOID (WINAPI *__imp_WLANAPI$WlanFreeMemory)(PVOID);
#undef WlanOpenHandle
#undef WlanCloseHandle
#undef WlanEnumInterfaces
#undef WlanGetProfile
#undef WlanGetProfileList
#undef WlanFreeMemory
#define WlanOpenHandle __imp_WLANAPI$WlanOpenHandle
#define WlanCloseHandle __imp_WLANAPI$WlanCloseHandle
#define WlanEnumInterfaces __imp_WLANAPI$WlanEnumInterfaces
#define WlanGetProfile __imp_WLANAPI$WlanGetProfile
#define WlanGetProfileList __imp_WLANAPI$WlanGetProfileList
#define WlanFreeMemory __imp_WLANAPI$WlanFreeMemory
#endif

#ifdef BOF
/* Current Windows SDK sddl.h declarations omit DECLSPEC_IMPORT. */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID Sid, LPSTR *StringSid);
#else
#include <sddl.h>
#endif

DECLSPEC_IMPORT LONG WINAPI RtlGetVersion(OSVERSIONINFOW *VersionInformation);

static BOOL ph_get_process_token(HANDLE *token);
static void ph_wide_ascii(const wchar_t *value, char *out, int capacity);

static int ph_len(const char *s) {
    int n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static void ph_copy_local(char *dst, int cap, const char *src) {
    int i = 0;
    if (!dst || cap <= 0) return;
    if (!src) src = "";
    while (i + 1 < cap && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = 0;
}

static void ph_append_local(char *dst, int cap, const char *src) {
    int at = ph_len(dst);
    if (at < cap) ph_copy_local(dst + at, cap - at, src);
}

static void ph_uint_text(unsigned long value, char *out, int cap) {
    char digits[32];
    int n = 0;
    if (!out || cap <= 0) return;
    if (value == 0) { out[0] = '0'; out[1] = 0; return; }
    while (value && n < (int)sizeof(digits)) { digits[n++] = (char)('0' + (value % 10)); value /= 10; }
    int at = 0;
    while (n > 0 && at + 1 < cap) out[at++] = digits[--n];
    out[at] = 0;
}

static char ph_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

static BOOL ph_equal_ci(const char *a, const char *b) {
    int i = 0;
    if (!a || !b) return a == b;
    while (a[i] && b[i]) {
        if (ph_lower(a[i]) != ph_lower(b[i])) return FALSE;
        i++;
    }
    return a[i] == 0 && b[i] == 0;
}

static BOOL ph_starts_ci(const char *value, const char *prefix) {
    int i = 0;
    if (!value || !prefix) return FALSE;
    while (prefix[i]) {
        if (!value[i] || ph_lower(value[i]) != ph_lower(prefix[i])) return FALSE;
        i++;
    }
    return TRUE;
}

static BOOL ph_ends_ci(const char *value, const char *suffix) {
    int value_length = ph_len(value), suffix_length = ph_len(suffix);
    if (suffix_length > value_length) return FALSE;
    return ph_equal_ci(value + value_length - suffix_length, suffix);
}

static BOOL ph_has_space(const char *value) {
    int i = 0;
    if (!value) return FALSE;
    while (value[i]) {
        if (value[i] == ' ' || value[i] == '\t') return TRUE;
        i++;
    }
    return FALSE;
}

static void ph_trim_path(char *value) {
    int start = 0, end, length;
    if (!value) return;
    length = ph_len(value);
    while (start < length && (value[start] == ' ' || value[start] == '\t' || value[start] == '"')) start++;
    end = length;
    while (end > start && (value[end-1] == ' ' || value[end-1] == '\t' || value[end-1] == '"')) end--;
    if (start > 0) {
        int i;
        for (i = start; i < end; i++) value[i-start] = value[i];
        end -= start;
    }
    while (end > 3 && (value[end-1] == '\\' || value[end-1] == '/')) end--;
    value[end] = 0;
}

static void ph_parent_path(const char *path, char *out, int capacity) {
    int length, slash = -1;
    if (!out || capacity <= 0) return;
    out[0] = 0;
    if (!path) return;
    length = ph_len(path);
    for (int i = 0; i < length; i++) if (path[i] == '\\' || path[i] == '/') slash = i;
    if (slash < 0) return;
    if (slash == 2 && path[1] == ':') slash++;
    for (int i = 0; i < slash && i + 1 < capacity; i++) out[i] = path[i];
    if (slash < capacity) out[slash] = 0;
    else out[capacity-1] = 0;
}

static BOOL ph_reg_dword(HKEY root, const char *subkey, const char *name, DWORD *value) {
    HKEY key = NULL;
    DWORD type = 0, size = sizeof(DWORD), data = 0;
    LONG result;
    if (!value) return FALSE;
    result = RegOpenKeyExA(root, subkey, 0, KEY_QUERY_VALUE, &key);
    if (result != ERROR_SUCCESS) return FALSE;
    result = RegQueryValueExA(key, name, NULL, &type, (LPBYTE)&data, &size);
    RegCloseKey(key);
    if (result != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(DWORD)) return FALSE;
    *value = data;
    return TRUE;
}

static char *ph_environment_value(const char *name) {
    DWORD needed;
    char *value;
    needed = GetEnvironmentVariableA(name, NULL, 0);
    if (!needed) return NULL;
    value = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed + 1);
    if (!value) return NULL;
    if (!GetEnvironmentVariableA(name, value, needed)) {
        HeapFree(GetProcessHeap(), 0, value);
        return NULL;
    }
    return value;
}

static char *ph_reg_string(HKEY root, const char *subkey, const char *name) {
    HKEY key = NULL;
    DWORD type = 0, size = 0;
    char *value = NULL;
    if (RegOpenKeyExA(root, subkey, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return NULL;
    if (RegQueryValueExA(key, name, NULL, &type, NULL, &size) != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ) || !size) {
        RegCloseKey(key);
        return NULL;
    }
    value = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 2);
    if (!value || RegQueryValueExA(key, name, NULL, &type, (LPBYTE)value, &size) != ERROR_SUCCESS) {
        if (value) HeapFree(GetProcessHeap(), 0, value);
        RegCloseKey(key);
        return NULL;
    }
    RegCloseKey(key);
    return value;
}

static BOOL ph_reg_ulong(HKEY root, const char *subkey, const char *name, DWORD *value) {
    char *text;
    DWORD parsed = 0;
    if (ph_reg_dword(root, subkey, name, value)) return TRUE;
    text = ph_reg_string(root, subkey, name);
    if (!text || !text[0]) { if (text) HeapFree(GetProcessHeap(), 0, text); return FALSE; }
    for (int i = 0; text[i]; i++) {
        if (text[i] < '0' || text[i] > '9') { HeapFree(GetProcessHeap(), 0, text); return FALSE; }
        parsed = parsed * 10 + (DWORD)(text[i] - '0');
    }
    HeapFree(GetProcessHeap(), 0, text); *value = parsed; return TRUE;
}

static BOOL ph_path_list_contains(const char *list, const char *candidate) {
    int at = 0;
    char segment[2048];
    if (!list || !candidate) return FALSE;
    while (list[at]) {
        int n = 0;
        while (list[at] && list[at] != ';') {
            if (n + 1 < (int)sizeof(segment)) segment[n++] = list[at];
            at++;
        }
        if (list[at] == ';') at++;
        segment[n] = 0;
        ph_trim_path(segment);
        if (ph_equal_ci(segment, candidate)) return TRUE;
    }
    return FALSE;
}

static BOOL ph_token_has_admin_group(void) {
    HANDLE token = NULL;
    TOKEN_GROUPS *groups = NULL;
    DWORD needed = 0;
    BOOL found = FALSE;
    if (!ph_get_process_token(&token)) return FALSE;
    GetTokenInformation(token, TokenGroups, NULL, 0, &needed);
    if (needed) groups = (TOKEN_GROUPS *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (groups && GetTokenInformation(token, TokenGroups, groups, needed, &needed)) {
        for (DWORD i = 0; i < groups->GroupCount; i++) {
            LPSTR sid_text = NULL;
            if (ConvertSidToStringSidA(groups->Groups[i].Sid, &sid_text)) {
                if (ph_equal_ci(sid_text, "S-1-5-32-544")) found = TRUE;
                LocalFree((HLOCAL)sid_text);
            }
            if (found) break;
        }
    }
    if (groups) HeapFree(GetProcessHeap(), 0, groups);
    CloseHandle(token);
    return found;
}

static void ph_emit_empty_edge(PH_GRAPH *g, const char *start, const char *end, const char *kind) {
    ph_emit_edge(g, start, end, kind, "{}");
}

static BOOL ph_get_process_token(HANDLE *token) {
    if (!token) return FALSE;
    *token = NULL;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, token)) return TRUE;
    return OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token);
}

static BOOL ph_access_check(PSECURITY_DESCRIPTOR sd, DWORD desired, GENERIC_MAPPING mapping) {
    HANDLE token = NULL, impersonation = NULL;
    PRIVILEGE_SET privileges;
    DWORD privilege_length = sizeof(privileges);
    DWORD granted = 0;
    BOOL access = FALSE;
    BOOL result;
    /* AccessCheck requires an impersonation token, so this handle also needs TOKEN_DUPLICATE. */
    if (!sd) return FALSE;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token) &&
        !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &token)) return FALSE;
    result = DuplicateToken(token, SecurityImpersonation, &impersonation);
    if (result) {
        result = AccessCheck(sd, impersonation, desired, &mapping, &privileges, &privilege_length, &granted, &access);
        if (!result) access = FALSE;
    }
    if (impersonation) CloseHandle(impersonation);
    if (token) CloseHandle(token);
    return access;
}

static BOOL ph_can_open_service(SC_HANDLE scm, const char *name, DWORD desired) {
    SC_HANDLE service;
    if (!scm || !name || !name[0]) return FALSE;
    service = OpenServiceA(scm, name, desired);
    if (!service) return FALSE;
    CloseServiceHandle(service);
    return TRUE;
}

static BOOL ph_service_can_change(SC_HANDLE scm, const char *name) {
    /* Opening the service for a right asks the SCM to evaluate the caller's effective token. */
    return ph_can_open_service(scm, name, SERVICE_CHANGE_CONFIG) ||
           ph_can_open_service(scm, name, WRITE_DAC) ||
           ph_can_open_service(scm, name, WRITE_OWNER);
}

static BOOL ph_file_allows_open(const char *path, DWORD desired) {
    HANDLE file;
    if (!path || !path[0]) return FALSE;
    file = CreateFileA(path, desired, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    CloseHandle(file);
    return TRUE;
}

static BOOL ph_file_allows(const char *path, DWORD desired) {
    PSECURITY_DESCRIPTOR sd = NULL;
    GENERIC_MAPPING mapping;
    DWORD error;
    BOOL result;
    if (!path || !path[0]) return FALSE;
    error = GetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &sd);
    if (error == ERROR_SUCCESS && sd) {
        mapping.GenericRead = FILE_GENERIC_READ;
        mapping.GenericWrite = FILE_GENERIC_WRITE;
        mapping.GenericExecute = FILE_GENERIC_EXECUTE;
        mapping.GenericAll = FILE_ALL_ACCESS;
        result = ph_access_check(sd, desired, mapping);
        LocalFree(sd);
        if (result) return TRUE;
    }
    /* Some third-party BOF loaders do not preserve token duplication semantics reliably. */
    return ph_file_allows_open(path, desired);
}

static BOOL ph_file_is_writable(const char *path) {
    DWORD attributes;
    char parent[4096];
    if (!path || !path[0]) return FALSE;
    attributes = GetFileAttributesA(path);
    if (attributes == INVALID_FILE_ATTRIBUTES) return FALSE;
    /* Match Test-WritableAcl: any one of content/create, WRITE_DAC, or WRITE_OWNER qualifies. */
    if (ph_file_allows(path, FILE_WRITE_DATA) || ph_file_allows(path, WRITE_DAC) || ph_file_allows(path, WRITE_OWNER)) return TRUE;
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) return FALSE;
    ph_parent_path(path, parent, sizeof(parent));
    if (!parent[0] || !ph_file_allows(parent, FILE_ADD_FILE)) return FALSE;
    return ph_file_allows(path, DELETE) || ph_file_allows(parent, FILE_DELETE_CHILD);
}

static void ph_binary_path(const char *service_path, char *out, int capacity) {
    int i = 0;
    int end = 0;
    if (!out || capacity <= 0) return;
    out[0] = 0;
    if (!service_path) return;
    while (service_path[i] == ' ' || service_path[i] == '\t') i++;
    if (service_path[i] == '"') {
        i++;
        while (service_path[i] && service_path[i] != '"' && end + 1 < capacity) out[end++] = service_path[i++];
    } else {
        while (service_path[i] && end + 1 < capacity) {
            if ((service_path[i] == '.' && (service_path[i+1] == 'e' || service_path[i+1] == 'E') &&
                 (service_path[i+2] == 'x' || service_path[i+2] == 'X') &&
                 (service_path[i+3] == 'e' || service_path[i+3] == 'E'))) {
                out[end++] = service_path[i++]; out[end++] = service_path[i++]; out[end++] = service_path[i++]; out[end++] = service_path[i++];
                break;
            }
            if (service_path[i] == ' ' || service_path[i] == '\t') break;
            out[end++] = service_path[i++];
        }
    }
    out[end] = 0;
}

static BOOL ph_is_system_account(const char *account) {
    return ph_equal_ci(account, "LocalSystem") || ph_equal_ci(account, "SYSTEM") ||
           ph_equal_ci(account, "NT AUTHORITY\\SYSTEM") || ph_equal_ci(account, "NT AUTHORITY/SYSTEM");
}

static BOOL ph_is_privileged_service_account(const char *account) {
    return ph_is_system_account(account) || ph_equal_ci(account, "LocalService") ||
           ph_equal_ci(account, "NT AUTHORITY\\LOCAL SERVICE") || ph_equal_ci(account, "NetworkService") ||
           ph_equal_ci(account, "NT AUTHORITY\\NETWORK SERVICE");
}

static const char *ph_service_state(DWORD state) {
    switch (state) {
    case SERVICE_RUNNING: return "Running";
    case SERVICE_STOPPED: return "Stopped";
    case SERVICE_START_PENDING: return "StartPending";
    case SERVICE_STOP_PENDING: return "StopPending";
    case SERVICE_PAUSED: return "Paused";
    default: return "Unknown";
    }
}

static const char *ph_start_mode(DWORD start_type) {
    switch (start_type) {
    case SERVICE_AUTO_START: return "Auto";
    case SERVICE_BOOT_START: return "Boot";
    case SERVICE_SYSTEM_START: return "System";
    case SERVICE_DEMAND_START: return "Manual";
    case SERVICE_DISABLED: return "Disabled";
    default: return "Unknown";
    }
}

static void ph_emit_core_node(PH_GRAPH *g, const char *id, const char *kind, const char *name,
                              const char *p1k, const char *p1v, const char *p2k, const char *p2v,
                              BOOL p3b, const char *p3k) {
    char props[4096];
    PH_JSON p;
    ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
    ph_json_add_string(&p, "name", name);
    if (p1k) ph_json_add_string(&p, p1k, p1v);
    if (p2k) ph_json_add_string(&p, p2k, p2v);
    if (p3k) ph_json_add_bool(&p, p3k, p3b);
    ph_json_add_string(&p, "hostname", g->hostname);
    ph_json_end_object(&p);
    ph_emit_node(g, id, kind, props);
}

void ph_collect_core(PH_GRAPH *g) {
    HANDLE token = NULL;
    char account[256];
    char domain[256];
    DWORD account_size = sizeof(account);
    DWORD domain_size = sizeof(domain);
    SID_NAME_USE sid_type;
    char os_version[64];
    char os_major[16], os_minor[16], os_build[16];
    OSVERSIONINFOW os;
    char props[4096];
    PH_JSON p;
    if (!g) return;

    ph_zero(account, sizeof(account));
    ph_zero(domain, sizeof(domain));
    ph_zero(os_version, sizeof(os_version));
    ph_zero(&os, sizeof(os));

    DWORD host_size = sizeof(g->hostname);
    if (!GetComputerNameA(g->hostname, &host_size)) ph_copy_local(g->hostname, sizeof(g->hostname), "UNKNOWN");
    DWORD user_size = sizeof(g->username);
    if (!GetUserNameA(g->username, &user_size)) ph_copy_local(g->username, sizeof(g->username), "UNKNOWN");

    if (ph_get_process_token(&token)) {
        TOKEN_USER *tu = NULL;
        DWORD needed = 0;
        GetTokenInformation(token, TokenUser, NULL, 0, &needed);
        if (needed) tu = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
        if (tu && GetTokenInformation(token, TokenUser, tu, needed, &needed)) {
            LPSTR sid_text = NULL;
            if (ConvertSidToStringSidA(tu->User.Sid, &sid_text)) {
                ph_copy_local(g->sid, sizeof(g->sid), sid_text);
                LocalFree((HLOCAL)sid_text);
            }
            LookupAccountSidA(NULL, tu->User.Sid, account, &account_size, domain, &domain_size, &sid_type);
            if (domain[0]) ph_copy_local(g->domain, sizeof(g->domain), domain);
            if (account[0]) ph_copy_local(g->username, sizeof(g->username), account);
        }
        if (tu) HeapFree(GetProcessHeap(), 0, tu);

        struct { DWORD TokenIsElevated; } elevation;
        DWORD elevation_size = sizeof(elevation);
        /* TokenElevation is information class 20; older MinGW headers omit its declaration. */
        if (GetTokenInformation(token, (TOKEN_INFORMATION_CLASS)20, &elevation, sizeof(elevation), &elevation_size)) {
            g->is_admin = elevation.TokenIsElevated ? TRUE : FALSE;
        }
        CloseHandle(token);
    }

    if (g->domain[0]) {
        ph_copy_local(g->identity, sizeof(g->identity), g->domain);
        int at = ph_len(g->identity);
        if (at + 1 < (int)sizeof(g->identity)) g->identity[at++] = '\\';
        ph_copy_local(g->identity + at, sizeof(g->identity) - at, g->username);
    } else {
        ph_copy_local(g->identity, sizeof(g->identity), g->username);
    }

    ph_id(g, "user", g->identity, g->current_user_id);
    ph_id(g, "target", "SYSTEM", g->system_id);
    ph_id(g, "target", "LocalAdmin", g->admin_id);
    ph_id(g, "computer", g->hostname, g->computer_id);

    os.dwOSVersionInfoSize = sizeof(os);
    if (RtlGetVersion(&os) >= 0) {
        ph_uint_text(os.dwMajorVersion, os_major, sizeof(os_major));
        ph_uint_text(os.dwMinorVersion, os_minor, sizeof(os_minor));
        ph_uint_text(os.dwBuildNumber, os_build, sizeof(os_build));
        ph_copy_local(os_version, sizeof(os_version), os_major);
        ph_append_local(os_version, sizeof(os_version), ".");
        ph_append_local(os_version, sizeof(os_version), os_minor);
        ph_append_local(os_version, sizeof(os_version), ".");
        ph_append_local(os_version, sizeof(os_version), os_build);
    } else ph_copy_local(os_version, sizeof(os_version), "Unknown");

    ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
    ph_json_add_string(&p, "name", g->identity); ph_json_add_string(&p, "username", g->username);
    ph_json_add_string(&p, "domain", g->domain); ph_json_add_string(&p, "sid", g->sid);
    ph_json_add_string(&p, "hostname", g->hostname); ph_json_add_bool(&p, "is_admin", g->is_admin); ph_json_end_object(&p);
    ph_emit_node(g, g->current_user_id, "[\"PHUser\"]", props);

    ph_emit_core_node(g, g->system_id, "[\"PHPrivTarget\"]", "NT AUTHORITY\\SYSTEM", "account", "NT AUTHORITY\\SYSTEM", NULL, NULL, FALSE, NULL);
    ph_emit_core_node(g, g->admin_id, "[\"PHPrivTarget\"]", "LOCAL ADMINISTRATOR", "account", "BUILTIN\\Administrators", NULL, NULL, FALSE, NULL);

    ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
    ph_json_add_string(&p, "name", g->hostname); ph_json_add_string(&p, "hostname", g->hostname);
    ph_json_add_string(&p, "os", "Windows"); ph_json_add_string(&p, "os_version", os_version);
    ph_json_add_string(&p, "collector", "PrivHound BOF"); ph_json_add_string(&p, "collector_version", "1.0.0");
#if defined(_WIN64)
    ph_json_add_string(&p, "arch", "AMD64");
#else
    ph_json_add_string(&p, "arch", "x86");
#endif
    ph_json_end_object(&p); ph_emit_node(g, g->computer_id, "[\"PHEndpoint\"]", props);

    ph_emit_empty_edge(g, g->computer_id, g->system_id, "PHHosts");
    ph_emit_empty_edge(g, g->computer_id, g->admin_id, "PHHosts");
    ph_emit_empty_edge(g, g->current_user_id, g->computer_id, "PHHasSessionOn");
}

static BOOL ph_is_dangerous(const char *name) {
    static const char *names[] = {
        "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeBackupPrivilege", "SeRestorePrivilege",
        "SeDebugPrivilege", "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege", "SeCreateTokenPrivilege",
        "SeTcbPrivilege", "SeManageVolumePrivilege"
    };
    for (int i=0; i<(int)(sizeof(names)/sizeof(names[0])); i++) if (ph_equal_ci(name, names[i])) return TRUE;
    return FALSE;
}

static const char *ph_priv_technique(const char *name) {
    if (ph_equal_ci(name, "SeImpersonatePrivilege") || ph_equal_ci(name, "SeAssignPrimaryTokenPrivilege")) return "Token impersonation via named pipe or COM";
    if (ph_equal_ci(name, "SeBackupPrivilege")) return "Read protected registry hives";
    if (ph_equal_ci(name, "SeRestorePrivilege")) return "Write protected files";
    if (ph_equal_ci(name, "SeDebugPrivilege")) return "Process injection into a privileged process";
    if (ph_equal_ci(name, "SeTakeOwnershipPrivilege")) return "Take ownership of protected objects";
    if (ph_equal_ci(name, "SeLoadDriverPrivilege")) return "Load a vulnerable kernel driver";
    if (ph_equal_ci(name, "SeCreateTokenPrivilege")) return "Create arbitrary tokens";
    if (ph_equal_ci(name, "SeTcbPrivilege")) return "Act as part of the operating system";
    if (ph_equal_ci(name, "SeManageVolumePrivilege")) return "Write protected files through volume management";
    return "Privilege abuse requires verification";
}

void ph_collect_token_privileges(PH_GRAPH *g) {
    HANDLE token = NULL;
    TOKEN_PRIVILEGES *privileges = NULL;
    DWORD needed = 0;
    if (!g) return;
    /* Match the PowerShell collector: privilege-escalation checks require a non-elevated context. */
    if (g->is_admin) return;
    if (!ph_get_process_token(&token)) { ph_emit_error(g, "TokenPrivileges", "OpenProcessToken failed"); return; }
    GetTokenInformation(token, TokenPrivileges, NULL, 0, &needed);
    if (!needed) { CloseHandle(token); ph_emit_error(g, "TokenPrivileges", "Token privilege query returned no data"); return; }
    privileges = (TOKEN_PRIVILEGES *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!privileges || !GetTokenInformation(token, TokenPrivileges, privileges, needed, &needed)) {
        if (privileges) HeapFree(GetProcessHeap(), 0, privileges);
        CloseHandle(token); ph_emit_error(g, "TokenPrivileges", "GetTokenInformation failed"); return;
    }
    for (DWORD i=0; i<privileges->PrivilegeCount; i++) {
        char name[128]; DWORD name_size = sizeof(name); LUID luid = privileges->Privileges[i].Luid;
        if (!LookupPrivilegeNameA(NULL, &luid, name, &name_size) || !ph_is_dangerous(name)) continue;
        char nid[33]; ph_id(g, "priv", name, nid);
        char props[2048]; PH_JSON p; ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
        ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "privilege", name);
        ph_json_add_bool(&p, "enabled", (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0);
        ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
        ph_emit_node(g, nid, "[\"PHTokenPrivilege\"]", props);
        ph_emit_edge(g, g->current_user_id, nid, "PHHasPrivilege", "{\"mitre\":\"T1134.001\"}");
        char edge_props[2048]; PH_JSON ep; ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep);
        ph_json_add_string(&ep, "technique", ph_priv_technique(name)); ph_json_add_string(&ep, "mitre", "T1134.001"); ph_json_end_object(&ep);
        ph_emit_edge(g, nid, g->system_id, "PHCanEscalateTo", edge_props);
        ph_emit_finding(g, "Priv", (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "HIGH" : "MEDIUM", name, ph_priv_technique(name));
    }
    HeapFree(GetProcessHeap(), 0, privileges);
    CloseHandle(token);
}

void ph_collect_services(PH_GRAPH *g) {
    SC_HANDLE scm = NULL;
    HKEY services_key = NULL;
    DWORD index = 0;
    if (!g) return;
    /* Match the PowerShell collector: service escalation checks require a non-elevated context. */
    if (g->is_admin) return;
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { ph_emit_error(g, "Services", "OpenSCManager failed"); return; }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0,
                      KEY_ENUMERATE_SUB_KEYS, &services_key) != ERROR_SUCCESS) {
        CloseServiceHandle(scm); ph_emit_error(g, "Services", "Could not enumerate the Services registry key"); return;
    }
    for (;;) {
        char service_name[512];
        DWORD service_name_length = sizeof(service_name);
        LONG enum_result = RegEnumKeyExA(services_key, index++, service_name, &service_name_length,
                                         NULL, NULL, NULL, NULL);
        SC_HANDLE service;
        if (enum_result == ERROR_NO_MORE_ITEMS) break;
        if (enum_result != ERROR_SUCCESS) continue;
        service = OpenServiceA(scm, service_name, SERVICE_QUERY_CONFIG);
        if (!service) continue;
        DWORD config_size = 0; QueryServiceConfigA(service, NULL, 0, &config_size);
        if (!config_size) { CloseServiceHandle(service); continue; }
        QUERY_SERVICE_CONFIGA *config = (QUERY_SERVICE_CONFIGA *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, config_size);
        if (!config || !QueryServiceConfigA(service, config, config_size, &config_size)) {
            if (config) HeapFree(GetProcessHeap(), 0, config);
            CloseServiceHandle(service);
            continue;
        }
        if (!(config->dwServiceType & SERVICE_WIN32)) {
            HeapFree(GetProcessHeap(), 0, config); CloseServiceHandle(service); continue;
        }
        char binary[1024]; ph_binary_path(config->lpBinaryPathName, binary, sizeof(binary));
        BOOL can_modify = ph_service_can_change(scm, service_name);
        BOOL bin_writable = ph_file_is_writable(binary);
        if (can_modify || bin_writable) {
            SERVICE_STATUS_PROCESS status;
            DWORD status_size = 0;
            SC_HANDLE status_service;
            ph_zero(&status, sizeof(status));
            status_service = OpenServiceA(scm, service_name, SERVICE_QUERY_STATUS);
            if (status_service) {
                QueryServiceStatusEx(status_service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status,
                                     sizeof(status), &status_size);
                CloseServiceHandle(status_service);
            }
            char nid[33]; ph_id(g, "service", service_name, nid);
            char props[4096]; PH_JSON p; ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
            char display[512]; ph_copy_local(display, sizeof(display), config->lpDisplayName ? config->lpDisplayName : service_name);
            char name[768]; ph_copy_local(name, sizeof(name), "SVC:"); ph_append_local(name, sizeof(name), service_name); ph_append_local(name, sizeof(name), "@"); ph_append_local(name, sizeof(name), g->hostname);
            ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "service_name", service_name);
            ph_json_add_string(&p, "display_name", display); ph_json_add_string(&p, "start_name", config->lpServiceStartName);
            ph_json_add_string(&p, "binary_path", config->lpBinaryPathName); ph_json_add_string(&p, "start_mode", ph_start_mode(config->dwStartType));
            ph_json_add_string(&p, "state", status.dwCurrentState ? ph_service_state(status.dwCurrentState) : "Unknown");
            ph_json_add_string(&p, "hostname", g->hostname); ph_json_add_bool(&p, "can_modify", can_modify); ph_json_add_bool(&p, "bin_writable", bin_writable); ph_json_end_object(&p);
            ph_emit_node(g, nid, "[\"PHService\"]", props);
            if (ph_is_privileged_service_account(config->lpServiceStartName)) {
                char ep[2048]; PH_JSON e; ph_json_init(&e, ep, sizeof(ep)); ph_json_start_object(&e);
                ph_json_add_string(&e, "run_account", config->lpServiceStartName); ph_json_end_object(&e);
                ph_emit_edge(g, nid, g->system_id, "PHRunsAs", ep);
            }
            if (can_modify) {
                ph_emit_edge(g, g->current_user_id, nid, "PHCanModifyService", "{\"technique\":\"ChangeServiceConfig API\",\"mitre\":\"T1574.011\"}");
                char finding[2048]; ph_copy_local(finding, sizeof(finding), "Modifiable service '"); ph_append_local(finding, sizeof(finding), service_name); ph_append_local(finding, sizeof(finding), "' runs as "); ph_append_local(finding, sizeof(finding), config->lpServiceStartName);
                ph_emit_finding(g, "SvcPerms", "HIGH", finding, "Verify the service configuration in the lab before making changes");
            }
            if (bin_writable) {
                ph_emit_edge(g, g->current_user_id, nid, "PHCanWriteBinary", "{\"technique\":\"Replace service binary\",\"mitre\":\"T1574.010\"}");
                char finding[2048]; ph_copy_local(finding, sizeof(finding), "Writable service binary for '"); ph_append_local(finding, sizeof(finding), service_name); ph_append_local(finding, sizeof(finding), "': "); ph_append_local(finding, sizeof(finding), binary);
                ph_emit_finding(g, "SvcBin", "HIGH", finding, "Verify file permissions in the lab before making changes");
            }
        }
        HeapFree(GetProcessHeap(), 0, config);
        CloseServiceHandle(service);
    }
    RegCloseKey(services_key);
    CloseServiceHandle(scm);
}

static BOOL ph_unquoted_hijack_path(const char *service_path, char *hijack, int capacity) {
    char expanded[4096];
    char build[4096];
    char parent[4096];
    char windows[512];
    char system32[768];
    const char *path = service_path;
    int at = 0, build_length = 0;
    DWORD expanded_length;
    if (!hijack || capacity <= 0) return FALSE;
    hijack[0] = 0;
    if (!service_path) return FALSE;
    while (*path == ' ' || *path == '\t') path++;
    if (!*path || *path == '"' || !ph_has_space(path)) return FALSE;

    expanded_length = ExpandEnvironmentStringsA(path, expanded, sizeof(expanded));
    if (expanded_length && expanded_length <= sizeof(expanded)) path = expanded;

    windows[0] = 0;
    if (GetWindowsDirectoryA(windows, sizeof(windows))) {
        ph_copy_local(system32, sizeof(system32), windows);
        ph_append_local(system32, sizeof(system32), "\\System32\\");
        if (ph_starts_ci(path, system32)) return FALSE;
    }

    build[0] = 0;
    while (path[at]) {
        int token_start, token_end;
        while (path[at] == ' ' || path[at] == '\t') at++;
        if (!path[at]) break;
        token_start = at;
        while (path[at] && path[at] != ' ' && path[at] != '\t') at++;
        token_end = at;
        if (build_length && build_length + 1 < (int)sizeof(build)) build[build_length++] = ' ';
        for (int i = token_start; i < token_end && build_length + 1 < (int)sizeof(build); i++) build[build_length++] = path[i];
        build[build_length] = 0;
        if (ph_ends_ci(build, ".exe")) break;
        ph_parent_path(build, parent, sizeof(parent));
        if (parent[0] && ph_file_is_writable(parent)) {
            ph_copy_local(hijack, capacity, build);
            ph_append_local(hijack, capacity, ".exe");
            return TRUE;
        }
    }
    return FALSE;
}

void ph_collect_unquoted_service_paths(PH_GRAPH *g) {
    SC_HANDLE scm = NULL;
    HKEY services_key = NULL;
    DWORD index = 0;
    if (!g || g->is_admin) return;
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { ph_emit_error(g, "Unquoted", "OpenSCManager failed"); return; }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0,
                      KEY_ENUMERATE_SUB_KEYS, &services_key) != ERROR_SUCCESS) {
        CloseServiceHandle(scm); ph_emit_error(g, "Unquoted", "Could not enumerate the Services registry key"); return;
    }
    for (;;) {
        char service_name[512];
        DWORD service_name_length = sizeof(service_name);
        LONG enum_result = RegEnumKeyExA(services_key, index++, service_name, &service_name_length,
                                         NULL, NULL, NULL, NULL);
        SC_HANDLE service;
        DWORD config_size = 0;
        QUERY_SERVICE_CONFIGA *config = NULL;
        char hijack[4096];
        if (enum_result == ERROR_NO_MORE_ITEMS) break;
        if (enum_result != ERROR_SUCCESS) continue;
        service = OpenServiceA(scm, service_name, SERVICE_QUERY_CONFIG);
        if (!service) continue;
        QueryServiceConfigA(service, NULL, 0, &config_size);
        if (config_size) config = (QUERY_SERVICE_CONFIGA *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, config_size);
        if (!config || !QueryServiceConfigA(service, config, config_size, &config_size)) {
            if (config) HeapFree(GetProcessHeap(), 0, config);
            CloseServiceHandle(service);
            continue;
        }
        if (!(config->dwServiceType & SERVICE_WIN32)) {
            HeapFree(GetProcessHeap(), 0, config); CloseServiceHandle(service); continue;
        }
        if (ph_unquoted_hijack_path(config->lpBinaryPathName, hijack, sizeof(hijack))) {
            char nid[33], props[8192], edge_props[4096], finding[4096], name[1024];
            PH_JSON p, ep;
            ph_id(g, "unquoted", service_name, nid);
            ph_copy_local(name, sizeof(name), "UNQUOTED:");
            ph_append_local(name, sizeof(name), service_name);
            ph_append_local(name, sizeof(name), "@");
            ph_append_local(name, sizeof(name), g->hostname);
            ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
            ph_json_add_string(&p, "name", name);
            ph_json_add_string(&p, "service_name", service_name);
            ph_json_add_string(&p, "original_path", config->lpBinaryPathName);
            ph_json_add_string(&p, "hijack_path", hijack);
            ph_json_add_string(&p, "start_name", config->lpServiceStartName);
            ph_json_add_string(&p, "hostname", g->hostname);
            ph_json_end_object(&p);
            ph_emit_node(g, nid, "[\"PHUnquotedPath\"]", props);
            ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep);
            ph_json_add_string(&ep, "hijack_path", hijack);
            ph_json_add_string(&ep, "mitre", "T1574.009");
            ph_json_end_object(&ep);
            ph_emit_edge(g, g->current_user_id, nid, "PHCanHijackPath", edge_props);
            if (ph_is_system_account(config->lpServiceStartName)) {
                ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep);
                ph_json_add_string(&ep, "run_account", config->lpServiceStartName);
                ph_json_end_object(&ep);
                ph_emit_edge(g, nid, g->system_id, "PHRunsAs", edge_props);
            }
            ph_copy_local(finding, sizeof(finding), "Unquoted '");
            ph_append_local(finding, sizeof(finding), service_name);
            ph_append_local(finding, sizeof(finding), "': ");
            ph_append_local(finding, sizeof(finding), config->lpBinaryPathName);
            ph_emit_finding(g, "Unquoted", "HIGH", finding, "Verify the writable intermediate path before placing a test file");
        }
        HeapFree(GetProcessHeap(), 0, config);
        CloseServiceHandle(service);
    }
    RegCloseKey(services_key);
    CloseServiceHandle(scm);
}

void ph_collect_writable_path(PH_GRAPH *g) {
    char *process_path = NULL, *machine_raw = NULL, *machine_path = NULL, *seen = NULL;
    char windows[512];
    int at = 0, seen_length = 0;
    if (!g || g->is_admin) return;
    process_path = ph_environment_value("PATH");
    if (!process_path) { ph_emit_error(g, "DLLHijack", "PATH is unavailable"); return; }
    machine_raw = ph_reg_string(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "Path");
    if (machine_raw) {
        DWORD machine_needed = ExpandEnvironmentStringsA(machine_raw, NULL, 0);
        if (machine_needed) {
            machine_path = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, machine_needed + 1);
            if (machine_path && !ExpandEnvironmentStringsA(machine_raw, machine_path, machine_needed)) {
                HeapFree(GetProcessHeap(), 0, machine_path); machine_path = NULL;
            }
        }
    }
    seen = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ph_len(process_path) + 2);
    windows[0] = 0;
    GetWindowsDirectoryA(windows, sizeof(windows));
    ph_trim_path(windows);
    while (process_path[at]) {
        char raw[2048], expanded[4096], nid[33], props[8192], edge_props[1024], name[4608], finding[4608];
        PH_JSON p, ep;
        int n = 0;
        DWORD expanded_length;
        while (process_path[at] && process_path[at] != ';') {
            if (n + 1 < (int)sizeof(raw)) raw[n++] = process_path[at];
            at++;
        }
        if (process_path[at] == ';') at++;
        raw[n] = 0;
        ph_trim_path(raw);
        if (!raw[0]) continue;
        expanded_length = ExpandEnvironmentStringsA(raw, expanded, sizeof(expanded));
        if (!expanded_length || expanded_length > sizeof(expanded)) ph_copy_local(expanded, sizeof(expanded), raw);
        ph_trim_path(expanded);
        if (!expanded[0] || ph_equal_ci(expanded, windows) ||
            (ph_starts_ci(expanded, windows) && expanded[ph_len(windows)] == '\\')) continue;
        if (seen && ph_path_list_contains(seen, expanded)) continue;
        if (seen && seen_length + ph_len(expanded) + 2 < ph_len(process_path) + 2) {
            ph_copy_local(seen + seen_length, ph_len(process_path) + 2 - seen_length, expanded);
            seen_length += ph_len(expanded);
            seen[seen_length++] = ';'; seen[seen_length] = 0;
        }
        if (!ph_file_is_writable(expanded)) continue;
        const char *scope = (machine_path && ph_path_list_contains(machine_path, expanded)) ? "machine" : "user/process";
        ph_id(g, "pathdir", expanded, nid);
        ph_copy_local(name, sizeof(name), "PATH:"); ph_append_local(name, sizeof(name), expanded);
        ph_append_local(name, sizeof(name), "@"); ph_append_local(name, sizeof(name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
        ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "directory", expanded);
        ph_json_add_string(&p, "scope", scope); ph_json_add_string(&p, "hostname", g->hostname);
        ph_json_end_object(&p);
        ph_emit_node(g, nid, "[\"PHWritablePath\"]", props);
        ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep);
        ph_json_add_string(&ep, "scope", scope); ph_json_end_object(&ep);
        ph_emit_edge(g, g->current_user_id, nid, "PHCanWriteTo", edge_props);
        ph_copy_local(finding, sizeof(finding), "Writable "); ph_append_local(finding, sizeof(finding), scope);
        ph_append_local(finding, sizeof(finding), " collector PATH: "); ph_append_local(finding, sizeof(finding), expanded);
        ph_append_local(finding, sizeof(finding), " (privileged DLL loading unverified)");
        ph_emit_finding(g, "DLLHijack", "MEDIUM", finding, "Identify a privileged process that loads from this directory");
    }
    if (seen) HeapFree(GetProcessHeap(), 0, seen);
    if (machine_path) HeapFree(GetProcessHeap(), 0, machine_path);
    if (machine_raw) HeapFree(GetProcessHeap(), 0, machine_raw);
    HeapFree(GetProcessHeap(), 0, process_path);
}

void ph_collect_always_install_elevated(PH_GRAPH *g) {
    DWORD machine = 0, user = 0;
    const char *key = "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer";
    if (!g) return;
    if (ph_reg_dword(HKEY_LOCAL_MACHINE, key, "AlwaysInstallElevated", &machine) && machine == 1 &&
        ph_reg_dword(HKEY_CURRENT_USER, key, "AlwaysInstallElevated", &user) && user == 1) {
        char nid[33], props[2048], name[1024];
        PH_JSON p;
        ph_id(g, "regkey", "AIE", nid);
        ph_copy_local(name, sizeof(name), "ALWAYSINSTALLELEVATED@"); ph_append_local(name, sizeof(name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
        ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
        ph_emit_node(g, nid, "[\"PHRegistryMisconfig\"]", props);
        ph_emit_edge(g, g->current_user_id, nid, "PHCanExploit", "{\"mitre\":\"T1548.002\"}");
        ph_emit_empty_edge(g, nid, g->system_id, "PHEscalatesTo");
        ph_emit_finding(g, "AIE", "CRITICAL", "AlwaysInstallElevated enabled in HKLM and HKCU", "Install an authorized test MSI in the isolated lab to validate the policy");
    }
}

void ph_collect_uac(PH_GRAPH *g) {
    const char *key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    DWORD enable_lua = 0, consent = 0, local_filter = 0;
    BOOL has_lua, has_consent, has_filter, in_admin_group;
    if (!g) return;
    has_lua = ph_reg_dword(HKEY_LOCAL_MACHINE, key, "EnableLUA", &enable_lua);
    has_consent = ph_reg_dword(HKEY_LOCAL_MACHINE, key, "ConsentPromptBehaviorAdmin", &consent);
    has_filter = ph_reg_dword(HKEY_LOCAL_MACHINE, key, "LocalAccountTokenFilterPolicy", &local_filter);
    in_admin_group = ph_token_has_admin_group();
    if (has_lua && enable_lua == 0) {
        char nid[33], props[2048], name[1024]; PH_JSON p;
        ph_id(g, "uac", "LUA_disabled", nid);
        ph_copy_local(name, sizeof(name), "UAC:DISABLED@"); ph_append_local(name, sizeof(name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
        ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "hostname", g->hostname);
        ph_json_add_int(&p, "enableLUA", enable_lua); if (has_consent) ph_json_add_int(&p, "consentBehavior", consent);
        ph_json_end_object(&p); ph_emit_node(g, nid, "[\"PHUACBypass\"]", props);
        ph_emit_edge(g, g->current_user_id, nid, "PHCanBypassUAC", "{\"mitre\":\"T1548.002\"}");
        ph_emit_empty_edge(g, nid, g->admin_id, "PHEscalatesTo");
        ph_emit_finding(g, "UAC", "HIGH", "UAC is disabled (EnableLUA=0)", "All processes run elevated for administrator accounts");
    } else if (has_consent && consent == 0 && in_admin_group) {
        char nid[33], props[2048], name[1024]; PH_JSON p;
        ph_id(g, "uac", "NoPrompt", nid);
        ph_copy_local(name, sizeof(name), "UAC:NOPROMPT@"); ph_append_local(name, sizeof(name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
        ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "hostname", g->hostname);
        if (has_lua) ph_json_add_int(&p, "enableLUA", enable_lua); ph_json_add_int(&p, "consentBehavior", consent);
        ph_json_end_object(&p); ph_emit_node(g, nid, "[\"PHUACBypass\"]", props);
        ph_emit_edge(g, g->current_user_id, nid, "PHCanBypassUAC", "{\"mitre\":\"T1548.002\"}");
        ph_emit_empty_edge(g, nid, g->admin_id, "PHEscalatesTo");
        ph_emit_finding(g, "UAC", "HIGH", "UAC is configured to never prompt administrators", "Validate elevation behavior in the isolated lab");
    } else if (in_admin_group && !g->is_admin) {
        ph_emit_finding(g, "UAC", "MEDIUM", "Administrator is running with a filtered token (normal UAC behavior; bypass unverified)", "Verify UAC policy before considering an elevation technique");
    }
    if (has_filter && local_filter == 1) {
        ph_emit_finding(g, "UAC", "MEDIUM", "LocalAccountTokenFilterPolicy=1 (remote administration via local accounts)", "Review whether remote local-account administration is required");
    }
}

static void ph_trim_text(char *value) {
    int start = 0, end, length;
    if (!value) return;
    length = ph_len(value);
    while (start < length && (value[start] == ' ' || value[start] == '\t' || value[start] == '\r' || value[start] == '\n')) start++;
    end = length;
    while (end > start && (value[end-1] == ' ' || value[end-1] == '\t' || value[end-1] == '\r' || value[end-1] == '\n')) end--;
    if (start > 0) {
        int i;
        for (i = start; i < end; i++) value[i-start] = value[i];
        end -= start;
    }
    value[end] = 0;
}

static const char *ph_find_ci(const char *value, const char *needle) {
    int needle_length;
    if (!value || !needle || !needle[0]) return value;
    needle_length = ph_len(needle);
    for (int at = 0; value[at]; at++) {
        int i = 0;
        while (i < needle_length && value[at+i] && ph_lower(value[at+i]) == ph_lower(needle[i])) i++;
        if (i == needle_length) return value + at;
    }
    return NULL;
}

static void ph_xml_decode(const char *value, char *out, int capacity) {
    int at = 0, written = 0;
    if (!out || capacity <= 0) return;
    if (!value) value = "";
    while (value[at] && written + 1 < capacity) {
        if (ph_starts_ci(value + at, "&quot;")) { out[written++] = '"'; at += 6; }
        else if (ph_starts_ci(value + at, "&apos;")) { out[written++] = '\''; at += 6; }
        else if (ph_starts_ci(value + at, "&amp;")) { out[written++] = '&'; at += 5; }
        else if (ph_starts_ci(value + at, "&lt;")) { out[written++] = '<'; at += 4; }
        else if (ph_starts_ci(value + at, "&gt;")) { out[written++] = '>'; at += 4; }
        else out[written++] = value[at++];
    }
    out[written] = 0;
}

static BOOL ph_xml_value(const char *xml, const char *tag, char *out, int capacity) {
    char open[128], close[128], encoded[4096];
    const char *start, *end;
    int length;
    if (!xml || !tag || !out || capacity <= 0) return FALSE;
    open[0] = 0; close[0] = 0;
    ph_append_local(open, sizeof(open), "<"); ph_append_local(open, sizeof(open), tag); ph_append_local(open, sizeof(open), ">");
    ph_append_local(close, sizeof(close), "</"); ph_append_local(close, sizeof(close), tag); ph_append_local(close, sizeof(close), ">");
    start = ph_find_ci(xml, open);
    if (!start) return FALSE;
    start += ph_len(open);
    end = ph_find_ci(start, close);
    if (!end) return FALSE;
    length = (int)(end - start);
    if (length >= (int)sizeof(encoded)) length = sizeof(encoded) - 1;
    {
        volatile char *encoded_write = encoded;
        for (int i = 0; i < length; i++) encoded_write[i] = start[i];
    }
    encoded[length] = 0;
    ph_xml_decode(encoded, out, capacity);
    ph_trim_text(out);
    return out[0] != 0;
}

static char *ph_read_text_file(const char *path) {
    HANDLE file;
    DWORD size, read = 0;
    unsigned char *raw = NULL;
    char *text = NULL;
    if (!path || !path[0]) return NULL;
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return NULL;
    size = GetFileSize(file, NULL);
    if (size == INVALID_FILE_SIZE || !size || size > (2u * 1024u * 1024u)) { CloseHandle(file); return NULL; }
    raw = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 2);
    if (!raw || !ReadFile(file, raw, size, &read, NULL) || !read) {
        if (raw) HeapFree(GetProcessHeap(), 0, raw);
        CloseHandle(file);
        return NULL;
    }
    CloseHandle(file);
    if ((read >= 2 && raw[0] == 0xff && raw[1] == 0xfe) || (read >= 2 && raw[1] == 0)) {
        DWORD offset = (raw[0] == 0xff && raw[1] == 0xfe) ? 2 : 0;
        DWORD characters = (read - offset) / 2;
        text = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, characters + 1);
        if (text) {
            for (DWORD i = 0; i < characters; i++) {
                unsigned char low = raw[offset + (i * 2)];
                unsigned char high = raw[offset + (i * 2) + 1];
                text[i] = high ? '?' : (char)low;
            }
        }
    } else {
        DWORD offset = (read >= 3 && raw[0] == 0xef && raw[1] == 0xbb && raw[2] == 0xbf) ? 3 : 0;
        text = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, read - offset + 1);
        if (text) for (DWORD i = offset; i < read; i++) text[i-offset] = (char)raw[i];
    }
    HeapFree(GetProcessHeap(), 0, raw);
    return text;
}

static void ph_expand_executable(const char *command, char *out, int capacity) {
    char parsed[4096], expanded[4096];
    DWORD expanded_length;
    if (!out || capacity <= 0) return;
    out[0] = 0;
    if (!command || !command[0]) return;
    ph_binary_path(command, parsed, sizeof(parsed));
    if (!parsed[0]) ph_copy_local(parsed, sizeof(parsed), command);
    expanded_length = ExpandEnvironmentStringsA(parsed, expanded, sizeof(expanded));
    if (expanded_length && expanded_length <= sizeof(expanded)) ph_copy_local(out, capacity, expanded);
    else ph_copy_local(out, capacity, parsed);
    ph_trim_path(out);
}

static const char *ph_last_component(const char *path) {
    const char *last = path;
    if (!path) return "";
    for (int i = 0; path[i]; i++) if (path[i] == '\\' || path[i] == '/') last = path + i + 1;
    return last;
}

static BOOL ph_is_system_task_account(const char *account) {
    return ph_is_system_account(account) || ph_equal_ci(account, "S-1-5-18");
}

static void ph_emit_task_file(PH_GRAPH *g, const char *path, const char *relative_name) {
    char *xml;
    char enabled[32], account[512], command[4096], executable[4096];
    const char *task_name;
    if (!g || !path || !relative_name) return;
    xml = ph_read_text_file(path);
    if (!xml) return;
    enabled[0] = 0;
    if (ph_xml_value(xml, "Enabled", enabled, sizeof(enabled)) && ph_equal_ci(enabled, "false")) {
        HeapFree(GetProcessHeap(), 0, xml); return;
    }
    account[0] = 0; command[0] = 0;
    if (!ph_xml_value(xml, "UserId", account, sizeof(account)) || !ph_is_system_task_account(account) ||
        !ph_xml_value(xml, "Command", command, sizeof(command))) {
        HeapFree(GetProcessHeap(), 0, xml); return;
    }
    ph_expand_executable(command, executable, sizeof(executable));
    if (!executable[0] || !ph_file_is_writable(executable)) { HeapFree(GetProcessHeap(), 0, xml); return; }
    task_name = ph_last_component(relative_name);
    {
        char nid[33], props[8192], edge_props[1024], name[1024], finding[4096];
        PH_JSON p, ep;
        ph_id(g, "task", task_name, nid);
        ph_copy_local(name, sizeof(name), "TASK:"); ph_append_local(name, sizeof(name), task_name);
        ph_append_local(name, sizeof(name), "@"); ph_append_local(name, sizeof(name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
        ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "task_name", task_name);
        ph_json_add_string(&p, "task_path", relative_name); ph_json_add_string(&p, "executable", executable);
        ph_json_add_string(&p, "run_account", account); ph_json_add_string(&p, "hostname", g->hostname);
        ph_json_end_object(&p); ph_emit_node(g, nid, "[\"PHScheduledTask\"]", props);
        ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep);
        ph_json_add_string(&ep, "mitre", "T1053.005"); ph_json_end_object(&ep);
        ph_emit_edge(g, g->current_user_id, nid, "PHCanWriteTaskBinary", edge_props);
        ph_emit_empty_edge(g, nid, g->system_id, "PHRunsAs");
        ph_copy_local(finding, sizeof(finding), "Writable task binary '"); ph_append_local(finding, sizeof(finding), task_name);
        ph_append_local(finding, sizeof(finding), "': "); ph_append_local(finding, sizeof(finding), executable);
        ph_emit_finding(g, "Task", "HIGH", finding, "Verify the task action and binary permissions in the isolated lab");
    }
    HeapFree(GetProcessHeap(), 0, xml);
}

static void ph_walk_task_directory(PH_GRAPH *g, const char *root, const char *relative, int depth) {
    char directory[4096], pattern[4096];
    WIN32_FIND_DATAA data;
    HANDLE find;
    if (!g || !root || depth > 16) return;
    ph_copy_local(directory, sizeof(directory), root);
    if (relative && relative[0]) { ph_append_local(directory, sizeof(directory), "\\"); ph_append_local(directory, sizeof(directory), relative); }
    ph_copy_local(pattern, sizeof(pattern), directory); ph_append_local(pattern, sizeof(pattern), "\\*");
    find = FindFirstFileA(pattern, &data);
    if (find == INVALID_HANDLE_VALUE) return;
    do {
        char child_relative[4096], child_path[4096];
        if (ph_equal_ci(data.cFileName, ".") || ph_equal_ci(data.cFileName, "..")) continue;
        child_relative[0] = 0;
        if (relative && relative[0]) { ph_append_local(child_relative, sizeof(child_relative), relative); ph_append_local(child_relative, sizeof(child_relative), "\\"); }
        ph_append_local(child_relative, sizeof(child_relative), data.cFileName);
        ph_copy_local(child_path, sizeof(child_path), root); ph_append_local(child_path, sizeof(child_path), "\\"); ph_append_local(child_path, sizeof(child_path), child_relative);
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) ph_walk_task_directory(g, root, child_relative, depth + 1);
        } else ph_emit_task_file(g, child_path, child_relative);
    } while (FindNextFileA(find, &data));
    FindClose(find);
}

void ph_collect_scheduled_tasks(PH_GRAPH *g) {
    char *system_root;
    char task_root[4096];
    if (!g || g->is_admin) return;
    system_root = ph_environment_value("SystemRoot");
    if (!system_root) { ph_emit_error(g, "Task", "SystemRoot is unavailable"); return; }
    ph_copy_local(task_root, sizeof(task_root), system_root); ph_append_local(task_root, sizeof(task_root), "\\System32\\Tasks");
    ph_walk_task_directory(g, task_root, "", 0);
    HeapFree(GetProcessHeap(), 0, system_root);
}

static void ph_collect_autorun_key(PH_GRAPH *g, HKEY root, const char *subkey, const char *display_key, const char *scope) {
    HKEY key = NULL;
    DWORD index = 0;
    if (RegOpenKeyExA(root, subkey, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return;
    for (;;) {
        char value_name[512], data[8192], command[8192], executable[4096];
        DWORD value_name_length = sizeof(value_name), data_size = sizeof(data) - 1, type = 0;
        LONG result = RegEnumValueA(key, index++, value_name, &value_name_length, NULL, &type, (LPBYTE)data, &data_size);
        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) continue;
        data[data_size < sizeof(data) ? data_size : sizeof(data)-1] = 0;
        if (type == REG_EXPAND_SZ) {
            DWORD needed = ExpandEnvironmentStringsA(data, command, sizeof(command));
            if (!needed || needed > sizeof(command)) ph_copy_local(command, sizeof(command), data);
        } else ph_copy_local(command, sizeof(command), data);
        ph_expand_executable(command, executable, sizeof(executable));
        if (!executable[0] || !ph_file_is_writable(executable)) continue;
        {
            char id_name[2048], nid[33], props[8192], edge_props[1024], name[1024], finding[4096];
            PH_JSON p, ep;
            ph_copy_local(id_name, sizeof(id_name), value_name); ph_append_local(id_name, sizeof(id_name), "_"); ph_append_local(id_name, sizeof(id_name), display_key);
            ph_id(g, "autorun", id_name, nid);
            ph_copy_local(name, sizeof(name), "AUTORUN:"); ph_append_local(name, sizeof(name), value_name); ph_append_local(name, sizeof(name), "@"); ph_append_local(name, sizeof(name), g->hostname);
            ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
            ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "value_name", value_name);
            ph_json_add_string(&p, "reg_key", display_key); ph_json_add_string(&p, "command", command);
            ph_json_add_string(&p, "executable", executable); ph_json_add_string(&p, "scope", scope);
            ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
            ph_emit_node(g, nid, "[\"PHAutoRun\"]", props);
            ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep);
            ph_json_add_string(&ep, "mitre", "T1547.001"); ph_json_add_string(&ep, "scope", scope); ph_json_end_object(&ep);
            ph_emit_edge(g, g->current_user_id, nid, "PHCanWriteAutorun", edge_props);
            ph_copy_local(finding, sizeof(finding), "Writable "); ph_append_local(finding, sizeof(finding), scope);
            ph_append_local(finding, sizeof(finding), " autorun '"); ph_append_local(finding, sizeof(finding), value_name);
            ph_append_local(finding, sizeof(finding), "': "); ph_append_local(finding, sizeof(finding), executable);
            ph_append_local(finding, sizeof(finding), " (privileged startup unverified)");
            ph_emit_finding(g, "Autorun", "MEDIUM", finding, "Verify which account executes the autorun in the isolated lab");
        }
    }
    RegCloseKey(key);
}

void ph_collect_autoruns(PH_GRAPH *g) {
    if (!g || g->is_admin) return;
    ph_collect_autorun_key(g, HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "machine");
    ph_collect_autorun_key(g, HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "machine");
    ph_collect_autorun_key(g, HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "user");
}

static BOOL ph_registry_key_is_writable(HKEY root, const char *subkey) {
    HKEY key = NULL;
    if (RegOpenKeyExA(root, subkey, 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS) { RegCloseKey(key); return TRUE; }
    if (RegOpenKeyExA(root, subkey, 0, WRITE_DAC, &key) == ERROR_SUCCESS) { RegCloseKey(key); return TRUE; }
    if (RegOpenKeyExA(root, subkey, 0, WRITE_OWNER, &key) == ERROR_SUCCESS) { RegCloseKey(key); return TRUE; }
    return FALSE;
}

void ph_collect_service_registry_keys(PH_GRAPH *g) {
    HKEY services = NULL;
    DWORD index = 0;
    if (!g || g->is_admin) return;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_ENUMERATE_SUB_KEYS, &services) != ERROR_SUCCESS) {
        ph_emit_error(g, "RegKey", "Could not enumerate the Services registry key"); return;
    }
    for (;;) {
        char service_name[512], subkey[1024];
        DWORD service_name_length = sizeof(service_name), start = 0;
        LONG result = RegEnumKeyExA(services, index++, service_name, &service_name_length, NULL, NULL, NULL, NULL);
        char *image = NULL, *account = NULL;
        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS) continue;
        ph_copy_local(subkey, sizeof(subkey), "SYSTEM\\CurrentControlSet\\Services\\"); ph_append_local(subkey, sizeof(subkey), service_name);
        if (!ph_registry_key_is_writable(HKEY_LOCAL_MACHINE, subkey) ||
            !ph_reg_dword(HKEY_LOCAL_MACHINE, subkey, "Start", &start) || start > 3) continue;
        image = ph_reg_string(HKEY_LOCAL_MACHINE, subkey, "ImagePath");
        if (!image || !image[0]) { if (image) HeapFree(GetProcessHeap(), 0, image); continue; }
        account = ph_reg_string(HKEY_LOCAL_MACHINE, subkey, "ObjectName");
        {
            char nid[33], props[8192], name[1024], finding[4096]; PH_JSON p;
            ph_id(g, "regservice", service_name, nid);
            ph_copy_local(name, sizeof(name), "REGKEY:"); ph_append_local(name, sizeof(name), service_name); ph_append_local(name, sizeof(name), "@"); ph_append_local(name, sizeof(name), g->hostname);
            ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
            ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "service", service_name);
            ph_json_add_string(&p, "image_path", image); ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
            ph_emit_node(g, nid, "[\"PHWritableRegKey\"]", props);
            ph_emit_edge(g, g->current_user_id, nid, "PHCanModifyRegKey", "{\"mitre\":\"T1574.011\"}");
            if (!account || !account[0] || ph_is_system_account(account)) ph_emit_empty_edge(g, nid, g->system_id, "PHRunsAs");
            ph_copy_local(finding, sizeof(finding), "Writable service registry key for '"); ph_append_local(finding, sizeof(finding), service_name); ph_append_local(finding, sizeof(finding), "'");
            ph_emit_finding(g, "RegKey", "HIGH", finding, "Verify write access to ImagePath in the isolated lab");
        }
        if (account) HeapFree(GetProcessHeap(), 0, account);
        HeapFree(GetProcessHeap(), 0, image);
    }
    RegCloseKey(services);
}

static BOOL ph_path_is_under(const char *path, const char *directory) {
    int length;
    if (!path || !directory) return FALSE;
    length = ph_len(directory);
    for (int i = 0; i < length; i++) if (!path[i] || ph_lower(path[i]) != ph_lower(directory[i])) return FALSE;
    return path[length] == '\\' || path[length] == '/';
}

static void ph_link_program_dir_services(PH_GRAPH *g, const char *directory, const char *directory_id) {
    SC_HANDLE scm = NULL;
    HKEY services = NULL;
    DWORD index = 0;
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_ENUMERATE_SUB_KEYS, &services) != ERROR_SUCCESS) {
        CloseServiceHandle(scm); return;
    }
    for (;;) {
        char service_name[512]; DWORD service_name_length = sizeof(service_name);
        LONG result = RegEnumKeyExA(services, index++, service_name, &service_name_length, NULL, NULL, NULL, NULL);
        SC_HANDLE service; DWORD needed = 0; QUERY_SERVICE_CONFIGA *config = NULL;
        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS) continue;
        service = OpenServiceA(scm, service_name, SERVICE_QUERY_CONFIG);
        if (!service) continue;
        QueryServiceConfigA(service, NULL, 0, &needed);
        if (needed) config = (QUERY_SERVICE_CONFIGA *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
        if (config && QueryServiceConfigA(service, config, needed, &needed) && (config->dwServiceType & SERVICE_WIN32)) {
            char binary[4096], service_id[33];
            ph_expand_executable(config->lpBinaryPathName, binary, sizeof(binary));
            if (ph_path_is_under(binary, directory)) {
                char props[8192], edge_props[4096], name[1024], finding[4096]; PH_JSON p, ep;
                ph_id(g, "service", service_name, service_id);
                ph_copy_local(name, sizeof(name), "SVC:"); ph_append_local(name, sizeof(name), service_name); ph_append_local(name, sizeof(name), "@"); ph_append_local(name, sizeof(name), g->hostname);
                ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
                ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "service_name", service_name);
                ph_json_add_string(&p, "display_name", config->lpDisplayName ? config->lpDisplayName : service_name);
                ph_json_add_string(&p, "start_name", config->lpServiceStartName); ph_json_add_string(&p, "binary_path", config->lpBinaryPathName);
                ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
                ph_emit_node(g, service_id, "[\"PHService\"]", props);
                ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep);
                ph_json_add_string(&ep, "binary_path", config->lpBinaryPathName); ph_json_end_object(&ep);
                ph_emit_edge(g, directory_id, service_id, "PHHostsBinaryFor", edge_props);
                if (ph_is_system_account(config->lpServiceStartName)) {
                    ph_emit_edge(g, service_id, g->system_id, "PHRunsAs", "{\"run_account\":\"LocalSystem\"}");
                }
                ph_copy_local(finding, sizeof(finding), "Writable directory hosts service '"); ph_append_local(finding, sizeof(finding), service_name); ph_append_local(finding, sizeof(finding), "' binary");
                ph_emit_finding(g, "ProgDir", "HIGH", finding, "Verify the hosted service binary before making changes");
            }
        }
        if (config) HeapFree(GetProcessHeap(), 0, config);
        CloseServiceHandle(service);
    }
    RegCloseKey(services); CloseServiceHandle(scm);
}

static void ph_collect_program_root(PH_GRAPH *g, const char *root) {
    char pattern[4096]; WIN32_FIND_DATAA data; HANDLE find;
    if (!root || !root[0]) return;
    ph_copy_local(pattern, sizeof(pattern), root); ph_append_local(pattern, sizeof(pattern), "\\*");
    find = FindFirstFileA(pattern, &data);
    if (find == INVALID_HANDLE_VALUE) return;
    do {
        char directory[4096];
        if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
            ph_equal_ci(data.cFileName, ".") || ph_equal_ci(data.cFileName, "..")) continue;
        ph_copy_local(directory, sizeof(directory), root); ph_append_local(directory, sizeof(directory), "\\"); ph_append_local(directory, sizeof(directory), data.cFileName);
        if (ph_file_is_writable(directory)) {
            char nid[33], props[8192], name[4608], finding[4608]; PH_JSON p;
            ph_id(g, "progdir", directory, nid);
            ph_copy_local(name, sizeof(name), "PROGDIR:"); ph_append_local(name, sizeof(name), data.cFileName); ph_append_local(name, sizeof(name), "@"); ph_append_local(name, sizeof(name), g->hostname);
            ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
            ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "directory", directory); ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
            ph_emit_node(g, nid, "[\"PHWritableProgramDir\"]", props);
            ph_emit_edge(g, g->current_user_id, nid, "PHCanWriteProgDir", "{\"mitre\":\"T1574.010\"}");
            ph_copy_local(finding, sizeof(finding), "Writable program directory: "); ph_append_local(finding, sizeof(finding), directory);
            ph_emit_finding(g, "ProgDir", "HIGH", finding, "Identify privileged applications or services loading from this directory");
            ph_link_program_dir_services(g, directory, nid);
        }
    } while (FindNextFileA(find, &data));
    FindClose(find);
}

void ph_collect_writable_program_dirs(PH_GRAPH *g) {
    char *program_files, *program_files_x86;
    if (!g || g->is_admin) return;
    program_files = ph_environment_value("ProgramFiles");
    program_files_x86 = ph_environment_value("ProgramFiles(x86)");
    if (program_files) ph_collect_program_root(g, program_files);
    if (program_files_x86 && (!program_files || !ph_equal_ci(program_files, program_files_x86))) ph_collect_program_root(g, program_files_x86);
    if (program_files_x86) HeapFree(GetProcessHeap(), 0, program_files_x86);
    if (program_files) HeapFree(GetProcessHeap(), 0, program_files);
}

void ph_collect_service_recovery(PH_GRAPH *g) {
    SC_HANDLE scm = NULL; HKEY services = NULL; DWORD index = 0;
    if (!g || g->is_admin) return;
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { ph_emit_error(g, "SvcRecovery", "OpenSCManager failed"); return; }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_ENUMERATE_SUB_KEYS, &services) != ERROR_SUCCESS) {
        CloseServiceHandle(scm); ph_emit_error(g, "SvcRecovery", "Could not enumerate the Services registry key"); return;
    }
    for (;;) {
        char service_name[512]; DWORD service_name_length = sizeof(service_name);
        LONG result = RegEnumKeyExA(services, index++, service_name, &service_name_length, NULL, NULL, NULL, NULL);
        SC_HANDLE service; DWORD failure_size = 0, config_size = 0;
        SERVICE_FAILURE_ACTIONSA *failure = NULL; QUERY_SERVICE_CONFIGA *config = NULL;
        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS) continue;
        service = OpenServiceA(scm, service_name, SERVICE_QUERY_CONFIG);
        if (!service) continue;
        QueryServiceConfig2A(service, SERVICE_CONFIG_FAILURE_ACTIONS, NULL, 0, &failure_size);
        if (failure_size) failure = (SERVICE_FAILURE_ACTIONSA *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, failure_size);
        if (!failure || !QueryServiceConfig2A(service, SERVICE_CONFIG_FAILURE_ACTIONS, (LPBYTE)failure, failure_size, &failure_size) ||
            !failure->lpCommand || !failure->lpCommand[0] || !failure->cActions || !failure->lpsaActions) {
            if (failure) HeapFree(GetProcessHeap(), 0, failure); CloseServiceHandle(service); continue;
        }
        {
            BOOL runs_command = FALSE;
            for (DWORD i = 0; i < failure->cActions; i++) if (failure->lpsaActions[i].Type == SC_ACTION_RUN_COMMAND) { runs_command = TRUE; break; }
            if (!runs_command) { HeapFree(GetProcessHeap(), 0, failure); CloseServiceHandle(service); continue; }
        }
        {
            char recovery_binary[4096];
            ph_expand_executable(failure->lpCommand, recovery_binary, sizeof(recovery_binary));
            if (!recovery_binary[0] || !ph_file_is_writable(recovery_binary)) { HeapFree(GetProcessHeap(), 0, failure); CloseServiceHandle(service); continue; }
            QueryServiceConfigA(service, NULL, 0, &config_size);
            if (config_size) config = (QUERY_SERVICE_CONFIGA *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, config_size);
            if (config && QueryServiceConfigA(service, config, config_size, &config_size)) {
                char nid[33], props[8192], edge_props[8192], name[1024], finding[4096]; PH_JSON p, ep;
                ph_id(g, "service", service_name, nid);
                ph_copy_local(name, sizeof(name), "SVC:"); ph_append_local(name, sizeof(name), service_name); ph_append_local(name, sizeof(name), "@"); ph_append_local(name, sizeof(name), g->hostname);
                ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
                ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "service_name", service_name);
                ph_json_add_string(&p, "display_name", config->lpDisplayName ? config->lpDisplayName : service_name);
                ph_json_add_string(&p, "start_name", config->lpServiceStartName); ph_json_add_string(&p, "binary_path", config->lpBinaryPathName);
                ph_json_add_string(&p, "recovery_command", failure->lpCommand); ph_json_add_string(&p, "recovery_binary", recovery_binary);
                ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
                ph_emit_node(g, nid, "[\"PHService\"]", props);
                if (ph_is_system_account(config->lpServiceStartName)) {
                    ph_emit_edge(g, nid, g->system_id, "PHRunsAs", "{\"run_account\":\"LocalSystem\"}");
                }
                ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep);
                ph_json_add_string(&ep, "recovery_binary", recovery_binary); ph_json_add_string(&ep, "recovery_command", failure->lpCommand);
                ph_json_add_string(&ep, "mitre", "T1574.010"); ph_json_end_object(&ep);
                ph_emit_edge(g, g->current_user_id, nid, "PHCanWriteRecoveryBin", edge_props);
                ph_copy_local(finding, sizeof(finding), "Service '"); ph_append_local(finding, sizeof(finding), service_name);
                ph_append_local(finding, sizeof(finding), "' recovery command binary is writable: "); ph_append_local(finding, sizeof(finding), recovery_binary);
                ph_emit_finding(g, "SvcRecovery", "HIGH", finding, "Verify the configured recovery command in the isolated lab");
            }
            if (config) HeapFree(GetProcessHeap(), 0, config);
        }
        HeapFree(GetProcessHeap(), 0, failure); CloseServiceHandle(service);
    }
    RegCloseKey(services); CloseServiceHandle(scm);
}

static void ph_sanitize_label(const char *value, char *out, int capacity) {
    int at = 0;
    if (!out || capacity <= 0) return;
    if (!value) value = "";
    while (*value && at + 1 < capacity) {
        char c = *value++;
        BOOL allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '_' || c == '-';
        out[at++] = allowed ? c : '_';
    }
    out[at] = 0;
}

static BOOL ph_file_exists(const char *path) {
    DWORD attributes;
    if (!path || !path[0]) return FALSE;
    attributes = GetFileAttributesA(path);
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

static BOOL ph_directory_exists(const char *path) {
    DWORD attributes;
    if (!path || !path[0]) return FALSE;
    attributes = GetFileAttributesA(path);
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY);
}

static BOOL ph_text_has(const char *path, const char *needle) {
    char *text;
    BOOL found;
    if (!ph_file_exists(path)) return FALSE;
    text = ph_read_text_file(path);
    if (!text) return FALSE;
    found = ph_find_ci(text, needle) != NULL;
    HeapFree(GetProcessHeap(), 0, text);
    return found;
}

typedef void (*PH_FILE_VISITOR)(PH_GRAPH *g, const char *path, const char *name);

static void ph_walk_files(PH_GRAPH *g, const char *directory, int depth, int max_depth, PH_FILE_VISITOR visitor) {
    char pattern[4096];
    WIN32_FIND_DATAA data;
    HANDLE find;
    if (!g || !directory || !visitor || depth > max_depth) return;
    ph_copy_local(pattern, sizeof(pattern), directory); ph_append_local(pattern, sizeof(pattern), "\\*");
    find = FindFirstFileA(pattern, &data);
    if (find == INVALID_HANDLE_VALUE) return;
    do {
        char child[4096];
        if (ph_equal_ci(data.cFileName, ".") || ph_equal_ci(data.cFileName, "..")) continue;
        ph_copy_local(child, sizeof(child), directory); ph_append_local(child, sizeof(child), "\\"); ph_append_local(child, sizeof(child), data.cFileName);
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && depth < max_depth) ph_walk_files(g, child, depth + 1, max_depth, visitor);
        } else visitor(g, child, data.cFileName);
    } while (FindNextFileA(find, &data));
    FindClose(find);
}

void ph_collect_stored_credentials(PH_GRAPH *g) {
    DWORD count = 0;
    PCREDENTIALA *credentials = NULL;
    if (!g) return;
    if (CredEnumerateA(NULL, 0, &count, &credentials) && credentials) {
        for (DWORD i = 0; i < count; i++) {
            PCREDENTIALA credential = credentials[i];
            char label[1024], id_name[1200], nid[33], props[8192], edge_props[1024], name[2048], finding[4096];
            PH_JSON p, ep;
            if (!credential || !credential->TargetName || !credential->TargetName[0]) continue;
            ph_sanitize_label(credential->TargetName, label, sizeof(label));
            ph_copy_local(id_name, sizeof(id_name), "cmdkey_"); ph_append_local(id_name, sizeof(id_name), label);
            ph_id(g, "cred", id_name, nid);
            ph_copy_local(name, sizeof(name), "STOREDCREDS:"); ph_append_local(name, sizeof(name), credential->TargetName);
            ph_append_local(name, sizeof(name), "@"); ph_append_local(name, sizeof(name), g->hostname);
            ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
            ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "source", "CredentialManager");
            ph_json_add_string(&p, "target", credential->TargetName);
            if (credential->UserName) ph_json_add_string(&p, "cred_user", credential->UserName);
            ph_json_add_int(&p, "cred_type", credential->Type); ph_json_add_bool(&p, "secret_emitted", FALSE);
            ph_json_add_bool(&p, "reusable_for_runas", FALSE); ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
            ph_emit_node(g, nid, "[\"PHStoredCredential\"]", props);
            ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep);
            ph_json_add_bool(&ep, "reusable_for_runas", FALSE); ph_json_end_object(&ep);
            ph_emit_edge(g, g->current_user_id, nid, "PHHasStoredCreds", edge_props);
            ph_copy_local(finding, sizeof(finding), "Stored credential metadata for target '"); ph_append_local(finding, sizeof(finding), credential->TargetName);
            ph_append_local(finding, sizeof(finding), "' (secret not collected; reuse unverified)");
            ph_emit_finding(g, "Creds", "MEDIUM", finding, "Review the Credential Manager entry under authorized conditions");
        }
        CredFree(credentials);
    }
    {
        const char *key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
        char *password = ph_reg_string(HKEY_LOCAL_MACHINE, key, "DefaultPassword");
        if (password && password[0]) {
            char *username = ph_reg_string(HKEY_LOCAL_MACHINE, key, "DefaultUserName");
            char *domain = ph_reg_string(HKEY_LOCAL_MACHINE, key, "DefaultDomainName");
            char nid[33], props[4096], name[1024]; PH_JSON p;
            ph_id(g, "cred", "autologon", nid);
            ph_copy_local(name, sizeof(name), "AUTOLOGON:"); ph_append_local(name, sizeof(name), username ? username : "UNKNOWN"); ph_append_local(name, sizeof(name), "@"); ph_append_local(name, sizeof(name), g->hostname);
            ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
            ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "source", "WinlogonAutoLogon");
            if (username) ph_json_add_string(&p, "username", username); if (domain) ph_json_add_string(&p, "domain", domain);
            ph_json_add_bool(&p, "password_present", TRUE); ph_json_add_bool(&p, "secret_emitted", FALSE);
            ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
            ph_emit_node(g, nid, "[\"PHStoredCredential\"]", props);
            ph_emit_empty_edge(g, g->current_user_id, nid, "PHCanReadCreds");
            ph_emit_finding(g, "AutoLogon", "CRITICAL", "Winlogon AutoLogon password is present (value intentionally not emitted)", "Review and remove plaintext AutoLogon credentials");
            if (domain) HeapFree(GetProcessHeap(), 0, domain); if (username) HeapFree(GetProcessHeap(), 0, username);
        }
        if (password) {
            ph_zero(password, ph_len(password));
            HeapFree(GetProcessHeap(), 0, password);
        }
    }
}

static BOOL ph_is_gpp_name(const char *name) {
    return ph_equal_ci(name, "Groups.xml") || ph_equal_ci(name, "Services.xml") ||
           ph_equal_ci(name, "Scheduledtasks.xml") || ph_equal_ci(name, "DataSources.xml") ||
           ph_equal_ci(name, "Printers.xml") || ph_equal_ci(name, "Drives.xml");
}

static void ph_gpp_visitor(PH_GRAPH *g, const char *path, const char *name) {
    if (!ph_is_gpp_name(name) || !ph_text_has(path, "cpassword=\"")) return;
    {
        char nid[33], props[8192], node_name[1024], finding[4096]; PH_JSON p;
        ph_id(g, "gpp", path, nid);
        ph_copy_local(node_name, sizeof(node_name), "GPP:"); ph_append_local(node_name, sizeof(node_name), name); ph_append_local(node_name, sizeof(node_name), "@"); ph_append_local(node_name, sizeof(node_name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
        ph_json_add_string(&p, "name", node_name); ph_json_add_string(&p, "file_path", path);
        ph_json_add_string(&p, "file_name", name); ph_json_add_bool(&p, "secret_emitted", FALSE);
        ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
        ph_emit_node(g, nid, "[\"PHGPPPassword\"]", props);
        ph_emit_edge(g, g->current_user_id, nid, "PHCanDecryptGPP", "{\"mitre\":\"T1552.006\"}");
        ph_copy_local(finding, sizeof(finding), "GPP cpassword attribute present in "); ph_append_local(finding, sizeof(finding), path);
        ph_emit_finding(g, "GPP", "CRITICAL", finding, "Review and remove legacy GPP password material");
    }
}

void ph_collect_gpp_passwords(PH_GRAPH *g) {
    char *program_data, *system_root;
    char path[4096];
    if (!g) return;
    program_data = ph_environment_value("ProgramData");
    system_root = ph_environment_value("SystemRoot");
    if (program_data) {
        ph_copy_local(path, sizeof(path), program_data); ph_append_local(path, sizeof(path), "\\Microsoft\\Group Policy\\History");
        if (ph_directory_exists(path)) ph_walk_files(g, path, 0, 12, ph_gpp_visitor);
        HeapFree(GetProcessHeap(), 0, program_data);
    }
    if (system_root) {
        ph_copy_local(path, sizeof(path), system_root); ph_append_local(path, sizeof(path), "\\SYSVOL");
        if (ph_directory_exists(path)) ph_walk_files(g, path, 0, 16, ph_gpp_visitor);
        HeapFree(GetProcessHeap(), 0, system_root);
    }
}

static void ph_lower_path(const char *value, char *out, int capacity) {
    int at = 0;
    volatile char *write = out;
    if (!out || capacity <= 0) return;
    if (!value) value = "";
    while (value[at] && at + 1 < capacity) { write[at] = ph_lower(value[at]); at++; }
    write[at] = 0;
}

static void ph_check_unattend(PH_GRAPH *g, const char *path) {
    char *text;
    BOOL has_marker;
    if (!g || !ph_file_exists(path)) return;
    text = ph_read_text_file(path);
    if (!text) return;
    has_marker = ph_find_ci(text, "<Password>") || ph_find_ci(text, "<AutoLogon>") || ph_find_ci(text, "<AdministratorPassword>");
    HeapFree(GetProcessHeap(), 0, text);
    if (has_marker) {
        char id_path[4096], nid[33], props[8192], name[1024], finding[4096]; PH_JSON p;
        const char *leaf = ph_last_component(path);
        ph_lower_path(path, id_path, sizeof(id_path)); ph_id(g, "unattend", id_path, nid);
        ph_copy_local(name, sizeof(name), "UNATTEND:"); ph_append_local(name, sizeof(name), leaf); ph_append_local(name, sizeof(name), "@"); ph_append_local(name, sizeof(name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
        ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "file_path", path);
        ph_json_add_bool(&p, "credential_marker_present", TRUE); ph_json_add_bool(&p, "secret_emitted", FALSE);
        ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
        ph_emit_node(g, nid, "[\"PHUnattendFile\"]", props);
        ph_emit_edge(g, g->current_user_id, nid, "PHCanReadCreds", "{\"mitre\":\"T1552.001\"}");
        ph_emit_empty_edge(g, nid, g->admin_id, "PHEscalatesTo");
        ph_copy_local(finding, sizeof(finding), "Unattend file contains credential-related elements: "); ph_append_local(finding, sizeof(finding), path);
        ph_emit_finding(g, "Unattend", "HIGH", finding, "Review the file securely; values are intentionally not emitted");
    }
}

void ph_collect_unattend_files(PH_GRAPH *g) {
    char *system_drive, *system_root;
    char path[4096];
    if (!g) return;
    system_drive = ph_environment_value("SystemDrive");
    system_root = ph_environment_value("SystemRoot");
    if (system_drive) {
        ph_copy_local(path, sizeof(path), system_drive); ph_append_local(path, sizeof(path), "\\unattend.xml"); ph_check_unattend(g, path);
        HeapFree(GetProcessHeap(), 0, system_drive);
    }
    if (system_root) {
        ph_copy_local(path, sizeof(path), system_root); ph_append_local(path, sizeof(path), "\\Panther\\unattend.xml"); ph_check_unattend(g, path);
        ph_copy_local(path, sizeof(path), system_root); ph_append_local(path, sizeof(path), "\\Panther\\Unattend\\unattend.xml"); ph_check_unattend(g, path);
        ph_copy_local(path, sizeof(path), system_root); ph_append_local(path, sizeof(path), "\\system32\\sysprep\\unattend.xml"); ph_check_unattend(g, path);
        ph_copy_local(path, sizeof(path), system_root); ph_append_local(path, sizeof(path), "\\system32\\sysprep\\sysprep.xml"); ph_check_unattend(g, path);
        ph_copy_local(path, sizeof(path), system_root); ph_append_local(path, sizeof(path), "\\system32\\sysprep\\Panther\\unattend.xml"); ph_check_unattend(g, path);
        HeapFree(GetProcessHeap(), 0, system_root);
    }
}

void ph_collect_ps_history(PH_GRAPH *g) {
    char *appdata;
    char path[4096];
    if (!g) return;
    appdata = ph_environment_value("APPDATA");
    if (appdata) {
        ph_copy_local(path, sizeof(path), appdata); ph_append_local(path, sizeof(path), "\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt");
        if (ph_file_exists(path)) {
            char nid[33], props[8192], name[1024]; PH_JSON p;
            BOOL indicator = ph_text_has(path, "password") || ph_text_has(path, "-AsPlainText") || ph_text_has(path, "token");
            ph_id(g, "pshist", "ConsoleHost_history", nid);
            ph_copy_local(name, sizeof(name), "PSHIST:ConsoleHost_history@"); ph_append_local(name, sizeof(name), g->hostname);
            ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
            ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "file_path", path); ph_json_add_string(&p, "source", "PSReadLine");
            ph_json_add_bool(&p, "credential_indicator", indicator); ph_json_add_bool(&p, "secret_emitted", FALSE);
            ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
            ph_emit_node(g, nid, "[\"PHPSHistory\"]", props);
            ph_emit_edge(g, g->current_user_id, nid, "PHCanReadHistory", "{\"source\":\"own-profile\"}");
            if (indicator) ph_emit_edge(g, nid, nid, "PHContainsCreds", "{\"source\":\"PSHistory\",\"secret_emitted\":false}");
            ph_emit_finding(g, "PSHistory", indicator ? "HIGH" : "MEDIUM", indicator ? "PowerShell history contains credential-related indicators (values not emitted)" : "PowerShell history is present (credentials unverified)", "Review the history locally under authorized conditions");
        }
        HeapFree(GetProcessHeap(), 0, appdata);
    }
    {
        const char *key = "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription";
        DWORD enabled = 0;
        char *directory = ph_reg_string(HKEY_LOCAL_MACHINE, key, "OutputDirectory");
        if (directory && ph_reg_dword(HKEY_LOCAL_MACHINE, key, "EnableTranscripting", &enabled) && enabled == 1 && ph_directory_exists(directory)) {
            char nid[33], props[8192], name[1024]; PH_JSON p;
            ph_id(g, "pshist", "Transcripts", nid);
            ph_copy_local(name, sizeof(name), "PSHIST:Transcripts@"); ph_append_local(name, sizeof(name), g->hostname);
            ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
            ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "file_path", directory); ph_json_add_string(&p, "source", "Transcription");
            ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
            ph_emit_node(g, nid, "[\"PHPSHistory\"]", props);
            ph_emit_edge(g, g->current_user_id, nid, "PHCanReadHistory", "{\"mitre\":\"T1552.001\"}");
            ph_emit_finding(g, "PSTranscript", "MEDIUM", "PowerShell transcript directory is configured and accessible", "Review transcripts locally for sensitive content");
        }
        if (directory) HeapFree(GetProcessHeap(), 0, directory);
    }
}

static void ph_emit_sensitive_file(PH_GRAPH *g, const char *path, const char *description) {
    char nid[33], props[8192], name[1024], finding[4096]; PH_JSON p;
    const char *leaf;
    BOOL indicator = FALSE;
    if (!g || !ph_file_exists(path)) return;
    leaf = ph_last_component(path);
    ph_id(g, "sensfile", path, nid);
    ph_copy_local(name, sizeof(name), "FILE:"); ph_append_local(name, sizeof(name), leaf); ph_append_local(name, sizeof(name), "@"); ph_append_local(name, sizeof(name), g->hostname);
    if (ph_ends_ci(path, ".git-credentials")) indicator = ph_text_has(path, "://") && ph_text_has(path, "@");
    else if (ph_ends_ci(path, ".rdg")) indicator = ph_text_has(path, "<password>");
    ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
    ph_json_add_string(&p, "name", name); ph_json_add_string(&p, "file_path", path); ph_json_add_string(&p, "description", description);
    ph_json_add_bool(&p, "credential_indicator", indicator); ph_json_add_bool(&p, "secret_emitted", FALSE);
    ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
    ph_emit_node(g, nid, "[\"PHSensitiveFile\"]", props);
    ph_emit_edge(g, g->current_user_id, nid, "PHCanAccessFile", "{\"mitre\":\"T1552.001\"}");
    if (indicator) ph_emit_edge(g, nid, nid, "PHContainsCreds", "{\"secret_emitted\":false}");
    ph_copy_local(finding, sizeof(finding), description); ph_append_local(finding, sizeof(finding), ": "); ph_append_local(finding, sizeof(finding), path);
    ph_emit_finding(g, "SensFile", indicator ? "HIGH" : "MEDIUM", finding, "Review or copy the file only under authorized conditions");
}

static void ph_sensitive_visitor(PH_GRAPH *g, const char *path, const char *name) {
    if (ph_ends_ci(name, ".kdbx")) ph_emit_sensitive_file(g, path, "KeePass database");
    else if (ph_ends_ci(name, ".rdg")) ph_emit_sensitive_file(g, path, "RDCMan configuration");
}

void ph_collect_sensitive_files(PH_GRAPH *g) {
    char *profile, *system_root;
    char path[4096];
    if (!g) return;
    profile = ph_environment_value("USERPROFILE");
    system_root = ph_environment_value("SystemRoot");
    if (profile) {
        ph_copy_local(path, sizeof(path), profile); ph_append_local(path, sizeof(path), "\\.git-credentials"); ph_emit_sensitive_file(g, path, "Git credentials");
        ph_walk_files(g, profile, 0, 3, ph_sensitive_visitor);
        HeapFree(GetProcessHeap(), 0, profile);
    }
    if (system_root) {
        ph_copy_local(path, sizeof(path), system_root); ph_append_local(path, sizeof(path), "\\repair\\SAM"); ph_emit_sensitive_file(g, path, "SAM backup");
        ph_copy_local(path, sizeof(path), system_root); ph_append_local(path, sizeof(path), "\\repair\\SYSTEM"); ph_emit_sensitive_file(g, path, "SYSTEM backup");
        ph_copy_local(path, sizeof(path), system_root); ph_append_local(path, sizeof(path), "\\System32\\config\\RegBack\\SAM"); ph_emit_sensitive_file(g, path, "SAM RegBack");
        ph_copy_local(path, sizeof(path), system_root); ph_append_local(path, sizeof(path), "\\System32\\config\\RegBack\\SYSTEM"); ph_emit_sensitive_file(g, path, "SYSTEM RegBack");
        HeapFree(GetProcessHeap(), 0, system_root);
    }
}

static BOOL ph_is_profile_excluded(PH_GRAPH *g, const char *name) {
    return ph_equal_ci(name, "Public") || ph_equal_ci(name, "Default") || ph_equal_ci(name, "Default User") ||
           ph_equal_ci(name, "All Users") || (g && ph_equal_ci(name, g->username));
}

static void ph_profile_sensitive_file(PH_GRAPH *g, const char *profile_id, const char *profile_name, const char *path, const char *description) {
    char nid[33], edge_props[1024], finding[4096];
    if (!ph_file_exists(path)) return;
    ph_emit_sensitive_file(g, path, description);
    ph_id(g, "sensfile", path, nid);
    ph_emit_edge(g, profile_id, nid, "PHProfileContains", "{}");
    {
        char props[1024]; PH_JSON p;
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p); ph_json_add_string(&p, "mitre", "T1552.001"); ph_json_add_string(&p, "profile", profile_name); ph_json_end_object(&p);
        ph_copy_local(edge_props, sizeof(edge_props), props);
    }
    ph_emit_edge(g, g->current_user_id, nid, "PHCanAccessFile", edge_props);
    ph_copy_local(finding, sizeof(finding), description); ph_append_local(finding, sizeof(finding), " in "); ph_append_local(finding, sizeof(finding), profile_name); ph_append_local(finding, sizeof(finding), "'s profile: "); ph_append_local(finding, sizeof(finding), path);
    ph_emit_finding(g, "CrossProfile", "HIGH", finding, "Review the file locally under authorized conditions; contents are not emitted");
}

static void ph_walk_profile_sensitive(PH_GRAPH *g, const char *profile_id, const char *profile_name, const char *directory, int depth, int *remaining) {
    char pattern[4096]; WIN32_FIND_DATAA data; HANDLE find;
    if (!g || !directory || !remaining || *remaining <= 0 || depth > 4) return;
    ph_copy_local(pattern, sizeof(pattern), directory); ph_append_local(pattern, sizeof(pattern), "\\*");
    find = FindFirstFileA(pattern, &data); if (find == INVALID_HANDLE_VALUE) return;
    do {
        char child[4096];
        if (*remaining <= 0) break;
        if (ph_equal_ci(data.cFileName, ".") || ph_equal_ci(data.cFileName, "..")) continue;
        ph_copy_local(child, sizeof(child), directory); ph_append_local(child, sizeof(child), "\\"); ph_append_local(child, sizeof(child), data.cFileName);
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) ph_walk_profile_sensitive(g, profile_id, profile_name, child, depth + 1, remaining);
        } else if (ph_equal_ci(data.cFileName, ".git-credentials")) {
            ph_profile_sensitive_file(g, profile_id, profile_name, child, "Git credentials"); (*remaining)--;
        } else if (ph_ends_ci(data.cFileName, ".kdbx")) {
            ph_profile_sensitive_file(g, profile_id, profile_name, child, "KeePass database"); (*remaining)--;
        } else if (ph_ends_ci(data.cFileName, ".rdg")) {
            ph_profile_sensitive_file(g, profile_id, profile_name, child, "RDCMan file"); (*remaining)--;
        }
    } while (FindNextFileA(find, &data));
    FindClose(find);
}

void ph_collect_cross_user_profiles(PH_GRAPH *g) {
    char *configured = NULL, *system_drive = NULL; char users_dir[4096], expanded[4096], pattern[4096];
    WIN32_FIND_DATAA data; HANDLE find;
    if (!g) return;
    configured = ph_reg_string(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", "ProfilesDirectory");
    if (configured) {
        DWORD needed = ExpandEnvironmentStringsA(configured, expanded, sizeof(expanded));
        ph_copy_local(users_dir, sizeof(users_dir), (needed && needed <= sizeof(expanded)) ? expanded : configured);
    } else {
        system_drive = ph_environment_value("SystemDrive"); ph_copy_local(users_dir, sizeof(users_dir), system_drive ? system_drive : "C:"); ph_append_local(users_dir, sizeof(users_dir), "\\Users");
    }
    if (configured) HeapFree(GetProcessHeap(), 0, configured); if (system_drive) HeapFree(GetProcessHeap(), 0, system_drive);
    if (!ph_directory_exists(users_dir)) return;
    ph_copy_local(pattern, sizeof(pattern), users_dir); ph_append_local(pattern, sizeof(pattern), "\\*");
    find = FindFirstFileA(pattern, &data); if (find == INVALID_HANDLE_VALUE) return;
    do {
        char profile_path[4096], profile_id[33], props[4096], node_name[1024], finding[4096], history[4096]; PH_JSON p; int remaining = 9;
        if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || ph_is_profile_excluded(g, data.cFileName) || ph_equal_ci(data.cFileName, ".") || ph_equal_ci(data.cFileName, "..")) continue;
        ph_copy_local(profile_path, sizeof(profile_path), users_dir); ph_append_local(profile_path, sizeof(profile_path), "\\"); ph_append_local(profile_path, sizeof(profile_path), data.cFileName);
        if (!ph_file_allows_open(profile_path, FILE_LIST_DIRECTORY)) continue;
        ph_id(g, "userprofile", data.cFileName, profile_id); ph_copy_local(node_name, sizeof(node_name), "PROFILE:"); ph_append_local(node_name, sizeof(node_name), data.cFileName); ph_append_local(node_name, sizeof(node_name), "@"); ph_append_local(node_name, sizeof(node_name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p); ph_json_add_string(&p, "name", node_name); ph_json_add_string(&p, "username", data.cFileName); ph_json_add_string(&p, "profile_path", profile_path); ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p); ph_emit_node(g, profile_id, "[\"PHUserProfile\"]", props);
        ph_emit_empty_edge(g, g->current_user_id, profile_id, "PHCanAccessProfile");
        ph_copy_local(finding, sizeof(finding), "Can access another user profile: "); ph_append_local(finding, sizeof(finding), profile_path); ph_emit_finding(g, "CrossProfile", "MEDIUM", finding, "Review profile ACLs and remove unnecessary cross-user read access");
        ph_walk_profile_sensitive(g, profile_id, data.cFileName, profile_path, 0, &remaining);
        ph_copy_local(history, sizeof(history), profile_path); ph_append_local(history, sizeof(history), "\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt");
        ph_profile_sensitive_file(g, profile_id, data.cFileName, history, "PowerShell history");
    } while (FindNextFileA(find, &data));
    FindClose(find);
}

static BOOL ph_reg_key_exists(HKEY root, const char *subkey) {
    HKEY key = NULL;
    if (RegOpenKeyExA(root, subkey, 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &key) != ERROR_SUCCESS) return FALSE;
    RegCloseKey(key);
    return TRUE;
}

static BOOL ph_query_service(const char *name, DWORD *state, DWORD *start_type) {
    SC_HANDLE scm = NULL, service = NULL;
    SERVICE_STATUS_PROCESS status;
    QUERY_SERVICE_CONFIGA *config = NULL;
    DWORD needed = 0;
    BOOL found = FALSE;
    if (state) *state = 0;
    if (start_type) *start_type = 0xffffffffu;
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return FALSE;
    service = OpenServiceA(scm, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!service) { CloseServiceHandle(scm); return FALSE; }
    found = TRUE;
    ph_zero(&status, sizeof(status));
    if (state && QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &needed)) *state = status.dwCurrentState;
    QueryServiceConfigA(service, NULL, 0, &needed);
    if (needed) config = (QUERY_SERVICE_CONFIGA *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (config && QueryServiceConfigA(service, config, needed, &needed) && start_type) *start_type = config->dwStartType;
    if (config) HeapFree(GetProcessHeap(), 0, config);
    CloseServiceHandle(service); CloseServiceHandle(scm);
    return found;
}

typedef struct _PH_JIT_DEF {
    const char *name;
    const char *service;
    const char *reg_key;
    const char *binary_suffix;
} PH_JIT_DEF;

void ph_collect_jit_admin_tools(PH_GRAPH *g) {
    static const PH_JIT_DEF tools[] = {
        {"MakeMeAdmin", "MakeMeAdminService", "SOFTWARE\\Sinclair Community College\\Make Me Admin", "\\Make Me Admin\\MakeMeAdminService.exe"},
        {"CyberArkEPM", "VfBackgroundService", "SOFTWARE\\CyberArk\\Endpoint Privilege Manager\\Agent", NULL},
        {"BeyondTrust", "BeyondTrustPrivilegeManagement", "SOFTWARE\\Avecto\\Privilege Guard Client", NULL},
        {"DelineaAgent", "ThycoticAgent", "SOFTWARE\\Thycotic\\Agent", NULL}
    };
    char *program_files = ph_environment_value("ProgramFiles");
    char *program_files_x86 = ph_environment_value("ProgramFiles(x86)");
    if (!g) return;
    for (unsigned int i = 0; i < sizeof(tools) / sizeof(tools[0]); i++) {
        DWORD state = 0, start = 0xffffffffu;
        BOOL service_found = ph_query_service(tools[i].service, &state, &start);
        BOOL registry_found = ph_reg_key_exists(HKEY_LOCAL_MACHINE, tools[i].reg_key);
        BOOL binary_found = FALSE;
        char binary[4096]; binary[0] = 0;
        if (tools[i].binary_suffix) {
            if (program_files) { ph_copy_local(binary, sizeof(binary), program_files); ph_append_local(binary, sizeof(binary), tools[i].binary_suffix); binary_found = ph_file_exists(binary); }
            if (!binary_found && program_files_x86) { ph_copy_local(binary, sizeof(binary), program_files_x86); ph_append_local(binary, sizeof(binary), tools[i].binary_suffix); binary_found = ph_file_exists(binary); }
        }
        if (service_found || registry_found || binary_found) {
            char nid[33], props[8192], edge_props[1024], node_name[1024], finding[2048]; PH_JSON p, ep;
            ph_id(g, "jitadmin", tools[i].name, nid);
            ph_copy_local(node_name, sizeof(node_name), "JIT:"); ph_append_local(node_name, sizeof(node_name), tools[i].name); ph_append_local(node_name, sizeof(node_name), "@"); ph_append_local(node_name, sizeof(node_name), g->hostname);
            ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p);
            ph_json_add_string(&p, "name", node_name); ph_json_add_string(&p, "tool_name", tools[i].name);
            ph_json_add_bool(&p, "service_found", service_found); ph_json_add_bool(&p, "registry_found", registry_found); ph_json_add_bool(&p, "binary_found", binary_found);
            if (service_found) { ph_json_add_string(&p, "service_state", ph_service_state(state)); ph_json_add_string(&p, "start_mode", ph_start_mode(start)); }
            if (binary_found) ph_json_add_string(&p, "binary", binary);
            ph_json_add_bool(&p, "request_authorized", FALSE); ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
            ph_emit_node(g, nid, "[\"PHJITAdminTool\"]", props);
            ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep); ph_json_add_string(&ep, "mitre", "T1548"); ph_json_add_string(&ep, "tool", tools[i].name); ph_json_add_bool(&ep, "authorization_unverified", TRUE); ph_json_end_object(&ep);
            ph_emit_edge(g, g->current_user_id, nid, "PHCanRequestJIT", edge_props);
            ph_emit_edge(g, nid, g->admin_id, "PHGrantsTempAdmin", "{\"authorization_unverified\":true}");
            ph_copy_local(finding, sizeof(finding), "JIT admin tool '"); ph_append_local(finding, sizeof(finding), tools[i].name); ph_append_local(finding, sizeof(finding), "' detected; current-user authorization is unverified");
            ph_emit_finding(g, "JITAdmin", "MEDIUM", finding, "Review the tool allow/deny policy before requesting elevation");
        }
    }
    if (program_files_x86) HeapFree(GetProcessHeap(), 0, program_files_x86);
    if (program_files) HeapFree(GetProcessHeap(), 0, program_files);
}

void ph_collect_print_spooler(PH_GRAPH *g) {
    DWORD state = 0, start = 0xffffffffu, no_warning = 0, restrict_admin = 1;
    BOOL weak_no_warning, weak_restrict;
    if (!g || !ph_query_service("Spooler", &state, &start) || state != SERVICE_RUNNING) return;
    weak_no_warning = ph_reg_dword(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint", "NoWarningNoElevationOnInstall", &no_warning) && no_warning == 1;
    weak_restrict = ph_reg_dword(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers", "RestrictDriverInstallationToAdministrators", &restrict_admin) && restrict_admin == 0;
    if (weak_no_warning || weak_restrict) {
        char nid[33], props[4096], reasons[256], node_name[512]; PH_JSON p;
        reasons[0] = 0;
        if (weak_no_warning) ph_append_local(reasons, sizeof(reasons), "NoWarningNoElevationOnInstall=1");
        if (weak_restrict) { if (reasons[0]) ph_append_local(reasons, sizeof(reasons), "; "); ph_append_local(reasons, sizeof(reasons), "RestrictDriverInstallationToAdministrators=0"); }
        ph_id(g, "printspooler", "Spooler", nid);
        ph_copy_local(node_name, sizeof(node_name), "PRINTSPOOLER@"); ph_append_local(node_name, sizeof(node_name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p); ph_json_add_string(&p, "name", node_name); ph_json_add_string(&p, "hostname", g->hostname);
        ph_json_add_string(&p, "state", "Running"); ph_json_add_string(&p, "reasons", reasons); ph_json_add_bool(&p, "weak_policy_observed", TRUE); ph_json_end_object(&p);
        ph_emit_node(g, nid, "[\"PHPrintSpooler\"]", props); ph_emit_edge(g, g->current_user_id, nid, "PHObservedSpoolerPolicy", "{\"weak_policy_observed\":true}");
        ph_emit_finding(g, "PrintSpooler", "MEDIUM", "Print Spooler is running with an explicitly weakened driver-install policy", "Review Point and Print policy and installed cumulative updates");
    }
}

void ph_collect_wsus_config(PH_GRAPH *g) {
    const char *key = "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate";
    char *server;
    DWORD use_wu = 0;
    if (!g) return;
    server = ph_reg_string(HKEY_LOCAL_MACHINE, key, "WUServer");
    if (server && ph_starts_ci(server, "http://") && ph_reg_dword(HKEY_LOCAL_MACHINE, key, "UseWUServer", &use_wu) && use_wu == 1) {
        char nid[33], props[4096], edge_props[4096], node_name[2048], finding[4096]; PH_JSON p, ep;
        ph_id(g, "wsus", "WSUSConfig", nid); ph_copy_local(node_name, sizeof(node_name), "WSUS:"); ph_append_local(node_name, sizeof(node_name), server); ph_append_local(node_name, sizeof(node_name), "@"); ph_append_local(node_name, sizeof(node_name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p); ph_json_add_string(&p, "name", node_name); ph_json_add_string(&p, "hostname", g->hostname); ph_json_add_string(&p, "wu_server", server); ph_json_add_bool(&p, "use_ssl", FALSE); ph_json_end_object(&p);
        ph_emit_node(g, nid, "[\"PHWSUSConfig\"]", props);
        ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep); ph_json_add_string(&ep, "mitre", "T1557"); ph_json_add_string(&ep, "wu_server", server); ph_json_end_object(&ep);
        ph_emit_edge(g, g->current_user_id, nid, "PHCanExploitWSUS", edge_props); ph_emit_empty_edge(g, nid, g->system_id, "PHEscalatesTo");
        ph_copy_local(finding, sizeof(finding), "WSUS uses HTTP rather than HTTPS: "); ph_append_local(finding, sizeof(finding), server);
        ph_emit_finding(g, "WSUS", "HIGH", finding, "Require HTTPS and validate the WSUS trust configuration");
    }
    if (server) HeapFree(GetProcessHeap(), 0, server);
}

typedef struct _PH_COM_DEF { const char *clsid; const char *description; } PH_COM_DEF;

void ph_collect_com_hijacking(PH_GRAPH *g) {
    static const PH_COM_DEF entries[] = {
        {"{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}", "Scheduled Task Handler"},
        {"{4590F811-1D3A-11D0-891F-00AA004B2E24}", "WBEM Locator"},
        {"{F56F6FDD-AA9D-4618-A949-C1B91AF43B1A}", "TaskBand Shell"},
        {"{C08AFD90-F2A1-11D1-8455-00A0C91F3880}", "SysTray"},
        {"{E6015C5B-B743-4A65-A1CF-4F26D877354A}", "DeviceAssociation"},
        {"{97D17A04-4438-4C29-A86A-4D2C2BC8B952}", "EventViewer COM"}
    };
    if (!g) return;
    for (unsigned int i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
        char machine_key[512], user_key[512];
        ph_copy_local(machine_key, sizeof(machine_key), "CLSID\\"); ph_append_local(machine_key, sizeof(machine_key), entries[i].clsid); ph_append_local(machine_key, sizeof(machine_key), "\\InprocServer32");
        ph_copy_local(user_key, sizeof(user_key), "Software\\Classes\\CLSID\\"); ph_append_local(user_key, sizeof(user_key), entries[i].clsid);
        if (ph_reg_key_exists(HKEY_CLASSES_ROOT, machine_key) && !ph_reg_key_exists(HKEY_CURRENT_USER, user_key)) {
            char *dll = ph_reg_string(HKEY_CLASSES_ROOT, machine_key, NULL);
            char nid[33], props[4096], edge_props[1024], node_name[1024], finding[2048]; PH_JSON p, ep;
            ph_id(g, "comhijack", entries[i].clsid, nid); ph_copy_local(node_name, sizeof(node_name), "COM:"); ph_append_local(node_name, sizeof(node_name), entries[i].description); ph_append_local(node_name, sizeof(node_name), "@"); ph_append_local(node_name, sizeof(node_name), g->hostname);
            ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p); ph_json_add_string(&p, "name", node_name); ph_json_add_string(&p, "clsid", entries[i].clsid); ph_json_add_string(&p, "description", entries[i].description); if (dll) ph_json_add_string(&p, "dll_path", dll); ph_json_add_bool(&p, "privileged_activation_verified", FALSE); ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p);
            ph_emit_node(g, nid, "[\"PHCOMHijack\"]", props);
            ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep); ph_json_add_string(&ep, "mitre", "T1546.015"); ph_json_add_string(&ep, "clsid", entries[i].clsid); ph_json_end_object(&ep); ph_emit_edge(g, g->current_user_id, nid, "PHCanOverrideCOM", edge_props);
            ph_copy_local(finding, sizeof(finding), "COM per-user override candidate: "); ph_append_local(finding, sizeof(finding), entries[i].description); ph_append_local(finding, sizeof(finding), "; privileged activation unverified"); ph_emit_finding(g, "COMHijack", "MEDIUM", finding, "Verify privileged activation through HKCU before treating this as an escalation path");
            if (dll) HeapFree(GetProcessHeap(), 0, dll);
        }
    }
}

typedef struct _PH_PIPE_DEF { const char *name; const char *description; const char *service; } PH_PIPE_DEF;

void ph_collect_named_pipe_permissions(PH_GRAPH *g) {
    static const PH_PIPE_DEF pipes[] = {
        {"spoolss", "Print Spooler", "Spooler"}, {"epmapper", "RPC Endpoint Mapper", "RpcEptMapper"},
        {"lsarpc", "LSA RPC", "SamSs"}, {"netlogon", "Netlogon", "Netlogon"}, {"samr", "SAM Remote", "SamSs"}
    };
    if (!g) return;
    for (unsigned int i = 0; i < sizeof(pipes) / sizeof(pipes[0]); i++) {
        char path[512]; HANDLE pipe;
        ph_copy_local(path, sizeof(path), "\\\\.\\pipe\\"); ph_append_local(path, sizeof(path), pipes[i].name);
        pipe = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (pipe != INVALID_HANDLE_VALUE) {
            char nid[33], props[4096], edge_props[512], node_name[1024], finding[2048]; PH_JSON p, ep;
            CloseHandle(pipe); ph_id(g, "namedpipe", pipes[i].name, nid); ph_copy_local(node_name, sizeof(node_name), "PIPE:"); ph_append_local(node_name, sizeof(node_name), pipes[i].name); ph_append_local(node_name, sizeof(node_name), "@"); ph_append_local(node_name, sizeof(node_name), g->hostname);
            ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p); ph_json_add_string(&p, "name", node_name); ph_json_add_string(&p, "pipe_name", pipes[i].name); ph_json_add_string(&p, "description", pipes[i].description); ph_json_add_string(&p, "service", pipes[i].service); ph_json_add_bool(&p, "impersonation_verified", FALSE); ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p); ph_emit_node(g, nid, "[\"PHNamedPipe\"]", props);
            ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep); ph_json_add_string(&ep, "pipe", pipes[i].name); ph_json_add_bool(&ep, "impersonation_verified", FALSE); ph_json_end_object(&ep); ph_emit_edge(g, g->current_user_id, nid, "PHCanConnectPipe", edge_props);
            ph_copy_local(finding, sizeof(finding), "Accessible named pipe: "); ph_append_local(finding, sizeof(finding), path); ph_append_local(finding, sizeof(finding), "; impersonation unverified"); ph_emit_finding(g, "NamedPipe", "MEDIUM", finding, "Inspect the pipe ACL, server identity, and impersonation behavior");
        }
    }
}

static void ph_emit_cached_credential(PH_GRAPH *g, const char *id_name, const char *source, const char *description, const char *host, const char *username, BOOL contains_secret) {
    char nid[33], props[8192], edge_props[1024], node_name[2048], finding[4096]; PH_JSON p, ep;
    ph_id(g, "cachedcreds", id_name, nid); ph_copy_local(node_name, sizeof(node_name), "CACHED:"); ph_append_local(node_name, sizeof(node_name), source); ph_append_local(node_name, sizeof(node_name), ":"); ph_append_local(node_name, sizeof(node_name), id_name); ph_append_local(node_name, sizeof(node_name), "@"); ph_append_local(node_name, sizeof(node_name), g->hostname);
    ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p); ph_json_add_string(&p, "name", node_name); ph_json_add_string(&p, "hostname", g->hostname); ph_json_add_string(&p, "source", source); ph_json_add_string(&p, "cache_id", id_name); ph_json_add_string(&p, "description", description); if (host) ph_json_add_string(&p, "host", host); if (username) ph_json_add_string(&p, "username", username); ph_json_add_bool(&p, "credential_indicator", contains_secret); ph_json_add_bool(&p, "secret_emitted", FALSE); ph_json_end_object(&p); ph_emit_node(g, nid, "[\"PHCachedCreds\"]", props);
    ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep); ph_json_add_string(&ep, "mitre", "T1552.001"); ph_json_add_string(&ep, "source", source); ph_json_end_object(&ep); ph_emit_edge(g, g->current_user_id, nid, "PHHasCachedCreds", edge_props);
    if (contains_secret) ph_emit_edge(g, nid, nid, "PHContainsCreds", "{\"secret_emitted\":false}");
    ph_copy_local(finding, sizeof(finding), description); ph_append_local(finding, sizeof(finding), " (secret not emitted)"); ph_emit_finding(g, "CachedCreds", contains_secret ? "HIGH" : "MEDIUM", finding, "Review the credential source locally under authorized conditions");
}

static void ph_collect_cached_registry_sessions(PH_GRAPH *g, const char *root_key, const char *source, const char *password_value, const char *host_value, const char *user_value) {
    HKEY root = NULL;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, root_key, 0, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &root) != ERROR_SUCCESS) return;
    for (DWORD index = 0;; index++) {
        char name[512], subkey[2048], id_name[1024], description[2048]; DWORD name_size = sizeof(name);
        char *password = NULL, *host = NULL, *username = NULL;
        if (RegEnumKeyExA(root, index, name, &name_size, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        ph_copy_local(subkey, sizeof(subkey), root_key); ph_append_local(subkey, sizeof(subkey), "\\"); ph_append_local(subkey, sizeof(subkey), name);
        password = ph_reg_string(HKEY_CURRENT_USER, subkey, password_value); host = ph_reg_string(HKEY_CURRENT_USER, subkey, host_value); if (user_value) username = ph_reg_string(HKEY_CURRENT_USER, subkey, user_value);
        if ((password && password[0]) || (host && host[0])) {
            ph_copy_local(id_name, sizeof(id_name), source); ph_append_local(id_name, sizeof(id_name), "_"); ph_append_local(id_name, sizeof(id_name), name);
            ph_copy_local(description, sizeof(description), source); ph_append_local(description, sizeof(description), " stored session: "); ph_append_local(description, sizeof(description), name);
            ph_emit_cached_credential(g, id_name, source, description, host, username, password && password[0]);
        }
        if (password) { ph_zero(password, ph_len(password)); HeapFree(GetProcessHeap(), 0, password); }
        if (host) HeapFree(GetProcessHeap(), 0, host); if (username) HeapFree(GetProcessHeap(), 0, username);
    }
    RegCloseKey(root);
}

static void ph_collect_filezilla_file(PH_GRAPH *g, const char *path) {
    char *text; char host[1024], user[1024]; BOOL secret;
    if (!ph_file_exists(path)) return;
    text = ph_read_text_file(path); if (!text) return;
    host[0] = 0; user[0] = 0; ph_xml_value(text, "Host", host, sizeof(host)); ph_xml_value(text, "User", user, sizeof(user));
    secret = ph_find_ci(text, "<Pass") != NULL;
    if (secret) {
        char id_name[2048], description[2048]; ph_copy_local(id_name, sizeof(id_name), "FileZilla_"); ph_append_local(id_name, sizeof(id_name), host[0] ? host : ph_last_component(path));
        ph_copy_local(description, sizeof(description), "FileZilla saved server in "); ph_append_local(description, sizeof(description), path);
        ph_emit_cached_credential(g, id_name, "FileZilla", description, host[0] ? host : NULL, user[0] ? user : NULL, TRUE);
    }
    ph_zero(text, ph_len(text)); HeapFree(GetProcessHeap(), 0, text);
}

static wchar_t ph_lower_wide(wchar_t c) { return (c >= L'A' && c <= L'Z') ? (wchar_t)(c + (L'a' - L'A')) : c; }

static BOOL ph_wide_contains_ci(const wchar_t *value, const wchar_t *needle) {
    if (!value || !needle || !needle[0]) return FALSE;
    for (int at = 0; value[at]; at++) {
        int i = 0; while (needle[i] && value[at + i] && ph_lower_wide(value[at + i]) == ph_lower_wide(needle[i])) i++;
        if (!needle[i]) return TRUE;
    }
    return FALSE;
}

static void ph_collect_wifi_profiles(PH_GRAPH *g) {
    HANDLE client = NULL; DWORD negotiated = 0; PWLAN_INTERFACE_INFO_LIST interfaces = NULL;
    if (!g || WlanOpenHandle(2, NULL, &negotiated, &client) != ERROR_SUCCESS) return;
    if (WlanEnumInterfaces(client, NULL, &interfaces) == ERROR_SUCCESS && interfaces) {
        for (DWORD i = 0; i < interfaces->dwNumberOfItems; i++) {
            PWLAN_PROFILE_INFO_LIST profiles = NULL;
            if (WlanGetProfileList(client, &interfaces->InterfaceInfo[i].InterfaceGuid, NULL, &profiles) != ERROR_SUCCESS || !profiles) continue;
            for (DWORD j = 0; j < profiles->dwNumberOfItems; j++) {
                LPWSTR xml = NULL; DWORD flags = 0, access = 0;
                if (WlanGetProfile(client, &interfaces->InterfaceInfo[i].InterfaceGuid, profiles->ProfileInfo[j].strProfileName, NULL, &xml, &flags, &access) == ERROR_SUCCESS && xml) {
                    if (ph_wide_contains_ci(xml, L"<keyMaterial>")) {
                        char profile[512], id_name[1024], description[2048];
                        ph_wide_ascii(profiles->ProfileInfo[j].strProfileName, profile, sizeof(profile)); ph_copy_local(id_name, sizeof(id_name), "WiFi_"); ph_append_local(id_name, sizeof(id_name), profile);
                        ph_copy_local(description, sizeof(description), "WiFi profile with stored key material: "); ph_append_local(description, sizeof(description), profile);
                        ph_emit_cached_credential(g, id_name, "WiFi", description, NULL, profile, TRUE);
                    }
                    WlanFreeMemory(xml);
                }
            }
            WlanFreeMemory(profiles);
        }
        WlanFreeMemory(interfaces);
    }
    WlanCloseHandle(client, NULL);
}

void ph_collect_cached_credentials(PH_GRAPH *g) {
    DWORD cached = 0;
    if (!g) return;
    if (ph_reg_ulong(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "CachedLogonsCount", &cached) && cached > 0) {
        char nid[33], props[4096], edge_props[512], node_name[512]; PH_JSON p, ep;
        ph_id(g, "cachedcreds", "DCC2", nid); ph_copy_local(node_name, sizeof(node_name), "CACHED:DOMAINLOGONPOLICY@"); ph_append_local(node_name, sizeof(node_name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p); ph_json_add_string(&p, "name", node_name); ph_json_add_string(&p, "hostname", g->hostname); ph_json_add_string(&p, "source", "CachedLogonsCount"); ph_json_add_string(&p, "description", "Cached domain logon policy is enabled; cache contents unverified"); ph_json_add_int(&p, "cached_count", cached); ph_json_add_bool(&p, "secret_emitted", FALSE); ph_json_end_object(&p); ph_emit_node(g, nid, "[\"PHCachedCreds\"]", props);
        ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep); ph_json_add_int(&ep, "cached_count", cached); ph_json_end_object(&ep); ph_emit_edge(g, g->current_user_id, nid, "PHCachedLogonsConfigured", edge_props);
        ph_emit_finding(g, "CachedCreds", "MEDIUM", "Cached domain logon policy permits entries; actual cache contents are unverified", "Confirm domain membership and whether domain logons have been cached");
    }
    ph_collect_cached_registry_sessions(g, "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions", "WinSCP", "Password", "HostName", "UserName");
    ph_collect_cached_registry_sessions(g, "SOFTWARE\\SimonTatham\\PuTTY\\Sessions", "PuTTY", "ProxyPassword", "HostName", "UserName");
    {
        char *appdata = ph_environment_value("APPDATA"); char path[4096];
        if (appdata) {
            ph_copy_local(path, sizeof(path), appdata); ph_append_local(path, sizeof(path), "\\FileZilla\\sitemanager.xml"); ph_collect_filezilla_file(g, path);
            ph_copy_local(path, sizeof(path), appdata); ph_append_local(path, sizeof(path), "\\FileZilla\\recentservers.xml"); ph_collect_filezilla_file(g, path);
            HeapFree(GetProcessHeap(), 0, appdata);
        }
    }
    ph_collect_wifi_profiles(g);
}

void ph_collect_webclient_relay(PH_GRAPH *g) {
    char *domain; DWORD state = 0, start = 0xffffffffu, ldap = 0; BOOL has_ldap;
    if (!g) return;
    domain = ph_reg_string(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Domain");
    if (!domain || !domain[0] || !ph_query_service("WebClient", &state, &start)) { if (domain) HeapFree(GetProcessHeap(), 0, domain); return; }
    has_ldap = ph_reg_dword(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\LDAP", "LDAPClientIntegrity", &ldap);
    if (!has_ldap) has_ldap = ph_reg_dword(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LDAP", "LDAPClientIntegrity", &ldap);
    if (start == SERVICE_DISABLED && has_ldap && ldap == 2) { HeapFree(GetProcessHeap(), 0, domain); return; }
    {
        char nid[33], props[4096], edge_props[2048], node_name[512], finding[4096]; PH_JSON p, ep;
        const char *signing = (has_ldap && ldap == 2) ? "required" : "not enforced";
        const char *severity = (start != SERVICE_DISABLED && !(has_ldap && ldap == 2)) ? "CRITICAL" : "MEDIUM";
        ph_id(g, "webclientrelay", g->hostname, nid); ph_copy_local(node_name, sizeof(node_name), "WebClientRelay@"); ph_append_local(node_name, sizeof(node_name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p); ph_json_add_string(&p, "name", node_name); ph_json_add_string(&p, "hostname", g->hostname); ph_json_add_string(&p, "domain", domain); ph_json_add_string(&p, "webclient_start", ph_start_mode(start)); ph_json_add_string(&p, "webclient_status", ph_service_state(state)); ph_json_add_string(&p, "ldap_signing", signing); ph_json_end_object(&p); ph_emit_node(g, nid, "[\"PHWebClientRelay\"]", props);
        ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep); ph_json_add_string(&ep, "mitre", "T1187"); ph_json_add_string(&ep, "start_type", ph_start_mode(start)); ph_json_add_string(&ep, "ldap_signing", signing); ph_json_end_object(&ep); ph_emit_edge(g, g->current_user_id, nid, "PHCanRelayWebClient", edge_props); ph_emit_edge(g, nid, g->system_id, "PHEscalatesTo", "{\"method\":\"NTLM relay preconditions observed; exploitability unverified\"}");
        ph_copy_local(finding, sizeof(finding), "WebClient relay preconditions observed; start mode "); ph_append_local(finding, sizeof(finding), ph_start_mode(start)); ph_append_local(finding, sizeof(finding), ", LDAP signing "); ph_append_local(finding, sizeof(finding), signing); ph_emit_finding(g, "WebClientRelay", severity, finding, "Validate relay protections and disable WebClient where unnecessary");
    }
    HeapFree(GetProcessHeap(), 0, domain);
}

typedef struct _PH_DISCOVERED_CRED {
    char *source;
    char *username;
    char *password;
    char source_node_id[33];
    struct _PH_DISCOVERED_CRED *next;
} PH_DISCOVERED_CRED;

static char *ph_secret_copy(const char *value) {
    int length; char *copy; volatile char *write;
    if (!value || !value[0]) return NULL;
    length = ph_len(value); copy = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, length + 1);
    if (!copy) return NULL;
    write = copy; for (int i = 0; i < length; i++) write[i] = value[i];
    return copy;
}

static void ph_add_credential(PH_DISCOVERED_CRED **head, const char *source, const char *username, const char *password, const char *source_node_id) {
    PH_DISCOVERED_CRED *credential;
    if (!head || !password || !password[0] || !source_node_id || !source_node_id[0]) return;
    credential = (PH_DISCOVERED_CRED *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*credential));
    if (!credential) return;
    credential->source = ph_secret_copy(source ? source : "Unknown");
    credential->username = ph_secret_copy(username ? username : "");
    credential->password = ph_secret_copy(password);
    ph_copy_local(credential->source_node_id, sizeof(credential->source_node_id), source_node_id);
    if (!credential->source || !credential->password) {
        if (credential->source) HeapFree(GetProcessHeap(), 0, credential->source);
        if (credential->username) HeapFree(GetProcessHeap(), 0, credential->username);
        if (credential->password) { ph_zero(credential->password, ph_len(credential->password)); HeapFree(GetProcessHeap(), 0, credential->password); }
        HeapFree(GetProcessHeap(), 0, credential); return;
    }
    credential->next = *head; *head = credential;
}

static void ph_free_credentials(PH_DISCOVERED_CRED *head) {
    while (head) {
        PH_DISCOVERED_CRED *next = head->next;
        if (head->source) HeapFree(GetProcessHeap(), 0, head->source);
        if (head->username) HeapFree(GetProcessHeap(), 0, head->username);
        if (head->password) { ph_zero(head->password, ph_len(head->password)); HeapFree(GetProcessHeap(), 0, head->password); }
        ph_zero(head, sizeof(*head)); HeapFree(GetProcessHeap(), 0, head); head = next;
    }
}

static void ph_copy_span(const char *start, const char *end, char *out, int capacity) {
    int length; volatile char *write = out;
    if (!out || capacity <= 0) return; out[0] = 0;
    if (!start || !end || end <= start) return;
    length = (int)(end - start); if (length >= capacity) length = capacity - 1;
    for (int i = 0; i < length; i++) write[i] = start[i]; write[length] = 0;
    ph_trim_text(out); ph_trim_path(out);
}

static void ph_collect_history_credentials(PH_GRAPH *g, PH_DISCOVERED_CRED **head, const char *path) {
    char *text; const char *cursor;
    if (!g || !head || !ph_file_exists(path)) return;
    text = ph_read_text_file(path); if (!text) return;
    cursor = text;
    while ((cursor = ph_find_ci(cursor, "/user:")) != NULL) {
        const char *user_start = cursor + 6, *user_end = user_start, *pass_start, *pass_end;
        char username[512], password[1024], source_id[33];
        while (*user_end && *user_end != ' ' && *user_end != '\t' && *user_end != '\r' && *user_end != '\n') user_end++;
        pass_start = user_end; while (*pass_start == ' ' || *pass_start == '\t') pass_start++;
        pass_end = pass_start;
        if (*pass_start == '"' || *pass_start == '\'') { char quote = *pass_start++; pass_end = pass_start; while (*pass_end && *pass_end != quote && *pass_end != '\r' && *pass_end != '\n') pass_end++; }
        else while (*pass_end && *pass_end != ' ' && *pass_end != '\t' && *pass_end != '\r' && *pass_end != '\n') pass_end++;
        ph_copy_span(user_start, user_end, username, sizeof(username)); ph_copy_span(pass_start, pass_end, password, sizeof(password));
        if (username[0] && password[0]) {
            ph_emit_sensitive_file(g, path, "PowerShell history credential source");
            ph_id(g, "sensfile", path, source_id); ph_add_credential(head, "PSHistory", username, password, source_id);
        }
        cursor = pass_end;
    }
    ph_zero(text, ph_len(text)); HeapFree(GetProcessHeap(), 0, text);
}

static BOOL ph_xml_attribute(const char *text, const char *attribute, char *out, int capacity) {
    char needle[128]; const char *start, *end;
    if (!out || capacity <= 0) return FALSE; out[0] = 0;
    ph_copy_local(needle, sizeof(needle), attribute); ph_append_local(needle, sizeof(needle), "=\"");
    start = ph_find_ci(text, needle); if (!start) return FALSE; start += ph_len(needle);
    end = start; while (*end && *end != '"' && *end != '\r' && *end != '\n') end++;
    ph_copy_span(start, end, out, capacity); return out[0] != 0;
}

static unsigned char *ph_base64_decode(const char *encoded, DWORD *decoded_size) {
    char *padded; unsigned char *decoded = NULL; DWORD size = 0; int length, padded_length;
    if (decoded_size) *decoded_size = 0; if (!encoded || !encoded[0]) return NULL;
    length = ph_len(encoded); padded_length = length; while ((padded_length % 4) != 0) padded_length++;
    padded = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, padded_length + 1); if (!padded) return NULL;
    { volatile char *write = padded; for (int i = 0; i < length; i++) write[i] = encoded[i]; for (int i = length; i < padded_length; i++) write[i] = '='; }
    if (!CryptStringToBinaryA(padded, padded_length, CRYPT_STRING_BASE64, NULL, &size, NULL, NULL) || !size) goto done;
    decoded = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 2); if (!decoded) goto done;
    if (!CryptStringToBinaryA(padded, padded_length, CRYPT_STRING_BASE64, decoded, &size, NULL, NULL)) { HeapFree(GetProcessHeap(), 0, decoded); decoded = NULL; goto done; }
    if (decoded_size) *decoded_size = size;
done:
    ph_zero(padded, padded_length); HeapFree(GetProcessHeap(), 0, padded); return decoded;
}

static void ph_decoded_text(const unsigned char *bytes, DWORD size, char *out, int capacity) {
    int written = 0; BOOL unicode;
    if (!out || capacity <= 0) return; out[0] = 0; if (!bytes || !size) return;
    unicode = size >= 2 && bytes[1] == 0;
    if (unicode) {
        for (DWORD i = 0; i + 1 < size && written + 1 < capacity; i += 2) out[written++] = bytes[i] ? (char)bytes[i] : 0;
    } else {
        for (DWORD i = 0; i < size && written + 1 < capacity; i++) out[written++] = (char)bytes[i];
    }
    out[written] = 0;
}

static BOOL ph_decrypt_gpp(const char *cpassword, char *out, int capacity) {
    static const unsigned char aes_key[32] = {0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b};
    HCRYPTPROV provider = 0; HCRYPTKEY key = 0; unsigned char *cipher = NULL; DWORD cipher_size = 0; BYTE blob[sizeof(BLOBHEADER) + sizeof(DWORD) + 32]; BLOBHEADER *header = (BLOBHEADER *)blob; DWORD *key_size = (DWORD *)(blob + sizeof(BLOBHEADER)); BOOL result = FALSE;
    if (!out || capacity <= 0) return FALSE; out[0] = 0;
    cipher = ph_base64_decode(cpassword, &cipher_size); if (!cipher || !cipher_size) goto done;
    ph_zero(blob, sizeof(blob)); header->bType = PLAINTEXTKEYBLOB; header->bVersion = CUR_BLOB_VERSION; header->aiKeyAlg = CALG_AES_256; *key_size = 32;
    { volatile BYTE *write = blob + sizeof(BLOBHEADER) + sizeof(DWORD); for (int i = 0; i < 32; i++) write[i] = aes_key[i]; }
    if (!CryptAcquireContextA(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) goto done;
    if (!CryptImportKey(provider, blob, sizeof(blob), 0, 0, &key)) goto done;
    if (!CryptDecrypt(key, 0, TRUE, 0, cipher, &cipher_size)) goto done;
    ph_decoded_text(cipher, cipher_size, out, capacity); result = out[0] != 0;
done:
    ph_zero(blob, sizeof(blob)); if (cipher) { ph_zero(cipher, cipher_size); HeapFree(GetProcessHeap(), 0, cipher); } if (key) CryptDestroyKey(key); if (provider) CryptReleaseContext(provider, 0); return result;
}

static void ph_collect_gpp_credentials_file(PH_GRAPH *g, PH_DISCOVERED_CRED **head, const char *path, const char *name) {
    char *text, cpassword[4096], username[1024], password[2048], source_id[33];
    if (!ph_is_gpp_name(name) || !ph_file_exists(path)) return;
    text = ph_read_text_file(path); if (!text) return;
    if (ph_xml_attribute(text, "cpassword", cpassword, sizeof(cpassword)) && ph_decrypt_gpp(cpassword, password, sizeof(password))) {
        username[0] = 0; ph_xml_attribute(text, "userName", username, sizeof(username)); ph_id(g, "gpp", path, source_id); ph_add_credential(head, "GPP", username, password, source_id); ph_zero(password, sizeof(password));
    }
    ph_zero(text, ph_len(text)); HeapFree(GetProcessHeap(), 0, text);
}

static void ph_walk_gpp_credentials(PH_GRAPH *g, PH_DISCOVERED_CRED **head, const char *directory, int depth) {
    char pattern[4096]; WIN32_FIND_DATAA data; HANDLE find;
    if (!g || !head || !directory || depth > 16) return;
    ph_copy_local(pattern, sizeof(pattern), directory); ph_append_local(pattern, sizeof(pattern), "\\*"); find = FindFirstFileA(pattern, &data); if (find == INVALID_HANDLE_VALUE) return;
    do {
        char child[4096]; if (ph_equal_ci(data.cFileName, ".") || ph_equal_ci(data.cFileName, "..")) continue;
        ph_copy_local(child, sizeof(child), directory); ph_append_local(child, sizeof(child), "\\"); ph_append_local(child, sizeof(child), data.cFileName);
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) ph_walk_gpp_credentials(g, head, child, depth + 1);
        else if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) ph_collect_gpp_credentials_file(g, head, child, data.cFileName);
    } while (FindNextFileA(find, &data)); FindClose(find);
}

static void ph_collect_unattend_credential(PH_GRAPH *g, PH_DISCOVERED_CRED **head, const char *path) {
    char *text; const char *password_section; char value[4096], plain[64], username[1024], password[4096], lowered[4096], source_id[33];
    if (!ph_file_exists(path)) return; text = ph_read_text_file(path); if (!text) return;
    password_section = ph_find_ci(text, "<Password"); if (!password_section) password_section = ph_find_ci(text, "<AdministratorPassword");
    if (password_section && ph_xml_value(password_section, "Value", value, sizeof(value))) {
        plain[0] = username[0] = password[0] = 0; ph_xml_value(password_section, "PlainText", plain, sizeof(plain)); ph_xml_value(text, "Username", username, sizeof(username));
        if (!username[0] && ph_find_ci(password_section, "<AdministratorPassword")) ph_copy_local(username, sizeof(username), "Administrator");
        if (ph_equal_ci(plain, "false")) {
            DWORD decoded_size = 0; unsigned char *decoded = ph_base64_decode(value, &decoded_size); if (decoded) { ph_decoded_text(decoded, decoded_size, password, sizeof(password)); ph_zero(decoded, decoded_size); HeapFree(GetProcessHeap(), 0, decoded); }
        } else ph_copy_local(password, sizeof(password), value);
        if (password[0]) { ph_lower_path(path, lowered, sizeof(lowered)); ph_id(g, "unattend", lowered, source_id); ph_add_credential(head, "Unattend", username, password, source_id); ph_zero(password, sizeof(password)); }
    }
    ph_zero(text, ph_len(text)); HeapFree(GetProcessHeap(), 0, text);
}

static void ph_collect_git_credential(PH_GRAPH *g, PH_DISCOVERED_CRED **head, const char *path) {
    char *text; const char *scheme, *colon, *at; char username[1024], password[2048], source_id[33];
    if (!ph_file_exists(path)) return; text = ph_read_text_file(path); if (!text) return;
    scheme = ph_find_ci(text, "://"); if (scheme) { scheme += 3; colon = scheme; while (*colon && *colon != ':' && *colon != '@' && *colon != '\r' && *colon != '\n') colon++; at = colon; while (*at && *at != '@' && *at != '\r' && *at != '\n') at++;
        if (*colon == ':' && *at == '@') { ph_copy_span(scheme, colon, username, sizeof(username)); ph_copy_span(colon + 1, at, password, sizeof(password)); ph_id(g, "sensfile", path, source_id); ph_add_credential(head, "GitCredentials", username, password, source_id); ph_zero(password, sizeof(password)); }
    }
    ph_zero(text, ph_len(text)); HeapFree(GetProcessHeap(), 0, text);
}

static void ph_collect_filezilla_credential(PH_GRAPH *g, PH_DISCOVERED_CRED **head, const char *path) {
    char *text; char host[1024], username[1024], value[4096], password[4096], id_name[2048], source_id[33]; const char *pass_start;
    if (!ph_file_exists(path)) return; text = ph_read_text_file(path); if (!text) return;
    host[0] = username[0] = value[0] = password[0] = 0; ph_xml_value(text, "Host", host, sizeof(host)); ph_xml_value(text, "User", username, sizeof(username)); pass_start = ph_find_ci(text, "<Pass");
    if (pass_start && ph_xml_value(ph_find_ci(pass_start, ">") ? ph_find_ci(pass_start, ">") + 1 : pass_start, "Pass", value, sizeof(value))) ph_copy_local(password, sizeof(password), value);
    if (!password[0] && pass_start) {
        const char *content = ph_find_ci(pass_start, ">"); const char *end = content ? ph_find_ci(content + 1, "</Pass>") : NULL; if (content && end) { ph_copy_span(content + 1, end, value, sizeof(value)); if (ph_find_ci(pass_start, "encoding=\"base64\"") && ph_find_ci(pass_start, "encoding=\"base64\"") < content) { DWORD size = 0; unsigned char *decoded = ph_base64_decode(value, &size); if (decoded) { ph_decoded_text(decoded, size, password, sizeof(password)); ph_zero(decoded, size); HeapFree(GetProcessHeap(), 0, decoded); } } else ph_copy_local(password, sizeof(password), value); }
    }
    if (password[0]) { ph_copy_local(id_name, sizeof(id_name), "FileZilla_"); ph_append_local(id_name, sizeof(id_name), host[0] ? host : ph_last_component(path)); ph_id(g, "cachedcreds", id_name, source_id); ph_add_credential(head, "FileZilla", username, password, source_id); ph_zero(password, sizeof(password)); }
    ph_zero(text, ph_len(text)); HeapFree(GetProcessHeap(), 0, text);
}

static void ph_collect_active_credential_sources(PH_GRAPH *g, PH_DISCOVERED_CRED **head) {
    const char *winlogon = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    char *password = ph_reg_string(HKEY_LOCAL_MACHINE, winlogon, "DefaultPassword");
    if (password && password[0]) {
        char *username = ph_reg_string(HKEY_LOCAL_MACHINE, winlogon, "DefaultUserName"); char source_id[33];
        ph_id(g, "cred", "autologon", source_id); ph_add_credential(head, "AutoLogon", username, password, source_id);
        if (username) HeapFree(GetProcessHeap(), 0, username);
    }
    if (password) { ph_zero(password, ph_len(password)); HeapFree(GetProcessHeap(), 0, password); }
    {
        char *program_data = ph_environment_value("ProgramData"), *system_root = ph_environment_value("SystemRoot"), *system_drive = ph_environment_value("SystemDrive"), *appdata = ph_environment_value("APPDATA"); char path[4096];
        if (program_data) { ph_copy_local(path, sizeof(path), program_data); ph_append_local(path, sizeof(path), "\\Microsoft\\Group Policy\\History"); ph_walk_gpp_credentials(g, head, path, 0); HeapFree(GetProcessHeap(), 0, program_data); }
        if (system_drive) { ph_copy_local(path, sizeof(path), system_drive); ph_append_local(path, sizeof(path), "\\unattend.xml"); ph_collect_unattend_credential(g, head, path); HeapFree(GetProcessHeap(), 0, system_drive); }
        if (system_root) {
            ph_copy_local(path, sizeof(path), system_root); ph_append_local(path, sizeof(path), "\\SYSVOL"); ph_walk_gpp_credentials(g, head, path, 0);
            ph_copy_local(path, sizeof(path), system_root); ph_append_local(path, sizeof(path), "\\Panther\\unattend.xml"); ph_collect_unattend_credential(g, head, path);
            ph_copy_local(path, sizeof(path), system_root); ph_append_local(path, sizeof(path), "\\Panther\\Unattend\\unattend.xml"); ph_collect_unattend_credential(g, head, path);
            ph_copy_local(path, sizeof(path), system_root); ph_append_local(path, sizeof(path), "\\system32\\sysprep\\unattend.xml"); ph_collect_unattend_credential(g, head, path);
            ph_copy_local(path, sizeof(path), system_root); ph_append_local(path, sizeof(path), "\\system32\\sysprep\\sysprep.xml"); ph_collect_unattend_credential(g, head, path);
            ph_copy_local(path, sizeof(path), system_root); ph_append_local(path, sizeof(path), "\\system32\\sysprep\\Panther\\unattend.xml"); ph_collect_unattend_credential(g, head, path); HeapFree(GetProcessHeap(), 0, system_root);
        }
        if (appdata) {
            ph_copy_local(path, sizeof(path), appdata); ph_append_local(path, sizeof(path), "\\FileZilla\\sitemanager.xml"); ph_collect_filezilla_credential(g, head, path);
            ph_copy_local(path, sizeof(path), appdata); ph_append_local(path, sizeof(path), "\\FileZilla\\recentservers.xml"); ph_collect_filezilla_credential(g, head, path); HeapFree(GetProcessHeap(), 0, appdata);
        }
    }
    {
        char *profiles = ph_reg_string(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", "ProfilesDirectory");
        char *system_drive = NULL, users_dir[4096], expanded[4096], pattern[4096]; WIN32_FIND_DATAA data; HANDLE find;
        if (profiles) {
            DWORD needed = ExpandEnvironmentStringsA(profiles, expanded, sizeof(expanded)); ph_copy_local(users_dir, sizeof(users_dir), (needed && needed <= sizeof(expanded)) ? expanded : profiles); HeapFree(GetProcessHeap(), 0, profiles);
        } else { system_drive = ph_environment_value("SystemDrive"); ph_copy_local(users_dir, sizeof(users_dir), system_drive ? system_drive : "C:"); ph_append_local(users_dir, sizeof(users_dir), "\\Users"); if (system_drive) HeapFree(GetProcessHeap(), 0, system_drive); }
        ph_copy_local(pattern, sizeof(pattern), users_dir); ph_append_local(pattern, sizeof(pattern), "\\*"); find = FindFirstFileA(pattern, &data);
        if (find != INVALID_HANDLE_VALUE) {
            do {
                char history[4096], git[4096];
                if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || ph_equal_ci(data.cFileName, ".") || ph_equal_ci(data.cFileName, "..")) continue;
                ph_copy_local(history, sizeof(history), users_dir); ph_append_local(history, sizeof(history), "\\"); ph_append_local(history, sizeof(history), data.cFileName); ph_append_local(history, sizeof(history), "\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt");
                ph_collect_history_credentials(g, head, history);
                ph_copy_local(git, sizeof(git), users_dir); ph_append_local(git, sizeof(git), "\\"); ph_append_local(git, sizeof(git), data.cFileName); ph_append_local(git, sizeof(git), "\\.git-credentials"); ph_collect_git_credential(g, head, git);
            } while (FindNextFileA(find, &data));
            FindClose(find);
        }
    }
}

static void ph_wide_ascii(const wchar_t *value, char *out, int capacity) {
    int at = 0; volatile char *write = out; if (!out || capacity <= 0) return; write[0] = 0; if (!value) return;
    while (value[at] && at + 1 < capacity) { write[at] = value[at] <= 0x7f ? (char)value[at] : '?'; at++; } write[at] = 0;
}

static BOOL ph_token_identity(HANDLE token, char *sid, int sid_capacity, BOOL *is_admin) {
    DWORD needed = 0, sid_size = SECURITY_MAX_SID_SIZE; TOKEN_USER *user = NULL; BYTE admin_sid[SECURITY_MAX_SID_SIZE]; LPSTR sid_text = NULL; BOOL member = FALSE;
    if (sid && sid_capacity > 0) sid[0] = 0; if (is_admin) *is_admin = FALSE; if (!token) return FALSE;
    GetTokenInformation(token, TokenUser, NULL, 0, &needed); if (!needed) return FALSE;
    user = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!user || !GetTokenInformation(token, TokenUser, user, needed, &needed)) { if (user) HeapFree(GetProcessHeap(), 0, user); return FALSE; }
    if (sid && ConvertSidToStringSidA(user->User.Sid, &sid_text)) { ph_copy_local(sid, sid_capacity, sid_text); LocalFree((HLOCAL)sid_text); }
    if (is_admin && CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admin_sid, &sid_size) && CheckTokenMembership(token, admin_sid, &member)) *is_admin = member;
    HeapFree(GetProcessHeap(), 0, user); return TRUE;
}

static void ph_collect_as_validated_user(PH_GRAPH *g, const char *local_user_id, HANDLE token) {
    char saved_id[33]; BOOL saved_admin, saved_context;
    if (!g || !local_user_id || !token || !ImpersonateLoggedOnUser(token)) return;
    ph_copy_local(saved_id, sizeof(saved_id), g->current_user_id); saved_admin = g->is_admin; saved_context = g->credential_context;
    ph_copy_local(g->current_user_id, sizeof(g->current_user_id), local_user_id); g->is_admin = FALSE; g->credential_context = TRUE;
    ph_collect_token_privileges(g); ph_collect_services(g); ph_collect_unquoted_service_paths(g); ph_collect_writable_path(g);
    ph_collect_scheduled_tasks(g); ph_collect_autoruns(g); ph_collect_service_registry_keys(g); ph_collect_writable_program_dirs(g); ph_collect_service_recovery(g);
    ph_copy_local(g->current_user_id, sizeof(g->current_user_id), saved_id); g->is_admin = saved_admin; g->credential_context = saved_context; RevertToSelf();
}

static void ph_validate_credential_for_user(PH_GRAPH *g, PH_DISCOVERED_CRED *credential, const char *username) {
    HANDLE token = NULL;
    if (!g || !credential || !username || !username[0] || !LogonUserA(username, ".", credential->password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &token)) return;
    {
        char sid[192], local_id[33], props[4096], edge_props[2048], node_name[1024], finding[2048]; BOOL is_admin = FALSE; PH_JSON p, ep;
        ph_token_identity(token, sid, sizeof(sid), &is_admin); ph_id(g, "localuser", username, local_id);
        ph_copy_local(node_name, sizeof(node_name), "LOCALUSER:"); ph_append_local(node_name, sizeof(node_name), username); ph_append_local(node_name, sizeof(node_name), "@"); ph_append_local(node_name, sizeof(node_name), g->hostname);
        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p); ph_json_add_string(&p, "name", node_name); ph_json_add_string(&p, "username", username); if (sid[0]) ph_json_add_string(&p, "sid", sid); ph_json_add_bool(&p, "is_admin", is_admin); ph_json_add_bool(&p, "credential_validated", TRUE); ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p); ph_emit_node(g, local_id, "[\"PHLocalUser\"]", props);
        ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep); ph_json_add_string(&ep, "source_type", credential->source); ph_json_add_string(&ep, "mitre", "T1078.003"); ph_json_add_bool(&ep, "tested", TRUE); ph_json_add_bool(&ep, "password_reuse", credential->username && credential->username[0] && !ph_equal_ci(username, credential->username)); ph_json_end_object(&ep); ph_emit_edge(g, credential->source_node_id, local_id, "PHCanLoginAs", edge_props);
        if (is_admin) ph_emit_edge(g, local_id, g->admin_id, "PHMemberOf", "{\"group\":\"BUILTIN\\\\Administrators\"}");
        ph_copy_local(finding, sizeof(finding), credential->source); ph_append_local(finding, sizeof(finding), " credential validated for local user '"); ph_append_local(finding, sizeof(finding), username); ph_append_local(finding, sizeof(finding), "' (secret not emitted)"); ph_emit_finding(g, "CredLogin", "CRITICAL", finding, "Rotate the exposed credential and review authentication logs");
        ph_collect_as_validated_user(g, local_id, token);
    }
    CloseHandle(token);
}

void ph_collect_credential_login_paths(PH_GRAPH *g) {
    PH_DISCOVERED_CRED *credentials = NULL, *credential;
    if (!g || !g->validate_credentials) return;
    ph_collect_active_credential_sources(g, &credentials);
    for (credential = credentials; credential; credential = credential->next) {
        if (credential->username && credential->username[0]) ph_validate_credential_for_user(g, credential, credential->username);
        if (g->spray_credentials) {
            DWORD resume = 0;
            do {
                LPUSER_INFO_1 buffer = NULL; DWORD entries = 0, total = 0;
                NET_API_STATUS status = NetUserEnum(NULL, 1, FILTER_NORMAL_ACCOUNT, (LPBYTE *)&buffer, MAX_PREFERRED_LENGTH, &entries, &total, &resume);
                if ((status != NERR_Success && status != ERROR_MORE_DATA) || !buffer) break;
                for (DWORD i = 0; i < entries; i++) {
                    char username[512]; ph_wide_ascii(buffer[i].usri1_name, username, sizeof(username));
                    if (!(buffer[i].usri1_flags & UF_ACCOUNTDISABLE) && username[0] && (!credential->username || !ph_equal_ci(username, credential->username))) ph_validate_credential_for_user(g, credential, username);
                }
                NetApiBufferFree(buffer); if (status == NERR_Success) break;
            } while (resume != 0);
        }
    }
    ph_free_credentials(credentials);
}

typedef struct _PH_WMI_SESSION {
    IWbemServices *services;
    BOOL uninitialize;
} PH_WMI_SESSION;

static const GUID PH_CLSID_WBEM_LOCATOR = {0x4590f811, 0x1d3a, 0x11d0, {0x89,0x1f,0x00,0xaa,0x00,0x4b,0x2e,0x24}};
static const GUID PH_IID_IWBEM_LOCATOR = {0xdc12a687, 0x737f, 0x11cf, {0x88,0x4d,0x00,0xaa,0x00,0x4b,0x2e,0x24}};

static BOOL ph_wmi_connect(const wchar_t *namespace_name, PH_WMI_SESSION *session) {
    HRESULT hr;
    IWbemLocator *locator = NULL;
    BSTR namespace_bstr = NULL;
    if (!namespace_name || !session) return FALSE;
    ph_zero(session, sizeof(*session));
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) session->uninitialize = TRUE;
    else if (hr != RPC_E_CHANGED_MODE) return FALSE;
    hr = CoCreateInstance(&PH_CLSID_WBEM_LOCATOR, NULL, CLSCTX_INPROC_SERVER, &PH_IID_IWBEM_LOCATOR, (void **)&locator);
    if (FAILED(hr) || !locator) goto fail;
    namespace_bstr = SysAllocString(namespace_name);
    if (!namespace_bstr) goto fail;
    hr = locator->lpVtbl->ConnectServer(locator, namespace_bstr, NULL, NULL, NULL, 0, NULL, NULL, &session->services);
    SysFreeString(namespace_bstr); namespace_bstr = NULL;
    locator->lpVtbl->Release(locator); locator = NULL;
    if (FAILED(hr) || !session->services) goto fail;
    hr = CoSetProxyBlanket((IUnknown *)session->services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr)) goto fail;
    return TRUE;
fail:
    if (namespace_bstr) SysFreeString(namespace_bstr);
    if (locator) locator->lpVtbl->Release(locator);
    if (session->services) { session->services->lpVtbl->Release(session->services); session->services = NULL; }
    if (session->uninitialize) { CoUninitialize(); session->uninitialize = FALSE; }
    return FALSE;
}

static void ph_wmi_close(PH_WMI_SESSION *session) {
    if (!session) return;
    if (session->services) session->services->lpVtbl->Release(session->services);
    if (session->uninitialize) CoUninitialize();
    ph_zero(session, sizeof(*session));
}

static IEnumWbemClassObject *ph_wmi_query(PH_WMI_SESSION *session, const wchar_t *query) {
    BSTR language = NULL, query_bstr = NULL;
    IEnumWbemClassObject *enumerator = NULL;
    HRESULT hr;
    if (!session || !session->services || !query) return NULL;
    language = SysAllocString(L"WQL"); query_bstr = SysAllocString(query);
    if (!language || !query_bstr) goto done;
    hr = session->services->lpVtbl->ExecQuery(session->services, language, query_bstr,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &enumerator);
    if (FAILED(hr)) enumerator = NULL;
done:
    if (query_bstr) SysFreeString(query_bstr); if (language) SysFreeString(language);
    return enumerator;
}

static IWbemClassObject *ph_wmi_next(IEnumWbemClassObject *enumerator) {
    IWbemClassObject *object = NULL; ULONG returned = 0;
    if (!enumerator) return NULL;
    if (FAILED(enumerator->lpVtbl->Next(enumerator, 3000, 1, &object, &returned)) || returned != 1) return NULL;
    return object;
}

static BOOL ph_wmi_string(IWbemClassObject *object, const wchar_t *property, char *out, int capacity) {
    VARIANT value; HRESULT hr; int written = 0;
    if (!out || capacity <= 0) return FALSE; out[0] = 0;
    if (!object || !property) return FALSE;
    ph_zero(&value, sizeof(value)); hr = object->lpVtbl->Get(object, property, 0, &value, NULL, NULL);
    if (SUCCEEDED(hr) && value.vt == VT_BSTR && value.bstrVal) {
        while (value.bstrVal[written] && written + 1 < capacity) {
            wchar_t c = value.bstrVal[written]; out[written] = c <= 0x7f ? (char)c : '?'; written++;
        }
        out[written] = 0;
    }
    VariantClear(&value); return out[0] != 0;
}

static BOOL ph_wmi_has_instance(const wchar_t *namespace_name, const wchar_t *query) {
    PH_WMI_SESSION session; IEnumWbemClassObject *enumerator; IWbemClassObject *object; BOOL found = FALSE;
    if (!ph_wmi_connect(namespace_name, &session)) return FALSE;
    enumerator = ph_wmi_query(&session, query);
    object = ph_wmi_next(enumerator);
    if (object) { found = TRUE; object->lpVtbl->Release(object); }
    if (enumerator) enumerator->lpVtbl->Release(enumerator); ph_wmi_close(&session); return found;
}

static void ph_emit_sccm_source(PH_GRAPH *g, const char *id_name, const char *source, const char *description) {
    char nid[33], props[4096], edge_props[1024], node_name[512], finding[2048]; PH_JSON p, ep;
    ph_id(g, "sccmcred", id_name, nid); ph_copy_local(node_name, sizeof(node_name), "SCCM:"); ph_append_local(node_name, sizeof(node_name), id_name); ph_append_local(node_name, sizeof(node_name), "@"); ph_append_local(node_name, sizeof(node_name), g->hostname);
    ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p); ph_json_add_string(&p, "name", node_name); ph_json_add_string(&p, "hostname", g->hostname); ph_json_add_string(&p, "source", source); ph_json_add_string(&p, "description", description); ph_json_add_bool(&p, "credential_presence_verified", FALSE); ph_json_add_bool(&p, "secret_emitted", FALSE); ph_json_end_object(&p); ph_emit_node(g, nid, "[\"PHSCCMCredential\"]", props);
    ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep); ph_json_add_string(&ep, "mitre", "T1552.001"); ph_json_add_string(&ep, "source", source); ph_json_add_bool(&ep, "secret_emitted", FALSE); ph_json_end_object(&ep); ph_emit_edge(g, g->current_user_id, nid, "PHCanReadNAA", edge_props);
    ph_copy_local(finding, sizeof(finding), description); ph_append_local(finding, sizeof(finding), "; embedded credentials are unverified and not emitted"); ph_emit_finding(g, "SCCM", "MEDIUM", finding, "Review the policy under authorized conditions before attempting decryption");
}

void ph_collect_sccm_credentials(PH_GRAPH *g) {
    DWORD state = 0, start = 0xffffffffu;
    if (!g || (!ph_reg_key_exists(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\CCMSetup") && !ph_query_service("CcmExec", &state, &start))) return;
    if (ph_wmi_has_instance(L"ROOT\\ccm\\policy\\Machine\\ActualConfig", L"SELECT * FROM CCM_NetworkAccessAccount"))
        ph_emit_sccm_source(g, "NAA", "CCM_NetworkAccessAccount", "SCCM Network Access Account policy found in WMI");
    if (ph_wmi_has_instance(L"ROOT\\ccm\\Policy\\Machine", L"SELECT * FROM CCM_TaskSequence"))
        ph_emit_sccm_source(g, "TaskSequence", "CCM_TaskSequence", "SCCM task-sequence policy found in WMI");
}

void ph_collect_wmi_subscriptions(PH_GRAPH *g) {
    PH_WMI_SESSION session; IEnumWbemClassObject *enumerator; IWbemClassObject *object;
    if (!g || !ph_wmi_connect(L"ROOT\\subscription", &session)) return;
    enumerator = ph_wmi_query(&session, L"SELECT * FROM __EventConsumer");
    while ((object = ph_wmi_next(enumerator)) != NULL) {
        char type[512], name[1024], binary[4096], command[4096];
        type[0] = name[0] = binary[0] = command[0] = 0;
        ph_wmi_string(object, L"__CLASS", type, sizeof(type)); ph_wmi_string(object, L"Name", name, sizeof(name));
        if (ph_equal_ci(type, "CommandLineEventConsumer")) {
            ph_wmi_string(object, L"ExecutablePath", binary, sizeof(binary));
            if (!binary[0] && ph_wmi_string(object, L"CommandLineTemplate", command, sizeof(command))) ph_expand_executable(command, binary, sizeof(binary));
        } else if (ph_equal_ci(type, "ActiveScriptEventConsumer")) ph_wmi_string(object, L"ScriptFileName", binary, sizeof(binary));
        if (name[0] && binary[0]) {
            char expanded[4096], parent[4096]; BOOL writable;
            ph_expand_executable(binary, expanded, sizeof(expanded)); ph_parent_path(expanded, parent, sizeof(parent));
            writable = ph_file_exists(expanded) ? ph_file_is_writable(expanded) : (parent[0] && ph_directory_exists(parent) && ph_file_allows(parent, FILE_ADD_FILE));
            if (writable) {
                char nid[33], props[8192], edge_props[1024], node_name[2048], finding[4096]; PH_JSON p, ep;
                ph_id(g, "wmisub", name, nid); ph_copy_local(node_name, sizeof(node_name), "WMI:"); ph_append_local(node_name, sizeof(node_name), name); ph_append_local(node_name, sizeof(node_name), "@"); ph_append_local(node_name, sizeof(node_name), g->hostname);
                ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p); ph_json_add_string(&p, "name", node_name); ph_json_add_string(&p, "consumer_name", name); ph_json_add_string(&p, "consumer_type", type); ph_json_add_string(&p, "binary_path", expanded); ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p); ph_emit_node(g, nid, "[\"PHWMISubscription\"]", props);
                ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep); ph_json_add_string(&ep, "mitre", "T1546.003"); ph_json_add_string(&ep, "consumer", name); ph_json_end_object(&ep); ph_emit_edge(g, g->current_user_id, nid, "PHCanModifyWMI", edge_props); ph_emit_edge(g, nid, g->system_id, "PHRunsAs", "{\"run_account\":\"SYSTEM\"}");
                ph_copy_local(finding, sizeof(finding), "Writable WMI consumer '"); ph_append_local(finding, sizeof(finding), name); ph_append_local(finding, sizeof(finding), "': "); ph_append_local(finding, sizeof(finding), expanded); ph_emit_finding(g, "WMISub", "HIGH", finding, "Review and correct the consumer binary or script ACL");
            }
        }
        object->lpVtbl->Release(object);
    }
    if (enumerator) enumerator->lpVtbl->Release(enumerator); ph_wmi_close(&session);
}

static void ph_shadow_sensitive(PH_GRAPH *g, const char *shadow_path, const char *shadow_id, const char *relative_path, char out_file_id[33]) {
    char full[4096], props[8192], edge_props[8192], node_name[2048]; PH_JSON p, ep;
    if (out_file_id) out_file_id[0] = 0;
    ph_copy_local(full, sizeof(full), shadow_path); if (full[ph_len(full)-1] != '\\') ph_append_local(full, sizeof(full), "\\"); ph_append_local(full, sizeof(full), relative_path);
    if (!ph_file_exists(full)) return;
    ph_id(g, "sensfile", full, out_file_id); ph_copy_local(node_name, sizeof(node_name), "SENSFILE:"); ph_append_local(node_name, sizeof(node_name), relative_path); ph_append_local(node_name, sizeof(node_name), "@"); ph_append_local(node_name, sizeof(node_name), g->hostname);
    ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p); ph_json_add_string(&p, "name", node_name); ph_json_add_string(&p, "file_path", full); ph_json_add_string(&p, "shadow_path", shadow_path); ph_json_add_string(&p, "relative_path", relative_path); ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p); ph_emit_node(g, out_file_id, "[\"PHSensitiveFile\"]", props);
    ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep); ph_json_add_string(&ep, "file_path", full); ph_json_end_object(&ep); ph_emit_edge(g, shadow_id, out_file_id, "PHContainsSensitiveFile", edge_props);
}

void ph_collect_shadow_copy_files(PH_GRAPH *g) {
    static const char *paths[] = {"Windows\\System32\\config\\SAM", "Windows\\System32\\config\\SYSTEM", "Windows\\System32\\config\\SECURITY", "Windows\\Panther\\unattend.xml", "Windows\\System32\\config\\RegBack\\SAM", "Windows\\System32\\config\\RegBack\\SYSTEM"};
    PH_WMI_SESSION session; IEnumWbemClassObject *enumerator; IWbemClassObject *object;
    if (!g || !ph_wmi_connect(L"ROOT\\CIMV2", &session)) return;
    enumerator = ph_wmi_query(&session, L"SELECT DeviceObject FROM Win32_ShadowCopy");
    while ((object = ph_wmi_next(enumerator)) != NULL) {
        char shadow[4096]; shadow[0] = 0; ph_wmi_string(object, L"DeviceObject", shadow, sizeof(shadow));
        if (shadow[0]) {
            char shadow_id[33], props[8192], edge_props[8192], node_name[4096], sam_id[33], system_id[33]; PH_JSON p, ep; BOOL emitted = FALSE;
            sam_id[0] = system_id[0] = 0; ph_id(g, "shadowcopy", shadow, shadow_id);
            for (unsigned int i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
                char file_id[33]; ph_shadow_sensitive(g, shadow, shadow_id, paths[i], file_id);
                if (file_id[0]) {
                    if (!emitted) {
                        ph_copy_local(node_name, sizeof(node_name), "SHADOW:"); ph_append_local(node_name, sizeof(node_name), shadow); ph_append_local(node_name, sizeof(node_name), "@"); ph_append_local(node_name, sizeof(node_name), g->hostname);
                        ph_json_init(&p, props, sizeof(props)); ph_json_start_object(&p); ph_json_add_string(&p, "name", node_name); ph_json_add_string(&p, "shadow_path", shadow); ph_json_add_string(&p, "hostname", g->hostname); ph_json_end_object(&p); ph_emit_node(g, shadow_id, "[\"PHShadowCopy\"]", props);
                        ph_json_init(&ep, edge_props, sizeof(edge_props)); ph_json_start_object(&ep); ph_json_add_string(&ep, "shadow_path", shadow); ph_json_add_string(&ep, "mitre", "T1003.002"); ph_json_end_object(&ep); ph_emit_edge(g, g->current_user_id, shadow_id, "PHCanAccessShadowCopy", edge_props); emitted = TRUE;
                    }
                    if (ph_equal_ci(paths[i], "Windows\\System32\\config\\SAM")) ph_copy_local(sam_id, sizeof(sam_id), file_id);
                    if (ph_equal_ci(paths[i], "Windows\\System32\\config\\SYSTEM")) ph_copy_local(system_id, sizeof(system_id), file_id);
                }
            }
            if (sam_id[0] && system_id[0]) ph_emit_edge(g, sam_id, g->admin_id, "PHCanExtractHashes", "{\"mitre\":\"T1003.002\",\"secret_emitted\":false}");
            if (emitted) ph_emit_finding(g, "ShadowCopy", "HIGH", "A shadow copy contains sensitive files accessible to the current token", "Review shadow-copy ACLs and protect registry hive backups");
        }
        object->lpVtbl->Release(object);
    }
    if (enumerator) enumerator->lpVtbl->Release(enumerator); ph_wmi_close(&session);
}

void ph_collect(PH_GRAPH *graph) {
    if (!graph) return;
    ph_collect_core(graph);
    ph_collect_token_privileges(graph);
    ph_collect_services(graph);
    ph_collect_unquoted_service_paths(graph);
    ph_collect_writable_path(graph);
    ph_collect_always_install_elevated(graph);
    ph_collect_uac(graph);
    ph_collect_scheduled_tasks(graph);
    ph_collect_autoruns(graph);
    ph_collect_service_registry_keys(graph);
    ph_collect_writable_program_dirs(graph);
    ph_collect_service_recovery(graph);
    ph_collect_stored_credentials(graph);
    ph_collect_gpp_passwords(graph);
    ph_collect_unattend_files(graph);
    ph_collect_ps_history(graph);
    ph_collect_sensitive_files(graph);
    ph_collect_cross_user_profiles(graph);
    ph_collect_jit_admin_tools(graph);
    ph_collect_print_spooler(graph);
    ph_collect_wsus_config(graph);
    ph_collect_com_hijacking(graph);
    ph_collect_named_pipe_permissions(graph);
    ph_collect_cached_credentials(graph);
    ph_collect_webclient_relay(graph);
    ph_collect_sccm_credentials(graph);
    ph_collect_wmi_subscriptions(graph);
    ph_collect_shadow_copy_files(graph);
    ph_collect_credential_login_paths(graph);
}

