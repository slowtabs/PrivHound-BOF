# BOF feature parity

The native x64 collector implements all 29 PowerShell check families. `implemented` means the native collector builds and passes local NDJSON/OpenGraph validation. `accepted` additionally means the positive lab fixture has been exercised from the intended non-elevated VM account.

| PowerShell check | BOF status | Delivery |
|---|---:|---:|
| WeakServicePermissions | accepted | 1 |
| UnquotedServicePaths | accepted | 2 |
| DLLHijacking | accepted | 2 |
| AlwaysInstallElevated | accepted | 2 |
| TokenPrivileges | implemented | 1 |
| ScheduledTasks | implemented | 3 |
| AutoRuns | implemented | 3 |
| ServiceRegistryKeys | implemented | 3 |
| StoredCredentials | implemented | 4 |
| GPPPasswords | implemented | 4 |
| UnattendFiles | implemented | 4 |
| PSHistory | implemented | 4 |
| SensitiveFiles | implemented | 4 |
| UACBypass | accepted | 2 |
| WritableProgramDirs | implemented | 3 |
| CrossUserProfiles | implemented | 5 |
| CredentialLoginPaths | implemented, opt-in | 5 |
| CrossUserPrivileges | implemented, opt-in | 5 |
| JITAdminTools | implemented | 5 |
| PrintSpooler | implemented | 6 |
| WSUSConfig | implemented | 6 |
| SCCMCredentials | implemented | 4 |
| COMHijacking | implemented | 6 |
| NamedPipePermissions | implemented | 6 |
| CachedCredentials | implemented | 5 |
| WMISubscriptions | implemented | 6 |
| WebClientRelay | implemented | 6 |
| ServiceRecoveryActions | implemented | 3 |
| ShadowCopyFiles | implemented | 6 |

## Safety differences

The default BOF is metadata-only and does not emit recovered passwords, WiFi keys, GPP plaintext, Credential Manager blobs, or other secret values. Secret buffers used by an explicitly requested credential-validation run are wiped before release.

Authentication is disabled by default:

- `validate-creds` tests a recovered credential only against its claimed local username.
- `spray-creds` additionally tests recovered passwords across enabled local accounts. It can create many authentication events and trigger lockout policy.

Candidate-only checks retain explicit verification properties. COM registration, named-pipe connectivity, JIT-tool presence, SCCM policy presence, and relay prerequisites are not represented as proof of exploitation.

## Remaining acceptance work

Full implementation is complete, but Iterations 3–6 still require positive VM acceptance. Each acceptance run must pass the build inspection, standalone harness, conversion and graph validator, fixture assertions, PowerShell comparison, and direct x64 COFF-loader or Beacon test described in `TESTING.md`.
