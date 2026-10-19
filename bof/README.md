# PrivHound x64 BOF

This directory contains the native x64 BOF implementation of all 29 PrivHound PowerShell check families. It emits newline-delimited JSON (NDJSON), which `scripts/Convert-PrivHoundNdjson.ps1` converts to BloodHound OpenGraph JSON.

The default mode is read-only and metadata-only. It does not exploit findings, modify configuration, establish persistence, or emit plaintext secrets. Credential validation and password-reuse testing are separate explicit modes because they generate authentication events and may interact with account-lockout policy.

## Build

From an x64 Native Tools Command Prompt for Visual Studio:

```bat
bof\build-msvc.bat
```

Outputs:

```text
bof\build\privhound.x64.bof.o
bof\build\privhound_harness.exe
```

The `.o` file is the BOF artifact. The harness runs the same collection core without Cobalt Strike. The build also inspects the BOF architecture, `go` entry point, Beacon imports, and Dynamic Function Resolution symbols.

MinGW-w64 is also supported:

```powershell
.\bof\build.ps1
```

## Run and convert

Safe metadata-only collection:

```powershell
.\bof\build\privhound_harness.exe -o C:\PrivHoundTest\bof.ndjson
.\scripts\Convert-PrivHoundNdjson.ps1 `
  -InputPath C:\PrivHoundTest\bof.ndjson `
  -OutputPath C:\PrivHoundTest\bof.json `
  -FindingsPath C:\PrivHoundTest\bof_findings.json
.\tests\Validate-PrivHoundOutput.ps1 `
  -NdjsonPath C:\PrivHoundTest\bof.ndjson `
  -OpenGraphPath C:\PrivHoundTest\bof.json
```

Explicit credential modes:

```powershell
# Test each recovered credential only against its claimed local username.
.\bof\build\privhound_harness.exe --validate-credentials -o C:\PrivHoundTest\validated.ndjson

# Also test recovered passwords against enabled local users. Review lockout policy first.
.\bof\build\privhound_harness.exe --spray-credentials -o C:\PrivHoundTest\spray.ndjson
```

No recovered secret is written to NDJSON in either mode.

## Beacon commands

Load `scripts/privhound.cna`, then use:

```text
privhound                 # safe metadata-only mode
privhound_validate_creds  # claimed-user validation
privhound_spray_creds     # cross-account reuse testing
```

Only use the last two in an authorized disposable lab. The wrapper currently supports x64 Beacon sessions.

## Coverage and testing

- `PARITY.md` tracks all check families and their acceptance status.
- `TESTING.md` contains the clean-VM setup, safe and active test flows, conversion, validation, comparison, and cleanup procedure.
- `tests/Inspect-PrivHoundBof.ps1` validates the COFF object.
- `tests/Validate-PrivHoundOutput.ps1` validates record structure, IDs, edge endpoints, and converted graph counts.

The native implementation uses Windows APIs directly. It does not spawn PowerShell, `sc.exe`, `schtasks.exe`, `netsh.exe`, or `vssadmin.exe`.
