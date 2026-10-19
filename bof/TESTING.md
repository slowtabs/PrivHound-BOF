# Full BOF acceptance testing

Use a disposable Windows 10/11 x64 VM and take a clean snapshot first. The lab setup intentionally creates vulnerable services, registry policy, files, scheduled tasks, and other escalation fixtures. Do not run it on a daily-use or production computer.

## 1. Build on the development machine

From an x64 Native Tools Command Prompt for Visual Studio:

```bat
bof\build-msvc.bat
```

Copy these items to the VM:

```text
bof\build\privhound.x64.bof.o
bof\build\privhound_harness.exe
lab\Setup-VulnLab.ps1
lab\Teardown-VulnLab.ps1
scripts\Convert-PrivHoundNdjson.ps1
tests\Validate-PrivHoundOutput.ps1
tests\Assert-Iteration1Lab.ps1
tests\Assert-Iteration2Lab.ps1
tests\Assert-Iteration3Lab.ps1
tests\Assert-Iteration4Lab.ps1
tests\Assert-FullParityLab.ps1
PrivHound.ps1
```

## 2. Create the lab fixtures

In an elevated PowerShell window inside the VM:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\lab\Setup-VulnLab.ps1
```

Confirm with `YES`. Then sign in as the non-elevated `PHLabUser` printed by the setup script. All comparison runs must use that same account and token elevation state.

## 3. Safe metadata-only run

```powershell
New-Item -ItemType Directory -Path C:\PrivHoundTest -Force | Out-Null
.\bof\build\privhound_harness.exe -o C:\PrivHoundTest\bof-safe.ndjson
.\scripts\Convert-PrivHoundNdjson.ps1 `
  -InputPath C:\PrivHoundTest\bof-safe.ndjson `
  -OutputPath C:\PrivHoundTest\bof-safe.json `
  -FindingsPath C:\PrivHoundTest\bof-safe-findings.json
.\tests\Validate-PrivHoundOutput.ps1 `
  -NdjsonPath C:\PrivHoundTest\bof-safe.ndjson `
  -OpenGraphPath C:\PrivHoundTest\bof-safe.json
.\tests\Assert-FullParityLab.ps1 `
  -GraphPath C:\PrivHoundTest\bof-safe.json
```

The safe output must contain no plaintext fixture passwords. A quick regression check is:

```powershell
Select-String C:\PrivHoundTest\bof-safe.ndjson `
  -Pattern @('PHLab_P@ssw0rd_TEST','PHLabXPriv_S3cret!','AdminFakeToken789') `
  -SimpleMatch
```

The command should return no matches.

## 4. Opt-in claimed-user validation

This mode calls `LogonUser` and creates authentication events. Use it only after confirming that the lab accounts cannot be locked out:

```powershell
.\bof\build\privhound_harness.exe --validate-credentials `
  -o C:\PrivHoundTest\bof-validated.ndjson
.\scripts\Convert-PrivHoundNdjson.ps1 `
  -InputPath C:\PrivHoundTest\bof-validated.ndjson `
  -OutputPath C:\PrivHoundTest\bof-validated.json
.\tests\Validate-PrivHoundOutput.ps1 `
  -NdjsonPath C:\PrivHoundTest\bof-validated.ndjson `
  -OpenGraphPath C:\PrivHoundTest\bof-validated.json
.\tests\Assert-FullParityLab.ps1 `
  -GraphPath C:\PrivHoundTest\bof-validated.json `
  -RequireCredentialPaths
```

`--validate-credentials` tests only a recovered credential's claimed local username. `--spray-credentials` additionally checks password reuse across enabled local users and should be reserved for the isolated lab after reviewing lockout policy.

## 5. PowerShell comparison

Generate a non-authenticating reference graph:

```powershell
.\PrivHound.ps1 -NoCredTest `
  -OutputPath C:\PrivHoundTest\powershell.json `
  -FindingsPath C:\PrivHoundTest\powershell-findings.json
.\tests\compare\Compare-PrivHoundGraphs.ps1 `
  -ReferencePath C:\PrivHoundTest\powershell.json `
  -CandidatePath C:\PrivHoundTest\bof-safe.json
```

Counts do not need to be byte-for-byte identical: native checks deliberately preserve candidate/verification properties and never emit secrets. Investigate missing expected fixture nodes or dangling edges.

## 6. Direct BOF-loader or Beacon test

With the Ap3x loader in the same VM directory:

```powershell
$records = & .\COFFLoader.exe go .\privhound.x64.bof.o 2>&1 |
  ForEach-Object { "$_" } |
  Where-Object { $_ -match '^\{"type":' }
[IO.File]::WriteAllLines(
  (Join-Path $PWD 'bof-loader.ndjson'),
  [string[]]$records,
  [Text.UTF8Encoding]::new($false)
)
```

Convert and validate `bof-loader.ndjson` as above. Loader argument conventions differ; use the harness or the Aggressor commands for credential-mode acceptance if the loader cannot pass raw arguments.

With `scripts\privhound.cna` loaded in an authorized x64 Beacon:

```text
privhound
privhound_validate_creds
privhound_spray_creds
```

The latter two commands are explicit active-authentication modes.

## 7. Cleanup

From an elevated PowerShell window:

```powershell
.\lab\Teardown-VulnLab.ps1
```

If teardown reports incomplete cleanup, revert the VM snapshot.
