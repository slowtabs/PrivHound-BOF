[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$GraphPath
)

$ErrorActionPreference = 'Stop'
$graph = Get-Content -LiteralPath $GraphPath -Raw | ConvertFrom-Json
$nodes = @($graph.graph.nodes)
$edges = @($graph.graph.edges)

& (Join-Path $PSScriptRoot 'Assert-Iteration3Lab.ps1') -GraphPath $GraphPath

function Assert-PHEdge([string]$Kind, [string]$EndId, [string]$Message) {
    if (-not ($edges | Where-Object { $_.kind -eq $Kind -and $_.end.value -eq $EndId })) { throw $Message }
}

$autoLogon = $nodes | Where-Object {
    $_.kinds -contains 'PHStoredCredential' -and $_.properties.source -eq 'WinlogonAutoLogon'
} | Select-Object -First 1
if (-not $autoLogon) { throw 'Iteration 4 graph has no Winlogon AutoLogon PHStoredCredential node.' }
if ($autoLogon.properties.PSObject.Properties.Name -contains 'password') { throw 'AutoLogon plaintext password was emitted.' }
if ($autoLogon.properties.secret_emitted -ne $false) { throw 'AutoLogon node does not explicitly report secret_emitted=false.' }
Assert-PHEdge 'PHCanReadCreds' $autoLogon.id 'AutoLogon node has no PHCanReadCreds edge.'

$gpp = $nodes | Where-Object {
    $_.kinds -contains 'PHGPPPassword' -and $_.properties.file_name -ieq 'Groups.xml'
} | Select-Object -First 1
if (-not $gpp) { throw 'Iteration 4 graph has no Groups.xml PHGPPPassword node.' }
Assert-PHEdge 'PHCanDecryptGPP' $gpp.id 'GPP node has no PHCanDecryptGPP edge.'

$unattend = $nodes | Where-Object {
    $_.kinds -contains 'PHUnattendFile' -and $_.properties.file_path -match '(?i)\\Panther\\unattend.xml$'
} | Select-Object -First 1
if (-not $unattend) { throw 'Iteration 4 graph has no Panther unattend.xml PHUnattendFile node.' }
Assert-PHEdge 'PHCanReadCreds' $unattend.id 'Unattend node has no PHCanReadCreds edge.'

$sensitive = $nodes | Where-Object {
    $_.kinds -contains 'PHSensitiveFile' -and $_.properties.file_path -match '(?i)\\.git-credentials$'
} | Select-Object -First 1
if (-not $sensitive) { throw 'Iteration 4 graph has no .git-credentials PHSensitiveFile node.' }
Assert-PHEdge 'PHCanAccessFile' $sensitive.id 'Sensitive file node has no PHCanAccessFile edge.'

"Iteration 4 lab assertions passed: autologon=1 gpp=1 unattend=1 sensitive_file=1 secrets_emitted=0"
