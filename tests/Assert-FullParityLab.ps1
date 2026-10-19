[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$GraphPath,
    [switch]$RequireCredentialPaths
)

$ErrorActionPreference = 'Stop'
$graph = Get-Content -LiteralPath $GraphPath -Raw | ConvertFrom-Json
$nodes = @($graph.graph.nodes)
$edges = @($graph.graph.edges)

& (Join-Path $PSScriptRoot 'Assert-Iteration4Lab.ps1') -GraphPath $GraphPath

function Get-PHNode([string]$Kind, [scriptblock]$Predicate) {
    $nodes | Where-Object { $_.kinds -contains $Kind -and (& $Predicate $_) } | Select-Object -First 1
}

function Assert-PHEdge([string]$Kind, [string]$StartId, [string]$EndId, [string]$Message) {
    $match = $edges | Where-Object {
        $_.kind -eq $Kind -and
        (-not $StartId -or $_.start.value -eq $StartId) -and
        (-not $EndId -or $_.end.value -eq $EndId)
    } | Select-Object -First 1
    if (-not $match) { throw $Message }
}

$profile = Get-PHNode 'PHUserProfile' { param($n) $n.properties.username -eq 'PHLabCrossUser' }
if (-not $profile) { throw 'Full-parity graph has no readable PHLabCrossUser profile.' }
Assert-PHEdge 'PHCanAccessProfile' $null $profile.id 'PHLabCrossUser profile has no PHCanAccessProfile edge.'

$jit = Get-PHNode 'PHJITAdminTool' { param($n) $n.properties.tool_name -eq 'MakeMeAdmin' }
if (-not $jit) { throw 'Full-parity graph has no MakeMeAdmin PHJITAdminTool node.' }
Assert-PHEdge 'PHCanRequestJIT' $null $jit.id 'MakeMeAdmin has no PHCanRequestJIT edge.'

$wsus = Get-PHNode 'PHWSUSConfig' { param($n) $n.properties.wu_server -eq 'http://wsus.phlab.local:8530' }
if (-not $wsus) { throw 'Full-parity graph has no lab HTTP WSUS node.' }
Assert-PHEdge 'PHCanExploitWSUS' $null $wsus.id 'Lab WSUS node has no PHCanExploitWSUS edge.'

$com = Get-PHNode 'PHCOMHijack' { param($n) $n.properties.clsid -ieq '{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}' }
if (-not $com) { throw 'Full-parity graph has no lab COM override candidate.' }
Assert-PHEdge 'PHCanOverrideCOM' $null $com.id 'Lab COM node has no PHCanOverrideCOM edge.'

$wmi = Get-PHNode 'PHWMISubscription' { param($n) $n.properties.consumer_name -eq 'PHLabWMIConsumer' }
if (-not $wmi) { throw 'Full-parity graph has no writable PHLabWMIConsumer node.' }
Assert-PHEdge 'PHCanModifyWMI' $null $wmi.id 'PHLabWMIConsumer has no PHCanModifyWMI edge.'

$secretPropertyNames = @('password','secret','credential_blob','key_material')
foreach ($node in $nodes) {
    foreach ($name in $secretPropertyNames) {
        if ($node.properties.PSObject.Properties.Name -contains $name) {
            throw "Node $($node.id) emitted forbidden secret property '$name'."
        }
    }
}

if ($RequireCredentialPaths) {
    $labUser = Get-PHNode 'PHLocalUser' { param($n) $n.properties.username -eq 'PHLabUser' -and $n.properties.credential_validated -eq $true }
    if (-not $labUser) { throw 'Validated graph has no credential-validated PHLabUser node.' }
    Assert-PHEdge 'PHCanLoginAs' $null $labUser.id 'PHLabUser has no PHCanLoginAs edge.'

    $xpriv = Get-PHNode 'PHLocalUser' { param($n) $n.properties.username -eq 'PHLabXPrivUser' -and $n.properties.credential_validated -eq $true }
    if (-not $xpriv) { throw 'Validated graph has no credential-validated PHLabXPrivUser node.' }
    Assert-PHEdge 'PHCanLoginAs' $null $xpriv.id 'PHLabXPrivUser has no PHCanLoginAs edge.'
    if (-not ($edges | Where-Object {
        $_.start.value -eq $xpriv.id -and $_.kind -in @(
            'PHCanWriteBinary','PHCanModifyService','PHCanWriteTaskBinary','PHCanWriteAutorun',
            'PHCanWriteProgDir','PHCanWriteRecoveryBin','PHCanHijackPath','PHCanWriteTo','PHHasPrivilege')
    })) { throw 'PHLabXPrivUser has no cross-user privilege edge.' }
}

"Full-parity lab assertions passed: profile=1 jit=1 wsus=1 com=1 wmi=1 credential_paths=$($RequireCredentialPaths.IsPresent) secrets_emitted=0"
