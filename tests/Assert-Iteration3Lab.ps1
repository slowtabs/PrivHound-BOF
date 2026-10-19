[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$GraphPath
)

$ErrorActionPreference = 'Stop'
$graph = Get-Content -LiteralPath $GraphPath -Raw | ConvertFrom-Json
$nodes = @($graph.graph.nodes)
$edges = @($graph.graph.edges)

& (Join-Path $PSScriptRoot 'Assert-Iteration2Lab.ps1') -GraphPath $GraphPath

function Assert-PHEdge([string]$Kind, [string]$EndId, [string]$Message) {
    if (-not ($edges | Where-Object { $_.kind -eq $Kind -and $_.end.value -eq $EndId })) {
        throw $Message
    }
}

$task = $nodes | Where-Object {
    $_.kinds -contains 'PHScheduledTask' -and $_.properties.task_name -eq 'PHLabVulnTask'
} | Select-Object -First 1
if (-not $task) { throw 'Iteration 3 graph has no PHLabVulnTask PHScheduledTask node.' }
Assert-PHEdge 'PHCanWriteTaskBinary' $task.id 'PHLabVulnTask has no PHCanWriteTaskBinary edge.'

$autorun = $nodes | Where-Object {
    $_.kinds -contains 'PHAutoRun' -and $_.properties.value_name -eq 'PHLabAutorun'
} | Select-Object -First 1
if (-not $autorun) { throw 'Iteration 3 graph has no PHLabAutorun PHAutoRun node.' }
Assert-PHEdge 'PHCanWriteAutorun' $autorun.id 'PHLabAutorun has no PHCanWriteAutorun edge.'

$registry = $nodes | Where-Object {
    $_.kinds -contains 'PHWritableRegKey' -and $_.properties.service -eq 'PHLabRegSvc'
} | Select-Object -First 1
if (-not $registry) { throw 'Iteration 3 graph has no PHLabRegSvc PHWritableRegKey node.' }
Assert-PHEdge 'PHCanModifyRegKey' $registry.id 'PHLabRegSvc has no PHCanModifyRegKey edge.'

$programDir = $nodes | Where-Object {
    $_.kinds -contains 'PHWritableProgramDir' -and $_.properties.directory -ieq 'C:\Program Files\PHLabApp'
} | Select-Object -First 1
if (-not $programDir) { throw 'Iteration 3 graph has no writable C:\Program Files\PHLabApp node.' }
Assert-PHEdge 'PHCanWriteProgDir' $programDir.id 'PHLabApp has no PHCanWriteProgDir edge.'

$recoveryService = $nodes | Where-Object {
    $_.kinds -contains 'PHService' -and $_.properties.service_name -eq 'PHLabRecoverySvc'
} | Select-Object -First 1
if (-not $recoveryService) { throw 'Iteration 3 graph has no PHLabRecoverySvc PHService node.' }
Assert-PHEdge 'PHCanWriteRecoveryBin' $recoveryService.id 'PHLabRecoverySvc has no PHCanWriteRecoveryBin edge.'

"Iteration 3 lab assertions passed: task=1 autorun=1 registry=1 program_dir=1 recovery=1"
