#requires -Version 5.1
<#
.SYNOPSIS
Runs an offline-capable, read-only local Windows Server posture assessment.
.DESCRIPTION
Use -Demo to render synthetic results without querying this host. Live scans require
64-bit Windows PowerShell 5.1 on Server 2019, 2022 or 2025. Output contains server
configuration evidence: store and share it under your client data handling rules.
.EXAMPLE
.\Invoke-WintelSecurityAssessment.ps1 -ClientName 'Example client'
.EXAMPLE
.\Invoke-WintelSecurityAssessment.ps1 -Demo -DemoRole DomainController
#>
[CmdletBinding()]
param(
    [string]$BaselinePath,
    [string]$OutputDirectory,
    [string]$ExceptionsPath,
    [string]$ClientName = '',
    [switch]$Demo,
    [ValidateSet('MemberServer','DomainController','StandaloneServer')][string]$DemoRole = 'MemberServer',
    [ValidateSet('2019','2022','2025')][string]$DemoRelease = '2022'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$stage = 'checking the PowerShell session'
try {
    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
        throw "This kit requires an approved FullLanguage session. Current language mode: $($ExecutionContext.SessionState.LanguageMode). See Docs\STARTUP.md."
    }
    if ([string]::IsNullOrWhiteSpace($BaselinePath)) { $BaselinePath = Join-Path $PSScriptRoot 'Baselines\windows-server-foundation.v1.json' }
    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $PSScriptRoot 'Reports' }
    $started = [datetime]::UtcNow.ToString('o')
    $stage = 'loading Modules\Assessment.psm1'
    Import-Module (Join-Path $PSScriptRoot 'Modules\Assessment.psm1') -Force
    $stage = 'loading Modules\Reporting.psm1'
    Import-Module (Join-Path $PSScriptRoot 'Modules\Reporting.psm1') -Force
    $stage = 'reading the baseline and exceptions'
    $baseline = Import-WskBaseline -Path $BaselinePath
    $exceptions = @(Import-WskExceptions -Path $ExceptionsPath)
    if ($Demo) {
        $stage = 'generating synthetic evidence'
        $snapshot = New-WskDemoSnapshot -Baseline $baseline -Role $DemoRole -Release $DemoRelease
        $context = $snapshot.Context; $facts = $snapshot.Facts; $mode = 'Demo'
    } else {
        $stage = 'checking the live assessment host'
        if ($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell 5.1 for live assessments.' }
        $stage = 'loading Modules\Collectors.psm1'
        Import-Module (Join-Path $PSScriptRoot 'Modules\Collectors.psm1') -Force
        $stage = 'identifying the local Windows Server'
        $context = Get-WskContext
        if (-not $context.Supported) { throw "Unsupported target: $($context.OSCaption), build $($context.BuildNumber), role $($context.Role). Live assessment supports Server 2019/2022/2025 only. Use -Demo for a synthetic preview." }
        $factNames = @($baseline.Controls | Where-Object { $_.Assessment -eq 'Automated' -and $context.Role -cin $_.Roles -and $context.ServerRelease -cin $_.Releases } | Select-Object -ExpandProperty Fact -Unique)
        Write-Host "Collecting $($factNames.Count) facts on $($context.ComputerName) ($($context.Role))..."
        $stage = 'collecting server configuration'
        $facts = Get-WskFacts -FactNames $factNames
        $mode = 'Live'
    }
    $stage = 'evaluating the baseline'
    $report = Invoke-WskEvaluation -Baseline $baseline -Context $context -Facts $facts -Exceptions $exceptions -ClientName $ClientName -Mode $mode -StartedAtUtc $started
    $hostLabel = $context.ComputerName -replace '[^A-Za-z0-9._-]','_'
    $runFolder = '{0}-{1}-{2}' -f ([datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ')),$hostLabel,$report.RunId.Substring(0,8)
    # Resolve a relative path against the caller's PowerShell location. The .NET
    # process working directory can still point to the shell's startup folder.
    $stage = "writing reports under '$OutputDirectory'"
    $outputRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
    $target = Join-Path $outputRoot $runFolder
    $paths = Export-WskReport -Report $report -OutputDirectory $target
    Write-Host "Mode: $mode | Baseline: $($baseline.Name) $($baseline.Version)"
    Write-Host "Pass: $($report.Summary.Pass) | Fail: $($report.Summary.Fail) | Review: $($report.Summary.Review) | Error: $($report.Summary.Error) | Excepted: $($report.Summary.Excepted)"
    Write-Host "HTML: $($paths.HtmlPath)"
    Write-Host "JSON: $($paths.JsonPath)"
    Write-Host "CSV:  $($paths.CsvPath)"
    Write-Host "WSK_REPORT_DIR=$runFolder"
    if ($report.Summary.Fail -gt 0) { exit 1 }
    if ($report.Summary.Review -gt 0 -or $report.Summary.Error -gt 0 -or $report.Summary.Excepted -gt 0 -or $report.Summary.Evaluated -eq 0) { exit 3 }
    exit 0
} catch {
    Write-Error -Message "Assessment could not complete while $stage. $($_.Exception.Message)" -ErrorAction Continue
    exit 2
}
