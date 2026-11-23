#requires -Version 5.1
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$kitRoot = Split-Path $PSScriptRoot -Parent
$importer = Join-Path $kitRoot 'Tools\ConvertFrom-WskXccdf.ps1'
$fixture = Join-Path $PSScriptRoot 'Fixtures\windows-server-synthetic.xccdf.xml'
$artifacts = Join-Path $PSScriptRoot ('Output\xccdf-' + [guid]::NewGuid().ToString('N').Substring(0,8))
$null = New-Item -ItemType Directory -Path $artifacts
Import-Module (Join-Path $kitRoot 'Modules\Assessment.psm1') -Force
Import-Module (Join-Path $kitRoot 'Modules\Reporting.psm1') -Force

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Read-ProfilePair {
    param([string]$Directory)
    $files = @(Get-ChildItem -LiteralPath $Directory -Filter '*.json' -File)
    Assert-True ($files.Count -eq 2) 'Expected exactly two baseline JSON files.'
    $profiles = @{}
    foreach ($file in $files) {
        $baseline = Import-WskBaseline -Path $file.FullName
        $profiles.Add($baseline.SourceProfileId, $baseline)
    }
    return $profiles
}

function Assert-SelectedRules {
    param($Baseline, [string[]]$Suffixes)
    $expected = @($Suffixes | ForEach-Object { 'xccdf_org.example_rule_' + $_ })
    $actual = @($Baseline.Controls | ForEach-Object { $_.SourceRuleId })
    Assert-True ($expected.Count -eq $actual.Count -and
        @(Compare-Object -ReferenceObject $expected -DifferenceObject $actual -CaseSensitive).Count -eq 0) (
        "Incorrect rule membership for $($Baseline.SourceProfileId): $($actual -join ', ')"
    )
}

function Assert-RejectedImport {
    param([string]$Case, [hashtable]$Overrides, [string]$MessagePattern)
    $settings = $options.Clone()
    $settings.OutputDirectory = Join-Path $artifacts $Case
    foreach ($key in $Overrides.Keys) { $settings[$key] = $Overrides[$key] }
    $rejected = $false
    $message = ''
    try { & $importer @settings | Out-Null } catch { $rejected = $true; $message = $_.Exception.Message }
    Assert-True $rejected "Importer accepted invalid input for $Case."
    if ($MessagePattern) { Assert-True ($message -match $MessagePattern) "Unexpected error for $Case. $message" }
    Assert-True (-not (Test-Path -LiteralPath $settings.OutputDirectory)) "Partial output was left for $Case."
}

$l1 = 'xccdf_org.example_profile_L1_Member'
$l2 = 'xccdf_org.example_profile_L2_Member'
$digest = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash
$sampleMapping = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $kitRoot 'Samples\CisImport\mapping.example.json') | ConvertFrom-Json
Assert-True ($sampleMapping.BenchmarkSha256 -eq $digest) 'The shipped mapping example targets a different fixture.'
foreach ($level in @(1,2)) {
    $sample = Import-WskBaseline -Path (Join-Path $kitRoot "Samples\CisImport\level-$level.example.json")
    Assert-True ($sample.SourceSha256 -eq $digest) "The shipped Level $level example targets a different fixture."
}
$options = @{
    Path = $fixture
    OutputDirectory = (Join-Path $artifacts 'manual')
    Level1ProfileId = $l1
    Level2ProfileId = $l2
    Role = 'MemberServer'
    Release = '2022'
}

$listed = @(& $importer -Path $fixture -ListProfiles)
Assert-True ($listed.Count -eq 2 -and $l1 -cin $listed.Id -and $l2 -cin $listed.Id) 'ListProfiles lost the original profile IDs.'

& $importer @options | Out-Null
$manual = Read-ProfilePair $options.OutputDirectory
Assert-SelectedRules $manual[$l1] @('record','visibility')
Assert-SelectedRules $manual[$l2] @('record','visibility','archive')
Assert-True ($manual[$l1].Id -cne $manual[$l2].Id) 'Levels must have distinct baseline identifiers.'

foreach ($baseline in $manual.Values) {
    Assert-True ($baseline.SourceBenchmarkId -ceq 'xccdf_org.example_benchmark_windows-server-2022' -and
        $baseline.SourceBenchmarkVersion -ceq '1.7.3' -and $baseline.SourceSha256 -eq $digest) 'Imported source identity differs from the fixture.'
    foreach ($control in $baseline.Controls) {
        Assert-True ($control.Assessment -eq 'Manual' -and $null -eq $control.Fact) 'An unmapped rule received an automated check.'
        Assert-True ($control.Roles.Count -eq 1 -and $control.Roles[0] -ceq 'MemberServer' -and
            $control.Releases.Count -eq 1 -and $control.Releases[0] -ceq '2022') 'Unexpected imported rule scope.'
    }
    $snapshot = New-WskDemoSnapshot -Baseline $baseline -Role MemberServer -Release 2022
    $report = Invoke-WskEvaluation -Baseline $baseline -Context $snapshot.Context -Facts @{} -Mode Demo
    Assert-True ($report.Summary.Review -eq $baseline.Controls.Count -and $null -eq $report.Summary.PassRatePercent) 'Unmapped rules must remain Review.'
}

$marker = Join-Path $options.OutputDirectory 'retained.txt'
[IO.File]::WriteAllText($marker, 'keep')
$before = @(Get-ChildItem -LiteralPath $options.OutputDirectory -File | Sort-Object Name | Get-FileHash)
$refused = $false
try { & $importer @options | Out-Null } catch { $refused = $true }
$after = @(Get-ChildItem -LiteralPath $options.OutputDirectory -File | Sort-Object Name | Get-FileHash)
Assert-True ($refused -and @(Compare-Object $before $after -Property Path,Hash).Count -eq 0) 'An existing output directory was overwritten.'

$mapping = [ordered]@{
    SchemaVersion = '1.0'; BenchmarkSha256 = $digest; Release = '2022'; Role = 'MemberServer'
    Rules = @([ordered]@{
        RuleId = 'xccdf_org.example_rule_visibility'
        Fact = 'Firewall.Domain.Enabled'; Operator = 'Equals'; Expected = $true; ExpectedDisplay = 'Enabled'
    })
}
$mappingPath = Join-Path $artifacts 'practice-mapping.json'
$mapping | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $mappingPath -Encoding UTF8
$mappedOptions = $options.Clone()
$mappedOptions.OutputDirectory = Join-Path $artifacts 'mapped'
$mappedOptions.MappingPath = $mappingPath
& $importer @mappedOptions | Out-Null
$mapped = Read-ProfilePair $mappedOptions.OutputDirectory
$mappingDigest = (Get-FileHash -LiteralPath $mappingPath -Algorithm SHA256).Hash
foreach ($level in @($l1,$l2)) {
    $baseline = $mapped[$level]
    $automated = @($baseline.Controls | Where-Object Assessment -eq Automated)
    Assert-True ($automated.Count -eq 1 -and $automated[0].Expected -is [bool] -and
        $automated[0].SourceRuleId -ceq 'xccdf_org.example_rule_visibility') 'Incorrect automation mapping.'
    $context = (New-WskDemoSnapshot $baseline -Role MemberServer -Release 2022).Context
    foreach ($test in @(@{Value=$true; Status='Pass'},@{Value=$false; Status='Fail'},@{Value='true'; Status='Error'})) {
        $facts = @{ 'Firewall.Domain.Enabled' = [pscustomobject]@{State='Collected'; Value=$test.Value; Evidence='Synthetic evidence'; Reason='Test case'} }
        $report = Invoke-WskEvaluation $baseline $context $facts -Mode Demo
        $result = @($report.Results | Where-Object Id -eq $automated[0].Id)
        Assert-True ($result.Count -eq 1 -and $result[0].Status -ceq $test.Status -and
            $report.Summary.Review -eq ($baseline.Controls.Count - 1)) "Unexpected $($test.Status) evaluation."
    }
    $reportDirectory = Join-Path $artifacts ('report-' + ($level -replace '^.*profile_', ''))
    $export = Export-WskReport -Report $report -OutputDirectory $reportDirectory
    $jsonReport = Get-Content -LiteralPath $export.JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($name in @('SourceBenchmarkId','SourceBenchmarkVersion','SourceProfileId','SourceSha256')) {
        Assert-True ($jsonReport.Baseline.$name -ceq $baseline.$name) "The JSON report lost $name."
    }
    Assert-True ($jsonReport.Baseline.SourceMappingSha256 -eq $mappingDigest) 'The JSON report lost the mapping digest.'
    foreach ($control in $baseline.Controls) {
        $row = @($jsonReport.Results | Where-Object Id -eq $control.Id)
        Assert-True ($row.Count -eq 1 -and $row[0].SourceRuleId -ceq $control.SourceRuleId) 'The JSON report lost its source rule identifier.'
    }
}

Assert-RejectedImport 'missing-source' @{Path=(Join-Path $artifacts 'absent.xml')}
Assert-RejectedImport 'wrong-role' @{Role='DomainController'}
Assert-RejectedImport 'wrong-release' @{Release='2025'}
Assert-RejectedImport 'missing-level' @{Level2ProfileId='xccdf_org.example_profile_Missing'}
Assert-RejectedImport 'swapped-levels' @{Level1ProfileId=$l2;Level2ProfileId=$l1}
$filename = 'cis-windows-server-2022-member-server-level-1.json'
$longDirectory = Join-Path $artifacts ('long-' + ('x' * (265 - $artifacts.Length - $filename.Length - 7)))
Assert-True ((Join-Path $longDirectory $filename).Length -eq 265) 'The path-length fixture must exceed legacy MAX_PATH.'
Assert-RejectedImport 'overlong-output' @{OutputDirectory=$longDirectory} '(?i)path.*(?:too long|limit|260)|(?:too long|limit|260).*path'
Assert-True (@(Get-ChildItem -LiteralPath $artifacts -Directory -Filter '.wsk-*').Count -eq 0) 'The path rejection left a staging directory.'

$xml = Get-Content -LiteralPath $fixture -Encoding UTF8 -Raw
foreach ($variant in @(
    @{Role='DomainController'; Label='Domain Controller'; Release='2019'; Benchmark='Synthetic Windows Server 2019 Benchmark'},
    @{Role='StandaloneServer'; Label=''; Release='2025'; Benchmark='Synthetic Windows Server 2025 Stand-alone Benchmark'}
)) {
    $variantSource = $xml.Replace('Synthetic Windows Server 2022 Benchmark', $variant.Benchmark)
    $variantSource = $variantSource.Replace('2022', $variant.Release).Replace('_Member', ('_' + $variant.Role))
    $profileSuffix = if ($variant.Label) { ' - ' + $variant.Label } else { '' }
    $variantSource = $variantSource.Replace(' - Member Server', $profileSuffix)
    $sourcePath = Join-Path $artifacts ($variant.Role + '.xml')
    [IO.File]::WriteAllText($sourcePath, $variantSource)
    $variantOptions = $options.Clone()
    $variantOptions.Path = $sourcePath
    $variantOptions.Release = $variant.Release
    $variantOptions.Role = $variant.Role
    $variantOptions.Level1ProfileId = $l1.Replace('_Member', ('_' + $variant.Role))
    $variantOptions.Level2ProfileId = $l2.Replace('_Member', ('_' + $variant.Role))
    $variantOptions.OutputDirectory = Join-Path $artifacts $variant.Role
    & $importer @variantOptions | Out-Null
    $variantProfiles = Read-ProfilePair $variantOptions.OutputDirectory
    foreach ($baseline in $variantProfiles.Values) {
        foreach ($control in $baseline.Controls) {
            Assert-True ($control.Roles.Count -eq 1 -and $control.Roles[0] -ceq $variant.Role -and
                $control.Releases.Count -eq 1 -and $control.Releases[0] -ceq $variant.Release) "Scope broadened on $($variant.Role)."
        }
    }
}
$doctype = Join-Path $artifacts 'doctype.xml'
[IO.File]::WriteAllText($doctype, $xml.Replace('<Benchmark xmlns=', "<!DOCTYPE Benchmark []>`n<Benchmark xmlns="))
Assert-RejectedImport 'prohibited-dtd' @{Path=$doctype}
$other = Join-Path $artifacts 'different-format.xml'
[IO.File]::WriteAllText($other, '<Inventory><Server>synthetic</Server></Inventory>')
Assert-RejectedImport 'unsupported-xml' @{Path=$other}

# In this variant Level 2 enables a cluster, deselects one member, then
# overrides a Value. A mapping for the unrefined level cannot grade this one.
$advancedSelect = '<select idref="xccdf_org.example_rule_archive" selected="true"/>'
$clusterSelect = @'
<select idref="workshop-extras" selected="true"/>
    <select idref="xccdf_org.example_rule_retired" selected="false"/>
    <refine-value idref="xccdf_org.example_value_worksheet" selector="alternate"/>
'@
$groupTag = '<Group id="xccdf_org.example_group_workshop">'
$withValue = @'
<Value id="xccdf_org.example_value_worksheet" type="string">
    <title>Worksheet for the practice exercise</title>
    <value>blue</value>
    <value selector="alternate">green</value>
  </Value>
  <Group id="xccdf_org.example_group_workshop">
'@
$refinedSource = $xml.Replace($advancedSelect,$clusterSelect).Replace($groupTag,$withValue)
foreach ($rule in @('archive','retired')) {
    $tag = '<Rule id="xccdf_org.example_rule_' + $rule + '"'
    $refinedSource = $refinedSource.Replace($tag,($tag + ' cluster-id="workshop-extras"'))
}
$refinedPath = Join-Path $artifacts 'refined.xml'
[IO.File]::WriteAllText($refinedPath, $refinedSource)
$refinedOptions = $mappedOptions.Clone()
$refinedOptions.Path = $refinedPath
$refinedOptions.OutputDirectory = Join-Path $artifacts 'refined'
$mapping.BenchmarkSha256 = (Get-FileHash -LiteralPath $refinedPath -Algorithm SHA256).Hash
$mapping | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $mappingPath -Encoding UTF8
& $importer @refinedOptions | Out-Null
$refined = Read-ProfilePair $refinedOptions.OutputDirectory
Assert-SelectedRules $refined[$l2] @('record','visibility','archive')
Assert-True (@($refined[$l1].Controls | Where-Object Assessment -eq Automated).Count -eq 1) 'A child refinement changed the parent profile.'
Assert-True (@($refined[$l2].Controls | Where-Object Assessment -ne Manual).Count -eq 0) 'An unverified value override received an automated result.'
Assert-True (@($refined[$l2].SourceProfileDirectives | Where-Object ProfileId -CEQ $l2).Count -gt 0) 'The profile value refinement was lost.'

$mapping.BenchmarkSha256 = '0' * 64
$mapping | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $mappingPath -Encoding UTF8
Assert-RejectedImport 'mapping-for-other-source' @{MappingPath=$mappingPath}

Write-Host 'PASS: imported profile membership, rule scope, source identity, mapped and manual assessments, invalid inputs and overwrite protection.'
