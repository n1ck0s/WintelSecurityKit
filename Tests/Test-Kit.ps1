#requires -Version 5.1
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'Modules\Assessment.psm1') -Force
Import-Module (Join-Path $root 'Modules\Reporting.psm1') -Force
$script:passed = 0
$script:failed = 0
$out = Join-Path $PSScriptRoot ('Output\' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $out -Force
function Assert-True { param([bool]$Condition,[string]$Message='Assertion failed'); if (-not $Condition) { throw $Message } }
function Assert-Throws { param([scriptblock]$Action); $threw=$false; try { & $Action | Out-Null } catch { $threw=$true }; Assert-True $threw 'Expected an exception.' }
function Test-Case {
    param([string]$Name,[scriptblock]$Action)
    try { & $Action; $script:passed++; Write-Host "PASS $Name" }
    catch { $script:failed++; Write-Host "FAIL $Name : $($_.Exception.Message)" -ForegroundColor Red }
}
function Copy-JsonObject { param($Object); return ($Object | ConvertTo-Json -Depth 30 | ConvertFrom-Json) }
function Save-Json { param($Object,[string]$Name); $path=Join-Path $out $Name; $Object | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $path -Encoding UTF8; return $path }
function New-TestControl {
    param([string]$Id,[string]$Operator='Equals',$Expected=$true)
    [pscustomobject]@{Id=$Id;Title="Test $Id";Category='Testing';Severity='High';Assessment='Automated';Roles=@('MemberServer','DomainController','StandaloneServer');Releases=@('2019','2022','2025');Fact=$Id;Operator=$Operator;Expected=$Expected;ExpectedDisplay='Fixture expectation';Rationale='Test fixture';Remediation='Review evidence';SourceUrl='https://learn.microsoft.com/windows-server/'}
}
function New-TestFact { param($Value,[string]$State='Collected'); [pscustomobject]@{State=$State;Value=$Value;Evidence='Offline fixture';Reason='Fixture reason'} }
$controls = @((New-TestControl 'PASS'),(New-TestControl 'FAIL'),(New-TestControl 'MISSING'),(New-TestControl 'ERROR'),(New-TestControl 'MANUAL'),(New-TestControl 'DC'))
$controls[4].Assessment='Manual'; $controls[4].Fact=$null; $controls[4].Operator=$null; $controls[4].Expected=$null
$controls[5].Roles=@('DomainController')
$baseline = [pscustomobject]@{SchemaVersion='1.0';Id='test-baseline';Name='Offline test';Version='1.0.0';Framework='Test';Description='Synthetic fixture';SourceUrls=@('https://learn.microsoft.com/windows-server/');Controls=$controls}
$context = [pscustomobject]@{ComputerName='TEST-HOST';MachineId='12345678-abcd-5678-9abc-123456789abc';OSCaption='Synthetic Server 2022';OSVersion='10.0.20348';BuildNumber='20348';ServerRelease='2022';Role='MemberServer';IsAdministrator=$false;CollectedAtUtc=[datetime]::UtcNow.ToString('o');Supported=$true;Is64Bit=$true}
$facts=@{PASS=(New-TestFact $true);FAIL=(New-TestFact $false);ERROR=(New-TestFact $null 'Error')}
$exception=[pscustomobject]@{ControlId='FAIL';ComputerName='TEST-HOST';ClientName='Customer A';MachineId=$context.MachineId;BaselineId='test-baseline';BaselineVersion='1.0.0';Reason='Approved test';Owner='Test owner';Ticket='TEST-1';ExpiresOn='2099-12-31'}

Test-Case 'Parse every script without executing collectors' {
    foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $_.Extension -in @('.ps1','.psm1') }) {
        $tokens=$null; $issues=$null
        $null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$issues)
        Assert-True (@($issues).Count -eq 0) "Parse failed: $($file.FullName): $issues"
    }
}
Test-Case 'Load bundled baseline and enforce unique IDs' {
    $b=Import-WskBaseline (Join-Path $root 'Baselines\windows-server-foundation.v1.json')
    Assert-True ($b.Controls.Count -gt 20)
}
Test-Case 'Valid baseline schema' { $p=Save-Json $baseline 'valid.json'; $b=Import-WskBaseline $p; Assert-True ($b.Controls.Count -eq 6) }
Test-Case 'Every shipped baseline validates and evaluates for each declared release and role' {
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $root 'Baselines') -Filter '*.json' -File) {
        $b=Import-WskBaseline $file.FullName
        foreach ($release in @('2019','2022','2025')) { foreach ($role in @('MemberServer','DomainController','StandaloneServer')) {
            $s=New-WskDemoSnapshot $b -Release $release -Role $role; $r=Invoke-WskEvaluation $b $s.Context $s.Facts -Mode Demo
            Assert-True ($r.Summary.Total -eq $b.Controls.Count -and $r.Summary.Total -eq ($r.Summary.Pass+$r.Summary.Fail+$r.Summary.Review+$r.Summary.Error+$r.Summary.Excepted+$r.Summary.NotApplicable)) "Incorrect result counts: $($b.Id), $release, $role"
        } }
    }
}
Test-Case 'Duplicate IDs rejected' { $b=Copy-JsonObject $baseline; $b.Controls[1].Id='PASS'; $p=Save-Json $b 'duplicate.json'; Assert-Throws { Import-WskBaseline $p } }
Test-Case 'Unknown operators rejected' { $b=Copy-JsonObject $baseline; $b.Controls[0].Operator='Execute'; $p=Save-Json $b 'operator.json'; Assert-Throws { Import-WskBaseline $p } }
Test-Case 'Numeric string expected value rejected' { $b=Copy-JsonObject $baseline; $b.Controls[0].Operator='GreaterOrEqual'; $b.Controls[0].Expected='14'; $p=Save-Json $b 'number.json'; Assert-Throws { Import-WskBaseline $p } }
Test-Case 'Inverted ranges rejected' { $b=Copy-JsonObject $baseline; $b.Controls[0].Operator='Between'; $b.Controls[0].Expected=@(10,1); $p=Save-Json $b 'range.json'; Assert-Throws { Import-WskBaseline $p } }
Test-Case 'Mixed expected membership types rejected' { $b=Copy-JsonObject $baseline; $b.Controls[0].Operator='In'; $b.Controls[0].Expected=@(1,'Block'); $p=Save-Json $b 'mixed.json'; Assert-Throws { Import-WskBaseline $p } }
Test-Case 'Executable source links rejected' { $b=Copy-JsonObject $baseline; $b.Controls[0].SourceUrl='javascript:alert(1)'; $p=Save-Json $b 'url.json'; Assert-Throws { Import-WskBaseline $p } }
Test-Case 'Applicability typos rejected' { $b=Copy-JsonObject $baseline; $b.Controls[0].Roles=@('DomainControler'); $p=Save-Json $b 'roles.json'; Assert-Throws { Import-WskBaseline $p } }
Test-Case 'Distinct statuses and score denominators' {
    $r=Invoke-WskEvaluation $baseline $context $facts -Mode Demo
    Assert-True ($r.Summary.Pass -eq 1 -and $r.Summary.Fail -eq 1 -and $r.Summary.Review -eq 2 -and $r.Summary.Error -eq 1 -and $r.Summary.NotApplicable -eq 1)
    Assert-True ($r.Summary.PassRatePercent -eq 50 -and $r.Summary.CoveragePercent -eq 50 -and $r.Summary.AutomatedApplicable -eq 4)
}
Test-Case 'Launcher GUID is preserved as the JSON correlation ID' {
    $requestedId=[guid]::NewGuid()
    $r=Invoke-WskEvaluation $baseline $context $facts -Mode Demo -RunId $requestedId
    Assert-True ($r.RunId -ceq $requestedId.ToString('N'))
}
Test-Case 'No evidence never produces a perfect score' {
    $r=Invoke-WskEvaluation $baseline $context @{} -Mode Demo
    Assert-True ($null -eq $r.Summary.PassRatePercent -and $r.Summary.CoveragePercent -eq 0 -and $r.Summary.Pass -eq 0)
}
Test-Case 'Boolean string is an error instead of a pass' {
    $f=@{PASS=(New-TestFact 'true')}; $r=Invoke-WskEvaluation $baseline $context $f -Mode Demo
    Assert-True (($r.Results | Where-Object Id -eq 'PASS').Status -eq 'Error')
}
Test-Case 'Null collected evidence is an error' {
    $r=Invoke-WskEvaluation $baseline $context @{PASS=(New-TestFact $null)} -Mode Demo
    Assert-True (($r.Results | Where-Object Id -eq 'PASS').Status -eq 'Error')
}
Test-Case 'Unavailable evidence is review' {
    $r=Invoke-WskEvaluation $baseline $context @{PASS=(New-TestFact $null 'Unavailable')} -Mode Demo
    Assert-True (($r.Results | Where-Object Id -eq 'PASS').Status -eq 'Review')
}
Test-Case 'Malformed fact is an error' {
    $r=Invoke-WskEvaluation $baseline $context @{PASS=[pscustomobject]@{State='Collected'}} -Mode Demo
    Assert-True (($r.Results | Where-Object Id -eq 'PASS').Status -eq 'Error')
}
Test-Case 'Exception preserves underlying failure and score' {
    $r=Invoke-WskEvaluation $baseline $context $facts -Exceptions @($exception) -ClientName 'Customer A' -Mode Demo
    Assert-True ($r.Summary.Excepted -eq 1 -and $r.Summary.Fail -eq 0 -and $r.Summary.UnderlyingFail -eq 1 -and $r.Summary.PassRatePercent -eq 50)
}
Test-Case 'Expired exception cannot hide a failure' {
    $e=Copy-JsonObject $exception; $e.ExpiresOn='2000-01-01'; $r=Invoke-WskEvaluation $baseline $context $facts -Exceptions @($e) -ClientName 'Customer A' -Mode Demo
    Assert-True ($r.Summary.Excepted -eq 0 -and $r.Summary.Fail -eq 1)
}
Test-Case 'Exception remains valid through its UTC expiry date' {
    $e=Copy-JsonObject $exception; $e.ExpiresOn='2026-11-14'; $r=Invoke-WskEvaluation $baseline $context $facts -Exceptions @($e) -ClientName 'Customer A' -Mode Demo -AsOfUtc ([datetime]'2026-11-14T23:59:59Z')
    Assert-True ($r.Summary.Excepted -eq 1)
}
Test-Case 'Exception cannot cross host boundaries' {
    $e=Copy-JsonObject $exception; $e.ComputerName='ANOTHER'; $r=Invoke-WskEvaluation $baseline $context $facts -Exceptions @($e) -ClientName 'Customer A' -Mode Demo
    Assert-True ($r.Summary.Excepted -eq 0)
}
Test-Case 'Exception cannot cross baseline versions' {
    $e=Copy-JsonObject $exception; $e.BaselineVersion='9.0.0'; $r=Invoke-WskEvaluation $baseline $context $facts -Exceptions @($e) -ClientName 'Customer A' -Mode Demo
    Assert-True ($r.Summary.Excepted -eq 0)
}
Test-Case 'Exception cannot turn missing evidence into accepted risk' {
    $e=Copy-JsonObject $exception; $e.ControlId='MISSING'; $r=Invoke-WskEvaluation $baseline $context $facts -Exceptions @($e) -ClientName 'Customer A' -Mode Demo
    Assert-True (($r.Results | Where-Object Id -eq 'MISSING').Status -eq 'Review')
}
Test-Case 'Exception JSON validates required fields and duplicates' {
    $d=[pscustomobject]@{SchemaVersion='1.1';Exceptions=@($exception)}; $p=Save-Json $d 'exceptions-valid.json'; $e=@(Import-WskExceptions $p); Assert-True ($e.Count -eq 1)
    $r=Invoke-WskEvaluation $baseline $context $facts -Exceptions $e -ClientName 'Customer A' -Mode Demo; Assert-True ($r.Summary.Excepted -eq 1)
    $d.Exceptions=@($exception,$exception); $p=Save-Json $d 'exceptions-duplicate.json'; Assert-Throws { Import-WskExceptions $p }
    $d.Exceptions=@((Copy-JsonObject $exception)); $d.Exceptions[0].Owner=''; $p=Save-Json $d 'exceptions-owner.json'; Assert-Throws { Import-WskExceptions $p }
    $d.Exceptions[0].Owner='Owner'; $d.Exceptions[0].ComputerName='*'; $p=Save-Json $d 'exceptions-wildcard.json'; Assert-Throws { Import-WskExceptions $p }
}
Test-Case 'Exceptions cannot cross customers with the same hostname and machine UUID' {
    foreach ($client in @('Customer B','customer a','Customer A ','')) {
        $r=Invoke-WskEvaluation $baseline $context $facts -Exceptions @($exception) -ClientName $client -Mode Demo
        Assert-True ($r.Summary.Excepted -eq 0 -and $r.Summary.Fail -eq 1)
    }
}
Test-Case 'Exceptions cannot cross machines with the same hostname and customer' {
    $other=Copy-JsonObject $context; $other.MachineId='22345678-abcd-5678-9abc-123456789abc'
    $r=Invoke-WskEvaluation $baseline $other $facts -Exceptions @($exception) -ClientName 'Customer A' -Mode Demo
    Assert-True ($r.Summary.Excepted -eq 0 -and $r.Summary.Fail -eq 1)
}
Test-Case 'Unavailable machine identity leaves ordinary results and rejects exceptions' {
    foreach ($value in @('','not-a-uuid','00000000-0000-0000-0000-000000000000','ffffffff-ffff-ffff-ffff-ffffffffffff')) {
        $c=Copy-JsonObject $context; $c.MachineId=$value
        $r=Invoke-WskEvaluation $baseline $c $facts -Exceptions @($exception) -ClientName 'Customer A' -Mode Demo
        Assert-True ($r.Summary.Excepted -eq 0 -and $r.Summary.Fail -eq 1 -and $r.Summary.Pass -eq 1)
        Assert-True (@($r.Warnings | Where-Object { $_ -like '*lacks a usable customer or machine identity*' }).Count -eq 1)
    }
    $c=Copy-JsonObject $context; $c.PSObject.Properties.Remove('MachineId')
    $r=Invoke-WskEvaluation $baseline $c $facts -Exceptions @($exception) -ClientName 'Customer A' -Mode Demo
    Assert-True ($r.Summary.Excepted -eq 0 -and $r.Summary.Fail -eq 1)
}
Test-Case 'Direct exception objects must carry valid customer and machine identity' {
    foreach ($property in @('ClientName','MachineId')) {
        $e=Copy-JsonObject $exception; $e.PSObject.Properties.Remove($property)
        $r=Invoke-WskEvaluation $baseline $context $facts -Exceptions @($e) -ClientName 'Customer A' -Mode Demo
        Assert-True ($r.Summary.Excepted -eq 0 -and $r.Summary.Fail -eq 1)
    }
    foreach ($value in @('not-a-uuid','00000000-0000-0000-0000-000000000000','ffffffff-ffff-ffff-ffff-ffffffffffff')) {
        $e=Copy-JsonObject $exception; $e.MachineId=$value
        $r=Invoke-WskEvaluation $baseline $context $facts -Exceptions @($e) -ClientName 'Customer A' -Mode Demo
        Assert-True ($r.Summary.Excepted -eq 0 -and $r.Summary.Fail -eq 1)
    }
}
Test-Case 'Legacy exception ledgers are ignored even if newer fields were added' {
    $d=[pscustomobject]@{SchemaVersion='1.0';Exceptions=@((Copy-JsonObject $exception))}
    foreach ($hasNewFields in @($true,$false)) {
        if (-not $hasNewFields) { $d.Exceptions[0].PSObject.Properties.Remove('ClientName'); $d.Exceptions[0].PSObject.Properties.Remove('MachineId') }
        $p=Save-Json $d 'exceptions-legacy.json'; $e=@(Import-WskExceptions $p)
        $r=Invoke-WskEvaluation $baseline $context $facts -Exceptions $e -ClientName 'Customer A' -Mode Demo
        Assert-True ($r.Summary.Excepted -eq 0 -and $r.Summary.Fail -eq 1)
        Assert-True (@($r.Warnings | Where-Object { $_ -like '*Migrate the ledger to schema 1.1*' }).Count -eq 1)
    }
}
Test-Case 'Bound exception schema rejects missing customer and unusable UUIDs' {
    foreach ($value in @('','not-a-uuid','00000000-0000-0000-0000-000000000000','ffffffff-ffff-ffff-ffff-ffffffffffff')) {
        $e=Copy-JsonObject $exception; $e.MachineId=$value
        $d=[pscustomobject]@{SchemaVersion='1.1';Exceptions=@($e)}; $p=Save-Json $d 'exceptions-invalid-uuid.json'
        Assert-Throws { Import-WskExceptions $p }
    }
    foreach ($property in @('ClientName','MachineId')) {
        $e=Copy-JsonObject $exception; $e.PSObject.Properties.Remove($property)
        $d=[pscustomobject]@{SchemaVersion='1.1';Exceptions=@($e)}; $p=Save-Json $d 'exceptions-missing-scope.json'
        Assert-Throws { Import-WskExceptions $p }
    }
}
Test-Case 'UUID formatting is normalized and hostname comparison ignores case' {
    $e=Copy-JsonObject $exception; $e.MachineId='{12345678-ABCD-5678-9ABC-123456789ABC}'; $e.ComputerName='test-host'
    $d=[pscustomobject]@{SchemaVersion='1.1';Exceptions=@($e)}; $p=Save-Json $d 'exceptions-normalized.json'; $read=@(Import-WskExceptions $p)
    Assert-True ($read[0].MachineId -ceq $context.MachineId)
    $r=Invoke-WskEvaluation $baseline $context $facts -Exceptions $read -ClientName 'Customer A' -Mode Demo
    Assert-True ($r.Summary.Excepted -eq 1)
}
Test-Case 'Ledger duplicates include customer and normalized machine UUID' {
    $e=Copy-JsonObject $exception; $e.ClientName='Customer B'
    $d=[pscustomobject]@{SchemaVersion='1.1';Exceptions=@($exception,$e)}; $p=Save-Json $d 'exceptions-different-client.json'
    Assert-True (@(Import-WskExceptions $p).Count -eq 2)
    $e.ClientName='customer a'; $p=Save-Json $d 'exceptions-case-client.json'; Assert-True (@(Import-WskExceptions $p).Count -eq 2)
    $e.ClientName='Customer A'; $e.MachineId='22345678-abcd-5678-9abc-123456789abc'
    $p=Save-Json $d 'exceptions-different-machine.json'; Assert-True (@(Import-WskExceptions $p).Count -eq 2)
    $e.MachineId='{12345678-ABCD-5678-9ABC-123456789ABC}'; $e.ComputerName='test-host'
    $p=Save-Json $d 'exceptions-normalized-duplicate.json'; Assert-Throws { Import-WskExceptions $p }
}
Test-Case 'Numeric comparison operators' {
    foreach ($spec in @(@('GreaterOrEqual',14,14),@('LessOrEqual',3,2),@('Between',@(1,5),5),@('In',@(1,2),2),@('NotEquals',0,1),@('Contains','x',@('x','y')))) {
        $b=Copy-JsonObject $baseline; $b.Controls=@((New-TestControl 'VALUE' $spec[0] $spec[1])); $r=Invoke-WskEvaluation $b $context @{VALUE=(New-TestFact $spec[2])} -Mode Demo
        Assert-True ($r.Summary.Pass -eq 1) "Failed operator $($spec[0])"
    }
}
Test-Case 'Domain controller local policy applicability' {
    $b=Import-WskBaseline (Join-Path $root 'Baselines\windows-server-foundation.v1.json'); $s=New-WskDemoSnapshot $b -Role DomainController
    $r=Invoke-WskEvaluation $b $s.Context $s.Facts -Mode Demo
    $local=@($r.Results | Where-Object { $_.Fact -like 'SecurityPolicy.*' -and $_.Status -ne 'NotApplicable' })
    Assert-True ($local.Count -eq 0)
}
Test-Case 'Contains cannot pass a partially invalid evidence array' {
    $b=Copy-JsonObject $baseline; $b.Controls=@((New-TestControl 'VALUE' 'Contains' 'x'))
    $r=Invoke-WskEvaluation $b $context @{VALUE=(New-TestFact @('x',1))} -Mode Demo
    Assert-True ($r.Summary.Error -eq 1)
}
Test-Case 'Demo all supported releases and roles' {
    $b=Import-WskBaseline (Join-Path $root 'Baselines\windows-server-foundation.v1.json')
    foreach ($release in @('2019','2022','2025')) { foreach ($role in @('MemberServer','DomainController','StandaloneServer')) {
        $s=New-WskDemoSnapshot $b -Release $release -Role $role; $r=Invoke-WskEvaluation $b $s.Context $s.Facts -Mode Demo
        Assert-True ($r.Results.Count -eq $b.Controls.Count -and $r.Mode -eq 'Demo')
    } }
}
Test-Case 'HTML encoding, offline assets and CSV formula defence' {
    $b=Copy-JsonObject $baseline; $b.Controls[0].Title='<script>alert(1)</script>'; $b.Controls[1].Title='=1+1'
    $r=Invoke-WskEvaluation $b $context $facts -Mode Demo -ClientName '<img src=x onerror=alert(1)>'
    $paths=Export-WskReport $r (Join-Path $out 'reports')
    $html=Get-Content -LiteralPath $paths.HtmlPath -Raw
    Assert-True (-not $html.Contains('<script>alert(1)</script>'))
    Assert-True (-not $html.Contains('<img src=x onerror=alert(1)>'))
    Assert-True (-not ($html -match '<(?:script|link)[^>]+(?:src|href)=["'']https?://'))
    $csv=@(Import-Csv -LiteralPath $paths.CsvPath)
    Assert-True (($csv | Where-Object Id -eq 'FAIL').Title.StartsWith("'="))
    $json=Get-Content -LiteralPath $paths.JsonPath -Raw | ConvertFrom-Json
    Assert-True ($json.Results.Count -eq 6 -and $json.Mode -eq 'Demo')
}
Write-Host "Tests: $script:passed passed; $script:failed failed. Artifacts: $out"
if ($script:failed -gt 0) { exit 1 }
exit 0
