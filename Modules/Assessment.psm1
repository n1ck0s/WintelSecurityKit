#requires -Version 5.1
Set-StrictMode -Version Latest

function Read-WskJson {
    param([Parameter(Mandatory)][string]$Path)
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -gt 5MB) { throw 'JSON input must be a file smaller than 5 MB.' }
    try { return (Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw "Invalid JSON in '$Path': $($_.Exception.Message)" }
}

function Assert-WskProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object -or $null -eq $Object.PSObject.Properties[$Name]) { throw "Required property '$Name' is missing." }
}

function Test-WskNumber {
    param($Value)
    return ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [single] -or $Value -is [double] -or $Value -is [decimal])
}

function Test-WskCompatibleType {
    param($Actual,$Expected)
    if (Test-WskNumber $Expected) { return (Test-WskNumber $Actual) }
    if ($Expected -is [bool]) { return ($Actual -is [bool]) }
    return ($Actual -is [string] -and $Expected -is [string])
}

function Import-WskBaseline {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $baseline = Read-WskJson -Path $Path
    foreach ($name in @('SchemaVersion','Id','Name','Version','Framework','Description','SourceUrls','Controls')) { Assert-WskProperty $baseline $name }
    if ($baseline.SchemaVersion -cne '1.0') { throw 'Unsupported baseline schema. Expected 1.0.' }
    foreach ($name in @('Id','Name','Version','Framework','Description')) {
        if ($baseline.$name -isnot [string] -or [string]::IsNullOrWhiteSpace($baseline.$name)) { throw "Baseline '$name' must be a nonempty string." }
    }
    if ($baseline.Id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$') { throw 'Invalid baseline ID.' }
    if ($baseline.Controls -isnot [array] -or $baseline.Controls.Count -lt 1 -or $baseline.Controls.Count -gt 2000) { throw 'Baseline requires 1 to 2000 controls in an array.' }
    if ($baseline.SourceUrls -isnot [array] -or $baseline.SourceUrls.Count -eq 0) { throw 'SourceUrls must be a nonempty array.' }
    foreach ($sourceUrl in $baseline.SourceUrls) {
        $sourceUri = $null
        if ($sourceUrl -isnot [string] -or -not [Uri]::TryCreate($sourceUrl,[UriKind]::Absolute,[ref]$sourceUri) -or $sourceUri.Scheme -notin @('http','https')) { throw 'Baseline source URLs must be absolute HTTP(S) links.' }
    }
    $ids = @{}
    foreach ($control in $baseline.Controls) {
        foreach ($name in @('Id','Title','Category','Severity','Assessment','Roles','Releases','Fact','Operator','Expected','ExpectedDisplay','Rationale','Remediation','SourceUrl')) { Assert-WskProperty $control $name }
        foreach ($name in @('Id','Title','Category','ExpectedDisplay','Rationale','Remediation')) {
            if ($control.$name -isnot [string] -or [string]::IsNullOrWhiteSpace($control.$name)) { throw "Control '$($control.Id)' requires nonempty '$name'." }
        }
        if ($control.Id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$' -or $ids.ContainsKey($control.Id)) { throw "Invalid or duplicate control ID '$($control.Id)'." }
        $ids[$control.Id] = $true
        if ($control.Severity -cnotin @('Critical','High','Medium','Low','Informational')) { throw "Invalid severity for '$($control.Id)'." }
        if ($control.Assessment -cnotin @('Automated','Manual')) { throw "Invalid assessment type for '$($control.Id)'." }
        foreach ($pair in @(@('Roles',@('MemberServer','DomainController','StandaloneServer')),@('Releases',@('2019','2022','2025')))) {
            $values = $control.($pair[0])
            if ($values -isnot [array] -or $values.Count -eq 0) { throw "'$($pair[0])' must be a nonempty array for '$($control.Id)'." }
            foreach ($v in $values) { if ($v -cnotin $pair[1]) { throw "Unsupported applicability '$v' for '$($control.Id)'." } }
        }
        $uri = $null
        if (-not [Uri]::TryCreate([string]$control.SourceUrl, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -notin @('http','https')) { throw "Invalid source URL for '$($control.Id)'." }
        if ($control.Assessment -eq 'Manual') { continue }
        if ($control.Fact -isnot [string] -or [string]::IsNullOrWhiteSpace($control.Fact)) { throw "Automated control '$($control.Id)' requires a fact name." }
        if ($control.Operator -cnotin @('Equals','NotEquals','GreaterOrEqual','LessOrEqual','Between','In','Contains')) { throw "Unsupported operator for '$($control.Id)'." }
        if ($null -eq $control.Expected) { throw "Automated control '$($control.Id)' requires an expected value." }
        if ($control.Operator -in @('GreaterOrEqual','LessOrEqual') -and -not (Test-WskNumber $control.Expected)) { throw "Numeric comparison requires a number for '$($control.Id)'." }
        if ($control.Operator -eq 'Between') {
            if ($control.Expected -isnot [array] -or $control.Expected.Count -ne 2 -or -not (Test-WskNumber $control.Expected[0]) -or -not (Test-WskNumber $control.Expected[1]) -or $control.Expected[0] -gt $control.Expected[1]) { throw "Between requires [minimum, maximum] for '$($control.Id)'." }
        }
        if ($control.Operator -eq 'In' -and ($control.Expected -isnot [array] -or $control.Expected.Count -eq 0)) { throw "In requires a nonempty array for '$($control.Id)'." }
        foreach ($v in @($control.Expected)) { if ($v -isnot [string] -and $v -isnot [bool] -and -not (Test-WskNumber $v)) { throw "Expected values must be scalar strings, booleans or numbers for '$($control.Id)'." } }
        if ($control.Operator -eq 'In') {
            foreach ($v in $control.Expected) { if (-not (Test-WskCompatibleType $v $control.Expected[0])) { throw "In requires values of one type for '$($control.Id)'." } }
        }
        if ($control.Operator -notin @('Between','In') -and $control.Expected -is [array]) { throw "Expected value must be scalar for '$($control.Id)'." }
    }
    return $baseline
}

function Import-WskExceptions {
    [CmdletBinding()]
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $document = Read-WskJson $Path
    Assert-WskProperty $document 'SchemaVersion'
    Assert-WskProperty $document 'Exceptions'
    if ($document.SchemaVersion -cne '1.0' -or $document.Exceptions -isnot [array]) { throw 'Invalid exceptions document schema.' }
    $seen = @{}
    foreach ($item in $document.Exceptions) {
        foreach ($name in @('ControlId','ComputerName','BaselineId','BaselineVersion','Reason','Owner','Ticket','ExpiresOn')) {
            Assert-WskProperty $item $name
            if ($item.$name -isnot [string] -or [string]::IsNullOrWhiteSpace($item.$name)) { throw "Exception requires a nonempty '$name'." }
        }
        if ($item.ComputerName -match '[*?\[\]]') { throw 'Exception ComputerName must identify one exact host; wildcards are not supported.' }
        $date = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($item.ExpiresOn,'yyyy-MM-dd',[cultureinfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$date)) { throw 'Exception ExpiresOn must use yyyy-MM-dd (valid through that UTC date).' }
        $key = '{0}|{1}|{2}|{3}' -f $item.ComputerName,$item.BaselineId,$item.BaselineVersion,$item.ControlId
        if ($seen.ContainsKey($key)) { throw "Duplicate exception '$key'." }
        $seen[$key] = $true
        Write-Output $item
    }
}

function Test-WskEqual {
    param($Actual,$Expected)
    if (Test-WskNumber $Expected) {
        if (-not (Test-WskNumber $Actual)) { throw 'Collected evidence has a different type than the numeric baseline value.' }
        return ([decimal]$Actual -eq [decimal]$Expected)
    }
    if ($Expected -is [bool]) {
        if ($Actual -isnot [bool]) { throw 'Collected evidence must be a boolean; strings are not coerced to booleans.' }
        return ($Actual -eq $Expected)
    }
    if ($Actual -isnot [string]) { throw 'Collected evidence must be a string for this comparison.' }
    return [string]::Equals($Actual,[string]$Expected,[StringComparison]::OrdinalIgnoreCase)
}

function Test-WskComparison {
    param($Actual,[string]$Operator,$Expected)
    if ($null -eq $Actual) { throw 'Collected evidence is null.' }
    switch ($Operator) {
        'Equals' { return (Test-WskEqual $Actual $Expected) }
        'NotEquals' { return (-not (Test-WskEqual $Actual $Expected)) }
        'GreaterOrEqual' { if (-not (Test-WskNumber $Actual)) { throw 'Expected numeric collected evidence.' }; return ([decimal]$Actual -ge [decimal]$Expected) }
        'LessOrEqual' { if (-not (Test-WskNumber $Actual)) { throw 'Expected numeric collected evidence.' }; return ([decimal]$Actual -le [decimal]$Expected) }
        'Between' { if (-not (Test-WskNumber $Actual)) { throw 'Expected numeric collected evidence.' }; return ([decimal]$Actual -ge [decimal]$Expected[0] -and [decimal]$Actual -le [decimal]$Expected[1]) }
        'In' { foreach ($v in $Expected) { if (Test-WskEqual $Actual $v) { return $true } }; return $false }
        'Contains' { if ($Actual -isnot [array]) { throw 'Contains requires an array of collected values.' }; foreach ($v in $Actual) { if (-not (Test-WskCompatibleType $v $Expected)) { throw 'Contains requires collected values of the expected type.' } }; foreach ($v in $Actual) { if (Test-WskEqual $v $Expected) { return $true } }; return $false }
        default { throw "Unknown comparison '$Operator'." }
    }
}

function Invoke-WskEvaluation {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Baseline,[Parameter(Mandatory)]$Context,[Parameter(Mandatory)][System.Collections.IDictionary]$Facts,
        [object[]]$Exceptions = @(), [string]$ClientName = '', [ValidateSet('Live','Demo')][string]$Mode = 'Live',
        [string]$StartedAtUtc = ([datetime]::UtcNow.ToString('o')), [datetime]$AsOfUtc = [datetime]::UtcNow,
        [guid]$RunId = [guid]::NewGuid())
    $warnings = New-Object 'System.Collections.Generic.List[string]'
    if ($Mode -eq 'Demo') { $warnings.Add('SYNTHETIC DEMONSTRATION: no server was assessed. All evidence is fabricated for preview and testing.') }
    if (-not $Context.IsAdministrator -and $Mode -eq 'Live') { $warnings.Add('The process is not elevated. Some evidence may be unavailable. Rerun in an approved elevated session for fuller collection.') }
    $warnings.Add('This baseline is a scoped posture assessment. It does not certify CIS, Microsoft baseline, STIG or Essential Eight compliance. Check the baseline version, applicability and manual evidence.')
    $validExceptions = @{}
    foreach ($exception in $Exceptions) {
        if ($exception.ComputerName -ine $Context.ComputerName -or $exception.BaselineId -cne $Baseline.Id -or $exception.BaselineVersion -cne $Baseline.Version) { $warnings.Add("Exception for '$($exception.ControlId)' does not match this host and baseline version; ignored."); continue }
        if ($exception.ControlId -notin @($Baseline.Controls.Id)) { $warnings.Add("Exception references unknown control '$($exception.ControlId)'; ignored."); continue }
        $expiry = [datetime]::ParseExact($exception.ExpiresOn,'yyyy-MM-dd',[cultureinfo]::InvariantCulture)
        if ($expiry.Date -lt $AsOfUtc.ToUniversalTime().Date) { $warnings.Add("Expired exception for '$($exception.ControlId)' ignored (expiry $($exception.ExpiresOn) UTC)."); continue }
        $validExceptions[$exception.ControlId] = $exception
    }
    $results = New-Object 'System.Collections.Generic.List[object]'
    foreach ($control in $Baseline.Controls) {
        $status = 'Review'; $actual = $null; $evidence = ''; $reason = ''; $exception = $null
        if ($Context.Role -cnotin $control.Roles -or $Context.ServerRelease -cnotin $control.Releases) { $status = 'NotApplicable'; $reason = 'Outside the control server release or role scope.' }
        elseif ($control.Assessment -eq 'Manual') { $reason = 'Requires evidence and an assessor decision outside this automated local scan.' }
        elseif (-not $Facts.Contains($control.Fact)) { $reason = 'The collector returned no fact for this control.' }
        else {
            $fact = $Facts[$control.Fact]
            try {
                foreach ($property in @('State','Value','Evidence','Reason')) { Assert-WskProperty $fact $property }
                $actual = $fact.Value; $evidence = [string]$fact.Evidence; $reason = [string]$fact.Reason
                switch -CaseSensitive ($fact.State) {
                    'Collected' { if (Test-WskComparison $actual $control.Operator $control.Expected) { $status = 'Pass' } else { $status = 'Fail' } }
                    'Unavailable' { $status = 'Review' }
                    'Error' { $status = 'Error' }
                    default { throw "Invalid fact state '$($fact.State)'." }
                }
            } catch { $status = 'Error'; $reason = $_.Exception.Message }
        }
        $underlyingStatus = $status
        if ($validExceptions.ContainsKey($control.Id)) {
            if ($status -eq 'Fail') { $exception = $validExceptions[$control.Id]; $status = 'Excepted' }
            else { $warnings.Add("Exception for '$($control.Id)' was not applied: its result is $status. Only confirmed failures may be excepted.") }
        }
        $row = [ordered]@{
            Id=$control.Id; Title=$control.Title; Category=$control.Category; Severity=$control.Severity; Status=$status; UnderlyingStatus=$underlyingStatus
            Expected=$control.ExpectedDisplay; Actual=$actual; Evidence=$evidence; Reason=$reason; Rationale=$control.Rationale; Remediation=$control.Remediation
            SourceUrl=$control.SourceUrl; Fact=$control.Fact; Assessment=$control.Assessment; Exception=$exception
        }
        if ($control.PSObject.Properties['SourceRuleId']) { $row.SourceRuleId = $control.SourceRuleId }
        $results.Add([pscustomobject]$row)
    }
    $summary = [ordered]@{}
    foreach ($status in @('Pass','Fail','Review','Error','NotApplicable','Excepted')) { $summary[$status] = @($results | Where-Object { $_.Status -eq $status }).Count }
    $summary.Total = $results.Count
    $summary.AutomatedApplicable = @($results | Where-Object { $_.Assessment -eq 'Automated' -and $_.UnderlyingStatus -ne 'NotApplicable' }).Count
    $summary.UnderlyingPass = @($results | Where-Object { $_.UnderlyingStatus -eq 'Pass' }).Count
    $summary.UnderlyingFail = @($results | Where-Object { $_.UnderlyingStatus -eq 'Fail' }).Count
    $summary.Evaluated = $summary.UnderlyingPass + $summary.UnderlyingFail
    if ($Baseline.PSObject.Properties['SourceProfileId']) {
        $applicable = $summary.Total - $summary.NotApplicable
        $manual = $applicable - $summary.AutomatedApplicable
        $warnings.Add("Imported profile $($Baseline.SourceProfileId). Of $applicable applicable recommendations, $($summary.Evaluated) produced a tested result and $manual require manual assessment. Compare unresolved items with the source benchmark.")
    }
    $summary.PassRatePercent = $null
    $summary.CoveragePercent = $null
    if ($summary.Evaluated -gt 0) { $summary.PassRatePercent = [math]::Round(100.0 * $summary.UnderlyingPass / $summary.Evaluated,1) }
    if ($summary.AutomatedApplicable -gt 0) { $summary.CoveragePercent = [math]::Round(100.0 * $summary.Evaluated / $summary.AutomatedApplicable,1) }
    $baselineInfo = [ordered]@{Id=$Baseline.Id;Name=$Baseline.Name;Version=$Baseline.Version;Framework=$Baseline.Framework;Description=$Baseline.Description;SourceUrls=$Baseline.SourceUrls}
    foreach ($key in @('SourceBenchmarkId','SourceBenchmarkVersion','SourceProfileId','SourceSha256','SourceMappingSha256')) {
        if ($Baseline.PSObject.Properties[$key]) { $baselineInfo[$key] = $Baseline.$key }
    }
    return [pscustomobject][ordered]@{
        SchemaVersion='1.0'; KitVersion='0.2.0'; RunId=$RunId.ToString('N'); StartedAtUtc=$StartedAtUtc; CompletedAtUtc=[datetime]::UtcNow.ToString('o')
        Mode=$Mode; ClientName=$ClientName; Context=$Context
        Baseline=[pscustomobject]$baselineInfo
        Summary=[pscustomobject]$summary; Results=$results.ToArray(); Warnings=$warnings.ToArray()
    }
}

function New-WskDemoSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Baseline,[ValidateSet('MemberServer','DomainController','StandaloneServer')][string]$Role='MemberServer',[ValidateSet('2019','2022','2025')][string]$Release='2022')
    $facts = @{}; $i = 0
    foreach ($c in $Baseline.Controls) {
        if ($c.Assessment -ne 'Automated') { continue }
        $i++
        $value = $c.Expected
        if ($c.Operator -in @('Between','In')) { $value = $c.Expected[0] }
        if ($c.Operator -eq 'Contains') { $value = @($c.Expected) }
        if ($c.Operator -eq 'NotEquals') { if ($value -is [bool]) { $value = -not $value } elseif (Test-WskNumber $value) { $value = $value + 1 } else { $value = 'Synthetic different value' } }
        $state = 'Collected'; $reason = ''
        if ($i % 11 -eq 0) { $state = 'Error'; $value = $null; $reason = 'Synthetic collector failure.' }
        elseif ($i % 7 -eq 0) { $state = 'Unavailable'; $value = $null; $reason = 'Synthetic unavailable evidence.' }
        elseif ($i % 5 -eq 0) {
            switch ($c.Operator) {
                'NotEquals' { $value = $c.Expected }
                'GreaterOrEqual' { $value = $c.Expected - 1 }
                'LessOrEqual' { $value = $c.Expected + 1 }
                'Between' { $value = $c.Expected[1] + 1 }
                'Contains' { $value = @() }
                'In' { if (Test-WskNumber $c.Expected[0]) { $value = ($c.Expected | Measure-Object -Maximum).Maximum + 1 } else { $value = '__synthetic_mismatch__' } }
                default { if ($value -is [bool]) { $value = -not $value } elseif (Test-WskNumber $value) { $value = $value + 1 } else { $value = 'Synthetic mismatch' } }
            }
        }
        $facts[$c.Fact] = [pscustomobject]@{State=$state;Value=$value;Evidence='SYNTHETIC sample evidence; no host queried.';Reason=$reason}
    }
    $builds = @{'2019'='17763';'2022'='20348';'2025'='26100'}
    $context = [pscustomobject]@{ComputerName="WSK-DEMO-$Release";OSCaption="SYNTHETIC Windows Server $Release";OSVersion="10.0.$($builds[$Release])";BuildNumber=$builds[$Release];ServerRelease=$Release;Role=$Role;IsAdministrator=$false;CollectedAtUtc=[datetime]::UtcNow.ToString('o');Supported=$true;Is64Bit=$true}
    return [pscustomobject]@{Context=$context;Facts=$facts}
}

Export-ModuleMember -Function Import-WskBaseline,Import-WskExceptions,Invoke-WskEvaluation,New-WskDemoSnapshot
