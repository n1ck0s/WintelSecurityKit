#requires -Version 5.1
Set-StrictMode -Version 2.0

function ConvertTo-WskDisplayText {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '(not available)' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool]) { return $Value.ToString().ToLowerInvariant() }
    if ($Value -is [ValueType]) { return [string]$Value }
    return ($Value | ConvertTo-Json -Depth 12 -Compress)
}

function ConvertTo-WskHtml {
    param([AllowNull()]$Value)
    return [System.Net.WebUtility]::HtmlEncode((ConvertTo-WskDisplayText $Value))
}

function ConvertTo-WskCsvCell {
    param([AllowNull()]$Value)
    $text = ConvertTo-WskDisplayText $Value
    # CSV quoting alone does not prevent spreadsheet formula execution.
    if ($text -match '^\s*[=+\-@]' -or $text -match '^[\t\r\n]') { return "'" + $text }
    return $text
}

function ConvertTo-WskSourceLink {
    param([AllowNull()]$Value)
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return '' }
    $uri = $null
    if ([Uri]::TryCreate([string]$Value, [UriKind]::Absolute, [ref]$uri) -and $uri.Scheme -in @('https', 'http')) {
        $safe = [System.Net.WebUtility]::HtmlEncode($uri.AbsoluteUri)
        return '<a href="' + $safe + '" target="_blank" rel="noopener noreferrer">Source documentation</a>'
    }
    return '<span class="muted">Source: ' + (ConvertTo-WskHtml $Value) + '</span>'
}

function Export-WskReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Report,
        [Parameter(Mandatory)][string]$OutputDirectory
    )
    $directory = [IO.Path]::GetFullPath($OutputDirectory)
    if (-not [IO.Directory]::Exists($directory)) { [void][IO.Directory]::CreateDirectory($directory) }
    $htmlPath = Join-Path $directory 'SecurityAssessment.html'
    $jsonPath = Join-Path $directory 'SecurityAssessment.json'
    $csvPath = Join-Path $directory 'SecurityAssessment.csv'
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($jsonPath, ($Report | ConvertTo-Json -Depth 40), $encoding)

    $csvRows = foreach ($result in $Report.Results) {
        [pscustomobject][ordered]@{
            ComputerName = ConvertTo-WskCsvCell $Report.Context.ComputerName
            ClientName = ConvertTo-WskCsvCell $Report.ClientName
            Baseline = ConvertTo-WskCsvCell $Report.Baseline.Name
            BaselineVersion = ConvertTo-WskCsvCell $Report.Baseline.Version
            Mode = ConvertTo-WskCsvCell $Report.Mode
            Id = ConvertTo-WskCsvCell $result.Id
            Title = ConvertTo-WskCsvCell $result.Title
            Category = ConvertTo-WskCsvCell $result.Category
            Severity = ConvertTo-WskCsvCell $result.Severity
            Assessment = ConvertTo-WskCsvCell $result.Assessment
            Status = ConvertTo-WskCsvCell $result.Status
            UnderlyingStatus = ConvertTo-WskCsvCell $result.UnderlyingStatus
            Expected = ConvertTo-WskCsvCell $result.Expected
            Actual = ConvertTo-WskCsvCell $result.Actual
            Evidence = ConvertTo-WskCsvCell $result.Evidence
            Reason = ConvertTo-WskCsvCell $result.Reason
            Rationale = ConvertTo-WskCsvCell $result.Rationale
            Remediation = ConvertTo-WskCsvCell $result.Remediation
            SourceUrl = ConvertTo-WskCsvCell $result.SourceUrl
            Fact = ConvertTo-WskCsvCell $result.Fact
            Exception = ConvertTo-WskCsvCell $result.Exception
        }
    }
    $csvLines = @($csvRows | ConvertTo-Csv -NoTypeInformation)
    [IO.File]::WriteAllLines($csvPath, [string[]]$csvLines, $encoding)

    $rows = New-Object Text.StringBuilder
    foreach ($result in $Report.Results) {
        $statusClass = switch ([string]$result.Status) {
            'Pass' { 'pass' }; 'Fail' { 'fail' }; 'Review' { 'review' }
            'Error' { 'error' }; 'Excepted' { 'excepted' }; default { 'na' }
        }
        $sourceLink = ConvertTo-WskSourceLink $result.SourceUrl
        $exceptionHtml = ''
        if ($null -ne $result.Exception) {
            $exceptionHtml = '<dt>Approved exception</dt><dd class="pre">' + (ConvertTo-WskHtml $result.Exception) + '</dd>'
        }
        [void]$rows.Append(@"
<tr class="finding" data-status="$(ConvertTo-WskHtml $result.Status)">
<td><span class="status $statusClass">$(ConvertTo-WskHtml $result.Status)</span><div class="minor">Underlying: $(ConvertTo-WskHtml $result.UnderlyingStatus)</div></td>
<td><details><summary><strong>$(ConvertTo-WskHtml $result.Title)</strong><span class="minor">$(ConvertTo-WskHtml $result.Id) &middot; $(ConvertTo-WskHtml $result.Category) &middot; $(ConvertTo-WskHtml $result.Assessment)</span></summary>
<dl><dt>Expected</dt><dd class="pre">$(ConvertTo-WskHtml $result.Expected)</dd><dt>Observed</dt><dd class="pre">$(ConvertTo-WskHtml $result.Actual)</dd>
<dt>Evidence</dt><dd class="pre">$(ConvertTo-WskHtml $result.Evidence)</dd><dt>Assessment notes</dt><dd class="pre">$(ConvertTo-WskHtml $result.Reason)</dd>
<dt>Why this matters</dt><dd>$(ConvertTo-WskHtml $result.Rationale)</dd><dt>Suggested action</dt><dd>$(ConvertTo-WskHtml $result.Remediation)</dd>
<dt>Fact</dt><dd class="pre">$(ConvertTo-WskHtml $result.Fact)</dd>$exceptionHtml</dl><p>$sourceLink</p></details></td>
<td>$(ConvertTo-WskHtml $result.Severity)</td></tr>
"@)
    }
    $warnings = ''
    if (@($Report.Warnings).Count -gt 0) {
        $warningItems = @($Report.Warnings | ForEach-Object { '<li>' + (ConvertTo-WskHtml $_) + '</li>' }) -join ''
        $warnings = '<aside class="notice"><strong>Assessment limitations</strong><ul>' + $warningItems + '</ul></aside>'
    }
    $demoBanner = ''
    if ($Report.Mode -eq 'Demo') { $demoBanner = '<aside class="demo">SAMPLE REPORT &mdash; synthetic evidence only. This report does not assess this computer.</aside>' }
    $passRate = 'N/A'
    $coverage = 'N/A'
    if ($null -ne $Report.Summary.PassRatePercent) { $passRate = (ConvertTo-WskHtml $Report.Summary.PassRatePercent) + '%' }
    if ($null -ne $Report.Summary.CoveragePercent) { $coverage = (ConvertTo-WskHtml $Report.Summary.CoveragePercent) + '%' }
    $sources = @($Report.Baseline.SourceUrls | ForEach-Object { ConvertTo-WskSourceLink $_ }) -join ' &middot; '
    $html = @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Security posture | $(ConvertTo-WskHtml $Report.Context.ComputerName)</title>
<style>
:root{color-scheme:light;--navy:#102b46;--ink:#19354b;--muted:#5b6e7c;--line:#dce5ec;--teal:#087f83}*{box-sizing:border-box}body{margin:0;background:#f2f6f9;color:var(--ink);font:15px/1.55 "Segoe UI",Arial,sans-serif}.wrap{max-width:1200px;margin:auto;padding:30px 26px}header{background:var(--navy);color:white}header .wrap{padding-top:34px;padding-bottom:32px}.eyebrow{font-size:12px;letter-spacing:2px;text-transform:uppercase;color:#a5dfe2;font-weight:700}h1{margin:8px 0;font-size:32px;line-height:1.2}h2{font-size:20px;margin:26px 0 12px}.subtitle{color:#d3e1eb;margin:0}.metadata{display:flex;gap:8px 25px;flex-wrap:wrap;margin-top:16px;font-size:13px}.metadata b{color:#b7d1e3;margin-right:5px}.demo{background:#fff0bf;border:1px solid #e3b647;color:#694600;padding:14px 18px;font-weight:700;margin-bottom:18px}.notice{background:#fff7e4;border-left:4px solid #bf8d24;padding:14px 18px;margin:18px 0}.notice ul{margin:6px 0;padding-left:20px}.scope{margin:0 0 20px;color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.card{background:white;padding:20px;border:1px solid var(--line);border-radius:8px}.card .label{font-size:12px;text-transform:uppercase;font-weight:700;color:var(--muted);letter-spacing:.6px}.card .number{font-size:34px;font-weight:700;color:var(--navy);line-height:1.3}.card small{color:var(--muted)}.card.failcard{border-top:3px solid #c4493d}.card.reviewcard{border-top:3px solid #c59525}.card.ratecard{border-top:3px solid var(--teal)}.explain{font-size:13px;color:var(--muted);margin-top:12px}.breakdown{background:white;border:1px solid var(--line);border-radius:8px;padding:13px 18px;display:flex;flex-wrap:wrap;gap:10px 22px;font-size:14px}.filters{display:flex;gap:12px;margin:14px 0;align-items:center;flex-wrap:wrap}.filters input{flex:1;min-width:220px}.filters input,.filters select,.filters button{font:inherit;padding:9px 12px;border:1px solid #b6c8d4;border-radius:5px;background:white;color:var(--ink)}.filters button{cursor:pointer}.filters label{font-weight:600;font-size:13px}.tablebox{border:1px solid var(--line);border-radius:8px;background:white;overflow:hidden}table{width:100%;border-collapse:collapse}th{text-align:left;background:#eaf0f5;padding:12px 16px;font-size:12px;text-transform:uppercase;letter-spacing:.5px}td{padding:15px 16px;border-top:1px solid var(--line);vertical-align:top}th:first-child{width:155px}th:last-child{width:90px}summary{cursor:pointer}summary strong{font-size:15px}.minor{font-size:12px;color:var(--muted);display:block;margin-top:4px}.status{font-size:12px;padding:4px 9px;border-radius:4px;font-weight:700;display:inline-block}.pass{color:#146543;background:#def2e8}.fail{color:#a32c25;background:#fde8e5}.review{color:#805a08;background:#fff1c7}.error{color:#8c2c6c;background:#f7e4f1}.excepted{color:#534184;background:#ece7fa}.na{color:#586b7c;background:#eaf0f4}dl{display:grid;grid-template-columns:140px 1fr;gap:10px;margin:18px 0}dt{font-size:12px;color:var(--muted);font-weight:700}dd{margin:0;overflow-wrap:anywhere;font-size:13px}.pre{white-space:pre-wrap;font-family:Consolas,monospace;font-size:12px}a{color:#076d8c}footer{margin-top:24px;font-size:12px;color:var(--muted)}.hidden{display:none!important}.muted{color:var(--muted)}#visibleCount{font-size:13px;color:var(--muted)}@media(max-width:750px){.cards{grid-template-columns:repeat(2,1fr)}.wrap{padding:20px 14px}td,th{padding:10px}th:first-child{width:110px}dl{grid-template-columns:1fr;gap:4px}dd{margin-bottom:10px}}@media print{body{background:white;font-size:11px}.wrap{max-width:none;padding:16px 0}header{background:white;color:var(--ink)}header .subtitle,header .metadata b,.eyebrow{color:var(--muted)}.filters{display:none}.cards{grid-template-columns:repeat(4,1fr)}.card{padding:10px}.card .number{font-size:25px}details>dl,details>p{display:block}tr{break-inside:avoid}footer{break-inside:avoid}}
</style></head><body><header><div class="wrap"><div class="eyebrow">Wintel Security Kit / posture assessment</div><h1>$(ConvertTo-WskHtml $Report.Context.ComputerName)</h1><p class="subtitle">$(ConvertTo-WskHtml $Report.Context.OSCaption) &middot; $(ConvertTo-WskHtml $Report.Context.Role)</p>
<div class="metadata"><span><b>Client</b>$(ConvertTo-WskHtml $Report.ClientName)</span><span><b>Baseline</b>$(ConvertTo-WskHtml $Report.Baseline.Name) v$(ConvertTo-WskHtml $Report.Baseline.Version)</span><span><b>Completed (UTC)</b>$(ConvertTo-WskHtml $Report.CompletedAtUtc)</span></div></div></header>
<main class="wrap">$demoBanner<p class="scope">Read-only, local configuration assessment. This baseline covers a defined subset of settings; it is not a CIS certification, a full benchmark assessment, or a vulnerability scan. Unknown evidence never counts as a pass.</p>
<div class="cards"><div class="card failcard"><div class="label">Failed controls</div><div class="number">$(ConvertTo-WskHtml $Report.Summary.Fail)</div><small>Excludes approved exceptions</small></div><div class="card reviewcard"><div class="label">Review / errors</div><div class="number">$([int]$Report.Summary.Review + [int]$Report.Summary.Error)</div><small>Evidence or manual action needed</small></div><div class="card ratecard"><div class="label">Tested pass rate</div><div class="number">$passRate</div><small>Underlying pass / (pass + fail)</small></div><div class="card ratecard"><div class="label">Automated coverage</div><div class="number">$coverage</div><small>$(ConvertTo-WskHtml $Report.Summary.Evaluated) / $(ConvertTo-WskHtml $Report.Summary.AutomatedApplicable) applicable automated checks</small></div></div>
<p class="explain">Pass rate uses all tested results, including approved exceptions. Coverage is the proportion of applicable automated checks with a Pass/Fail result. Manual checks, missing evidence and collector errors are not passes. An exception records accepted risk; it does not improve the tested pass rate.</p>
<div class="breakdown"><span><b>Pass:</b> $(ConvertTo-WskHtml $Report.Summary.Pass)</span><span><b>Fail:</b> $(ConvertTo-WskHtml $Report.Summary.Fail)</span><span><b>Review:</b> $(ConvertTo-WskHtml $Report.Summary.Review)</span><span><b>Error:</b> $(ConvertTo-WskHtml $Report.Summary.Error)</span><span><b>Excepted:</b> $(ConvertTo-WskHtml $Report.Summary.Excepted)</span><span><b>Not applicable:</b> $(ConvertTo-WskHtml $Report.Summary.NotApplicable)</span><span><b>Total:</b> $(ConvertTo-WskHtml $Report.Summary.Total)</span></div>
$warnings<h2>Findings and evidence</h2><div class="filters"><label for="search">Search</label><input id="search" type="search" placeholder="Control, setting or evidence"><label for="status">Status</label><select id="status"><option value="">All statuses</option><option>Fail</option><option>Review</option><option>Error</option><option>Excepted</option><option>Pass</option><option>NotApplicable</option></select><button type="button" id="expand">Expand visible details</button><span id="visibleCount" aria-live="polite"></span></div>
<div class="tablebox"><table><thead><tr><th>Status</th><th>Control / evidence</th><th>Severity</th></tr></thead><tbody>$($rows.ToString())</tbody></table></div><p id="empty" class="hidden">No findings match these filters.</p>
<footer><p>$(ConvertTo-WskHtml $Report.Baseline.Description)</p><p>Framework: $(ConvertTo-WskHtml $Report.Baseline.Framework) &middot; Run: $(ConvertTo-WskHtml $Report.RunId) &middot; Kit: $(ConvertTo-WskHtml $Report.KitVersion) &middot; Schema: $(ConvertTo-WskHtml $Report.SchemaVersion)</p><p>Started (UTC): $(ConvertTo-WskHtml $Report.StartedAtUtc) &middot; Evidence collected (UTC): $(ConvertTo-WskHtml $Report.Context.CollectedAtUtc) &middot; Elevated: $(ConvertTo-WskHtml $Report.Context.IsAdministrator)</p><p>$sources</p><p>Report files can contain sensitive system configuration. Store and share through your approved service-management process. Suggested actions require normal change assessment before implementation.</p></footer></main>
<script>
(function(){'use strict';var rows=Array.prototype.slice.call(document.querySelectorAll('.finding'));var search=document.getElementById('search');var status=document.getElementById('status');function filter(){var q=search.value.toLowerCase();var n=0;rows.forEach(function(row){var show=(!status.value||row.getAttribute('data-status')===status.value)&&row.textContent.toLowerCase().indexOf(q)!==-1;row.classList.toggle('hidden',!show);if(show)n++;});document.getElementById('visibleCount').textContent=n+' of '+rows.length+' shown';document.getElementById('empty').classList.toggle('hidden',n!==0);}search.addEventListener('input',filter);status.addEventListener('change',filter);document.getElementById('expand').addEventListener('click',function(){rows.forEach(function(row){if(!row.classList.contains('hidden'))row.querySelector('details').open=true;});});filter();})();
</script></body></html>
"@
    [IO.File]::WriteAllText($htmlPath, $html, $encoding)
    return [pscustomobject]@{ HtmlPath = $htmlPath; JsonPath = $jsonPath; CsvPath = $csvPath }
}

Export-ModuleMember -Function Export-WskReport
