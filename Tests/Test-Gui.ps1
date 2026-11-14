#requires -Version 5.1
<# Exercise the launcher's real synthetic child process and completion handler without showing a window. #>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$testDirectory = $PSScriptRoot
$launcher = Join-Path (Split-Path $testDirectory -Parent) 'Start-WintelSecurityGui.ps1'
. $launcher
try {
    if ($form.Visible -or $openButton.Enabled) { throw 'Unexpected initial launcher state.' }
    Show-WskBundledSample
    if ($script:scanProcess -or -not $openButton.Enabled -or $statusLabel.Text -notlike 'Bundled synthetic sample loaded*') {
        throw 'Packaged sample preview must be available without starting an assessment process.'
    }
    if ($script:lastHtmlPath -ne (Join-Path $script:kitRoot 'Samples\Demo\SecurityAssessment.html') -or $logBox.Text -notmatch 'Fail: \d+') {
        throw 'Sample preview did not display the bundled report and labelled counts.'
    }
    $script:runId = [guid]::NewGuid()
    $script:activeOutput = Join-Path $testDirectory 'Output'
    Complete-WskAssessment -ExitCode 1
    if ($openButton.Enabled -or $script:lastHtmlPath -or $statusLabel.Text -notlike 'Assessment could not complete*' -or
        $logBox.Text -notlike '*Invoke-WintelSecurityAssessment.ps1*' -or $logBox.Text -notlike '*Docs\STARTUP.md*') {
        throw 'A blocked PowerShell console must display CLI reproduction and startup diagnostics.'
    }
    # Inspect the actual launcher's native interactive configuration without
    # spawning a live collection or presenting a console during this test.
    function Start-WskConsoleProcess {
        param([Diagnostics.ProcessStartInfo]$StartInfo)
        if (-not $StartInfo.UseShellExecute -or $StartInfo.WindowStyle -ne 'Normal' -or $StartInfo.CreateNoWindow -or
            $StartInfo.RedirectStandardInput -or $StartInfo.RedirectStandardOutput -or $StartInfo.RedirectStandardError -or
            $StartInfo.Arguments -match '-NonInteractive|-ExecutionPolicy|-EncodedCommand|-Command' -or
            $StartInfo.Arguments -notmatch '"-File"' -or $StartInfo.Arguments -notmatch '"-RunId"') {
            throw 'Native interactive console contract was violated.'
        }
        $StartInfo.UseShellExecute = $false
        $StartInfo.CreateNoWindow = $true
        $StartInfo.Arguments += ' "-Demo"'
        return [Diagnostics.Process]::Start($StartInfo)
    }
    $clientValue = 'Example "client" ' + [char]0x03A9 + '\'
    $clientField.Text = $clientValue
    $outputField.Text = Join-Path $testDirectory ('Output\GUI smoke ' + [guid]::NewGuid().ToString('N').Substring(0,8))
    Start-WskAssessment
    if ($null -eq $script:scanProcess -or $runButton.Enabled) { throw ('Unable to start demo: ' + $logBox.Text) }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ($null -ne $script:scanProcess -and [DateTime]::UtcNow -lt $deadline) {
        [Windows.Forms.Application]::DoEvents()
        [Threading.Thread]::Sleep(40)
    }
    if ($null -ne $script:scanProcess) { throw 'Timed out waiting for the sample assessment.' }
    if (-not $openButton.Enabled -or -not $runButton.Enabled -or -not $script:lastHtmlPath) {
        throw ('Launcher did not expose the completed report: ' + $statusLabel.Text + ' / ' + $logBox.Text)
    }
    if (-not [IO.File]::Exists($script:lastHtmlPath)) { throw 'Missing HTML report.' }
    $resultFile = [IO.Path]::ChangeExtension($script:lastHtmlPath, '.json')
    $result = Get-Content -LiteralPath $resultFile -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($result.Mode -ne 'Demo' -or $result.ClientName -cne $clientValue -or $result.Summary.Total -ne 40) {
        throw 'Synthetic report content or quoted Unicode client argument did not round-trip.'
    }
    if ($result.Summary.Fail -lt 1 -or $statusLabel.Text -notlike 'Assessment complete. Failed controls*') { throw 'A completed sample with failures was classified incorrectly.' }
    if ($result.RunId -cne $script:runId.ToString('N')) { throw 'The full caller-generated run ID did not round-trip.' }
    $script:startedAt = [DateTime]::UtcNow
    Complete-WskAssessment -ExitCode 1
    if ($openButton.Enabled -or $script:lastHtmlPath -or $logBox.Text -notlike '*predates this assessment*') { throw 'An old run was accepted as the current report.' }
    $collision = $script:runId.ToString('N').Substring(0,8) + [guid]::NewGuid().ToString('N').Substring(8)
    $script:runId = [guid]::ParseExact($collision, 'N')
    $logBox.Clear()
    Complete-WskAssessment -ExitCode 1
    if ($openButton.Enabled -or $script:lastHtmlPath -or $logBox.Text -notlike '*No unique completed report*') { throw 'Report with a matching prefix but different full run ID was accepted.' }
    Write-Host 'PASS: interactive console configuration, packaged sample, CLI reproduction, synthetic results, full run ID matching, stale report rejection and quoted Unicode arguments.'
} finally {
    $timer.Stop()
    $timer.Dispose()
    if ($null -ne $script:scanProcess) {
        if (-not $script:scanProcess.HasExited) { $script:scanProcess.Kill() }
        $script:scanProcess.Dispose()
    }
    $form.Dispose()
}
