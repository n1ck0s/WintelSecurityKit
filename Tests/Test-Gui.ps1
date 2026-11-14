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
    Complete-WskAssessment -ExitCode 1 -ConsoleOutput '' -ConsoleError 'AuthorizationManager check failed. FullyQualifiedErrorId : UnauthorizedAccess'
    if ($openButton.Enabled -or $script:lastHtmlPath -or $statusLabel.Text -notlike '*authorization error*' -or
        $logBox.Text -notlike '*FullyQualifiedErrorId : UnauthorizedAccess*' -or $logBox.Text -notlike '*Docs\STARTUP.md*') {
        throw 'A blocked PowerShell child was classified as an assessment or raw error details were lost.'
    }
    Complete-WskAssessment -ExitCode 1 -ConsoleOutput 'PowerShell startup failure' -ConsoleError 'Unspecific load failure'
    if ($openButton.Enabled -or $statusLabel.Text -notlike 'Assessment could not complete*' -or $logBox.Text -notlike '*No unique report completion marker*') {
        throw 'A child exit code of 1 without the assessment marker must not be classified as findings.'
    }
    $clientValue = 'Example "client" ' + [char]0x03A9 + '\'
    $clientField.Text = $clientValue
    $outputField.Text = Join-Path $testDirectory ('Output\GUI smoke ' + [guid]::NewGuid().ToString('N').Substring(0,8))
    Start-WskAssessment -Demo $true
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
    $completedMarker = 'WSK_REPORT_DIR=' + (Split-Path (Split-Path $script:lastHtmlPath -Parent) -Leaf)
    $script:startedAt = [DateTime]::UtcNow
    Complete-WskAssessment -ExitCode 1 -ConsoleOutput $completedMarker -ConsoleError ''
    if ($openButton.Enabled -or $script:lastHtmlPath -or $logBox.Text -notlike '*another assessment*') { throw 'An old run was accepted as the current report.' }
    Write-Host 'PASS: packaged sample preview without a child process, blocked PowerShell diagnostics, missing marker, completed synthetic assessment, stale report rejection and quoted Unicode arguments.'
} finally {
    $timer.Stop()
    $timer.Dispose()
    if ($null -ne $script:scanProcess) {
        if (-not $script:scanProcess.HasExited) { $script:scanProcess.Kill() }
        $script:scanProcess.Dispose()
    }
    $form.Dispose()
}
