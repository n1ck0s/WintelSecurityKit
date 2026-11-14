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
    Write-Host 'PASS: hidden WinForms launcher, synthetic child process, argument round-trip, completion state and HTML/JSON report discovery.'
} finally {
    $timer.Stop()
    $timer.Dispose()
    if ($null -ne $script:scanProcess) {
        if (-not $script:scanProcess.HasExited) { $script:scanProcess.Kill() }
        $script:scanProcess.Dispose()
    }
    $form.Dispose()
}
