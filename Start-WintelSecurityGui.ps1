#requires -Version 5.1
<#
.SYNOPSIS
Portable local assessment launcher. Use Invoke-WintelSecurityAssessment.ps1 on Server Core.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess) {
    throw 'The graphical launcher requires 64-bit Windows PowerShell 5.1. Use the command-line entry point on Server Core.'
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

function ConvertTo-WskProcessArgument {
    param([AllowEmptyString()][string]$Value)
    if ($Value.IndexOf([char]0) -ge 0) { throw 'Arguments cannot contain a null character.' }
    # Windows CommandLineToArgvW escaping, with no intervening command shell.
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

$script:kitRoot = $PSScriptRoot
$script:scanProcess = $null
$script:stdoutTask = $null
$script:stderrTask = $null
$script:lastHtmlPath = $null
$script:activeOutput = $null
$script:startedAt = $null

$form = New-Object Windows.Forms.Form
$form.Text = 'Wintel Security Kit'
$form.Size = New-Object Drawing.Size(1020, 800)
$form.MinimumSize = New-Object Drawing.Size(900, 740)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object Drawing.Font('Segoe UI', 10)
$form.BackColor = [Drawing.Color]::FromArgb(242, 246, 249)

$header = New-Object Windows.Forms.Panel
$header.Dock = 'Top'; $header.Height = 112; $header.BackColor = [Drawing.Color]::FromArgb(16, 43, 70)
$title = New-Object Windows.Forms.Label
$title.Text = 'Wintel Security Kit'; $title.Location = New-Object Drawing.Point(24, 18); $title.Size = New-Object Drawing.Size(800, 35)
$title.Font = New-Object Drawing.Font('Segoe UI', 22, [Drawing.FontStyle]::Bold); $title.ForeColor = [Drawing.Color]::White
$subtitle = New-Object Windows.Forms.Label
$subtitle.Text = 'Portable Windows Server posture assessment  |  2019 / 2022 / 2025'
$subtitle.Location = New-Object Drawing.Point(26, 65); $subtitle.Size = New-Object Drawing.Size(900, 26); $subtitle.ForeColor = [Drawing.Color]::FromArgb(188, 216, 233)
$header.Controls.AddRange(@($title, $subtitle)); $form.Controls.Add($header)

$body = New-Object Windows.Forms.TableLayoutPanel
$body.Dock = 'Fill'; $body.Padding = New-Object Windows.Forms.Padding(24, 16, 24, 16); $body.ColumnCount = 3; $body.RowCount = 9
[void]$body.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute, 140)))
[void]$body.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 100)))
[void]$body.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute, 100)))
foreach ($height in @(57, 44, 44, 44, 44, 46, 40)) { [void]$body.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, $height))) }
[void]$body.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 100)))
[void]$body.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 32)))
$form.Controls.Add($body); $body.BringToFront()

$scope = New-Object Windows.Forms.Label
$scope.Text = 'Local assessment; no configuration changes; unknown is not pass; baseline subset, not CIS certification.' + [Environment]::NewLine + 'Use an elevated session for live collection. Run sample uses synthetic evidence and can run on a workstation.'
$scope.Dock = 'Fill'; $scope.ForeColor = [Drawing.Color]::FromArgb(60, 83, 100)
$body.Controls.Add($scope, 0, 0); $body.SetColumnSpan($scope, 3)

function Add-WskField {
    param([string]$Label, [int]$Row, [string]$Text)
    $labelControl = New-Object Windows.Forms.Label
    $labelControl.Text = $Label; $labelControl.Dock = 'Fill'; $labelControl.TextAlign = 'MiddleLeft'
    $textControl = New-Object Windows.Forms.TextBox
    $textControl.Text = $Text; $textControl.Dock = 'Fill'; $textControl.Margin = New-Object Windows.Forms.Padding(3, 8, 10, 5)
    $body.Controls.Add($labelControl, 0, $Row); $body.Controls.Add($textControl, 1, $Row)
    return $textControl
}
$clientField = Add-WskField -Label 'Client / site' -Row 1 -Text ''
$baselineField = Add-WskField -Label 'Baseline JSON' -Row 2 -Text ''
$baselineField.AccessibleDescription = 'Leave blank to use the bundled baseline.'
$exceptionField = Add-WskField -Label 'Exceptions JSON' -Row 3 -Text ''
$outputField = Add-WskField -Label 'Reports folder' -Row 4 -Text (Join-Path $script:kitRoot 'Reports')

$baselineButton = New-Object Windows.Forms.Button
$baselineButton.Text = 'Browse...'; $baselineButton.Dock = 'Fill'; $baselineButton.Margin = New-Object Windows.Forms.Padding(3, 5, 0, 5)
$baselineButton.Add_Click({
    $dialog = New-Object Windows.Forms.OpenFileDialog
    try { $dialog.Filter = 'JSON baseline (*.json)|*.json'; $dialog.InitialDirectory = Join-Path $script:kitRoot 'Baselines'; if ($dialog.ShowDialog($form) -eq 'OK') { $baselineField.Text = $dialog.FileName } } finally { $dialog.Dispose() }
})
$body.Controls.Add($baselineButton, 2, 2)
$exceptionButton = New-Object Windows.Forms.Button
$exceptionButton.Text = 'Browse...'; $exceptionButton.Dock = 'Fill'; $exceptionButton.Margin = New-Object Windows.Forms.Padding(3, 5, 0, 5)
$exceptionButton.Add_Click({
    $dialog = New-Object Windows.Forms.OpenFileDialog
    try { $dialog.Filter = 'JSON exceptions (*.json)|*.json'; $dialog.InitialDirectory = Join-Path $script:kitRoot 'Samples'; if ($dialog.ShowDialog($form) -eq 'OK') { $exceptionField.Text = $dialog.FileName } } finally { $dialog.Dispose() }
})
$body.Controls.Add($exceptionButton, 2, 3)
$outputButton = New-Object Windows.Forms.Button
$outputButton.Text = 'Browse...'; $outputButton.Dock = 'Fill'; $outputButton.Margin = New-Object Windows.Forms.Padding(3, 5, 0, 5)
$outputButton.Add_Click({
    $dialog = New-Object Windows.Forms.FolderBrowserDialog
    try { $dialog.Description = 'Choose the parent folder for assessment reports'; if (Test-Path -LiteralPath $outputField.Text -PathType Container) { $dialog.SelectedPath = $outputField.Text }; if ($dialog.ShowDialog($form) -eq 'OK') { $outputField.Text = $dialog.SelectedPath } } finally { $dialog.Dispose() }
})
$body.Controls.Add($outputButton, 2, 4)

$buttons = New-Object Windows.Forms.FlowLayoutPanel
$buttons.Dock = 'Fill'; $buttons.WrapContents = $false
$runButton = New-Object Windows.Forms.Button
$runButton.Text = 'Run assessment'; $runButton.Size = New-Object Drawing.Size(160, 36)
$runButton.BackColor = [Drawing.Color]::FromArgb(8, 127, 131); $runButton.ForeColor = [Drawing.Color]::White; $runButton.FlatStyle = 'Flat'
$sampleButton = New-Object Windows.Forms.Button
$sampleButton.Text = 'Run sample'; $sampleButton.Size = New-Object Drawing.Size(130, 36)
$openButton = New-Object Windows.Forms.Button
$openButton.Text = 'Open HTML report'; $openButton.Size = New-Object Drawing.Size(160, 36); $openButton.Enabled = $false
$buttons.Controls.AddRange(@($runButton, $sampleButton, $openButton)); $body.Controls.Add($buttons, 0, 5); $body.SetColumnSpan($buttons, 3)
$statusLabel = New-Object Windows.Forms.Label
$statusLabel.Text = 'Ready. Leave the baseline field blank to use the bundled settings.'; $statusLabel.Dock = 'Fill'; $statusLabel.TextAlign = 'MiddleLeft'; $statusLabel.ForeColor = [Drawing.Color]::FromArgb(16, 43, 70)
$body.Controls.Add($statusLabel, 0, 6); $body.SetColumnSpan($statusLabel, 3)
$logBox = New-Object Windows.Forms.TextBox
$logBox.Multiline = $true; $logBox.ReadOnly = $true; $logBox.ScrollBars = 'Both'; $logBox.WordWrap = $false; $logBox.Dock = 'Fill'; $logBox.BackColor = [Drawing.Color]::White; $logBox.Font = New-Object Drawing.Font('Consolas', 9)
$logBox.Text = 'The command-line entry point supports Server Core and scripted execution.' + [Environment]::NewLine + 'Invoke-WintelSecurityAssessment.ps1 -Demo -OutputDirectory .\Reports' + [Environment]::NewLine + [Environment]::NewLine + 'This launcher respects the existing PowerShell execution policy. No modules are downloaded.'
$body.Controls.Add($logBox, 0, 7); $body.SetColumnSpan($logBox, 3)
$footnote = New-Object Windows.Forms.Label
$footnote.Text = 'Outputs: self-contained HTML, JSON and CSV. Reports may contain sensitive system configuration.'; $footnote.Dock = 'Fill'; $footnote.TextAlign = 'MiddleLeft'; $footnote.Font = New-Object Drawing.Font('Segoe UI', 9); $footnote.ForeColor = [Drawing.Color]::FromArgb(91, 110, 124)
$body.Controls.Add($footnote, 0, 8); $body.SetColumnSpan($footnote, 3)

$timer = New-Object Windows.Forms.Timer
$timer.Interval = 300
function Set-WskRunningState {
    param([bool]$Running)
    foreach ($control in @($runButton, $sampleButton, $clientField, $baselineField, $exceptionField, $outputField, $baselineButton, $exceptionButton, $outputButton)) { $control.Enabled = -not $Running }
    $openButton.Enabled = (-not $Running -and -not [string]::IsNullOrWhiteSpace($script:lastHtmlPath))
}
function Start-WskAssessment {
    param([bool]$Demo)
    if ($null -ne $script:scanProcess) { return }
    try {
        if ([string]::IsNullOrWhiteSpace($outputField.Text)) { throw 'Choose a reports folder.' }
        $entryPoint = Join-Path $script:kitRoot 'Invoke-WintelSecurityAssessment.ps1'
        if (-not (Test-Path -LiteralPath $entryPoint -PathType Leaf)) { throw "Command-line entry point not found: $entryPoint" }
        foreach ($field in @($baselineField, $exceptionField)) {
            if (-not [string]::IsNullOrWhiteSpace($field.Text) -and -not (Test-Path -LiteralPath $field.Text -PathType Leaf)) { throw "File not found: $($field.Text)" }
        }
        $script:activeOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($outputField.Text)
        $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $entryPoint, '-OutputDirectory', $script:activeOutput)
        if (-not [string]::IsNullOrWhiteSpace($baselineField.Text)) { $arguments += @('-BaselinePath', [IO.Path]::GetFullPath($baselineField.Text)) }
        if (-not [string]::IsNullOrWhiteSpace($exceptionField.Text)) { $arguments += @('-ExceptionsPath', [IO.Path]::GetFullPath($exceptionField.Text)) }
        if (-not [string]::IsNullOrWhiteSpace($clientField.Text)) { $arguments += @('-ClientName', $clientField.Text) }
        if ($Demo) { $arguments += '-Demo' }
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = Join-Path $PSHOME 'powershell.exe'
        $info.Arguments = (@($arguments | ForEach-Object { ConvertTo-WskProcessArgument $_ }) -join ' ')
        $info.WorkingDirectory = $script:kitRoot; $info.UseShellExecute = $false; $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
        $script:scanProcess = New-Object Diagnostics.Process
        $script:scanProcess.StartInfo = $info
        [void]$script:scanProcess.Start()
        # Drain both pipes concurrently; polling only completed tasks keeps the UI responsive.
        $script:stdoutTask = $script:scanProcess.StandardOutput.ReadToEndAsync()
        $script:stderrTask = $script:scanProcess.StandardError.ReadToEndAsync()
        $script:startedAt = [DateTime]::UtcNow
        $script:lastHtmlPath = $null
        $logBox.Text = 'Running ' + $(if ($Demo) { 'sample assessment' } else { 'local assessment' }) + '...' + [Environment]::NewLine + 'Output: ' + $script:activeOutput
        Set-WskRunningState $true
        $timer.Start()
    } catch {
        if ($null -ne $script:scanProcess) { $script:scanProcess.Dispose(); $script:scanProcess = $null }
        $statusLabel.Text = 'Unable to start the assessment.'
        $logBox.AppendText([Environment]::NewLine + $_.Exception.Message)
        Set-WskRunningState $false
    }
}
$timer.Add_Tick({
    try {
        if ($null -eq $script:scanProcess) { $timer.Stop(); return }
        $elapsed = [int]([DateTime]::UtcNow - $script:startedAt).TotalSeconds
        $statusLabel.Text = "Assessment running... $elapsed seconds. Evidence collection may take several minutes."
        if (-not $script:scanProcess.HasExited -or -not $script:stdoutTask.IsCompleted -or -not $script:stderrTask.IsCompleted) { return }
        $timer.Stop()
        $exitCode = $script:scanProcess.ExitCode
        $logBox.AppendText([Environment]::NewLine + $script:stdoutTask.Result)
        if (-not [string]::IsNullOrWhiteSpace($script:stderrTask.Result)) { $logBox.AppendText([Environment]::NewLine + $script:stderrTask.Result) }
        $script:scanProcess.Dispose(); $script:scanProcess = $null
        # Use the child's own run directory, including when simultaneous scans share an output parent.
        $runMarkers = [regex]::Matches($script:stdoutTask.Result, '(?m)^WSK_REPORT_DIR=([0-9]{8}T[0-9]{6}Z-[A-Za-z0-9._-]+-[a-f0-9]{8})\r?$')
        if ($exitCode -in @(0,1,3) -and $runMarkers.Count -gt 0) {
            $runDirectory = Join-Path $script:activeOutput $runMarkers[$runMarkers.Count - 1].Groups[1].Value
            $reportPath = Join-Path $runDirectory 'SecurityAssessment.html'
            if ([IO.File]::Exists($reportPath)) { $script:lastHtmlPath = $reportPath }
        }
        $statusLabel.Text = switch ($exitCode) {
            0 { 'Assessment complete. No failed or incomplete checks.' }
            1 { 'Assessment complete. Failed controls require attention.' }
            2 { 'Assessment could not complete. Review the error details below.' }
            3 { 'Assessment complete. Review outstanding evidence or approved exceptions.' }
            default { "Assessment exited with code $exitCode. Review the details below." }
        }
        Set-WskRunningState $false
    } catch {
        $timer.Stop()
        $statusLabel.Text = 'Unable to finish displaying the assessment result.'
        $logBox.AppendText([Environment]::NewLine + $_.Exception.Message)
        if ($null -ne $script:scanProcess -and $script:scanProcess.HasExited) { $script:scanProcess.Dispose(); $script:scanProcess = $null }
        Set-WskRunningState ($null -ne $script:scanProcess)
    }
})
$runButton.Add_Click({ Start-WskAssessment -Demo $false })
$sampleButton.Add_Click({ Start-WskAssessment -Demo $true })
$openButton.Add_Click({
    try {
        if (-not [string]::IsNullOrWhiteSpace($script:lastHtmlPath) -and (Test-Path -LiteralPath $script:lastHtmlPath -PathType Leaf)) {
            $openInfo = New-Object Diagnostics.ProcessStartInfo
            $openInfo.FileName = $script:lastHtmlPath; $openInfo.UseShellExecute = $true
            [void][Diagnostics.Process]::Start($openInfo)
        }
    } catch { [void][Windows.Forms.MessageBox]::Show($form, $_.Exception.Message, 'Could not open report', 'OK', 'Error') }
})
$form.Add_FormClosing({
    param($sender, $eventArgs)
    if ($null -ne $script:scanProcess -and -not $script:scanProcess.HasExited) {
        $answer = [Windows.Forms.MessageBox]::Show($form, 'Stop the current read-only scan and close? Partial output may remain.', 'Assessment running', 'YesNo', 'Question')
        if ($answer -ne 'Yes') { $eventArgs.Cancel = $true; return }
        try { $script:scanProcess.Kill() } catch { $eventArgs.Cancel = $true; return }
    }
    $timer.Stop()
})
# Dot-sourcing constructs the form for an embedding caller, which owns its lifetime.
if ($MyInvocation.InvocationName -eq '.') { return }
try { [void]$form.ShowDialog() }
finally {
    $timer.Dispose()
    if ($null -ne $script:scanProcess) { $script:scanProcess.Dispose() }
    $form.Dispose()
}
