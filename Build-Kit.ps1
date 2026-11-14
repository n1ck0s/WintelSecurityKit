#requires -Version 5.1
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$kitRoot = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')
$prefix = $kitRoot + '\'
# Package only release inputs. Client reports, custom policies and exception ledgers
# must not leak into a redistributed kit merely because they are in the same folder.
$releaseFiles = @(
    'README.md','Build-Kit.ps1','Launch-GUI.cmd','Start-WintelSecurityGui.ps1','Invoke-WintelSecurityAssessment.ps1',
    'Modules\Assessment.psm1','Modules\Collectors.psm1','Modules\Reporting.psm1',
    'Baselines\windows-server-foundation.v1.json','Baselines\microsoft-windows-server-subset.v1.json',
    'Docs\BASELINE-FORMAT.md','Docs\SOURCES.md','Docs\MICROSOFT-SUBSET.md','Docs\PILOT-ACCEPTANCE.md',
    'Samples\exceptions.example.json','Samples\Demo\SecurityAssessment.html','Samples\Demo\SecurityAssessment.json','Samples\Demo\SecurityAssessment.csv',
    'Samples\Demo\README.md','Samples\Demo\CONSOLE.txt','Samples\Demo\Report-preview.png',
    'Tests\Test-Kit.ps1','Tests\Test-Collectors.ps1','Tests\Test-Gui.ps1'
)
$files = @(foreach ($relative in $releaseFiles) {
    $file = Get-Item -LiteralPath (Join-Path $kitRoot $relative) -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -eq 0) { throw "Release input missing or empty: $relative" }
    $file
})
$manifest = foreach ($file in $files) {
    '{0}  {1}' -f (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant(),$file.FullName.Substring($prefix.Length).Replace('\','/')
}
$encoding = New-Object Text.UTF8Encoding($false)
$manifestPath = Join-Path $kitRoot 'SHA256SUMS.txt'
[IO.File]::WriteAllLines($manifestPath,[string[]]$manifest,$encoding)
$files += Get-Item -LiteralPath $manifestPath
$dist = Join-Path $kitRoot 'Dist'
$null = New-Item -ItemType Directory -Path $dist -Force
$zipPath = Join-Path $dist 'WintelSecurityKit-0.1.0.zip'
Add-Type -AssemblyName System.IO.Compression
$stream = [IO.File]::Open($zipPath,[IO.FileMode]::Create,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
$archive = $null
try {
    $archive = New-Object IO.Compression.ZipArchive($stream,[IO.Compression.ZipArchiveMode]::Create,$false)
    foreach ($file in $files) {
        $relative = $file.FullName.Substring($prefix.Length).Replace('\','/')
        $entry = $archive.CreateEntry(('WintelSecurityKit/' + $relative),[IO.Compression.CompressionLevel]::Optimal)
        $source = [IO.File]::OpenRead($file.FullName); $destination = $null
        try { $destination = $entry.Open(); $source.CopyTo($destination) }
        finally { if ($null -ne $destination) { $destination.Dispose() }; $source.Dispose() }
    }
} finally { if ($null -ne $archive) { $archive.Dispose() }; $stream.Dispose() }
$hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(($zipPath + '.sha256'),($hash + '  ' + [IO.Path]::GetFileName($zipPath) + [Environment]::NewLine),$encoding)
Write-Host "Package: $zipPath"
Write-Host "Files: $($files.Count) | SHA256: $hash"
