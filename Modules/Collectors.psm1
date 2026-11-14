#requires -Version 5.1
Set-StrictMode -Version Latest

function New-WskFact {
    param([string]$State, $Value, [string]$Evidence = '', [string]$Reason = '')
    [pscustomobject]@{ State = $State; Value = $Value; Evidence = $Evidence; Reason = $Reason }
}

function Get-WskContext {
    <# Only reads inventory. Windows client builds can match server builds, so ProductType is mandatory. #>
    [CmdletBinding()]
    param()
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    switch ([string]$os.ProductType) {
        '1' { $role = 'Workstation' }
        '2' { $role = 'DomainController' }
        '3' {
            if ($computer.PartOfDomain -isnot [bool]) { throw 'Unable to determine domain membership from Win32_ComputerSystem.PartOfDomain.' }
            if ($computer.PartOfDomain) { $role = 'MemberServer' } else { $role = 'StandaloneServer' }
        }
        default { throw 'Unable to identify the Windows product type from Win32_OperatingSystem.ProductType.' }
    }
    $release = 'Unsupported'
    if ($role -ne 'Workstation') {
        switch ([string]$os.BuildNumber) {
            '17763' { $release = '2019' }
            '20348' { $release = '2022' }
            '26100' { $release = '2025' }
        }
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    finally { $identity.Dispose() }
    [pscustomobject]@{
        ComputerName = [string]$computer.Name
        OSCaption = [string]$os.Caption
        OSVersion = [string]$os.Version
        BuildNumber = [string]$os.BuildNumber
        ServerRelease = $release
        Role = $role
        IsAdministrator = [bool]$admin
        CollectedAtUtc = [DateTime]::UtcNow.ToString('o')
        Supported = ($release -ne 'Unsupported')
        Is64Bit = [Environment]::Is64BitProcess
    }
}

function Get-WskRegistryFact {
    param([string]$FactName)
    $parts = $FactName.Split('|')
    if ($parts.Count -ne 3 -or [string]::IsNullOrWhiteSpace($parts[1]) -or [string]::IsNullOrWhiteSpace($parts[2])) {
        return New-WskFact -State Error -Value $null -Reason 'Registry facts require Registry|HKLM subkey|value name.'
    }
    $base = $null
    $key = $null
    $evidence = 'HKLM (64-bit)\{0}\{1}' -f $parts[1], $parts[2]
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $key = $base.OpenSubKey($parts[1], $false)
        if ($null -eq $key -or @($key.GetValueNames()) -notcontains $parts[2]) {
            return New-WskFact -State Unavailable -Value $null -Evidence $evidence -Reason 'No explicit registry value exists. An operating-system default was not inferred.'
        }
        $value = $key.GetValue($parts[2], $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        return New-WskFact -State Collected -Value $value -Evidence $evidence
    }
    catch { return New-WskFact -State Error -Value $null -Evidence $evidence -Reason $_.Exception.Message }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        if ($null -ne $base) { $base.Dispose() }
    }
}

function Get-WskCachedSource {
    param([hashtable]$Cache, [string]$Name, [string]$Command, [scriptblock]$Read)
    if (-not $Cache.ContainsKey($Name)) {
        if ($Command -and -not (Get-Command -Name $Command -ErrorAction SilentlyContinue)) {
            $Cache[$Name] = [pscustomobject]@{ State = 'Unavailable'; Data = $null; Reason = "Required Windows command is unavailable: $Command" }
        }
        else {
            try {
                $data = & $Read
                if ($null -eq $data) { throw "The $Name collector returned no data." }
                $Cache[$Name] = [pscustomobject]@{ State = 'Collected'; Data = $data; Reason = '' }
            }
            catch { $Cache[$Name] = [pscustomobject]@{ State = 'Error'; Data = $null; Reason = $_.Exception.Message } }
        }
    }
    return $Cache[$Name]
}

function Get-WskPropertyFact {
    param($Source, [string]$Property, [string]$Evidence)
    if ($Source.State -ne 'Collected') {
        return New-WskFact -State $Source.State -Value $null -Evidence $Evidence -Reason $Source.Reason
    }
    $entry = $Source.Data.PSObject.Properties[$Property]
    if ($null -eq $entry -or $null -eq $entry.Value) {
        return New-WskFact -State Unavailable -Value $null -Evidence $Evidence -Reason "The Windows provider did not return $Property."
    }
    return New-WskFact -State Collected -Value $entry.Value -Evidence $Evidence
}

function Remove-WskPolicyExport {
    [CmdletBinding()]
    param([string]$OwnedPath, [string]$TempRoot)
    try {
        $resolved = (Resolve-Path -LiteralPath $OwnedPath -ErrorAction Stop).ProviderPath
        $directory = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
        if ($resolved -ne $OwnedPath -or [IO.Path]::GetDirectoryName($resolved) -ne $TempRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) -or
            $directory.Name -notmatch '^WintelSecurityKit-[a-f0-9]{32}$' -or -not $directory.PSIsContainer -or
            ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'The export directory failed the ownership check.'
        }
        foreach ($fileName in @('policy.inf', 'export.log')) {
            $path = Join-Path $resolved $fileName
            if (Test-Path -LiteralPath $path) {
                $file = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
                [IO.File]::Delete($path)
            }
        }
        # The nonrecursive overload refuses a directory containing any unexpected entries.
        [IO.Directory]::Delete($resolved, $false)
    }
    catch { Write-Warning "Temporary policy export cleanup incomplete at '$OwnedPath'. $($_.Exception.Message)" }
}

function Read-WskSecurityPolicy {
    <#
    secedit /export reads policy; it does not apply policy. /mergedpolicy includes local and domain
    security policy for this computer. These account-policy facts concern LOCAL accounts only.
    They do not establish domain-wide password policy, fine-grained policy, or per-user resultant policy.
    #>
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $name = 'WintelSecurityKit-' + [Guid]::NewGuid().ToString('N')
    $ownedPath = [IO.Path]::GetFullPath((Join-Path $tempRoot $name))
    $expectedParent = $tempRoot.TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ([IO.Path]::GetDirectoryName($ownedPath) -ne $expectedParent) { throw 'Unsafe policy export path.' }
    $created = $false
    try {
        if (Test-Path -LiteralPath $ownedPath) { throw 'Policy export directory already exists.' }
        $null = New-Item -ItemType Directory -Path $ownedPath -ErrorAction Stop
        $created = $true
        $exportPath = Join-Path $ownedPath 'policy.inf'
        $logPath = Join-Path $ownedPath 'export.log'
        $secedit = Join-Path $env:SystemRoot 'System32\secedit.exe'
        $null = & $secedit /export /mergedpolicy /cfg $exportPath /areas SECURITYPOLICY /log $logPath /quiet 2>&1
        if ($LASTEXITCODE -ne 0) { throw "secedit export failed with exit code $LASTEXITCODE. Run an elevated session and review local security-policy access." }
        if (-not (Test-Path -LiteralPath $exportPath -PathType Leaf)) { throw 'secedit did not produce a policy export.' }
        $values = @{}
        $section = ''
        foreach ($line in Get-Content -LiteralPath $exportPath -ErrorAction Stop) {
            if ($line -match '^\s*\[([^\]]+)\]\s*$') { $section = $Matches[1]; continue }
            if ($section -eq 'System Access' -and $line -match '^\s*([A-Za-z]+)\s*=\s*(-?\d+)\s*$') {
                $values[$Matches[1]] = [int]$Matches[2]
            }
        }
        return $values
    }
    finally {
        if ($created -and (Test-Path -LiteralPath $ownedPath)) { Remove-WskPolicyExport -OwnedPath $ownedPath -TempRoot $tempRoot }
    }
}

function Get-WskFacts {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$FactNames)
    if (-not [Environment]::Is64BitProcess) { throw 'Run the kit in 64-bit Windows PowerShell to use the native security providers.' }
    $facts = @{}
    $cache = @{}
    foreach ($name in @($FactNames | Select-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        try {
            if ($name.StartsWith('Registry|', [StringComparison]::OrdinalIgnoreCase)) {
                $facts[$name] = Get-WskRegistryFact -FactName $name
                continue
            }
            if ($name -match '^Firewall\.(Domain|Private|Public)\.(Enabled|DefaultInboundAction)$') {
                $profile = $Matches[1]
                $property = $Matches[2]
                $source = Get-WskCachedSource -Cache $cache -Name Firewall -Command Get-NetFirewallProfile -Read {
                    Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop
                }
                if ($source.State -ne 'Collected') {
                    $facts[$name] = New-WskFact -State $source.State -Value $null -Reason $source.Reason -Evidence 'Get-NetFirewallProfile -PolicyStore ActiveStore'
                }
                else {
                    $selected = @($source.Data | Where-Object { [string]$_.Name -eq $profile })
                    if ($selected.Count -ne 1) {
                        $facts[$name] = New-WskFact -State Unavailable -Value $null -Reason "Expected one effective $profile firewall profile."
                    }
                    else {
                        $value = [string]$selected[0].$property
                        if ($value -eq 'NotConfigured' -or [string]::IsNullOrWhiteSpace($value)) {
                            $facts[$name] = New-WskFact -State Unavailable -Value $null -Reason 'The effective firewall provider did not resolve this setting.' -Evidence "ActiveStore $profile $property"
                        }
                        elseif ($property -eq 'Enabled') {
                            if ($value -notin @('True', 'False', '0', '1')) { throw "Unexpected firewall Enabled value: $value" }
                            $facts[$name] = New-WskFact -State Collected -Value ($value -in @('True', '1')) -Evidence "ActiveStore $profile $property"
                        }
                        else { $facts[$name] = New-WskFact -State Collected -Value $value -Evidence "ActiveStore $profile $property" }
                    }
                }
                continue
            }
            if ($name -match '^SmbServer\.(EnableSMB1Protocol|RequireSecuritySignature)$') {
                $property = $Matches[1]
                $source = Get-WskCachedSource -Cache $cache -Name SmbServer -Command Get-SmbServerConfiguration -Read { Get-SmbServerConfiguration -ErrorAction Stop }
                $facts[$name] = Get-WskPropertyFact -Source $source -Property $property -Evidence "Get-SmbServerConfiguration $property"
                continue
            }
            if ($name -match '^SmbClient\.(RequireSecuritySignature|EnableInsecureGuestLogons)$') {
                $property = $Matches[1]
                $source = Get-WskCachedSource -Cache $cache -Name SmbClient -Command Get-SmbClientConfiguration -Read { Get-SmbClientConfiguration -ErrorAction Stop }
                $facts[$name] = Get-WskPropertyFact -Source $source -Property $property -Evidence "Get-SmbClientConfiguration $property"
                continue
            }
            if ($name -match '^Defender\.(AntivirusEnabled|RealTimeProtectionEnabled|AntivirusSignatureAge)$') {
                $property = $Matches[1]
                $source = Get-WskCachedSource -Cache $cache -Name Defender -Command Get-MpComputerStatus -Read { Get-MpComputerStatus -ErrorAction Stop }
                $facts[$name] = Get-WskPropertyFact -Source $source -Property $property -Evidence "Get-MpComputerStatus $property; other endpoint-security products are not assessed"
                continue
            }
            if ($name -eq 'BitLocker.OSProtected') {
                $source = Get-WskCachedSource -Cache $cache -Name BitLocker -Command Get-BitLockerVolume -Read {
                    # Only retain status fields. Never collect key protectors or recovery passwords.
                    Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop | Select-Object MountPoint, ProtectionStatus, VolumeStatus
                }
                if ($source.State -ne 'Collected') {
                    $facts[$name] = New-WskFact -State $source.State -Value $null -Reason $source.Reason -Evidence 'Get-BitLockerVolume OS volume status only'
                }
                else {
                    $volumes = @($source.Data)
                    if ($volumes.Count -ne 1 -or $null -eq $volumes[0].ProtectionStatus -or $null -eq $volumes[0].VolumeStatus) {
                        $facts[$name] = New-WskFact -State Unavailable -Value $null -Reason 'A unique operating-system volume with complete status was not returned.'
                    }
                    else {
                        $protection = [string]$volumes[0].ProtectionStatus
                        $volume = [string]$volumes[0].VolumeStatus
                        $facts[$name] = New-WskFact -State Collected -Value ($protection -eq 'On' -and $volume -eq 'FullyEncrypted') -Evidence "OS volume protection=$protection; volume status=$volume. Other disks are not assessed."
                    }
                }
                continue
            }
            if ($name -match '^SecurityPolicy\.(MinimumPasswordLength|PasswordComplexity|PasswordHistorySize|LockoutBadCount|LockoutDuration|ResetLockoutCount|ClearTextPassword)$') {
                $property = $Matches[1]
                $context = Get-WskCachedSource -Cache $cache -Name Context -Read { Get-WskContext }
                if ($context.State -ne 'Collected') {
                    $facts[$name] = New-WskFact -State $context.State -Value $null -Reason $context.Reason
                    continue
                }
                if ($context.Data.Role -eq 'DomainController') {
                    $facts[$name] = New-WskFact -State Unavailable -Value $null -Reason 'Domain controllers require domain and fine-grained password-policy review; local-account export is not sufficient evidence.'
                    continue
                }
                $source = Get-WskCachedSource -Cache $cache -Name SecurityPolicy -Command secedit.exe -Read { Read-WskSecurityPolicy }
                if ($source.State -ne 'Collected') {
                    $facts[$name] = New-WskFact -State $source.State -Value $null -Reason $source.Reason -Evidence 'secedit /export /mergedpolicy; local accounts only'
                }
                elseif (-not $source.Data.ContainsKey($property)) {
                    $facts[$name] = New-WskFact -State Unavailable -Value $null -Reason "The merged security-policy export did not include $property." -Evidence 'secedit local-account policy'
                }
                else { $facts[$name] = New-WskFact -State Collected -Value $source.Data[$property] -Evidence "secedit merged policy $property; local accounts only, not domain accounts or fine-grained policies" }
                continue
            }
            $facts[$name] = New-WskFact -State Unavailable -Value $null -Reason 'No collector is implemented for this fact name.'
        }
        catch { $facts[$name] = New-WskFact -State Error -Value $null -Reason $_.Exception.Message }
    }
    return $facts
}

Export-ModuleMember -Function Get-WskContext, Get-WskFacts
