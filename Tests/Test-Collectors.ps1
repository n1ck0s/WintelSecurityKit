#requires -Version 5.1
<# Offline collector contract checks. Windows provider calls are replaced inside the module scope. #>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$module = Import-Module (Join-Path $PSScriptRoot '..\Modules\Collectors.psm1') -Force -PassThru
& $module {
    $script:checks = 0
    function Assert-Collector {
        param([bool]$Condition,[string]$Description)
        if (-not $Condition) { throw "Collector test failed: $Description" }
        $script:checks++
    }
    function Get-CimInstance {
        param([string]$ClassName, [string[]]$Property)
        if ($ClassName -eq $script:deniedClass) { throw 'Synthetic Access denied' }
        if ($ClassName -eq 'Win32_OperatingSystem') { return $script:mockOs }
        if ($ClassName -eq 'Win32_ComputerSystem') { return $script:mockComputer }
        throw "Unexpected inventory provider $ClassName"
    }
    $script:deniedClass = ''
    $script:mockOs = [pscustomobject]@{ProductType=3;BuildNumber='20348';Version='10.0';Caption='Synthetic server';CSName='SYNTHETIC'}
    $script:mockComputer = [pscustomobject]@{Name='SYNTHETIC';PartOfDomain=$true}
    $context = Get-WskContext
    Assert-Collector ($context.Supported -and $context.ServerRelease -eq '2022' -and $context.Role -eq 'MemberServer') 'known member inventory'
    $script:mockComputer.PartOfDomain = $false
    Assert-Collector ((Get-WskContext).Role -eq 'StandaloneServer') 'explicit workgroup membership'
    $script:mockOs.ProductType = 2
    $script:deniedClass = 'Win32_ComputerSystem'
    Assert-Collector ((Get-WskContext).Role -eq 'DomainController') 'DC product type suffices without the computer system query'
    $script:mockOs.ProductType = 1
    $script:mockOs.BuildNumber = '26100'
    Assert-Collector (-not (Get-WskContext).Supported) 'client gets an unsupported result without a domain-membership query'
    $script:mockOs.ProductType = 3
    $rejected = $false
    try { $null = Get-WskContext } catch { $rejected = $_.Exception.Message -match 'Win32_ComputerSystem' -and $_.Exception.Message -match 'Synthetic Access denied' }
    Assert-Collector $rejected 'membership inventory failure identifies both provider and Windows error'
    $script:deniedClass = 'Win32_OperatingSystem'
    $rejected = $false
    try { $null = Get-WskContext } catch { $rejected = $_.Exception.Message -match 'Win32_OperatingSystem' -and $_.Exception.Message -match 'Synthetic Access denied' }
    Assert-Collector $rejected 'OS inventory failure identifies both provider and Windows error'
    $script:deniedClass = ''
    $script:mockOs.BuildNumber = '99999'
    Assert-Collector (-not (Get-WskContext).Supported) 'unrecognised server build is unsupported'
    $script:mockOs.BuildNumber = '20348'
    foreach ($invalid in @($null, 0, 99)) {
        $script:mockOs.ProductType = $invalid
        $rejected = $false
        try { $null = Get-WskContext } catch { $rejected = $_.Exception.Message -like '*ProductType*' }
        Assert-Collector $rejected 'missing or unexpected product type prevents assessment'
    }
    $script:mockOs.ProductType = 3
    $script:mockComputer.PartOfDomain = $null
    $rejected = $false
    try { $null = Get-WskContext } catch { $rejected = $_.Exception.Message -like '*PartOfDomain*' }
    Assert-Collector $rejected 'unknown domain membership prevents assessment'

    $testTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $testExport = Join-Path $testTempRoot ('WintelSecurityKit-' + [guid]::NewGuid().ToString('N'))
    $extra = Join-Path $testExport 'unexpected'
    $marker = Join-Path $extra 'marker.txt'
    $testPolicy = Join-Path $testExport 'policy.inf'
    $testLog = Join-Path $testExport 'export.log'
    $null = New-Item -ItemType Directory -Path $testExport -ErrorAction Stop
    try {
        $null = New-Item -ItemType Directory -Path $extra -ErrorAction Stop
        foreach ($file in @($marker,$testPolicy,$testLog)) { [IO.File]::WriteAllText($file, 'Synthetic fixture') }
        Remove-WskPolicyExport -OwnedPath $testExport -TempRoot $testTempRoot -WarningAction SilentlyContinue
        Assert-Collector ([IO.File]::Exists($marker)) 'cleanup leaves unexpected directory contents intact'
        Assert-Collector (-not [IO.File]::Exists($testPolicy) -and -not [IO.File]::Exists($testLog)) 'cleanup removes only the known export files'
        [IO.File]::Delete($marker)
        [IO.Directory]::Delete($extra, $false)
        Remove-WskPolicyExport -OwnedPath $testExport -TempRoot $testTempRoot
        Assert-Collector (-not [IO.Directory]::Exists($testExport)) 'empty owned directory removed'
    }
    finally {
        foreach ($file in @($marker,$testPolicy,$testLog)) { if ([IO.File]::Exists($file)) { [IO.File]::Delete($file) } }
        foreach ($folder in @($extra,$testExport)) { if ([IO.Directory]::Exists($folder)) { [IO.Directory]::Delete($folder,$false) } }
    }
    $script:mockRole = 'MemberServer'
    $script:mockCalls = @{}
    function Add-MockCall([string]$Name) {
        if (-not $script:mockCalls.ContainsKey($Name)) { $script:mockCalls[$Name] = 0 }
        $script:mockCalls[$Name]++
    }
    function Get-WskContext { [pscustomobject]@{ Role = $script:mockRole } }
    function Get-SmbServerConfiguration {
        Add-MockCall SmbServer
        [pscustomobject]@{ EnableSMB1Protocol = $false; RequireSecuritySignature = $true }
    }
    function Get-SmbClientConfiguration { throw 'Synthetic permission denial.' }
    function Get-NetFirewallProfile {
        param([string]$PolicyStore)
        Add-MockCall Firewall
        Assert-Collector ($PolicyStore -eq 'ActiveStore') 'firewall uses effective ActiveStore'
        [pscustomobject]@{ Name = 'Domain'; Enabled = 'True'; DefaultInboundAction = 'Block' }
        [pscustomobject]@{ Name = 'Private'; Enabled = 'False'; DefaultInboundAction = 'NotConfigured' }
        [pscustomobject]@{ Name = 'Public'; Enabled = 'NotConfigured'; DefaultInboundAction = 'Block' }
    }
    function Get-MpComputerStatus {
        Add-MockCall Defender
        [pscustomobject]@{ AntivirusEnabled = $true; RealTimeProtectionEnabled = $false }
    }
    function Get-BitLockerVolume {
        [pscustomobject]@{MountPoint='C:';ProtectionStatus='On';VolumeStatus='FullyEncrypted';KeyProtector='MUST NOT BE RETAINED'}
    }
    function Read-WskSecurityPolicy {
        Add-MockCall SecurityPolicy
        @{MinimumPasswordLength=14;ClearTextPassword=0}
    }
    function Get-WskRegistryFact {
        param([string]$FactName)
        New-WskFact -State Unavailable -Value $null -Evidence $FactName -Reason 'Synthetic missing value.'
    }
    $facts = Get-WskFacts -FactNames @(
        'SmbServer.EnableSMB1Protocol','SmbServer.RequireSecuritySignature','SmbClient.RequireSecuritySignature',
        'Firewall.Domain.Enabled','Firewall.Domain.DefaultInboundAction','Firewall.Private.Enabled',
        'Firewall.Private.DefaultInboundAction','Firewall.Public.Enabled','Defender.AntivirusEnabled',
        'Defender.RealTimeProtectionEnabled','Defender.AntivirusSignatureAge','BitLocker.OSProtected',
        'SecurityPolicy.MinimumPasswordLength','SecurityPolicy.ClearTextPassword','SecurityPolicy.PasswordHistorySize',
        'Registry|MOCK|Missing','Unknown'
    )
    Assert-Collector ($facts -is [hashtable]) 'fact collection returns one hashtable'
    Assert-Collector ($facts['SmbServer.EnableSMB1Protocol'].Value -is [bool] -and -not $facts['SmbServer.EnableSMB1Protocol'].Value) 'SMB false remains a typed collected value'
    Assert-Collector ($facts['SmbServer.RequireSecuritySignature'].Value -eq $true) 'SMB signing true'
    Assert-Collector ($script:mockCalls.SmbServer -eq 1) 'SMB query is cached'
    Assert-Collector ($facts['SmbClient.RequireSecuritySignature'].State -eq 'Error') 'command error is not a false pass'
    Assert-Collector ($facts['Firewall.Domain.Enabled'].Value -is [bool] -and $facts['Firewall.Domain.Enabled'].Value) 'firewall true normalization'
    Assert-Collector ($facts['Firewall.Private.Enabled'].Value -eq $false) 'firewall false normalization'
    Assert-Collector ($facts['Firewall.Domain.DefaultInboundAction'].Value -eq 'Block') 'firewall action normalization'
    Assert-Collector ($facts['Firewall.Private.DefaultInboundAction'].State -eq 'Unavailable') 'unresolved firewall action is not inferred'
    Assert-Collector ($facts['Firewall.Public.Enabled'].State -eq 'Unavailable') 'unresolved firewall enablement is not inferred'
    Assert-Collector ($script:mockCalls.Firewall -eq 1) 'firewall query is cached'
    Assert-Collector ($facts['Defender.RealTimeProtectionEnabled'].Value -eq $false) 'Defender disabled state remains explicit evidence'
    Assert-Collector ($facts['Defender.AntivirusSignatureAge'].State -eq 'Unavailable') 'missing Defender property is not zero'
    Assert-Collector ($script:mockCalls.Defender -eq 1) 'Defender query is cached'
    Assert-Collector ($facts['BitLocker.OSProtected'].Value -eq $true) 'protected fully encrypted OS disk'
    Assert-Collector (($facts['BitLocker.OSProtected'] | ConvertTo-Json -Depth 5) -notmatch 'MUST NOT BE RETAINED') 'BitLocker key material is not retained'
    Assert-Collector ($facts['SecurityPolicy.MinimumPasswordLength'].Value -eq 14) 'numeric local policy preserved'
    Assert-Collector ($facts['SecurityPolicy.ClearTextPassword'].Value -eq 0) 'zero local policy value is collected'
    Assert-Collector ($facts['SecurityPolicy.PasswordHistorySize'].State -eq 'Unavailable') 'missing local policy is not a zero default'
    Assert-Collector ($script:mockCalls.SecurityPolicy -eq 1) 'policy export is cached'
    Assert-Collector ($facts['Registry|MOCK|Missing'].State -eq 'Unavailable') 'missing registry evidence remains unavailable'
    Assert-Collector ($facts.Unknown.State -eq 'Unavailable') 'unknown collector is unavailable'
    $script:mockRole = 'DomainController'
    $dcFacts = Get-WskFacts -FactNames @('SecurityPolicy.MinimumPasswordLength')
    Assert-Collector ($dcFacts['SecurityPolicy.MinimumPasswordLength'].State -eq 'Unavailable') 'DC account policies are not inferred from local export'
    Assert-Collector ($script:mockCalls.SecurityPolicy -eq 1) 'DC did not trigger local policy export'
    function Get-BitLockerVolume { [pscustomobject]@{MountPoint='C:';ProtectionStatus='Off';VolumeStatus='FullyEncrypted'} }
    $suspended = Get-WskFacts -FactNames @('BitLocker.OSProtected')
    Assert-Collector ($suspended['BitLocker.OSProtected'].Value -eq $false) 'suspended encrypted OS disk does not pass'
    $missingSource = Get-WskCachedSource -Cache @{} -Name Missing -Command 'Get-WskNonexistentProviderForTest' -Read { throw 'This must not execute.' }
    Assert-Collector ($missingSource.State -eq 'Unavailable') 'missing Windows command is unavailable'
    Write-Host "PASS: $script:checks offline collector assertions. No host security providers queried."
}
Remove-Module $module -Force
