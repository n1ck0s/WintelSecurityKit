#requires -Version 5.1
Set-StrictMode -Version Latest

function Assert-WskMappingProperties {
    param($Object, [string[]]$Names, [string]$Location)
    if ($Object -isnot [pscustomobject]) { throw "Expected a JSON object in $Location." }
    $present = @($Object.PSObject.Properties.Name)
    foreach ($name in $Names) {
        if ($name -cnotin $present) { throw "Missing '$name' in $Location." }
    }
    foreach ($name in $present) {
        if ($name -cnotin $Names) { throw "Unexpected '$name' in $Location." }
    }
}

function Get-WskMappedFactType {
    param([string]$Fact, [string]$Role)
    switch -Regex ($Fact) {
        '^Firewall\.(Domain|Private|Public)\.Enabled$' { return 'Boolean' }
        '^Firewall\.(Domain|Private|Public)\.DefaultInboundAction$' { return 'String' }
        '^SmbServer\.(EnableSMB1Protocol|RequireSecuritySignature)$' { return 'Boolean' }
        '^SmbClient\.(RequireSecuritySignature|EnableInsecureGuestLogons)$' { return 'Boolean' }
        '^Defender\.(AntivirusEnabled|RealTimeProtectionEnabled)$' { return 'Boolean' }
        '^Defender\.AntivirusSignatureAge$' { return 'Number' }
        '^BitLocker\.OSProtected$' { return 'Boolean' }
        '^SecurityPolicy\.(MinimumPasswordLength|PasswordComplexity|PasswordHistorySize|LockoutBadCount|LockoutDuration|ResetLockoutCount|ClearTextPassword)$' {
            if ($Role -eq 'DomainController') { throw "Local-account policy fact '$Fact' is unavailable on domain controllers." }
            return 'Number'
        }
        '^Registry\|' {
            $parts = $Fact.Split('|')
            if ($parts.Count -ne 3 -or [string]::IsNullOrWhiteSpace($parts[2]) -or $Fact -match '[\x00-\x1f]') {
                throw "Invalid registry fact '$Fact'. Expected Registry|HKLM subkey|value name."
            }
            $segments = $parts[1].Split('\')
            if ($segments[0] -match '^(?:HK(?:LM|CU|CR|U|CC)|HKEY_[^\\]+|Registry::):?$' -or
                $parts[1] -match '[:/]' -or $segments -contains '' -or $segments -contains '.' -or $segments -contains '..') {
                throw "Registry fact '$Fact' requires a subkey relative to HKLM."
            }
            return 'Registry'
        }
        default { throw "No kit collector is implemented for '$Fact'." }
    }
}

function Assert-WskMappedComparison {
    param($Rule, [string]$FactType)
    $operator = $Rule.Operator
    $expected = $Rule.Expected
    $id = $Rule.RuleId
    if ($operator -cnotin @('Equals','NotEquals','GreaterOrEqual','LessOrEqual','Between','In','Contains')) {
        throw "Unsupported comparison '$operator' for '$id'."
    }
    if ($operator -eq 'Contains' -and $FactType -ne 'Registry') { throw "The collector for '$id' returns a scalar. Contains requires an array fact." }
    if ($operator -in @('Between','In')) {
        if ($expected -isnot [array] -or $expected.Length -eq 0) { throw "'$operator' requires an expected array for '$id'." }
        if ($operator -eq 'Between' -and $expected.Length -ne 2) { throw "Between requires exactly two bounds for '$id'." }
    } elseif ($null -eq $expected -or $expected -is [array]) {
        throw "'$operator' requires a scalar expected value for '$id'."
    }
    $firstType = $null
    foreach ($value in @($expected)) {
        if ($value -is [string]) { $type = 'String' }
        elseif ($value -is [bool]) { $type = 'Boolean' }
        elseif ($value -is [int] -or $value -is [long] -or $value -is [double] -or $value -is [decimal]) {
            # The assessment engine compares numbers as Decimal.
            try { $null = [decimal]$value } catch { throw "Expected number exceeds the kit's supported range for '$id'." }
            $type = 'Number'
        } else { throw "Expected a JSON string, boolean or number for '$id'." }
        if ($firstType -and $firstType -ne $type) { throw "Expected values must all have the same type for '$id'." }
        $firstType = $type
        if ($FactType -ne 'Registry' -and $FactType -ne $type) { throw "Fact '$($Rule.Fact)' requires expected type $FactType for '$id'." }
        if ($FactType -eq 'Registry' -and $type -eq 'Boolean') { throw "Use the registry value's native string or numeric type for '$id'." }
        if ($operator -in @('GreaterOrEqual','LessOrEqual','Between') -and $type -ne 'Number') { throw "Numeric comparison '$operator' requires numbers for '$id'." }
    }
    if ($operator -eq 'Between' -and [decimal]$expected[0] -gt [decimal]$expected[1]) { throw "Between bounds are reversed for '$id'." }
}

function Import-WskXccdfMapping {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$BenchmarkSha256,
        [Parameter(Mandatory)][ValidateSet('MemberServer','DomainController','StandaloneServer')][string]$Role,
        [Parameter(Mandatory)][ValidateSet('2019','2022','2025')][string]$Release,
        [Parameter(Mandatory)][string[]]$RuleIds
    )
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file -isnot [IO.FileInfo] -or $file.Length -gt 5MB) { throw 'The mapping must be a JSON file no larger than 5 MB.' }
    $document = Get-Content -LiteralPath $file.FullName -Encoding UTF8 -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    Assert-WskMappingProperties $document @('SchemaVersion','BenchmarkSha256','Role','Release','Rules') 'the mapping'
    if ($document.SchemaVersion -isnot [string] -or $document.SchemaVersion -cne '1.0') { throw 'Unsupported mapping schema. Expected 1.0.' }
    if ($document.BenchmarkSha256 -isnot [string] -or $document.BenchmarkSha256 -ine $BenchmarkSha256) { throw 'The mapping SHA-256 does not match this exact benchmark file.' }
    if ($document.Role -isnot [string] -or $document.Role -cne $Role -or $document.Release -isnot [string] -or $document.Release -cne $Release) {
        throw 'The mapping role or Windows Server release does not match the import.'
    }
    if ($document.Rules -isnot [array] -or $document.Rules.Count -gt 2000) { throw 'Mapping Rules must be an array of up to 2000 entries.' }
    $known = [Collections.Generic.HashSet[string]]::new($RuleIds, [StringComparer]::Ordinal)
    $mapped = [hashtable]::new([StringComparer]::Ordinal)
    foreach ($rule in $document.Rules) {
        Assert-WskMappingProperties $rule @('RuleId','Fact','Operator','Expected','ExpectedDisplay') 'a mapping entry'
        foreach ($name in @('RuleId','Fact','Operator','ExpectedDisplay')) {
            if ($rule.$name -isnot [string] -or [string]::IsNullOrWhiteSpace($rule.$name)) { throw "Mapping '$name' must be a nonempty string." }
        }
        if (-not $known.Contains($rule.RuleId)) { throw "Mapping references an unknown XCCDF rule '$($rule.RuleId)'." }
        if ($mapped.ContainsKey($rule.RuleId)) { throw "Duplicate mapping for '$($rule.RuleId)'." }
        $type = Get-WskMappedFactType $rule.Fact $Role
        Assert-WskMappedComparison $rule $type
        $mapped.Add($rule.RuleId, $rule)
    }
    return $mapped
}

Export-ModuleMember -Function Import-WskXccdfMapping
