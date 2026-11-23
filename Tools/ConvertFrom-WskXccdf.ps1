#requires -Version 5.1
<#
.SYNOPSIS
Converts two explicitly selected profiles in a local Windows Server XCCDF Benchmark to kit baselines.
.DESCRIPTION
Use -ListProfiles to discover the exact identifiers. OutputDirectory must be a new folder.
The converter reads profile membership and rule titles. Manual evidence is required unless
an operator supplies a reviewed mapping for the exact source file, server release and role.
#>
[CmdletBinding(DefaultParameterSetName='Convert')]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory,ParameterSetName='List')][switch]$ListProfiles,
    [Parameter(Mandatory,ParameterSetName='Convert')][string]$Level1ProfileId,
    [Parameter(Mandatory,ParameterSetName='Convert')][string]$Level2ProfileId,
    [Parameter(Mandatory,ParameterSetName='Convert')][ValidateSet('2019','2022','2025')][string]$Release,
    [Parameter(Mandatory,ParameterSetName='Convert')][ValidateSet('MemberServer','DomainController','StandaloneServer')][string]$Role,
    [Parameter(Mandatory,ParameterSetName='Convert')][string]$OutputDirectory,
    [Parameter(ParameterSetName='Convert')][string]$MappingPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RequiredText($parent, [string]$name) {
    $node = $parent.SelectSingleNode("x:$name", $namespaces)
    if ($null -eq $node -or [string]::IsNullOrWhiteSpace($node.InnerText)) {
        throw "Missing $name on $($parent.LocalName) '$($parent.GetAttribute('id'))'."
    }
    return $node.InnerText.Trim()
}

function Get-BooleanAttribute($node, [string]$name, [bool]$default) {
    if (-not $node.HasAttribute($name)) { return $default }
    return [Xml.XmlConvert]::ToBoolean($node.GetAttribute($name))
}

function Get-TextHash([string]$value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($value))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Add-IndexedNode($index, $node) {
    $key = $node.GetAttribute('id')
    if ([string]::IsNullOrWhiteSpace($key) -or $index.ContainsKey($key)) {
        throw "Missing or duplicate $($node.LocalName) identifier '$key'."
    }
    $index.Add($key,$node)
}

function Assert-ProfileScope($profile, [int]$level) {
    $title = Get-RequiredText $profile 'title'
    $label = ($title + ' ' + $profile.GetAttribute('id')) -replace '[_./-]', ' '
    foreach ($match in [regex]::Matches($label, '(?i)Windows\s+Server\s+(20\d\d)')) {
        if ($match.Groups[1].Value -ne $Release) { throw "Profile '$title' names a different Windows Server release." }
    }
    $levels = @([regex]::Matches($label,'(?i)(?<![A-Za-z0-9])(?:L|Level)\s*([12])(?![A-Za-z0-9])') |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
    if ($levels.Count -ne 1 -or $levels[0] -ne [string]$level) { throw "Cannot confirm Level $level for profile '$title'." }
    $rolePatterns = [ordered]@{
        MemberServer='(?i)(?<![a-z0-9])(?:member\s*servers?|MS)(?![a-z0-9])'
        DomainController='(?i)(?<![a-z0-9])(?:domain\s*controllers?|DC)(?![a-z0-9])'
        StandaloneServer='(?i)(?<![a-z0-9])stand\s*alone(?:\s*servers?)?(?![a-z0-9])'
    }
    $roles = @($rolePatterns.Keys | Where-Object { $label -match $rolePatterns[$_] })
    if ($roles.Count -eq 0 -and $benchmarkTitle -match $rolePatterns.StandaloneServer) { $roles = @('StandaloneServer') }
    if ($roles.Count -ne 1 -or $roles[0] -cne $Role -or
        ($benchmarkTitle -match $rolePatterns.StandaloneServer -and $Role -ne 'StandaloneServer')) {
        throw "Cannot confirm $Role applicability for profile '$title' in '$benchmarkTitle'."
    }
    if (Get-BooleanAttribute $profile 'abstract' $false) { throw "Profile '$title' is abstract." }
}

function Get-ProfileChain($profile) {
    $chain = [Collections.Generic.List[Xml.XmlElement]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $current = $profile
    while ($null -ne $current) {
        if (-not $seen.Add($current.GetAttribute('id'))) { throw "Cyclic profile inheritance at '$($current.GetAttribute('id'))'." }
        $chain.Add($current)
        $parentId = $current.GetAttribute('extends')
        if (-not $parentId) { break }
        if (-not $profiles.ContainsKey($parentId)) { throw "Unknown parent profile '$parentId'." }
        $current = $profiles[$parentId]
    }
    $chain.Reverse()
    return $chain.ToArray()
}

function Get-SelectedRules($chain) {
    $selection = [Collections.Generic.Dictionary[string,bool]]::new([StringComparer]::Ordinal)
    $profilePlatforms = [Collections.Generic.List[string]]::new()
    foreach ($part in $chain) {
        foreach ($child in $part.SelectNodes('x:*',$namespaces)) {
            if ($child.LocalName -eq 'platform') { $profilePlatforms.Add($child.GetAttribute('idref')); continue }
            if ($child.LocalName -cne 'select') { continue }
            $ref = $child.GetAttribute('idref')
            if (-not $child.HasAttribute('selected')) { throw "Missing selected flag on profile selector '$ref'." }
            $selected = Get-BooleanAttribute $child 'selected' $true
            if ($items.ContainsKey($ref)) { $selection[$ref] = $selected }
            elseif ($clusters.ContainsKey($ref)) {
                foreach ($member in $clusters[$ref]) { $selection[$member]=$selected }
            } else { throw "Unknown selection item or cluster '$ref'." }
        }
    }
    foreach ($rule in $rules) {
        $ancestors = $rule.SelectNodes('ancestor-or-self::x:Group | self::x:Rule', $namespaces)
        $applies = $true
        foreach ($item in $ancestors) {
            $id = $item.GetAttribute('id')
            $enabled = if ($selection.ContainsKey($id)) { $selection[$id] } else { Get-BooleanAttribute $item 'selected' $true }
            if (-not $enabled) { $applies = $false; break }
        }
        if (-not $applies) { continue }
        $platformRefs = @($profilePlatforms.ToArray()) + @($rule.SelectNodes('ancestor-or-self::x:Group/x:platform | x:platform', $namespaces) | ForEach-Object { $_.GetAttribute('idref') })
        foreach ($item in $ancestors) {
            if ($null -ne $item.SelectSingleNode('x:requires | x:conflicts', $namespaces)) {
                throw "Unsupported conditional selection on '$($item.GetAttribute('id'))'."
            }
        }
        [pscustomobject]@{ Rule=$rule; PlatformRefs=$platformRefs }
    }
}

function New-KitBaseline([string]$profileId, [int]$level) {
    if (-not $profiles.ContainsKey($profileId)) { throw "Unknown profile '$profileId'. Use -ListProfiles for exact identifiers." }
    $profile = $profiles[$profileId]
    Assert-ProfileScope $profile $level
    $profileTitle = Get-RequiredText $profile 'title'
    $chain = @(Get-ProfileChain $profile)
    # Value bindings can influence a check indirectly. Retain the declared
    # membership and source instructions; use manual evidence throughout any
    # profile with refinements until a reviewer evaluates these semantics.
    $directives = @(foreach ($part in $chain) {
        foreach ($directive in $part.SelectNodes('x:set-value | x:set-complex-value | x:refine-value | x:refine-rule', $namespaces)) {
            [pscustomobject]@{ProfileId=$part.GetAttribute('id'); Directive=$directive.OuterXml}
        }
    })
    $controls = @(foreach ($entry in Get-SelectedRules $chain) {
        $rule = $entry.Rule
        $ruleId = $rule.GetAttribute('id')
        $title = Get-RequiredText $rule 'title'
        $control = [ordered]@{
            Id=$controlIds[$ruleId]; Title=$title; Category='Benchmark recommendation'; Severity='Informational'
            Assessment='Manual'; Roles=@($Role); Releases=@($Release); Fact=$null; Operator=$null; Expected=$null
            ExpectedDisplay='Check the target in the selected benchmark recommendation.'
            Rationale="Source rule $ruleId. Use the selected benchmark edition and profile to assess the server."
            Remediation='Assess the source recommendation and record the result and supporting evidence.'
            SourceUrl=$sourceUrl; SourceRuleId=$ruleId; SourcePlatformIds=@($entry.PlatformRefs)
        }
        switch -CaseSensitive ($rule.GetAttribute('severity')) {
            'high' { $control.Severity='High' }
            'medium' { $control.Severity='Medium' }
            'low' { $control.Severity='Low' }
        }
        if ($entry.PlatformRefs.Count -gt 0) {
            $control.ExpectedDisplay += ' Confirm the source platform applicability.'
        }
        if ($directives.Count -gt 0) {
            $control.ExpectedDisplay += ' Review the source profile refinements and value bindings.'
        }
        if ($mapping.ContainsKey($ruleId) -and $directives.Count -eq 0) {
            if ($entry.PlatformRefs.Count -gt 0 -or
                ($rule.HasAttribute('role') -and $rule.GetAttribute('role') -ne 'full') -or
                (Get-BooleanAttribute $rule 'multiple' $false)) {
                throw "Automated mapping for '$ruleId' requires rule-specific platform, role or multiple-instance evaluation. Remove that mapping to retain manual review."
            }
            $row = $mapping[$ruleId]
            $control.Assessment = 'Automated'
            foreach ($key in @('Fact','Operator','Expected','ExpectedDisplay')) { $control[$key]=$row.$key }
        }
        [pscustomobject]$control
    })
    if ($controls.Count -eq 0) { throw "Profile '$profileId' selects no rules." }
    $identity = Get-TextHash ($benchmarkId + '|' + $version + '|' + $digest + '|' + $profileId + '|' + $mappingDigest)
    [pscustomobject][ordered]@{
        SchemaVersion='1.0'; Id="xccdf-$Release-$roleSlug-l$level-$($identity.Substring(0,20))"
        Name="$benchmarkTitle - $profileTitle"; Version=$version; Framework='Imported XCCDF profile'
        Description="Source '$benchmarkTitle' revision '$version', profile '$profileTitle' ($profileId). Confirm the edition and benchmark-level platform qualification before use. Unmapped recommendations require manual evidence."
        SourceUrls=@($sourceUrl); SourceBenchmarkId=$benchmarkId; SourceBenchmarkTitle=$benchmarkTitle
        SourceBenchmarkVersion=$version; SourceProfileId=$profileId; SourceProfileTitle=$profileTitle; SourceSha256=$digest
        SourceBenchmarkPlatformIds=@($benchmark.SelectNodes('x:platform',$namespaces) | ForEach-Object { $_.GetAttribute('idref') })
        SourceMappingSha256=$mappingDigest; SourceProfileDirectives=$directives; Controls=$controls
    }
}

$sourceFile = Get-Item -LiteralPath $Path
if ($sourceFile -isnot [IO.FileInfo] -or $sourceFile.Length -gt 64MB) { throw 'Select a plain XCCDF XML file up to 64 MB.' }
$settings = [Xml.XmlReaderSettings]::new()
$settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
$settings.XmlResolver = $null
$settings.MaxCharactersInDocument = 64MB
$doc = [Xml.XmlDocument]::new()
$doc.XmlResolver = $null
# Hash and parse the same bytes while holding the source read-only.
$stream = [IO.File]::OpenRead($sourceFile.FullName)
try {
    $digest = (Get-FileHash -InputStream $stream -Algorithm SHA256).Hash.ToLowerInvariant()
    $stream.Position = 0
    $reader = [Xml.XmlReader]::Create($stream,$settings)
    try { $doc.Load($reader) } finally { $reader.Dispose() }
} finally { $stream.Dispose() }
$benchmark = $doc.DocumentElement
if ($null -eq $benchmark -or $benchmark.LocalName -cne 'Benchmark' -or
    $benchmark.NamespaceURI -cnotin @('http://checklists.nist.gov/xccdf/1.1','http://checklists.nist.gov/xccdf/1.2')) {
    throw 'Expected a standalone XCCDF 1.1 or 1.2 Benchmark document.'
}
$namespaces = [Xml.XmlNamespaceManager]::new($doc.NameTable)
$namespaces.AddNamespace('x',$benchmark.NamespaceURI)
$benchmarkId = $benchmark.GetAttribute('id')
if ([string]::IsNullOrWhiteSpace($benchmarkId)) { throw 'Benchmark id is required.' }
$benchmarkTitle = Get-RequiredText $benchmark 'title'
$version = Get-RequiredText $benchmark 'version'
$profiles = [Collections.Generic.Dictionary[string,Xml.XmlElement]]::new([StringComparer]::Ordinal)
foreach ($profile in $benchmark.SelectNodes('x:Profile',$namespaces)) { Add-IndexedNode $profiles $profile }
if ($ListProfiles) {
    foreach ($profile in $benchmark.SelectNodes('x:Profile',$namespaces)) {
        [pscustomobject]@{Id=$profile.GetAttribute('id');Title=Get-RequiredText $profile 'title';BenchmarkId=$benchmarkId;BenchmarkTitle=$benchmarkTitle;BenchmarkVersion=$version;Sha256=$digest}
    }
    return
}
if ($Level1ProfileId -ceq $Level2ProfileId) { throw 'Provide different Level 1 and Level 2 profiles.' }
$years = @([regex]::Matches($benchmarkTitle,'(?<!\d)(20\d\d)(?!\d)') | ForEach-Object Value | Sort-Object -Unique)
if ($benchmarkTitle -notmatch '(?i)Windows\s+Server' -or $years.Count -ne 1 -or $years[0] -ne $Release) {
    throw "Cannot confirm Windows Server $Release in the benchmark title '$benchmarkTitle'."
}
$roleSlug = @{MemberServer='member-server';DomainController='domain-controller';StandaloneServer='standalone-server'}[$Role]
$items = [Collections.Generic.Dictionary[string,Xml.XmlElement]]::new([StringComparer]::Ordinal)
$clusters = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
$rules = [Collections.Generic.List[Xml.XmlElement]]::new()
$controlIds = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
foreach ($item in $benchmark.SelectNodes('.//x:Group | .//x:Rule', $namespaces)) {
    if ($item.ParentNode.LocalName -cnotin @('Benchmark','Group') -or $item.ParentNode.NamespaceURI -cne $benchmark.NamespaceURI) { throw 'Unexpected Group or Rule outside the benchmark item hierarchy.' }
    if ($item.HasAttribute('extends') -or (Get-BooleanAttribute $item 'abstract' $false)) {
        throw "Unsupported item inheritance or abstract item on '$($item.GetAttribute('id'))'."
    }
    Add-IndexedNode $items $item
    $cluster = $item.GetAttribute('cluster-id')
    if ($cluster) {
        if (-not $clusters.ContainsKey($cluster)) { $clusters.Add($cluster, [Collections.Generic.List[string]]::new()) }
        $clusters[$cluster].Add($item.GetAttribute('id'))
    }
    if ($item.LocalName -ceq 'Rule') { $rules.Add($item) }
}
foreach ($cluster in $clusters.Keys) {
    if ($items.ContainsKey($cluster)) { throw "Cluster '$cluster' collides with an item identifier." }
}
# XCCDF IDs are case-sensitive; kit IDs are case-insensitive. Hash ambiguous or long IDs.
$occurrences = @{}
foreach ($rule in $rules) {
    $id=$rule.GetAttribute('id')
    if ($occurrences.ContainsKey($id)) { $occurrences[$id]++ } else { $occurrences[$id]=1 }
}
foreach ($rule in $rules) {
    $id=$rule.GetAttribute('id')
    $kitId = if ($occurrences[$id] -gt 1 -or $id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$' -or $id -match '^wsk-rule-') {
        'wsk-rule-' + (Get-TextHash $id)
    } else { $id }
    $controlIds.Add($id,$kitId)
}
$sourceUrl='https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/xccdf'
if ($benchmarkTitle -match '(?i)\bCIS\b|Center for Internet Security') { $sourceUrl='https://www.cisecurity.org/benchmark/microsoft_windows_server' }
foreach ($link in $benchmark.SelectNodes('x:reference[@href]', $namespaces)) {
    $uri=$null
    if ([Uri]::TryCreate($link.GetAttribute('href'),[UriKind]::Absolute,[ref]$uri) -and $uri.Scheme -in @('http','https')) { $sourceUrl=$uri.AbsoluteUri; break }
}
$mapping = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
$mappingDigest = $null
if ($MappingPath) {
    Import-Module (Join-Path $PSScriptRoot 'WskXccdfMapping.psm1') -ErrorAction Stop
    $mappingFile = Get-Item -LiteralPath $MappingPath
    $mappingLock = [IO.File]::OpenRead($mappingFile.FullName)
    try {
        $mappingDigest = (Get-FileHash -InputStream $mappingLock -Algorithm SHA256).Hash.ToLowerInvariant()
        $mapping = Import-WskXccdfMapping -Path $mappingFile.FullName -BenchmarkSha256 $digest -Role $Role -Release $Release -RuleIds @($controlIds.Keys)
    } finally { $mappingLock.Dispose() }
}
try { $directory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory) }
catch [IO.PathTooLongException] { throw 'Output path exceeds Windows PowerShell 5.1 legacy path limits. Choose a shorter output directory.' }
if ([IO.File]::Exists($directory) -or [IO.Directory]::Exists($directory)) { throw "Output directory already exists: $directory. Choose a new directory for the pair." }
$directory = $directory.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
$filenames = @("cis-windows-server-$Release-$roleSlug-level-1.json","cis-windows-server-$Release-$roleSlug-level-2.json")
# Windows PowerShell 5.1 and the framework APIs used below have legacy path
# limits. Check both publication locations before creating any directories.
if ($directory.Length -ge 248) {
    throw 'Output path exceeds Windows PowerShell 5.1 legacy path limits. Choose a shorter output directory.'
}
$parentPath = [IO.Path]::GetDirectoryName($directory)
$stage = [IO.Path]::Combine($parentPath,('.wsk-' + [guid]::NewGuid().ToString('N').Substring(0,12)))
foreach ($location in @($directory,$stage)) {
    foreach ($file in $filenames) {
        if ($location.Length -ge 248 -or [IO.Path]::Combine($location,$file).Length -ge 260) {
            throw 'Generated baseline paths exceed Windows PowerShell 5.1 legacy path limits. Choose a shorter output directory.'
        }
    }
}
$baselines = @((New-KitBaseline $Level1ProfileId 1), (New-KitBaseline $Level2ProfileId 2))
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules\Assessment.psm1') -ErrorAction Stop
$null = [IO.Directory]::CreateDirectory($parentPath)
$null = New-Item -Path $stage -ItemType Directory
try {
    for ($i=0; $i -lt $baselines.Count; $i++) {
        $stagedPath = Join-Path $stage $filenames[$i]
        [IO.File]::WriteAllText($stagedPath,($baselines[$i] | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
        $null = Import-WskBaseline -Path $stagedPath
    }
    [IO.Directory]::Move($stage,$directory)
} finally {
    try {
        if ([IO.Directory]::Exists($stage)) {
            foreach ($file in $filenames) { [IO.File]::Delete([IO.Path]::Combine($stage,$file)) }
            [IO.Directory]::Delete($stage)
        }
    } catch { Write-Warning "Temporary files remain at '$stage': $($_.Exception.Message)" -WarningAction Continue }
}
foreach ($file in $filenames) { Get-Item -LiteralPath ([IO.Path]::Combine($directory,$file)) }
