# Import CIS Level 1 and Level 2 profiles

Start with an authorised Windows Server **XCCDF Benchmark XML** file for the release and role you assess. CIS publishes separate Windows Server editions and offers XCCDF through SecureSuite. The profile level and the benchmark document version are separate fields. The importer reads both from the selected export and runs offline. [CIS Windows Server catalogue](https://www.cisecurity.org/benchmark/microsoft_windows_server) · [CIS profile and format FAQ](https://www.cisecurity.org/cis-benchmarks/cis-benchmarks-faq)

## Generate the two baselines

Open 64-bit Windows PowerShell 5.1 in the extracted kit. Enter the path to your local XML and list the profile IDs.

```powershell
$xml = Read-Host 'Full path to the authorised XCCDF XML file'
$profiles = .\Tools\ConvertFrom-WskXccdf.ps1 -Path $xml -ListProfiles
$profiles | Format-List Id, Title, BenchmarkTitle, BenchmarkVersion
```

Choose the Level 1 and Level 2 IDs for the **same server role**. For example, for a Windows Server 2022 member server, run the following. For other targets, change `Release`, `Role` and the destination folder. Valid roles are `MemberServer`, `DomainController` and `StandaloneServer`. For a standalone server use its own benchmark edition.

```powershell
$import = @{
    Path            = $xml
    Level1ProfileId = (Read-Host 'Exact Level 1 profile ID')
    Level2ProfileId = (Read-Host 'Exact Level 2 profile ID')
    Release         = '2022'
    Role            = 'MemberServer'
    OutputDirectory = '.\Baselines\Imported\2022-member'
}
$baselines = .\Tools\ConvertFrom-WskXccdf.ps1 @import
$baselines | Select-Object Name, FullName
```

Use a new output directory each time. A successful import creates two JSON files together. Keep the source export, mappings and generated profiles in the location approved for your engagement. The kit's package builder includes only the synthetic examples.

Choose a short destination path on Windows PowerShell 5.1. The importer checks the generated filenames against its legacy path limits before writing. If it requests a shorter path, use a location such as `C:\SecurityBaselines\2022-member`.

## Run the assessment

In the GUI, select **Baseline JSON → Browse**, open your import directory and select the file ending in `level-1.json` or `level-2.json`. Select **Run assessment** on the matching server. For the 2022 member-server example, the equivalent CLI command for Level 2 is below.

```powershell
.\Invoke-WintelSecurityAssessment.ps1 -BaselinePath '.\Baselines\Imported\2022-member\cis-windows-server-2022-member-server-level-2.json'
```

Each selected rule initially requires manual review. On the matching server a manual-only profile produces **Review** rows, a null tested pass rate and CLI exit code **3**. HTML, JSON and CSV reports are still written. Controls for a different role or release show **NotApplicable**. The JSON report records the exact source profile ID, benchmark version, file fingerprint and source rule IDs.

## Add an automated check

For a rule whose complete audit can be expressed by one kit fact and comparison, create a mapping JSON. Set `BenchmarkSha256` to the XML's SHA-256 from `Get-FileHash -LiteralPath $xml`, use the exact source rule ID, and specify the same release and role as the import. Supply expected values as JSON booleans, numbers, strings or arrays as required by the operator. Run the importer again with `-MappingPath` and a new output directory. A mapping should be valid for every selected level in which that rule occurs. Leave rules requiring additional evidence for manual review. [Synthetic mapping file](../Samples/CisImport/mapping.example.json) · [Fact and operator catalogue](BASELINE-FORMAT.md)

Review each profile's rule set against the source export before deployment. The importer reads profile selection and inheritance. It does not run OVAL, execute XCCDF checks or fixes, resolve remote files, or infer an audit from the text of a recommendation. Use the source rule ID to locate the authoritative audit instructions for each **Review** result. A percentage in the report covers only checks the kit evaluated.

The importer accepts a standalone XCCDF 1.1 or 1.2 `Benchmark` document up to 64 MB. Extract the benchmark XML first if the download is a ZIP. It follows inherited profiles, group defaults and cluster selectors. Profiles that refine rule behaviour or set values retain those source directives and use manual review throughout. Item inheritance and conditional rule selection can require a resolved export. An unsupported selection stops the import before it publishes either file. [XCCDF specification](https://csrc.nist.gov/pubs/ir/7275/r4/upd1/final)

## Try it with the included example

The example uses an invented Windows Server 2022 member-server benchmark. Its two levels and firewall mapping demonstrate the workflow and contain no CIS recommendations. The ready-to-open JSON files can be selected directly in the kit. [Example Level 1 JSON](../Samples/CisImport/level-1.example.json) · [Example Level 2 JSON](../Samples/CisImport/level-2.example.json)

For this fixture, Level 1 contains one automated check and one manual item. Level 2 inherits both and adds a second manual item. In demo mode the mapped check passes and both Level 2 manual items appear as **Review**.

```powershell
.\Invoke-WintelSecurityAssessment.ps1 -Demo -DemoRelease 2022 -DemoRole MemberServer -BaselinePath '.\Samples\CisImport\level-2.example.json'
```

To regenerate the examples from their source, use the following command with a new output folder.

```powershell
$example = @{
    Path            = '.\Tests\Fixtures\windows-server-synthetic.xccdf.xml'
    Level1ProfileId = 'xccdf_org.example_profile_L1_Member'
    Level2ProfileId = 'xccdf_org.example_profile_L2_Member'
    Release         = '2022'
    Role            = 'MemberServer'
    MappingPath     = '.\Samples\CisImport\mapping.example.json'
    OutputDirectory = '.\Baselines\Imported\synthetic-example'
}
.\Tools\ConvertFrom-WskXccdf.ps1 @example
```
