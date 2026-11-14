# When Windows PowerShell reports “AuthorizationManager check failed”

## Run a live assessment

In kit 0.1.2, select **Run assessment** and look for the Windows PowerShell console. Windows can ask about the runner and again when it loads an Internet-marked module. Review the named file and respond according to your organisation's approval. After a completed run, the GUI enables **Open HTML report**.

In 0.1.1 the GUI started the live runner with `-NonInteractive`. With an effective execution policy of `Unrestricted`, Windows PowerShell can still warn before running downloaded files. If a warning needs a response, the old runner can fail before collecting any evidence. A present `Zone.Identifier` alone does not identify the zone. [PowerShell execution policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1) · [Windows PowerShell launch options](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1)

For any version, open **64-bit Windows PowerShell 5.1** in the extracted kit folder and run the following command. This keeps the Windows message visible if startup fails. Record the first error, named file and time if your deployment team needs to investigate.

```powershell
.\Invoke-WintelSecurityAssessment.ps1
```

## View the sample

Select **Load sample**, then **Open HTML report**, or open `Samples\Demo\SecurityAssessment.html` directly from the extracted kit. The sample uses synthetic data and opens in a browser without starting the runner. On Server Core, open it on a workstation. [Sample output guide](../Samples/Demo/README.md)

## Inspect the local copy

Open **64-bit Windows PowerShell 5.1** under the same account and elevation level used for the launcher. Change to the extracted directory containing `Invoke-WintelSecurityAssessment.ps1`. Enter these commands at the prompt. They read the current console's settings and file metadata.

```powershell
Get-ExecutionPolicy -List
Get-ExecutionPolicy

$kitFiles = @(
    '.\Start-WintelSecurityGui.ps1'
    '.\Invoke-WintelSecurityAssessment.ps1'
    '.\Modules\Assessment.psm1'
    '.\Modules\Reporting.psm1'
    '.\Modules\Collectors.psm1'
)

Get-AuthenticodeSignature -LiteralPath $kitFiles |
    Select-Object Path, Status, @{Name='Publisher'; Expression={$_.SignerCertificate.Subject}} |
    Format-List

foreach ($file in $kitFiles) {
    try {
        $streams = Get-Item -LiteralPath $file -Stream * -ErrorAction Stop
        $zoneResult = @($streams | Where-Object Stream -eq 'Zone.Identifier').Count -gt 0
        $zoneId = if ($zoneResult) {
            Get-Content -LiteralPath $file -Stream Zone.Identifier -ErrorAction Stop |
                Select-String '^\s*ZoneId\s*=\s*(\d+)\s*$' |
                ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -First 1
        }
        [pscustomobject]@{ File = $file; HasZoneIdentifier = $zoneResult; ZoneId = $zoneId }
    } catch {
        [pscustomobject]@{ File = $file; HasZoneIdentifier = 'Unknown'; Detail = $_.Exception.Message }
    }
}
```

The first command lists scope policies in precedence order. The second reports the effective policy in this console. A defined Group Policy at `MachinePolicy` or `UserPolicy` takes precedence over the lower scopes. `Restricted` can account for a script refusal. `AllSigned` requires trusted signatures on scripts and modules. Under `RemoteSigned`, Internet-origin files can require trusted signatures. [Execution policy guidance](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1) · [Get-ExecutionPolicy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-executionpolicy?view=powershell-5.1)

`NotSigned` indicates that Windows found no Authenticode signature. If the applicable policy requires signing, give the kit version, the named file, the status and publisher to the organisation's Windows deployment team. Have the reviewed launcher, runner and modules signed and distributed through its existing trusted code-signing process. For `HashMismatch` or an invalid signature, obtain a verified copy from the release owner. A valid signature may still need publisher approval through the organisation's deployment process. [Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature?view=powershell-5.1) · [PowerShell script signing](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing?view=powershell-5.1)

`ZoneId=3` identifies the Internet zone. The commands above print only the numeric zone field from the stream, so you can share the result without disclosing the download URL. [Windows security zones](https://learn.microsoft.com/en-us/dotnet/api/system.security.securityzone) · [Get-Item stream support](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item?view=powershell-5.1)

If the cause remains unclear, ask the Windows security team to correlate the time and file path with **AppLocker → MSI and Script** and **CodeIntegrity → Operational** under Event Viewer → Applications and Services Logs → Microsoft → Windows. Record a matching event ID, policy name and whether it reports enforcement or audit. An audit event alone does not establish that application control prevented the run. [Microsoft application-control troubleshooting](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/appcontrol-debugging-and-troubleshooting)
