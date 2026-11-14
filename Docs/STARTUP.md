# When Windows PowerShell reports “AuthorizationManager check failed”

If the launcher shows `Running sample assessment...` followed by `AuthorizationManager check failed`, `SecurityError` or `UnauthorizedAccess`, **open [the included sample HTML report](../Samples/Demo/SecurityAssessment.html) directly from the extracted kit**. It opens in a browser without starting PowerShell. The [sample guide](../Samples/Demo/README.md) explains the findings. On Server Core, view the bundled example on a workstation.

In the updated launcher, select **Load sample**, then **Open HTML report** to view the bundled example. The earlier **Run sample** button started a second Windows PowerShell process. Live assessments still use this child process. The GUI can open successfully while Windows declines to run the assessment script or one of its modules. The child uses `-NonInteractive`, so a publisher or other trust decision that requires an interactive prompt can fail there. The full error text, the path it names and the time of the attempt help identify which file Windows was checking. That message alone leaves the cause unresolved. [Windows PowerShell launch options](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1)

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
        [pscustomobject]@{ File = $file; HasZoneIdentifier = $zoneResult }
    } catch {
        [pscustomobject]@{ File = $file; HasZoneIdentifier = 'Unknown'; Detail = $_.Exception.Message }
    }
}
```

The first command lists scope policies in precedence order. The second reports the effective policy in this console. A defined Group Policy at `MachinePolicy` or `UserPolicy` takes precedence over the lower scopes. `Restricted` can account for a script refusal. `AllSigned` requires trusted signatures on scripts and modules. Under `RemoteSigned`, Internet-origin files can require trusted signatures. [Execution policy guidance](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1) · [Get-ExecutionPolicy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-executionpolicy?view=powershell-5.1)

`NotSigned` indicates that Windows found no Authenticode signature. If the applicable policy requires signing, give the kit version, the named file, the status and publisher to the organisation's Windows deployment team. Have the reviewed launcher, runner and modules signed and distributed through its existing trusted code-signing process. For `HashMismatch` or an invalid signature, obtain a verified copy from the release owner. A valid signature may still need publisher approval through the organisation's deployment process. [Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature?view=powershell-5.1) · [PowerShell script signing](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing?view=powershell-5.1)

`HasZoneIdentifier` records whether that alternate data stream exists on each extracted file. A present stream supplies a clue about file origin. Its presence alone does not establish the zone or the reason for the refusal. [Get-Item stream support](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item?view=powershell-5.1)

If the cause remains unclear, ask the Windows security team to correlate the time and file path with **AppLocker → MSI and Script** and **CodeIntegrity → Operational** under Event Viewer → Applications and Services Logs → Microsoft → Windows. Record a matching event ID, policy name and whether it reports enforcement or audit. An audit event alone does not establish that application control prevented the run. [Microsoft application-control troubleshooting](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/appcontrol-debugging-and-troubleshooting)
