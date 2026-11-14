# Microsoft Azure compute security baseline subset

Select `Baselines/microsoft-windows-server-subset.v1.json` in the launcher or pass it to the CLI with `-BaselinePath`. The kit compares five Windows registry settings with the values Microsoft publishes for its Azure compute security baseline. It reads the local server and requires no Azure connection.

Profile version **1.0.0** references two Microsoft Learn tables, reviewed **14 November 2026**. The table for Server 2019 and 2022 shows an update date of **1 March 2023**. The separate 2025 table shows **7 November 2025**. These dates identify the source revisions used to create this profile. [2019/2022 reference](https://learn.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows) · [2025 reference](https://learn.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows-server-2025)

| Kit rule suffix | Microsoft reference identifier | Machine registry value | Published target |
| --- | --- | --- | --- |
| 01 | CCE-36869-6 | UAC `EnableLUA` | 1 |
| 02 | AZ-WIN-73645 | Interactive logon `InactivityTimeoutSecs` | 1 to 900 seconds inclusive |
| 03 | CCE-36325-9 | SMB client `RequireSecuritySignature` | 1 |
| 04 | CCE-37864-6 | SMB server `RequireSecuritySignature` | 1 |
| 05 | CCE-36062-8 | Domain firewall profile `EnableFirewall` | 1 |

The five `MS-AZ-A` rules apply to Server 2019 and 2022. The five `MS-AZ-B` rules use the Server 2025 reference. This preserves a release-specific source link on every finding. The source lists all three roles for the older five rules. For Server 2025, it lists only domain controllers and member servers for the domain firewall rule. A Server 2025 standalone server therefore receives four applicable tests. Every other supported release and role receives five.

The kit reads the numeric registry values in Microsoft's tables using the 64-bit HKLM view. The named values are documented as DWORDs. A missing value produces Review. Numeric equality and range checks evaluate the observed number. Confirm the registry kind separately if exact type attestation is required. For an operational check of effective firewall and SMB state, use the foundation profile.

Severity follows the Microsoft table, with the kit's High label used for Microsoft's Important label. The local pass rate covers the selected, evaluated settings. Azure Policy assignments, customised guest configurations and the rest of the Microsoft baseline require their own assessment.

