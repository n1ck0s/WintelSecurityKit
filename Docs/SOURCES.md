# Baseline sources and interpretation

Research reviewed: **14 November 2026**. Bundled policy: **windows-server-foundation 1.0.0**.

The 40 checks are an original foundation profile: 32 automated checks and 8 manual evidence prompts. This is a limited posture assessment, not a complete implementation of CIS, Microsoft security baselines, DISA STIG, or Essential Eight. The version identifies this kit's policy, not a third-party benchmark version. No licensed CIS benchmark text or CIS control numbers are bundled.

## What each result means

- **Effective configuration:** firewall ActiveStore and SMB configuration values are read through Windows interfaces. They do not establish network reachability, allowed-rule quality or every installed protocol component.
- **Explicit policy:** registry controls compare the stored machine value. Missing values remain **Review** even when an OS may have a secure default. The kit does not infer runtime enforcement after a recent change or pending reboot.
- **Local accounts:** the security-policy export is assessed only on member and standalone servers. It does not prove the password policy of domain accounts or individual fine-grained policy assignments.
- **Endpoint protection:** Defender checks describe Defender specifically. Approved alternative products require management-console evidence and a documented exception; a disabled Defender result is not proof that no antivirus exists.
- **Manual evidence:** local snapshots cannot establish MFA coverage, restore success, complete patch compliance, application-control effectiveness, or organisation-wide maturity.

## Explicit policy choices

The foundation profile selects: at least 14 password characters; 24 remembered passwords; 1–10 failed attempts; a reset interval of at least 15 minutes; an inactivity limit of 1–900 seconds; and Defender security intelligence no more than one day old. These are **kit thresholds for review with the customer**, not a claim that all standards or all Microsoft baseline releases require the same values. Very low lockout thresholds can cause denial of service. Lockout duration, reset interval and threshold must be assessed together.

UAC administrator prompt values 1, 2 and 5 are accepted; standard-user elevation is denied in this profile. BitLocker requires the OS volume to report both Protection On and FullyEncrypted; it does not assess other volumes or recovery escrow. The installer check covers HKLM only. Script-block logging checks Windows PowerShell policy only; collection, protection and retention of logs need separate validation.

NoLMHash and legacy LAN Manager authentication policy checks apply to Server 2019/2022 only. Server 2025 changed legacy authentication behavior, including removal of the NoLMHash policy described in its [release notes](https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-windows-server-2025). LDAP security is manual because release, upgrade history and enforcement precedence affect the conclusion.

## Primary references

| Checks | Documentation |
| --- | --- |
| WSK-001–006 | [Windows Firewall command-line configuration](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-with-command-line) |
| WSK-007 | [Detect SMB protocol configuration](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3) |
| WSK-008–009 | [SMB signing behavior](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing) |
| WSK-010 | [SMB guest authentication](https://learn.microsoft.com/en-us/windows-server/storage/file-server/enable-insecure-guest-logons-smb2-and-smb3) |
| WSK-011–013, WSK-106 | [Defender on Windows Server](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows-server-configure); [status properties](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus) |
| WSK-014 | [BitLocker operations](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide) |
| WSK-015 | [Microsoft Windows configuration reference](https://learn.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows) |
| WSK-016–020 | [Complexity](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements); [history](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enforce-password-history); [lockout threshold](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold); [counter reset](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/reset-account-lockout-counter-after); [reversible storage](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) |
| WSK-021–024 | [UAC policy and registry values](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration) |
| WSK-025–027 | [LM hash policy](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/prevent-windows-store-lm-hash-password); [LAN Manager authentication level](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level); [WDigest policy](https://support.microsoft.com/en-us/security/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014) |
| WSK-028 | [Windows PowerShell logging policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowspowershell) |
| WSK-029 | [Machine inactivity policy](https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/troubleshoot-unexpected-rds-session-locks-or-disconnections) |
| WSK-030 | [Windows Installer elevated-install policy](https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated) |
| WSK-031 | [Audit policy precedence](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/security-auditing-settings-not-applied-when-deploy-domain-based-policy) |
| WSK-032 | [Server 2025 configuration reference](https://learn.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows-server-2025); [earlier Windows configuration reference](https://learn.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows) |
| WSK-101–104 | [Essential Eight reference](https://www.cyber.gov.au/publication/essential-eight-maturity-model) — prompts cover selected themes only; no maturity rating is calculated |
| WSK-105 | [Fine-grained password policies and resultant policy](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/fine-grained-password-policies) |
| WSK-107 | [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing); [channel binding](https://learn.microsoft.com/en-gb/windows-server/identity/ad-ds/ldap-channel-binding) |
| WSK-108 | [RDP and NLA](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access); [RDS certificates](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remote-desktop-services-certificates) |

Each control also carries a source URL in the baseline and report. Some policy reference articles retain older product titles; their setting descriptions are used alongside server-specific references. Source pages can change independently of this versioned JSON file.

## Adding a formal standard

Obtain the exact benchmark and version for each server release and role through your organisation's permitted source. The [CIS Windows Server catalogue](https://www.cisecurity.org/benchmark/microsoft_windows_server) lists distinct editions; its free PDF offer specifies non-commercial use. Confirm that your organisation's entitlement covers its intended managed-service use and redistribution.

For Microsoft baselines, use the relevant package from the [Security Compliance Toolkit](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10). For Server 2025, also review [OSConfig baselines](https://learn.microsoft.com/en-us/windows-server/security/osconfig/osconfig-how-to-configure-security-baselines).

Create a separately named, versioned customer JSON profile; retain source version, approved interpretation and review evidence. The engine supports a finite set of collectors and comparisons, so unsupported checks remain manual or require a reviewed collector enhancement. A benchmark identifier in a JSON file does not make the tool certified or establish complete coverage.

