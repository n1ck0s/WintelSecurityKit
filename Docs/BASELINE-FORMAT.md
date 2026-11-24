# Baseline format 1.0

A baseline is a UTF-8 JSON document, at most 5 MB and 2,000 controls. Copy the bundled profile and give your own policy a distinct ID and version. Record the exact upstream document revision in its description. Never label a partial profile as complete benchmark coverage.

```json
{
  "SchemaVersion": "1.0",
  "Id": "customer-example",
  "Name": "Customer approved firewall subset",
  "Version": "1.0.0",
  "Framework": "Customer policy",
  "Description": "One illustrative check; not full standard coverage.",
  "SourceUrls": ["https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/"],
  "Controls": [{
    "Id": "CUSTOM-001",
    "Title": "Domain firewall profile enabled",
    "Category": "Network",
    "Severity": "High",
    "Assessment": "Automated",
    "Roles": ["MemberServer", "DomainController", "StandaloneServer"],
    "Releases": ["2019", "2022", "2025"],
    "Fact": "Firewall.Domain.Enabled",
    "Operator": "Equals",
    "Expected": true,
    "ExpectedDisplay": "Enabled",
    "Rationale": "Host filtering must be enabled.",
    "Remediation": "Review the approved firewall policy and application requirements.",
    "SourceUrl": "https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/"
  }]
}
```

Required fields appear above. IDs are unique, case-insensitive alphanumeric/dot/hyphen/underscore strings (first character alphanumeric, at most 100 characters). Supported severities: Critical, High, Medium, Low, Informational. Roles and releases must be explicit nonempty arrays of supported values.

Manual controls use `"Assessment": "Manual"` and `null` for Fact, Operator and Expected. They still require ExpectedDisplay, source, rationale, remediation and applicability. Automated controls require a supported operator and typed expected value. Source links must be HTTP(S).

| Operator | Expected | Evaluation |
| --- | --- | --- |
| Equals / NotEquals | Boolean, number or string | Strict type; strings use ordinal, case-insensitive comparison |
| GreaterOrEqual / LessOrEqual | Number | Inclusive numerical threshold |
| Between | Two numbers `[min,max]` | Inclusive bounds; min must not exceed max |
| In | Nonempty array of one type | Actual scalar equals one expected item |
| Contains | Scalar | Actual array contains expected item; all collected elements must have the expected type |

Strings are never coerced to booleans or numbers. A type mismatch produces Error. Missing registry values are Review; there is no automatic default-value assumption. Unsupported collector names are Review, never Pass. A custom JSON file cannot execute PowerShell commands or fetch remote evidence.

## Collector catalogue

| Fact | Value / scope |
| --- | --- |
| `Firewall.Domain.Enabled`, `Firewall.Private.Enabled`, `Firewall.Public.Enabled` | Boolean from ActiveStore |
| `Firewall.Domain.DefaultInboundAction`, `Firewall.Private.DefaultInboundAction`, `Firewall.Public.DefaultInboundAction` | Resolved string, e.g. `Block`; NotConfigured becomes Review |
| `SmbServer.EnableSMB1Protocol` | Boolean; SMB server only |
| `SmbServer.RequireSecuritySignature` | Boolean |
| `SmbClient.RequireSecuritySignature` | Boolean |
| `SmbClient.EnableInsecureGuestLogons` | Boolean |
| `Defender.AntivirusEnabled`, `Defender.RealTimeProtectionEnabled` | Boolean; Microsoft Defender only |
| `Defender.AntivirusSignatureAge` | Numeric age in days |
| `BitLocker.OSProtected` | Boolean: protection On and volume FullyEncrypted; OS volume only. Unknown or unrecognized status becomes Review; known Off or incomplete encryption is false. |
| `SecurityPolicy.MinimumPasswordLength`, `PasswordComplexity`, `PasswordHistorySize`, `LockoutBadCount`, `LockoutDuration`, `ResetLockoutCount`, `ClearTextPassword` | Prefix each name with `SecurityPolicy.`; integer from local-account merged security policy; unavailable on DCs |
| `Registry\|<HKLM subkey>\|<value name>` | Actual registry value through Registry64; delimiter is a literal pipe, no backslash escaping |

Registry example: `Registry|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System|EnableLUA` in JSON. Only HKLM is supported; omit an HKLM prefix. Standard JSON requires backslashes within paths to be doubled. JSON is a trusted local configuration input; review custom paths to avoid collecting unnecessary sensitive values.

Collectors are cached per source during a scan. Each fact has State (Collected/Unavailable/Error), typed Value, Evidence and Reason. Reports preserve the observed value and source evidence. There is no executable rule DSL, compound expression or dependency evaluator in this release: split conditions into precise controls, add a reviewed collector, or use manual evidence.

## Baseline review before release

Locally imported XCCDF profiles also carry the benchmark and profile identifiers, source SHA-256, and the exact rule ID in each control's `SourceRuleId`. Level 1 and Level 2 have distinct kit IDs. Changing the source document or automation mapping generates a new baseline ID so earlier exceptions require review. [CIS import walkthrough](CIS-IMPORT.md)

Record the baseline owner, exact authoritative version, licensing entitlement where applicable, role/release applicability, setting semantics, evidence source and expected-value type. Test known pass/fail/missing states on each applicable release. Compare results with native Windows tools and the authoritative assessment procedure. Revise the baseline version whenever policy interpretation changes, then reapprove any exceptions bound to its previous version.
