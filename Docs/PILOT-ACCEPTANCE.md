# Pilot acceptance

Use this checklist for the 0.2.1 pilot.

| Pilot target | Validate |
| --- | --- |
| Server 2019 / 2022 / 2025 member servers | Elevated and limited access; effective firewall/SMB; local policy vs known settings |
| Each domain-controller release | DC role detection; local-account controls not applicable; domain/LDAP manual evidence retained |
| Standalone server | Role identification and local-account scope |
| Server Core | CLI operation and usable exported report |
| Desktop Experience | Load the bundled sample. With a reviewed Internet-marked kit under the target policy, confirm any permitted trust prompt appears in the visible console. Declining must leave the GUI without a new report. For an approved run, confirm the GUI opens that run's HTML. |
| Defender active / approved third-party EDR | Accurate Defender-specific results, manual EDR evidence and approved exceptions |
| BitLocker absent / unknown / suspended / encrypting / fully encrypted | Unavailable or unknown states remain Review; known Off/in-progress states fail; On/FullyEncrypted passes; no recovery material in output |
| Restricted permissions / absent optional components | No false pass; Review/Error and clear evidence |
| CIS profiles | Compare both generated sets of source rule IDs against the authorised edition, role and profiles. Independently verify every automated mapping against the benchmark's complete audit procedure on a representative server. |

For every target, independently compare a selection of passes and every unexpected failure with native Windows tools and the approved baseline. Confirm that reading explicit registry policy does not get mistaken for proof of effective enforcement or completed restart.

Check that every emitted control has a status, manual work is visible, and exception expiry plus customer/machine/host/baseline binding behave as expected. Reusing a ledger on another customer's same-named server must leave its failure unexcepted. Confirm missing machine UUIDs and legacy schema 1.0 ledgers produce warnings and no applied exceptions. Check report files remain within the customer location and temporary policy exports are removed after normal completion. On interruption, inspect the session temp folder for owned export leftovers.

Record OS build/patch level, role, PowerShell version, kit and baseline hashes, operator, sample evidence, discrepancy resolution and service owner sign-off. Include the full exact benchmark coverage review before offering a formal CIS/STIG/Microsoft compliance service.
