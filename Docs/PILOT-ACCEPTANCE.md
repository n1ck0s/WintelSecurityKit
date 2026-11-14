# Pilot acceptance

Release 0.1.1 is ready for a controlled pilot, not a claim of production certification.

| Pilot target | Validate |
| --- | --- |
| Server 2019 / 2022 / 2025 member servers | Elevated and limited access; effective firewall/SMB; local policy vs known settings |
| Each domain-controller release | DC role detection; local-account controls not applicable; domain/LDAP manual evidence retained |
| Standalone server | Role identification and local-account scope |
| Server Core | CLI operation and usable exported report |
| Desktop Experience | GUI responsiveness, error handling, bundled sample loading, fresh report generation and report opening |
| Defender active / approved third-party EDR | Accurate Defender-specific results, manual EDR evidence and approved exceptions |
| BitLocker absent / suspended / encrypting / fully encrypted | Missing, false and true states remain distinct; no recovery material in output |
| Restricted permissions / absent optional components | No false pass; Review/Error and clear evidence |

For every target, independently compare a selection of passes and every unexpected failure with native Windows tools and the approved baseline. Confirm that reading explicit registry policy does not get mistaken for proof of effective enforcement or completed restart.

Check that every emitted control has a status, manual work is visible, exception expiry and host/baseline binding behave as expected, report files remain within the customer location, and temporary policy exports are removed after normal completion. On interruption, inspect the session temp folder for owned export leftovers.

Record OS build/patch level, role, PowerShell version, kit and baseline hashes, operator, sample evidence, discrepancy resolution and service owner sign-off. Include the full exact benchmark coverage review before offering a formal CIS/STIG/Microsoft compliance service.
