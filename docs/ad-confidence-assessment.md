# How confident are we that krb-credd works with Microsoft Active Directory?

*Assessment as of 2026-10-10, version 2.3.0. Nothing in this repository has yet
been run against Microsoft AD; this is reasoning, not lab evidence.
`tests/verify-ad.sh` turns it into a firm answer.*

## Summary

**High confidence in the approach; moderate confidence that a first lab run
works without a configuration fix.**

krb-credd does nothing exotic. It uses AD's standard *constrained delegation
with protocol transition* (S4U2Self, then S4U2Proxy), which is how many Linux
and Windows front ends obtain Kerberos tickets for users. It does so through
MIT's ordinary `kinit`, `kvno` and `klist`. AD is the reference implementation
of these extensions, and this configuration is what Microsoft recommends in
place of unconstrained delegation.

## Confidence by component

| Component | Confidence | Why |
|---|---|---|
| Broker logs in with its keytab (`kinit -k`) | High | Standard `ktpass` setup. The usual pitfall, a keytab key or salt that doesn't match AD, is easy to detect and covered in the test-lab runbook (sections 5.5, 9.1 and 14). |
| AD issues tickets in the user's name to the listed service (S4U2Self + S4U2Proxy) | High | Exactly what `msDS-AllowedToDelegateTo` and "use any authentication protocol" (`TrustedToAuthForDelegation`) exist for. Needs AES enabled on the accounts; both are in the runbook. |
| AD refuses Protected Users / "sensitive and cannot be delegated" accounts, and services not on the allow-list | High | AD's own enforcement; krb-credd only reports the result. |
| Encryption | High | The runbook sets AES256 on every account. A back-end service still issuing RC4 tickets only produces a warning since 2.3.0. |
| Login hook, Slurm TaskProlog, shared home, installing caches as the user | Medium-high | Standard Linux pieces. The logic is tested end to end, but not yet on a real cluster with NFS root squashing. |
| **2.3.0 check of the user name in tickets** | **Medium** | The most likely thing to trip. It assumes AD writes the user's `sAMAccountName` (or the uidmap principal) as the ticket's client name. That is believed to be AD's behaviour but has not been verified. If AD names users differently, valid users get `bad_ticket`. Mitigations: `ticket_checks = warn` relaxes that check; `verify-ad.sh` reports the exact name AD uses. |
| Users from another AD domain | Low / untested | Classic (non-resource-based) constrained delegation is restricted across domain boundaries by MS-SFU unless resource-based delegation is configured. Keep the test lab to one domain. |
| Ticket lifetimes | High, with a quirk | AD's defaults (10 h tickets, 7-day renewal) match the configuration. A delegated ticket cannot outlive the broker's own TGT, so some mints get shorter tickets and are simply re-minted sooner. |

## What could go wrong on the first run, most likely first

1. **AD configuration slips:** a keytab whose key doesn't match AD, a missing or
   duplicate SPN, AES not enabled on an account. Common, and `krb-credd --check`
   and `tests/verify-ad.sh` pinpoint them.
2. **The user-name check** described above. One configuration line works
   around it (`ticket_checks = warn`), and `verify-ad.sh` reveals it at once.
3. **Lab plumbing:** firewall, DNS, time sync, SSSD UID mapping. Ordinary
   troubleshooting, covered in section 14 of the runbook.

## What testing has and hasn't covered

| Covered | Not yet covered |
|---|---|
| Full S4U2Self + S4U2Proxy path against an MIT KDC with a delegation allow-list (38 end-to-end checks) | Microsoft Active Directory (PAC handling, its allow-list evaluation, how it names users in S4U tickets) |
| MIT Kerberos 1.20.1 and 1.21.3 (RHEL 9's version), both `kvno -U` and `-I` | Real Slurm cluster |
| 45 unit tests, including the 2.3.0 safety controls | Real shared filesystem with root_squash or `sec=krb5p` |
| Independent code review of 2.3.0 | Live Hive/HDFS back ends |
| `tests/verify-ad.sh` dry run against the MIT test KDC (23/23) | `verify-ad.sh` against your AD (the UPN probe can only be exercised there) |

Treat the testing as strong evidence that krb-credd's own logic is right, not
as proof of Active Directory compatibility.

## How to turn this into a firm answer

On the broker node, after the test-lab runbook's sections 5 to 9:

```bash
cd /opt/krb-hpc
sudo tests/verify-ad.sh --user jdoe --user asmith --refused ptest \
     --url http://svc01.test.lab/whoami/ --kill-switch
```

Look first at section 3 of the report, the line
`AD names jdoe in tickets as: …`. If it is not `jdoe@TEST.LAB`, the 2.3.0
name check needs adjusting (or `ticket_checks = warn` until it is). The report
is saved to `/var/tmp/krb-hpc-ad-test-<timestamp>.txt`.

## Sources

- [FreeIPA design: Constrained delegation for Kerberos services](https://freeipa.readthedocs.io/en/stable/_sources/designs/rbcd.md)
  (summary of MS-SFU's cross-realm restriction on S4U2Proxy, and the
  forwardable-ticket requirement)
- This repository: `AD-SETUP.md`, `SECURITY.md`, `docs/hpc-test-lab-setup-runbook.docx`,
  `tests/verify-ad.sh`, `tests/verify-shared-home.output.txt`
