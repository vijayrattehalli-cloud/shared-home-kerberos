# CRAFT vs orthrus: Implementation Cost and Cyber Security Risk

Oct 14, 2026

**Bottom line:** orthrus is cheaper to stand up and exposes less when a user
credential is stolen; its single largest risk is concentrated in one place, the
broker keytab on the login node. CRAFT's privileged modes cost more in PKI and
policy work, and a compromise of their service credential yields full logins
as users.

**Basis.** This document reframes
[`craft-vs-orthrus-comparison.docx`](craft-vs-orthrus-comparison.docx)
(CRAFT commit 38e4c6e; orthrus 2.3.0) through cost and risk. CRAFT was not
built or run, so its ratings rest on its documentation. Ratings are relative
(Low / Medium / High); no dollar or effort figures exist for either design.

## Implementation cost

| Cost factor | CRAFT | orthrus | Lower cost |
|---|---|---|---|
| AD / PKI setup | **High** (modes 1–2): Mode 1 needs AD CS, CES, a dedicated template and enrollment-agent restrictions; Mode 2 needs a 2016+ KDC with Key Trust and attribute-write delegation; both need a KDC PKINIT certificate. Mode 3: none. | **Low:** one service account with an SPN, protocol transition and an allow-list | orthrus |
| Linux build and packaging | **Medium–High:** C++20, GCC 13+, OpenSSL 3, libcurl, libxml2, OpenLDAP, SASL, PKINIT plugin; a setuid binary to package carefully on RHEL 9 | **Low:** Python standard library and MIT krb5 1.19+; nothing to compile | orthrus |
| Per-node footprint | **High** for modes 1–2 under Slurm: fresh logins happen where jobs run, so the setuid launcher, service keytab and DC access are needed on compute nodes; trust anchors and current CRLs on every host | **Low:** one login node holds the keytab; compute nodes only read the cache from the shared home | orthrus |
| Slurm / HPC integration | **High:** no Slurm hook, no queued-job coverage; `craft-maintain` runs inside each job, so integration would have to be built | **Low:** already built (login-node daemon watching `squeue`, TaskProlog, multi-node via shared home) | orthrus |
| Ongoing operations | **Medium–High:** CRL distribution (stale CRL stops logins), template and enrollment-agent upkeep, KDC PKINIT certificate renewal | **Low–Medium:** keytab rotation (unless gMSA), an AD change per new back-end | orthrus |
| Security approval effort (CSCR) | **High** for modes 1–2: enrollment agents and `msDS-KeyCredentialLink` writes are known attack paths; software smart-card-logon certificates in a CAC environment need explicit PKI-team sign-off, hard to fit within a 3-month review | **Medium:** constrained delegation from a root daemon still needs scrutiny, but no PKI policy exceptions | orthrus |
| Coverage of other needs | **Lower overall** if users need SMB, LDAP or web as themselves: one tool covers all | **Higher** in that case: each new back-end is an AD change; full-TGT needs require a second tool | CRAFT |
| Maturity and testing burden | **High:** 23 commits since late Sep 2026; "reference implementation"; no audit or fuzzing | **Medium:** unit and hardening tests; end to end only against an MIT KDC until `tests/verify-ad.sh` passes on real AD | Slight edge to orthrus |

## Cyber security risk

| Risk factor | CRAFT | orthrus | Lower risk |
|---|---|---|---|
| Stolen user cache | **High:** full TGT to everything the user can reach, renewable up to 7 days | **Low:** listed back-ends only, about 10 hours, not renewable | orthrus |
| Compromised service credential | **Critical:** Mode 1 issues smart-card-logon certificates for anyone in the approved group; Mode 2 takes over any account in the delegated OU; either is full login as those users | **High:** tickets to the listed services as any delegable user; no TGT | orthrus |
| Credentials at rest | Mode 3: **unencrypted private key in the home directory** (NFS-visible on HPC); Mode 2: key left in AD if cleanup fails | One keytab on the login node; caches in the shared home | orthrus (but see NFS exposure below) |
| Privileged attack surface | setuid launcher plus a service account holding the agent key or a directory-write keytab, potentially on every compute node | Root daemon (4 capabilities) plus broker keytab, on one login node | orthrus |
| Reliance on known attacker techniques | Enrollment-agent abuse (AD CS "ESC3" pattern) and "shadow credentials" (`msDS-KeyCredentialLink`); legitimate use becomes noise defenders must filter | S4U constrained delegation, bounded by an AD-enforced allow-list; consistent with Microsoft Guardian forbidding only unrestricted delegation | orthrus |
| Fit with CAC assurance | **Weak:** CRAFT's notes say a software smart-card-logon key is not evidence of hardware custody or a second factor | **Neutral:** users still authenticate with CAC; the broker acts afterwards | orthrus |
| Availability dependencies | Stale CRL or expired KDC PKINIT certificate blocks all logins | Login-node outage or keytab expiry stops new tickets; existing caches last about 10 hours | orthrus |
| Validation of what AD returns | **Strong:** principal, flags, encryption and actual lifetime; refuses shortened grants | **Good, newer:** since 2.3.0, right user, every service, no TGT, AES session key; AD name form still to confirm | CRAFT |
| Audit trail | **Strong per user:** CA issuance (mode 1) or directory write (mode 2) per login | DC delegation events, all from one broker account; needs correlation to users | CRAFT |
| Emergency stop | `enabled=no` or remove execute permission | `/etc/krb-hpc/disabled`, immediate, no restart | Even |

**Tally:** orthrus is lower cost on 7 of 8 factors and lower risk on 7 of 10.
CRAFT is stronger on return-value validation, per-user audit, and serving users
who truly need a full TGT.

## Potato assessment (hostile critic)

### Three failure modes

1. **The broker keytab becomes the single point of compromise.** Root on the
   login node, or a leaked keytab, lets an attacker mint Hive, HDFS and lakeFS
   tickets as any delegable user. Concentrated risk is easier to defend, but
   catastrophic if lost.
   *Early signal:* S4U requests from an unexpected host or outside the daemon's
   normal cadence.
   *Mitigation:* move to a gMSA; mark privileged accounts "sensitive and cannot
   be delegated" or add them to Protected Users; treat the login node as
   tier-0-adjacent with tight admin access and dedicated monitoring.
2. **Allow-list creep.** Every target added to `delegate_targets` widens what a
   stolen cache or compromised broker reaches, until the smaller-blast-radius
   argument quietly stops being true.
   *Early signal:* frequent AD change requests to add SPNs.
   *Mitigation:* require a CSCR addendum per new target and an annual review of
   the full list.
3. **The shared home undoes the cache protections.** Per-home `0700` is the
   control; on NFSv3 or `sec=sys`, root on any node can read any user's cache.
   *Early signal:* the home export lacks `root_squash`, or uses `sec=sys`
   across many nodes.
   *Mitigation:* NFSv4 with `sec=krb5p` where feasible, enforce `root_squash`,
   audit node root access. Otherwise one compromised compute node exposes every
   running user's tickets for up to 10 hours (see README "Residual risks" and
   `ARCHITECTURE.md` §8).

### Two unproven assumptions

1. **That AD behaves like the MIT test KDC.** S4U2Self/S4U2Proxy behaviour, the
   principal name form AD puts in tickets, encryption types (RC4 fallback) and
   the 2.3.0 cache checks are untested on real AD.
   *Test:* run `tests/verify-ad.sh` in the AD test lab and make its PASS a
   go/no-go gate before the pilot.
2. **That users do not need a full TGT.** The cost advantage holds only if HPC
   users need nothing beyond the listed back-ends. If SMB shares, LDAP or
   Kerberized web apps as themselves appear after rollout, a second tool
   (possibly CRAFT) is needed and both costs are paid.
   *Test:* survey workflows and job scripts for Kerberos use outside Hive, HDFS
   and lakeFS before the CSCR is finalized.

### One counter-argument

> "orthrus is custom code with an all-powerful broker and a very small team
> behind it. CRAFT uses PKINIT, the standard Microsoft-supported way to obtain
> a TGT, and the enterprise already runs PKI for CAC, so the PKI cost is partly
> sunk. Sustaining a bespoke delegation daemon is the bigger long-term risk."

This has force on sustainment: a bespoke privileged daemon with few
maintainers is a real risk, and CRAFT's per-user audit is better. However, CAC
certificates come from the DoD PKI, not the organization's AD CS, so CRAFT
modes 1–2 still need *new* AD-side PKI or directory-write delegation, which is
exactly where the attack-path and approval costs sit. CRAFT also lacks Slurm
integration, so custom code is needed either way.

**Compromise:** keep orthrus for HPC jobs and fund sustainment from the start
(documentation, a second maintainer, gMSA, real-AD acceptance testing);
revisit CRAFT mode 2 only if a confirmed full-TGT need emerges.

## Sources

- [`craft-vs-orthrus-comparison.docx`](craft-vs-orthrus-comparison.docx)
  (CRAFT README, `source/SECURITY.md`, delegation guides at commit 38e4c6e;
  this repository at v2.2.0/2.3.0)
- [`../SECURITY.md`](../SECURITY.md), [`../ARCHITECTURE.md`](../ARCHITECTURE.md),
  [`../README.md`](../README.md), [`../CHANGELOG.md`](../CHANGELOG.md)
