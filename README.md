# shared-home-kerberos (Python)

Kerberos for a **CAC-authenticated, UID/GID HPC cluster** — pure Python.

Users log in to the HPC with a **CAC** (which can't obtain a Kerberos TGT on the
HPC), GSSAPI credential forwarding over SSH is blocked, and the cluster knows
users only by POSIX UID/GID. This package gives their jobs working **Active
Directory Kerberos credentials** on login nodes and on **every compute node of a
Slurm job**, including **Hive** access — with the fewest moving parts, and
**without a standing secret per user**.

> **The idea in one line:** **`krb-credd` — a Kerberos client broker (root)** —
> holds **one** broker service-account keytab and uses **Kerberos constrained
> delegation (S4U2Self + S4U2Proxy)** to mint each user's backend **service
> tickets**, writing them into the user's home directory on the **shared
> filesystem** — so every compute node already sees them. A one-line Slurm
> TaskProlog points `KRB5CCNAME` at the cache. No SPANK plugin, no KCM, no
> node-side daemon, and no per-user keytabs.

`krb-credd` is a **client** of Active Directory — it runs **no KDC or realm of
its own**. AD is the single KDC; the daemon authenticates with one service keytab
and calls S4U as an ordinary MIT krb5 client. (It is deliberately **not** NVIDIA
Sybil, which forges tickets from the KDC database and must run on an MIT/FreeIPA
KDC — see [`ARCHITECTURE.md`](ARCHITECTURE.md) §2.1.1.)

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full design,
[`AD-SETUP.md`](AD-SETUP.md) for the Active Directory side (broker account,
constrained delegation, enrollment), and [`SECURITY.md`](SECURITY.md) for the
threat model and hardening. Two diagrams:
[`docs/krb-credd-system-architecture.svg`](docs/krb-credd-system-architecture.svg)
is the end-to-end system (login → krb-credd → AD → shared-home → compute →
backends, with the numbered flow), and
[`docs/krb-credd-architecture.svg`](docs/krb-credd-architecture.svg) is the
cross-boundary view (the broker as an MIT krb5 **client** in the Linux boundary,
AD's KDC in the Windows boundary, S4U over TCP 88 across the realm edge).

## Why constrained delegation (not per-user keytabs)

A keytab is a long-term, exportable key — the opposite of what CAC/PIV gives you
— and one per user is a large credential-management and attack surface. Since AD
permits constrained delegation, the daemon instead authenticates **once** as a
single broker account and impersonates each user's **real** AD identity via S4U.

| | Per-user keytabs | **This (broker + S4U)** |
|---|---|---|
| Standing secrets | one keytab **per user** | **one** broker keytab (gMSA/HSM-backable) |
| Credential ↔ CAC | fully decoupled, copyable | one controlled account, scoped by AD allow-list |
| What the user gets | a general-purpose TGT | **service tickets to enumerated backends only** (least privilege) |
| Revoke everyone | rotate N keytabs | rotate/disable **one** account |
| Identity to backends | `hpc-<user>` shadow acct + `auth_to_local` | the user's **real** identity (`jdoe@REALM`) |

## Components

```
login/broker tier                         shared filesystem        compute fabric
  krb-credd (root)
    ├ broker TGT ── kinit (1 keytab) ──▶ AD KDC
    └ per user: S4U2Self + S4U2Proxy ──▶ AD KDC  (msDS-AllowedToDelegateTo)
        writes as the user (setpriv)      $HOME/.krb5/krb5cc_hpc ◀─mnt─ cn001..cnNNN
                                          (0700 dir, 0600 file)        TaskProlog sets
  krb-get (user cmd)  ─ eval $(krb-get)                               KRB5CCNAME
                                               ▲ every task reads the same file
                                               ▼
                                        Hive / HDFS (AD-homed)
```

| Path | What it is |
|---|---|
| `src/krbhpc/credd.py` | the daemon: keep the broker TGT fresh; mint/re-mint per-user service tickets by S4U; install into `$HOME`; UNIX socket with `SO_PEERCRED`; `squeue`-watch refresh |
| `src/krbhpc/get.py` | `krb-get` — ask the daemon to refresh now, print the `KRB5CCNAME` export |
| `bin/krb-install-ccache` | self-contained helper run **as the user** via `setpriv` (root-squash-safe, atomic) |
| `src/krbhpc/hive_client.py` | Hive over Kerberos in Python (impyla/GSSAPI) — no JDK, no shim |
| `src/krbhpc/_krb.py` | durations, `klist` parsing (UTC), error classification, MIT version check, and kinit/klist/**kvno (S4U)** wrappers run by absolute path |
| `slurm/taskprolog.krb.sh` | the one line that exports `KRB5CCNAME` on every node |
| `config/` | `credd.conf`, `krb5.conf`, `uidmap.conf`, `profile.d` hook |
| `systemd/krb-credd.service` | run the daemon (sandboxed) |
| `tests/` | `verify-shared-home.sh` (end-to-end, full S4U path) + `test_krb_helpers.py` + `test_daemon.py` + `test_hardening.py` (unit) |

## Install

```bash
pip install .                 # console scripts: krb-credd, krb-get, krb-install-ccache
pip install '.[hive]'         # + impyla for the Python Hive client
# or run straight from the repo without installing:
bin/krb-credd -c /etc/krb-hpc/credd.conf
```

Runtime system deps: `python3 >= 3.9`, MIT krb5 **1.19 or newer** client tools
(`kinit`, `klist`, `kvno` — 1.19 added `kvno --out-cache`; the daemon checks at
start-up), `setpriv` (util-linux), and the Slurm client (`squeue`) when
`watch_slurm` is on.

## Quickstart

```bash
# 1. deploy config (edit realm/KDC/broker/targets first)
install -D config/krb5.conf       /etc/krb5.conf
install -D config/credd.conf      /etc/krb-hpc/credd.conf
install -D config/uidmap.conf     /etc/krb-hpc/uidmap.conf
install -D bin/krb-install-ccache /usr/local/libexec/krb-hpc/krb-install-ccache
# broker keytab (root:0600) -> /etc/krb-hpc/broker.keytab   (see AD-SETUP.md)

# 2. AD side (once): create the broker account, set msDS-AllowedToDelegateTo +
#    TrustedToAuthForDelegation, escrow its keytab. See AD-SETUP.md.

# 3. enroll a user: add 'jdoe jdoe' to uidmap.conf (real AD principal), and make
#    sure jdoe is delegation-eligible and the backends are in delegate_targets.
systemctl enable --now krb-credd

# 4. user logs in (profile.d runs krb-get) -> service tickets land in ~/.krb5
eval "$(krb-get)"; klist           # shows hive/_HOST, hdfs/_HOST service tickets

# 5. a job: every node sees the same cache
sbatch hive-jdbc/...               # see hive_client usage in ARCHITECTURE.md §4.3
```

## Test

```bash
python3 tests/test_krb_helpers.py                       # parsing, error classes, tool wrapper (no Kerberos)
python3 tests/test_daemon.py                            # config, refresh backoff, admin scripts
python3 tests/test_hardening.py                         # fail-closed permission checks
sudo MIT_PREFIX=/opt/mitkrb5 KDB_TEST_MODULE_DIR=<krb5-src>/src/plugins/kdb/test \
     tests/verify-shared-home.sh                        # end-to-end (MIT KDC + root)
```

The end-to-end test runs the **real daemon** against a throwaway MIT KDC that
uses MIT's *test* database module, which — unlike the default file database —
can hold a constrained-delegation allow-list (the stand-in for AD's
`msDS-AllowedToDelegateTo`). So the **complete** path runs: broker TGT from one
keytab → S4U2Self → S4U2Proxy → install as the user (0600, service tickets only)
→ four simulated compute nodes → the service accepts the ticket as the real
user → unattended re-mint → atomic broker renewal. It also checks the
refusals and safeguards: MIT older than 1.19, a writable Kerberos tool, an
un-enrolled user, a non-delegable user (refused with a clear message and backed
off in the background), a backend not on the allow-list, and a hostile
`KRB5CCNAME`/`KRB5_TRACE`/`KRB5_CONFIG`/`LC_ALL`/`TZ` environment. Recorded
output: [`tests/verify-shared-home.output.txt`](tests/verify-shared-home.output.txt).

> Distribution packages don't ship MIT's test KDB module (`test.so`); the
> script's header shows how to build MIT krb5 from source to get it.

## Trade-offs

1. **Concentrated broker risk.** One keytab replaces N — smaller and more
   auditable — but its compromise lets an attacker mint tickets to the
   allow-listed backends as any delegation-eligible user. Back it with a
   gMSA/HSM, keep the SPN allow-list minimal, monitor the broker account, and
   rely on backend authorization (Ranger) as a second gate. `SECURITY.md` §5.
2. **The cache on shared storage.** It lives in `$HOME`, so it's readable by
   anyone who can act as that UID on that filesystem (incl. root on NFS
   `sec=sys`). Mitigate with `sec=krb5p` home, `root_squash`, and short
   service-ticket lifetimes. The exposure is smaller than with a TGT — only
   service tickets to the enumerated backends. `ARCHITECTURE.md` §8.

If these are unacceptable, a node-local-KCM design is the alternative; this repo
is the shared-home design only.

## Integrations

- **Hive / HDFS** — the job's cache already holds the `hive/_HOST`, `hdfs/_HOST`
  service tickets; use them over GSSAPI (see `src/krbhpc/hive_client.py`).
- **lakeFS Enterprise over Spark/S3A** — lakeFS has no native Kerberos, so a
  small Kerberos-authenticated **credential broker** trades the job's ticket
  (SPNEGO) for a short-lived lakeFS access key that an S3A credentials provider
  feeds to Spark. Design + config in
  [`docs/lakefs-integration.md`](docs/lakefs-integration.md); diagram in
  [`docs/lakefs-s3a-architecture.svg`](docs/lakefs-s3a-architecture.svg); a
  **runnable reference** (broker + S3A provider + e2e test) in
  [`integrations/lakefs/`](integrations/lakefs/).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
