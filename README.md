# shared-home-kerberos (Python)

Kerberos for a **CAC-authenticated, UID/GID HPC cluster** — pure Python.

Users log in to the HPC with a **CAC** (so the CAC can't obtain a Kerberos TGT
on the HPC), and the cluster knows them only by POSIX UID/GID. This package
gives them working **Active Directory Kerberos tickets** on login nodes and on
**every compute node of a Slurm job**, including **Hive** access — with the
fewest moving parts of any approach.

> **The idea in one line:** a root daemon writes each user's AD TGT into their
> home directory on the **shared filesystem**, so every compute node already
> sees it; a one-line Slurm TaskProlog points `KRB5CCNAME` at it. No SPANK
> plugin, no KCM, no node-side daemon.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full design,
[`AD-SETUP.md`](AD-SETUP.md) for the Active Directory side (enrollment, scoped
`hpc-<user>` accounts, key rotation), and [`SECURITY.md`](SECURITY.md) for the
threat model and hardening.

## Why Python (vs the earlier JDK edition)

The Python implementation is strictly simpler because it sidesteps two things
the Java edition had to work around:

| | Java edition | **This (Python)** |
|---|---|---|
| Write the ccache | hand-written `CCacheWriter` (MIT format via public APIs) | **MIT `kinit` writes it natively** — no serializer |
| Hive on the client | JDK-24 `Subject.callAs` + a one-class driver **shim** (JDK 24 removed the Security Manager) | **GSSAPI from the FILE ccache** via impyla/PyHive — no shim |
| Runtime | a JDK 24 | `python3` + MIT krb5 tools + `setpriv` |

## Components

```
login/broker tier                       shared filesystem        compute fabric
  krb-credd (root) ── kinit keytab ──▶ AD
      writes as the user (setpriv)      $HOME/.krb5/krb5cc_hpc ◀─mnt─ cn001..cnNNN
                                        (0700 dir, 0600 file)        TaskProlog sets
  krb-get (user cmd)  ─ eval $(krb-get)                              KRB5CCNAME
                                               ▲ every task reads the same file
                                               ▼
                                        Hive / HDFS (AD-homed)
```

| Path | What it is |
|---|---|
| `src/krbhpc/credd.py` | the daemon: acquire (`kinit -k`), renew, re-acquire, install into `$HOME`; UNIX socket with `SO_PEERCRED`; `squeue`-watch refresh |
| `src/krbhpc/get.py` | `krb-get` — ask the daemon to refresh your ticket, print the `KRB5CCNAME` export |
| `bin/krb-install-ccache` | self-contained helper run **as the user** via `setpriv` (root-squash-safe, atomic) |
| `src/krbhpc/hive_client.py` | Hive over Kerberos in Python (impyla/GSSAPI) — no JDK, no shim |
| `src/krbhpc/_krb.py` | duration + `klist` parsing + kinit/klist wrappers |
| `slurm/taskprolog.krb.sh` | the one line that exports `KRB5CCNAME` on every node |
| `config/` | `credd.conf`, `krb5.conf`, `uidmap.conf`, `profile.d` hook |
| `admin/` | AD enrollment, monthly key rotation, revoke |
| `systemd/krb-credd.service` | run the daemon |
| `tests/` | `verify-shared-home.sh` (end-to-end) + `test_krb_helpers.py` + `test_hardening.py` (unit) |

## Install

```bash
pip install .                 # console scripts: krb-credd, krb-get, krb-install-ccache
pip install '.[hive]'         # + impyla for the Python Hive client
# or run straight from the repo without installing:
bin/krb-credd -c /etc/krb-hpc/credd.conf
```

Runtime system deps: `python3 >= 3.9`, MIT krb5 client tools (`kinit`, `klist`),
`setpriv` (util-linux), and the Slurm client (`squeue`) when `watch_slurm` is on.

## Quickstart

```bash
# 1. deploy config (edit realm/KDC/accounts first)
install -D config/krb5.conf       /etc/krb5.conf
install -D config/credd.conf      /etc/krb-hpc/credd.conf
install -D config/uidmap.conf     /etc/krb-hpc/uidmap.conf
install -D bin/krb-install-ccache /usr/local/libexec/krb-hpc/krb-install-ccache

# 2. enroll a user (dedicated AD account) and run the daemon
admin/enroll_user.sh jdoe hpc-jdoe
systemctl enable --now krb-credd

# 3. user logs in (profile.d runs krb-get) → ticket lands in ~/.krb5
eval "$(krb-get)"; klist -f          # flags must include F (forwardable) and R

# 4. a job: every node sees the same ticket
sbatch hive-jdbc/...  # see hive_client usage in ARCHITECTURE.md §4
```

## Test

```bash
python3 tests/test_krb_helpers.py                       # unit (no Kerberos needed)
python3 tests/test_hardening.py                         # fail-closed permission checks
JAVA_HOME= sudo -E tests/verify-shared-home.sh          # end-to-end (needs MIT krb5 + root)
```

The end-to-end test stands up a throwaway MIT realm, runs the **real Python
daemon**, and asserts: a forwardable TGT is issued into `$HOME`; all four
simulated compute nodes use that one file; a service accepts it with
`auth_to_local`; and the `squeue`-watch renews it live. Recorded output:
[`tests/verify-shared-home.output.txt`](tests/verify-shared-home.output.txt).

## The one trade-off

The ticket lives in `$HOME` on shared storage, so it is readable by anyone who
can act as that UID on that filesystem — including root on an NFS `sec=sys`
client. Mitigate with Kerberized NFS (`sec=krb5p`) for home, `root_squash` on
managed-only mounts, and a short `renew_lifetime` (the daemon re-acquires
anyway). See `ARCHITECTURE.md` §8. If that exposure is unacceptable, a
node-local-KCM design is the alternative; this repo is the shared-home design
only.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
