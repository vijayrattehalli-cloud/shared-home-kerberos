# Architecture — Shared-Home Kerberos for a CAC / UID-GID HPC Cluster

> Detailed design document. For a quickstart and deployment checklist, see
> [`README.md`](README.md); for the Active Directory side see
> [`AD-SETUP.md`](AD-SETUP.md) and for the threat model
> [`SECURITY.md`](SECURITY.md). This document covers the problem, the design and
> its rationale, component internals, the on-disk ticket format, sequence flows,
> and an operations runbook.

---

## 1. Problem statement

An HPC cluster must let users reach **Kerberized services** (Hive, HDFS, and
similar) from login nodes and from **every compute node of a Slurm job**, under
these conditions:

1. Users authenticate to the HPC with a **CAC** (smartcard), read on a Windows
   PC against Active Directory. The CAC **cannot** be used through GSSAPI/PKINIT
   on the HPC to obtain a Kerberos TGT.
2. **GSSAPI credential forwarding over SSH is blocked**, so the TGT the CAC
   produced on the Windows PC cannot be delegated into the login node either.
3. The HPC scheduler and nodes know users only by **POSIX UID/GID**; they have
   no native Kerberos knowledge.
4. The Kerberized services are homed in **Active Directory** (one realm), and
   AD policy **forbids unconstrained delegation** but **permits constrained
   delegation** (S4U).
5. Jobs are **multi-day / long-queued**, so credentials must refresh
   **unattended** — with no human and no card present.

The design question is twofold: **(a)** how is a credential obtained at all,
given the CAC limitation and the forwarding block, and **(b)** how does it
become usable on every node of a job. This document answers both with the
**shared-home + constrained-delegation** approach.

---

## 2. Core design decision

Two independent decisions define the architecture.

### 2.1 Issuance: one broker account + constrained delegation (not per-user keytabs)

Because the CAC cannot obtain a TGT on the HPC and forwarding is blocked, a
privileged daemon (**`krb-credd`**) authenticates to AD and obtains each user's
credentials on their behalf. The naïve way to do that is an escrowed **per-user
keytab** — but a keytab is a long-term, exportable, copyable key, which is
exactly the property CAC/PIV exists to eliminate, and it means **N standing
secrets** to escrow, rotate, protect, and revoke. That weakens the reason for
using CAC in the first place.

Instead, the daemon holds **one** credential — a single **broker service
account** — and uses **Kerberos constrained delegation** to impersonate each
enrolled user:

1. **Broker TGT** — `kinit` the broker's own forwardable, renewable TGT from its
   one keytab. This is the **unattended-renewal engine**: it re-`kinit`s forever
   with no human, which is what makes multi-day jobs possible.
2. **S4U2Self + S4U2Proxy** — using that broker TGT, request **service tickets**
   to the allow-listed backends *on behalf of the user's real AD identity*
   (`kvno -U <user> -P <spn>…`). Protocol transition (S4U2Self) is the formal
   mechanism for "I authenticated this user by a non-Kerberos means (CAC at the
   PC); now mint Kerberos tickets to the backends."
3. **Install** — write the resulting cache into the user's shared home.

This is the enterprise-standard pattern for a non-Kerberos front end that needs
Kerberos to backends, and it collapses N keytabs into **one** broker credential
scoped — by AD's `msDS-AllowedToDelegateTo` — to exactly the enumerated service
SPNs and nothing else.

**Consequence: no general-purpose TGT.** The user's cache holds **service
tickets to the enumerated backends only** — not a TGT. There is no approved way
to perform Kerberos initial authentication *as the user* on the HPC (that was
requirement (a)), so the design deliberately issues no TGT; S4U is least
privilege by construction. Every Kerberized backend a job touches must be listed
in `delegate_targets` **and** in the broker account's `msDS-AllowedToDelegateTo`.

**The users are impersonated by their real AD identity** (`jdoe@REALM`), so
there are no `hpc-<user>` shadow accounts and `auth_to_local` needs no prefix
rewriting. Those accounts must be **delegation-eligible** — not in Protected
Users, not flagged "sensitive — cannot be delegated" — or S4U2Proxy to them
fails. See [`AD-SETUP.md`](AD-SETUP.md).

### 2.2 Propagation: the shared filesystem *is* the transport

Every production HPC cluster mounts user **home directories on a shared
filesystem** (NFS / GPFS / Lustre) visible on every node. The design exploits
this directly: the daemon writes the ticket cache to `$HOME/.krb5/krb5cc_hpc`,
and because that path resolves identically on every node, the tickets are
**already present everywhere**. "Forwarding to the job's nodes" collapses to a
one-line Slurm `TaskProlog` that sets `KRB5CCNAME` to that path.

Consequence: there is **no SPANK plugin, no KCM, no node-side daemon, and no
ticket-copy step**. The entire compute-fabric surface of the design is a shared
mount plus an environment variable. This is the design's defining property —
maximum simplicity — and its defining trade-off (§8).

---

## 3. Components

```
 login/broker tier                         shared filesystem            compute fabric
 ┌─────────────────────────┐               ┌───────────────────┐        ┌──────────────┐
 │ krb-credd (root, Python)│── writes as ─▶ │ $HOME/.krb5/      │ ◀─mnt─ │ cn001..cnNNN │
 │  ├ broker TGT (1 keytab)│   the user     │   krb5cc_hpc      │        │ TaskProlog   │
 │  ├ UidMap (uidmap)      │   (setpriv)    │  (0700 dir,       │        │  sets        │
 │  ├ TicketManager        │                │   0600 file)      │        │  KRB5CCNAME  │
 │  │   mint(S4U)/install  │                └───────────────────┘        └──────────────┘
 │  ├ Krb5 (kinit/kvno)    │                         ▲
 │  └ UNIX socket (GET)    │                         │ every task reads the same file
 │ krb-get (user cmd)      │                         ▼
 └─────────────────────────┘                Hive / HDFS (AD-homed services)
       │  S4U2Self + S4U2Proxy
       ▼
   Active Directory KDC  (authorizes delegation via msDS-AllowedToDelegateTo)
```

| Component | Runs as | Responsibility |
|---|---|---|
| `krb-credd` (`src/krbhpc/credd.py`) | root, on login/broker nodes | keep the broker TGT fresh; mint, re-mint, and install each user's service tickets |
| `krb-get` (`src/krbhpc/get.py`) | the user | ask the daemon (over its UNIX socket) to refresh now; print the `KRB5CCNAME` export |
| `krb-install-ccache` (`bin/`) | **the user** (via `setpriv`) | atomically write the ticket bytes into `$HOME` with correct ownership/mode |
| `TaskProlog` (`slurm/`) | the user, per task | export `KRB5CCNAME` pointing at the home cache |
| Hive client (`src/krbhpc/hive_client.py`) | the user, in the job | authenticate to Hive from the FILE ccache via Python GSSAPI (impyla) |

### 3.1 `krb-credd` internals (by module)

- **`credd.py`** — process entry point and request handling. A
  `socketserver.ThreadingMixIn` UNIX-domain server reads the peer's
  kernel-verified identity with `getsockopt(SO_PEERCRED)`; a background thread
  runs the periodic refresh pass. Standard library only; no third-party deps.
- **`credd.TicketManager`** — the credential lifecycle:
  - *broker TGT* (`_ensure_broker`) — `kinit -f -r <renew> -l <life> -k -t
    <broker_keytab> <broker_principal>`; renews with `kinit -R` while possible,
    re-`kinit`s from the keytab past the renew limit. One credential, refreshed
    unattended; everything else rides on it.
  - *mint* (`_mint`) — constrained delegation: `kvno -c FILE:<broker_cc>
    --out-cache FILE:<tmp> -U <user> -P <spn>…` performs S4U2Self then S4U2Proxy
    and writes the user's **service tickets** (no TGT) to a native MIT FILE
    cache. Atomic temp-file + `os.replace`.
  - *install* (`_install`) — hand the ccache bytes to `krb-install-ccache` under
    `setpriv --reuid=<uid> --regid=<gid> --init-groups --inh-caps=-all
    --bounding-set=-all --no-new-privs`, so the write happens with the user's
    identity (root-squash-safe), with all capabilities dropped.
- **`credd.UidMap`** — the `uidmap.conf` (UID/username → **real AD principal**)
  map, re-read on mtime change (enrollment needs no restart). Refuses to load
  the file unless it is root-owned and not group/world writable.
- **`_krb.py`** — `duration_seconds`, `klist` parsing (`parse_klist` for the
  broker TGT, `earliest_expiry` for a service-ticket cache), and thin
  `kinit`/`klist`/`kvno` wrappers that scrub injection-vector env vars and pin
  `KRB5_CONFIG` and `LC_ALL=C`. Pure functions are unit-tested in
  `tests/test_krb_helpers.py`.
- **`get.py` / `install_ccache.py`** — the `krb-get` client and the
  self-contained install helper (the helper imports nothing beyond the stdlib,
  because the daemon runs it from a libexec path far from the package).

### 3.2 Freshness: why tickets never expire mid-job

`krb-credd` keeps tickets fresh for any user who is **active**, defined as:
(1) they ran `krb-get` within `active_window`, **or** (2) they have a pending or
running Slurm job (the daemon runs `squeue` each refresh cycle). Service tickets
cannot be renewed, so the daemon **re-mints** them (a fresh S4U call) within
`renew_margin` of the earliest expiry; the broker's own TGT is what renews /
re-acquires unattended from the keytab. A job that waits days in the queue, or
runs for days, therefore still finds valid tickets in `$HOME`.

---

## 4. Sequence flows

### 4.1 Interactive login

```
user ── CAC ──▶ sshd/PAM (login01)         [OS login; UID established]
  login shell sources /etc/profile.d/krb-hpc.sh
    └▶ krb-get ──unix socket(GET)──▶ krb-credd
                                      UidMap.principal(uid) → jdoe
                                      TicketManager.ensure():
                                        _ensure_broker(): broker TGT fresh (kinit -k / -R)
                                        _mint(): kvno -U jdoe -P hive/… hdfs/…  → native FILE cache
                                        setpriv(uid) krb-install-ccache → $HOME/.krb5/krb5cc_hpc
    ◀── "export KRB5CCNAME=FILE:$HOME/.krb5/krb5cc_hpc"
  shell now has service tickets to the enumerated backends
```

### 4.2 Slurm job across N nodes

```
sbatch job.sh
  (krb-credd already keeps the in-home cache fresh because squeue shows the job)
  for each allocated node cn001..cnNNN:
    slurmd starts the task as the user
      TaskProlog: test -s $HOME/.krb5/krb5cc_hpc → echo export KRB5CCNAME=FILE:$HOME/.krb5/krb5cc_hpc
    task runs → reads KRB5CCNAME → uses the hive/_HOST@REALM service ticket → query
```

No step copies or forwards the ticket; every node reads the same file.

### 4.2.1 How the Slurm job gets its credentials

A common misconception: the job does **not** obtain a TGT. There is no `kinit`,
no PKINIT, and no Kerberos initial authentication inside the job — and in this
design there is **no user TGT at all**. The job *inherits* a cache of **service
tickets** that `krb-credd` minted earlier, out-of-band, by constrained
delegation.

**Who obtains them, and how.** `krb-credd` (root, login/broker tier) keeps one
broker TGT alive from one keytab, and mints each user's service tickets with
S4U — this is the only place credentials are produced:

```
# once, kept fresh unattended:
kinit -f -r 7d -l 10h -k -t /etc/krb-hpc/broker.keytab \
      -c FILE:<broker_cc> hpc-broker/hpc-mgmt.corp.example.mil      # _ensure_broker

# per user, on demand and before expiry:
kvno -c FILE:<broker_cc> --out-cache FILE:<master> -U jdoe \
     -P hive/hiveserver2.corp.example.mil@REALM \
        hdfs/namenode.corp.example.mil@REALM                        # _mint (S4U2Self+S4U2Proxy)
```

`kvno` writes a native FILE ccache of service tickets, which the daemon installs
into the user's shared home as the user (`setpriv` → `krb-install-ccache`):
`$HOME/.krb5/krb5cc_hpc`.

**Two independent triggers** ensure the cache exists by the time the job runs,
whether or not the user is at a shell:

1. **Interactive login** — `/etc/profile.d/krb-hpc.sh` runs `krb-get`.
2. **The daemon's Slurm watch** — each refresh cycle `krb-credd` runs
   `squeue -h -a -t PD,CF,R,CG -o %U` (`TicketManager._slurm_uids`) and calls
   `ensure(uid)` for **every user with a pending/configuring/running/completing
   job**, minting for anyone whose cache is missing or near expiry.

Trigger (2) is what answers "how does the job get its credentials": the moment
the job appears in the queue, the daemon sees the UID and mints via S4U — so
even a job submitted non-interactively (cron, a script, no login) gets tickets,
provided the user is enrolled.

**The only job-time step** is the TaskProlog pointing the task at that existing
cache (it runs as the user, before each task, on every node):

```bash
cc="${HOME}/.krb5/krb5cc_hpc"
[[ -s "$cc" ]] && echo "export KRB5CCNAME=FILE:${cc}"     # Slurm injects this into the task env
```

**During the job**, the same `squeue` watch keeps the in-home cache re-minted
before expiry, so it never goes stale mid-run. The job then simply *uses* the
service tickets already in the cache (GSSAPI reads `KRB5CCNAME` and finds the
`hive/_HOST@REALM` ticket without needing a TGT).

> In one line: the job's credentials are minted before and outside the job by
> `krb-credd`'s constrained-delegation `kvno` — on one broker TGT, triggered by
> login or by the job appearing in `squeue` — deposited in shared home, and
> merely pointed-to by the TaskProlog. The job performs no Kerberos
> authentication itself and never holds a TGT.

### 4.3 Hive on the client (Python)

```
krbhpc.hive_client:
  impala.dbapi.connect(host, port, auth_mechanism="GSSAPI",
                       kerberos_service_name="hive", use_ssl=True)
  # GSSAPI reads KRB5CCNAME (FILE:$HOME/.krb5/krb5cc_hpc) and finds the cached
  # hive/_HOST service ticket directly -- no TGT needed when the service ticket
  # is already present. The requested service name MUST match the SPN of the
  # minted ticket (watch host canonicalization).
  cur.execute(sql)
```

There is **no Security Manager, no `Subject.callAs`, and no Hive driver shim**.
The only client dependency is `pip install 'impyla[kerberos]'`.

---

## 5. On-disk ticket format (written by `kinit`/`kvno`)

The daemon does **not** serialize ccaches itself — the MIT tools write the
standard credential cache. This section documents the format for reference. It
is an MIT credential cache, **version `0x0504`**, big-endian:

```
uint16  file format version      = 0x0504
uint16  header length            = 12
  uint16 tag = 1 (DeltaTime), uint16 len = 8, uint32 time_offset=0, uint32 usec_offset=0
principal  default principal     (name-type, component count, realm, components…)
credential (one per ticket; here one per delegated SERVICE, no krbtgt):
  principal  client               (the real user, e.g. jdoe@REALM)
  principal  server               (e.g. hive/hs2.corp@REALM)
  keyblock   session key          (uint16 enctype, uint32 len, bytes)
  uint32 x4  authtime, starttime, endtime, renew_till  (epoch seconds)
  uint8      is_skey = 0
  uint32     ticket_flags         (RFC 4120 bit n stored as 1<<(31-n))
  uint32     num_addresses = 0 (or list)
  uint32     num_authdata        (S4U tickets carry a PAC in authdata)
  count+ bytes  ticket            (ASN.1 DER)
  countA+ bytes second_ticket = empty
```

The result is readable by MIT/Heimdal `klist`/`kvno`, python-gssapi, impyla, and
other GSSAPI consumers. *Verified in the tests: the daemon-installed cache is
accepted by a real service over GSSAPI, and by `klist`/`kvno`.*

---

## 6. Configuration surface

| File | Key settings |
|---|---|
| `config/credd.conf` | `[broker]` INI: `realm`, `broker_principal`, `broker_keytab`, `broker_ccache`, `delegate_targets` (backend SPNs = the S4U allow-list), `state_dir`, `map_file`, `unix_socket`, `ccache_path={home}/.krb5/krb5cc_hpc`, `install_helper`, `setpriv`, `broker_lifetime`, `broker_renew`, `renew_margin`, `min_reissue_interval`, `refresh_interval`, `active_window`, `watch_slurm`, `squeue` |
| `config/krb5.conf` | single AD realm, AES-only enctypes, `udp_preference_limit=1` (TCP for PAC-laden tickets), `default_ccache_name=FILE:`, `auth_to_local = DEFAULT` (real user names) |
| `config/uidmap.conf` | `<username|uid>  <real AD user principal>`; root-owned, 0644 |
| `config/profile.d-krb-hpc.sh` | runs `krb-get` at login |
| `systemd/krb-credd.service` | runs `krb-credd`, sandboxed; `ReadWritePaths` includes the home roots; capped `CapabilityBoundingSet` (see [`SECURITY.md`](SECURITY.md) §4) |

---

## 7. Active Directory requirements

Full steps in [`AD-SETUP.md`](AD-SETUP.md). In brief:

- **One broker service account** (e.g. `hpc-broker/<mgmt-host>`), AES256, with a
  single keytab escrowed `root:0600` on the broker (ideally HSM- or gMSA-backed).
- The broker is configured for **constrained delegation with protocol
  transition**: `TrustedToAuthForDelegation` set, and `msDS-AllowedToDelegateTo`
  listing exactly the backend SPNs (`hive/…`, `hdfs/…`) — these must match
  `delegate_targets`.
- **Each real HPC user account** must be **delegation-eligible**: AES-enabled,
  **not** in Protected Users, **not** flagged "sensitive — cannot be delegated".
- Backend service SPNs registered on AES-enabled service accounts; those service
  keytabs live on the service hosts, never on the HPC node.
- Realm: PAC-hardening updates (KB5008380 / CVE-2021-42287) in enforcement mode;
  RC4/DES disabled.

---

## 8. Threat model and the central trade-off

Full treatment in [`SECURITY.md`](SECURITY.md). The two headline points:

### 8.1 Concentrated credential risk (the broker keytab)

Collapsing N per-user keytabs into one broker credential is a large reduction in
credential-management surface — one secret to rotate and audit instead of N —
but it **concentrates** risk: whoever holds the broker keytab can, via protocol
transition, mint tickets to the allow-listed backends as **any delegation-
eligible user, without proof of that user**. Mitigations: back the key with an
**HSM or gMSA** (no static key on disk), keep `msDS-AllowedToDelegateTo` /
`delegate_targets` as tight as possible, monitor the broker account's usage
(its pattern is highly predictable), and rely on each backend's own
authorization (Ranger) as a second gate. The daemon enforces `root:0600` on the
keytab and refuses to start otherwise.

### 8.2 The ticket on shared storage

The cache lives in `$HOME` on a shared filesystem, so it is readable by anyone
who can act as that UID on that filesystem — including **root on an NFS
`sec=sys` client**. This is the price of the design's simplicity. Mitigations,
in order: **Kerberized NFS (`sec=krb5p`)** for home; mount home only on managed
nodes with **`root_squash`**; keep service-ticket lifetimes short (the daemon
re-mints anyway); `0700` dir / `0600` file (enforced by the install helper).
Note the exposure is **smaller** than with a TGT: a stolen cache yields only
service tickets to the enumerated backends, not a TGT usable anywhere.

### 8.3 Revocation

Remove the UID→account mapping (stops minting and refresh, since the map is
re-read on change) and shred the in-home copy as the user; outstanding service
tickets expire within their lifetime. To cut a user off hard, remove their
account from the backends' authorization and/or disable the AD account.
Revoking **everyone** is one action: rotate or disable the broker account.

---

## 9. Failure modes and behavior

| Condition | Behavior |
|---|---|
| User not enrolled (`uidmap` miss) | `krb-get` returns an error; nothing written |
| User account not delegation-eligible (Protected Users / sensitive) | S4U2Proxy fails at the KDC; logged; no cache written for that user |
| Backend SPN not in `msDS-AllowedToDelegateTo` | S4U2Proxy returns "constrained delegation failed"; logged |
| Broker keytab missing / not root:0600 | daemon refuses to start (fail-closed) |
| Broker TGT expired, KDC reachable | re-`kinit` from the keytab on next mint/refresh |
| Service ticket near expiry | re-minted via a fresh S4U call |
| Home filesystem unmounted on a node | TaskProlog finds no cache; task runs without one (fails at the service, not silently) |
| Daemon down | existing in-home caches keep working until expiry; no new minting |
| `uidmap.conf` group/world writable | daemon refuses to load it |
| Clock skew vs AD | `kinit`/`kvno` fail on time bounds; keep NTP in sync |

---

## 10. Operations runbook

- **Enroll:** add the user to `uidmap.conf` (real AD principal); confirm the
  account is delegation-eligible; ensure the backends they need are in
  `delegate_targets` and `msDS-AllowedToDelegateTo`. No daemon restart needed.
- **Add a backend:** add its SPN to both `delegate_targets` and the broker's
  `msDS-AllowedToDelegateTo`; restart the daemon to pick up the config.
- **Verify propagation:** `srun -N4 bash -c 'klist -s && echo $(hostname) ok'`.
- **Rotate the broker key:** re-export the keytab (`+rndPass`), replace it
  `root:0600`, restart the daemon. Prefer gMSA so AD auto-rotates.
- **Health:** the daemon logs each broker (re)acquire, mint, and install; alert
  on repeated mint failures (delegation/AD problem) and on `uidmap` load refusals.
- **Upgrade Python:** stdlib only; a Python bump needs no rebuild — just restart.

---

## 11. What is tested, and what is not

`tests/verify-shared-home.sh` runs the **real Python daemon** against an MIT KDC
standing in for AD (`tests/verify-shared-home.output.txt`):

- **Section 1** — the daemon obtains the **broker TGT from one keytab** (the
  unattended-renewal engine) and issues a well-formed **S4U2Self+S4U2Proxy**
  request.
- **Section 2** — install-as-user into shared home (0600, owned by the user), a
  cache of **service tickets with no TGT**, all four simulated compute nodes
  reading the one file, service accept + `auth_to_local → jdoe`, and the
  re-mint/refresh path.

**Known test-harness limitation:** the S4U2Proxy *authorization* list
(`msDS-AllowedToDelegateTo`) can only be stored by **Active Directory** or an
LDAP-backed MIT KDC. The file/DB2 KDC used in the test **cannot** store it, so
the proxy leg returns "constrained delegation failed". Section 1 asserts exactly
that — proving the broker auth and the S4U request are correct and that only the
AD-side allow-list is absent — and Section 2 drives the propagation path with an
equivalent real-user service-ticket cache. On real AD the daemon's mint produces
that cache and the two sections join into one unbroken path. **Not exercised
here:** real AD delegation authorization, a real shared filesystem with
`root_squash`/`sec=krb5p`, real Slurm, and a live HiveServer2 — all
site-integration points to confirm in a lab.
