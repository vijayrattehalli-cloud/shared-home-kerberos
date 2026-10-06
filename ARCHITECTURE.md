# Architecture — Shared-Home Kerberos for a CAC / UID-GID HPC Cluster

> Detailed design document. For a quickstart and deployment checklist, see
> [`README.md`](README.md). This document covers the problem, the design and its
> rationale, component internals, the on-disk ticket format, sequence flows,
> the threat model, failure modes, and an operations runbook.

---

## 1. Problem statement

An HPC cluster must let users reach **Kerberized services** (Hive, HDFS, and
similar) from login nodes and from **every compute node of a Slurm job**, under
these conditions:

1. Users authenticate to the HPC with a **CAC** (smartcard). The CAC **cannot**
   be used through GSSAPI/PKINIT on the HPC to obtain a Kerberos TGT.
2. The HPC scheduler and nodes know users only by **POSIX UID/GID**; they have
   no native Kerberos knowledge.
3. The Kerberized services are homed in **Active Directory** (one realm).
4. A Slurm job spans many compute nodes; each task must present the user's
   Kerberos credential to the services it reads.

The design question is twofold: **(a)** how is a TGT obtained at all, given the
CAC limitation, and **(b)** how does that one TGT become usable on every node of
a job. This document answers both with the **shared-home** approach.

---

## 2. Core design decision

Two independent decisions define the architecture.

### 2.1 Issuance: a root broker daemon, not the CAC

Because the CAC cannot obtain a TGT on the HPC, a privileged daemon
(**`krb-credd`**) performs the Active Directory login *on the user's behalf*,
using an **escrowed, per-user keytab** for a dedicated AD account
(`hpc-<user>`). The CAC's role is reduced to gating the OS login; the Kerberos
credential is a genuine AD TGT obtained by the daemon through a normal keytab
authentication — an approved initial-authentication path.

Rationale for a dedicated account per user (rather than the person's own
CAC-bound account): CAC accounts are typically *smartcard-required* (SCRIL),
and Active Directory may roll their password autonomously, which would silently
invalidate an escrowed keytab. A dedicated `hpc-<user>` account has a stable,
rotation-controlled key and allows service-side authorization (Ranger/HDFS) to
be scoped to batch identities.

### 2.2 Propagation: the shared filesystem *is* the transport

Every production HPC cluster mounts user **home directories on a shared
filesystem** (NFS / GPFS / Lustre) visible on every node. The design exploits
this directly: the daemon writes the TGT to
`$HOME/.krb5/krb5cc_hpc`, and because that path resolves identically on every
node, the ticket is **already present everywhere**. "Forwarding to the job's
nodes" collapses to a one-line Slurm `TaskProlog` that sets `KRB5CCNAME` to that
path.

Consequence: there is **no SPANK plugin, no KCM, no node-side daemon, and no
ticket-copy step**. The entire compute-fabric surface of the design is a shared
mount plus an environment variable. This is the design's defining property —
maximum simplicity — and its defining trade-off (§8).

---

## 3. Components

```
 login/broker tier                         shared filesystem            compute fabric
 ┌───────────────────────┐                 ┌───────────────────┐        ┌──────────────┐
 │ krb-credd (root, JDK24)│── writes as ──▶ │ $HOME/.krb5/      │ ◀─mnt─ │ cn001..cnNNN │
 │  ├ Accounts (uidmap)   │   the user      │   krb5cc_hpc      │        │ TaskProlog   │
 │  ├ TicketManager       │   (setpriv)     │  (0700 dir,       │        │  sets        │
 │  │   acquire/renew/    │                 │   0600 file)      │        │  KRB5CCNAME  │
 │  │   install           │                 └───────────────────┘        └──────────────┘
 │  ├ CCacheWriter        │                          ▲
 │  └ UNIX socket (GET)   │                          │ every task reads the same file
 │ krb-get (user cmd)     │                          ▼
 └───────────────────────┘                  Hive / HDFS (AD-homed services)
```

| Component | Runs as | Responsibility |
|---|---|---|
| `krb-credd` (`daemon/`) | root, on login/broker nodes | obtain, renew, re-acquire, and install each user's AD TGT into their home |
| `krb-get` (`bin/`) | the user | ask the daemon (over its UNIX socket) to refresh the ticket now; print the `KRB5CCNAME` export |
| `krb-install-ccache` (`bin/`) | **the user** (via `setpriv`) | atomically write the ticket bytes into `$HOME` with correct ownership/mode |
| `TaskProlog` (`slurm/`) | the user, per task | export `KRB5CCNAME` pointing at the home ticket |
| Hive JDBC client + shim (`hive-jdbc/`) | the user, in the job | authenticate to Hive from the FILE ccache on JDK 24 |
| `enroll/rotate/revoke` (`admin/`) | admin | AD account lifecycle and key rotation |

### 3.1 `krb-credd` internals (by source file)

- **`KrbCredd.java`** — process entry point. Opens a UNIX-domain `ServerSocket`
  (`java.net`), reads the peer's kernel-verified identity via
  `jdk.net.ExtendedSocketOptions.SO_PEERCRED`, dispatches each connection on a
  **virtual thread**, and schedules the periodic refresh pass. Runs with **no
  Security Manager** (JEP 486 removed it in JDK 24); nothing here needs it.
- **`TicketManager.java`** — the credential lifecycle:
  - *acquire* — a JAAS `Krb5LoginModule` login using the user's keytab
    (`useKeyTab=true`, `storeKey=false`, `isInitiator=true`), yielding a
    forwardable, renewable `KerberosTicket`.
  - *renew* — `KerberosTicket.refresh()` while inside the renew window;
    re-acquire from the keytab once past `renewTill`.
  - *install* — serialize via `CCacheWriter` and hand the bytes to
    `krb-install-ccache` under `setpriv --reuid=<uid> --regid=<gid>
    --init-groups`, so the write happens with the user's identity.
- **`CCacheWriter.java`** — serializes the `KerberosTicket` to the **MIT FILE
  credential-cache format** (§5) using only public JDK APIs. This avoids
  `--add-exports` into `sun.security.krb5.*`, so the daemon is robust across JDK
  updates.
- **`Accounts.java`** — `getent passwd` lookups and the `uidmap.conf`
  (UID/username → AD principal) map, re-read on mtime change (enrollment needs
  no restart). Enforces that `uidmap.conf` is root-owned and not group/world
  writable.
- **`Config.java` / `Log.java` / `KrbGet.java`** — configuration parsing,
  logging, and the user-facing `krb-get` client.

### 3.2 Freshness: why tickets never expire mid-job

`krb-credd` keeps a ticket fresh for any user who is **active**, defined as:
(1) they ran `krb-get` within `active_window`, **or** (2) they have a pending or
running Slurm job (the daemon runs `squeue` each refresh cycle). It renews
within `renew_margin` of expiry and re-acquires from the keytab once the renew
limit is reached. A job that waits days in the queue, or runs past the 7-day
renew horizon, therefore still finds a valid ticket in `$HOME`.

---

## 4. Sequence flows

### 4.1 Interactive login

```
user ── CAC ──▶ sshd/PAM (login01)         [OS login; UID established]
  login shell sources /etc/profile.d/krb-hpc.sh
    └▶ krb-get ──unix socket(GET)──▶ krb-credd
                                      Accounts.principal(uid) → hpc-jdoe@REALM
                                      TicketManager.ensure():
                                        acquire via keytab (or renew)
                                        CCacheWriter → bytes
                                        setpriv(uid) krb-install-ccache → $HOME/.krb5/krb5cc_hpc
    ◀── "export KRB5CCNAME=FILE:$HOME/.krb5/krb5cc_hpc"
  shell now has a working AD TGT
```

### 4.2 Slurm job across N nodes

```
sbatch job.sh
  (krb-credd already keeps the in-home ticket fresh because squeue shows the job)
  for each allocated node cn001..cnNNN:
    slurmd starts the task as the user
      TaskProlog: test -s $HOME/.krb5/krb5cc_hpc  →  echo export KRB5CCNAME=FILE:$HOME/.krb5/krb5cc_hpc
    task runs → reads KRB5CCNAME → GSSAPI to hive/_HOST@REALM → service ticket (with PAC) → query
```

No step copies or forwards the ticket; every node reads the same file.

### 4.3 Hive JDBC on JDK 24

```
HiveKerberosClient24:
  JAAS login (useTicketCache=true, ticketCache=$KRB5CCNAME, doNotPrompt, renewTGT=false)
  Subject.callAs(subject, () -> DriverManager.getConnection(url))     [JDK 24: not doAs/getSubject]
  driver's TSubjectAssumingTransport → (SHIM) Subject.current()+callAs → SASL/GSSAPI → Hive
```

The one-class shim replaces the driver's `TSubjectAssumingTransport`, whose
stock `Subject.getSubject(AccessControlContext)` call throws
`UnsupportedOperationException` on JDK 24. `build-shim.sh` compiles the shim
against the exact driver jar, so an API mismatch fails at build time; the client
refuses to run unless the shim is the class that loads.

---

## 5. On-disk ticket format (what `CCacheWriter` writes)

The output is an MIT credential cache, **version `0x0504`**, big-endian:

```
uint16  file format version      = 0x0504
uint16  header length            = 12
  uint16 tag = 1 (DeltaTime), uint16 len = 8, uint32 time_offset=0, uint32 usec_offset=0
principal  default principal     (name-type, component count, realm, components…)
credential (one, the TGT):
  principal  client
  principal  server              (krbtgt/REALM@REALM)
  keyblock   session key          (uint16 enctype, uint32 len, bytes)
  uint32 x4  authtime, starttime, endtime, renew_till  (epoch seconds)
  uint8      is_skey = 0
  uint32     ticket_flags         (RFC 4120 bit n stored as 1<<(31-n))
  uint32     num_addresses = 0 (or list)
  uint32     num_authdata = 0
  count+ bytes  ticket            (ASN.1 DER)
  countA+ bytes second_ticket = empty
```

This is the documented MIT `ccache` format; the result is readable by MIT/
Heimdal `klist`/`kvno`, the JDK's own `Krb5LoginModule`, python-gssapi, and
other GSSAPI consumers. Writing it directly (rather than via a private JDK API)
is a deliberate portability choice. *Verified in the tests: MIT tools and the
JDK both consume the daemon-written cache.*

---

## 6. Configuration surface

| File | Key settings |
|---|---|
| `config/credd.properties` | `realm`, `keytab_dir`, `uid_map`, `ccache_path={home}/.krb5/krb5cc_hpc`, `install_helper`, `setpriv`, `ticket_lifetime`, `renew_lifetime`, `renew_margin`, `refresh_interval`, `active_window`, `watch_slurm`, `squeue` |
| `config/krb5.conf` | single AD realm, AES-only enctypes, `udp_preference_limit=1` (TCP for PAC-laden tickets), `default_ccache_name=FILE:` (Java can't read KEYRING/KCM), `auth_to_local` mapping `hpc-<u>`→`<u>` |
| `config/uidmap.conf` | `<username|uid>  <AD sAMAccountName>`; root-owned, 0644 |
| `config/profile.d-krb-hpc.sh` | runs `krb-get` at login |
| `systemd/krb-credd.service` | JDK 24 runtime, `ReadWritePaths` includes the home roots, `CapabilityBoundingSet` = `CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_DAC_READ_SEARCH` |

---

## 7. Active Directory requirements

For each dedicated `hpc-<user>` account (typically in an HPC OU):

- **AES256 enabled** (`msDS-SupportedEncryptionTypes` ⊇ `0x18`); RC4/DES off.
- **"Account is sensitive and cannot be delegated" = OFF**, and the account is
  **not in Protected Users** — otherwise the issued TGT is **not forwardable**
  and jobs that delegate onward fail. (The test asserts the `F` flag precisely
  for this reason.)
- Domain Kerberos policy: max ticket life ≥ `ticket_lifetime` (10h), max renewal
  ≥ `renew_lifetime` (7d).
- The broker's **enrollment identity** is delegated only *reset-password* and
  *write `msDS-SupportedEncryptionTypes`* on the HPC OU — never Domain Admin.
- Each Kerberized service SPN (`hive/<host>`, `nn/<host>`, `dn/<host>`) is
  registered on an AES-enabled AD service account.

---

## 8. Threat model and the central trade-off

### 8.1 What the design protects

- **Issuance keys** (`/etc/krb-hpc/keytabs/*.keytab`) are `root:0600` on the
  broker only, rotated monthly (`admin/rotate_keys.sh`). The broker is a
  **tier-0** host; compromise exposes those users' escrowed keys.
- **Identity binding at issuance** is kernel-enforced: `krb-credd` takes the
  requesting UID from `SO_PEERCRED`, never from the request body, so a user can
  obtain only their own ticket, and only if enrolled.
- **No compute-fabric attack surface**: there is no privileged node daemon or
  listener on the compute nodes — a genuine advantage over KCM/SPANK designs.

### 8.2 The trade-off (the ticket on shared storage)

The ticket lives in `$HOME` on a shared filesystem. It is therefore readable by
**anyone who can act as that UID on that filesystem** — including **root on any
client that mounts home over NFS with `sec=sys`**. This is the price of the
design's simplicity and must be accepted explicitly.

Mitigations, in order of effectiveness:

1. **Kerberized NFS (`sec=krb5p`)** for home — removes the `sec=sys` root-impersonation path.
2. Mount home only on **managed** nodes, with **`root_squash`**.
3. Keep **`renew_lifetime` short** (e.g. 1 day) in the daemon's `krb5.conf`: the
   daemon re-acquires from the keytab regardless, so a stolen ticket cannot be
   renewed for a week.
4. Per-job `0700` directory and `0600` file (enforced by `krb-install-ccache`).

If this exposure is unacceptable for the environment, a node-local-KCM design
(outside the scope of this repo) is the alternative; this repo is deliberately
the shared-home design only.

### 8.3 Revocation

`admin/revoke_user.sh` removes the UID→account mapping (stops issuance and
refresh, since the map is re-read on change) and shreds the in-home copy **as
the user**. Then disable the AD account to stop future logins; outstanding
tickets expire within `ticket_lifetime`.

---

## 9. Failure modes and behavior

| Condition | Behavior |
|---|---|
| User not enrolled (`uidmap` miss) | `krb-get` returns an error; no ticket written |
| Keytab missing/stale | `TicketManager.acquire` fails; logged; prior ticket (if any) remains |
| Renew fails but keytab valid | falls back to re-acquire from keytab |
| Past renew limit | re-acquire from keytab on next refresh |
| Home filesystem unmounted on a node | TaskProlog finds no ticket; prints a diagnostic; task runs without a ticket (fails at the service, not silently) |
| Daemon down | existing in-home tickets keep working until expiry; no new issuance/refresh |
| `uidmap.conf` group/world writable | daemon refuses to load it (privilege-safety check) |
| Clock skew vs AD | `kinit`/validation fails on `exp`/`nbf`; keep NTP in sync |

---

## 10. Operations runbook

- **Enroll:** `admin/enroll_user.sh <user> <hpc-account>` → user logs in →
  `klist -f` must show flags **F** and **R**.
- **Verify propagation:** `srun -N4 bash -c 'klist -s && echo $(hostname) ok'`.
- **Rotate keys:** monthly via `admin/rotate_keys.sh` (systemd timer). Safe
  online: outstanding tickets stay valid; the daemon re-acquires with the new
  key on next refresh.
- **Revoke:** `admin/revoke_user.sh <user> <hpc-account>` + disable the AD account.
- **Health:** the daemon logs each acquire/renew/install; alert on repeated
  acquire failures (keytab or AD problem) and on `uidmap` load refusals.
- **Upgrade JDK:** the daemon uses only standard modules and public APIs; a JDK
  minor/major bump needs only a rebuild (`daemon/build.sh`) and a service
  restart.

---

## 11. What is tested, and what is not

`tests/verify-shared-home.sh` runs the **real JDK 24 daemon** against an MIT KDC
standing in for enterprise AD and asserts the full chain
(`tests/verify-shared-home.output.txt`):

1. the daemon issues a **forwardable** TGT into `$HOME`, owned by the user, mode 600;
2. **all four simulated compute nodes** use that one in-home file to reach the service;
3. the service accepts it over GSSAPI and `auth_to_local` maps the account;
4. the `squeue`-watch refresh **renews** the in-home ticket live.

The multi-node step is simulated by multiple readers of the single home-path
file — exactly what a shared mount presents to every node — so the propagation
mechanism is proven. **Not exercised here:** real Active Directory, a real
shared filesystem with `root_squash`/`sec=krb5p`, real Slurm, and a live
HiveServer2. Those are site-integration points to confirm in a lab.
