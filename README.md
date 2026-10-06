# Shared-Home Architecture — one ticket in `$HOME`, visible on every node

**The idea in one sentence:** the user's Kerberos TGT lives in their home
directory on the cluster's shared filesystem, so every compute node already
sees it — "forwarding to the job's nodes" is nothing more than pointing each
task at `$HOME/.krb5/krb5cc_hpc`. No SPANK plugin, no KCM, no Sybil, no
per-node agent.

This is the **simplest** of the HPC-Kerberos designs to operate. Its one
requirement is that **home directories are on a filesystem every compute node
mounts** (NFS / GPFS / Lustre) — which is already true on essentially every
real HPC cluster.

It is `krb-hpc-v2` **solution B**, recreated here as a standalone bundle. The
daemon is pure **JDK 24** with no third-party dependencies.

---

## 1. How it works

```
 CAC login ─▶ login node (uid 21001)
                │ profile.d → krb-get
                ▼
        ┌────────────────────────┐  JAAS Krb5LoginModule + escrowed keytab
        │ krb-credd (JDK 24, root)│ ─────────────────────────────────────▶ enterprise AD DCs
        │ uidmap + keytabs        │ ◀── forwardable, renewable AD TGT
        └────────────────────────┘
                │ writes, AS THE USER (setpriv), to:
                ▼
     $HOME/.krb5/krb5cc_hpc   ── on the SHARED filesystem ──┐
                                                            │  (one file, mounted everywhere)
     ┌───────────────┬───────────────┬───────────────┬─────┘
     ▼               ▼               ▼               ▼
   cn001           cn002           cn003           cn004
   TaskProlog: export KRB5CCNAME=FILE:$HOME/.krb5/krb5cc_hpc     (identical on every node)
     │
     ▼
   tasks → Hive / HDFS   (service tickets obtained from the real AD TGT)
```

Two moving parts, total:

1. **`krb-credd`** (one daemon, on the login/broker tier) issues each user's
   AD TGT from an escrowed per-user keytab and writes it into their home
   directory **as the user** (via `setpriv` + `krb-install-ccache`, so it works
   on root-squashed NFS/GPFS/Lustre). It then **keeps every active ticket
   fresh**: it renews before expiry, re-acquires from the keytab past the renew
   limit, and watches `squeue` so any user with a pending or running job is
   refreshed even if they logged out.

2. **A one-line Slurm TaskProlog** exports `KRB5CCNAME` pointing at that home
   file on each node. That's the entire "propagation" mechanism.

There is no node-side daemon, no ticket copy, and nothing to clean up at job
end — the file is the user's and simply persists in their home.

---

## 2. Why this is correct — and verified

Because the ticket is a **genuine AD TGT** (krb-credd does the real AD login the
CAC can't), everything downstream is ordinary Kerberos:

- A compute node uses the in-home TGT to request `hive/_HOST@REALM`; the real
  KDC issues the service ticket **with a PAC**; the AD-homed Hive service
  accepts it; `auth_to_local` yields the local username.
- Nothing is forged, so none of the PAC-enforcement concerns from the
  forging-based designs apply.

**Verified** (`tests/verify-shared-home.sh`, runs the real JDK 24 daemon against
an MIT KDC standing in for enterprise AD; reproducible, idempotent):

| Check | Result |
|---|---|
| krb-credd issues the TGT into `$HOME/.krb5/krb5cc_hpc` | PASS |
| Ticket owned by the user, mode 600 | PASS |
| TGT is **forwardable** | PASS |
| **All 4 simulated compute nodes** use that one in-home file to reach the service | PASS |
| Service accepts it over GSSAPI; `auth_to_local` maps the account | PASS |
| squeue-watch **renews** the in-home ticket live during a job | PASS |

The daemon itself is the same code that passed the `e2e-daemon.sh` suite in
`krb-hpc-v2`.

---

## 3. Bundle contents

| Path | Purpose |
|---|---|
| `daemon/src/hpc/krb/*.java` → `krb-credd.jar` (`daemon/build.sh`) | the daemon + `KrbGet`; JDK 24 standard modules only |
| `bin/krb-get` | user command / profile.d hook (wraps `hpc.krb.KrbGet`) |
| `bin/krb-install-ccache` | writes the ticket **as the user** (root-squash-safe), atomically |
| `slurm/taskprolog.krb.sh` | the one line that exports `KRB5CCNAME` on every node |
| `slurm/prolog.krb.sh` | optional, diagnostics only (logs if a job's ticket is missing) |
| `slurm/slurm.conf.snippet` | `TaskProlog=…` (no SPANK, no PrologFlags needed) |
| `config/credd.properties` | daemon config (realm, ccache path, refresh, squeue-watch) |
| `config/krb5.conf` | AD realm, AES-only, `auth_to_local` |
| `config/uidmap.conf` | UID / username → AD account |
| `config/profile.d-krb-hpc.sh` | login-time `krb-get` |
| `systemd/krb-credd.service` | runs the daemon on a JDK 24 runtime |
| `hive-jdbc/` | JDK 24 Hive client + driver shim + sample job |
| `admin/*` | AD enrollment (`msktutil`/`ktpass`), monthly key rotation, revoke |
| `tests/verify-shared-home.sh` + recorded output | the proof above |

### The daemon, by file
- `KrbCredd.java` — UNIX-socket front door (`SO_PEERCRED` for identity), virtual-thread handlers, refresh scheduler. No Security Manager (JEP 486).
- `TicketManager.java` — acquire (JAAS keytab login), renew (`KerberosTicket.refresh()`), re-acquire past renew-till, install via `setpriv`.
- `CCacheWriter.java` — serialises the ticket to the MIT **FILE** ccache format using only public APIs (no `--add-exports` into `sun.security.krb5`), so MIT tools *and* the JDK both read it, and it survives JDK updates.
- `Accounts.java` — `getent` lookups + the UID→principal map.
- `Config.java`, `Log.java`, `KrbGet.java` — config, logging, the user command.

---

## 4. Hive JDBC (JDK 24)

Identical to the `krb-hpc-v2` Java-24 client: log in from the in-home FILE
cache, open the connection inside `Subject.callAs`, and load the one-class
`TSubjectAssumingTransport` shim ahead of the driver (JDK 24 removed the
Security Manager, so the stock driver's `Subject.getSubject` call throws). The
only row-1 specifics:

- Service principal names the AD realm: `hive/_HOST@CORP.EXAMPLE.MIL`.
- Use binary transport + `kerberosAuthType=fromSubject`.

Build: `hive-jdbc/build.sh /opt/hive/jdbc/hive-jdbc-<ver>-standalone.jar`
(compiles the shim against your exact driver jar, so an API mismatch fails at
build time). On JDK 17/21 you can instead use the simpler client from
`krb-hpc-v2` solution A — the realm of the service principal doesn't change that
path.

---

## 5. Active Directory requirements (same as any forwarding design)

- Dedicated `hpc-<user>` accounts in an HPC OU, **AES256 enabled**.
- **"Account is sensitive and cannot be delegated" OFF**, and **not in Protected
  Users** — otherwise the TGT isn't forwardable. (The test checks the F flag.)
- Domain policy: max ticket life ≥ 10h, max renewal ≥ 7d.
- Broker enrollment identity: reset-password + write-enctype on that OU only.
- Register the Hive/HDFS SPNs on AES-enabled AD service accounts.

Why a dedicated account, not the CAC account: AD can roll a smart-card-required
account's password at will, silently invalidating the escrowed keytab.

---

## 6. Security notes and the one real trade-off

- **Issuance keys** (`/etc/krb-hpc/keytabs`) are `root:0600` on the broker only,
  rotated monthly (`admin/rotate_keys.sh`). Treat the broker as tier-0.
- **The trade-off that defines this design:** the ticket sits in `$HOME` on a
  shared filesystem, so it is readable by anyone who can act as that UID on that
  filesystem — including **root on any client that mounts home over NFS
  `sec=sys`**. This is the price of the simplicity.
  - Mitigations: mount home only on **managed** nodes, with `root_squash`;
    prefer **Kerberized NFS (`sec=krb5p`)** for home if available; keep
    `renew_lifetime` **short** (e.g. 1 day) in the daemon's `krb5.conf` — the
    daemon re-acquires from the keytab anyway, so a stolen ticket can't be
    renewed for a week.
  - If that exposure is unacceptable, use the **Sybil forwarding-only** bundle
    (`krb-hpc-ad-fwd`) or krb-credd `native` mode instead, which keep the ticket
    in node-local KCM rather than on shared storage.
- **Revocation:** `admin/revoke_user.sh` (removes mapping + shreds the home
  copy as the user) **plus** disable the AD account. Outstanding tickets expire
  within `ticket_lifetime`.
- **No node-side attack surface:** there is no node daemon or privileged
  listener on the compute fabric — a point in this design's favor.

---

## 7. Deployment

1. **AD:** HPC OU, delegated enrollment identity, Hive/HDFS SPNs, AES on
   accounts, clear the "sensitive"/Protected-Users flags.
2. **Broker/login tier:** install a **JDK 24 runtime**, `setpriv` (util-linux),
   MIT krb5 client. Run `daemon/build.sh`; copy `krb-credd.jar` to
   `/opt/krb-hpc/`; install `config/*`, `bin/krb-install-ccache` (to
   `/usr/local/libexec/krb-hpc/`), `bin/krb-get`, and the systemd unit. Add your
   home roots to the unit's `ReadWritePaths`. Enable `krb-credd` + monthly
   rotation.
3. **Slurm:** install `slurm/taskprolog.krb.sh`, merge `slurm.conf.snippet`,
   `scontrol reconfigure`. (No SPANK, no KCM, nothing on compute nodes beyond a
   JDK for the Hive client.)
4. **Login nodes:** `bin/krb-get` + `config/profile.d-krb-hpc.sh`.
5. **Verify:** `admin/enroll_user.sh jdoe hpc-jdoe` → log in → `klist -f` shows
   **F** and **R** → `srun -N4 klist -s && echo ok` → `sbatch
   hive-jdbc/hive_job.sbatch`.

---

## 8. When to pick this vs. the alternatives

| | Shared-home (this) | Sybil forwarding-only (`krb-hpc-ad-fwd`) | krb-credd native (`krb-hpc-v2` sol. A) |
|---|---|---|---|
| Node-side components | **none** (just the shared mount) | sybild + SPANK + sssd-kcm | MUNGE + mTLS listener |
| Ticket location on nodes | `$HOME` (shared FS) | node-local KCM | node-local FILE |
| Simplicity | **highest** | lowest | middle |
| Needs home mounted on every node | **yes** | no | no |
| Shared-FS ticket exposure | yes (mitigate as §6) | no | no |

**Pick shared-home when** your compute nodes mount home directories (the normal
case) and you want the fewest moving parts. **Avoid it when** you cannot accept
a ticket living on shared storage, or nodes don't mount home — then use one of
the node-local-KCM designs.

---

## 9. Tested here vs. needs your environment

**Tested:** the full daemon→home→multi-node→service path and live renewal
(`tests/verify-shared-home.sh`, all 6 checks, repeatable), with the real JDK 24
daemon against an MIT KDC. **Not tested here:** real Active Directory, a real
shared filesystem with `root_squash`, real Slurm, and a live HiveServer2. The
multi-node step is simulated by multiple readers of the one home-path file —
which is exactly what a shared mount presents to every node — so the mechanism
is proven; confirm against your actual mount and scheduler in a lab.
