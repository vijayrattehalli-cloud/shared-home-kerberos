# Security model — shared-home krb-credd (constrained delegation)

This document states what `krb-credd` is trusted to do, what it defends against,
what it explicitly does **not**, and the concrete hardening in the code, the
systemd unit, and Active Directory. Read it alongside
[`ARCHITECTURE.md`](ARCHITECTURE.md) and [`AD-SETUP.md`](AD-SETUP.md).

---

## 1. What the daemon is

`krb-credd` is a small root daemon on the HPC login/management plane. It holds
**one** credential — a single broker service account's keytab — keeps that
broker's TGT fresh, and uses **Kerberos constrained delegation (S4U2Self +
S4U2Proxy)** to mint each enrolled user's **service tickets** to the allow-listed
backends. It writes those into the user's home on the shared filesystem
(`$HOME/.krb5/krb5cc_hpc`), where every compute node already sees them.

There are **no per-user keytabs** and **no user TGT** — the user's cache holds
only service tickets to the enumerated backends. The single broker keytab is the
one piece of long-term key material on the HPC side, so it is the one component
whose compromise matters most. The design concentrates — and then hardens — that
one secret rather than scattering N of them.

---

## 2. Trust boundaries

| Principal | Trusted for |
|-----------|-------------|
| **root on the HPC management node** | Fully trusted; it owns the broker keytab and the daemon. |
| **The AD KDC / domain admins** | Trusted to mint tickets and to authorize delegation via `msDS-AllowedToDelegateTo`. Out of scope to defend against. |
| **The shared filesystem** | Trusted for integrity and per-home `0700` ownership (see §5). |
| **An ordinary (unprivileged) local user** | **Untrusted** — the threat we defend against. May connect to the socket, race files, craft symlinks, spam requests. |
| **A user's own job / processes** | Get exactly that user's service tickets — never anyone else's. |

Central guarantee: **an unprivileged local user can obtain their own service
tickets and nobody else's, and only if enrolled and delegation-eligible.**

---

## 3. Attacker model and mitigations

### 3.1 Identity spoofing on the socket
The requester's UID is read from the kernel via `SO_PEERCRED` — never from the
request (whose grammar is a single literal `GET`). A user connecting as UID 1234
can only cause tickets for UID 1234 to be minted into UID 1234's home. The socket
is mode `0666` deliberately: anyone may *connect*, but `SO_PEERCRED` + enrollment
decide whose tickets (if any) are produced.

### 3.2 Privilege escalation via the install helper
The cache is copied into `$HOME` by re-executing `krb-install-ccache` **as the
target user** through `setpriv` with `--reuid/--regid --init-groups`,
`--inh-caps=-all --bounding-set=-all`, `--no-new-privs`, and a minimal scrubbed
environment (`PATH`, `HOME`). The write happens as the user, so the shared FS
enforces that it lands in their `0700` home; a symlink/hardlink trick can only
redirect it somewhere the user can already write. The helper is **self-contained
stdlib Python**, so there is no module-search hijack when it runs from libexec.

### 3.3 Tampering with the files the daemon trusts
Before trusting any input the daemon fails **closed** via `_assert_secure()`,
requiring each path to be root-owned (uid 0), not a symlink (checked with
`lstat`), of the expected type, and not group/world writable — and for the
**broker keytab**, `strict` mode requires mode **0600 or stricter** so the key
cannot leak even by read. Enforced at startup for `broker_keytab`, `state_dir`,
the `install_helper`, and the config file. `uidmap.conf` is re-read on mtime
change and rejected unless root-owned and not group/world writable. Covered by
[`tests/test_hardening.py`](tests/test_hardening.py) (9 cases).

### 3.4 Environment-based code injection into the krb5 tools
`kinit`/`klist`/`kvno` are run by **absolute path** (configurable in
`credd.conf`, never looked up on `PATH`); at start-up each must resolve to a
root-owned file that others can't write, and `klist -V` must report MIT 1.19+.
They run with `LD_PRELOAD`, `LD_AUDIT`, `KRB5CCNAME`, `KRB5_KTNAME`,
`KRB5_CLIENT_KTNAME`, `KRB5_TRACE`, `KRB5_KDC_PROFILE`, `KRB5RCACHEDIR`,
`KRB5RCACHETYPE`, `KRB5_CONFIG`, `TZ`, `LANG`, `LANGUAGE` and all `LC_*`
scrubbed (every call passes `-c`/`-t`/`--out-cache` explicitly), then
`KRB5_CONFIG`, `LC_ALL=C` and `TZ=UTC0` pinned. `LD_LIBRARY_PATH` is preserved
for sites with a non-standard krb5 prefix — acceptable because the daemon's
environment is controlled by systemd, not by any user. The end-to-end test
starts the daemon with hostile values for these and checks they have no effect.
`kvno` gets a throwaway copy of the broker cache, so the real one never
collects users' service tickets.

### 3.5 Local denial of service
`MAX_CLIENTS` (32) bounds concurrent requests with a `BoundedSemaphore` (shed
with `ERR busy`); `CLIENT_TIMEOUT_S` (10s) caps a slow client; `min_reissue_
interval` (10s) throttles re-copying into `$HOME` so `krb-get` spam cannot drive
repeated `setpriv`+write storms. The cheap validity check still runs each call.
After a failure only an admin can fix (not delegable, unknown principal,
rejected cache), a user's requests are answered from the cached error for
`failure_cooldown` (60s), so a refused user cannot turn logins or scripts into
a stream of requests to the domain controller. Transient errors are not cached.

### 3.5a Unexpected tickets from the KDC
Every freshly minted cache is inspected before it replaces anything: it must
name the expected user (the uidmap principal or `<linux name>@REALM`,
case-insensitive), cover every `delegate_targets` entry, contain no TGT, have
an AES session key, and have at least 5 minutes of life. Otherwise it is
discarded (`bad_ticket`) and the previous cache stays. This guards against an
enterprise-name lookup resolving to a different AD account and against RC4
session keys. A back-end ticket encrypted with RC4 (chosen by the target
service account) and extra non-TGT entries are logged, not refused. With
`ticket_checks = warn` only the two name-matching checks are relaxed; the TGT,
client, session-key and lifetime checks always apply. Caches minted before
start-up (or before a uidmap change) are checked on first use.

### 3.5b Emergency stop and account scope
`disable_file` is a kill switch: while it exists nothing is minted or
installed, effective immediately. Its directory must be root-owned and not
writable by others, and no ancestor may let others replace it, so only root
can trip it. `min_uid` (1000) keeps root and system
accounts out of scope even if enrolled by mistake. Neither revokes tickets
already issued.

### 3.6 Information disclosure
Unexpected failures return a terse `ERR could not obtain ticket`; details go to
the daemon log. The daemon disables core dumps and marks itself non-dumpable
(`prctl(PR_SET_DUMPABLE, 0)`), and the unit sets `LimitCORE=0`, so tickets held
in its memory are not written to core files or readable through `/proc` by
other processes. Caches are `0600`; master copies in `state_dir` and the broker
ccache are `0600` under a `0700` root-owned dir.

---

## 4. systemd confinement

The unit runs the daemon under: `ProtectSystem=strict` with an explicit
`ReadWritePaths` allowlist (`/var/lib/krb-hpc /run/krb-hpc /home`),
`ProtectKernelTunables/Modules/Logs`, `ProtectControlGroups`, `ProtectClock`,
`ProtectHostname`, `RestrictNamespaces`, `LockPersonality`,
`MemoryDenyWriteExecute`, `RestrictRealtime`, `RestrictAddressFamilies=AF_UNIX
AF_INET AF_INET6`, a capped `CapabilityBoundingSet` of just `CAP_SETUID CAP_SETGID
CAP_SETPCAP` (for `setpriv`) and the read-only `CAP_DAC_READ_SEARCH` (to notice a
deleted home cache) — no `CAP_DAC_OVERRIDE`, `CAP_CHOWN` or `CAP_FOWNER`, since
the daemon writes only its own root-owned files and every write into a home
happens as the user; the end-to-end test runs the daemon with exactly this set —
and a
`SystemCallFilter` of `@system-service @setuid` minus the dangerous groups.
`NoNewPrivileges` is intentionally **off** at the unit level (so `setpriv` can
transition identity); the `setpriv` child itself runs `--no-new-privs` with all
caps dropped, so privilege never travels into user code.

---

## 5. Residual risk / explicitly out of scope

- **Concentrated broker risk.** One keytab replaces N, which is a smaller,
  more auditable, more revocable surface — but its compromise lets an attacker
  mint tickets to the **allow-listed backends** as **any delegation-eligible
  user, without proof of that user** (protocol transition). This is the central
  trade. Contain it with: an **HSM- or gMSA-backed** key (no static key on
  disk); the **tightest possible** `msDS-AllowedToDelegateTo` / `delegate_targets`;
  monitoring of the broker account (its S4U usage pattern is highly predictable);
  and each backend's own authorization (Ranger) as a second gate. The blast
  radius is bounded by the SPN allow-list — the broker can never mint a TGT or
  reach a service not on the list.
- **Root compromise** of the management node is game over by definition; the
  broker keytab lives there. Keep that node small, patched, access-controlled.
- **Shared-filesystem trust.** The design relies on the FS honoring per-home
  `0700` ownership. A misconfigured export (e.g. `no_root_squash` + loose home
  perms, or an attacker with write access to another user's home) breaks the
  isolation the `setpriv` write depends on. Note the exposure is **smaller** than
  with a TGT: a stolen cache yields only service tickets to the enumerated
  backends. Mitigate with `sec=krb5p` home, `root_squash` on managed mounts, and
  short service-ticket lifetimes (the daemon re-mints).
- **Delegation eligibility.** Users must not be in Protected Users / sensitive-
  for-delegation, or S4U2Proxy fails for them. Privileged accounts are therefore
  not a fit for this design and must be handled out of band.
- **Not every user gets tickets.** Enrollment in `uidmap.conf` + delegation
  eligibility + backend SPNs on the allow-list are the gates.

---

## 6. Active Directory hardening (summary)

Full steps in [`AD-SETUP.md`](AD-SETUP.md): one broker account, AES-only, with
`TrustedToAuthForDelegation` and a **minimal** `msDS-AllowedToDelegateTo`; the
keytab gMSA/HSM-backed and root:0600; every user account AES and delegation-
eligible; backend SPNs on their own accounts with keytabs only on service hosts;
realm PAC-hardening (KB5008380 / CVE-2021-42287) in enforcement mode; RC4/DES
disabled; key rotation and broker-usage monitoring in place.

---

## Reporting

Please report suspected vulnerabilities privately to the repository owner rather
than opening a public issue.
