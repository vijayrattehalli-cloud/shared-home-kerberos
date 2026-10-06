# Security model — shared-home krb-credd

This document states what `krb-credd` is trusted to do, what it defends
against, what it explicitly does **not** defend against, and the concrete
hardening measures in the code, the systemd unit, and the Active Directory
configuration. Read it alongside [`ARCHITECTURE.md`](ARCHITECTURE.md) and
[`AD-SETUP.md`](AD-SETUP.md).

---

## 1. What the daemon is

`krb-credd` is a small root daemon on the HPC login/management plane. For each
**enrolled** user it obtains an Active Directory TGT from an escrowed, per-user
keytab and writes the resulting credential cache into that user's home
directory (`$HOME/.krb5/krb5cc_hpc`) on the shared filesystem, where every
compute node already sees it. It keeps active users' tickets fresh.

It is the one component that holds long-term Kerberos key material on the HPC
side, so it is also the one component whose compromise matters most. The design
is built around containing that blast radius.

---

## 2. Trust boundaries

| Principal | Trusted for |
|-----------|-------------|
| **root on the HPC management node** | Fully trusted. Already owns the keytabs and the daemon; `krb-credd` adds no new privilege a root attacker lacks. |
| **The AD KDC / domain admins** | Trusted to mint tickets and define the `hpc-<user>` accounts. Out of scope to defend against. |
| **The shared filesystem** | Trusted for integrity and for enforcing per-home `0700` ownership. See §5 caveat. |
| **An ordinary (unprivileged) local user** | **Untrusted.** The threat we actively defend against. May connect to the socket, race files, craft symlinks, and spam requests. |
| **A user's own job / processes** | Get exactly that user's ticket — never anyone else's. |

The central guarantee: **an unprivileged local user can obtain their own ticket
and nobody else's, and only if an administrator has enrolled them.**

---

## 3. Attacker model and mitigations

### 3.1 Identity spoofing on the socket
The front door is a UNIX-domain socket. The requester's UID is read from the
kernel via `SO_PEERCRED` — it is **never** taken from the request payload. The
request grammar is a single literal `GET`; there is no field in which a caller
can name a different user. A user who connects as UID 1234 can only ever cause
a ticket for UID 1234 to be (re)issued into UID 1234's home.

The socket is mode `0666` deliberately: anyone may *connect*, but
`SO_PEERCRED` + enrollment decide whose ticket (if any) is produced.

### 3.2 Privilege escalation via the install helper
The ticket is copied into `$HOME` by re-executing a tiny helper
(`krb-install-ccache`) **as the target user** through `setpriv`, with:
- `--reuid`/`--regid` + `--init-groups` — drop to the user's real identity,
- `--inh-caps=-all --bounding-set=-all` — drop every capability,
- `--no-new-privs` — the child can never regain privilege (no setuid/fscaps),
- a minimal, scrubbed environment (`PATH`, `HOME` only).

Because the write happens as the user, the shared FS enforces that it lands in
*their* `0700` home and nowhere else; a symlink or hardlink trick can only ever
redirect the write to somewhere the user themselves can already write.

The helper is **self-contained stdlib Python** (no import of the package), so
there is no `PYTHONPATH`/module-search hijack surface when it runs from the
libexec path.

### 3.3 Tampering with the files the daemon trusts
Before the daemon trusts any of its inputs it fails **closed** via
`_assert_secure()`, which requires each path to be:
- owned by **root (uid 0)**,
- **not a symlink** (checked with `lstat`, so the link itself is inspected),
- of the **expected type** (dir vs regular file),
- **not group/world writable** (`0o022` mask); and for **secret keytabs**,
  `strict` mode requires mode **0600 or stricter** (`0o077` mask) so a key
  cannot leak even by *read*.

This is enforced at startup for `keytab_dir`, `state_dir`, the `install_helper`,
and the config file, and again on every `kinit` for the specific user keytab.
`uidmap.conf` is re-read on mtime change and rejected unless root-owned and not
group/world writable, so enrollment edits need no restart but a tampered map is
refused. These checks are covered by [`tests/test_hardening.py`](tests/test_hardening.py)
(9 cases).

### 3.4 Environment-based code injection into the krb5 tools
`kinit`/`klist` are run with a scrubbed environment: `LD_PRELOAD`, `LD_AUDIT`,
`KRB5CCNAME`, `KRB5_KTNAME`, and `KRB5_TRACE` are removed (every call passes
`-c`/`-t` explicitly, so cache/keytab pointers must not leak in), while
`KRB5_CONFIG` and `LC_ALL=C` are pinned. `LD_LIBRARY_PATH` is *preserved* on
purpose — sites that install MIT krb5 under a non-standard prefix rely on it —
which is acceptable because the daemon's own environment is controlled by
systemd, not by any user.

### 3.5 Local denial of service
- `MAX_CLIENTS` (32) bounds concurrent in-flight requests with a
  `BoundedSemaphore`; past that the daemon replies `ERR busy` and sheds load
  instead of spawning unbounded threads.
- `CLIENT_TIMEOUT_S` (10s) caps how long a slow/stuck client can hold a slot.
- `min_reissue_interval` (default 10s) throttles re-copying a ticket into
  `$HOME`, so a user spamming `krb-get` cannot drive repeated `setpriv`+write
  storms; the cheap validity check still runs every call.

### 3.6 Information disclosure
Error text sent back over the socket is deliberately terse
(`ERR could not obtain ticket`) for unexpected failures; details go to the
daemon log, not the client. Tickets are written `0600`; the master copies in
`state_dir` are `0700`-dir, root-owned.

---

## 4. systemd confinement

The unit (`systemd/krb-credd.service`) runs the daemon under a strong sandbox:
`ProtectSystem=strict` with an explicit `ReadWritePaths` allowlist
(`/var/lib/krb-hpc /run/krb-hpc /home`), `ProtectKernelTunables/Modules/Logs`,
`ProtectControlGroups`, `ProtectClock`, `RestrictNamespaces`, `LockPersonality`,
`MemoryDenyWriteExecute`, `RestrictRealtime`,
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, a capped
`CapabilityBoundingSet` (only `CAP_SETUID CAP_SETGID CAP_SETPCAP
CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE`), and a
`SystemCallFilter` of `@system-service @setuid` minus the dangerous groups.

`NoNewPrivileges` is intentionally **left off** at the unit level because
`setpriv` must be able to transition identity — but the `setpriv` child itself
runs with `--no-new-privs` and all capabilities dropped, so the privilege
*never* travels downward into user code.

---

## 5. Residual risk / explicitly out of scope

- **Root compromise** of the management node is game over by definition; the
  keytabs live there. Keep that node small, patched, and access-controlled.
- **Shared-filesystem trust.** The design relies on the FS honoring per-home
  `0700` ownership and not being writable by other users. A misconfigured
  export (e.g. `no_root_squash` plus loose home perms, or an attacker with
  write access to another user's home) breaks the isolation the `setpriv`
  write depends on. Audit home-directory permissions.
- **AD account compromise / escrow.** Each `hpc-<user>` keytab is a standing
  credential. §6 and `AD-SETUP.md` constrain what it can do (no delegation,
  Protected Users, scoped rights); rotation limits the window. This is a
  deliberate trade for the "CAC can't do PKINIT on HPC" constraint, not a
  zero-risk posture.
- **Not every user gets a ticket.** Enrollment in `uidmap.conf` + an escrowed
  keytab is the gate. An un-enrolled UID gets `ERR uid ... is not enrolled`.

---

## 6. Active Directory hardening (summary)

Full steps in [`AD-SETUP.md`](AD-SETUP.md). In brief, each `hpc-<user>` account
should be: AES-only; flagged **Account is sensitive and cannot be delegated**;
a member of **Protected Users**; granted no rights beyond logon to the target
Kerberized services; and on a key-rotation schedule. The realm must have the
PAC-hardening updates (KB5008380 / CVE-2021-42287) applied so a captured keytab
cannot be used to forge cross-account PACs.

---

## Reporting

Please report suspected vulnerabilities privately to the repository owner rather
than opening a public issue.
