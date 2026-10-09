# Changelog

## 2.2.0

From a critical review for efficiency, simplicity, supportability and
robustness. Same design, same MIT tools.

**Robustness**
- `krb-get` times out (30 s, `KRB_HPC_TIMEOUT`) so a stuck daemon can't hang
  logins, and shell-quotes the path it prints for `eval`.
- A home cache the user deleted is put back on the next refresh pass.
- After a restart the daemon resumes refreshing previously active users and
  runs its first refresh pass immediately instead of 5 minutes later.
- The TaskProlog finds the home directory even when `HOME` is unset
  (`sbatch --export=NONE`).
- The install helper `fsync`s before renaming into place.

**Efficiency**
- `klist` results are memoized per cache file (inode, mtime, size): an
  unchanged cache costs a `stat()` instead of a process, so the steady-state
  refresh pass starts no Kerberos processes for users who don't need a mint.
- Users who aren't enrolled are filtered out before the broker is checked.

**Simplicity / supportability**
- One install helper: `bin/krb-install-ccache` is now a symlink to
  `src/krbhpc/install_ccache.py`.
- `krb-credd --check [--user NAME]` validates a deployment without starting
  the daemon.
- `credd.conf`: unknown options (typos) are logged; missing required options
  and bad durations fail with a one-line message instead of a traceback.
- Per-user state is pruned when a user goes idle.
- systemd unit: dropped `CAP_DAC_OVERRIDE`, `CAP_CHOWN`, `CAP_FOWNER` (only
  `SETUID`, `SETGID`, `SETPCAP`, `DAC_READ_SEARCH` remain); documented that
  non-`/home` home roots must be added to `ReadWritePaths`.

**Tests**
- End-to-end: 28 checks (was 22), with the daemon run under exactly the
  systemd unit's capabilities; new checks for cache repair, restart resume,
  `--check`, and config typos.
- Unit: 14 helper, 10 daemon, 9 hardening tests.

## 2.1.0

Same design and the same MIT command-line tools; hardening, robustness and a
much stronger test.

**Correctness**
- `kvno` stores every S4U2Proxy ticket in the cache it is given, even with
  `--out-cache`, so the broker cache collected every user's service tickets.
  Each mint now runs `kvno` on a throwaway copy of the broker cache.
- Broker renewal (`kinit -R`) rewrote the broker cache in place while other
  threads could be reading it; it now renews a copy and renames it into place.
- `klist` times are produced and parsed in UTC (`TZ=UTC0` + `timegm`), removing
  the ambiguous hour when daylight saving time ends.

**Hardening**
- Kerberos tools run by absolute path (`kinit`, `klist`, `kvno` in
  `credd.conf`); each must be root-owned and not writable by others.
- Start-up refuses non-MIT tools or MIT older than 1.19 (needed for
  `kvno --out-cache`) and logs the version found.
- More environment variables scrubbed from the tools (`KRB5_CONFIG`,
  `KRB5_CLIENT_KTNAME`, `KRB5_KDC_PROFILE`, `KRB5RCACHE*`, `TZ`, `LANG`, `LC_*`).
- `uidmap.conf` gets the same checks as other trusted files, including "not a
  symlink".
- Admin scripts match users exactly (no regular expressions): `enroll_user.sh`
  detects an existing entry by name or UID; `revoke_user.sh` can't remove
  another user whose name merely matches a pattern, and rewrites the map
  atomically.

**Operations**
- Failures are classified (`kdc_unreachable`, `timeout`, `clock_skew`,
  `not_delegable`, `unknown_principal`, `broker_key`, `bad_cache`, `other`) in
  the log; users get a plain-language reason for the common ones.
- Background refresh runs users in parallel (`refresh_workers`, default 4),
  checks the broker TGT once per pass, and backs off a failing user instead of
  retrying every pass.
- `s4u_name_type` makes `kvno -U` (enterprise name, the previous behavior and
  default) vs `-I` (plain principal) an explicit choice.
- Stale "TGT" wording fixed in `krb-get`, the login hook and the TaskProlog;
  `slurm.conf.snippet` header corrected.

**Tests**
- `verify-shared-home.sh` now uses MIT's test KDB module, which can hold a
  constrained-delegation allow-list, so the full S4U path runs end to end
  (22 checks), including refusals and the safeguards above.
- New `test_daemon.py`; `test_krb_helpers.py` extended (13 tests).
