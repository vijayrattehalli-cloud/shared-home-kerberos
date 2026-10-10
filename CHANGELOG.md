# Changelog

## 2.3.0

Safety controls informed by a comparison with CRAFT (a PKINIT-based design).
Same architecture, same MIT tools; all new options have safe defaults.

**Every minted cache is checked before it is used.** After `kvno` mints a
user's tickets, the daemon reads the new cache (`klist -e -f`) and publishes it
only if it holds tickets for the expected user (case-insensitive), exactly one
for each `delegate_targets` entry and nothing else, no TGT, AES encryption only,
and at least 5 minutes of life. A cache that fails is discarded, the previous
one stays in place, and the failure is classified `bad_ticket`. This catches
wrong-account resolution, KDC policy drift and RC4 fallback before any job
sees the tickets.

**Administrator kill switch.** While `disable_file` (default
`/etc/krb-hpc/disabled`) exists, nothing is minted or installed: `krb-get` is
refused and background refresh pauses. Takes effect at once, no restart.

**System accounts are never served.** `min_uid` (default 1000): a UID below it
is refused even if enrolled by mistake.

**Per-user failure cooldown.** After a failed mint, that user's requests get
the same error for `failure_cooldown` (default 60 s) without another request to
AD, so repeated logins or scripts can't hammer the domain controller.

**`krb-get --status`.** Shows the caller whether they are enrolled, when their
tickets expire, any scheduled retry and the last error. Never mints.

**Process hardening.** The daemon disables core dumps and marks itself
non-dumpable at start-up; the unit adds `LimitCORE=0`.

**Upgrade note:** the right-hand column of `uidmap.conf` must be the
account's `sAMAccountName` (bare or `name@REALM`), which is the client name AD
puts in the tickets. A UPN alias that differs from it now fails validation as
`bad_ticket`; run `krb-credd --check --user <name>` for each enrolled user after
upgrading.

**Other**
- If AD issues tickets shorter than `renew_margin`, the daemon logs one
  warning (every pass would otherwise re-mint silently).
- `krb-credd --check` reports the kill switch and validates its test mint.
- Tests: new `tests/test_safety.py` (8 cases); the end-to-end script adds 8
  checks (36 in total).

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
