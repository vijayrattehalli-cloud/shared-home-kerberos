# Changelog

## Unreleased

- `docs/krb-credd-call-graph.md` (and an interactive `.html` copy): call-graph
  diagrams of the whole data flow, with file:line references for every function.
- `tests/verify-ad.sh`: an acceptance test to run on the broker node against a
  real Active Directory. Non-destructive; checks the broker keytab and TGT, a
  real S4U mint per user with `kvno -U` and `-I` (reporting the exact name AD
  puts in the tickets, encryption types and lifetimes, and whether the 2.3.0
  checks accept them), Protected Users and allow-list refusals, `--check`,
  end-to-end `krb-get`/`--status`/web service, and optionally the kill switch.
  Saves a PASS/FAIL report. Dry-run against the MIT test KDC: 23/23.

## 2.3.0

Safety controls informed by a comparison with CRAFT (a PKINIT-based design).
Same architecture, same MIT tools; all new options have safe defaults.

**Every minted cache is checked before it is used.** After `kvno` mints a
user's tickets, the daemon reads the new cache (`klist -e -f`) and publishes it
only if the tickets are for the expected user (the uidmap principal or
`<linux name>@REALM`, case-insensitive), cover every `delegate_targets` entry,
contain no TGT, use an AES session key, and have at least 5 minutes of life. A
cache that fails is discarded, the previous one stays in place, and the
failure is classified `bad_ticket`. Extra non-TGT entries and a back-end
ticket encrypted with RC4 (a setting on the target service account) are logged
as warnings, not refused. Caches minted before an upgrade or a uidmap change
are checked on first use. `ticket_checks = warn` relaxes only the two
name-matching checks, for sites still sorting out name formats.

**Administrator kill switch.** While `disable_file` (default
`/etc/krb-hpc/disabled`) exists, nothing is minted or installed: `krb-get` is
refused, background refresh pauses, and `--check` sends nothing to AD. Takes
effect at once, no restart. The path must be absolute and only root may be
able to create it (checked at start-up).

**System accounts are never served.** `min_uid` (default: `UID_MIN` from
`/etc/login.defs`, else 1000): a UID below it is refused even if enrolled by
mistake. Start-up and `--check` report any enrolled UID below the floor.

**Per-user failure cooldown.** After a failure only an admin can fix (account
not delegable, unknown principal, rejected cache), that user's requests get
the same error for `failure_cooldown` (default 60 s) without another request to
AD. Transient errors (KDC unreachable, timeout) are always retried at once, and
cooldown answers don't lengthen the background backoff.

**`krb-get --status`.** Shows the caller whether they are enrolled, when their
tickets expire, any scheduled retry and the last error. Never mints.

**Process hardening.** The daemon disables core dumps and marks itself
non-dumpable at start-up; the unit adds `LimitCORE=0`.

**Upgrade notes**
- Tickets must name the uidmap principal or `<linux name>@REALM`. A user of
  another AD domain needs a fully qualified uidmap entry (`jdoe@EAST.CORP`).
  Run `krb-credd --check --user <name>` for a few enrolled users after
  upgrading; set `ticket_checks = warn` temporarily if names need sorting out.
- Enrolled users with UIDs below `min_uid` are refused; `--check` lists them.

**Other**
- If AD issues tickets shorter than `renew_margin`, the daemon logs one
  warning (every pass would otherwise re-mint silently).
- `krb-credd --check` reports the kill switch and validates its test mint.
- Duplicate `delegate_targets` are ignored; an empty list is a config error.
- Tests: new `tests/test_safety.py` (12 cases); the end-to-end script adds 10
  checks (38 in total) and passes on MIT 1.20.1 and 1.21.3 (RHEL 9's version),
  in enterprise and principal name modes.
- Revised after an independent review of the first 2.3.0 draft, which found
  the original checks too strict for common AD setups (UPN mappings, RC4
  back-end tickets) and the cooldown replaying transient errors.

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
