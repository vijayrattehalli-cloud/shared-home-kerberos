# Changelog

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
