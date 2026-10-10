# Contributing

## Layout
- `src/krbhpc/` — the Python package (daemon, client, install helper, Hive client, helpers)
- `bin/` — runnable wrappers (also installed as console scripts via `pip install .`)
- `config/`, `slurm/`, `systemd/`, `admin/` — deployment assets
- `tests/` — unit tests (`test_krb_helpers.py`, `test_daemon.py`, `test_hardening.py`, `test_safety.py`), the end-to-end `verify-shared-home.sh`, and `verify-ad.sh` (acceptance test against a real AD)

## Install / run
```bash
pip install .            # console scripts: krb-credd, krb-get, krb-install-ccache
pip install '.[hive]'    # + impyla for the Python Hive client
# or run from the repo without installing:
bin/krb-credd -c /etc/krb-hpc/credd.conf
```

## Test
```bash
python3 tests/test_krb_helpers.py                 # parsing, error classes, tool wrapper; no Kerberos
python3 tests/test_daemon.py                      # config, backoff, admin scripts (root for some cases)
python3 tests/test_hardening.py                   # fail-closed permission checks
python3 tests/test_safety.py                      # cache validation, kill switch, min_uid, cooldown, status
sudo MIT_PREFIX=... KDB_TEST_MODULE_DIR=... tests/verify-shared-home.sh   # end-to-end; MIT KDC + root
```
The end-to-end test stands up a throwaway MIT realm and runs the real daemon;
it touches nothing outside its temp dirs and three transient test users.

## Scope & style
- This repo is the **shared-home** design only. Keep PRs focused on it;
  KCM/SPANK and cross-realm forwarding are intentionally out of scope.
- Python: standard library only for the daemon/client/helper (impyla is an
  optional extra, used solely by the Hive client). Target `python3 >= 3.9`.
- Shell (Slurm hooks, admin): `bash -n` clean.
