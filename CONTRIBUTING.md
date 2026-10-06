# Contributing

## Layout
- `src/krbhpc/` — the Python package (daemon, client, install helper, Hive client, helpers)
- `bin/` — runnable wrappers (also installed as console scripts via `pip install .`)
- `config/`, `slurm/`, `systemd/`, `admin/` — deployment assets
- `tests/` — unit tests (`test_krb_helpers.py`) and the end-to-end `verify-shared-home.sh`

## Install / run
```bash
pip install .            # console scripts: krb-credd, krb-get, krb-install-ccache
pip install '.[hive]'    # + impyla for the Python Hive client
# or run from the repo without installing:
bin/krb-credd -c /etc/krb-hpc/credd.conf
```

## Test
```bash
python3 tests/test_krb_helpers.py                 # pure-function unit tests, no Kerberos
sudo -E tests/verify-shared-home.sh               # end-to-end; needs MIT krb5 tools + root
```
The end-to-end test stands up a throwaway MIT realm and runs the real daemon;
it touches nothing outside its temp dir and a transient test user.

## Scope & style
- This repo is the **shared-home** design only. Keep PRs focused on it;
  KCM/SPANK and cross-realm forwarding are intentionally out of scope.
- Python: standard library only for the daemon/client/helper (impyla is an
  optional extra, used solely by the Hive client). Target `python3 >= 3.9`.
- Shell (Slurm hooks, admin): `bash -n` clean.
