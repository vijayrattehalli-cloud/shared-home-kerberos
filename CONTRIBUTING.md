# Contributing

## Build
```bash
JAVA_HOME=/path/to/jdk24 daemon/build.sh        # produces daemon/krb-credd.jar
JAVA_HOME=/path/to/jdk24 hive-jdbc/build.sh <hive-jdbc-standalone.jar>
```

## Test
```bash
JAVA_HOME=/path/to/jdk24 sudo -E tests/verify-shared-home.sh
```
Requires MIT krb5 server+client tools on PATH. The test stands up a throwaway
MIT realm; it touches nothing outside its temp dir and a transient test user.

## Scope
This repository is the **shared-home** Kerberos design only. Please keep PRs
focused on that design; alternative forwarding mechanisms (KCM/SPANK, cross-realm)
are intentionally out of scope here.

## Style
- Java: standard JDK 24, public APIs only (no `--add-exports`), no third-party deps.
- Shell: `bash -n` clean; POSIX where practical.
