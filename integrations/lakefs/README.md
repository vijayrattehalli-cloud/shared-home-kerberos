# lakeFS integration — runnable reference

A working reference for the two pieces that bridge a krb-credd Kerberos ticket
to **lakeFS Enterprise** over **Spark / S3A** (design: [`../../docs/lakefs-integration.md`](../../docs/lakefs-integration.md)):

```
broker/    lakeFS credential broker  — SPNEGO (via Apache+mod_auth_gssapi) → mints a
           short-lived lakeFS access key via the lakeFS Auth API.
provider/  S3A AWSCredentialsProvider — on each Spark executor, trades the job's
           Kerberos ticket (SPNEGO) at the broker for that key and feeds it to S3A.
tests/     verify-lakefs-broker.sh   — end-to-end test against a throwaway MIT KDC
           + a stdlib mock lakeFS (no real lakeFS or Apache needed).
```

## The flow (recap)

```
krb-credd  → shared-home:  HTTP/lakefs-sts service ticket (pre-minted; no TGT)
Spark executor (S3A provider) → broker:  SPNEGO (Authorization: Negotiate)
broker (behind mod_auth_gssapi) → lakeFS Auth API:  mint short-lived access key
broker → executor:  { access_key_id, secret_access_key, expiry }
executor S3A (SigV4) → lakeFS S3 gateway → object store
```

The broker **does not speak GSSAPI itself** — Apache + `mod_auth_gssapi` performs
the SPNEGO handshake against the broker's `HTTP/<host>` keytab and passes the
authenticated principal as `REMOTE_USER`. The broker trusts `REMOTE_USER`, so it
**must** be reachable only through that proxy (bind to 127.0.0.1; set
`BROKER_TRUSTED_PROXIES`).

## Run the test

```bash
# needs: python3 (Flask, requests) + MIT krb5 tools (incl. gss-server) on PATH
integrations/lakefs/tests/verify-lakefs-broker.sh
```

It verifies, with no real lakeFS/Apache:
- **Part 1 (mint path):** an unauthenticated request is rejected (401); with an
  authenticated principal (as `mod_auth_gssapi` sets `REMOTE_USER`) the broker
  maps `jdoe@REALM → jdoe`, calls the lakeFS Auth API with admin auth, and
  returns a short-lived `{access_key_id, secret_access_key, expiry}`.
- **Part 2 (Kerberos SPN auth):** a user's ticket authenticates to the broker's
  `HTTP/<host>` service principal and resolves to the right local name — exactly
  the identity `mod_auth_gssapi` would hand the broker. Proven with MIT
  `gss-server`/`gss-client`.

Recorded output: [`tests/verify-lakefs-broker.output.txt`](tests/verify-lakefs-broker.output.txt).
The one piece the harness does not run is Apache wiring Part 2's SPNEGO to Part
1's `REMOTE_USER` — that is `broker/apache-mod-auth-gssapi.conf`.

## Deploy

1. **AD / krb-credd.** Register `HTTP/lakefs-sts.<domain>` on a service account;
   add that SPN to the broker account's `msDS-AllowedToDelegateTo` **and** to
   krb-credd's `delegate_targets`. krb-credd then mints that ticket into
   shared-home for every enrolled user.
2. **Broker host (next to lakeFS).** Export its `HTTP/<host>` keytab; run Apache
   with `broker/apache-mod-auth-gssapi.conf`; run the Flask broker behind it:
   ```bash
   pip install -r broker/requirements.txt
   BROKER_LISTEN=127.0.0.1:8640 BROKER_REMOTE_USER_SOURCE=header:X-Remote-User \
   BROKER_TRUSTED_PROXIES=127.0.0.1 LAKEFS_ENDPOINT=https://lakefs.corp:8000 \
   LAKEFS_ADMIN_ACCESS_KEY_ID=... LAKEFS_ADMIN_SECRET_ACCESS_KEY=... \
   gunicorn -b 127.0.0.1:8640 lakefs_cred_broker:app
   ```
   (The admin credential is the one controlled standing secret here — HSM/secret-
   store it and scope its lakeFS RBAC to credential creation.)
3. **Spark.** `mvn -q clean package` in `provider/`, deploy the jar to every node,
   and apply `provider/spark-s3a.conf.example` (set `-Dsun.security.jgss.native=true`
   so JGSS reads the native, no-TGT ccache).

## Confirm against your lakeFS

- The exact Enterprise **Auth API / STS** call that mints a short-TTL key (the
  broker uses `POST /api/v1/auth/users/{user}/credentials`; if your edition
  supports an explicit TTL or an STS exchange, prefer it).
- `jdoe@REALM → lakeFS user` mapping / auto-provisioning so RBAC resolves.
- SPN hostname canonicalization so the minted ticket matches the requested SPN.
