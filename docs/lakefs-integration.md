# lakeFS integration — Spark / S3A on lakeFS Enterprise

How a Slurm job authenticates to **lakeFS Enterprise** over **S3A/Spark** when
credentials come from [`krb-credd`](../README.md). Companion diagram:
[`docs/lakefs-s3a-architecture.svg`](lakefs-s3a-architecture.svg).

> A **runnable reference** for the two new pieces (the credential broker and the
> S3A provider), with an end-to-end test against a local MIT KDC, lives in
> [`integrations/lakefs/`](../integrations/lakefs/). This page is the design;
> that directory is the code. Confirm the exact lakeFS Enterprise Auth/STS
> request shapes against current lakeFS docs before production.

---

## 1. The mismatch

Spark reads/writes lakeFS data through **S3A** against the **lakeFS S3 gateway**,
which authenticates with a **lakeFS access-key pair** (`access_key_id` +
`secret_access_key`, S3 SigV4). krb-credd gives the job a **Kerberos service
ticket**, not a lakeFS key, and lakeFS has **no native Kerberos/SPNEGO**. So a
small bridge turns "the job holds a Kerberos ticket for *jdoe*" into "the job
holds a short-lived lakeFS key for *jdoe*."

A key consequence of the krb-credd design matters here: the job's cache holds
**only pre-minted service tickets, no TGT**. So **every** service the job
authenticates to must have its SPN in krb-credd's `delegate_targets` — including
the broker below. The job cannot obtain a ticket on the fly; krb-credd must have
minted it already.

---

## 2. Components

| Component | New? | Role |
|---|---|---|
| **krb-credd** | existing | Mints the job a service ticket for the broker SPN into `$HOME/.krb5/krb5cc_hpc` (present on every node). |
| **lakeFS credential broker** | **new** | SPNEGO endpoint (`mod_auth_gssapi`). Verifies the Kerberos identity, maps principal → lakeFS user, mints a **short-lived lakeFS access key** via the lakeFS Enterprise Auth API, returns `{id, secret, expiry}`. |
| **S3A credentials provider** | **new** | Runs on each Spark executor. Calls the broker over SPNEGO (using `KRB5CCNAME`), caches the lakeFS key, refreshes before expiry. |
| **lakeFS Enterprise + S3 gateway + object store** | existing | Serve the data; RBAC applies the mapped user's policies. |

---

## 3. AD / krb-credd setup (one-time)

1. Register an SPN for the broker, e.g. `HTTP/lakefs-sts.corp.example.mil` on a
   dedicated AD service account.
2. Add that SPN to the broker account's `msDS-AllowedToDelegateTo` **and** to
   krb-credd's `delegate_targets` in `credd.conf`:
   ```ini
   delegate_targets = hive/hiveserver2.corp.example.mil@CORP.EXAMPLE.MIL \
                      hdfs/namenode.corp.example.mil@CORP.EXAMPLE.MIL \
                      HTTP/lakefs-sts.corp.example.mil@CORP.EXAMPLE.MIL
   ```
   krb-credd now mints that `HTTP/lakefs-sts` service ticket into the shared-home
   cache for every enrolled user (no restart for the AD change; restart the
   daemon to pick up the new `delegate_targets`).
3. The broker host holds a **lakeFS admin credential** (to mint keys) — one
   controlled standing secret, HSM/secret-store backed, exactly like krb-credd's
   broker keytab. Scope its lakeFS policy to credential creation if your RBAC
   allows.

---

## 4. End-to-end flow

```
1. krb-credd  → shared-home:  HTTP/lakefs-sts service ticket (pre-minted; no TGT)
2. Spark executor (as the user) reads KRB5CCNAME → the cached service ticket
3. executor  → broker:        SPNEGO  (Authorization: Negotiate <ticket>)
4. broker    → lakeFS Auth API: mint a SHORT-LIVED access key for the mapped user
5. broker    → executor:      { access_key_id, secret_access_key, expiry }
6. executor S3A (SigV4 w/ lakeFS key) → lakeFS S3 gateway → object store
   (near expiry, the provider re-runs steps 3–5 — long/queued jobs never stall)
```

Because executors run under the user's UID on compute nodes with `KRB5CCNAME`
pointing at shared-home, **each executor authenticates itself** to the broker as
the user — no secret is distributed from the driver.

---

## 5. Spark / S3A configuration

```bash
spark-submit \
  --conf spark.hadoop.fs.s3a.endpoint=https://lakefs.corp.example.mil:8000 \
  --conf spark.hadoop.fs.s3a.path.style.access=true \
  --conf spark.hadoop.fs.s3a.connection.ssl.enabled=true \
  --conf spark.hadoop.fs.s3a.aws.credentials.provider=com.example.LakeFSKerberosCredentialProvider \
  --conf spark.hadoop.fs.s3a.ext.lakefs.broker.url=https://lakefs-sts.corp.example.mil/credentials \
  --conf spark.hadoop.fs.s3a.ext.lakefs.broker.spn=HTTP/lakefs-sts.corp.example.mil \
  ...
```
```python
# a lakeFS repo is the S3 "bucket"; the branch is the first path element
df = spark.read.parquet("s3a://my-repo/main/datasets/events/")
df.write.mode("overwrite").parquet("s3a://my-repo/experiment-x/out/")
```

### The custom credentials provider (sketch)

Implement Hadoop's `AWSCredentialsProvider` (v1) / `AwsCredentialsProvider` (v2):

```java
public class LakeFSKerberosCredentialProvider implements AWSCredentialsProvider {
  private volatile AWSCredentials cached;
  private volatile Instant expiresAt = Instant.EPOCH;

  public AWSCredentials getCredentials() {
    if (cached != null && Instant.now().isBefore(expiresAt.minusSeconds(60)))
      return cached;                                   // still fresh
    // SPNEGO GET to the broker, using the FILE ccache krb-credd installed.
    // The ccache has NO TGT, only the pre-minted HTTP/lakefs-sts service
    // ticket, so GSSAPI must target exactly that SPN (watch host canon.).
    HttpURLConnection c = spnegoConnect(brokerUrl, brokerSpn); // Negotiate
    Json r = Json.parse(c.getInputStream());                   // {id,secret,expiry}
    cached = new BasicAWSCredentials(r.get("access_key_id"), r.get("secret_access_key"));
    expiresAt = Instant.parse(r.get("expiry"));
    return cached;
  }
  public void refresh() { expiresAt = Instant.EPOCH; }
}
```

JVM SPNEGO reads the native FILE ccache via the Krb5 login module with
`useTicketCache=true` (or the default `KRB5CCNAME`). Since the cache holds only
the service ticket (no TGT), the provider must request **exactly** the
`HTTP/lakefs-sts…` SPN krb-credd minted — GSSAPI cannot fetch a different one.

> **Simpler fallback (not recommended for long jobs):** the driver fetches one
> key from the broker and sets `fs.s3a.access.key`/`secret.key` in the job conf.
> This distributes the secret and cannot refresh — use only for short jobs.

---

## 6. Alternative: lakeFS Enterprise STS / external principals

Instead of the broker calling the Auth API directly, the broker can mint an
**OIDC/SAML assertion** (e.g. via ADFS, after SPNEGO) and exchange it through
lakeFS Enterprise **STS login / external principals** for temporary lakeFS
credentials. This is more "lakeFS-native" but adds an IdP hop; the Auth-API
broker in §2–5 is simpler for headless Spark. Confirm the exact STS request and
whether it returns S3-gateway-usable keys against current lakeFS docs.

---

## 7. Security notes

- **One controlled secret, not N:** the broker's lakeFS admin credential is the
  only standing secret added — HSM/secret-store it, scope its RBAC to credential
  creation, monitor it. Same philosophy as krb-credd's broker keytab.
- **Short-lived keys:** mint with the shortest practical TTL; authorization is
  the mapped lakeFS user's RBAC (branch/repo policies), so a leaked key is
  bounded in both time and scope.
- **No key on disk:** the provider holds the key in executor memory and refreshes
  via SPNEGO; nothing is written to the job's filesystem.
- **Identity mapping:** `jdoe@REALM` → a lakeFS user/group must be provisioned
  (or auto-provisioned at first mint) so RBAC resolves.
- **Pre-minted tickets only:** the broker SPN must be in `delegate_targets`, and
  the provider must request that exact SPN (the cache has no TGT to fall back on).

---

## 8. To confirm before implementing

- The lakeFS Enterprise **Auth API** call that creates an access key and whether
  it accepts an explicit short **TTL** (else use STS/external principals for
  temporary creds).
- lakeFS edition features in your deployment (SSO/STS/Remote Authenticator are
  Enterprise).
- SPN **hostname canonicalization** so the minted ticket matches the SPN the
  provider requests.

Sources: [lakeFS SSO](https://docs.lakefs.io/security/sso/) ·
[Remote Authenticator](https://docs.lakefs.io/security/remote-authenticator/) ·
[STS login](https://docs.lakefs.io/security/sts-login/) ·
[Auth API / credentials](https://pydocs.lakefs.io/docs/AuthApi.html) ·
[Enterprise config](https://docs.lakefs.io/enterprise/configuration/)
