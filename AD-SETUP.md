# Active Directory setup for shared-home krb-credd

This is the domain-side companion to [`ARCHITECTURE.md`](ARCHITECTURE.md) and
[`SECURITY.md`](SECURITY.md). It answers two questions directly:

1. **Does every HPC user get a TGT?** — No. Only *enrolled* users do.
2. **How do you set up Active Directory to support this safely?**

Throughout, the example realm is `CORP.EXAMPLE.MIL` and per-user service
accounts follow the pattern `hpc-<samaccountname>` (e.g. `hpc-jdoe`).

---

## 1. Why a dedicated AD account per user (and not the user's own account)

The binding constraint is that the CAC on the HPC side **cannot** perform
PKINIT/GSSAPI to obtain a TGT as the human user, yet the HPC knows users only by
UID/GID and must reach Kerberized services in the enterprise realm. So instead
of the user's primary AD account, each enrolled HPC user gets a **dedicated,
purpose-built AD account** whose key is escrowed on the HPC management node as a
keytab. `krb-credd` `kinit`s from that keytab.

This is a deliberate trade: a standing credential exists for each enrolled user.
The rest of this document is about making that credential as weak and as
contained as possible — it should be able to do exactly one thing (authenticate
to the approved Kerberized services as a mappable identity) and nothing else.

`auth_to_local` on the service side maps `hpc-jdoe@CORP.EXAMPLE.MIL` back to the
POSIX name `jdoe`, so services see the right user. (Verified in
`config/krb5.conf`: the `RULE` strips the `hpc-` prefix.)

---

## 2. Enrollment is the gate — "not everyone gets a TGT"

A user receives a ticket **only if both** of these exist:

1. a line in `uidmap.conf` mapping their UID → `hpc-<user>` principal, **and**
2. an escrowed keytab `keytab_dir/hpc-<user>.keytab` (root:0600).

An un-enrolled UID that connects to the socket gets `ERR uid <n> is not
enrolled` and no ticket. Enrollment is an explicit administrative act — create
the AD account, export the keytab, add the uidmap line — not a blanket "every
POSIX user on the cluster." Scope it to the users and the services that actually
need Kerberized access.

---

## 3. Step-by-step AD configuration

### 3.1 Create an OU and a delegated enrollment identity
```
OU=HPC-Service-Accounts,OU=HPC,DC=corp,DC=example,DC=mil
```
Put every `hpc-<user>` account in this OU. Delegate to the HPC admin team (or a
dedicated enrollment service account) **only** the rights to create/manage
accounts *within this OU* — not domain-wide. Nothing in HPC should hold broad
directory rights.

### 3.2 Create each per-user account (AES-only, no interactive logon)
PowerShell (run by the delegated enrollment identity):
```powershell
$u = "jdoe"
$acct = "hpc-$u"
New-ADUser -Name $acct -SamAccountName $acct `
  -Path "OU=HPC-Service-Accounts,OU=HPC,DC=corp,DC=example,DC=mil" `
  -AccountPassword (Read-Host -AsSecureString "pw") -Enabled $true `
  -KerberosEncryptionType AES256 `
  -Description "HPC escrowed Kerberos identity for $u (managed by krb-credd)"

# AES only — no RC4/DES:
Set-ADUser $acct -Replace @{ 'msDS-SupportedEncryptionTypes' = 0x18 }  # AES128+AES256
```

### 3.3 Make the account un-delegatable and sensitive
Microsoft Guardian / site policy forbids unrestricted delegation, and this
design does not need it — the forwardable TGT is carried by the shared home, not
by Kerberos delegation. So lock delegation **off**:
```powershell
# "Account is sensitive and cannot be delegated":
Set-ADAccountControl $acct -AccountNotDelegated $true

# Add to Protected Users (forces AES, no RC4/NTLM, no delegation,
# short TGT lifetime for this account class):
Add-ADGroupMember -Identity "Protected Users" -Members $acct
```
> **Note on Protected Users + ticket lifetime.** Protected Users caps the TGT
> lifetime (commonly 4 hours). `krb-credd` already renews/re-acquires well
> inside any such window, so this is compatible — but confirm the daemon's
> `renew_margin` is shorter than the enforced lifetime. If a site's policy
> makes that impractical for long-queued jobs, the account can instead be left
> out of Protected Users while **keeping** `AccountNotDelegated`, AES-only, and
> the scoped rights below; document the choice.

### 3.4 Grant least privilege — logon to the target services only
These accounts should authenticate to the approved Kerberized DAE/Hive/etc.
services and do nothing else:
- **No** membership in operational or admin groups.
- **No** local logon rights on Windows infrastructure (deny via GPO:
  *Deny log on locally* / *Deny log on through RDP* for the OU).
- Grant access to each target service exactly as you would a normal user of
  that service (e.g. the Hive/Ranger authorization that maps to `jdoe`).

### 3.5 Service Principal Names
The per-user accounts are *clients*; they normally need **no** SPN. Register
SPNs only on the **service** accounts (Hive, HDFS, etc.), e.g.
`hive/host.corp.example.mil@CORP.EXAMPLE.MIL`, and export those service keytabs
to the service hosts — never to the HPC node.

### 3.6 Export and escrow the keytab
Export AES keys for the account and move the keytab to the HPC management node:
```powershell
ktpass -princ hpc-jdoe@CORP.EXAMPLE.MIL -mapUser hpc-jdoe `
  -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL +rndPass `
  -out hpc-jdoe.keytab
```
On the HPC node, place it under `keytab_dir` as `hpc-jdoe.keytab`, **root:0600**.
The daemon refuses any keytab that is not root-owned and 0600 (see
`SECURITY.md` §3.3). Transfer over an encrypted channel and delete the
intermediate file from the Windows side.

### 3.7 Add the uidmap line
```
# /etc/krb-hpc/uidmap.conf  (root:0644, not group/world writable)
jdoe   hpc-jdoe
# or by numeric uid:
# 24070 hpc-jdoe
```
No daemon restart needed — `uidmap.conf` is re-read on mtime change.

---

## 4. Realm-level hardening (do this once)

- **Apply the PAC-hardening updates** (KB5008380 / CVE-2021-42287 and the
  related sAMAccountName-spoofing fixes) on all domain controllers, in
  enforcement mode. This prevents a captured keytab from being leveraged to
  forge a PAC for a different (e.g. privileged) account.
- **Disable RC4/DES** realm-wide where feasible; require AES. The `hpc-*`
  accounts are already AES-only (§3.2).
- **Cross-realm:** if HPC and enterprise are separate realms, use a one-way
  trust with the HPC realm trusting enterprise, AES trust keys, and a tight
  `auth_to_local`. (This repo's default is a single realm; see
  `ARCHITECTURE.md` for the topology discussion.)
- **Monitoring:** alert on use of any `hpc-*` account from anywhere other than
  the expected service hosts, on authentication failures, and on account
  modification within the HPC OU. These accounts have a very predictable usage
  shape, which makes anomalies easy to spot.

---

## 5. Key rotation

Escrowed keys are standing credentials, so rotate them:
- Rotate each `hpc-<user>` key on a schedule (e.g. every 30–90 days) and on any
  suspicion of compromise or when a user offboards.
- Rotation = re-export the keytab (`+rndPass` mints a new random key and
  invalidates the old) and atomically replace the file under `keytab_dir`
  (root:0600). In-flight tickets keep working until renewal; the next
  `_acquire` uses the new key.
- **Offboarding:** disable/delete the AD account, delete the keytab, and remove
  the `uidmap.conf` line. Any of the three alone stops new tickets; do all
  three.

---

## 6. Checklist

- [ ] Dedicated OU with delegated (not domain-wide) enrollment rights
- [ ] `hpc-<user>` account per enrolled user, AES256, no interactive logon
- [ ] `AccountNotDelegated = true` on every account
- [ ] Protected Users membership (or documented exception) 
- [ ] Least-privilege service access only; denied local/RDP logon via GPO
- [ ] SPNs only on service accounts, service keytabs only on service hosts
- [ ] Keytab escrowed root:0600 on the HPC node; intermediate copies destroyed
- [ ] `uidmap.conf` line added (root:0644)
- [ ] DC PAC-hardening updates applied in enforcement mode; RC4/DES disabled
- [ ] Rotation + offboarding runbook in place; monitoring on `hpc-*` usage
