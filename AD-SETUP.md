# Active Directory setup for shared-home krb-credd (constrained delegation)

This is the domain-side companion to [`ARCHITECTURE.md`](ARCHITECTURE.md) and
[`SECURITY.md`](SECURITY.md). It answers two questions directly:

1. **Does every HPC user get a ticket?** — No. Only *enrolled* users do.
2. **How do you set up Active Directory to support this safely?**

The example realm is `CORP.EXAMPLE.MIL`. There is exactly **one** service
account for the whole cluster — the broker — and **no** per-user shadow
accounts or per-user keytabs.

---

## 1. Why one broker account + constrained delegation

The binding constraints: the CAC cannot do PKINIT on the HPC, GSSAPI credential
forwarding over SSH is blocked, and jobs run unattended for days. Something must
authenticate to AD without the card and refresh forever on its own.

Escrowing a **keytab per user** would do that, but a keytab is a long-term,
exportable key — the opposite of what CAC/PIV gives you — and N of them is a
large credential-management and attack surface. Since AD **permits constrained
delegation**, the better answer is a single **broker service account** that uses
**S4U2Self + S4U2Proxy** (protocol transition + constrained delegation) to mint
each user's service tickets on demand. This is the standard pattern for "a front
end authenticated the user by a non-Kerberos means, and now needs Kerberos to
specific backends."

What the users get is **service tickets to the enumerated backends only** — not
a general-purpose TGT. The broker impersonates each user's **real** AD identity,
so `auth_to_local` maps `jdoe@CORP.EXAMPLE.MIL → jdoe` with no prefix rewriting.

---

## 2. Enrollment is the gate — "not everyone gets a ticket"

A user receives tickets **only if**:

1. there is a line in `uidmap.conf` mapping their UID → their real AD principal, **and**
2. their AD account is **delegation-eligible** (see §4), **and**
3. the backends they need are in the broker's `msDS-AllowedToDelegateTo` **and** `delegate_targets`.

An un-enrolled UID that connects to the socket gets `ERR uid <n> is not
enrolled`. Enrollment is a deliberate administrative act, scoped to the users
and services that actually need Kerberized access — not a blanket "every POSIX
user on the cluster."

---

## 3. The broker account

### 3.1 Create it (AES-only, no interactive logon)
```powershell
$broker = "hpc-broker"
New-ADUser -Name $broker -SamAccountName $broker `
  -Path "OU=HPC-Service,OU=HPC,DC=corp,DC=example,DC=mil" `
  -AccountPassword (Read-Host -AsSecureString "pw") -Enabled $true `
  -KerberosEncryptionType AES256 `
  -Description "HPC Kerberos broker (krb-credd); constrained delegation to DAE backends"

# Register the broker's own SPN (it must be a service to use S4U):
setspn -S hpc-broker/hpc-mgmt.corp.example.mil $broker
```

### 3.2 Enable constrained delegation **with protocol transition**
Protocol transition (S4U2Self) lets the broker obtain a ticket "as the user"
without the user's credential; constrained delegation (S4U2Proxy) restricts
what it can then reach to an explicit SPN list.
```powershell
# Allowed targets = exactly the Kerberized backends jobs use:
Set-ADUser hpc-broker -Add @{ 'msDS-AllowedToDelegateTo' = @(
  'hive/hiveserver2.corp.example.mil',
  'hdfs/namenode.corp.example.mil'
)}

# "Use any authentication protocol" = protocol transition (TrustedToAuthForDelegation):
Set-ADAccountControl hpc-broker -TrustedToAuthForDelegation $true
```
> This list is the security boundary. Keep it **minimal** — every SPN added is
> something the broker can mint for any user. It must match `delegate_targets`
> in `credd.conf` exactly (same SPNs, realm-qualified).

### 3.3 Escrow the one keytab
```powershell
ktpass -princ hpc-broker/hpc-mgmt.corp.example.mil@CORP.EXAMPLE.MIL `
  -mapUser hpc-broker -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL +rndPass `
  -out broker.keytab
```
On the HPC management node, place it at `broker_keytab` (`/etc/krb-hpc/broker.keytab`),
**root:0600**. The daemon refuses any broker keytab that is not root-owned and
0600. Transfer over an encrypted channel and destroy the intermediate file.

> **Prefer a gMSA.** A group Managed Service Account has AD auto-rotate the
> password every 30 days, retrievable only by authorized hosts — no static key
> on disk. It requires the broker host be domain-joined and in the gMSA's
> `PrincipalsAllowedToRetrieveManagedPassword`. If gMSA isn't feasible, back the
> static keytab with an HSM/KMS and rotate on a schedule (§6).

---

## 4. The user accounts (delegation-eligible)

Because the broker impersonates each user's **real** identity, those accounts
must be valid S4U2Proxy targets:

- **AES-enabled** (`msDS-SupportedEncryptionTypes ⊇ 0x18`); RC4/DES off.
- **NOT** in **Protected Users** (that group blocks being a delegation target).
- **NOT** flagged **"Account is sensitive and cannot be delegated"**
  (`AccountNotDelegated = $false`).

> Ordinary HPC users are normally outside Protected Users (it's reserved for
> admins), so this usually holds already. Verify for your population:
> ```powershell
> Get-ADUser jdoe -Properties AccountNotDelegated,MemberOf |
>   Select-Object AccountNotDelegated,
>     @{n='Protected';e={$_.MemberOf -match 'Protected Users'}}
> ```
> If any HPC users *are* privileged accounts in Protected Users, they cannot be
> delegated; handle those out of band (they are not a fit for this design).

No per-user keytab, SPN, or password export is involved — these are the users'
normal accounts, untouched except for the eligibility check.

---

## 5. Backends, SPNs, and auth_to_local

- Register each backend SPN (`hive/host`, `hdfs/host`, …) on its **own**
  AES-enabled service account, and deploy those service keytabs to the service
  hosts — **never** to the HPC node.
- Keep the backend SPN set in `msDS-AllowedToDelegateTo` and `delegate_targets`
  in lockstep.
- `krb5.conf` uses `auth_to_local = DEFAULT`; service tickets already name the
  real user (`jdoe@REALM`), so backends see `jdoe` directly. Authorization
  (Ranger/HDFS ACLs) is applied to the real user as usual and is the second gate
  behind delegation.

---

## 6. Realm hardening and rotation

- **PAC-hardening updates** (KB5008380 / CVE-2021-42287 and related
  sAMAccountName-spoofing fixes) on all DCs, in enforcement mode — so a captured
  broker keytab cannot be leveraged to forge a PAC for a privileged account.
- **Disable RC4/DES** realm-wide; require AES.
- **Rotate the broker key** on a schedule (gMSA does this automatically; a
  static keytab via `ktpass +rndPass` + atomic replace `root:0600` + daemon
  restart). In-flight tickets keep working; the next mint uses the new key.
- **Monitoring:** the broker account's usage is highly predictable (S4U from one
  host to a fixed SPN set). Alert on S4U from any other host, on targets outside
  the allow-list, and on changes to `msDS-AllowedToDelegateTo`.
- **Offboarding a user:** remove their `uidmap.conf` line (stops minting at the
  next refresh) and remove their backend authorization. **Revoking everyone** is
  a single action: disable or rotate the broker account.

---

## 7. Checklist

- [ ] One broker service account, AES256, no interactive logon, with its own SPN
- [ ] `msDS-AllowedToDelegateTo` = exactly the backend SPNs (matches `delegate_targets`)
- [ ] `TrustedToAuthForDelegation = $true` (protocol transition)
- [ ] Broker keytab escrowed root:0600 (or gMSA/HSM-backed); intermediate copies destroyed
- [ ] Every enrolled user account is AES, not in Protected Users, not sensitive-for-delegation
- [ ] Backend SPNs on their own service accounts; service keytabs only on service hosts
- [ ] `uidmap.conf` lines (uid/name → real AD principal), root:0644
- [ ] DC PAC-hardening in enforcement mode; RC4/DES disabled
- [ ] Rotation + offboarding runbook; monitoring on the broker account's S4U usage
