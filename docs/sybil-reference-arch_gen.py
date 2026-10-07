#!/usr/bin/env python3
"""Generate the *correct* NVIDIA/sybil reference architecture diagram.

Verified against the project's own docs (github.com/NVIDIA/sybil):
  - sybild is "a privileged daemon hosted alongside the KDC" providing S4U
    delegation/impersonation; sybil is the CLI; a SPANK plugin integrates Slurm.
  - "Both KCM and the Sybil server need to be deployed alongside the KDC."
  - Backend: MIT Kerberos with the LDAP backend (required for S4U) or FreeIPA/IdM.
  - Mechanism: Microsoft S4U protocol extensions (S4U2Self + S4U2Proxy) + GSSAPI;
    authz via /etc/sybil.toml ACLs + krbAllowedToDelegateTo (LDAP) + +ok_as_delegate.
  - Auth model: an authorized principal does `kinit -k`, then `sybil kinit user@REALM`.
  - Active Directory is NOT in Sybil's documented environment.

So the correct picture is a SINGLE MIT-LDAP / FreeIPA realm (all Linux) with the
Sybil daemon co-located at the KDC -- there is no Windows/AD boundary. For the
AD-targeted S4U *client* adaptation in this repo, see krb-credd-architecture.*.

Renders docs/sybil-reference-architecture.{svg,png,pdf}.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from matplotlib.lines import Line2D

W, H = 1560, 1000
REALM, CORE, HPC, ACCENT = "#3F6B4E", "#2E8B57", "#2F6FB0", "#C77D0A"
REALM_FILL, CORE_FILL, HPC_FILL = "#F3F8F4", "#EAF6EE", "#EAF2FB"
INK, SUB, GREY = "#1A2330", "#5A6675", "#8290A0"
GAP_L, GAP_R, GMID = 700, 876, 788

fig = plt.figure(figsize=(15.6, 10), dpi=100)
ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, W); ax.set_ylim(0, H); ax.axis("off")
fig.patch.set_facecolor("white")


def box(x, y, w, h, *, fc="white", ec=INK, lw=1.6, r=0.02, z=2):
    ax.add_patch(FancyBboxPatch((x, y), w, h, fc=fc, ec=ec, lw=lw, zorder=z,
                 boxstyle=f"round,pad=0,rounding_size={r*min(w,h)}"))


def text(x, y, s, *, size=12, c=INK, w="normal", ha="left", va="top", z=5, ls=1.3, **kw):
    ax.text(x, y, s, fontsize=size, color=c, fontweight=w, ha=ha, va=va, zorder=z,
            linespacing=ls, fontfamily=["DejaVu Sans", "Arial", "sans-serif"], **kw)


def arrow(p0, p1, *, c=INK, lw=2.0, style="-|>", rad=0.0, z=4, ls="-"):
    ax.add_patch(FancyArrowPatch(p0, p1, arrowstyle=style, mutation_scale=15,
                 lw=lw, color=c, zorder=z, linestyle=ls,
                 connectionstyle=f"arc3,rad={rad}", shrinkA=1, shrinkB=1))


# ---------- title ----------
text(W/2, 978, "NVIDIA Sybil — Reference Architecture  (as the project documents it)",
     size=20, w="bold", ha="center")
text(W/2, 949, "sybild runs ALONGSIDE the KDC and impersonates users via S4U for Slurm batch jobs  •  MIT (LDAP backend) or FreeIPA / RHEL IdM",
     size=11.5, c=SUB, ha="center")
text(W/2, 929, "one Linux Kerberos realm — NOT Active Directory (AD is not in Sybil's supported environment; for the AD client adaptation see krb-credd-architecture)",
     size=9.5, c=SUB, ha="center", style="italic")

# ---------- single realm (all Linux) ----------
box(36, 66, 1488, 852, fc=REALM_FILL, ec=REALM, lw=2.4, r=0.01, z=1)
text(54, 905, "SINGLE KERBEROS REALM  —  MIT Kerberos (LDAP backend) or FreeIPA / RHEL IdM   •   all Linux",
     size=12.5, w="bold", c=REALM)

# two tiers inside the realm
box(60, 100, 640, 788, fc=CORE_FILL, ec=CORE, lw=1.8, r=0.014, z=1)
text(78, 872, "KDC TRUST CORE  —  co-located “alongside the KDC”", size=11.5, w="bold", c=CORE)
box(876, 100, 624, 788, fc=HPC_FILL, ec=HPC, lw=1.8, r=0.014, z=1)
text(894, 872, "HPC  /  SLURM", size=11.5, w="bold", c=HPC)

# ======================= KDC TRUST CORE (left) =======================
# KDC + LDAP
box(82, 548, 596, 300, fc="white", ec=CORE, lw=1.8)
text(100, 832, "MIT KDC (LDAP backend)  /  FreeIPA IdM", size=12.8, w="bold", c=CORE)
text(100, 800, "•  AS / TGS   (Kerberos, TCP 88)", size=11.3)
box(100, 572, 560, 200, fc="#F4FAF6", ec=CORE, lw=1.3, r=0.03)
text(118, 758, "LDAP directory  (backend — required for S4U)", size=11.4, w="bold", c=CORE)
text(118, 728, "•  krbAllowedToDelegateTo  =  { svc/… }\n"
               "      ← the S4U2Proxy allow-list\n"
               "•  target services flagged  +ok_as_delegate\n"
               "•  “Allow delegation to the Sybil server”", size=10.6, ls=1.5)

# sybild (focal)
box(82, 322, 596, 196, fc="#FFF8EE", ec=ACCENT, lw=2.6)
text(100, 500, "sybild — privileged delegation daemon", size=12.8, w="bold", c=ACCENT)
text(100, 468, "•  hosted ALONGSIDE the KDC\n"
               "•  impersonates users via S4U2Self + S4U2Proxy (GSSAPI)\n"
               "•  ACLs in /etc/sybil.toml  •  sybil service keytab\n"
               "•  NOT a KDC — no master key; uses a service principal", size=10.6, ls=1.5)

# KCM
box(82, 130, 596, 162, fc="white", ec=CORE, lw=1.8)
text(100, 274, "KCM — Kerberos Credential Manager", size=12.4, w="bold", c=CORE)
text(100, 244, "•  “store delegated credentials” via the KCM protocol\n"
               "•  deployed alongside the KDC + sybild\n"
               "•  the credential store the job's creds come from", size=10.6, ls=1.5)

# internal core arrows
arrow((380, 548), (380, 518), c=CORE, lw=1.8)                 # KDC <-> sybild (S4U)
arrow((380, 518), (380, 548), c=CORE, lw=1.8)
text(392, 538, "S4U2Self + S4U2Proxy\n(authorized by LDAP)", size=9.4, c=CORE, va="center")
arrow((250, 322), (250, 292), c=CORE, lw=1.8)                 # sybild -> KCM store
text(262, 312, "store delegated creds", size=9.4, c=CORE)

# ======================= HPC / SLURM (right) =======================
box(898, 648, 580, 200, fc="white", ec=HPC, lw=1.7)
text(916, 832, "Login / submit node", size=12.6, w="bold")
text(916, 802, "•  authorized principal:  kinit -k\n"
               "•  sybil kinit user@DOMAIN.LAN   (CLI → sybild)\n"
               "•  authenticated delegation — not blanket unattended", size=10.8, ls=1.5)

box(898, 486, 580, 130, fc="white", ec=HPC, lw=1.7)
text(916, 600, "Slurm controller", size=12.6, w="bold")
text(916, 570, "•  sbatch  --kerberos=yes\n"
               "•  SPANK plugin hooks the job lifecycle", size=10.8, ls=1.5)

box(898, 300, 580, 156, fc="white", ec=HPC, lw=1.7)
text(916, 440, "Compute nodes  cn001..cnNNN", size=12.6, w="bold")
text(916, 410, "•  SPANK plugin: forward + renew the user's creds\n"
               "      across the job lifecycle (pulled from KCM)\n"
               "•  job authenticates as the user", size=10.8, ls=1.5)

box(898, 130, 580, 140, fc="white", ec=HPC, lw=1.7)
text(916, 254, "Kerberized backends  (same realm)", size=12.4, w="bold")
text(916, 224, "•  NFS / Lustre / HDFS / …\n"
               "•  accept the delegated service tickets over GSSAPI", size=10.8, ls=1.5)

# internal HPC arrows
arrow((1188, 648), (1188, 616), c=HPC, lw=1.8)
text(1200, 636, "submit", size=9.4, c=HPC)
arrow((1188, 486), (1188, 456), c=HPC, lw=1.8)
text(1200, 476, "launch tasks", size=9.4, c=HPC)
arrow((1188, 300), (1188, 270), c=HPC, lw=1.8)
text(1200, 290, "use creds (GSSAPI)", size=9.4, c=HPC)

# ======================= CROSS-TIER (in the gap lane only) =======================
# login -> KDC: kinit -k
arrow((898, 760), (GAP_L, 790), c="#1F4E79", lw=2.0, style="-|>", rad=0.08)
text(GMID, 806, "kinit -k  (user)", size=9.8, w="bold", c="#1F4E79", ha="center", va="bottom")
# login -> sybild: sybil kinit user@REALM
arrow((898, 700), (GAP_L+2, 470), c="#1F4E79", lw=2.0, style="-|>", rad=0.10)
text(GMID, 648, "sybil kinit\nuser@DOMAIN", size=9.8, w="bold", c="#1F4E79", ha="center", va="center")
# KCM/sybild -> compute: SPANK forward+renew
arrow((GAP_L+2, 240), (898, 360), c=ACCENT, lw=2.1, style="-|>", rad=-0.12)
text(GMID, 300, "SPANK: forward +\nrenew creds\n(--kerberos=yes)", size=9.6, w="bold", c=ACCENT,
     ha="center", va="center", ls=1.3)

# ---------- legend / footnote ----------
box(36, 14, 1488, 40, fc="#FBFCFE", ec="#D7DEE7", lw=1.2, r=0.08)
ly = 34; x = 60
for col, lab in [("#1F4E79", "Kerberos / S4U (TCP 88)"), (CORE, "KDC-core internal"),
                 (HPC, "HPC / Slurm internal"), (ACCENT, "Sybil credential delivery")]:
    ax.add_line(Line2D([x, x+36], [ly, ly], color=col, lw=2.6, zorder=6))
    text(x+44, ly, lab, size=10.2, va="center"); x += 44 + len(lab)*6.7 + 34
text(x, ly, "Focal: sybild (amber)", size=10.2, c=ACCENT, w="bold", va="center")
text(1508, 34, "Source: github.com/NVIDIA/sybil", size=9, c=GREY, ha="right", va="center", style="italic")

for ext in ("svg", "png", "pdf"):
    fig.savefig(f"docs/sybil-reference-architecture.{ext}", facecolor="white", pad_inches=0)
print("wrote docs/sybil-reference-architecture.{svg,png,pdf}")
