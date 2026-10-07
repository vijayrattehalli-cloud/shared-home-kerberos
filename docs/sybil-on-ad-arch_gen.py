#!/usr/bin/env python3
"""Sybil pointed at Active Directory: Linux sybild as a REMOTE S4U client of the
Windows AD KDC. This is what "Sybil connecting to AD" actually looks like.

Honest caveat baked into the diagram: NVIDIA/sybil documents MIT-LDAP / FreeIPA
with sybild co-located on the KDC. Running it against AD drops two assumptions:
  - "alongside the KDC" -> sybild is a REMOTE client (AD DC is Windows), and
  - the MIT LDAP backend -> AD natively provides msDS-AllowedToDelegateTo.
The S4U mechanism itself is AD-native (MS-SFU), so the core works.

Renders docs/sybil-on-ad-architecture.{svg,png,pdf}.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from matplotlib.lines import Line2D

W, H = 1560, 1000
WIN, LNX, ACCENT = "#2F6FB0", "#2E8B57", "#C77D0A"
WIN_FILL, LNX_FILL = "#EAF2FB", "#EAF6EE"
INK, SUB, KRB, WARN = "#1A2330", "#5A6675", "#1F4E79", "#B5531A"
LANE_L, LANE_R, MID = 650, 910, 780

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
    ax.add_patch(FancyArrowPatch(p0, p1, arrowstyle=style, mutation_scale=16,
                 lw=lw, color=c, zorder=z, linestyle=ls,
                 connectionstyle=f"arc3,rad={rad}", shrinkA=1, shrinkB=1))


# ---------- title ----------
text(W/2, 978, "Sybil pointed at Active Directory — Linux sybild (S4U client) ↔ Windows AD KDC",
     size=19.5, w="bold", ha="center")
text(W/2, 950, "sybild runs in the Linux boundary as a REMOTE S4U client of AD (not co-located with the KDC); AD provides the delegation allow-list",
     size=11.3, c=SUB, ha="center")

# caveat banner
box(300, 898, 960, 30, fc="#FFF4E8", ec=WARN, lw=1.3, r=0.2, z=6)
text(W/2, 913, "Not an upstream-documented deployment — NVIDIA/sybil targets MIT-LDAP / FreeIPA with sybild ON the KDC; "
     "see sybil-reference-architecture for its native form.", size=9.3, c=WARN, ha="center", va="center", z=7)

# ---------- zones + boundary ----------
box(40, 70, 610, 818, fc=WIN_FILL, ec=WIN, lw=2.2, r=0.012, z=1)
box(910, 70, 610, 818, fc=LNX_FILL, ec=LNX, lw=2.2, r=0.012, z=1)
text(58, 876, "WINDOWS BOUNDARY  •  Active Directory domain", size=12.5, w="bold", c=WIN)
text(928, 876, "LINUX BOUNDARY  •  HPC cluster (UID / GID)", size=12.5, w="bold", c=LNX)
ax.add_line(Line2D([MID, MID], [60, 888], color="#8A99AB", lw=2.0, ls=(0, (6, 5)), zorder=3))
ax.text(MID, 86, "TRUST  BOUNDARY", rotation=90, fontsize=9.5, color="#6B7A8D",
        ha="center", va="bottom", fontweight="bold", zorder=6)

# ======================= WINDOWS / AD =======================
box(70, 648, 560, 118, fc="white", ec=WIN)
text(90, 752, "AD domain controller host(s)", size=12.6, w="bold")
text(90, 724, "•  Windows — you cannot host sybild here\n"
              "•  so sybild must talk to AD over the network", size=11)

box(70, 150, 560, 470, fc="white", ec=WIN, lw=2.0)
text(90, 602, "Active Directory Domain Controller — KDC", size=13.5, w="bold", c=WIN)
text(90, 567, "•  AS / TGS   (Kerberos, TCP 88)\n"
              "•  native S4U (MS-SFU) + PAC  (KB5008380)\n"
              "•  the SINGLE KDC — issues every ticket", size=11.3, ls=1.45)
box(90, 170, 520, 190, fc="#F4F8FD", ec=WIN, lw=1.3, r=0.03)
text(108, 342, "Delegation policy  (replaces Sybil's LDAP backend)", size=11.4, w="bold", c=WIN)
text(108, 312, "•  msDS-AllowedToDelegateTo = { hive/…, hdfs/… }\n"
               "      ← the S4U2Proxy allow-list (native in AD)\n"
               "•  sybil svc acct: TrustedToAuthForDelegation\n"
               "•  users: delegation-eligible (not Protected Users)", size=10.5, ls=1.5)

# ======================= LINUX / HPC =======================
box(930, 792, 570, 84, fc="white", ec=LNX)
text(950, 862, "Login / submit node", size=12.4, w="bold")
text(950, 835, "•  sybil kinit user@REALM   •   sbatch --kerberos=yes", size=10.8)

box(930, 452, 570, 318, fc="#FFF8EE", ec=ACCENT, lw=2.6)
text(950, 754, "Sybil (sybild) — S4U client of AD  (root)", size=13.2, w="bold", c=ACCENT)
text(950, 722, "•  REMOTE client of AD — NOT co-located with the KDC\n"
               "•  impersonates users: S4U2Self + S4U2Proxy (GSSAPI)\n"
               "•  sybil SERVICE account + keytab in AD (not a KDC)\n"
               "•  sybil CLI  •  KCM credential store (Linux-side)\n"
               "•  ACLs in /etc/sybil.toml",
     size=10.7, ls=1.5)
box(950, 468, 530, 74, fc="#FDF1E3", ec=WARN, lw=1.2, r=0.04)
text(966, 528, "changed from stock Sybil:", size=9.6, w="bold", c=WARN)
text(966, 508, "•  no “alongside the KDC” (AD DC is Windows) → remote client\n"
               "•  no MIT LDAP backend → AD’s msDS-AllowedToDelegateTo instead",
     size=9.3, c=WARN, ls=1.4)

box(930, 300, 270, 120, fc="white", ec=LNX)
text(950, 405, "Compute nodes cnNNN", size=11.8, w="bold")
text(950, 378, "SPANK plugin:\nforward + renew job\ncreds (from KCM)", size=10.4, ls=1.4)

box(1230, 300, 270, 120, fc="white", ec=LNX)
text(1250, 405, "Shared store / home", size=11.8, w="bold")
text(1250, 378, "KCM or $HOME ccache\nvisible to the job\n(service tickets)", size=10.4, ls=1.4)

box(930, 150, 570, 115, fc="white", ec=LNX)
text(950, 246, "Kerberized backends — Hive / HDFS  (AD realm)", size=12, w="bold")
text(950, 214, "•  accept the user's hive/_HOST service ticket (GSSAPI)\n"
               "•  verify PAC for authz (Ranger)", size=10.6, ls=1.5)

# intra-Linux
arrow((1215, 792), (1215, 770), c=LNX, lw=1.7)
text(1225, 784, "sybil / SPANK", size=9.4, c=LNX)
arrow((1065, 452), (1065, 420), c=LNX, lw=1.7)
text(1077, 440, "deliver creds", size=9.3, c=LNX)
arrow((1200, 360), (1230, 360), c=LNX, lw=1.7)
arrow((1065, 300), (1010, 265), c=LNX, lw=1.7, rad=0.2)
text(1050, 285, "use ticket (GSSAPI)", size=9.3, c=LNX, ha="left")

# ======================= CROSS-BOUNDARY S4U (lane only) =======================
text(MID, 588, "Kerberos / S4U  •  TCP 88", size=10, c=KRB, w="bold", ha="center", va="bottom", style="italic")

def kerb(y, l1, l2=None):
    arrow((LANE_R-5, y), (LANE_L+5, y), c=KRB, lw=2.2, style="<|-|>")
    text(MID, y + 10, l1, size=10, w="bold", c=KRB, ha="center", va="bottom")
    if l2:
        text(MID, y - 8, l2, size=8.6, c=KRB, ha="center", va="top")

kerb(548, "①  kinit -k  →  sybil svc TGT", "(sybil keytab)")
kerb(498, "②  S4U2Self  →  evidence ticket")
kerb(455, "③  S4U2Proxy  →  Hive/HDFS tkts", "(for <user>)")

# ---------- legend ----------
box(40, 14, 1480, 40, fc="#FBFCFE", ec="#D7DEE7", lw=1.2, r=0.08)
ly = 34; x = 70
for col, lab in [(KRB, "Kerberos / S4U across boundary (TCP 88)"),
                 (LNX, "local / credential-delivery path"),
                 (WARN, "what changes from stock Sybil")]:
    ax.add_line(Line2D([x, x+38], [ly, ly], color=col, lw=2.6, zorder=6))
    text(x+46, ly, lab, size=10.3, va="center"); x += 46 + len(lab)*6.9 + 40
text(x, ly, "Focal: sybild (amber)", size=10.3, c=ACCENT, w="bold", va="center")
text(1508, 34, "Source: github.com/NVIDIA/sybil + MS-SFU", size=9, c=SUB, ha="right", va="center", style="italic")

for ext in ("svg", "png", "pdf"):
    fig.savefig(f"docs/sybil-on-ad-architecture.{ext}", facecolor="white", pad_inches=0)
print("wrote docs/sybil-on-ad-architecture.{svg,png,pdf}")
