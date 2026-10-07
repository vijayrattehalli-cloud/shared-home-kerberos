#!/usr/bin/env python3
"""Generate the krb-credd cross-boundary architecture diagram.

krb-credd (the Linux-side credential broker daemon) is an MIT krb5 CLIENT of
Active Directory -- it has NO KDC or realm of its own. It sits in the HPC/Linux
trust boundary and talks Kerberos across the realm edge to the AD KDC in the
Windows boundary, minting per-user service tickets by constrained delegation
(S4U2Self + S4U2Proxy). Renders docs/krb-credd-architecture.{svg,png,pdf}.

(The box was previously labeled "Sybil". It is relabeled here because it runs in
S4U client mode against AD -- not Sybil's native KDC-adjacent design, which
assumes an MIT/FreeIPA KDC the daemon sits next to. AD is the sole KDC.)

Layout rule that keeps it legible: the two trust boundaries are wide zone boxes
with a clear CENTER LANE between them; every cross-boundary arrow and its label
lives entirely inside that lane, never over zone text.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Circle
from matplotlib.lines import Line2D

W, H = 1560, 1000
WIN, LNX, ACCENT = "#2F6FB0", "#2E8B57", "#C77D0A"
WIN_FILL, LNX_FILL = "#EAF2FB", "#EAF6EE"
INK, SUB, RED, KRB = "#1A2330", "#5A6675", "#C0392B", "#1F4E79"
LANE_L, LANE_R, MID = 650, 910, 780   # center lane bounds and boundary x

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
text(W/2, 977, "krb-credd Credential Broker — Linux Kerberos CLIENT ↔ Active Directory KDC",
     size=20, w="bold", ha="center")
text(W/2, 948, "The broker is an MIT krb5 CLIENT of AD (no KDC of its own); it mints per-user service tickets by constrained delegation (S4U) across the realm edge",
     size=11.5, c=SUB, ha="center")
text(W/2, 928, "(the broker runs in S4U client mode against AD — not Sybil's native KDC-adjacent design; AD is the sole KDC)",
     size=9.5, c=SUB, ha="center", style="italic")

# ---------- zone backgrounds ----------
box(40, 70, 610, 848, fc=WIN_FILL, ec=WIN, lw=2.2, r=0.012, z=1)
box(910, 70, 610, 848, fc=LNX_FILL, ec=LNX, lw=2.2, r=0.012, z=1)
text(58, 905, "WINDOWS BOUNDARY  •  Active Directory domain", size=12.5, w="bold", c=WIN)
text(928, 905, "LINUX BOUNDARY  •  HPC cluster (UID / GID)", size=12.5, w="bold", c=LNX)

# ---------- center lane + trust boundary ----------
ax.add_line(Line2D([MID, MID], [60, 918], color="#8A99AB", lw=2.0, ls=(0, (6, 5)), zorder=3))
ax.text(MID, 90, "TRUST  BOUNDARY", rotation=90, fontsize=9.5,
        color="#6B7A8D", ha="center", va="bottom", fontweight="bold", zorder=6)

# ======================= WINDOWS SIDE =======================
box(70, 822, 230, 60, fc="white", ec=WIN, lw=1.4)
text(185, 852, "CAC / PIV smartcard", size=12, w="bold", ha="center", va="center")

box(70, 648, 560, 150, fc="white", ec=WIN)
text(90, 784, "User Windows workstation  (AD-joined)", size=12.8, w="bold")
text(90, 752, "•  CAC logon  →  PKINIT  →  user TGT (held locally)\n"
              "•  the user TGT stays on Windows", size=11.3)
text(90, 682, "✗  SSH GSSAPI credential forwarding is BLOCKED", size=11.3, w="bold", c=RED)

box(70, 150, 560, 430, fc="white", ec=WIN, lw=2.0)
text(90, 562, "Active Directory Domain Controller — KDC", size=13.5, w="bold", c=WIN)
text(90, 527, "•  AS / TGS   (Kerberos, TCP 88)\n"
              "•  kadmin  •  LDAP  •  DNS\n"
              "•  PAC signing & validation  (KB5008380)", size=11.3, ls=1.45)
box(90, 170, 520, 170, fc="#F4F8FD", ec=WIN, lw=1.3, r=0.03)
text(108, 322, "Delegation policy  (authorizes the broker's S4U)", size=11.6, w="bold", c=WIN)
text(108, 292, "•  msDS-AllowedToDelegateTo = { hive/…, hdfs/… }\n"
               "      ← the S4U allow-list (the boundary of trust)\n"
               "•  broker: TrustedToAuthForDelegation (protocol transition)\n"
               "•  users: delegation-eligible (not Protected Users)", size=10.6, ls=1.5)

# intra-Windows: CAC -> workstation -> KDC
arrow((185, 822), (185, 798), c=WIN, lw=1.7)
arrow((320, 648), (320, 580), c=WIN, lw=1.7)
text(332, 622, "PKINIT (CAC)\n→ user TGT", size=9.8, c=WIN)

# ======================= LINUX SIDE =======================
box(930, 800, 570, 88, fc="white", ec=LNX)
text(950, 874, "Login node  —  sshd / PAM", size=12.6, w="bold")
text(950, 846, "•  CAC-gated OS login (UID / GID only)\n"
               "•  the node itself knows no Kerberos", size=11)

box(930, 452, 570, 300, fc="#FFF8EE", ec=ACCENT, lw=2.6)
text(950, 738, "krb-credd — Kerberos client broker  (root)", size=13.5, w="bold", c=ACCENT)
text(950, 706, "•  MIT krb5 CLIENT of AD — NO KDC / realm of its own\n"
               "      (libkrb5 / GSSAPI • broker keytab • krb5.conf • ccache)\n"
               "•  holds ONE broker keytab  (gMSA / HSM-backable)\n"
               "•  broker TGT:  kinit -k  (renewable, unattended)\n"
               "•  mints per-user SERVICE tickets  (S4U2Self + S4U2Proxy)\n"
               "•  installs as the user  (setpriv → $HOME, 0600)\n"
               "•  front door: UNIX socket, SO_PEERCRED  ◀  krb-get",
     size=10.6, ls=1.45)

box(930, 300, 270, 120, fc="white", ec=LNX)
text(950, 405, "Shared filesystem home", size=11.8, w="bold")
text(950, 378, "$HOME/.krb5/krb5cc_hpc\n(0700 dir / 0600 file)\nservice tickets — no TGT", size=10.6, ls=1.4)

box(1230, 300, 270, 120, fc="white", ec=LNX)
text(1250, 405, "Compute nodes cn001..cnNNN", size=11.8, w="bold")
text(1250, 378, "Slurm TaskProlog →\nKRB5CCNAME points here\n(every node, same cache)", size=10.6, ls=1.4)

box(930, 150, 570, 115, fc="white", ec=LNX)
text(950, 246, "Kerberized backends — Hive / HDFS  (AD realm)", size=12.2, w="bold")
text(950, 214, "•  accept the user's hive/_HOST service ticket (GSSAPI)\n"
               "•  verify with own service key; check PAC for authz (Ranger)", size=10.8, ls=1.5)

# intra-Linux arrows
arrow((1215, 800), (1215, 752), c=LNX, lw=1.7)
text(1225, 782, "krb-get  (UNIX socket, GET)", size=9.8, c=LNX)
arrow((1010, 452), (1010, 420), c=LNX, lw=1.7)
text(1022, 440, "write as user (setpriv)", size=9.6, c=LNX)
arrow((1200, 360), (1230, 360), c=LNX, lw=1.7)
text(1215, 372, "shared\nmount", size=9.2, c=LNX, ha="center", va="bottom")
arrow((1365, 300), (1230, 265), c=LNX, lw=1.7, rad=-0.2)
text(1375, 286, "use service\nticket (GSSAPI)", size=9.6, c=LNX)

# ======================= CROSS-BOUNDARY (in the lane only) =======================
text(MID, 586, "Kerberos  •  TCP 88", size=10, c=KRB, w="bold", ha="center", va="bottom", style="italic")

def kerb(y, l1, l2=None):
    arrow((LANE_R-5, y), (LANE_L+5, y), c=KRB, lw=2.2, style="<|-|>")
    text(MID, y + 10, l1, size=10, w="bold", c=KRB, ha="center", va="bottom")
    if l2:
        text(MID, y - 8, l2, size=8.6, c=KRB, ha="center", va="top")

kerb(548, "①  kinit -k  →  broker TGT", "(broker keytab)")
kerb(498, "②  S4U2Self  →  evidence ticket")
kerb(455, "③  S4U2Proxy  →  Hive/HDFS tkts", "(for <user>)")

# BLOCKED path across the lane (workstation TGT does not reach Linux)
arrow((LANE_L+5, 700), (LANE_R-5, 700), c=RED, lw=1.9, style="-|>", ls=(0, (5, 4)))
ax.add_patch(Circle((MID, 700), 12, fill=False, ec=RED, lw=2.2, zorder=7))
ax.add_line(Line2D([MID-8.5, MID+8.5], [700-8.5, 700+8.5], color=RED, lw=2.2, zorder=8))
text(MID, 732, "user TGT not forwarded\n(SSH GSSAPI blocked)\n— why the broker exists",
     size=9.4, w="bold", c=RED, ha="center", va="bottom", ls=1.3)

# faint validation: services -> KDC across the lane
arrow((LANE_R-5, 198), (LANE_L+5, 300), c="#9AA7B5", lw=1.4, style="-|>", ls=(0, (3, 3)), rad=0.12)
text(MID, 170, "service-ticket /\nPAC validation", size=9, c="#8290A0", ha="center", va="top", ls=1.3)

# ---------- legend ----------
box(40, 14, 1480, 40, fc="#FBFCFE", ec="#D7DEE7", lw=1.2, r=0.08)
ly = 34; x = 66
for col, st, lab in [
        (KRB, "-", "Kerberos across boundary (TCP 88)"),
        (LNX, "-", "local / shared-filesystem path"),
        (RED, (0, (5, 4)), "blocked path (what the design works around)"),
        ("#9AA7B5", (0, (3, 3)), "validation")]:
    ax.add_line(Line2D([x, x+38], [ly, ly], color=col, lw=2.4, ls=st, zorder=6))
    text(x+46, ly, lab, size=10.3, va="center"); x += 46 + len(lab)*6.9 + 34
text(x, ly, "Focal node: krb-credd (amber)", size=10.3, c=ACCENT, w="bold", va="center")

for ext in ("svg", "png", "pdf"):
    fig.savefig(f"docs/krb-credd-architecture.{ext}", facecolor="white", pad_inches=0)
print("wrote docs/krb-credd-architecture.{svg,png,pdf}")
