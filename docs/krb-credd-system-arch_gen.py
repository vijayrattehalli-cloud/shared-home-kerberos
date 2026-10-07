#!/usr/bin/env python3
"""Canonical end-to-end system architecture for the krb-credd solution.

krb-credd -- a Kerberos client broker (root) -- authenticates to Active Directory
with one broker keytab, mints each user's SERVICE tickets by S4U constrained
delegation, installs them (as the user) into shared-home, and the Slurm
TaskProlog makes them visible on every compute node. AD is the single KDC.

Renders docs/krb-credd-system-architecture.{svg,png,pdf}.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Circle
from matplotlib.lines import Line2D

W, H = 1600, 1040
WIN, LNX, ACCENT, FS = "#2F6FB0", "#2E8B57", "#C77D0A", "#6D4FA1"
INK, SUB = "#1A2330", "#5A6675"
WIN_FILL, LNX_FILL, FS_FILL = "#EAF2FB", "#EAF6EE", "#F3EFFA"

fig = plt.figure(figsize=(16, 10.4), dpi=100)
ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, W); ax.set_ylim(0, H); ax.axis("off")
fig.patch.set_facecolor("white")


def box(x, y, w, h, *, fc="white", ec=INK, lw=1.6, r=0.02, z=2):
    ax.add_patch(FancyBboxPatch((x, y), w, h, fc=fc, ec=ec, lw=lw, zorder=z,
                 boxstyle=f"round,pad=0,rounding_size={r*min(w,h)}"))


def text(x, y, s, *, size=12, c=INK, w="normal", ha="left", va="top", z=5, ls=1.35, **kw):
    ax.text(x, y, s, fontsize=size, color=c, fontweight=w, ha=ha, va=va, zorder=z,
            linespacing=ls, fontfamily=["DejaVu Sans", "Arial", "sans-serif"], **kw)


def arrow(p0, p1, *, c=INK, lw=2.2, style="-|>", rad=0.0, z=4, ls="-"):
    ax.add_patch(FancyArrowPatch(p0, p1, arrowstyle=style, mutation_scale=17,
                 lw=lw, color=c, zorder=z, linestyle=ls,
                 connectionstyle=f"arc3,rad={rad}", shrinkA=2, shrinkB=2))


def cnum(x, y, n, c=INK, rad=15):
    ax.add_patch(Circle((x, y), rad, fc="white", ec=c, lw=2.2, zorder=8))
    text(x, y, n, size=12, c=c, w="bold", ha="center", va="center", z=9)


# ---------- title ----------
text(W/2, 1014, "krb-credd — Kerberos Client Broker (root): System Architecture",
     size=21, w="bold", ha="center")
text(W/2, 986, "One broker keytab → S4U service tickets from Active Directory → installed as the user into shared-home → visible on every Slurm compute node",
     size=12, c=SUB, ha="center")

# ---------- AD KDC (top) ----------
box(430, 852, 620, 112, fc=WIN_FILL, ec=WIN, lw=2.2, r=0.04)
text(740, 944, "Active Directory — KDC  (Windows; single realm)", size=13.5, w="bold", c=WIN, ha="center")
text(740, 916, "issues every ticket  •  authorizes constrained delegation via msDS-AllowedToDelegateTo\n"
               "native S4U (MS-SFU) + PAC (KB5008380)  —  krb-credd holds NO KDC key material",
     size=10.6, c=INK, ha="center", ls=1.5)

# ---------- user + CAC (top-left) ----------
box(40, 790, 250, 52, fc="#FBFCFE", ec=SUB, lw=1.3, r=0.06)
text(165, 816, "User  •  CAC / PuTTY / SSH", size=11, w="bold", c=INK, ha="center", va="center")

# ---------- main pipeline row ----------
ROW_Y, ROW_H = 430, 330
# Login node
box(40, ROW_Y, 250, ROW_H, fc=LNX_FILL, ec=LNX, lw=1.8)
text(60, ROW_Y+ROW_H-22, "Login node", size=12.6, w="bold")
text(60, ROW_Y+ROW_H-52, "•  CAC-gated OS login\n•  users known by UID/GID\n"
     "•  knows no Kerberos\n•  profile.d runs krb-get", size=10.8, ls=1.6)

# krb-credd (focal)
box(350, ROW_Y-10, 380, ROW_H+20, fc="#FFF8EE", ec=ACCENT, lw=2.6)
text(540, ROW_Y+ROW_H-2, "krb-credd — Kerberos client broker (root)", size=12.6, w="bold", c=ACCENT, ha="center")
text(368, ROW_Y+ROW_H-36, "•  front door: UNIX socket, SO_PEERCRED\n"
     "•  broker TGT: kinit -k (ONE keytab, renewable)\n"
     "•  mint: S4U2Self + S4U2Proxy (kvno -U -P)\n"
     "•  install as the user: setpriv → $HOME (0600)\n"
     "•  refresh loop: squeue-watch re-mints\n"
     "•  MIT krb5 CLIENT of AD — no KDC of its own", size=10.4, ls=1.68)

# Shared FS
box(790, ROW_Y+30, 240, ROW_H-60, fc="#FBFCFE", ec="#8aa0b5", lw=1.8)
text(910, ROW_Y+ROW_H-42, "Shared filesystem", size=12, w="bold", ha="center")
text(810, ROW_Y+ROW_H-74, "$HOME/.krb5/\n   krb5cc_hpc\n\nNFS / GPFS / Lustre\n0700 dir / 0600 file\nservice tickets — no TGT",
     size=10.4, ls=1.55)

# Compute nodes
box(1090, ROW_Y, 230, ROW_H, fc=LNX_FILL, ec=LNX, lw=1.8)
text(1205, ROW_Y+ROW_H-22, "Slurm compute", size=12.4, w="bold", ha="center")
text(1110, ROW_Y+ROW_H-52, "cn001 .. cnNNN\n\n•  mounts the same\n   home on every node\n•  TaskProlog sets\n   KRB5CCNAME\n•  job runs as user",
     size=10.6, ls=1.55)

# Backends
box(1340, ROW_Y+40, 230, ROW_H-80, fc=LNX_FILL, ec=LNX, lw=1.8)
text(1455, ROW_Y+ROW_H-52, "Kerberized backends", size=11.6, w="bold", ha="center")
text(1360, ROW_Y+ROW_H-82, "Hive / HDFS\n(AD realm)\n\n•  accept hive/_HOST\n   ticket (GSSAPI)\n•  verify PAC (Ranger)",
     size=10.6, ls=1.55)

# ---------- arrows + circled step numbers ----------
my = ROW_Y + ROW_H/2
arrow((165, 790), (165, ROW_Y+ROW_H), c=SUB, lw=1.8); cnum(165, 778, "1", SUB, 13)
arrow((290, my), (350, my), c=LNX); cnum(320, my+30, "2", LNX)
# krb-credd -> AD KDC (two up arrows)
arrow((480, ROW_Y+ROW_H+10), (480, 852), c=WIN); cnum(480, 822, "3", WIN)
arrow((600, ROW_Y+ROW_H+10), (600, 852), c=WIN); cnum(600, 822, "4", WIN)
arrow((730, my), (790, my), c=ACCENT); cnum(760, my+30, "5", ACCENT)
arrow((1030, my), (1090, my), c=LNX); cnum(1060, my+30, "6", LNX)
arrow((1320, my), (1340, my), c=LNX); cnum(1330, my+34, "7", LNX)
# refresh self-loop on krb-credd
arrow((372, ROW_Y+40), (372, ROW_Y-2), c=ACCENT, lw=1.8, style="-|>", rad=-0.9)
cnum(348, ROW_Y+18, "↻", ACCENT, 13)

# ---------- flow key (bottom) ----------
box(40, 70, 1530, 300, fc="#FBFCFE", ec="#D7DEE7", lw=1.4, r=0.02)
text(60, 356, "End-to-end flow", size=12.5, w="bold", c=INK)
steps_l = [
  ("1", SUB, "CAC / PuTTY / SSH login establishes the user’s UID/GID on the login node (no Kerberos on the HPC side)."),
  ("2", LNX, "profile.d runs krb-get → krb-credd over a UNIX socket; the UID comes from SO_PEERCRED (kernel-verified, never the request)."),
  ("3", WIN, "krb-credd keeps its broker TGT fresh: kinit -k from ONE keytab (renewable, unattended) — obtained from AD."),
  ("4", WIN, "krb-credd mints the user’s SERVICE tickets: S4U2Self + S4U2Proxy (kvno -U user -P spns); AD authorizes via msDS-AllowedToDelegateTo."),
]
steps_r = [
  ("5", ACCENT, "krb-credd installs the cache AS THE USER (setpriv, atomic, 0700/0600) into $HOME/.krb5/krb5cc_hpc on shared storage."),
  ("6", LNX, "Every compute node mounts the same home; the Slurm TaskProlog points KRB5CCNAME at the cache — no copy, no node daemon."),
  ("7", LNX, "The job uses the hive/_HOST (etc.) service ticket over GSSAPI; the backend verifies it and checks the PAC (Ranger)."),
  ("↻", ACCENT, "The squeue-watch refresh loop RE-MINTS service tickets before expiry, so long or queued jobs never find them stale."),
]
import textwrap
def keycol2(x, steps, chars):
    y = 322
    for n, c, s in steps:
        cnum(x, y, n, c, 12)
        wrapped = "\n".join(textwrap.wrap(s, chars))
        text(x+26, y+13, wrapped, size=10.3, c=INK, ls=1.4)
        y -= 66
keycol2(80, steps_l, 92)
keycol2(820, steps_r, 92)

for ext in ("svg", "png", "pdf"):
    fig.savefig(f"docs/krb-credd-system-architecture.{ext}", facecolor="white", pad_inches=0)
print("wrote docs/krb-credd-system-architecture.{svg,png,pdf}")
