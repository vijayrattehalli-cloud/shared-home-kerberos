#!/usr/bin/env python3
"""Why NVIDIA/sybil's sybild cannot run as a remote Active Directory client.

Verified against the source (github.com/NVIDIA/sybil):
  - Impersonation ("sybil kinit user@REALM") always FORGES a user TGT:
    src/lib.rs:266  krb::Credentials::forge(user, "krbtgt/REALM", ...)  (no toggle)
  - The forged ticket is signed with the realm's krbtgt key, which sybild reads
    from the KDC database via kadm5:
    src/krb/krbutil.c:148-176 encrypt_ticket() -> kadm5_get_principal_keys()
    src/krb/krbutil.c:214-286 krbutil_forge_creds(); :42 kadm5_init(KADMIN_PRINCIPAL)
  - The GSSAPI S4U path (src/gss.rs:154 .impersonate) is only for sybild's
    OUTBOUND client contexts, not for minting the user's ticket.

AD exposes no kadm5/KDB key interface and never releases the krbtgt key
(extracting it is DCSync -- full domain compromise), so sybild's core operation
is impossible against AD. Renders docs/sybil-ad-incompatibility.{svg,png,pdf}.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Circle
from matplotlib.lines import Line2D

W, H = 1560, 1000
WIN, LNX, ACCENT, RED, OK = "#2F6FB0", "#2E8B57", "#C77D0A", "#C0392B", "#2E8B57"
WIN_FILL, LNX_FILL = "#EAF2FB", "#FFF8EE"
INK, SUB = "#1A2330", "#5A6675"
MID = 780

fig = plt.figure(figsize=(15.6, 10), dpi=100)
ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, W); ax.set_ylim(0, H); ax.axis("off")
fig.patch.set_facecolor("white")


def box(x, y, w, h, *, fc="white", ec=INK, lw=1.6, r=0.02, z=2):
    ax.add_patch(FancyBboxPatch((x, y), w, h, fc=fc, ec=ec, lw=lw, zorder=z,
                 boxstyle=f"round,pad=0,rounding_size={r*min(w,h)}"))


def text(x, y, s, *, size=12, c=INK, w="normal", ha="left", va="top", z=5, ls=1.35, **kw):
    ax.text(x, y, s, fontsize=size, color=c, fontweight=w, ha=ha, va=va, zorder=z,
            linespacing=ls, fontfamily=["DejaVu Sans", "Arial", "sans-serif"], **kw)


def arrow(p0, p1, *, c=INK, lw=2.0, style="-|>", rad=0.0, z=4, ls="-"):
    ax.add_patch(FancyArrowPatch(p0, p1, arrowstyle=style, mutation_scale=18,
                 lw=lw, color=c, zorder=z, linestyle=ls,
                 connectionstyle=f"arc3,rad={rad}", shrinkA=1, shrinkB=1))


# ---------- title ----------
text(W/2, 976, "Why Sybil (sybild) CANNOT run as a remote Active Directory client",
     size=20, w="bold", ha="center")
text(W/2, 947, "sybild impersonates by FORGING a TGT signed with the realm krbtgt key, which it reads from the KDC database via kadm5 — AD exposes no such interface",
     size=11.3, c=SUB, ha="center")

# ---------- zones ----------
box(40, 330, 700, 452, fc=WIN_FILL, ec=WIN, lw=2.2, r=0.015, z=1)
box(820, 330, 700, 452, fc=LNX_FILL, ec=ACCENT, lw=2.2, r=0.015, z=1)
text(58, 770, "WINDOWS  •  Active Directory", size=12.5, w="bold", c=WIN)
text(838, 770, "LINUX  •  sybild (NVIDIA/sybil)", size=12.5, w="bold", c=ACCENT)
ax.add_line(Line2D([MID, MID], [320, 792], color="#8A99AB", lw=2.0, ls=(0, (6, 5)), zorder=3))

# ---------- AD KDC (left) ----------
box(70, 360, 640, 360, fc="white", ec=WIN, lw=2.0)
text(90, 700, "Active Directory Domain Controller — KDC", size=13.5, w="bold", c=WIN)
text(90, 664,
     "•  issues tickets via the Kerberos protocol, but…\n"
     "•  exposes NO kadm5 / KDB key interface to clients\n"
     "•  the krbtgt key never leaves the domain controller\n"
     "•  pulling principal keys out of AD = DCSync\n"
     "      = full domain compromise (an attack, not an API)\n"
     "•  S4U is supported — but that is a CLIENT protocol,\n"
     "      not the key-level DB access sybild requires",
     size=11.3, ls=1.6)

# ---------- sybild (right) ----------
box(850, 360, 640, 360, fc="white", ec=ACCENT, lw=2.2)
text(870, 700, "sybild — impersonation mechanism", size=13.5, w="bold", c=ACCENT)
text(870, 664,
     "•  `sybil kinit user@REALM`  always FORGES a TGT\n"
     "      krb::Credentials::forge(user, “krbtgt/REALM”)   [lib.rs:266]\n"
     "•  signs it with the realm krbtgt key, which it reads\n"
     "      from the KDC DB:  kadm5_get_principal_keys()\n"
     "      [krbutil.c:159]  —  daemon runs kadm5_init()  [:42]\n"
     "•  no S4U-only mode — forging is unconditional\n"
     "•  ⇒ needs KDB access + co-location with an\n"
     "      MIT / FreeIPA KDC",
     size=11.3, ls=1.6)

# ---------- blocked cross-boundary ----------
arrow((850, 500), (710, 500), c=RED, lw=2.4, style="-|>", ls=(0, (5, 4)))
ax.add_patch(Circle((MID, 500), 15, fill=False, ec=RED, lw=2.6, zorder=7))
ax.add_line(Line2D([MID-10.5, MID+10.5], [500-10.5, 500+10.5], color=RED, lw=2.6, zorder=8))
text(MID, 548, "sybild asks for the\nkrbtgt key from the KDC DB", size=10, w="bold", c=RED,
     ha="center", va="bottom", ls=1.3)
text(MID, 452, "AD will never export it\n→ sybild cannot operate against AD", size=10, w="bold",
     c=RED, ha="center", va="top", ls=1.3)

# ---------- pivot: what works ----------
box(70, 120, 1420, 150, fc="#EAF6EE", ec=OK, lw=2.0, r=0.03)
text(90, 250, "What actually works against AD  →  krb-credd", size=13.5, w="bold", c=OK)
text(90, 218,
     "krb-credd is a Kerberos S4U *client* of AD: it holds a sybil-style SERVICE keytab and calls S4U2Self / S4U2Proxy over the wire — AD\n"
     "issues every ticket and authorizes delegation via msDS-AllowedToDelegateTo. No KDB access, no key reading, no co-location with the KDC.\n"
     "Same goal as Sybil (impersonate batch users), DIFFERENT and AD-supported mechanism (constrained delegation, not forging).  See docs/krb-credd-architecture.",
     size=11, c=INK, ls=1.6)

# ---------- footer / citation ----------
box(40, 14, 1480, 40, fc="#FBFCFE", ec="#D7DEE7", lw=1.2, r=0.08)
ax.add_line(Line2D([66, 104], [34, 34], color=RED, lw=2.6, ls=(0, (5, 4)), zorder=6))
text(112, 34, "blocked: key-level DB access AD does not provide", size=10.3, va="center")
text(1508, 34, "Verified in NVIDIA/sybil source — lib.rs:266, krbutil.c:42/159/214-286",
     size=9.2, c=SUB, ha="right", va="center", style="italic")

for ext in ("svg", "png", "pdf"):
    fig.savefig(f"docs/sybil-ad-incompatibility.{ext}", facecolor="white", pad_inches=0)
print("wrote docs/sybil-ad-incompatibility.{svg,png,pdf}")
