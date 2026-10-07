#!/usr/bin/env python3
"""Architecture: Slurm/Spark job authenticating to lakeFS Enterprise over S3A,
with credentials bridged from krb-credd's Kerberos ticket.

krb-credd pre-mints a service ticket for the broker SPN (HTTP/lakefs-sts) into
shared-home; a Spark S3A credentials provider SPNEGOs to a lakeFS credential
broker, which mints a SHORT-LIVED lakeFS access key via the lakeFS Enterprise
Auth API; the executor then uses that key (SigV4) against the lakeFS S3 gateway.

Renders docs/lakefs-s3a-architecture.{svg,png,pdf}.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Circle
from matplotlib.lines import Line2D
import textwrap

W, H = 1600, 1000
WIN, LNX, ACCENT, LAKE = "#2F6FB0", "#2E8B57", "#C77D0A", "#1F8A8A"
INK, SUB = "#1A2330", "#5A6675"
WIN_FILL, LNX_FILL, LAKE_FILL = "#EAF2FB", "#EAF6EE", "#E7F4F4"

fig = plt.figure(figsize=(16, 10), dpi=100)
ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, W); ax.set_ylim(0, H); ax.axis("off")
fig.patch.set_facecolor("white")


def box(x, y, w, h, *, fc="white", ec=INK, lw=1.6, r=0.02, z=2):
    ax.add_patch(FancyBboxPatch((x, y), w, h, fc=fc, ec=ec, lw=lw, zorder=z,
                 boxstyle=f"round,pad=0,rounding_size={r*min(w,h)}"))


def text(x, y, s, *, size=12, c=INK, w="normal", ha="left", va="top", z=5, ls=1.35, **kw):
    ax.text(x, y, s, fontsize=size, color=c, fontweight=w, ha=ha, va=va, zorder=z,
            linespacing=ls, fontfamily=["DejaVu Sans", "Arial", "sans-serif"], **kw)


def arrow(p0, p1, *, c=INK, lw=2.2, style="-|>", rad=0.0, z=4, ls="-"):
    ax.add_patch(FancyArrowPatch(p0, p1, arrowstyle=style, mutation_scale=16,
                 lw=lw, color=c, zorder=z, linestyle=ls,
                 connectionstyle=f"arc3,rad={rad}", shrinkA=2, shrinkB=2))


def cnum(x, y, n, c=INK, rad=14):
    ax.add_patch(Circle((x, y), rad, fc="white", ec=c, lw=2.2, zorder=8))
    text(x, y, n, size=12, c=c, w="bold", ha="center", va="center", z=9)


# ---------- title ----------
text(W/2, 975, "Slurm / Spark \u2192 lakeFS Enterprise over S3A, with krb-credd-bridged credentials",
     size=19, w="bold", ha="center")
text(W/2, 948, "krb-credd gives the job a Kerberos ticket; a credential broker trades it (SPNEGO) for a SHORT-LIVED lakeFS access key that S3A uses (SigV4)",
     size=11.3, c=SUB, ha="center")

# ---------- AD KDC (top) ----------
box(470, 846, 560, 86, fc=WIN_FILL, ec=WIN, lw=2.0, r=0.05)
text(750, 916, "Active Directory \u2014 KDC", size=12.5, w="bold", c=WIN, ha="center")
text(750, 892, "krb-credd pre-minted the HTTP/lakefs-sts service ticket via S4U\n(SPN must be in delegate_targets + msDS-AllowedToDelegateTo)",
     size=10, c=INK, ha="center", ls=1.5)

ROW_Y, ROW_H = 430, 330

# ---------- krb-credd + shared-home (left) ----------
box(40, ROW_Y, 250, ROW_H, fc=LNX_FILL, ec=LNX, lw=1.8)
text(60, ROW_Y+ROW_H-22, "krb-credd (existing)", size=12, w="bold")
text(60, ROW_Y+ROW_H-50, "mints the HTTP/lakefs-sts\nSERVICE ticket into\nshared-home", size=10.6, ls=1.5)
box(58, ROW_Y+24, 214, 96, fc="white", ec="#8aa0b5", lw=1.3, r=0.05)
text(70, ROW_Y+104, "$HOME/.krb5/krb5cc_hpc", size=10, w="bold")
text(70, ROW_Y+80, "\u2022 service ticket, NO TGT\n\u2022 present on every node\n\u2022 KRB5CCNAME points here", size=9.5, ls=1.5)

# ---------- Spark executor (focal) ----------
box(350, ROW_Y-10, 360, ROW_H+20, fc="#FFF8EE", ec=ACCENT, lw=2.6)
text(530, ROW_Y+ROW_H-2, "Slurm compute \u2014 Spark executor (as user)", size=11.6, w="bold", c=ACCENT, ha="center")
text(368, ROW_Y+ROW_H-34, "\u2022 reads KRB5CCNAME (shared-home ticket)\n"
     "\u2022 S3A custom credentials provider:\n"
     "    fs.s3a.aws.credentials.provider =\n"
     "    LakeFSKerberosCredentialProvider\n"
     "\u2022 SPNEGO \u2192 broker; cache key; refresh\n"
     "   before expiry\n"
     "\u2022 S3A SigV4 with the lakeFS key", size=10.1, ls=1.55)

# ---------- lakeFS credential broker ----------
box(770, ROW_Y+20, 300, ROW_H-40, fc=LAKE_FILL, ec=LAKE, lw=2.2)
text(920, ROW_Y+ROW_H-34, "lakeFS credential broker", size=12, w="bold", c=LAKE, ha="center")
text(788, ROW_Y+ROW_H-64, "\u2022 SPNEGO (mod_auth_gssapi)\n"
     "\u2022 verify Kerberos id \u2192 map to\n   lakeFS user\n"
     "\u2022 mint SHORT-LIVED lakeFS key\n   (Auth API / STS)\n"
     "\u2022 holds lakeFS admin cred\n   (one secret, HSM)", size=9.8, ls=1.55)

# ---------- lakeFS Enterprise (right) ----------
box(1130, ROW_Y, 430, ROW_H, fc=LAKE_FILL, ec=LAKE, lw=1.8)
text(1345, ROW_Y+ROW_H-22, "lakeFS Enterprise", size=12.4, w="bold", c=LAKE, ha="center")
box(1148, ROW_Y+ROW_H-130, 394, 78, fc="white", ec=LAKE, lw=1.3, r=0.04)
text(1162, ROW_Y+ROW_H-62, "Auth API / STS \u2014 mint access key", size=10.4, w="bold")
text(1162, ROW_Y+ROW_H-84, "short-lived { access_key_id, secret, expiry }\nRBAC = the mapped user's policies", size=9.6, ls=1.5)
box(1148, ROW_Y+20, 394, 150, fc="white", ec=LAKE, lw=1.3, r=0.04)
text(1162, ROW_Y+150, "S3 gateway  (S3 SigV4)", size=10.6, w="bold")
text(1162, ROW_Y+126, "s3a://repo/branch/path\u2026\npath-style; repo = bucket, branch = 1st path", size=9.6, ls=1.5)
text(1162, ROW_Y+78, "\u2193", size=14, c=LAKE)
text(1162, ROW_Y+56, "Object store (S3 / GCS / Azure / MinIO)", size=10, c=INK)

# ---------- arrows + numbered flow ----------
my = ROW_Y + ROW_H/2
arrow((290, my+70), (350, my+70), c=LNX); cnum(320, my+100, "1", LNX)   # krb-credd -> executor (ticket in shared home)
arrow((710, my+40), (770, my+40), c=ACCENT); cnum(740, my+72, "3", ACCENT)   # executor -> broker SPNEGO
arrow((770, my-40), (710, my-40), c=LAKE, rad=0.0); cnum(740, my-72, "5", LAKE)   # broker -> executor key
arrow((1070, my+30), (1130, my+30), c=LAKE); cnum(1100, my+60, "4", LAKE)   # broker -> lakeFS Auth API
# executor S3A -> gateway: route BELOW the broker box
arrow((706, ROW_Y+36), (1130, ROW_Y+150), c=ACCENT, lw=2.4, rad=-0.28); cnum(905, ROW_Y+6, "6", ACCENT)
# krb-credd up to AD KDC (already-minted, dashed)
arrow((165, ROW_Y+ROW_H), (470, 852), c=WIN, lw=1.5, ls=(0, (5, 4)), rad=0.12); cnum(300, 812, "0", WIN, 12)

# ---------- flow key ----------
box(40, 70, 1520, 300, fc="#FBFCFE", ec="#D7DEE7", lw=1.4, r=0.02)
text(60, 356, "Flow", size=12.5, w="bold", c=INK)
steps = [
  ("0", WIN, "(prereq) the broker SPN HTTP/lakefs-sts is in krb-credd's delegate_targets and the broker's msDS-AllowedToDelegateTo."),
  ("1", LNX, "krb-credd mints that service ticket into $HOME/.krb5/krb5cc_hpc on every node (no TGT \u2014 only pre-minted service tickets)."),
  ("2", ACCENT, "The Spark executor (running as the user) reads KRB5CCNAME; its S3A credentials provider finds the HTTP/lakefs-sts ticket."),
  ("3", ACCENT, "The provider calls the credential broker over SPNEGO (Authorization: Negotiate) \u2014 targeting exactly that SPN (no TGT to fetch another)."),
  ("4", LAKE, "The broker verifies the Kerberos identity, maps it to a lakeFS user, and mints a SHORT-LIVED lakeFS access key via the Auth API / STS."),
  ("5", LAKE, "The broker returns { access_key_id, secret_access_key, expiry }; the provider caches it and refreshes via SPNEGO before expiry."),
  ("6", ACCENT, "S3A uses the key (S3 SigV4) against the lakeFS S3 gateway: spark.read/write on s3a://repo/branch/\u2026 ; RBAC = the mapped user."),
]
colx = [80, 820]
import math
left = steps[:4]; right = steps[4:]
def col(x, rows):
    y = 322
    for n, c, s in rows:
        cnum(x, y, n, c, 12)
        text(x+24, y+13, "\n".join(textwrap.wrap(s, 86)), size=10.1, c=INK, ls=1.4)
        y -= 62
col(80, left); col(820, right)

for ext in ("svg", "png", "pdf"):
    fig.savefig(f"docs/lakefs-s3a-architecture.{ext}", facecolor="white", pad_inches=0)
print("wrote docs/lakefs-s3a-architecture.{svg,png,pdf}")
