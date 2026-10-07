#!/usr/bin/env python3
"""lakeFS credential broker.

Bridges a Kerberos identity to a SHORT-LIVED lakeFS access key so a Slurm/Spark
job (which holds only a krb-credd-minted service ticket) can reach lakeFS
Enterprise over S3A.

Trust model
-----------
This Flask app does NOT speak GSSAPI itself. In production it runs *behind
Apache + mod_auth_gssapi*, which performs the SPNEGO handshake against the
broker's HTTP/<host> keytab and passes the authenticated client principal to
this app as REMOTE_USER. The app therefore:

  1. reads the already-authenticated principal (REMOTE_USER),
  2. maps it to a lakeFS user (auth_to_local-style: strip @REALM),
  3. calls the lakeFS Auth API to MINT a fresh access key for that user,
  4. returns {access_key_id, secret_access_key, expiry, lakefs_user}.

SECURITY: because it trusts REMOTE_USER, this app MUST only be reachable through
the mod_auth_gssapi reverse proxy. Bind it to 127.0.0.1 and/or set
BROKER_TRUSTED_PROXIES to the proxy's address(es). Never expose it directly.

Config (environment)
--------------------
  BROKER_LISTEN              host:port to bind (default 127.0.0.1:8640)
  BROKER_REMOTE_USER_SOURCE  "environ" (default; REMOTE_USER from WSGI, set by
                             mod_auth_gssapi) or "header:X-Remote-User" (reverse
                             proxy sets it; only safe with BROKER_TRUSTED_PROXIES)
  BROKER_TRUSTED_PROXIES     comma-separated client IPs allowed to set the header
                             (required when source is header:*)
  BROKER_REALM               Kerberos realm to strip for auth_to_local (optional)
  BROKER_USER_MAP            optional file: "<principal-or-user>  <lakefs-user>"
  LAKEFS_ENDPOINT            e.g. https://lakefs.corp.example.mil:8000
  LAKEFS_ADMIN_ACCESS_KEY_ID / LAKEFS_ADMIN_SECRET_ACCESS_KEY  admin creds
  LAKEFS_VERIFY_TLS          "1" (default) / "0"
  KEY_TTL_SECONDS            expiry hint returned to the provider (default 3600)

Dependencies: Flask, requests (stdlib otherwise). No GSSAPI library needed.
"""
from __future__ import annotations

import os
import time
import logging
from datetime import datetime, timezone, timedelta

import requests
from flask import Flask, request, jsonify, abort

log = logging.getLogger("lakefs-cred-broker")
app = Flask(__name__)


def _cfg(name, default=None, required=False):
    v = os.environ.get(name, default)
    if required and not v:
        raise SystemExit(f"missing required env {name}")
    return v


class Config:
    listen = _cfg("BROKER_LISTEN", "127.0.0.1:8640")
    source = _cfg("BROKER_REMOTE_USER_SOURCE", "environ")
    trusted_proxies = {p.strip() for p in _cfg("BROKER_TRUSTED_PROXIES", "").split(",") if p.strip()}
    realm = _cfg("BROKER_REALM", "")
    user_map_file = _cfg("BROKER_USER_MAP", "")
    lakefs_endpoint = _cfg("LAKEFS_ENDPOINT", "http://127.0.0.1:8000").rstrip("/")
    admin_key = _cfg("LAKEFS_ADMIN_ACCESS_KEY_ID", "")
    admin_secret = _cfg("LAKEFS_ADMIN_SECRET_ACCESS_KEY", "")
    verify_tls = _cfg("LAKEFS_VERIFY_TLS", "1") != "0"
    key_ttl = int(_cfg("KEY_TTL_SECONDS", "3600"))


def _load_user_map(path: str) -> dict:
    m = {}
    if not path:
        return m
    with open(path) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            a, b = line.split()[:2]
            m[a] = b
    return m


USER_MAP = _load_user_map(Config.user_map_file)


def authenticated_principal() -> str:
    """The principal mod_auth_gssapi authenticated (never taken from the body)."""
    if Config.source.startswith("header:"):
        # reverse-proxy mode: only trust the header from an allow-listed proxy
        peer = request.remote_addr
        if Config.trusted_proxies and peer not in Config.trusted_proxies:
            log.warning("rejecting %s header from untrusted peer %s", Config.source, peer)
            abort(403)
        header = Config.source.split(":", 1)[1]
        princ = request.headers.get(header, "")
    else:
        princ = request.environ.get("REMOTE_USER", "")
    if not princ:
        abort(401, "no authenticated principal (is mod_auth_gssapi in front?)")
    return princ


def map_to_lakefs_user(principal: str) -> str:
    if principal in USER_MAP:
        return USER_MAP[principal]
    local = principal.split("@", 1)[0]          # auth_to_local: strip @REALM
    if principal in (local, f"{local}@{Config.realm}"):
        return USER_MAP.get(local, local)
    return USER_MAP.get(local, local)


def mint_lakefs_key(lakefs_user: str) -> dict:
    """POST /api/v1/auth/users/{user}/credentials on lakeFS (admin-authenticated).
    Returns lakeFS CredentialsWithSecret {access_key_id, secret_access_key, ...}."""
    url = f"{Config.lakefs_endpoint}/api/v1/auth/users/{lakefs_user}/credentials"
    r = requests.post(url, auth=(Config.admin_key, Config.admin_secret),
                      verify=Config.verify_tls, timeout=15)
    if r.status_code == 404:
        abort(404, f"lakeFS user {lakefs_user!r} not found (provision it, or enable auto-create)")
    if r.status_code >= 300:
        log.error("lakeFS create-credentials failed %s: %s", r.status_code, r.text[:300])
        abort(502, "lakeFS credential creation failed")
    return r.json()


@app.get("/healthz")
def healthz():
    return jsonify(status="ok", lakefs=Config.lakefs_endpoint)


@app.post("/credentials")
def credentials():
    principal = authenticated_principal()
    lakefs_user = map_to_lakefs_user(principal)
    key = mint_lakefs_key(lakefs_user)
    expiry = datetime.now(timezone.utc) + timedelta(seconds=Config.key_ttl)
    log.info("issued lakeFS key for principal=%s -> user=%s akid=%s",
             principal, lakefs_user, key.get("access_key_id"))
    return jsonify(
        access_key_id=key["access_key_id"],
        secret_access_key=key["secret_access_key"],
        lakefs_user=lakefs_user,
        principal=principal,
        expiry=expiry.isoformat(),
    )


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    host, _, port = Config.listen.partition(":")
    if Config.source.startswith("header:") and not Config.trusted_proxies:
        log.warning("REMOTE_USER source is a header but BROKER_TRUSTED_PROXIES is "
                    "empty -- only use this behind an isolated reverse proxy")
    log.info("lakeFS credential broker on %s (lakeFS=%s, source=%s)",
             Config.listen, Config.lakefs_endpoint, Config.source)
    app.run(host=host or "127.0.0.1", port=int(port or "8640"))


if __name__ == "__main__":
    main()
