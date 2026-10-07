#!/usr/bin/env python3
"""Minimal stand-in for the lakeFS Auth API, for the broker e2e test only.

Implements just POST /api/v1/auth/users/{user}/credentials -> a fake
CredentialsWithSecret, and records the last call to a file so the test can
assert the broker mapped the Kerberos principal to the right lakeFS user and
presented admin auth. Standard library only; NOT lakeFS.
"""
import base64
import json
import os
import secrets
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RECORD = os.environ.get("MOCK_LAKEFS_RECORD", "/tmp/mock_lakefs_last.json")
ADMIN_KEY = os.environ.get("MOCK_LAKEFS_ADMIN_KEY", "")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            return self._json(200, {"status": "ok"})
        self._json(404, {"message": "not found"})

    def do_POST(self):
        parts = self.path.strip("/").split("/")
        # /api/v1/auth/users/{user}/credentials
        if len(parts) == 6 and parts[:3] == ["api", "v1", "auth"] and \
                parts[3] == "users" and parts[5] == "credentials":
            user = parts[4]
            auth = self.headers.get("Authorization", "")
            admin_seen = ""
            if auth.startswith("Basic "):
                try:
                    admin_seen = base64.b64decode(auth[6:]).decode().split(":", 1)[0]
                except Exception:
                    admin_seen = "(unparseable)"
            # enforce admin auth if the test configured one
            if ADMIN_KEY and admin_seen != ADMIN_KEY:
                return self._json(401, {"message": "unauthorized (admin auth required)"})
            akid = "AKIAMOCK" + secrets.token_hex(8).upper()
            secret = secrets.token_urlsafe(30)
            with open(RECORD, "w") as fh:
                json.dump({"user": user, "admin": admin_seen, "ts": time.time()}, fh)
            return self._json(201, {
                "access_key_id": akid,
                "secret_access_key": secret,
                "creation_date": int(time.time()),
            })
        self._json(404, {"message": "not found"})


def main():
    host, port = os.environ.get("MOCK_LAKEFS_LISTEN", "127.0.0.1:8000").split(":")
    srv = ThreadingHTTPServer((host, int(port)), H)
    print(f"mock-lakeFS on {host}:{port}", file=sys.stderr, flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
