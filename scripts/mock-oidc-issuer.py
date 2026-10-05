#!/usr/bin/env python3
"""The mock OpenID Connect issuer of the P6.5 interop (stdlib + openssl CLI).

Modes:
  serve  the issuer endpoints on the loopback: discovery, jwks,
         /authorize (the 302 redirect with the code) and /token
         (the PKCE S256 check, the RS256 id_token via openssl dgst)
  mint   one id_token of the same key straight to stdout (the e2e
         negatives: the tampered, the expired, the wrong-nonce token
         ride the client --oidc-token bypass)

No pip: python3 stdlib plus the openssl binary for the key and the
signature. The issuer speaks plain http (the loopback test shape).
"""

import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KID = "mock-rsa-1"

# the issued codes: code -> the bound authorize parameters
CODES = {}


def die(msg):
    sys.stderr.write("mock-oidc-issuer: %s\n" % msg)
    sys.exit(1)


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def run_openssl(args, stdin=None):
    res = subprocess.run(
        ["openssl"] + args, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if res.returncode != 0:
        die("openssl %s failed: %s" % (args[0], res.stderr.decode(errors="replace").strip()))
    return res.stdout


def ensure_key(key_path):
    """The RSA key of the issuer, generated once per keys dir."""
    if not os.path.exists(key_path):
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        run_openssl(["genrsa", "-out", key_path, "2048"])
    return key_path


def public_jwk(key_path):
    """The RSA JWK of the key: the PKCS#1 RSAPublicKey DER (n, e)."""
    der = run_openssl(
        ["rsa", "-in", key_path, "-RSAPublicKey_out", "-outform", "DER"]
    )
    body = parse_der_sequence(der)
    n, e = body
    return {
        "kty": "RSA",
        "kid": KID,
        "n": b64url(n),
        "e": b64url(e),
    }


def parse_der_sequence(der):
    """The minimal walk: SEQUENCE { INTEGER, INTEGER } of the pubkey."""
    if der[0] != 0x30:
        die("expected the pubkey SEQUENCE")
    pos = read_len(der, 1)[0]
    vals = []
    for _ in range(2):
        if der[pos] != 0x02:
            die("expected an INTEGER in the pubkey")
        pos, n = read_len(der, pos + 1)
        vals.append(der[pos : pos + n])
        pos += n
    return vals


def read_len(der, pos):
    first = der[pos]
    if first < 0x80:
        return pos + 1, first
    nbytes = first & 0x7F
    length = int.from_bytes(der[pos + 1 : pos + 1 + nbytes], "big")
    return pos + 1 + nbytes, length


def rs256_sign(key_path, signing_input):
    sig = run_openssl(
        ["dgst", "-sha256", "-sign", key_path], stdin=signing_input.encode()
    )
    return b64url(sig)


def make_id_token(key_path, issuer, audience, nonce, ttl, subject="tester"):
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": KID}
    payload = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "exp": now + ttl,
        "iat": now,
        "nonce": nonce,
    }
    head = b64url(json.dumps(header, separators=(",", ":")).encode())
    body = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = head + "." + body
    return signing_input + "." + rs256_sign(key_path, signing_input)


class IssuerHandler(BaseHTTPRequestHandler):
    issuer = ""
    key_path = ""
    token_ttl = 600
    nonce_override = None
    client_id = None

    def log_message(self, fmt, *args):  # quieter e2e logs
        sys.stderr.write("mock-oidc: %s\n" % (fmt % args))

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _form(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode()).items()}

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path
        if route == "/.well-known/openid-configuration":
            self._send_json(
                {
                    "issuer": self.issuer,
                    "authorization_endpoint": self.issuer + "/authorize",
                    "token_endpoint": self.issuer + "/token",
                    "jwks_uri": self.issuer + "/jwks.json",
                }
            )
            return
        if route == "/jwks.json":
            self._send_json({"keys": [public_jwk(self.key_path)]})
            return
        if route == "/authorize":
            q = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
            code = secrets.token_urlsafe(24)
            CODES[code] = {
                "nonce": q.get("nonce", ""),
                "challenge": q.get("code_challenge", ""),
                "method": q.get("code_challenge_method", ""),
                "redirect_uri": q.get("redirect_uri", ""),
                "client_id": q.get("client_id", ""),
            }
            sep = "&" if "?" in CODES[code]["redirect_uri"] else "?"
            location = "%s%scode=%s&state=%s" % (
                CODES[code]["redirect_uri"],
                sep,
                urllib.parse.quote(code),
                urllib.parse.quote(q.get("state", "")),
            )
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send_json({"error": "not_found"}, status=404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/token":
            self._send_json({"error": "not_found"}, status=404)
            return
        form = self._form()
        code = form.get("code", "")
        bound = CODES.pop(code, None)
        if bound is None:
            self._send_json({"error": "invalid_grant"}, status=400)
            return
        if self.client_id and form.get("client_id", "") != self.client_id:
            self._send_json({"error": "unauthorized_client"}, status=400)
            return
        if bound["client_id"] and form.get("client_id", "") != bound["client_id"]:
            self._send_json({"error": "unauthorized_client"}, status=400)
            return
        if form.get("redirect_uri", "") != bound["redirect_uri"]:
            self._send_json({"error": "invalid_grant"}, status=400)
            return
        verifier = form.get("code_verifier", "")
        if bound["method"] == "S256":
            want = b64url(hashlib.sha256(verifier.encode()).digest())
            if want != bound["challenge"]:
                self._send_json({"error": "invalid_grant"}, status=400)
                return
        nonce = bound["nonce"]
        if self.nonce_override is not None:
            nonce = self.nonce_override
        token = make_id_token(
            self.key_path, self.issuer, form.get("client_id", ""), nonce, self.token_ttl
        )
        self._send_json(
            {"access_token": "mock-access", "id_token": token, "token_type": "Bearer"}
        )


def cmd_serve(args):
    key_path = ensure_key(os.path.join(args.keys, "issuer-key.pem"))
    server = ThreadingHTTPServer(("127.0.0.1", args.port), IssuerHandler)
    port = server.server_address[1]
    IssuerHandler.issuer = "http://127.0.0.1:%d" % port
    IssuerHandler.key_path = key_path
    IssuerHandler.token_ttl = args.token_ttl
    IssuerHandler.nonce_override = args.nonce_override
    IssuerHandler.client_id = args.client_id
    print("MOCK-OIDC-LISTEN port=%d" % port, flush=True)
    print("MOCK-OIDC-ISSUER %s" % IssuerHandler.issuer, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def cmd_mint(args):
    key_path = args.key or os.path.join(args.keys, "issuer-key.pem")
    if not os.path.exists(key_path):
        die("no key at %s (start the serve mode first or pass --key)" % key_path)
    print(make_id_token(key_path, args.issuer, args.audience, args.nonce, args.ttl))


def main():
    parser = argparse.ArgumentParser(description="mock OIDC issuer (stdlib + openssl)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="run the issuer endpoints")
    serve.add_argument("--port", type=int, default=0, help="listen port, 0 picks one")
    serve.add_argument("--keys", default="/tmp/mock-oidc-keys", help="the keys dir")
    serve.add_argument("--token-ttl", type=int, default=600, help="id_token exp offset")
    serve.add_argument("--nonce-override", default=None, help="bind this wrong nonce")
    serve.add_argument("--client-id", default=None, help="restrict the client id")
    serve.set_defaults(func=cmd_serve)

    mint = sub.add_parser("mint", help="print one id_token")
    mint.add_argument("--key", default=None, help="the issuer key PEM")
    mint.add_argument("--keys", default="/tmp/mock-oidc-keys", help="the keys dir fallback")
    mint.add_argument("--issuer", required=True)
    mint.add_argument("--audience", required=True)
    mint.add_argument("--nonce", default="")
    mint.add_argument("--ttl", type=int, default=600, help="id_token exp offset")
    mint.set_defaults(func=cmd_mint)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
