#!/usr/bin/env python3
"""
browser.py - Selenium solver for the SPA-route-access challenges.

A few challenges are only detected once their Angular page is actually rendered
(privacy policy, token sale, web3 sandbox, admin section). Those need a real
browser. The DOM-XSS / SVG-injection / close-notifications challenges are handled
without a browser by realtime.py (direct socket.io emits), so they are not here.

Run standalone:      python3 browser.py --host localhost --port 3000
Via the main runner: python3 solve.py --browser

Requires: selenium (Selenium Manager auto-provisions chromedriver for the local
Chrome install; no manual driver setup needed).
"""
from __future__ import annotations

import time

from core import Config, Client, Challenges, ok, warn, fail, log

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    _HAVE_SELENIUM = True
except Exception:  # noqa
    _HAVE_SELENIUM = False

# SPA routes whose mere (authenticated) rendering solves a challenge.
ROUTES = [
    ("privacyPolicyChallenge", "/#/privacy-security/privacy-policy"),
    ("tokenSaleChallenge", "/#/tokensale-ico-ea"),
    ("web3SandboxChallenge", "/#/web3-sandbox"),
    ("adminSectionChallenge", "/#/administration"),
]


def _driver():
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1280,900")
    opts.set_capability("unhandledPromptBehavior", "accept")
    return webdriver.Chrome(options=opts)


def run(cfg: Config):
    if not _HAVE_SELENIUM:
        fail("selenium not installed - run: pip install selenium")
        return
    client = Client(cfg)
    ch = Challenges(client)
    ch.refresh()
    base = cfg.base

    try:
        d = _driver()
    except Exception as e:  # noqa
        fail(f"could not start headless Chrome: {e}")
        return

    log("\n\033[1m▶ Browser-driven (SPA-route) challenges\033[0m")
    try:
        # authenticate the SPA by seeding a valid admin JWT into storage
        client.login("admin@juice-sh.op", "admin123")
        d.get(base + "/")
        time.sleep(1)
        d.execute_script("window.localStorage.setItem('token', arguments[0]);", client.token)

        for _key, route in ROUTES:
            d.get(base + route)
            time.sleep(2.5)
            ok(f"visited {route}")
        time.sleep(1.5)
    finally:
        d.quit()

    ch.refresh()
    log("\n\033[1mBrowser run complete.\033[0m")
    for key, _route in ROUTES:
        state = "\033[92msolved\033[0m" if ch.solved(key) else "\033[93munsolved\033[0m"
        log(f"   {key:<40} {state}")


if __name__ == "__main__":
    run(Config.from_args())
