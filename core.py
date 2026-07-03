#!/usr/bin/env python3
"""
core.py - Shared client + verification harness for the OWASP Juice Shop solver.

Rewritten for Juice Shop v20.x (Python 3). Provides:
  * Config     - target URL from CLI args / env
  * Client     - a requests.Session wrapper with login / register / JWT helpers
  * Challenges - reads /api/Challenges/ to verify what is actually solved
  * register_solver / SOLVERS - a registry so category modules can plug in

Every solver function receives a ``Client`` and returns nothing; success is
verified out-of-band by re-reading the challenge status from the server, so a
solver that "runs clean" but does not flip the challenge is still reported as
unsolved.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

import requests

requests.packages.urllib3.disable_warnings()  # tolerate self-signed https targets


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    protocol: str = "http"
    hostname: str = "localhost"
    port: int = 3000

    @property
    def base(self) -> str:
        return f"{self.protocol}://{self.hostname}:{self.port}"

    @classmethod
    def from_args(cls, argv: Optional[List[str]] = None) -> "Config":
        p = argparse.ArgumentParser(description="Run the Juice Shop solver against a target.")
        p.add_argument("--protocol", default=os.getenv("JS_PROTOCOL", "http"), help="http or https")
        p.add_argument("--hostname", default=os.getenv("JS_HOST", "localhost"), help="target host")
        p.add_argument("--port", type=int, default=int(os.getenv("JS_PORT", "3000")), help="target port")
        p.add_argument("--only", default=None,
                       help="comma-separated challenge keys (or category names) to run")
        p.add_argument("--list", action="store_true", help="list challenges + solved status and exit")
        p.add_argument("--no-verify", action="store_true", help="skip the before/after solved-status diff")
        p.add_argument("--browser", action="store_true",
                       help="also run the Selenium browser solver for client-side challenges")
        args, _ = p.parse_known_args(argv)
        cfg = cls(protocol=args.protocol, hostname=args.hostname, port=args.port)
        cfg.only = args.only          # type: ignore[attr-defined]
        cfg.list = args.list          # type: ignore[attr-defined]
        cfg.verify = not args.no_verify  # type: ignore[attr-defined]
        cfg.browser = args.browser    # type: ignore[attr-defined]
        return cfg


# --------------------------------------------------------------------------- #
# HTTP client
# --------------------------------------------------------------------------- #
class Client:
    """Thin wrapper over requests.Session with Juice Shop conveniences."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.base = cfg.base
        self.s = requests.Session()
        self.s.verify = False
        self.token: Optional[str] = None
        self.bid: Optional[int] = None       # basket id of the logged-in user
        self.email: Optional[str] = None

    # -- low level -------------------------------------------------------- #
    def url(self, path: str) -> str:
        return self.base + path if path.startswith("/") else f"{self.base}/{path}"

    def _auth_headers(self, extra: Optional[dict] = None) -> dict:
        h = {}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
            h["Cookie"] = f"token={self.token}"
        if extra:
            h.update(extra)
        return h

    def get(self, path, **kw):
        kw.setdefault("headers", {}).update(self._auth_headers())
        return self.s.get(self.url(path), timeout=30, **kw)

    def post(self, path, **kw):
        kw.setdefault("headers", {}).update(self._auth_headers())
        return self.s.post(self.url(path), timeout=30, **kw)

    def put(self, path, **kw):
        kw.setdefault("headers", {}).update(self._auth_headers())
        return self.s.put(self.url(path), timeout=30, **kw)

    def delete(self, path, **kw):
        kw.setdefault("headers", {}).update(self._auth_headers())
        return self.s.delete(self.url(path), timeout=30, **kw)

    def patch(self, path, **kw):
        kw.setdefault("headers", {}).update(self._auth_headers())
        return self.s.patch(self.url(path), timeout=30, **kw)

    # -- auth ------------------------------------------------------------- #
    def login(self, email: str, password: str, raw_email: bool = False) -> bool:
        """Login via /rest/user/login. ``raw_email`` passes the string as-is
        (used for SQLi payloads). Returns True and stores token on success."""
        r = self.s.post(self.url("/rest/user/login"),
                        json={"email": email, "password": password},
                        headers={"Content-Type": "application/json"},
                        timeout=30, verify=False)
        if r.status_code == 200 and r.json().get("authentication"):
            auth = r.json()["authentication"]
            self.token = auth["token"]
            self.bid = auth.get("bid")
            self.email = auth.get("umail", email)
            return True
        return False

    def register(self, email: str, password: str,
                 security_answer: str = "solver", security_question_id: int = 2,
                 role: Optional[str] = None) -> requests.Response:
        body = {
            "email": email, "password": password, "passwordRepeat": password,
            "securityQuestion": {"id": security_question_id},
            "securityAnswer": security_answer,
        }
        if role:
            body["role"] = role
        return self.s.post(self.url("/api/Users"),
                           json=body, headers={"Content-Type": "application/json"},
                           timeout=30, verify=False)

    def ensure_user(self, email: str, password: str, **kw) -> bool:
        """Register (ignore 'already exists') then login."""
        self.register(email, password, **kw)
        return self.login(email, password)

    # -- feedback / captcha --------------------------------------------- #
    def captcha(self):
        """GET /rest/captcha/ - returns (captchaId, answer). The dev endpoint
        conveniently returns the correct answer alongside the challenge."""
        r = self.s.get(self.url("/rest/captcha/"), timeout=30, verify=False)
        j = r.json()
        return j.get("captchaId"), str(j.get("answer"))

    def add_feedback(self, comment: str, rating: int = 1, user_id=None):
        cid, ans = self.captcha()
        body = {"captchaId": cid, "captcha": ans, "comment": comment, "rating": rating}
        if user_id is not None:
            body["UserId"] = user_id
        return self.post("/api/Feedbacks", json=body)

    def jwt_payload(self) -> dict:
        if not self.token:
            return {}
        try:
            body = self.token.split(".")[1]
            body += "=" * (-len(body) % 4)
            return json.loads(base64.urlsafe_b64decode(body))
        except Exception:
            return {}


# --------------------------------------------------------------------------- #
# Challenge status
# --------------------------------------------------------------------------- #
class Challenges:
    def __init__(self, client: Client):
        self.c = client
        self._by_key: Dict[str, dict] = {}

    def refresh(self) -> Dict[str, dict]:
        r = self.c.s.get(self.c.url("/api/Challenges/"), timeout=30, verify=False)
        data = r.json().get("data", [])
        self._by_key = {ch["key"]: ch for ch in data}
        return self._by_key

    def solved(self, key: str) -> bool:
        return bool(self._by_key.get(key, {}).get("solved"))

    def solved_count(self) -> int:
        return sum(1 for ch in self._by_key.values() if ch.get("solved"))

    def total(self) -> int:
        return len(self._by_key)


# --------------------------------------------------------------------------- #
# Solver registry
# --------------------------------------------------------------------------- #
@dataclass
class Solver:
    keys: List[str]                 # challenge keys this solver targets
    name: str                       # human label
    fn: Callable[[Client], None]    # does the exploit
    category: str = ""


SOLVERS: List[Solver] = []


def register_solver(keys, name, category=""):
    """Decorator to register a solver function for one or more challenge keys."""
    if isinstance(keys, str):
        keys = [keys]

    def deco(fn):
        SOLVERS.append(Solver(keys=keys, name=name, fn=fn, category=category))
        return fn
    return deco


# --------------------------------------------------------------------------- #
# Small shared helpers used across category modules
# --------------------------------------------------------------------------- #
def log(msg: str):
    print(msg, flush=True)


def ok(msg: str):
    print(f"  \033[92m✓\033[0m {msg}", flush=True)


def warn(msg: str):
    print(f"  \033[93m!\033[0m {msg}", flush=True)


def fail(msg: str):
    print(f"  \033[91m✗\033[0m {msg}", flush=True)


def retry(fn, tries=3, delay=0.4):
    last = None
    for _ in range(tries):
        try:
            return fn()
        except Exception as e:  # noqa
            last = e
            time.sleep(delay)
    if last:
        raise last
