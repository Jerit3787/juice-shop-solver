#!/usr/bin/env python3
"""
solve.py - Entry point for the OWASP Juice Shop solver (v20.x, Python 3).

Usage:
    python3 solve.py                       # solve everything against localhost:3000
    python3 solve.py --host 10.0.0.5       # different target
    python3 solve.py --only injection      # run one category
    python3 solve.py --only loginAdminChallenge,dbSchemaChallenge
    python3 solve.py --list                # show challenge status and exit

Each solver performs a real exploit against the target; success is confirmed by
re-reading /api/Challenges/ afterwards, so the final report reflects what the
*server* actually marked solved, not merely what ran without error.
"""
from __future__ import annotations

import sys
import time
import traceback

from core import Config, Client, Challenges, SOLVERS, log, ok, fail, warn

# Importing the category modules registers their solvers into core.SOLVERS.
import injection            # noqa: E402,F401
import access_control       # noqa: E402,F401
import sensitive_data       # noqa: E402,F401
import authentication as _auth  # noqa: E402,F401
import input_validation     # noqa: E402,F401
import filehandling         # noqa: E402,F401
import misc_challenges      # noqa: E402,F401
import xss                  # noqa: E402,F401
import crypto               # noqa: E402,F401
import components           # noqa: E402,F401
import realtime             # noqa: E402,F401


RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
DIM = "\033[2m"


def matches_filter(solver, flt: set) -> bool:
    if not flt:
        return True
    if solver.category.lower() in flt:
        return True
    return any(k.lower() in flt for k in solver.keys)


def main():
    cfg = Config.from_args()
    client = Client(cfg)
    ch = Challenges(client)

    log(f"{BOLD}Juice Shop Solver{RESET}  →  {cfg.base}")
    try:
        before = ch.refresh()
    except Exception as e:
        fail(f"Cannot reach the challenge API at {cfg.base}/api/Challenges/ : {e}")
        sys.exit(1)
    log(f"Target has {ch.total()} challenges, {ch.solved_count()} already solved.\n")

    if getattr(cfg, "list", False):
        for key, c in sorted(before.items(), key=lambda kv: (kv[1]["category"], kv[1]["difficulty"])):
            mark = f"{GREEN}✓{RESET}" if c["solved"] else " "
            log(f" [{mark}] {key:<42} d{c['difficulty']} {DIM}{c['category']}{RESET}")
        return

    flt = set()
    if getattr(cfg, "only", None):
        flt = {x.strip().lower() for x in cfg.only.split(",") if x.strip()}

    solvers = [s for s in SOLVERS if matches_filter(s, flt)]
    log(f"Running {len(solvers)} solver group(s)...\n")

    ran = []
    for s in solvers:
        # Skip if every targeted challenge is already solved.
        if all(ch.solved(k) for k in s.keys):
            continue
        # Skip if every targeted challenge is disabled in this environment.
        if all(before.get(k, {}).get("disabledEnv") for k in s.keys) and not flt:
            continue
        label = f"{s.category}/{s.name}" if s.category else s.name
        log(f"{BOLD}▶ {label}{RESET}  {DIM}{','.join(s.keys)}{RESET}")
        try:
            s.fn(client)
        except Exception as e:
            fail(f"{s.name} raised {type(e).__name__}: {e}")
            if "--trace" in sys.argv:
                traceback.print_exc()
        ran.append(s)

    # Optional: drive a headless browser for the client-side-only challenges.
    if getattr(cfg, "browser", False):
        try:
            import browser
            browser.run(cfg)
        except Exception as e:  # noqa
            fail(f"browser solver failed: {e}")

    # Give the server a beat to persist async challenge detections.
    time.sleep(1.5)
    after = ch.refresh()

    # ------------------------------------------------------------------- #
    # Report
    # ------------------------------------------------------------------- #
    newly = [k for k, c in after.items() if c["solved"] and not before.get(k, {}).get("solved")]
    still = [k for k, c in after.items() if not c["solved"] and not c.get("disabledEnv")]
    disabled = [k for k, c in after.items() if not c["solved"] and c.get("disabledEnv")]

    total_solved = sum(1 for c in after.values() if c["solved"])
    solvable = len(after) - len(disabled)

    log(f"\n{BOLD}{'='*60}{RESET}")
    log(f"{BOLD}RESULTS{RESET}")
    log(f"{BOLD}{'='*60}{RESET}")
    log(f"Solved this run : {GREEN}{len(newly)}{RESET}")
    for k in sorted(newly):
        ok(k)
    log(f"\nTotal solved    : {GREEN}{total_solved}{RESET} / {len(after)} "
        f"({GREEN}{total_solved}/{solvable}{RESET} of those solvable in this environment)")

    if disabled:
        log(f"\n{DIM}Disabled on this instance ({len(disabled)}) - env-gated (e.g. Docker), cannot be solved here:{RESET}")
        for k in sorted(disabled, key=lambda x: (after[x]['category'], after[x]['difficulty'])):
            c = after[k]
            log(f"   {DIM}·{RESET} {k:<42} {DIM}{c['disabledEnv']} / {c['category']}{RESET}")

    if still:
        log(f"\n{YELLOW}Unsolved ({len(still)}) - need a browser/wallet/LLM or manual step:{RESET}")
        for k in sorted(still, key=lambda x: (after[x]['category'], after[x]['difficulty'])):
            c = after[k]
            log(f"   {DIM}·{RESET} {k:<42} d{c['difficulty']} {DIM}{c['category']}{RESET}")


if __name__ == "__main__":
    main()
