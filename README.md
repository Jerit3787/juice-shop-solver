# Juice Shop Solver (v20.x)

An automated exploit suite for the [OWASP Juice Shop](https://github.com/juice-shop/juice-shop).
It performs the real attack for each challenge against a running instance and
**verifies success out-of-band** by reading the server's own challenge-tracking
API (`/api/Challenges/`) — so the final report reflects what the target actually
marked solved, not merely what ran without error.

> Rewritten from scratch for **Juice Shop v20** and **Python 3**. The original
> project (unixerius / USHIken / incognitjoe) targeted v2.18 on Python 2.7; the
> API, auth flow and challenge set have changed completely since then. Exploits
> here are derived from the official Juice Shop test suite
> (`test/cypress/e2e`, `test/api`) and the server's own detection logic.

## Results

Against a stock **v20.1.1** instance this suite solves **91 of 113** challenges
— i.e. **every challenge that is solvable in the target environment**:

| Bucket | Count | Notes |
|--------|------:|-------|
| ✅ Solved | **91** | via HTTP API, WebSocket, or headless browser |
| 🚫 Disabled on target | 13 | `disabledEnv` (e.g. Docker turns off the RCE/DoS/alert-XSS challenges) — cannot be solved on that instance by design |
| 🌐 Needs a Web3 wallet | 4 | `nftUnlock`, `nftMint`, `web3Wallet`, `manipulateClock` — require MetaMask + a chain |
| 🤖 Needs the LLM chatbot | 4 | `chatbotPromptInjection`, `chatbotGreedyInjection`, `systemPromptExtraction`, `aiDebugging` — require the AI chatbot feature (an API key) to be enabled |
| ⏱️ Timing side-channel | 1 | `timingAttack` — statistically flaky to automate |

The three "needs external infra" buckets are environment limitations, not gaps in
the exploits. On an instance where those features are enabled the same approach
applies.

## Requirements

- A running Juice Shop (default target `http://localhost:3000`)
- Python 3.9+
- `pip install -r requirements.txt`
- For `--browser`: a local Google Chrome (Selenium Manager auto-downloads the
  matching driver — no manual chromedriver setup)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 solve.py                       # solve everything against localhost:3000
python3 solve.py --browser             # also drive headless Chrome for SPA-route challenges
python3 solve.py --host 10.0.0.5 --port 3000 --protocol http
python3 solve.py --list                # show every challenge + solved status, then exit
python3 solve.py --only injection      # run a single category
python3 solve.py --only loginJimChallenge,dbSchemaChallenge   # run specific challenge keys
```

The runner reads the challenge status before and after, then prints:

- **Solved this run** — challenges flipped from unsolved → solved
- **Total solved** — `N / 113` and `N / <solvable-here>`
- **Disabled on this instance** — env-gated challenges it skipped
- **Unsolved** — anything left, with the reason bucket

Re-running is safe: already-solved and env-disabled challenges are skipped.

> Tip: to see a full clean sweep, reset the target first
> (`Score Board → “…” → reset`, or restart with a fresh DB), then run `solve.py`.

## How it works

```
solve.py            orchestrator: reads /api/Challenges/, runs solvers, verifies, reports
core.py             Client (requests session, login/register/JWT/captcha helpers),
                    Challenges (status), and the register_solver() registry
├── injection.py        SQLi, NoSQLi, SSTI, chatbot prompt-injection
├── access_control.py   basket access/manipulation, forged feedback/review, CSRF, SSRF, product tampering
├── authentication.py   password resets, 2FA (TOTP), OAuth, ghost login, change-password
├── sensitive_data.py   leaked-credential logins, password-hash leak, geo-stalking, blueprint, data export
├── input_validation.py registration abuse, negative order, uploads, free deluxe, zero stars
├── filehandling.py     FTP poison-null-byte, hidden URLs, XXE/YAML/zip uploads, local file read
├── misc_challenges.py  metrics, security.txt, CSAF, redirects, captcha bypass, B2B deserialization DoS
├── xss.py              XSS injections (server-side-detected variants)
├── crypto.py           weak-crypto report, forged coupon (z85), continue-code forgery (hashids)
├── components.py       vulnerable-library reports, typosquatting, JWT (alg:none + forged HMAC)
├── realtime.py         WebSocket (socket.io) challenges: DOM XSS, bonus payload, SVG injection, close-notifications
└── browser.py          Selenium: SPA-route challenges (privacy policy, token sale, web3 sandbox, admin section)
payloads/               XXE / YAML-bomb / zip-slip attack files (from the Juice Shop test corpus)
```

Every solver targets one or more challenge **keys** and is verified against the
live server, so coverage stays honest as the target evolves.

## Adding / fixing a solver

```python
from core import register_solver, Client, ok, fail

@register_solver("someChallengeKey", "Human label", "Category")
def my_solver(c: Client):
    r = c.get("/rest/....")     # perform the real exploit
    ok(f"did the thing ({r.status_code})")
    # success is confirmed automatically by re-reading /api/Challenges/
```

When a challenge won't flip, check its detection in the target source
(`routes/`, `lib/startup/registerWebsocketEvents.ts`, `routes/verify.ts`) and its
`disabledEnv` in `/api/Challenges/` — several are intentionally off under Docker.
