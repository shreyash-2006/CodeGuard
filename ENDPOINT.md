# Exposing CodeGuard with Uvicorn + ngrok

Hand this to whoever runs it. It follows the organizer's procedure; the only
CodeGuard-specific bits are the route (`/check`), the fixed schema, and the fact
that the app already never returns 4xx/5xx.

If you'd rather not run a tunnel, the **always-on Render deployment** is already
live: `https://codeguard-bdmu.onrender.com/check` (no header needed).

---

## 1. Prerequisites

- Python 3.10+ (3.11/3.12 recommended)
- A free [ngrok](https://ngrok.com) account
- ngrok installed (this machine: `C:\Users\<you>\AppData\Local\ngrok\ngrok.exe`)

---

## 2. Python environment

```bash
cd D:\hackathon
python -m venv .venv
.venv\Scripts\activate            # Windows
# source .venv/bin/activate       # macOS/Linux
pip install -r requirements.txt
```

Already-installed machine? Skip the venv — the service only needs `requirements.txt`.

---

## 3. The endpoint

`main.py` in the repo root re-exports the real app, so `uvicorn main:app` works
exactly as the guide describes. One service, no duplicated logic:

```python
from codeguard.api import app        # POST /check, /batch, /batch/csv, /analyze, /health, /ui
```

Contract (`POST /check`):

```jsonc
// request
{ "code": "import os; os.system('rm -rf /')" }

// response  — always HTTP 200, always this shape
{
  "verdict": "block",             // "block" | "allow"
  "risk_score": 0.9139,           // float 0..1, 4 dp
  "categories": ["destructive_command"],
  "code_language": "bash",
  "reason": "Blocked: destructive_command — … (line 1). Risk 0.91.",
  "vulnerable_lines": [1]
}
```

Invariant: `verdict=="block"` ⟺ `categories` non-empty ⟺ `risk_score ≥ 0.5`.
Malformed input → HTTP 200 with `verdict:"allow"`, `reason:"Empty input"`.

---

## 4. Run locally

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
# or:  python main.py
```

Verify before exposing:

```bash
curl -X POST http://localhost:8000/check -H "Content-Type: application/json" -d "{\"code\":\"rm -rf /\"}"
curl http://localhost:8000/health
```

Leave this terminal running.

---

## 5–6. ngrok: install + authenticate (one-time)

```bash
ngrok config add-authtoken <YOUR_AUTHTOKEN>     # from https://dashboard.ngrok.com
```

On this machine ngrok lives at `%LOCALAPPDATA%\ngrok\ngrok.exe`; use the full
path if `ngrok` isn't on `PATH`.

---

## 7. Expose it (new terminal, keep uvicorn running)

```bash
ngrok http 8000
```

ngrok prints e.g. `Forwarding  https://abcd1234.ngrok-free.app -> http://localhost:8000`.
The public endpoint is the **base + the route**:

```
https://abcd1234.ngrok-free.app/check
```

Or run both with the helper (prints the URL for you):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\expose.ps1
```

---

## 8. Test the PUBLIC URL (not localhost)

```bash
curl -X POST https://abcd1234.ngrok-free.app/check \
  -H "Content-Type: application/json" \
  -d "{\"code\":\"rm -rf /\"}"
```

> **Important — ngrok free-tier interstitial.** A plain request may return an HTML
> warning page instead of JSON. Send the bypass header (and tell the caller to do
> the same, or use the Render URL which needs no header):
>
> ```bash
> curl -X POST https://abcd1234.ngrok-free.app/check \
>   -H "Content-Type: application/json" \
>   -H "ngrok-skip-browser-warning: true" \
>   -d "{\"code\":\"rm -rf /\"}"
> ```

Only share the URL once both the local curl **and** the public curl return JSON.

---

## 9. Keep it alive

- Do **not** close either terminal while the URL is in use.
- Do **not** restart ngrok — the free tier assigns a **new random URL** each run.
- Disable sleep/screen-lock: Windows → Settings → System → Power & sleep → Sleep: **Never**.
- Stay on a stable network; moving Wi-Fi/sleeping breaks the tunnel.

---

## 10. Share

Give the **full URL including `/check`**:

```
https://abcd1234.ngrok-free.app/check
```

Callers must send `Content-Type: application/json` and (on ngrok free)
`ngrok-skip-browser-warning: true`. The Render URL needs neither.

---

## Troubleshooting

| Symptom | Likely cause | Fix | Fix on |
|---|---|---|---|
| `ERR_NGROK_…` | Auth token not set | `ngrok config add-authtoken …` | Creator |
| Public URL returns HTML, not JSON | ngrok browser-warning interstitial | Add `ngrok-skip-browser-warning: true` | Caller (creator should tell them) |
| Connection refused on public URL | uvicorn not running / wrong port | Confirm uvicorn is up on the port passed to `ngrok http` | Creator |
| URL changed after a restart | Free ngrok rotates URLs each session | Don't restart; re-share if it did change | Creator (re-share); Caller (update) |
| Works on localhost, not via ngrok | Host header / CORS | `ngrok http --host-header=rewrite 8000` | Creator |
| Caller gets 422 | Body didn't match schema | Caller sends `{"code":"..."}` | Caller |
| Caller gets 500 | Unhandled exception | CodeGuard already returns HTTP 200 fail-closed; report the body | Creator (shouldn't happen) |
| Caller times out | Service slow / laptop asleep / network dropped | Creator checks both processes alive; disable sleep | Creator |
| Caller can't reach URL at all | Wrong URL / tunnel down | Caller re-confirms the exact URL; creator confirms both processes run | Both — verify independently |

The 422 row is the only one that can't happen here: CodeGuard's `/check` always
answers HTTP 200 with a schema-valid body, including for `{}`, `null`, empty, or
non-JSON requests.
