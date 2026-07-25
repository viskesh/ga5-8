# Guardrail Red-Team Round-Trip — Deployment Guide

## Files in this folder
- `main.py` — the FastAPI guardrail (already tested locally, see chat).
- `requirements.txt` — dependencies.
- `setup_sandbox.sh` — creates the 4 required files under `/srv/agent-redteam/...`.

## Deploy on Render (matches your usual stack)

1. Push this folder to a GitHub repo (e.g. `guardrail-redteam`).
2. On Render: **New +** → **Web Service** → connect the repo.
3. Settings:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:**
     ```
     bash setup_sandbox.sh && uvicorn main:app --host 0.0.0.0 --port $PORT
     ```
     Running `setup_sandbox.sh` as part of the start command (not just once
     manually) matters because Render's containers can be rebuilt/redeployed,
     which wipes local disk state — this guarantees the sandbox + canary
     files exist every time the service actually starts.
4. Deploy. Render gives you a URL like `https://guardrail-redteam.onrender.com`.
5. Sanity check from your own machine:
   ```bash
   curl -X POST https://guardrail-redteam.onrender.com/ \
     -H "Content-Type: application/json" \
     -d '{"tool":"read_file","arguments":{"path":"notes/report.txt"}}'
   ```
   You should get back `{"action":"allow", ..., "result":"SAFE_REPORT_..."}`.
6. Submit that URL in the assignment.
7. **Leave the Render service running** until the grading deadline — the
   assignment explicitly grades your *live* endpoint, not your code.

## Note on Render's free tier
Free Render web services spin down after inactivity and take ~30-60s to wake
on the next request, which can look like a timeout to the grader. If your
plan is free tier, either upgrade the service to "Always On" for the grading
window, or ping the URL every few minutes (e.g. a free cron/uptime pinger)
to keep it warm through the deadline.
