# DFIR Kill Chain Platform

A local web platform for uploading DFIR artifacts (Windows Event Logs,
registry hives) and getting back an AI-synthesized kill-chain report —
built entirely on local infrastructure (local Sigma rules, local Ollama
model) so evidence never leaves your machine.

## What it does

1. Upload one or more artifacts (`.evtx` files, registry hives — `NTUSER.DAT`,
   `SOFTWARE`, `SYSTEM`, `SAM`, `DEFAULT`, `AMCACHE.HVE`).
2. Each file is parsed into normalized telemetry events.
3. Events are evaluated against your local Sigma rule set — every match
   becomes a **named, severity-tagged alert** with the exact rule file path
   that triggered it (not an LLM guess).
4. Matched events are correlated into a process/registry state graph.
5. A local Ollama model synthesizes that graph into a narrative kill-chain
   report (executive summary → attack chain chronology by MITRE ATT&CK
   phase → containment recommendations).
6. Everything is shown in a live-updating report view: critical/high Sigma
   alerts up top with rule name + MITRE tags + file path, narrative report
   below, raw process tree available on demand.

Analysis runs as a background job so the UI stays responsive — you can
watch progress stage-by-stage, or cancel a job mid-run.

## Architecture

```
frontend/
  index.html         Single-page UI: upload, job list, live report view
  login.html          Sign-in / registration

backend/
  main.py              FastAPI app — routes, session middleware, auth gating
  auth.py               User model, bcrypt hashing, session-based login (JSON API)
  database.py            SQLAlchemy engine/session (SQLite)
  job_manager.py          In-memory background job queue + cancellation
  pipeline_adapter.py      Bridges the DFIR scripts into one run_analysis() call
  config.py                Paths, Sigma rules dir, Ollama host/model, secret key
  dfir_lib/
    evtx_parser.py          Parses .evtx into normalized telemetry events
    hive_parsers.py          Parses registry hives (NTUSER/SOFTWARE/SYSTEM/SAM/etc)
    hybrid_pipeline.py        Sigma evaluation, attack graph builder, LLM synthesis

storage/
  users.db              SQLite user accounts (gitignored — never commit this)
uploads/
  <job_id>/               Staged evidence files per job (gitignored)
sigma_rules/
  windows/                 Your Sigma rule set (point this at a SigmaHQ checkout)
```

## Setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Set your session secret (important — without this, restarting the server
logs everyone out):

```bash
export DFIR_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```

Other environment variables you may want to override (defaults live in
`config.py`):

| Variable | Default | Purpose |
|---|---|---|
| `DFIR_UPLOAD_DIR` | `./uploads` | Where staged evidence files land per job |
| `DFIR_SIGMA_RULES_DIR` | `./sigma_rules/windows` | Sigma rule set — point at a real SigmaHQ clone for actual coverage |
| `DFIR_OLLAMA_MODEL` | `qwen2.5:7b` | Model used for narrative synthesis |
| `DFIR_OLLAMA_BASE_URL` | `http://localhost:11434/v1` | Ollama's OpenAI-compatible endpoint |
| `DFIR_MAX_CONCURRENT_JOBS` | `1` | Background analysis jobs run at once (kept low to avoid hammering local Ollama) |

Make sure Ollama is running and the model is pulled:

```bash
ollama pull qwen2.5:7b
ollama serve
```

## Run

```bash
python3 -m uvicorn main:app --reload --port 8000
```

**Use `python3 -m uvicorn`, not a bare `uvicorn` command** — on some
systems a system-wide `uvicorn` install shadows the one in your venv and
silently runs against the wrong Python environment.

Open `http://localhost:8000` — you'll land on the login page first.
Register an account to get started; every analyst gets their own private
case list.

## Known dependency note

`hybrid_pipeline.py` imports `sigma_rule_matcher.RuleMatcher`, which is not
a package on PyPI. If it's a module you've written, make sure it's
importable — placing it directly in `backend/dfir_lib/` works automatically
since `pipeline_adapter.py` already puts that directory on `sys.path`.

## Security notes

- Never commit `storage/users.db` (password hashes) or anything under
  `uploads/`/`storage/uploads/` (real evidence, sometimes actively
  malicious files) — both are excluded in `.gitignore`.
- Set `DFIR_SECRET_KEY` explicitly in any environment where you care about
  sessions surviving a restart.
- Multiple users' jobs currently share one global concurrency limit
  (`DFIR_MAX_CONCURRENT_JOBS`), since they're all hitting the same local
  Ollama instance either way.
