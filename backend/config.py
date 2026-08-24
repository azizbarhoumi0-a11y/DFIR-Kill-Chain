"""
Central configuration for the DFIR platform.
Everything here can be overridden with environment variables so you can move
the app around (e.g. point SIGMA_RULES_DIR at a real SigmaHQ checkout) without
touching code.
"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Where uploaded evidence files are staged per-job before parsing.
UPLOAD_DIR = Path(os.environ.get("DFIR_UPLOAD_DIR", BASE_DIR / "uploads"))

# --- Auth (multi-user) ---
DB_PATH = Path(os.environ.get("DFIR_DB_PATH", BASE_DIR / "storage" / "users.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# IMPORTANT: set DFIR_SECRET_KEY yourself (env var) in any environment that
# needs sessions to survive a restart. Without it, a fresh random key is
# generated every boot, which silently logs out every user each restart.
SECRET_KEY = os.environ.get("DFIR_SECRET_KEY") or secrets.token_hex(32)

# Where Sigma rule .yml/.yaml files live. Point this at a SigmaHQ clone
# (rules/windows) for real detection coverage — the repo ships with an
# empty folder so the app runs out of the box with zero alerts.
SIGMA_RULES_DIR = Path(
    os.environ.get("DFIR_SIGMA_RULES_DIR", BASE_DIR / "sigma_rules" / "windows")
)

# Local Ollama model used for the narrative kill-chain synthesis.
OLLAMA_MODEL = os.environ.get("DFIR_OLLAMA_MODEL", "qwen2.5:7b")
OLLAMA_BASE_URL = os.environ.get("DFIR_OLLAMA_BASE_URL", "http://localhost:11434/v1")

# Single-user local tool: keep exactly one analysis running at a time so we
# don't hammer the local Ollama instance with concurrent requests.
MAX_CONCURRENT_JOBS = int(os.environ.get("DFIR_MAX_CONCURRENT_JOBS", "1"))

# File extensions routed to the EVTX parser; everything else uploaded goes to
# the registry-hive dispatcher (which auto-detects hive type from its header).
EVTX_EXTENSIONS = {".evtx"}

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
SIGMA_RULES_DIR.mkdir(parents=True, exist_ok=True)
