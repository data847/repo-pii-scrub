"""Environment assembly shared by every batch driver.

Kept separate from the org-specific drivers so generic tooling (verification,
single-repo runs) does not have to import a client repo catalog.
"""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SALT_FILE = ROOT / ".salt"
ENV_FILE = ROOT / ".env"

# Forwarded into each scrub worker process.
WORKER_ENV_KEYS = (
    "PATH",
    "REPO_SANITIZER_SALT",
    "ANTHROPIC_API_KEY",
    "PII_SCRUB_MODEL",
    "PII_SCRUB_NER_SERVICE_URL",
    "PII_SCRUB_NER_SCOPE",
    "PII_SCRUB_NER_DEVICE",
    "PII_SCRUB_STEP_TIMEOUT",
    "PII_SCRUB_GATE_TIMEOUT",
    "TOKENIZERS_PARALLELISM",
)


def env_file() -> Path | None:
    return ENV_FILE if ENV_FILE.is_file() else None


def load_env_file(env: dict[str, str], path: Path | None) -> None:
    """Merge KEY=VALUE lines from *path*, never overriding an existing value."""
    if path is None or not path.is_file():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip("'\"")
        if key and key not in env:
            env[key] = val


def build_env() -> dict[str, str]:
    """Process env plus the salt, the skill's tool paths, and .env values."""
    env = os.environ.copy()
    if not env.get("REPO_SANITIZER_SALT") and SALT_FILE.is_file():
        env["REPO_SANITIZER_SALT"] = SALT_FILE.read_text().strip()
    tools = ROOT / ".tools" / "bin"
    venv = ROOT / ".venv" / "bin"
    env["PATH"] = f"{venv}:{tools}:{env.get('PATH', '')}"
    load_env_file(env, env_file())
    return env


def worker_env_from(env: dict[str, str]) -> dict[str, str]:
    selected = {k: env[k] for k in WORKER_ENV_KEYS if k in env}
    selected["PATH"] = env["PATH"]
    return selected
