"""Persist PII scrub pipeline state between gates."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    return json.loads(path.read_text())


def save(path: Path, data: dict[str, Any]) -> None:
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(data, indent=2))


def init_run(
    path: Path,
    *,
    run_id: str,
    repo_slug: str,
    source: str,
    rulepack: str,
    fast_mode: bool = False,
) -> dict[str, Any]:
    data = {
        "run_id": run_id,
        "repo_slug": repo_slug,
        "source": source,
        "rulepack": rulepack,
        "fast_mode": fast_mode,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "current_gate": "clone",
        "gates_completed": [],
    }
    save(path, data)
    return data
