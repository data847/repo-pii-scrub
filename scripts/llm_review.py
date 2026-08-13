"""LLM privacy review for sanitized repos (Gate 3)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

_METRICS = Path(__file__).resolve().parents[2] / "dataset-repo-metrics" / "scripts"
sys.path.insert(0, str(_METRICS))

from claude_client import call_anthropic, load_dotenv, parse_json_response  # noqa: E402

DEFAULT_ENV = Path(__file__).resolve().parents[1] / ".env"
DEFAULT_MODEL = os.environ.get("PII_SCRUB_MODEL", "claude-sonnet-4-6")

SYSTEM = """You are a privacy reviewer for code dataset delivery.

Review sanitized repository samples for ANY remaining PII or re-identification risk:
- Real person names, emails, phone numbers, addresses
- Company / client / product names that identify the originating org
- Internal hostnames, IPs, URLs, API endpoints tied to a specific company
- Secrets, tokens, credentials, connection strings
- Geographic or business-context clues that deanonymize the codebase

Reply with a single JSON object only — no markdown fences."""

PROMPT_TEMPLATE = """Review this sanitized repository sample.

Sanitizer gate summary (if any):
{context}

Code sample:
{payload}

Return JSON:
{{
  "verdict": "PASS" | "FAIL" | "WARN",
  "blocker_count": 0,
  "findings": [
    {{
      "severity": "BLOCKER" | "WARN" | "OK",
      "location": "file path + snippet",
      "reason": "one sentence",
      "suggested_fix": "redact | replace | remove file"
    }}
  ],
  "summary": "one paragraph"
}}

Verdict rules:
- PASS: zero BLOCKER findings
- FAIL: one or more BLOCKER findings
- WARN: no blockers but non-trivial WARN items remain
"""


def ensure_env(env_file: Path | None = None) -> None:
    load_dotenv(env_file or DEFAULT_ENV)


def run_llm_review(work_root: Path, *, model: str = DEFAULT_MODEL) -> dict[str, Any]:
    payload_path = work_root / "llm_review_payload.txt"
    context_path = work_root / "llm_review_context.txt"
    if not payload_path.is_file():
        raise FileNotFoundError(f"Missing {payload_path}; run llm-review --prepare first")

    payload = payload_path.read_text(errors="replace")[:180_000]
    context = context_path.read_text(errors="replace")[:20_000] if context_path.is_file() else ""
    prompt = PROMPT_TEMPLATE.format(context=context or "(none)", payload=payload)

    raw = call_anthropic(prompt=prompt, system=SYSTEM, model=model, max_tokens=8192)
    result = parse_json_response(raw)
    result.setdefault("verdict", "FAIL")
    result.setdefault("model", model)
    result.setdefault("source", "anthropic_api")

    out_path = work_root / "llm_review.json"
    out_path.write_text(json.dumps(result, indent=2) + "\n")

    notes_path = work_root / "llm_review_notes.md"
    lines = [
        f"# LLM Privacy Review — {result.get('verdict', 'UNKNOWN')}",
        "",
        result.get("summary", ""),
        "",
        "## Findings",
        "",
    ]
    for f in result.get("findings") or []:
        lines.append(
            f"- **{f.get('severity', '?')}** `{f.get('location', '?')}` — "
            f"{f.get('reason', '')} → {f.get('suggested_fix', '')}"
        )
    notes_path.write_text("\n".join(lines) + "\n")
    return result
