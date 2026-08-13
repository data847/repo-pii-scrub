# Repo PII Scrub — Reference

Full workflow for preparing a codebase for dataset delivery.

Pipeline skill: use `scripts/orchestrator.py` (see [SKILL.md](SKILL.md)).  
This document is the detailed manual for each step.

---

## Step 1 — Clone or use existing repo

**Orchestrator:** `orchestrator.py clone --run-dir $RUN`

- Clones git URL to `{run-dir}/source/`, or copies a local directory.
- Writes `commit_count_before.txt` and `head_before.txt`.

---

## Step 2 — Scrub PII with repo-sanitizer

**Orchestrator:** `orchestrator.py sanitize --run-dir $RUN [--pre-scan]`

1. Optional pre-scan → `{run-dir}/scan-pre/`
2. `repo-sanitizer sanitize --gate` → `{run-dir}/sanitized/`
3. Clone `sanitized/output/sanitized.bundle` → `{run-dir}/clean/`
4. Build LLM sample files

Requires `REPO_SANITIZER_SALT` and a valid `rules/` rulepack.

---

## Step 3 — Verify using LLM

**Orchestrator:** `orchestrator.py llm-review --run-dir $RUN [--auto] [--human-approved]`

- Reads `{run-dir}/llm_review_payload.txt` (sampled files from `clean/`)
- Calls Anthropic API with privacy-review prompt
- Writes `llm_review.json` and `llm_review_notes.md`

| Verdict | Action |
|---------|--------|
| **PASS** | Proceed to Step 4 |
| **FAIL** | Update rulepack → re-run Step 2 |
| **WARN** | Human sign-off via `--human-approved` |

---

## Step 4 — Reset git history to the first 5% of commits

**Orchestrator:** `orchestrator.py trim --run-dir $RUN --human-approved [--history-pct 5]`

Keeps earliest N% of commits (default 5%, minimum 1):

```bash
TOTAL=$(git rev-list --count HEAD)
KEEP=$(( TOTAL * 5 / 100 )); [ "$KEEP" -lt 1 ] && KEEP=1
NEW_HEAD=$(git rev-list --reverse HEAD | sed -n "${KEEP}p")
git checkout -B main "$NEW_HEAD"
git filter-repo --force --refs refs/heads/main
```

---

## Step 5 — Verify for PII (post-trim)

**Orchestrator:** `orchestrator.py verify --run-dir $RUN`

- `repo-sanitizer scan` + `gate` on `{run-dir}/clean/`
- `gitleaks detect --redact`

Both must exit 0.

---

## Step 6 — Zip the repo

**Orchestrator:** `orchestrator.py package --run-dir $RUN`

Produces:

- `{repo_slug}_sanitized_first5pct.zip` — includes `.git` history
- `MANIFEST.json` — commits before/after, bundle SHA, LLM review path

Excludes: `node_modules`, `.venv`, `vendor`, `dist`, `build`, `.next`, `__pycache__`.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `gitleaks not found` | `brew install gitleaks` |
| `Rulepack not found` | Copy from repo-sanitizer `examples/rules/` → `rules/` |
| Sanitize gate fails | Inspect `scan-pre/artifacts/`; extend dictionaries |
| LLM FAIL | Add client/org terms to `rules/dictionaries/` |
| `git filter-repo` missing | `pip install git-filter-repo` |
| LFS / binary leaks | Add denied paths in rulepack; repo-sanitizer skips LFS fetch |

---

## Manual commands (without orchestrator)

See the original workflow doc at  
`skills/dataset-repo-metrics/REPO_PII_SCRUB_WORKFLOW.md` (legacy path; prefer this skill).
