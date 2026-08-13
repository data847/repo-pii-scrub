---
name: repo-pii-scrub
description: >-
  Human-in-the-loop pipeline to scrub PII from codebases using repo-sanitizer,
  LLM privacy review, git history trim (first 5%), post-trim verification, and
  zip packaging for dataset delivery. Use when anonymizing repos, scrubbing PII,
  preparing sanitized repo deliverables, or running the repo-sanitizer workflow.
disable-model-invocation: true
---

# Repo PII Scrub Pipeline

Seven gates. **Never skip a gate or proceed without explicit human approval where required.**

| Gate | Command | Human decides |
|------|---------|---------------|
| 0 init | `orchestrator.py init` | Source repo, slug, rulepack |
| 1 clone | `orchestrator.py clone` | Accept baseline commit count |
| 2 sanitize | `orchestrator.py sanitize` | Accept sanitizer gate results |
| 2b brand | `orchestrator.py brand-map` | Approve brand → pseudonym map |
| 3 llm | `orchestrator.py llm-review` | Approve PASS/WARN before trim |
| 4 trim | `orchestrator.py trim --human-approved` | Approve history reduction |
| 5 verify | `orchestrator.py verify` | Accept post-trim scan |
| 6 package | `orchestrator.py package` | Accept final zip |

## Why Gate 2b exists

Pass-1 (`sanitize`) redacts PII, secrets and endpoints but **never rewrites a brand
or organization name** — those are reported as a *Pass-2 worklist*, so the
`ORG_NAME` / `BRAND_*` gates fail by design on any repo that names its own company.
Gate 2b builds a deterministic brand map (`term → ANON_ORG_<hash>`) from that
worklist plus any `--term` you supply, then runs Pass-3 `apply-map` to substitute
those brands across every blob, commit message, and path.

Without this gate the pipeline can never deliver such a repo: Pass-1 keeps failing
its brand gates forever.

## Prerequisites

```bash
cd skills/repo-pii-scrub
python -m venv .venv && .venv/bin/pip install -r requirements.txt
brew install gitleaks          # macOS
pip install git-filter-repo

# Copy rulepack — see rules/README.md
export REPO_SANITIZER_SALT="$(openssl rand -hex 32)"   # never commit
export ANTHROPIC_API_KEY=...                           # Gate 3
```

| Requirement | Notes |
|-------------|-------|
| `repo-sanitizer` | PII + secrets scrub; requires gitleaks |
| `REPO_SANITIZER_SALT` | Deterministic redaction salt — never commit it |
| `rules/` | Rulepack directory |
| `ANTHROPIC_API_KEY` | LLM privacy review (Gate 3) |
| Batch runs | `scripts/run_batch.py --repos-file <list>` |

Values are read from `.env` in this directory if present.

### NER device and the shared service

`rules/policies.yaml` sets `ner.device`. **On a machine without CUDA (e.g. Apple
Silicon) this must be `cpu`** — a `cuda:0` value makes the model load hang.

Each sanitize worker otherwise loads its own ~700 MB transformer model, which
exhausts memory and deadlocks under parallelism. Start one shared service and
point the workers at it:

```bash
python scripts/ner_service_manager.py --device cpu --idle-timeout 0   # once
export PII_SCRUB_NER_SERVICE_URL=http://127.0.0.1:8765
```

| Variable | Purpose |
|----------|---------|
| `PII_SCRUB_NER_SERVICE_URL` | Use a shared NER service instead of per-worker models |
| `PII_SCRUB_NER_DEVICE` | `cpu` / `cuda:0` / `auto` (default `cpu`) |
| `PII_SCRUB_NER_SCOPE` | `head` (working tree, default), `all` (history too, slow), `off` |
| `PII_SCRUB_STEP_TIMEOUT` | Per-command cap, seconds (`0` = unlimited) |
| `PII_SCRUB_GATE_TIMEOUT` | Per-gate cap, seconds (`0` = unlimited) |

## Verifying the pipeline

`make_pii_fixture.py` generates a medium-sized repo seeded with every PII and
secret class the rulepack detects — in the working tree, in blobs that exist only
in deleted history, in commit messages, and in author identities. `verify_pii_fixture.py`
then proves none of those literals survive.

```bash
python scripts/run_pipeline_verification.py --history-pct 100
```

`--history-pct 100` keeps every commit so the leak scan covers the whole history
rather than only the delivered slice. Run `verify_pii_fixture.py --check-patterns`
alone to confirm each planted value still matches its detector — otherwise a
"clean" result could just mean the value never matched anything.

## Agent workflow (mandatory)

When the user invokes this skill:

1. **Read** [reference.md](reference.md) for step details and troubleshooting.
2. **Gate 0** — `init` with `--repo-slug`, `--source`, `--run-id`.
3. **Gate 1** — `clone`. Report commits before scrub.
4. **Gate 2** — `sanitize --pre-scan`. Report sanitizer `result.json` gate status.
5. **Gate 2b** — `brand-map`. Present the proposed brand → pseudonym map and the
   terms it will rewrite across all history before accepting it.
6. **STOP.** Present LLM sample path. Ask: *"Run LLM privacy review?"*
6. **Gate 3** — `llm-review --auto` then `--human-approved` if WARN. **STOP on FAIL** — update rulepack, re-run Gate 2.
7. **STOP.** Ask: *"Approve trimming history to first 5%?"*
8. **Gate 4** — `trim --human-approved`.
9. **Gate 5** — `verify`. Report gate + gitleaks exit code.
10. **Gate 6** — `package`. Deliver zip path + `MANIFEST.json`.

**Never** run Gates 3–6 in one shot without human checkpoints.

## Quick commands

```bash
RUN=outputs/my-repo-scrub
python scripts/orchestrator.py init \
  --run-id my-repo-scrub \
  --repo-slug org__my-repo \
  --source git@github.com:org/my-repo.git

python scripts/orchestrator.py clone --run-dir $RUN
python scripts/orchestrator.py sanitize --run-dir $RUN --pre-scan
python scripts/orchestrator.py brand-map --run-dir $RUN --term AcmeCorp
python scripts/orchestrator.py llm-review --run-dir $RUN --auto
python scripts/orchestrator.py llm-review --run-dir $RUN --human-approved
python scripts/orchestrator.py trim --run-dir $RUN --human-approved
python scripts/orchestrator.py verify --run-dir $RUN
python scripts/orchestrator.py package --run-dir $RUN
python scripts/orchestrator.py status --run-dir $RUN
```

Full walkthrough: [examples.md](examples.md)

## Outputs (per run directory)

| Path | Gate |
|------|------|
| `source/` | 1 — original clone |
| `sanitized/output/sanitized.bundle` | 2 |
| `brand_map.json`, `sanitized-brands/` | 2b |
| `clean/` | 2b — materialized sanitized repo |
| `llm_review.json`, `llm_review_notes.md` | 3 |
| `commit_count_after_trim.txt` | 4 |
| `gate-post-trim/` | 5 |
| **`{slug}_sanitized_first5pct.zip`**, `MANIFEST.json` | 6 |

## Using a local repo (skip remote clone)

```bash
python scripts/orchestrator.py init \
  --run-id local-scrub \
  --repo-slug acme__api \
  --source /abs/path/to/existing/repo
```

## After packaging

Run **`dataset-repo-metrics`** on `clean/` or the extracted zip for compiled-sheet metrics.

## Agent checklist

```
- [ ] Confirm source (URL or local path) and repo slug with user
- [ ] Verify REPO_SANITIZER_SALT is set
- [ ] Verify rules/ rulepack exists (see rules/README.md)
- [ ] Confirm ner.device matches the host (cpu when there is no CUDA)
- [ ] Run gates 1–2; report sanitizer gate pass/fail
- [ ] Gate 2b — present brand map for approval
- [ ] STOP — LLM review; block on FAIL
- [ ] STOP — human approval before trim
- [ ] Run gates 4–6
- [ ] Report: zip path, commits before/after, LLM verdict, bundle SHA
```

## Key paths

```
repo-pii-scrub/
├── SKILL.md
├── reference.md                        # full step-by-step workflow
├── examples.md
├── rules/                              # repo-sanitizer rulepack (customize per org)
├── scripts/orchestrator.py             # pipeline entry point (gates 0–6)
├── scripts/run_batch.py                # batch driver (--repos-file)
├── scripts/ner_service_manager.py      # shared NER service
├── scripts/make_pii_fixture.py         # PII fixture generator
├── scripts/verify_pii_fixture.py       # leak scanner / detector self-check
├── scripts/run_pipeline_verification.py
└── outputs/{run-id}/                   # per-run artifacts
```

## Related

- [Fermatix/repo-sanitizer](https://github.com/Fermatix/repo-sanitizer) — scrub engine
