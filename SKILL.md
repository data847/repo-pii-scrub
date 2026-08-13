---
name: repo-pii-scrub
description: >-
  Pipeline to scrub PII and secrets from codebases using repo-sanitizer, with a
  brand pseudonymization pass, an independent gitleaks assertion, and zip
  packaging for dataset delivery. Full git history is delivered. Use when
  anonymizing repos, scrubbing PII, preparing sanitized repo deliverables, or
  running the repo-sanitizer workflow.
disable-model-invocation: true
---

# Repo PII Scrub Pipeline

Four gates. The sanitizer's own gates decide whether a repo is clean; `package`
adds an independent gitleaks check before zipping.

| Gate | Command | Purpose |
|------|---------|---------|
| 0 init | `orchestrator.py init` | Register source repo, slug, rulepack |
| 1 clone | `orchestrator.py clone` | Clone or copy source; record baseline commit count |
| 2 sanitize | `orchestrator.py sanitize` | Pass-1 scrub (regex, secrets, endpoints, NER) |
| 2b brand-map | `orchestrator.py brand-map` | Pass-2/Pass-3 brand pseudonyms; materialize `clean/` |
| 3 package | `orchestrator.py package` | gitleaks assertion + zip + `MANIFEST.json` |

In fast mode (`--fast`) NER is off and there is no brand pass, so `sanitize` goes
straight to `package`.

## Prerequisites

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
brew install gitleaks          # macOS

# Copy rulepack — see rules/README.md
export REPO_SANITIZER_SALT="$(openssl rand -hex 32)"   # never commit
```

| Requirement | Notes |
|-------------|-------|
| `repo-sanitizer` | PII + secrets scrub; requires gitleaks |
| `REPO_SANITIZER_SALT` | Deterministic redaction salt — the only required secret |
| `rules/` | Rulepack directory |
| Batch runs | `scripts/run_batch.py --repos-file <list>` |

## Configuration

| Variable | Purpose |
|----------|---------|
| `PII_SCRUB_NER_SERVICE_URL` | Use a shared NER service instead of per-worker models |
| `PII_SCRUB_NER_DEVICE` | `cpu` / `cuda:0` / `auto` (default `cpu`) |
| `PII_SCRUB_NER_SCOPE` | `head` (working tree, default), `all` (history too, slow), `off` |
| `PII_SCRUB_STEP_TIMEOUT` | Per-command cap, seconds (`0` = unlimited) |
| `PII_SCRUB_GATE_TIMEOUT` | Per-gate cap, seconds (`0` = unlimited) |

## Normal vs fast mode

| | Normal | Fast |
|---|---|---|
| NER (person/org names in free text) | on | off |
| Brand pseudonym pass | yes | no |
| Runtime, 1 MB / 473 files / 42 commits | ~25 min | ~22 s |
| Planted fixture PII redacted | 59/59 | 57/59 |

NER is ~98% of normal-mode runtime. Fast mode catches everything with a regex or
entropy signature (keys, tokens, emails, phones, endpoints, IDs) but leaves
free-text person names, so it is not suitable for external delivery.

Use a shared NER service for parallel batches — otherwise each worker loads its
own ~700 MB model and the pool deadlocks:

```bash
python scripts/ner_service_manager.py --port 8765 --device cpu
export PII_SCRUB_NER_SERVICE_URL=http://127.0.0.1:8765
```

## Agent workflow

1. **Read** [reference.md](reference.md) for step details and troubleshooting.
2. **Gate 0** — `init` with `--repo-slug`, `--source`, `--run-id`.
3. **Gate 1** — `clone`. Report commits before scrub.
4. **Gate 2** — `sanitize --pre-scan`. Report sanitizer `result.json` gate status.
5. **Gate 2b** — `brand-map`, passing `--term` for each known brand/org name.
6. **Gate 3** — `package`. Deliver zip path + `MANIFEST.json`.

Stop and report if any gate fails; do not hand over a deliverable from a failed
run. A `sanitize` gate failure means the rulepack needs work — fix it and re-run
Gate 2 rather than forcing past it.

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
python scripts/orchestrator.py package --run-dir $RUN
python scripts/orchestrator.py status --run-dir $RUN
```

Full walkthrough: [examples.md](examples.md)

## Outputs (per run directory)

| Path | Gate |
|------|------|
| `source/` | 1 — original clone |
| `commit_count_before.txt`, `head_before.txt` | 1 |
| `scan-pre/` | 2 — read-only pre-scan report |
| `sanitized/output/sanitized.bundle` | 2 |
| `brand_map.json`, `sanitized-brands/` | 2b |
| `clean/` | 2b — materialized sanitized repo, full history |
| `gitleaks.json`, `gitleaks.log` | 3 — independent secret scan (locations only) |
| **`{slug}_sanitized.zip`**, `MANIFEST.json` | 3 |

## Verifying the pipeline

`scripts/make_pii_fixture.py` builds a synthetic repo with 59 planted PII values
across the working tree, history-only blobs, commit messages, and author
identities. `scripts/run_pipeline_verification.py` runs the whole pipeline
against it and asserts that none of them survive:

```bash
python scripts/run_pipeline_verification.py --reuse-fixture
```

## Using a local repo (skip remote clone)

```bash
python scripts/orchestrator.py init \
  --run-id local-scrub \
  --repo-slug acme__api \
  --source /abs/path/to/existing/repo
```

## Agent checklist

```
- [ ] Confirm source (URL or local path) and repo slug with user
- [ ] Verify REPO_SANITIZER_SALT is set
- [ ] Verify rules/ rulepack exists (see rules/README.md)
- [ ] Collect brand/org terms to pass to brand-map
- [ ] Run gates 1–3; report sanitizer gate pass/fail
- [ ] Report: zip path, commits delivered, gitleaks result, bundle SHA
```

## Key paths

```
├── SKILL.md
├── reference.md              # full step-by-step workflow
├── examples.md
├── rules/                    # repo-sanitizer rulepack (customize per org)
├── scripts/orchestrator.py   # pipeline entry point
└── outputs/{run-id}/         # per-run artifacts
```

## Related

- [Fermatix/repo-sanitizer](https://github.com/Fermatix/repo-sanitizer) — scrub engine
