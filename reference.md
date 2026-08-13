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

## Step 2 — Scrub PII with repo-sanitizer (Pass-1)

**Orchestrator:** `orchestrator.py sanitize --run-dir $RUN [--pre-scan]`

1. Optional pre-scan → `{run-dir}/scan-pre/`. This is read-only and reports a
   finding count; findings are expected and are not a failure.
2. `repo-sanitizer sanitize --gate` → `{run-dir}/sanitized/`

Requires `REPO_SANITIZER_SALT` and a valid `rules/` rulepack.

The sanitizer's gates are what decide whether a repo is clean. If a gate fails on
anything other than a brand/org name, extend the rulepack and re-run this step —
do not proceed.

Brand and org gates (`ORG_NAME`, `BRAND_IDENTIFIER`, `BRAND_PATH`,
`PACKAGE_NAMESPACE`) are not failures here. They are carried forward as a
worklist for Step 2b, which is where they get pseudonymized.

---

## Step 2b — Brand map (Pass-2 and Pass-3)

**Orchestrator:** `orchestrator.py brand-map --run-dir $RUN [--term AcmeCorp ...]`

1. Collect brand terms: the Pass-1 worklist plus any explicit `--term` values.
2. Assign each a deterministic salted pseudonym → `brand_map.json`.
3. `repo-sanitizer apply-map` rewrites them across all of git history →
   `{run-dir}/sanitized-brands/`.
4. Clone the resulting bundle → `{run-dir}/clean/`.

Pass terms you know about explicitly. Terms are never derived from the repo slug,
because generic words in a slug ("app", "backend") would rewrite unrelated code.

In fast mode there is no brand pass; `sanitize` materializes `clean/` itself.

---

## Step 3 — Package

**Orchestrator:** `orchestrator.py package --run-dir $RUN`

1. gitleaks assertion over `clean/`. The sanitizer's `REDACTED_<hash>`
   placeholders are high-entropy, so gitleaks flags them as generic API keys;
   those are filtered out by value and only genuine findings fail the gate. The
   scan runs unredacted to make that distinction, then the raw report is deleted
   and only locations (rule, file, line) are kept in `gitleaks.json`.
2. Zip → `{repo_slug}_sanitized.zip`, including full `.git` history.
3. `MANIFEST.json` — commits before, commits delivered, bundle SHA, secret-scan path.

Excludes: `node_modules`, `.venv`, `vendor`, `dist`, `build`, `.next`, `__pycache__`.

---

## Verifying the pipeline itself

`scripts/make_pii_fixture.py` builds a synthetic repo with 59 planted PII values
spread across the working tree, history-only blobs, commit messages, and author
identities, and writes a manifest of them.

`scripts/verify_pii_fixture.py` has two modes:

- `--check-patterns` asserts each planted value actually matches its intended
  detector, so a passing scrub cannot be an artifact of a broken fixture.
- default mode scans a deliverable (directory or zip) for every planted literal
  across the working tree, all history blobs, and commit metadata.

`scripts/run_pipeline_verification.py` chains both around a real pipeline run:

```bash
python scripts/run_pipeline_verification.py --reuse-fixture
```

Normal mode redacts 59/59. Fast mode redacts 57/59, leaving free-text person
names that only NER can find.

---

## Performance

NER dominates normal-mode runtime — roughly 98% of it, across three passes over
the tree. Everything else is negligible (regex PII ~0.2s, secrets ~0.002s,
endpoints ~0.06s on a 1 MB repo).

For parallel batches, run one shared NER service instead of letting each worker
load its own ~700 MB model, which exhausts memory and deadlocks the pool:

```bash
python scripts/ner_service_manager.py --port 8765 --device cpu
export PII_SCRUB_NER_SERVICE_URL=http://127.0.0.1:8765
```

Use `--device cpu` on Apple Silicon. A `cuda:0` default will hang on a machine
without CUDA rather than failing outright.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `gitleaks not found` | `brew install gitleaks` |
| `Rulepack not found` | Copy from repo-sanitizer `examples/rules/` → `rules/` |
| Sanitize gate fails | Inspect `scan-pre/artifacts/`; extend dictionaries |
| Brand gate still failing after Pass-3 | Add the term explicitly via `--term` |
| Sanitize hangs at 0% CPU | NER model loading on a non-CUDA device, or one model per worker — set `ner.device: cpu` and use the shared NER service |
| `gitleaks found N real secret(s)` | Genuine leak in the deliverable; extend the rulepack and re-run Step 2 |
| `git filter-repo` missing | `pip install git-filter-repo` |
| LFS / binary leaks | Add denied paths in rulepack; repo-sanitizer skips LFS fetch |

---

## Manual commands (without orchestrator)

See the original workflow doc at  
`skills/dataset-repo-metrics/REPO_PII_SCRUB_WORKFLOW.md` (legacy path; prefer this skill).
