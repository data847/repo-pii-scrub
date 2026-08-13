# Examples — Repo PII Scrub

## Example 1 — GitHub repo end-to-end

```bash
cd skills/repo-pii-scrub
export REPO_SANITIZER_SALT="$(openssl rand -hex 32)"
export ANTHROPIC_API_KEY=sk-...

# One-time: install rulepack
git clone --depth 1 https://github.com/Fermatix/repo-sanitizer /tmp/repo-sanitizer
cp -a /tmp/repo-sanitizer/examples/rules/* rules/

RUN=outputs/acme-api-scrub

python scripts/orchestrator.py init \
  --run-id acme-api-scrub \
  --repo-slug acme-corp__api \
  --source git@github.com:acme-corp/api.git

python scripts/orchestrator.py clone --run-dir $RUN
python scripts/orchestrator.py sanitize --run-dir $RUN --pre-scan

# Review pre-scan if needed
cat $RUN/scan-pre/artifacts/scan_report_pre.json | head

python scripts/orchestrator.py llm-review --run-dir $RUN --auto
# If WARN:
python scripts/orchestrator.py llm-review --run-dir $RUN --human-approved

python scripts/orchestrator.py trim --run-dir $RUN --human-approved
python scripts/orchestrator.py verify --run-dir $RUN
python scripts/orchestrator.py package --run-dir $RUN

ls -lh $RUN/acme-corp__api_sanitized_first5pct.zip
cat $RUN/MANIFEST.json
```

## Example 2 — Local clone already on disk

```bash
RUN=outputs/local-scrub

python scripts/orchestrator.py init \
  --run-id local-scrub \
  --repo-slug web-genie__nodejs__flotivo \
  --source /Users/me/DataLabs/web-genie/work/nodejs_flotivo/clone

python scripts/orchestrator.py clone --run-dir $RUN
# ... same gates 2–6
```

## Example 3 — LLM FAIL → fix rulepack → retry

```bash
# After llm-review returns FAIL with client name "AcmeWidget"
echo "AcmeWidget" >> rules/dictionaries/clients.txt
echo "acmewidget.com" >> rules/dictionaries/domains.txt

# Reset gate state manually if needed — or re-init run
python scripts/orchestrator.py status --run-dir $RUN
# current_gate should still be "llm" — re-run sanitize from gate 2:
# Edit run_state.json: set current_gate to "sanitize", remove "sanitize" from gates_completed
# Or simpler: start a new --run-id

python scripts/orchestrator.py sanitize --run-dir $RUN
python scripts/orchestrator.py llm-review --run-dir $RUN --auto
```

## Example 4 — Custom history percentage

```bash
python scripts/orchestrator.py init \
  --run-id big-repo-scrub \
  --repo-slug org__monorepo \
  --source git@github.com:org/monorepo.git \
  --history-pct 10

python scripts/orchestrator.py trim --run-dir outputs/big-repo-scrub --human-approved --history-pct 10
```

## Example 5 — Metrics after delivery

```bash
cd ../dataset-repo-metrics
.venv/bin/python scripts/analyze_repo.py \
  ../repo-pii-scrub/outputs/acme-api-scrub/clean
```
