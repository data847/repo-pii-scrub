# Examples — Repo PII Scrub

## Example 1 — GitHub repo end-to-end

```bash
cd skills/repo-pii-scrub
export REPO_SANITIZER_SALT="$(openssl rand -hex 32)"

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

# Pass every brand/org name you know about
python scripts/orchestrator.py brand-map --run-dir $RUN \
  --term AcmeCorp --term acme-corp --term acmecorp.com

python scripts/orchestrator.py package --run-dir $RUN

ls -lh $RUN/acme-corp__api_sanitized.zip
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
# ... same gates 2 → 2b → 3
```

## Example 3 — Sanitize gate fails → fix rulepack → retry

```bash
# A gate failure on anything other than a brand name means the rulepack is short
# a term. Add it, then re-run gate 2.
echo "AcmeWidget" >> rules/dictionaries/clients.txt
echo "acmewidget.com" >> rules/dictionaries/domains.txt

python scripts/orchestrator.py status --run-dir $RUN
# current_gate is still "sanitize", so just re-run it:
python scripts/orchestrator.py sanitize --run-dir $RUN
```

## Example 4 — Fast mode (internal triage only)

```bash
# NER off, no brand pass: seconds instead of minutes, but free-text person names
# survive. Not for external delivery.
python scripts/orchestrator.py init \
  --run-id quick-look \
  --repo-slug org__monorepo \
  --source git@github.com:org/monorepo.git \
  --fast

RUN=outputs/quick-look
python scripts/orchestrator.py clone --run-dir $RUN
python scripts/orchestrator.py sanitize --run-dir $RUN
python scripts/orchestrator.py package --run-dir $RUN
```

## Example 5 — Parallel batch with a shared NER service

```bash
# One model load serves every worker; without this the pool deadlocks.
python scripts/ner_service_manager.py --port 8765 --device cpu &
export PII_SCRUB_NER_SERVICE_URL=http://127.0.0.1:8765

python scripts/run_batch.py --repos-file repos.txt --workers 4
```

## Example 6 — Verify the pipeline against the PII fixture

```bash
python scripts/run_pipeline_verification.py --reuse-fixture
# → VERIFICATION PASSED, 59/59 planted values redacted
```

## Example 7 — Metrics after delivery

```bash
cd ../dataset-repo-metrics
.venv/bin/python scripts/analyze_repo.py \
  ../repo-pii-scrub/outputs/acme-api-scrub/clean
```
