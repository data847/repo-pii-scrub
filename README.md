# repo-pii-scrub

A gated pipeline for removing PII, secrets and company-identifying data from Git
repositories — including their entire history — and packaging the result for delivery.

It wraps [`repo-sanitizer`](https://github.com/Fermatix/repo-sanitizer) with an
orchestrator, a brand-anonymization pass, an independent secret assertion, and a
reproducible verification harness that proves the pipeline actually redacts what it
claims to.

## Why the gates matter

Scrubbing a repo is not idempotent and not reversible. Each gate writes its state to
`run_state.json`, so a run can be inspected, resumed, or stopped between steps rather
than being one opaque command that either works or silently ships a leak.

| Gate | Command | What it does |
|------|---------|--------------|
| 0 | `init` | Register source, slug, rulepack |
| 1 | `clone` | Clone/copy the source, record baseline commit count |
| 2 | `sanitize` | Pass-1: redact PII/secrets/endpoints, rewrite all history, run gates |
| 2b | `brand-map` | Pass-2 brand map + Pass-3 `apply-map` across all history |
| 3 | `package` | gitleaks assertion, zip the deliverable, write `MANIFEST.json` |

Full git history is delivered. The sanitizer's own gates are what decide whether a repo
is clean, so a `sanitize` failure means the rulepack needs a term added — not that the
gate should be bypassed.

## The brand pass (Gate 2b)

Pass-1 deliberately **never rewrites an organization or brand name**. It reports them
as a *Pass-2 worklist*, which means the `ORG_NAME` / `BRAND_*` gates fail on any repo
that mentions its own company — permanently, no matter how many times you re-run.

Gate 2b closes that loop. It resolves each worklist finding back to its literal text,
reduces it to the brand token (dropping generic descriptors, so
`AcmePay Payments Platform` yields `AcmePay`), assigns a deterministic salted
pseudonym (`ANON_ORG_<hash>`), and runs Pass-3 `apply-map` to substitute it in every
blob, commit message and path name.

Terms come from the worklist plus any you pass explicitly:

```bash
python scripts/orchestrator.py brand-map --run-dir $RUN \
  --term AcmePay --term acmepayments --term АкмеПэй
```

Terms are only ever taken from findings and explicit `--term` flags — never derived
from the repo slug, which would map generic words like `repo` or `app` and corrupt
unrelated content.

## Quick start

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
brew install gitleaks                                   # or your package manager

export REPO_SANITIZER_SALT="$(openssl rand -hex 32)"     # never commit this

RUN=outputs/my-scrub
python scripts/orchestrator.py init --run-id my-scrub \
  --repo-slug org__my-repo --source /path/to/repo
python scripts/orchestrator.py clone     --run-dir $RUN
python scripts/orchestrator.py sanitize  --run-dir $RUN --pre-scan
python scripts/orchestrator.py brand-map --run-dir $RUN --term MyCompany
python scripts/orchestrator.py package   --run-dir $RUN
```

## Normal vs fast mode

`--fast` at `init` turns NER off and skips the brand pass. On a 1 MB / 473-file /
42-commit fixture that is ~22 s against ~25 min, and it redacts 57 of 59 planted
values instead of all 59. The two survivors are free-text person names, which only NER
finds — so fast mode is for internal triage, not delivery. A fast run's `MANIFEST.json`
says `"mode": "fast"` and `"not_for_external_delivery": true`.

`run_batch.py` accepts `--term` (repeatable) and `--terms-file` to seed the brand pass.

NER accounts for roughly 98% of normal-mode runtime. Every other detector is
negligible: regex PII ~0.2 s, secrets ~0.002 s, endpoints ~0.06 s.

## NER: device and the shared service

`rules/policies.yaml` sets `ner.device`. **On a host without CUDA (Apple Silicon
included) this must be `cpu`.** A `cuda:0` value there makes the model load hang
indefinitely rather than failing fast.

The NER model is roughly 700 MB. Every sanitize worker loads its own copy unless you
give them a shared service, which under parallelism exhausts memory and deadlocks —
processes sit at 0% CPU forever. Start one service and export its URL:

```bash
python scripts/ner_service_manager.py --device cpu --idle-timeout 0
export PII_SCRUB_NER_SERVICE_URL=http://127.0.0.1:8765
```

With the service running, workers stay small (tens of MB) and delegate inference over
HTTP.

| Variable | Default | Purpose |
|----------|---------|---------|
| `PII_SCRUB_NER_SERVICE_URL` | unset | Share one NER service across workers |
| `PII_SCRUB_NER_DEVICE` | `cpu` | `cpu` / `cuda:0` / `auto` |
| `PII_SCRUB_NER_SCOPE` | `head` | `head` = working tree, `all` = history too (slow), `off` |
| `PII_SCRUB_STEP_TIMEOUT` | `7200` | Per-command cap in seconds (`0` = unlimited) |
| `PII_SCRUB_GATE_TIMEOUT` | `10800` | Per-gate cap in seconds (`0` = unlimited) |

The timeouts exist so a wedged subprocess surfaces as a failed gate instead of a job
that appears to run for hours.

## Verifying the pipeline

A privacy pipeline you have not tested is a privacy pipeline you do not have. This
repo ships a fixture generator and a leak scanner.

```bash
python scripts/run_pipeline_verification.py --reuse-fixture
```

`make_pii_fixture.py` builds a medium-sized repo (hundreds of files, tens of commits)
seeded with every PII and secret class in the rulepack — emails, phone numbers, SSNs,
card numbers, IBANs, Russian passport/INN/OGRN/KPP/ФИО, JWTs, PEM keys, AWS/GitHub/
GitLab/Slack/Stripe/SendGrid/Google/npm/PyPI/Twilio/Mailchimp/Telegram credentials,
DSNs for Postgres/MySQL/MongoDB/Redis/AMQP, JDBC URLs, internal hostnames and public
IPs. It plants them in four distinct places:

- the working tree at `HEAD`
- blobs that exist **only in deleted history**
- commit messages
- commit author and committer identities

`verify_pii_fixture.py` then searches the deliverable — working tree, every history
blob, and all commit metadata — for each planted literal.

Crucially, `--check-patterns` first asserts that every planted value still matches its
own detector regex. Without that step a "clean" result is ambiguous: it could mean the
detector worked, or that the test value never matched anything in the first place.

```bash
python scripts/verify_pii_fixture.py --check-patterns
python scripts/verify_pii_fixture.py --repo path/to/clean --zip path/to/deliverable.zip
```

### A note on test IP addresses

Documentation ranges such as `203.0.113.0/24` (RFC 5737) are **intentionally kept** by
the endpoint detector — they are not real deployment fingerprints. A fixture must use a
globally routable address to exercise public-IP redaction at all.

## Batch runs

```bash
python scripts/run_batch.py --repos-file repos.txt --workers 4
```

`repos.txt` takes one repo per line, `slug` then path (a bare path derives the slug
from the directory name). Blank lines and `#` comments are ignored; `.json` files are
also accepted as a list or a `{slug: path}` mapping.

```
org__service-a   /abs/path/to/service-a
org__service-b   /abs/path/to/service-b
/abs/path/to/service-c
```

## Repository layout

```
├── SKILL.md                            # agent-facing workflow contract
├── reference.md                        # step-by-step detail and troubleshooting
├── examples.md
├── rules/                              # rulepack: regex patterns, policies, dictionaries
└── scripts/
    ├── orchestrator.py                 # gates 0–3
    ├── steps.py                        # step implementations
    ├── state.py                        # run-state persistence
    ├── batch_env.py                    # shared environment assembly
    ├── run_batch.py                    # batch driver
    ├── ner_service_manager.py          # shared NER service lifecycle
    ├── make_pii_fixture.py             # fixture generator
    ├── verify_pii_fixture.py           # leak scanner + detector self-check
    └── run_pipeline_verification.py    # end-to-end verification
```

## Security notes

- `REPO_SANITIZER_SALT` determines every pseudonym. Treat it as a secret: with the
  salt, hashed values become linkable back to their originals.
- `.env`, `.salt`, `outputs/` and `fixtures/` are gitignored. Never commit them.
- The fixture's planted credentials are synthetic, non-functional vendor
  documentation values. Do not replace them with real ones.
- `package` hard-fails if gitleaks finds a real secret in the deliverable. The
  sanitizer's own `REDACTED_<hash>` placeholders are high-entropy and would otherwise
  be reported as generic API keys, so they are filtered out by value. That filtering
  requires an unredacted scan, so the raw report is deleted immediately and only
  locations (rule, file, line) are kept in `gitleaks.json` — a matched secret is never
  written to disk or into an error message.

## Credits

Scrub engine: [Fermatix/repo-sanitizer](https://github.com/Fermatix/repo-sanitizer).
The `rules/` rulepack derives from that project.
