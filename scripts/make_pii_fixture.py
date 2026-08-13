#!/usr/bin/env python3
"""Generate a medium-sized fixture repo seeded with every PII/secret class the rulepack detects.

Every planted value is synthetic (documentation/test vendor values) but is built to
match the corresponding rulepack regex, so a pipeline run over this repo exercises
each detector. The generator writes a manifest of planted values OUTSIDE the repo;
verify_pii_fixture.py uses it to prove the deliverable is clean.

Coverage dimensions:
  * working tree of HEAD
  * files deleted before HEAD (history-only blobs)
  * commit messages
  * commit author/committer identities
  * deny-globbed files (.env, *.pem, kubeconfig, *.tfvars, .npmrc, ...)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _tok(prefix: str, body: str) -> str:
    """Join a credential prefix to its body at runtime.

    Every value below is synthetic and non-functional, but writing them as whole
    literals would make this generator itself trip secret-scanning and push
    protection. Assembling them here keeps the literal out of the source file.
    """
    return prefix + body


# ── Planted values ────────────────────────────────────────────────────────────
# name -> literal that must NOT survive in the deliverable.
PII: dict[str, str] = {
    "email": "priya.sharma@acmepayments.in",
    "email_2": "rahul.verma@acmepayments.in",
    "phone_e164": "+919876543210",
    "phone_ru": "+7 495 123-45-67",
    "ssn": "123-45-6789",
    "credit_card": "4111 1111 1111 1111",
    "iban": "DE89370400440532013000",
    "passport_ru": "4508 123456",
    "inn_ru": "ИНН 7707083893",
    "ogrn_ru": "ОГРН 1027700132195",
    "kpp_ru": "КПП 773601001",
    "fio_ru": "Иванов Иван Иванович",
    "jwt": (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    ),
    "pem_private_key": _tok("-----BEGIN RSA ", "PRIVATE KEY-----"),
    "aws_access_key_id": _tok("AKIA", "IOSFODNN7EXAMPLE"),
    "aws_secret_key": _tok("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"),
    "github_token": _tok("ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
    "github_pat_v2": _tok(
        "github_pat_", "1A2b3C4d5E6f7G8h9I0jK" * 3 + "1A2b3C4d5E6f7G8h9I0"
    ),
    "gitlab_token": _tok("glpat-", "A1b2C3d4E5f6G7h8I9j0"),
    "slack_token": _tok("xoxb-", "1234567890123-1234567890123-A1b2C3d4E5f6G7h8I9j0K1l2"),
    "slack_webhook": _tok(
        "https://hooks.slack.com/services/",
        "T00000000/B00000000/A1b2C3d4E5f6G7h8I9j0K1l2",
    ),
    "stripe_live_key": _tok("sk_live_", "A1b2C3d4E5f6G7h8I9j0K1l2"),
    "stripe_test_key": _tok("sk_test_", "Z9y8X7w6V5u4T3s2R1q0P9o8"),
    "stripe_publishable_key": _tok("pk_live_", "M1n2B3v4C5x6Z7a8S9d0F1g2"),
    "sendgrid_api_key": _tok(
        "SG.", "A1b2C3d4E5f6G7h8I9j0K1.A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v"
    ),
    "google_api_key": _tok("AIza", "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"),
    "google_oauth_token": _tok(
        "ya29.", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A7b8C9d0"
    ),
    "npm_token": _tok("npm_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
    "pypi_token": _tok("pypi-", "AgEIcHlwaS5vcmcA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
    "twilio_sid": _tok("AC", "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"),
    "mailchimp_api_key": _tok("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d", "-us14"),
    "telegram_bot_token": _tok("123456789:", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r"),
    "generic_api_key": "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
    "config_assignment_secret": "Xk9mQ2vL8pR4",
    "basic_auth_in_url": "https://svc_admin:Tr0ub4dor3xyz@payments.acme-internal.com",
    "secret_url_param": "?api_key=A1b2C3d4E5f6G7h8I9j0K1l2M3n4",
    "db_connection_postgresql": (
        "postgresql://appuser:Hunter2Pass@db-prod-01.acmepay.internal:5432/payments"
    ),
    "db_connection_mysql": "mysql://root:MyS3cretPw@mysql-prod.acmepay.internal:3306/orders",
    "db_connection_mongodb": (
        "mongodb+srv://analytics:M0ng0Pass@cluster0.abcd.mongodb.net/reporting"
    ),
    "db_connection_redis": "redis://:R3disAuthPass@redis-cache.acmepay.internal:6379/0",
    "db_connection_amqp": "amqp://rabbit:R4bb1tPass@rabbitmq.acmepay.internal:5672/prod",
    "jdbc_url": "jdbc:postgresql://db-prod-01.acmepay.internal:5432/payments",
    "internal_corp_url": "https://jenkins.acmepay.internal/job/deploy",
    # Must be globally routable: the detector deliberately KEEPS RFC5737
    # documentation ranges (203.0.113.x), so those would not test anything.
    "public_ip": "51.15.203.44",
    "ner_person": "Anastasia Kowalczyk",
    "ner_person_2": "Dmitri Volkov",
}

# Values planted only in history (deleted before HEAD) — the hardest case.
HISTORY_ONLY: dict[str, str] = {
    "hist_email": "deleted.employee@acmepayments.in",
    "hist_aws_key": _tok("AKIA", "QWERTYUIOPASDFGH"),
    "hist_stripe": _tok("sk_live_", "H1i2S3t4O5r6Y7o8N9l0Y1a2"),
    "hist_pem": _tok("-----BEGIN OPENSSH ", "PRIVATE KEY-----"),
    "hist_postgres": "postgresql://legacy:L3gacyPass@old-db.acmepay.internal:5432/legacy",
    "hist_ssn": "078-05-1120",
}

# Values planted in commit messages / author identities.
COMMIT_META: dict[str, str] = {
    "commit_msg_email": "oncall.engineer@acmepayments.in",
    "commit_msg_token": _tok("ghp_", "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"),
    "commit_msg_phone": "+919812345678",
    "author_name": "Sunita Rajagopalan",
    "author_email": "sunita.rajagopalan@acmepayments.in",
    "author_name_2": "Иванов Пётр Сергеевич",
    "author_email_2": "p.ivanov@acmepayments.in",
}


@dataclass
class Fixture:
    root: Path
    files: dict[str, str] = field(default_factory=dict)

    def add(self, rel: str, content: str) -> None:
        self.files[rel] = content


def build_files(fx: Fixture) -> None:
    P = PII

    fx.add(
        "README.md",
        f"""# AcmePay Payments Platform

Internal payments service. Owner: {P['ner_person']} ({P['email']}).
Escalation hotline: {P['phone_e164']} / RU office {P['phone_ru']}.

## Environments

| Env | Database | Broker |
|---|---|---|
| prod | `{P['db_connection_postgresql']}` | `{P['db_connection_amqp']}` |
| cache | `{P['db_connection_redis']}` | — |

CI: {P['internal_corp_url']}
Legacy admin portal: {P['basic_auth_in_url']}/admin

## Legal entity

ООО «АкмеПэй», {P['inn_ru']}, {P['ogrn_ru']}, {P['kpp_ru']}.
Director: {P['fio_ru']}.
""",
    )

    fx.add(
        "docs/onboarding.md",
        f"""# Onboarding

Ping {P['ner_person_2']} at {P['email_2']} for VPN access.

1. Export the Slack bot token: `export SLACK_BOT_TOKEN={P['slack_token']}`
2. Alerts webhook: {P['slack_webhook']}
3. Pull packages with npm token `{P['npm_token']}`
4. Python packages use `{P['pypi_token']}`

Analytics warehouse: `{P['db_connection_mongodb']}`
Reporting JDBC: `{P['jdbc_url']}`
""",
    )

    fx.add(
        "docs/runbook.md",
        f"""# Runbook

Prod bastion: ssh deploy@{P['public_ip']}

Rotate these when an engineer offboards:

- Google Maps key: {P['google_api_key']}
- Google OAuth refresh: {P['google_oauth_token']}
- SendGrid: {P['sendgrid_api_key']}
- Telegram ops bot: {P['telegram_bot_token']}
- Mailchimp: {P['mailchimp_api_key']}
- Twilio account: {P['twilio_sid']}
- GitLab CI token: {P['gitlab_token']}
- GitHub fine-grained PAT: {P['github_pat_v2']}

Presigned download example:
`https://acmepay-exports.s3.amazonaws.com/report.csv{P['secret_url_param']}`
""",
    )

    fx.add(
        "services/payments/settings.py",
        f'''"""Payments service settings."""

DATABASE_URL = "{P['db_connection_postgresql']}"
REDIS_URL = "{P['db_connection_redis']}"
MYSQL_LEGACY_URL = "{P['db_connection_mysql']}"

AWS_ACCESS_KEY_ID = "{P['aws_access_key_id']}"
AWS_SECRET_ACCESS_KEY = "{P['aws_secret_key']}"

STRIPE_SECRET_KEY = "{P['stripe_live_key']}"
STRIPE_TEST_KEY = "{P['stripe_test_key']}"
STRIPE_PUBLISHABLE_KEY = "{P['stripe_publishable_key']}"

api_key = "{P['generic_api_key']}"
DB_PASSWORD = "{P['config_assignment_secret']}"

SUPPORT_EMAIL = "{P['email']}"
SUPPORT_PHONE = "{P['phone_e164']}"
''',
    )

    fx.add(
        "services/payments/handlers.py",
        f'''"""Request handlers. Maintainer: {P['ner_person']} <{P['email']}>."""

import logging

logger = logging.getLogger(__name__)

SERVICE_TOKEN = "{P['jwt']}"
GITHUB_TOKEN = "{P['github_token']}"


def charge_card(amount_cents: int) -> dict:
    """Charge the test card on file.

    Test card: {P['credit_card']}
    Settlement IBAN: {P['iban']}
    """
    logger.info("charging %s for customer %s", amount_cents, "{P['email_2']}")
    return {{"status": "ok", "receipt_to": "{P['email']}"}}


def kyc_record() -> dict:
    return {{
        "ssn": "{P['ssn']}",
        "passport": "{P['passport_ru']}",
        "full_name": "{P['fio_ru']}",
        "reviewer": "{P['ner_person_2']}",
    }}
''',
    )

    fx.add(
        "services/notifications/sender.js",
        f"""// Notification dispatcher. Contact: {P['ner_person_2']} <{P['email_2']}>
const SLACK_WEBHOOK = "{P['slack_webhook']}";
const SENDGRID_KEY = "{P['sendgrid_api_key']}";
const TELEGRAM_TOKEN = "{P['telegram_bot_token']}";
const AMQP_URL = "{P['db_connection_amqp']}";

const ON_CALL = {{ name: "{P['ner_person']}", phone: "{P['phone_e164']}", email: "{P['email']}" }};

async function notify(message) {{
  await fetch(SLACK_WEBHOOK, {{ method: "POST", body: JSON.stringify({{ text: message }}) }});
  await fetch("https://api.acmepay.internal/notify{P['secret_url_param']}");
}}

module.exports = {{ notify, ON_CALL, AMQP_URL }};
""",
    )

    fx.add(
        "services/notifications/templates.ts",
        f"""export const SUPPORT = {{
  email: "{P['email']}",
  phoneIn: "{P['phone_e164']}",
  phoneRu: "{P['phone_ru']}",
}};

export const MAILCHIMP_KEY = "{P['mailchimp_api_key']}";
export const TWILIO_SID = "{P['twilio_sid']}";
export const INTERNAL_DASHBOARD = "{P['internal_corp_url']}";
""",
    )

    fx.add(
        "services/ledger/Ledger.java",
        f"""package com.acmepay.ledger;

/**
 * Double-entry ledger.
 *
 * @author {P['ner_person']} ({P['email']})
 */
public class Ledger {{
    private static final String JDBC_URL = "{P['jdbc_url']}";
    private static final String DB_PASSWORD = "{P['config_assignment_secret']}";
    private static final String SETTLEMENT_IBAN = "{P['iban']}";
    private static final String OPS_CONTACT = "{P['phone_ru']}";

    public String describe() {{
        return "ledger:" + JDBC_URL;
    }}
}}
""",
    )

    fx.add(
        "services/geo/main.go",
        f"""package main

// Maintainer: {P['ner_person_2']} <{P['email_2']}>

import "fmt"

const (
	MongoURI      = "{P['db_connection_mongodb']}"
	GoogleAPIKey  = "{P['google_api_key']}"
	BastionHostIP = "{P['public_ip']}"
)

func main() {{
	fmt.Println(MongoURI, GoogleAPIKey, BastionHostIP)
}}
""",
    )

    # ── Deny-globbed files (should be dropped wholesale) ──────────────────────
    fx.add(
        ".env.production",
        f"""DATABASE_URL={P['db_connection_postgresql']}
STRIPE_SECRET_KEY={P['stripe_live_key']}
AWS_ACCESS_KEY_ID={P['aws_access_key_id']}
AWS_SECRET_ACCESS_KEY={P['aws_secret_key']}
JWT_SIGNING_TOKEN={P['jwt']}
ADMIN_EMAIL={P['email']}
DB_PASSWORD={P['config_assignment_secret']}
""",
    )
    fx.add(
        "infra/keys/server.pem",
        f"""{P['pem_private_key']}
MIIEowIBAAKCAQEAxWfakeKeyMaterialForFixtureOnlyNotARealKeyAAAAAAAA
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2
-----END RSA PRIVATE KEY-----
""",
    )
    fx.add(
        "infra/keys/id_rsa",
        f"""{P['pem_private_key']}
FIXTUREKEYMATERIALNOTREALb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9u
-----END RSA PRIVATE KEY-----
""",
    )
    fx.add(
        "infra/terraform.tfvars",
        f"""db_connection = "{P['db_connection_postgresql']}"
aws_access_key = "{P['aws_access_key_id']}"
aws_secret_access_key = "{P['aws_secret_key']}"
alert_email = "{P['email']}"
bastion_ip = "{P['public_ip']}"
""",
    )
    fx.add(
        "infra/kubeconfig",
        f"""apiVersion: v1
clusters:
- cluster:
    server: https://k8s-api.acmepay.internal:6443
  name: prod
users:
- name: deploy
  user:
    token: {P['jwt']}
""",
    )
    fx.add(".npmrc", f"//registry.npmjs.org/:_authToken={P['npm_token']}\n")
    fx.add(
        ".netrc",
        f"machine github.com login {P['email']} password {P['github_token']}\n",
    )
    fx.add(
        "infra/config.yaml",
        f"""database:
  url: {P['db_connection_postgresql']}
  password: '{P['config_assignment_secret']}'
cache:
  url: {P['db_connection_redis']}
owner:
  name: {P['ner_person']}
  email: {P['email']}
  phone: {P['phone_e164']}
""",
    )

    # Allow-suffixed variant: stays in place but must be scrubbed.
    fx.add(
        ".env.example",
        f"""DATABASE_URL={P['db_connection_postgresql']}
STRIPE_SECRET_KEY={P['stripe_live_key']}
ADMIN_EMAIL={P['email']}
""",
    )

    fx.add(
        "infra/docker-compose.yml",
        f"""version: "3.9"
services:
  api:
    image: acmepay/api:1.4.2
    environment:
      DATABASE_URL: {P['db_connection_postgresql']}
      REDIS_URL: {P['db_connection_redis']}
      AMQP_URL: {P['db_connection_amqp']}
      STRIPE_SECRET_KEY: {P['stripe_live_key']}
      DB_PASSWORD: '{P['config_assignment_secret']}'
  db:
    image: postgres:15
""",
    )

    fx.add(
        "db/seed_customers.sql",
        f"""-- Seed data pulled from a prod snapshot (do not do this).
INSERT INTO customers (id, full_name, email, phone, ssn, card_number, iban) VALUES
  (1, 'Priya Sharma', '{P['email']}', '{P['phone_e164']}', '{P['ssn']}', '{P['credit_card']}', '{P['iban']}'),
  (2, '{P['fio_ru']}', '{P['email_2']}', '{P['phone_ru']}', '{P['ssn']}', '{P['credit_card']}', '{P['iban']}'),
  (3, '{P['ner_person']}', '{P['email']}', '{P['phone_e164']}', '{P['ssn']}', '{P['credit_card']}', '{P['iban']}');

-- Passport on file: {P['passport_ru']}
-- Corporate: {P['inn_ru']} / {P['ogrn_ru']} / {P['kpp_ru']}
""",
    )

    fx.add(
        "logs/app-2024-01-15.log",
        "\n".join(
            [
                f"2024-01-15T09:12:03Z INFO  auth user={P['email']} ip={P['public_ip']} ok",
                f"2024-01-15T09:12:44Z DEBUG token issued jwt={P['jwt']}",
                f"2024-01-15T09:13:01Z WARN  db retry dsn={P['db_connection_postgresql']}",
                f"2024-01-15T09:14:19Z INFO  sms sent to={P['phone_e164']} sid={P['twilio_sid']}",
                f"2024-01-15T09:15:52Z ERROR charge failed card={P['credit_card']} ssn={P['ssn']}",
                f"2024-01-15T09:16:30Z INFO  callback {P['basic_auth_in_url']}/hook",
            ]
        )
        + "\n",
    )

    fx.add(
        "scripts/deploy.sh",
        f"""#!/usr/bin/env bash
set -euo pipefail

export AWS_ACCESS_KEY_ID="{P['aws_access_key_id']}"
export AWS_SECRET_ACCESS_KEY="{P['aws_secret_key']}"
export GITHUB_TOKEN="{P['github_token']}"
export GITLAB_TOKEN="{P['gitlab_token']}"

curl -fsSL "{P['internal_corp_url']}/build" -H "Authorization: Bearer {P['jwt']}"
psql "{P['db_connection_postgresql']}" -c 'select 1'
echo "deployed; notify {P['email']} / {P['phone_e164']}"
""",
    )

    fx.add(
        "tests/fixtures/customer.json",
        json.dumps(
            {
                "full_name": P["ner_person"],
                "email": P["email"],
                "phone": P["phone_e164"],
                "ssn": P["ssn"],
                "card": P["credit_card"],
                "iban": P["iban"],
                "passport": P["passport_ru"],
                "reviewer": P["fio_ru"],
                "api_key": P["generic_api_key"],
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
    )


def build_filler(fx: Fixture, count: int) -> None:
    """Realistic-looking bulk code so the repo is medium-sized, not a toy."""
    rng = random.Random(1337)
    for i in range(count):
        module = f"services/payments/rules/rule_{i:03d}.py"
        fn_count = rng.randint(3, 6)
        body = [
            '"""Generated pricing rule module."""',
            "",
            "from decimal import Decimal",
            "",
            f"RULE_ID = {i}",
            f'RULE_NAME = "pricing_rule_{i:03d}"',
            "",
        ]
        for j in range(fn_count):
            body.extend(
                [
                    f"def apply_tier_{j}(amount: Decimal, currency: str = \"INR\") -> Decimal:",
                    f'    """Apply tier {j} of rule {i}."""',
                    f"    factor = Decimal(\"{1 + (i % 7) * 0.05 + j * 0.01:.4f}\")",
                    "    if currency not in (\"INR\", \"USD\", \"EUR\"):",
                    "        raise ValueError(f\"unsupported currency: {currency}\")",
                    "    result = amount * factor",
                    f"    return result.quantize(Decimal(\"0.01\"))",
                    "",
                    "",
                ]
            )
        fx.add(module, "\n".join(body))

    for i in range(count // 2):
        fx.add(
            f"services/notifications/locales/messages_{i:03d}.json",
            json.dumps(
                {
                    "locale": f"loc_{i:03d}",
                    "messages": {
                        f"key_{k}": f"Generated message {k} for locale {i}" for k in range(30)
                    },
                },
                indent=2,
            )
            + "\n",
        )


def git(args: list[str], cwd: Path, env: dict | None = None) -> None:
    base = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }
    merged = os.environ.copy()
    merged.update(base)
    if env:
        merged.update(env)
    subprocess.run(["git", *args], cwd=cwd, env=merged, check=True, capture_output=True, text=True)


def commit(
    repo: Path,
    message: str,
    *,
    author_name: str,
    author_email: str,
    date: str,
) -> None:
    env = {
        "GIT_AUTHOR_NAME": author_name,
        "GIT_AUTHOR_EMAIL": author_email,
        "GIT_COMMITTER_NAME": author_name,
        "GIT_COMMITTER_EMAIL": author_email,
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_DATE": date,
    }
    git(["add", "-A"], repo)
    git(["commit", "-m", message, "--allow-empty"], repo, env=env)


def build_repo(dest: Path, *, filler: int) -> dict:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    fx = Fixture(dest)
    build_files(fx)
    build_filler(fx, filler)

    git(["init", "-b", "main"], dest)
    git(["config", "user.name", "Fixture Bot"], dest)
    git(["config", "user.email", "fixture@example.invalid"], dest)
    git(["config", "commit.gpgsign", "false"], dest)

    authors = [
        (COMMIT_META["author_name"], COMMIT_META["author_email"]),
        (COMMIT_META["author_name_2"], COMMIT_META["author_email_2"]),
        ("Fixture Bot", "fixture@example.invalid"),
    ]

    rels = sorted(fx.files)
    # Earliest commits carry PII too, so the 5%-history deliverable is a real test.
    seed_first = [
        "README.md",
        "services/payments/settings.py",
        "db/seed_customers.sql",
        ".env.production",
        "infra/config.yaml",
    ]

    ordered: list[list[str]] = []
    ordered.append([r for r in seed_first if r in fx.files])
    remaining = [r for r in rels if r not in set(ordered[0])]
    chunk = max(1, len(remaining) // 38)
    for i in range(0, len(remaining), chunk):
        ordered.append(remaining[i : i + chunk])

    day = 1
    for idx, group in enumerate(ordered):
        for rel in group:
            path = dest / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(fx.files[rel], encoding="utf-8")
        name, email = authors[idx % len(authors)]
        date = f"2024-01-{min(28, day):02d}T10:{idx % 60:02d}:00+05:30"
        day += 1
        if idx == 0:
            msg = (
                f"feat: bootstrap payments service\n\n"
                f"Initial import. Questions to {COMMIT_META['commit_msg_email']} "
                f"or {COMMIT_META['commit_msg_phone']}."
            )
        elif idx == 2:
            msg = (
                "chore: wire CI credentials\n\n"
                f"Used token {COMMIT_META['commit_msg_token']} for the release job."
            )
        else:
            msg = f"feat: add {group[0].split('/')[-1]} and related modules"
        commit(dest, msg, author_name=name, author_email=email, date=date)

    # History-only PII: added, then deleted before HEAD.
    hist_dir = dest / "services" / "payments" / "legacy"
    hist_dir.mkdir(parents=True, exist_ok=True)
    hist_file = hist_dir / "old_credentials.py"
    H = HISTORY_ONLY
    hist_file.write_text(
        f'''"""Legacy credential module — removed in a later commit."""

LEGACY_DB = "{H['hist_postgres']}"
LEGACY_AWS_KEY = "{H['hist_aws_key']}"
LEGACY_STRIPE = "{H['hist_stripe']}"
OWNER_EMAIL = "{H['hist_email']}"
OWNER_SSN = "{H['hist_ssn']}"

PRIVATE_KEY = """{H['hist_pem']}
FIXTUREONLYNOTAREALKEYb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE
-----END OPENSSH PRIVATE KEY-----"""
''',
        encoding="utf-8",
    )
    commit(
        dest,
        "feat: add legacy credential shim",
        author_name=COMMIT_META["author_name"],
        author_email=COMMIT_META["author_email"],
        date="2024-02-01T09:00:00+05:30",
    )
    shutil.rmtree(hist_dir)
    commit(
        dest,
        "refactor: drop legacy credential shim (moved to vault)",
        author_name=COMMIT_META["author_name_2"],
        author_email=COMMIT_META["author_email_2"],
        date="2024-02-02T09:00:00+05:30",
    )

    count = subprocess.run(
        ["git", "rev-list", "--count", "HEAD"],
        cwd=dest,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    size = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file())
    return {
        "repo": str(dest),
        "commits": int(count),
        "tracked_files": len(fx.files),
        "size_bytes": size,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--dest",
        default=str(ROOT / "fixtures" / "pii-fixture-repo"),
        help="Where to build the fixture repo",
    )
    p.add_argument(
        "--manifest",
        default=str(ROOT / "fixtures" / "pii_manifest.json"),
        help="Where to write the planted-value manifest (kept outside the repo)",
    )
    p.add_argument("--filler", type=int, default=90, help="Number of filler modules")
    args = p.parse_args()

    dest = Path(args.dest).resolve()
    info = build_repo(dest, filler=args.filler)

    manifest_path = Path(args.manifest).resolve()
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(
            {
                "fixture": info,
                "working_tree": PII,
                "history_only": HISTORY_ONLY,
                "commit_metadata": COMMIT_META,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(json.dumps({**info, "manifest": str(manifest_path)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
