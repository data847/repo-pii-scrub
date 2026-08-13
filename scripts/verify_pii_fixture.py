#!/usr/bin/env python3
"""Verify a scrubbed fixture deliverable contains none of the planted PII.

Two modes:
  --check-patterns   assert each planted value matches its rulepack regex, so a
                     clean result means "detector fired", not "value never matched".
  (default)          scan a deliverable for every planted literal across the
                     working tree, every history blob, commit messages, and
                     author/committer identities.

Exit code 1 if any planted value survives (or, with --check-patterns, if any
planted value fails to match its own detector).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Latin personal names and IPs have no regex in the rulepack by design (NER and
# EndpointDetector own them), so --check-patterns skips them.
NON_REGEX_KEYS = {"ner_person", "ner_person_2", "public_ip", "author_name"}

# Planted key -> rulepack pattern name, when the names differ.
PATTERN_ALIASES = {
    "email_2": "email",
    "hist_email": "email",
    "hist_aws_key": "aws_access_key_id",
    "hist_stripe": "stripe_live_key",
    "hist_pem": "pem_private_key",
    "hist_postgres": "db_connection_postgresql",
    "hist_ssn": "ssn",
    "commit_msg_email": "email",
    "commit_msg_token": "github_token",
    "commit_msg_phone": "phone_e164",
    "author_email": "email",
    "author_email_2": "email",
    "author_name_2": "fio_ru",
}


def load_rulepack_patterns(rulepack: Path) -> dict[str, str]:
    import yaml

    data = yaml.safe_load((rulepack / "regex" / "pii_patterns.yaml").read_text(encoding="utf-8"))
    return {p["name"]: p["pattern"] for p in data["patterns"]}


def planted_values(manifest: dict) -> dict[str, str]:
    merged: dict[str, str] = {}
    for section in ("working_tree", "history_only", "commit_metadata"):
        merged.update(manifest.get(section, {}))
    return merged


def check_patterns(manifest: dict, rulepack: Path) -> int:
    patterns = load_rulepack_patterns(rulepack)
    values = planted_values(manifest)

    unmatched: list[str] = []
    matched = 0
    skipped: list[str] = []

    for key, value in values.items():
        if key in NON_REGEX_KEYS:
            skipped.append(key)
            continue
        pattern_name = PATTERN_ALIASES.get(key, key)
        regex = patterns.get(pattern_name)
        if regex is None:
            unmatched.append(f"{key}: no rulepack pattern named '{pattern_name}'")
            continue
        # Some patterns need surrounding context (assignment form); test both.
        candidates = [value, f'api_key = "{value}"', f'DB_PASSWORD = "{value}"']
        if pattern_name == "aws_secret_key":
            candidates.append(f'AWS_SECRET_ACCESS_KEY = "{value}"')
        if pattern_name == "secret_url_param":
            candidates.append(f"https://example.com/x{value}")
        if any(re.search(regex, c) for c in candidates):
            matched += 1
        else:
            unmatched.append(f"{key}: value does not match /{pattern_name}/")

    print(f"pattern self-check: {matched} matched, {len(skipped)} skipped (non-regex detectors)")
    for key in sorted(skipped):
        print(f"  skipped: {key}")
    if unmatched:
        print("\nFIXTURE PROBLEMS (planted value would never be detected):")
        for line in unmatched:
            print(f"  {line}")
        return 1
    print("\nAll regex-backed planted values match their detector.")
    return 0


def git_out(args: list[str], cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout


def scan_repo(repo: Path, values: dict[str, str]) -> dict[str, list[str]]:
    """Search working tree, all history blobs, and commit metadata."""
    hits: dict[str, list[str]] = {}

    def record(key: str, where: str) -> None:
        hits.setdefault(key, [])
        if where not in hits[key]:
            hits[key].append(where)

    # Working tree
    for path in repo.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(repo))
        for key, value in values.items():
            if value in text:
                record(key, f"worktree:{rel}")

    if not (repo / ".git").exists():
        return hits

    # Commit messages + author/committer identities across all refs
    log = git_out(["log", "--all", "--format=%H%n%an <%ae>%n%cn <%ce>%n%B%n--END--"], repo)
    for key, value in values.items():
        if value in log:
            record(key, "commit_metadata_or_message")

    # Every blob in history
    rev = subprocess.run(
        ["git", "rev-list", "--objects", "--all"], cwd=repo, capture_output=True, text=True
    )
    shas = []
    for line in rev.stdout.splitlines():
        parts = line.split(maxsplit=1)
        if parts:
            shas.append(parts[0])
    if shas:
        proc = subprocess.run(
            ["git", "cat-file", "--batch"],
            cwd=repo,
            input="\n".join(shas) + "\n",
            capture_output=True,
            text=True,
            errors="ignore",
        )
        for key, value in values.items():
            if value in proc.stdout:
                record(key, "history_blob")

    return hits


def scan_zip(zip_path: Path, values: dict[str, str]) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            try:
                raw = zf.read(info).decode("utf-8", errors="ignore")
            except (OSError, zipfile.BadZipFile):
                continue
            for key, value in values.items():
                if value in raw:
                    hits.setdefault(key, [])
                    entry = f"zip:{info.filename}"
                    if entry not in hits[key]:
                        hits[key].append(entry)
    return hits


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--manifest",
        default=str(ROOT / "fixtures" / "pii_manifest.json"),
        help="Planted-value manifest from make_pii_fixture.py",
    )
    p.add_argument("--rulepack", default=str(ROOT / "rules"))
    p.add_argument("--check-patterns", action="store_true", help="Fixture sanity check only")
    p.add_argument("--repo", help="Scrubbed git repo to scan (e.g. the run's clean/ dir)")
    p.add_argument("--zip", dest="zip_path", help="Deliverable zip to scan")
    args = p.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))

    if args.check_patterns:
        return check_patterns(manifest, Path(args.rulepack))

    values = planted_values(manifest)
    if not (args.repo or args.zip_path):
        p.error("pass --repo and/or --zip (or --check-patterns)")

    all_hits: dict[str, list[str]] = {}
    targets: list[str] = []

    if args.repo:
        repo = Path(args.repo).resolve()
        targets.append(str(repo))
        for key, where in scan_repo(repo, values).items():
            all_hits.setdefault(key, []).extend(where)

    if args.zip_path:
        zp = Path(args.zip_path).resolve()
        targets.append(str(zp))
        for key, where in scan_zip(zp, values).items():
            all_hits.setdefault(key, []).extend(where)

    total = len(values)
    leaked = len(all_hits)
    print(f"scanned: {', '.join(targets)}")
    print(f"planted values: {total}")
    print(f"clean: {total - leaked}")
    print(f"LEAKED: {leaked}")

    if all_hits:
        print("\nSurviving values:")
        for key in sorted(all_hits):
            locations = all_hits[key][:5]
            preview = values[key][:32]
            print(f"  {key} = {preview!r}")
            for loc in locations:
                print(f"      {loc}")
        return 1

    print("\nPASS — no planted PII survived in the deliverable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
