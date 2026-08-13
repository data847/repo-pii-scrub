"""Pipeline step implementations for repo PII scrub."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path


DEFAULT_STEP_TIMEOUT = 7200

# What the sanitizer substitutes for a secret. The digest is high-entropy, so
# gitleaks flags every placeholder; the post-trim gate filters these out.
PLACEHOLDER_SECRET = re.compile(r"REDACTED_[0-9a-f]{6,}")


def step_timeout() -> int | None:
    """Wall-clock cap per external command; 0 disables it."""
    raw = os.environ.get("PII_SCRUB_STEP_TIMEOUT", "").strip()
    if not raw:
        return DEFAULT_STEP_TIMEOUT
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_STEP_TIMEOUT
    return value if value > 0 else None


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict | None = None,
    timeout: int | None = -1,
) -> subprocess.CompletedProcess:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    limit = step_timeout() if timeout == -1 else timeout
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=merged,
            capture_output=True,
            text=True,
            timeout=limit,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Command timed out after {limit}s: {' '.join(cmd)}") from exc
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def require_tool(name: str) -> None:
    proc = subprocess.run(["which", name], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"Required tool not found on PATH: {name}")


def repair_macos_case_collisions(repo: Path) -> bool:
    """Remove duplicate git paths that collide on case-insensitive macOS (e.g. README.md vs readme.md)."""
    if not (repo / ".git").exists():
        return False
    subprocess.run(["git", "config", "core.ignorecase", "true"], cwd=repo, check=False)
    proc = subprocess.run(["git", "ls-files"], cwd=repo, capture_output=True, text=True)
    if proc.returncode != 0:
        return False
    by_lower: dict[str, list[str]] = {}
    for path in proc.stdout.splitlines():
        if path:
            by_lower.setdefault(path.lower(), []).append(path)
    drop_paths: list[str] = []
    for variants in by_lower.values():
        if len(variants) <= 1:
            continue
        # Prefer mixed/upper-case basename (README.md over readme.md)
        keep = sorted(variants, key=lambda p: (p == p.lower(), p))[0]
        drop_paths.extend(p for p in variants if p != keep)
    if not drop_paths:
        return False
    cmd = ["git", "filter-repo", "--force", "--invert-paths", *[f"--path={p}" for p in drop_paths]]
    run(cmd, cwd=repo)
    return True


def check_prerequisites() -> None:
    for tool in ("git", "gitleaks", "repo-sanitizer", "git-filter-repo"):
        require_tool(tool)
    if not os.environ.get("REPO_SANITIZER_SALT", "").strip():
        raise RuntimeError("REPO_SANITIZER_SALT must be set (never commit this value)")


def _sanitizer_fast_args(fast: bool) -> list[str]:
    """NER wiring shared by scan/sanitize/gate calls.

    A shared NER service (PII_SCRUB_NER_SERVICE_URL) keeps parallel workers from
    each loading the ~700 MB transformer model, which otherwise deadlocks.
    """
    if fast:
        return ["--ner-scope", "off"]

    args: list[str] = []
    scope = os.environ.get("PII_SCRUB_NER_SCOPE", "").strip()
    if scope:
        args.extend(["--ner-scope", scope])

    service_url = os.environ.get("PII_SCRUB_NER_SERVICE_URL", "").strip()
    if service_url:
        args.extend(["--ner-service-url", service_url])
    else:
        device = os.environ.get("PII_SCRUB_NER_DEVICE", "cpu").strip()
        if device:
            args.extend(["--ner-device", device])
    return args


def clone_or_copy_source(source: str, dest: Path, *, fast: bool = False) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() or dest.is_symlink():
        if dest.is_symlink():
            dest.unlink()
        else:
            shutil.rmtree(dest)
    src_path = Path(source)
    if src_path.is_dir():
        if fast:
            dest.symlink_to(src_path.resolve(), target_is_directory=True)
        else:
            shutil.copytree(src_path, dest, symlinks=True)
    else:
        run(["git", "clone", source, str(dest)])


def record_baseline(repo: Path, work_root: Path) -> dict:
    total = run(["git", "rev-list", "--count", "HEAD"], cwd=repo).stdout.strip()
    head = run(["git", "log", "-1", "--format=%H %ci %s"], cwd=repo).stdout.strip()
    work_root.mkdir(parents=True, exist_ok=True)
    (work_root / "commit_count_before.txt").write_text(total + "\n")
    (work_root / "head_before.txt").write_text(head + "\n")
    return {"commits_before": int(total), "head_before": head}


def scan_pre(source: Path, rulepack: Path, out: Path, *, fast: bool = False) -> int:
    """Read-only pre-scan. Returns the finding count.

    `repo-sanitizer scan` exits non-zero simply to signal "findings exist", which
    is the normal case for any real repo, so a written report counts as success.
    """
    out.mkdir(parents=True, exist_ok=True)
    cmd = [
        "repo-sanitizer",
        "scan",
        str(source),
        "--rulepack",
        str(rulepack),
        "--out",
        str(out),
        *_sanitizer_fast_args(fast),
    ]
    report = out / "artifacts" / "scan_report_pre.json"
    try:
        run(cmd)
    except RuntimeError:
        if not report.is_file():
            raise
    if not report.is_file():
        return 0
    try:
        return len(json.loads(report.read_text()))
    except (OSError, json.JSONDecodeError):
        return 0


def sanitize(source: Path, rulepack: Path, out: Path, *, fast: bool = False) -> list[str]:
    """Run Pass-1. Returns the brand-worklist gates that still fail (empty = fully clean).

    A brand-only gate failure is expected and resolved by Pass-2/Pass-3; anything
    else re-raises.
    """
    out.mkdir(parents=True, exist_ok=True)
    gate_args = ["--no-gate"] if fast else ["--gate"]
    cmd = [
        "repo-sanitizer",
        "sanitize",
        str(source),
        "--rulepack",
        str(rulepack),
        "--out",
        str(out),
        *gate_args,
        *_sanitizer_fast_args(fast),
    ]
    try:
        run(cmd)
    except RuntimeError:
        result = load_result_json(out)
        failing = failing_gates(result)
        bundle = out / "output" / "sanitized.bundle"
        if not failing or (failing - BRAND_WORKLIST_GATES) or not bundle.is_file():
            raise
        return sorted(failing)
    return []


# Brand/org findings are a Pass-2 worklist by design: Pass-1 never auto-rewrites a
# brand, so these gates fail until the brand map is applied (Pass-3 apply-map).
# Any OTHER failing gate is a hard stop.
BRAND_WORKLIST_GATES = frozenset(
    {"ORG_NAME", "BRAND_IDENTIFIER", "BRAND_PATH", "PACKAGE_NAMESPACE"}
)

# Generic descriptors dropped when reducing a flagged span to the brand token
# ("AcmePay Payments Platform" -> "AcmePay").
BRAND_STOPWORDS = frozenset(
    {
        "the", "and", "of", "for", "app", "api", "sdk", "web", "www", "inc", "llc",
        "ltd", "limited", "corp", "corporation", "company", "co", "group", "holding",
        "holdings", "gmbh", "pvt", "private", "plc", "sa", "bv", "ag", "oy", "ab",
        "payments", "payment", "platform", "service", "services", "solution",
        "solutions", "system", "systems", "software", "technologies", "technology",
        "tech", "labs", "lab", "studio", "digital", "media", "team", "project",
        "product", "products", "cloud", "data", "analytics", "engineering",
        "internal", "global", "online", "mobile", "backend", "frontend", "server",
        "client", "portal", "dashboard", "core", "common", "shared", "main",
    }
)

# Any-script word of 3+ chars (Cyrillic brand forms must match too).
_BRAND_TOKEN = re.compile(r"[^\W\d_][^\W_]{2,}")


def failing_gates(result: dict) -> set[str]:
    """Blocking gates that did not pass."""
    return {
        name
        for name, gate in (result.get("gates") or {}).items()
        if not gate.get("passed", True) and gate.get("blocking", True)
    }


def brand_worklist_terms(sanitized_out: Path, extra_terms: tuple[str, ...] = ()) -> list[str]:
    """Brand tokens to map, from the Pass-1 worklist findings plus caller-supplied names."""
    report = sanitized_out / "artifacts" / "scan_report_post.json"
    work = sanitized_out / "work"
    spans: list[str] = []

    if report.is_file():
        try:
            findings = json.loads(report.read_text())
        except (OSError, json.JSONDecodeError):
            findings = []
        for finding in findings if isinstance(findings, list) else []:
            if finding.get("category") not in {"ORG_NAME", "BRAND", "CODENAME", "CLIENT"}:
                continue
            text = _resolve_span(work, finding)
            if text:
                spans.append(text)

    terms: dict[str, None] = {}
    for raw in (*spans, *extra_terms):
        for token in _BRAND_TOKEN.findall(raw):
            if token.lower() in BRAND_STOPWORDS:
                continue
            terms.setdefault(token, None)
    return sorted(terms, key=lambda t: (-len(t), t.lower()))


def _resolve_span(work: Path, finding: dict) -> str:
    """Recover the literal text a finding points at (offsets are line-relative)."""
    rel = finding.get("file_path")
    start, end = finding.get("offset_start"), finding.get("offset_end")
    if not rel or start is None or end is None:
        return ""
    path = work / rel
    if not path.is_file():
        return ""
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    line_no = finding.get("line") or 1
    if 1 <= line_no <= len(lines):
        candidate = lines[line_no - 1][start:end]
        if candidate.strip():
            return candidate.strip()
    return ""


def brand_pseudonym(term: str) -> str:
    salt = os.environ.get("REPO_SANITIZER_SALT", "")
    digest = hashlib.sha256(f"{salt}:org:{term.lower()}".encode()).hexdigest()[:12]
    return f"ANON_ORG_{digest}"


def write_brand_map(terms: list[str], work_root: Path) -> Path:
    """Pass-2: deterministic brand map (literal, case-insensitive rows)."""
    work_root.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "pattern": term,
            "replacement": brand_pseudonym(term),
            "is_regex": False,
            "preserve_case": False,
        }
        for term in terms
    ]
    path = work_root / "brand_map.json"
    path.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def apply_brand_map(sanitized_out: Path, brand_map: Path, out: Path) -> Path:
    """Pass-3: rewrite mapped brands across all history and re-bundle."""
    out.mkdir(parents=True, exist_ok=True)
    run(
        [
            "repo-sanitizer",
            "apply-map",
            str(sanitized_out / "work"),
            "--brand-map",
            str(brand_map),
            "--out",
            str(out),
        ]
    )
    bundle = out / "output" / "sanitized.bundle"
    if not bundle.is_file():
        raise RuntimeError(f"apply-map did not produce a bundle: {bundle}")
    return bundle


def materialize_clean(bundle: Path, clean: Path) -> None:
    if clean.exists():
        shutil.rmtree(clean)
    run(
        ["git", "clone", str(bundle), str(clean)],
        env={"GIT_LFS_SKIP_SMUDGE": "1"},
    )


def load_result_json(sanitized_out: Path) -> dict:
    path = sanitized_out / "artifacts" / "result.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text())


def assert_no_secrets(clean: Path, work_root: Path) -> int:
    """Fail if gitleaks finds a real secret in the deliverable. Returns hits ignored.

    An independent second opinion on the sanitizer's own gates, and cheap enough
    (~0.2s) to run unconditionally before packaging.

    The sanitizer's placeholders are high-entropy, so gitleaks reports every one
    as a generic-api-key. Those are filtered out by value, which means the scan
    must run unredacted; the raw report is deleted immediately afterwards so only
    a redacted summary is kept on disk.
    """
    clean = clean.resolve()
    work_root.mkdir(parents=True, exist_ok=True)
    raw = work_root / "gitleaks.raw.json"
    proc = subprocess.run(
        [
            "gitleaks",
            "detect",
            "--source",
            str(clean),
            "--report-path",
            str(raw),
            "--exit-code",
            "0",
        ],
        capture_output=True,
        text=True,
    )
    log = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raw.unlink(missing_ok=True)
        raise RuntimeError(f"gitleaks could not scan {clean} ({proc.returncode}): {log}")

    try:
        findings = json.loads(raw.read_text()) if raw.is_file() else []
    except json.JSONDecodeError as exc:
        raw.unlink(missing_ok=True)
        raise RuntimeError(f"gitleaks wrote an unreadable report: {exc}") from exc
    finally:
        raw.unlink(missing_ok=True)

    real = [f for f in findings if not PLACEHOLDER_SECRET.fullmatch(f.get("Secret", "").strip())]
    # Location only — never persist or surface the matched secret itself.
    summary = [
        {"rule": f.get("RuleID"), "file": f.get("File"), "line": f.get("StartLine")} for f in real
    ]
    (work_root / "gitleaks.json").write_text(json.dumps(summary, indent=2) + "\n")
    (work_root / "gitleaks.log").write_text(log, encoding="utf-8")

    ignored = len(findings) - len(real)
    if real:
        where = ", ".join(f"{s['rule']} @ {s['file']}:{s['line']}" for s in summary[:5])
        raise RuntimeError(
            f"gitleaks found {len(real)} real secret(s) in the deliverable: {where}"
            f"{' ...' if len(real) > 5 else ''}"
        )
    return ignored


def package_deliverable(work_root: Path, repo_slug: str) -> Path:
    clean = work_root / "clean"
    zip_name = f"{repo_slug}_sanitized.zip"
    zip_path = work_root / zip_name
    if zip_path.exists():
        zip_path.unlink()

    excludes = [
        "*/node_modules/*",
        "*/.venv/*",
        "*/vendor/*",
        "*/dist/*",
        "*/build/*",
        "*/.next/*",
        "*/__pycache__/*",
    ]
    cmd = ["zip", "-r", str(zip_path), "clean", *[f"-x{pat}" for pat in excludes]]
    run(cmd, cwd=work_root)

    commits_before = (work_root / "commit_count_before.txt").read_text().strip()
    bundle_sha = load_result_json(work_root / "sanitized").get("bundle_sha256", "unknown")
    source = ""
    state_path = work_root / "run_state.json"
    if state_path.is_file():
        source = json.loads(state_path.read_text()).get("source", "")

    manifest = {
        "repo_slug": repo_slug,
        "source": source,
        "commits_before": int(commits_before) if commits_before.isdigit() else commits_before,
        # History is delivered whole; the count is read back rather than assumed
        # because the sanitizer drops commits that become empty after redaction.
        "commits_delivered": int(
            run(["git", "rev-list", "--count", "HEAD"], cwd=clean).stdout.strip()
        ),
        "sanitizer_bundle_sha256": bundle_sha,
        "secret_scan": "gitleaks.json",
        "zip": zip_name,
    }
    (work_root / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return zip_path
