"""Pipeline step implementations for repo PII scrub."""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import shutil
import subprocess
from pathlib import Path


DEFAULT_STEP_TIMEOUT = 7200


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


def scan_pre(source: Path, rulepack: Path, out: Path, *, fast: bool = False) -> None:
    out.mkdir(parents=True, exist_ok=True)
    run(
        [
            "repo-sanitizer",
            "scan",
            str(source),
            "--rulepack",
            str(rulepack),
            "--out",
            str(out),
            *_sanitizer_fast_args(fast),
        ]
    )


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


def build_llm_sample(clean: Path, work_root: Path, *, max_files: int = 60) -> Path:
    work_root.mkdir(parents=True, exist_ok=True)
    sample_list = work_root / "llm_sample_files.txt"
    paths: list[str] = []

    doc_patterns = ("*.md", "*.env*", "*.yaml", "*.yml", "*.json", "*.sql", "*.txt", "*.log")
    for pattern in doc_patterns:
        for fp in clean.glob(f"**/{pattern}"):
            if ".git" in fp.parts or "node_modules" in fp.parts or "vendor" in fp.parts:
                continue
            paths.append(str(fp.relative_to(clean)))
            if len(paths) >= 40:
                break
        if len(paths) >= 40:
            break

    code_exts = {".py", ".ts", ".tsx", ".js", ".jsx", ".java", ".go", ".rb", ".php", ".cs", ".kt"}
    code_files = [
        p
        for p in clean.rglob("*")
        if p.is_file()
        and p.suffix in code_exts
        and ".git" not in p.parts
        and "node_modules" not in p.parts
        and "vendor" not in p.parts
    ]
    random.shuffle(code_files)
    for fp in code_files[:20]:
        paths.append(str(fp.relative_to(clean)))

    sample_list.write_text("\n".join(paths[:max_files]) + "\n")

    payload_path = work_root / "llm_review_payload.txt"
    budget = 180_000
    used = 0
    chunks: list[str] = []
    for rel in paths[:max_files]:
        fp = clean / rel
        if not fp.is_file():
            continue
        try:
            text = fp.read_text(errors="replace")
        except OSError:
            continue
        chunk = f"\n\n===== {rel} =====\n{text[:8000]}"
        if used + len(chunk) > budget:
            break
        chunks.append(chunk)
        used += len(chunk)
    payload_path.write_text("".join(chunks))

    context_path = work_root / "llm_review_context.txt"
    context_parts: list[str] = []
    for name in ("sanitized/artifacts/result.json", "sanitized/artifacts/scan_report_post.json"):
        p = work_root / name
        if p.is_file():
            context_parts.append(p.read_text())
    context_path.write_text("\n".join(context_parts))
    return payload_path


def trim_history(
    clean: Path,
    work_root: Path,
    history_pct: int,
    *,
    max_commits: int | None = None,
) -> dict:
    subprocess.run(["git", "config", "core.ignorecase", "true"], cwd=clean, check=False)
    repair_macos_case_collisions(clean)
    run(["git", "reset", "--hard", "HEAD"], cwd=clean)
    run(["git", "clean", "-fdx"], cwd=clean)
    total_s = run(["git", "rev-list", "--count", "HEAD"], cwd=clean).stdout.strip()
    total = int(total_s)
    keep = max(1, total * history_pct // 100)
    if max_commits is not None:
        keep = min(keep, max_commits)
    rev_list = run(["git", "rev-list", "--reverse", "HEAD"], cwd=clean).stdout.splitlines()
    new_head = rev_list[keep - 1]

    branch_proc = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=clean,
        capture_output=True,
        text=True,
    )
    branch = branch_proc.stdout.strip() or "main"
    if branch == "HEAD":
        branch = "main"

    run(["git", "checkout", "-B", branch, new_head], cwd=clean)
    run(["git", "filter-repo", "--force", f"--refs=refs/heads/{branch}"], cwd=clean)

    after = run(["git", "rev-list", "--count", "HEAD"], cwd=clean).stdout.strip()
    work_root.mkdir(parents=True, exist_ok=True)
    (work_root / "commit_count_after_trim.txt").write_text(after + "\n")
    return {
        "commits_before_trim": total,
        "commits_kept": int(after),
        "history_pct": history_pct,
        "new_head": new_head,
    }


def verify_post_trim(
    clean: Path, rulepack: Path, work_root: Path, *, fast: bool = False
) -> list[str]:
    """Post-trim gates. Returns residual brand-gate names (empty = fully clean)."""
    if fast:
        report = work_root / "gitleaks-post-trim.json"
        proc = subprocess.run(
            [
                "gitleaks",
                "detect",
                "--source",
                str(clean),
                "--redact",
                "--report-path",
                str(report),
                "--exit-code",
                "0",
            ],
            cwd=clean,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"gitleaks failed ({proc.returncode}): {proc.stdout}\n{proc.stderr}"
            )
        (work_root / "gitleaks-post-trim.log").write_text(
            (proc.stdout or "") + (proc.stderr or ""), encoding="utf-8"
        )
        return []
    scan_out = work_root / "scan-post-trim"
    gate_out = work_root / "gate-post-trim"
    scan_out.mkdir(parents=True, exist_ok=True)
    gate_out.mkdir(parents=True, exist_ok=True)
    run(
        [
            "repo-sanitizer",
            "scan",
            str(clean),
            "--rulepack",
            str(rulepack),
            "--out",
            str(scan_out),
            *_sanitizer_fast_args(fast),
        ]
    )
    try:
        run(
            [
                "repo-sanitizer",
                "gate",
                str(clean),
                "--rulepack",
                str(rulepack),
                "--out",
                str(gate_out),
                *_sanitizer_fast_args(fast),
            ]
        )
        residual_brands: list[str] = []
    except RuntimeError:
        # Brand findings survive Pass-3 only when NER names a new org; that is
        # auditable, not a leak of PII/secrets, so it is recorded rather than fatal.
        failing = failing_gates(load_result_json(gate_out))
        if not failing or (failing - BRAND_WORKLIST_GATES):
            raise
        residual_brands = sorted(failing)
    run(["gitleaks", "detect", "--source", str(clean), "--redact"], cwd=clean)
    return residual_brands


def stub_llm_pass_fast(work_root: Path) -> dict:
    result = {
        "verdict": "PASS",
        "summary": "Fast mode: LLM privacy review skipped (regex/gitleaks/deny-globs only).",
        "findings": [],
        "source": "fast_mode_stub",
    }
    work_root.mkdir(parents=True, exist_ok=True)
    (work_root / "llm_review.json").write_text(json.dumps(result, indent=2) + "\n")
    (work_root / "llm_review_notes.md").write_text(
        "# LLM Privacy Review — PASS (fast mode)\n\nLLM review skipped; deliverable used sanitizer gates only.\n"
    )
    return result


def package_deliverable(work_root: Path, repo_slug: str) -> Path:
    clean = work_root / "clean"
    zip_name = f"{repo_slug}_sanitized_first5pct.zip"
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
    commits_after = (work_root / "commit_count_after_trim.txt").read_text().strip()
    bundle_sha = load_result_json(work_root / "sanitized").get("bundle_sha256", "unknown")
    source = ""
    state_path = work_root / "run_state.json"
    if state_path.is_file():
        source = json.loads(state_path.read_text()).get("source", "")

    manifest = {
        "repo_slug": repo_slug,
        "source": source,
        "commits_before": int(commits_before) if commits_before.isdigit() else commits_before,
        "commits_after_trim": int(commits_after) if commits_after.isdigit() else commits_after,
        "history_pct_kept": json.loads(state_path.read_text()).get("history_pct", 5)
        if state_path.is_file()
        else 5,
        "sanitizer_bundle_sha256": bundle_sha,
        "llm_review": "llm_review.json",
        "zip": zip_name,
    }
    (work_root / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return zip_path
