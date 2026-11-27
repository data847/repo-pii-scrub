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


def clone_or_copy_source(source: str, dest: Path, *, fast: bool = False, mutate: bool = False) -> None:
    """`mutate`: the copy will be rewritten (pruned), so never symlink the original."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() or dest.is_symlink():
        if dest.is_symlink():
            dest.unlink()
        else:
            shutil.rmtree(dest)
    src_path = Path(source)
    if src_path.is_dir():
        if fast and not mutate:
            dest.symlink_to(src_path.resolve(), target_is_directory=True)
        else:
            shutil.copytree(src_path, dest, symlinks=True)
    else:
        run(["git", "clone", source, str(dest)])


# ── Pre-sanitize pruning ──────────────────────────────────────────────────────
# Files and directories removed from EVERY commit before any redaction runs. Data
# dumps (.sql/.csv/.log) can carry secrets and PII in shapes no regex covers, and
# vendored library code is third-party, not the author's, so both are dropped
# outright rather than scrubbed. A trailing "/" means "a directory of this name at
# any depth"; anything else is a raw git-filter-repo --path-glob.
DEFAULT_PRUNE = (
    "*.sql", "*.csv", "*.tsv", "*.xml", "*.log", "*.dump",
    "node_modules/", "bower_components/", "jspm_packages/", "vendor/", "third_party/",
    "third-party/", "Pods/", "Carthage/", "site-packages/", ".venv/", "venv/",
    "*.min.js", "*.min.css",
    # Files that are lists of people.
    "AUTHORS", "*/AUTHORS", "AUTHORS.*", "*/AUTHORS.*", "CONTRIBUTORS", "*/CONTRIBUTORS",
    "CONTRIBUTORS.*", "*/CONTRIBUTORS.*", "MAINTAINERS", "*/MAINTAINERS", "OWNERS", "*/OWNERS",
    ".mailmap", "*/.mailmap",
)


def prune_patterns(extra: list[str] | None = None, *, defaults: bool = True) -> list[str]:
    """Expand the prune list to git-filter-repo path globs (fnmatch; `*` crosses `/`)."""
    out: list[str] = []
    for item in [*(DEFAULT_PRUNE if defaults else ()), *(extra or ())]:
        item = item.strip()
        if not item:
            continue
        if item.endswith("/"):
            name = item.rstrip("/")
            out += [f"{name}/*", f"*/{name}/*"]
        else:
            out.append(item)
    return list(dict.fromkeys(out))


def prune_history(repo: Path, globs: list[str]) -> dict:
    """Delete every path matching `globs` from the whole history of `repo` (in place)."""
    if not globs:
        return {"pruned_globs": []}
    cmd = ["git", "filter-repo", "--force", "--invert-paths"]
    for g in globs:
        cmd += ["--path-glob", g]
    run(cmd, cwd=repo)
    return {"pruned_globs": globs}


# ── Company / domain seeds for the brand pass ─────────────────────────────────
# Author-email domains that say nothing about the company (and must never become a
# brand term, or every `gmail` in the code would be rewritten).
FREE_MAIL = {
    "gmail", "googlemail", "yahoo", "ymail", "outlook", "hotmail", "live", "msn", "icloud",
    "me", "mac", "aol", "proton", "protonmail", "pm", "gmx", "mail", "yandex", "ya", "rambler",
    "qq", "163", "126", "zoho", "hey", "fastmail", "github", "gitlab", "bitbucket", "example",
    "localhost", "localdomain", "users", "noreply", "invalid", "local", "internal", "test",
}
_SLD_SUFFIX = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne"}


def domain_label(domain: str) -> str | None:
    """`test.snapdeal.com` -> `snapdeal`; `foo.co.uk` -> `foo`; None for free-mail etc."""
    parts = [p for p in domain.lower().strip(".").split(".") if p]
    if len(parts) < 2:
        return None
    parts = parts[:-1]                                   # drop the TLD
    if len(parts) > 1 and parts[-1] in _SLD_SUFFIX:
        parts = parts[:-1]
    label = parts[-1]
    if len(label) < 4 or label in FREE_MAIL or not re.fullmatch(r"[a-z0-9-]+", label):
        return None
    return label


def company_terms(companies: list[str] | None, domains: list[str] | None) -> list[str]:
    """User-supplied company names and domains -> brand terms (a domain also seeds its label)."""
    terms: dict[str, None] = {}
    for c in companies or ():
        c = c.strip()
        if len(c) >= 3:
            terms.setdefault(c, None)
    for d in domains or ():
        d = re.sub(r"^https?://", "", d.strip().lower()).split("/")[0].lstrip("*.")
        if not d:
            continue
        # The name label covers every subdomain/TLD (test.acme.com, acme.io); a separate
        # `acme.com` row would map the same hosts to a *different* pseudonym.
        label = domain_label(d)
        terms.setdefault(label or d, None)
    return list(terms)


def author_domain_terms(repo: Path) -> list[str]:
    """Brand terms derived from the commit author/committer email domains."""
    out = run(["git", "log", "--all", "--format=%ae%n%ce"], cwd=repo).stdout
    seen: dict[str, None] = {}
    for line in out.splitlines():
        if "@" in line:
            label = domain_label(line.rsplit("@", 1)[1])
            if label:
                seen.setdefault(label, None)
    return list(seen)


# ── Author names from git history (no NER) ────────────────────────────────────
# The people who committed are the people whose names turn up in comments, strings
# and messages with no `@author` tag in front of them. Their identities are read
# from `git log` and redacted as literals everywhere (case-insensitive).
_GENERIC_IDENTITY = frozenset(
    {
        "bot", "jenkins", "github", "gitlab", "bitbucket", "noreply", "admin", "administrator", "root",
        "unknown", "ubuntu", "build", "system", "runner", "deploy", "release", "automation", "service",
        "support", "info", "team", "dev", "test", "user", "git", "ci", "ec2", "svc", "server", "ops",
        "devops", "jira", "gerrit", "sonar", "nobody", "anonymous", "default", "master", "main",
    }
)


def _is_generic_identity(text: str) -> bool:
    """Token-wise, so `Devendra`/`Gitanjali` are people but `ec2-user`/`ci-bot` are not."""
    toks = [t for t in re.split(r"[^a-z]+", text.lower()) if t]
    return not toks or any(t in _GENERIC_IDENTITY or t.endswith("bot") for t in toks)


COMMON_WORDS = frozenset(
    {
        "about", "above", "after", "again", "agent", "alert", "alpha", "angel", "apple", "basic",
        "begin", "being", "below", "black", "blank", "blind", "block", "board", "brain", "brown",
        "build", "carry", "chain", "chart", "check", "chief", "child", "clean", "clear", "click",
        "close", "cloud", "coach", "color", "count", "cover", "craft", "cross", "crown", "daily",
        "dance", "delta", "depth", "dream", "drive", "early", "earth", "eight", "email", "empty",
        "enter", "entry", "equal", "error", "event", "every", "extra", "field", "final", "first",
        "flash", "float", "floor", "focus", "force", "frame", "fresh", "front", "grand", "grant",
        "graph", "green", "group", "guard", "guest", "guide", "happy", "heart", "heavy", "hello",
        "horse", "hotel", "house", "human", "hunter", "image", "index", "inner", "input", "issue",
        "jordan", "judge", "known", "label", "large", "later", "layer", "learn", "least", "leave",
        "level", "light", "limit", "local", "logic", "loose", "lower", "lucky", "major", "march",
        "match", "mason", "maybe", "media", "merge", "metal", "might", "minor", "model", "month",
        "mount", "mouse", "movie", "music", "never", "night", "noble", "noise", "north", "notes",
        "novel", "other", "paper", "party", "patch", "peace", "phase", "phone", "photo", "piece",
        "pilot", "pitch", "place", "plain", "plane", "plant", "point", "power", "press", "price",
        "pride", "prime", "print", "prior", "proof", "queen", "quick", "quiet", "radio", "range",
        "rapid", "ratio", "reach", "ready", "right", "river", "robot", "rough", "round", "route",
        "royal", "scale", "scene", "scope", "score", "sense", "setup", "seven", "shape", "share",
        "sharp", "sheet", "shift", "short", "sight", "since", "skill", "sleep", "small", "smart",
        "smith", "solid", "solve", "sorry", "sound", "south", "space", "speed", "spend", "split",
        "sport", "staff", "stage", "stand", "start", "state", "steam", "steel", "stick", "still",
        "stock", "stone", "store", "storm", "story", "strip", "study", "style", "sugar", "super",
        "sweet", "table", "taken", "taste", "teach", "thank", "their", "theme", "there", "thing",
        "think", "third", "three", "throw", "tight", "title", "today", "token", "total", "touch",
        "tower", "track", "trade", "train", "treat", "trend", "trial", "truck", "trust", "truth",
        "twice", "under", "union", "unity", "until", "upper", "urban", "usage", "usual", "value",
        "video", "visit", "voice", "waste", "watch", "water", "wheel", "where", "which", "while",
        "white", "whole", "whose", "woman", "world", "worry", "worth", "would", "write", "wrong",
        "young", "youth",
    }
)


def author_name_terms(repo: Path, mode: str = "full", *, limit: int = 1500) -> list[str]:
    """Literals for the people in `git log`: full names (+ first.last / first_last /
    `Last, First` forms) and email handles. mode "all" also adds single first/last name
    tokens of 5+ letters that are not common English words; "off" returns []."""
    if mode == "off":
        return []
    out = run(["git", "log", "--all", "--format=%an%x09%ae%n%cn%x09%ce"], cwd=repo).stdout
    freq: dict[str, int] = {}
    spell: dict[str, str] = {}
    for line in out.splitlines():
        name, _, email = line.partition("\t")
        name = re.sub(r"\s+", " ", name).strip()
        cands: list[str] = []
        if name and "@" not in name and not _is_generic_identity(name):
            toks = re.findall(r"[^\W\d_]{2,}", name)
            if len(toks) >= 2 and len(" ".join(toks)) >= 5:
                first, last = toks[0], toks[-1]
                cands += [" ".join(toks), f"{first} {last}", f"{last}, {first}", f"{first}.{last}", f"{first}_{last}"]
                if len(first + last) >= 8:
                    cands.append(f"{first}{last}")
            elif mode == "all" and len(toks) == 1:
                cands.append(toks[0])
            if mode == "all":
                cands += [t for t in toks if len(t) >= 5 and t.lower() not in COMMON_WORDS]
        if "@" in email:
            lp = email.split("@", 1)[0].split("+", 1)[0]
            if (len(lp) >= 5 and re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]+", lp)
                    and not _is_generic_identity(lp)
                    and (re.search(r"[._-]", lp) or len(lp) >= 6)):
                cands.append(lp)
        for c in cands:
            c = c.strip()
            if len(c) >= 5 and c.lower() not in BRAND_STOPWORDS and c.lower() not in NOISE_TERMS:
                freq[c.lower()] = freq.get(c.lower(), 0) + 1
                spell.setdefault(c.lower(), c)
    ranked = sorted(freq, key=lambda k: -freq[k])
    return [spell[k] for k in ranked[:limit]]


# ── Company name from copyright headers ───────────────────────────────────────
# `Copyright 2016 Acme Technologies (P) Limited. All rights reserved.` names the
# legal entity in every file header. Entities with a legal-form suffix that occur in
# >= 2 files are seeded automatically, except well-known public licensors.
_PUBLIC_LICENSORS = (
    "apache", "foundation", "oracle", "sun microsystems", "google", "microsoft", "facebook",
    "meta platforms", "mozilla", "eclipse", "jetbrains", "red hat", "jboss", "pivotal", "vmware",
    "spring", "ibm", "amazon", "the regents", "free software", "mit", "gnu", "intel", "nvidia",
    "twitter", "netflix", "linkedin", "square", "stripe", "elastic", "hashicorp", "docker",
    "the authors", "contributors", "all rights", "your name", "company name", "yourcompany",
)
_COPYRIGHT_RE = re.compile(
    r"(?i)copyright\s*(?:\(c\)|\u00a9|&copy;)?\s*(?:19|20)\d{2}(?:\s*[-\u2013,]\s*(?:19|20)\d{2})*\.?\s+(?:by\s+)?"
    r"([A-Z][A-Za-z0-9&.,'\- ]{1,70}?)\s*(?:\(P\)\s*)?"
    r"(?:Private\s+Limited|Pvt\.?\s*Ltd\.?|Limited|Ltd\.?|Incorporated|Inc\.?|LLC|GmbH|Corporation|Corp\.?)\b"
)


def copyright_terms(repo: Path, *, min_files: int = 2) -> list[str]:
    """Legal-entity names found in copyright headers of the checked-out tree."""
    proc = subprocess.run(
        ["git", "grep", "-I", "-i", "-E", "copyright[^a-z]*(19|20)[0-9]{2}"],
        cwd=str(repo), capture_output=True, text=True, errors="replace",
    )
    counts: dict[str, set[str]] = {}
    for line in proc.stdout.splitlines():
        path, _, text = line.partition(":")
        for m in _COPYRIGHT_RE.finditer(text):
            name = re.sub(r"\s+", " ", m.group(1)).strip(" .,-")
            low = name.lower()
            if len(name) < 3 or any(p in low for p in _PUBLIC_LICENSORS):
                continue
            counts.setdefault(name, set()).add(path)
    return [n for n, files in sorted(counts.items(), key=lambda kv: -len(kv[1])) if len(files) >= min_files]


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


# Machine names, OS words and account names that the Pass-1 worklist picks up from
# author identities / hostnames. As global case-insensitive substring rules they
# rewrite ordinary code (`com`, `test`, `user`, `new`) and are not brands.
NOISE_TERMS = frozenset(
    {
        "com", "org", "net", "io", "www", "test", "tests", "testing", "user", "users",
        "admin", "administrator", "administrators", "root", "host", "localhost", "local",
        "new", "non", "pro", "mac", "macbook", "imac", "laptop", "latitude", "lenovo",
        "thinkpad", "ubuntu", "machine", "virtual", "compute", "side", "apple", "apples",
        "exclusively", "default", "demo", "sample", "example", "dev", "prod", "stage",
        "staging", "build", "master", "main", "windows", "linux", "desktop", "server",
    }
)
MIN_WORKLIST_LEN = 4


def _collides_with_pseudonyms(term: str, terms: list[str]) -> bool:
    """A term that occurs inside `ANON_ORG_<hash>` (or any other pseudonym) would match
    its own replacement, so apply-map's re-check can never pass (`non` in `ANON_ORG`)."""
    t = term.lower()
    return (
        any(t in brand_pseudonym(o).lower() or t in person_pseudonym(o).lower() for o in terms)
        or t in "anon_org_" or t in "anon_per_"
    )


def brand_worklist_terms(
    sanitized_out: Path,
    extra_terms: tuple[str, ...] = (),
    *,
    seeds: tuple[str, ...] = (),
    person_seeds: tuple[str, ...] = (),
    use_worklist: bool = True,
) -> list[str]:
    """Brand terms to map.

    * `seeds` — company names / domain labels the user (or the author-email derivation)
      supplied: taken VERBATIM (never split on `.`), exempt from the noise filter.
    * Pass-1 worklist findings + `extra_terms` — tokenised, then filtered: stopwords,
      machine/account noise, terms < 4 chars, and anything that would match inside a
      pseudonym. `use_worklist=False` (fast mode) skips the findings altogether.
    """
    report = sanitized_out / "artifacts" / "scan_report_post.json"
    work = sanitized_out / "work"
    spans: list[str] = []

    if use_worklist and report.is_file():
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

    terms: dict[str, str] = {}                      # lower-case key -> first spelling
    for seed in seeds:
        seed = seed.strip()
        if seed:
            terms.setdefault(seed.lower(), seed)
    for p in person_seeds:                          # git author names: verbatim, after the company
        p = p.strip()
        if p:
            terms.setdefault(p.lower(), p)
    for raw in ([*spans, *extra_terms] if use_worklist else list(extra_terms)):
        for token in _BRAND_TOKEN.findall(raw):
            low = token.lower()
            if low in BRAND_STOPWORDS or low in NOISE_TERMS or len(token) < MIN_WORKLIST_LEN:
                continue
            terms.setdefault(low, token)
    # Rows are case-insensitive, so `Snapdeal`/`snapdeal` is ONE row (two rows collide).
    out = list(terms.values())
    out = [t for t in out if not _collides_with_pseudonyms(t, out)]
    return sorted(out, key=lambda t: (-len(t), t.lower()))


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


def person_pseudonym(term: str) -> str:
    salt = os.environ.get("REPO_SANITIZER_SALT", "")
    digest = hashlib.sha256(f"{salt}:per:{term.lower()}".encode()).hexdigest()[:12]
    return f"ANON_PER_{digest}"


def write_brand_map(terms: list[str], work_root: Path, person: frozenset[str] = frozenset()) -> Path:
    """Pass-2: deterministic brand map (literal, case-insensitive rows). Terms whose
    lower-case form is in `person` map to ANON_PER_<hash>, the rest to ANON_ORG_<hash>."""
    work_root.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "pattern": term,
            "replacement": person_pseudonym(term) if term.lower() in person else brand_pseudonym(term),
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


def residual_scan(clean: Path, rules: Path, *, per_rule_cap: int = 25) -> dict:
    """Re-apply the rulepack's patterns to the FINISHED tree and history head: anything
    that still matches is a miss. Report-only (never blocks) and value-free: just
    rule, file and line, so the report itself carries no PII."""
    import yaml

    pats = yaml.safe_load((rules / "regex" / "pii_patterns.yaml").read_text())["patterns"]
    compiled = []
    for p in pats:
        try:
            compiled.append((p["name"], re.compile(p["pattern"], re.M)))
        except re.error:
            continue
    skip = ("REDACTED_", "ANON_ORG_", "ANON_PER_", "example.invalid", "203.0.113.", "2001:db8")
    counts: dict[str, int] = {}
    samples: dict[str, list[dict]] = {}
    files = run(["git", "ls-files", "-z"], cwd=clean).stdout.split("\0")
    for rel in filter(None, files):
        path = clean / rel
        try:
            if not path.is_file() or path.is_symlink():
                continue
            raw = path.read_bytes()
            if b"\0" in raw[:8192]:
                continue
            text = raw.decode("utf-8", "replace")
        except OSError:
            continue
        for name, rx in compiled:
            for m in rx.finditer(text):
                val = m.group(1) if (m.groups() and m.group(1)) else m.group()
                if any(k in val for k in skip) or name in {"credit_card"}:
                    continue
                counts[name] = counts.get(name, 0) + 1
                lst = samples.setdefault(name, [])
                if len(lst) < per_rule_cap:
                    lst.append({"file": rel, "line": text.count("\n", 0, m.start()) + 1})
    return {"total": sum(counts.values()), "by_rule": dict(sorted(counts.items(), key=lambda kv: -kv[1])), "samples": samples}


def package_deliverable(work_root: Path, repo_slug: str, residual: dict | None = None) -> Path:
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
        "residual_scan": (
            {"total": residual["total"], "by_rule": residual["by_rule"], "details": "RESIDUAL.json"}
            if residual is not None else None
        ),
        "zip": zip_name,
    }
    (work_root / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return zip_path
