#!/usr/bin/env python3
"""Run repo-pii-scrub pipeline on a batch of local repo paths."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORCH = ROOT / "scripts" / "orchestrator.py"
sys.path.insert(0, str(ROOT / "scripts"))
from batch_env import load_env_file, worker_env_from  # noqa: E402
from steps import missing_tools, preflight_message  # noqa: E402

DEFAULT_BATCH_ID = "batch"
BATCH_ROOT = ROOT / "outputs" / DEFAULT_BATCH_ID


DEFAULT_GATE_TIMEOUT = 10800


def gate_timeout() -> int | None:
    """Wall-clock cap per orchestrator gate; 0 disables it."""
    raw = os.environ.get("PII_SCRUB_GATE_TIMEOUT", "").strip()
    if not raw:
        return DEFAULT_GATE_TIMEOUT
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_GATE_TIMEOUT
    return value if value > 0 else None


def run_step(cmd: list[str], env: dict) -> tuple[int, str]:
    limit = gate_timeout()
    try:
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=limit)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        return 124, f"{stdout}{stderr}\nTIMEOUT: gate exceeded {limit}s"
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out


def _write_repo_log(slug: str, log: list[str], batch_root: Path | None = None) -> None:
    root = batch_root or BATCH_ROOT
    log_dir = root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / f"{slug}.log").write_text("\n".join(log), encoding="utf-8")



def _mode_name(fast: bool) -> str:
    return "fast" if fast else "normal"


def _recorded_mode(run_dir: Path, slug: str) -> str | None:
    """Mode a finished run was produced in; manifests predating the field were normal."""
    manifest = run_dir / "MANIFEST.json"
    if manifest.is_file():
        try:
            return json.loads(manifest.read_text()).get("mode", "normal")
        except (OSError, json.JSONDecodeError):
            return None
    return None


def _ensure_mode_state(run_dir: Path, *, fast: bool) -> None:
    """Reconcile an existing run with the requested mode.

    A half-done normal run can be promoted to fast. Anything else that disagrees
    (a fast run asked for normal, or a finished run in the other mode) is wiped:
    a fast artifact must never be passed off as a normal one.
    """
    import shutil

    state_path = run_dir / "run_state.json"
    if not state_path.is_file():
        return
    state = json.loads(state_path.read_text())
    if bool(state.get("fast_mode")) == fast:
        return
    if fast and state.get("current_gate") != "done":
        state["fast_mode"] = True
        state_path.write_text(json.dumps(state, indent=2) + "\n")
        return
    print(f"Mode changed for {run_dir.name}: discarding previous run", flush=True)
    shutil.rmtree(run_dir)


def _reset_stuck_sanitize(run_dir: Path, *, fast: bool) -> None:
    """Drop partial slow-mode sanitize work so fast mode can re-run cleanly."""
    if not fast:
        return
    clean = run_dir / "clean"
    sanitized = run_dir / "sanitized"
    if clean.is_dir():
        return
    if sanitized.is_dir():
        import shutil

        shutil.rmtree(sanitized)
    state_path = run_dir / "run_state.json"
    if state_path.is_file():
        state = json.loads(state_path.read_text())
        completed = state.get("gates_completed", [])
        if state.get("current_gate") == "clone" or "clone" not in completed:
            return
        if state.get("current_gate") == "sanitize" or "sanitize" not in completed:
            state["current_gate"] = "sanitize"
            state["gates_completed"] = [g for g in completed if g != "sanitize"]
            state_path.write_text(json.dumps(state, indent=2) + "\n")


def pipeline_repo(
    slug: str,
    source: Path,
    *,
    batch_id: str,
    batch_root: Path | None = None,
    env: dict,
    fast: bool,
    brand_terms: list[str] | None = None,
) -> dict:
    log: list[str] = []
    root = batch_root or BATCH_ROOT
    if not source.is_dir() or not (source / ".git").exists():
        result = {"slug": slug, "status": "skip", "reason": f"no git repo at {source}"}
        _write_repo_log(slug, log, root)
        return result

    run_dir = root / slug
    run_id = f"{batch_id}/{slug}"

    def step(name: str, cmd: list[str]) -> int:
        code, out = run_step(cmd, env)
        log.append(f"=== {name} (exit {code}) ===\n{out[-4000:]}")
        return code

    _ensure_mode_state(run_dir, fast=fast)
    _reset_stuck_sanitize(run_dir, fast=fast)

    if not (run_dir / "run_state.json").is_file():
        init_cmd = [
            sys.executable,
            str(ORCH),
            "init",
            "--run-id",
            run_id,
            "--repo-slug",
            slug,
            "--source",
            str(source),
        ]
        if fast:
            init_cmd.append("--fast")
        if step("init", init_cmd):
            result = {"slug": slug, "status": "fail", "gate": "init", "log": log}
            _write_repo_log(slug, log, root)
            return result

    state_path = run_dir / "run_state.json"
    if state_path.is_file():
        state = json.loads(state_path.read_text())
        gate = state.get("current_gate", "clone")
    else:
        gate = "clone"

    if gate == "clone":
        if step("clone", [sys.executable, str(ORCH), "clone", "--run-dir", str(run_dir)]):
            result = {"slug": slug, "status": "fail", "gate": "clone", "log": log}
            _write_repo_log(slug, log, root)
            return result

    state = json.loads(state_path.read_text())
    gate = state.get("current_gate", "sanitize")

    if gate == "sanitize":
        if step("sanitize", [sys.executable, str(ORCH), "sanitize", "--run-dir", str(run_dir)]):
            result = {"slug": slug, "status": "fail", "gate": "sanitize", "log": log}
            _write_repo_log(slug, log, root)
            return result

    state = json.loads(state_path.read_text())
    gate = state.get("current_gate", "brand")

    if gate == "brand":
        brand_cmd = [sys.executable, str(ORCH), "brand-map", "--run-dir", str(run_dir)]
        for term in brand_terms or ():
            brand_cmd.extend(["--term", term])
        if step("brand-map", brand_cmd):
            result = {"slug": slug, "status": "fail", "gate": "brand", "log": log}
            _write_repo_log(slug, log, root)
            return result

    state = json.loads(state_path.read_text())
    gate = state.get("current_gate", "package")

    if gate == "package":
        if step("package", [sys.executable, str(ORCH), "package", "--run-dir", str(run_dir)]):
            result = {"slug": slug, "status": "fail", "gate": "package", "log": log}
            _write_repo_log(slug, log, root)
            return result

    zip_path = run_dir / f"{slug}_sanitized.zip"
    result = {
        "slug": slug,
        "status": "done",
        "zip": str(zip_path) if zip_path.is_file() else None,
        "log": log,
    }
    _write_repo_log(slug, log, root)
    return result


def _pipeline_repo_worker(payload: dict) -> dict:
    """ProcessPool entrypoint."""
    global BATCH_ROOT
    BATCH_ROOT = Path(payload["batch_root"])
    env = payload["env"]
    for key, val in env.items():
        os.environ[key] = val
    try:
        result = pipeline_repo(
            payload["slug"],
            Path(payload["source"]),
            batch_id=payload["batch_id"],
            batch_root=BATCH_ROOT,
            env=env,
            fast=payload["fast"],
            brand_terms=payload.get("brand_terms"),
        )
    except Exception as exc:  # noqa: BLE001
        result = {"slug": payload["slug"], "status": "fail", "gate": "worker", "error": str(exc), "log": []}
        _write_repo_log(payload["slug"], [str(exc)], BATCH_ROOT)
    return result


def _should_skip_resume(slug: str, *, batch_root: Path | None = None, fast: bool = False) -> bool:
    root = batch_root or BATCH_ROOT
    run_dir = root / slug
    if (run_dir / f"{slug}_sanitized.zip").is_file():
        return _recorded_mode(run_dir, slug) == _mode_name(fast)
    state_path = run_dir / "run_state.json"
    if not state_path.is_file():
        return False
    state = json.loads(state_path.read_text())
    return state.get("current_gate") == "done" and bool(state.get("fast_mode")) == fast


def discover_repos(repos_file: Path) -> list[tuple[str, Path]]:
    """Load `slug<TAB|whitespace>path` lines, or a JSON list/mapping, from *repos_file*.

    Blank lines and `#` comments are ignored. When only a path is given, the slug
    is derived from the directory name. Duplicate slugs keep the first entry.
    """
    if not repos_file.is_file():
        raise SystemExit(f"Repo list not found: {repos_file}")

    items: list[tuple[str, Path]] = []
    text = repos_file.read_text(encoding="utf-8")

    if repos_file.suffix.lower() == ".json":
        data = json.loads(text)
        if isinstance(data, dict):
            items = [(slug, Path(path)) for slug, path in data.items()]
        else:
            for entry in data:
                if isinstance(entry, dict):
                    path = Path(entry["path"])
                    items.append((entry.get("slug") or path.name, path))
                else:
                    items.append((Path(entry).name, Path(entry)))
    else:
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                items.append((parts[0], Path(parts[1]).expanduser()))
            else:
                path = Path(parts[0]).expanduser()
                items.append((path.name, path))

    seen: set[str] = set()
    out: list[tuple[str, Path]] = []
    for slug, path in items:
        if slug in seen:
            continue
        seen.add(slug)
        out.append((slug, path))
    return out


def collect_terms(terms: list[str], terms_file: str | None) -> list[str]:
    out = [t.strip() for t in terms if t and t.strip()]
    if terms_file:
        path = Path(terms_file).expanduser()
        if not path.is_file():
            raise SystemExit(f"Terms file not found: {path}")
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return list(dict.fromkeys(out))


def main() -> int:
    p = argparse.ArgumentParser(description="Batch PII scrub pipeline")
    p.add_argument("--batch-id", default=DEFAULT_BATCH_ID)
    p.add_argument(
        "--repos-file",
        required=True,
        help="Repo list: 'slug <path>' lines (or JSON). See README.",
    )
    p.add_argument(
        "--fast",
        action="store_true",
        help="Fast mode: NER off, symlink source, no brand pass (regex/secrets only)",
    )
    p.add_argument("--env-file", default=str(ROOT / ".env"))
    p.add_argument("--limit", type=int, default=0, help="Max repos (0 = all)")
    p.add_argument("--workers", type=int, default=1, help="Parallel repo workers (default 1)")
    p.add_argument("--resume", action="store_true", help="Skip repos already past sanitize / packaged")
    p.add_argument("--slug", action="append", help="Run only these slugs")
    p.add_argument(
        "--term",
        action="append",
        default=[],
        help="Extra brand/org term to map in every repo (repeatable; ignored with --fast)",
    )
    p.add_argument("--terms-file", help="File with one brand term per line (# comments ok)")
    args = p.parse_args()

    global BATCH_ROOT
    BATCH_ROOT = ROOT / "outputs" / args.batch_id
    batch_root = BATCH_ROOT

    brand_terms = collect_terms(args.term, args.terms_file)

    salt_path = ROOT / ".salt"
    if not os.environ.get("REPO_SANITIZER_SALT"):
        if salt_path.is_file():
            os.environ["REPO_SANITIZER_SALT"] = salt_path.read_text().strip()
        else:
            import secrets

            val = secrets.token_hex(32)
            # 0600 from creation: the salt makes pseudonyms reproducible, so it is a secret.
            fd = os.open(salt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(val + "\n")
            os.chmod(salt_path, 0o600)
            os.environ["REPO_SANITIZER_SALT"] = val
            print(
                f"WARNING: REPO_SANITIZER_SALT was unset; generated a random one at {salt_path}. "
                "Set it explicitly if you need stable pseudonyms across machines.",
                file=sys.stderr,
            )

    tools = ROOT / ".tools" / "bin"
    venv = ROOT / ".venv" / "bin"
    env = os.environ.copy()
    env["PATH"] = f"{venv}:{tools}:{env.get('PATH', '')}"

    missing = missing_tools(env["PATH"])
    if missing:
        print(f"ERROR: {preflight_message(missing)}", file=sys.stderr)
        return 2

    repos = discover_repos(Path(args.repos_file).expanduser())
    if args.slug:
        want = set(args.slug)
        repos = [(s, p) for s, p in repos if s in want]

    if args.limit:
        repos = repos[: args.limit]

    load_env_file(env, Path(args.env_file) if args.env_file else None)

    if args.resume:
        pending: list[tuple[str, Path]] = []
        for slug, path in repos:
            if _should_skip_resume(slug, batch_root=batch_root, fast=args.fast):
                print(f"SKIP (resume) {slug}", flush=True)
            else:
                pending.append((slug, path))
        repos = pending

    worker_env = worker_env_from(env)

    payloads = [
        {
            "slug": slug,
            "source": str(path),
            "batch_id": args.batch_id,
            "batch_root": str(batch_root),
            "env": worker_env,
            "fast": args.fast,
            "brand_terms": brand_terms,
        }
        for slug, path in repos
    ]

    results: list[dict] = []
    workers = max(1, args.workers)
    if workers == 1:
        for slug, path in repos:
            print(f"\n>>> {slug}", flush=True)
            results.append(
                pipeline_repo(
                    slug,
                    path,
                    batch_id=args.batch_id,
                    batch_root=batch_root,
                    env=env,
                    fast=args.fast,
                    brand_terms=brand_terms,
                )
            )
    else:
        print(f"Running {len(payloads)} repos with {workers} parallel workers", flush=True)
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_pipeline_repo_worker, p): p["slug"] for p in payloads}
            for fut in as_completed(futures):
                slug = futures[fut]
                try:
                    result = fut.result()
                except Exception as exc:  # noqa: BLE001
                    result = {"slug": slug, "status": "fail", "gate": "worker", "error": str(exc)}
                print(f"{result.get('status', '?'):8} {slug}", flush=True)
                results.append(result)
        results.sort(key=lambda r: r.get("slug", ""))

    summary_path = BATCH_ROOT / "batch_summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "batch_id": args.batch_id,
        "at": datetime.now(timezone.utc).isoformat(),
        "total": len(results),
        "done": sum(1 for r in results if r["status"] == "done"),
        "partial": sum(1 for r in results if r["status"] == "partial"),
        "fail": sum(1 for r in results if r["status"] == "fail"),
        "skip": sum(1 for r in results if r["status"] == "skip"),
        "fast": args.fast,
        "results": results,
    }
    summary_path.write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps({k: payload[k] for k in ("total", "done", "partial", "fail", "skip")}, indent=2))
    print(f"Summary: {summary_path}")
    return 0 if payload["fail"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
