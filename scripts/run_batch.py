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



def _ensure_fast_state(run_dir: Path, *, fast: bool) -> None:
    state_path = run_dir / "run_state.json"
    if not fast or not state_path.is_file():
        return
    state = json.loads(state_path.read_text())
    if state.get("fast_mode"):
        return
    state["fast_mode"] = True
    state_path.write_text(json.dumps(state, indent=2) + "\n")


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
    skip_llm: bool,
    fast: bool,
    env_file: Path | None,
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
    deliver = fast or not skip_llm

    def step(name: str, cmd: list[str]) -> int:
        code, out = run_step(cmd, env)
        log.append(f"=== {name} (exit {code}) ===\n{out[-4000:]}")
        return code

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
        step("init", init_cmd)
    elif fast:
        _ensure_fast_state(run_dir, fast=True)

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
    gate = state.get("current_gate", "llm")

    if gate == "llm" and deliver:
        llm_cmd = [
            sys.executable,
            str(ORCH),
            "llm-review",
            "--run-dir",
            str(run_dir),
            "--auto",
            "--human-approved",
        ]
        if env_file:
            llm_cmd.extend(["--env-file", str(env_file)])
        if step("llm", llm_cmd):
            result = {"slug": slug, "status": "fail", "gate": "llm", "log": log}
            _write_repo_log(slug, log, root)
            return result
    elif gate == "llm" and skip_llm and not fast:
        log.append("=== llm SKIPPED (--skip-llm) ===")

    state = json.loads(state_path.read_text())
    gate = state.get("current_gate", "trim")

    if gate == "llm" and not deliver:
        result = {"slug": slug, "status": "partial", "gate": "llm", "log": log}
        _write_repo_log(slug, log, root)
        return result

    if gate == "trim":
        if step(
            "trim",
            [sys.executable, str(ORCH), "trim", "--run-dir", str(run_dir), "--human-approved"],
        ):
            result = {"slug": slug, "status": "fail", "gate": "trim", "log": log}
            _write_repo_log(slug, log, root)
            return result

    state = json.loads(state_path.read_text())
    gate = state.get("current_gate", "verify")

    if gate == "verify":
        if step("verify", [sys.executable, str(ORCH), "verify", "--run-dir", str(run_dir)]):
            result = {"slug": slug, "status": "fail", "gate": "verify", "log": log}
            _write_repo_log(slug, log, root)
            return result

    state = json.loads(state_path.read_text())
    gate = state.get("current_gate", "package")

    if gate == "package":
        if step("package", [sys.executable, str(ORCH), "package", "--run-dir", str(run_dir)]):
            result = {"slug": slug, "status": "fail", "gate": "package", "log": log}
            _write_repo_log(slug, log, root)
            return result

    zip_path = run_dir / f"{slug}_sanitized_first5pct.zip"
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
            skip_llm=payload["skip_llm"],
            fast=payload["fast"],
            env_file=Path(payload["env_file"]) if payload.get("env_file") else None,
            brand_terms=payload.get("brand_terms"),
        )
    except Exception as exc:  # noqa: BLE001
        result = {"slug": payload["slug"], "status": "fail", "gate": "worker", "error": str(exc), "log": []}
        _write_repo_log(payload["slug"], [str(exc)], BATCH_ROOT)
    return result


def _should_skip_resume(slug: str, *, skip_llm: bool, fast: bool, batch_root: Path | None = None) -> bool:
    root = batch_root or BATCH_ROOT
    state_path = root / slug / "run_state.json"
    zip_path = root / slug / f"{slug}_sanitized_first5pct.zip"
    if zip_path.is_file():
        return True
    if not state_path.is_file():
        return False
    state = json.loads(state_path.read_text())
    gate = state.get("current_gate", "")
    if gate == "done":
        return True
    if fast:
        return False
    if skip_llm and gate in {"llm", "trim", "verify", "package", "done"}:
        return True
    return False


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


def main() -> int:
    p = argparse.ArgumentParser(description="Batch PII scrub pipeline")
    p.add_argument("--batch-id", default=DEFAULT_BATCH_ID)
    p.add_argument(
        "--repos-file",
        required=True,
        help="Repo list: 'slug <path>' lines (or JSON). See README.",
    )
    p.add_argument("--skip-llm", action="store_true", help="Stop after sanitize (Gate 2); ignored with --fast")
    p.add_argument(
        "--fast",
        action="store_true",
        help="Fast mode: NER off, symlink source, stub LLM, gitleaks-only verify, full zip deliverable",
    )
    p.add_argument("--env-file", default=str(ROOT / ".env"))
    p.add_argument("--limit", type=int, default=0, help="Max repos (0 = all)")
    p.add_argument("--workers", type=int, default=1, help="Parallel repo workers (default 1)")
    p.add_argument("--resume", action="store_true", help="Skip repos already past sanitize / packaged")
    p.add_argument("--slug", action="append", help="Run only these slugs")
    args = p.parse_args()

    global BATCH_ROOT
    BATCH_ROOT = ROOT / "outputs" / args.batch_id
    batch_root = BATCH_ROOT

    salt_path = ROOT / ".salt"
    if not os.environ.get("REPO_SANITIZER_SALT"):
        if salt_path.is_file():
            os.environ["REPO_SANITIZER_SALT"] = salt_path.read_text().strip()
        else:
            import secrets

            val = secrets.token_hex(32)
            salt_path.write_text(val + "\n")
            os.environ["REPO_SANITIZER_SALT"] = val

    tools = ROOT / ".tools" / "bin"
    venv = ROOT / ".venv" / "bin"
    env = os.environ.copy()
    env["PATH"] = f"{venv}:{tools}:{env.get('PATH', '')}"

    repos = discover_repos(Path(args.repos_file).expanduser())
    if args.slug:
        want = set(args.slug)
        repos = [(s, p) for s, p in repos if s in want]

    if args.limit:
        repos = repos[: args.limit]

    env_file = Path(args.env_file) if args.env_file else None
    if env_file and env_file.is_file():
        for raw in env_file.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip().strip("'\"")
            if key and key not in env:
                env[key] = val

    if args.fast:
        args.skip_llm = False

    if args.resume:
        pending: list[tuple[str, Path]] = []
        for slug, path in repos:
            if _should_skip_resume(slug, skip_llm=args.skip_llm, fast=args.fast, batch_root=batch_root):
                print(f"SKIP (resume) {slug}", flush=True)
            else:
                pending.append((slug, path))
        repos = pending

    worker_env = {
        k: env[k]
        for k in ("PATH", "REPO_SANITIZER_SALT", "ANTHROPIC_API_KEY", "PII_SCRUB_MODEL")
        if k in env
    }
    worker_env["PATH"] = env["PATH"]

    payloads = [
        {
            "slug": slug,
            "source": str(path),
            "batch_id": args.batch_id,
            "batch_root": str(batch_root),
            "env": worker_env,
            "skip_llm": args.skip_llm,
            "fast": args.fast,
            "env_file": str(env_file) if env_file else "",
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
                    skip_llm=args.skip_llm,
                    fast=args.fast,
                    env_file=env_file,
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
        "skip_llm": args.skip_llm,
        "fast": args.fast,
        "results": results,
    }
    summary_path.write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps({k: payload[k] for k in ("total", "done", "partial", "fail", "skip")}, indent=2))
    print(f"Summary: {summary_path}")
    return 0 if payload["fail"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
