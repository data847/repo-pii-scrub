#!/usr/bin/env python3
"""
PII scrub pipeline for dataset repo delivery.

Gates:
  0 init      — register run (source, slug, rulepack)
  1 clone     — clone or copy source repo
  2 sanitize  — repo-sanitizer scan + sanitize (Pass-1)
  2b brand-map— Pass-2 brand map + Pass-3 apply-map, materialize clean clone
  3 package   — gitleaks assertion + zip + MANIFEST.json

Full git history is delivered. The sanitizer's own gates decide whether a repo is
clean; `package` adds an independent gitleaks check before zipping.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from batch_env import load_env_file  # noqa: E402
from state import init_run, load, save  # noqa: E402
from steps import (  # noqa: E402
    apply_brand_map,
    assert_no_secrets,
    brand_pseudonym,
    brand_worklist_terms,
    check_prerequisites,
    clone_or_copy_source,
    materialize_clean,
    package_deliverable,
    record_baseline,
    sanitize,
    scan_pre,
    write_brand_map,
)


def run_dir_for(run_id: str) -> Path:
    return ROOT / "outputs" / run_id


def require_gate(state: dict, expected: str) -> None:
    if state.get("current_gate") != expected:
        raise SystemExit(
            f"Expected gate '{expected}', current gate is '{state.get('current_gate')}'. "
            f"Completed: {state.get('gates_completed')}"
        )


def mark_gate(state_path: Path, state: dict, gate: str, nxt: str) -> None:
    if gate not in state["gates_completed"]:
        state["gates_completed"].append(gate)
    state["current_gate"] = nxt
    save(state_path, state)


def _fast(state: dict) -> bool:
    return bool(state.get("fast_mode"))


def cmd_init(args: argparse.Namespace) -> int:
    load_env_file(os.environ, Path(args.env_file) if args.env_file else None)
    run_dir = run_dir_for(args.run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    rulepack = Path(args.rulepack).resolve()
    if not rulepack.is_dir():
        print(f"WARNING: rulepack directory not found yet: {rulepack}", file=sys.stderr)
        print("Copy repo-sanitizer examples/rules before Gate 2 (see rules/README.md)", file=sys.stderr)

    state_path = run_dir / "run_state.json"
    state = init_run(
        state_path,
        run_id=args.run_id,
        repo_slug=args.repo_slug,
        source=args.source,
        rulepack=str(rulepack),
        fast_mode=bool(args.fast),
    )
    print(json.dumps({"run_dir": str(run_dir), **state}, indent=2))
    return 0


def cmd_clone(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    state_path = run_dir / "run_state.json"
    state = load(state_path)
    require_gate(state, "clone")
    check_prerequisites()

    source = args.source or state["source"]
    dest = run_dir / "source"
    clone_or_copy_source(source, dest, fast=_fast(state))
    baseline = record_baseline(dest, run_dir)
    mark_gate(state_path, state, "clone", "sanitize")
    print("\n=== GATE 1 COMPLETE: CLONE ===")
    print(json.dumps({"source": str(dest), **baseline}, indent=2))
    return 0


def cmd_sanitize(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    state_path = run_dir / "run_state.json"
    state = load(state_path)
    require_gate(state, "sanitize")
    check_prerequisites()

    rulepack = Path(state["rulepack"])
    if not rulepack.is_dir():
        raise SystemExit(f"Rulepack not found: {rulepack}. See rules/README.md")
    source = run_dir / "source"
    if not source.is_dir():
        raise SystemExit(f"Missing source clone: {source}")

    if args.pre_scan:
        found = scan_pre(source, rulepack, run_dir / "scan-pre", fast=_fast(state))
        print(f"Pre-scan: {found} findings — {run_dir / 'scan-pre'}")

    sanitized = run_dir / "sanitized"
    worklist = sanitize(source, rulepack, sanitized, fast=_fast(state))
    bundle = sanitized / "output" / "sanitized.bundle"
    if not bundle.is_file():
        raise SystemExit(f"Sanitizer did not produce bundle: {bundle}")

    # Normal mode always continues into Pass-2/Pass-3, which is where the clean
    # clone is materialized. Fast mode has no brand pass.
    if not _fast(state):
        state["brand_worklist"] = worklist
        mark_gate(state_path, state, "sanitize", "brand")
        print("\n=== GATE 2 COMPLETE: SANITIZE ===")
        if worklist:
            print(f"Brand gates awaiting Pass-2: {', '.join(worklist)}")
        print("Next: orchestrator.py brand-map --run-dir <dir>")
        return 0

    materialize_clean(bundle, run_dir / "clean")
    mark_gate(state_path, state, "sanitize", "package")
    print("\n=== GATE 2 COMPLETE: SANITIZE ===")
    print(f"Clean repo: {run_dir / 'clean'}")
    return 0


def cmd_brand_map(args: argparse.Namespace) -> int:
    """Gate 2b: Pass-2 brand map + Pass-3 apply-map across all history."""
    run_dir = Path(args.run_dir)
    state_path = run_dir / "run_state.json"
    state = load(state_path)
    require_gate(state, "brand")
    check_prerequisites()

    sanitized = run_dir / "sanitized"
    # Only explicit --term seeds: deriving terms from the slug would map generic
    # words ("repo", "app") and mangle unrelated content.
    terms = brand_worklist_terms(sanitized, extra_terms=tuple(args.term or ()))

    if not terms:
        print("No brand terms to map; carrying Pass-1 bundle forward.")
        materialize_clean(sanitized / "output" / "sanitized.bundle", run_dir / "clean")
        mark_gate(state_path, state, "brand", "package")
        return 0

    brand_map = write_brand_map(terms, run_dir)
    print(f"Pass-2 brand map ({len(terms)} terms): {brand_map}")
    for term in terms:
        print(f"  {term} -> {brand_pseudonym(term)}")

    finalized = run_dir / "sanitized-brands"
    bundle = apply_brand_map(sanitized, brand_map, finalized)

    materialize_clean(bundle, run_dir / "clean")

    state["brand_terms"] = terms
    state["brand_map"] = str(brand_map)
    mark_gate(state_path, state, "brand", "package")
    print("\n=== GATE 2b COMPLETE: BRAND MAP (Pass-3 applied) ===")
    print(f"Clean repo: {run_dir / 'clean'}")
    return 0


def cmd_package(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    state_path = run_dir / "run_state.json"
    state = load(state_path)
    require_gate(state, "package")
    check_prerequisites()

    ignored = assert_no_secrets(run_dir / "clean", run_dir)
    print(f"Secret scan clean ({ignored} redaction placeholders ignored)")

    zip_path = package_deliverable(run_dir, state["repo_slug"])
    mark_gate(state_path, state, "package", "done")
    print("\n=== GATE 3 COMPLETE: PACKAGE ===")
    print(f"Zip: {zip_path}")
    print(f"Manifest: {run_dir / 'MANIFEST.json'}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    state = load(Path(args.run_dir) / "run_state.json")
    print(json.dumps(state, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Repo PII scrub pipeline orchestrator")
    sub = p.add_subparsers(dest="command", required=True)

    init_p = sub.add_parser("init", help="Gate 0: initialize run")
    init_p.add_argument("--run-id", required=True)
    init_p.add_argument("--repo-slug", required=True, help="e.g. org__my-repo")
    init_p.add_argument("--source", required=True, help="git URL or local path")
    init_p.add_argument("--rulepack", default=str(ROOT / "rules"))
    init_p.add_argument(
        "--fast",
        action="store_true",
        help="Fast mode: symlink source, NER off, no brand pass (regex/secrets only)",
    )
    init_p.add_argument("--env-file")
    init_p.set_defaults(func=cmd_init)

    clone_p = sub.add_parser("clone", help="Gate 1: clone or copy source")
    clone_p.add_argument("--run-dir", required=True)
    clone_p.add_argument("--source", help="Override source from init")
    clone_p.set_defaults(func=cmd_clone)

    sanitize_p = sub.add_parser("sanitize", help="Gate 2: scrub PII")
    sanitize_p.add_argument("--run-dir", required=True)
    sanitize_p.add_argument("--pre-scan", action="store_true")
    sanitize_p.set_defaults(func=cmd_sanitize)

    brand_p = sub.add_parser("brand-map", help="Gate 2b: Pass-2 brand map + Pass-3 apply-map")
    brand_p.add_argument("--run-dir", required=True)
    brand_p.add_argument(
        "--term",
        action="append",
        help="Extra brand term to map (repeatable); worklist findings are added automatically",
    )
    brand_p.set_defaults(func=cmd_brand_map)

    package_p = sub.add_parser("package", help="Gate 3: secret scan + zip deliverable")
    package_p.add_argument("--run-dir", required=True)
    package_p.set_defaults(func=cmd_package)

    status_p = sub.add_parser("status", help="Show run state")
    status_p.add_argument("--run-dir", required=True)
    status_p.set_defaults(func=cmd_status)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
