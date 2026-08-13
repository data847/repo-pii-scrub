#!/usr/bin/env python3
"""
Human-in-the-loop PII scrub pipeline for dataset repo delivery.

Gates:
  0 init      — register run (source, slug, rulepack)
  1 clone     — clone or copy source repo
  2 sanitize  — repo-sanitizer scan + sanitize + materialize clean clone
  3 llm       — LLM privacy review (requires --human-approved to proceed past WARN/FAIL)
  4 trim      — keep first N percent of commits (default 5)
  5 verify    — post-trim repo-sanitizer gate + gitleaks
  6 package   — zip + MANIFEST.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from llm_review import DEFAULT_MODEL, ensure_env, run_llm_review  # noqa: E402
from state import init_run, load, save  # noqa: E402
from steps import (  # noqa: E402
    apply_brand_map,
    brand_pseudonym,
    brand_worklist_terms,
    build_llm_sample,
    check_prerequisites,
    clone_or_copy_source,
    materialize_clean,
    package_deliverable,
    record_baseline,
    sanitize,
    scan_pre,
    stub_llm_pass_fast,
    trim_history,
    verify_post_trim,
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
    ensure_env(Path(args.env_file) if args.env_file else None)
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
        history_pct=args.history_pct,
        model=args.model,
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
        scan_pre(source, rulepack, run_dir / "scan-pre", fast=_fast(state))
        print(f"Pre-scan written to {run_dir / 'scan-pre'}")

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
    mark_gate(state_path, state, "sanitize", "llm")
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
        build_llm_sample(run_dir / "clean", run_dir)
        mark_gate(state_path, state, "brand", "llm")
        return 0

    brand_map = write_brand_map(terms, run_dir)
    print(f"Pass-2 brand map ({len(terms)} terms): {brand_map}")
    for term in terms:
        print(f"  {term} -> {brand_pseudonym(term)}")

    finalized = run_dir / "sanitized-brands"
    bundle = apply_brand_map(sanitized, brand_map, finalized)

    materialize_clean(bundle, run_dir / "clean")
    build_llm_sample(run_dir / "clean", run_dir)

    state["brand_terms"] = terms
    state["brand_map"] = str(brand_map)
    mark_gate(state_path, state, "brand", "llm")
    print("\n=== GATE 2b COMPLETE: BRAND MAP (Pass-3 applied) ===")
    print(f"Clean repo: {run_dir / 'clean'}")
    return 0


def cmd_llm_review(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    state_path = run_dir / "run_state.json"
    state = load(state_path)
    require_gate(state, "llm")
    ensure_env(Path(args.env_file) if args.env_file else None)

    if args.prepare_only:
        build_llm_sample(run_dir / "clean", run_dir)
        print(f"Prepared {run_dir / 'llm_review_payload.txt'}")
        return 0

    if not args.human_approved and not args.auto and not _fast(state):
        raise SystemExit("Gate 3 requires --human-approved or --auto to run LLM review")

    if _fast(state):
        result = stub_llm_pass_fast(run_dir)
        state["llm_verdict"] = result.get("verdict")
        state["human_approvals"]["llm"] = True
        mark_gate(state_path, state, "llm", "trim")
        print("\n=== GATE 3 COMPLETE: LLM REVIEW (fast mode stub) ===")
        print(json.dumps(result, indent=2))
        return 0

    result = run_llm_review(run_dir, model=state.get("model", DEFAULT_MODEL))
    state["llm_verdict"] = result.get("verdict")
    verdict = result.get("verdict", "FAIL")

    if verdict == "FAIL":
        save(state_path, state)
        print("\n=== GATE 3 FAILED: LLM REVIEW ===")
        print(json.dumps(result, indent=2))
        print("\nUpdate rulepack → re-run sanitize. Do not proceed to trim.")
        return 1

    if verdict == "WARN" and not args.human_approved:
        save(state_path, state)
        print("\n=== GATE 3 WARN: human approval required ===")
        print(json.dumps(result, indent=2))
        print("\nRe-run with --human-approved after reviewing llm_review_notes.md")
        return 1

    if args.human_approved:
        state["human_approvals"]["llm"] = True

    mark_gate(state_path, state, "llm", "trim")
    print("\n=== GATE 3 COMPLETE: LLM REVIEW ===")
    print(f"Verdict: {verdict}")
    print(f"Notes: {run_dir / 'llm_review_notes.md'}")
    return 0


def cmd_trim(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    state_path = run_dir / "run_state.json"
    state = load(state_path)
    require_gate(state, "trim")

    if not args.human_approved:
        raise SystemExit("Gate 4 requires --human-approved")

    clean = run_dir / "clean"
    if not clean.is_dir():
        raise SystemExit(f"Missing clean repo: {clean}")

    pct = args.history_pct if args.history_pct is not None else state.get("history_pct", 5)
    info = trim_history(clean, run_dir, pct)
    state["human_approvals"]["trim"] = True
    mark_gate(state_path, state, "trim", "verify")
    print("\n=== GATE 4 COMPLETE: TRIM HISTORY ===")
    print(json.dumps(info, indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    state_path = run_dir / "run_state.json"
    state = load(state_path)
    require_gate(state, "verify")
    check_prerequisites()

    rulepack = Path(state["rulepack"])
    residual_brands = verify_post_trim(run_dir / "clean", rulepack, run_dir, fast=_fast(state))
    state["residual_brand_gates"] = residual_brands
    mark_gate(state_path, state, "verify", "package")
    print("\n=== GATE 5 COMPLETE: VERIFY ===")
    if residual_brands:
        print(f"WARNING: residual brand gates (auditable, not PII): {', '.join(residual_brands)}")
    print(f"Gate report: {run_dir / 'gate-post-trim' / 'artifacts' / 'result.json'}")
    return 0


def cmd_package(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    state_path = run_dir / "run_state.json"
    state = load(state_path)
    require_gate(state, "package")

    zip_path = package_deliverable(run_dir, state["repo_slug"])
    mark_gate(state_path, state, "package", "done")
    print("\n=== GATE 6 COMPLETE: PACKAGE ===")
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
    init_p.add_argument("--history-pct", type=int, default=5, help="Earliest commits to keep, as percent (default 5)")
    init_p.add_argument("--model", default=DEFAULT_MODEL, help="Anthropic model for Gate 3")
    init_p.add_argument("--fast", action="store_true", help="Fast mode: symlink source, NER off, gitleaks-only verify")
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

    llm_p = sub.add_parser("llm-review", help="Gate 3: LLM privacy review")
    llm_p.add_argument("--run-dir", required=True)
    llm_p.add_argument("--human-approved", action="store_true")
    llm_p.add_argument("--auto", action="store_true", help="Run LLM; still blocks on FAIL")
    llm_p.add_argument("--prepare-only", action="store_true")
    llm_p.add_argument("--env-file")
    llm_p.set_defaults(func=cmd_llm_review)

    trim_p = sub.add_parser("trim", help="Gate 4: trim to first N percent of commits")
    trim_p.add_argument("--run-dir", required=True)
    trim_p.add_argument("--human-approved", action="store_true")
    trim_p.add_argument("--history-pct", type=int)
    trim_p.set_defaults(func=cmd_trim)

    verify_p = sub.add_parser("verify", help="Gate 5: post-trim verification")
    verify_p.add_argument("--run-dir", required=True)
    verify_p.set_defaults(func=cmd_verify)

    package_p = sub.add_parser("package", help="Gate 6: zip deliverable")
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
