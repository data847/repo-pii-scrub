#!/usr/bin/env python3
"""End-to-end pipeline verification against the PII fixture repo.

Runs the same `pipeline_repo` the org batches use (clone + sanitize + brand-map +
package), then asserts that not one planted PII value survives in the deliverable.
Full history is delivered, so the leak scan covers every commit.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from batch_env import build_env, worker_env_from  # noqa: E402
from ner_service_manager import NerService  # noqa: E402
from run_batch import pipeline_repo  # noqa: E402

ORCH = SCRIPTS / "orchestrator.py"
VERIFIER = SCRIPTS / "verify_pii_fixture.py"
FIXTURE_MAKER = SCRIPTS / "make_pii_fixture.py"


def log(msg: str) -> None:
    print(msg, flush=True)


def build_fixture(dest: Path, manifest: Path, filler: int) -> dict:
    proc = subprocess.run(
        [
            sys.executable,
            str(FIXTURE_MAKER),
            "--dest",
            str(dest),
            "--manifest",
            str(manifest),
            "--filler",
            str(filler),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


def init_run(run_dir: Path, run_id: str, slug: str, source: Path, env: dict) -> None:
    run_dir.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            str(ORCH),
            "init",
            "--run-id",
            run_id,
            "--repo-slug",
            slug,
            "--source",
            str(source),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )


def verify(manifest: Path, *, repo: Path | None, zip_path: Path | None, env: dict) -> tuple[int, str]:
    cmd = [sys.executable, str(VERIFIER), "--manifest", str(manifest)]
    if repo:
        cmd.extend(["--repo", str(repo)])
    if zip_path:
        cmd.extend(["--zip", str(zip_path)])
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--slug", default="pii-fixture-repo")
    p.add_argument("--batch-id", default="_verification")
    p.add_argument("--filler", type=int, default=300, help="Filler modules in the fixture")
    p.add_argument("--ner-device", default="cpu")
    p.add_argument("--ner-port", type=int, default=8765)
    p.add_argument("--ner-scope", default="head", choices=("head", "all", "off"))
    p.add_argument("--step-timeout", type=int, default=3600)
    p.add_argument("--gate-timeout", type=int, default=5400)
    p.add_argument("--reuse-fixture", action="store_true", help="Do not regenerate the fixture")
    p.add_argument(
        "--brand-term",
        action="append",
        default=["AcmePay", "acmepayments", "АкмеПэй"],
        help="Brand terms for the Pass-2 map (fixture defaults to its own org names)",
    )
    args = p.parse_args()

    fixture = ROOT / "fixtures" / "pii-fixture-repo"
    manifest = ROOT / "fixtures" / "pii_manifest.json"

    if args.reuse_fixture and fixture.is_dir() and manifest.is_file():
        info = json.loads(manifest.read_text())["fixture"]
        log(f"Reusing fixture: {info['tracked_files']} files, {info['commits']} commits")
    else:
        log("Building fixture repo...")
        info = build_fixture(fixture, manifest, args.filler)
        log(
            f"Fixture: {info['tracked_files']} files, {info['commits']} commits, "
            f"{info['size_bytes'] / 1_048_576:.1f} MB"
        )

    env = build_env()
    if not env.get("REPO_SANITIZER_SALT"):
        log("ERROR: REPO_SANITIZER_SALT missing (.salt file)")
        return 1

    env["PII_SCRUB_NER_SCOPE"] = args.ner_scope
    env["PII_SCRUB_NER_DEVICE"] = args.ner_device
    env["PII_SCRUB_STEP_TIMEOUT"] = str(args.step_timeout)
    env["PII_SCRUB_GATE_TIMEOUT"] = str(args.gate_timeout)
    env["TOKENIZERS_PARALLELISM"] = "false"

    log("Fixture self-check (planted values must match their detectors)...")
    check = subprocess.run(
        [sys.executable, str(VERIFIER), "--manifest", str(manifest), "--check-patterns"],
        env=env,
        capture_output=True,
        text=True,
    )
    log(check.stdout.strip())
    if check.returncode != 0:
        log("ERROR: fixture is not self-consistent; fix the planted values first")
        return 1

    service: NerService | None = None
    if args.ner_scope != "off":
        service = NerService(port=args.ner_port, device=args.ner_device, rulepack=ROOT / "rules")
        log(f"Starting shared NER service (device={args.ner_device})...")
        env["PII_SCRUB_NER_SERVICE_URL"] = service.start()
        log(f"NER service ready: {env['PII_SCRUB_NER_SERVICE_URL']}")

    batch_root = ROOT / "outputs" / args.batch_id
    run_dir = batch_root / args.slug
    if run_dir.exists():
        shutil.rmtree(run_dir)

    started = time.time()
    try:
        init_run(run_dir, f"{args.batch_id}/{args.slug}", args.slug, fixture, env)
        log("Running normal-mode pipeline (full history)...")
        result = pipeline_repo(
            args.slug,
            fixture,
            batch_id=args.batch_id,
            batch_root=batch_root,
            env=worker_env_from(env),
            fast=False,
            brand_terms=args.brand_term,
        )
    finally:
        if service is not None:
            service.stop()

    elapsed = time.time() - started
    log(f"\nPipeline finished in {elapsed / 60:.1f} min: status={result.get('status')}")

    log_path = batch_root / "logs" / f"{args.slug}.log"
    if result.get("status") != "done":
        log(f"FAILED at gate '{result.get('gate')}' — see {log_path}")
        for entry in result.get("log", [])[-2:]:
            log(entry[-3000:])
        return 1

    clean = run_dir / "clean"
    zip_path = Path(result["zip"]) if result.get("zip") else None

    log("\n=== Leak scan: clean repo (working tree + all history + commit metadata) ===")
    code_repo, out_repo = verify(manifest, repo=clean, zip_path=None, env=env)
    log(out_repo.strip())

    code_zip, out_zip = 0, ""
    if zip_path and zip_path.is_file():
        log("\n=== Leak scan: deliverable zip ===")
        code_zip, out_zip = verify(manifest, repo=None, zip_path=zip_path, env=env)
        log(out_zip.strip())

    gate_report = run_dir / "sanitized" / "artifacts" / "result.json"
    if gate_report.is_file():
        data = json.loads(gate_report.read_text())
        log("\n=== Sanitizer report ===")
        log(
            json.dumps(
                {k: data[k] for k in ("findings_total", "gate", "bundle_sha256") if k in data},
                indent=2,
            )
        )

    secret_scan = run_dir / "gitleaks.json"
    if secret_scan.is_file():
        hits = json.loads(secret_scan.read_text())
        log(f"\nIndependent secret scan (gitleaks): {len(hits)} real finding(s)")

    ok = code_repo == 0 and code_zip == 0
    log("\n" + ("=" * 60))
    log("VERIFICATION PASSED" if ok else "VERIFICATION FAILED")
    log("=" * 60)
    log(f"run dir: {run_dir}")
    if zip_path:
        log(f"deliverable: {zip_path}")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
