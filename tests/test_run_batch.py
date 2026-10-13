from __future__ import annotations

import json
import os
import stat
import sys

import pytest

import run_batch
import steps


def test_collect_terms_dedupes_and_reads_file(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("# c\nAcme\n\nBeta\n")
    assert run_batch.collect_terms(["Acme", " Gamma "], str(f)) == ["Acme", "Gamma", "Beta"]


def test_terms_reach_brand_map_gate(tmp_path, monkeypatch):
    src = tmp_path / "src"
    (src / ".git").mkdir(parents=True)
    calls = []
    run_dir = tmp_path / "root" / "slug"

    def fake_step(cmd, env):
        calls.append(cmd)
        sub = cmd[2]
        run_dir.mkdir(parents=True, exist_ok=True)
        gates = {"init": "clone", "clone": "sanitize", "sanitize": "brand", "brand-map": "package", "package": "done"}
        (run_dir / "run_state.json").write_text(json.dumps({"current_gate": gates[sub], "fast_mode": False}))
        return 0, ""

    monkeypatch.setattr(run_batch, "run_step", fake_step)
    res = run_batch.pipeline_repo(
        "slug", src, batch_id="b", batch_root=tmp_path / "root", env={}, fast=False, brand_terms=["Acme", "Beta"]
    )
    assert res["status"] == "done"
    brand = next(c for c in calls if c[2] == "brand-map")
    assert brand.count("--term") == 2 and "Acme" in brand and "Beta" in brand


def test_every_gate_and_the_total_print_a_timing_line(tmp_path, monkeypatch, capsys):
    src = tmp_path / "src"
    (src / ".git").mkdir(parents=True)
    run_dir = tmp_path / "root" / "slug"

    def fake_step(cmd, env):
        run_dir.mkdir(parents=True, exist_ok=True)
        gates = {"init": "clone", "clone": "sanitize", "sanitize": "brand", "brand-map": "package", "package": "done"}
        (run_dir / "run_state.json").write_text(json.dumps({"current_gate": gates[cmd[2]], "fast_mode": False}))
        return 0, ""

    monkeypatch.setattr(run_batch, "run_step", fake_step)
    run_batch.pipeline_repo("slug", src, batch_id="b", batch_root=tmp_path / "root", env={}, fast=False)
    lines = [ln.split() for ln in capsys.readouterr().out.splitlines() if ln.startswith("SCRUB-TIMING")]
    assert [(ln[1], ln[2]) for ln in lines] == [("slug", "init"), ("slug", "clone"), ("slug", "sanitize"), ("slug", "brand-map"),
                                                 ("slug", "package"), ("slug", "total")]
    assert all(float(ln[3]) >= 0 for ln in lines) and lines[0][4] == "exit=0" and len(lines[-1]) == 4


def test_a_failed_gate_still_reports_its_time_and_the_total(tmp_path, monkeypatch, capsys):
    src = tmp_path / "src"
    (src / ".git").mkdir(parents=True)
    monkeypatch.setattr(run_batch, "run_step", lambda cmd, env: (1, "boom"))
    run_batch.pipeline_repo("slug", src, batch_id="b", batch_root=tmp_path / "root", env={}, fast=False)
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("SCRUB-TIMING slug init ") and out[0].endswith("exit=1") and out[-1].startswith("SCRUB-TIMING slug total ")


def test_init_failure_stops(tmp_path, monkeypatch):
    src = tmp_path / "src"
    (src / ".git").mkdir(parents=True)
    calls = []
    monkeypatch.setattr(run_batch, "run_step", lambda cmd, env: (calls.append(cmd), (1, "boom"))[1])
    res = run_batch.pipeline_repo("slug", src, batch_id="b", batch_root=tmp_path / "root", env={}, fast=False)
    assert res["status"] == "fail" and res["gate"] == "init"
    assert len(calls) == 1


def _done_run(root, slug, mode, *, fast_state):
    d = root / slug
    d.mkdir(parents=True)
    (d / f"{slug}_sanitized.zip").write_text("z")
    manifest = {"mode": mode} if mode else {}
    (d / "MANIFEST.json").write_text(json.dumps(manifest))
    (d / "run_state.json").write_text(json.dumps({"current_gate": "done", "fast_mode": fast_state}))
    return d


def test_resume_compares_mode(tmp_path):
    _done_run(tmp_path, "a", "fast", fast_state=True)
    assert run_batch._should_skip_resume("a", batch_root=tmp_path, fast=True)
    assert not run_batch._should_skip_resume("a", batch_root=tmp_path, fast=False)
    _done_run(tmp_path, "b", None, fast_state=False)  # legacy manifest == normal
    assert run_batch._should_skip_resume("b", batch_root=tmp_path, fast=False)
    assert not run_batch._should_skip_resume("b", batch_root=tmp_path, fast=True)


def test_mode_flip_both_directions(tmp_path):
    d = tmp_path / "x"
    d.mkdir()
    state = d / "run_state.json"
    state.write_text(json.dumps({"current_gate": "sanitize", "fast_mode": False}))
    run_batch._ensure_mode_state(d, fast=True)  # unfinished normal -> fast kept
    assert json.loads(state.read_text())["fast_mode"] is True
    run_batch._ensure_mode_state(d, fast=False)  # fast -> normal must not reuse it
    assert not d.exists()


def test_salt_file_is_private(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run_batch, "ROOT", tmp_path)
    monkeypatch.delenv("REPO_SANITIZER_SALT", raising=False)
    monkeypatch.setattr(steps, "missing_tools", lambda path=None: [])
    monkeypatch.setattr(run_batch, "missing_tools", lambda path=None: [])
    repos = tmp_path / "repos.txt"
    repos.write_text("")
    monkeypatch.setattr(sys, "argv", ["run_batch", "--repos-file", str(repos), "--env-file", ""])
    run_batch.main()
    salt = tmp_path / ".salt"
    assert stat.S_IMODE(salt.stat().st_mode) == 0o600
    assert "WARNING" in capsys.readouterr().err


def test_main_preflight_exits_2(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run_batch, "ROOT", tmp_path)
    monkeypatch.setenv("REPO_SANITIZER_SALT", "s")
    monkeypatch.setattr(run_batch, "missing_tools", lambda path=None: ["gitleaks"])
    repos = tmp_path / "repos.txt"
    repos.write_text("")
    monkeypatch.setattr(sys, "argv", ["run_batch", "--repos-file", str(repos), "--env-file", ""])
    assert run_batch.main() == 2
    assert "gitleaks" in capsys.readouterr().err
