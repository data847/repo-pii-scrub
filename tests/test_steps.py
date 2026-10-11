"""Regression tests; need only git and zip, never gitleaks/repo-sanitizer."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest

import steps

GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, env=GIT_ENV, check=True, capture_output=True, text=True
    ).stdout.strip()


def make_repo(path: Path, files: dict[str, str] | None = None) -> Path:
    path.mkdir(parents=True)
    git(path, "init", "-q", "-b", "main")
    for name, text in (files or {"a.txt": "a"}).items():
        (path / name).parent.mkdir(parents=True, exist_ok=True)
        (path / name).write_text(text)
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "c1")
    return path


# 18: untrusted hooks / fsmonitor
def test_hooks_path_not_executed(tmp_path):
    repo = make_repo(tmp_path / "r")
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    marker = tmp_path / "hook-ran"
    hook = hooks / "post-commit"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)
    git(repo, "config", "core.hooksPath", str(hooks))

    (repo / "b.txt").write_text("b")
    git(repo, "add", "b.txt")
    git(repo, "commit", "-q", "-m", "control")
    assert marker.exists(), "control: unhardened git should run the hook"
    marker.unlink()

    (repo / "c.txt").write_text("c")
    steps.run(["git", "add", "c.txt"], cwd=repo)
    steps.run(["git", "commit", "-q", "-m", "hardened"], cwd=repo, env=GIT_ENV)
    assert not marker.exists()


def test_fsmonitor_not_executed(tmp_path):
    repo = make_repo(tmp_path / "r")
    marker = tmp_path / "fsmon-ran"
    script = tmp_path / "fsmon.sh"
    script.write_text(f"#!/bin/sh\ntouch {marker}\nprintf '\\0'\n")
    script.chmod(0o755)
    git(repo, "config", "core.fsmonitor", str(script))

    subprocess.run(["git", "status"], cwd=repo, env=GIT_ENV, capture_output=True)
    assert marker.exists(), "control: unhardened git should run fsmonitor"
    marker.unlink()

    steps.run(["git", "status"], cwd=repo)
    assert not marker.exists()


# 15: --all counts
def test_commit_counts_cover_all_branches(tmp_path):
    repo = make_repo(tmp_path / "r")
    git(repo, "checkout", "-q", "-b", "side")
    (repo / "s.txt").write_text("s")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "side")
    git(repo, "checkout", "-q", "main")
    base = steps.record_baseline(repo, tmp_path / "work")
    assert base["commits_before"] == 2


# 8: origin removed, branches local, tags lightweight
def test_materialize_clean_detaches_origin(tmp_path):
    repo = make_repo(tmp_path / "r")
    git(repo, "branch", "feature")
    git(repo, "tag", "-a", "v1", "-m", "secret message by someone")
    bundle = tmp_path / "s.bundle"
    git(repo, "bundle", "create", str(bundle), "--all")

    clean = tmp_path / "clean"
    steps.materialize_clean(bundle, clean)

    assert git(clean, "remote") == ""
    cfg = (clean / ".git" / "config").read_text()
    assert str(bundle) not in cfg
    heads = set(git(clean, "for-each-ref", "--format=%(refname)", "refs/heads").splitlines())
    assert {"refs/heads/main", "refs/heads/feature"} <= heads
    assert git(clean, "for-each-ref", "refs/remotes") == ""
    assert git(clean, "cat-file", "-t", "refs/tags/v1") == "commit"


def test_verify_refs_flags_brand_and_email(tmp_path):
    repo = make_repo(tmp_path / "r")
    git(repo, "branch", "acmepay-fix")
    with pytest.raises(RuntimeError, match="acmepay-fix"):
        steps.verify_refs(repo, ["AcmePay"])
    git(repo, "branch", "-D", "acmepay-fix")
    git(repo, "tag", "bob@corp.com")
    with pytest.raises(RuntimeError, match="bob@corp.com"):
        steps.verify_refs(repo, [])
    git(repo, "tag", "-d", "bob@corp.com")
    assert "main" in steps.verify_refs(repo, ["AcmePay"])


# 7, 9, 14: packaging
def make_work_root(tmp_path: Path, *, fast: bool) -> Path:
    work = tmp_path / "work"
    clean = make_repo(work / "clean", {"a.txt": "a", "vendor/lib.c": "int x;"})
    secret = tmp_path / "host-secret.txt"
    secret.write_text("TOPSECRET-HOST-CONTENT")
    (clean / "link").symlink_to(secret)
    git(clean, "add", "-A")
    git(clean, "commit", "-q", "-m", "link")
    (work / "commit_count_before.txt").write_text("2\n")
    (work / "run_state.json").write_text(json.dumps({"source": "x", "fast_mode": fast}))
    return work


def test_package_stores_symlinks_not_targets(tmp_path):
    work = make_work_root(tmp_path, fast=False)
    zip_path = steps.package_deliverable(work, "slug")
    with zipfile.ZipFile(zip_path) as zf:
        info = zf.getinfo("clean/link")
        assert stat.S_ISLNK(info.external_attr >> 16)
        assert b"TOPSECRET" not in zf.read("clean/link")
        # vendor/ is no longer silently dropped
        assert "clean/vendor/lib.c" in zf.namelist()


def test_manifest_labels_mode(tmp_path):
    work = make_work_root(tmp_path, fast=True)
    steps.package_deliverable(work, "slug")
    m = json.loads((work / "MANIFEST.json").read_text())
    assert m["mode"] == "fast" and m["not_for_external_delivery"] is True
    assert m["zip_excludes"] and "main" in m["refs"]
    assert m["commits_delivered"] == 2

    work2 = tmp_path / "w2"
    work2.mkdir()
    work3 = make_work_root(work2, fast=False)
    steps.package_deliverable(work3, "slug")
    m = json.loads((work3 / "MANIFEST.json").read_text())
    assert m["mode"] == "normal" and m["not_for_external_delivery"] is False


# 1: gitleaks gate cannot be disabled by the client repo
def test_gitleaks_invocation_ignores_repo_config(tmp_path, monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        report = Path(cmd[cmd.index("--report-path") + 1])
        report.write_text("[]")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(steps.subprocess, "run", fake_run)
    clean = tmp_path / "clean"
    clean.mkdir()
    steps.assert_no_secrets(clean, tmp_path / "work")
    cmd = seen["cmd"]
    assert "--ignore-gitleaks-allow" in cmd
    config = Path(cmd[cmd.index("--config") + 1])
    ignore = Path(cmd[cmd.index("--gitleaks-ignore-path") + 1])
    assert config.parent == tmp_path / "work" and "useDefault = true" in config.read_text()
    assert ignore.read_text() == "" and ignore.parent == tmp_path / "work"


# 13: preflight
def test_preflight_names_missing_tools(monkeypatch):
    monkeypatch.setattr(steps.shutil, "which", lambda t, path=None: None if t in ("gitleaks", "zip") else "/x")
    missing = steps.missing_tools()
    assert missing == ["gitleaks", "zip"]
    assert "gitleaks, zip" in steps.preflight_message(missing)
    assert "git-filter-repo" not in steps.REQUIRED_TOOLS
    monkeypatch.setenv("REPO_SANITIZER_SALT", "x")
    with pytest.raises(RuntimeError, match="gitleaks, zip"):
        steps.check_prerequisites()
