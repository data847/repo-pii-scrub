"""Shared NER service lifecycle.

One service loads the transformer model once; every sanitize/scan worker calls it
over HTTP. Without this, each parallel worker loads its own ~700 MB model, which
exhausts memory and deadlocks.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PORT = 8765
DEFAULT_DEVICE = "cpu"


def health(port: int, *, timeout: float = 3.0) -> str | None:
    """Return the service status ("ready" / "loading"), or None if unreachable."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")).get("status")
    except (OSError, urllib.error.HTTPError, ValueError):
        return None


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(1.0)
        return sock.connect_ex((host, port)) == 0


class NerService:
    """Start (or reuse) a shared NER service and expose its URL."""

    def __init__(
        self,
        *,
        port: int = DEFAULT_PORT,
        device: str = DEFAULT_DEVICE,
        rulepack: Path | None = None,
        idle_timeout: int = 0,
        log_path: Path | None = None,
    ) -> None:
        self.port = port
        self.device = device
        self.rulepack = rulepack or (ROOT / "rules")
        self.idle_timeout = idle_timeout
        self.log_path = log_path or (ROOT / "outputs" / "_watchdog" / "ner_service.log")
        self.url = f"http://127.0.0.1:{port}"
        self.proc: subprocess.Popen | None = None
        self.reused = False

    def start(self, *, wait_seconds: int = 600) -> str:
        if port_open(self.port):
            self.reused = True
            self._wait_ready(wait_seconds)
            return self.url

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        binary = ROOT / ".venv" / "bin" / "repo-sanitizer"
        cmd = [
            str(binary),
            "ner-service",
            "--port",
            str(self.port),
            "--device",
            self.device,
            "--rulepack",
            str(self.rulepack),
            "--idle-timeout",
            str(self.idle_timeout),
        ]
        env = os.environ.copy()
        env["PATH"] = f"{ROOT / '.venv' / 'bin'}:{ROOT / '.tools' / 'bin'}:{env.get('PATH', '')}"
        # Model load is single-threaded here; workers get their parallelism from the batch.
        env.setdefault("TOKENIZERS_PARALLELISM", "false")

        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(f"\n=== ner-service start {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ===\n")
            fh.flush()
            self.proc = subprocess.Popen(
                cmd,
                stdout=fh,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                env=env,
                cwd=str(ROOT),
                start_new_session=True,
            )

        try:
            self._wait_ready(wait_seconds)
        except Exception:
            self.stop()
            raise
        return self.url

    def _wait_ready(self, wait_seconds: int) -> None:
        deadline = time.time() + wait_seconds
        while time.time() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                raise RuntimeError(
                    f"ner-service exited early (code {self.proc.returncode}); see {self.log_path}"
                )
            if health(self.port) == "ready":
                return
            time.sleep(2)
        raise RuntimeError(
            f"ner-service did not become ready within {wait_seconds}s; see {self.log_path}"
        )

    def stop(self) -> None:
        if self.reused or self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def __enter__(self) -> str:
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()


def main() -> int:
    import argparse

    p = argparse.ArgumentParser(description="Start a shared NER service in the foreground")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--device", default=DEFAULT_DEVICE)
    p.add_argument("--idle-timeout", type=int, default=0)
    args = p.parse_args()

    svc = NerService(port=args.port, device=args.device, idle_timeout=args.idle_timeout)
    url = svc.start()
    print(f"NER service ready at {url} (log: {svc.log_path})", flush=True)
    try:
        while svc.proc and svc.proc.poll() is None:
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        svc.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
