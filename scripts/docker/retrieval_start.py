"""
Start command of the retrieval service's Docker container.

1. Checks the data folder (/data, mounted read-only) with retrieval_data.py, and stops with a
   clear message if something is missing - instead of a long Python error later.
2. Turns the ATT&CK technique ranking off if its build is not in the data folder (or TRE_TECHNIQUES=0).
3. Picks CPU thread counts that fit this machine, unless they are set in .env.
4. Starts the service (uvicorn) and, once it has loaded, sends warm-up questions: the first
   questions after a start are slow (the models' first runs) and could exceed the service's
   3-second limit. Only then is the WARM_FILE written, which the container's health check
   requires - so "healthy" means "answers real questions at full speed".

Written in Python, not as a shell script, so a Windows checkout (CRLF line endings) still works.
"""
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import retrieval_data  # noqa: E402

DATA = Path(os.environ.get("RETRIEVAL_DATA", "/data"))
PORT = os.environ.get("PORT", "8000")
WARM_FILE = Path(os.environ.get("RETRIEVAL_WARM_FILE", "/tmp/retrieval-warm"))
BASE = f"http://127.0.0.1:{PORT}/api/v1"
# One question per route: exact ID, nickname, free text with ATT&CK technique ranking.
WARM_UP = ["CVE-2021-44228", "EternalBlue SMB remote code execution",
           "attackers dumped LSASS memory with mimikatz to steal credentials"]


def log(message: str) -> None:
    print(f"[retrieval-start] {message}", flush=True)


def prepare() -> None:
    want_techniques = os.environ.get("TRE_TECHNIQUES", "1") not in ("0", "false", "off")
    result = retrieval_data.check(DATA, full=False, techniques=want_techniques)
    for warning in result["warnings"]:
        log(f"WARNING: {warning}")
    if not result["ok"]:
        log(f"The retrieval data in {DATA} is not usable:")
        for problem in result["problems"]:
            log(f"  - {problem}")
        log("Put the retrieval data folder next to docker-compose.yml (or set RETRIEVAL_DATA_DIR in .env); "
            "see docs/DOCKER_SETUP.md, section 'The retrieval data'.")
        sys.exit(1)
    log("data OK: " + ", ".join(f"{k} {v}" for k, v in result["builds"].items()))

    if not result["techniques"]:
        os.environ.pop("TRE_TECH_DIR", None)          # the service then leaves the technique route off
        reason = "TRE_TECHNIQUES=0" if not want_techniques else "no techniques build in the data folder"
        log(f"ATT&CK technique ranking: off ({reason})")

    cpus = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else (os.cpu_count() or 1)
    threads = str(max(1, min(8, cpus)))               # 8 = the server's measured setting per process
    for name in ("TRE_NUM_THREADS", "TRE_TORCH_THREADS", "TRE_BLAS_THREADS"):
        if not os.environ.get(name, "").strip():
            os.environ[name] = threads
    log(f"CPU threads: {os.environ['TRE_NUM_THREADS']} (of {cpus} available)")


def _status(url: str, body: dict = None, timeout: float = 30) -> int:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"},
                                 method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, OSError):
        return 0


def warm_up(service: subprocess.Popen) -> None:
    started = time.monotonic()
    while service.poll() is None and _status(f"{BASE}/ready", timeout=5) != 200:
        time.sleep(2)
    if service.poll() is not None:
        return
    log(f"indexes and models loaded after {time.monotonic() - started:.0f} s; warming up")
    for question in WARM_UP:
        for _ in range(10):                           # a cold first run may hit the 3 s limit (503)
            if service.poll() is not None:
                return
            if _status(f"{BASE}/threats/match", {"query": question, "top_k": 3}) == 200:
                break
            time.sleep(1)
        else:
            log(f"WARNING: warm-up question {question!r} did not get an answer; continuing")
    WARM_FILE.write_text(str(int(time.time())), encoding="utf-8")
    log(f"ready for requests ({time.monotonic() - started:.0f} s after start)")


def main() -> None:
    prepare()
    WARM_FILE.unlink(missing_ok=True)
    log(f"starting the service on port {PORT}; loading the indexes and models takes 1-3 minutes")
    service = subprocess.Popen([sys.executable, "-m", "uvicorn", "threat_retrieval_engine.api.main:app",
                                "--host", "0.0.0.0", "--port", PORT, "--workers", "1"])

    def forward(signum, _frame):                      # docker stop -> the service shuts down cleanly
        if service.poll() is None:
            service.send_signal(signum)

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)
    threading.Thread(target=warm_up, args=(service,), daemon=True).start()
    code = service.wait()
    WARM_FILE.unlink(missing_ok=True)
    sys.exit(128 - code if code < 0 else code)      # ended by a signal: the usual 128 + signal number


if __name__ == "__main__":
    main()
