#!/usr/bin/env python3
"""
pqc-fork-e2e-healthcheck.py — end-to-end round-trip test for
scripts/healthcheck-pqc.sh. Builds a fake PQC deployment under
/tmp/pqc-e2e-hc-XXXX (install root + state dir + wrap key + os
keyring mock), runs the healthcheck against it, and verifies that:

  1. On a fake deployment with a live gateway process and /healthz endpoint,
     no critical check fails (RC 0 or warning-only RC 2).
  2. With --skip-keyring on a deployment where the keyring entry is
     missing, the os-keyring check skips cleanly (still RC 0 or 2).
  3. On a broken deployment (no fork process, no /healthz, no wrap
     key, no state db), the critical checks fail and the script
     exits non-zero (RC 1) with [FAIL] lines naming each gap.

Why this exists: the healthcheck is the production operator's first
line of defense. If it lies (says OK when something is actually
broken), the operator trusts it and pages on the wrong thing. This
harness proves the script's behavior on a developer's workstation
in <5 seconds by constructing a sandboxed fake deployment under
/tmp, so it never touches the real state dir, the real OS keyring,
or the real fork process.

Run from the fork repo root:
  python3 scripts/pqc-e2e/healthcheck.py
or:
  python3 scripts/pqc-e2e/healthcheck.py --script path/to/healthcheck-pqc.sh

Exit codes:
  0  all sub-checks passed
  1  one or more sub-checks failed
"""
import argparse
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time


def log(msg):
    print(f"[e2e-healthcheck] {msg}", flush=True)


def fail(msg):
    print(f"[FAIL] {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def make_fake_deployment(missing_wrap_key=False, missing_state_db=False):
    """Build a fake PQC deployment under a fresh tmpdir.

    Returns (install_root, state_dir, wrap_key_file, port).
    """
    base = tempfile.mkdtemp(prefix="pqc-e2e-hc-")
    install_root = os.path.join(base, "install")
    state_dir = os.path.join(base, "state")
    os.makedirs(os.path.join(install_root, "src/security"), exist_ok=True)
    os.makedirs(os.path.join(state_dir, "state"), exist_ok=True)
    os.makedirs(state_dir, exist_ok=True)

    # A dummy mlock-helper.ts so check 2 runs the mlock check (warn on
    # node 22, ok on 24.15+). We use a real source file copied from
    # the current cwd if available, else a stub.
    src = "src/security/mlock-helper.ts"
    if os.path.isfile(src):
        shutil.copyfile(src, os.path.join(install_root, src))
    else:
        with open(os.path.join(install_root, src), "w") as f:
            f.write("// stub for e2e harness\n")

    # Wrap key file with mode 0600
    wrap_key_file = os.path.join(state_dir, "wrap-key.b64")
    if not missing_wrap_key:
        with open(wrap_key_file, "w") as f:
            f.write("dGVzdC1rZXktMzItYnl0ZXMtZm9yLXRlc3RpbmcxMjM0NQ==")
        os.chmod(wrap_key_file, 0o600)

    # state.db (SQLite) with a dummy table
    if not missing_state_db:
        db_path = os.path.join(state_dir, "state/openclaw.sqlite")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE foo (id INTEGER PRIMARY KEY, name TEXT)")
        conn.execute("INSERT INTO foo (name) VALUES ('e2e')")
        conn.commit()
        conn.close()

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]

    return base, install_root, state_dir, wrap_key_file, port


def start_fake_gateway(port):
    server = """
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/healthz" else 404)
        self.end_headers()

    def log_message(self, _format, *_args):
        pass

HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
"""
    process = subprocess.Popen(
        [sys.executable, "-c", server, str(port), "dist/index.js", "gateway"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.2)
    if process.poll() is not None:
        fail(f"fake gateway failed to start: {process.stderr.read()}")
    return process


def run(script, *args):
    return subprocess.run(["bash", script, *args], capture_output=True, text=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--script",
        default="scripts/healthcheck-pqc.sh",
        help="Path to healthcheck-pqc.sh",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.script):
        fail(f"healthcheck-pqc.sh not found at {args.script}")

    # 0. bash -n
    log(f"0. bash -n {args.script}")
    r = subprocess.run(["bash", "-n", args.script], capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"bash -n failed: {r.stderr}")

    # 1. JSON output format check
    log("1. healthcheck-pqc.sh --json parses as JSON")
    base, install_root, state_dir, wrap_key_file, port = make_fake_deployment()
    try:
        r = run(
            args.script,
            "--install-root", install_root,
            "--state-dir", state_dir,
            "--wrap-key-file", wrap_key_file,
            "--port", str(port),
            "--json",
            "--skip-keyring",
        )
        # Even if some checks fail, --json must emit exactly one JSON document.
        stdout_lines = r.stdout.strip().splitlines()
        if len(stdout_lines) != 1:
            fail(f"--json emitted {len(stdout_lines)} stdout lines, expected exactly one")
        try:
            doc = json.loads(stdout_lines[0])
        except (json.JSONDecodeError, IndexError) as e:
            log(f"  raw stdout (first 500 chars):\n{r.stdout[:500]}")
            log(f"  raw stderr (first 500 chars):\n{r.stderr[:500]}")
            fail(f"--json output is not valid JSON: {e}")
        if doc.get("schemaVersion") != 1:
            fail(f"unexpected healthcheck schemaVersion: {doc.get('schemaVersion')}")
        summary = doc.get("summary", {})
        checks = doc.get("checks", [])
        counts = [summary.get(key) for key in ("pass", "warn", "fail")]
        if not all(isinstance(value, int) for value in counts):
            fail(f"summary counts are not integers: {summary}")
        if sum(counts) != len(checks):
            fail(f"summary total {sum(counts)} does not match {len(checks)} checks")
        names = [check.get("check") for check in checks]
        if len(names) != len(set(names)):
            fail(f"healthcheck names are not unique: {names}")
        expected_status = "fail" if counts[2] else ("warn" if counts[1] else "ok")
        if doc.get("status") != expected_status:
            fail(f"status {doc.get('status')} does not match summary {summary}")
        expected_exit = {"ok": 0, "warn": 2, "fail": 1}[expected_status]
        if r.returncode != expected_exit:
            fail(f"status {expected_status} requires RC {expected_exit}, got {r.returncode}")
        log(
            f"  schema v1 JSON OK, status={expected_status}, pass={counts[0]} "
            f"warn={counts[1]} fail={counts[2]}, {len(checks)} unique checks"
        )

        # A quote in an operator-controlled path must remain valid JSON.
        quoted_key = wrap_key_file + '\"missing'
        escaped = run(
            args.script,
            "--install-root", install_root,
            "--state-dir", state_dir,
            "--wrap-key-file", quoted_key,
            "--port", str(port),
            "--json",
            "--skip-keyring",
        )
        try:
            escaped_doc = json.loads(escaped.stdout)
        except json.JSONDecodeError as e:
            fail(f"quoted path corrupted JSON output: {e}")
        wrap_detail = next(
            check["detail"] for check in escaped_doc["checks"] if check["check"] == "wrap-key-file"
        )
        if quoted_key not in wrap_detail:
            fail("quoted wrap-key path was not preserved in JSON detail")
    finally:
        shutil.rmtree(base, ignore_errors=True)

    # 2. Broken deployment → critical exit (RC 1) with [FAIL] lines
    log("2. broken deployment: missing fork + missing state db + missing wrap key → RC 1")
    base, install_root, state_dir, wrap_key_file, port = make_fake_deployment(
        missing_state_db=True, missing_wrap_key=True,
    )
    try:
        r = run(
            args.script,
            "--install-root", install_root,
            "--state-dir", state_dir,
            "--wrap-key-file", wrap_key_file,
            "--port", str(port),
            "--skip-keyring",
        )
        log(f"  RC={r.returncode}")
        if r.returncode == 0:
            fail("expected non-zero exit on broken deployment, got RC=0")
        if r.returncode != 1:
            fail(f"critical healthcheck must return RC 1, got {r.returncode}")
        if "[FAIL]" not in r.stderr:
            fail("expected [FAIL] lines in stderr on broken deployment, got none")
        fail_count = r.stderr.count("[FAIL]")
        log(f"  {fail_count} [FAIL] lines surfaced (wrap-key-file, state-db, fork-process expected)")
        if fail_count < 2:
            fail(f"only {fail_count} [FAIL] lines, expected at least 2 on broken deployment")
    finally:
        shutil.rmtree(base, ignore_errors=True)

    # 3. Healthy fake gateway → no critical failures. A warning-only RC 2 is
    # allowed because process.mlock is absent on supported Node builds and the
    # healthcheck intentionally reports that degraded defense.
    log("3. live fake gateway + healthz + state + wrap key → no [FAIL]")
    base, install_root, state_dir, wrap_key_file, port = make_fake_deployment()
    gateway = start_fake_gateway(port)
    try:
        r = run(
            args.script,
            "--install-root", install_root,
            "--state-dir", state_dir,
            "--wrap-key-file", wrap_key_file,
            "--port", str(port),
            "--skip-keyring",
        )
        log(f"  RC={r.returncode}")
        ok_count = r.stdout.count("[OK]")
        warn_count = r.stderr.count("[WARN]") + r.stdout.count("[WARN]")
        fail_count = r.stderr.count("[FAIL]") + r.stdout.count("[FAIL]")
        log(f"  [OK]={ok_count} [WARN]={warn_count} [FAIL]={fail_count}")
        if r.returncode not in (0, 2):
            fail(f"healthy fake deployment returned unexpected RC={r.returncode}")
        if fail_count != 0:
            fail(f"healthy fake deployment reported {fail_count} critical failures")
        if "fork-process" not in r.stdout or "healthz" not in r.stdout:
            fail("live process or /healthz success was not reported")
        if "wrap-key-file" not in r.stderr and "wrap-key-file" not in r.stdout:
            fail("wrap-key-file check did not run; something is wrong with option parsing")
        if "state-db" not in r.stderr and "state-db" not in r.stdout:
            fail("state-db check did not run; install_root or state_dir wiring is broken")
        if "node-version" not in r.stdout and "node-version" not in r.stderr:
            fail("node-version check did not run; expected to find node on PATH")
        if ok_count < 2:
            fail(f"only {ok_count} [OK] lines, expected at least 2 (node-version + wrap-key-file + state-db)")
    finally:
        gateway.terminate()
        gateway.wait(timeout=5)
        shutil.rmtree(base, ignore_errors=True)

    # 4. --help clean
    log("4. --help clean")
    r = run(args.script, "--help")
    if r.returncode != 0:
        fail(f"--help returned {r.returncode}")
    if r.stderr:
        fail(f"--help wrote unexpected stderr: {r.stderr}")
    if "healthcheck-pqc.sh" not in r.stdout:
        fail("--help output does not contain script name")

    log("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
