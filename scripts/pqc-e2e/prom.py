#!/usr/bin/env python3
"""E2E test for scripts/pqc-textfile-collector.sh.

Builds a fake /tmp deployment (healthcheck state dir + install
root + backup dir with one tarball), runs the collector, and
verifies:

  1. bash -n syntax
  2. --help clean
  3. textfile-dir not writable → RC 2 (misconfigured)
  4. textfile-dir writable + empty state + 1 tarball → RC 1
     (partial: healthcheck fails because nothing is there, but
     the partial Prometheus file is still written with backup_*)
  5. The emitted textfile matches Prometheus exposition format
     (every metric has a # HELP and # TYPE line, values are
     integers, no Python str(...) artifacts)
  6. A failing but parseable healthcheck still exports all check
     counts/statuses, while the collector returns partial-failure RC 1

This harness is the same shape as the other scripts/pqc-e2e
harnesses, so the pattern is consistent
across the deploy toolchain.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile


def log(msg):
    print(f"[e2e-prom] {msg}", flush=True)


def fail(msg):
    print(f"[FAIL] {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def main():
    script = "scripts/pqc-textfile-collector.sh"
    healthcheck = os.path.abspath("scripts/healthcheck-pqc.sh")
    if not os.path.isfile(script):
        fail(f"{script} not found")
    if not os.path.isfile(healthcheck):
        fail(f"{healthcheck} not found")

    # 0. bash -n
    log("0. bash -n")
    r = subprocess.run(["bash", "-n", script], capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"bash -n failed: {r.stderr}")

    # 1. --help clean
    log("1. --help clean")
    r = subprocess.run(["bash", script, "--help"], capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"--help returned {r.returncode}: {r.stdout} {r.stderr}")
    if "pqc-textfile-collector" not in r.stdout:
        fail("--help does not contain script name")

    # 2. textfile dir not writable → RC 2
    log("2. unwritable textfile dir → RC 2 (misconfigured)")
    bad = "/proc/this-cannot-be-created-anywhere/pqc.prom"
    r = subprocess.run(["bash", script, "--textfile-dir", bad], capture_output=True, text=True)
    if r.returncode != 2:
        fail(f"expected RC 2 for unwritable textfile dir, got {r.returncode}")
    if "[FAIL]" not in r.stderr:
        fail("expected [FAIL] in stderr for unwritable textfile dir")
    log(f"  RC=2, [FAIL] in stderr: OK")

    # 3. happy path partial: empty state, 1 tarball → RC 1
    log("3. partial deployment: empty state + 1 tarball → RC 1, partial file written")
    tmp = tempfile.mkdtemp(prefix="pqc-e2e-prom-")
    try:
        tf_dir = os.path.join(tmp, "prom")
        state = os.path.join(tmp, "state")
        install = os.path.join(tmp, "install")
        backup = os.path.join(tmp, "backups")
        os.makedirs(tf_dir, exist_ok=True)
        os.makedirs(state, exist_ok=True)
        os.makedirs(install, exist_ok=True)
        os.makedirs(backup, exist_ok=True)
        # Drop a fake tarball
        tarball = os.path.join(backup, "pqc-openclaw-2026-09-02T150000Z.tar.gz")
        with open(tarball, "wb") as f:
            f.write(b"X" * 1234)
        r = subprocess.run([
            "bash", script,
            "--textfile-dir", tf_dir,
            "--healthcheck-bin", healthcheck,
            "--healthcheck-state-dir", state,
            "--healthcheck-install-root", install,
            "--backup-dir", backup,
            "--verbose",
        ], capture_output=True, text=True)
        log(f"  RC={r.returncode}")
        if r.returncode != 1:
            fail(f"expected RC 1 (partial), got {r.returncode}")
        prom = os.path.join(tf_dir, "pqc.prom")
        if not os.path.isfile(prom):
            fail(f"pqc.prom not written at {prom}")
        # 4. Prometheus format check
        log("4. Prometheus exposition format")
        text = open(prom).read()
        # Every metric (non-comment, non-blank) must have HELP+TYPE
        metrics = [m for m in text.split("\n") if m and not m.startswith("#")]
        if not metrics:
            fail("no metrics in pqc.prom")
        metric_names = {line.split("{", 1)[0].split(" ", 1)[0] for line in metrics}
        for name in metric_names:
            if not re.search(rf"^# HELP {re.escape(name)} ", text, re.MULTILINE):
                fail(f"metric has no HELP declaration: {name}")
            if not re.search(rf"^# TYPE {re.escape(name)} ", text, re.MULTILINE):
                fail(f"metric has no TYPE declaration: {name}")
        # Required gauges
        required = [
            "pqc_healthcheck_pass_checks_total",
            "pqc_healthcheck_warn_checks_total",
            "pqc_healthcheck_fail_checks_total",
            "pqc_healthcheck_last_run_success",
            "pqc_healthcheck_last_run_timestamp_seconds",
            "pqc_backup_last_bytes",
            "pqc_backup_last_run_timestamp_seconds",
            "pqc_backup_last_run_success",
            "pqc_backup_s3_uploaded",
        ]
        for m in required:
            # Match either plain "name value" or "name{labels...} value"
            if not re.search(rf"^{re.escape(m)}(\{{[^}}]*\}})? \d", text, re.MULTILINE):
                fail(f"required metric missing or malformed: {m}")
        # Value lines: name [labels] integer
        bad_value_lines = [m for m in metrics if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*(\{[^}]*\})? -?\d+(\.\d+)?$", m)]
        if bad_value_lines:
            fail(f"malformed metric lines: {bad_value_lines}")
        log(f"  {len(metrics)} metric lines, all match Prometheus exposition format: OK")
        # Backup bytes matches
        if "pqc_backup_last_bytes 1234" not in text:
            fail("pqc_backup_last_bytes does not match the tarball size (1234)")
        log(f"  pqc_backup_last_bytes 1234 matches tarball size: OK")
        # The healthcheck is unhealthy but its schema-v1 JSON is parseable, so
        # the collector must preserve counts/per-check metrics while returning 1.
        if "pqc_healthcheck_last_run_success 1" not in text:
            fail("pqc_healthcheck_last_run_success should be 1 for parseable JSON")
        fail_match = re.search(r"^pqc_healthcheck_fail_checks_total (\d+)$", text, re.MULTILINE)
        if not fail_match or int(fail_match.group(1)) == 0:
            fail("healthcheck failure count was lost while parsing JSON")
        check_lines = re.findall(r'^pqc_healthcheck_check_status\{check="[^"]+"\} [012]$', text, re.MULTILINE)
        if len(check_lines) != 8:
            fail(f"expected 8 per-check metrics, got {len(check_lines)}")
        log("  parseable unhealthy healthcheck retained 8 check metrics: OK")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # 5. atomic write: the .tmp.$$ file should never be left behind
    log("5. atomic write: no .tmp.* files in textfile-dir after run")
    # Re-run a happy partial to check
    tmp2 = tempfile.mkdtemp(prefix="pqc-e2e-prom-cleanup-")
    try:
        tf_dir = os.path.join(tmp2, "prom")
        state = os.path.join(tmp2, "state")
        install = os.path.join(tmp2, "install")
        backup = os.path.join(tmp2, "backups")
        for d in (tf_dir, state, install, backup):
            os.makedirs(d, exist_ok=True)
        with open(os.path.join(backup, "pqc-openclaw-2026-09-02T150000Z.tar.gz"), "wb") as f:
            f.write(b"X")
        subprocess.run([
            "bash", script, "--textfile-dir", tf_dir,
            "--healthcheck-bin", healthcheck,
            "--healthcheck-state-dir", state,
            "--healthcheck-install-root", install,
            "--backup-dir", backup,
        ], capture_output=True)
        leftover = [f for f in os.listdir(tf_dir) if f.startswith("pqc.prom.tmp")]
        if leftover:
            fail(f"leftover .tmp files: {leftover}")
        log(f"  no .tmp.* leftovers in {tf_dir}: OK")
    finally:
        shutil.rmtree(tmp2, ignore_errors=True)

    log("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
