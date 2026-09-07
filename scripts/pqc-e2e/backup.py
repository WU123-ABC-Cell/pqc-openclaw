#!/usr/bin/env python3
"""
pqc-fork-e2e-backup.py — end-to-end round-trip test for scripts/backup-pqc.sh.

Proves the full backup pipeline on a fake /tmp state directory:
  1. backup-pqc.sh (real run)   → tarball + sha256 sidecar
  2. tar -tzf                   → archive reads cleanly
  3. sqlite3 .schema            → embedded state.db is a valid sqlite db
  4. backup-pqc.sh --verify     → standalone verify mode re-checks
                                   sha256 + tar + sqlite in one command
  5. concurrent lock            → a held .backup.lock/pid makes a
                                   second run fail with a [FAIL] lock
                                   line that names the holder's PID
  6. retention                  → 15 fake-old tarballs + 1 new = 16,
                                   run real backup, expect 5-6 to be
                                   pruned (keep 11 = 7 daily + 4 weekly)

Run from the fork repo root:
  python3 scripts/pqc-e2e/backup.py
or:
  python3 scripts/pqc-e2e/backup.py --script path/to/backup-pqc.sh

Exit codes:
  0  all checks passed
  1  one or more critical failures
  2  non-critical warnings (e.g. --skip-healthcheck was used)

Why this exists: the script is meant to be invoked from a daily cron
on the production host, where a silent failure (broken tar, corrupt
db, retention too aggressive, concurrent run clobbering the lock)
would surface only when an operator tries to restore. This harness
catches those failures on a developer's workstation in <5 seconds.
"""
import argparse
import datetime
import glob
import hashlib
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile


def log(msg):
    print(f"[e2e-backup] {msg}", flush=True)


def fail(msg):
    print(f"[FAIL] {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def make_state_dir():
    state = tempfile.mkdtemp(prefix="pqc-e2e-state-")
    os.makedirs(os.path.join(state, "mlock"), exist_ok=True)
    os.makedirs(os.path.join(state, "auth-profile-secrets"), exist_ok=True)
    db_path = os.path.join(state, "state.db")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE foo (id INTEGER PRIMARY KEY, name TEXT, ts INTEGER)")
    conn.execute("INSERT INTO foo (name, ts) VALUES ('hello', 1000), ('world', 2000), ('pqc', 3000)")
    conn.commit()
    conn.close()
    with open(os.path.join(state, "wrap-key.b64"), "w") as f:
        f.write("dGVzdC1rZXktMzItYnl0ZXMtZm9yLXRlc3RpbmcxMjM0NQ==")
    with open(os.path.join(state, "pqc-audit.log"), "w") as f:
        f.write('{"event":"mlock","bytes":32,"timestamp":"2026-09-02T15:00:00Z"}\n')
    return state


def run(script, *args):
    r = subprocess.run(["bash", script, *args], capture_output=True, text=True)
    return r


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--script",
        default="scripts/backup-pqc.sh",
        help="Path to backup-pqc.sh (default: scripts/backup-pqc.sh, resolved from CWD)",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.script):
        fail(f"backup-pqc.sh not found at {args.script}; pass --script /path/to/backup-pqc.sh")

    # 0. bash -n syntax check (catches typos before the test runs)
    log(f"0. bash -n {args.script}")
    r = subprocess.run(["bash", "-n", args.script], capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"bash -n failed: {r.stderr}")

    state = make_state_dir()
    backup = tempfile.mkdtemp(prefix="pqc-e2e-backup-")
    log(f"  state:  {state}")
    log(f"  backup: {backup}")

    try:
        # 1. real backup
        log("1. backup-pqc.sh (real run, --skip-s3 --skip-healthcheck --label e2e-test)")
        r = run(
            args.script,
            "--state-dir", state,
            "--backup-dir", backup,
            "--skip-s3", "--skip-healthcheck",
            "--label", "e2e-test",
        )
        log(f"  RC={r.returncode}")
        for line in r.stdout.splitlines():
            log(f"    stdout | {line}")
        for line in r.stderr.splitlines():
            if line.strip():
                log(f"    stderr | {line}")
        if r.returncode not in (0, 2):
            fail(f"backup returned {r.returncode}, expected 0 or 2 (warn)")

        # 2. tarball exists
        tarballs = sorted(glob.glob(os.path.join(backup, "*.tar.gz")))
        if not tarballs:
            fail("no tarball in backup dir after run")
        latest = tarballs[-1]
        log(f"2. tarball on disk: {os.path.basename(latest)} ({os.path.getsize(latest)} bytes)")

        # Filename sanity: must NOT end in "-.tar.gz" (the LABEL
        # sanitization bug we caught during 4d21407bde self-review).
        if os.path.basename(latest).endswith("-.tar.gz"):
            fail(f"filename ends in '-.tar.gz' (LABEL newline bug regressed): {latest}")

        # 3. sha256 sidecar matches
        side = latest + ".sha256"
        if not os.path.isfile(side):
            fail(f"missing sha256 sidecar: {side}")
        expected = open(side).read().split()[0]
        actual = hashlib.sha256(open(latest, "rb").read()).hexdigest()
        log(f"3. sha256 sidecar: expected={expected[:16]}... actual={actual[:16]}...")
        if expected != actual:
            fail(f"sha256 mismatch: expected {expected}, got {actual}")

        # 4. tar -tzf reads cleanly
        with tarfile.open(latest) as tf:
            members = tf.getnames()
        log(f"4. tar -tzf: {len(members)} entries, no exception")
        if not any(m.endswith("state.db") for m in members):
            fail("no state.db inside the tarball")
        if any("/mlock/" in m for m in members):
            fail("mlock/ tmpfs was included in the tarball (should be excluded)")

        # 5. sqlite3 .schema on extracted state.db
        with tempfile.TemporaryDirectory() as v:
            with tarfile.open(latest) as tf:
                tf.extractall(v)
            db = None
            for root, _, files in os.walk(v):
                if "state.db" in files:
                    db = os.path.join(root, "state.db")
                    break
            if not db:
                fail("no state.db in extracted tarball")
            r = subprocess.run(["sqlite3", db, ".schema"], capture_output=True, text=True)
            if r.returncode != 0:
                fail(f"sqlite3 .schema failed: {r.stderr}")
            log("5. sqlite3 .schema: OK")

        # 6. --verify standalone mode
        log(f"6. backup-pqc.sh --verify {latest}")
        r = run(args.script, "--verify", latest)
        if r.returncode != 0:
            fail(f"--verify returned {r.returncode}: {r.stdout} {r.stderr}")
        log(f"  --verify RC=0, last line: {r.stdout.strip().splitlines()[-1]}")

        # 7. concurrent lock: hold lock manually, expect [FAIL] lock
        #    that names the holder PID.
        log("7. concurrent lock test (stale pid 999999 holds .backup.lock/pid)")
        lock_dir = os.path.join(backup, ".backup.lock")
        os.makedirs(lock_dir, exist_ok=True)
        with open(os.path.join(lock_dir, "pid"), "w") as f:
            f.write("999999")
        try:
            r = run(
                args.script,
                "--state-dir", state,
                "--backup-dir", backup,
                "--skip-s3", "--skip-healthcheck",
                "--label", "should-fail-due-to-lock",
            )
            if r.returncode == 0:
                fail("backup succeeded despite held lock!")
            if "999999" not in r.stderr:
                fail(f"holder PID 999999 not surfaced in failure: {r.stderr}")
            log("  RC=1, holder PID 999999 surfaced in [FAIL] lock line: OK")
        finally:
            shutil.rmtree(lock_dir, ignore_errors=True)

        # 8. retention: 15 fake old + 1 new = 16, expect 5-6 pruned
        #    (keep 11 = 7 daily + 4 weekly; but the count math is
        #    sensitive to the ordering of mtimes, so we accept 5-6).
        log("8. retention test: 15 fake-old tarballs + 1 new = 16 → expect 5-6 pruned")
        for i in range(15):
            age = i + 1
            ts = (datetime.datetime(2026, 9, 2, 3, 0, 0) - datetime.timedelta(days=age)).strftime("%Y-%m-%dT%H%M%SZ")
            fake_name = f"pqc-openclaw-{ts}.fake-{i:02d}.tar.gz"
            fake_path = os.path.join(backup, fake_name)
            with open(fake_path, "wb") as f:
                f.write(b"FAKE-OLD-BACKUP")
            mtime = (datetime.datetime(2026, 9, 2, 3, 0, 0) - datetime.timedelta(days=age)).timestamp()
            os.utime(fake_path, (mtime, mtime))
            with open(fake_path + ".sha256", "w") as f:
                f.write(f"0000deadbeef{i:04x}  {fake_name}\n")
        before = len([f for f in os.listdir(backup) if f.endswith(".tar.gz")])
        r = run(
            args.script,
            "--state-dir", state,
            "--backup-dir", backup,
            "--skip-s3", "--skip-healthcheck",
            "--label", "retention-test",
        )
        after = len([f for f in os.listdir(backup) if f.endswith(".tar.gz")])
        pruned = before - after
        log(f"  before={before} after={after} pruned={pruned}")
        if not (4 <= pruned <= 8):
            fail(f"retention pruned {pruned}, expected 4-8 (keep 11 of 16, math sensitive to mtime ordering)")
        if after != 11:
            fail(f"retention kept {after}, expected 11 (=7 daily + 4 weekly)")

        log("ALL CHECKS PASSED")
    finally:
        shutil.rmtree(state, ignore_errors=True)
        shutil.rmtree(backup, ignore_errors=True)


if __name__ == "__main__":
    main()
