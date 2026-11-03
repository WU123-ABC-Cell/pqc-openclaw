#!/usr/bin/env python3
"""
pqc-fork-e2e-backup.py — end-to-end round-trip test for scripts/backup-pqc.sh.

Proves the full backup pipeline on a fake /tmp state directory:
  1. backup-pqc.sh (real run)   → tarball + sha256 sidecar
  2. tar -tzf                   → archive reads cleanly
  3. SQLite integrity + restore → current state/openclaw.sqlite survives intact
  4. backup-pqc.sh --verify     → standalone verify mode re-checks
                                   sha256 + tar + sqlite in one command
  5. layout compatibility       → current and legacy SQLite paths verify
  6. corrupt-db rejection       → invalid current DB never gets published
  7. concurrent lock            → a held .backup.lock/pid makes a
                                   second run fail with a [FAIL] lock
                                   line that names the holder's PID
  8. retention                  → old archives are pruned only after success
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
import json
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
    os.makedirs(os.path.join(state, "state"), exist_ok=True)
    db_path = os.path.join(state, "state", "openclaw.sqlite")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE foo (id INTEGER PRIMARY KEY, name TEXT, ts INTEGER)")
    conn.execute("INSERT INTO foo (name, ts) VALUES ('hello', 1000), ('world', 2000), ('pqc', 3000)")
    conn.commit()
    conn.close()
    with open(os.path.join(state, "wrap-key.b64"), "w") as f:
        f.write("dGVzdC1rZXktMzItYnl0ZXMtZm9yLXRlc3RpbmcxMjM0NQ==")
    os.makedirs(os.path.join(state, "keys"), exist_ok=True)
    with open(os.path.join(state, "keys", "current.key"), "w") as f:
        f.write("Y3VzdG9tLWtleS1tdXN0LXN0YXktb3V0LW9mLWJhY2t1cHM=")
    os.link(os.path.join(state, "wrap-key.b64"), os.path.join(state, "innocent-default.txt"))
    os.link(os.path.join(state, "keys", "current.key"), os.path.join(state, "innocent-custom.txt"))
    with open(os.path.join(state, "ordinary.b64"), "w") as f:
        f.write("ordinary-data")
    os.link(os.path.join(state, "ordinary.b64"), os.path.join(state, "ordinary-hardlink"))
    with open(os.path.join(state, "openclaw.env"), "w") as f:
        f.write("OPENCLAW_GATEWAY_TOKEN=must-not-enter-backup\n")
    with open(os.path.join(state, "pqc-audit.log"), "w") as f:
        f.write('{"event":"mlock","bytes":32,"timestamp":"2026-09-02T15:00:00Z"}\n')
    return state


def run(script, *args, env=None):
    isolated_env = os.environ.copy()
    isolated_env.pop("OPENCLAW_WRAP_KEY_FILE", None)
    if env:
        isolated_env.update(env)
    r = subprocess.run(["bash", script, *args], capture_output=True, text=True, env=isolated_env)
    return r


def python_shim(directory, injection):
    # Inject at the real descriptor/tarfile boundary without a production hook.
    path = os.path.join(directory, "python3")
    with open(path, "w") as f:
        f.write(f"#!{sys.executable}\nimport os, sys, tarfile\n")
        f.write("sys.argv.pop(1)\nrestore = lambda: None\n")
        f.write(injection)
        f.write("\ntry:\n    exec(compile(sys.stdin.read(), '<backup-snapshot>', 'exec'))\nfinally:\n    restore()\n")
    os.chmod(path, 0o700)


def check_key_boundaries(script):
    for mode in ("final-symlink", "parent-symlink", "state-symlink", "external-hardlink", "env-and-cli", "special-names", "selector-aba", "nested-backup", "json"):
        with tempfile.TemporaryDirectory(prefix="pqc-key-boundary-") as root:
            state = make_state_dir()
            try:
                backup = os.path.join(root, "backups")
                selected = os.path.join(state, "keys", "current.key")
                env = {}
                state_input = state
                excluded = ["wrap-key.b64", "innocent-default.txt", "keys/current.key", "innocent-custom.txt"]
                if mode == "nested-backup":
                    backup = os.path.join(state, "backups")
                elif mode == "final-symlink":
                    link = os.path.join(root, "selected-link")
                    os.symlink(selected, link)
                    selected = link
                elif mode == "parent-symlink":
                    os.symlink(os.path.join(state, "keys"), os.path.join(root, "key-directory"))
                    selected = os.path.join(root, "key-directory", "current.key")
                elif mode == "state-symlink":
                    state_input = os.path.join(root, "state-link")
                    os.symlink(state, state_input)
                elif mode == "external-hardlink":
                    external = os.path.join(root, "external-key")
                    os.rename(selected, external)
                    selected = external
                elif mode == "env-and-cli":
                    daemon_key = os.path.join(state, "daemon.key")
                    with open(daemon_key, "w") as f:
                        f.write("daemon-key")
                    os.link(daemon_key, os.path.join(state, "daemon-alias"))
                    env["OPENCLAW_WRAP_KEY_FILE"] = daemon_key
                    excluded += ["daemon.key", "daemon-alias"]
                elif mode == "special-names":
                    special = os.path.join(state, "keys", "-key[abc]*\ntrailing\n")
                    os.rename(selected, special)
                    selected = special
                    excluded += ["keys/-key[abc]*\ntrailing\n"]
                elif mode == "selector-aba":
                    selector = os.path.join(root, "selector")
                    os.symlink(selected, selector)
                    other = os.path.join(root, "other-key")
                    with open(other, "w") as f:
                        f.write("other-key")
                    shim = os.path.join(root, "bin")
                    os.mkdir(shim)
                    python_shim(shim, '''
real_listdir = os.listdir
def listdir(fd):
    os.unlink(os.environ["KEY_SELECTOR"])
    os.symlink(os.environ["OTHER_KEY"], os.environ["KEY_SELECTOR"])
    return real_listdir(fd)
os.listdir = listdir
def restore():
    os.unlink(os.environ["KEY_SELECTOR"])
    os.symlink(os.environ["INITIAL_KEY"], os.environ["KEY_SELECTOR"])
''')
                    env = {"PATH": shim + os.pathsep + os.environ["PATH"],
                           "OTHER_KEY": other, "INITIAL_KEY": selected, "KEY_SELECTOR": selector}
                    selected = selector
                controls = ["ordinary.b64", "ordinary-hardlink", "--checkpoint-action=exec=not-a-command", "space name", "newline\nfile", "literal[abc]*"]
                for name in controls[2:]:
                    with open(os.path.join(state, name), "w") as f:
                        f.write("ordinary-data")
                os.symlink("./ordinary.b64", os.path.join(state, "ordinary-symlink"))
                os.symlink("./missing", os.path.join(state, "dangling-symlink"))
                os.symlink("./cyclic-symlink", os.path.join(state, "cyclic-symlink"))
                options = ["--state-dir", state_input, "--backup-dir", backup,
                           "--wrap-key-file", selected, "--skip-healthcheck", "--skip-s3"]
                if mode == "json":
                    options += ["--json"]
                r = run(script, *options, env=env)
                if r.returncode not in (0, 2):
                    fail(f"key boundary {mode}: {r.returncode}: {r.stdout} {r.stderr}")
                archives = glob.glob(os.path.join(backup, "*.tar.gz"))
                if len(archives) != 1:
                    fail(f"key boundary {mode}: expected one published archive")
                with tarfile.open(archives[0]) as tf:
                    members = tf.getnames()
                    if any("/.pqc-backup-" in member for member in members):
                        fail("private staging was included in the backup")
                    if any("pqc-openclaw-state/" + name in members for name in excluded):
                        fail(f"key boundary {mode}: secret path or alias was included")
                    if not all("pqc-openclaw-state/" + name in members for name in controls):
                        fail(f"key boundary {mode}: legitimate special-name files were lost")
                    link = tf.getmember("pqc-openclaw-state/ordinary-symlink")
                    if not link.issym() or link.linkname != "./ordinary.b64":
                        fail(f"key boundary {mode}: ordinary symlink target was rewritten")
                    for name, target in (("dangling-symlink", "./missing"), ("cyclic-symlink", "./cyclic-symlink")):
                        link = tf.getmember("pqc-openclaw-state/" + name)
                        if not link.issym() or link.linkname != target:
                            fail(f"key boundary {mode}: unresolved symlink was lost or rewritten")
                    secrets = [b"dGVzdC1rZXktMzItYnl0ZXMtZm9yLXRlc3RpbmcxMjM0NQ==",
                               b"Y3VzdG9tLWtleS1tdXN0LXN0YXktb3V0LW9mLWJhY2t1cHM="]
                    if any(any(secret in tf.extractfile(member).read() for secret in secrets)
                           for member in tf.getmembers() if member.isfile()):
                        fail(f"key boundary {mode}: raw key content survived")
                if mode == "json" and json.loads(r.stdout.splitlines()[-1])["event"] != "backup-complete":
                    fail("JSON mode did not report a complete backup")
                log(f"  key boundary {mode}: OK")
            finally:
                shutil.rmtree(state, ignore_errors=True)

    with tempfile.TemporaryDirectory(prefix="pqc-key-faults-") as root:
        state = make_state_dir()
        try:
            backup = os.path.join(root, "backups")
            dry_backup = os.path.join(root, "dry-backup")
            r = run(script, "--state-dir", os.path.join(root, "missing"), "--backup-dir", dry_backup, "--dry-run")
            if r.returncode != 0 or os.path.exists(dry_backup):
                fail("dry-run changed the filesystem or failed for missing state")
            for selected in ("relative-key", os.path.join(state, "keys"), os.path.join(root, "absent-parent", "key")):
                r = run(script, "--state-dir", state, "--backup-dir", backup,
                        "--wrap-key-file", selected, "--skip-healthcheck", "--skip-s3")
                if r.returncode != 1 or glob.glob(os.path.join(backup, "*.tar.gz")) or os.path.exists(os.path.join(backup, ".backup.lock")):
                    fail("invalid/uncertain key metadata did not fail cleanly before publication")
            log("  invalid metadata and dry-run: OK")

            no_python = os.path.join(root, "no-python")
            os.mkdir(no_python)
            os.symlink(shutil.which("bash"), os.path.join(no_python, "bash"))
            r = run(script, "--state-dir", state, "--backup-dir", backup,
                    "--skip-healthcheck", "--skip-s3", env={"PATH": no_python})
            if r.returncode != 1 or "python3 is required" not in r.stderr or os.path.exists(os.path.join(backup, ".backup.lock")):
                fail("missing python3 did not fail with actionable diagnostics before locking")

            dangling = os.path.join(root, "dangling-key")
            os.symlink(os.path.join(root, "absent-key"), dangling)
            r = run(script, "--state-dir", state, "--backup-dir", backup,
                    "--wrap-key-file", dangling, "--skip-healthcheck", "--skip-s3")
            if r.returncode != 1 or glob.glob(os.path.join(backup, "*.tar.gz")):
                fail("dangling key did not fail closed")

            # Fault injection occurs at the real tar boundary, not the filter.
            shim = os.path.join(root, "bin")
            os.mkdir(shim)
            scratch = os.path.join(root, "scratch")
            os.mkdir(scratch)
            real_tar = shutil.which("tar")
            # Both GNU/BSD stat branches must fail; no plaintext fallback.
            with open(os.path.join(shim, "stat"), "w") as f:
                f.write('#!/usr/bin/env bash\nexit 1\n')
            os.chmod(os.path.join(shim, "stat"), 0o700)
            r = run(script, "--state-dir", state, "--backup-dir", backup,
                    "--skip-healthcheck", "--skip-s3",
                    env={"PATH": shim + os.pathsep + os.environ["PATH"], "TMPDIR": scratch})
            if r.returncode != 1 or "cannot inspect wrapping key or archive source metadata" not in r.stderr or os.listdir(scratch):
                fail("metadata failure was silently accepted or left scratch state")
            os.unlink(os.path.join(shim, "stat"))
            key = os.path.join(state, "wrap-key.b64")
            with open(os.path.join(shim, "tar"), "w") as f:
                f.write('#!/usr/bin/env bash\n"$REAL_TAR" "$@" || exit $?\nif [[ "$1" == "-xzf" ]]; then printf changed-key-size > "$TEST_KEY"; fi\n')
            os.chmod(os.path.join(shim, "tar"), 0o700)
            marker = os.path.join(root, "uploaded")
            with open(os.path.join(shim, "aws"), "w") as f:
                f.write('#!/usr/bin/env bash\ntouch "$UPLOAD_MARKER"\n')
            os.chmod(os.path.join(shim, "aws"), 0o700)
            sentinel = os.path.join(backup, "pqc-openclaw-old.tar.gz")
            with open(sentinel, "w") as f:
                f.write("previous-backup")
            r = run(script, "--state-dir", state, "--backup-dir", backup,
                    "--skip-healthcheck", "--s3-bucket", "test-only",
                    "--retention-daily", "0", "--retention-weekly", "0",
                    env={"PATH": shim + os.pathsep + os.environ["PATH"], "REAL_TAR": real_tar,
                         "TEST_KEY": key, "TMPDIR": scratch, "UPLOAD_MARKER": marker})
            if r.returncode != 1 or "changed during backup" not in r.stderr:
                fail(f"changed key was not rejected: {r.stdout} {r.stderr}")
            if glob.glob(os.path.join(backup, "*.tar.gz")) != [sentinel] or os.listdir(scratch) or os.path.exists(marker):
                fail("failed key check published, pruned, uploaded or left scratch state")
            log("  changed key: no publication, pruning, upload or scratch leak: OK")

            # Missing default key is legitimate when a non-file provider owns it.
            os.unlink(key)
            os.unlink(os.path.join(state, "innocent-default.txt"))
            missing_backup = os.path.join(root, "missing-key-backup")
            r = run(script, "--state-dir", state, "--backup-dir", missing_backup,
                    "--skip-healthcheck", "--skip-s3")
            if r.returncode not in (0, 2) or len(glob.glob(os.path.join(missing_backup, "*.tar.gz"))) != 1:
                fail("absent default key blocked a legitimate backup")
            log("  missing default key, dangling key and metadata failure: OK")
        finally:
            shutil.rmtree(state, ignore_errors=True)


def check_source_swaps(script):
    for mode in ("candidate", "ancestor", "candidate-fd", "ancestor-fd", "current-key"):
        with tempfile.TemporaryDirectory(prefix="pqc-source-swap-") as root:
            state = make_state_dir()
            try:
                backup = os.path.join(root, "backups")
                shim = os.path.join(root, "bin")
                os.mkdir(shim)
                victim = os.path.join(state, "victim")
                secret = os.path.join(root, "secret")
                saved = os.path.join(root, "saved")
                if mode.startswith("ancestor"):
                    os.mkdir(victim)
                    os.mkdir(secret)
                    victim = os.path.join(victim, "entry")
                    secret = os.path.join(secret, "entry")
                with open(victim, "w") as f:
                    f.write("ordinary-data")
                os.link(os.path.join(state, "wrap-key.b64"), secret)
                victim_swap = os.path.dirname(victim) if mode.startswith("ancestor") else victim
                secret_swap = os.path.dirname(secret) if mode.startswith("ancestor") else secret
                marker = os.path.join(root, "injected")
                with open(os.path.join(shim, "tar"), "w") as f:
                    f.write('''#!/usr/bin/env bash
if [[ "$1" == "-czf" ]]; then
  mv "$VICTIM" "$SAVED"
  mv "$SECRET" "$VICTIM"
  "$REAL_TAR" "$@"
  rc=$?
  mv "$VICTIM" "$SECRET"
  mv "$SAVED" "$VICTIM"
  exit "$rc"
fi
exec "$REAL_TAR" "$@"
''')
                os.chmod(os.path.join(shim, "tar"), 0o700)
                if mode.endswith("-fd"):
                    python_shim(shim, '''
real_open = os.open
def open_source(name, flags, *args, **kwargs):
    if name == "victim" and "dir_fd" in kwargs:
        os.rename(os.environ["VICTIM"], os.environ["SAVED"])
        os.rename(os.environ["SECRET"], os.environ["VICTIM"])
        try:
            descriptor = real_open(name, flags, *args, **kwargs)
            with open(os.environ["INJECTION_MARKER"], "w") as f:
                f.write("injected")
            return descriptor
        finally:
            os.rename(os.environ["VICTIM"], os.environ["SECRET"])
            os.rename(os.environ["SAVED"], os.environ["VICTIM"])
    return real_open(name, flags, *args, **kwargs)
os.open = open_source
''')
                elif mode == "current-key":
                    # The current selector's inode is different from the pinned
                    # original. Exclude it too, even when the selector is restored.
                    selector = os.path.join(root, "selector")
                    os.symlink(os.path.join(state, "wrap-key.b64"), selector)
                    python_shim(shim, '''
real_stat = os.stat
def source_stat(name, *args, **kwargs):
    if name == "victim" and "dir_fd" in kwargs:
        os.unlink(os.environ["KEY_SELECTOR"])
        os.symlink(os.environ["VICTIM"], os.environ["KEY_SELECTOR"])
        with open(os.environ["INJECTION_MARKER"], "w") as f:
            f.write("injected")
    return real_stat(name, *args, **kwargs)
os.stat = source_stat
def restore():
    os.unlink(os.environ["KEY_SELECTOR"])
    os.symlink(os.environ["INITIAL_KEY"], os.environ["KEY_SELECTOR"])
''')
                else:
                    selector = os.path.join(state, "wrap-key.b64")
                options = ["--state-dir", state, "--backup-dir", backup,
                           "--skip-healthcheck", "--skip-s3"]
                if mode == "current-key":
                    options += ["--wrap-key-file", selector]
                r = run(script, *options,
                        env={"PATH": shim + os.pathsep + os.environ["PATH"],
                             "REAL_TAR": shutil.which("tar"), "VICTIM": victim_swap,
                             "SECRET": secret_swap, "SAVED": saved,
                             "KEY_SELECTOR": selector if mode == "current-key" else "unused",
                             "INITIAL_KEY": os.path.join(state, "wrap-key.b64"),
                             "INJECTION_MARKER": marker})
                if mode == "current-key" and (r.returncode not in (0, 2) or
                                              len(glob.glob(os.path.join(backup, "*.tar.gz"))) != 1):
                    fail(f"current-key selector case did not complete: {r.stderr}")
                if mode.endswith("-fd") and (not os.path.exists(marker) or r.returncode != 1):
                    fail(f"{mode} did not exercise and reject a swapped descriptor: {r.stderr}")
                if mode.endswith("-fd") and (glob.glob(os.path.join(backup, "*.tar.gz")) or
                                             os.path.exists(os.path.join(backup, ".backup.lock")) or
                                             glob.glob(os.path.join(backup, ".pqc-backup-*"))):
                    fail(f"{mode} published or left lock/private staging")
                for archive in glob.glob(os.path.join(backup, "*.tar.gz")):
                    with tarfile.open(archive) as tf:
                        if mode == "current-key" and (not os.path.exists(marker) or
                                                       "pqc-openclaw-state/victim" in tf.getnames()):
                            fail("current selector inode was not excluded")
                        if any(b"dGVzdC1rZXktMzItYnl0ZXMtZm9yLXRlc3RpbmcxMjM0NQ==" in tf.extractfile(m).read()
                               for m in tf.getmembers() if m.isfile()):
                            fail(f"{mode} swap-and-restore leaked wrapping key bytes")
                if r.returncode not in (0, 1, 2):
                    fail(f"{mode} swap unexpected exit: {r.stderr}")
                log(f"  {mode} swap-and-restore: no key bytes published: OK")
            finally:
                shutil.rmtree(state, ignore_errors=True)


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
            "--wrap-key-file", os.path.join(state, "keys", "..", "keys", "current.key"),
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
        if "pqc-openclaw-state/state/openclaw.sqlite" not in members:
            fail("no current state/openclaw.sqlite inside the tarball")
        if any("/mlock/" in m for m in members):
            fail("mlock/ tmpfs was included in the tarball (should be excluded)")
        if "pqc-openclaw-state/wrap-key.b64" in members:
            fail("wrapping key was co-located with encrypted state in the backup")
        if "pqc-openclaw-state/keys/current.key" in members:
            fail("custom wrapping key was co-located with encrypted state in the backup")
        if any("pqc-openclaw-state/" + name in members for name in
               ("innocent-default.txt", "innocent-custom.txt")):
            fail("wrapping-key hardlink aliases entered the backup")
        if not all("pqc-openclaw-state/" + name in members for name in
                   ("ordinary.b64", "ordinary-hardlink")):
            fail("ordinary files or their hardlinks were lost")
        if "pqc-openclaw-state/openclaw.env" in members:
            fail("legacy service secrets were included in the backup")

        # 5. Restore the archive and prove the current database plus key material
        #    survive with their contents intact, not merely as readable files.
        with tempfile.TemporaryDirectory() as v:
            with tarfile.open(latest) as tf:
                tf.extractall(v)
            restored_root = os.path.join(v, "pqc-openclaw-state")
            db = os.path.join(restored_root, "state", "openclaw.sqlite")
            if not os.path.isfile(db):
                fail("no current state/openclaw.sqlite in restored tree")
            r = subprocess.run(
                [
                    "sqlite3",
                    db,
                    "PRAGMA integrity_check; SELECT group_concat(name, ',') FROM (SELECT name FROM foo ORDER BY id);",
                ],
                capture_output=True,
                text=True,
            )
            if r.returncode != 0:
                fail(f"sqlite3 restore verification failed: {r.stderr}")
            lines = r.stdout.strip().splitlines()
            if lines != ["ok", "hello,world,pqc"]:
                fail(f"restored database contents differ: {lines}")
            if os.path.exists(os.path.join(restored_root, "wrap-key.b64")):
                fail("restored tree unexpectedly contains wrap-key.b64")
            if os.path.exists(os.path.join(restored_root, "keys", "current.key")):
                fail("restored tree unexpectedly contains custom wrapping key")
            log("5. restored current SQLite database without co-located key material: OK")

        # 6. --verify standalone mode
        log(f"6. backup-pqc.sh --verify {latest}")
        r = run(args.script, "--verify", latest)
        if r.returncode != 0:
            fail(f"--verify returned {r.returncode}: {r.stdout} {r.stderr}")
        log(f"  --verify RC=0, last line: {r.stdout.strip().splitlines()[-1]}")

        # 6b. Legacy state.db archives remain verifiable during migration.
        legacy_root = tempfile.mkdtemp(prefix="pqc-e2e-legacy-state-")
        try:
            legacy_state = os.path.join(legacy_root, "pqc-openclaw-state")
            os.makedirs(legacy_state, exist_ok=True)
            legacy_db = os.path.join(legacy_state, "state.db")
            conn = sqlite3.connect(legacy_db)
            conn.execute("CREATE TABLE legacy (id INTEGER PRIMARY KEY)")
            conn.commit()
            conn.close()
            legacy_tar = os.path.join(backup, "pqc-openclaw-legacy-fixture.tar.gz")
            with tarfile.open(legacy_tar, "w:gz") as tf:
                tf.add(legacy_state, arcname="pqc-openclaw-state")
            legacy_sha = hashlib.sha256(open(legacy_tar, "rb").read()).hexdigest()
            with open(legacy_tar + ".sha256", "w") as f:
                f.write(f"{legacy_sha}  {os.path.basename(legacy_tar)}\n")
            log("6b. legacy state.db archive remains verifiable")
            r = run(args.script, "--verify", legacy_tar)
            if r.returncode != 0:
                fail(f"legacy --verify returned {r.returncode}: {r.stdout} {r.stderr}")
            log("  legacy --verify RC=0: OK")
        finally:
            shutil.rmtree(legacy_root, ignore_errors=True)

        # 6c. A corrupt current-layout database must never be published as a
        #     successful restore point, even when healthcheck is skipped.
        corrupt_state = tempfile.mkdtemp(prefix="pqc-e2e-corrupt-state-")
        corrupt_backup = tempfile.mkdtemp(prefix="pqc-e2e-corrupt-backup-")
        try:
            os.makedirs(os.path.join(corrupt_state, "state"), exist_ok=True)
            with open(os.path.join(corrupt_state, "state", "openclaw.sqlite"), "wb") as f:
                f.write(b"not-a-sqlite-database")
            old_good = os.path.join(corrupt_backup, "pqc-openclaw-2020-01-01T030000Z.known-good.tar.gz")
            with open(old_good, "wb") as archive:
                archive.write(b"EXISTING-RESTORE-POINT")
            with open(old_good + ".sha256", "w") as sidecar:
                sidecar.write("existing sidecar\n")
            log("6c. corrupt current SQLite is rejected before publication")
            r = run(
                args.script,
                "--state-dir", corrupt_state,
                "--backup-dir", corrupt_backup,
                "--skip-s3", "--skip-healthcheck",
                "--label", "must-not-publish",
            )
            if r.returncode == 0:
                fail("backup accepted a corrupt current-layout database")
            if glob.glob(os.path.join(corrupt_backup, "*.must-not-publish.tar.gz")):
                fail("corrupt backup was published before self-verification")
            if not os.path.isfile(old_good) or not os.path.isfile(old_good + ".sha256"):
                fail("failed backup pruned an existing restore point")
            log("  rejected without publishing or pruning: OK")
        finally:
            shutil.rmtree(corrupt_state, ignore_errors=True)
            shutil.rmtree(corrupt_backup, ignore_errors=True)

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

        # 8. Dense history must span daily dates and four older ISO weeks.
        #    Two runs on a date compete for that date's slot; mtime is noise.
        log("8. retention test: seven UTC dates plus four older ISO weeks")
        with tempfile.TemporaryDirectory(prefix="pqc-e2e-retention-") as rotation_dir:
            today = datetime.datetime.now(datetime.timezone.utc).date()

            def fixture(when, label="fixture"):
                name = f"pqc-openclaw-{when.strftime('%Y-%m-%dT%H%M%SZ')}.{label}.tar.gz"
                target = os.path.join(rotation_dir, name)
                with open(target, "wb") as archive:
                    archive.write(b"OLD-BACKUP")
                with open(target + ".sha256", "w") as sidecar:
                    sidecar.write(f"fixture  {name}\n")
                return target

            candidates = []
            for age in range(1, 50):
                day = today - datetime.timedelta(days=age)
                candidates.append(fixture(datetime.datetime.combine(day, datetime.time(3))))
            older_same_day = candidates[0]
            newer_same_day = fixture(
                datetime.datetime.combine(today - datetime.timedelta(days=1), datetime.time(4)),
                "manual",
            )
            # Falsify mtime ordering: an old archive appears newer by mtime.
            os.utime(candidates[-1], (2_000_000_000, 2_000_000_000))
            legacy = os.path.join(rotation_dir, "pqc-openclaw-legacy.tar.gz")
            with open(legacy, "wb") as archive:
                archive.write(b"UNKNOWN-NAME")
            r = run(
                args.script, "--state-dir", state, "--backup-dir", rotation_dir + os.sep,
                "--skip-s3", "--skip-healthcheck", "--label", "retention-test",
            )
            if r.returncode not in (0, 2):
                fail(f"retention backup failed: {r.stdout} {r.stderr}")
            retained = [
                path for path in glob.glob(os.path.join(rotation_dir, "*.tar.gz"))
                if path != legacy
            ]
            daily = {today - datetime.timedelta(days=age) for age in range(7)}
            daily_weeks = {day.isocalendar()[:2] for day in daily}
            retained_days = set()
            older_weeks = set()
            for archive in retained:
                stamp = os.path.basename(archive)[13:31]
                day = datetime.datetime.strptime(stamp, "%Y-%m-%dT%H%M%SZ").date()
                retained_days.add(day)
                if day not in daily:
                    older_weeks.add(day.isocalendar()[:2])
                if not os.path.isfile(archive + ".sha256"):
                    fail(f"retained archive has no checksum sidecar: {archive}")
            if (
                len(retained) != 11 or not daily.issubset(retained_days)
                or len(older_weeks) != 4 or older_weeks & daily_weeks
            ):
                fail(f"retention did not keep 7 dates plus 4 older weeks: {retained}")
            if not os.path.isfile(newer_same_day) or os.path.exists(older_same_day):
                fail("retention did not select the newest archive on a UTC date")
            if os.path.exists(older_same_day + ".sha256") or not os.path.isfile(legacy):
                fail("retention removed an unknown archive or kept a pruned sidecar")

        # A sparse history cannot fill all eleven slots; ISO week 1 crosses
        # the calendar-year boundary and must still count as one week.
        log("8b. sparse history and ISO year boundary")
        with tempfile.TemporaryDirectory(prefix="pqc-e2e-weeks-") as weeks_dir:
            week_fixtures = {}
            for day in ("2025-12-15", "2025-12-22", "2025-12-31", "2026-01-01", "2026-01-05"):
                stamp = datetime.datetime.fromisoformat(day).strftime("%Y-%m-%dT030000Z")
                name = f"pqc-openclaw-{stamp}.history.tar.gz"
                target = os.path.join(weeks_dir, name)
                with open(target, "wb") as archive:
                    archive.write(b"OLD-BACKUP")
                with open(target + ".sha256", "w") as sidecar:
                    sidecar.write(f"fixture  {name}\n")
                week_fixtures[day] = target
            r = run(
                args.script, "--state-dir", state, "--backup-dir", weeks_dir,
                "--skip-s3", "--skip-healthcheck", "--retention-daily", "0",
                "--retention-weekly", "4", "--label", "weekly-test",
            )
            if r.returncode not in (0, 2):
                fail(f"weekly retention backup failed: {r.stdout} {r.stderr}")
            if not os.path.exists(week_fixtures["2026-01-01"]) or os.path.exists(week_fixtures["2025-12-31"]):
                fail("ISO week 1 was split at New Year")
            if os.path.exists(week_fixtures["2025-12-15"]):
                fail("oldest weekly archive should have been pruned")

        with tempfile.TemporaryDirectory(prefix="pqc-e2e-sparse-") as sparse_dir:
            for date in ("2026-01-01", "2026-03-01"):
                name = f"pqc-openclaw-{date}T030000Z.history.tar.gz"
                with open(os.path.join(sparse_dir, name), "wb") as archive:
                    archive.write(b"OLD-BACKUP")
            r = run(
                args.script, "--state-dir", state, "--backup-dir", sparse_dir,
                "--skip-s3", "--skip-healthcheck", "--label", "sparse-test",
            )
            if r.returncode not in (0, 2):
                fail(f"sparse retention backup failed: {r.stdout} {r.stderr}")
            if len(glob.glob(os.path.join(sparse_dir, "*.tar.gz"))) != 3:
                fail("sparse history should retain its three available dates")
            r = run(
                args.script, "--state-dir", state, "--backup-dir", sparse_dir,
                "--skip-s3", "--skip-healthcheck", "--retention-daily", "0",
                "--retention-weekly", "0", "--label", "keep-new-only",
            )
            if r.returncode not in (0, 2):
                fail(f"zero-limit retention backup failed: {r.stdout} {r.stderr}")
            remaining = glob.glob(os.path.join(sparse_dir, "*.tar.gz"))
            if len(remaining) != 1 or "keep-new-only" not in remaining[0]:
                fail("zero limits must still retain the newly verified archive")

        r = run(
            args.script, "--state-dir", state, "--backup-dir", backup,
            "--skip-s3", "--skip-healthcheck", "--retention-daily", "08",
        )
        if r.returncode == 0 or "retention limits" not in r.stderr:
            fail("malformed retention limit was accepted")

        log("9. key aliases, special filenames and failure boundaries")
        check_key_boundaries(args.script)
        check_source_swaps(args.script)
        log("ALL CHECKS PASSED")
    finally:
        shutil.rmtree(state, ignore_errors=True)
        shutil.rmtree(backup, ignore_errors=True)


if __name__ == "__main__":
    main()
