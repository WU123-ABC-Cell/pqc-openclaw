#!/usr/bin/env python3
"""
pqc-fork-e2e-install.py — end-to-end round-trip test for
scripts/install-pqc.sh. Since this script provisions system-level
resources (system user, systemd unit, OS keyring) and requires
root, this harness cannot run a full install inside a developer
sandbox. Instead it verifies:

  1. bash -n syntax check.
  2. --help renders cleanly and lists every option the docstring
     promises (catches the common bug where the usage block lists
     a flag that the case statement does not handle).
  3. Running as non-root exits with a clear, actionable error
     message naming the script and the fix (sudo bash ...).
  4. Each --skip-* flag is accepted by the case statement (catches
     the bug where a new flag is documented but the case entry
     was forgotten — we already saw this in 920b6a25f7 with
     --skip-systemd's late addition).
  5. With --help-style option-parse-only flags (no install step
     actually runs), argument parsing does not trigger any
     side effects (no files written, no users created, no
     services touched).
  6. The OS detection rejects unsupported OS strings with a clear
     error (run via a uname-mocked env that wraps uname).

Why this exists: install-pqc.sh touches /etc/passwd, /etc/systemd,
and the OS keyring. A typo in the script (e.g. `rm -rf /etc/...`
with an empty variable) would have catastrophic consequences.
Catching that in CI before the script reaches a real production
host saves the operator from a very bad day.

Run from the fork repo root:
  python3 scripts/pqc-e2e/install.py
or:
  python3 scripts/pqc-e2e/install.py --script path/to/install-pqc.sh
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile


def log(msg):
    print(f"[e2e-install] {msg}", flush=True)


def fail(msg):
    print(f"[FAIL] {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def run(*args, **kwargs):
    return subprocess.run(["bash", *args], capture_output=True, text=True, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--script",
        default="scripts/install-pqc.sh",
        help="Path to install-pqc.sh",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.script):
        fail(f"install-pqc.sh not found at {args.script}")

    # 0. bash -n syntax check
    log(f"0. bash -n {args.script}")
    r = subprocess.run(["bash", "-n", args.script], capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"bash -n failed: {r.stderr}")

    # 1. --help clean and lists every docstring option
    log("1. --help renders and matches docstring options")
    r = run(args.script, "--help")
    if r.returncode != 0:
        fail(f"--help returned {r.returncode}: {r.stdout} {r.stderr}")
    help_text = r.stdout
    # Extract docstring USAGE block (between "USAGE" and "EXAMPLES" or end)
    usage_match = re.search(r"USAGE\s*\n(.*?)(?:\nEXAMPLES|\nREQUIREMENTS|\Z)",
                            help_text, re.DOTALL)
    if not usage_match:
        fail("--help output does not contain a USAGE block (expected 'USAGE\\n...')")
    usage_block = usage_match.group(1)
    # Each --flag in the docstring USAGE block should be implemented in
    # the case statement.
    doc_flags = set(re.findall(r"--[a-z][a-z-]+", usage_block))
    case_src = open(args.script).read()
    case_match = re.search(
        r'while \[\[ \$# -gt 0 \]\]; do\s+case "\$1" in(.*?)\s+esac\s+done',
        case_src,
        re.DOTALL,
    )
    if not case_match:
        fail("could not locate installer option parser case block")
    case_flags = set(re.findall(r"^\s*(--[a-z][a-z-]+)\)", case_match.group(1), re.MULTILINE))
    # help is special — never appears as a case branch
    doc_flags.discard("--help")
    missing = doc_flags - case_flags
    if missing:
        fail(f"docstring USAGE lists flags {missing} that the case statement does not handle")
    log(f"  {len(doc_flags)} --flag(s) in docstring, all handled by case statement: OK")

    # 2. Running as non-root fails with a clear message
    log("2. running as non-root must exit with a clear, actionable error")
    r = run(args.script)
    if r.returncode == 0:
        fail("non-root run returned 0; expected die() from EUID check")
    err = r.stderr
    if "this script must run as root" not in err or "sudo bash" not in err:
        fail(f"non-root error is not the documented actionable failure: {err}")
    if "Unknown option" in err:
        fail(f"non-root check reached the wrong failure path: {err}")
    log(f"  RC={r.returncode}, exact root/sudo guidance: OK")

    # 3. --skip-systemd / --skip-keyring / --skip-build accepted by case
    log("3. --skip-systemd / --skip-keyring / --skip-build are accepted by the case statement")
    for skip_flag in ("--skip-systemd", "--skip-keyring", "--skip-build"):
        # Will still fail at EUID check, but only AFTER successful case
        # parsing; if the case branch is missing, the script will emit
        # 'Unknown option' and exit 1 from a different code path. We
        # discriminate by looking for "Unknown option" in stderr.
        r = run(args.script, skip_flag)
        if "Unknown option" in (r.stderr + r.stdout):
            fail(f"{skip_flag} not handled by case (got 'Unknown option')")
        log(f"  {skip_flag}: case statement accepts it (no 'Unknown option')")

    # 4. Argument parsing must not touch the host filesystem
    log("4. argument parsing has no side effects (--help on a copy of the script in /tmp)")
    tmp = tempfile.mkdtemp(prefix="pqc-e2e-install-")
    try:
        copy = os.path.join(tmp, "install-pqc.sh")
        shutil.copyfile(args.script, copy)
        os.chmod(copy, 0o755)
        r = run(copy, "--help")
        if r.returncode != 0:
            fail(f"--help on copy returned {r.returncode}: {r.stdout} {r.stderr}")
        files = sorted(os.listdir(tmp))
        log(f"  /tmp dir after --help: {files}")
        if files != ["install-pqc.sh"]:
            fail(f"unexpected files created during --help: {files}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # 5. --install-root / --state-dir / --node-version / --service-user options
    #    must be accepted by the case statement (caught the same way as
    #    --skip-*: the case must match the flag and consume its arg).
    log("5. all value-taking options from the docstring are case-handled")
    value_flags = [
        "--install-root",
        "--state-dir",
        "--node-version",
        "--service-user",
        "--sandbox-root",
    ]
    for vf in value_flags:
        if vf not in case_flags:
            fail(f"{vf} not handled in case statement")
    log(f"  {len(value_flags)} value-taking flags all handled: OK")

    # 6. Unsupported OS values fail before any install action.
    log("6. unsupported OS is rejected before installation")
    fake_bin = tempfile.mkdtemp(prefix="pqc-e2e-install-bin-")
    try:
        fake_uname = os.path.join(fake_bin, "uname")
        with open(fake_uname, "w") as handle:
            handle.write("#!/usr/bin/env bash\nprintf 'Plan9\\n'\n")
        os.chmod(fake_uname, 0o755)
        env = {**os.environ, "PATH": fake_bin + os.pathsep + os.environ["PATH"]}
        r = run(args.script, env=env)
        if r.returncode == 0 or "unsupported OS: Plan9" not in r.stderr:
            fail(f"unsupported OS did not fail clearly: {r.stdout} {r.stderr}")
    finally:
        shutil.rmtree(fake_bin, ignore_errors=True)

    # 7. Documented exit behavior: help exits 0; non-root exits 1.
    log("7. --help exits 0, missing-required-sudo exits non-zero")
    r = run(args.script, "--help")
    if r.returncode != 0:
        fail(f"--help should exit 0, got {r.returncode}")
    r = run(args.script)
    if r.returncode == 0:
        fail("bare invocation should exit non-zero (no sudo)")
    log("  exit code semantics: OK")

    log("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
