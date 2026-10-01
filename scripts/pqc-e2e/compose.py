#!/usr/bin/env python3
"""
pqc-fork-e2e-compose.py — static / structural validation for
docker-compose.pqc.yml. This is NOT a substitute for
`docker compose config` (we run on dev machines without a Docker
daemon), but it covers the checks that `docker compose config`
would fail on at parse time:

  1. YAML well-formed (the repository-pinned `yaml` package)
  2. Top-level keys: services, secrets, networks
  3. The gateway has image/build, environment, and a healthcheck
  4. PQC secrets (gateway_token, wrap_key) are declared at the
     top level AND referenced by the gateway service (otherwise
     docker compose would warn "secret not used")
  5. No inert PQC security switches or fake mlock tmpfs are advertised
  6. Cap_drop list contains NET_RAW, NET_ADMIN, SYS_PTRACE,
     SYS_ADMIN (the documented hardening in the file header)
  7. read_only: true on the gateway (defense-in-depth)
  8. healthcheck.test starts with CMD (compose-required) and
     references the same /usr/local/bin/healthcheck-pqc.sh path
     the in-container mount exposes (catches the
     /usr/local/share/.../usr/local/bin/... mismatch we hit in
     7582ca01ba)
  9. user is set to a non-root UID (1000:1000)
 10. mem_limit / pids_limit are set (catches accidental removal
     during refactors)
 11. The bind-mount source path for healthcheck-pqc.sh defaults
     to /usr/local/bin/healthcheck-pqc.sh (matches what
     install-pqc.sh installs to)
 12. secrets_file env names (OPENCLAW_GATEWAY_TOKEN_FILE,
     OPENCLAW_WRAP_KEY_FILE) are referenced in the gateway
     environment

Why this exists: docker-compose.pqc.yml is an evaluation recipe.
Structural checks catch missing secrets and misleading security
settings, but they do not prove runtime logging, memory locking, or
production readiness.

Run from the fork repo root:
  python3 scripts/pqc-e2e/compose.py
or:
  python3 scripts/pqc-e2e/compose.py --file path/to/docker-compose.pqc.yml
"""
import argparse
import json
import os
import re
import subprocess
import sys


def log(msg):
    print(f"[e2e-compose] {msg}", flush=True)


def fail(msg):
    print(f"[FAIL] {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--file",
        default="docker-compose.pqc.yml",
        help="Path to docker-compose.pqc.yml",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        fail(f"docker-compose.pqc.yml not found at {args.file}")

    # 1. well-formed YAML
    log(f"1. YAML well-formed: {args.file}")
    with open(args.file, "rb") as f:
        data = f.read()
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    parser_script = """
import fs from "node:fs";
import YAML from "yaml";
process.stdout.write(JSON.stringify(YAML.parse(fs.readFileSync(process.argv[1], "utf8"))));
"""
    parsed = subprocess.run(
        ["node", "--input-type=module", "-e", parser_script, args.file],
        capture_output=True,
        text=True,
    )
    if parsed.returncode != 0:
        fail(f"YAML parse error: {parsed.stderr.strip()}")
    try:
        doc = json.loads(parsed.stdout)
    except json.JSONDecodeError as error:
        fail(f"YAML parser returned invalid JSON: {error}")
    log("  repository-pinned YAML parser OK")

    # 2. top-level keys
    log("2. top-level keys")
    for k in ("services", "secrets", "networks"):
        if k not in doc:
            fail(f"missing top-level key: {k}")
    log(f"  services={list(doc['services'])} secrets={list(doc['secrets'])}")

    # 3. gateway service
    log("3. openclaw-gateway service shape")
    if "openclaw-gateway" not in doc["services"]:
        fail("openclaw-gateway service missing")
    gw = doc["services"]["openclaw-gateway"]
    for k in ("image", "environment", "healthcheck", "volumes", "cap_drop", "security_opt"):
        if k not in gw:
            fail(f"openclaw-gateway missing key: {k}")
    if "build" not in gw and "image" not in gw:
        fail("openclaw-gateway has neither build nor image")
    log(f"  image={gw['image']}, build={gw.get('build', {}).get('context', '?')}")

    # 4. PQC secrets declared + referenced
    log("4. PQC secrets (gateway_token, wrap_key) declared + referenced")
    for s in ("gateway_token", "wrap_key"):
        if s not in doc["secrets"]:
            fail(f"top-level secret missing: {s}")
        if s not in (gw.get("secrets") or []):
            fail(f"openclaw-gateway does not reference secret: {s}")
    log("  gateway_token + wrap_key: declared + referenced: OK")

    # 5. Reject inert security knobs and a volume unrelated to mlock(2).
    log("5. no inert PQC security switches or fake mlock volume")
    forbidden = {"PQC_LOG_LEVEL", "PQC_AUDIT_LOG_PATH", "PQC_REQUIRE_MLOCK"}
    for name, service in doc["services"].items():
        environment = service.get("environment") or {}
        configured = set(environment) if isinstance(environment, dict) else {
            str(entry).split("=", 1)[0] for entry in environment
        }
        if configured & forbidden:
            fail(f"{name} advertises unsupported PQC controls: {sorted(configured & forbidden)}")
        if "com.pqc-openclaw.security.audit-level" in (service.get("labels") or {}):
            fail(f"{name} advertises an unverified audit level")
    if "mlock_tmpfs" in (doc.get("volumes") or {}):
        fail("mlock_tmpfs is not connected to the secure-memory backend")
    if any("mlock_tmpfs" in str(mount) for mount in gw["volumes"]):
        fail("gateway mounts an unused mlock_tmpfs volume")
    log("  unsupported controls absent: OK")

    # 6. cap_drop
    log("6. cap_drop hardening (NET_RAW, NET_ADMIN, SYS_PTRACE, SYS_ADMIN)")
    expected = {"NET_RAW", "NET_ADMIN", "SYS_PTRACE", "SYS_ADMIN"}
    actual = set(gw.get("cap_drop") or [])
    missing = expected - actual
    if missing:
        fail(f"cap_drop missing capabilities: {missing}")
    log(f"  cap_drop: {sorted(actual)}")

    # 7. read_only
    log("7. read_only: true on gateway")
    if not gw.get("read_only"):
        fail("openclaw-gateway does not set read_only: true")
    log("  read_only: true: OK")

    # 8. healthcheck path consistency (regression for 7582ca01ba bug)
    log("8. healthcheck mount source == target == /usr/local/bin/healthcheck-pqc.sh")
    healthcheck_mounts = [v for v in gw["volumes"] if "healthcheck" in v]
    if not healthcheck_mounts:
        fail("no healthcheck bind mount on openclaw-gateway")
    for m in healthcheck_mounts:
        # Format: "src:target:ro"  (might have env-var prefix)
        parts = m.split(":")
        if len(parts) < 2:
            fail(f"malformed volume mount: {m}")
        src, target = parts[0], parts[-2]
        if "healthcheck" in src and "/usr/local/bin/healthcheck-pqc.sh" not in src:
            fail(f"healthcheck mount source does not end with /usr/local/bin/healthcheck-pqc.sh: {m}")
        if "healthcheck" in target and target != "/usr/local/bin/healthcheck-pqc.sh":
            fail(f"healthcheck mount target is not /usr/local/bin/healthcheck-pqc.sh: {m}")
    healthcheck_test = gw["healthcheck"].get("test") or []
    if not healthcheck_test or healthcheck_test[0] != "CMD":
        fail(f"healthcheck.test must start with CMD; got {healthcheck_test}")
    joined = " ".join(healthcheck_test)
    if "/usr/local/bin/healthcheck-pqc.sh" not in joined:
        fail(f"healthcheck.test does not reference /usr/local/bin/healthcheck-pqc.sh: {joined}")
    log(f"  healthcheck mount + test path consistent: OK")

    # 9. user is non-root
    log("9. user is non-root (1000:1000 or similar)")
    user = gw.get("user")
    if not user or str(user).startswith("0"):
        fail(f"openclaw-gateway user is root or unset: {user}")
    log(f"  user: {user}")

    # 10. resource limits
    log("10. mem_limit + pids_limit set")
    if not gw.get("mem_limit"):
        fail("openclaw-gateway mem_limit not set")
    if not gw.get("pids_limit"):
        fail("openclaw-gateway pids_limit not set")
    log(f"  mem_limit={gw['mem_limit']} pids_limit={gw['pids_limit']}")

    # 11. healthcheck bind-mount default path
    log("11. healthcheck bind-mount default is /usr/local/bin/healthcheck-pqc.sh")
    found_default = False
    for m in gw["volumes"]:
        if "PQC_HEALTHCHECK_PATH" in m and "/usr/local/bin/healthcheck-pqc.sh" in m:
            found_default = True
    if not found_default:
        fail("PQC_HEALTHCHECK_PATH default is not /usr/local/bin/healthcheck-pqc.sh "
             "(regression: 7582ca01ba fixed this — should be /usr/local/bin/...)")
    log("  PQC_HEALTHCHECK_PATH default = /usr/local/bin/healthcheck-pqc.sh: OK")

    # 12. *_FILE env vars referenced
    log("12. *_FILE env vars in gateway environment")
    env_block = gw["environment"]
    env_str = "\n".join(f"{k}: {v}" for k, v in env_block.items()) if isinstance(env_block, dict) else "\n".join(env_block)
    for needle in ("OPENCLAW_GATEWAY_TOKEN_FILE", "OPENCLAW_WRAP_KEY_FILE"):
        if needle not in env_str:
            fail(f"{needle} not in openclaw-gateway environment block")
    log(f"  OPENCLAW_GATEWAY_TOKEN_FILE + OPENCLAW_WRAP_KEY_FILE present: OK")

    log("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
