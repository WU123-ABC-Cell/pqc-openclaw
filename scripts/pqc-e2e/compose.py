#!/usr/bin/env python3
"""
pqc-fork-e2e-compose.py — static / structural validation for
docker-compose.pqc.yml. This checks selected structural and security
invariants without a Docker daemon. It does not replace
`docker compose config` or actual container creation and cold start:

  1. YAML well-formed (the repository-pinned `yaml` package)
  2. Top-level keys: services, secrets, networks
  3. The gateway has image/build, environment, and a healthcheck
  4. PQC secrets (gateway_token, wrap_key) are declared at the
     top level AND referenced by the gateway service (otherwise
     docker compose would warn "secret not used")
  5. No inert PQC security switches or fake mlock tmpfs are advertised
     and neither service overrides Docker's default seccomp policy
  6. Cap_drop list contains NET_RAW, NET_ADMIN, SYS_PTRACE,
     SYS_ADMIN (the documented hardening in the file header)
  7. read_only: true on the gateway (defense-in-depth)
  8. healthcheck.test uses the mounted script with container state/key paths,
     and maps warning-only exit 2 to Docker success while critical failures
     remain unhealthy (also catches the mount-path regression in 7582ca01ba)
  9. user is set to a non-root UID (1000:1000)
 10. mem_limit / pids_limit are set (catches accidental removal
     during refactors)
 11. The bind-mount source path for healthcheck-pqc.sh defaults
     to /usr/local/bin/healthcheck-pqc.sh (matches what
     install-pqc.sh installs to)
 12. The gateway and CLI both route the mounted gateway token through the
     shipped entrypoint; the wrap-key file remains configured directly

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
import tempfile


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
    for name in ("openclaw-gateway", "openclaw-cli"):
        service = doc["services"].get(name)
        if not service:
            fail(f"{name} service is missing")
        options = service.get("security_opt") or []
        if "no-new-privileges:true" not in options:
            fail(f"{name} does not enable no-new-privileges")
        if any(str(option).startswith(("seccomp:", "seccomp=")) for option in options):
            fail(f"{name} unexpectedly overrides the daemon seccomp policy")
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
    log("8. healthcheck mount, container paths, and exit mapping")
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
    if len(healthcheck_test) != 4 or healthcheck_test[:3] != ["CMD", "bash", "-c"]:
        fail(f"healthcheck.test must run the container adapter via CMD bash -c: {healthcheck_test}")
    health_command = healthcheck_test[3]
    script_path = "/usr/local/bin/healthcheck-pqc.sh"
    if script_path not in health_command:
        fail(f"healthcheck.test does not reference {script_path}: {health_command}")
    for flag, path in (
        ("--state-dir", gw["environment"]["OPENCLAW_STATE_DIR"]),
        ("--wrap-key-file", gw["environment"]["OPENCLAW_WRAP_KEY_FILE"]),
        ("--install-root", "/app"),
    ):
        if f"{flag} {path}" not in health_command:
            fail(f"healthcheck.test does not use the container {flag} path {path}")
    if "--skip-keyring" not in health_command or "--json" not in health_command:
        fail("healthcheck.test must skip unused OS keyring and retain JSON diagnostics")
    with tempfile.TemporaryDirectory(prefix="pqc-compose-health-") as tmp:
        fake_health = os.path.join(tmp, "healthcheck-pqc.sh")
        with open(fake_health, "w", encoding="utf8") as stub:
            stub.write('printf "{\\"status\\":\\"probe\\"}\\n"\nexit "$PQC_TEST_HEALTH_EXIT"\n')
        # Compose reduces $$ to $ before the container runs this command.
        shell_command = health_command.replace("$$", "$")
        shell_command = shell_command.replace(script_path, fake_health)
        for script_exit, expected_exit in ((0, 0), (2, 0), (1, 1), (3, 1)):
            env = dict(os.environ, PQC_TEST_HEALTH_EXIT=str(script_exit))
            probe = subprocess.run(["bash", "-c", shell_command], env=env,
                                   capture_output=True, text=True)
            if probe.returncode != expected_exit or '"status":"probe"' not in probe.stdout:
                fail(f"healthcheck exit {script_exit} mapped to {probe.returncode}; expected {expected_exit}")
    log("  container paths and health exit mapping: OK")

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
    log("12. token file connected to gateway and CLI entrypoints")
    env_block = gw["environment"]
    env_str = "\n".join(f"{k}: {v}" for k, v in env_block.items()) if isinstance(env_block, dict) else "\n".join(env_block)
    for needle in ("OPENCLAW_GATEWAY_TOKEN_FILE", "OPENCLAW_WRAP_KEY_FILE"):
        if needle not in env_str:
            fail(f"{needle} not in openclaw-gateway environment block")
    cli = doc["services"].get("openclaw-cli") or {}
    if cli.get("environment", {}).get("OPENCLAW_GATEWAY_TOKEN_FILE") != gw["environment"].get("OPENCLAW_GATEWAY_TOKEN_FILE"):
        fail("gateway and CLI must reference the same token secret path")
    wrapper = "/app/scripts/pqc-token-entrypoint.sh"
    if gw.get("command", [None])[0] != wrapper or cli.get("entrypoint", [None])[0] != wrapper:
        fail("gateway and CLI must both run the token-file entrypoint")
    if gw["command"][1:5] != ["node", "dist/index.js", "gateway", "--auth"] or gw["command"][5] != "token":
        fail("Compose gateway must select token auth explicitly")
    if "gateway_token" not in (cli.get("secrets") or []):
        fail("CLI does not mount gateway_token")
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    entrypoint_path = os.path.join(repo_root, "scripts", "pqc-token-entrypoint.sh")
    if not os.path.isfile(entrypoint_path):
        fail("gateway token entrypoint is missing")
    with open(os.path.join(repo_root, "Dockerfile"), encoding="utf8") as dockerfile:
        if "COPY --from=runtime-assets --chown=node:node --chmod=0755 /app/scripts/pqc-token-entrypoint.sh ./scripts/pqc-token-entrypoint.sh" not in dockerfile.read():
            fail("runtime image does not contain executable gateway token entrypoint")
    with open(os.path.join(repo_root, ".dockerignore"), encoding="utf8") as dockerignore:
        if "/secrets" not in dockerignore.read().splitlines():
            fail("Compose host secret directory is not excluded from Docker build context")
    log("  gateway and CLI token-file entrypoint wired into Compose and image: OK")

    # Execute the actual bridge with a disposable non-secret fixture. This
    # catches a structurally present but inert _FILE configuration.
    if os.name == "posix":
        with tempfile.TemporaryDirectory(prefix="pqc-compose-token-") as tmp:
            secret_file = os.path.join(tmp, "gateway-token")
            with open(secret_file, "w", encoding="ascii") as secret:
                secret.write("compose-token-test-value-32-bytes\n")
            os.chmod(secret_file, 0o400)
            probe = ["sh", entrypoint_path, "node", "-e", "process.exit(process.env.OPENCLAW_GATEWAY_TOKEN === 'compose-token-test-value-32-bytes' ? 0 : 1)"]
            env = {**os.environ, "OPENCLAW_GATEWAY_TOKEN_FILE": secret_file}
            env.pop("OPENCLAW_GATEWAY_TOKEN", None)
            if subprocess.run(probe, env=env, capture_output=True).returncode != 0:
                fail("token entrypoint did not pass file content to gateway process")
            env["OPENCLAW_GATEWAY_TOKEN_FILE"] = os.path.join(tmp, "missing")
            if subprocess.run(probe, env=env, capture_output=True).returncode != 78:
                fail("token entrypoint did not fail closed for missing secret")
            env["OPENCLAW_GATEWAY_TOKEN_FILE"] = secret_file
            env["OPENCLAW_GATEWAY_TOKEN"] = "conflicting-token"
            if subprocess.run(probe, env=env, capture_output=True).returncode != 78:
                fail("token entrypoint did not reject conflicting token sources")
            env.pop("OPENCLAW_GATEWAY_TOKEN_FILE")
            env["OPENCLAW_GATEWAY_TOKEN"] = "compose-token-test-value-32-bytes"
            if subprocess.run(probe, env=env, capture_output=True).returncode != 0:
                fail("token entrypoint broke the existing environment token path")
            os.chmod(secret_file, 0o600)
            with open(secret_file, "w", encoding="ascii") as secret:
                pass
            os.chmod(secret_file, 0o400)
            env.pop("OPENCLAW_GATEWAY_TOKEN")
            env["OPENCLAW_GATEWAY_TOKEN_FILE"] = secret_file
            if subprocess.run(probe, env=env, capture_output=True).returncode != 78:
                fail("token entrypoint did not reject an empty secret")
        log("  token file, missing/empty/conflict rejection, and env control: OK")

    log("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
