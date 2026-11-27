"""Run a secretless, native ARM64 acceptance test against the stock PQC Compose file."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys

root = Path(sys.argv[1]).resolve(strict=True)
image, candidate = sys.argv[2:4]
source = root / "source"
project = "pqcarm64acceptance"
assert root.name.startswith("pqc-arm64-acceptance.")
assert os.getuid() == 0 and os.uname().machine == "aarch64"
assert source.is_dir() and re.fullmatch(r"[0-9a-f]{40}", candidate)
assert image == "pqc-openclaw:arm64-acceptance"

token = secrets.token_hex(32)
wrong_token = secrets.token_hex(32)
wrap_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
fixture_secrets = (token, wrong_token, wrap_key)


def redact(text):
    for value in fixture_secrets:
        text = text.replace(value, "[FIXTURE-REDACTED]")
    return text


def run(label, argv, allowed=(0,), timeout=120):
    reply = subprocess.run(
        argv, cwd=source, capture_output=True, text=True, stdin=subprocess.DEVNULL,
        timeout=timeout, env={"PATH": os.environ["PATH"], "HOME": str(root), "LANG": "C.UTF-8"},
    )
    if reply.returncode not in allowed:
        print(redact(reply.stderr[-3000:]), file=sys.stderr)
        raise RuntimeError(f"{label}: unexpected exit {reply.returncode}")
    return reply


for name in ("state", "workspace", "auth", "backups"):
    directory = root / name
    directory.mkdir(mode=0o700)
    os.chown(directory, 1000, 1000)

# Generate secrets after the image has been built.
secret_dir = source / "secrets"
secret_dir.mkdir(mode=0o700)
for name, value in (("gateway-token", token), ("wrap-key.b64", wrap_key)):
    path = secret_dir / name
    path.write_text(value + "\n")
    os.chown(path, 1000, 1000)
    path.chmod(0o400)

leases = [socket.socket() for _ in range(3)]
for lease in leases:
    lease.bind(("127.0.0.1", 0))
ports = [lease.getsockname()[1] for lease in leases]
for lease in leases:
    lease.close()

fixture_env = root / "fixture.env"
values = {
    "PQC_IMAGE": image,
    "OPENCLAW_STATE_DIR": root / "state",
    "OPENCLAW_WORKSPACE_DIR": root / "workspace",
    "OPENCLAW_AUTH_PROFILE_SECRET_DIR": root / "auth",
    "OPENCLAW_BACKUP_DIR": root / "backups",
    "PQC_HEALTHCHECK_PATH": source / "scripts/healthcheck-pqc.sh",
    "OPENCLAW_GATEWAY_PORT": f"127.0.0.1:{ports[0]}",
    "OPENCLAW_BRIDGE_PORT": f"127.0.0.1:{ports[1]}",
    "OPENCLAW_MSTEAMS_PORT": f"127.0.0.1:{ports[2]}",
}
fixture_env.write_text("".join(f"{name}={value}\n" for name, value in values.items()))
compose = ["docker", "compose", "--env-file", str(fixture_env), "-f", "docker-compose.pqc.yml", "-p", project]
one_off = compose + ["run", "--rm", "--no-deps", "-T", "--pull", "never"]
with_cli = one_off + ["openclaw-cli"]
inside = compose + ["exec", "-T", "openclaw-gateway"]
addon = "/app/src/security/native/build/Release/mlock_addon.node"


def gateway_process(cid):
    init = int(run("container PID", ["docker", "inspect", "--format", "{{.State.Pid}}", cid]).stdout)
    joined = run("container processes", ["docker", "top", cid, "-eo", "pid,ppid,comm"]).stdout
    parents = {int(row.split()[0]): int(row.split()[1]) for row in joined.splitlines()[1:]}
    namespace = (Path(f"/proc/{init}") / "ns/pid").readlink()
    candidates = []
    for pid in parents:
        parent = parents[pid]
        while parent in parents and parent != init:
            parent = parents[parent]
        if parent != init:
            continue
        proc = Path(f"/proc/{pid}")
        try:
            if (proc / "exe").readlink().name != "node" or (proc / "ns/pid").readlink() != namespace:
                continue
            command = (proc / "cmdline").read_bytes().split(b"\0")
        except FileNotFoundError:
            continue
        if command[0].startswith(b"openclaw-gateway") or (
            any(arg.endswith(b"dist/index.js") for arg in command[1:]) and b"gateway" in command[1:]
        ):
            candidates.append(proc)
    assert len(candidates) == 1, f"Expected one gateway process, found {len(candidates)}"
    return candidates[0]


try:
    config = json.dumps([
        {"path": "gateway.mode", "value": "local"},
        {"path": "gateway.controlUi.enabled", "value": False},
    ])
    run("initial config", one_off + ["--entrypoint", "node", "openclaw-gateway",
                                     "dist/index.js", "config", "set", "--batch-json", config])
    health = run("authenticated CLI health", compose + ["run", "--rm", "-T", "--pull", "never",
                 "openclaw-cli", "health", "--json"], timeout=330)
    assert json.loads(health.stdout)["ok"] is True
    mounts = run("secret permissions", inside + ["sh", "-ec",
                 'for f in /run/secrets/gateway_token /run/secrets/wrap_key; do '
                 'test -r "$f" && test -s "$f"; stat -c "%u:%g:%a" "$f"; done']).stdout.splitlines()
    assert mounts == ["1000:1000:400", "1000:1000:400"]
    probe = run("Compose memory probe", inside + ["node", "dist/docker-healthcheck.js",
                                                  "--probe-mlock"]).stdout.strip()
    assert probe == "mlock-probe:verified"
    assert run("runtime Node architecture", inside + ["node", "-p", "process.arch"]).stdout.strip() == "arm64"

    identity = json.loads(run("gateway identity", with_cli + [
        "gateway", "call", "gateway.identity.get", "--json",
    ]).stdout)
    assert all(isinstance(identity.get(key), str) and identity[key] for key in ("deviceId", "publicKey"))

    cid = run("gateway container", compose + ["ps", "-q", "openclaw-gateway"]).stdout.strip()
    proc = gateway_process(cid)
    status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
    assert status["Uid"].split() == ["1000"] * 4
    assert status["Seccomp"].strip() == "2" and status["NoNewPrivs"].strip() == "1"
    assert int(status["CapEff"], 16) == 0
    assert re.search(r"^Max core file size\s+0\s+0\b", (proc / "limits").read_text(), re.M)
    assert any(line.split(maxsplit=5)[-1] == addon for line in (proc / "maps").read_text().splitlines())
    binary = Path(f"/proc/{proc.name}/root{addon}")
    assert binary.stat().st_uid == 0 and stat.S_IMODE(binary.stat().st_mode) == 0o644
    locked_and_dontdump = 0
    for mapping in re.split(r"\n(?=[0-9a-f]+-[0-9a-f]+\s)", (proc / "smaps").read_text()):
        flags = re.search(r"^VmFlags:\s*(.*)$", mapping, re.M)
        locked = re.search(r"^Locked:\s*(\d+) kB$", mapping, re.M)
        if flags and locked and {"lo", "dd"}.issubset(flags.group(1).split()):
            locked_and_dontdump += int(locked.group(1))
    locked_total = int(status["VmLck"].split()[0])
    assert locked_total >= locked_and_dontdump > 0

    denied = run("wrong-token denial", with_cli + [
        "gateway", "call", "health", "--token", wrong_token, "--json",
    ], allowed=(1,))
    assert "token mismatch" in (denied.stdout + denied.stderr).lower()
    result = {
        "candidate": candidate, "host": os.uname().machine, "image_platform": "linux/arm64",
        "image": run("image ID", ["docker", "image", "inspect", "--format", "{{.Id}}", image]).stdout.strip(),
        "uid": 1000, "addon_path": addon, "addon_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "locked_kib": locked_total, "locked_and_dontdump_kib": locked_and_dontdump,
        "synthetic_probe": probe, "authenticated_health": True, "wrong_token_denied": True,
        "identity_loaded": True, "secret_mounts": mounts, "seccomp": 2, "no_new_privileges": True,
    }
    print("PQC_ARM64_ACCEPTANCE=" + json.dumps(result, sort_keys=True), flush=True)
finally:
    run("Compose teardown", compose + ["down", "--remove-orphans"], timeout=180)
