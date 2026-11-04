"""Exercise a built gateway and CLI with the Compose token-file entrypoint.

The probe uses a disposable state directory and a loopback port. It does not
start Docker or claim that Compose mounts and container permissions work.
"""

import argparse
import json
import os
import secrets
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def clean_env(state: Path) -> dict[str, str]:
    env = {
        k: v for k, v in os.environ.items()
        if not k.startswith('OPENCLAW_') and not k.lower().endswith('_proxy')
    }
    env['NO_PROXY'] = '127.0.0.1,localhost'
    env['HOME'] = str(state.parent / 'home')
    env['OPENCLAW_HOME'] = env['HOME']
    env['OPENCLAW_STATE_DIR'] = str(state)
    env['OPENCLAW_CONFIG_PATH'] = str(state / 'openclaw.json')
    env['OPENCLAW_CONFIG_DIR'] = str(state)
    env['OPENCLAW_DISABLE_BONJOUR'] = '1'
    return env


parser = argparse.ArgumentParser()
parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
args = parser.parse_args()
if os.getuid() == 0:
    parser.error('run this probe as a non-root service user')
repo = args.repo.resolve()
wrapper = repo / 'scripts/pqc-token-entrypoint.sh'
node = ['node', str(repo / 'dist/index.js')]
if not wrapper.is_file() or not (repo / 'dist/index.js').is_file():
    parser.error('--repo must contain the token entrypoint and a built dist/index.js')

with tempfile.TemporaryDirectory(prefix='pqc-token-gateway-') as td:
    root = Path(td)
    state = root / 'gateway-state'
    state.mkdir()
    (root / 'home').mkdir()
    secret = root / 'gateway-token'
    fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, 'w') as secret_out:
        secret_out.write(secrets.token_urlsafe(48))
    if secret.stat().st_uid != os.getuid() or (secret.stat().st_mode & 0o777) != 0o400:
        raise RuntimeError('token file owner or mode is not the expected non-root 0400')
    env = clean_env(state)
    env['OPENCLAW_GATEWAY_TOKEN_FILE'] = str(secret)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    with (root / 'gateway.log').open('w') as out:
        gateway = subprocess.Popen(
            [
                'sh', str(wrapper), *node, 'gateway', '--auth', 'token', '--bind',
                'loopback', '--port', str(port), '--allow-unconfigured', '--verbose',
            ],
            cwd=repo, env=env, stdout=out, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            client_env = env.copy()
            good_cmd = [
                'sh', str(wrapper), *node, 'gateway', 'health', '--port', str(port),
                '--timeout', '3000', '--json',
            ]
            good = None
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if gateway.poll() is not None:
                    raise RuntimeError(f'gateway exited early with {gateway.returncode}')
                good = subprocess.run(
                    good_cmd, cwd=repo, env=client_env, capture_output=True,
                    text=True, timeout=8,
                )
                if good.returncode == 0:
                    break
                time.sleep(1)
            if good is None or good.returncode != 0:
                token = secret.read_text()
                print('health stdout:', (good.stdout if good else '')[-1500:].replace(token, '[REDACTED]'))
                print('health stderr:', (good.stderr if good else '')[-1500:].replace(token, '[REDACTED]'))
                print('gateway log:', (root / 'gateway.log').read_text()[-2500:].replace(token, '[REDACTED]'))
                raise RuntimeError(f'file-token health failed: {good.returncode if good else "not run"}')
            if json.loads(good.stdout).get('ok') is not True:
                raise RuntimeError('file-token health returned success without ok=true')
            print('file-token gateway/CLI health: PASS')
            wrong = subprocess.run(
                [
                    *node, 'gateway', 'health', '--port', str(port),
                    '--token', 'definitely-wrong', '--timeout', '3000', '--json',
                ],
                cwd=repo, env=clean_env(state), capture_output=True, text=True,
                timeout=8,
            )
            if wrong.returncode == 0:
                raise RuntimeError('wrong-token health unexpectedly succeeded')
            wrong_error = json.loads(wrong.stdout).get('error') or {}
            if 'unauthorized: gateway token mismatch' not in str(wrong_error).lower():
                raise RuntimeError(f'wrong-token request failed for a different reason: {wrong_error}')
            print('wrong-token denial: PASS')
            print('secret owner/mode and gateway UID:', secret.stat().st_uid,
                  oct(secret.stat().st_mode & 0o777), os.getuid())
        finally:
            if gateway.poll() is None:
                os.killpg(gateway.pid, signal.SIGTERM)
                try:
                    gateway.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    os.killpg(gateway.pid, signal.SIGKILL)
                    gateway.wait(timeout=8)
