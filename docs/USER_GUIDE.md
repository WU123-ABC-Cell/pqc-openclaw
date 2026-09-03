# USER_GUIDE — PQC OpenClaw Fork

**Audience**: an end user who has just cloned this repo and wants to
get a working post-quantum-hardened OpenClaw instance running on
their own machine or in a container. This is the step-by-step
"how to actually use the product" doc that goes with [README.md](../README.md).

**Prerequisite**: a working terminal, basic shell literacy, ~30
minutes of focused time. The guide assumes Linux (Ubuntu 22.04+),
with macOS 13+ and WSL2 Ubuntu noted where the steps differ.

**Not for**:

- On-call SREs (you want [OPERATIONS.md](OPERATIONS.md))
- Auditors / academics (you want [pqc-whitepaper.md](pqc-whitepaper.md))
- People migrating from upstream OpenClaw ([MIGRATION.md](MIGRATION.md))
- The impatient (the 5-minute quick start is in [README.md](../README.md))

---

## 0. What you have when this guide is done

By the end of §6, you will have:

- A running `pqc-openclaw` daemon, listening on port 18789
- A wrap key, generated fresh and stored in your OS keyring
  (libsecret on Linux, Keychain on macOS) and as a 0600 fallback
  file in `$STATE_DIR/wrap-key.b64`
- A systemd unit (Linux) or launchd plist (macOS) that starts
  the daemon on boot
- A daily backup cron, writing to `/var/backups/pqc-openclaw/`
  with a sha256 sidecar
- A healthcheck you can run from cron or CI

If you only need to _try it_ for an hour and throw it away, skip
§3 (systemd), §4 (backup cron), and §6 (the persistent-state parts).
§1, §2, §5, and the 5-line example in §0 are enough for a one-shot
test on your laptop.

---

## 1. Install

### 1.1 Linux (Ubuntu 22.04+ / Debian 12+)

```sh
# 1. Clone the fork
git clone https://github.com/WU123-ABC-Cell/pqc-openclaw.git
cd pqc-openclaw

# 2. Install Node.js 22.23.1 (pinned by .nvmrc)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
source "$HOME/.nvm/nvm.sh"
nvm install 22.23.1
nvm use    # reads .nvmrc

# 3. Install OS-keyring dependency
sudo apt-get update
sudo apt-get install -y libsecret-1-0 libsecret-1-dev gnome-keyring dbus-x11

# 4. 1-command installer (6 steps, takes 3-5 min)
sudo bash scripts/install-pqc.sh
```

The installer does, in order:

1. Verifies Node 22.22.3+ / 24.15+ / 25.9+ is on `PATH` (refuses otherwise)
2. Installs pnpm if missing (idempotent: skips if present)
3. `pnpm install --frozen-lockfile` + `pnpm run build` (compile to `dist/`)
4. Provisions a **fresh** 32-byte wrap key in the OS keyring
   (libsecret on Linux, Keychain on macOS) and a 0600-mode file
   fallback at `$STATE_DIR/wrap-key.b64`
5. Installs `/usr/local/bin/healthcheck-pqc.sh` and
   `/usr/local/bin/backup-pqc.sh` (idempotent)
6. Installs `/etc/systemd/system/pqc-openclaw.service` and
   `systemctl daemon-reload`. **The unit is NOT started** —
   you do that in §3.

If step 4 (keyring provisioning) fails on your distro, the
installer prints a one-time warning and falls back to the file
path. See [MLOCK.md §"Wrap-key provisioning fallback"](MLOCK.md)
for the manual override.

### 1.2 macOS 13+

```sh
# 1. Clone
git clone https://github.com/WU123-ABC-Cell/pqc-openclaw.git
cd pqc-openclaw

# 2. Install Node 22.23.1 via nvm (Homebrew is fine too, nvm just
#    matches what CI uses)
brew install nvm    # or use the nvm install script from 1.1
nvm install 22.23.1
nvm use

# 3. No libsecret needed — Keychain is built-in
# 4. Installer (no sudo needed; uses launchd not systemd)
bash scripts/install-pqc.sh
```

`scripts/install-pqc.sh` auto-detects macOS via `uname -s` and
falls through to the `launchd` path. The Keychain entry lives at
service `pqc-openclaw`, account `wrap-key-current`.

### 1.3 WSL2 Ubuntu (20.04+)

```sh
# Same as 1.1, but the systemd unit does NOT auto-start in WSL.
# Step 6's "systemctl enable" is harmless but does nothing.
# To start the daemon manually, see §3.3.
```

WSL2 does not have a real systemd by default (unless you enabled
it with `systemd=true` in `/etc/wsl.conf`). For a real production
deployment, use a Linux VM or container, not WSL.

### 1.4 Container (Docker / Podman)

```sh
git clone https://github.com/WU123-ABC-Cell/pqc-openclaw.git
cd pqc-openclaw

# Build + run with the production-hardened compose recipe
docker compose -f docker-compose.pqc.yml up -d

# Healthcheck (uses the bind-mounted healthcheck-pqc.sh)
docker compose -f docker-compose.pqc.yml exec openclaw-gateway \
    bash /usr/local/bin/healthcheck-pqc.sh --json
```

The compose file (`docker-compose.pqc.yml`) does the hardening
work for you: read-only rootfs, cap-drop on `NET_RAW` /
`NET_ADMIN` / `SYS_PTRACE` / `SYS_ADMIN`, no-new-privileges,
seccomp default, non-root user 1000:1000, mlock tmpfs,
mem_limit 1g, pids_limit 256. See the file header for the full
rationale.

### 1.5 What `install-pqc.sh` accepts

```sh
sudo bash scripts/install-pqc.sh \
    --install-root /opt/pqc-openclaw \
    --state-dir /var/lib/pqc-openclaw \
    --service-user pqc-openclaw \
    --node-version 22.23.1 \
    --skip-keyring        # use file fallback only (no OS keyring)
    --skip-systemd        # no systemd unit (containers)
    --skip-build          # use existing dist/ (faster iteration)
```

`--help` lists every flag with a one-liner. The defaults are
sane for a single-host production install.

---

## 2. First-time setup

The installer leaves you with the daemon installed but not
running. This section brings it up for the first time and
verifies each piece is healthy.

### 2.1 Start the daemon

```sh
# Linux (with systemd)
sudo systemctl enable --now pqc-openclaw

# macOS (launchd)
sudo launchctl load -w /Library/LaunchDaemons/com.pqc-openclaw.plist
sudo launchctl start com.pqc-openclaw

# WSL2 / container (foreground)
sudo -u pqc-openclaw bash -c '
  cd /opt/pqc-openclaw
  source /etc/pqc-openclaw/pqc-openclaw.env
  node dist/index.js gateway --bind 127.0.0.1 --port 18789
'
```

### 2.2 Smoke test the HTTP endpoint

```sh
curl -fsS http://127.0.0.1:18789/healthz
# → "OK"
```

A 200 OK here means the gateway accepted the connection and
responded. A 000 (connection refused) means the daemon is not
listening yet — check `journalctl -u pqc-openclaw -n 50` (Linux)
or `log show --predicate 'process == "pqc-openclaw"' --last 1m`
(macOS).

### 2.3 Run the 8-check healthcheck

```sh
sudo bash /usr/local/bin/healthcheck-pqc.sh --json | jq
```

Expected output (abridged):

```json
{
  "summary": {"pass": 8, "warn": 0, "fail": 0},
  "checks": [
    {"check": "node-version", "status": "ok", "detail": "v22.23.1 (supported)"},
    {"check": "mlock", "status": "warn", "detail": "process.mlock unavailable; wrap key NOT pinned in physical RAM. Upgrade to Node 24.15+ for mlock active path."},
    ...
  ]
}
```

`mlock` being `warn` on Node 22 is **expected and non-critical**.
The wrap key is still in the OS keyring (encrypted at rest) and
the file fallback is mode 0600. The `warn` exists so you know
your machine is not getting the RAM-pinning defense — only
relevant if you are worried about cold-boot attacks. See
[OPERATIONS.md §"When to page the security team"](OPERATIONS.md#5-when-to-page-the-security-team)
for the threat-model reasoning.

A `fail` on any other check is a problem — jump to
[OPERATIONS.md §"Failure modes"](OPERATIONS.md#2-the-five-things-that-will-page-you-and-what-to-do)
and follow the recovery steps for the matching check name.

### 2.4 Verify the wrap key is in the OS keyring

```sh
# Linux (libsecret via Python secretstorage)
python3 -c "
import secretstorage
conn = secretstorage.dbus_init()
for c in conn.get_all_collections():
    for i in c.get_all_items():
        a = i.get_attributes()
        if a.get('application') == 'pqc-openclaw' and a.get('username') == 'wrap-key-current':
            print('OK keyring entry found')
            exit(0)
print('MISSING'); exit(1)
" && echo "OK keyring"

# macOS (Keychain)
security find-generic-password -s pqc-openclaw -a wrap-key-current
# (should print <data> and exit 0)
```

If the keyring entry is missing but the file fallback exists
at `$STATE_DIR/wrap-key.b64` with mode 0600, the daemon still
works — the keyring is the live source of truth, the file is
the recovery backup. See [MLOCK.md](MLOCK.md).

---

## 3. Daily operations

### 3.1 Start / stop / restart

```sh
# Linux
sudo systemctl start pqc-openclaw
sudo systemctl stop pqc-openclaw
sudo systemctl restart pqc-openclaw

# macOS
sudo launchctl start com.pqc-openclaw
sudo launchctl stop com.pqc-openclaw
sudo launchctl kickstart -k system/com.pqc-openclaw  # restart

# WSL2 / container (foreground)
pkill -f 'dist/index.js gateway'      # stop
sudo -u pqc-openclaw bash -c '...node dist/index.js gateway...' &  # start
```

### 3.2 Check status

```sh
# Linux
sudo systemctl status pqc-openclaw
sudo journalctl -u pqc-openclaw -n 50 --no-pager   # last 50 log lines

# Quick "is it up?" check (no sudo needed)
pgrep -af 'dist/index.js gateway' && echo "RUNNING" || echo "STOPPED"

# macOS
sudo launchctl list | grep pqc-openclaw
log show --predicate 'process == "pqc-openclaw"' --last 5m
```

### 3.3 Tail the audit log

```sh
sudo tail -f /var/lib/pqc-openclaw/pqc-audit.log
```

The audit log is JSONL, one event per line. PQC-specific events
are tagged `[PQC]`:

| Event              | When                         | What it tells you                                                |
| ------------------ | ---------------------------- | ---------------------------------------------------------------- |
| `Mlock`            | On first wrap of a new key   | wrap key is RAM-pinned (or would be on Node 24.15+)              |
| `Munlock`          | On graceful shutdown         | wrap key scrubbed from RAM before exit                           |
| `MlockUnavailable` | Once per process, on startup | runtime lacks `process.mlock`; key in OS keyring, not RAM-pinned |

See [MLOCK.md](MLOCK.md) for the full event schema and
what `status:ok` / `status:fail` mean.

### 3.4 Update

The fork is in active development. To update:

```sh
# 1. Stop the daemon
sudo systemctl stop pqc-openclaw

# 2. Take a pre-upgrade backup
sudo bash /usr/local/bin/backup-pqc.sh --label pre-upgrade-$(date +%Y-%m-%d)

# 3. Pull the new code
cd /opt/pqc-openclaw
sudo -u pqc-openclaw git pull
sudo -u pqc-openclaw pnpm install --frozen-lockfile
sudo -u pqc-openclaw pnpm run build

# 4. Restart
sudo systemctl start pqc-openclaw
sudo bash /usr/local/bin/healthcheck-pqc.sh --json
```

If `pnpm install --frozen-lockfile` fails, your `pnpm-lock.yaml`
has drifted from upstream. Run `pnpm install` once (without
`--frozen-lockfile`) and commit the updated `pnpm-lock.yaml`.
See [CHANGELOG.md](../CHANGELOG.md) for what changed in the
version you are upgrading to.

---

## 4. Backups

The installer wires up a daily cron at 3 AM. To check it ran:

```sh
ls -la /var/backups/pqc-openclaw/
# Should show ~7 daily + 4 weekly tarballs, each with a
# matching .sha256 sidecar

# Verify the most recent backup
LATEST=$(ls -t /var/backups/pqc-openclaw/*.tar.gz | head -1)
sudo bash /usr/local/bin/backup-pqc.sh --verify "$LATEST"
# → "verify OK: ..."
```

For off-host storage, edit `/etc/pqc-openclaw/pqc-openclaw.env`:

```sh
S3_BUCKET=my-pqc-backups
S3_ENDPOINT=https://s3.us-west-1.amazonaws.com   # optional, for non-AWS
# S3_PREFIX=pqc-openclaw                          # optional, default shown
```

Then trigger a one-shot:

```sh
sudo bash /usr/local/bin/backup-pqc.sh --json | tee /tmp/backup.out
```

A 0 exit code means the tarball was written, sha256-verified,
and (if configured) uploaded. A 1 means one of the sources
failed but a partial file was still produced (check the JSON).
A 2 means non-critical (e.g. healthcheck warned but the backup
proceeded).

See [OPERATIONS.md §"Backup hygiene"](OPERATIONS.md#3-backup-hygiene)
for the full restore-from-backup procedure and retention
tuning.

---

## 5. ML-DSA-65 / ML-KEM-768 quick start

Once the daemon is running, the cryptographic operations are
exposed via the standard OpenClaw client API. Below are the
two primitives you are most likely to use.

### 5.1 ML-DSA-65 sign + verify

```js
import { ml_dsa65 } from "@noble/post-quantum";
import { randomBytes } from "node:crypto";

// Generate a key pair
const { publicKey, secretKey } = ml_dsa65.keygen(randomBytes(32));

// Sign
const message = Buffer.from("the quick brown fox jumps over the lazy dog");
const signature = ml_dsa65.sign(secretKey, message);
// signature is 3309 bytes for ML-DSA-65

// Verify
const ok = ml_dsa65.verify(publicKey, message, signature);
console.log("verified:", ok); // → "verified: true"

// Tamper detection
const tampered = Buffer.from("the quick brown FOX jumps over the lazy dog");
const ok2 = ml_dsa65.verify(publicKey, tampered, signature);
console.log("verified (tampered):", ok2); // → "verified (tampered): false"
```

The full `examples/ml-dsa-65-sign-verify.mjs` script also shows
how to import the fork's PQC-aware audit logger to emit
`[PQC] Mlock` events on first wrap.

### 5.2 ML-KEM-768 encap + decap

```js
import { ml_kem768 } from "@noble/post-quantum";
import { randomBytes } from "node:crypto";

// Receiver generates a key pair
const { publicKey, secretKey } = ml_kem768.keygen(randomBytes(32));

// Sender encapsulates a shared secret + ciphertext
const { sharedSecret, ciphertext } = ml_kem768.encapsulate(publicKey);
// sharedSecret: 32 bytes
// ciphertext:   1088 bytes for ML-KEM-768

// Receiver decapsulates the same shared secret from the ciphertext
const recovered = ml_kem768.decapsulate(secretKey, ciphertext);

console.log("shared secret match:", Buffer.compare(sharedSecret, recovered) === 0);
// → "shared secret match: true"
```

The full `examples/ml-kem-768-encap-decap.mjs` script shows the
hybrid pattern: derive an AES-256-GCM key from `sharedSecret`
and use it to encrypt a multi-megabyte payload (the public-key
op is constant-time; the symmetric op is authenticated).

### 5.3 When to use Ed25519 (legacy) instead of ML-DSA-65

If a client cannot install `@noble/post-quantum` (e.g. an old
embedded system), the fork can fall back to Ed25519 signatures
on the same wire protocol. The client sends a flag in the
TLS-like handshake; the daemon negotiates the strongest
algorithm both sides support. See [OPERATIONS.md §"PQC vs
Ed25519 client compatibility"](OPERATIONS.md#2-the-five-things-that-will-page-you-and-what-to-do)
for the negotiation table.

For new deployments, **always use ML-DSA-65**. Ed25519 is
there for compatibility, not for security.

---

## 6. Frequently asked questions

### 6.1 "How do I upgrade to Node 24.15+ to get mlock active?"

```sh
# 1. Stop the daemon
sudo systemctl stop pqc-openclaw

# 2. Install Node 24.15+ via nvm
source "$HOME/.nvm/nvm.sh"
nvm install 24.15.0
nvm use 24.15.0

# 3. Verify
node --version    # v24.15.0
node -e 'process.exit(typeof process.mlock === "function" ? 0 : 1)'
# → exit 0 means mlock is available

# 4. Restart the daemon (it auto-detects the new Node)
sudo systemctl start pqc-openclaw
sudo bash /usr/local/bin/healthcheck-pqc.sh --json
# → mlock check should now be "ok" instead of "warn"
```

The 4-step procedure is also documented inline in
[MLOCK.md §"Manual mlock validation"](MLOCK.md).

### 6.2 "How do I rotate the wrap key?"

Rotating invalidates every encrypted blob in `state.db`. Plan
a 5-minute maintenance window.

```sh
sudo systemctl stop pqc-openclaw
sudo -u pqc-openclaw secret-tool clear service pqc-openclaw username wrap-key-current
sudo shred -u /var/lib/pqc-openclaw/wrap-key.b64
sudo bash /opt/pqc-openclaw/scripts/install-pqc.sh --skip-build --skip-systemd
sudo systemctl start pqc-openclaw
sudo bash /usr/local/bin/healthcheck-pqc.sh --json
```

If the keyring entry AND the file fallback are both gone, you
have lost the ability to decrypt the state db. Restore from
the most recent backup at §4.

### 6.3 "The healthcheck says `mlock unavailable`. Is this bad?"

No, see [§2.3](#23-run-the-8-check-healthcheck). It just means
your runtime is Node 22 and you are not getting the RAM-pinning
defense. The wrap key is still protected by the OS keyring
(encrypted at rest, access-gated to your login session) and
the file fallback (mode 0600). To upgrade, follow §6.1.

### 6.4 "How do I uninstall?"

```sh
# 1. Stop the daemon
sudo systemctl stop pqc-openclaw
sudo systemctl disable pqc-openclaw

# 2. Remove the systemd unit + binary scripts
sudo rm /etc/systemd/system/pqc-openclaw.service
sudo rm /usr/local/bin/healthcheck-pqc.sh /usr/local/bin/backup-pqc.sh

# 3. (Optional) Wipe state
sudo rm -rf /var/lib/pqc-openclaw /var/backups/pqc-openclaw /opt/pqc-openclaw

# 4. (Optional) Wipe the OS keyring entry
sudo -u pqc-openclaw secret-tool clear service pqc-openclaw username wrap-key-current
```

Step 4 is **non-reversible**: if you have not extracted the
key, your state db can no longer be decrypted. Keep at
least one backup before uninstalling.

### 6.5 "Can I run multiple instances on the same host?"

Yes, with caveats. Use different `--install-root`, `--state-dir`,
and `--service-user` per instance, and bind to different
ports (`--port 28789` etc). The state dirs must not overlap
or you will corrupt one of them. Each instance has its own
wrap key. See [docker-compose.pqc.yml](../docker-compose.pqc.yml)
for the multi-container pattern (one service per instance,
one mlock tmpfs per instance).

### 6.6 "How do I migrate from upstream OpenClaw?"

See [MIGRATION.md](MIGRATION.md). The TL;DR: snapshot the
upstream state, install the PQC fork into a separate root,
copy the state, validate, then switch traffic. The migration
is in-place (no parallel deploy) and reversible in 5 minutes.

### 6.7 "What is the audit-grade story?"

The fork has a paper-grade self-audit at
[constant-time-audit.md](constant-time-audit.md) and 28
operations × 129,200 trials of empirical cache-timing
verification at 0 leak. The third-party cryptographer audit
is in P0 backlog; the RFP is being prepared. Until that
audit, the fork is **not** suitable for government / financial
deployments where a signed auditor letter is required. It is
**fine** for engineering teams who can read the self-audit
and the verification log themselves.

### 6.8 "Where do I report a vulnerability?"

See [SECURITY.md](../SECURITY.md). We aim to acknowledge
within 72 hours and ship a critical fix within 30 days.

---

## 7. Troubleshooting

The 5 most common first-time issues, in order of frequency:

### 7.1 "`[FAIL] node-version: vX.Y.Z (need 22.22.3+, 24.15+, or 25.9+)`"

Your Node is too old. Upgrade with `nvm install 22.23.1 && nvm use`.
The `.nvmrc` file in the repo root pins 22.23.1; `nvm use`
alone will read it.

### 7.2 "`[FAIL] wrap-key-file: not found`"

The install step 4 (keyring provisioning) failed silently.
Re-run `bash scripts/install-pqc.sh` — it is idempotent and
will re-provision the key.

### 7.3 "`[FAIL] healthz: GET /healthz returned 000000`"

The daemon is not listening. Check `journalctl -u pqc-openclaw -n 50`
for the actual error. Common causes:

- Port 18789 already in use: `sudo ss -ltn 'sport = :18789'`
- Wrong working directory: the systemd unit should
  `WorkingDirectory=/opt/pqc-openclaw`. Check
  `systemctl show pqc-openclaw | grep WorkingDirectory`
- Missing env vars: the systemd unit should
  `EnvironmentFile=/etc/pqc-openclaw/pqc-openclaw.env`.
  Check `systemctl show pqc-openclaw | grep EnvironmentFile`

### 7.4 "Restart loop (systemd says `activating` then `failed` repeatedly)"

The fork is crashing within the first second of startup. Tail
the journal:

```sh
sudo journalctl -u pqc-openclaw -n 200 --no-pager | grep -i -E 'error|fatal|cannot|missing'
```

Common causes, in order of frequency:

- Missing wrap key (see §7.2)
- Port 18789 already in use (see §7.3)
- Node version out of range (see §7.1)
- `mlock-helper.ts` missing (`ls /opt/pqc-openclaw/src/security/mlock-helper.ts`;
  if absent, the build was incomplete — re-run `pnpm run build`)
- Disk full (`df -h /var/lib/pqc-openclaw`)

### 7.5 "`backup-pqc.sh` says `[FAIL] lock: another backup-pqc.sh is already running`"

A previous run did not release the lock (crashed mid-run, or
was killed by `kill -9`). Check who holds the lock:

```sh
ls -la /var/backups/pqc-openclaw/.backup.lock
cat /var/backups/pqc-openclaw/.backup.lock/pid
# Cross-reference with `ps -p <pid>` to see if it's still alive
```

If the holder is dead, remove the stale lock:

```sh
sudo rm -rf /var/backups/pqc-openclaw/.backup.lock
sudo bash /usr/local/bin/backup-pqc.sh --verbose
```

For more failure modes, see
[OPERATIONS.md §"Failure modes"](OPERATIONS.md#2-the-five-things-that-will-page-you-and-what-to-do).

---

## 8. Where to go next

You are now running a post-quantum-hardened OpenClaw instance.
What you can do with it:

- **Build something**: import the example apps in [`examples/`](../examples/),
  wire them into your own code via the standard OpenClaw client SDK.
- **Deploy it for real**: follow [MIGRATION.md](MIGRATION.md)
  to bring production traffic over.
- **Audit it**: read [pqc-whitepaper.md](pqc-whitepaper.md) +
  [constant-time-audit.md](constant-time-audit.md). Spot a
  weakness? File an issue or see [SECURITY.md](../SECURITY.md).
- **Operate it**: bookmark [OPERATIONS.md](OPERATIONS.md) for
  the on-call runbook.
- **Get help**: file an issue at
  https://github.com/WU123-ABC-Cell/pqc-openclaw/issues.

The cryptography is real, the verification is empirical, the
deployment story is production-grade. Welcome aboard.
