# USER_GUIDE — PQC OpenClaw Fork

**Audience**: an end user who has just cloned this repo and wants to
get a working post-quantum-hardened OpenClaw instance running on
their own machine or in a container. This is the step-by-step
"how to actually use the product" doc that goes with the repository README.

**Prerequisite**: a working terminal, basic shell literacy, ~30
minutes of focused time. The guide assumes Linux (Ubuntu 22.04+),
with macOS 13+ and WSL2 Ubuntu noted where the steps differ.

**Not for**:

- On-call SREs (you want [OPERATIONS](/security/OPERATIONS))
- Auditors / academics (you want [the whitepaper](/security/pqc-whitepaper))
- People migrating from upstream OpenClaw ([MIGRATION](/security/MIGRATION))
- The impatient (the 5-minute quick start is in the repository README)

---

## 0. What you have when this guide is done

By the end of §6, you will have:

- A running `pqc-openclaw` daemon, listening on port 18789
- A fresh mode-0600 file-backed wrap key at `$STATE_DIR/wrap-key.b64`
- A rendered systemd unit on Linux; the operator enables it explicitly
- Backup and Prometheus collector wrappers ready for operator-managed scheduling
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

# 2. Install the Node.js version pinned by .nvmrc
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
source "$HOME/.nvm/nvm.sh"
nvm install
nvm use    # reads .nvmrc

# 3. 1-command installer
sudo bash scripts/install-pqc.sh
```

The installer does, in order:

1. Enforces the requested Node version and repository-pinned pnpm version.
2. Copies the exact committed workspace to the install root.
3. Runs `pnpm install --frozen-lockfile`, then `pnpm run build`.
4. Writes a fresh 32-byte file-backed key at `$STATE_DIR/wrap-key.b64` (0600).
5. Installs the healthcheck, backup, and Prometheus collector wrappers.
6. Renders the Linux systemd unit and creates `$STATE_DIR/openclaw.env`.

The installer does not populate an OS keyring. That is an explicit later
operation because platform keyrings may require an interactive unlock.

### 1.2 macOS 13+ (manual service management)

```sh
# 1. Clone
git clone https://github.com/WU123-ABC-Cell/pqc-openclaw.git
cd pqc-openclaw

# 2. Install the version pinned by .nvmrc
brew install nvm    # or use the nvm install script from 1.1
nvm install
nvm use

# 3. The production installer currently requires root even on macOS
sudo bash scripts/install-pqc.sh --skip-systemd
```

The installer does not render a launchd plist or write Keychain entries. A
macOS operator must configure both explicitly after reviewing the generated
paths. The Linux systemd flow below does not apply.

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
    --node-version 24.16.0 \
    --skip-keyring \
    --skip-systemd \
    --skip-build
```

For a fully isolated Linux validation, `--sandbox-root PATH` requires an
existing empty, non-symlink directory owned by the caller with mode 0700.

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

# WSL2 / manual foreground start
sudo -u pqc-openclaw bash -c '
  cd /opt/pqc-openclaw
  set -a; source /var/lib/pqc-openclaw/openclaw.env; set +a
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
sudo bash /usr/local/bin/healthcheck-pqc.sh --json --skip-keyring | jq
```

Require `summary.fail` to be zero. The exact pass/warn split varies with
optional host capabilities and whether the gateway has emitted PQC events.
Example (abridged):

```json
{
  "summary": {"pass": 6, "warn": 2, "fail": 0},
  "checks": [
    {"check": "node-version", "status": "ok", "detail": "supported"},
    {"check": "mlock", "status": "warn", "detail": "no locking backend available"},
    ...
  ]
}
```

An `mlock` warning means neither the process hook nor native addon could lock
the cached key. The default at-rest source remains the mode-0600 file. See
[OPERATIONS](/security/OPERATIONS#5-when-to-page-the-security-team)
for the threat-model reasoning.

A `fail` on any other check is a problem — jump to
[OPERATIONS](/security/OPERATIONS#2-the-five-things-that-will-page-you-and-what-to-do)
and follow the recovery steps for the matching check name.

### 2.4 Verify the default wrap-key file

```sh
sudo test -f /var/lib/pqc-openclaw/wrap-key.b64
sudo stat -c '%a %U:%G %n' /var/lib/pqc-openclaw/wrap-key.b64
```

Expect mode 600 and the configured service user/group. After an explicit OS
keyring migration, pass matching service/account values to the healthcheck.
See [MLOCK](/security/MLOCK).

---

## 3. Daily operations

### 3.1 Start / stop / restart

```sh
# Linux
sudo systemctl start pqc-openclaw
sudo systemctl stop pqc-openclaw
sudo systemctl restart pqc-openclaw

# macOS (only after you have installed your own launchd plist)
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

| Event               | When                         | What it tells you                              |
| ------------------- | ---------------------------- | ---------------------------------------------- |
| `mlock`             | When a cached key is locked  | a runtime or native backend reported success   |
| `munlock`           | When the keyring releases it | the cached key was zeroed and unlock attempted |
| `mlock-unavailable` | Once per process             | neither locking backend is available           |

See [MLOCK](/security/MLOCK) for the full event schema and
what `status:ok` / `status:fail` mean.

### 3.4 Update

The fork is in active development. To update:

```sh
# 1. Stop the daemon
sudo systemctl stop pqc-openclaw

# 2. Take a pre-upgrade backup
sudo bash /usr/local/bin/backup-pqc.sh --label pre-upgrade-$(date +%Y-%m-%d)

# 3. Update the retained source checkout, then reinstall its committed tree.
#    /opt/pqc-openclaw has no .git directory by design.
git -C /srv/pqc-openclaw-source pull --ff-only
sudo bash /srv/pqc-openclaw-source/scripts/install-pqc.sh

# 4. Restart
sudo systemctl start pqc-openclaw
sudo bash /usr/local/bin/healthcheck-pqc.sh --json --skip-keyring
```

If `pnpm install --frozen-lockfile` fails, your `pnpm-lock.yaml`
has drifted from upstream. Run `pnpm install` once (without
`--frozen-lockfile`) and commit the updated `pnpm-lock.yaml`.
See the repository `CHANGELOG.md` for what changed in the
version you are upgrading to.

---

## 4. Backups

On Linux, the installer renders `pqc-openclaw-backup.service` and
`pqc-openclaw-backup.timer` and enables the timer when systemd is active. The
timer runs daily at 03:00 with up to 15 minutes of jitter and catches up after
downtime. On WSL without systemd, the units are rendered but not enabled. Verify
the schedule and run one on-demand backup before relying on it:

```sh
systemctl list-timers pqc-openclaw-backup.timer
sudo systemctl start pqc-openclaw-backup.service
sudo systemctl status pqc-openclaw-backup.service --no-pager
ls -la /var/backups/pqc-openclaw/
# Should show ~7 daily + 4 weekly tarballs, each with a
# matching .sha256 sidecar

# Verify the most recent backup
LATEST=$(ls -t /var/backups/pqc-openclaw/*.tar.gz | head -1)
sudo bash /usr/local/bin/backup-pqc.sh --verify "$LATEST"
# → "verify OK: ..."
```

For off-host storage, set these variables in the scheduler environment (the
gateway's `$STATE_DIR/openclaw.env` is not loaded by the backup service):

```sh
S3_BUCKET=my-pqc-backups
S3_ENDPOINT=https://s3.us-west-1.amazonaws.com   # optional, for non-AWS
# S3_PREFIX=pqc-openclaw                          # optional, default shown
```

Then trigger a one-shot:

```sh
sudo bash /usr/local/bin/backup-pqc.sh --json | tee /tmp/backup.out
```

A 0 exit code means the tarball was written, sha256-verified, its current
`state/openclaw.sqlite` database passed `PRAGMA integrity_check`, and (if
configured) it was uploaded. Legacy archives containing `state.db` remain
verifiable. The self-check runs before publication, so a corrupt database is
not left behind as an apparently usable restore point.

See [OPERATIONS](/security/OPERATIONS#3-backup-hygiene)
for the full restore-from-backup procedure and retention
tuning.

---

## 5. ML-DSA-65 / ML-KEM-768 quick start

These direct library examples demonstrate the primitives used by the fork. They
are not a claim that the running gateway exposes a raw cryptography API.

### 5.1 ML-DSA-65 sign + verify

```js
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { randomBytes } from "node:crypto";

// Generate a key pair
const { publicKey, secretKey } = ml_dsa65.keygen(randomBytes(32));

// Sign
const message = Buffer.from("the quick brown fox jumps over the lazy dog");
const signature = ml_dsa65.sign(message, secretKey);
// signature is 3309 bytes for ML-DSA-65

// Verify
const ok = ml_dsa65.verify(signature, message, publicKey);
console.log("verified:", ok); // → "verified: true"

// Tamper detection
const tampered = Buffer.from("the quick brown FOX jumps over the lazy dog");
const ok2 = ml_dsa65.verify(signature, tampered, publicKey);
console.log("verified (tampered):", ok2); // → "verified (tampered): false"
```

See the repository tests for integration and tamper-rejection coverage.

### 5.2 ML-KEM-768 encap + decap

```js
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { randomBytes } from "node:crypto";

// Receiver generates a key pair
const { publicKey, secretKey } = ml_kem768.keygen(randomBytes(64));

// Sender encapsulates a shared secret + ciphertext
const { sharedSecret, cipherText } = ml_kem768.encapsulate(publicKey);
// sharedSecret: 32 bytes
// cipherText:   1088 bytes for ML-KEM-768

// Receiver decapsulates the same shared secret from the ciphertext
const recovered = ml_kem768.decapsulate(cipherText, secretKey);

console.log("shared secret match:", Buffer.compare(sharedSecret, recovered) === 0);
// → "shared secret match: true"
```

The shared secret can then be fed into a reviewed KDF/envelope construction; do
not use it as an application protocol without domain separation and key
confirmation appropriate to that protocol.

### 5.3 When to use Ed25519 (legacy) instead of ML-DSA-65

If a client cannot install `@noble/post-quantum` (e.g. an old
embedded system), the fork can fall back to Ed25519 signatures
on the same wire protocol. The client sends a flag in the
TLS-like handshake; the daemon negotiates the strongest
algorithm both sides support. See [OPERATIONS.md §"PQC vs
Ed25519 client compatibility"](/security/OPERATIONS#2-the-five-things-that-will-page-you-and-what-to-do)
for the negotiation table.

For new deployments, **always use ML-DSA-65**. Ed25519 is
there for compatibility, not for security.

---

## 6. Frequently asked questions

### 6.1 "How do I activate the Linux mlock backend?"

```sh
# 1. Stop the daemon
sudo systemctl stop pqc-openclaw

# 2. Build the checked-in native addon in the installed tree
cd /opt/pqc-openclaw
sudo -u pqc-openclaw pnpm build:native

# 3. Verify the addon reports available
node -e 'const a=require("./src/security/native/mlock-addon.cjs"); process.exit(a.isAvailable()?0:1)'

# 4. Restart and verify
sudo systemctl start pqc-openclaw
sudo bash /usr/local/bin/healthcheck-pqc.sh --json --skip-keyring
```

Node 24.15.0 does not expose `process.mlock`; changing Node alone is not enough.
The native backend protects against swap, not core dumps. See
[MLOCK](/security/MLOCK).

### 6.2 "How do I rotate the wrap key?"

There is no supported operator-facing transactional rewrap command yet. Do not
rotate by deleting key material: doing so makes existing ciphertext and old
backups unreadable. Preserve and verify the old key and backup, then use a
reviewed migration procedure when one is available. Treat generation of a new
key as destructive reinitialization, not routine rotation.

### 6.3 "The healthcheck says `mlock unavailable`. Is this bad?"

It means neither the runtime hook nor native addon could lock the cached key, so
you are not getting swap protection. The default file remains protected by mode
0600, but that is separate from RAM pinning. Diagnose or rebuild the native
addon as in §6.1.

### 6.4 "How do I uninstall?"

```sh
# 1. Stop the daemon
sudo systemctl stop pqc-openclaw
sudo systemctl disable pqc-openclaw

# 2. Remove the systemd unit + binary scripts
sudo rm /etc/systemd/system/pqc-openclaw.service
sudo rm /usr/local/bin/healthcheck-pqc.sh /usr/local/bin/backup-pqc.sh \
  /usr/local/bin/pqc-textfile-collector.sh

# 3. (Optional) Wipe state
sudo rm -rf /var/lib/pqc-openclaw /var/backups/pqc-openclaw /opt/pqc-openclaw

# 4. (Optional) remove an OS keyring entry only if you explicitly created one
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
wrap key. See the repository `docker-compose.pqc.yml`
for the multi-container pattern (one service per instance,
one mlock tmpfs per instance).

### 6.6 "How do I migrate from upstream OpenClaw?"

See [MIGRATION](/security/MIGRATION). The TL;DR: snapshot the
upstream state, install the PQC fork into a separate root,
copy the state, validate, then switch traffic. Reversibility depends on a
verified snapshot, retained key material, and a rehearsed restore.

### 6.7 "What is the audit-grade story?"

The fork has a paper-grade self-audit at
[constant-time audit](/security/constant-time-audit) and a historical campaign
of 28 user-space/cache-hierarchy measurements across 129,200 trials. No
statistically significant difference exceeded the recorded threshold; this is
not proof of constant-time behavior. The third-party cryptographer audit
is in P0 backlog; the RFP is being prepared. Until that
audit, the fork is **not** suitable for government / financial
deployments where a signed auditor letter is required. It is
**fine** for engineering teams who can read the self-audit
and the verification log themselves.

### 6.8 "Where do I report a vulnerability?"

See the repository `SECURITY.md`. We aim to acknowledge
within 72 hours and ship a critical fix within 30 days.

---

## 7. Troubleshooting

The 5 most common first-time issues, in order of frequency:

### 7.1 "`[FAIL] node-version: vX.Y.Z (need 22.22.3+, 24.15+, or 25.9+)`"

Your Node is too old. From the source checkout, run `nvm install && nvm use`;
both commands read the current `.nvmrc`.

### 7.2 "`[FAIL] wrap-key-file: not found`"

Do not generate a replacement if encrypted state already exists. Recover the
exact file from a verified backup. On a truly fresh deployment, rerun the
installer from its source checkout to provision the initial file key.

### 7.3 "`[FAIL] healthz: GET /healthz returned 000000`"

The daemon is not listening. Check `journalctl -u pqc-openclaw -n 50`
for the actual error. Common causes:

- Port 18789 already in use: `sudo ss -ltn 'sport = :18789'`
- Wrong working directory: the systemd unit should
  `WorkingDirectory=/opt/pqc-openclaw`. Check
  `systemctl show pqc-openclaw | grep WorkingDirectory`
- Missing env vars: the systemd unit should
  `EnvironmentFile=-/var/lib/pqc-openclaw/openclaw.env`.
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
[OPERATIONS](/security/OPERATIONS#2-the-five-things-that-will-page-you-and-what-to-do).

---

## 8. Where to go next

You are now running a post-quantum-hardened OpenClaw instance.
What you can do with it:

- **Build something**: import the example apps under repository `examples/`,
  wire them into your own code via the standard OpenClaw client SDK.
- **Deploy it for real**: follow [MIGRATION](/security/MIGRATION)
  to bring production traffic over.
- **Audit it**: read [the whitepaper](/security/pqc-whitepaper) +
  [constant-time audit](/security/constant-time-audit). Spot a
  weakness? File an issue or see the repository `SECURITY.md`.
- **Operate it**: bookmark [OPERATIONS](/security/OPERATIONS) for
  the on-call runbook.
- **Get help**: file an issue at
  <https://github.com/WU123-ABC-Cell/pqc-openclaw/issues>.

The cryptography and retained evidence are inspectable; the operational limits
above are part of the deployment contract.
