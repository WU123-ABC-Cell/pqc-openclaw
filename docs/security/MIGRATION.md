# MIGRATION — OpenClaw upstream → PQC fork

**Audience**: operator who has an existing upstream OpenClaw
deployment and wants to move it to the PQC fork without losing
chat history, auth profiles, or workspace scratch.

**Scope**: the migration is in-place. We do not require a parallel
"new" deployment; the upstream service is stopped, the PQC fork is
installed into a different root, the state is copied across, and the
PQC fork is started on the same port (18789) so clients do not need
to reconfigure.

**Risk profile**: **medium**. The data on the wire is unchanged
(Ed25519 signatures from the upstream are not re-validated by the
PQC fork for the duration of the migration; the PQC fork only
re-signs new traffic). The data at rest changes through an additive SQLite
migration that adds four nullable PQC columns to `device_identities`; legacy
rows are preserved. Existing encrypted secrets must retain their original wrap
key until a tested rewrap procedure succeeds. A bad migration leaves the
upstream install untouched and reversible in 5 minutes — see §6.

**What this document is not**: it does not cover
"first-time-install" (use `bash scripts/install-pqc.sh` directly) or
"side-by-side test" (run the PQC fork on a different port and a
different state dir while the upstream stays on 18789). Both are
documented in `docs/security/OPERATIONS.md` and `PQC-FORK.md`.

---

## 0. Why migrate at all

The PQC fork is wire-compatible with upstream OpenClaw on the
client-facing API surface. The differences are entirely
**internally hardening**:

1. **Algorithm layer**: the PQC fork can negotiate
   `ml-dsa-65` / `ml-kem-768` for client auth in addition to
   `ed25519` / `x25519` (see `docs/security/pqc-whitepaper.md`).
   During migration, you keep `ed25519` enabled; you can flip to
   `ml-dsa-65` after the migration is validated.
2. **Storage layer**: an additive migration adds four nullable PQC columns to
   `device_identities` while preserving legacy rows. Existing encrypted data is
   not automatically rewrapped with a new key.
3. **Side-channel evidence**: 14 retained timing summaries reported no
   statistically significant difference under the recorded setup (`|t| < 4.5`).
   They are historical measurements, not proof of constant-time behavior.
4. **Wrap key**: the installer writes `$STATE_DIR/wrap-key.b64` with mode 0600;
   OS-keyring migration is explicit. On supported builds the native addon moves
   the decoded key into a dedicated locked mapping and scrubs the source. Linux
   also applies `MADV_DONTDUMP`; privileged process-memory inspection remains
   outside this control.

If you do not need any of those, you do not need to migrate.

---

## 1. Prerequisites

Before you start, verify each of these on the **upstream** host:

```sh
# 1. The upstream service is up and healthy
sudo systemctl status openclaw-gateway   # or whatever the unit is called
curl -fsS http://127.0.0.1:18789/healthz  # → 200 OK

# 2. You have a recent backup
sudo ls -la /var/backups/openclaw/ 2>/dev/null || echo "no upstream backup dir"
# If the upstream does not back up automatically, do a manual snapshot now:
sudo systemctl stop openclaw-gateway
sudo tar -czf /root/openclaw-upstream-pre-migration-$(date +%Y-%m-%d).tar.gz \
    /var/lib/openclaw/ /etc/openclaw/
sudo systemctl start openclaw-gateway

# 3. You have sudo
sudo -n true && echo "sudo OK" || echo "sudo requires password — re-login first"

# 4. Node.js is in range
node --version    # needs 22.22.3+, 24.15+, or 25.9+
# If not, install Node 22.23.1 from NodeSource first; the PQC
# fork's install-pqc.sh will detect this and refuse to proceed
# rather than install Node for you (the install script is
# deliberately conservative).

# 5. pnpm is available
pnpm --version    # must match the packageManager pin (currently 11.15.1)

# 6. Optional: the OS keyring is accessible if you plan to migrate
#    away from the default file-backed key.
#    On Linux:
sudo -u openclaw secret-tool --version  # ≥ 0.20
#    On macOS:
security list-keychains  # should print at least one keychain
```

If any of these fail, **stop here** and fix them. A migration
without a working backup or sudo is a one-way door.

---

## 2. Pre-migration: snapshot the upstream state

This is your rollback target.

```sh
# 1. Capture upstream version + config
UPSTREAM_VERSION=$(curl -fsS http://127.0.0.1:18789/healthz \
  | jq -r .version 2>/dev/null || echo "unknown")
echo "upstream version: $UPSTREAM_VERSION" | sudo tee /root/upstream-pre-migration.meta

sudo systemctl show openclaw-gateway \
  | sudo tee /root/upstream-pre-migration.systemd-show.txt

# 2. Stop the upstream service
sudo systemctl stop openclaw-gateway

# 3. Snapshot the state dir + config dir
sudo tar -czf /root/openclaw-upstream-pre-migration-$(date +%Y-%m-%d).tar.gz \
    -C / \
    --exclude='var/lib/openclaw/mlock' \
    --exclude='*.sock' \
    --exclude='*.log' \
    var/lib/openclaw/ etc/openclaw/

# 4. Capture the wrapping key, IF the upstream stored one
sudo find /var/lib/openclaw -name 'wrap-key*' -o -name '*.b64' \
    | sudo xargs -I {} cp {} /root/upstream-pre-migration-keys/
sudo chmod 0400 /root/upstream-pre-migration-keys/*

# 5. Confirm the snapshot
sudo ls -la /root/openclaw-upstream-pre-migration-*

# 6. Restart the upstream (we are not touching it yet)
sudo systemctl start openclaw-gateway
sudo systemctl status openclaw-gateway
```

You now have:

- `/root/openclaw-upstream-pre-migration-YYYY-MM-DD.tar.gz` — the
  full state (sqlite, auth profiles, config, wrap key fallback)
- `/root/upstream-pre-migration.meta` — version string
- `/root/upstream-pre-migration.systemd-show.txt` — env vars +
  unit definition
- `/root/upstream-pre-migration-keys/` — any wrap keys (mode 0400)

Keep these for at least 30 days.

---

## 3. Install the PQC fork

We install the PQC fork into a **separate root** (`/opt/pqc-openclaw`
vs the upstream's typical `/opt/openclaw` or wherever it lives) so
the two coexist during validation. The systemd unit for the PQC
fork will run on the **same port** (18789) so clients do not need
to know.

```sh
# 1. Clone the fork into a source checkout separate from the install root
sudo git clone https://github.com/WU123-ABC-Cell/pqc-openclaw.git /srv/pqc-openclaw-source
cd /srv/pqc-openclaw-source

# 2. Run the one-command installer
sudo bash scripts/install-pqc.sh \
    --install-root /opt/pqc-openclaw \
    --state-dir /var/lib/pqc-openclaw \
    --service-user openclaw \
    --node-version 22.23.1
```

What this does, in order:

1. Enforces the requested Node version and repository-pinned pnpm version.
2. Copies the exact committed workspace into the install root.
3. Runs `pnpm install --frozen-lockfile`, then builds `dist/`.
4. Writes a fresh file-backed key to `$STATE_DIR/wrap-key.b64` (mode 0600).
5. Installs the healthcheck, backup, and Prometheus collector wrappers.
6. Renders `/etc/systemd/system/pqc-openclaw.service` and creates
   `$STATE_DIR/openclaw.env`; it does not start the unit or populate an OS keyring.

---

## 4. Migrate the state

The PQC fork applies additive SQLite changes while preserving legacy rows. Copy
state only while both services are stopped. Existing encrypted data also needs
the exact key that originally wrapped it.

```sh
# 1. Stop the upstream (we are now committing to the migration)
sudo systemctl stop openclaw-gateway
sudo systemctl disable openclaw-gateway   # so it does not auto-start

# 2. Stop the PQC fork (it should not be running yet, but be safe)
sudo systemctl stop pqc-openclaw 2>/dev/null || true

# 3. Copy the state
sudo rsync -a --delete \
    --exclude='wrap-key*' \
    --exclude='*.log' \
    /var/lib/openclaw/ /var/lib/pqc-openclaw/

# 4. Copy the config (if it lives in /etc/openclaw)
sudo rsync -a /etc/openclaw/ /etc/pqc-openclaw/ 2>/dev/null || true
sudo chown -R openclaw:openclaw /var/lib/pqc-openclaw /etc/pqc-openclaw

# 5. Preserve the existing wrap key. Do not assume first read rewraps data.
sudo cp /var/lib/openclaw/wrap-key.b64 /var/lib/pqc-openclaw/wrap-key.b64
sudo chown openclaw:openclaw /var/lib/pqc-openclaw/wrap-key.b64
sudo chmod 0600 /var/lib/pqc-openclaw/wrap-key.b64

# Do not replace or delete the old key until every encrypted row has been
# transactionally rewrapped and verified. If no operator-facing rotation
# command is available in this build, stop here and retain the old key.

# 6. Sanity check the state before starting
sudo sqlite3 /var/lib/pqc-openclaw/state/openclaw.sqlite "PRAGMA integrity_check;"
# → "ok"
```

---

## 5. Validate

```sh
# 1. Start the PQC fork
sudo systemctl enable --now pqc-openclaw
sudo journalctl -u pqc-openclaw -f   # tail in another shell

# 2. Wait for the healthcheck to come up
sudo bash /usr/local/bin/healthcheck-pqc.sh --json --skip-keyring
# Expect: fail: 0; warnings describe optional host capabilities.

# 3. Verify a real client can connect
curl -fsS http://127.0.0.1:18789/healthz
# → 200 OK

# 4. Verify the audit log is writing
sudo tail -f /var/lib/pqc-openclaw/pqc-audit.log
# Expect: PQC events on first wrap of a new key

# 5. Take a baseline backup
sudo bash /usr/local/bin/backup-pqc.sh --label post-migration
sudo ls -la /var/backups/pqc-openclaw/
# Expect: a tarball + .sha256 sidecar

# 6. Verify the backup is good
sudo bash /usr/local/bin/backup-pqc.sh --verify \
    /var/backups/pqc-openclaw/pqc-openclaw-*-post-migration.tar.gz
# Expect: "verify OK: ..."

# 7. Keep the existing compatibility profile until every client path has been
#    tested against the PQC profile. Algorithm policy changes are separate from
#    state migration.

# 8. Review all three self-contained PQC workflows under .github/workflows/.
```

If any of steps 1-6 fail, jump to §6 (rollback).

---

## 6. Rollback plan

If migration validation fails, stop the PQC service and follow the verified
restore procedure from `docs/security/OPERATIONS.md`. Restore into a staging
directory first, inspect the exact paths, and only then replace the named
upstream state/config directories according to your deployment's recovery plan.

```sh
# 1. Stop the PQC fork
sudo systemctl stop pqc-openclaw
sudo systemctl disable pqc-openclaw

# 2. Restore the verified pre-migration snapshot using the reviewed runbook.
# 3. Restart and verify the upstream.
sudo systemctl enable --now openclaw-gateway
sudo systemctl status openclaw-gateway
curl -fsS http://127.0.0.1:18789/healthz
# → 200 OK
```

A rollback is only as reliable as the snapshot and restore rehearsal. Do not
claim byte identity until hashes and application-level decryptability have been
verified. If rollback fails, redeploy the upstream from IaC and restore the
verified snapshot while retaining all original key material.

---

## 7. Side-by-side mode (alternative to in-place)

If you cannot afford a 30-second downtime window, run the PQC
fork on a **different port** and a **different state dir** while
the upstream stays on 18789.

```sh
sudo useradd --system --home /var/lib/pqc-openclaw-test --shell /usr/sbin/nologin openclaw-test
cd /srv/pqc-openclaw-source
sudo bash scripts/install-pqc.sh \
    --install-root /opt/pqc-openclaw \
    --state-dir /var/lib/pqc-openclaw-test \
    --service-user openclaw-test \
    --skip-systemd

# Start it manually on a different port:
sudo -u openclaw-test bash -c '
  export OPENCLAW_STATE_DIR=/var/lib/pqc-openclaw-test
  export OPENCLAW_GATEWAY_PORT=28789
  export OPENCLAW_GATEWAY_BIND=loopback
  set -a; source /var/lib/pqc-openclaw-test/openclaw.env; set +a
  node /opt/pqc-openclaw/dist/index.js gateway --bind loopback --port 28789
'

# Smoke test:
curl -fsS http://127.0.0.1:28789/healthz
```

When you are confident in the PQC fork, run §4 (migrate the state)
and §5 (validate) as in the in-place flow. The window of
inconsistency is the time between "stop upstream" and "start
PQC fork" — typically 5-15 seconds.

---

## 8. See also

- `docs/security/OPERATIONS.md` — day-2 operations (after migration)
- `docs/security/MLOCK.md` — mlock design + validation
- `PQC-FORK.md` — TL;DR + scope + limitations
- `CHANGELOG.md` — release notes (look for the `M1`-`M14` migration
  section for the historical list of behavior changes)
- `scripts/install-pqc.sh` — the one-command installer
- `scripts/healthcheck-pqc.sh` — 8-check health probe
- `scripts/backup-pqc.sh` — daily backup + verify
- `docker-compose.pqc.yml` — alternative container-based deploy
