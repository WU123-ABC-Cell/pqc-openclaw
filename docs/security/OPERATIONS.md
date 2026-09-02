# OPERATIONS — PQC OpenClaw fork production operator playbook

**Audience**: on-call SRE / DevOps engineer who has just been paged about
the PQC fork and needs to (a) figure out what is wrong, (b) decide
whether to restart / roll back / page the security team, and (c) leave
a clean handoff for the next shift.

**Tone**: terse, runbook-style. No marketing, no exhortation, no
"this should never happen". When something can go wrong, this document
tells you what to do.

**Source of truth**: this file lives at `docs/security/OPERATIONS.md`
in the fork repo. If the production deployment diverges from what this
file says (new flag, new path, new check), file a PR to update it.
**Do not** rely on tribal knowledge.

---

## 0. Where things live on a production host

After `bash scripts/install-pqc.sh` finishes successfully on Ubuntu
22.04+ / WSL2 Ubuntu / macOS 13+:

| Path                                                   | What it is                                                                                                 | Why it is there                                                                       |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `/opt/pqc-openclaw/`                                   | fork checkout + `dist/` build                                                                              | `INSTALL_ROOT`, the systemd unit's `WorkingDirectory`                                 |
| `/var/lib/pqc-openclaw/`                               | state dir: `state.db`, `pqc-audit.log`, `wrap-key.b64` fallback, `auth-profile-secrets/`, `mlock/` (tmpfs) | `STATE_DIR`, the systemd unit's `StateDirectory`                                      |
| `/var/backups/pqc-openclaw/`                           | local backup tarballs + `.sha256` sidecars                                                                 | `BACKUP_DIR` for `backup-pqc.sh` cron                                                 |
| `/etc/systemd/system/pqc-openclaw.service`             | systemd unit                                                                                               | installed by `install-pqc.sh --service-name pqc-openclaw` (default)                   |
| `/usr/local/bin/healthcheck-pqc.sh`                    | 8-check health probe                                                                                       | installed by `install-pqc.sh`; used by systemd `ExecStartPost` and Docker healthcheck |
| `/usr/local/bin/backup-pqc.sh`                         | daily backup runner                                                                                        | installed by `install-pqc.sh`; cron target                                            |
| `~/.local/share/keyrings/` (GNOME) or Keychain (macOS) | OS keyring entry for the wrap key                                                                          | written by `install-pqc.sh` (M6.B / 8/29)                                             |
| `OPENCLAW_GATEWAY_TOKEN` env var                       | gateway client auth                                                                                        | set in `/etc/pqc-openclaw/pqc-openclaw.env` (mode 0600)                               |
| `OPENCLAW_WRAP_KEY_FILE` env var                       | path to the 32-byte wrap key                                                                               | set in `/etc/pqc-openclaw/pqc-openclaw.env` (mode 0600)                               |

The systemd unit loads `/etc/pqc-openclaw/pqc-openclaw.env` before
starting the gateway. **Do not** edit env vars in the unit file
directly — `install-pqc.sh` will overwrite them on the next run.

---

## 1. Day-2 tasks (the ones you will actually do)

### 1.1 Check whether the fork is up

```sh
sudo systemctl status pqc-openclaw
sudo bash /usr/local/bin/healthcheck-pqc.sh --json
```

A healthy fork reports `pass: 8`, `warn: 0`, `fail: 0` (or `pass: 7`,
`warn: 1` if running on Node 22 — the `mlock` warn is non-critical
because Node 22's defensive no-op path is still safe, just not
pinned in physical RAM).

If `--json` returns `fail > 0`, jump to §2.

### 1.2 Tail the audit log

```sh
sudo journalctl -u pqc-openclaw -f
sudo tail -f /var/lib/pqc-openclaw/pqc-audit.log
```

The audit log is JSONL, one event per line. PQC-specific events are
tagged `[PQC]` and emit on a separate stream so security monitoring
can ingest them without parsing the full Gateway log. The three PQC
events are:

| Event              | When                         | What it tells you                                                                                   |
| ------------------ | ---------------------------- | --------------------------------------------------------------------------------------------------- |
| `Mlock`            | On first wrap of a new key   | wrap key is now pinned in physical RAM (or would be on Node 24.15+)                                 |
| `Munlock`          | On graceful shutdown         | wrap key was scrubbed from RAM before exit                                                          |
| `MlockUnavailable` | Once per process, on startup | the runtime does not have `process.mlock`; key is not RAM-pinned but is still wrapped in OS keyring |

See `docs/security/MLOCK.md` for the full event schema.

### 1.3 Restart the fork (graceful)

```sh
sudo systemctl restart pqc-openclaw
sudo journalctl -u pqc-openclaw -n 50 --no-pager
sudo bash /usr/local/bin/healthcheck-pqc.sh
```

The graceful path takes ~3-6 seconds (the M12 v3 source-level
`cachedDefaultKeyring` singleton warms once on first call, then is
shared by 12+ startup callers). If restart loops, jump to §2.4.

### 1.4 Roll back to the previous release

```sh
# 1. snapshot current state
sudo bash /usr/local/bin/backup-pqc.sh --label pre-rollback-$(date +%Y-%m-%d)

# 2. check out the previous tag
sudo systemctl stop pqc-openclaw
sudo -u pqc-openclaw bash -c '
  cd /opt/pqc-openclaw
  git fetch --tags
  git checkout v0.9.0   # the last-known-good tag
  pnpm install --frozen-lockfile
  pnpm run build
'

# 3. restart
sudo systemctl start pqc-openclaw
sudo bash /usr/local/bin/healthcheck-pqc.sh
```

If the previous tag is missing, check `git log --oneline --decorate`
in `/opt/pqc-openclaw` for the most recent commit before today's
degradation.

### 1.5 Rotate the wrap key (planned)

Rotating the wrap key invalidates every encrypted blob in the state
db. Plan a 5-minute maintenance window.

```sh
# 1. snapshot
sudo bash /usr/local/bin/backup-pqc.sh --label pre-key-rotation-$(date +%Y-%m-%d)

# 2. stop the gateway
sudo systemctl stop pqc-openclaw

# 3. delete the OS keyring entry (keytar + libsecret)
#    and the file fallback
sudo -u pqc-openclaw secret-tool clear service pqc-openclaw username wrap-key-current
sudo shred -u /var/lib/pqc-openclaw/wrap-key.b64

# 4. start the gateway; install-pqc.sh step 4 re-provisions a fresh 32-byte key
sudo bash /opt/pqc-openclaw/scripts/install-pqc.sh --skip-build --skip-systemd
sudo systemctl start pqc-openclaw

# 5. validate
sudo bash /usr/local/bin/healthcheck-pqc.sh
```

**Important**: rotating the wrap key means every previously-encrypted
secret in `state.db` is now unreadable. If you have backups that were
encrypted with the old key, you cannot decrypt them with the new
key. This is intentional. Decide whether to destroy old backups
(`sudo rm /var/backups/pqc-openclaw/pqc-openclaw-*-pre-key-rotation-*.tar.gz`)
or keep them in cold storage for forensic purposes.

### 1.6 Run an on-demand backup before a risky change

```sh
sudo bash /usr/local/bin/backup-pqc.sh --label pre-upgrade-$(date +%Y-%m-%d) --verbose
```

The label is sanitized (`[A-Za-z0-9_-]` only; everything else becomes
`-`), so it is safe to interpolate `$(date +...)` without escaping.

---

## 2. The five things that will page you (and what to do)

### 2.1 `[FAIL] wrap-key-file: not found at /var/lib/pqc-openclaw/wrap-key.b64`

The wrap key file is missing. Either it was never provisioned, or
something deleted it.

```sh
# Check if the OS keyring entry is still there (it should be enough to recover):
sudo -u pqc-openclaw secret-tool lookup service pqc-openclaw username wrap-key-current

# If the keyring entry is also missing, you need a fresh install:
sudo bash /opt/pqc-openclaw/scripts/install-pqc.sh --skip-build --skip-systemd
```

If both the file fallback AND the OS keyring entry are gone, you
have lost the ability to decrypt the state db. Restore from the
most recent backup.

### 2.2 `[FAIL] state-db: SQLite integrity_check failed`

The state database is corrupt. This usually means one of:

- The disk is dying (`dmesg | grep -i 'i/o error'`).
- The OS killed the process mid-write (OOM kill or power loss).
- Something is writing to the db file outside the fork (a runaway
  cronjob, a `find / -delete` gone wrong, etc).

```sh
# 1. Stop the fork so nothing else writes to the db
sudo systemctl stop pqc-openclaw

# 2. Inspect the corruption
sudo sqlite3 /var/lib/pqc-openclaw/state/openclaw.sqlite "PRAGMA integrity_check;"

# 3. If the db is salvageable, dump + reload
sudo sqlite3 /var/lib/pqc-openclaw/state/openclaw.sqlite ".dump" \
  | sudo sqlite3 /var/lib/pqc-openclaw/state/openclaw.sqlite.recovered

# 4. Otherwise, restore from backup
sudo tar -xzf /var/backups/pqc-openclaw/pqc-openclaw-YYYY-MM-DD-*.tar.gz \
    -C /var/lib/pqc-openclaw --strip-components=1
sudo systemctl start pqc-openclaw
```

### 2.3 `[FAIL] healthz: GET /healthz returned 000000`

The fork process is running (or systemd thinks it is) but the HTTP
endpoint is not responding.

```sh
# Is the port bound?
sudo ss -ltn 'sport = :18789'

# Is the process actually alive?
sudo systemctl status pqc-openclaw
sudo journalctl -u pqc-openclaw -n 100 --no-pager | tail -50

# Is it OOM-killed?
sudo dmesg | grep -i 'killed process'

# Try a manual start in the foreground to see the error
sudo -u pqc-openclaw bash -c '
  cd /opt/pqc-openclaw
  set -a; source /etc/pqc-openclaw/pqc-openclaw.env; set +a
  node dist/index.js gateway --bind 127.0.0.1 --port 18789
'
```

### 2.4 Restart loop (systemd says `activating` then `failed` repeatedly)

The fork is crashing within the first second of startup. Common
causes, in order of frequency:

```sh
sudo journalctl -u pqc-openclaw -n 200 --no-pager | grep -i -E 'error|fatal|cannot|missing'
```

- **Missing wrap key**: see §2.1.
- **Port 18789 already in use** (`ss -ltn 'sport = :18789'`).
- **Node version out of range** (`node --version`; needs 22.22.3+ / 24.15+ / 25.9+).
- **mlock-helper.ts missing** (`ls /opt/pqc-openclaw/src/security/mlock-helper.ts`; if absent, the build was incomplete; rerun `pnpm run build`).
- **Disk full** (`df -h /var/lib/pqc-openclaw`).

### 2.5 `[WARN] mlock: process.mlock unavailable`

Non-critical. The wrap key is **not** pinned in physical RAM but is
still wrapped in the OS keyring. The defensive no-op path is safe
to run; you just do not get the RAM-pinning guarantee.

To upgrade to the active mlock path: bump Node to 24.15+, rebuild
the image, and redeploy. See `docs/security/MLOCK.md` §"Manual mlock
validation" for the 4-step validation.

If you do not plan to upgrade Node, you can suppress the warning
by setting `PQC_REQUIRE_MLOCK=0` in the env file (it is the default).

---

## 3. Backup hygiene

### 3.1 Verify a backup before relying on it

```sh
sudo bash /usr/local/bin/backup-pqc.sh --verify /var/backups/pqc-openclaw/pqc-openclaw-2026-09-02-030000.tar.gz
```

A passing verify means: sha256 matches, tar -tzf reads cleanly, and
the embedded state.db passes `sqlite3 .schema`. **Do not skip this
step** before a restore.

### 3.2 Restore from a backup

```sh
sudo systemctl stop pqc-openclaw
sudo tar -xzf /var/backups/pqc-openclaw/pqc-openclaw-YYYY-MM-DD-*.tar.gz \
    -C /var/lib/pqc-openclaw --strip-components=1
sudo systemctl start pqc-openclaw
sudo bash /usr/local/bin/healthcheck-pqc.sh
```

The tarball preserves the `pqc-openclaw-state/` directory layout
(see `backup-pqc.sh` for the exact `--transform` rule).

### 3.3 Backup schedule

Default cron (installed by `install-pqc.sh`):

```cron
0 3 * * * /usr/local/bin/backup-pqc.sh --json >> /var/log/pqc-backup.log 2>&1
```

Retention: 7 daily + 4 weekly (defaults). Adjust with
`--retention-daily N --retention-weekly N`. The cleanup runs **after**
the new tarball is verified, so a failed run never rotates the only
good copy.

If you also have S3 off-host storage, set `--s3-bucket my-bucket` in
the cron line (or set `S3_BUCKET` in the env file):

```cron
0 3 * * * S3_BUCKET=my-pqc-backups /usr/local/bin/backup-pqc.sh --json >> /var/log/pqc-backup.log 2>&1
```

---

## 4. Monitoring integration

The healthcheck and backup scripts emit grep-friendly lines and
optionally a JSON document. Suggested monitoring patterns:

| Source                                | What to alert on                                                                    |
| ------------------------------------- | ----------------------------------------------------------------------------------- |
| `healthcheck-pqc.sh` cron every 5 min | exit code != 0 for >2 consecutive runs                                              |
| `healthcheck-pqc.sh --json` parsed    | any check with `status=fail`                                                        |
| `pqc-audit.log` (tailable)            | `event` in {`mlock-unavailable`} lasting > 24h suggests Node never got upgraded     |
| `backup-pqc.sh --json` daily          | `fail > 0` in the JSON summary; or no tarball created in 25h                        |
| `journalctl -u pqc-openclaw`          | `[PQC]` event with `status:fail`; or no `[PQC]` events at all in 7d (fork not used) |

For Prometheus, the `healthcheck-pqc.sh --json` output is parseable
by a small textfile collector script. See the example in
`scripts/pqc-textfile-collector.sh` (TODO: add in a follow-up).

---

## 5. When to page the security team

| Symptom                                                                   | Page?                                  | Why                                                                                                 |
| ------------------------------------------------------------------------- | -------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `[FAIL] wrap-key-file: unsafe permissions` (mode 0644 etc)                | **Yes**                                | The wrap key is world-readable. Possible leak. Rotate the key and investigate how the mode changed. |
| `[FAIL] os-keyring: Secret Service entry not found` after a clean install | No                                     | Likely a fresh deployment that has not yet been used. Run `install-pqc.sh` again.                   |
| `[WARN] os-keyring: Secret Service check returned: <error>`               | **Yes** if it persists across restarts | The dbus session or libsecret has a problem; the wrap key is unprotected.                           |
| Sudden drop in `[PQC]` events to zero                                     | No                                     | Could just mean no traffic. Cross-check with normal Gateway traffic.                                |
| `[PQC] MlockUnavailable` reappears after every restart                    | No, but file a follow-up               | Node 22 is expected to lack mlock. Plan a Node 24.15+ upgrade.                                      |
| `journalctl` shows unexpected key access from outside the fork process    | **Yes**                                | Possible compromise. Stop the fork, rotate the key, restore from backup, forensic the host.         |

---

## 6. Reference: full env var inventory

Read by `install-pqc.sh` and the systemd unit (set in
`/etc/pqc-openclaw/pqc-openclaw.env`):

| Var                      | Default                    | Purpose                                               |
| ------------------------ | -------------------------- | ----------------------------------------------------- |
| `OPENCLAW_STATE_DIR`     | `/var/lib/pqc-openclaw`    | sqlite, audit log, key fallback, auth-profile secrets |
| `OPENCLAW_CONFIG_PATH`   | `$STATE_DIR/openclaw.json` | runtime config                                        |
| `OPENCLAW_WORKSPACE_DIR` | `$STATE_DIR/workspace`     | agent workspace scratch                               |
| `OPENCLAW_GATEWAY_TOKEN` | (random 32 bytes)          | client auth                                           |
| `OPENCLAW_WRAP_KEY_FILE` | `$STATE_DIR/wrap-key.b64`  | 32 raw bytes, base64url-encoded                       |
| `OPENCLAW_GATEWAY_PORT`  | `18789`                    | main gateway port                                     |
| `OPENCLAW_GATEWAY_BIND`  | `lan`                      | `lan` / `loopback` / `0.0.0.0`                        |
| `PQC_REQUIRE_MLOCK`      | `0`                        | `1` to fail-closed if mlock unavailable               |
| `PQC_AUDIT_LOG_PATH`     | `$STATE_DIR/pqc-audit.log` | JSONL audit log                                       |
| `PQC_LOG_LEVEL`          | `info`                     | `debug` / `info` / `warn` / `error`                   |

Read by `healthcheck-pqc.sh` (defaults shown):

| Var                   | Default            | Purpose                           |
| --------------------- | ------------------ | --------------------------------- |
| `SERVICE_NAME`        | `pqc-openclaw`     | systemd unit name                 |
| `WRAP_KEY_OS_SERVICE` | `pqc-openclaw`     | Secret Service `application` attr |
| `WRAP_KEY_OS_ACCOUNT` | `wrap-key-current` | Secret Service `username` attr    |

Read by `backup-pqc.sh` (defaults shown):

| Var                | Default                     | Purpose                       |
| ------------------ | --------------------------- | ----------------------------- |
| `BACKUP_DIR`       | `/var/backups/pqc-openclaw` | local tarball dir             |
| `RETENTION_DAILY`  | `7`                         | N daily backups to keep       |
| `RETENTION_WEEKLY` | `4`                         | N weekly backups to keep      |
| `S3_BUCKET`        | (unset)                     | S3 bucket for off-host upload |
| `S3_ENDPOINT`      | (unset)                     | for MinIO/Wasabi/B2           |

---

## 7. See also

- `docs/security/MLOCK.md` — full mlock design + validation
- `docs/security/MLOCK.md` §"Manual mlock validation" — 4 steps to validate mlock on a new host
- `docs/security/MIGRATION.md` — moving an existing upstream OpenClaw deployment to the PQC fork
- `docs/security/PAPER-SUBMISSION-CHECKLIST.md` — paper-grade evidence index
- `docs/security/constant-time-audit.md` — 308-line constant-time self-audit
- `SECURITY.md` — vulnerability disclosure policy
- `PQC-FORK.md` — TL;DR + scope + limitations
- `CHANGELOG.md` — release history
- `pqc-fork-scripts/` — E2E test harnesses (`pqc-fork-e2e-{backup,healthcheck,install,compose}.py`)
