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

After a default production run of `bash scripts/install-pqc.sh` on Linux:

| Path                                       | What it is                                               | Why it is there                                          |
| ------------------------------------------ | -------------------------------------------------------- | -------------------------------------------------------- |
| `/opt/pqc-openclaw/`                       | committed source tree plus the generated build           | `INSTALL_ROOT`, the systemd unit's `WorkingDirectory`    |
| `/var/lib/pqc-openclaw/`                   | state root, mode-0600 `wrap-key.b64`, and `openclaw.env` | `STATE_DIR`; runtime data is created beneath it          |
| `/var/backups/pqc-openclaw/`               | local backup tarballs + `.sha256` sidecars               | default `BACKUP_DIR`; scheduling is operator-managed     |
| `/etc/systemd/system/pqc-openclaw.service` | generated systemd unit                                   | written by the installer; fixed service name             |
| `/usr/local/bin/healthcheck-pqc.sh`        | 8-check health probe                                     | installed wrapper; invoke from monitoring as desired     |
| `/usr/local/bin/backup-pqc.sh`             | on-demand backup runner                                  | installed wrapper; no scheduler is created automatically |
| `/usr/local/bin/pqc-textfile-collector.sh` | Prometheus textfile collector                            | installed wrapper; no scheduler is created automatically |
| `OPENCLAW_GATEWAY_TOKEN` env var           | gateway client auth                                      | set in `$STATE_DIR/openclaw.env` (mode 0600)             |
| `OPENCLAW_WRAP_KEY_FILE` env var           | path to the file-backed 32-byte wrap key                 | set directly in the generated unit                       |

The systemd unit loads `$STATE_DIR/openclaw.env` before
starting the gateway. **Do not** edit env vars in the unit file
directly — `install-pqc.sh` will overwrite them on the next run.
The installer does not migrate the wrap key into an OS keyring; that
remains an explicit operator action because it may require an interactive unlock.

---

## 1. Day-2 tasks (the ones you will actually do)

### 1.1 Check whether the fork is up

```sh
sudo systemctl status pqc-openclaw
sudo bash /usr/local/bin/healthcheck-pqc.sh --json --skip-keyring
```

A healthy default file-backed deployment reports `fail: 0`. The pass/warn
split depends on optional host capabilities and whether the gateway has emitted
PQC events. Do not infer mlock availability from the Node major version: the
Linux native addon is the current fallback on supported builds.

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

| Event               | When                         | What it tells you                                                                                     |
| ------------------- | ---------------------------- | ----------------------------------------------------------------------------------------------------- |
| `mlock`             | When a cached key is locked  | the runtime or native addon reported a successful lock                                                |
| `munlock`           | When the keyring releases it | the cached key was zeroed and an unlock was attempted                                                 |
| `mlock-unavailable` | Once per process             | neither the runtime hook nor native addon could lock the key; the service may continue with a warning |

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

### 1.4 Roll back to a known-good commit

```sh
# 1. snapshot current state
sudo bash /usr/local/bin/backup-pqc.sh --label pre-rollback-$(date +%Y-%m-%d)

# 2. From a separate source checkout, select a verified commit. The installed
#    tree is created with git archive and intentionally has no .git directory.
sudo systemctl stop pqc-openclaw
git -C /srv/pqc-openclaw-source fetch --tags
git -C /srv/pqc-openclaw-source checkout <known-good-commit>
sudo bash /srv/pqc-openclaw-source/scripts/install-pqc.sh

# 3. restart
sudo systemctl start pqc-openclaw
sudo bash /usr/local/bin/healthcheck-pqc.sh
```

Record and verify the rollback commit before the maintenance window. Do not
assume a particular release tag exists.

### 1.5 Rotate the wrap key (destructive until migration tooling exists)

There is no supported in-place ciphertext rewrapping command yet. Replacing or
deleting the current key makes data encrypted with it unreadable, including in
old backups. Do not improvise a rotation during an incident. Stop the service,
take and verify a backup, preserve the old key under the incident retention
policy, and use a reviewed migration procedure before switching keys. If loss of
all existing encrypted secrets is explicitly acceptable, treat new-key
provisioning as a destructive reinitialization and document that decision.

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
# Check an OS keyring only if this deployment was explicitly migrated to one:
sudo -u pqc-openclaw secret-tool lookup service pqc-openclaw username wrap-key-current

# Otherwise recover the exact key file from a verified backup.
```

Generating a fresh key does not recover existing ciphertext. If every retained
copy of the old key is gone, the affected encrypted data is unrecoverable.

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
  set -a; source /var/lib/pqc-openclaw/openclaw.env; set +a
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

### 2.5 `[WARN] mlock: process and native addon unavailable`

The wrap key is **not** pinned and may be swapped. This warning says nothing
about whether the file or OS-keyring source is configured. On Linux, rebuild the
checked-in native addon and run the standalone 32-byte roundtrip described in
`docs/security/MLOCK.md`. There is no documented `PQC_REQUIRE_MLOCK` switch;
do not suppress the warning by inventing one.

---

## 3. Backup hygiene

### 3.1 Verify a backup before relying on it

```sh
sudo bash /usr/local/bin/backup-pqc.sh --verify /var/backups/pqc-openclaw/pqc-openclaw-2026-09-02-030000.tar.gz
```

A passing verify means the sha256 matches, the tar archive reads cleanly, and
the current `$STATE_DIR/state/openclaw.sqlite` (or a legacy `state.db`) passes
`PRAGMA integrity_check`. The same check runs before a newly created archive is
published, so failed validation does not leave a corrupt tarball among the
available restore points.

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

The installer does not create a scheduler. After validating the command, an
operator may add a cron entry such as:

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
| `pqc-audit.log` (tailable)            | repeated `mlock-unavailable` means neither locking backend is active                |
| `backup-pqc.sh --json` daily          | `fail > 0` in the JSON summary; or no tarball created in 25h                        |
| `journalctl -u pqc-openclaw`          | `[PQC]` event with `status:fail`; or no `[PQC]` events at all in 7d (fork not used) |

For Prometheus, use `scripts/pqc-textfile-collector.sh`. The installer copies the
wrapper to `/usr/local/bin`, but scheduling and node_exporter configuration are
operator-managed.

---

## 5. When to page the security team

| Symptom                                                                         | Page?                                  | Why                                                                                                 |
| ------------------------------------------------------------------------------- | -------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `[FAIL] wrap-key-file: unsafe permissions` (mode 0644 etc)                      | **Yes**                                | The wrap key is world-readable. Possible leak. Rotate the key and investigate how the mode changed. |
| `[FAIL] os-keyring: Secret Service entry not found` after a file-backed install | No                                     | Expected until explicit OS-keyring migration; monitor with `--skip-keyring` meanwhile.              |
| `[WARN] os-keyring: Secret Service check returned: <error>`                     | **Yes** if it persists across restarts | The dbus session or libsecret has a problem; the wrap key is unprotected.                           |
| Sudden drop in `[PQC]` events to zero                                           | No                                     | Could just mean no traffic. Cross-check with normal Gateway traffic.                                |
| `[PQC] mlock-unavailable` reappears after every restart                         | No, but file a follow-up               | Rebuild or diagnose the native addon; changing Node alone does not enable `process.mlock`.          |
| `journalctl` shows unexpected key access from outside the fork process          | **Yes**                                | Possible compromise. Stop the fork, rotate the key, restore from backup, forensic the host.         |

---

## 6. Reference: full env var inventory

Values written or referenced by the generated systemd unit:

| Var                            | Default                   | Purpose                                               |
| ------------------------------ | ------------------------- | ----------------------------------------------------- |
| `OPENCLAW_STATE_DIR`           | `/var/lib/pqc-openclaw`   | sqlite, audit log, key fallback, auth-profile secrets |
| `OPENCLAW_GATEWAY_TOKEN`       | (random 32 bytes)         | client auth                                           |
| `OPENCLAW_WRAP_KEY_FILE`       | `$STATE_DIR/wrap-key.b64` | 32 raw bytes, base64url-encoded                       |
| `OPENCLAW_WRAP_KEY_OS_SERVICE` | `pqc-openclaw`            | optional OS-keyring service identifier                |
| `OPENCLAW_WRAP_KEY_OS_ACCOUNT` | `wrap-key-YYYY-MM`        | generated OS-keyring account identifier               |
| `OPENCLAW_WRAP_KEY_OS_ID`      | `wrap-key-YYYY-MM`        | generated OS-keyring key id                           |

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
- `scripts/pqc-e2e/` — self-contained deploy harnesses used by CI and local verification
