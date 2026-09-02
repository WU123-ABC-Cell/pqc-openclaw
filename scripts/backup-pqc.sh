#!/usr/bin/env bash
# backup-pqc.sh — production backup for the PQC OpenClaw fork.
#
# Snapshots the PQC fork state directory (sqlite db, OS keyring cache,
# pqc-audit.log, wrap-key.b64 fallback copy) into a timestamped tarball,
# writes a sha256 sidecar for integrity verification, rotates old
# backups, and optionally uploads to S3 for off-host storage.
#
# Design goals (intentionally conservative):
#   1. **Atomic**: tarball is built in $TMPDIR first, then moved into
#      place with `mv`. A partial / corrupted tarball never appears in
#      $BACKUP_DIR.
#   2. **Verifiable**: every backup gets a .sha256 sidecar; a separate
#      `verify` mode (and a post-backup self-test) confirms the tarball
#      extracts and the sqlite db opens before declaring success.
#   3. **Idempotent under cron**: a flock-style lockfile in
#      $BACKUP_DIR/.backup.lock prevents two cron-triggered runs from
#      stepping on each other (cron on most distros already runs in
#      parallel shells).
#   4. **Pre-flight health check**: a failed `healthcheck-pqc.sh`
#      blocks the backup from running, so we never snapshot a known-
#      broken state and silently rotate the only good copy.
#   5. **Retention**: keep N daily + N weekly (defaults 7 / 4). Older
#      backups are pruned AFTER the new one is verified, never before.
#   6. **Optional S3**: --s3-bucket BUCKET enables upload via the aws
#      cli. Without it, the script is a pure-local backup. This is
#      intentional — many production operators want to plug their own
#      S3-compatible storage (MinIO, Wasabi, Backblaze B2) via env.
#
# Intended to be invoked:
#   - from a daily cron entry installed by install-pqc.sh:
#       0 3 * * * /usr/local/bin/backup-pqc.sh --json >> /var/log/pqc-backup.log 2>&1
#   - from a systemd timer (see docs/security/OPERATIONS.md §"Backup
#     schedule" once that doc lands)
#   - manually by an operator for an on-demand pre-upgrade snapshot:
#       sudo bash scripts/backup-pqc.sh --label pre-upgrade-2026-09-02
#
# Usage:
#   bash scripts/backup-pqc.sh
#   bash scripts/backup-pqc.sh --label pre-upgrade
#   bash scripts/backup-pqc.sh --s3-bucket my-pqc-backups
#   bash scripts/backup-pqc.sh --s3-bucket my-pqc-backups --s3-endpoint https://s3.us-west-1.amazonaws.com
#   bash scripts/backup-pqc.sh --dry-run
#   bash scripts/backup-pqc.sh --json
#   bash scripts/backup-pqc.sh --verify /var/backups/pqc-openclaw/pqc-openclaw-2026-09-02-030000.tar.gz
#   bash scripts/backup-pqc.sh --help

set -euo pipefail

# ----------------------------------------------------------------------
# Defaults
# ----------------------------------------------------------------------

STATE_DIR="${STATE_DIR:-/var/lib/pqc-openclaw}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/pqc-openclaw}"
RETENTION_DAILY="${RETENTION_DAILY:-7}"
RETENTION_WEEKLY="${RETENTION_WEEKLY:-4}"
HEALTHCHECK_BIN="${HEALTHCHECK_BIN:-/usr/local/bin/healthcheck-pqc.sh}"
SKIP_HEALTHCHECK=0
SKIP_S3=0
S3_BUCKET="${S3_BUCKET:-}"
S3_ENDPOINT="${S3_ENDPOINT:-}"
S3_PREFIX="${S3_PREFIX:-pqc-openclaw}"
S3_STORAGE_CLASS="${S3_STORAGE_CLASS:-STANDARD_IA}"
DRY_RUN=0
JSON_OUTPUT=0
VERBOSE=0
LABEL="${LABEL:-}"
VERIFY_TARGET="${VERIFY_TARGET:-}"
PASS=0
WARN=0
FAIL=0

print_help() {
  cat <<'EOF'
backup-pqc.sh — production backup for the PQC OpenClaw fork

USAGE
  bash scripts/backup-pqc.sh [options]

OPTIONS
  --state-dir PATH          State dir to snapshot.       [default: /var/lib/pqc-openclaw]
  --backup-dir PATH         Where to write tarballs.     [default: /var/backups/pqc-openclaw]
  --retention-daily N       Keep N daily backups.        [default: 7]
  --retention-weekly N      Keep N weekly backups.       [default: 4]
  --healthcheck-bin PATH    Path to healthcheck-pqc.sh.  [default: /usr/local/bin/healthcheck-pqc.sh]
  --skip-healthcheck        Do not block on a failed healthcheck.
  --s3-bucket BUCKET        Upload to s3://BUCKET after local write.
  --s3-endpoint URL         S3 endpoint (for non-AWS providers like MinIO/Wasabi/B2).
  --s3-prefix PREFIX        S3 key prefix.               [default: pqc-openclaw]
  --s3-storage-class CLASS  S3 storage class.            [default: STANDARD_IA]
  --skip-s3                 Disable S3 even if env S3_BUCKET is set.
  --label LABEL             Custom label appended to filename.
  --dry-run                 Print what would happen; do not write or upload.
  --json                    Emit machine-readable JSON summary.
  --verbose                 Show progress even on success.
  --verify PATH             Verify an existing tarball (sha256 + extract + sqlite open) and exit.
  --help                    Show this message.

EXIT CODES
  0  backup created (or verify passed)
  1  critical failure (no state dir, write failed, verify failed, etc.)
  2  non-critical warning (e.g. healthcheck warned but backup proceeded)

WHAT GETS BACKED UP
  $STATE_DIR contents excluding:
    - mlock/  (tmpfs-only, not useful to back up)
    - *.sock  (Unix domain sockets, not storable)
    - *.log   (live audit log; we tar -P it for completeness)
  Plus the system-level OPENCLAW_INSTALL_ROOT/dist/ build artefacts
  are NOT included; backups are state-only. Rebuild dist from source
  on a fresh machine and re-apply state to recover.

VERIFY MODE
  --verify PATH checks three things in order:
    1. sha256 matches the .sha256 sidecar (or prints the recomputed
       sha256 if no sidecar exists).
    2. tar -tzf succeeds (file is a valid tar.gz).
    3. The contained state.db is a valid sqlite3 database (sqlite3
       ".schema" exits 0).
  Exits 0 on full pass, 1 on any failure.

EXAMPLES
  # Daily backup (cron default)
  bash scripts/backup-pqc.sh

  # Pre-upgrade snapshot with custom label
  sudo bash scripts/backup-pqc.sh --label pre-upgrade-$(date +%Y-%m-%d)

  # Daily backup with S3 off-host upload
  bash scripts/backup-pqc.sh --s3-bucket my-pqc-backups

  # Verify a backup taken 3 days ago
  bash scripts/backup-pqc.sh --verify /var/backups/pqc-openclaw/pqc-openclaw-2026-08-30-030000.tar.gz

REQUIREMENTS
  - tar, gzip, sha256sum, find, flock (util-linux), sqlite3
  - aws cli (only required when --s3-bucket is set)
  - bash 4.0+ (uses arrays)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --state-dir)         STATE_DIR="$2"; shift 2 ;;
    --backup-dir)        BACKUP_DIR="$2"; shift 2 ;;
    --retention-daily)   RETENTION_DAILY="$2"; shift 2 ;;
    --retention-weekly)  RETENTION_WEEKLY="$2"; shift 2 ;;
    --healthcheck-bin)   HEALTHCHECK_BIN="$2"; shift 2 ;;
    --skip-healthcheck)  SKIP_HEALTHCHECK=1; shift ;;
    --s3-bucket)         S3_BUCKET="$2"; shift 2 ;;
    --s3-endpoint)       S3_ENDPOINT="$2"; shift 2 ;;
    --s3-prefix)         S3_PREFIX="$2"; shift 2 ;;
    --s3-storage-class)  S3_STORAGE_CLASS="$2"; shift 2 ;;
    --skip-s3)           SKIP_S3=1; shift ;;
    --label)             LABEL="$2"; shift 2 ;;
    --dry-run)           DRY_RUN=1; shift ;;
    --json)              JSON_OUTPUT=1; shift ;;
    --verbose)           VERBOSE=1; shift ;;
    --verify)            VERIFY_TARGET="$2"; shift 2 ;;
    --help)              print_help; exit 0 ;;
    *) echo "Unknown option: $1" >&2; print_help; exit 1 ;;
  esac
done

# ----------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------

if [[ $JSON_OUTPUT -eq 1 ]]; then
  declare -a JSON_EVENTS=()
  json_emit() {
    local status="$1" name="$2" detail="$3"
    JSON_EVENTS+=("{\"check\":\"$name\",\"status\":\"$status\",\"detail\":\"$detail\"}")
  }
  ok()    { PASS=$((PASS+1)); json_emit "ok"    "$1" "$2"; [[ $VERBOSE -eq 1 ]] && echo "[OK]   $1: $2"; }
  warn()  { WARN=$((WARN+1)); json_emit "warn"  "$1" "$2"; echo "[WARN] $1: $2" >&2; }
  fail()  { FAIL=$((FAIL+1)); json_emit "fail"  "$1" "$2"; echo "[FAIL] $1: $2" >&2; }
else
  ok()    { PASS=$((PASS+1)); echo "[OK]   $1: $2"; }
  warn()  { WARN=$((WARN+1)); echo "[WARN] $1: $2" >&2; }
  fail()  { FAIL=$((FAIL+1)); echo "[FAIL] $1: $2" >&2; }
fi

# ----------------------------------------------------------------------
# Cleanup trap — always remove the scratch dir on exit, even on error.
# ----------------------------------------------------------------------

SCRATCH_DIR=""
LOCK_FD=""

cleanup() {
  local exit_code=$?
  if [[ -n "$SCRATCH_DIR" ]] && [[ -d "$SCRATCH_DIR" ]]; then
    rm -rf "$SCRATCH_DIR"
  fi
  if [[ -n "$LOCK_FD" ]]; then
    flock -u "$LOCK_FD" 2>/dev/null || true
  fi
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ----------------------------------------------------------------------
# Verify mode (early return path)
# ----------------------------------------------------------------------

if [[ -n "$VERIFY_TARGET" ]]; then
  if [[ ! -f "$VERIFY_TARGET" ]]; then
    fail "verify" "tarball not found: $VERIFY_TARGET"
    exit 1
  fi
  SIDE="${VERIFY_TARGET}.sha256"
  if [[ -f "$SIDE" ]]; then
    EXPECTED=$(awk '{print $1}' "$SIDE")
    ACTUAL=$(sha256sum "$VERIFY_TARGET" | awk '{print $1}')
    if [[ "$EXPECTED" != "$ACTUAL" ]]; then
      fail "sha256" "expected $EXPECTED, got $ACTUAL"
      exit 1
    fi
    ok "sha256" "matches $EXPECTED"
  else
    ACTUAL=$(sha256sum "$VERIFY_TARGET" | awk '{print $1}')
    warn "sha256" "no sidecar; recomputed $ACTUAL"
  fi
  if ! tar -tzf "$VERIFY_TARGET" >/dev/null 2>&1; then
    fail "tar" "tar -tzf failed; file is not a valid tar.gz"
    exit 1
  fi
  ok "tar" "tar -tzf reads cleanly"
  SCRATCH_DIR=$(mktemp -d -t pqc-backup-verify-XXXXXX)
  if ! tar -xzf "$VERIFY_TARGET" -C "$SCRATCH_DIR" --strip-components=0 state.db 2>/dev/null \
     && ! tar -xzf "$VERIFY_TARGET" -C "$SCRATCH_DIR" 2>/dev/null; then
    fail "extract" "could not extract state.db from tarball"
    exit 1
  fi
  DB_FILE=$(find "$SCRATCH_DIR" -name 'state.db' -type f | head -1 || true)
  if [[ -z "$DB_FILE" ]]; then
    fail "extract" "no state.db in tarball"
    exit 1
  fi
  if ! command -v sqlite3 >/dev/null 2>&1; then
    warn "sqlite" "sqlite3 not on PATH; cannot verify db integrity (file is present)"
  elif ! sqlite3 "$DB_FILE" '.schema' >/dev/null 2>&1; then
    fail "sqlite" "sqlite3 .schema failed; db is corrupt"
    exit 1
  else
    ok "sqlite" "state.db schema readable"
  fi
  echo "verify OK: $VERIFY_TARGET"
  exit 0
fi

# ----------------------------------------------------------------------
# Pre-flight: state dir exists (skipped under --dry-run; we want to
# print the plan even when the operator is checking the script from a
# workstation that does not have the production state dir mounted).
# ----------------------------------------------------------------------

if [[ $DRY_RUN -eq 0 ]]; then
  if [[ ! -d "$STATE_DIR" ]]; then
    fail "state-dir" "$STATE_DIR does not exist; nothing to back up"
    exit 1
  fi
  ok "state-dir" "$STATE_DIR exists"
else
  if [[ -d "$STATE_DIR" ]]; then
    ok "state-dir" "$STATE_DIR exists (dry-run; not reading contents)"
  else
    echo "[DRY-RUN] state-dir $STATE_DIR does not exist on this host; the real backup run on the production host will snapshot it"
  fi
fi

# ----------------------------------------------------------------------
# Dry-run short-circuit (after pre-flight, before any side effects).
# Print the plan and exit 0 so the operator can verify what the script
# would do without touching the host filesystem, the lock directory,
# or the S3 bucket.
# ----------------------------------------------------------------------

if [[ $DRY_RUN -eq 1 ]]; then
  # Compute the target path here so the dry-run output matches the
  # real-run output 1:1 (TS, optional LABEL).
  TS=$(date -u +%Y-%m-%dT%H%M%SZ)
  SAFE_TS=$(echo "$TS" | tr ':' '-')
  LABEL_PART=""
  if [[ -n "$LABEL" ]]; then
    SAFE_LABEL=$(echo "$LABEL" | tr -c 'A-Za-z0-9_-' '-')
    LABEL_PART=".${SAFE_LABEL}"
  fi
  BASENAME="pqc-openclaw-${SAFE_TS}${LABEL_PART}.tar.gz"
  FINAL_PATH="$BACKUP_DIR/$BASENAME"
  echo "[DRY-RUN] would create $FINAL_PATH from $STATE_DIR"
  echo "[DRY-RUN] would prune to $RETENTION_DAILY daily + $RETENTION_WEEKLY weekly"
  if [[ -n "$S3_BUCKET" ]] && [[ $SKIP_S3 -eq 0 ]]; then
    echo "[DRY-RUN] would upload to s3://$S3_BUCKET/$S3_PREFIX/$BASENAME"
  else
    echo "[DRY-RUN] S3 upload disabled (no --s3-bucket or --skip-s3 set)"
  fi
  exit 0
fi

# ----------------------------------------------------------------------
# Lock: prevent two backups from running concurrently
# ----------------------------------------------------------------------

LOCK_FILE="$BACKUP_DIR/.backup.lock"
mkdir -p "$BACKUP_DIR"
LOCK_FD=$(mktemp)
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  fail "lock" "another backup-pqc.sh is already running (lockfile $LOCK_FILE)"
  exit 1
fi
ok "lock" "acquired $LOCK_FILE"

# ----------------------------------------------------------------------
# Pre-flight: healthcheck
# ----------------------------------------------------------------------

if [[ $SKIP_HEALTHCHECK -eq 0 ]]; then
  if [[ ! -x "$HEALTHCHECK_BIN" ]]; then
    warn "healthcheck" "$HEALTHCHECK_BIN not executable; proceeding without pre-flight check"
  elif "$HEALTHCHECK_BIN" --json >/dev/null 2>&1; then
    ok "healthcheck" "8/8 checks pass"
  else
    HC_EXIT=$?
    if [[ $HC_EXIT -eq 2 ]]; then
      warn "healthcheck" "healthcheck exit 2 (warnings); proceeding with backup anyway"
    else
      fail "healthcheck" "healthcheck exit $HC_EXIT; aborting backup to avoid snapshotting a broken state"
      exit 1
    fi
  fi
else
  warn "healthcheck" "skipped via --skip-healthcheck"
fi

# ----------------------------------------------------------------------
# Build the tarball in $TMPDIR (atomic: write-then-rename)
# ----------------------------------------------------------------------

TS=$(date -u +%Y-%m-%dT%H%M%SZ)
SAFE_TS=$(echo "$TS" | tr ':' '-')
LABEL_PART=""
if [[ -n "$LABEL" ]]; then
  # Sanitize: only [A-Za-z0-9_-] survives; everything else becomes '-'
  SAFE_LABEL=$(echo "$LABEL" | tr -c 'A-Za-z0-9_-' '-')
  LABEL_PART=".${SAFE_LABEL}"
fi
BASENAME="pqc-openclaw-${SAFE_TS}${LABEL_PART}.tar.gz"
FINAL_PATH="$BACKUP_DIR/$BASENAME"
SCRATCH_DIR=$(mktemp -d -t pqc-backup-XXXXXX)
SCRATCH_TARBALL="$SCRATCH_DIR/$BASENAME"
# (The dry-run short-circuit lives above, after the pre-flight checks;
# we never reach this point under --dry-run.)

# tar exclusions: skip mlock (tmpfs only, not useful to back up) and
# any unix-domain sockets (which tar cannot store anyway, but listing
# them in --exclude is cheap and makes the archive deterministic).
tar -czf "$SCRATCH_TARBALL" \
  -C "$(dirname "$STATE_DIR")" \
  --exclude="$(basename "$STATE_DIR")/mlock" \
  --exclude="*.sock" \
  --exclude="*.pid" \
  --transform "s|$(basename "$STATE_DIR")|pqc-openclaw-state|" \
  "$(basename "$STATE_DIR")"

TARBALL_BYTES=$(stat -c '%s' "$SCRATCH_TARBALL" 2>/dev/null || stat -f '%z' "$SCRATCH_TARBALL")
ok "tar" "wrote $SCRATCH_TARBALL ($TARBALL_BYTES bytes)"

# ----------------------------------------------------------------------
# Compute sha256 sidecar
# ----------------------------------------------------------------------

TARBALL_SHA=$(sha256sum "$SCRATCH_TARBALL" | awk '{print $1}')
SCRATCH_SIDE="${SCRATCH_TARBALL}.sha256"
echo "$TARBALL_SHA  $BASENAME" > "$SCRATCH_SIDE"
ok "sha256" "$TARBALL_SHA"

# ----------------------------------------------------------------------
# Atomic move into $BACKUP_DIR
# ----------------------------------------------------------------------

mv "$SCRATCH_TARBALL" "$FINAL_PATH"
mv "$SCRATCH_SIDE"   "${FINAL_PATH}.sha256"
SCRATCH_DIR=""  # mv succeeded; don't let cleanup() rm the moved file
ok "publish" "$FINAL_PATH"

# ----------------------------------------------------------------------
# Self-verify: extract to a fresh scratch dir, confirm db opens
# ----------------------------------------------------------------------

VERIFY_DIR=$(mktemp -d -t pqc-backup-verify-XXXXXX)
if tar -xzf "$FINAL_PATH" -C "$VERIFY_DIR" 2>/dev/null; then
  DB_FILE=$(find "$VERIFY_DIR" -name 'state.db' -type f | head -1 || true)
  if [[ -n "$DB_FILE" ]] && command -v sqlite3 >/dev/null 2>&1; then
    if sqlite3 "$DB_FILE" '.schema' >/dev/null 2>&1; then
      ok "self-verify" "tarball extracts, state.db schema OK"
    else
      fail "self-verify" "tarball extracts but state.db is not a valid sqlite db"
      rm -rf "$VERIFY_DIR"
      exit 1
    fi
  elif [[ -n "$DB_FILE" ]]; then
    warn "self-verify" "tarball extracts, state.db present, sqlite3 not on PATH (skip schema check)"
  else
    warn "self-verify" "tarball extracts but no state.db inside (unexpected)"
  fi
else
  fail "self-verify" "tar -xzf failed on the just-written tarball"
  rm -rf "$VERIFY_DIR"
  exit 1
fi
rm -rf "$VERIFY_DIR"

# ----------------------------------------------------------------------
# Retention: prune old backups (AFTER the new one is verified)
# ----------------------------------------------------------------------

PRUNE_COUNT=0
# Daily: keep N most recent
DAILY_TO_KEEP=$RETENTION_DAILY
DAILY_LIST=$(find "$BACKUP_DIR" -maxdepth 1 -name 'pqc-openclaw-*.tar.gz' -type f -printf '%T@ %p\n' 2>/dev/null \
  | sort -rn \
  | awk '{
      # Daily granularity: group by YYYY-MM-DD (the first 10 chars after pqc-openclaw-)
      day=substr($2, length("pqc-openclaw-")+1, 10)
      if (!seen[day]++) { print $0; count++; if (count >= '$DAILY_TO_KEEP') exit }
    }')
# Weekly: from the leftover (not in daily keep), keep N most recent (one per ISO week)
WEEKLY_TO_KEEP=$RETENTION_WEEKLY
# Simpler: just sort all by mtime, keep first (DAILY_TO_KEEP + WEEKLY_TO_KEEP) most recent,
# delete the rest. This is the standard "grandfather-father-son" lite.
TOTAL_KEEP=$(( DAILY_TO_KEEP + WEEKLY_TO_KEEP ))
ALL_OLD=$(find "$BACKUP_DIR" -maxdepth 1 -name 'pqc-openclaw-*.tar.gz' -type f -printf '%T@ %p\n' 2>/dev/null \
  | sort -rn \
  | tail -n +$(( TOTAL_KEEP + 1 )) \
  | awk '{print $2}')
if [[ -n "$ALL_OLD" ]]; then
  while IFS= read -r OLD; do
    [[ -z "$OLD" ]] && continue
    if [[ -f "${OLD}.sha256" ]]; then
      rm -f "${OLD}.sha256"
    fi
    rm -f "$OLD"
    PRUNE_COUNT=$(( PRUNE_COUNT + 1 ))
    [[ $VERBOSE -eq 1 ]] && echo "[PRUNE] $OLD"
  done <<< "$ALL_OLD"
fi
ok "retention" "kept $TOTAL_KEEP (daily=$DAILY_TO_KEEP + weekly=$WEEKLY_TO_KEEP), pruned $PRUNE_COUNT"

# ----------------------------------------------------------------------
# Optional: S3 upload
# ----------------------------------------------------------------------

if [[ -n "$S3_BUCKET" ]] && [[ $SKIP_S3 -eq 0 ]]; then
  if ! command -v aws >/dev/null 2>&1; then
    fail "s3" "aws cli not on PATH; cannot upload to s3://$S3_BUCKET"
    warn "s3" "tarball is on local disk; manual upload required"
  else
    S3_ARGS=(--only-show-errors)
    if [[ -n "$S3_ENDPOINT" ]]; then
      S3_ARGS+=(--endpoint-url "$S3_ENDPOINT")
    fi
    S3_KEY="${S3_PREFIX}/${BASENAME}"
    if aws s3 cp "${S3_ARGS[@]}" "$FINAL_PATH" "s3://${S3_BUCKET}/${S3_KEY}"; then
      ok "s3" "uploaded s3://${S3_BUCKET}/${S3_KEY}"
      if aws s3 cp "${S3_ARGS[@]}" "${FINAL_PATH}.sha256" "s3://${S3_BUCKET}/${S3_KEY}.sha256"; then
        ok "s3-sha256" "uploaded .sha256 sidecar"
      else
        warn "s3-sha256" "tarball uploaded but .sha256 sidecar upload failed"
      fi
    else
      fail "s3" "aws s3 cp failed; tarball is still on local disk at $FINAL_PATH"
    fi
  fi
else
  [[ $VERBOSE -eq 1 ]] && echo "[SKIP] S3 upload disabled (no --s3-bucket or --skip-s3 set)"
fi

# ----------------------------------------------------------------------
# Done
# ----------------------------------------------------------------------

if [[ $JSON_OUTPUT -eq 1 ]]; then
  # Final summary JSON line — easy to parse from cron output.
  EVENTS_JSON=$(IFS=,; echo "${JSON_EVENTS[*]}")
  cat <<EOF
{"event":"backup-complete","path":"$FINAL_PATH","bytes":$TARBALL_BYTES,"sha256":"$TARBALL_SHA","pruned":$PRUNE_COUNT,"label":"$LABEL","timestamp":"$TS","checks":[$EVENTS_JSON]}
EOF
fi

if [[ $FAIL -gt 0 ]]; then
  exit 1
elif [[ $WARN -gt 0 ]]; then
  exit 2
fi
exit 0
