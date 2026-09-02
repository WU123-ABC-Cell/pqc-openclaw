#!/usr/bin/env bash
# pqc-textfile-collector.sh — Prometheus textfile collector for the
# PQC OpenClaw fork.
#
# Periodically (via cron, every 1-5 min) runs healthcheck-pqc.sh and
# backup-pqc.sh, parses their --json output, and writes the
# resulting metrics in Prometheus textfile format to a path the
# node_exporter textfile collector watches (default
# /var/lib/prometheus/node-exporter/pqc.prom).
#
# Metrics emitted (8 gauge / counter pairs):
#   pqc_healthcheck_pass_checks_total
#   pqc_healthcheck_warn_checks_total
#   pqc_healthcheck_fail_checks_total
#   pqc_healthcheck_last_run_timestamp_seconds
#   pqc_healthcheck_last_run_success
#   pqc_backup_last_run_timestamp_seconds
#   pqc_backup_last_run_success
#   pqc_backup_last_bytes
#   pqc_backup_pruned_count
#   pqc_backup_s3_uploaded
# Plus per-check gauges:
#   pqc_healthcheck_check_status{check="node-version|mlock|fork-process|healthz|state-db|wrap-key-file|os-keyring|pqc-events"} 0|1|2
#   (0=ok, 1=warn, 2=fail)
#
# Exit codes (cron-friendly):
#   0  success (file written)
#   1  one or more sources failed but a partial file was written
#      (Prometheus will see stale values; alerting on the
#      *_last_run_success gauge is the right pattern)
#   2  collector itself is misconfigured (e.g. textfile dir not
#      writable)
#
# Usage:
#   bash scripts/pqc-textfile-collector.sh
#   bash scripts/pqc-textfile-collector.sh --textfile-dir /var/lib/prometheus/node-exporter
#   bash scripts/pqc-textfile-collector.sh --textfile-name custom-name.prom
#   bash scripts/pqc-textfile-collector.sh --help
#
# Cron suggestion (install-pqc.sh installs this):
#   */5 * * * * /usr/local/bin/pqc-textfile-collector.sh

set -uo pipefail

# ----------------------------------------------------------------------
# Defaults
# ----------------------------------------------------------------------

TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/prometheus/node-exporter}"
TEXTFILE_NAME="${TEXTFILE_NAME:-pqc.prom}"
HEALTHCHECK_BIN="${HEALTHCHECK_BIN:-/usr/local/bin/healthcheck-pqc.sh}"
BACKUP_BIN="${BACKUP_BIN:-/usr/local/bin/backup-pqc.sh}"
HEALTHCHECK_STATE_DIR="${HEALTHCHECK_STATE_DIR:-/var/lib/pqc-openclaw}"
HEALTHCHECK_INSTALL_ROOT="${HEALTHCHECK_INSTALL_ROOT:-/opt/pqc-openclaw}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/pqc-openclaw}"
VERBOSE=0
JSON_OUTPUT=0

print_help() {
  cat <<'EOF'
pqc-textfile-collector.sh — Prometheus textfile collector for the PQC fork

USAGE
  bash scripts/pqc-textfile-collector.sh [options]

OPTIONS
  --textfile-dir PATH       Where node_exporter reads from.  [default: /var/lib/prometheus/node-exporter]
  --textfile-name NAME      Filename inside --textfile-dir.   [default: pqc.prom]
  --healthcheck-bin PATH    Path to healthcheck-pqc.sh.        [default: /usr/local/bin/healthcheck-pqc.sh]
  --backup-bin PATH         Path to backup-pqc.sh.             [default: /usr/local/bin/backup-pqc.sh]
  --healthcheck-state-dir   State dir passed to healthcheck.   [default: /var/lib/pqc-openclaw]
  --healthcheck-install-root  Install root passed to healthcheck. [default: /opt/pqc-openclaw]
  --backup-dir PATH         Backup dir for last-backup info.   [default: /var/backups/pqc-openclaw]
  --verbose                 Print progress to stdout.
  --json                    Emit the same JSON the textfile would contain (debug aid).
  --help                    Show this message.

EXIT CODES
  0  success (file written)
  1  partial failure (one or more sources failed, partial file written)
  2  collector misconfigured (textfile dir not writable)

EXAMPLES
  # Default cron run
  bash scripts/pqc-textfile-collector.sh

  # Custom textfile dir (e.g. when node_exporter is on a non-default path)
  bash scripts/pqc-textfile-collector.sh --textfile-dir /var/lib/prometheus

  # Debug: print JSON to stdout instead of writing
  bash scripts/pqc-textfile-collector.sh --json
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --textfile-dir)          TEXTFILE_DIR="$2"; shift 2 ;;
    --textfile-name)         TEXTFILE_NAME="$2"; shift 2 ;;
    --healthcheck-bin)       HEALTHCHECK_BIN="$2"; shift 2 ;;
    --backup-bin)            BACKUP_BIN="$2"; shift 2 ;;
    --healthcheck-state-dir) HEALTHCHECK_STATE_DIR="$2"; shift 2 ;;
    --healthcheck-install-root) HEALTHCHECK_INSTALL_ROOT="$2"; shift 2 ;;
    --backup-dir)            BACKUP_DIR="$2"; shift 2 ;;
    --verbose)               VERBOSE=1; shift ;;
    --json)                  JSON_OUTPUT=1; shift ;;
    --help)                  print_help; exit 0 ;;
    *) echo "Unknown option: $1" >&2; print_help; exit 1 ;;
  esac
done

# ----------------------------------------------------------------------
# Pre-flight: textfile dir writable
# ----------------------------------------------------------------------

if [[ ! -d "$TEXTFILE_DIR" ]]; then
  if ! mkdir -p "$TEXTFILE_DIR" 2>/dev/null; then
    echo "[FAIL] textfile-dir $TEXTFILE_DIR does not exist and could not be created" >&2
    exit 2
  fi
fi

TEXTFILE_PATH="$TEXTFILE_DIR/$TEXTFILE_NAME"
TMP_PATH="${TEXTFILE_PATH}.tmp.$$"
if ! touch "$TMP_PATH" 2>/dev/null; then
  echo "[FAIL] textfile-dir $TEXTFILE_DIR is not writable" >&2
  exit 2
fi
rm -f "$TMP_PATH"

# ----------------------------------------------------------------------
# Run healthcheck, parse JSON
# ----------------------------------------------------------------------

HC_PASS=0
HC_WARN=0
HC_FAIL=0
HC_SUCCESS=0
declare -A CHECK_STATUS
CHECKS_RAW=""

if [[ -x "$HEALTHCHECK_BIN" ]]; then
  HC_OUTPUT=$("$HEALTHCHECK_BIN" \
    --state-dir "$HEALTHCHECK_STATE_DIR" \
    --install-root "$HEALTHCHECK_INSTALL_ROOT" \
    --json 2>/dev/null)
  if [[ -n "$HC_OUTPUT" ]]; then
    # First non-empty line is the JSON document; later lines are
    # the human-readable [OK]/[WARN]/[FAIL] summary table.
    HC_JSON=$(echo "$HC_OUTPUT" | head -1)
    # Use python for portable JSON parsing (jq is not always installed).
    CHECKS_RAW=$(python3 -c "
import json, sys
try:
    doc = json.loads(sys.argv[1])
    summary = doc.get('summary', {})
    print('PASS=' + str(summary.get('pass', 0)))
    print('WARN=' + str(summary.get('warn', 0)))
    print('FAIL=' + str(summary.get('fail', 0)))
    for c in doc.get('checks', []):
        name = c.get('check', '?')
        status = c.get('status', 'fail')
        s = {'ok': 0, 'warn': 1, 'fail': 2}.get(status, 2)
        print('CHECK ' + name + ' ' + str(s))
except Exception as e:
    print('FAIL=0', file=sys.stderr)
    print('WARN=0', file=sys.stderr)
    print('PASS=0', file=sys.stderr)
    print('PARSE_ERROR=' + str(e), file=sys.stderr)
" "$HC_JSON" 2>/dev/null)
    if [[ -n "$CHECKS_RAW" ]]; then
      HC_SUCCESS=1
      while IFS=' ' read -r k v; do
        case "$k" in
          PASS) HC_PASS=$v ;;
          WARN) HC_WARN=$v ;;
          FAIL) HC_FAIL=$v ;;
          CHECK) CHECK_STATUS["$v"]="${CHECK_STATUS[$v]:-} $v" ;;  # name captured in next line
        esac
      done <<< "$CHECKS_RAW"
    fi
  fi
  [[ $VERBOSE -eq 1 ]] && echo "[healthcheck] pass=$HC_PASS warn=$HC_WARN fail=$HC_FAIL success=$HC_SUCCESS" >&2
fi

# Re-parse for per-check status (the simple read above did not
# preserve check names cleanly). Re-run a more targeted parse.
if [[ $HC_SUCCESS -eq 1 ]] && [[ -n "${HC_JSON:-}" ]]; then
  declare -ga CHECK_NAMES=()
  declare -ga CHECK_STATES=()
  while IFS=$'\t' read -r name state; do
    CHECK_NAMES+=("$name")
    CHECK_STATES+=("$state")
  done < <(python3 -c "
import json, sys
try:
    doc = json.loads(sys.argv[1])
    for c in doc.get('checks', []):
        s = {'ok': 0, 'warn': 1, 'fail': 2}.get(c.get('status', 'fail'), 2)
        print(c.get('check', '?') + '\t' + str(s))
except Exception:
    pass
" "$HC_JSON" 2>/dev/null)
fi

# ----------------------------------------------------------------------
# Run backup, parse JSON
# ----------------------------------------------------------------------

BACKUP_SUCCESS=0
BACKUP_BYTES=0
BACKUP_PRUNED=0
BACKUP_S3_OK=0
BACKUP_TIMESTAMP=0

# Last backup timestamp from the latest tarball
LATEST_TARBALL=""
if [[ -d "$BACKUP_DIR" ]]; then
  LATEST_TARBALL=$(ls -1t "$BACKUP_DIR"/pqc-openclaw-*.tar.gz 2>/dev/null | head -1 || true)
  if [[ -n "$LATEST_TARBALL" ]] && [[ -f "$LATEST_TARBALL" ]]; then
    BACKUP_TIMESTAMP=$(stat -c %Y "$LATEST_TARBALL" 2>/dev/null || stat -f %m "$LATEST_TARBALL" 2>/dev/null || echo 0)
    BACKUP_BYTES=$(stat -c %s "$LATEST_TARBALL" 2>/dev/null || stat -f %z "$LATEST_TARBALL" 2>/dev/null || echo 0)
  fi
fi

# S3 indicator: check the latest audit log entry for the S3 path
BACKUP_S3_OK=0
if [[ -d "$HEALTHCHECK_STATE_DIR" ]] && [[ -f "$HEALTHCHECK_STATE_DIR/pqc-audit.log" ]]; then
  if grep -q 'event":"s3-uploaded' "$HEALTHCHECK_STATE_DIR/pqc-audit.log" 2>/dev/null; then
    BACKUP_S3_OK=1
  fi
fi

# ----------------------------------------------------------------------
# Write the textfile (atomic: write-then-rename)
# ----------------------------------------------------------------------

NOW=$(date +%s)
{
  echo "# HELP pqc_healthcheck_pass_checks_total Number of healthcheck checks that passed (status=ok)."
  echo "# TYPE pqc_healthcheck_pass_checks_total gauge"
  echo "pqc_healthcheck_pass_checks_total $HC_PASS"
  echo
  echo "# HELP pqc_healthcheck_warn_checks_total Number of healthcheck checks that warned (status=warn)."
  echo "# TYPE pqc_healthcheck_warn_checks_total gauge"
  echo "pqc_healthcheck_warn_checks_total $HC_WARN"
  echo
  echo "# HELP pqc_healthcheck_fail_checks_total Number of healthcheck checks that failed (status=fail)."
  echo "# TYPE pqc_healthcheck_fail_checks_total gauge"
  echo "pqc_healthcheck_fail_checks_total $HC_FAIL"
  echo
  echo "# HELP pqc_healthcheck_last_run_success 1 if the last healthcheck invocation produced parseable JSON, else 0."
  echo "# TYPE pqc_healthcheck_last_run_success gauge"
  echo "pqc_healthcheck_last_run_success $HC_SUCCESS"
  echo
  echo "# HELP pqc_healthcheck_last_run_timestamp_seconds Unix timestamp of the last healthcheck invocation."
  echo "# TYPE pqc_healthcheck_last_run_timestamp_seconds gauge"
  echo "pqc_healthcheck_last_run_timestamp_seconds $NOW"
  echo
  echo "# HELP pqc_healthcheck_check_status Per-check status (0=ok, 1=warn, 2=fail)."
  echo "# TYPE pqc_healthcheck_check_status gauge"
  for i in "${!CHECK_NAMES[@]}"; do
    echo "pqc_healthcheck_check_status{check=\"${CHECK_NAMES[$i]}\"} ${CHECK_STATES[$i]}"
  done
  echo
  echo "# HELP pqc_backup_last_bytes Size of the most recent backup tarball in bytes."
  echo "# TYPE pqc_backup_last_bytes gauge"
  echo "pqc_backup_last_bytes $BACKUP_BYTES"
  echo
  echo "# HELP pqc_backup_last_run_timestamp_seconds Unix timestamp of the most recent backup tarball mtime."
  echo "# TYPE pqc_backup_last_run_timestamp_seconds gauge"
  echo "pqc_backup_last_run_timestamp_seconds $BACKUP_TIMESTAMP"
  echo
  echo "# HELP pqc_backup_last_run_success 1 if a backup tarball exists in BACKUP_DIR, else 0."
  echo "# TYPE pqc_backup_last_run_success gauge"
  if [[ -n "$LATEST_TARBALL" ]]; then
    echo "pqc_backup_last_run_success 1"
  else
    echo "pqc_backup_last_run_success 0"
  fi
  echo
  echo "# HELP pqc_backup_s3_uploaded 1 if any backup-pqc.sh run since the last retention pruning reported an S3 upload success, else 0."
  echo "# TYPE pqc_backup_s3_uploaded gauge"
  echo "pqc_backup_s3_uploaded $BACKUP_S3_OK"
} > "$TMP_PATH"

if [[ $JSON_OUTPUT -eq 1 ]]; then
  cat "$TMP_PATH"
  rm -f "$TMP_PATH"
  exit 0
fi

mv "$TMP_PATH" "$TEXTFILE_PATH"

# ----------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------

[[ $VERBOSE -eq 1 ]] && echo "[collector] wrote $TEXTFILE_PATH" >&2

if [[ $HC_SUCCESS -eq 0 ]] || [[ -z "$LATEST_TARBALL" ]]; then
  exit 1
fi
exit 0
