#!/usr/bin/env bash
# healthcheck-pqc.sh — production health check for the PQC OpenClaw fork.
#
# Verifies:
#   1. Node.js version is in the supported range
#   2. PQC fork process is running
#   3. /healthz HTTP endpoint responds
#   4. state.db (SQLite) is accessible
#   5. Wrap key file exists and is mode 0600/0400
#   6. OS keyring entry exists (if not --skip-keyring)
#   7. process or native-addon mlock is available, otherwise warn
#   8. PQC events appear in journal (if systemd-managed)
#
# Exit codes:
#   0  all checks passed
#   1  one or more critical checks failed (fork unhealthy, key missing)
#   2  non-critical warnings (for example, no mlock backend)
#
# Output is grep-friendly: each line starts with [OK], [WARN], or [FAIL].
# Designed for use in:
#   - operator-configured systemd or cron monitoring
#   - cron + monitoring (Prometheus node_exporter textfile collector)
#   - CI pre-deploy verification
#
# Usage:
#   bash scripts/healthcheck-pqc.sh
#   bash scripts/healthcheck-pqc.sh --skip-keyring
#   bash scripts/healthcheck-pqc.sh --port 18789
#   bash scripts/healthcheck-pqc.sh --state-dir /var/lib/pqc-openclaw
#   bash scripts/healthcheck-pqc.sh --json   # machine-readable output

set -uo pipefail

# ----------------------------------------------------------------------
# Defaults
# ----------------------------------------------------------------------

PORT="${PORT:-18789}"
STATE_DIR="${STATE_DIR:-/var/lib/pqc-openclaw}"
INSTALL_ROOT="${INSTALL_ROOT:-/opt/pqc-openclaw}"
SERVICE_NAME="${SERVICE_NAME:-pqc-openclaw}"
WRAP_KEY_FILE="${WRAP_KEY_FILE:-$STATE_DIR/wrap-key.b64}"
WRAP_KEY_OS_SERVICE="${WRAP_KEY_OS_SERVICE:-pqc-openclaw}"
# Detect OS once so the checks below (which compare against $OS) actually
# run on Linux + macOS. Without this, ${OS:-} defaults to "" and every
# `[[ $OS == "linux" ]]` evaluates false, silently skipping check 6
# (wrap-key-file), check 7 (os-keyring platform branch), and check 8
# (journal). The ${OS:-} form was a defense for set -u but it masked
# the fact that $OS was never populated.
case "$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]')" in
  linux*)  OS=linux ;;
  darwin*) OS=macos ;;
  *)       OS=unknown ;;
esac
WRAP_KEY_OS_ACCOUNT="${WRAP_KEY_OS_ACCOUNT:-wrap-key-current}"
SKIP_KEYRING=0
JSON_OUTPUT=0
VERBOSE=0

PASS=0
WARN=0
FAIL=0

print_help() {
  cat <<'EOF'
healthcheck-pqc.sh — production health check for the PQC OpenClaw fork

USAGE
  bash scripts/healthcheck-pqc.sh [options]

OPTIONS
  --port PORT          Gateway port.            [default: 18789]
  --state-dir PATH     State dir.               [default: /var/lib/pqc-openclaw]
  --install-root PATH  Where the fork is installed. [default: /opt/pqc-openclaw]
  --service-name NAME  systemd service name.    [default: pqc-openclaw]
  --wrap-key-file PATH Wrap key file path.      [default: $STATE_DIR/wrap-key.b64]
  --wrap-key-os-service SVC  OS keyring service. [default: pqc-openclaw]
  --wrap-key-os-account ACCT  OS keyring account. [default: wrap-key-current]
  --skip-keyring       Skip OS keyring check (file keyring only).
  --json               Emit machine-readable JSON.
  --verbose            Show check details even on success.
  --help               Show this message.

EXIT CODES
  0  all checks passed
  1  critical check failed (fork unhealthy, key missing)
  2  non-critical warnings (for example, no mlock backend)

OUTPUT
  Each line is prefixed with [OK], [WARN], or [FAIL] for easy grep.
  Use --json for Prometheus / Nagios / monitoring integration.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)               PORT="$2"; shift 2 ;;
    --state-dir)          STATE_DIR="$2"; shift 2 ;;
    --install-root)       INSTALL_ROOT="$2"; shift 2 ;;
    --service-name)       SERVICE_NAME="$2"; shift 2 ;;
    --wrap-key-file)      WRAP_KEY_FILE="$2"; shift 2 ;;
    --wrap-key-os-service) WRAP_KEY_OS_SERVICE="$2"; shift 2 ;;
    --wrap-key-os-account) WRAP_KEY_OS_ACCOUNT="$2"; shift 2 ;;
    --skip-keyring)       SKIP_KEYRING=1; shift ;;
    --json)               JSON_OUTPUT=1; shift ;;
    --verbose)            VERBOSE=1; shift ;;
    --help)               print_help; exit 0 ;;
    *) echo "Unknown option: $1" >&2; print_help; exit 1 ;;
  esac
done

# ----------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------

if [[ $JSON_OUTPUT -eq 1 ]]; then
  # JSON output: accumulate results, emit one document on stdout at the end.
  # Escape operator-controlled paths and command output so a quote, backslash,
  # tab, or newline cannot corrupt the machine-readable contract.
  declare -a JSON_RESULTS=()
  json_escape() {
    local value="$1"
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\n'/\\n}
    value=${value//$'\r'/\\r}
    value=${value//$'\t'/\\t}
    printf '%s' "$value"
  }
  json_emit() {
    local status="$1" name="$2" detail="$3"
    JSON_RESULTS+=("{\"check\":\"$(json_escape "$name")\",\"status\":\"$(json_escape "$status")\",\"detail\":\"$(json_escape "$detail")\"}")
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
# Check 1: Node.js version is in the supported range
# ----------------------------------------------------------------------

if ! command -v node >/dev/null 2>&1; then
  fail "node" "node not on PATH"
elif ! node -e 'process.exit(0)' >/dev/null 2>&1; then
  fail "node" "node --version failed"
else
  NODE_VER=$(node --version 2>/dev/null | sed 's/^v//')
  # Accept any of 22.22.3+, 24.15+, 25.9+ — use string compare (bash
  # arithmetic can't handle "22.23.1" since it has a non-numeric component).
  NODE_OK=0
  case "$NODE_VER" in
    22.22.3 | 22.22.* | 22.23.* | 22.24.* | 22.25.* | 22.26.* | 22.27.* | 22.28.* | 22.29.*) NODE_OK=1 ;;
    24.15.* | 24.16.* | 24.17.* | 24.18.* | 24.19.* | 24.2* | 24.3*)  NODE_OK=1 ;;
    25.9.* | 25.10.* | 25.11.* | 25.12.* | 25.13.* | 25.14.* | 25.15.* | 25.16.* | 25.17.* | 25.18.* | 25.19.* | 25.2*) NODE_OK=1 ;;
  esac
  if [[ $NODE_OK -eq 1 ]]; then
    ok "node-version" "v$NODE_VER (supported)"
  else
    fail "node-version" "v$NODE_VER (need 22.22.3+, 24.15+, or 25.9+)"
  fi
fi

# ----------------------------------------------------------------------
# Check 2: feature-detected mlock availability — non-critical warning
# ----------------------------------------------------------------------

if [[ -d "$INSTALL_ROOT" ]] && [[ -f "$INSTALL_ROOT/src/security/mlock-helper.ts" ]]; then
  if node -e 'process.exit(typeof process.mlock === "function" && typeof process.munlock === "function" ? 0 : 1)' >/dev/null 2>&1; then
    ok "mlock" "process.mlock/process.munlock available"
  elif [[ -f "$INSTALL_ROOT/src/security/native/mlock-addon.cjs" ]] && (
    cd "$INSTALL_ROOT" &&
      node -e 'const addon=require("./src/security/native/mlock-addon.cjs"); process.exit(addon.isAvailable() ? 0 : 1)'
  ) >/dev/null 2>&1; then
    ok "mlock" "native N-API mlock backend available"
  else
    warn "mlock" "process and native mlock backends unavailable; wrap key is not pinned in physical RAM"
  fi
else
  warn "mlock" "install root not found; skipping mlock check"
fi

# ----------------------------------------------------------------------
# Check 3: fork process is running
# ----------------------------------------------------------------------

if pgrep -af "dist/index.js gateway" >/dev/null 2>&1; then
  PIDS=$(pgrep -f "dist/index.js gateway" | head -3 | tr '\n' ' ')
  ok "fork-process" "running (PIDs: $PIDS)"
elif [[ "${OS:-}" == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    warn "fork-process" "systemd says $SERVICE_NAME is active but no 'dist/index.js gateway' process found (restart loop?)"
  else
    fail "fork-process" "no fork process running, systemd service $SERVICE_NAME not active"
  fi
else
  fail "fork-process" "no fork process running"
fi

# ----------------------------------------------------------------------
# Check 4: /healthz HTTP endpoint responds
# ----------------------------------------------------------------------

if command -v curl >/dev/null 2>&1; then
  HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/healthz" 2>/dev/null || echo "000")
  case "$HTTP_CODE" in
    200) ok "healthz" "GET /healthz returned 200" ;;
    000) fail "healthz" "GET /healthz timed out or connection refused (port $PORT)" ;;
    *)   fail "healthz" "GET /healthz returned $HTTP_CODE" ;;
  esac
else
  warn "healthz" "curl not available; skipping HTTP check"
fi

# ----------------------------------------------------------------------
# Check 5: state.db (SQLite) is accessible
# ----------------------------------------------------------------------

if [[ -f "$STATE_DIR/state/openclaw.sqlite" ]]; then
  if command -v sqlite3 >/dev/null 2>&1; then
    if sqlite3 "$STATE_DIR/state/openclaw.sqlite" "PRAGMA integrity_check;" 2>/dev/null | grep -q "^ok$"; then
      SIZE=$(stat -c %s "$STATE_DIR/state/openclaw.sqlite" 2>/dev/null || stat -f %z "$STATE_DIR/state/openclaw.sqlite" 2>/dev/null)
      ok "state-db" "integrity ok, ${SIZE} bytes"
    else
      fail "state-db" "SQLite integrity_check failed (corruption?)"
    fi
  else
    ok "state-db" "file present (sqlite3 cli not available for deeper check)"
  fi
else
  warn "state-db" "not found at $STATE_DIR/state/openclaw.sqlite"
fi

# ----------------------------------------------------------------------
# Check 6: wrap key file exists with safe permissions
# ----------------------------------------------------------------------

if [[ -f "$WRAP_KEY_FILE" ]]; then
  if [[ "${OS:-}" == "linux" || "${OS:-}" == "macos" ]]; then
    if command -v stat >/dev/null 2>&1; then
      MODE=$(stat -c %a "$WRAP_KEY_FILE" 2>/dev/null || stat -f %p "$WRAP_KEY_FILE" 2>/dev/null | tail -c 4)
      # POSIX bits: world-readable is a security hole
      if [[ "${MODE: -1}" =~ [0-7] ]] && (( MODE & 0o077 )); then
        fail "wrap-key-file" "file $WRAP_KEY_FILE has unsafe permissions (mode=$MODE); expected 0600 or 0400"
      else
        SIZE=$(stat -c %s "$WRAP_KEY_FILE" 2>/dev/null || stat -f %z "$WRAP_KEY_FILE" 2>/dev/null)
        ok "wrap-key-file" "$WRAP_KEY_FILE mode=$MODE size=${SIZE}b"
      fi
    fi
  fi
else
  fail "wrap-key-file" "not found at $WRAP_KEY_FILE (run scripts/install-pqc.sh to provision)"
fi

# ----------------------------------------------------------------------
# Check 7: OS keyring entry exists (Linux libsecret, macOS Keychain)
# ----------------------------------------------------------------------

if [[ $SKIP_KEYRING -eq 0 ]]; then
  if [[ "${OS:-}" == "macos" ]]; then
    if command -v security >/dev/null 2>&1; then
      # macOS Keychain lookup. service=generic, account=service
      if security find-generic-password -s "$WRAP_KEY_OS_SERVICE" -a "$WRAP_KEY_OS_ACCOUNT" >/dev/null 2>&1; then
        ok "os-keyring" "macOS Keychain entry found (service=$WRAP_KEY_OS_SERVICE, account=$WRAP_KEY_OS_ACCOUNT)"
      else
        fail "os-keyring" "macOS Keychain entry not found (service=$WRAP_KEY_OS_SERVICE, account=$WRAP_KEY_OS_ACCOUNT)"
      fi
    else
      warn "os-keyring" "macOS 'security' cli not available; cannot check Keychain"
    fi
  elif [[ "${OS:-}" == "linux" ]]; then
    if command -v python3 >/dev/null 2>&1 && python3 -c 'import secretstorage' 2>/dev/null; then
      KEYRING_OK=$(python3 -c "
import secretstorage
conn = secretstorage.dbus_init()
for coll in conn.get_all_collections():
    for item in coll.get_all_items():
        attrs = item.get_attributes()
        if attrs.get('application') == '${WRAP_KEY_OS_SERVICE}' and attrs.get('username') == '${WRAP_KEY_OS_ACCOUNT}':
            print('ok')
            exit(0)
print('missing')
" 2>/dev/null)
      case "$KEYRING_OK" in
        ok)      ok "os-keyring" "Secret Service entry found (service=$WRAP_KEY_OS_SERVICE, account=$WRAP_KEY_OS_ACCOUNT)" ;;
        missing) fail "os-keyring" "Secret Service entry not found (run scripts/install-pqc.sh to provision)" ;;
        *)       warn "os-keyring" "Secret Service check returned: $KEYRING_OK" ;;
      esac
    else
      warn "os-keyring" "python3 + secretstorage not available; cannot check Secret Service. Install with: pip install secretstorage"
    fi
  fi
else
  ok "os-keyring" "skipped (--skip-keyring)"
fi

# ----------------------------------------------------------------------
# Check 8: PQC events in journal (if systemd-managed)
# ----------------------------------------------------------------------

if [[ "${OS:-}" == "linux" ]] && command -v journalctl >/dev/null 2>&1; then
  PQC_COUNT=$(journalctl -u "$SERVICE_NAME" --since "1 hour ago" 2>/dev/null | grep -c '\[PQC\]' || true)
  PQC_OK_COUNT=$(journalctl -u "$SERVICE_NAME" --since "1 hour ago" 2>/dev/null | grep -c '\[PQC\].*status:ok' || true)
  PQC_FAIL_COUNT=$(journalctl -u "$SERVICE_NAME" --since "1 hour ago" 2>/dev/null | grep -c '\[PQC\].*status:fail' || true)
  if [[ $PQC_COUNT -gt 0 ]]; then
    if [[ $PQC_FAIL_COUNT -gt 0 ]]; then
      warn "pqc-events" "$PQC_COUNT [PQC] events in last hour ($PQC_OK_COUNT ok, $PQC_FAIL_COUNT fail)"
    else
      ok "pqc-events" "$PQC_COUNT [PQC] events in last hour (all $PQC_OK_COUNT ok)"
    fi
  else
    warn "pqc-events" "no [PQC] events in last hour (fork not used yet?)"
  fi
else
  warn "pqc-events" "journalctl not available (non-systemd or non-Linux)"
fi

# ----------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------

if [[ $JSON_OUTPUT -eq 1 ]]; then
  if [[ $FAIL -gt 0 ]]; then
    OVERALL_STATUS=fail
  elif [[ $WARN -gt 0 ]]; then
    OVERALL_STATUS=warn
  else
    OVERALL_STATUS=ok
  fi
  printf '{"schemaVersion":1,"status":"%s","summary":{"pass":%d,"warn":%d,"fail":%d},"checks":[%s]}\n' \
    "$OVERALL_STATUS" "$PASS" "$WARN" "$FAIL" \
    "$(IFS=,; echo "${JSON_RESULTS[*]}")"
else
  echo ""
  echo "=========================================="
  echo "PQC fork healthcheck summary"
  echo "=========================================="
  echo "  pass: $PASS"
  echo "  warn: $WARN"
  echo "  fail: $FAIL"
  echo "=========================================="
fi

if [[ $FAIL -gt 0 ]]; then
  exit 1  # critical
elif [[ $WARN -gt 0 ]]; then
  exit 2  # non-critical
else
  exit 0  # all green
fi
