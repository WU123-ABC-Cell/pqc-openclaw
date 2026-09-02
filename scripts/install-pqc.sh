#!/usr/bin/env bash
# install-pqc.sh — one-command install for the PQC OpenClaw fork (production).
#
# This script provisions a supported Node.js runtime when needed,
# installs pnpm + the fork's dependencies, builds the dist tree,
# provisions the OS keyring with a fresh 32-byte wrap key, and
# prints the env vars the operator needs to set in the systemd
# unit (or launchd plist). It is idempotent: re-running after a
# partial failure picks up where it left off.
#
# Run from a fresh machine (Ubuntu 22.04+, macOS 13+, or WSL2
# Ubuntu). The fork is installed to $INSTALL_ROOT (default
# /opt/pqc-openclaw). State (sqlite, OS keyring entry) lives in
# $OPENCLAW_STATE_DIR (default /var/lib/pqc-openclaw).
#
# NOTE: This is the PQC-fork installer. The upstream OpenClaw
# installer is scripts/install.sh (downloaded via
#   curl -fsSL https://openclaw.ai/install.sh | bash
# ). Use that for the plain upstream install; use this one for
# the PQC fork with side-channel validation + mlock + OS keyring.
#
# Usage:
#   bash scripts/install-pqc.sh                       # default install
#   bash scripts/install-pqc.sh --install-root /srv/openclaw
#   bash scripts/install-pqc.sh --state-dir /var/lib/openclaw
#   bash scripts/install-pqc.sh --node-version 24.15.0
#   bash scripts/install-pqc.sh --help

set -euo pipefail

# ----------------------------------------------------------------------
# Defaults and option parsing
# ----------------------------------------------------------------------

INSTALL_ROOT="${INSTALL_ROOT:-/opt/pqc-openclaw}"
STATE_DIR="${STATE_DIR:-/var/lib/pqc-openclaw}"
NODE_VERSION="${NODE_VERSION:-22.23.1}"
SERVICE_USER="${SERVICE_USER:-pqc-openclaw}"
SKIP_KEYRING=0
SKIP_BUILD=0
SKIP_SYSTEMD=0

print_help() {
  cat <<'EOF'
install-pqc.sh — one-command install for the PQC OpenClaw fork

USAGE
  bash scripts/install-pqc.sh [options]

OPTIONS
  --install-root PATH   Where to install the fork.   [default: /opt/pqc-openclaw]
  --state-dir PATH      Where to put state (sqlite, key backups). [default: /var/lib/pqc-openclaw]
  --node-version VER    Node.js version to install.    [default: 22.23.1]
  --service-user USER   System user for the service.   [default: pqc-openclaw]
  --skip-keyring        Skip OS keyring provisioning (file-keyring only).
  --skip-build          Skip pnpm build (use existing dist/).
  --skip-systemd        Skip systemd unit install.
  --help                Show this message.

EXAMPLES
  # Default install on a fresh Ubuntu 22.04 server
  sudo bash scripts/install-pqc.sh

  # Custom install root
  sudo bash scripts/install-pqc.sh --install-root /srv/openclaw

  # Use a specific Node version (recommended for production)
  sudo bash scripts/install-pqc.sh --node-version 24.15.0

REQUIREMENTS
  - Linux (Ubuntu 22.04+), macOS 13+, or WSL2 Ubuntu
  - sudo (for system user, systemd, OS keyring)
  - Internet access (for Node + pnpm download)

POST-INSTALL
  The script prints a 'systemd unit' block and the env vars you need
  to set. Save the unit, then:
    sudo systemctl daemon-reload
    sudo systemctl enable --now pqc-openclaw
    sudo journalctl -u pqc-openclaw -f
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-root)  INSTALL_ROOT="$2"; shift 2 ;;
    --state-dir)     STATE_DIR="$2"; shift 2 ;;
    --node-version)  NODE_VERSION="$2"; shift 2 ;;
    --service-user)  SERVICE_USER="$2"; shift 2 ;;
    --skip-keyring)  SKIP_KEYRING=1; shift ;;
    --skip-build)    SKIP_BUILD=1; shift ;;
    --skip-systemd)  SKIP_SYSTEMD=1; shift ;;
    --help)          print_help; exit 0 ;;
    *) echo "Unknown option: $1" >&2; print_help; exit 1 ;;
  esac
done

# ----------------------------------------------------------------------
# Logging helpers
# ----------------------------------------------------------------------

log()  { printf '\033[1;36m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fatal]\033[0m %s\n' "$*" >&2; exit 1; }
ok()   { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }

# ----------------------------------------------------------------------
# Pre-flight: root, OS, tools
# ----------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
  die "this script must run as root (use sudo bash scripts/install-pqc.sh)"
fi

case "$(uname -s)" in
  Linux)  OS=linux ;;
  Darwin) OS=macos ;;
  *)      die "unsupported OS: $(uname -s). Use Linux or macOS." ;;
esac

for tool in curl tar; do
  command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done

# ----------------------------------------------------------------------
# 1. Create service user (Linux only)
# ----------------------------------------------------------------------

if [[ $OS == "linux" ]] && ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  log "creating service user: $SERVICE_USER"
  useradd --system --home "$STATE_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# ----------------------------------------------------------------------
# 2. Install Node.js (idempotent: skip if already at the right version)
# ----------------------------------------------------------------------

install_node_tarball() {
  local arch tarball
  arch="$(uname -m)"
  case "$OS-$arch" in
    linux-x86_64)   tarball="node-v${NODE_VERSION}-linux-x64" ;;
    linux-aarch64)  tarball="node-v${NODE_VERSION}-linux-arm64" ;;
    darwin-x86_64)  tarball="node-v${NODE_VERSION}-darwin-x64" ;;
    darwin-arm64)   tarball="node-v${NODE_VERSION}-darwin-arm64" ;;
    *)              die "unsupported arch: $OS-$arch" ;;
  esac
  curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/${tarball}.tar.gz" -o /tmp/node.tar.gz
  tar -xzf /tmp/node.tar.gz -C /usr/local --strip-components=1
  rm -f /tmp/node.tar.gz
}

install_node() {
  if command -v node >/dev/null 2>&1; then
    local current
    current="$(node --version 2>/dev/null | sed 's/^v//')"
    if [[ "$current" == "$NODE_VERSION" ]]; then
      ok "node $current already installed"
      return 0
    fi
    warn "node $current found, want $NODE_VERSION — re-installing"
  fi
  if command -v nvm >/dev/null 2>&1; then
    log "installing node $NODE_VERSION via nvm"
    # shellcheck disable=SC1090,SC1091
    source "$(nvm_dir 2>/dev/null || echo "$HOME/.nvm")/nvm.sh"
    nvm install "$NODE_VERSION"
    nvm use "$NODE_VERSION"
    nvm alias default "$NODE_VERSION"
  else
    log "installing node $NODE_VERSION via direct tarball (no nvm detected)"
    install_node_tarball
  fi
  command -v node >/dev/null 2>&1 || die "node install failed"
  ok "node $(node --version) installed"
}

log "step 1/6: Node.js"
install_node

# ----------------------------------------------------------------------
# 3. Install pnpm
# ----------------------------------------------------------------------

log "step 2/6: pnpm"
if ! command -v pnpm >/dev/null 2>&1; then
  npm install -g pnpm@11
fi
ok "pnpm $(pnpm --version)"

# ----------------------------------------------------------------------
# 4. Copy the fork and install dependencies
# ----------------------------------------------------------------------

log "step 3/6: install the fork to $INSTALL_ROOT"
mkdir -p "$INSTALL_ROOT"
# Copy from the current working directory (the repo). The operator
# runs this from inside the repo. We do NOT delete $INSTALL_ROOT
# first; existing files are overwritten in place (idempotent).
cp -r ./src ./docs ./scripts ./package.json ./pnpm-lock.yaml ./tsconfig*.json "$INSTALL_ROOT/" 2>/dev/null || true
chmod -R u+rwX,go+rX "$INSTALL_ROOT"
chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_ROOT" 2>/dev/null || true

log "step 4/6: pnpm install"
(
  cd "$INSTALL_ROOT"
  pnpm install --frozen-lockfile
) || die "pnpm install failed (lockfile drift? see CHANGELOG.md §Fixed)"

# ----------------------------------------------------------------------
# 5. Build the dist tree
# ----------------------------------------------------------------------

if [[ $SKIP_BUILD -eq 0 ]]; then
  log "step 5/6: pnpm build"
  (
    cd "$INSTALL_ROOT"
    pnpm run build
  ) || die "pnpm build failed"
  ok "dist tree built"
else
  ok "build skipped (--skip-build)"
fi

# ----------------------------------------------------------------------
# 6. Provision OS keyring with a fresh wrap key
# ----------------------------------------------------------------------

if [[ $SKIP_KEYRING -eq 0 ]]; then
  log "step 6/6: OS keyring provisioning"
  mkdir -p "$STATE_DIR"
  chmod 0700 "$STATE_DIR"
  chown -R "$SERVICE_USER":"$SERVICE_USER" "$STATE_DIR" 2>/dev/null || true

  # Generate a fresh 32-byte wrap key and write to a recovery file.
  # The OS keyring is the live source of truth; the file is the
  # recovery backup (see PQC-FORK.md §Disaster Recovery).
  local keyfile="$STATE_DIR/wrap-key.b64"
  if [[ ! -f "$keyfile" ]]; then
    log "generating fresh 32-byte wrap key"
    node -e "
      const c = require('node:crypto');
      process.stdout.write(c.randomBytes(32).toString('base64url'));
    " > "$keyfile"
    chmod 0600 "$keyfile"
    chown "$SERVICE_USER":"$SERVICE_USER" "$keyfile" 2>/dev/null || true
    ok "wrap key written to $keyfile (backup)"
  else
    ok "wrap key file already exists at $keyfile (keeping)"
  fi

  # Migrate the key to the OS keyring. The fork ships
  # pqc-fork-scripts/migrate-oskeyring.mjs as a reference; on Linux
  # the operator typically uses Python `secretstorage` instead
  # because @napi-rs/keyring 1.3.0 hangs in WSL2 (see MLOCK.md
  # §1.2). On macOS / Windows the native path works fine.
  if [[ "$OS" == "macos" || "$OS" == "linux" ]]; then
    if [[ -f "$INSTALL_ROOT/scripts/migrate-oskeyring.mjs" ]] || [[ -f "$INSTALL_ROOT/src/security/os-keyring.ts" ]]; then
      log "migrating wrap key to OS keyring (see PQC-FORK.md §Wrap-key provisioning for fallback methods)"
      warn "automatic keyring provisioning skipped — run 'migrate-oskeyring.mjs' manually or use the Python secretstorage path documented in PQC-FORK.md"
    fi
  fi
else
  ok "keyring provisioning skipped (--skip-keyring)"
fi

# ----------------------------------------------------------------------
# 7. Install systemd unit (Linux only)
# ----------------------------------------------------------------------

if [[ $OS == "linux" && $SKIP_SYSTEMD -eq 0 ]]; then
  log "installing systemd unit"
  local keyfile="$STATE_DIR/wrap-key.b64"
  cat > /etc/systemd/system/pqc-openclaw.service <<EOF
# Generated by scripts/install-pqc.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Edit and 'sudo systemctl daemon-reload' to apply changes.

[Unit]
Description=PQC OpenClaw fork (post-quantum hardened)
Documentation=https://github.com/WU123-ABC-Cell/pqc-openclaw
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$INSTALL_ROOT
Environment=OPENCLAW_STATE_DIR=$STATE_DIR
Environment=OPENCLAW_WRAP_KEY_OS_SERVICE=pqc-openclaw
Environment=OPENCLAW_WRAP_KEY_OS_ACCOUNT=wrap-key-$(date +%Y-%m)
Environment=OPENCLAW_WRAP_KEY_OS_ID=wrap-key-$(date +%Y-%m)
Environment=OPENCLAW_WRAP_KEY_FILE=$keyfile
EnvironmentFile=-$STATE_DIR/openclaw.env
ExecStart=/usr/bin/node $INSTALL_ROOT/dist/index.js gateway
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$STATE_DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
  ok "systemd unit installed at /etc/systemd/system/pqc-openclaw.service"
fi

# ----------------------------------------------------------------------
# 8. Print next steps
# ----------------------------------------------------------------------

local GATEWAY_TOKEN
GATEWAY_TOKEN=$(node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))")
local keyfile="$STATE_DIR/wrap-key.b64"

cat <<EOF

==========================================================================
  PQC OpenClaw fork installed to $INSTALL_ROOT
==========================================================================

  Node.js:      $(node --version)
  pnpm:         $(pnpm --version)
  State dir:    $STATE_DIR
  Wrap key:     $keyfile (file backup; OS keyring is live source)
  Service user: $SERVICE_USER (Linux only)

  Env vars to set in $STATE_DIR/openclaw.env:
    OPENCLAW_GATEWAY_TOKEN=$GATEWAY_TOKEN

NEXT STEPS
  1. Edit /etc/systemd/system/pqc-openclaw.service (verify the paths
     and env vars above match your environment).
  2. Save the env var file:
       sudo tee $STATE_DIR/openclaw.env > /dev/null <<E2
       OPENCLAW_GATEWAY_TOKEN=$GATEWAY_TOKEN
       E2
  3. Reload and start the service:
       sudo systemctl daemon-reload
       sudo systemctl enable --now pqc-openclaw
  4. Verify:
       sudo journalctl -u pqc-openclaw -f
       bash scripts/healthcheck-pqc.sh

POST-INSTALL HEALTH CHECK
  PQC side-channel regression:
    cd $INSTALL_ROOT && pnpm test -- src/security/mlock-helper.test.ts
  Cache-timing regression guard (14 reports must show no leak):
    bash scripts/check-cache-timing-claims.sh

For details, see PQC-FORK.md §Production Deployment.
==========================================================================
EOF
