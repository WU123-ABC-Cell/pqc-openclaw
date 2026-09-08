#!/usr/bin/env bash
# install-pqc.sh — one-command install for the PQC OpenClaw fork (production).
#
# This script provisions a supported Node.js runtime when needed,
# installs pnpm + the fork's dependencies, builds the dist tree,
# provisions a file-backed fresh 32-byte wrap key, renders a Linux systemd
# unit, and creates the gateway-token environment file. It is idempotent:
# re-running after a
# partial failure picks up where it left off.
#
# Run from a fresh machine (Ubuntu 22.04+, macOS 13+, or WSL2
# Ubuntu). The managed service path is implemented for Linux; macOS requires
# manual service configuration. The fork is installed to $INSTALL_ROOT (default
# /opt/pqc-openclaw). State and the default file-backed key live in
# $OPENCLAW_STATE_DIR (default /var/lib/pqc-openclaw).
#
# NOTE: This is the PQC-fork installer. The upstream OpenClaw
# installer is scripts/install.sh (downloaded via
#   curl -fsSL https://openclaw.ai/install.sh | bash
# ). Use that for the plain upstream install; use this one for
# the PQC fork. OS-keyring migration remains an explicit operator step.
#
# Usage:
#   bash scripts/install-pqc.sh                       # default install
#   bash scripts/install-pqc.sh --install-root /srv/openclaw
#   bash scripts/install-pqc.sh --state-dir /var/lib/openclaw
#   bash scripts/install-pqc.sh --node-version 24.15.0
#   bash scripts/install-pqc.sh --help

set -euo pipefail
umask 077

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
SANDBOX_ROOT=""

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
  --sandbox-root PATH   Install and build inside an empty 0700 test root.
  --skip-keyring        Skip wrap-key file provisioning.
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
  - root for a production install (system user, /opt, /usr/local, systemd)
  - Internet access (for Node + pnpm download)

POST-INSTALL
  On Linux the script writes the systemd unit and gateway-token env file.
  Review them, then:
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
    --sandbox-root)  SANDBOX_ROOT="$2"; shift 2 ;;
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

case "$(uname -s)" in
  Linux)  OS=linux ;;
  Darwin) OS=macos ;;
  *)      die "unsupported OS: $(uname -s). Use Linux or macOS." ;;
esac

for tool in curl git tar; do
  command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done

SOURCE_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || die "run this installer from a Git checkout"
SOURCE_ROOT=$(cd "$SOURCE_ROOT" && pwd -P)

if [[ -n "$SANDBOX_ROOT" ]]; then
  [[ $OS == "linux" ]] || die "--sandbox-root is supported on Linux only"
  [[ "$SANDBOX_ROOT" == /* ]] || die "--sandbox-root must be an absolute path"
  [[ -d "$SANDBOX_ROOT" && ! -L "$SANDBOX_ROOT" ]] || die "--sandbox-root must be an existing directory, not a symlink"
  SANDBOX_ROOT=$(cd "$SANDBOX_ROOT" && pwd -P)
  [[ "$SANDBOX_ROOT" != "/" ]] || die "--sandbox-root must not be /"
  [[ $(stat -c %u "$SANDBOX_ROOT") == "$EUID" ]] || die "--sandbox-root must be owned by the current user"
  [[ $(stat -c %a "$SANDBOX_ROOT") == "700" ]] || die "--sandbox-root must have mode 0700"
  [[ -z $(find "$SANDBOX_ROOT" -mindepth 1 -maxdepth 1 -print -quit) ]] || die "--sandbox-root must be empty"

  INSTALL_ROOT="$SANDBOX_ROOT/opt/pqc-openclaw"
  STATE_DIR="$SANDBOX_ROOT/var/lib/pqc-openclaw"
  BIN_DIR="$SANDBOX_ROOT/usr/local/bin"
  SYSTEMD_UNIT_DIR="$SANDBOX_ROOT/etc/systemd/system"
  SERVICE_USER=$(id -un)
else
  if [[ $EUID -ne 0 ]]; then
    die "this script must run as root (use sudo bash scripts/install-pqc.sh)"
  fi
  BIN_DIR="/usr/local/bin"
  SYSTEMD_UNIT_DIR="/etc/systemd/system"
fi

# ----------------------------------------------------------------------
# 1. Create service user (Linux only)
# ----------------------------------------------------------------------

if [[ -z "$SANDBOX_ROOT" && $OS == "linux" ]] && ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
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
    if [[ -n "$SANDBOX_ROOT" ]]; then
      die "sandbox mode requires existing node $NODE_VERSION (found $current)"
    fi
    warn "node $current found, want $NODE_VERSION — re-installing"
  fi
  if [[ -n "$SANDBOX_ROOT" ]]; then
    die "sandbox mode requires node $NODE_VERSION in PATH"
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
PNPM_VERSION=$(node -e '
  const value = require(process.argv[1]).packageManager || "";
  const match = /^pnpm@([^+]+)/.exec(value);
  if (!match) process.exit(1);
  process.stdout.write(match[1]);
' "$SOURCE_ROOT/package.json") || die "package.json does not pin packageManager to pnpm"
if ! command -v pnpm >/dev/null 2>&1; then
  [[ -z "$SANDBOX_ROOT" ]] || die "sandbox mode requires pnpm $PNPM_VERSION in PATH"
  npm install -g "pnpm@$PNPM_VERSION"
fi
CURRENT_PNPM_VERSION=$(pnpm --version)
[[ "$CURRENT_PNPM_VERSION" == "$PNPM_VERSION" ]] || die "pnpm $CURRENT_PNPM_VERSION found, require pinned $PNPM_VERSION"
ok "pnpm $CURRENT_PNPM_VERSION"

# ----------------------------------------------------------------------
# 4. Copy the fork and install dependencies
# ----------------------------------------------------------------------

log "step 3/6: install the fork to $INSTALL_ROOT"
mkdir -p "$INSTALL_ROOT"
INSTALL_ROOT=$(cd "$INSTALL_ROOT" && pwd -P)
case "$INSTALL_ROOT/" in
  "$SOURCE_ROOT/"*) die "--install-root must be outside the source checkout" ;;
esac

# Install exactly the committed tree. This includes the complete pnpm
# workspace (packages/, extensions/, patches/, pnpm-workspace.yaml, and build
# configuration) without copying .git, node_modules, ignored build output, or
# unrelated untracked files that may contain operator secrets.
if ! git -C "$SOURCE_ROOT" diff --quiet || ! git -C "$SOURCE_ROOT" diff --cached --quiet; then
  warn "source checkout has uncommitted changes; installing committed HEAD only"
fi
git -C "$SOURCE_ROOT" archive --format=tar HEAD | tar -xf - -C "$INSTALL_ROOT"
chmod -R u+rwX,go+rX "$INSTALL_ROOT"
if [[ -z "$SANDBOX_ROOT" ]]; then
  chown -R "$SERVICE_USER" "$INSTALL_ROOT" || die "failed to assign install tree to $SERVICE_USER"
fi

log "installing operator wrappers to $BIN_DIR"
mkdir -p "$BIN_DIR"
for wrapper in healthcheck-pqc.sh backup-pqc.sh pqc-textfile-collector.sh; do
  install -m 0755 "$INSTALL_ROOT/scripts/$wrapper" "$BIN_DIR/$wrapper"
done

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
# 6. Provision a fresh file-backed wrap key
# ----------------------------------------------------------------------

mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"
if [[ -z "$SANDBOX_ROOT" ]]; then
  chown -R "$SERVICE_USER" "$STATE_DIR" || die "failed to assign state directory to $SERVICE_USER"
fi

if [[ $SKIP_KEYRING -eq 0 ]]; then
  log "step 6/6: wrap-key file provisioning"

  # Generate a fresh 32-byte wrap key. The generated service unit uses this
  # file directly; operators can migrate it to a platform keyring separately.
  keyfile="$STATE_DIR/wrap-key.b64"
  if [[ ! -f "$keyfile" ]]; then
    log "generating fresh 32-byte wrap key"
    node -e "
      const c = require('node:crypto');
      process.stdout.write(c.randomBytes(32).toString('base64url'));
    " > "$keyfile"
    chmod 0600 "$keyfile"
    if [[ -z "$SANDBOX_ROOT" ]]; then
      chown "$SERVICE_USER" "$keyfile" || die "failed to assign wrap key to $SERVICE_USER"
    fi
    ok "wrap key written to $keyfile (backup)"
  else
    ok "wrap key file already exists at $keyfile (keeping)"
  fi

  # OS-keyring migration remains an explicit operator step because it can
  # require an interactive platform unlock prompt.
  if [[ "$OS" == "macos" || "$OS" == "linux" ]]; then
    if [[ -f "$INSTALL_ROOT/scripts/migrate-oskeyring.mjs" ]] || [[ -f "$INSTALL_ROOT/src/security/os-keyring.ts" ]]; then
      warn "automatic OS-keyring migration skipped; follow PQC-FORK.md §Wrap-key provisioning if required"
    fi
  fi
else
  ok "keyring provisioning skipped (--skip-keyring)"
fi

# ----------------------------------------------------------------------
# 7. Install systemd unit (Linux only)
# ----------------------------------------------------------------------

if [[ $OS == "linux" && $SKIP_SYSTEMD -eq 0 ]]; then
  log "rendering systemd unit"
  keyfile="$STATE_DIR/wrap-key.b64"
  NODE_BIN=$(command -v node)
  [[ "$NODE_BIN" == /* ]] || die "node executable path must be absolute"
  mkdir -p "$SYSTEMD_UNIT_DIR"
  cat > "$SYSTEMD_UNIT_DIR/pqc-openclaw.service" <<EOF
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
ExecStart=$NODE_BIN $INSTALL_ROOT/dist/index.js gateway
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
  ok "systemd unit rendered at $SYSTEMD_UNIT_DIR/pqc-openclaw.service"
fi

# ----------------------------------------------------------------------
# 8. Print next steps
# ----------------------------------------------------------------------

GATEWAY_TOKEN=$(node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))")
keyfile="$STATE_DIR/wrap-key.b64"
ENV_FILE="$STATE_DIR/openclaw.env"
if [[ ! -f "$ENV_FILE" ]]; then
  printf 'OPENCLAW_GATEWAY_TOKEN=%s\n' "$GATEWAY_TOKEN" > "$ENV_FILE"
  chmod 0600 "$ENV_FILE"
  if [[ -z "$SANDBOX_ROOT" ]]; then
    chown "$SERVICE_USER" "$ENV_FILE" || die "failed to assign environment file to $SERVICE_USER"
  fi
fi
unset GATEWAY_TOKEN

if [[ -n "$SANDBOX_ROOT" ]]; then
  cat <<EOF

=========================================================================
  PQC OpenClaw sandbox install complete
=========================================================================
  Install root: $INSTALL_ROOT
  State dir:    $STATE_DIR
  Wrapper dir:  $BIN_DIR
  Systemd unit: $SYSTEMD_UNIT_DIR/pqc-openclaw.service (rendered only)
  Gateway env:  $ENV_FILE (mode 0600; token not printed)

  No host users, system services, OS keyrings, /etc, or /usr/local paths
  were modified.
=========================================================================
EOF
  exit 0
fi

cat <<EOF

==========================================================================
  PQC OpenClaw fork installed to $INSTALL_ROOT
==========================================================================

  Node.js:      $(node --version)
  pnpm:         $(pnpm --version)
  State dir:    $STATE_DIR
  Wrap key:     $keyfile (service file source; mode 0600)
  Service user: $SERVICE_USER (Linux only)

  Gateway env:   $ENV_FILE (mode 0600; token not printed)

NEXT STEPS
  1. Edit $SYSTEMD_UNIT_DIR/pqc-openclaw.service (verify the paths
     and env vars above match your environment).
  2. Review the generated environment file at $ENV_FILE.
  3. Reload and start the service:
       sudo systemctl daemon-reload
       sudo systemctl enable --now pqc-openclaw
  4. Verify:
       sudo journalctl -u pqc-openclaw -f
       /usr/local/bin/healthcheck-pqc.sh --skip-keyring

POST-INSTALL HEALTH CHECK
  Focused mlock regression:
    cd $INSTALL_ROOT && node scripts/run-vitest.mjs run src/security/mlock-helper.test.ts
  Cache-timing evidence-integrity guard (14 checked-in reports):
    cd $INSTALL_ROOT && node scripts/check-pqc-cache-timing-evidence.mjs

For details, see PQC-FORK.md §Production Deployment.
==========================================================================
EOF
