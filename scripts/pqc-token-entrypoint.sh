#!/bin/sh
# Compose-only bridge for the gateway token secret. The application consumes
# OPENCLAW_GATEWAY_TOKEN, while Compose mounts the secret as a file.
set -eu

if [ -n "${OPENCLAW_GATEWAY_TOKEN_FILE:-}" ]; then
  case "$OPENCLAW_GATEWAY_TOKEN_FILE" in
    /*) ;;
    *) echo 'gateway token file path must be absolute' >&2; exit 78 ;;
  esac
  if [ -n "${OPENCLAW_GATEWAY_TOKEN:-}" ]; then
    echo 'configure either gateway token or gateway token file, not both' >&2
    exit 78
  fi
  if [ ! -f "$OPENCLAW_GATEWAY_TOKEN_FILE" ] || [ ! -r "$OPENCLAW_GATEWAY_TOKEN_FILE" ]; then
    echo 'gateway token file is missing or unreadable' >&2
    exit 78
  fi
  if ! OPENCLAW_GATEWAY_TOKEN=$(cat -- "$OPENCLAW_GATEWAY_TOKEN_FILE"); then
    echo 'gateway token file could not be read' >&2
    exit 78
  fi
  if [ -z "$OPENCLAW_GATEWAY_TOKEN" ]; then
    echo 'gateway token file is empty' >&2
    exit 78
  fi
  export OPENCLAW_GATEWAY_TOKEN
fi

exec "$@"
