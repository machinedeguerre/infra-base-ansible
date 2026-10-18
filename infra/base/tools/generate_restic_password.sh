#!/usr/bin/env bash
set -euo pipefail

# Generates the restic repository password for one backup source host (used
# by the restic_source role) and stores it vault-encrypted in that host's
# host_vars. Refuses to overwrite: changing the password makes existing
# repositories unreadable — the vault copy is what restores depend on.

if [ "$#" -lt 1 ]; then
  echo "ERROR: Ansible inventory host name is required (argument to this script)" >&2
  exit 1
fi

INVENTORY_HOST_NAME="$1"

if ! host_exists_in_inventory "$INVENTORY_HOST_NAME"; then
  echo "ERROR: Host not found in inventory: $INVENTORY_HOST_NAME" >&2
  exit 1
fi

VAULT_FILE="$PROJECT_ROOT/inventory/host_vars/${INVENTORY_HOST_NAME}/restic_password.vault.yml"

if [ -e "$VAULT_FILE" ]; then
  echo "ERROR: $VAULT_FILE already exists." >&2
  echo "Changing the restic password makes existing repositories unreadable; remove the file manually first if you really mean it." >&2
  exit 1
fi

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: Missing required command: $1" >&2
    exit 1
  }
}

umask 077

require_cmd ansible-vault
require_cmd openssl
require_cmd mktemp

password="$(openssl rand -base64 32 | tr -d '\n')"

tmp_plain="$(mktemp)"
cleanup() {
  shred -u "$tmp_plain" 2>/dev/null || rm -f "$tmp_plain"
}
trap cleanup EXIT

cat >"$tmp_plain" <<YAML
# Restic repository password for ${INVENTORY_HOST_NAME} (vault-encrypted).
# The authoritative copy: restores depend on it. Never rotate casually.
backup_restic_password: "${password}"
YAML

mkdir -p "$(dirname "$VAULT_FILE")"

ansible-vault encrypt "$tmp_plain" --encrypt-vault-id project --output "$VAULT_FILE"

echo "Vault written to: $VAULT_FILE"
