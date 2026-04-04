#!/usr/bin/env bash
set -euo pipefail

# Generates WireGuard node keys (role-agnostic)
# Stores them in an Ansible Vault YAML file
# Prints the public key to stdout at the end

if [ "$#" -lt 1 ]; then
  echo "ERROR: Ansible inventory host name is required (argument to this script)" >&2
  exit 1
fi

INVENTORY_HOST_NAME="$1"

if ! host_exists_in_inventory "$INVENTORY_HOST_NAME"; then
  echo "ERROR: Host not found in inventory: $INVENTORY_HOST_NAME" >&2
  exit 1
fi

VAULT_FILE="$PROJECT_ROOT/inventory/host_vars/${INVENTORY_HOST_NAME}/wireguard.vault.yml"
VAULT_DIR="$(dirname "$VAULT_FILE")"
mkdir -p "$VAULT_DIR"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: Missing required command: $1" >&2
    exit 1
  }
}

umask 077

require_cmd wg
require_cmd ansible-vault
require_cmd mktemp

# --- Generate keys ---
private_key="$(wg genkey)"
public_key="$(printf '%s' "$private_key" | wg pubkey)"

# --- Write temporary YAML ---
tmp_plain="$(mktemp)"
cleanup() {
  shred -u "$tmp_plain" 2>/dev/null || rm -f "$tmp_plain"
}
trap cleanup EXIT

cat >"$tmp_plain" <<YAML
# WireGuard node secrets (vault-encrypted)
# These keys can be used for both server and client mode
# Note: Public key is calculated from private key automatically, no need to store it
wireguard_private_key: "${private_key}"
YAML

mkdir -p "$(dirname "$VAULT_FILE")"

ansible-vault encrypt "$tmp_plain" --encrypt-vault-id project --output "$VAULT_FILE"

echo "Vault written to: $VAULT_FILE"
echo
echo "Public key:"
echo "$public_key"