#!/usr/bin/env bash
set -euo pipefail

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

if [ ! -f "$VAULT_FILE" ]; then
  echo "ERROR: WireGuard vault file not found: $VAULT_FILE" >&2
  echo "Generate keys first with: generate_wireguard_keys.sh $INVENTORY_HOST_NAME" >&2
  exit 1
fi

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: Missing required command: $1" >&2
    exit 1
  }
}

require_cmd ansible-vault
require_cmd wg

# Decrypt vault file and extract private key, then calculate public key
vault_content=$(ansible-vault view "$VAULT_FILE" --vault-id project 2>/dev/null)

if [ $? -ne 0 ]; then
  echo "ERROR: Failed to decrypt vault file" >&2
  exit 1
fi

private_key=$(echo "$vault_content" | grep -E '^wireguard_private_key:' | sed 's/^wireguard_private_key:[[:space:]]*//' | sed 's/^"//' | sed 's/"$//' | sed "s/^'//" | sed "s/'$//" | tr -d ' ')

if [ -z "$private_key" ]; then
  echo "ERROR: Could not extract private key from vault file" >&2
  exit 1
fi

# Calculate public key from private key
public_key=$(printf '%s' "$private_key" | wg pubkey)

if [ -z "$public_key" ]; then
  echo "ERROR: Failed to calculate public key from private key" >&2
  exit 1
fi

echo "$public_key"
