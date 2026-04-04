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

VAULT_FILE="$PROJECT_ROOT/inventory/host_vars/${INVENTORY_HOST_NAME}/root_password.vault.yml"

if [ ! -f "$VAULT_FILE" ]; then
  echo "ERROR: Root password vault file not found: $VAULT_FILE" >&2
  echo "Generate password first with: generate_root_password.sh $INVENTORY_HOST_NAME" >&2
  exit 1
fi

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: Missing required command: $1" >&2
    exit 1
  }
}

require_cmd ansible-vault

# Decrypt vault file and extract root password
vault_content=$(ansible-vault view "$VAULT_FILE" --vault-id project 2>/dev/null)

if [ $? -ne 0 ]; then
  echo "ERROR: Failed to decrypt vault file" >&2
  exit 1
fi

root_password=$(echo "$vault_content" | grep -E '^root_password:' | sed 's/^root_password:[[:space:]]*//' | sed 's/^"//' | sed 's/"$//' | sed "s/^'//" | sed "s/'$//" | tr -d ' ')

if [ -z "$root_password" ]; then
  echo "ERROR: Could not extract root password from vault file" >&2
  exit 1
fi

echo "$root_password"
