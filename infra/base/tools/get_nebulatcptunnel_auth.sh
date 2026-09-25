#!/usr/bin/env bash
set -euo pipefail

# Prints the tunnel credential as user:password, ready to pass to
# `chisel client --auth <user:password>`.

if [ "$#" -lt 1 ]; then
  echo "ERROR: Ansible inventory host name is required (argument to this script)" >&2
  echo "Usage: infratool get_nebulatcptunnel_auth <host>" >&2
  exit 1
fi

INVENTORY_HOST_NAME="$1"

if ! host_exists_in_inventory "$INVENTORY_HOST_NAME"; then
  echo "ERROR: Host not found in inventory: $INVENTORY_HOST_NAME" >&2
  exit 1
fi

VAULT_FILE="$PROJECT_ROOT/inventory/host_vars/${INVENTORY_HOST_NAME}/nebulatcptunnel.vault.yml"

if [ ! -f "$VAULT_FILE" ]; then
  echo "ERROR: Tunnel auth vault file not found: $VAULT_FILE" >&2
  echo "Generate credentials first with: generate_nebulatcptunnel_auth.sh $INVENTORY_HOST_NAME" >&2
  exit 1
fi

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: Missing required command: $1" >&2
    exit 1
  }
}

require_cmd ansible-vault

# Decrypt vault file and extract user + password
vault_content=$(ansible-vault view "$VAULT_FILE" --vault-id project 2>/dev/null)

if [ $? -ne 0 ]; then
  echo "ERROR: Failed to decrypt vault file" >&2
  exit 1
fi

extract() {
  echo "$vault_content" | grep -E "^$1:" | sed "s/^$1:[[:space:]]*//" | sed 's/^"//' | sed 's/"$//' | sed "s/^'//" | sed "s/'$//" | tr -d ' '
}

auth_user=$(extract nebulatcptunnel_auth_user)
auth_password=$(extract nebulatcptunnel_auth_password)

if [ -z "$auth_user" ] || [ -z "$auth_password" ]; then
  echo "ERROR: Could not extract user/password from vault file" >&2
  exit 1
fi

echo "${auth_user}:${auth_password}"
