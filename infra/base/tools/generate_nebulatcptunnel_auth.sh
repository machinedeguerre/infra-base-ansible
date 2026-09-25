#!/usr/bin/env bash
set -euo pipefail

# Generates nebulatcptunnel (chisel) tunnel credentials (user + random password)
# Stores them in an Ansible Vault YAML file:
#   host_vars/<host>/nebulatcptunnel.vault.yml

if [ "$#" -lt 1 ]; then
  echo "ERROR: Ansible inventory host name is required (argument to this script)" >&2
  echo "Usage: infratool generate_nebulatcptunnel_auth <host> [username]" >&2
  exit 1
fi

INVENTORY_HOST_NAME="$1"
TUNNEL_USER="${2:-user}"

if ! host_exists_in_inventory "$INVENTORY_HOST_NAME"; then
  echo "ERROR: Host not found in inventory: $INVENTORY_HOST_NAME" >&2
  exit 1
fi

VAULT_FILE="$PROJECT_ROOT/inventory/host_vars/${INVENTORY_HOST_NAME}/nebulatcptunnel.vault.yml"
VAULT_DIR="$(dirname "$VAULT_FILE")"
mkdir -p "$VAULT_DIR"

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

# --- Generate password (URL-safe base64) ---
password="$(openssl rand -base64 32 | tr -d '\n' | tr '+/' '-_')"

# --- Write temporary YAML ---
tmp_plain="$(mktemp)"
cleanup() {
  shred -u "$tmp_plain" 2>/dev/null || rm -f "$tmp_plain"
}
trap cleanup EXIT

cat >"$tmp_plain" <<YAML
# nebulatcptunnel (chisel) tunnel credentials (vault-encrypted)
nebulatcptunnel_auth_user: "${TUNNEL_USER}"
nebulatcptunnel_auth_password: "${password}"
YAML

ansible-vault encrypt "$tmp_plain" --encrypt-vault-id project --output "$VAULT_FILE"

echo "Vault written to: $VAULT_FILE"
echo "Auth user: ${TUNNEL_USER}"
echo "Retrieve the password later with:"
echo "  ansible-vault view \"$VAULT_FILE\""
