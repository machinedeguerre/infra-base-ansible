#!/usr/bin/env bash
set -euo pipefail

# Generates a k3s cluster join token (shared by all nodes in that cluster)
# and stores it vault-encrypted in group_vars for the cluster's inventory
# group (k3s_<cluster>). Refuses to overwrite an existing token — changing
# it is disruptive (agents must re-join).

if [ "$#" -lt 1 ]; then
  echo "ERROR: Cluster name is required (argument to this script), e.g. 'internal'" >&2
  exit 1
fi

CLUSTER_NAME="$1"

if ! printf '%s' "$CLUSTER_NAME" | grep -Eq '^[a-z0-9-]+$'; then
  echo "ERROR: Cluster name must match ^[a-z0-9-]+$: $CLUSTER_NAME" >&2
  exit 1
fi

VAULT_FILE="$PROJECT_ROOT/inventory/group_vars/k3s_${CLUSTER_NAME}/kubernetes_token.vault.yml"

if [ -e "$VAULT_FILE" ]; then
  echo "ERROR: $VAULT_FILE already exists." >&2
  echo "Changing the cluster token forces every node to re-join; remove the file manually first if you really mean it." >&2
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

# --- Generate token ---
token="$(openssl rand -base64 32 | tr -d '\n')"

# --- Write temporary YAML ---
tmp_plain="$(mktemp)"
cleanup() {
  shred -u "$tmp_plain" 2>/dev/null || rm -f "$tmp_plain"
}
trap cleanup EXIT

cat >"$tmp_plain" <<YAML
# k3s cluster join token for cluster ${CLUSTER_NAME} (vault-encrypted)
kubernetes_token: "${token}"
YAML

mkdir -p "$(dirname "$VAULT_FILE")"

ansible-vault encrypt "$tmp_plain" --encrypt-vault-id project --output "$VAULT_FILE"

echo "Vault written to: $VAULT_FILE"
