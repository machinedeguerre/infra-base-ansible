#!/usr/bin/env bash
export PROJECT_ROOT="$(pwd)"
export PROJECT_INVENTORY_FILE="${PROJECT_ROOT}/inventory/hosts.yml"
export COLLECTION_ROOT="${PROJECT_ROOT}/collections/ansible_collections/infra/base"
export TOOLS_DIR="${COLLECTION_ROOT}/tools"
export ANSIBLE_VAULT_PASSWORD_FILE="${COLLECTION_ROOT}/scripts/vault_pass_gpg.sh"

export INFRA_VAULT_CACHE_KEY="${INFRA_VAULT_CACHE_KEY:-$(openssl rand -hex 32)}"
_vault_cache_cleanup() {
  local key_tag
  key_tag="$(printf '%s' "$INFRA_VAULT_CACHE_KEY" | sha256sum | cut -c1-16)"
  rm -f "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"/infratool-vault-*-"$key_tag"
}
trap _vault_cache_cleanup EXIT

if [ ! -d playbooks ] || [ ! -d inventory ] || [ ! -d $TOOLS_DIR ]; then
  echo "This script is supposed to run in the scope of an ansible project." >&2
  echo "Run it from the root of your ansible project (where the playbooks directory is located)." >&2
  exit 1
fi

########################################################
# Helper functions (to be used by tools)
########################################################

# Function to check if a host exists in the inventory
# Usage: host_exists_in_inventory <hostname>
# Returns 0 if host exists, 1 if not found, 2 if inventory file doesn't exist or invalid arguments
# Example:
#   if ! host_exists_in_inventory "myhost"; then
#     echo "Host not found in inventory"
#     exit 1
#   fi

host_exists_in_inventory() {
  local hostname="$1"

  if [ -z "$hostname" ]; then
    echo "ERROR: hostname argument is required" >&2
    return 2
  fi

  if [ ! -f "$PROJECT_INVENTORY_FILE" ]; then
    echo "ERROR: Inventory file not found: $PROJECT_INVENTORY_FILE" >&2
    return 2
  fi

  # Read YAML file directly to avoid needing to decrypt vaults
  # This parses the inventory structure without loading variables
  # Look for hostname as a key in hosts sections (common YAML inventory formats)
  
  # Pattern 1: hostname as a key under hosts (e.g., "  hostname:" or "    hostname:")
  if grep -E "^\s+${hostname}\s*:" "$PROJECT_INVENTORY_FILE" >/dev/null 2>&1; then
    return 0
  fi

  # Pattern 2: hostname in a list format (e.g., "  - hostname" or "    - hostname")
  if grep -E "^\s+-\s+${hostname}\s*$" "$PROJECT_INVENTORY_FILE" >/dev/null 2>&1; then
    return 0
  fi

  # Pattern 3: hostname as a standalone key at any indentation level
  # This catches cases where hostname might be at different indentation levels
  if grep -E "^[[:space:]]*${hostname}[[:space:]]*:" "$PROJECT_INVENTORY_FILE" >/dev/null 2>&1; then
    return 0
  fi

  # Host not found
  return 1
}

export -f host_exists_in_inventory

########################################################
# Main logic
########################################################

# If no arguments are provided, list the available tools.
if [ $# -eq 0 ] || [ ! -e "$TOOLS_DIR/$1.sh" ]; then
  for tool in $(ls $TOOLS_DIR | grep '\.sh$' | grep -v infratool.sh); do
    echo "  $tool" | sed 's/\.sh$//'
  done
  exit 0
fi

# Otherwise, run the tool with the given arguments.
$TOOLS_DIR/$1.sh "${@:2}"
