#!/usr/bin/env bash
#
# Import a vault file from another project, re-encrypting it with this project's vault password.
#
# Usage: infratool import_vault <source_vault_file> <destination_path>
#
# The source project root is detected automatically by walking up from the source file
# until a directory containing both playbooks/ and inventory/ is found.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: infratool import_vault <source_vault_file> <destination_path>" >&2
  exit 1
fi

SRC_FILE="$(realpath "$1")"
DEST_FILE="$2"

# Resolve destination relative to PROJECT_ROOT if not absolute
if [[ "$DEST_FILE" != /* ]]; then
  DEST_FILE="${PROJECT_ROOT}/${DEST_FILE}"
fi

if [[ ! -f "$SRC_FILE" ]]; then
  echo "Error: Source file not found: $SRC_FILE" >&2
  exit 1
fi

# Find source project root by walking up from the source file
find_project_root() {
  local dir="$1"
  while [[ "$dir" != "/" ]]; do
    if [[ -d "$dir/playbooks" && -d "$dir/inventory" ]]; then
      echo "$dir"
      return 0
    fi
    dir="$(dirname "$dir")"
  done
  return 1
}

SRC_PROJECT_ROOT="$(find_project_root "$(dirname "$SRC_FILE")")" || {
  echo "Error: Could not find project root for $SRC_FILE" >&2
  echo "Looked for a parent directory containing both playbooks/ and inventory/" >&2
  exit 1
}

SRC_VAULT_PASS="$SRC_PROJECT_ROOT/.vault-pass.gpg"
DEST_VAULT_PASS="$PROJECT_ROOT/.vault-pass.gpg"

if [[ ! -f "$SRC_VAULT_PASS" ]]; then
  echo "Error: Source vault password not found: $SRC_VAULT_PASS" >&2
  exit 1
fi

if [[ ! -f "$DEST_VAULT_PASS" ]]; then
  echo "Error: Destination vault password not found: $DEST_VAULT_PASS" >&2
  exit 1
fi

VAULT_PASS_SCRIPT="${COLLECTION_ROOT}/scripts/vault_pass_gpg.sh"

# Decrypt with source project's vault password, re-encrypt with ours
(cd "$SRC_PROJECT_ROOT" && ansible-vault decrypt --vault-password-file "$VAULT_PASS_SCRIPT" --output - "$SRC_FILE") \
  | (cd "$PROJECT_ROOT" && ansible-vault encrypt --vault-password-file "$VAULT_PASS_SCRIPT" --output "$DEST_FILE")

echo "Imported $(basename "$SRC_FILE") -> $DEST_FILE"
