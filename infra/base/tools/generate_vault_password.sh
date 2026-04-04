#!/usr/bin/env bash

# Run this script to create/rotate the vault password,
# which is encrypted with the public keys of all vault users and stored in .vault-pass.gpg.

set -euo pipefail
pushd "$(dirname "$0")" >/dev/null

GPG_ID_FILE="$PROJECT_ROOT/.gpg-id"

if [[ ! -f "$GPG_ID_FILE" ]]; then
  echo "Error: $GPG_ID_FILE not found." >&2
  echo "Create it with one GPG fingerprint per line." >&2
  exit 1
fi

OUT_FILE="$PROJECT_ROOT/.vault-pass.gpg"
PASS_BYTES=32

gpg_args=()
while IFS= read -r line; do
  line="${line%%#*}"
  line="${line// /}"
  [[ -z "$line" ]] && continue
  gpg_args+=(--recipient "$line")
done < "$GPG_ID_FILE"

if [[ ${#gpg_args[@]} -eq 0 ]]; then
  echo "Error: No GPG recipients found in $GPG_ID_FILE." >&2
  exit 1
fi

openssl rand -base64 "$PASS_BYTES" \
  | gpg --batch --yes --trust-model always --encrypt "${gpg_args[@]}" --output "$OUT_FILE"

popd >/dev/null
