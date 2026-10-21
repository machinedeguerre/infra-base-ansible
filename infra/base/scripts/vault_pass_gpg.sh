#!/usr/bin/env bash
set -euo pipefail

# Vault password source with a per-command encrypted cache.
#
# The GPG key lives on a YubiKey with touch confirmation, and one top-level
# command may invoke this script many times (every ansible-vault call does).
# To keep that at ONE touch per command, the decrypted password is cached in
# tmpfs — but never in plaintext:
#
#   - The entry point (infratool.sh) generates a random per-command key in
#     INFRA_VAULT_CACHE_KEY and removes the cache on exit (trap).
#   - This script REQUIRES that key (hard error otherwise). With a fresh
#     cache file it decrypts it (no GPG, no touch); otherwise it asks GPG
#     (the touch) and writes the cache, AES-256-encrypted with the key.
#   - The key dies with the command's environment, so a cache file that
#     survives a crash (trap never ran) is useless ciphertext in tmpfs,
#     gone at logout. No TTL needed. Plaintext never touches disk.
#   - The file name is <project-tag>-<key-tag>, so concurrent commands
#     never clobber each other and the trap can clean exactly its own
#     files, across projects (import_vault touches two).
#
# WITHOUT the key (plain ansible-vault/ansible-playbook outside ./infratool)
# the script degrades to the original behavior: GPG on every call — works,
# but costs a touch each time. Set the key yourself to opt in:
#   export INFRA_VAULT_CACHE_KEY="$(openssl rand -hex 32)"

GPG_FILE="./.vault-pass.gpg"

emit() {
  # Normalized output (exactly one trailing newline) so the cached and
  # uncached paths yield byte-identical passwords to ansible.
  printf '%s\n' "$1"
}

RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"

# No cache key, or no usable tmpfs — no cache; just decrypt every time
# (the pre-cache behavior).
if [ -z "${INFRA_VAULT_CACHE_KEY:-}" ] \
  || [ ! -d "$RUNTIME_DIR" ] || [ ! -w "$RUNTIME_DIR" ]; then
  emit "$(gpg --quiet --batch --decrypt "$GPG_FILE")"
  exit 0
fi

PATH_TAG="$(realpath "$GPG_FILE" | sha256sum | cut -c1-16)"
KEY_TAG="$(printf '%s' "$INFRA_VAULT_CACHE_KEY" | sha256sum | cut -c1-16)"
CACHE_FILE="$RUNTIME_DIR/infratool-vault-${PATH_TAG}-${KEY_TAG}"

if [ -f "$CACHE_FILE" ]; then
  emit "$(openssl enc -d -aes-256-cbc -pbkdf2 \
            -pass env:INFRA_VAULT_CACHE_KEY -in "$CACHE_FILE")"
  exit 0
fi

pass="$(gpg --quiet --batch --decrypt "$GPG_FILE")"
umask 077
printf '%s' "$pass" | openssl enc -aes-256-cbc -pbkdf2 \
  -pass env:INFRA_VAULT_CACHE_KEY -out "$CACHE_FILE"
emit "$pass"
