#!/usr/bin/env bash
set -euo pipefail

# Generic vault-backed kubernetes Secrets, one vault file per cluster:
#   inventory/group_vars/k3s_<cluster>/kubernetes_secrets.vault.yml
# holding a single variable `kubernetes_secrets`, a dict keyed
# "<namespace>/<secret-name>" of data-key -> value. The kubernetes role
# renders it into Opaque Secrets through the k3s manifests mechanism.
#
# The checked-in contract (names only, never values) lives next to it in
#   inventory/group_vars/k3s_<cluster>/kubernetes_secrets_declared.yml
# as `kubernetes_required_secrets` / `kubernetes_optional_secrets` — the
# role refuses to deploy while a required secret is missing, and reports
# vault entries declared in neither (Reports step).
#
# Usage:
#   kubernetes_secret set    <cluster> <namespace> <secret> <key> [value|-]
#   kubernetes_secret get    <cluster> <namespace> <secret> <key>
#   kubernetes_secret list   <cluster>
#   kubernetes_secret delete <cluster> <namespace> <secret> [key]
#   kubernetes_secret check  <cluster>
#
# `set` without a value prompts twice with hidden input (preferred: nothing
# lands in shell history); `-` reads the value verbatim from stdin (e.g. a
# PEM file). Values are text — binary data is not supported.
# `delete` removes one key, or the whole secret when key is omitted.
# `check` compares the contract against the vault both ways and exits
# non-zero when a required entry is missing or an undeclared one exists.

usage() {
  sed -n 's/^#   kubernetes_secret /  kubernetes_secret /p' "$0" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: Missing required command: $1" >&2
    exit 1
  }
}

require_cmd ansible-vault
require_cmd python3
require_cmd mktemp

[ "$#" -ge 2 ] || usage

ACTION="$1"
CLUSTER="$2"

if ! printf '%s' "$CLUSTER" | grep -Eq '^[a-z0-9-]+$'; then
  echo "ERROR: Cluster name must match ^[a-z0-9-]+$: $CLUSTER" >&2
  exit 1
fi

CLUSTER_DIR="$PROJECT_ROOT/inventory/group_vars/k3s_${CLUSTER}"
if [ ! -d "$CLUSTER_DIR" ]; then
  echo "ERROR: No such cluster group_vars directory: $CLUSTER_DIR" >&2
  exit 1
fi

VAULT_FILE="$CLUSTER_DIR/kubernetes_secrets.vault.yml"
DECLARED_FILE="$CLUSTER_DIR/kubernetes_secrets_declared.yml"

# RFC 1123 DNS labels/names for namespace and secret name; kubernetes
# Secret data-key charset for keys.
validate_ns_name_key() {
  local ns="$1" name="$2" key="${3:-}"
  if ! printf '%s' "$ns" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'; then
    echo "ERROR: Invalid namespace (RFC 1123 label, max 63 chars): $ns" >&2
    exit 1
  fi
  if ! printf '%s' "$name" | grep -Eq '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$' \
    || [ "${#name}" -gt 253 ]; then
    echo "ERROR: Invalid secret name (RFC 1123 subdomain, max 253 chars): $name" >&2
    exit 1
  fi
  if [ -n "$key" ] && { ! printf '%s' "$key" | grep -Eq '^[A-Za-z0-9._-]+$' \
    || [ "${#key}" -gt 253 ]; }; then
    echo "ERROR: Invalid data key ([A-Za-z0-9._-]+, max 253 chars): $key" >&2
    exit 1
  fi
}

umask 077

TMP_PLAIN="$(mktemp)"
TMP_VALUE="$(mktemp)"
cleanup() {
  shred -u "$TMP_PLAIN" "$TMP_VALUE" 2>/dev/null || rm -f "$TMP_PLAIN" "$TMP_VALUE"
}
trap cleanup EXIT

# Decrypt the current vault contents (empty file when the vault does not
# exist yet) — all YAML work happens on the plaintext in python below.
if [ -f "$VAULT_FILE" ]; then
  ansible-vault view "$VAULT_FILE" > "$TMP_PLAIN"
fi

# One python entrypoint for everything YAML: reads the decrypted plaintext
# and the declared contract, performs the operation, and (for mutations)
# rewrites the plaintext for re-encryption. The secret value travels via
# the environment, never argv (argv is world-readable in /proc).
run_py() {
  KS_PLAIN="$TMP_PLAIN" KS_VALUE_FILE="$TMP_VALUE" \
  KS_DECLARED="$DECLARED_FILE" KS_CLUSTER="$CLUSTER" \
    python3 - "$@" <<'PY'
import os, sys, yaml

op = sys.argv[1]
args = sys.argv[2:]
plain_path = os.environ["KS_PLAIN"]
declared_path = os.environ["KS_DECLARED"]
cluster = os.environ["KS_CLUSTER"]

HEADER = f"""\
# Kubernetes Secrets for cluster {cluster} (vault-encrypted).
# Managed by `./infratool kubernetes_secret` — contract (required/optional)
# in kubernetes_secrets_declared.yml next to this file.
"""

def load_secrets():
    with open(plain_path) as f:
        data = yaml.safe_load(f) or {}
    secrets = data.get("kubernetes_secrets") or {}
    if not isinstance(secrets, dict):
        sys.exit("ERROR: kubernetes_secrets in the vault file is not a dict")
    return secrets

def save_secrets(secrets):
    with open(plain_path, "w") as f:
        f.write(HEADER)
        yaml.safe_dump({"kubernetes_secrets": secrets}, f,
                       default_flow_style=False, allow_unicode=True,
                       width=1000000, sort_keys=True)

def load_declared():
    required, optional = {}, {}
    if os.path.exists(declared_path):
        with open(declared_path) as f:
            data = yaml.safe_load(f) or {}
        required = data.get("kubernetes_required_secrets") or {}
        optional = data.get("kubernetes_optional_secrets") or {}
    return required, optional

def declared_keys(ref):
    required, optional = load_declared()
    return set(required.get(ref) or []) | set(optional.get(ref) or [])

secrets = load_secrets()

if op == "set":
    ns, name, key = args
    ref = f"{ns}/{name}"
    # Value from the stdin buffer file (verbatim, trailing newline preserved
    # — bash command substitution would strip it; python's own stdin is
    # occupied by this script's heredoc) or from the environment (never argv).
    if os.environ.get("KS_VALUE_FROM") == "stdin":
        with open(os.environ["KS_VALUE_FILE"]) as f:
            value = f.read()
    else:
        value = os.environ["KS_VALUE"]
    if not value:
        sys.exit("ERROR: Empty value")
    secrets.setdefault(ref, {})[key] = value
    save_secrets(secrets)
    if key not in declared_keys(ref):
        print(f"WARNING: {ref} key '{key}' is not declared — add it to "
              f"{os.path.relpath(declared_path)} (required or optional), or "
              "the Reports step will flag it as stale.", file=sys.stderr)

elif op == "get":
    ns, name, key = args
    ref = f"{ns}/{name}"
    if ref not in secrets or key not in secrets[ref]:
        sys.exit(f"ERROR: {ref} key '{key}' not found in the vault")
    value = secrets[ref][key]
    sys.stdout.write(value)
    if not value.endswith("\n"):
        sys.stdout.write("\n")

elif op == "list":
    if not secrets:
        print("(no secrets in vault)")
    for ref in sorted(secrets):
        print(f"{ref}: {', '.join(sorted(secrets[ref]))}")

elif op == "delete":
    ns, name = args[0], args[1]
    key = args[2] if len(args) > 2 else None
    ref = f"{ns}/{name}"
    if ref not in secrets:
        sys.exit(f"ERROR: {ref} not found in the vault")
    required, _ = load_declared()
    if key is None:
        removed = sorted(secrets.pop(ref))
        required_hit = sorted(set(removed) & set(required.get(ref) or []))
    else:
        if key not in secrets[ref]:
            sys.exit(f"ERROR: {ref} key '{key}' not found in the vault")
        del secrets[ref][key]
        if not secrets[ref]:
            del secrets[ref]
        removed = [key]
        required_hit = [key] if key in (required.get(ref) or []) else []
    save_secrets(secrets)
    print(f"Deleted {ref} key(s): {', '.join(removed)}")
    if required_hit:
        print(f"WARNING: {ref} key(s) {', '.join(required_hit)} are declared "
              "REQUIRED — the next ansible run will fail until they are set "
              "again (or the requirement is removed from "
              f"{os.path.relpath(declared_path)}).", file=sys.stderr)

elif op == "check":
    required, optional = load_declared()
    problems = 0
    for ref in sorted(required):
        ns_name = ref.split("/", 1)
        for key in required[ref] or []:
            if key not in secrets.get(ref, {}):
                problems += 1
                print(f"MISSING required: {ref} key '{key}'\n"
                      f"  -> ./infratool kubernetes_secret set {cluster} "
                      f"{ns_name[0]} {ns_name[1]} {key}")
    declared = {ref: set(required.get(ref) or []) | set(optional.get(ref) or [])
                for ref in set(required) | set(optional)}
    for ref in sorted(secrets):
        ns_name = ref.split("/", 1)
        for key in sorted(secrets[ref]):
            if key not in declared.get(ref, set()):
                problems += 1
                print(f"UNDECLARED in vault (stale?): {ref} key '{key}'\n"
                      f"  -> declare it in {os.path.relpath(declared_path)}, "
                      "or remove it:\n"
                      f"     ./infratool kubernetes_secret delete {cluster} "
                      f"{ns_name[0]} {ns_name[1]} {key}")
    if problems:
        sys.exit(1)
    print(f"OK: vault and contract agree for cluster {cluster}")

else:
    sys.exit(f"ERROR: unknown operation: {op}")
PY
}

encrypt_back() {
  ansible-vault encrypt "$TMP_PLAIN" --encrypt-vault-id project --output "$VAULT_FILE"
  echo "Vault written to: $VAULT_FILE"
}

case "$ACTION" in
  set)
    [ "$#" -ge 5 ] && [ "$#" -le 6 ] || usage
    NS="$3"; NAME="$4"; KEY="$5"
    validate_ns_name_key "$NS" "$NAME" "$KEY"
    if [ "$#" -eq 6 ] && [ "$6" = "-" ]; then
      # Buffer stdin to a (shredded) tmp file and let python read it from
      # there, verbatim: $(cat) would strip trailing newlines (matters for
      # PEM material), and python's stdin is occupied by the script heredoc.
      cat > "$TMP_VALUE"
      KS_VALUE_FROM=stdin run_py set "$NS" "$NAME" "$KEY"
    else
      if [ "$#" -eq 6 ]; then
        VALUE="$6"
        echo "NOTE: passing the value as an argument puts it in your shell history;" >&2
        echo "      prefer omitting it (hidden prompt) or '-' (stdin)." >&2
      else
        read -rs -p "Value for ${NS}/${NAME} key '${KEY}': " VALUE </dev/tty; echo >&2
        read -rs -p "Repeat value: " VALUE2 </dev/tty; echo >&2
        if [ "$VALUE" != "$VALUE2" ]; then
          echo "ERROR: Values do not match" >&2
          exit 1
        fi
      fi
      KS_VALUE="$VALUE" run_py set "$NS" "$NAME" "$KEY"
    fi
    encrypt_back
    ;;
  get)
    [ "$#" -eq 5 ] || usage
    validate_ns_name_key "$3" "$4" "$5"
    [ -f "$VAULT_FILE" ] || { echo "ERROR: No vault file: $VAULT_FILE" >&2; exit 1; }
    run_py get "$3" "$4" "$5"
    ;;
  list)
    [ "$#" -eq 2 ] || usage
    run_py list
    ;;
  delete)
    [ "$#" -ge 4 ] && [ "$#" -le 5 ] || usage
    validate_ns_name_key "$3" "$4" "${5:-}"
    [ -f "$VAULT_FILE" ] || { echo "ERROR: No vault file: $VAULT_FILE" >&2; exit 1; }
    run_py delete "$3" "$4" ${5:+"$5"}
    encrypt_back
    ;;
  check)
    [ "$#" -eq 2 ] || usage
    run_py check
    ;;
  *)
    usage
    ;;
esac
