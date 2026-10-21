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
# The same file may declare REFERENCES (`kubernetes_secret_references`):
# "<ns>/<name>": "<target-ns>/<target-name>" replicates the target's whole
# data as a Secret in the referencing namespace. Where a secret is copied is
# configuration, not a secret — references are edited in that file directly,
# never stored in the vault. A reference must point at a concrete vault
# entry: dangling targets, reference chains and a reference name colliding
# with a vault entry are hard errors (here and in the ansible run).
#
# Usage:
#   kubernetes_secret set      <cluster> <namespace> <secret> <key> [value|-]
#   kubernetes_secret generate <cluster> <namespace> <secret> <key>
#   kubernetes_secret get      <cluster> <namespace> <secret> <key>
#   kubernetes_secret copy     <from-cluster> <from-ns> <from-secret> <from-key> <to-cluster> <to-ns> <to-secret> <to-key>
#   kubernetes_secret move     <from-cluster> <from-ns> <from-secret> <from-key> <to-cluster> <to-ns> <to-secret> <to-key>
#   kubernetes_secret list     <cluster>
#   kubernetes_secret delete   <cluster> <namespace> <secret> [key]
#   kubernetes_secret check    <cluster>
#
# `set` without a value prompts twice with hidden input (preferred: nothing
# lands in shell history); `-` reads the value verbatim from stdin (e.g. a
# PEM file). Values are text — binary data is not supported.
# `generate` is `set` with a random value (~192 bits), for machine-only
# secrets no human ever needs to type; it refuses to overwrite an existing
# key (rotation = deliberate delete first).
# `get` resolves references transparently; `list` shows them alongside the
# vault entries. `delete` removes one key, or the whole secret when key is
# omitted; a secret still pointed at by a reference cannot be deleted.
# `copy` duplicates one value to another key/secret/namespace/cluster (both
# clusters must be in this project); `move` is copy + delete of the source
# key, with the same guards as delete. Neither overwrites an existing
# destination key — delete it first if you really mean to replace it.
# `check` validates the EFFECTIVE contract against the vault both ways:
# it fetches contract + vault structure (names only) through the kubernetes
# role's secrets_contract entrypoint, so requirements derived by enabled
# role components are included — this tool itself knows nothing about them.
# Exits non-zero on any problem. No host connections are made.

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
TMP_DST="$(mktemp)"
TMP_CONTRACT="$(mktemp)"
cleanup() {
  shred -u "$TMP_PLAIN" "$TMP_VALUE" "$TMP_DST" "$TMP_CONTRACT" 2>/dev/null \
    || rm -f "$TMP_PLAIN" "$TMP_VALUE" "$TMP_DST" "$TMP_CONTRACT"
}
trap cleanup EXIT

# Decrypt the current vault contents (empty file when the vault does not
# exist yet) — all YAML work happens on the plaintext in python below.
# `check` never needs it: it works from the effective contract instead.
if [ "$ACTION" != "check" ] && [ -f "$VAULT_FILE" ]; then
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
from secrets import token_urlsafe

op = sys.argv[1]
args = sys.argv[2:]
plain_path = os.environ["KS_PLAIN"]
declared_path = os.environ["KS_DECLARED"]
cluster = os.environ["KS_CLUSTER"]

def header(cluster_name):
    return (f"# Kubernetes Secrets for cluster {cluster_name} "
            "(vault-encrypted).\n"
            "# Managed by `./infratool kubernetes_secret` — contract "
            "(required/optional)\n"
            "# in kubernetes_secrets_declared.yml next to this file.\n")

def load_secrets(path=None):
    path = path or plain_path
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    secrets = data.get("kubernetes_secrets") or {}
    if not isinstance(secrets, dict):
        sys.exit("ERROR: kubernetes_secrets in the vault file is not a dict")
    for ref, entry in secrets.items():
        if not isinstance(entry, dict):
            sys.exit(f"ERROR: vault entry {ref} is not a dict of key -> "
                     "value. The vault holds concrete secrets only — "
                     "references belong in kubernetes_secrets_declared.yml "
                     "(kubernetes_secret_references).")
    return secrets

def save_secrets(secrets, path=None, cluster_name=None):
    with open(path or plain_path, "w") as f:
        f.write(header(cluster_name or cluster))
        yaml.safe_dump({"kubernetes_secrets": secrets}, f,
                       default_flow_style=False, allow_unicode=True,
                       width=1000000, sort_keys=True)

def load_declared(path=None):
    # Four generic contract categories, nothing else:
    #   required  — must exist in the vault (created with `set`)
    #   generated — must exist in the vault, machine-generated (`generate`)
    #   optional  — may exist
    #   references — replicate another entry into a namespace
    path = path or declared_path
    required, generated, optional, references = {}, {}, {}, {}
    if os.path.exists(path):
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        required = data.get("kubernetes_required_secrets") or {}
        generated = data.get("kubernetes_generated_secrets") or {}
        optional = data.get("kubernetes_optional_secrets") or {}
        references = data.get("kubernetes_secret_references") or {}
    return required, generated, optional, references

def declared_keys(ref):
    required, generated, optional, _ = load_declared()
    return (set(required.get(ref) or []) | set(generated.get(ref) or [])
            | set(optional.get(ref) or []))

def required_keys(ref, required, generated):
    # generated entries are required too — they just carry a different verb.
    return set(required.get(ref) or []) | set(generated.get(ref) or [])

# References live in the checked-in declared file, never in the vault:
# "<ns>/<name>" -> "<target-ns>/<target-name>" replicates the target's data
# in the referencing namespace. resolved() follows one level only —
# reference chains are invalid and rejected by check/the ansible run.
def resolved(secrets, references, ref):
    target = references.get(ref)
    if target is not None:
        return secrets.get(target, {})
    return secrets.get(ref, {})

def referrers(references, target):
    return sorted(k for k, v in references.items() if v == target)

secrets = load_secrets()
_, _, _, references = load_declared()

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
    if ref in references:
        sys.exit(f"ERROR: {ref} is declared as a reference to "
                 f"{references[ref]} in {os.path.relpath(declared_path)} — "
                 "set the key on the target instead, or remove the reference")
    secrets.setdefault(ref, {})[key] = value
    save_secrets(secrets)
    if key not in declared_keys(ref):
        print(f"WARNING: {ref} key '{key}' is not declared — add it to "
              f"{os.path.relpath(declared_path)} (required or optional), or "
              "the Reports step will flag it as stale.", file=sys.stderr)

elif op == "generate":
    ns, name, key = args
    ref = f"{ns}/{name}"
    if ref in references:
        sys.exit(f"ERROR: {ref} is declared as a reference to "
                 f"{references[ref]} in {os.path.relpath(declared_path)} — "
                 "generate on the target instead, or remove the reference")
    if key in secrets.get(ref, {}):
        sys.exit(f"ERROR: {ref} key '{key}' already exists — a generated "
                 "secret is never rotated by accident; delete it first if "
                 "you really mean it")
    secrets.setdefault(ref, {})[key] = token_urlsafe(24)
    save_secrets(secrets)
    print(f"Generated random value for {ref} key '{key}'")
    if key not in declared_keys(ref):
        print(f"WARNING: {ref} key '{key}' is not declared — add it to "
              f"{os.path.relpath(declared_path)} (required or optional), or "
              "the Reports step will flag it as stale.", file=sys.stderr)

elif op == "get":
    ns, name, key = args
    ref = f"{ns}/{name}"
    if ref in references and references[ref] not in secrets:
        sys.exit(f"ERROR: {ref} is a reference to {references[ref]}, which "
                 "is not in the vault (broken reference)")
    if ref not in references and ref not in secrets:
        sys.exit(f"ERROR: {ref} not found (vault or references)")
    data = resolved(secrets, references, ref)
    if key not in data:
        sys.exit(f"ERROR: {ref} key '{key}' not found in the vault")
    value = data[key]
    sys.stdout.write(value)
    if not value.endswith("\n"):
        sys.stdout.write("\n")

elif op in ("copy", "move"):
    sns, sname, skey, dns, dname, dkey = args
    src = f"{sns}/{sname}"
    dst = f"{dns}/{dname}"
    same_vault = os.environ.get("KS_SAME_VAULT") == "1"
    dst_cluster = os.environ["KS_CLUSTER_DST"]
    dst_declared_path = os.environ["KS_DECLARED_DST"]
    if same_vault:
        dst_secrets = secrets
        dst_references = references
    else:
        dst_secrets = load_secrets(os.environ["KS_PLAIN_DST"])
        _, _, _, dst_references = load_declared(dst_declared_path)

    if same_vault and src == dst and skey == dkey:
        sys.exit("ERROR: source and destination are the same")

    # Source: read like get (references resolve); move mutates the source,
    # so it must be a concrete vault entry.
    if op == "move" and src in references:
        sys.exit(f"ERROR: {src} is a reference to {references[src]} — "
                 "move from the concrete target instead")
    src_data = resolved(secrets, references, src)
    if skey not in src_data:
        sys.exit(f"ERROR: {src} key '{skey}' not found in the vault "
                 f"(cluster {cluster})")

    # Destination: same guards as set, plus no silent overwrite.
    if dst in dst_references:
        sys.exit(f"ERROR: {dst} (cluster {dst_cluster}) is declared as a "
                 f"reference to {dst_references[dst]} in "
                 f"{os.path.relpath(dst_declared_path)} — write to the "
                 "target instead, or remove the reference")
    if dkey in dst_secrets.get(dst, {}):
        sys.exit(f"ERROR: {dst} key '{dkey}' already exists in cluster "
                 f"{dst_cluster} — delete it first if you really mean to "
                 "replace it")

    if op == "move":
        # Same guards as delete: never leave a reference dangling. A rename
        # within the same secret is fine — the new key lands before the old
        # one is removed.
        refs_here = referrers(references, src)
        if (len(secrets[src]) == 1 and refs_here
                and not (same_vault and dst == src)):
            sys.exit(f"ERROR: '{skey}' is the last key of {src}, which is "
                     f"referenced by {', '.join(refs_here)} — remove the "
                     f"reference(s) from {os.path.relpath(declared_path)} "
                     "first")

    dst_secrets.setdefault(dst, {})[dkey] = src_data[skey]
    if op == "move":
        del secrets[src][skey]
        if not secrets[src]:
            del secrets[src]
        save_secrets(secrets)
        if not same_vault:
            save_secrets(dst_secrets, os.environ["KS_PLAIN_DST"], dst_cluster)
    elif same_vault:
        save_secrets(secrets)
    else:
        save_secrets(dst_secrets, os.environ["KS_PLAIN_DST"], dst_cluster)

    verb = "Moved" if op == "move" else "Copied"
    print(f"{verb} {src} key '{skey}' (cluster {cluster}) -> "
          f"{dst} key '{dkey}' (cluster {dst_cluster})")
    if op == "move":
        required, generated, _, _ = load_declared()
        if skey in required_keys(src, required, generated):
            print(f"WARNING: {src} key '{skey}' is declared REQUIRED in "
                  f"cluster {cluster} — the next ansible run will fail until "
                  "it is set again (or the requirement is removed from "
                  f"{os.path.relpath(declared_path)}).", file=sys.stderr)
    req_d, gen_d, opt_d, _ = load_declared(dst_declared_path)
    if dkey not in (set(req_d.get(dst) or []) | set(gen_d.get(dst) or [])
                    | set(opt_d.get(dst) or [])):
        print(f"WARNING: {dst} key '{dkey}' is not declared — add it to "
              f"{os.path.relpath(dst_declared_path)} (required or optional), "
              "or the Reports step will flag it as stale.", file=sys.stderr)

elif op == "list":
    if not secrets and not references:
        print("(no secrets in vault)")
    for ref in sorted(secrets):
        print(f"{ref}: {', '.join(sorted(secrets[ref]))}")
    for ref in sorted(references):
        print(f"{ref} -> {references[ref]} (reference)")

elif op == "delete":
    ns, name = args[0], args[1]
    key = args[2] if len(args) > 2 else None
    ref = f"{ns}/{name}"
    if ref in references:
        sys.exit(f"ERROR: {ref} is a reference declared in "
                 f"{os.path.relpath(declared_path)} — remove it there "
                 "(kubernetes_secret_references), not here")
    if ref not in secrets:
        sys.exit(f"ERROR: {ref} not found in the vault")
    required, generated, _, _ = load_declared()
    # Deleting a secret (or its last key) would leave any reference pointing
    # at it dangling — an invalid state this tool never writes.
    refs_here = referrers(references, ref)
    if key is None:
        if refs_here:
            sys.exit(f"ERROR: {ref} is referenced by {', '.join(refs_here)} — "
                     "remove the reference(s) from "
                     f"{os.path.relpath(declared_path)} first")
        removed = sorted(secrets.pop(ref))
        required_hit = sorted(set(removed) & required_keys(ref, required, generated))
    else:
        if key not in secrets[ref]:
            sys.exit(f"ERROR: {ref} key '{key}' not found in the vault")
        if len(secrets[ref]) == 1 and refs_here:
            sys.exit(f"ERROR: '{key}' is the last key of {ref}, which is "
                     f"referenced by {', '.join(refs_here)} — remove the "
                     "reference(s) from "
                     f"{os.path.relpath(declared_path)} first")
        del secrets[ref][key]
        if not secrets[ref]:
            del secrets[ref]
        removed = [key]
        required_hit = [key] if key in required_keys(ref, required, generated) else []
    save_secrets(secrets)
    print(f"Deleted {ref} key(s): {', '.join(removed)}")
    if required_hit:
        print(f"WARNING: {ref} key(s) {', '.join(required_hit)} are declared "
              "REQUIRED — the next ansible run will fail until they are set "
              "again (or the requirement is removed from "
              f"{os.path.relpath(declared_path)}).", file=sys.stderr)

elif op == "check":
    # Everything comes from the EFFECTIVE contract fetched via ansible
    # (checked-in contract variables merged with component-derived entries,
    # plus the vault structure — names only). This tool knows nothing about
    # components or where the variables were defined.
    import json
    with open(os.environ["KS_CONTRACT"]) as f:
        contract = json.load(f)
    c_required = contract.get("required") or {}
    c_generated = contract.get("generated") or {}
    c_optional = contract.get("optional") or {}
    c_references = contract.get("references") or {}
    c_vault = contract.get("vault") or {}  # "<ns>/<name>" -> [key, ...]
    problems = 0

    def vault_keys(ref):
        target = c_references.get(ref)
        return set(c_vault.get(target if target is not None else ref) or [])

    for ref in sorted(c_references):
        target = c_references[ref]
        if ref in c_vault:
            problems += 1
            print(f"COLLIDING reference: {ref} -> {target}, but {ref} is "
                  "also a concrete vault entry — remove one of them")
        if target in c_references:
            problems += 1
            print(f"INVALID reference: {ref} -> {target}, which is itself a "
                  f"reference (to {c_references[target]}) — references must "
                  "point at a concrete vault secret")
        elif target not in c_vault:
            problems += 1
            print(f"BROKEN reference: {ref} -> {target} (target not in the "
                  "vault) — the ansible run will refuse to deploy manifests")
    for ref in sorted(set(c_required) | set(c_generated)):
        ns_name = ref.split("/", 1)
        keys = set(c_required.get(ref) or []) | set(c_generated.get(ref) or [])
        for key in sorted(keys):
            if key not in vault_keys(ref):
                problems += 1
                verb = "generate" if key in (c_generated.get(ref) or []) else "set"
                print(f"MISSING required: {ref} key '{key}'\n"
                      f"  -> ./infratool kubernetes_secret {verb} {cluster} "
                      f"{ns_name[0]} {ns_name[1]} {key}")
    declared = {ref: set(c_required.get(ref) or []) | set(c_generated.get(ref) or [])
                     | set(c_optional.get(ref) or [])
                for ref in set(c_required) | set(c_generated) | set(c_optional)}
    for ref in sorted(c_vault):
        ns_name = ref.split("/", 1)
        for key in sorted(c_vault[ref] or []):
            if key in declared.get(ref, set()):
                continue
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
  local tmp="${1:-$TMP_PLAIN}" out="${2:-$VAULT_FILE}"
  ansible-vault encrypt "$tmp" --encrypt-vault-id project --output "$out"
  echo "Vault written to: $out"
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
  generate)
    [ "$#" -eq 5 ] || usage
    validate_ns_name_key "$3" "$4" "$5"
    run_py generate "$3" "$4" "$5"
    encrypt_back
    ;;
  get)
    [ "$#" -eq 5 ] || usage
    validate_ns_name_key "$3" "$4" "$5"
    [ -f "$VAULT_FILE" ] || { echo "ERROR: No vault file: $VAULT_FILE" >&2; exit 1; }
    run_py get "$3" "$4" "$5"
    ;;
  copy|move)
    [ "$#" -eq 9 ] || usage
    validate_ns_name_key "$3" "$4" "$5"
    DST_CLUSTER="$6"
    if ! printf '%s' "$DST_CLUSTER" | grep -Eq '^[a-z0-9-]+$'; then
      echo "ERROR: Cluster name must match ^[a-z0-9-]+$: $DST_CLUSTER" >&2
      exit 1
    fi
    DST_CLUSTER_DIR="$PROJECT_ROOT/inventory/group_vars/k3s_${DST_CLUSTER}"
    if [ ! -d "$DST_CLUSTER_DIR" ]; then
      echo "ERROR: No such cluster group_vars directory: $DST_CLUSTER_DIR" >&2
      exit 1
    fi
    validate_ns_name_key "$7" "$8" "$9"
    [ -f "$VAULT_FILE" ] || { echo "ERROR: No vault file: $VAULT_FILE" >&2; exit 1; }
    export KS_CLUSTER_DST="$DST_CLUSTER"
    export KS_DECLARED_DST="$DST_CLUSTER_DIR/kubernetes_secrets_declared.yml"
    if [ "$CLUSTER" = "$DST_CLUSTER" ]; then
      # One vault: python mutates the single plaintext, re-encrypted once.
      export KS_SAME_VAULT=1 KS_PLAIN_DST="$TMP_PLAIN"
      run_py "$ACTION" "$3" "$4" "$5" "$7" "$8" "$9"
      encrypt_back
    else
      DST_VAULT_FILE="$DST_CLUSTER_DIR/kubernetes_secrets.vault.yml"
      if [ -f "$DST_VAULT_FILE" ]; then
        ansible-vault view "$DST_VAULT_FILE" > "$TMP_DST"
      fi
      export KS_SAME_VAULT=0 KS_PLAIN_DST="$TMP_DST"
      run_py "$ACTION" "$3" "$4" "$5" "$7" "$8" "$9"
      # Destination first: if the source encrypt then failed, the value
      # exists twice (copy-state) rather than nowhere.
      encrypt_back "$TMP_DST" "$DST_VAULT_FILE"
      if [ "$ACTION" = "move" ]; then
        encrypt_back
      fi
    fi
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
    require_cmd ansible
    # Fetch the EFFECTIVE contract (checked-in vars merged with what enabled
    # role components derive) plus the vault structure (names only) through
    # the kubernetes role's secrets_contract entrypoint. No host connections
    # are made; vault decryption happens on the controller — one cached
    # password fetch for the whole command.
    if ! ansible "k3s_${CLUSTER}" -m include_role \
        -a "name=infra.base.kubernetes tasks_from=secrets_contract" \
        -e "kubernetes_secrets_contract_dest=$TMP_CONTRACT" \
        -e "ansible_python_interpreter=auto_silent" >/dev/null; then
      echo "ERROR: Failed to fetch the secrets contract via ansible" >&2
      exit 1
    fi
    if [ ! -s "$TMP_CONTRACT" ]; then
      echo "ERROR: Got no contract — does inventory group k3s_${CLUSTER} have a server?" >&2
      exit 1
    fi
    KS_CONTRACT="$TMP_CONTRACT" run_py check
    ;;
  *)
    usage
    ;;
esac
