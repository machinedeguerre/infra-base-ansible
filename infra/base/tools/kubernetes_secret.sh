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
# never stored in the vault. A reference must point at a concrete entry:
# dangling targets, reference chains and a reference name colliding with a
# vault entry are hard errors (here and in the ansible run).
#
# It may also declare DERIVED data keys (`kubernetes_known_hosts_secrets`):
# "<ns>/<name>": {"<key>": [<inventory host>, ...]} fills that data key with
# ssh known_hosts lines for the named machines, built from the host keys
# this repo already manages for them (host_vars/<host>/hostkeys.vault.yml).
# Nothing is stored in the vault, so a host key rotation flows straight
# through — and this tool refuses to `set`/`generate`/`get` such a key, with
# a pointer to the declaration. A data key has exactly one source: derived,
# vault, or neither. Vault-backed and derived keys may share a secret (the
# private key from the vault, its known_hosts derived).
#
# Usage:
#   kubernetes_secret set      <cluster> <namespace> <secret> <key> [value|-]
#   kubernetes_secret generate <cluster> <namespace> <secret> <key>
#   kubernetes_secret generate-ssh-keypair <priv-cluster> <priv-ns> <priv-secret> <priv-key> <pub-cluster> <pub-ns> <pub-secret> <pub-key> [comment]
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
# `generate-ssh-keypair` is the same idea for an ssh key pair (ed25519): the
# PRIVATE half lands in the first secret and the PUBLIC half in the second,
# which may be in a DIFFERENT cluster — the usual shape, since the side that
# must trust the key is rarely the side that uses it. The key material is
# created in a shredded temp dir and never passes through argv, a shell
# variable or a file that outlives the command; the human never sees the
# private half. Both halves are written in one go (no half-provisioned
# state) and neither destination key is overwritten — rotation is a
# deliberate delete of both first. The optional comment goes into the
# public key (default: <priv-secret>@<priv-cluster>).
# `get` resolves references transparently; `list` shows them alongside the
# vault entries. `delete` removes one key, or the whole secret when key is
# omitted; a secret still pointed at by a reference cannot be deleted.
# `copy` duplicates one value to another key/secret/namespace/cluster (both
# clusters must be in this project); `move` is copy + delete of the source
# key, with the same guards as delete. Neither overwrites an existing
# destination key — delete it first if you really mean to replace it.
# EVERY command starts by fetching the EFFECTIVE contract (checked-in
# contract variables merged with whatever enabled role components derive)
# through the kubernetes role's secrets_contract entrypoint — so warnings,
# delete guards and references always see component-derived requirements;
# this tool itself knows nothing about components. No host connections are
# made, but the cluster's inventory group must exist. `check` additionally
# validates contract vs vault both ways and exits non-zero on any problem.

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
require_cmd ansible
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
TMP_CONTRACT_DST="$(mktemp)"
# ssh-keygen needs to WRITE two files itself (and refuses to overwrite), so
# the key pair gets a private dir instead of mktemp files. Shredded below.
TMP_SSHDIR="$(mktemp -d)"
cleanup() {
  shred -u "$TMP_PLAIN" "$TMP_VALUE" "$TMP_DST" \
    "$TMP_CONTRACT" "$TMP_CONTRACT_DST" 2>/dev/null \
    || rm -f "$TMP_PLAIN" "$TMP_VALUE" "$TMP_DST" \
      "$TMP_CONTRACT" "$TMP_CONTRACT_DST"
  if [ -d "$TMP_SSHDIR" ]; then
    find "$TMP_SSHDIR" -type f -exec shred -u {} + 2>/dev/null \
      || rm -f "$TMP_SSHDIR"/*
    rmdir "$TMP_SSHDIR" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Fetch the EFFECTIVE contract for a cluster (see the header) to a local
# file. Pure controller-side work: no host connections, one cached vault
# password fetch shared with the ansible-vault calls below.
fetch_contract() {
  local cluster="$1" out="$2"
  if ! ansible "k3s_${cluster}" -m include_role \
      -a "name=infra.base.kubernetes tasks_from=secrets_contract" \
      -e "kubernetes_secrets_contract_dest=$out" \
      -e "ansible_python_interpreter=auto_silent" >/dev/null; then
    echo "ERROR: Failed to fetch the secrets contract via ansible (cluster ${cluster})" >&2
    exit 1
  fi
  if [ ! -s "$out" ]; then
    echo "ERROR: Got no contract — does inventory group k3s_${cluster} have a server?" >&2
    exit 1
  fi
}

fetch_contract "$CLUSTER" "$TMP_CONTRACT"

# Decrypt the current vault contents (empty file when the vault does not
# exist yet) — all YAML work happens on the plaintext in python below.
# `check` never needs it: it works from the contract's vault structure.
if [ "$ACTION" != "check" ] && [ -f "$VAULT_FILE" ]; then
  ansible-vault view "$VAULT_FILE" > "$TMP_PLAIN"
fi

# One python entrypoint for everything YAML: reads the decrypted plaintext
# and the declared contract, performs the operation, and (for mutations)
# rewrites the plaintext for re-encryption. The secret value travels via
# the environment, never argv (argv is world-readable in /proc).
run_py() {
  KS_PLAIN="$TMP_PLAIN" KS_VALUE_FILE="$TMP_VALUE" \
  KS_CONTRACT="$TMP_CONTRACT" \
  KS_DECLARED="$DECLARED_FILE" KS_CLUSTER="$CLUSTER" \
    python3 - "$@" <<'PY'
import json, os, sys, yaml
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

# The EFFECTIVE contract, fetched through the kubernetes role's
# secrets_contract entrypoint before python runs: the checked-in contract
# variables (required/generated/optional/references) merged with whatever
# enabled components derive, plus the vault structure (names only). Every
# declared/reference decision below uses it — never raw files — so
# component-derived requirements are always visible.
def load_contract(path):
    with open(path) as f:
        data = json.load(f)
    return {k: (data.get(k) or {}) for k in
            ("required", "generated", "optional", "references",
             "known_hosts", "vault")}

contract = load_contract(os.environ["KS_CONTRACT"])

def declared_keys(ref, c=None):
    c = c or contract
    return (set(c["required"].get(ref) or [])
            | set(c["generated"].get(ref) or [])
            | set(c["optional"].get(ref) or []))

def required_keys(ref, c=None):
    # generated entries are required too — they just carry a different verb.
    c = c or contract
    return set(c["required"].get(ref) or []) | set(c["generated"].get(ref) or [])

# DERIVED keys (kubernetes_known_hosts_secrets in the declared file): built
# by the role from the host keys this repo already manages, never stored in
# the vault. This tool therefore refuses to write them and cannot read them
# back — it would be lying about where the value comes from.
def derived_keys(ref, c=None):
    c = c or contract
    return set(c["known_hosts"].get(ref) or [])

def refuse_if_derived(ref, key, c=None, path=None, cluster_name=None):
    if key in derived_keys(ref, c):
        sys.exit(f"ERROR: {ref} key '{key}' (cluster "
                 f"{cluster_name or cluster}) is DERIVED from host keys "
                 "(kubernetes_known_hosts_secrets in "
                 f"{os.path.relpath(path or declared_path)}) — the role "
                 "renders it at deploy time, so there is nothing to store "
                 "here. Change the declaration instead.")

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
references = contract["references"]

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
    refuse_if_derived(ref, key)
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
    refuse_if_derived(ref, key)
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

elif op == "generate-ssh-keypair":
    # The two halves of one ed25519 key pair, written in a single pass:
    # the private one here, the public one in (possibly) another cluster's
    # vault. ssh-keygen has already created them in the shredded temp dir.
    ns, name, key, pns, pname, pkey = args
    ref = f"{ns}/{name}"
    pref = f"{pns}/{pname}"
    same_vault = os.environ.get("KS_SAME_VAULT") == "1"
    pub_cluster = os.environ["KS_CLUSTER_DST"]
    pub_declared_path = os.environ["KS_DECLARED_DST"]
    if same_vault:
        pub_secrets = secrets
        pub_contract = contract
    else:
        pub_secrets = load_secrets(os.environ["KS_PLAIN_DST"])
        pub_contract = load_contract(os.environ["KS_CONTRACT_DST"])
    pub_references = pub_contract["references"]

    if same_vault and ref == pref and key == pkey:
        sys.exit("ERROR: the private and public halves would overwrite each "
                 "other — give them different secrets or keys")
    for entry, refs, path, cluster_name in (
            (ref, references, declared_path, cluster),
            (pref, pub_references, pub_declared_path, pub_cluster)):
        if entry in refs:
            sys.exit(f"ERROR: {entry} (cluster {cluster_name}) is declared as "
                     f"a reference to {refs[entry]} in "
                     f"{os.path.relpath(path)} — write to the target "
                     "instead, or remove the reference")
    refuse_if_derived(ref, key)
    refuse_if_derived(pref, pkey, pub_contract, pub_declared_path, pub_cluster)
    # Neither half is overwritten: a key pair is rotated deliberately, by
    # deleting BOTH halves first (a new private key with the old public one
    # left in place would lock the tunnel out).
    if key in secrets.get(ref, {}):
        sys.exit(f"ERROR: {ref} key '{key}' already exists in cluster "
                 f"{cluster} — delete both halves first to rotate the pair")
    if pkey in pub_secrets.get(pref, {}):
        sys.exit(f"ERROR: {pref} key '{pkey}' already exists in cluster "
                 f"{pub_cluster} — delete both halves first to rotate the pair")

    ssh_dir = os.environ["KS_SSH_DIR"]
    with open(os.path.join(ssh_dir, "key")) as f:
        private = f.read()
    with open(os.path.join(ssh_dir, "key.pub")) as f:
        public = f.read()
    if not private or not public:
        sys.exit("ERROR: ssh-keygen produced an empty key pair")

    secrets.setdefault(ref, {})[key] = private
    pub_secrets.setdefault(pref, {})[pkey] = public
    if same_vault:
        save_secrets(secrets)
    else:
        # Public half first: if the private encrypt then failed, the pair is
        # recoverable (delete the public half and run again) rather than the
        # private key being the only thing that survived.
        save_secrets(pub_secrets, os.environ["KS_PLAIN_DST"], pub_cluster)
        save_secrets(secrets)
    print(f"Generated ssh key pair: private -> {ref} key '{key}' "
          f"(cluster {cluster}), public -> {pref} key '{pkey}' "
          f"(cluster {pub_cluster})")
    print(f"Public key: {public.strip()}")
    for entry, data_key, c, path in (
            (ref, key, contract, declared_path),
            (pref, pkey, pub_contract, pub_declared_path)):
        if data_key not in declared_keys(entry, c):
            print(f"WARNING: {entry} key '{data_key}' is not declared — add "
                  f"it to {os.path.relpath(path)} (required or optional), or "
                  "the Reports step will flag it as stale.", file=sys.stderr)

elif op == "get":
    ns, name, key = args
    ref = f"{ns}/{name}"
    if ref in references and references[ref] not in secrets:
        sys.exit(f"ERROR: {ref} is a reference to {references[ref]}, which "
                 "is not in the vault (broken reference)")
    refuse_if_derived(ref, key)
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
        dst_contract = contract
    else:
        dst_secrets = load_secrets(os.environ["KS_PLAIN_DST"])
        dst_contract = load_contract(os.environ["KS_CONTRACT_DST"])
    dst_references = dst_contract["references"]

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
        if skey in required_keys(src):
            print(f"WARNING: {src} key '{skey}' is REQUIRED by the effective "
                  f"contract in cluster {cluster} — the next ansible run "
                  "will fail until it is set again (or the requirement "
                  "itself is removed).", file=sys.stderr)
    if dkey not in declared_keys(dst, dst_contract):
        print(f"WARNING: {dst} key '{dkey}' is not declared — add it to "
              f"{os.path.relpath(dst_declared_path)} (required or optional), "
              "or the Reports step will flag it as stale.", file=sys.stderr)

elif op == "list":
    known = contract["known_hosts"]
    if not secrets and not references and not known:
        print("(no secrets in vault)")
    for ref in sorted(secrets):
        print(f"{ref}: {', '.join(sorted(secrets[ref]))}")
    for ref in sorted(known):
        print(f"{ref}: {', '.join(sorted(known[ref] or []))} "
              "(derived: known_hosts)")
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
    # Deleting a secret (or its last key) would leave any reference pointing
    # at it dangling — an invalid state this tool never writes.
    refs_here = referrers(references, ref)
    if key is None:
        if refs_here:
            sys.exit(f"ERROR: {ref} is referenced by {', '.join(refs_here)} — "
                     "remove the reference(s) from "
                     f"{os.path.relpath(declared_path)} first")
        removed = sorted(secrets.pop(ref))
        required_hit = sorted(set(removed) & required_keys(ref))
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
        required_hit = [key] if key in required_keys(ref) else []
    save_secrets(secrets)
    print(f"Deleted {ref} key(s): {', '.join(removed)}")
    if required_hit:
        print(f"WARNING: {ref} key(s) {', '.join(required_hit)} are REQUIRED "
              "by the effective contract — the next ansible run will fail "
              "until they are set again (or the requirement itself is "
              "removed).", file=sys.stderr)

elif op == "check":
    c_required = contract["required"]
    c_generated = contract["generated"]
    c_optional = contract["optional"]
    c_references = contract["references"]
    c_known = contract["known_hosts"]  # derived, never in the vault
    c_vault = contract["vault"]  # "<ns>/<name>" -> [key, ...]
    problems = 0

    def vault_keys(ref):
        target = c_references.get(ref)
        ref = target if target is not None else ref
        return set(c_vault.get(ref) or []) | set(c_known.get(ref) or [])

    for ref in sorted(c_references):
        target = c_references[ref]
        if ref in c_vault:
            problems += 1
            print(f"COLLIDING reference: {ref} -> {target}, but {ref} is "
                  "also a concrete vault entry — remove one of them")
        if ref in c_known:
            problems += 1
            print(f"COLLIDING reference: {ref} -> {target}, but {ref} also "
                  "declares derived known_hosts keys — remove one of them")
        if target in c_references:
            problems += 1
            print(f"INVALID reference: {ref} -> {target}, which is itself a "
                  f"reference (to {c_references[target]}) — references must "
                  "point at a concrete secret")
        elif target not in c_vault and target not in c_known:
            problems += 1
            print(f"BROKEN reference: {ref} -> {target} (target exists "
                  "neither in the vault nor as a derived entry) — the "
                  "ansible run will refuse to deploy manifests")

    # A data key has exactly one source. Declaring a derived key in the
    # contract too (or leaving a stored copy in the vault) is what the
    # ansible run fails on — name it here, where it is cheap to find.
    for ref in sorted(c_known):
        derived = set(c_known[ref] or [])
        for key in sorted(derived & set(c_vault.get(ref) or [])):
            problems += 1
            print(f"TWO SOURCES: {ref} key '{key}' is derived "
                  "(kubernetes_known_hosts_secrets) but also stored in the "
                  "vault\n  -> remove the stored copy: ./infratool "
                  f"kubernetes_secret delete {cluster} "
                  f"{ref.split('/', 1)[0]} {ref.split('/', 1)[1]} {key}")
        for key in sorted(derived & (set(c_required.get(ref) or [])
                                     | set(c_generated.get(ref) or [])
                                     | set(c_optional.get(ref) or []))):
            problems += 1
            print(f"TWO SOURCES: {ref} key '{key}' is derived "
                  "(kubernetes_known_hosts_secrets) but also declared as "
                  "required/generated/optional\n  -> remove it from the "
                  f"contract in {os.path.relpath(declared_path)}")
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
    # Derived keys count as declared here, so a stored copy of one is
    # reported as TWO SOURCES above and not a second time as stale.
    declared = {ref: set(c_required.get(ref) or []) | set(c_generated.get(ref) or [])
                     | set(c_optional.get(ref) or []) | set(c_known.get(ref) or [])
                for ref in set(c_required) | set(c_generated) | set(c_optional)
                            | set(c_known)}
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
  generate-ssh-keypair)
    [ "$#" -ge 9 ] && [ "$#" -le 10 ] || usage
    require_cmd ssh-keygen
    validate_ns_name_key "$3" "$4" "$5"
    PUB_CLUSTER="$6"
    if ! printf '%s' "$PUB_CLUSTER" | grep -Eq '^[a-z0-9-]+$'; then
      echo "ERROR: Cluster name must match ^[a-z0-9-]+$: $PUB_CLUSTER" >&2
      exit 1
    fi
    PUB_CLUSTER_DIR="$PROJECT_ROOT/inventory/group_vars/k3s_${PUB_CLUSTER}"
    if [ ! -d "$PUB_CLUSTER_DIR" ]; then
      echo "ERROR: No such cluster group_vars directory: $PUB_CLUSTER_DIR" >&2
      exit 1
    fi
    validate_ns_name_key "$7" "$8" "$9"
    # ed25519: one shape, no size knob to get wrong. The pair is created in
    # the shredded temp dir and read from there by python — the material
    # never reaches argv or a shell variable.
    ssh-keygen -q -t ed25519 -N '' -C "${10:-$4@$CLUSTER}" -f "$TMP_SSHDIR/key"
    export KS_SSH_DIR="$TMP_SSHDIR"
    export KS_CLUSTER_DST="$PUB_CLUSTER"
    export KS_DECLARED_DST="$PUB_CLUSTER_DIR/kubernetes_secrets_declared.yml"
    # No source-vault requirement (unlike copy): a key pair may well be the
    # first secret a cluster gets.
    if [ "$CLUSTER" = "$PUB_CLUSTER" ]; then
      # One vault: python mutates the single plaintext, re-encrypted once.
      export KS_SAME_VAULT=1 KS_PLAIN_DST="$TMP_PLAIN"
      run_py "$ACTION" "$3" "$4" "$5" "$7" "$8" "$9"
      encrypt_back
    else
      fetch_contract "$PUB_CLUSTER" "$TMP_CONTRACT_DST"
      PUB_VAULT_FILE="$PUB_CLUSTER_DIR/kubernetes_secrets.vault.yml"
      if [ -f "$PUB_VAULT_FILE" ]; then
        ansible-vault view "$PUB_VAULT_FILE" > "$TMP_DST"
      fi
      export KS_SAME_VAULT=0 KS_PLAIN_DST="$TMP_DST" \
        KS_CONTRACT_DST="$TMP_CONTRACT_DST"
      run_py "$ACTION" "$3" "$4" "$5" "$7" "$8" "$9"
      # Public half first: a failure after it leaves a recoverable state
      # (delete the public half and run again), not a private key whose
      # public counterpart was lost.
      encrypt_back "$TMP_DST" "$PUB_VAULT_FILE"
      encrypt_back
    fi
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
      fetch_contract "$DST_CLUSTER" "$TMP_CONTRACT_DST"
      DST_VAULT_FILE="$DST_CLUSTER_DIR/kubernetes_secrets.vault.yml"
      if [ -f "$DST_VAULT_FILE" ]; then
        ansible-vault view "$DST_VAULT_FILE" > "$TMP_DST"
      fi
      export KS_SAME_VAULT=0 KS_PLAIN_DST="$TMP_DST" \
        KS_CONTRACT_DST="$TMP_CONTRACT_DST"
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
    run_py check
    ;;
  *)
    usage
    ;;
esac
