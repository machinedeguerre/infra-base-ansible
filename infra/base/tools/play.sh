#!/usr/bin/env bash
set -euo pipefail

# infratool play — run ansible-playbook with strict SSH host key checking
# against a known_hosts file derived from the vaulted host keys.
#
# Regenerates <project>/.known_hosts from inventory/host_vars/*/hostkeys.vault.yml
# when stale (any file under inventory/ newer than it, or line count mismatch),
# then execs ansible-playbook with the given arguments.
#
# Usage:
#   ./infratool play [--tofu] <ansible-playbook arguments...>
#
#   --tofu   Disable host key checking for THIS run only. Use solely when
#            bootstrapping a freshly installed host: it still presents its
#            installer-generated host keys until the sshd role has deployed
#            the vaulted ones, after which strict checking works.

KNOWN_HOSTS="${PROJECT_ROOT}/.known_hosts"

usage() {
  sed -n '3,17p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 1
}

TOFU=0
if [ "${1:-}" = "--tofu" ]; then
  TOFU=1
  shift
fi
[ "$#" -ge 1 ] || usage

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: Required command not found: $1" >&2
    exit 127
  }
}
require ansible-playbook
require ansible-inventory
require ansible-vault
require python3

# The cache is only a convenience: a stale file can never open anything up —
# SSH fails closed on a missing or mismatching key, and the fix is a regen.
known_hosts_is_fresh() {
  [ -s "$KNOWN_HOSTS" ] || return 1
  local expected actual
  expected="$(sed -n '1s/^# infratool-known-hosts lines=\([0-9][0-9]*\)$/\1/p' "$KNOWN_HOSTS")"
  [ -n "$expected" ] || return 1
  actual="$(grep -c '^[^#]' "$KNOWN_HOSTS" || true)"
  [ "$actual" = "$expected" ] || return 1
  [ -z "$(find "${PROJECT_ROOT}/inventory" -newer "$KNOWN_HOSTS" -print -quit)" ] || return 1
}

generate_known_hosts() {
  echo "Regenerating ${KNOWN_HOSTS} from vaulted host keys..." >&2
  umask 077
  local tmp
  tmp="$(mktemp "${KNOWN_HOSTS}.XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -f '${tmp}'" EXIT

  python3 - "$PROJECT_ROOT" > "$tmp" <<'PYEOF'
import json
import os
import subprocess
import sys

import yaml

root = sys.argv[1]

inv = json.loads(
    subprocess.run(
        ["ansible-inventory", "--list"],
        cwd=root, check=True, capture_output=True, text=True,
    ).stdout
)
hostvars = inv.get("_meta", {}).get("hostvars", {})

lines = []
for host in sorted(hostvars):
    vault = os.path.join(root, "inventory", "host_vars", host, "hostkeys.vault.yml")
    if not os.path.exists(vault):
        print(f"WARNING: {host}: no hostkeys.vault.yml - host key cannot be pinned; "
              f"connections to it will fail until keys are generated "
              f"(./infratool generate_sshd_hostkeys {host})", file=sys.stderr)
        continue

    hv = hostvars[host]
    addrs = []
    for var in ("ansible_host", "nebula_ip"):
        val = hv.get(var)
        if val and str(val) not in addrs:
            addrs.append(str(val))
    if not addrs:
        addrs = [host]

    data = yaml.safe_load(
        subprocess.run(
            ["ansible-vault", "view", vault],
            cwd=root, check=True, capture_output=True, text=True,
        ).stdout
    )
    for item in data.get("sshd_host_keys", []):
        pub = str(item.get("public", "")).strip()
        parts = pub.split()
        if len(parts) < 2:
            continue
        lines.append(f"{','.join(addrs)} {parts[0]} {parts[1]}")

print(f"# infratool-known-hosts lines={len(lines)}")
for line in lines:
    print(line)
PYEOF

  mv "$tmp" "$KNOWN_HOSTS"
  trap - EXIT
  echo "Wrote ${KNOWN_HOSTS} ($(grep -c '^[^#]' "$KNOWN_HOSTS" || true) entries)." >&2
}

if known_hosts_is_fresh; then
  echo "Using cached ${KNOWN_HOSTS}." >&2
else
  generate_known_hosts
fi

if [ "$TOFU" = "1" ]; then
  echo "WARNING: --tofu: SSH host key checking is DISABLED for this run." >&2
  export ANSIBLE_HOST_KEY_CHECKING=False
fi

exec ansible-playbook "$@"
