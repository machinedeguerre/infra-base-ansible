#!/usr/bin/env bash
#
# Generate a self-contained Nebula bundle (.zip) for a host that is NOT
# managed by this Ansible project. The bundle contains everything needed
# to run Nebula on the target via Docker:
#
#   pki/ca.crt          - Nebula CA certificate
#   pki/host.crt        - Signed host certificate
#   pki/host.key        - Host private key
#   nebula.yml          - Nebula config
#   Dockerfile          - Builds a container with the pinned nebula binary
#   docker-compose.yml  - Runs nebula on host networking with the tun device
#   README.txt          - Install instructions + the command that produced it
#
# Shared config (listen port, lighthouses, static host map, unsafe routes,
# cert duration, nebula version) is taken from inventory/group_vars/all and
# the nebula role's defaults, so an external node lands on the same mesh
# and cert-rotation cadence as hosts managed by the `nebula` role.
#
# Usage:
#   infratool generate_nebula_bundle \
#     --name NAME --ip IP --groups G1,G2 [--unsafe-networks CIDRs] [--output PATH]

set -euo pipefail

usage() {
  cat >&2 <<EOF
Usage: infratool generate_nebula_bundle --name NAME --ip IP --groups G1,G2 [OPTIONS]

Required:
  --name NAME               Cert name (identifies the host; also used for zip filename)
  --ip IP                   Nebula overlay IP (e.g. 172.24.1.99)
  --groups G1,G2,...        Comma-separated group list embedded in the cert

Optional:
  --unsafe-networks CIDRs   Comma-separated subnets this host is authorized
                            to route through Nebula (embedded in cert).
  --duration DUR            Cert validity as a Go duration (e.g. 87600h for
                            ~10 years). Default: nebula_cert_duration from
                            role defaults / group_vars. External hosts get no
                            automatic rotation, so longer durations are OK here.
  --activate-lighthouse     Make this host a lighthouse AND relay. Also
                            adds "lighthouse" to the cert's groups if not
                            already present.
  --output PATH             Output zip path. Default: ./nebula-<NAME>-<YYYY-MM-DD>.zip
  -h, --help                Show this help.
EOF
  exit "${1:-1}"
}

# --- Argument parsing -------------------------------------------------------

NAME=""
IP=""
CERT_GROUPS=""
UNSAFE_NETWORKS=""
OUTPUT=""
ACTIVATE_LIGHTHOUSE=0
DURATION=""

# Preserve the original argv so the README can show the exact command that
# produced the bundle (copy-pasteable to regenerate later).
ORIG_ARGV=("$@")

while [ "$#" -gt 0 ]; do
  case "$1" in
    --name)                 NAME="$2"; shift 2 ;;
    --ip)                   IP="$2"; shift 2 ;;
    --groups)               CERT_GROUPS="$2"; shift 2 ;;
    --unsafe-networks)      UNSAFE_NETWORKS="$2"; shift 2 ;;
    --duration)             DURATION="$2"; shift 2 ;;
    --activate-lighthouse)  ACTIVATE_LIGHTHOUSE=1; shift ;;
    --output)               OUTPUT="$2"; shift 2 ;;
    -h|--help)              usage 0 ;;
    *) echo "ERROR: Unknown argument: $1" >&2; usage ;;
  esac
done

if [ -z "$NAME" ] || [ -z "$IP" ] || [ -z "$CERT_GROUPS" ]; then
  echo "ERROR: --name, --ip and --groups are required" >&2
  usage
fi

# When acting as a lighthouse, the cert should also carry the "lighthouse"
# group so mesh-wide firewall policies that reference `group: lighthouse`
# apply consistently.
if [ "$ACTIVATE_LIGHTHOUSE" = "1" ] \
   && [[ ",${CERT_GROUPS}," != *,lighthouse,* ]]; then
  CERT_GROUPS="${CERT_GROUPS},lighthouse"
fi

if [[ ! "$NAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "ERROR: --name must contain only [A-Za-z0-9._-]" >&2
  exit 1
fi

if [[ ! "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: --ip must be a plain IPv4 address (e.g. 172.24.1.99)" >&2
  exit 1
fi

if [ -n "$DURATION" ] && [[ ! "$DURATION" =~ ^([0-9]+h)?([0-9]+m)?([0-9]+s)?$ || -z "$DURATION" ]]; then
  echo "ERROR: --duration must be a Go duration like 87600h or 2160h30m" >&2
  exit 1
fi

# Date stamp is used both for the default zip filename and for the wrapping
# directory inside the zip so extracting never spills files into the cwd.
DATE_STAMP="$(date +%Y-%m-%d)"
BUNDLE_DIR="nebula-${NAME}-${DATE_STAMP}"
: "${OUTPUT:=$(pwd)/${BUNDLE_DIR}.zip}"

# --- Command availability ---------------------------------------------------

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: Missing required command: $1" >&2
    exit 127
  }
}

require_cmd nebula-cert
require_cmd ansible-vault
require_cmd zip
require_cmd python3
require_cmd mktemp

# --- Project file locations -------------------------------------------------

VAULT_FILE="$PROJECT_ROOT/inventory/group_vars/all/nebula_ca.vault.yml"
GROUP_VARS_FILE="$PROJECT_ROOT/inventory/group_vars/all/main.yml"
ROLE_DEFAULTS_FILE="$COLLECTION_ROOT/roles/nebula/defaults/main.yml"

for f in "$VAULT_FILE" "$GROUP_VARS_FILE" "$ROLE_DEFAULTS_FILE"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: Required file not found: $f" >&2
    exit 1
  fi
done

# --- Working directory ------------------------------------------------------

umask 077
WORK_DIR="$(mktemp -d -t nebula-bundle-XXXXXX)"
STAGE_DIR="$WORK_DIR/$BUNDLE_DIR"
PKI_DIR="$STAGE_DIR/pki"
mkdir -p "$PKI_DIR"

cleanup() {
  if [[ -n "${WORK_DIR:-}" && -d "${WORK_DIR:-}" ]]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

# --- Merge nebula settings from role defaults + group_vars/all --------------
# Values follow the same precedence Ansible uses at play time: group_vars
# override role defaults. Everything below (version, listen port, lighthouses,
# static host map, unsafe routes) is authoritative — this tool intentionally
# does NOT expose CLI flags to override them. Cert duration is the exception:
# --duration overrides it, since external hosts have no automatic rotation.

export BUNDLE_ROLE_DEFAULTS="$ROLE_DEFAULTS_FILE"
export BUNDLE_GROUP_VARS="$GROUP_VARS_FILE"

eval "$(
python3 <<'PY'
import os, shlex, yaml
def load(path):
    with open(path) as f:
        return yaml.safe_load(f) or {}
d = load(os.environ["BUNDLE_ROLE_DEFAULTS"])
d.update(load(os.environ["BUNDLE_GROUP_VARS"]))
print("NEBULA_VERSION="       + shlex.quote(str(d["nebula_version"])))
print("NEBULA_CERT_DURATION=" + shlex.quote(str(d["nebula_cert_duration"])))
print("NEBULA_LISTEN_PORT="   + shlex.quote(str(d.get("nebula_listen_port", 4242))))
PY
)"

if [ -n "$DURATION" ]; then
  NEBULA_CERT_DURATION="$DURATION"
fi

# --- Extract CA material from the vault -------------------------------------

echo "Decrypting CA material from vault..."
ansible-vault view "$VAULT_FILE" --vault-id project > "$WORK_DIR/ca_vault.yml"

python3 - "$WORK_DIR/ca_vault.yml" "$PKI_DIR/ca.crt" "$WORK_DIR/ca.key" <<'PY'
import sys, yaml
vault_path, ca_crt_out, ca_key_out = sys.argv[1:4]
with open(vault_path) as f:
    d = yaml.safe_load(f)
for key, out in (("nebula_ca_crt_pem", ca_crt_out),
                 ("nebula_ca_key_pem", ca_key_out)):
    if key not in d:
        sys.exit(f"ERROR: '{key}' not found in vault file")
    with open(out, "w") as f:
        f.write(d[key])
PY

# --- Sign the host certificate ---------------------------------------------

echo "Signing host certificate for ${NAME} (${IP}/16) [duration=${NEBULA_CERT_DURATION}]..."
SIGN_ARGS=(
  sign
  -ca-crt "$PKI_DIR/ca.crt"
  -ca-key "$WORK_DIR/ca.key"
  -name   "$NAME"
  -networks "${IP}/16"
  -groups "$CERT_GROUPS"
  -duration "$NEBULA_CERT_DURATION"
  -out-crt "$PKI_DIR/host.crt"
  -out-key "$PKI_DIR/host.key"
)
if [ -n "$UNSAFE_NETWORKS" ]; then
  SIGN_ARGS+=(-unsafe-networks "$UNSAFE_NETWORKS")
fi
nebula-cert "${SIGN_ARGS[@]}"

# --- Render nebula.yml ------------------------------------------------------

echo "Rendering nebula.yml..."
export BUNDLE_NAME="$NAME"
export BUNDLE_IP="$IP"
export BUNDLE_GROUPS="$CERT_GROUPS"
export BUNDLE_UNSAFE_NETWORKS="$UNSAFE_NETWORKS"
export BUNDLE_LISTEN_PORT="$NEBULA_LISTEN_PORT"
export BUNDLE_IS_LIGHTHOUSE="$ACTIVATE_LIGHTHOUSE"

python3 - "$STAGE_DIR/nebula.yml" <<'PY'
import os, sys, yaml

out_path = sys.argv[1]
name = os.environ["BUNDLE_NAME"]
ip = os.environ["BUNDLE_IP"]
groups = [g for g in os.environ["BUNDLE_GROUPS"].split(",") if g]
unsafe_networks = [n for n in os.environ["BUNDLE_UNSAFE_NETWORKS"].split(",") if n]
listen_port = int(os.environ["BUNDLE_LISTEN_PORT"])
is_lighthouse = os.environ["BUNDLE_IS_LIGHTHOUSE"] == "1"
group_vars_path = os.environ["BUNDLE_GROUP_VARS"]

with open(group_vars_path) as f:
    gv = yaml.safe_load(f) or {}

lighthouse_ip = gv.get("nebula_lighthouse_ip", []) or []
static_host_map = gv.get("nebula_static_host_map", {}) or {}
unsafe_routes = gv.get("nebula_unsafe_routes", []) or []

# Same filtering the role's template does: drop routes that point at
# ourselves, and drop routes whose CIDR is already served locally.
filtered_routes = [
    r for r in unsafe_routes
    if r.get("via") != ip and r.get("route") not in unsafe_networks
]

# When this host is itself a lighthouse, its own IP must not appear as
# either a static-host entry or in the list of lighthouses to contact.
filtered_static_host_map = {
    k: list(v) for k, v in static_host_map.items()
    if not (is_lighthouse and k == ip)
}
peer_lighthouses = [
    lh for lh in lighthouse_ip
    if not (is_lighthouse and lh == ip)
]

lighthouse_section = {
    "am_lighthouse": is_lighthouse,
    "interval": 60,
    "hosts": peer_lighthouses,
}

# Lighthouses act as relays for everyone else; regular hosts route through
# the mesh's lighthouses when direct hole-punching fails.
if is_lighthouse:
    relay_section = {"am_relay": True, "use_relays": False}
else:
    relay_section = {
        "am_relay": False,
        "use_relays": True,
        "relays": list(lighthouse_ip),
    }

config = {
    "pki": {
        "ca":   "/etc/nebula/pki/ca.crt",
        "cert": "/etc/nebula/pki/host.crt",
        "key":  "/etc/nebula/pki/host.key",
    },
    "static_host_map": filtered_static_host_map,
    "lighthouse": lighthouse_section,
    "listen": {"host": "0.0.0.0", "port": listen_port},
    # Maximally aggressive NAT traversal: punch, respond, and keep the
    # delays as low as Nebula allows so tunnels come up quickly on flaky
    # or CGNAT'd links.
    "punchy": {
        "punch": True,
        "respond": True,
        "delay": "1s",
        "respond_delay": "1s",
    },
    "relay": relay_section,
    "tun": {"device": "tun0"},
    "firewall": {
        "inbound": [
            {"port": "any", "proto": "icmp", "host": "any"},
            {"port": 22,    "proto": "tcp",  "host": "any"},
        ],
        "outbound": [
            {"port": "any", "proto": "any", "host": "any"},
        ],
    },
}

if filtered_routes:
    config["tun"]["unsafe_routes"] = [
        {"route": r["route"], "via": r["via"]} for r in filtered_routes
    ]

if unsafe_networks:
    for rule in config["firewall"]["inbound"]:
        rule["local_cidr"] = "any"
    for rule in config["firewall"]["outbound"]:
        rule["local_cidr"] = "any"
    for subnet in unsafe_networks:
        config["firewall"]["inbound"].append({
            "port": "any", "proto": "any", "group": "sysop",
            "local_cidr": subnet,
        })

role = "lighthouse + relay" if is_lighthouse else "client"
header = (
    f"# Nebula config for {name} ({ip}) — role: {role}\n"
    f"# Generated by infratool generate_nebula_bundle.\n"
    f"# Groups embedded in cert: {', '.join(groups)}\n"
    "# Adjust the firewall section to fit this host's role.\n\n"
)
with open(out_path, "w") as f:
    f.write(header)
    yaml.safe_dump(config, f, sort_keys=False, default_flow_style=False)
PY

# --- Dockerfile -------------------------------------------------------------

cat > "$STAGE_DIR/Dockerfile" <<EOF
# Pinned to match the nebula version used by the Ansible-managed hosts.
FROM debian:12-slim

ARG NEBULA_VERSION=${NEBULA_VERSION}

RUN apt-get update \\
 && apt-get install -y --no-install-recommends ca-certificates curl \\
 && rm -rf /var/lib/apt/lists/* \\
 && arch=\$(dpkg --print-architecture) \\
 && case "\$arch" in \\
      amd64) narch=amd64 ;; \\
      arm64) narch=arm64 ;; \\
      armhf) narch=armv7 ;; \\
      *) echo "unsupported arch: \$arch" >&2; exit 1 ;; \\
    esac \\
 && curl -fsSL -o /tmp/nebula.tgz \\
      "https://github.com/slackhq/nebula/releases/download/v\${NEBULA_VERSION}/nebula-linux-\${narch}.tar.gz" \\
 && tar -xzf /tmp/nebula.tgz -C /usr/local/bin nebula \\
 && rm /tmp/nebula.tgz

ENTRYPOINT ["/usr/local/bin/nebula", "-config", "/etc/nebula/nebula.yml"]
EOF

# --- docker-compose.yml -----------------------------------------------------

cat > "$STAGE_DIR/docker-compose.yml" <<'EOF'
services:
  nebula:
    build: .
    container_name: nebula
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_BIND_SERVICE
    devices:
      - /dev/net/tun:/dev/net/tun
    volumes:
      - ./nebula.yml:/etc/nebula/nebula.yml:ro
      - ./pki:/etc/nebula/pki:ro
EOF

# --- README -----------------------------------------------------------------

# Rebuild a copy-pasteable command line from the parsed args so users can
# regenerate this exact bundle later.
QUOTED_CMD="infratool generate_nebula_bundle"
for a in "${ORIG_ARGV[@]}"; do
  QUOTED_CMD+=" $(printf '%q' "$a")"
done

cat > "$STAGE_DIR/README.txt" <<EOF
Nebula bundle for host: ${NAME}
Nebula IP:  ${IP}
Groups:     ${CERT_GROUPS}
Generated:  $(date -Iseconds)

Created with:
  ${QUOTED_CMD}

Contents
--------
  pki/ca.crt          Nebula CA certificate
  pki/host.crt        Signed host certificate (valid for ${NEBULA_CERT_DURATION})
  pki/host.key        Host private key (keep secret!)
  nebula.yml          Nebula config (edit firewall rules as needed)
  Dockerfile          Builds a container with nebula v${NEBULA_VERSION}
  docker-compose.yml  Runs nebula with host networking + /dev/net/tun

Install on target host
----------------------
  sudo unzip -o $(basename "$OUTPUT") -d /etc      # extracts into /etc/${BUNDLE_DIR}
  sudo chown -R root:root /etc/${BUNDLE_DIR}
  sudo chmod 0600 /etc/${BUNDLE_DIR}/pki/host.key
  cd /etc/${BUNDLE_DIR}
  sudo docker compose up -d --build

Verify
------
  sudo docker compose ps
  sudo docker compose logs -f nebula
  ping ${IP}     # from another mesh member
EOF

# --- Zip it up --------------------------------------------------------------

echo "Building zip: ${OUTPUT}"
rm -f "$OUTPUT"
( cd "$WORK_DIR" && zip -qr "$OUTPUT" "$BUNDLE_DIR" )

echo
if [ "$ACTIVATE_LIGHTHOUSE" = "1" ]; then
  ROLE_SUMMARY="lighthouse+relay"
else
  ROLE_SUMMARY="client"
fi

echo "Done."
echo "  Bundle: $OUTPUT"
echo "  Cert:   name=$NAME ip=$IP groups=$CERT_GROUPS duration=$NEBULA_CERT_DURATION role=$ROLE_SUMMARY"
