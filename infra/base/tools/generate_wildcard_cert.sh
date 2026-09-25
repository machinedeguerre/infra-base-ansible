#!/usr/bin/env bash
#
# Generate a Let's Encrypt wildcard certificate via the manual DNS-01 challenge.
#
# Usage: infratool generate_wildcard_cert <domain>
#
# Produces a wildcard cert valid for *.<domain> and <domain> itself, and stores
# it (fullchain + private key) in:
#
#   inventory/group_vars/all/wildcard_cert.<domain>.vault.yml
#
# If a vault file already exists for the domain and the cert inside it was
# issued less than 7 days ago (per the certificate's own notBefore field),
# regeneration is skipped.

set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "ERROR: Domain name is required (argument to this script)" >&2
  echo "Usage: infratool generate_wildcard_cert <domain>" >&2
  exit 1
fi

DOMAIN="$1"

if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$ ]]; then
  echo "ERROR: Not a valid domain name: $DOMAIN" >&2
  exit 1
fi

VAULT_FILE="$PROJECT_ROOT/inventory/group_vars/all/wildcard_cert.${DOMAIN}.vault.yml"
VAULT_DIR="$(dirname "$VAULT_FILE")"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: Required command not found: $1" >&2
    exit 127
  }
}

require certbot
require ansible-vault
require openssl
require mktemp
require sed
require date
require dig

# ---------------------------------------------------------------------------
# Skip if an existing cert is still fresh (< 7 days old by notBefore).
# ---------------------------------------------------------------------------
if [ -f "$VAULT_FILE" ]; then
  # The PEM is stored indented under a YAML block scalar; strip leading
  # whitespace or openssl refuses to parse it.
  existing_cert=$(
    ansible-vault view "$VAULT_FILE" \
      | sed -n 's/^[[:space:]]*//; /-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p'
  )

  if [ -n "$existing_cert" ]; then
    if not_before=$(echo "$existing_cert" | openssl x509 -noout -startdate 2>/dev/null | sed 's/^notBefore=//') \
        && [ -n "$not_before" ]; then
      not_before_epoch=$(date -d "$not_before" +%s)
      seven_days_ago=$(date -d '7 days ago' +%s)

      if [ "$not_before_epoch" -gt "$seven_days_ago" ]; then
        age_days=$(( ($(date +%s) - not_before_epoch) / 86400 ))
        echo "Existing certificate in $VAULT_FILE was issued ${age_days} day(s) ago — skipping (< 7 days old)."
        exit 0
      fi
    else
      echo "WARNING: Could not parse existing certificate in $VAULT_FILE — regenerating." >&2
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Run certbot in an isolated temp directory so nothing is written system-wide.
# A manual-auth-hook is generated on the fly: it prints the TXT record the
# user needs to deploy and then polls the zone's authoritative nameserver
# until the record is visible — so certbot only proceeds once propagation
# is confirmed, avoiding the "press Enter too early" failure mode.
# ---------------------------------------------------------------------------
WORK_DIR="$(mktemp -d)"
cleanup() {
  local rc=$?
  if [[ -n "${WORK_DIR:-}" && -d "${WORK_DIR:-}" ]]; then
    if [ "$rc" -ne 0 ]; then
      echo "" >&2
      echo "Script failed. Certbot logs preserved at:" >&2
      echo "  $WORK_DIR/logs/letsencrypt.log" >&2
      echo "Remove the directory manually when done: rm -rf $WORK_DIR" >&2
    else
      rm -rf "$WORK_DIR"
    fi
  fi
}
trap cleanup EXIT

umask 077

AUTH_HOOK="${WORK_DIR}/auth-hook.sh"
cat > "$AUTH_HOOK" <<'HOOK_EOF'
#!/usr/bin/env bash
set -euo pipefail

# Certbot captures stdout/stderr from hooks and only prints them after the
# hook returns -- so we write user-facing output to /dev/tty directly,
# bypassing the capture, so the user actually sees the prompts in real time.
exec >/dev/tty 2>&1

record_name="_acme-challenge.${CERTBOT_DOMAIN}"
expected="$CERTBOT_VALIDATION"
timeout_seconds=600
poll_interval=5

find_auth_ns() {
  local d="$1"
  while [ -n "$d" ] && [[ "$d" == *.* ]]; do
    local ns
    ns=$(dig +short NS "$d" 2>/dev/null | grep -v '^$' | head -1)
    if [ -n "$ns" ]; then
      echo "${ns%.}"
      return 0
    fi
    d="${d#*.}"
  done
  return 1
}

ns=$(find_auth_ns "$CERTBOT_DOMAIN") || {
  echo "ERROR: Could not find authoritative nameserver for $CERTBOT_DOMAIN"
  exit 1
}

cat <<EOF

================================================================
Deploy a DNS TXT record (ADDITIVE — do NOT remove any existing
_acme-challenge records added in a previous step):

  Name:  ${record_name}
  Type:  TXT
  Value: ${expected}

Authoritative NS to poll: ${ns}
Challenges remaining after this one: ${CERTBOT_REMAINING_CHALLENGES:-?}
================================================================

EOF

read -r -p "Press Enter once you have deployed the record to start polling... " </dev/tty

echo "Polling ${ns} every ${poll_interval}s (timeout ${timeout_seconds}s)..."

elapsed=0
while [ "$elapsed" -lt "$timeout_seconds" ]; do
  if dig @"$ns" +short TXT "$record_name" 2>/dev/null | grep -qF "\"${expected}\""; then
    echo "  → Record visible after ${elapsed}s. Waiting 5s for cache settle, then continuing."
    sleep 5
    exit 0
  fi
  sleep "$poll_interval"
  elapsed=$((elapsed + poll_interval))
  printf "  ... still waiting (%ds elapsed)\n" "$elapsed"
done

echo "ERROR: Timed out after ${timeout_seconds}s waiting for TXT record."
exit 1
HOOK_EOF
chmod +x "$AUTH_HOOK"

echo ""
echo "Requesting certificate for *.${DOMAIN} and ${DOMAIN} ..."
echo ""

certbot certonly \
  --manual \
  --preferred-challenges dns \
  --manual-auth-hook "$AUTH_HOOK" \
  --agree-tos \
  --register-unsafely-without-email \
  --config-dir "$WORK_DIR/config" \
  --work-dir  "$WORK_DIR/work" \
  --logs-dir  "$WORK_DIR/logs" \
  -d "*.${DOMAIN}" \
  -d "${DOMAIN}"

CERT_DIR="$WORK_DIR/config/live/${DOMAIN}"
if [ ! -f "$CERT_DIR/fullchain.pem" ] || [ ! -f "$CERT_DIR/privkey.pem" ]; then
  echo "ERROR: certbot did not produce the expected files in $CERT_DIR" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Build the plaintext YAML and encrypt it into the vault file.
# Top-level dict so multiple domains can coexist when merged from
# group_vars/all/*.yml.
# ---------------------------------------------------------------------------
mkdir -p "$VAULT_DIR"
tmp_plain="${WORK_DIR}/vault_plain.yml"

{
  echo "# Wildcard certificate for *.${DOMAIN} (Let's Encrypt, DNS-01)"
  echo "# Generated by generate_wildcard_cert.sh"
  echo ""
  echo "wildcard_certs:"
  echo "  \"${DOMAIN}\":"
  echo "    fullchain: |"
  sed 's/^/      /' "$CERT_DIR/fullchain.pem"
  echo "    privkey: |"
  sed 's/^/      /' "$CERT_DIR/privkey.pem"
} > "$tmp_plain"

echo ""
echo "Encrypting vault file → $VAULT_FILE"

ansible-vault encrypt \
  --output "$VAULT_FILE" \
  --encrypt-vault-id project \
  "$tmp_plain"

echo "Vault file created successfully."
