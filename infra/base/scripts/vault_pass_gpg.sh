#!/usr/bin/env bash
set -euo pipefail
GPG_FILE="./.vault-pass.gpg"
exec gpg --quiet --batch --decrypt ./.vault-pass.gpg
