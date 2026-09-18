#!/bin/sh
# Baked into the e2e Jenkins image. Shows what a job does with the RAW token that
# `withVaultJwtToken` puts in the environment: log into Vault itself, read a secret, hand the
# token back. Kept in a file (rather than inline in the Jenkinsfile) purely to avoid nested
# quoting — a real job would do the same thing.
set -e
: "${VAULT_ADDR:?VAULT_ADDR is not set}"
: "${VAULT_ROLE:?VAULT_ROLE is not set}"
: "${VAULT_ID_TOKEN:?VAULT_ID_TOKEN is not set}"

printf '{"jwt":"%s","role":"%s"}' "$VAULT_ID_TOKEN" "$VAULT_ROLE" > /tmp/vjs-login.json
TOKEN=$(curl -sf --data @/tmp/vjs-login.json "$VAULT_ADDR/v1/auth/jwt/login" \
  | sed -n 's/.*"client_token":"\([^"]*\)".*/\1/p')
rm -f /tmp/vjs-login.json
[ -n "$TOKEN" ] || { echo "manual JWT login FAILED"; exit 1; }
echo "manual JWT login OK"

# grep -q, never echo: the plugin masks the id token here, not the secret behind it.
curl -sf -H "X-Vault-Token: $TOKEN" "$VAULT_ADDR/v1/secret/data/production/db" \
  | grep -q '"password"' && echo "manual KV read OK"

curl -sf -X POST -H "X-Vault-Token: $TOKEN" "$VAULT_ADDR/v1/auth/token/revoke-self" >/dev/null || true
