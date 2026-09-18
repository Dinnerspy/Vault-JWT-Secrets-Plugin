#!/usr/bin/env bash
# Configures the dockerized Vault dev server for the e2e test:
# enables JWT auth trusting the Jenkins OIDC issuer, creates a role bound to the
# job identity, and seeds a KV v2 secret.
set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_TOKEN="${VAULT_TOKEN:-root}"

JENKINS_ISSUER="${JENKINS_ISSUER:-http://jenkins:8080/oidc}"
VAULT_AUDIENCE="${VAULT_AUDIENCE:-http://vault:8200}"

run() { docker exec -e VAULT_ADDR="$VAULT_ADDR" -e VAULT_TOKEN="$VAULT_TOKEN" vjs-vault "$@"; }

echo "Waiting for Jenkins OIDC discovery to be reachable from Vault..."
for i in $(seq 1 40); do
  if run wget -q -O- "${JENKINS_ISSUER}/.well-known/openid-configuration" >/dev/null 2>&1; then
    echo "  discovery reachable"
    break
  fi
  sleep 3
done

echo "Enabling JWT auth..."
run vault auth enable jwt 2>/dev/null || echo "  (already enabled)"

echo "Configuring JWT auth to trust ${JENKINS_ISSUER}..."
run vault write auth/jwt/config \
  oidc_discovery_url="${JENKINS_ISSUER}" \
  bound_issuer="${JENKINS_ISSUER}"

echo "Writing read policy..."
run sh -c 'vault policy write e2e - <<EOF
path "secret/data/production/db" { capabilities = ["read"] }
EOF'

echo "Creating role 'e2e' bound to the team-a FOLDER identity..."
# Authorize by the plugin's enriched `folder_path` claim (the Jenkins analog of GitLab's
# namespace_path): any job under the team-a folder may assume this role, regardless of its
# leaf job name. Pass the whole role as a JSON body on stdin so the nested bound_claims
# object survives docker exec shell quoting intact.
run sh -c "vault write auth/jwt/role/e2e - <<'EOF'
{
  \"role_type\": \"jwt\",
  \"user_claim\": \"sub\",
  \"bound_audiences\": \"${VAULT_AUDIENCE}\",
  \"bound_claims_type\": \"glob\",
  \"bound_claims\": { \"folder_path\": \"team-a*\" },
  \"token_policies\": \"e2e\",
  \"token_ttl\": \"120s\",
  \"token_num_uses\": 5
}
EOF"

# A second, identical role. The pipeline reaches it only via the GitLab-compatible
# VAULT_AUTH_ROLE variable, proving that env-var config overrides the folder's role.
echo "Creating role 'e2e-env' (selected via VAULT_AUTH_ROLE)..."
run sh -c "vault write auth/jwt/role/e2e-env - <<'EOF'
{
  \"role_type\": \"jwt\",
  \"user_claim\": \"sub\",
  \"bound_audiences\": \"${VAULT_AUDIENCE}\",
  \"bound_claims_type\": \"glob\",
  \"bound_claims\": { \"folder_path\": \"team-a*\" },
  \"token_policies\": \"e2e\",
  \"token_ttl\": \"120s\",
  \"token_num_uses\": 5
}
EOF"

echo "Seeding secret..."
run vault kv put secret/production/db password="s3cr3t-e2e-value" apikey="AKIA-e2e-file-value"

echo "Vault configured."
