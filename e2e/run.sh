#!/usr/bin/env bash
# End-to-end acceptance test: dockerized Jenkins + Vault, real JWT login, real KV v2 read.
#
# Demonstrates the real-world model: NO global Vault config. The team-a folder owns its
# Vault coordinates (URL, role, mount); the pipeline just lists the secrets it wants.
# Vault authorizes the whole folder via the enriched `folder_path` JWT claim.
#
# Asserts the pipeline succeeds, secret values are fetched, and they are masked in the log.
#
# Env knobs: SKIP_BUILD=1 reuse existing target/*.hpi · KEEP_UP=1 leave containers running.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$HERE"

SECRET_ENV="s3cr3t-e2e-value"
SECRET_FILE="AKIA-e2e-file-value"
JENKINS_URL="http://localhost:18080"
AUDIENCE="http://vault:8200"
JOB_PATH="job/team-a/job/deploy"          # team-a/deploy → REST path
AUTH="admin:admin"

cleanup() {
  if [ -n "${KEEP_UP:-}" ]; then
    echo "== KEEP_UP set: leaving containers running ($JENKINS_URL, admin/admin) =="
    return
  fi
  echo "== tearing down =="
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Issue an authenticated crumbed POST against Jenkins.
jpost() {
  local path="$1"
  local crumb
  crumb=$(curl -s --cookie-jar /tmp/vjs-cookies -u "$AUTH" \
    "$JENKINS_URL/crumbIssuer/api/json" | sed -n 's/.*"crumb":"\([^"]*\)".*/\1/p')
  curl -s --cookie /tmp/vjs-cookies -u "$AUTH" -H "Jenkins-Crumb: $crumb" -X POST "$JENKINS_URL/$path"
}

echo "== 1. building plugin =="
if [ -n "${SKIP_BUILD:-}" ]; then
  echo "  SKIP_BUILD set, using existing target/*.hpi"
else
  (cd "$ROOT" && ./build.sh -DskipTests clean package)
fi
cp "$ROOT"/target/*.hpi "$HERE/" 2>/dev/null || true
mkdir -p "$HERE/target" && cp "$ROOT"/target/*.hpi "$HERE/target/"

echo "== 2. starting stack =="
# Start from a clean slate: jenkins/jenkins declares /var/jenkins_home as a VOLUME, so a
# stale volume from a previous run would shadow the casc.yaml baked into the fresh image.
docker compose down -v --remove-orphans >/dev/null 2>&1 || true
docker compose up -d --build

echo "== 3. waiting for Jenkins =="
for i in $(seq 1 60); do
  if curl -sf "$JENKINS_URL/login" >/dev/null 2>&1; then echo "  Jenkins up"; break; fi
  sleep 3
done

echo "== 4. provisioning the OIDC issuer =="
# In production the FIRST pipeline build auto-provisions the id-token credential (and thus
# publishes the OIDC discovery + JWKS endpoints) via IdTokenSupplier. Vault, however,
# validates its oidc_discovery_url at config time — so the issuer must exist before step 5.
# Here we invoke that same provisioning method directly to make the ordering deterministic.
CRUMB=$(curl -s --cookie-jar /tmp/vjs-cookies -u "$AUTH" \
  "$JENKINS_URL/crumbIssuer/api/json" | sed -n 's/.*"crumb":"\([^"]*\)".*/\1/p')
curl -s --cookie /tmp/vjs-cookies -u "$AUTH" -H "Jenkins-Crumb: $CRUMB" \
  --data-urlencode "script=println io.jenkins.plugins.vault_jwt_secrets.idtoken.IdTokenSupplier.getOrCreateIdTokenCredentials('$AUDIENCE')" \
  "$JENKINS_URL/scriptText"
echo "  waiting for OIDC discovery to publish..."
for i in $(seq 1 20); do
  if curl -sf "$JENKINS_URL/oidc/.well-known/openid-configuration" >/dev/null 2>&1; then
    echo "  discovery live"; break
  fi
  sleep 2
done

echo "== 5. configuring Vault =="
bash "$HERE/vault-init.sh"

echo "== 6. triggering pipeline (team-a/deploy) =="
jpost "$JOB_PATH/build?delay=0sec"

echo "== 7. waiting for build to finish =="
RESULT=""
for i in $(seq 1 60); do
  sleep 3
  JSON=$(curl -s -u "$AUTH" "$JENKINS_URL/$JOB_PATH/lastBuild/api/json" 2>/dev/null || true)
  if echo "$JSON" | grep -q '"building":false'; then
    RESULT=$(echo "$JSON" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')
    break
  fi
done

LOG=$(curl -s -u "$AUTH" "$JENKINS_URL/$JOB_PATH/lastBuild/consoleText" || true)
echo "----- build log -----"
echo "$LOG"
echo "---------------------"

echo "== 8. assertions =="
fail=0
[ "$RESULT" = "SUCCESS" ] && echo "  [ok] build SUCCESS" || { echo "  [FAIL] build result=$RESULT"; fail=1; }
echo "$LOG" | grep -q "env secret is \*\*\*\*" && echo "  [ok] env secret masked" || { echo "  [FAIL] env secret not masked"; fail=1; }
echo "$LOG" | grep -q "credential secret is \*\*\*\*" && echo "  [ok] credential secret masked" || { echo "  [FAIL] credential not masked"; fail=1; }
echo "$LOG" | grep -q "file holds: \*\*\*\*" && echo "  [ok] file secret masked" || { echo "  [FAIL] file secret not masked"; fail=1; }
echo "$LOG" | grep -q "env-configured secret is \*\*\*\*" && echo "  [ok] VAULT_AUTH_ROLE config honoured" || { echo "  [FAIL] VAULT_* env config did not work"; fail=1; }
echo "$LOG" | grep -q "raw token is \*\*\*\*" && echo "  [ok] raw id token masked" || { echo "  [FAIL] raw id token not masked"; fail=1; }
echo "$LOG" | grep -q "manual JWT login OK" && echo "  [ok] manual login with raw token" || { echo "  [FAIL] manual JWT login failed"; fail=1; }
echo "$LOG" | grep -q "manual KV read OK" && echo "  [ok] manual KV read with raw token" || { echo "  [FAIL] manual KV read failed"; fail=1; }
if echo "$LOG" | grep -qF "$SECRET_ENV"; then echo "  [FAIL] env secret value LEAKED"; fail=1; else echo "  [ok] env secret value absent"; fi
if echo "$LOG" | grep -qF "$SECRET_FILE"; then echo "  [FAIL] file secret value LEAKED"; fail=1; else echo "  [ok] file secret value absent"; fi

if [ "$fail" -eq 0 ]; then echo "== E2E PASSED =="; exit 0; else echo "== E2E FAILED =="; exit 1; fi
