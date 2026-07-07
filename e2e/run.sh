#!/usr/bin/env bash
# End-to-end acceptance test: dockerized Jenkins + Vault, real JWT login, real KV v2 read.
# Asserts the pipeline succeeds, secret values are fetched, and they are masked in the log.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$HERE"

SECRET_ENV="s3cr3t-e2e-value"
SECRET_FILE="AKIA-e2e-file-value"
JENKINS_URL="http://localhost:18080"
JOB="vault-e2e"

cleanup() { echo "== tearing down =="; docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== 1. building plugin =="
if [ -n "${SKIP_BUILD:-}" ]; then
  echo "  SKIP_BUILD set, using existing target/*.hpi"
else
  (cd "$ROOT" && mvn -B -ntp -DskipTests clean package)
fi
cp "$ROOT"/target/*.hpi "$HERE/" 2>/dev/null || true
mkdir -p "$HERE/target" && cp "$ROOT"/target/*.hpi "$HERE/target/"

echo "== 2. starting stack =="
docker compose up -d --build

echo "== 3. waiting for Jenkins =="
for i in $(seq 1 60); do
  if curl -sf "$JENKINS_URL/login" >/dev/null 2>&1; then echo "  Jenkins up"; break; fi
  sleep 3
done

echo "== 4. configuring Vault =="
bash "$HERE/vault-init.sh"

echo "== 5. triggering pipeline =="
AUTH="admin:admin"
CRUMB=$(curl -s --cookie-jar /tmp/vjs-cookies -u "$AUTH" \
  "$JENKINS_URL/crumbIssuer/api/json" | sed -n 's/.*"crumb":"\([^"]*\)".*/\1/p')
curl -s --cookie /tmp/vjs-cookies -u "$AUTH" -H "Jenkins-Crumb: $CRUMB" \
  -X POST "$JENKINS_URL/job/$JOB/build?delay=0sec"

echo "== 6. waiting for build to finish =="
RESULT=""
for i in $(seq 1 60); do
  sleep 3
  JSON=$(curl -s -u "$AUTH" "$JENKINS_URL/job/$JOB/lastBuild/api/json" 2>/dev/null || true)
  if echo "$JSON" | grep -q '"building":false'; then
    RESULT=$(echo "$JSON" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')
    break
  fi
done

LOG=$(curl -s -u "$AUTH" "$JENKINS_URL/job/$JOB/lastBuild/consoleText" || true)
echo "----- build log -----"
echo "$LOG"
echo "---------------------"

echo "== 7. assertions =="
fail=0
[ "$RESULT" = "SUCCESS" ] && echo "  [ok] build SUCCESS" || { echo "  [FAIL] build result=$RESULT"; fail=1; }
echo "$LOG" | grep -q "env secret is \*\*\*\*" && echo "  [ok] env secret masked" || { echo "  [FAIL] env secret not masked"; fail=1; }
echo "$LOG" | grep -q "credential secret is \*\*\*\*" && echo "  [ok] credential secret masked" || { echo "  [FAIL] credential not masked"; fail=1; }
echo "$LOG" | grep -q "file holds: \*\*\*\*" && echo "  [ok] file secret masked" || { echo "  [FAIL] file secret not masked"; fail=1; }
if echo "$LOG" | grep -qF "$SECRET_ENV"; then echo "  [FAIL] env secret value LEAKED"; fail=1; else echo "  [ok] env secret value absent"; fi
if echo "$LOG" | grep -qF "$SECRET_FILE"; then echo "  [FAIL] file secret value LEAKED"; fail=1; else echo "  [ok] file secret value absent"; fi

if [ "$fail" -eq 0 ]; then echo "== E2E PASSED =="; exit 0; else echo "== E2E FAILED =="; exit 1; fi
