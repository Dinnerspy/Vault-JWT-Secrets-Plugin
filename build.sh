#!/usr/bin/env bash
# Build/test the plugin inside a throwaway Maven+JDK17 Docker container — no host JDK/Maven needed.
#
# Sources are copied into the container's own filesystem before building, because JenkinsRule's
# temp-directory cleanup fails on the WSL /mnt/c mount. The Maven repo is cached in a named volume
# (vjs-m2) so repeat builds are fast, and any built .hpi is copied back to ./target on the host.
#
# Usage:
#   ./build.sh                 # mvn verify (tests + spotless + spotbugs + package)
#   ./build.sh -DskipTests package
#   ./build.sh clean test
#   ./build.sh --fmt           # run spotless:apply and copy the reformatted sources back
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${MAVEN_IMAGE:-maven:3.9-eclipse-temurin-17}"
FMT=""
if [ "${1:-}" = "--fmt" ]; then
  FMT=1
  shift
fi
GOALS="${*:-verify}"

# Only public images are used here; sidestep a flaky Docker Desktop credential helper under WSL.
if [ -z "${DOCKER_CONFIG:-}" ]; then
  export DOCKER_CONFIG="$HOME/.docker-clean"
  mkdir -p "$DOCKER_CONFIG"
  [ -f "$DOCKER_CONFIG/config.json" ] || printf '{}' > "$DOCKER_CONFIG/config.json"
fi

mkdir -p "$REPO/target"

# --fmt: sources are mounted read-only, so reformat inside the container and copy the result back.
if [ -n "$FMT" ]; then
  docker run --rm \
    -v "$REPO":/src:ro \
    -v "$REPO/target":/out \
    -v vjs-m2:/root/.m2 \
    -w /build \
    "$IMAGE" bash -euc "
      cp -a /src/pom.xml /src/src /build/
      mvn -B -ntp spotless:apply
      rm -rf /out/fmt-src && cp -a /build/src /out/fmt-src
    "
  cp -a "$REPO/target/fmt-src/." "$REPO/src/"
  rm -rf "$REPO/target/fmt-src"
  echo "Sources reformatted."
  exit 0
fi

docker run --rm \
  -v "$REPO":/src:ro \
  -v "$REPO/target":/out \
  -v vjs-m2:/root/.m2 \
  -w /build \
  "$IMAGE" bash -euc "
    cp -a /src/pom.xml /src/src /build/
    mvn -B -ntp $GOALS
    cp -f /build/target/*.hpi /out/ 2>/dev/null || true
  "

echo "Artifacts in $REPO/target:"
ls -1 "$REPO"/target/*.hpi 2>/dev/null || echo "  (no .hpi produced for these goals)"
