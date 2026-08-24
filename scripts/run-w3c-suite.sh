#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run the official W3C VC Data Model 2.0 test suite against a running instance.
#
# This is opt-in and NOT part of CI: it needs a live server and a database, so it is not
# hermetic. See test/w3c/README.md for the full story, including what we have and have not
# actually run.
set -euo pipefail

SUITE_REPO="https://github.com/w3c/vc-data-model-2.0-test-suite.git"
SUITE_DIR="test/w3c/.suite"
BASE_URL="${W3C_SUITE_BASE_URL:-http://localhost:3000}"
ADMIN_API_KEY="${ADMIN_API_KEY:-dev-admin-key}"
PROXY_PORT="${W3C_PROXY_PORT:-3100}"

echo "==> Checking that an OpenResidency instance is up at ${BASE_URL}"
if ! curl -fsS "${BASE_URL}/.well-known/openid-credential-issuer" >/dev/null 2>&1; then
  echo "ERROR: nothing is answering at ${BASE_URL}."
  echo "       Start the stack first:"
  echo "         docker compose up -d db && npm run prisma:migrate"
  echo "         ADMIN_API_KEY=dev-admin-key npm run start:dev"
  exit 1
fi

if [ ! -d "${SUITE_DIR}" ]; then
  echo "==> Cloning the W3C suite into ${SUITE_DIR}"
  git clone --depth 1 "${SUITE_REPO}" "${SUITE_DIR}"
fi

echo "==> Installing the suite"
(cd "${SUITE_DIR}" && npm install --no-audit --no-fund)

# The suite drops the Authorization header from localConfig.cjs on its plain-http code
# path, so it cannot reach the admin-guarded VC-API on its own. Put a shim in front that
# adds the credential rather than removing the guard -- see test/w3c/auth-proxy.cjs.
TARGET_PORT="$(printf '%s' "${BASE_URL}" | sed -E 's|^https?://[^:/]+:?([0-9]*)/?.*$|\1|')"
TARGET_PORT="${TARGET_PORT:-3000}"
echo "==> Starting the authenticating shim on 127.0.0.1:${PROXY_PORT}"
ADMIN_API_KEY="${ADMIN_API_KEY}" W3C_PROXY_PORT="${PROXY_PORT}" \
  W3C_PROXY_TARGET_PORT="${TARGET_PORT}" node test/w3c/auth-proxy.cjs &
PROXY_PID=$!
trap 'kill "${PROXY_PID}" 2>/dev/null || true' EXIT

for _ in $(seq 1 20); do
  curl -fsS -o /dev/null "http://127.0.0.1:${PROXY_PORT}/.well-known/openid-credential-issuer" && break
  sleep 0.25
done

echo "==> Running the suite against ${BASE_URL} (via 127.0.0.1:${PROXY_PORT})"
cp test/w3c/localConfig.cjs "${SUITE_DIR}/localConfig.cjs"
(cd "${SUITE_DIR}" && W3C_SUITE_BASE_URL="http://127.0.0.1:${PROXY_PORT}" \
  ADMIN_API_KEY="${ADMIN_API_KEY}" npm test) || {
  echo ""
  echo "The W3C suite reported failures. That is useful information, not a disaster."
  echo "Please open an issue with the output -- see test/w3c/README.md."
  exit 1
}
