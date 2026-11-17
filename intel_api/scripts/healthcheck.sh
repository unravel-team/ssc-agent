#!/usr/bin/env bash
#
# healthcheck.sh — probe the intel_api service's liveness endpoint.
#
# A developer runs this by hand (or from CI) to confirm the Sources API is up.
# It hits the service's OWN /v1/health route and prints the JSON it returns.
#
# Usage:
#   scripts/healthcheck.sh                      # defaults to http://127.0.0.1:8787
#   BASE_URL=https://intel.internal scripts/healthcheck.sh
#   scripts/healthcheck.sh https://intel.internal
#
# Exit codes:
#   0  service answered with HTTP 2xx
#   1  could not connect / timed out
#   2  connected but got a non-2xx status
#
set -euo pipefail

# Configurable target. Default is the service's local port (see intel_api/Dockerfile EXPOSE 8787).
BASE_URL="${1:-${BASE_URL:-http://127.0.0.1:8787}}"
BASE_URL="${BASE_URL%/}"          # trim any trailing slash
HEALTH_PATH="${HEALTH_PATH:-/v1/health}"
TIMEOUT="${TIMEOUT:-5}"           # seconds

url="${BASE_URL}${HEALTH_PATH}"
echo "GET ${url}" >&2

# -s silent, -S show errors, -m overall timeout; capture body + trailing HTTP status.
response="$(curl -sS -m "${TIMEOUT}" -w '\n%{http_code}' "${url}")" || {
  echo "healthcheck: could not reach ${url}" >&2
  exit 1
}

status="${response##*$'\n'}"      # last line = status code
body="${response%$'\n'*}"         # everything before it = body

echo "${body}"
echo "HTTP ${status}" >&2

if [[ "${status}" =~ ^2 ]]; then
  exit 0
else
  echo "healthcheck: service returned HTTP ${status}" >&2
  exit 2
fi
