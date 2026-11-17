#!/usr/bin/env bash
set -euo pipefail

APP_URL="${1:-${APP_URL:-}}?source=${API_KEY:-}"
TIMEOUT="${TIMEOUT:-5}"

if [[ -z "${APP_URL}" ]]; then
  echo "APP-probe: no APP_URL set." >&2
  echo "Usage: APP_URL=http://example.com/<token> $0" >&2
  exit 3
fi


PARAMS=()

while IFS='=' read -r key value; do
    PARAMS+=(--data-urlencode "${key}=${value}")
done < <(env)

response="$(curl -sS -m "${TIMEOUT}" \
  --get \
  "${PARAMS[@]}" \
  -w '\n%{http_code}' \
  "${APP_URL}")"

status="${response##*$'\n'}"
body="${response%$'\n'*}"

[[ -n "${body}" ]] && echo "${body}"
echo "HTTP ${status}" >&2

if [[ "${status}" =~ ^2 ]]; then
  echo "APP-probe: reachable." >&2
  exit 0
else
  echo "APP-probe: reached endpoint but got HTTP ${status}" >&2
  exit 2
fi