#!/usr/bin/env bash
# Copies the secrets from intel_api/.env into the Fly app (API and agents on one machine), without printing them.
# See FLY.md.
#
#   ./fly-secrets.sh                       after `fly mpg attach` (it gives the app its DATABASE_URL)
#   ./fly-secrets.sh 'postgres://...'      or with a connection string for another Postgres
#
# The app name defaults to unravel-ssc-api; set FLY_API_APP to change it.
# Secrets are staged: they take effect on the next `fly deploy`.
set -euo pipefail
cd "$(dirname "$0")"

API_APP=${FLY_API_APP:-unravel-ssc-api}
DB_URL=${1:-}
[ -f .env ] || { echo "no intel_api/.env: copy .env.example and fill it in first" >&2; exit 1; }

# a value from .env (KEY=VALUE lines; nothing in the file is executed)
val() { grep -m1 "^$1=" .env | cut -d= -f2- || true; }

API_KEYS=$(val SSC_INTEL_API_KEYS)
AGENT_KEY=$(val SSC_AGENT_KEY)
[ -n "$API_KEYS" ] && [ -n "$AGENT_KEY" ] || { echo "SSC_INTEL_API_KEYS and SSC_AGENT_KEY must be set in .env" >&2; exit 1; }

# one app: fly_start.py hands each process only its own part
{
  if [ -n "$DB_URL" ]; then printf 'SSC_INTEL_DB_URL=%s\n' "$DB_URL"; fi
  printf 'SSC_INTEL_API_KEYS=%s,agent:%s\n' "$API_KEYS" "$AGENT_KEY"   # the agents' key, as compose adds it
  printf 'SSC_AGENT_KEY=%s\n' "$AGENT_KEY"
  for k in GITHUB_TOKEN NVD_API_KEY VULNCHECK_API_KEY X_BEARER_TOKEN BSKY_HANDLE BSKY_APP_PASSWORD \
           CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_API_KEY SSC_AGENT_MODEL SSC_VERIFY_MODEL SSC_VERIFY_BUDGET_USD; do
    v=$(val "$k")
    if [ -n "$v" ]; then printf '%s=%s\n' "$k" "$v"; fi
  done
} | fly secrets import --app "$API_APP" --stage

echo "Secrets staged for $API_APP. Check the names (never the values) with: fly secrets list -a $API_APP"
