#!/usr/bin/env bash
# Usage: ./deploy-all.sh   (after: npx wrangler login, and secrets set per worker — see howtouse.md)
set -e
for w in login launch menu heartbeat feature; do (cd "$(dirname "$0")/$w" && npx wrangler deploy); done
