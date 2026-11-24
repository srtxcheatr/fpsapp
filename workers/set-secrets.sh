#!/usr/bin/env bash
# Reads secrets from ./secrets.env (output of tools/gen-keys.js) and pushes them to all 5 workers.
set -e
cd "$(dirname "$0")"; set -a; source ./secrets.env; set +a
for w in login launch menu heartbeat feature; do
  (cd $w
   printf %s "$WORKER_SECRET"     | npx wrangler secret put WORKER_SECRET
   printf %s "$SESSION_SECRET"    | npx wrangler secret put SESSION_SECRET
   printf %s "$GUARD_PRIVATE_KEY" | npx wrangler secret put GUARD_PRIVATE_KEY)
done
