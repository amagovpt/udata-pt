#!/usr/bin/env bash
#
# Manage the disposable test stack used by Playwright destructive tests.
#
# Usage:
#   scripts/test_db.sh up      # start MongoDB+Redis on 27018/6380
#   scripts/test_db.sh down    # stop and wipe volumes
#   scripts/test_db.sh wait    # block until MongoDB is healthy
#   scripts/test_db.sh reset   # down + up (fresh DB)
#
# All ports/data are isolated from the dev stack on 27017/6379.

set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE_FILE="docker-compose.test.yml"
MONGO_HOST="localhost"
MONGO_PORT="27019"

case "${1:-}" in
  up)
    docker compose -f "$COMPOSE_FILE" up -d
    echo "[test-db] containers started; waiting for MongoDB on $MONGO_HOST:$MONGO_PORT…"
    "$0" wait
    ;;
  down)
    docker compose -f "$COMPOSE_FILE" down -v
    echo "[test-db] stopped + volumes removed"
    ;;
  reset)
    "$0" down
    "$0" up
    ;;
  wait)
    # Use the container's own mongosh — avoids requiring it on the host.
    for _ in $(seq 1 30); do
      if docker exec udata-mongodb-test mongosh --quiet \
        --eval "db.adminCommand('ping').ok" >/dev/null 2>&1; then
        echo "[test-db] MongoDB ready on $MONGO_HOST:$MONGO_PORT"
        exit 0
      fi
      sleep 1
    done
    echo "[test-db] timed out waiting for MongoDB" >&2
    exit 1
    ;;
  *)
    echo "Usage: $0 {up|down|reset|wait}" >&2
    exit 64
    ;;
esac
