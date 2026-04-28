#!/usr/bin/env bash
#
# Boot a dedicated udata backend on port 7001 against the disposable
# MongoDB+Redis stack (docker-compose.test.yml).
#
# Usage:
#   scripts/start_test_backend.sh         # run in foreground
#   scripts/start_test_backend.sh --bg    # detach (writes PID to .test-backend.pid)
#   scripts/start_test_backend.sh stop    # kill the detached backend
#
# The backend reads udata.test.cfg via UDATA_SETTINGS, so MongoDB/Redis
# point at 27018/6380.
set -euo pipefail

cd "$(dirname "$0")/.."

PID_FILE=".test-backend.pid"
LOG_FILE=".test-backend.log"
PORT="${PORT:-7001}"
HOST="${HOST:-127.0.0.1}"

case "${1:-}" in
  stop)
    if [[ -f "$PID_FILE" ]]; then
      kill "$(cat "$PID_FILE")" 2>/dev/null || true
      rm -f "$PID_FILE"
      echo "[test-backend] stopped"
    fi
    exit 0
    ;;
  --bg)
    bash "$0" stop || true
    nohup bash "$0" run >"$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    echo "[test-backend] pid $(cat "$PID_FILE") log=$LOG_FILE"
    # Wait for readiness so the caller can immediately seed/auth.
    for _ in $(seq 1 60); do
      if curl -fsS "http://$HOST:$PORT/api/1/site/" >/dev/null 2>&1; then
        echo "[test-backend] ready on http://$HOST:$PORT"
        exit 0
      fi
      sleep 1
    done
    echo "[test-backend] timed out waiting for backend" >&2
    exit 1
    ;;
  run|"")
    export UDATA_SETTINGS="$(pwd)/udata.test.cfg"
    export FLASK_DEBUG=1
    # Use the test WSGI app — calls standalone() so API + frontend blueprints register.
    exec uv run flask --app udata.wsgi_test:app run --host "$HOST" --port "$PORT"
    ;;
  *)
    echo "Usage: $0 [run|--bg|stop]" >&2
    exit 64
    ;;
esac
