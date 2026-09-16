#!/usr/bin/env bash
#
# Prove the test suite is no longer intermittent (LEDG-2489).
#
# Usage:
#   scripts/ten_green_runs.sh [runs]     # default: 10
#
# Why ten and not one: in an intermittent suite a green run proves nothing.
# The failures moved between runs, so only a streak is evidence.
#
# 🚩 What this script exists to tell apart, and why the obvious check is wrong.
#
# The suite used to run against the DEVELOPMENT MongoDB, which restarts under
# `restart: unless-stopped` and killed connections mid-run. A first version of
# this check watched RestartCount to spot that -- but the TEST container
# declares no restart policy at all, so its RestartCount is permanently 0. If
# it died mid-streak it would simply stay dead, every later run would fail, and
# "red with no restart" would have read as "the suite is flaky": the exact
# wrong diagnosis, sending someone to investigate a healthy suite.
#
# So what is watched is whether the container is RUNNING and whether StartedAt
# moved. A run only counts as evidence about the suite when the database was
# alive and the same instance from beginning to end.
#
#   green, container intact              -> counts toward the streak
#   red,   container intact              -> the suite IS still flaky. STOP and
#                                           diagnose. Never silence a test.
#   any,   container restarted or gone   -> outside interference. Logged,
#                                           repeated, does NOT count.

set -euo pipefail

cd "$(dirname "$0")/.."

RUNS="${1:-10}"
CONTAINER="udata-mongodb-test"
PYTEST=(uv run pytest -p no:sugar -q -n 4 --dist loadscope udata)

state() {
    docker inspect "$CONTAINER" --format '{{.State.Running}} {{.State.StartedAt}}' 2>/dev/null \
        || echo "absent -"
}

green=0
attempt=0
discarded=0

while [ "$green" -lt "$RUNS" ]; do
    attempt=$((attempt + 1))
    before="$(state)"

    if [ "${before%% *}" != "true" ]; then
        echo "run ${attempt}: test database is not running — start it with"
        echo "  docker compose -f docker-compose.test.yml up -d"
        exit 1
    fi

    printf 'run %-3s (%s/%s green) ... ' "$attempt" "$green" "$RUNS"
    if "${PYTEST[@]}" > "/tmp/ten_green_runs_${attempt}.log" 2>&1; then
        outcome=pass
    else
        outcome=fail
    fi
    after="$(state)"

    if [ "$before" != "$after" ]; then
        discarded=$((discarded + 1))
        echo "DISCARDED — the test database restarted or went away during the run"
        echo "    before: $before"
        echo "    after:  $after"
        echo "    outside interference, not a suite failure. Repeating."
        continue
    fi

    if [ "$outcome" = pass ]; then
        green=$((green + 1))
        echo "pass"
    else
        echo "FAIL — and the database was intact throughout."
        echo
        echo "  The suite is still intermittent. This is the answer the check exists"
        echo "  to give, so do NOT disable, xfail or loosen the failing tests:"
        echo "  go back to diagnosis."
        echo
        grep -E '^(FAILED|ERROR)' "/tmp/ten_green_runs_${attempt}.log" || true
        echo
        echo "  Full log: /tmp/ten_green_runs_${attempt}.log"
        exit 1
    fi
done

echo
echo "${green}/${RUNS} PASS — database intact in every counted run."
[ "$discarded" -gt 0 ] && echo "(${discarded} run(s) discarded for outside interference.)"
