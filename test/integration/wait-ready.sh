#!/usr/bin/env bash
# Wait until the stack is actually answering, not merely "started".
#
# bash specifically, not sh: this uses /dev/tcp, which dash does not provide.
#
# `docker compose --wait` returns when containers are running, which for Ray
# is well before the dashboard binds. Polling for a real response is the
# difference between a flaky suite and a trustworthy one - and a fixed sleep
# would be both slower and still wrong.
set -eu

timeout_s="${WAIT_TIMEOUT:-180}"
deadline=$(( $(date +%s) + timeout_s ))

# host:port pairs that must answer before the tests mean anything.
endpoints="
172.31.77.10:8265
172.31.77.11:8888
172.31.77.12:5000
172.31.77.13:11434
172.31.77.20:8000
172.31.77.21:8000
172.31.77.22:8081
172.31.77.23:30000
172.31.77.24:9400
172.31.77.30:6817
172.31.77.40:8000
172.31.77.42:8081
"

pending="$endpoints"
while [ "$(date +%s)" -lt "$deadline" ]; do
  still_pending=""
  for ep in $pending; do
    host="${ep%:*}"
    port="${ep##*:}"
    # A completed TCP connect is the readiness signal; ray-guard itself does
    # no more than this to decide a port is open.
    if ! (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
      still_pending="$still_pending $ep"
    fi
  done
  pending="$still_pending"
  if [ -z "$(echo "$pending" | tr -d '[:space:]')" ]; then
    echo "stack ready"
    exit 0
  fi
  sleep 2
done

echo "timed out after ${timeout_s}s waiting for:$pending" >&2
exit 1
