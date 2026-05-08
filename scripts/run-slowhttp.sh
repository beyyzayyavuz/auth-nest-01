#!/bin/bash
set -e
MODE="${1:-slowloris}"
DURATION="${2:-1800}"  # 30 dakika

case "$MODE" in
  slowloris)
    docker compose exec slowhttptest \
      slowhttptest -c 500 -H -i 10 -r 50 -t GET \
        -u http://host.docker.internal:8080/ \
        -x 24 -p 3 -l "$DURATION"
    ;;
  slow_post)
    docker compose exec slowhttptest \
      slowhttptest -c 500 -B -i 110 -r 50 -t POST \
        -u http://host.docker.internal:8080/auth/login \
        -x 60 -p 3 -l "$DURATION" \
        -H "Content-Type: application/json"
    ;;
  slow_read)
    docker compose exec slowhttptest \
      slowhttptest -c 500 -X -r 50 \
        -u "http://host.docker.internal:8080/user/search?q=test" \
        -l "$DURATION"
    ;;
  *)
    echo "Unknown mode: $MODE. Use slowloris|slow_post|slow_read"
    exit 1
    ;;
esac