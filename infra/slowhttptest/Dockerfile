#FROM alpine:3.19

#RUN apk add --no-cache slowhttptest curl

# Default no-op; gerçek komut docker compose run ile verilir
#CMD ["sleep", "infinity"]

#It did not work with alpine, so switched to debian (build error)


FROM debian:bookworm-slim

# Install slowhttptest and curl
RUN apt-get update \
  && apt-get install -y --no-install-recommends slowhttptest curl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Keep container alive; actual commands are run manually with docker compose exec
CMD ["sleep", "infinity"]