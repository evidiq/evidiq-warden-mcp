#!/usr/bin/env bash
# Deploy EVIDIQ Warden as a Docker container behind the shared Coolify Traefik
# proxy on the mcp.evidiq.dev box. Routed by PathPrefix(/warden) with the prefix
# stripped, so the container still sees /mcp, /x402, /health, /skill.md.
set -euo pipefail

IMAGE="${IMAGE:-evidiq-warden:latest}"
NAME="${NAME:-evidiq-warden}"
NETWORK="${NETWORK:-coolify}"
ENV_FILE="${ENV_FILE:-/root/evidiq-warden.env}"
HOST_PORT="${HOST_PORT:-3008}"

docker rm -f "$NAME" >/dev/null 2>&1 || true

docker run -d \
  --name "$NAME" \
  --restart unless-stopped \
  --network "$NETWORK" \
  --env-file "$ENV_FILE" \
  -p 127.0.0.1:${HOST_PORT}:3000 \
  --label 'traefik.enable=true' \
  --label 'traefik.http.middlewares.warden-strip.stripprefix.prefixes=/warden' \
  --label 'traefik.http.routers.warden.middlewares=warden-strip' \
  --label 'traefik.http.routers.warden.rule=Host(`mcp.evidiq.dev`) && PathPrefix(`/warden`)' \
  --label 'traefik.http.routers.warden.tls=true' \
  --label 'traefik.http.routers.warden.tls.certresolver=letsencrypt' \
  --label 'traefik.http.services.warden.loadbalancer.server.port=3000' \
  "$IMAGE"

echo "started:"
docker ps --filter "name=^/${NAME}$" --format '{{.Names}}  {{.Status}}'
