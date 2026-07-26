# Build stage
FROM node:22-bookworm-slim AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY server.ts start-server.ts skill.md THIRD_PARTY_NOTICES.md LICENSE ./
COPY lib ./lib
COPY data ./data

RUN npm run build && npm prune --omit=dev

# Runtime stage
FROM node:22-bookworm-slim AS runtime
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Non-root runtime user per Runbook §28-B
RUN useradd --create-home --uid 10001 warden && \
    mkdir -p /tmp/evidiq-warden-artifacts && \
    chown warden:warden /tmp/evidiq-warden-artifacts && \
    chmod 0700 /tmp/evidiq-warden-artifacts

COPY --from=build --chown=warden:warden /app/package.json /app/package-lock.json ./
COPY --from=build --chown=warden:warden /app/node_modules ./node_modules
COPY --from=build --chown=warden:warden /app/dist ./dist
COPY --from=build --chown=warden:warden /app/data ./data
COPY --from=build --chown=warden:warden /app/skill.md /app/THIRD_PARTY_NOTICES.md /app/LICENSE ./

USER warden:warden
EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

CMD ["node", "dist/start-server.js"]
