# ---------------------------------------------------------------------------
# Stage 1: build the static page from source using the same Node toolchain
# the test/verify phases use.
# ---------------------------------------------------------------------------
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json ./
COPY scripts ./scripts
COPY src ./src
# Fixture generation and build need no third-party packages (zero deps).
RUN node scripts/generate-fixtures.mjs \
 && node scripts/build-page.mjs

# ---------------------------------------------------------------------------
# Stage web: serve the page + health response with nginx on port 8080.
# The host-side port is configurable through Compose / -p.
# ---------------------------------------------------------------------------
FROM nginx:1.27-alpine AS web
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD wget -qO- http://127.0.0.1:8080/healthz | grep -q '"status":"ok"' || exit 1
CMD ["nginx", "-g", "daemon off;"]

# ---------------------------------------------------------------------------
# Stage verify: one-shot acceptance container.
# Runs logical chain tests, page build and HTTP smoke against the bundled
# server, then exits 0 (accepted) / non-zero (rejected).
# ---------------------------------------------------------------------------
FROM node:20-alpine AS verify
WORKDIR /app
COPY package.json ./
COPY scripts ./scripts
COPY src ./src
COPY test ./test
# Regenerable artifacts; keep image self-contained by generating in-script.
ENV VERIFY_PORT=8091
CMD ["node", "scripts/verify.mjs"]
