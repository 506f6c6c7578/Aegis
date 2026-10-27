# syntax=docker/dockerfile:1.7

ARG NODE_IMAGE=node:24.22.1-alpine3.24@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53

FROM ${NODE_IMAGE} AS base

ENV CI=true \
    ASTRO_TELEMETRY_DISABLED=1

WORKDIR /app

RUN npm install --global --ignore-scripts pnpm@12.6.0 && npm cache clean --force

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./

FROM base AS build

RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile

COPY astro.config.ts tsconfig.json components.json ./
COPY scripts/nginx-security-headers.ts ./scripts/
COPY src ./src

RUN pnpm build \
    && mkdir -p dist/nginx \
    && node scripts/nginx-security-headers.ts > dist/nginx/security-headers.conf \
    && find dist/client -type f \( -name '*.html' -o -name '*.css' -o -name '*.js' -o -name '*.svg' -o -name '*.txt' \) \
        -exec sh -c 'gzip -9 -n -c "$1" > "$1.gz"' _ {} \;

FROM ${NODE_IMAGE} AS app

RUN apk upgrade --no-cache \
    && rm -rf /usr/local/lib/node_modules /opt/yarn-v* \
        /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=4321

WORKDIR /app

COPY --chown=root:root --from=build /app/dist/server ./dist/server

USER node

EXPOSE 4321

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:4321/rapport/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA').then((response) => process.exit(response.ok ? 0 : 1), () => process.exit(1))"

CMD ["node", "dist/server/entry.mjs"]

FROM nginxinc/nginx-unprivileged:1.30.6-alpine3.24@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03 AS web

USER root

RUN apk upgrade --no-cache \
    && sed -i 's/^worker_processes .*/worker_processes 1;/' /etc/nginx/nginx.conf

COPY --chown=root:root docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --chown=root:root --from=build /app/dist/nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY --chown=root:root --from=build /app/dist/client /srv/aegis

USER 101

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q --spider http://127.0.0.1:8080/ || exit 1
