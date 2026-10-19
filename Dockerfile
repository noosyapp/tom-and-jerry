# Base image ships Chromium and all its OS libraries, so there is no apt step and
# no dependency on the Debian mirrors. Pinned to match the Playwright npm version.
FROM mcr.microsoft.com/playwright:v1.64.1-noble

ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
# Pinned to pnpm 9 (via package.json "packageManager"): pnpm 10+ turns an unapproved
# dependency build script into a fatal install error that no config here reliably
# silences. pnpm 9 installs cleanly and esbuild/tsx work.
RUN corepack enable && corepack prepare pnpm@9.15.9 --activate

WORKDIR /app

COPY package.json ./
RUN pnpm install
# Browsers already live in the base image; this is a fast no-op unless the resolved
# Playwright version drifts, in which case it fetches chromium over HTTPS (no apt).
RUN pnpm exec playwright install chromium

COPY . .

CMD ["pnpm", "dev"]
