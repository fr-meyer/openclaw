FROM node:24.16.0-bookworm@sha256:0fff24ba994c5450728278d000f7e8395ac22a8832b9f295723cf9411dae8df0
WORKDIR /app
COPY . /app
ENV CI=true COREPACK_ENABLE_DOWNLOAD_PROMPT=0 COREPACK_HOME=/opt/corepack COREPACK_DEFAULT_TO_LATEST=0 PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
RUN command -v bash && command -v git && command -v python3 && command -v corepack && test "$(node -p process.versions.node)" = 24.16.0  && corepack enable --install-directory /usr/local/bin  && corepack prepare pnpm@12.9.0+sha512.8f64efa0b792986ca98ae568791bcd7722807e274c4f0c1d9853c62116495c584119db98762a2a5343b1684d361b9ae26fdd16d551666d7635346d3fae830ddd --activate  && test "$(pnpm --version)" = 12.9.0  && pnpm install --frozen-lockfile --ignore-scripts --registry=https://registry.npmjs.org  && test -d /app/ui/node_modules  && node .github/qualification/b-image-dependencies.mjs
