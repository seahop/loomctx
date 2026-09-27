# TypeScript SDK toolchain (D-026): generate types from the contract schema,
# build, and test against a live engine. Nothing installs on the host.
FROM node:26-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80
WORKDIR /app
# package-lock.json is committed: `npm ci` installs exactly it and fails if it
# disagrees with package.json (regenerate inside node, never on the host)
COPY sdk/typescript/package.json sdk/typescript/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY sdk/typescript/tsconfig.json ./
COPY sdk/typescript/scripts ./scripts
COPY sdk/typescript/src ./src
COPY sdk/typescript/test ./test
COPY contracts/schemas.json /contracts/schemas.json
ENV LOOMCTX_SCHEMAS=/contracts/schemas.json
CMD ["sh", "-c", "npm run check-gen && npm run build && npm test"]
