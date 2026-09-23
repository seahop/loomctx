# TypeScript SDK toolchain (D-026): generate types from the contract schema,
# build, and test against a live engine. Nothing installs on the host.
FROM node:22-alpine@sha256:b6f26b36c8ff49624cfdac716b8ea1138d606df02586a77d364bb5536a634f85
WORKDIR /app
COPY sdk/typescript/package.json ./
RUN npm install --no-audit --no-fund
COPY sdk/typescript/tsconfig.json ./
COPY sdk/typescript/scripts ./scripts
COPY sdk/typescript/src ./src
COPY sdk/typescript/test ./test
COPY contracts/schemas.json /contracts/schemas.json
ENV LOOM_SCHEMAS=/contracts/schemas.json
CMD ["sh", "-c", "npm run check-gen && npm run build && npm test"]
