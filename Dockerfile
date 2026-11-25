# Verification-only container for the Web3User Permission Lab SDK.
# This repository is a library, not a long-running service.
FROM node:26.11.1-bookworm-slim AS verify

# Install OpenSSL and CA certificates required for mTLS certificate generation and validation.
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Match the repository's declared package-manager baseline.
RUN npm install --global npm@11.20.0

# Prepare workspace directory with dedicated non-root user ownership.
# The official Node.js image provides the 'node' user (UID 1000, GID 1000).
WORKDIR /workspace
RUN chown -R node:node /workspace

# Switch to non-root user for dependency installation, build, and runtime execution.
USER node

# Install from the committed lockfile before copying source files.
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci

COPY --chown=node:node . .

# Build SDK distribution and verify TypeScript compilation as non-root user.
RUN npm run build \
 && npx tsc --noEmit

# Default verification command: executes all Linux-compatible test suites,
# examples, persistent replay verification, and npm packaging dry-run.
# Real etcd tests (**/*.real.test.ts) require native Windows executables (.tmp/)
# and are excluded from the Linux container verification.
CMD ["sh", "-c", "npx vitest run --exclude \"**/*.real.test.ts\" && npx tsx examples/basic-authorization.ts && npm run demo:persistent-replay -- --verify && npm pack --dry-run --json"]
