# Contributing to Web3User Permission Lab

Thank you for your interest in contributing to Web3User Permission Lab! This document outlines the development workflow, testing standards, and architectural invariants for the project.

---

## Development Prerequisites

- **Node.js**: Version `22.13.0` or later. The engine uses the built-in `node:sqlite` module, which is available stably without experimental flags in Node.js 22.13.0+.
- **npm**: Modern npm (bundled with Node.js 22+).
- **Git**: For version control.

---

## Getting Started

1. **Clone the repository:**
   ```bash
   git clone https://github.com/syedsenterprises/Web3User-Permission-Lab.git
   cd Web3User-Permission-Lab
   ```

2. **Install development dependencies:**
   ```bash
   npm install
   ```

3. **Build the TypeScript distribution:**
   ```bash
   npm run build
   ```

---

## Testing & Verification Standards

All contributions must pass the complete test suite and static analysis before being submitted.

1. **Run the automated test suite:**
   ```bash
   npm test
   ```
   *(All 17 test suites and 332 tests must pass cleanly).*

2. **Verify static TypeScript compilation:**
   ```bash
   npx tsc --noEmit
   ```

3. **Verify the basic authorization integration example:**
   ```bash
   npx tsx examples/basic-authorization.ts
   ```

4. **Verify the persistent replay demonstration:**
   ```bash
   npm run demo:persistent-replay -- --verify
   ```

5. **Verify package bundling:**
   ```bash
   npm pack --dry-run
   ```
   Ensure no test files (`test/`), internal documentation (`docs/`), website preview assets (`website-preview/`), or demo CLI binaries (`dist/demo`) leak into the packaged distribution.

---

## Core Architectural Invariants

Contributions modifying engine or storage logic must respect these core invariants:

- **Fail-Closed Security Model:** Any ambiguous input, unsupported transaction selector, expired timestamp, or malformed calldata must resolve to `DENY` or `UNKNOWN`. Operations must never fail open.
- **Off-Chain Scope:** The library is an off-chain decision engine. It does not sign Ethereum transactions with wallet keys (`secp256k1`), connect to RPC providers, or broadcast to mempools.
- **SQLite WAL & Durability:** Owned SQLite connections enforce `PRAGMA journal_mode = WAL;` and `PRAGMA synchronous = FULL;` by default. Contention uses bounded backoff with full jitter.
- **Zero Runtime Dependencies:** The runtime engine strictly avoids third-party npm dependencies and relies exclusively on Node.js built-in modules (`node:crypto`, `node:sqlite`, `node:fs`, `node:path`, `node:os`).
- **Secret Hygiene:** Never commit private keys, mnemonic seeds, API tokens, or real account credentials. Ephemeral test keys must be generated dynamically in memory during test execution.
- **Package Safeguard:** The `"private": true` setting in `package.json` must remain preserved.

---

## Pull Request Guidelines

1. **Create a topic branch:** Branch from `main` with a descriptive name (e.g. `fix/calldata-boundary-check`).
2. **Follow conventional commits:** Use descriptive, conventional commit prefixes (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`).
3. **Check formatting & whitespace:** Run `git diff --check` to ensure there are no trailing whitespace errors or improper line endings.
4. **Submit a Pull Request:** Provide a clear description of the problem, the proposed solution, and the test evidence.
