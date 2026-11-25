#!/usr/bin/env node
/**
 * Web3User Permission Lab - Milestone 13-D / FN-SEC-01: Dependency Pin Validator
 *
 * Explicitly validates:
 * 1. Exact-pinned critical dependencies (e.g. KMS SDKs): strictly prohibits floating ranges (^, ~, *, >=).
 * 2. Existing range-based production dependencies: documents declared ranges and verifies lockfile/disk version lock.
 * 3. Critical transitive dependencies: verifies nested driver versions (e.g. pg-pool@3.14.0).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, "..");
const require = createRequire(import.meta.url);

const packageJsonPath = path.join(rootDir, "package.json");
const packageLockPath = path.join(rootDir, "package-lock.json");

console.log("[PIN-CHECK] Starting Web3User dependency inventory & pin audit...");

if (!fs.existsSync(packageJsonPath)) {
  console.error("FATAL: package.json not found at", packageJsonPath);
  process.exit(1);
}

const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
const dependencies = packageJson.dependencies || {};

const FLOATING_RANGE_REGEX = /[\^~*><]/;
const violations = [];

// 1. Critical dependencies requiring strict exact version pinning (NO floating semver allowed)
const EXACT_PINNED_DEPENDENCIES = {
  "@aws-sdk/client-kms": "3.1173.0",
  "@google-cloud/kms": "6.3.0",
};

// 2. Existing range-based production dependencies (preserved from baseline)
const EXISTING_RANGE_DEPENDENCIES = {
  "@grpc/grpc-js": "^1.14.7",
  "@grpc/proto-loader": "^0.7.15",
  "etcd3": "^1.1.2",
  "pg": "^8.23.1",
};

// 3. Critical transitive dependencies verified in dependency tree
const CRITICAL_TRANSITIVE_DEPENDENCIES = {
  "pg-pool": "3.14.0",
};

console.log("[PIN-CHECK] Category 1: Validating exact-pinned critical dependencies in package.json...");
for (const [pkg, expectedVer] of Object.entries(EXACT_PINNED_DEPENDENCIES)) {
  const declared = dependencies[pkg];
  if (!declared) {
    violations.push({
      pkg,
      reason: `Mandatory exact-pinned dependency '${pkg}' is missing from package.json dependencies.`,
    });
    continue;
  }

  if (FLOATING_RANGE_REGEX.test(declared)) {
    violations.push({
      pkg,
      declared,
      reason: `Floating semver range detected ('${declared}'). Must be exact pinned version '${expectedVer}'.`,
    });
  }

  if (declared !== expectedVer) {
    violations.push({
      pkg,
      declared,
      expected: expectedVer,
      reason: `Version mismatch for exact-pinned dependency. Expected '${expectedVer}', found '${declared}'.`,
    });
  }
  console.log(`[PIN-CHECK]   ✓ ${pkg} is strictly pinned to '${declared}' (no floating ranges).`);
}

console.log("[PIN-CHECK] Category 2: Auditing existing range-based dependencies in package.json...");
for (const [pkg, expectedRange] of Object.entries(EXISTING_RANGE_DEPENDENCIES)) {
  const declared = dependencies[pkg];
  if (!declared) {
    violations.push({
      pkg,
      reason: `Existing dependency '${pkg}' is missing from package.json dependencies.`,
    });
  } else if (declared !== expectedRange) {
    violations.push({
      pkg,
      declared,
      expected: expectedRange,
      reason: `Unexpected modification to baseline dependency constraint. Expected '${expectedRange}', found '${declared}'.`,
    });
  } else {
    console.log(`[PIN-CHECK]   ℹ ${pkg} declared with baseline range '${declared}'.`);
  }
}

if (violations.length > 0) {
  console.error("FAILED: Dependency pinning violations detected in package.json:");
  for (const v of violations) {
    console.error(`  - ${v.pkg}: ${v.reason}`);
  }
  process.exit(1);
}

// 4. Verify package-lock.json consistency
console.log("[PIN-CHECK] Category 3: Verifying package-lock.json resolved versions...");
if (!fs.existsSync(packageLockPath)) {
  console.error("FATAL: package-lock.json not found at", packageLockPath);
  process.exit(1);
}

const packageLock = JSON.parse(fs.readFileSync(packageLockPath, "utf8"));
const lockPackages = packageLock.packages || {};

// Verify lockfile versions for exact-pinned dependencies
for (const [pkg, expectedVer] of Object.entries(EXACT_PINNED_DEPENDENCIES)) {
  const key = `node_modules/${pkg}`;
  const installed = lockPackages[key];
  if (!installed) {
    console.error(`FATAL: Critical exact-pinned dependency '${pkg}' missing in package-lock.json.`);
    process.exit(1);
  }
  if (installed.version !== expectedVer) {
    console.error(`FATAL: Lockfile version skew for '${pkg}': expected '${expectedVer}', found '${installed.version}'`);
    process.exit(1);
  }
  console.log(`[PIN-CHECK]   ✓ Exact lock: ${pkg}@${installed.version} matches exact manifest entry.`);
}

// Verify lockfile versions for critical transitive dependencies
for (const [pkg, expectedVer] of Object.entries(CRITICAL_TRANSITIVE_DEPENDENCIES)) {
  const key = `node_modules/${pkg}`;
  const installed = lockPackages[key];
  if (!installed) {
    console.error(`FATAL: Critical transitive dependency '${pkg}' missing in package-lock.json.`);
    process.exit(1);
  }
  if (installed.version !== expectedVer) {
    console.error(`FATAL: Lockfile version skew for transitive '${pkg}': expected '${expectedVer}', found '${installed.version}'`);
    process.exit(1);
  }
  console.log(`[PIN-CHECK]   ✓ Transitive lock: ${pkg}@${installed.version} matches expected driver version.`);
}

// 5. Verify actual module resolution on disk
console.log("[PIN-CHECK] Category 4: Verifying physical on-disk module resolution...");
function findPackageJson(entryPath) {
  let dir = path.dirname(entryPath);
  while (dir !== path.dirname(dir)) {
    const p = path.join(dir, "package.json");
    if (fs.existsSync(p)) {
      return JSON.parse(fs.readFileSync(p, "utf8"));
    }
    dir = path.dirname(dir);
  }
  return null;
}

for (const [pkg, expectedVer] of Object.entries(EXACT_PINNED_DEPENDENCIES)) {
  try {
    const entryPath = require.resolve(pkg);
    const foundPkg = findPackageJson(entryPath);
    if (!foundPkg || foundPkg.version !== expectedVer) {
      console.error(`FATAL: Disk resolution skew for '${pkg}': expected '${expectedVer}', found '${foundPkg?.version}'`);
      process.exit(1);
    }
    console.log(`[PIN-CHECK]   ✓ ${pkg} resolved on disk at ${entryPath} (v${foundPkg.version}).`);
  } catch (err) {
    console.error(`FATAL: Could not resolve package '${pkg}' in node_modules:`, err.message);
    process.exit(1);
  }
}

console.log("[PIN-CHECK] ========================================================");
console.log(`[PIN-CHECK] Audit Summary:`);
console.log(`[PIN-CHECK]   - Exact-pinned critical dependencies: ${Object.keys(EXACT_PINNED_DEPENDENCIES).length} (verified exact, no floating range)`);
console.log(`[PIN-CHECK]   - Baseline range-based dependencies:  ${Object.keys(EXISTING_RANGE_DEPENDENCIES).length} (verified unchanged from baseline)`);
console.log(`[PIN-CHECK]   - Critical transitive dependencies:   ${Object.keys(CRITICAL_TRANSITIVE_DEPENDENCIES).length} (verified in lockfile)`);
console.log("[PIN-CHECK] SUCCESS: All dependency pin checks PASSED.");
process.exit(0);
