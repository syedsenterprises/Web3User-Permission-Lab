/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Dependency Pin Validator
 *
 * Enforces exact driver versions (pg@8.23.1, pg-pool@3.14.0) and structural API shapes
 * from pg's own internal module resolution context strictly before listener binding.
 */

import { createRequire } from "node:module";
import * as path from "node:path";
import * as fs from "node:fs";

export class DependencyPinValidator {
  static readonly EXPECTED_PG_VERSION = "8.23.1";
  static readonly EXPECTED_PG_POOL_VERSION = "3.14.0";

  private static findPackageJson(entryPath: string): { name: string; version: string } {
    let dir = path.dirname(entryPath);
    while (dir !== path.dirname(dir)) {
      const pkgPath = path.join(dir, "package.json");
      if (fs.existsSync(pkgPath)) {
        return JSON.parse(fs.readFileSync(pkgPath, "utf8"));
      }
      dir = path.dirname(dir);
    }
    throw new Error(`package.json not found in directory hierarchy of ${entryPath}`);
  }

  static assertPinnedDependencies(): void {
    let resolvedPgVersion: string;
    let resolvedNestedPgPoolVersion: string;

    try {
      // 1. Resolve pg entrypoint and version from disk hierarchy (handles lib/index.js)
      const pgEntry = require.resolve("pg");
      const pgPkg = this.findPackageJson(pgEntry);
      resolvedPgVersion = pgPkg.version;

      // 2. Resolve pg-pool from within pg's own internal module-resolution context
      // (Eliminates root vs nested resolution skew and subpath export boundaries)
      const pgRequire = createRequire(pgEntry);
      const pgPoolEntry = pgRequire.resolve("pg-pool");
      const pgPoolPkg = this.findPackageJson(pgPoolEntry);
      resolvedNestedPgPoolVersion = pgPoolPkg.version;

      // 3. Structural API Verification: verify expected public and private APIs
      const pg = require("pg");
      const Pool = pgRequire("pg-pool");

      if (typeof pg.Pool !== "function" || typeof Pool !== "function") {
        throw new Error("pg.Pool or pg-pool is not a constructor");
      }
      if (typeof pg.Pool.prototype.connect !== "function") {
        throw new Error("pg.Pool.prototype.connect missing");
      }
      if (typeof pg.Pool.prototype.end !== "function") {
        throw new Error("pg.Pool.prototype.end missing");
      }
      if (typeof (Pool.prototype as any)._remove !== "function") {
        throw new Error("pg-pool prototype._remove missing (eviction adapter requires _remove)");
      }
      if (typeof (Pool.prototype as any).destroy !== "undefined") {
        throw new Error("Unexpected pool.destroy detected; unverified pool disposal shape");
      }
    } catch (err: any) {
      console.error("FATAL: Failed to resolve database driver packages in module tree", err);
      process.exit(1);
    }

    if (
      resolvedPgVersion !== this.EXPECTED_PG_VERSION ||
      resolvedNestedPgPoolVersion !== this.EXPECTED_PG_POOL_VERSION
    ) {
      console.error("FATAL: Dependency tree drift detected! Pinned driver versions required.", {
        expected: { pg: this.EXPECTED_PG_VERSION, "pg-pool": this.EXPECTED_PG_POOL_VERSION },
        resolved: { pg: resolvedPgVersion, "pg-pool (from pg context)": resolvedNestedPgPoolVersion },
      });
      // Strict fail-closed startup abort: NEVER open gRPC listener under unverified driver versions
      process.exit(1);
    }
  }
}
