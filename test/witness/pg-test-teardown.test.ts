/**
 * Web3User Permission Lab - Deterministic PostgreSQL Test Teardown Regression Suite
 *
 * Verifies pg-test-teardown.ts across all 8 required lifecycle scenarios without
 * arbitrary sleeps or process-wide exception handlers.
 */

import { EventEmitter } from "node:events";
import { describe, it, expect } from "vitest";
import type pg from "pg";
import {
  registerManagedTestPool,
  getTestPoolDiagnostics,
  assertNoUnexpectedPoolErrors,
  endManagedTestPool,
  destroyDisposableTestDb,
  closeAdminTestPool,
} from "./helpers/pg-test-teardown.js";

class MockTeardownPool extends EventEmitter {
  public endCalls = 0;
  public shouldRejectEnd = false;
  public queries: string[] = [];
  public remainingBackends: Array<{ pid: number }> = [];
  public onEnd?: () => void;

  public async query(sql: string): Promise<{ rows: Array<{ pid: number }> }> {
    this.queries.push(sql);
    if (sql.includes("SELECT pid") && sql.includes("pg_stat_activity")) {
      return { rows: this.remainingBackends };
    }
    return { rows: [] };
  }

  public async end(): Promise<void> {
    this.endCalls += 1;
    if (this.onEnd) {
      this.onEnd();
    }
    if (this.shouldRejectEnd) {
      throw new Error("SIMULATED_TEST_POOL_END_FAILURE");
    }
  }
}

describe("PostgreSQL Test Teardown Race Remediation", () => {
  it("1 & 5. absorbs expected 57P01 during intentional teardown without unhandled Vitest errors", async () => {
    const adminPool = new MockTeardownPool();
    const pool = new MockTeardownPool();
    registerManagedTestPool(pool as unknown as pg.Pool);

    // Simulate pg-pool resolving pool.end() and emitting late 57P01 on closing socket
    pool.onEnd = () => {
      queueMicrotask(() => {
        pool.emit(
          "error",
          Object.assign(new Error("terminating connection due to administrator command"), {
            code: "57P01",
          })
        );
      });
    };

    const tracked = ["db_expected_57p01"];
    await destroyDisposableTestDb({
      adminPool: adminPool as unknown as pg.Pool,
      dbName: "db_expected_57p01",
      pool: pool as unknown as pg.Pool,
      trackedDatabases: tracked,
    });

    // Late 57P01 after CLOSED must also be absorbed cleanly
    pool.emit(
      "error",
      Object.assign(new Error("terminating connection due to administrator command"), {
        code: "57P01",
      })
    );

    const diag = getTestPoolDiagnostics(pool as unknown as pg.Pool);
    expect(diag).toMatchObject({
      state: "CLOSED",
      listenerAttached: true,
      expectedShutdown57P01Count: 2,
      unexpectedErrorCount: 0,
    });
    expect(tracked).toHaveLength(0);
    await closeAdminTestPool(adminPool as unknown as pg.Pool);
  });

  it("2. fails teardown when unexpected pool errors occur during normal execution or non-57P01 during shutdown", async () => {
    const adminPool = new MockTeardownPool();
    const pool = new MockTeardownPool();
    registerManagedTestPool(pool as unknown as pg.Pool);

    // Unexpected 57P01 during ACTIVE test execution must fail
    pool.emit(
      "error",
      Object.assign(new Error("unexpected mid-test termination"), { code: "57P01" })
    );

    await expect(
      destroyDisposableTestDb({
        adminPool: adminPool as unknown as pg.Pool,
        dbName: "db_unexpected_active",
        pool: pool as unknown as pg.Pool,
      })
    ).rejects.toThrow(/57P01: unexpected mid-test termination/);

    // Non-57P01 during shutdown must also fail
    const pool2 = new MockTeardownPool();
    registerManagedTestPool(pool2 as unknown as pg.Pool);
    pool2.onEnd = () => {
      pool2.emit("error", Object.assign(new Error("socket reset"), { code: "ECONNRESET" }));
    };
    await expect(
      destroyDisposableTestDb({
        adminPool: adminPool as unknown as pg.Pool,
        dbName: "db_unexpected_shutdown",
        pool: pool2 as unknown as pg.Pool,
      })
    ).rejects.toThrow(/ECONNRESET: socket reset/);
  });

  it("3 & 4. handles late socket errors after shutdown and propagates pool.end() rejection", async () => {
    const adminPool = new MockTeardownPool();
    const pool = new MockTeardownPool();
    pool.shouldRejectEnd = true;
    registerManagedTestPool(pool as unknown as pg.Pool);

    await expect(
      destroyDisposableTestDb({
        adminPool: adminPool as unknown as pg.Pool,
        dbName: "db_reject_end",
        pool: pool as unknown as pg.Pool,
      })
    ).rejects.toThrow("SIMULATED_TEST_POOL_END_FAILURE");

    expect(getTestPoolDiagnostics(pool as unknown as pg.Pool)?.state).toBe("CLOSED");
    expect(() =>
      pool.emit("error", Object.assign(new Error("late 57P01"), { code: "57P01" }))
    ).not.toThrow();
    assertNoUnexpectedPoolErrors(pool as unknown as pg.Pool);
  });

  it("6 & 8. prevents duplicate listener installation and supports repeated/concurrent teardown safely", async () => {
    const pool = new MockTeardownPool();
    registerManagedTestPool(pool as unknown as pg.Pool);
    registerManagedTestPool(pool as unknown as pg.Pool);
    expect(pool.listenerCount("error")).toBe(1);

    await Promise.all([
      endManagedTestPool(pool as unknown as pg.Pool),
      endManagedTestPool(pool as unknown as pg.Pool),
      endManagedTestPool(pool as unknown as pg.Pool),
    ]);
    expect(pool.endCalls).toBe(1);
    expect(pool.listenerCount("error")).toBe(1);
  });

  it("7. terminates lingering database backends only when pg_stat_activity reports remaining pids", async () => {
    const adminNoBackends = new MockTeardownPool();
    await destroyDisposableTestDb({
      adminPool: adminNoBackends as unknown as pg.Pool,
      dbName: "db_clean",
    });
    expect(adminNoBackends.queries.some((q) => q.includes("pg_terminate_backend"))).toBe(false);

    const adminWithBackends = new MockTeardownPool();
    adminWithBackends.remainingBackends = [{ pid: 4242 }];
    await destroyDisposableTestDb({
      adminPool: adminWithBackends as unknown as pg.Pool,
      dbName: "db_lingering",
    });
    expect(adminWithBackends.queries.some((q) => q.includes("pg_terminate_backend"))).toBe(true);
  });
});
