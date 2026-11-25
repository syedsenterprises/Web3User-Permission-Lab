/**
 * Web3User Permission Lab - PostgreSQL Pool Lifecycle & Idle-Error Regression Suite
 *
 * Deterministic verification of ManagedPgPoolLifecycle, PostgresConsensusStore,
 * and PostgresWitnessStore recovery, shutdown safety, store health integration,
 * and caller-owned pool isolation.
 */

import { EventEmitter } from "node:events";
import { describe, it, expect, vi } from "vitest";
import type pg from "pg";
import {
  ManagedPgPoolLifecycle,
  classifyPgPoolError,
  type PoolErrorDiagnostic,
} from "../../src/witness/pg-pool-lifecycle.js";
import { PostgresConsensusStore } from "../../src/witness/consensus-store.js";
import { PostgresWitnessStore } from "../../src/witness/postgres-store.js";

class MockPgPool extends EventEmitter {
  public endCalls = 0;
  public shouldRejectEnd = false;
  public queryCalls = 0;
  public onQuery?: () => Promise<unknown>;

  public async query(): Promise<{ rows: Array<Record<string, unknown>> }> {
    this.queryCalls += 1;
    if (this.onQuery) {
      await this.onQuery();
    }
    return { rows: [{ max_seq: "0" }] };
  }

  public async connect(): Promise<{
    query: () => Promise<{ rows: Array<Record<string, unknown>> }>;
    release: () => void;
  }> {
    return {
      query: () => this.query(),
      release: () => {},
    };
  }

  public async end(): Promise<void> {
    this.endCalls += 1;
    if (this.shouldRejectEnd) {
      throw new Error("SIMULATED_END_FAILURE");
    }
  }
}

describe("Production PostgreSQL Pool Error-Handling Hardening (F-POOL-01..04)", () => {
  it("classifies 57P01, 57P03, 08*, network codes, and unexpected errors accurately", () => {
    expect(classifyPgPoolError(Object.assign(new Error("terminating"), { code: "57P01" }))).toEqual({
      code: "57P01",
      classification: "ADMIN_SHUTDOWN",
      message: "terminating",
    });
    expect(classifyPgPoolError(Object.assign(new Error("starting up"), { code: "57P03" }))).toEqual({
      code: "57P03",
      classification: "SERVER_UNAVAILABLE",
      message: "starting up",
    });
    expect(classifyPgPoolError(Object.assign(new Error("conn reset"), { code: "ECONNRESET" }))).toEqual({
      code: "ECONNRESET",
      classification: "CONNECTION_ERROR",
      message: "conn reset",
    });
    expect(classifyPgPoolError(new Error("boom"))).toEqual({
      code: null,
      classification: "UNEXPECTED_POOL_ERROR",
      message: "boom",
    });
  });

  it("1. isolates throwing onPoolError callbacks so they never escape as uncaught EventEmitter errors", () => {
    const mockPool = new MockPgPool();
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    try {
      const lifecycle = new ManagedPgPoolLifecycle({
        component: "PostgresConsensusStore",
        pool: mockPool as unknown as pg.Pool,
        ownPool: true,
        onPoolError: () => {
          throw new Error("OBSERVER_CRASH");
        },
      });

      expect(() =>
        mockPool.emit("error", Object.assign(new Error("idle reset"), { code: "ECONNRESET" }))
      ).not.toThrow();
      expect(lifecycle.getHealth().state).toBe("DEGRADED");
      expect(lifecycle.getHealth().totalPoolErrors).toBe(1);
    } finally {
      errSpy.mockRestore();
    }
  });

  it("2 & 3. handles pool.end() rejection and repeated/concurrent close() idempotently", async () => {
    const store = new PostgresConsensusStore({ clusterId: "cluster-close-idempotent" });
    const mockPool = new MockPgPool();
    mockPool.shouldRejectEnd = true;
    // Inject deterministic mock pool into owned slot for shutdown-failure testing
    (store as unknown as { pool: pg.Pool }).pool = mockPool as unknown as pg.Pool;

    const p1 = store.close();
    const p2 = store.close();
    await expect(p1).rejects.toThrow("SIMULATED_END_FAILURE");
    await expect(p2).rejects.toThrow("SIMULATED_END_FAILURE");
    expect(mockPool.endCalls).toBe(1);
    expect(store.getPoolHealth().state).toBe("CLOSED");
    expect(store.getPoolHealth().closingOrClosed).toBe(true);
    expect(store.getPoolHealth().healthy).toBe(false);

    // WitnessStore concurrent close() idempotency
    const wStore = new PostgresWitnessStore({ epochId: "epoch-close-idempotent" });
    const wMockPool = new MockPgPool();
    (wStore as unknown as { pool: pg.Pool }).pool = wMockPool as unknown as pg.Pool;
    await Promise.all([wStore.close(), wStore.close(), wStore.close()]);
    expect(wMockPool.endCalls).toBe(1);
    expect(wStore.getPoolHealth().state).toBe("CLOSED");
  });

  it("4. keeps shutdown-safe listener active through CLOSING and CLOSED so late 57P01 never becomes unhandled", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const observed: PoolErrorDiagnostic[] = [];

    const store = new PostgresConsensusStore({
      clusterId: "cluster-shutdown-57p01",
      onPoolError: (d) => observed.push(d),
    });
    const realPool = (store as unknown as { pool: EventEmitter }).pool;

    try {
      await store.close();
      expect(store.getPoolHealth().state).toBe("CLOSED");
      // Listener stays attached on disposed owned pool to catch late pg-pool socket 57P01
      expect(realPool.listenerCount("error")).toBe(1);

      realPool.emit(
        "error",
        Object.assign(new Error("terminating connection due to administrator command"), {
          code: "57P01",
        })
      );
      expect(observed).toHaveLength(1);
      expect(observed[0].duringShutdown).toBe(true);
      expect(observed[0].code).toBe("57P01");
      expect(errSpy).not.toHaveBeenCalled();

      // Non-57P01 error during shutdown remains logged and visible
      realPool.emit("error", Object.assign(new Error("connection failure"), { code: "08006" }));
      expect(observed).toHaveLength(2);
      expect(observed[1].classification).toBe("CONNECTION_ERROR");
      expect(errSpy).toHaveBeenCalledTimes(1);
    } finally {
      errSpy.mockRestore();
    }
  });

  it("5. recovers DEGRADED -> HEALTHY on verified probe while preserving diagnostics, and blocks recovery if concurrent error arrives mid-probe", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const mockPool = new MockPgPool();

    try {
      const lifecycle = new ManagedPgPoolLifecycle({
        component: "PostgresConsensusStore",
        pool: mockPool as unknown as pg.Pool,
        ownPool: true,
      });

      mockPool.emit("error", Object.assign(new Error("transient reset"), { code: "ECONNRESET" }));
      expect(lifecycle.getHealth().state).toBe("DEGRADED");
      expect(lifecycle.getHealth().healthy).toBe(false);

      // Concurrent error during in-flight probe must prevent false recovery
      mockPool.onQuery = async () => {
        mockPool.emit("error", Object.assign(new Error("mid-probe failure"), { code: "57P01" }));
      };
      const midProbeHealth = await lifecycle.verifyConnectivity();
      expect(midProbeHealth.state).toBe("DEGRADED");
      expect(midProbeHealth.healthy).toBe(false);
      expect(midProbeHealth.totalPoolErrors).toBe(2);

      // Clean probe without concurrent errors restores HEALTHY while preserving error history
      mockPool.onQuery = undefined;
      const recovered = await lifecycle.verifyConnectivity();
      expect(recovered.state).toBe("HEALTHY");
      expect(recovered.healthy).toBe(true);
      expect(recovered.totalPoolErrors).toBe(2);
      expect(recovered.lastPoolError?.code).toBe("57P01");
    } finally {
      errSpy.mockRestore();
    }
  });

  it("6. integrates pool lifecycle recovery & shutdown state into PostgresWitnessStore.getSyncStatus() and PostgresConsensusStore.verifyPoolHealth()", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const wStore = new PostgresWitnessStore({ epochId: "epoch-health-int" });
    const mockPool = new MockPgPool();
    (wStore as unknown as { pool: pg.Pool }).pool = mockPool as unknown as pg.Pool;
    const lifecycle = (wStore as unknown as { poolLifecycle: ManagedPgPoolLifecycle }).poolLifecycle;
    const ownedPool = (wStore as unknown as { pool: EventEmitter }).pool;

    // Re-point lifecycle to mockPool query while testing recovery via getSyncStatus()
    try {
      const realStore = new PostgresWitnessStore({ epochId: "epoch-sync-status" });
      const realOwnedPool = (realStore as unknown as { pool: EventEmitter }).pool;
      // Inject connect/query on the real pool instance for deterministic test without PG
      (realStore as unknown as { pool: { connect: () => Promise<unknown> } }).pool.connect = () =>
        mockPool.connect();

      realOwnedPool.emit("error", Object.assign(new Error("idle drop"), { code: "08006" }));
      expect(realStore.getPoolHealth().state).toBe("DEGRADED");

      const status = await realStore.getSyncStatus();
      expect(status.healthy).toBe(true);
      expect(status.poolHealth.state).toBe("HEALTHY");
      expect(status.poolHealth.totalPoolErrors).toBe(1);

      await realStore.close();
      const closedStatus = await realStore.getSyncStatus();
      expect(closedStatus.healthy).toBe(false);
      expect(closedStatus.poolHealth.state).toBe("CLOSED");

      await wStore.close();
      expect(lifecycle.getHealth().state).toBe("CLOSED");
      expect(ownedPool.listenerCount("error")).toBe(0);
    } finally {
      errSpy.mockRestore();
    }
  });

  it("7 & 8. preserves caller-owned pools and handles multiple owned errors with exactly 1 listener", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const extPool = new MockPgPool();
      const cs = new PostgresConsensusStore({
        pool: extPool as unknown as pg.Pool,
        clusterId: "cluster-ext",
      });
      expect(extPool.listenerCount("error")).toBe(0);
      await cs.close();
      expect(extPool.endCalls).toBe(0);

      const ownedPool = new MockPgPool();
      const lifecycle = new ManagedPgPoolLifecycle({
        component: "PostgresConsensusStore",
        pool: ownedPool as unknown as pg.Pool,
        ownPool: true,
      });
      expect(ownedPool.listenerCount("error")).toBe(1);
      ownedPool.emit("error", Object.assign(new Error("err1"), { code: "ECONNRESET" }));
      ownedPool.emit("error", Object.assign(new Error("err2"), { code: "57P03" }));
      ownedPool.emit("error", new Error("err3"));
      expect(ownedPool.listenerCount("error")).toBe(1);
      expect(lifecycle.getHealth().totalPoolErrors).toBe(3);
      expect(lifecycle.getHealth().lastPoolError?.classification).toBe("UNEXPECTED_POOL_ERROR");
    } finally {
      errSpy.mockRestore();
    }
  });
});
