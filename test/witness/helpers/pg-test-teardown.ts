/**
 * Web3User Permission Lab - Deterministic PostgreSQL Test Teardown Helper
 *
 * Prevents the pg-pool@3.14.0 teardown race where `await pool.end()` resolves
 * before server-side sockets finish closing and subsequent `pg_terminate_backend`
 * triggers `57P01` on closing idle clients without a pool `"error"` listener.
 *
 * Guarantees:
 * - Exactly one `"error"` listener per test-owned pool (via WeakMap guard).
 * - Expected `57P01` is only accepted during intentional `CLOSING`/`CLOSED` teardown.
 * - Unexpected errors during normal execution, or non-`57P01` errors during
 *   shutdown, are recorded and fail the test via `assertNoUnexpectedPoolErrors()`.
 * - Zero arbitrary sleeps, zero process-wide exception handlers.
 */

import pg, { type PoolConfig } from "pg";

export type TestPoolState = "ACTIVE" | "CLOSING" | "CLOSED";

interface ManagedTestPoolRecord {
  state: TestPoolState;
  listenerAttached: boolean;
  expectedShutdown57P01Count: number;
  unexpectedErrors: Error[];
  closePromise: Promise<void> | null;
  readonly listener: (err: Error) => void;
}

const poolRegistry = new WeakMap<pg.Pool, ManagedTestPoolRecord>();

function getErrorCode(err: unknown): string | undefined {
  if (err && typeof err === "object" && "code" in err) {
    const code = (err as { code?: unknown }).code;
    return typeof code === "string" ? code : undefined;
  }
  return undefined;
}

/**
 * Attaches a single deterministic `"error"` listener to a test-owned `pg.Pool`.
 * Safe to call multiple times on the same pool; never installs duplicate listeners.
 */
export function registerManagedTestPool(pool: pg.Pool): ManagedTestPoolRecord {
  const existing = poolRegistry.get(pool);
  if (existing) {
    return existing;
  }

  const record: ManagedTestPoolRecord = {
    state: "ACTIVE",
    listenerAttached: false,
    expectedShutdown57P01Count: 0,
    unexpectedErrors: [],
    closePromise: null,
    listener: (err: Error) => {
      const code = getErrorCode(err);
      const duringShutdown = record.state === "CLOSING" || record.state === "CLOSED";
      if (duringShutdown && code === "57P01") {
        record.expectedShutdown57P01Count += 1;
        return;
      }
      record.unexpectedErrors.push(err);
    },
  };

  pool.on("error", record.listener);
  record.listenerAttached = true;
  poolRegistry.set(pool, record);
  return record;
}

export function createManagedTestPool(config: PoolConfig): pg.Pool {
  const pool = new pg.Pool(config);
  registerManagedTestPool(pool);
  return pool;
}

export function getTestPoolDiagnostics(pool: pg.Pool): {
  state: TestPoolState;
  listenerAttached: boolean;
  expectedShutdown57P01Count: number;
  unexpectedErrorCount: number;
} | null {
  const rec = poolRegistry.get(pool);
  if (!rec) return null;
  return {
    state: rec.state,
    listenerAttached: rec.listenerAttached,
    expectedShutdown57P01Count: rec.expectedShutdown57P01Count,
    unexpectedErrorCount: rec.unexpectedErrors.length,
  };
}

export function assertNoUnexpectedPoolErrors(pool: pg.Pool, label = "pg.Pool"): void {
  const rec = poolRegistry.get(pool);
  if (!rec || rec.unexpectedErrors.length === 0) {
    return;
  }
  const summary = rec.unexpectedErrors
    .map((e) => `${getErrorCode(e) ?? "UNKNOWN"}: ${e.message}`)
    .join("; ");
  throw new Error(`Unexpected ${label} error(s) observed: ${summary}`);
}

/**
 * Idempotently closes a test-owned `pg.Pool`, keeping the shutdown-safe `"error"`
 * listener active through `CLOSING` and `CLOSED` to absorb late `pg-pool` socket `57P01`.
 */
export async function endManagedTestPool(pool: pg.Pool): Promise<void> {
  const rec = registerManagedTestPool(pool);
  if (rec.closePromise) {
    return rec.closePromise;
  }

  rec.state = "CLOSING";
  rec.closePromise = (async () => {
    try {
      await pool.end();
    } finally {
      rec.state = "CLOSED";
    }
  })();
  return rec.closePromise;
}

/**
 * Deterministically ends the disposable DB pool, terminates any lingering backends
 * on `dbName` if present, drops `dbName`, and asserts zero unexpected pool errors.
 */
export async function destroyDisposableTestDb(params: {
  adminPool: pg.Pool;
  dbName: string;
  pool?: pg.Pool;
  trackedDatabases?: string[];
}): Promise<void> {
  const { adminPool, dbName, pool, trackedDatabases } = params;
  registerManagedTestPool(adminPool);

  let endError: unknown = null;
  if (pool) {
    try {
      await endManagedTestPool(pool);
    } catch (err) {
      endError = err;
    }
  }

  try {
    const active = await adminPool.query<{ pid: number }>(
      `SELECT pid
       FROM pg_stat_activity
       WHERE datname = $1 AND pid <> pg_backend_pid()`,
      [dbName]
    );
    if (active.rows.length > 0) {
      await adminPool.query(
        `SELECT pg_terminate_backend(pid)
         FROM pg_stat_activity
         WHERE datname = $1 AND pid <> pg_backend_pid()`,
        [dbName]
      );
    }
    await adminPool.query(`DROP DATABASE IF EXISTS "${dbName}"`);
    if (trackedDatabases) {
      const idx = trackedDatabases.indexOf(dbName);
      if (idx !== -1) {
        trackedDatabases.splice(idx, 1);
      }
    }
  } finally {
    if (endError) {
      throw endError;
    }
    if (pool) {
      assertNoUnexpectedPoolErrors(pool, `disposable pool (${dbName})`);
    }
  }
}

/**
 * Cleans up any remaining tracked disposable databases, ends `adminPool`,
 * and asserts zero unexpected pool errors on `adminPool`.
 */
export async function closeAdminTestPool(
  adminPool: pg.Pool,
  trackedDatabases: string[] = []
): Promise<void> {
  registerManagedTestPool(adminPool);

  for (const dbName of [...trackedDatabases]) {
    try {
      await destroyDisposableTestDb({ adminPool, dbName, trackedDatabases });
    } catch {
      // Best-effort sweep of leftover DBs during outer afterAll
    }
  }

  await endManagedTestPool(adminPool);
  assertNoUnexpectedPoolErrors(adminPool, "adminPool");
}
