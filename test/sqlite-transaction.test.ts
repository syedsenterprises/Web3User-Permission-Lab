import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  BASE_CONTENTION_DELAY_MS,
  MAX_CONTENTION_BUDGET_MS,
  MAX_CONTENTION_DELAY_MS,
  MAX_CONTENTION_RETRIES,
  SQLITE_BUSY,
  SQLITE_CORRUPT,
  SQLITE_FULL,
  SQLITE_IOERR,
  SQLITE_LOCKED,
  beginImmediateWithRetry,
  calculateBackoffWithJitter,
  getSqliteErrcode,
  isBusyOrLockedError,
  isFatalIOError,
  sleepSync,
  withImmediateTransaction,
} from "../src/sqlite-transaction.js";

describe("Milestone 6.4: SQLite Transaction Safety and Rollback Invariants", () => {
  let directory: string | undefined;

  function databasePath(filename: string = "test-trans.sqlite"): string {
    directory ??= mkdtempSync(join(tmpdir(), "web3user-trans-"));
    return join(directory, filename);
  }

  afterEach(() => {
    if (directory) {
      rmSync(directory, { recursive: true, force: true });
      directory = undefined;
    }
  });

  // 1. Successful commit
  it("executes a callback and commits changes inside an immediate transaction", () => {
    const db = new DatabaseSync(":memory:");
    db.exec("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT);");

    const result = withImmediateTransaction(db, () => {
      db.prepare("INSERT INTO test_table VALUES (1, 'alice')").run();
      return "SUCCESS_VALUE";
    });

    expect(result).toBe("SUCCESS_VALUE");
    const row = db.prepare("SELECT name FROM test_table WHERE id = 1").get() as { name: string } | undefined;
    expect(row?.name).toBe("alice");
    db.close();
  });

  // 2. Callback failure rolls back partial writes and rethrows original error
  it("rolls back partial writes and rethrows the original error when callback throws", () => {
    const db = new DatabaseSync(":memory:");
    db.exec("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT);");

    const customError = new Error("Custom business error inside transaction");

    expect(() => {
      withImmediateTransaction(db, () => {
        db.prepare("INSERT INTO test_table VALUES (1, 'partial_write')").run();
        throw customError;
      });
    }).toThrow("Custom business error inside transaction");

    // Partial write must be completely rolled back
    const countRow = db.prepare("SELECT count(*) as c FROM test_table").get() as { c: number };
    expect(countRow.c).toBe(0);

    // Verify transaction was closed and database remains immediately usable for new transactions
    expect(() => {
      db.exec("BEGIN IMMEDIATE;");
      db.exec("INSERT INTO test_table VALUES (2, 'bob');");
      db.exec("COMMIT;");
    }).not.toThrow();

    const row = db.prepare("SELECT name FROM test_table WHERE id = 2").get() as { name: string } | undefined;
    expect(row?.name).toBe("bob");
    db.close();
  });

  // 3. Deferred foreign key constraint failure on COMMIT rolls back and cleans up
  it("rolls back and cleans up transaction when COMMIT fails on deferred foreign keys", () => {
    const db = new DatabaseSync(":memory:");
    db.exec("PRAGMA foreign_keys = ON;");
    db.exec(`
      CREATE TABLE parent (id INTEGER PRIMARY KEY);
      CREATE TABLE child (
        id INTEGER PRIMARY KEY,
        parent_id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED
      );
    `);

    // In a deferred constraint setup, the INSERT succeeds during the callback,
    // but COMMIT fails when SQLite checks constraint integrity at commit time.
    expect(() => {
      withImmediateTransaction(db, () => {
        db.prepare("INSERT INTO child VALUES (1, 9999)").run(); // parent 9999 does not exist
      });
    }).toThrow(/FOREIGN KEY constraint failed/i);

    // The partial child row must have been rolled back
    const countRow = db.prepare("SELECT count(*) as c FROM child").get() as { c: number };
    expect(countRow.c).toBe(0);

    // The database must not be left in an open or uncommitted transaction state
    expect(() => {
      db.exec("BEGIN IMMEDIATE;");
      db.exec("INSERT INTO parent VALUES (1);");
      db.exec("INSERT INTO child VALUES (1, 1);");
      db.exec("COMMIT;");
    }).not.toThrow();

    const validRow = db.prepare("SELECT count(*) as c FROM child").get() as { c: number };
    expect(validRow.c).toBe(1);
    db.close();
  });

  // 4. Bounded contention retry handling
  it("handles write contention with bounded retry and fails closed when limit is exceeded", () => {
    const dbFile = databasePath();
    const db1 = new DatabaseSync(dbFile);
    const db2 = new DatabaseSync(dbFile);

    // db2 fast timeout for test
    db2.exec("PRAGMA busy_timeout = 5;");

    // db1 acquires exclusive immediate write lock
    db1.exec("BEGIN IMMEDIATE;");

    // db2 attempts withImmediateTransaction with maxRetries=2
    expect(() => {
      withImmediateTransaction(
        db2,
        () => {
          return "unreachable";
        },
        2,
        5,
      );
    }).toThrow("Database is busy; transaction contention retry limit exceeded.");

    // Release lock on db1
    db1.exec("ROLLBACK;");

    // Now db2 succeeds
    const res = withImmediateTransaction(db2, () => "now_free");
    expect(res).toBe("now_free");

    db1.close();
    db2.close();
  });

  // 5. beginImmediateWithRetry rethrows non-busy errors immediately
  it("rethrows non-busy SQLite errors immediately without retry", () => {
    const db = new DatabaseSync(":memory:");
    db.close(); // Closed database produces immediate non-busy error

    expect(() => {
      beginImmediateWithRetry(db, 3, 5);
    }).toThrow();
  });

  // 6. isBusyOrLockedError correctly classifies SQLite errors
  it("correctly identifies busy and locked errors", () => {
    expect(isBusyOrLockedError(new Error("database is busy"))).toBe(true);
    expect(isBusyOrLockedError(new Error("database is locked"))).toBe(true);
    expect(isBusyOrLockedError(new Error("SQLITE_BUSY: database table is locked"))).toBe(true);
    expect(isBusyOrLockedError(new Error("UNIQUE constraint failed"))).toBe(false);
    expect(isBusyOrLockedError(new Error("syntax error"))).toBe(false);
    expect(isBusyOrLockedError("string error")).toBe(false);
    expect(isBusyOrLockedError(null)).toBe(false);
  });

  // 7. sleepSync synchronous delay
  it("sleepSync provides synchronous non-spinning delay", () => {
    const start = Date.now();
    sleepSync(15);
    const elapsed = Date.now() - start;
    expect(elapsed).toBeGreaterThanOrEqual(10);

    // Non-positive delay returns immediately
    const start2 = Date.now();
    sleepSync(0);
    sleepSync(-5);
    expect(Date.now() - start2).toBeLessThan(10);
  });

  // 8. calculateBackoffWithJitter deterministically scales with attempt and clamps to maximum ceiling
  it("calculates exponential backoff with full jitter deterministically", () => {
    // Attempt <= 0 returns 0
    expect(calculateBackoffWithJitter(0)).toBe(0);
    expect(calculateBackoffWithJitter(-1)).toBe(0);

    // Full jitter with randomFn = () => 0 returns 0 for any attempt
    expect(calculateBackoffWithJitter(1, 15, 100, () => 0)).toBe(0);
    expect(calculateBackoffWithJitter(2, 15, 100, () => 0)).toBe(0);

    // Full jitter with randomFn = () => 0.9999 returns maximum ceiling for attempt
    // attempt 1: ceiling = min(100, 15 * 2^0) = 15
    expect(calculateBackoffWithJitter(1, 15, 100, () => 0.9999)).toBe(15);
    // attempt 2: ceiling = min(100, 15 * 2^1) = 30
    expect(calculateBackoffWithJitter(2, 15, 100, () => 0.9999)).toBe(30);
    // attempt 3: ceiling = min(100, 15 * 2^2) = 60
    expect(calculateBackoffWithJitter(3, 15, 100, () => 0.9999)).toBe(60);
    // attempt 4: ceiling = min(100, 15 * 2^3 = 120) = 100
    expect(calculateBackoffWithJitter(4, 15, 100, () => 0.9999)).toBe(100);
    // attempt 5: ceiling = min(100, 15 * 2^4 = 240) = 100
    expect(calculateBackoffWithJitter(5, 15, 100, () => 0.9999)).toBe(100);

    // Midpoint jitter (randomFn = () => 0.5)
    expect(calculateBackoffWithJitter(1, 15, 100, () => 0.5)).toBe(8); // floor(0.5 * 16)
    expect(calculateBackoffWithJitter(2, 15, 100, () => 0.5)).toBe(15); // floor(0.5 * 31)
  });

  // 9. Cumulative retry budget clamps and halts retries when exhausted
  it("halts retries when cumulative budget is exhausted even if retry count remains", () => {
    const dbFile = databasePath("budget-exhaustion.sqlite");
    const db1 = new DatabaseSync(dbFile);
    const db2 = new DatabaseSync(dbFile);

    try {
      db2.exec("PRAGMA busy_timeout = 1;");
      db1.exec("BEGIN IMMEDIATE;");

      const delaysRecorded: number[] = [];
      const mockSleep = (ms: number) => {
        delaysRecorded.push(ms);
      };

      // Ceiling per attempt with base 15ms:
      // attempt 1: min(100, 15 * 2^0) = 15
      // attempt 2: min(100, 15 * 2^1) = 30
      // Budget = 20ms:
      // attempt 1 consumes 15ms (elapsed = 15ms, remaining = 5ms)
      // attempt 2 wants 30ms, clamped to remaining budget 5ms (elapsed = 20ms)
      // attempt 3 sees elapsedBudget (20) >= maxBudget (20) -> halts without sleeping
      const result = beginImmediateWithRetry(
        db2,
        10, // high retry count
        15, // base delay
        20, // max budget
        () => 1.0, // mock random producing maximum ceiling
        mockSleep, // mock sleep recorder
      );

      expect(result).toBe(false);
      expect(delaysRecorded).toEqual([15, 5]);
      expect(delaysRecorded.reduce((a, b) => a + b, 0)).toBe(20);
    } finally {
      try {
        db1.exec("ROLLBACK;");
      } catch {}
      db1.close();
      db2.close();
    }
  });

  // 10. Default retry constants match specification (5 attempts, 15ms base, 100ms max, 250ms budget)
  it("exposes default retry constants matching specification", () => {
    expect(MAX_CONTENTION_RETRIES).toBe(5);
    expect(BASE_CONTENTION_DELAY_MS).toBe(15);
    expect(MAX_CONTENTION_DELAY_MS).toBe(100);
    expect(MAX_CONTENTION_BUDGET_MS).toBe(250);
  });

  // 11. isFatalIOError discrimination
  it("distinguishes fatal I/O errors from transient contention and capacity errors", () => {
    expect(isFatalIOError(new Error("sqlite error: disk I/O error (SQLITE_IOERR)"))).toBe(true);
    expect(isFatalIOError(new Error("sqlite error: database disk image is malformed (SQLITE_CORRUPT)"))).toBe(true);
    expect(isFatalIOError("Fatal storage I/O error: device detached")).toBe(true);
    expect(isFatalIOError(new Error("database or disk is full (SQLITE_FULL)"))).toBe(false);
    expect(isFatalIOError(new Error("database is locked (SQLITE_BUSY)"))).toBe(false);
    expect(isFatalIOError(new Error("UNIQUE constraint failed (SQLITE_CONSTRAINT)"))).toBe(false);
    expect(isFatalIOError(null)).toBe(false);
    expect(isFatalIOError(undefined)).toBe(false);
  });

  // 12. Rollback failure during transaction abort notifies failure handler without masking original error
  it("notifies failure handler on fatal rollback error without masking original callback error", () => {
    const db = new DatabaseSync(":memory:");
    db.exec("CREATE TABLE t (x INT);");

    let fatalReported: unknown;
    const originalExec = db.exec.bind(db);
    db.exec = (sql: string) => {
      if (sql.includes("ROLLBACK")) {
        throw new Error("disk I/O error during rollback (SQLITE_IOERR)");
      }
      return originalExec(sql);
    };

    const originalError = new Error("Original application error");

    expect(() => {
      withImmediateTransaction(
        db,
        () => {
          throw originalError;
        },
        undefined,
        undefined,
        undefined,
        undefined,
        (err) => {
          fatalReported = err;
        },
      );
    }).toThrow("Original application error");

    // The rollback I/O error was reported to failure handler
    expect(fatalReported).toBeInstanceOf(Error);
    expect((fatalReported as Error).message).toContain("SQLITE_IOERR");

    db.close();
  });

  // 13. Structured SQLite error codes inspection and extended code masking
  it("recognizes structured SQLite error codes and extended codes", () => {
    // Helper extraction
    expect(getSqliteErrcode({ errcode: SQLITE_BUSY })).toBe(SQLITE_BUSY);
    expect(getSqliteErrcode({ errcode: SQLITE_LOCKED })).toBe(SQLITE_LOCKED);
    expect(getSqliteErrcode({ errcode: SQLITE_IOERR })).toBe(SQLITE_IOERR);
    expect(getSqliteErrcode({ errcode: SQLITE_CORRUPT })).toBe(SQLITE_CORRUPT);
    expect(getSqliteErrcode({ errcode: SQLITE_FULL })).toBe(SQLITE_FULL);
    // Extended error codes (masking with 0xff)
    expect(getSqliteErrcode({ errcode: 266 })).toBe(SQLITE_IOERR); // SQLITE_IOERR_READ
    expect(getSqliteErrcode({ errcode: 522 })).toBe(SQLITE_IOERR); // SQLITE_IOERR_SHORT_READ
    expect(getSqliteErrcode({ errcode: 261 })).toBe(SQLITE_BUSY); // SQLITE_BUSY_RECOVERY
    expect(getSqliteErrcode({ errcode: "not a number" })).toBeUndefined();
    expect(getSqliteErrcode(null)).toBeUndefined();
    expect(getSqliteErrcode(undefined)).toBeUndefined();

    // isFatalIOError structured vs fallback
    expect(isFatalIOError({ errcode: SQLITE_IOERR })).toBe(true);
    expect(isFatalIOError({ errcode: SQLITE_CORRUPT })).toBe(true);
    expect(isFatalIOError({ errcode: 266 })).toBe(true);
    expect(isFatalIOError({ errcode: SQLITE_FULL })).toBe(false);
    expect(isFatalIOError({ errcode: SQLITE_BUSY })).toBe(false);
    expect(isFatalIOError({ errcode: 19 })).toBe(false); // SQLITE_CONSTRAINT

    // isBusyOrLockedError structured vs fallback
    expect(isBusyOrLockedError({ errcode: SQLITE_BUSY })).toBe(true);
    expect(isBusyOrLockedError({ errcode: SQLITE_LOCKED })).toBe(true);
    expect(isBusyOrLockedError({ errcode: 261 })).toBe(true);
    expect(isBusyOrLockedError({ errcode: SQLITE_IOERR })).toBe(false);
    expect(isBusyOrLockedError({ errcode: SQLITE_FULL })).toBe(false);
  });

  // 14. Dedicated onRollbackFailure path distinguishes rollback failures from commit failures
  it("invokes onRollbackFailure with rollback and original errors without calling onCommitFailure", () => {
    const db = new DatabaseSync(":memory:");
    db.exec("CREATE TABLE t (x INT);");

    let rollbackErrorReceived: unknown;
    let originalErrorReceived: unknown;
    let commitErrorCalled = false;

    const originalExec = db.exec.bind(db);
    db.exec = (sql: string) => {
      if (sql.includes("ROLLBACK")) {
        throw new Error("sqlite error: disk I/O error during rollback (SQLITE_IOERR)");
      }
      return originalExec(sql);
    };

    const originalError = new Error("Business logic aborted");

    expect(() => {
      withImmediateTransaction(
        db,
        () => {
          throw originalError;
        },
        undefined,
        undefined,
        undefined,
        undefined,
        (_commitErr) => {
          commitErrorCalled = true;
        },
        (rollbackErr, origErr) => {
          rollbackErrorReceived = rollbackErr;
          originalErrorReceived = origErr;
        },
      );
    }).toThrow("Business logic aborted");

    expect(commitErrorCalled).toBe(false);
    expect(rollbackErrorReceived).toBeInstanceOf(Error);
    expect((rollbackErrorReceived as Error).message).toContain("SQLITE_IOERR");
    expect(originalErrorReceived).toBe(originalError);

    db.close();
  });

  // 15. Ambiguous COMMIT failure invokes onCommitFailure and NOT onRollbackFailure
  it("invokes onCommitFailure exclusively when COMMIT fails, never onRollbackFailure", () => {
    const db = new DatabaseSync(":memory:");
    db.exec("CREATE TABLE t (x INT);");

    let commitErrorReceived: unknown;
    let rollbackFailureCalled = false;

    const originalExec = db.exec.bind(db);
    db.exec = (sql: string) => {
      if (sql.includes("COMMIT")) {
        throw new Error("sqlite error: disk I/O error during commit (SQLITE_IOERR)");
      }
      return originalExec(sql);
    };

    expect(() => {
      withImmediateTransaction(
        db,
        () => {
          return "ok";
        },
        undefined,
        undefined,
        undefined,
        undefined,
        (commitErr) => {
          commitErrorReceived = commitErr;
        },
        (_rollbackErr) => {
          rollbackFailureCalled = true;
        },
      );
    }).toThrow("SQLITE_IOERR");

    expect(commitErrorReceived).toBeInstanceOf(Error);
    expect((commitErrorReceived as Error).message).toContain("during commit");
    expect(rollbackFailureCalled).toBe(false);

    db.close();
  });
});
