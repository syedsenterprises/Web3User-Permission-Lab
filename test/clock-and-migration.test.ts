import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { SystemClock, TestClock } from "../src/clock.js";
import { SQLiteAuthorizationStore } from "../src/authorization-store.js";

describe("Milestone 6.2 Phase 1: Clock Abstraction", () => {
  it("SystemClock returns plausible current Unix seconds", () => {
    const clock = new SystemClock();
    const before = Math.floor(Date.now() / 1000);
    const now = clock.nowSeconds();
    const after = Math.floor(Date.now() / 1000);

    expect(now).toBeGreaterThanOrEqual(before);
    expect(now).toBeLessThanOrEqual(after);
    expect(Number.isSafeInteger(now)).toBe(true);
  });

  it("TestClock handles initialization, setting, and advancing time deterministically", () => {
    const clock = new TestClock(100);
    expect(clock.nowSeconds()).toBe(100);

    clock.advance(50);
    expect(clock.nowSeconds()).toBe(150);

    clock.set(300);
    expect(clock.nowSeconds()).toBe(300);

    expect(() => new TestClock(-1)).toThrow("Initial seconds must be a non-negative safe integer.");
    expect(() => clock.set(-10)).toThrow("Seconds must be a non-negative safe integer.");
    expect(() => clock.advance(-5)).toThrow("Advance duration must be a non-negative safe integer.");
  });
});

describe("Milestone 6.2 Phase 1: Persisted Clock High-Water State", () => {
  let directory: string | undefined;

  function databasePath(filename = "clock-test.sqlite"): string {
    directory ??= mkdtempSync(join(tmpdir(), "web3user-clock-"));
    return join(directory, filename);
  }

  afterEach(() => {
    if (directory) {
      rmSync(directory, { recursive: true, force: true });
      directory = undefined;
    }
  });

  it("initializes high-water mark with injected clock time and advances forward", () => {
    const clock = new TestClock(500);
    const dbFile = databasePath();
    const store = new SQLiteAuthorizationStore(dbFile, clock);

    try {
      expect(store.getHighWaterMark()).toBe(500);

      // Advance clock and high-water mark
      clock.advance(100);
      store.advanceHighWaterMark(clock.nowSeconds());
      expect(store.getHighWaterMark()).toBe(600);

      // Equal timestamp is accepted without error
      store.advanceHighWaterMark(600);
      expect(store.getHighWaterMark()).toBe(600);
    } finally {
      store.close();
    }
  });

  it("rejects clock rollback without lowering the persisted high-water mark", () => {
    const clock = new TestClock(1000);
    const dbFile = databasePath();
    const store = new SQLiteAuthorizationStore(dbFile, clock);

    try {
      expect(store.getHighWaterMark()).toBe(1000);

      // Advance to 1200
      store.advanceHighWaterMark(1200);
      expect(store.getHighWaterMark()).toBe(1200);

      // Attempt rollback to 1100
      expect(() => store.advanceHighWaterMark(1100)).toThrow(
        "Clock rollback detected: current time (1100s) precedes persisted high-water mark (1200s).",
      );

      // High-water mark remains strictly at 1200
      expect(store.getHighWaterMark()).toBe(1200);

      // Reopening database preserves the high-water mark
      store.close();
      const reopened = new SQLiteAuthorizationStore(dbFile, new TestClock(800));
      try {
        expect(reopened.getHighWaterMark()).toBe(1200);
        // Operation with clock behind high-water mark fails
        expect(() => reopened.advanceHighWaterMark(800)).toThrow("Clock rollback detected");
      } finally {
        reopened.close();
      }
    } finally {
      try { store.close(); } catch {}
    }
  });

  it("handles high-water advances across separate SQLite connections to the same file", () => {
    const dbFile = databasePath();
    const store1 = new SQLiteAuthorizationStore(dbFile, new TestClock(100));
    const store2 = new SQLiteAuthorizationStore(dbFile, new TestClock(100));

    try {
      expect(store1.getHighWaterMark()).toBe(100);
      expect(store2.getHighWaterMark()).toBe(100);

      // Connection 1 advances to 200
      store1.advanceHighWaterMark(200);
      expect(store1.getHighWaterMark()).toBe(200);
      expect(store2.getHighWaterMark()).toBe(200);

      // Connection 2 advances to 300
      store2.advanceHighWaterMark(300);
      expect(store1.getHighWaterMark()).toBe(300);
      expect(store2.getHighWaterMark()).toBe(300);

      // Connection 1 cannot execute with rolled-back time
      expect(() => store1.advanceHighWaterMark(250)).toThrow("Clock rollback detected");
      expect(store1.getHighWaterMark()).toBe(300);
      expect(store2.getHighWaterMark()).toBe(300);
    } finally {
      store1.close();
      store2.close();
    }
  });

  it("preserves advanced high-water mark even when a subsequent operation fails", () => {
    const dbFile = databasePath();
    const clock = new TestClock(1000);
    const store = new SQLiteAuthorizationStore(dbFile, clock);

    try {
      // Simulate advanceHighWaterMark before a business validation failure
      store.advanceHighWaterMark(1500);

      // Business validation failure (e.g. attempting to reserve an invalid blank ID)
      // The high-water mark was persisted immediately
      expect(store.getHighWaterMark()).toBe(1500);

      // Next call with a rolled-back time is rejected
      expect(() => store.advanceHighWaterMark(1400)).toThrow("Clock rollback detected");
    } finally {
      store.close();
    }
  });
});

describe("Milestone 6.2 Phase 1: Governance Tables and Schema Migration", () => {
  let directory: string | undefined;

  function databasePath(filename = "migration-test.sqlite"): string {
    directory ??= mkdtempSync(join(tmpdir(), "web3user-migration-"));
    return join(directory, filename);
  }

  afterEach(() => {
    if (directory) {
      rmSync(directory, { recursive: true, force: true });
      directory = undefined;
    }
  });

  it("creates governance tables on fresh database", () => {
    const dbFile = databasePath();
    const store = new SQLiteAuthorizationStore(dbFile, new TestClock(100));

    try {
      const rawDb = new DatabaseSync(dbFile);
      try {
        const tables = (
          rawDb.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>
        ).map((r) => r.name);

        expect(tables).toContain("consumed_authorization_ids");
        expect(tables).toContain("system_clock_state");
        expect(tables).toContain("policies");
        expect(tables).toContain("policy_revisions");
        expect(tables).toContain("issuer_keys");

        const columns = (
          rawDb.prepare("PRAGMA table_info(consumed_authorization_ids)").all() as Array<{ name: string }>
        ).map((c) => c.name);

        expect(columns).toContain("authorization_id");
        expect(columns).toContain("binding_digest");
        expect(columns).toContain("state");
        expect(columns).toContain("consumed_at");
        expect(columns).toContain("artifact_version");
        expect(columns).toContain("key_id");
        expect(columns).toContain("issued_at_seconds");
      } finally {
        rawDb.close();
      }
    } finally {
      store.close();
    }
  });

  it("migrates a disposable copy of historical Milestone 5A database preserving tombstones", () => {
    const dbFile = databasePath("auth-5a-copy.sqlite");
    copyFileSync(".demo-data/authorization-replay.sqlite", dbFile);

    // Verify pre-migration state in disposable copy
    const preDb = new DatabaseSync(dbFile);
    const preRows = preDb.prepare("SELECT * FROM consumed_authorization_ids").all() as Array<{
      authorization_id: string;
      consumed_at: string;
    }>;
    expect(preRows.length).toBeGreaterThan(0);
    const originalRow = preRows[0];
    preDb.close();

    // Open with SQLiteAuthorizationStore to trigger migration
    const store = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
    try {
      const postDb = new DatabaseSync(dbFile);
      try {
        const postRows = postDb.prepare("SELECT * FROM consumed_authorization_ids").all() as Array<Record<string, unknown>>;
        expect(postRows).toHaveLength(preRows.length);

        const migratedRow = postRows.find((r) => r.authorization_id === originalRow.authorization_id);
        expect(migratedRow).toBeDefined();
        expect(migratedRow?.state).toBe("consumed");
        expect(migratedRow?.consumed_at).toBe(originalRow.consumed_at);
        expect(migratedRow?.artifact_version).toBe(1);
        expect(migratedRow?.key_id).toBeNull();
        expect(migratedRow?.issued_at_seconds).toBeNull();
      } finally {
        postDb.close();
      }
    } finally {
      store.close();
    }
  });

  it("migrates a disposable copy of historical Milestone 5B database preserving bound tombstones", () => {
    const dbFile = databasePath("auth-5b-copy.sqlite");
    copyFileSync(".demo-data/bound-authorization-replay.sqlite", dbFile);

    const preDb = new DatabaseSync(dbFile);
    const preRows = preDb.prepare("SELECT * FROM consumed_authorization_ids").all() as Array<{
      authorization_id: string;
      binding_digest: string;
      consumed_at: string;
    }>;
    expect(preRows.length).toBeGreaterThan(0);
    const originalRow = preRows[0];
    preDb.close();

    const store = new SQLiteAuthorizationStore(dbFile, new TestClock(2000));
    try {
      const postDb = new DatabaseSync(dbFile);
      try {
        const postRows = postDb.prepare("SELECT * FROM consumed_authorization_ids").all() as Array<Record<string, unknown>>;
        expect(postRows).toHaveLength(preRows.length);

        const migratedRow = postRows.find((r) => r.authorization_id === originalRow.authorization_id);
        expect(migratedRow).toBeDefined();
        expect(migratedRow?.state).toBe("consumed");
        expect(migratedRow?.binding_digest).toBe(originalRow.binding_digest);
        expect(migratedRow?.consumed_at).toBe(originalRow.consumed_at);
        expect(migratedRow?.artifact_version).toBe(1);
      } finally {
        postDb.close();
      }
    } finally {
      store.close();
    }
  });

  it("converts unconsumed legacy V2 rows into legacy_void while preserving V1 and consumed rows", () => {
    const dbFile = databasePath("v2-void-test.sqlite");
    const initDb = new DatabaseSync(dbFile);

    // Simulate historical Milestone 6.1 database with various records
    initDb.exec(`
      CREATE TABLE consumed_authorization_ids (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT,
        state TEXT NOT NULL DEFAULT 'consumed' CHECK (state IN ('issued', 'consumed')),
        consumed_at TEXT,
        artifact_version INTEGER NOT NULL DEFAULT 1
      );
      INSERT INTO consumed_authorization_ids VALUES ('v2-unconsumed-1', 'sha256:v2a', 'issued', NULL, 2);
      INSERT INTO consumed_authorization_ids VALUES ('v1-unconsumed-1', 'sha256:v1a', 'issued', NULL, 1);
      INSERT INTO consumed_authorization_ids VALUES ('v2-consumed-1', 'sha256:v2b', 'consumed', '2026-10-22 10:00:00', 2);
    `);
    initDb.close();

    const store = new SQLiteAuthorizationStore(dbFile, new TestClock(3000));
    try {
      const postDb = new DatabaseSync(dbFile);
      try {
        const rows = postDb.prepare("SELECT * FROM consumed_authorization_ids ORDER BY authorization_id").all() as Array<Record<string, unknown>>;
        expect(rows).toHaveLength(3);

        const v2Unconsumed = rows.find((r) => r.authorization_id === "v2-unconsumed-1");
        expect(v2Unconsumed?.state).toBe("legacy_void");
        expect(v2Unconsumed?.artifact_version).toBe(2);
        expect(v2Unconsumed?.key_id).toBeNull();

        const v1Unconsumed = rows.find((r) => r.authorization_id === "v1-unconsumed-1");
        expect(v1Unconsumed?.state).toBe("issued");
        expect(v1Unconsumed?.artifact_version).toBe(1);

        const v2Consumed = rows.find((r) => r.authorization_id === "v2-consumed-1");
        expect(v2Consumed?.state).toBe("consumed");
        expect(v2Consumed?.consumed_at).toBe("2026-10-22 10:00:00");
      } finally {
        postDb.close();
      }
    } finally {
      store.close();
    }
  });

  it("recovers safely from an interrupted prior migration without dropping the surviving data", () => {
    const dbFile = databasePath("interrupted-test.sqlite");
    const initDb = new DatabaseSync(dbFile);

    // Simulate an interrupted migration where consumed_authorization_ids was dropped,
    // and only consumed_authorization_ids_v3 survived before process died.
    initDb.exec(`
      CREATE TABLE consumed_authorization_ids_v3 (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT,
        state TEXT NOT NULL DEFAULT 'consumed' CHECK (state IN ('issued', 'consumed', 'legacy_void', 'cancelled')),
        consumed_at TEXT,
        artifact_version INTEGER NOT NULL DEFAULT 1,
        key_id TEXT,
        issued_at_seconds INTEGER
      );
      INSERT INTO consumed_authorization_ids_v3 VALUES ('survivor-001', 'sha256:survive', 'consumed', '2026-10-22 12:00:00', 1, NULL, NULL);
    `);
    initDb.close();

    // Reopen with store — it must detect consumed_authorization_ids_v3 as the only surviving data and recover
    const store = new SQLiteAuthorizationStore(dbFile, new TestClock(4000));
    try {
      const postDb = new DatabaseSync(dbFile);
      try {
        const rows = postDb.prepare("SELECT * FROM consumed_authorization_ids").all() as Array<Record<string, unknown>>;
        expect(rows).toHaveLength(1);
        expect(rows[0].authorization_id).toBe("survivor-001");
        expect(rows[0].state).toBe("consumed");
      } finally {
        postDb.close();
      }
    } finally {
      store.close();
    }
  });

  it("preserves V3 schema on subsequent restarts without repeating migration (idempotent)", () => {
    const dbFile = databasePath("idempotent-test.sqlite");
    const store1 = new SQLiteAuthorizationStore(dbFile, new TestClock(5000));
    store1.reserve("auth-restart-001");
    store1.issueBound("auth-restart-002", "sha256:restart", 3, "key-001", 5000);
    store1.close();

    const store2 = new SQLiteAuthorizationStore(dbFile, new TestClock(5000));
    try {
      const postDb = new DatabaseSync(dbFile);
      try {
        const rows = postDb.prepare("SELECT * FROM consumed_authorization_ids ORDER BY authorization_id").all() as Array<Record<string, unknown>>;
        expect(rows).toHaveLength(2);
        expect(rows[0].authorization_id).toBe("auth-restart-001");
        expect(rows[0].state).toBe("consumed");

        expect(rows[1].authorization_id).toBe("auth-restart-002");
        expect(rows[1].state).toBe("issued");
        expect(rows[1].artifact_version).toBe(3);
        expect(rows[1].key_id).toBe("key-001");
        expect(rows[1].issued_at_seconds).toBe(5000);
      } finally {
        postDb.close();
      }
    } finally {
      store2.close();
    }
  });
});

describe("Phase 1 Remediation: Ambiguous Migration Recovery & Atomic Discovery", () => {
  let directory: string | undefined;

  function databasePath(filename: string): string {
    directory ??= mkdtempSync(join(tmpdir(), "web3user-remediation-"));
    return join(directory, filename);
  }

  afterEach(() => {
    if (directory) {
      rmSync(directory, { recursive: true, force: true });
      directory = undefined;
    }
  });

  // Test 1: Original and temporary tables with identical contents recover safely.
  it("recovers safely and drops duplicate temporary table when both tables are provably identical", () => {
    const dbFile = databasePath("identical-tables.sqlite");
    const initDb = new DatabaseSync(dbFile);
    initDb.exec(`
      CREATE TABLE consumed_authorization_ids (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT,
        state TEXT NOT NULL DEFAULT 'consumed' CHECK (state IN ('issued', 'consumed', 'legacy_void', 'cancelled')),
        consumed_at TEXT,
        artifact_version INTEGER NOT NULL DEFAULT 1,
        key_id TEXT,
        issued_at_seconds INTEGER
      );
      INSERT INTO consumed_authorization_ids VALUES ('auth-1', 'sha256:1', 'consumed', '2026-10-22', 1, NULL, NULL);

      CREATE TABLE consumed_authorization_ids_v3 (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT,
        state TEXT NOT NULL DEFAULT 'consumed' CHECK (state IN ('issued', 'consumed', 'legacy_void', 'cancelled')),
        consumed_at TEXT,
        artifact_version INTEGER NOT NULL DEFAULT 1,
        key_id TEXT,
        issued_at_seconds INTEGER
      );
      INSERT INTO consumed_authorization_ids_v3 VALUES ('auth-1', 'sha256:1', 'consumed', '2026-10-22', 1, NULL, NULL);
    `);
    initDb.close();

    const store = new SQLiteAuthorizationStore(dbFile, new TestClock(100));
    try {
      const verifyDb = new DatabaseSync(dbFile);
      try {
        const tables = (verifyDb.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>).map((r) => r.name);
        expect(tables).toContain("consumed_authorization_ids");
        expect(tables).not.toContain("consumed_authorization_ids_v3");

        const rows = verifyDb.prepare("SELECT * FROM consumed_authorization_ids").all() as Array<Record<string, unknown>>;
        expect(rows).toHaveLength(1);
        expect(rows[0].authorization_id).toBe("auth-1");
        expect(rows[0].state).toBe("consumed");
      } finally {
        verifyDb.close();
      }
    } finally {
      store.close();
    }
  });

  // Test 2: Both tables with conflicting row contents cause a clear error and preserve both tables exactly.
  it("throws clear error and preserves both tables exactly when row contents conflict", () => {
    const dbFile = databasePath("conflicting-tables.sqlite");
    const initDb = new DatabaseSync(dbFile);
    initDb.exec(`
      CREATE TABLE consumed_authorization_ids (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT,
        state TEXT NOT NULL DEFAULT 'consumed',
        consumed_at TEXT,
        artifact_version INTEGER NOT NULL DEFAULT 1
      );
      INSERT INTO consumed_authorization_ids VALUES ('auth-original', 'sha256:orig', 'consumed', '2026-10-22', 1);

      CREATE TABLE consumed_authorization_ids_v3 (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT,
        state TEXT NOT NULL DEFAULT 'consumed',
        consumed_at TEXT,
        artifact_version INTEGER NOT NULL DEFAULT 1
      );
      INSERT INTO consumed_authorization_ids_v3 VALUES ('auth-different', 'sha256:diff', 'consumed', '2026-10-22', 1);
    `);
    initDb.close();

    expect(() => new SQLiteAuthorizationStore(dbFile, new TestClock(100))).toThrow(
      "Ambiguous migration state: both consumed_authorization_ids and consumed_authorization_ids_v3 exist with conflicting row contents. Halting to preserve data for investigation."
    );

    // Verify both tables and their contents are preserved exactly
    const verifyDb = new DatabaseSync(dbFile);
    try {
      const tables = (verifyDb.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>).map((r) => r.name);
      expect(tables).toContain("consumed_authorization_ids");
      expect(tables).toContain("consumed_authorization_ids_v3");

      const origRows = verifyDb.prepare("SELECT * FROM consumed_authorization_ids").all() as Array<Record<string, unknown>>;
      expect(origRows).toHaveLength(1);
      expect(origRows[0].authorization_id).toBe("auth-original");

      const v3Rows = verifyDb.prepare("SELECT * FROM consumed_authorization_ids_v3").all() as Array<Record<string, unknown>>;
      expect(v3Rows).toHaveLength(1);
      expect(v3Rows[0].authorization_id).toBe("auth-different");
    } finally {
      verifyDb.close();
    }
  });

  // Test 3: Both tables with matching IDs but differing values are treated as conflicting.
  it("treats matching IDs with differing values as conflicting and preserves both tables", () => {
    const dbFile = databasePath("differing-values.sqlite");
    const initDb = new DatabaseSync(dbFile);
    initDb.exec(`
      CREATE TABLE consumed_authorization_ids (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT,
        state TEXT NOT NULL DEFAULT 'consumed',
        consumed_at TEXT,
        artifact_version INTEGER NOT NULL DEFAULT 1
      );
      INSERT INTO consumed_authorization_ids VALUES ('auth-common-id', 'sha256:digest-A', 'consumed', '2026-10-22', 1);

      CREATE TABLE consumed_authorization_ids_v3 (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT,
        state TEXT NOT NULL DEFAULT 'consumed',
        consumed_at TEXT,
        artifact_version INTEGER NOT NULL DEFAULT 1
      );
      INSERT INTO consumed_authorization_ids_v3 VALUES ('auth-common-id', 'sha256:digest-DIFFERENT', 'consumed', '2026-10-22', 1);
    `);
    initDb.close();

    expect(() => new SQLiteAuthorizationStore(dbFile, new TestClock(100))).toThrow(
      "Ambiguous migration state: both consumed_authorization_ids and consumed_authorization_ids_v3 exist with conflicting row contents. Halting to preserve data for investigation."
    );

    const verifyDb = new DatabaseSync(dbFile);
    try {
      const origRows = verifyDb.prepare("SELECT * FROM consumed_authorization_ids").all() as Array<Record<string, unknown>>;
      expect(origRows[0].binding_digest).toBe("sha256:digest-A");

      const v3Rows = verifyDb.prepare("SELECT * FROM consumed_authorization_ids_v3").all() as Array<Record<string, unknown>>;
      expect(v3Rows[0].binding_digest).toBe("sha256:digest-DIFFERENT");
    } finally {
      verifyDb.close();
    }
  });

  // Test 4: A temporary table containing unique replay-protection records is never silently discarded.
  it("never silently discards a temporary table containing unique replay-protection records", () => {
    const dbFile = databasePath("unique-records-in-temp.sqlite");
    const initDb = new DatabaseSync(dbFile);
    initDb.exec(`
      CREATE TABLE consumed_authorization_ids (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT,
        state TEXT NOT NULL DEFAULT 'consumed',
        consumed_at TEXT,
        artifact_version INTEGER NOT NULL DEFAULT 1
      );
      INSERT INTO consumed_authorization_ids VALUES ('auth-1', 'sha256:1', 'consumed', '2026-10-22', 1);

      CREATE TABLE consumed_authorization_ids_v3 (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT,
        state TEXT NOT NULL DEFAULT 'consumed',
        consumed_at TEXT,
        artifact_version INTEGER NOT NULL DEFAULT 1
      );
      INSERT INTO consumed_authorization_ids_v3 VALUES ('auth-1', 'sha256:1', 'consumed', '2026-10-22', 1);
      INSERT INTO consumed_authorization_ids_v3 VALUES ('auth-unique-2', 'sha256:unique', 'consumed', '2026-10-22', 1);
    `);
    initDb.close();

    expect(() => new SQLiteAuthorizationStore(dbFile, new TestClock(100))).toThrow(
      "Ambiguous migration state: both consumed_authorization_ids (1 rows) and consumed_authorization_ids_v3 (2 rows) exist with different row counts. Halting to preserve data for investigation."
    );

    const verifyDb = new DatabaseSync(dbFile);
    try {
      const v3Rows = verifyDb.prepare("SELECT * FROM consumed_authorization_ids_v3").all() as Array<Record<string, unknown>>;
      expect(v3Rows).toHaveLength(2);
      expect(v3Rows.some((r) => r.authorization_id === "auth-unique-2")).toBe(true);
    } finally {
      verifyDb.close();
    }
  });

  // Test 5: Two connections initializing the same unmigrated database do not overwrite migrated key_id or other fields.
  it("two connections initializing the same unmigrated database do not overwrite migrated key_id or fields", () => {
    const dbFile = databasePath("concurrent-init-test.sqlite");
    const initDb = new DatabaseSync(dbFile);
    initDb.exec(`
      CREATE TABLE consumed_authorization_ids (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT,
        state TEXT NOT NULL DEFAULT 'consumed',
        consumed_at TEXT,
        artifact_version INTEGER NOT NULL DEFAULT 1
      );
      INSERT INTO consumed_authorization_ids VALUES ('auth-pre-migrated', 'sha256:pre', 'consumed', '2026-10-22', 1);
    `);
    initDb.close();

    // Connection 1 opens and migrates the table to V3
    const store1 = new SQLiteAuthorizationStore(dbFile, new TestClock(100));
    // Connection 1 issues a V3 authorization with key_id and issued_at_seconds
    expect(store1.issueBound("v3-auth-key-test", "sha256:v3", 3, "key-alpha", 12345)).toBe(true);

    // Connection 2 opens against the same database file (which now has V3 schema and new record)
    const store2 = new SQLiteAuthorizationStore(dbFile, new TestClock(100));

    try {
      // Verify that Connection 2's initialization did NOT overwrite or nullify key-alpha or 12345
      const verifyDb = new DatabaseSync(dbFile);
      try {
        const row = verifyDb.prepare(
          "SELECT * FROM consumed_authorization_ids WHERE authorization_id = 'v3-auth-key-test'"
        ).get() as Record<string, unknown>;

        expect(row).toBeDefined();
        expect(row.artifact_version).toBe(3);
        expect(row.key_id).toBe("key-alpha");
        expect(row.issued_at_seconds).toBe(12345);
        expect(row.state).toBe("issued");
      } finally {
        verifyDb.close();
      }
    } finally {
      store1.close();
      store2.close();
    }
  });

  // Test 6: An interrupted migration can be retried safely without losing replay tombstones.
  it("safely retries an interrupted migration without losing replay tombstones", () => {
    const dbFile = databasePath("retry-interrupted.sqlite");
    const initDb = new DatabaseSync(dbFile);

    // Simulate an interrupted migration where consumed_authorization_ids was dropped,
    // and only consumed_authorization_ids_v3 survived with replay tombstones.
    initDb.exec(`
      CREATE TABLE consumed_authorization_ids_v3 (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT,
        state TEXT NOT NULL DEFAULT 'consumed' CHECK (state IN ('issued', 'consumed', 'legacy_void', 'cancelled')),
        consumed_at TEXT,
        artifact_version INTEGER NOT NULL DEFAULT 1,
        key_id TEXT,
        issued_at_seconds INTEGER
      );
      INSERT INTO consumed_authorization_ids_v3 VALUES ('tombstone-survivor-1', 'sha256:t1', 'consumed', '2026-10-22 10:00:00', 1, NULL, NULL);
      INSERT INTO consumed_authorization_ids_v3 VALUES ('tombstone-survivor-2', 'sha256:t2', 'consumed', '2026-10-22 11:00:00', 1, NULL, NULL);
    `);
    initDb.close();

    // Store opens, recovers the table, and commits
    const store = new SQLiteAuthorizationStore(dbFile, new TestClock(100));
    try {
      const verifyDb = new DatabaseSync(dbFile);
      try {
        const rows = verifyDb.prepare("SELECT * FROM consumed_authorization_ids ORDER BY authorization_id").all() as Array<Record<string, unknown>>;
        expect(rows).toHaveLength(2);
        expect(rows[0].authorization_id).toBe("tombstone-survivor-1");
        expect(rows[0].state).toBe("consumed");
        expect(rows[0].consumed_at).toBe("2026-10-22 10:00:00");
        expect(rows[1].authorization_id).toBe("tombstone-survivor-2");
        expect(rows[1].state).toBe("consumed");
      } finally {
        verifyDb.close();
      }
    } finally {
      store.close();
    }
  });

  // Test 7: Re-running migration is idempotent.
  it("re-running migration across repeated opens is completely idempotent", () => {
    const dbFile = databasePath("re-run-idempotent.sqlite");
    const store1 = new SQLiteAuthorizationStore(dbFile, new TestClock(100));
    store1.reserve("idempotent-tombstone-001");
    store1.close();

    // Reopen 2
    const store2 = new SQLiteAuthorizationStore(dbFile, new TestClock(100));
    store2.reserve("idempotent-tombstone-002");
    store2.close();

    // Reopen 3
    const store3 = new SQLiteAuthorizationStore(dbFile, new TestClock(100));
    try {
      const verifyDb = new DatabaseSync(dbFile);
      try {
        const rows = verifyDb.prepare("SELECT * FROM consumed_authorization_ids ORDER BY authorization_id").all() as Array<Record<string, unknown>>;
        expect(rows).toHaveLength(2);
        expect(rows[0].authorization_id).toBe("idempotent-tombstone-001");
        expect(rows[1].authorization_id).toBe("idempotent-tombstone-002");

        const columns = (verifyDb.prepare("PRAGMA table_info(consumed_authorization_ids)").all() as Array<{ name: string }>).map((c) => c.name);
        expect(columns).toEqual(["authorization_id", "binding_digest", "state", "consumed_at", "artifact_version", "key_id", "issued_at_seconds"]);
      } finally {
        verifyDb.close();
      }
    } finally {
      store3.close();
    }
  });
});
