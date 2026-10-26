import { fork } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { SQLiteAuthorizationStore } from "../src/authorization-store.js";
import { TestClock } from "../src/clock.js";
import { Web3UserEngine } from "../src/engine.js";
import type { DemoPolicy } from "../src/policy.js";
import type { TransactionRequest } from "../src/transaction-envelope.js";

const MAX_UINT256 = (1n << 256n) - 1n;

describe("Milestone 9: Legacy SQLite Schema Migration (policy_budget_accumulators)", () => {
  const openStores: SQLiteAuthorizationStore[] = [];
  const openEngines: Web3UserEngine[] = [];
  const createdDirs: string[] = [];

  function createTestDbPath(prefix = "web3user-m9-mig-"): string {
    const dir = mkdtempSync(join(tmpdir(), prefix));
    createdDirs.push(dir);
    return join(dir, "migration-test.sqlite");
  }

  afterEach(() => {
    while (openStores.length > 0) {
      try {
        openStores.pop()?.close();
      } catch {}
    }
    while (openEngines.length > 0) {
      try {
        openEngines.pop()?.close();
      } catch {}
    }
    while (createdDirs.length > 0) {
      const dir = createdDirs.pop();
      if (dir) {
        try {
          rmSync(dir, { recursive: true, force: true });
        } catch {}
      }
    }
  });

  function createKeypair() {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    return { publicKey, privateKey, pem };
  }

  function encodeCalldata(recipient: string, amount: bigint): string {
    const selector = "0xa9059cbb";
    const recipientWord = recipient.slice(2).toLowerCase().padStart(64, "0");
    const amountWord = amount.toString(16).padStart(64, "0");
    return `${selector}${recipientWord}${amountWord}`;
  }

  const TARGET = "0x1111111111111111111111111111111111111111";
  const RECIPIENT = "0x2222222222222222222222222222222222222222";

  /**
   * Helper to seed an authentic Milestone 8 SQLite database containing the looser
   * M8 policy_budget_accumulators schema:
   * CHECK (length(spent_amount) <= 78 AND spent_amount GLOB '[0-9]*')
   */
  function seedM8Database(dbFile: string, options?: { customAccumulatorSql?: string }) {
    const rawDb = new DatabaseSync(dbFile);
    rawDb.exec(`
      CREATE TABLE system_clock_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        high_water_seconds INTEGER NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      INSERT INTO system_clock_state (id, high_water_seconds) VALUES (1, 1000);

      CREATE TABLE consumed_authorization_ids (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT,
        state TEXT NOT NULL DEFAULT 'consumed'
          CHECK (state IN ('issued', 'consumed', 'legacy_void', 'cancelled')),
        consumed_at TEXT,
        artifact_version INTEGER NOT NULL DEFAULT 1,
        key_id TEXT,
        issued_at_seconds INTEGER
      );

      CREATE TABLE policies (
        policy_id TEXT PRIMARY KEY,
        current_revision INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'retired')),
        policy_json TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE policy_revisions (
        policy_id TEXT NOT NULL,
        revision INTEGER NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'retired')),
        policy_json TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (policy_id, revision)
      );

      CREATE TABLE issuer_keys (
        key_id TEXT PRIMARY KEY,
        public_key_pem TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired', 'revoked')),
        valid_from_seconds INTEGER,
        expires_at_seconds INTEGER,
        retired_at_seconds INTEGER,
        revoked_at_seconds INTEGER,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      ${
        options?.customAccumulatorSql ??
        `
        CREATE TABLE policy_budget_accumulators (
          policy_id TEXT NOT NULL,
          window_type TEXT NOT NULL CHECK (window_type IN ('HOURLY', 'DAILY')),
          window_start INTEGER NOT NULL,
          spent_amount TEXT NOT NULL CHECK (length(spent_amount) <= 78 AND spent_amount GLOB '[0-9]*'),
          last_updated_at TEXT NOT NULL DEFAULT '2026-10-25 10:00:00',
          PRIMARY KEY (policy_id, window_type, window_start),
          FOREIGN KEY (policy_id) REFERENCES policies(policy_id) ON DELETE CASCADE
        );
        CREATE INDEX idx_budget_accumulators_lookup
          ON policy_budget_accumulators (policy_id, window_type, window_start);
      `
      }
    `);
    rawDb.close();
  }

  // =========================================================================
  // 1. Clean M8 Upgrades & Exact Row Preservation
  // =========================================================================
  it("safely upgrades existing clean M8 tables to strict numeric CHECK constraint with exact row preservation", () => {
    const dbFile = createTestDbPath("clean-m8-");
    seedM8Database(dbFile);

    // Insert 5 valid M8 accumulator rows across different policies and window types
    const rawDb = new DatabaseSync(dbFile);
    rawDb.exec(`
      INSERT INTO policies (policy_id, current_revision, status, policy_json) VALUES
        ('pol-1', 1, 'active', '{"version":1,"policyId":"pol-1"}'),
        ('pol-2', 1, 'active', '{"version":1,"policyId":"pol-2"}');

      INSERT INTO policy_budget_accumulators (policy_id, window_type, window_start, spent_amount, last_updated_at) VALUES
        ('pol-1', 'HOURLY', 0, '100', '2026-10-25 10:01:00'),
        ('pol-1', 'HOURLY', 3600, '250', '2026-10-25 11:01:00'),
        ('pol-1', 'DAILY', 0, '350', '2026-10-25 11:02:00'),
        ('pol-2', 'HOURLY', 0, '0', '2026-10-25 10:05:00'),
        ('pol-2', 'DAILY', 0, '${MAX_UINT256.toString(10)}', '2026-10-25 10:06:00');
    `);
    rawDb.close();

    // Verify pre-migration DDL contains the looser M8 constraint
    const preDb = new DatabaseSync(dbFile);
    const preMaster = preDb.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'policy_budget_accumulators'").get() as { sql: string };
    expect(preMaster.sql).toContain("GLOB '[0-9]*'");
    expect(preMaster.sql).not.toContain("*[^0-9]*");
    preDb.close();

    // Open store -> triggers migrateBudgetAccumulators()
    const store = new SQLiteAuthorizationStore(dbFile, new TestClock(2000));
    openStores.push(store);

    // Verify post-migration DDL in sqlite_master contains the strict constraint
    const postDb = new DatabaseSync(dbFile);
    try {
      const postMaster = postDb.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'policy_budget_accumulators'").get() as { sql: string };
      expect(postMaster.sql).toContain("NOT (spent_amount GLOB '*[^0-9]*')");
      expect(postMaster.sql).toContain("length(spent_amount) > 0");

      // Verify all 5 rows were preserved verbatim
      const rows = postDb.prepare("SELECT * FROM policy_budget_accumulators ORDER BY policy_id, window_type, window_start").all() as Array<{
        policy_id: string;
        window_type: string;
        window_start: number;
        spent_amount: string;
        last_updated_at: string;
      }>;
      expect(rows).toHaveLength(5);

      expect(rows[0]).toEqual({
        policy_id: "pol-1",
        window_type: "DAILY",
        window_start: 0,
        spent_amount: "350",
        last_updated_at: "2026-10-25 11:02:00",
      });
      expect(rows[1]).toEqual({
        policy_id: "pol-1",
        window_type: "HOURLY",
        window_start: 0,
        spent_amount: "100",
        last_updated_at: "2026-10-25 10:01:00",
      });
      expect(rows[2]).toEqual({
        policy_id: "pol-1",
        window_type: "HOURLY",
        window_start: 3600,
        spent_amount: "250",
        last_updated_at: "2026-10-25 11:01:00",
      });
      expect(rows[3]).toEqual({
        policy_id: "pol-2",
        window_type: "DAILY",
        window_start: 0,
        spent_amount: MAX_UINT256.toString(10),
        last_updated_at: "2026-10-25 10:06:00",
      });
      expect(rows[4]).toEqual({
        policy_id: "pol-2",
        window_type: "HOURLY",
        window_start: 0,
        spent_amount: "0",
        last_updated_at: "2026-10-25 10:05:00",
      });

      // Verify index is present and active
      const indexRow = postDb.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_budget_accumulators_lookup'").get();
      expect(indexRow).toBeDefined();

      // Verify the new CHECK constraint actively rejects invalid writes
      expect(() => {
        postDb.prepare(`
          INSERT INTO policy_budget_accumulators (policy_id, window_type, window_start, spent_amount)
          VALUES ('pol-1', 'HOURLY', 7200, '100abc')
        `).run();
      }).toThrow(/constraint failed/i);
    } finally {
      postDb.close();
    }
  });

  // =========================================================================
  // 2. Migration Idempotence
  // =========================================================================
  it("is strictly idempotent and does not repeat migration on subsequent startups", () => {
    const dbFile = createTestDbPath("idempotent-mig-");
    seedM8Database(dbFile);

    // Initial upgrade
    const store1 = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
    store1.close();

    const rawDb = new DatabaseSync(dbFile);
    const ddlAfterFirst = (rawDb.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'policy_budget_accumulators'").get() as { sql: string }).sql;
    rawDb.close();

    // Second startup
    const store2 = new SQLiteAuthorizationStore(dbFile, new TestClock(1100));
    store2.close();

    const rawDb2 = new DatabaseSync(dbFile);
    const ddlAfterSecond = (rawDb2.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'policy_budget_accumulators'").get() as { sql: string }).sql;
    rawDb2.close();

    expect(ddlAfterFirst).toBe(ddlAfterSecond);
    expect(ddlAfterSecond).toContain("NOT (spent_amount GLOB '*[^0-9]*')");
  });

  // =========================================================================
  // 3. Malformed Legacy Values Fail Closed
  // =========================================================================
  it("aborts initialization with clear error when malformed rows exist and preserves legacy table unchanged", () => {
    const testCases = [
      { name: "letters appended", value: "100abc" },
      { name: "empty string", value: "" },
      { name: "negative sign", value: "-50" },
      { name: "decimal dot", value: "12.34" },
      { name: "whitespace", value: " 50" },
      { name: "exceeds 78 chars", value: "9".repeat(79) },
    ];

    for (const tc of testCases) {
      const dbFile = createTestDbPath(`malformed-${tc.name.replace(/\s+/g, "-")}-`);
      seedM8Database(dbFile);

      // Insert valid row + corrupted row using M8 table
      const rawDb = new DatabaseSync(dbFile);
      rawDb.exec(`
        INSERT INTO policies (policy_id, current_revision, status, policy_json) VALUES
          ('pol-malformed', 1, 'active', '{"version":1,"policyId":"pol-malformed"}');

        INSERT INTO policy_budget_accumulators (policy_id, window_type, window_start, spent_amount) VALUES
          ('pol-malformed', 'HOURLY', 0, '100');
      `);

      // Bypass M8 check if needed for length/empty string
      rawDb.exec("PRAGMA ignore_check_constraints = ON;");
      rawDb.prepare(`
        INSERT INTO policy_budget_accumulators (policy_id, window_type, window_start, spent_amount)
        VALUES ('pol-malformed', 'HOURLY', 3600, ?)
      `).run(tc.value);
      rawDb.exec("PRAGMA ignore_check_constraints = OFF;");
      rawDb.close();

      // Opening store MUST throw explicit migration error
      expect(() => {
        new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      }).toThrow(/Cannot migrate policy_budget_accumulators: table contains 1 malformed accumulator row\(s\)/);

      // Verify original table and both rows are completely preserved and untouched
      const postDb = new DatabaseSync(dbFile);
      try {
        const masterRow = postDb.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'policy_budget_accumulators'").get() as { sql: string };
        expect(masterRow.sql).not.toContain("*[^0-9]*"); // table was NOT upgraded or replaced

        const rows = postDb.prepare("SELECT * FROM policy_budget_accumulators ORDER BY window_start").all() as Array<{
          window_start: number;
          spent_amount: string;
        }>;
        expect(rows).toHaveLength(2);
        expect(rows[0].spent_amount).toBe("100");
        expect(rows[1].spent_amount).toBe(tc.value);
      } finally {
        postDb.close();
      }
    }
  });

  // =========================================================================
  // 4. Atomic Rollback on Injected Migration Failure
  // =========================================================================
  it("rolls back completely on unexpected failure during table rebuild, leaving M8 table intact", () => {
    const dbFile = createTestDbPath("rollback-injected-");
    seedM8Database(dbFile);

    const rawDb = new DatabaseSync(dbFile);
    rawDb.exec(`
      INSERT INTO policies (policy_id, current_revision, status, policy_json) VALUES
        ('pol-rollback', 1, 'active', '{"version":1}');
      INSERT INTO policy_budget_accumulators (policy_id, window_type, window_start, spent_amount) VALUES
        ('pol-rollback', 'HOURLY', 0, '150');
    `);
    rawDb.close();

    // Intercept DatabaseSync.prototype.exec to inject failure during DROP TABLE
    const originalExec = DatabaseSync.prototype.exec;
    DatabaseSync.prototype.exec = function (sql: string) {
      if (typeof sql === "string" && sql.includes("DROP TABLE policy_budget_accumulators;")) {
        throw new Error("Simulated storage failure during migration drop (SQLITE_IOERR)");
      }
      return originalExec.call(this, sql);
    };

    try {
      expect(() => {
        new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      }).toThrow("Simulated storage failure during migration drop (SQLITE_IOERR)");
    } finally {
      DatabaseSync.prototype.exec = originalExec;
    }

    // Verify database state: original M8 table and row are intact; no _v2 staging table remains
    const verifyDb = new DatabaseSync(dbFile);
    try {
      const tables = (verifyDb.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>).map((t) => t.name);
      expect(tables).toContain("policy_budget_accumulators");
      expect(tables).not.toContain("policy_budget_accumulators_v2");

      const rows = verifyDb.prepare("SELECT spent_amount FROM policy_budget_accumulators").all() as Array<{ spent_amount: string }>;
      expect(rows).toHaveLength(1);
      expect(rows[0].spent_amount).toBe("150");
    } finally {
      verifyDb.close();
    }
  });

  // =========================================================================
  // 5. Foreign Key & Cascade Preservation
  // =========================================================================
  it("preserves foreign key cascading semantics after migration", () => {
    const dbFile = createTestDbPath("fk-cascade-");
    seedM8Database(dbFile);

    const rawDb = new DatabaseSync(dbFile);
    rawDb.exec(`
      INSERT INTO policies (policy_id, current_revision, status, policy_json) VALUES
        ('pol-cascade-1', 1, 'active', '{"version":1}'),
        ('pol-cascade-2', 1, 'active', '{"version":1}');

      INSERT INTO policy_budget_accumulators (policy_id, window_type, window_start, spent_amount) VALUES
        ('pol-cascade-1', 'HOURLY', 0, '100'),
        ('pol-cascade-1', 'DAILY', 0, '100'),
        ('pol-cascade-2', 'HOURLY', 0, '200');
    `);
    rawDb.close();

    // Run migration
    const store = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
    openStores.push(store);

    // Open connection with foreign keys enabled
    const fkDb = new DatabaseSync(dbFile);
    try {
      fkDb.exec("PRAGMA foreign_keys = ON;");

      // Verify foreign key constraint definition in DDL
      const ddl = (fkDb.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'policy_budget_accumulators'").get() as { sql: string }).sql;
      expect(ddl).toContain("FOREIGN KEY (policy_id) REFERENCES policies(policy_id) ON DELETE CASCADE");

      // Delete pol-cascade-1
      fkDb.prepare("DELETE FROM policies WHERE policy_id = 'pol-cascade-1'").run();

      // Accumulator rows for pol-cascade-1 must have cascaded and deleted automatically
      const rows = fkDb.prepare("SELECT * FROM policy_budget_accumulators").all() as Array<{ policy_id: string }>;
      expect(rows).toHaveLength(1);
      expect(rows[0].policy_id).toBe("pol-cascade-2");
    } finally {
      fkDb.close();
    }
  });

  // =========================================================================
  // 6. Crash Recovery & Staging Table Ambiguity
  // =========================================================================
  describe("Crash Recovery & Staging Table Protection", () => {
    it("never promotes an empty orphan staging table, fails closed, and preserves database state", () => {
      const dbFile = createTestDbPath("orphaned-empty-");
      seedM8Database(dbFile);

      // Simulate state where policy_budget_accumulators was dropped and empty policy_budget_accumulators_v2 exists
      const rawDb = new DatabaseSync(dbFile);
      rawDb.exec(`
        INSERT INTO policies (policy_id, current_revision, status, policy_json) VALUES
          ('pol-empty-orphan', 1, 'active', '{"version":1}');

        CREATE TABLE policy_budget_accumulators_v2 (
          policy_id TEXT NOT NULL,
          window_type TEXT NOT NULL CHECK (window_type IN ('HOURLY', 'DAILY')),
          window_start INTEGER NOT NULL,
          spent_amount TEXT NOT NULL CHECK (length(spent_amount) > 0 AND length(spent_amount) <= 78 AND NOT (spent_amount GLOB '*[^0-9]*')),
          last_updated_at TEXT NOT NULL DEFAULT '2026-10-25 12:00:00',
          PRIMARY KEY (policy_id, window_type, window_start),
          FOREIGN KEY (policy_id) REFERENCES policies(policy_id) ON DELETE CASCADE
        );
        DROP TABLE policy_budget_accumulators;
      `);
      rawDb.close();

      // Opening store MUST fail closed with explicit migration-state error
      expect(() => {
        new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      }).toThrow(/Incomplete or ambiguous migration state: canonical table 'policy_budget_accumulators' is missing but staging table 'policy_budget_accumulators_v2' exists/);

      // Verify that database was preserved unchanged (neither renamed nor dropped)
      const verifyDb = new DatabaseSync(dbFile);
      try {
        const tables = (verifyDb.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>).map((t) => t.name);
        expect(tables).not.toContain("policy_budget_accumulators");
        expect(tables).toContain("policy_budget_accumulators_v2");
        const count = (verifyDb.prepare("SELECT COUNT(*) AS c FROM policy_budget_accumulators_v2").get() as { c: number }).c;
        expect(count).toBe(0);
      } finally {
        verifyDb.close();
      }
    });

    it("never promotes a partially populated orphan staging table, fails closed, and preserves all rows", () => {
      const dbFile = createTestDbPath("orphaned-partial-");
      seedM8Database(dbFile);

      const rawDb = new DatabaseSync(dbFile);
      rawDb.exec(`
        INSERT INTO policies (policy_id, current_revision, status, policy_json) VALUES
          ('pol-partial-orphan', 1, 'active', '{"version":1}');

        CREATE TABLE policy_budget_accumulators_v2 (
          policy_id TEXT NOT NULL,
          window_type TEXT NOT NULL CHECK (window_type IN ('HOURLY', 'DAILY')),
          window_start INTEGER NOT NULL,
          spent_amount TEXT NOT NULL CHECK (length(spent_amount) > 0 AND length(spent_amount) <= 78 AND NOT (spent_amount GLOB '*[^0-9]*')),
          last_updated_at TEXT NOT NULL DEFAULT '2026-10-25 12:00:00',
          PRIMARY KEY (policy_id, window_type, window_start),
          FOREIGN KEY (policy_id) REFERENCES policies(policy_id) ON DELETE CASCADE
        );
        INSERT INTO policy_budget_accumulators_v2 VALUES ('pol-partial-orphan', 'HOURLY', 0, '350', '2026-10-25 12:00:00');
        DROP TABLE policy_budget_accumulators;
      `);
      rawDb.close();

      // Opening store MUST fail closed with explicit migration-state error
      expect(() => {
        new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      }).toThrow(/Incomplete or ambiguous migration state: canonical table 'policy_budget_accumulators' is missing but staging table 'policy_budget_accumulators_v2' exists/);

      // Verify that database was preserved unchanged (neither renamed nor dropped, rows intact)
      const verifyDb = new DatabaseSync(dbFile);
      try {
        const tables = (verifyDb.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>).map((t) => t.name);
        expect(tables).not.toContain("policy_budget_accumulators");
        expect(tables).toContain("policy_budget_accumulators_v2");
        const rows = verifyDb.prepare("SELECT * FROM policy_budget_accumulators_v2").all() as Array<{ policy_id: string; spent_amount: string }>;
        expect(rows).toHaveLength(1);
        expect(rows[0].policy_id).toBe("pol-partial-orphan");
        expect(rows[0].spent_amount).toBe("350");
      } finally {
        verifyDb.close();
      }
    });

    it("rejects a malformed table containing the *[^0-9]* substring and halts without destructive repair", () => {
      const dbFile = createTestDbPath("malformed-substring-");
      seedM8Database(dbFile, {
        customAccumulatorSql: `
          CREATE TABLE policy_budget_accumulators (
            id TEXT PRIMARY KEY,
            note TEXT CHECK (note GLOB '*[^0-9]*')
          );
        `,
      });

      expect(() => {
        new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      }).toThrow(/Cannot migrate policy_budget_accumulators: table schema does not match either the verified strict schema or the supported Milestone 8 legacy schema/);

      // Verify original malformed table was preserved without destructive repair
      const verifyDb = new DatabaseSync(dbFile);
      try {
        const masterRow = verifyDb.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'policy_budget_accumulators'").get() as { sql: string };
        expect(masterRow.sql).toContain("note TEXT");
      } finally {
        verifyDb.close();
      }
    });

    it("fails closed on missing columns, wrong PK, wrong CHECK constraint, or wrong foreign key definition", () => {
      const structuralFailures = [
        {
          name: "missing last_updated_at column",
          sql: `
            CREATE TABLE policy_budget_accumulators (
              policy_id TEXT NOT NULL,
              window_type TEXT NOT NULL CHECK (window_type IN ('HOURLY', 'DAILY')),
              window_start INTEGER NOT NULL,
              spent_amount TEXT NOT NULL CHECK (length(spent_amount) <= 78 AND spent_amount GLOB '[0-9]*'),
              PRIMARY KEY (policy_id, window_type, window_start),
              FOREIGN KEY (policy_id) REFERENCES policies(policy_id) ON DELETE CASCADE
            );
          `,
        },
        {
          name: "wrong primary key (single column)",
          sql: `
            CREATE TABLE policy_budget_accumulators (
              policy_id TEXT PRIMARY KEY,
              window_type TEXT NOT NULL CHECK (window_type IN ('HOURLY', 'DAILY')),
              window_start INTEGER NOT NULL,
              spent_amount TEXT NOT NULL CHECK (length(spent_amount) <= 78 AND spent_amount GLOB '[0-9]*'),
              last_updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              FOREIGN KEY (policy_id) REFERENCES policies(policy_id) ON DELETE CASCADE
            );
          `,
        },
        {
          name: "missing ON DELETE CASCADE on foreign key",
          sql: `
            CREATE TABLE policy_budget_accumulators (
              policy_id TEXT NOT NULL,
              window_type TEXT NOT NULL CHECK (window_type IN ('HOURLY', 'DAILY')),
              window_start INTEGER NOT NULL,
              spent_amount TEXT NOT NULL CHECK (length(spent_amount) <= 78 AND spent_amount GLOB '[0-9]*'),
              last_updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              PRIMARY KEY (policy_id, window_type, window_start),
              FOREIGN KEY (policy_id) REFERENCES policies(policy_id)
            );
          `,
        },
        {
          name: "missing length constraint in CHECK",
          sql: `
            CREATE TABLE policy_budget_accumulators (
              policy_id TEXT NOT NULL,
              window_type TEXT NOT NULL CHECK (window_type IN ('HOURLY', 'DAILY')),
              window_start INTEGER NOT NULL,
              spent_amount TEXT NOT NULL CHECK (spent_amount GLOB '[0-9]*'),
              last_updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              PRIMARY KEY (policy_id, window_type, window_start),
              FOREIGN KEY (policy_id) REFERENCES policies(policy_id) ON DELETE CASCADE
            );
          `,
        },
      ];

      for (const tc of structuralFailures) {
        const dbFile = createTestDbPath(`structural-${tc.name.replace(/\s+/g, "-")}-`);
        seedM8Database(dbFile, { customAccumulatorSql: tc.sql });

        expect(() => {
          new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
        }).toThrow(/Cannot migrate policy_budget_accumulators: table schema does not match either the verified strict schema or the supported Milestone 8 legacy schema/);

        // Verify table was preserved untouched
        const verifyDb = new DatabaseSync(dbFile);
        try {
          const masterRow = verifyDb.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'policy_budget_accumulators'").get() as { sql: string };
          expect(masterRow).toBeDefined();
        } finally {
          verifyDb.close();
        }
      }
    });

    it("drops identical staging table when both original and v2 tables exist", () => {
      const dbFile = createTestDbPath("staging-identical-");
      seedM8Database(dbFile);

      const rawDb = new DatabaseSync(dbFile);
      rawDb.exec(`
        INSERT INTO policies (policy_id, current_revision, status, policy_json) VALUES
          ('pol-dup', 1, 'active', '{"version":1}');

        INSERT INTO policy_budget_accumulators VALUES ('pol-dup', 'HOURLY', 0, '100', '2026-10-25 10:00:00');

        CREATE TABLE policy_budget_accumulators_v2 (
          policy_id TEXT NOT NULL,
          window_type TEXT NOT NULL CHECK (window_type IN ('HOURLY', 'DAILY')),
          window_start INTEGER NOT NULL,
          spent_amount TEXT NOT NULL CHECK (length(spent_amount) > 0 AND length(spent_amount) <= 78 AND NOT (spent_amount GLOB '*[^0-9]*')),
          last_updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (policy_id, window_type, window_start)
        );
        INSERT INTO policy_budget_accumulators_v2 VALUES ('pol-dup', 'HOURLY', 0, '100', '2026-10-25 10:00:00');
      `);
      rawDb.close();

      const store = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      openStores.push(store);

      const verifyDb = new DatabaseSync(dbFile);
      try {
        const tables = (verifyDb.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>).map((t) => t.name);
        expect(tables).toContain("policy_budget_accumulators");
        expect(tables).not.toContain("policy_budget_accumulators_v2");
      } finally {
        verifyDb.close();
      }
    });

    it("halts startup with clear error when original and staging tables have conflicting data", () => {
      const dbFile = createTestDbPath("staging-conflict-");
      seedM8Database(dbFile);

      const rawDb = new DatabaseSync(dbFile);
      rawDb.exec(`
        INSERT INTO policies (policy_id, current_revision, status, policy_json) VALUES
          ('pol-conf', 1, 'active', '{"version":1}');

        INSERT INTO policy_budget_accumulators VALUES ('pol-conf', 'HOURLY', 0, '100', '2026-10-25 10:00:00');

        CREATE TABLE policy_budget_accumulators_v2 (
          policy_id TEXT NOT NULL,
          window_type TEXT NOT NULL CHECK (window_type IN ('HOURLY', 'DAILY')),
          window_start INTEGER NOT NULL,
          spent_amount TEXT NOT NULL CHECK (length(spent_amount) > 0 AND length(spent_amount) <= 78 AND NOT (spent_amount GLOB '*[^0-9]*')),
          last_updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (policy_id, window_type, window_start)
        );
        INSERT INTO policy_budget_accumulators_v2 VALUES ('pol-conf', 'HOURLY', 0, '999', '2026-10-25 10:00:00');
      `);
      rawDb.close();

      expect(() => {
        new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      }).toThrow(/Ambiguous migration state: both policy_budget_accumulators and policy_budget_accumulators_v2 exist with conflicting row contents/);
    });
  });

  // =========================================================================
  // 7. Concurrent Process Initialization
  // =========================================================================
  it("handles concurrent initialization from separate OS processes without corruption or race conditions", async () => {
    const dbFile = createTestDbPath("concurrent-mig-");
    seedM8Database(dbFile);

    const rawDb = new DatabaseSync(dbFile);
    rawDb.exec(`
      INSERT INTO policies (policy_id, current_revision, status, policy_json) VALUES
        ('pol-conc', 1, 'active', '{"version":1}');
      INSERT INTO policy_budget_accumulators VALUES ('pol-conc', 'HOURLY', 0, '50', '2026-10-25 10:00:00');
    `);
    rawDb.close();

    const workerScript = `
      import { SQLiteAuthorizationStore } from './src/authorization-store.js';
      import { TestClock } from './src/clock.js';

      try {
        const store = new SQLiteAuthorizationStore(${JSON.stringify(dbFile)}, new TestClock(1000));
        const val = store.getPolicyBudgetAccumulator('pol-conc', 'HOURLY', 0);
        if (!val || val.spentAmount !== '50') {
          process.exit(2);
        }
        store.close();
        process.exit(0);
      } catch (err) {
        console.error(err);
        process.exit(1);
      }
    `;

    const runWorker = () =>
      new Promise<number>((resolvePromise) => {
        const child = fork("-e", [workerScript], {
          execArgv: ["--input-type=module", "--import", "tsx/esm"],
          silent: true,
        });
        child.on("exit", (code) => resolvePromise(code ?? 1));
      });

    // Run 3 workers simultaneously attempting to migrate/initialize the same M8 database
    const results = await Promise.all([runWorker(), runWorker(), runWorker()]);
    expect(results).toEqual([0, 0, 0]);

    // Verify database is cleanly migrated
    const verifyDb = new DatabaseSync(dbFile);
    try {
      const sql = (verifyDb.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'policy_budget_accumulators'").get() as { sql: string }).sql;
      expect(sql).toContain("NOT (spent_amount GLOB '*[^0-9]*')");
      const row = verifyDb.prepare("SELECT spent_amount FROM policy_budget_accumulators WHERE policy_id = 'pol-conc'").get() as { spent_amount: string };
      expect(row.spent_amount).toBe("50");
    } finally {
      verifyDb.close();
    }
  }, 25000);

  // =========================================================================
  // 8. Active Budget Continuity
  // =========================================================================
  it("preserves active budget continuity across M8-to-M9 migration without resetting spent amounts", () => {
    const dbFile = createTestDbPath("active-budget-continuity-");
    seedM8Database(dbFile);

    const { privateKey, pem } = createKeypair();

    // Setup policy with hourly budget of 200 in M8 database
    const policy: DemoPolicy = {
      version: 1,
      policyId: "pol-continuity",
      allowedTarget: TARGET,
      allowedRecipient: RECIPIENT,
      allowedSelector: "0xa9059cbb",
      maxAmount: "100",
      validFrom: 0,
      expiresAt: 20000,
      revoked: false,
      budget: {
        window: "HOURLY",
        maxCumulativeAmount: "200",
      },
    };

    const rawDb = new DatabaseSync(dbFile);
    rawDb.prepare(`
      INSERT INTO policies (policy_id, current_revision, status, policy_json)
      VALUES (?, 1, 'active', ?)
    `).run(policy.policyId, JSON.stringify(policy));

    rawDb.prepare(`
      INSERT INTO issuer_keys (key_id, public_key_pem, status, valid_from_seconds, expires_at_seconds)
      VALUES ('k-continuity', ?, 'active', 0, 20000)
    `).run(pem);

    // Seed existing M8 spending of 60 in current window (0..3600)
    rawDb.prepare(`
      INSERT INTO policy_budget_accumulators (policy_id, window_type, window_start, spent_amount)
      VALUES (?, 'HOURLY', 0, '60')
    `).run(policy.policyId);
    rawDb.close();

    // Now open via Web3UserEngine, triggering transparent M9 schema migration
    const clock = new TestClock(1000);
    const engine = new Web3UserEngine({
      databasePath: dbFile,
      clock: { clock, maxStartupForwardGapSeconds: 200_000 },
    });
    openEngines.push(engine);

    // 1. Check budget status: must show spentAmount = 60, remainingAmount = 140 (NEVER reset to 0 or 200)
    const status = engine.policies.getBudgetStatus(policy.policyId, 1000);
    expect(status?.hasBudget).toBe(true);
    expect(status?.spentAmount).toBe("60");
    expect(status?.remainingAmount).toBe("140");

    // 2. Consume an additional 50 units -> succeeds and updates spend to 110
    const req1: TransactionRequest = {
      chainId: "1",
      sender: TARGET,
      target: TARGET,
      calldata: encodeCalldata(RECIPIENT, 50n),
      value: "0",
    };
    const issue1 = engine.issue({
      signer: { keyId: "k-continuity", privateKey },
      authorizationId: "auth-mig-1",
      policyId: policy.policyId,
      request: req1,
    });
    expect(issue1.decision).toBe("ALLOW");
    if (issue1.decision !== "ALLOW") throw new Error("issue1 failed");

    const consume1 = engine.consume({
      artifact: issue1.artifact,
      request: req1,
    });
    expect(consume1.decision).toBe("ALLOW");

    const statusAfterSpend = engine.policies.getBudgetStatus(policy.policyId, 1000);
    expect(statusAfterSpend?.spentAmount).toBe("110");
    expect(statusAfterSpend?.remainingAmount).toBe("90");

    // 3. Attempt to consume 100 units -> DENIED because 110 + 100 > 200 (budget enforcement intact)
    const req2: TransactionRequest = {
      chainId: "1",
      sender: TARGET,
      target: TARGET,
      calldata: encodeCalldata(RECIPIENT, 100n),
      value: "0",
    };
    const issue2 = engine.issue({
      signer: { keyId: "k-continuity", privateKey },
      authorizationId: "auth-mig-2",
      policyId: policy.policyId,
      request: req2,
    });
    expect(issue2.decision).toBe("ALLOW");
    if (issue2.decision !== "ALLOW") throw new Error("issue2 failed");

    const consume2 = engine.consume({
      artifact: issue2.artifact,
      request: req2,
    });
    expect(consume2.decision).toBe("DENY");
    expect(consume2.reasons[0]).toContain("Cumulative spending budget exceeded for hourly window");
    expect(consume2.reasons[0]).toContain("requested: 100");
    expect(consume2.reasons[0]).toContain("available: 90");
  });
});
