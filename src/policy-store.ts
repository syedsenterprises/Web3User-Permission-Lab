import { DatabaseSync } from "node:sqlite";
import { type Clock, systemClock } from "./clock.js";
import { type DemoPolicy, normalizeDemoPolicy } from "./policy.js";
import { withImmediateTransaction } from "./sqlite-transaction.js";

export type PolicyStatus = "active" | "revoked" | "retired";

export interface PolicyRecord {
  readonly policyId: string;
  readonly revision: number;
  readonly status: PolicyStatus;
  readonly policy: DemoPolicy;
  readonly updatedAt: string;
}

export interface PolicyRevisionRecord {
  readonly policyId: string;
  readonly revision: number;
  readonly status: PolicyStatus;
  readonly policy: DemoPolicy;
  readonly createdAt: string;
}

export interface PolicyStore {
  registerPolicy(policy: DemoPolicy, initialRevision?: number): PolicyRecord;
  getPolicy(policyId: string): PolicyRecord | null;
  getPolicyRevision(policyId: string, revision: number): PolicyRevisionRecord | null;
  listPolicyRevisions(policyId: string): PolicyRevisionRecord[];
  listPolicies(statusFilter?: PolicyStatus): PolicyRecord[];
  updatePolicy(policy: DemoPolicy, expectedCurrentRevision?: number): PolicyRecord;
  revokePolicy(policyId: string, expectedCurrentRevision?: number): PolicyRecord;
  restorePolicy(policyId: string, updatedPolicy?: DemoPolicy, expectedCurrentRevision?: number): PolicyRecord;
  retirePolicy(policyId: string, expectedCurrentRevision?: number): PolicyRecord;
  deletePolicy(policyId: string, expectedCurrentRevision?: number): boolean;
  recreatePolicy(policy: DemoPolicy, newRevision?: number): PolicyRecord;
  close(): void;
}

export class SQLitePolicyStore implements PolicyStore {
  private readonly db: DatabaseSync;
  private readonly ownsDb: boolean;
  private readonly clock: Clock;

  constructor(database: string | DatabaseSync, clock: Clock = systemClock) {
    this.clock = clock;
    if (typeof database === "string") {
      this.db = new DatabaseSync(database);
      this.ownsDb = true;
      try {
        this.db.exec("PRAGMA journal_mode = WAL;");
      } catch {
        // Ignored for in-memory or unsupported database configurations
      }
      this.db.exec("PRAGMA busy_timeout = 5000;");
    } else {
      this.db = database;
      this.ownsDb = false;
    }

    try {
      this.initializeSchema();
    } catch (err) {
      if (this.ownsDb) {
        try {
          this.db.close();
        } catch {}
      }
      throw err;
    }
  }

  private initializeSchema(): void {
    withImmediateTransaction(this.db, () => {
      // 1. Ensure system_clock_state exists
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS system_clock_state (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          high_water_seconds INTEGER NOT NULL,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
      `);
      this.db.prepare(`
        INSERT INTO system_clock_state (id, high_water_seconds)
        VALUES (1, ?)
        ON CONFLICT(id) DO NOTHING;
      `).run(this.clock.nowSeconds());

      // 2. Ensure policies and policy_revisions tables exist with safe migration
      this.ensurePoliciesTable();
      this.ensurePolicyRevisionsTable();
    });
  }

  private ensurePoliciesTable(): void {
    const tables = (
      this.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>
    ).map((t) => t.name);

    if (!tables.includes("policies")) {
      this.db.exec(`
        CREATE TABLE policies (
          policy_id TEXT PRIMARY KEY,
          current_revision INTEGER NOT NULL DEFAULT 1,
          status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'retired')),
          policy_json TEXT NOT NULL,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
      `);
      return;
    }

    const cols = (
      this.db.prepare("PRAGMA table_info(policies)").all() as Array<{ name: string }>
    ).map((c) => c.name);
    const masterRow = this.db.prepare(
      "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'policies'"
    ).get() as { sql: string } | undefined;
    const sql = masterRow?.sql ?? "";

    const hasAllCols =
      cols.includes("policy_id") &&
      cols.includes("current_revision") &&
      cols.includes("status") &&
      cols.includes("policy_json") &&
      cols.includes("updated_at");
    const hasCheck = sql.includes("active") && sql.includes("revoked") && sql.includes("retired");

    if (!hasAllCols || !hasCheck) {
      this.db.exec(`
        CREATE TABLE policies_temp (
          policy_id TEXT PRIMARY KEY,
          current_revision INTEGER NOT NULL DEFAULT 1,
          status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'retired')),
          policy_json TEXT NOT NULL,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        INSERT INTO policies_temp (policy_id, current_revision, status, policy_json, updated_at)
        SELECT
          policy_id,
          ${cols.includes("current_revision") ? "COALESCE(current_revision, 1)" : "1"},
          ${cols.includes("status") ? "CASE WHEN status IN ('active', 'revoked', 'retired') THEN status ELSE 'active' END" : "'active'"},
          policy_json,
          ${cols.includes("updated_at") ? "COALESCE(updated_at, CURRENT_TIMESTAMP)" : "CURRENT_TIMESTAMP"}
        FROM policies;

        DROP TABLE policies;
        ALTER TABLE policies_temp RENAME TO policies;
      `);
    }
  }

  private ensurePolicyRevisionsTable(): void {
    const tables = (
      this.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>
    ).map((t) => t.name);

    if (!tables.includes("policy_revisions")) {
      this.db.exec(`
        CREATE TABLE policy_revisions (
          policy_id TEXT NOT NULL,
          revision INTEGER NOT NULL,
          status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'retired')),
          policy_json TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (policy_id, revision)
        );
      `);
      return;
    }

    const cols = (
      this.db.prepare("PRAGMA table_info(policy_revisions)").all() as Array<{ name: string }>
    ).map((c) => c.name);
    const masterRow = this.db.prepare(
      "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'policy_revisions'"
    ).get() as { sql: string } | undefined;
    const sql = masterRow?.sql ?? "";

    const hasAllCols =
      cols.includes("policy_id") &&
      cols.includes("revision") &&
      cols.includes("status") &&
      cols.includes("policy_json") &&
      cols.includes("created_at");
    const hasCheck = sql.includes("active") && sql.includes("revoked") && sql.includes("retired");
    const hasPk = sql.includes("PRIMARY KEY") && sql.includes("policy_id") && sql.includes("revision");

    if (!hasAllCols || !hasCheck || !hasPk) {
      this.db.exec(`
        CREATE TABLE policy_revisions_temp (
          policy_id TEXT NOT NULL,
          revision INTEGER NOT NULL,
          status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'retired')),
          policy_json TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (policy_id, revision)
        );

        INSERT INTO policy_revisions_temp (policy_id, revision, status, policy_json, created_at)
        SELECT
          policy_id,
          ${cols.includes("revision") ? "COALESCE(revision, 1)" : "1"},
          ${cols.includes("status") ? "CASE WHEN status IN ('active', 'revoked', 'retired') THEN status ELSE 'active' END" : "'active'"},
          policy_json,
          ${cols.includes("created_at") ? "COALESCE(created_at, CURRENT_TIMESTAMP)" : "CURRENT_TIMESTAMP"}
        FROM policy_revisions;

        DROP TABLE policy_revisions;
        ALTER TABLE policy_revisions_temp RENAME TO policy_revisions;
      `);
    }
  }

  registerPolicy(policyInput: DemoPolicy, initialRevision: number = 1): PolicyRecord {
    const normalized = normalizeDemoPolicy(policyInput);
    if (!normalized) {
      throw new Error("Invalid policy: failed normalization.");
    }
    if (!Number.isSafeInteger(initialRevision) || initialRevision < 1) {
      throw new Error(`Initial revision must be a positive safe integer, got ${initialRevision}.`);
    }

    withImmediateTransaction(this.db, () => {
      // 1. Check if policy is currently active or known in policies table
      const existing = this.db.prepare(
        "SELECT policy_id FROM policies WHERE policy_id = ?"
      ).get(normalized.policyId);

      if (existing) {
        throw new Error(`Policy '${normalized.policyId}' is already registered.`);
      }

      // 2. Check historical revisions in policy_revisions
      const maxRevRow = this.db.prepare(
        "SELECT MAX(revision) AS maxRev FROM policy_revisions WHERE policy_id = ?"
      ).get(normalized.policyId) as { maxRev: number | null } | undefined;

      const maxRev = maxRevRow?.maxRev;
      if (maxRev !== null && maxRev !== undefined) {
        // Policy was previously deleted! Recreating requires revision > maxRev
        if (initialRevision <= maxRev) {
          throw new Error(
            `Cannot recreate deleted policy '${normalized.policyId}' with revision ${initialRevision}: must be strictly greater than historical maximum revision (${maxRev}).`
          );
        }
      }

      const policyJson = JSON.stringify(normalized);
      this.db.prepare(`
        INSERT INTO policies (policy_id, current_revision, status, policy_json, updated_at)
        VALUES (?, ?, 'active', ?, CURRENT_TIMESTAMP)
      `).run(normalized.policyId, initialRevision, policyJson);

      this.db.prepare(`
        INSERT INTO policy_revisions (policy_id, revision, status, policy_json, created_at)
        VALUES (?, ?, 'active', ?, CURRENT_TIMESTAMP)
      `).run(normalized.policyId, initialRevision, policyJson);
    });

    return this.getPolicy(normalized.policyId)!;
  }

  getPolicy(policyId: string): PolicyRecord | null {
    const row = this.db.prepare(
      "SELECT policy_id, current_revision, status, policy_json, updated_at FROM policies WHERE policy_id = ?"
    ).get(policyId) as {
      policy_id: string;
      current_revision: number;
      status: PolicyStatus;
      policy_json: string;
      updated_at: string;
    } | undefined;

    if (!row) return null;

    return Object.freeze({
      policyId: row.policy_id,
      revision: row.current_revision,
      status: row.status,
      policy: Object.freeze(JSON.parse(row.policy_json) as DemoPolicy),
      updatedAt: row.updated_at,
    });
  }

  getPolicyRevision(policyId: string, revision: number): PolicyRevisionRecord | null {
    const row = this.db.prepare(
      "SELECT policy_id, revision, status, policy_json, created_at FROM policy_revisions WHERE policy_id = ? AND revision = ?"
    ).get(policyId, revision) as {
      policy_id: string;
      revision: number;
      status: PolicyStatus;
      policy_json: string;
      created_at: string;
    } | undefined;

    if (!row) return null;

    return Object.freeze({
      policyId: row.policy_id,
      revision: row.revision,
      status: row.status,
      policy: Object.freeze(JSON.parse(row.policy_json) as DemoPolicy),
      createdAt: row.created_at,
    });
  }

  listPolicyRevisions(policyId: string): PolicyRevisionRecord[] {
    const rows = this.db.prepare(
      "SELECT policy_id, revision, status, policy_json, created_at FROM policy_revisions WHERE policy_id = ? ORDER BY revision ASC"
    ).all(policyId) as Array<{
      policy_id: string;
      revision: number;
      status: PolicyStatus;
      policy_json: string;
      created_at: string;
    }>;

    return rows.map((r) =>
      Object.freeze({
        policyId: r.policy_id,
        revision: r.revision,
        status: r.status,
        policy: Object.freeze(JSON.parse(r.policy_json) as DemoPolicy),
        createdAt: r.created_at,
      })
    );
  }

  listPolicies(statusFilter?: PolicyStatus): PolicyRecord[] {
    let rows: Array<{ policy_id: string }>;
    if (statusFilter) {
      rows = this.db.prepare(
        "SELECT policy_id FROM policies WHERE status = ? ORDER BY policy_id ASC"
      ).all(statusFilter) as Array<{ policy_id: string }>;
    } else {
      rows = this.db.prepare(
        "SELECT policy_id FROM policies ORDER BY policy_id ASC"
      ).all() as Array<{ policy_id: string }>;
    }

    const result: PolicyRecord[] = [];
    for (const row of rows) {
      const record = this.getPolicy(row.policy_id);
      if (record !== null) {
        result.push(record);
      }
    }
    return result;
  }

  updatePolicy(policyInput: DemoPolicy, expectedCurrentRevision?: number): PolicyRecord {
    const normalized = normalizeDemoPolicy(policyInput);
    if (!normalized) {
      throw new Error("Invalid policy: failed normalization.");
    }

    withImmediateTransaction(this.db, () => {
      const row = this.db.prepare(
        "SELECT policy_id, current_revision, status FROM policies WHERE policy_id = ?"
      ).get(normalized.policyId) as {
        policy_id: string;
        current_revision: number;
        status: PolicyStatus;
      } | undefined;

      if (!row) {
        throw new Error(`Policy '${normalized.policyId}' not found.`);
      }

      if (row.status === "retired") {
        throw new Error(`Cannot update retired policy '${normalized.policyId}'; retirement is terminal.`);
      }
      if (row.status === "revoked") {
        throw new Error(`Cannot update revoked policy '${normalized.policyId}'; restore policy before updating.`);
      }

      if (expectedCurrentRevision !== undefined && row.current_revision !== expectedCurrentRevision) {
        throw new Error(
          `Stale revision for policy '${normalized.policyId}': expected revision ${expectedCurrentRevision}, but current revision is ${row.current_revision}.`
        );
      }

      const newRevision = row.current_revision + 1;
      const policyJson = JSON.stringify(normalized);

      const res = this.db.prepare(`
        UPDATE policies
        SET current_revision = ?, policy_json = ?, updated_at = CURRENT_TIMESTAMP
        WHERE policy_id = ? AND current_revision = ?
      `).run(newRevision, policyJson, normalized.policyId, row.current_revision);

      if (res.changes !== 1) {
        throw new Error(`Concurrent update conflict for policy '${normalized.policyId}'.`);
      }

      this.db.prepare(`
        INSERT INTO policy_revisions (policy_id, revision, status, policy_json, created_at)
        VALUES (?, ?, 'active', ?, CURRENT_TIMESTAMP)
      `).run(normalized.policyId, newRevision, policyJson);
    });

    return this.getPolicy(normalized.policyId)!;
  }

  revokePolicy(policyId: string, expectedCurrentRevision?: number): PolicyRecord {
    if (typeof policyId !== "string" || policyId.trim().length === 0) {
      throw new Error("Policy ID must be a non-empty string.");
    }

    withImmediateTransaction(this.db, () => {
      const row = this.db.prepare(
        "SELECT policy_id, current_revision, status, policy_json FROM policies WHERE policy_id = ?"
      ).get(policyId) as {
        policy_id: string;
        current_revision: number;
        status: PolicyStatus;
        policy_json: string;
      } | undefined;

      if (!row) {
        throw new Error(`Policy '${policyId}' not found.`);
      }

      if (row.status === "retired") {
        throw new Error(`Cannot revoke retired policy '${policyId}'; retirement is terminal.`);
      }

      if (expectedCurrentRevision !== undefined && row.current_revision !== expectedCurrentRevision) {
        throw new Error(
          `Stale revision for policy '${policyId}': expected revision ${expectedCurrentRevision}, but current revision is ${row.current_revision}.`
        );
      }

      if (row.status === "revoked") {
        return;
      }

      const newRevision = row.current_revision + 1;
      const currentPolicy = JSON.parse(row.policy_json) as DemoPolicy;
      const revokedPolicy: DemoPolicy = { ...currentPolicy, revoked: true };
      const policyJson = JSON.stringify(revokedPolicy);

      this.db.prepare(`
        UPDATE policies
        SET current_revision = ?, status = 'revoked', policy_json = ?, updated_at = CURRENT_TIMESTAMP
        WHERE policy_id = ? AND current_revision = ?
      `).run(newRevision, policyJson, policyId, row.current_revision);

      this.db.prepare(`
        INSERT INTO policy_revisions (policy_id, revision, status, policy_json, created_at)
        VALUES (?, ?, 'revoked', ?, CURRENT_TIMESTAMP)
      `).run(policyId, newRevision, policyJson);
    });

    return this.getPolicy(policyId)!;
  }

  restorePolicy(
    policyId: string,
    updatedPolicy?: DemoPolicy,
    expectedCurrentRevision?: number
  ): PolicyRecord {
    if (typeof policyId !== "string" || policyId.trim().length === 0) {
      throw new Error("Policy ID must be a non-empty string.");
    }

    withImmediateTransaction(this.db, () => {
      const row = this.db.prepare(
        "SELECT policy_id, current_revision, status, policy_json FROM policies WHERE policy_id = ?"
      ).get(policyId) as {
        policy_id: string;
        current_revision: number;
        status: PolicyStatus;
        policy_json: string;
      } | undefined;

      if (!row) {
        throw new Error(`Policy '${policyId}' not found.`);
      }

      if (row.status === "active") {
        throw new Error(`Policy '${policyId}' is already active.`);
      }

      if (row.status === "retired") {
        throw new Error(`Cannot restore retired policy '${policyId}'; retirement is terminal.`);
      }

      if (expectedCurrentRevision !== undefined && row.current_revision !== expectedCurrentRevision) {
        throw new Error(
          `Stale revision for policy '${policyId}': expected revision ${expectedCurrentRevision}, but current revision is ${row.current_revision}.`
        );
      }

      let restoredPolicy: DemoPolicy;
      if (updatedPolicy) {
        const normalized = normalizeDemoPolicy(updatedPolicy);
        if (!normalized) {
          throw new Error("Invalid updated policy: failed normalization.");
        }
        if (normalized.policyId !== policyId) {
          throw new Error(
            `Policy ID mismatch: updated policy ID '${normalized.policyId}' does not match target policy ID '${policyId}'.`
          );
        }
        restoredPolicy = { ...normalized, revoked: false };
      } else {
        const currentPolicy = JSON.parse(row.policy_json) as DemoPolicy;
        restoredPolicy = { ...currentPolicy, revoked: false };
      }

      const newRevision = row.current_revision + 1;
      const policyJson = JSON.stringify(restoredPolicy);

      this.db.prepare(`
        UPDATE policies
        SET current_revision = ?, status = 'active', policy_json = ?, updated_at = CURRENT_TIMESTAMP
        WHERE policy_id = ? AND current_revision = ?
      `).run(newRevision, policyJson, policyId, row.current_revision);

      this.db.prepare(`
        INSERT INTO policy_revisions (policy_id, revision, status, policy_json, created_at)
        VALUES (?, ?, 'active', ?, CURRENT_TIMESTAMP)
      `).run(policyId, newRevision, policyJson);
    });

    return this.getPolicy(policyId)!;
  }

  retirePolicy(policyId: string, expectedCurrentRevision?: number): PolicyRecord {
    if (typeof policyId !== "string" || policyId.trim().length === 0) {
      throw new Error("Policy ID must be a non-empty string.");
    }

    withImmediateTransaction(this.db, () => {
      const row = this.db.prepare(
        "SELECT policy_id, current_revision, status, policy_json FROM policies WHERE policy_id = ?"
      ).get(policyId) as {
        policy_id: string;
        current_revision: number;
        status: PolicyStatus;
        policy_json: string;
      } | undefined;

      if (!row) {
        throw new Error(`Policy '${policyId}' not found.`);
      }

      if (expectedCurrentRevision !== undefined && row.current_revision !== expectedCurrentRevision) {
        throw new Error(
          `Stale revision for policy '${policyId}': expected revision ${expectedCurrentRevision}, but current revision is ${row.current_revision}.`
        );
      }

      if (row.status === "retired") {
        return;
      }

      const newRevision = row.current_revision + 1;
      const currentPolicy = JSON.parse(row.policy_json) as DemoPolicy;
      const policyJson = JSON.stringify(currentPolicy);

      this.db.prepare(`
        UPDATE policies
        SET current_revision = ?, status = 'retired', updated_at = CURRENT_TIMESTAMP
        WHERE policy_id = ? AND current_revision = ?
      `).run(newRevision, policyId, row.current_revision);

      this.db.prepare(`
        INSERT INTO policy_revisions (policy_id, revision, status, policy_json, created_at)
        VALUES (?, ?, 'retired', ?, CURRENT_TIMESTAMP)
      `).run(policyId, newRevision, policyJson);
    });

    return this.getPolicy(policyId)!;
  }

  deletePolicy(policyId: string, expectedCurrentRevision?: number): boolean {
    if (typeof policyId !== "string" || policyId.trim().length === 0) {
      throw new Error("Policy ID must be a non-empty string.");
    }

    let deleted = false;
    withImmediateTransaction(this.db, () => {
      const row = this.db.prepare(
        "SELECT policy_id, current_revision FROM policies WHERE policy_id = ?"
      ).get(policyId) as { policy_id: string; current_revision: number } | undefined;

      if (!row) {
        deleted = false;
        return;
      }

      if (expectedCurrentRevision !== undefined && row.current_revision !== expectedCurrentRevision) {
        throw new Error(
          `Stale revision for policy '${policyId}': expected revision ${expectedCurrentRevision}, but current revision is ${row.current_revision}.`
        );
      }

      this.db.prepare("DELETE FROM policies WHERE policy_id = ?").run(policyId);
      deleted = true;
    });

    return deleted;
  }

  recreatePolicy(policy: DemoPolicy, newRevision?: number): PolicyRecord {
    return this.registerPolicy(policy, newRevision);
  }

  close(): void {
    if (this.ownsDb) {
      this.db.close();
    }
  }
}
