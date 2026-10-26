import { DatabaseSync } from "node:sqlite";
import {
  type Clock,
  systemClock,
  ClockGuard,
  type MonotonicClock,
  type ClockCandidate,
  TestClock,
} from "./clock.js";
import { SQLiteKeyStore } from "./key-store.js";
import { SQLitePolicyStore } from "./policy-store.js";
import { type BudgetWindowType } from "./policy.js";
import { isFatalIOError, withImmediateTransaction } from "./sqlite-transaction.js";

export * from "./policy-store.js";
export * from "./key-store.js";
export * from "./sqlite-transaction.js";

export type SQLiteSynchronousMode = "OFF" | "NORMAL" | "FULL" | "EXTRA";
export type CheckpointMode = "PASSIVE" | "FULL" | "RESTART" | "TRUNCATE";

export interface CheckpointResult {
  readonly busy: boolean;
  readonly logFrames: number;
  readonly checkpointedFrames: number;
}

export interface SQLiteAuthorizationStoreOptions {
  readonly clock?: Clock;
  /**
   * When true, allows legacy V1 (bound) and V2 (signed) operations.
   * When false (default), calling legacy reservation, V1 issuance/consumption, or V2 issuance/consumption
   * immediately fails closed, guaranteeing that only strict V3 governed authorizations
   * can be issued or consumed in the database.
   */
  readonly allowLegacyArtifactVersions?: boolean;
  readonly monotonicClock?: MonotonicClock;
  readonly clockGuard?: ClockGuard;
  readonly maxStartupForwardGapSeconds?: number;
  readonly synchronous?: SQLiteSynchronousMode;
  readonly onFatalTaint?: (reason: string) => void;
  readonly busyTimeoutMs?: number;
}

/**
 * Contract required by the persistent consumption boundary: `reserve` must
 * durably and atomically reserve a unique ID, and must throw on storage
 * failure. An in-memory implementation does not satisfy this contract.
 */
export interface AuthorizationIdStore {
  reserve(authorizationId: string): boolean;
  close(): void;
}

/**
 * Store contract for bound artifacts. Issuance must persist the expected
 * binding before a caller may consume the authorization.
 *
 * The optional version discriminator enforces artifact-version isolation:
 * a v1 consumption request only consumes records issued for v1, a v2
 * consumption request only consumes records issued for v2, and a v3
 * consumption request enforces key identity and issuance timestamp matching.
 */
export interface BoundAuthorizationIdStore extends AuthorizationIdStore {
  issueBound(
    authorizationId: string,
    bindingDigest: string,
    version?: number,
    keyId?: string,
    issuedAtSeconds?: number,
  ): boolean;
  consumeBound(
    authorizationId: string,
    bindingDigest: string,
    version?: number,
    keyId?: string,
    issuedAtSeconds?: number,
  ): boolean;
  cancelAuthorization?(
    authorizationId: string,
  ): boolean;
}

export type AuthorizationState = "issued" | "consumed" | "legacy_void" | "cancelled";

export interface AuthorizationRecord {
  readonly authorizationId: string;
  readonly bindingDigest: string | null;
  readonly state: AuthorizationState;
  readonly consumedAt: string | null;
  readonly artifactVersion: number;
  readonly keyId: string | null;
  readonly issuedAtSeconds: number | null;
}

/**
 * Persistent, atomic authorization-ID reservation with artifact-version discrimination,
 * clock rollback protection, and authoritative policy/key governance schema.
 * The database must be stored on a durable local filesystem and shared by
 * every caller that needs common replay protection.
 */
export class SQLiteAuthorizationStore implements BoundAuthorizationIdStore {
  private readonly db: DatabaseSync;
  private readonly clock: Clock;
  private readonly allowLegacyArtifactVersions: boolean;
  private readonly clockGuard: ClockGuard;
  private tainted: boolean = false;
  private taintedReason: string | undefined;
  private readonly onFatalTaint?: (reason: string) => void;

  constructor(
    databasePath: string,
    clockOrOptions: Clock | SQLiteAuthorizationStoreOptions = systemClock,
    options?: SQLiteAuthorizationStoreOptions,
  ) {
    let resolvedClock: Clock = systemClock;
    let resolvedLegacy = false;
    let resolvedMonotonic: MonotonicClock | undefined;
    let resolvedGuard: ClockGuard | undefined;
    let resolvedGap: number | undefined;
    let resolvedSynchronous: SQLiteSynchronousMode = "FULL";
    let resolvedFatalTaint: ((reason: string) => void) | undefined;
    let resolvedBusyTimeout: number | undefined;

    if (options && typeof options === "object") {
      resolvedClock =
        clockOrOptions && "nowSeconds" in clockOrOptions
          ? clockOrOptions
          : (options.clock ?? systemClock);
      resolvedLegacy = options.allowLegacyArtifactVersions ?? false;
      resolvedMonotonic = options.monotonicClock;
      resolvedGuard = options.clockGuard;
      resolvedGap = options.maxStartupForwardGapSeconds;
      resolvedSynchronous = options.synchronous ?? "FULL";
      resolvedFatalTaint = options.onFatalTaint;
      resolvedBusyTimeout = options.busyTimeoutMs;
    } else if (clockOrOptions && "nowSeconds" in clockOrOptions) {
      resolvedClock = clockOrOptions;
      resolvedLegacy = false;
    } else if (clockOrOptions && typeof clockOrOptions === "object") {
      resolvedClock = clockOrOptions.clock ?? systemClock;
      resolvedLegacy = clockOrOptions.allowLegacyArtifactVersions ?? false;
      resolvedMonotonic = clockOrOptions.monotonicClock;
      resolvedGuard = clockOrOptions.clockGuard;
      resolvedGap = clockOrOptions.maxStartupForwardGapSeconds;
      resolvedSynchronous = clockOrOptions.synchronous ?? "FULL";
      resolvedFatalTaint = clockOrOptions.onFatalTaint;
      resolvedBusyTimeout = clockOrOptions.busyTimeoutMs;
    }

    this.clock = resolvedClock;
    this.allowLegacyArtifactVersions = resolvedLegacy;
    this.onFatalTaint = resolvedFatalTaint;

    this.clockGuard =
      resolvedGuard ??
      new ClockGuard(this.clock, resolvedMonotonic, {
        maxStartupForwardGapSeconds: resolvedGap,
      });

    this.db = new DatabaseSync(databasePath);

    try {
      this.db.exec("PRAGMA journal_mode = WAL;");
    } catch {
      // Ignored for in-memory or unsupported database configurations
    }
    const syncMode = ["OFF", "NORMAL", "FULL", "EXTRA"].includes(resolvedSynchronous)
      ? resolvedSynchronous
      : "FULL";
    try {
      this.db.exec(`PRAGMA synchronous = ${syncMode};`);
    } catch {
      // Ignored for in-memory or unsupported database configurations
    }
    const busyTimeout =
      typeof resolvedBusyTimeout === "number" &&
      Number.isFinite(resolvedBusyTimeout) &&
      resolvedBusyTimeout >= 0
        ? Math.floor(resolvedBusyTimeout)
        : 5000;
    this.db.exec(`PRAGMA busy_timeout = ${busyTimeout};`);

    try {
      this.initializeSchema();
    } catch (err) {
      try {
        this.db.close();
      } catch {}
      throw err;
    }
  }

  isTainted(): boolean {
    return this.tainted || this.clockGuard.isTainted();
  }

  getTaintedReason(): string | undefined {
    return this.taintedReason ?? this.clockGuard.getTaintedReason();
  }

  markTainted(reason: string): void {
    if (this.tainted) {
      return;
    }
    this.tainted = true;
    this.taintedReason = reason;
    this.clockGuard.taintConnection(reason);
    try {
      this.db.close();
    } catch {}
    if (this.onFatalTaint) {
      try {
        this.onFatalTaint(reason);
      } catch {}
    }
  }

  private handleFatalIO(err: unknown): void {
    if (isFatalIOError(err) && !this.isTainted()) {
      this.markTainted(
        `Fatal storage I/O error: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  getClockGuard(): ClockGuard {
    return this.clockGuard;
  }

  isLegacyAllowed(): boolean {
    return this.allowLegacyArtifactVersions;
  }

  getAllowLegacyArtifactVersions(): boolean {
    return this.allowLegacyArtifactVersions;
  }

  private initializeSchema(): void {
    withImmediateTransaction(this.db, () => {
      // 1. Recover from interrupted migration if applicable.
      // If consumed_authorization_ids_v3 exists but consumed_authorization_ids does NOT,
      // consumed_authorization_ids_v3 contains the only surviving copy of data.
      const tableRows = this.db.prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table'",
      ).all() as Array<{ name: string }>;
      const tableNames = new Set(tableRows.map((t) => t.name));

      if (
        !tableNames.has("consumed_authorization_ids") &&
        tableNames.has("consumed_authorization_ids_v3")
      ) {
        this.db.exec(
          "ALTER TABLE consumed_authorization_ids_v3 RENAME TO consumed_authorization_ids;",
        );
        tableNames.delete("consumed_authorization_ids_v3");
        tableNames.add("consumed_authorization_ids");
      } else if (
        tableNames.has("consumed_authorization_ids") &&
        tableNames.has("consumed_authorization_ids_v3")
      ) {
        // Both tables exist. Verify whether v3 is provably identical or an empty temp table.
        // If conflicting or differing, fail closed and preserve both tables for investigation.
        this.resolveMultiTableAmbiguity();
        tableNames.delete("consumed_authorization_ids_v3");
      }

      if (
        !tableNames.has("policy_budget_accumulators") &&
        tableNames.has("policy_budget_accumulators_v2")
      ) {
        throw new Error(
          "Incomplete or ambiguous migration state: canonical table 'policy_budget_accumulators' is missing but staging table 'policy_budget_accumulators_v2' exists. Halting startup to prevent unverified budget reset; manual database inspection required.",
        );
      } else if (
        tableNames.has("policy_budget_accumulators") &&
        tableNames.has("policy_budget_accumulators_v2")
      ) {
        this.resolveBudgetAccumulatorsAmbiguity();
        tableNames.delete("policy_budget_accumulators_v2");
      }

      // 2. Fresh database setup
      if (!tableNames.has("consumed_authorization_ids")) {
        this.db.exec(`
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
        `);
      } else {
        // 3. Inspect existing table structure under the transaction lock
        const columns = this.db.prepare(
          "PRAGMA table_info(consumed_authorization_ids)",
        ).all() as Array<{ name: string; notnull: number }>;
        const colMap = new Map(columns.map((c) => [c.name, c]));
        const masterRow = this.db.prepare(
          "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'consumed_authorization_ids'",
        ).get() as { sql: string } | undefined;
        const tableSql = masterRow ? masterRow.sql : "";

        const isFullyMigrated =
          colMap.has("key_id") &&
          colMap.has("issued_at_seconds") &&
          tableSql.includes("legacy_void") &&
          colMap.get("consumed_at")?.notnull === 0;

        if (!isFullyMigrated) {
          const hasBindingDigest = colMap.has("binding_digest");
          const hasState = colMap.has("state");
          const hasConsumedAt = colMap.has("consumed_at");
          const hasArtifactVersion = colMap.has("artifact_version");
          const hasKeyId = colMap.has("key_id");
          const hasIssuedAt = colMap.has("issued_at_seconds");

          const bindingExpr = hasBindingDigest ? "binding_digest" : "NULL";
          const stateExpr = `
            CASE
              WHEN ${hasState ? "state" : "'consumed'"} = 'issued'
                AND ${hasArtifactVersion ? "artifact_version" : "1"} = 2
                AND ${hasKeyId ? "(key_id IS NULL OR TRIM(key_id) = '')" : "1=1"}
                THEN 'legacy_void'
              ELSE COALESCE(${hasState ? "state" : "'consumed'"}, 'consumed')
            END
          `;
          const consumedAtExpr = hasConsumedAt ? "consumed_at" : "NULL";
          const versionExpr = hasArtifactVersion ? "COALESCE(artifact_version, 1)" : "1";
          const keyIdExpr = hasKeyId ? "key_id" : "NULL";
          const issuedAtExpr = hasIssuedAt ? "issued_at_seconds" : "NULL";

          // Query any non-automatic indexes to preserve them
          const indexes = this.db.prepare(
            "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'consumed_authorization_ids' AND sql IS NOT NULL",
          ).all() as Array<{ name: string; sql: string }>;

          this.db.exec(`
            CREATE TABLE consumed_authorization_ids_v3 (
              authorization_id TEXT PRIMARY KEY,
              binding_digest TEXT,
              state TEXT NOT NULL DEFAULT 'consumed'
                CHECK (state IN ('issued', 'consumed', 'legacy_void', 'cancelled')),
              consumed_at TEXT,
              artifact_version INTEGER NOT NULL DEFAULT 1,
              key_id TEXT,
              issued_at_seconds INTEGER
            );

            INSERT INTO consumed_authorization_ids_v3 (
              authorization_id,
              binding_digest,
              state,
              consumed_at,
              artifact_version,
              key_id,
              issued_at_seconds
            )
            SELECT
              authorization_id,
              ${bindingExpr},
              ${stateExpr},
              ${consumedAtExpr},
              ${versionExpr},
              ${keyIdExpr},
              ${issuedAtExpr}
            FROM consumed_authorization_ids;

            DROP TABLE consumed_authorization_ids;
            ALTER TABLE consumed_authorization_ids_v3 RENAME TO consumed_authorization_ids;
          `);

          for (const idx of indexes) {
            this.db.exec(idx.sql);
          }
        }
      }

      // 4. Governance tables (under the same transaction)
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS system_clock_state (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          high_water_seconds INTEGER NOT NULL,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
      `);

      this.ensureGovernanceTables();

      const existingClockRow = this.db.prepare(
        "SELECT high_water_seconds FROM system_clock_state WHERE id = 1"
      ).get() as { high_water_seconds: number } | undefined;

      const currentNow = this.clock.nowSeconds();

      if (!existingClockRow) {
        this.db.prepare(`
          INSERT INTO system_clock_state (id, high_water_seconds)
          VALUES (1, ?)
        `).run(currentNow);
      } else {
        const startupGap = currentNow - existingClockRow.high_water_seconds;
        if (startupGap > this.clockGuard.getMaxStartupForwardGapSeconds()) {
          throw new Error(
            `Store startup rejected: forward clock gap of ${startupGap} seconds exceeds maximum allowed startup threshold (${this.clockGuard.getMaxStartupForwardGapSeconds()}s).`
          );
        }
      }
    });
  }

  private resolveMultiTableAmbiguity(): void {
    const v3Count = (
      this.db.prepare(
        "SELECT COUNT(*) AS c FROM consumed_authorization_ids_v3",
      ).get() as { c: number }
    ).c;

    if (v3Count === 0) {
      this.db.exec("DROP TABLE consumed_authorization_ids_v3;");
      return;
    }

    const origCols = this.db.prepare(
      "PRAGMA table_info(consumed_authorization_ids)",
    ).all() as Array<{ name: string }>;
    const v3Cols = this.db.prepare(
      "PRAGMA table_info(consumed_authorization_ids_v3)",
    ).all() as Array<{ name: string }>;

    const origColNames = origCols.map((c) => c.name).sort();
    const v3ColNames = v3Cols.map((c) => c.name).sort();

    if (
      origColNames.length !== v3ColNames.length ||
      origColNames.some((col, idx) => col !== v3ColNames[idx])
    ) {
      throw new Error(
        "Ambiguous migration state: both consumed_authorization_ids and consumed_authorization_ids_v3 exist with conflicting schemas. Halting to preserve data for investigation.",
      );
    }

    const origCount = (
      this.db.prepare(
        "SELECT COUNT(*) AS c FROM consumed_authorization_ids",
      ).get() as { c: number }
    ).c;

    if (origCount !== v3Count) {
      throw new Error(
        `Ambiguous migration state: both consumed_authorization_ids (${origCount} rows) and consumed_authorization_ids_v3 (${v3Count} rows) exist with different row counts. Halting to preserve data for investigation.`,
      );
    }

    const selectCols = origCols.map((c) => c.name).join(", ");
    const diff1 = (
      this.db.prepare(`
        SELECT ${selectCols} FROM consumed_authorization_ids
        EXCEPT
        SELECT ${selectCols} FROM consumed_authorization_ids_v3
      `).all() as Array<unknown>
    );

    const diff2 = (
      this.db.prepare(`
        SELECT ${selectCols} FROM consumed_authorization_ids_v3
        EXCEPT
        SELECT ${selectCols} FROM consumed_authorization_ids
      `).all() as Array<unknown>
    );

    if (diff1.length > 0 || diff2.length > 0) {
      throw new Error(
        "Ambiguous migration state: both consumed_authorization_ids and consumed_authorization_ids_v3 exist with conflicting row contents. Halting to preserve data for investigation.",
      );
    }

    this.db.exec("DROP TABLE consumed_authorization_ids_v3;");
  }

  private resolveBudgetAccumulatorsAmbiguity(): void {
    const v2Count = (
      this.db.prepare(
        "SELECT COUNT(*) AS c FROM policy_budget_accumulators_v2",
      ).get() as { c: number }
    ).c;

    if (v2Count === 0) {
      this.db.exec("DROP TABLE policy_budget_accumulators_v2;");
      return;
    }

    const origCols = (this.db.prepare(
      "PRAGMA table_info(policy_budget_accumulators)",
    ).all() as Array<{ name: string }>).map((c) => c.name).sort();

    const v2Cols = (this.db.prepare(
      "PRAGMA table_info(policy_budget_accumulators_v2)",
    ).all() as Array<{ name: string }>).map((c) => c.name).sort();

    if (
      origCols.length !== v2Cols.length ||
      origCols.some((col, idx) => col !== v2Cols[idx])
    ) {
      throw new Error(
        "Ambiguous migration state: both policy_budget_accumulators and policy_budget_accumulators_v2 exist with conflicting schemas. Halting to preserve data for investigation.",
      );
    }

    const origCount = (
      this.db.prepare(
        "SELECT COUNT(*) AS c FROM policy_budget_accumulators",
      ).get() as { c: number }
    ).c;

    if (origCount !== v2Count) {
      throw new Error(
        `Ambiguous migration state: both policy_budget_accumulators (${origCount} rows) and policy_budget_accumulators_v2 (${v2Count} rows) exist with different row counts. Halting to preserve data for investigation.`,
      );
    }

    const selectCols = "policy_id, window_type, window_start, spent_amount, last_updated_at";
    const diff1 = (
      this.db.prepare(`
        SELECT ${selectCols} FROM policy_budget_accumulators
        EXCEPT
        SELECT ${selectCols} FROM policy_budget_accumulators_v2
      `).all() as Array<unknown>
    );

    const diff2 = (
      this.db.prepare(`
        SELECT ${selectCols} FROM policy_budget_accumulators_v2
        EXCEPT
        SELECT ${selectCols} FROM policy_budget_accumulators
      `).all() as Array<unknown>
    );

    if (diff1.length > 0 || diff2.length > 0) {
      throw new Error(
        "Ambiguous migration state: both policy_budget_accumulators and policy_budget_accumulators_v2 exist with conflicting row contents. Halting to preserve data for investigation.",
      );
    }

    this.db.exec("DROP TABLE policy_budget_accumulators_v2;");
  }

  private migrateBudgetAccumulators(): void {
    const columns = this.db.prepare(
      "PRAGMA table_info(policy_budget_accumulators)",
    ).all() as Array<{
      name: string;
      type: string;
      notnull: number;
      pk: number;
    }>;
    const colMap = new Map(columns.map((c) => [c.name, c]));

    const masterRow = this.db.prepare(
      "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'policy_budget_accumulators'",
    ).get() as { sql: string } | undefined;
    const tableSql = masterRow?.sql ?? "";

    const fkList = this.db.prepare(
      "PRAGMA foreign_key_list(policy_budget_accumulators)",
    ).all() as Array<{
      table: string;
      from: string;
      to: string;
      on_delete: string;
    }>;

    // 1. Verify standard composite schema structure common to both M8 and strict M9:
    // Exactly 5 columns with correct types, NOT NULL constraints, and composite primary key (policy_id, window_type, window_start)
    const hasExpectedColumns =
      columns.length === 5 &&
      colMap.get("policy_id")?.type === "TEXT" &&
      colMap.get("policy_id")?.notnull === 1 &&
      colMap.get("policy_id")?.pk === 1 &&
      colMap.get("window_type")?.type === "TEXT" &&
      colMap.get("window_type")?.notnull === 1 &&
      colMap.get("window_type")?.pk === 2 &&
      colMap.get("window_start")?.type === "INTEGER" &&
      colMap.get("window_start")?.notnull === 1 &&
      colMap.get("window_start")?.pk === 3 &&
      colMap.get("spent_amount")?.type === "TEXT" &&
      colMap.get("spent_amount")?.notnull === 1 &&
      colMap.get("spent_amount")?.pk === 0 &&
      colMap.get("last_updated_at")?.type === "TEXT" &&
      colMap.get("last_updated_at")?.notnull === 1 &&
      colMap.get("last_updated_at")?.pk === 0;

    const hasExpectedForeignKey =
      fkList.length === 1 &&
      fkList[0].table.toLowerCase() === "policies" &&
      fkList[0].from.toLowerCase() === "policy_id" &&
      fkList[0].to.toLowerCase() === "policy_id" &&
      fkList[0].on_delete.toUpperCase() === "CASCADE";

    const hasExpectedWindowTypeCheck =
      /window_type\s+IN\s*\(\s*['"]HOURLY['"]\s*,\s*['"]DAILY['"]\s*\)/i.test(tableSql);

    const hasStrictNumericCheck =
      /length\(spent_amount\)\s*>\s*0/i.test(tableSql) &&
      /length\(spent_amount\)\s*<=\s*78/i.test(tableSql) &&
      /NOT\s*\(?\s*spent_amount\s+GLOB\s+['"]\*\[\^0-9\]\*['"]\s*\)?/i.test(tableSql);

    const isStrictSchema =
      hasExpectedColumns &&
      hasExpectedForeignKey &&
      hasExpectedWindowTypeCheck &&
      hasStrictNumericCheck;

    if (isStrictSchema) {
      this.db.exec(`
        CREATE INDEX IF NOT EXISTS idx_budget_accumulators_lookup
          ON policy_budget_accumulators (policy_id, window_type, window_start);
      `);
      return;
    }

    // 2. Check if the schema matches the recognized supported M8 legacy schema
    const hasM8NumericCheck =
      /length\(spent_amount\)\s*<=\s*78/i.test(tableSql) &&
      /spent_amount\s+GLOB\s+['"]\[0-9\]\*['"]/i.test(tableSql) &&
      !tableSql.includes("*[^0-9]*");

    const isSupportedM8Legacy =
      hasExpectedColumns &&
      hasExpectedForeignKey &&
      hasExpectedWindowTypeCheck &&
      hasM8NumericCheck;

    if (!isSupportedM8Legacy) {
      throw new Error(
        "Cannot migrate policy_budget_accumulators: table schema does not match either the verified strict schema or the supported Milestone 8 legacy schema. Halting startup to prevent data loss or destructive repair; manual database inspection required.",
      );
    }

    // 1. Pre-validate every existing spent_amount and row integrity.
    // If ANY row is malformed, abort initialization with a clear migration error.
    // Never delete, sanitize, truncate, or reset malformed accumulators.
    const rows = this.db.prepare(
      "SELECT policy_id, window_type, window_start, spent_amount FROM policy_budget_accumulators",
    ).all() as Array<{ policy_id: unknown; window_type: unknown; window_start: unknown; spent_amount: unknown }>;

    const invalidRows: Array<{ policy_id: unknown; window_type: unknown; window_start: unknown; spent_amount: unknown }> = [];

    for (const r of rows) {
      const isPolicyValid = typeof r.policy_id === "string" && r.policy_id.length > 0;
      const isWindowTypeValid = r.window_type === "HOURLY" || r.window_type === "DAILY";
      const isWindowStartValid = typeof r.window_start === "number" && Number.isSafeInteger(r.window_start) && r.window_start >= 0;
      const isSpentValid =
        typeof r.spent_amount === "string" &&
        r.spent_amount.length > 0 &&
        r.spent_amount.length <= 78 &&
        /^[0-9]+$/.test(r.spent_amount);

      if (!isPolicyValid || !isWindowTypeValid || !isWindowStartValid || !isSpentValid) {
        invalidRows.push(r);
      }
    }

    if (invalidRows.length > 0) {
      const sample = invalidRows.slice(0, 3).map(
        (r) => `(policy_id: '${r.policy_id}', window_type: '${r.window_type}', window_start: ${r.window_start}, spent_amount: '${r.spent_amount}')`,
      ).join(", ");
      throw new Error(
        `Cannot migrate policy_budget_accumulators: table contains ${invalidRows.length} malformed accumulator row(s) failing strict numeric validation [${sample}]. Migration halted to prevent silent budget reset or data loss; original table preserved for investigation.`,
      );
    }

    // 2. Query any non-automatic indexes to preserve them
    const indexes = this.db.prepare(
      "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'policy_budget_accumulators' AND sql IS NOT NULL",
    ).all() as Array<{ name: string; sql: string }>;

    // 3. Atomically rebuild table with strict schema
    this.db.exec(`
      CREATE TABLE policy_budget_accumulators_v2 (
        policy_id TEXT NOT NULL,
        window_type TEXT NOT NULL CHECK (window_type IN ('HOURLY', 'DAILY')),
        window_start INTEGER NOT NULL,
        spent_amount TEXT NOT NULL CHECK (length(spent_amount) > 0 AND length(spent_amount) <= 78 AND NOT (spent_amount GLOB '*[^0-9]*')),
        last_updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (policy_id, window_type, window_start),
        FOREIGN KEY (policy_id) REFERENCES policies(policy_id) ON DELETE CASCADE
      );

      INSERT INTO policy_budget_accumulators_v2 (
        policy_id,
        window_type,
        window_start,
        spent_amount,
        last_updated_at
      )
      SELECT
        policy_id,
        window_type,
        window_start,
        spent_amount,
        last_updated_at
      FROM policy_budget_accumulators;

      DROP TABLE policy_budget_accumulators;
      ALTER TABLE policy_budget_accumulators_v2 RENAME TO policy_budget_accumulators;
    `);

    for (const idx of indexes) {
      this.db.exec(idx.sql);
    }

    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_budget_accumulators_lookup
        ON policy_budget_accumulators (policy_id, window_type, window_start);
    `);
  }

  private ensureGovernanceTables(): void {
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
    } else {
      const cols = (this.db.prepare("PRAGMA table_info(policies)").all() as Array<{ name: string }>).map((c) => c.name);
      if (!cols.includes("updated_at") || !cols.includes("current_revision")) {
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
    } else {
      const cols = (this.db.prepare("PRAGMA table_info(policy_revisions)").all() as Array<{ name: string }>).map((c) => c.name);
      if (!cols.includes("created_at") || !cols.includes("revision")) {
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

    if (!tables.includes("issuer_keys")) {
      this.db.exec(`
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
      `);
    } else {
      const cols = (this.db.prepare("PRAGMA table_info(issuer_keys)").all() as Array<{ name: string }>).map((c) => c.name);
      const masterRow = this.db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'issuer_keys'").get() as { sql: string } | undefined;
      const sql = masterRow?.sql ?? "";
      const hasAllCols = cols.includes("retired_at_seconds") && cols.includes("revoked_at_seconds") && cols.includes("valid_from_seconds") && cols.includes("expires_at_seconds");
      const hasCheck = sql.includes("active") && sql.includes("retired") && sql.includes("revoked");

      if (!hasAllCols || !hasCheck) {
        const indexes = this.db.prepare(
          "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'issuer_keys' AND sql IS NOT NULL"
        ).all() as Array<{ name: string; sql: string }>;

        this.db.exec(`
          CREATE TABLE issuer_keys_temp (
            key_id TEXT PRIMARY KEY,
            public_key_pem TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired', 'revoked')),
            valid_from_seconds INTEGER,
            expires_at_seconds INTEGER,
            retired_at_seconds INTEGER,
            revoked_at_seconds INTEGER,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
          );
          INSERT INTO issuer_keys_temp (
            key_id, public_key_pem, status, valid_from_seconds, expires_at_seconds,
            retired_at_seconds, revoked_at_seconds, created_at
          )
          SELECT
            key_id,
            public_key_pem,
            ${cols.includes("status") ? "CASE WHEN status IN ('active', 'retired', 'revoked') THEN status ELSE 'active' END" : "'active'"},
            ${cols.includes("valid_from_seconds") ? "valid_from_seconds" : "NULL"},
            ${cols.includes("expires_at_seconds") ? "expires_at_seconds" : "NULL"},
            ${cols.includes("retired_at_seconds") ? "retired_at_seconds" : "NULL"},
            ${cols.includes("revoked_at_seconds") ? "revoked_at_seconds" : "NULL"},
            ${cols.includes("created_at") ? "COALESCE(created_at, CURRENT_TIMESTAMP)" : "CURRENT_TIMESTAMP"}
          FROM issuer_keys;
          DROP TABLE issuer_keys;
          ALTER TABLE issuer_keys_temp RENAME TO issuer_keys;
        `);

        for (const idx of indexes) {
          this.db.exec(idx.sql);
        }
      }
    }

    // Milestone 8 & 9: Policy budget accumulators for cumulative spending windows
    if (!tables.includes("policy_budget_accumulators")) {
      this.db.exec(`
        CREATE TABLE policy_budget_accumulators (
          policy_id TEXT NOT NULL,
          window_type TEXT NOT NULL CHECK (window_type IN ('HOURLY', 'DAILY')),
          window_start INTEGER NOT NULL,
          spent_amount TEXT NOT NULL CHECK (length(spent_amount) > 0 AND length(spent_amount) <= 78 AND NOT (spent_amount GLOB '*[^0-9]*')),
          last_updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (policy_id, window_type, window_start),
          FOREIGN KEY (policy_id) REFERENCES policies(policy_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_budget_accumulators_lookup
          ON policy_budget_accumulators (policy_id, window_type, window_start);
      `);
    } else {
      this.migrateBudgetAccumulators();
    }
  }

  /**
   * Retrieves the current accumulated spend for a specific policy and window bucket.
   */
  getPolicyBudgetAccumulator(
    policyId: string,
    windowType: BudgetWindowType,
    windowStart: number,
  ): { spentAmount: string; lastUpdatedAt: string } | null {
    if (this.isTainted()) {
      throw new Error(`SQLiteAuthorizationStore database connection is tainted and unusable: ${this.getTaintedReason()}`);
    }
    const row = this.db.prepare(`
      SELECT spent_amount, last_updated_at
      FROM policy_budget_accumulators
      WHERE policy_id = ? AND window_type = ? AND window_start = ?
    `).get(policyId, windowType, windowStart) as { spent_amount: string; last_updated_at: string } | undefined;

    return row ? { spentAmount: row.spent_amount, lastUpdatedAt: row.last_updated_at } : null;
  }

  /**
   * Lists all historical budget accumulator buckets for a policy.
   */
  listPolicyBudgetAccumulators(
    policyId: string,
  ): Array<{ windowType: BudgetWindowType; windowStart: number; spentAmount: string; lastUpdatedAt: string }> {
    if (this.isTainted()) {
      throw new Error(`SQLiteAuthorizationStore database connection is tainted and unusable: ${this.getTaintedReason()}`);
    }
    const rows = this.db.prepare(`
      SELECT window_type, window_start, spent_amount, last_updated_at
      FROM policy_budget_accumulators
      WHERE policy_id = ?
      ORDER BY window_start DESC
    `).all(policyId) as Array<{
      window_type: BudgetWindowType;
      window_start: number;
      spent_amount: string;
      last_updated_at: string;
    }>;

    return rows.map((r) => ({
      windowType: r.window_type,
      windowStart: r.window_start,
      spentAmount: r.spent_amount,
      lastUpdatedAt: r.last_updated_at,
    }));
  }

  /**
   * Advances the persisted clock high-water mark.
   * Throws an Error if a clock rollback is detected.
   * Persists forward time advancement immediately and independently of subsequent business validation.
   */
  advanceHighWaterMark(nowSeconds: number): void {
    if (!Number.isSafeInteger(nowSeconds) || nowSeconds < 0) {
      throw new Error("Evaluation timestamp must be a non-negative safe integer.");
    }
    if (this.isTainted()) {
      throw new Error(
        `SQLiteAuthorizationStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }

    if (!this.clockGuard.acquireLock()) {
      throw new Error("Concurrent transaction in progress within same process; operation serialized.");
    }

    try {
      if (this.clock instanceof TestClock && nowSeconds > this.clock.nowSeconds()) {
        this.clock.advance(nowSeconds - this.clock.nowSeconds());
      }

      const candidate: ClockCandidate = {
        wallSeconds: nowSeconds,
        monotonicNanos: this.clockGuard.getMonotonicClock().nowNanoseconds(),
      };

      try {
        withImmediateTransaction(
          this.db,
          () => {
            const row = this.db.prepare(
              "SELECT high_water_seconds FROM system_clock_state WHERE id = 1",
            ).get() as { high_water_seconds: number } | undefined;

            if (!row) {
              this.db.prepare(
                "INSERT INTO system_clock_state (id, high_water_seconds) VALUES (1, ?)",
              ).run(nowSeconds);
              return;
            }

            const clockEval = this.clockGuard.evaluateCandidate(candidate, row.high_water_seconds);
            if (clockEval.decision !== "ALLOW") {
              throw new Error(clockEval.reason);
            }

            if (nowSeconds < row.high_water_seconds) {
              throw new Error(
                `Clock rollback detected: current time (${nowSeconds}s) precedes persisted high-water mark (${row.high_water_seconds}s).`,
              );
            }

            if (nowSeconds > row.high_water_seconds) {
              this.db.prepare(`
                UPDATE system_clock_state
                SET high_water_seconds = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = 1 AND high_water_seconds < ?
              `).run(nowSeconds, nowSeconds);
            }
          },
          undefined,
          undefined,
          undefined,
          () => {
            this.clockGuard.publishCandidate(candidate);
          },
          (commitErr) => {
            this.markTainted(
              `Commit failure with uncertain outcome: ${commitErr instanceof Error ? commitErr.message : String(commitErr)}`,
            );
          },
          (rollbackErr) => {
            this.markTainted(
              `Fatal rollback failure: ${rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr)}`,
            );
          },
        );
      } catch (err) {
        this.handleFatalIO(err);
        throw err;
      }
    } finally {
      this.clockGuard.releaseLock();
    }
  }

  getHighWaterMark(): number | null {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteAuthorizationStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    try {
      const row = this.db.prepare(
        "SELECT high_water_seconds FROM system_clock_state WHERE id = 1",
      ).get() as { high_water_seconds: number } | undefined;
      return row ? row.high_water_seconds : null;
    } catch (err) {
      this.handleFatalIO(err);
      throw err;
    }
  }

  getClock(): Clock {
    return this.clock;
  }

  /**
   * Returns true only when this call reserves a previously unused ID.
   * Legacy reservations are classified as artifact_version = 1.
   */
  reserve(authorizationId: string): boolean {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteAuthorizationStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    if (authorizationId.length > 128) {
      throw new Error("Authorization ID exceeds maximum length of 128 characters.");
    }
    if (!this.allowLegacyArtifactVersions) {
      throw new Error("Legacy authorization artifact versions are disabled by configuration.");
    }

    try {
      const result = this.db.prepare(`
        INSERT INTO consumed_authorization_ids (authorization_id, state, consumed_at, artifact_version)
        VALUES (?, 'consumed', CURRENT_TIMESTAMP, 1)
        ON CONFLICT(authorization_id) DO NOTHING
      `).run(authorizationId);

      return result.changes === 1;
    } catch (err) {
      this.handleFatalIO(err);
      throw err;
    }
  }

  /**
   * Persist a previously unused authorization ID, expected binding, artifact version,
   * and optional key ID and issuance timestamp.
   * A newly issued authorization has consumed_at = NULL.
   */
  issueBound(
    authorizationId: string,
    bindingDigest: string,
    version: number = 1,
    keyId?: string,
    issuedAtSeconds?: number,
  ): boolean {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteAuthorizationStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    if (authorizationId.length > 128) {
      throw new Error("Authorization ID exceeds maximum length of 128 characters.");
    }
    if (version !== 3 && !this.allowLegacyArtifactVersions) {
      throw new Error("Legacy authorization artifact versions are disabled by configuration.");
    }

    try {
      const result = this.db.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, artifact_version, key_id, issued_at_seconds
        ) VALUES (?, ?, 'issued', NULL, ?, ?, ?)
        ON CONFLICT(authorization_id) DO NOTHING
      `).run(
        authorizationId,
        bindingDigest,
        version,
        keyId ?? null,
        issuedAtSeconds ?? null,
      );

      return result.changes === 1;
    } catch (err) {
      this.handleFatalIO(err);
      throw err;
    }
  }

  /**
   * Atomically consume one issued ID only when its binding and artifact version match exactly.
   * If keyId and issuedAtSeconds are provided, they must match exactly as well.
   * Sets consumed_at = CURRENT_TIMESTAMP upon successful transition.
   */
  consumeBound(
    authorizationId: string,
    bindingDigest: string,
    version: number = 1,
    keyId?: string,
    issuedAtSeconds?: number,
  ): boolean {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteAuthorizationStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    if (authorizationId.length > 128) {
      throw new Error("Authorization ID exceeds maximum length of 128 characters.");
    }
    if (version !== 3 && !this.allowLegacyArtifactVersions) {
      throw new Error("Legacy authorization artifact versions are disabled by configuration.");
    }
    try {
      if (keyId !== undefined && issuedAtSeconds !== undefined) {
        const result = this.db.prepare(`
          UPDATE consumed_authorization_ids
          SET state = 'consumed', consumed_at = CURRENT_TIMESTAMP
          WHERE authorization_id = ?
            AND binding_digest = ?
            AND state = 'issued'
            AND artifact_version = ?
            AND key_id = ?
            AND issued_at_seconds = ?
        `).run(authorizationId, bindingDigest, version, keyId, issuedAtSeconds);

        return result.changes === 1;
      }

      const result = this.db.prepare(`
        UPDATE consumed_authorization_ids
        SET state = 'consumed', consumed_at = CURRENT_TIMESTAMP
        WHERE authorization_id = ?
          AND binding_digest = ?
          AND state = 'issued'
          AND artifact_version = ?
      `).run(authorizationId, bindingDigest, version);

      return result.changes === 1;
    } catch (err) {
      this.handleFatalIO(err);
      throw err;
    }
  }

  /**
   * Atomically cancels an issued, unconsumed authorization.
   *
   * Only transitions an authorization record from 'issued' to 'cancelled'.
   * Returns true if the authorization was successfully cancelled.
   * Returns false if the authorization is unknown, already consumed, already cancelled,
   * or not in 'issued' state.
   * Throws an Error if authorizationId exceeds maximum length of 128 characters,
   * or if the record is a legacy artifact version when legacy artifacts are disabled.
   */
  cancelAuthorization(authorizationId: string): boolean {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteAuthorizationStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    if (this.clockGuard.getState() === "TRIPPED_CLOSED") {
      throw new Error(
        `Store clock monitor is in a tripped state: ${this.clockGuard.getTripReason()}`,
      );
    }
    if (this.clockGuard.getState() === "EXPIRED") {
      throw new Error(
        "Process clock anchor has expired (maximum uptime exceeded); restart required.",
      );
    }
    if (typeof authorizationId !== "string") {
      return false;
    }
    const normalized = authorizationId.trim();
    if (normalized.length === 0) {
      return false;
    }
    if (normalized.length > 128) {
      throw new Error("Authorization ID exceeds maximum length of 128 characters.");
    }

    if (!this.clockGuard.acquireLock()) {
      throw new Error(
        "Concurrent transaction in progress within same process; ClockGuard lock acquisition failed.",
      );
    }

    try {
      try {
        return withImmediateTransaction(
          this.db,
          () => {
            const row = this.db.prepare(
              "SELECT artifact_version, state FROM consumed_authorization_ids WHERE authorization_id = ?"
            ).get(normalized) as { artifact_version: number; state: string } | undefined;

            if (!row || row.state !== "issued") {
              return false;
            }

            if (row.artifact_version !== 3 && !this.allowLegacyArtifactVersions) {
              throw new Error("Legacy authorization artifact versions are disabled by configuration.");
            }

            const result = this.db.prepare(`
              UPDATE consumed_authorization_ids
              SET state = 'cancelled', consumed_at = CURRENT_TIMESTAMP
              WHERE authorization_id = ? AND state = 'issued'
            `).run(normalized);

            return result.changes === 1;
          },
          undefined,
          undefined,
          undefined,
          undefined,
          (commitErr) => {
            this.markTainted(
              `Commit failure with uncertain outcome: ${commitErr instanceof Error ? commitErr.message : String(commitErr)}`,
            );
          },
          (rollbackErr) => {
            this.markTainted(
              `Fatal rollback failure: ${rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr)}`,
            );
          },
        );
      } catch (err) {
        this.handleFatalIO(err);
        throw err;
      }
    } finally {
      this.clockGuard.releaseLock();
    }
  }

  getDatabase(): DatabaseSync {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteAuthorizationStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    return this.db;
  }

  getPolicyStore(): SQLitePolicyStore {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteAuthorizationStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    return new SQLitePolicyStore(this.db, this.clock, this.clockGuard, {
      onFatalTaint: (reason) => this.markTainted(reason),
    });
  }

  getKeyStore(): SQLiteKeyStore {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteAuthorizationStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    return new SQLiteKeyStore(this.db, this.clock, this.clockGuard, {
      onFatalTaint: (reason) => this.markTainted(reason),
    });
  }

  getAuthorizationRecord(authorizationId: string): AuthorizationRecord | null {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteAuthorizationStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    try {
      const row = this.db.prepare(
        "SELECT * FROM consumed_authorization_ids WHERE authorization_id = ?"
      ).get(authorizationId) as {
        authorization_id: string;
        binding_digest: string | null;
        state: "issued" | "consumed" | "legacy_void" | "cancelled";
        consumed_at: string | null;
        artifact_version: number;
        key_id: string | null;
        issued_at_seconds: number | null;
      } | undefined;

      if (!row) return null;

      return {
        authorizationId: row.authorization_id,
        bindingDigest: row.binding_digest,
        state: row.state,
        consumedAt: row.consumed_at,
        artifactVersion: row.artifact_version,
        keyId: row.key_id,
        issuedAtSeconds: row.issued_at_seconds,
      };
    } catch (err) {
      this.handleFatalIO(err);
      throw err;
    }
  }

  getSynchronousMode(): SQLiteSynchronousMode {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteAuthorizationStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    try {
      const row = this.db.prepare("PRAGMA synchronous;").get() as { synchronous: number } | undefined;
      switch (row?.synchronous) {
        case 0:
          return "OFF";
        case 1:
          return "NORMAL";
        case 2:
          return "FULL";
        case 3:
          return "EXTRA";
        default:
          return "FULL";
      }
    } catch (err) {
      this.handleFatalIO(err);
      throw err;
    }
  }

  getJournalMode(): string {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteAuthorizationStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    try {
      const row = this.db.prepare("PRAGMA journal_mode;").get() as { journal_mode: string } | undefined;
      return row?.journal_mode ?? "unknown";
    } catch (err) {
      this.handleFatalIO(err);
      throw err;
    }
  }

  checkpoint(mode: CheckpointMode = "PASSIVE"): CheckpointResult {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteAuthorizationStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    const validModes: CheckpointMode[] = ["PASSIVE", "FULL", "RESTART", "TRUNCATE"];
    if (!validModes.includes(mode)) {
      throw new Error(
        `Invalid checkpoint mode: '${String(mode)}'. Valid modes are PASSIVE, FULL, RESTART, TRUNCATE.`,
      );
    }

    try {
      const row = this.db.prepare(`PRAGMA wal_checkpoint(${mode});`).get() as
        | { busy: number; log: number; checkpointed: number }
        | undefined;

      return {
        busy: row ? row.busy !== 0 : false,
        logFrames: row ? row.log : 0,
        checkpointedFrames: row ? row.checkpointed : 0,
      };
    } catch (err) {
      this.handleFatalIO(err);
      throw err;
    }
  }

  checkIntegrity(): boolean {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteAuthorizationStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    try {
      const rows = this.db.prepare("PRAGMA integrity_check;").all() as Array<{ integrity_check: string }>;
      return rows.length === 1 && rows[0].integrity_check === "ok";
    } catch (err) {
      this.handleFatalIO(err);
      throw err;
    }
  }

  close(): void {
    try {
      this.db.close();
    } catch {}
  }
}
