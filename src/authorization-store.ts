import { DatabaseSync } from "node:sqlite";
import { type Clock, systemClock } from "./clock.js";
import { SQLiteKeyStore } from "./key-store.js";
import { SQLitePolicyStore } from "./policy-store.js";

export * from "./policy-store.js";
export * from "./key-store.js";

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

  constructor(databasePath: string, clock: Clock = systemClock) {
    this.clock = clock;
    this.db = new DatabaseSync(databasePath);

    try {
      this.db.exec("PRAGMA journal_mode = WAL;");
    } catch {
      // Ignored for in-memory or unsupported database configurations
    }
    this.db.exec("PRAGMA busy_timeout = 5000;");

    try {
      this.initializeSchema();
    } catch (err) {
      try {
        this.db.close();
      } catch {}
      throw err;
    }
  }

  private initializeSchema(): void {
    this.db.exec("BEGIN IMMEDIATE;");
    try {
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

      // Safe initialization of clock high-water state
      this.db.prepare(`
        INSERT INTO system_clock_state (id, high_water_seconds)
        VALUES (1, ?)
        ON CONFLICT(id) DO NOTHING;
      `).run(this.clock.nowSeconds());

      this.db.exec("COMMIT;");
    } catch (err) {
      try {
        this.db.exec("ROLLBACK;");
      } catch {}
      throw err;
    }
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

    let attempt = 0;
    while (attempt < 3) {
      attempt++;
      try {
        this.db.exec("BEGIN IMMEDIATE;");
        break;
      } catch (err) {
        if (err instanceof Error && /busy|locked/i.test(err.message) && attempt < 3) {
          const start = Date.now();
          while (Date.now() - start < 25) {}
          continue;
        }
        throw new Error("Database is busy; transaction contention retry limit exceeded.");
      }
    }
    try {
      const row = this.db.prepare(
        "SELECT high_water_seconds FROM system_clock_state WHERE id = 1",
      ).get() as { high_water_seconds: number } | undefined;

      if (!row) {
        this.db.prepare(
          "INSERT INTO system_clock_state (id, high_water_seconds) VALUES (1, ?)",
        ).run(nowSeconds);
        this.db.exec("COMMIT;");
        return;
      }

      if (nowSeconds < row.high_water_seconds) {
        this.db.exec("ROLLBACK;");
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

      this.db.exec("COMMIT;");
    } catch (err) {
      try {
        this.db.exec("ROLLBACK;");
      } catch {}
      throw err;
    }
  }

  getHighWaterMark(): number | null {
    const row = this.db.prepare(
      "SELECT high_water_seconds FROM system_clock_state WHERE id = 1",
    ).get() as { high_water_seconds: number } | undefined;
    return row ? row.high_water_seconds : null;
  }

  getClock(): Clock {
    return this.clock;
  }

  /**
   * Returns true only when this call reserves a previously unused ID.
   * Legacy reservations are classified as artifact_version = 1.
   */
  reserve(authorizationId: string): boolean {
    const result = this.db.prepare(`
      INSERT INTO consumed_authorization_ids (authorization_id, state, consumed_at, artifact_version)
      VALUES (?, 'consumed', CURRENT_TIMESTAMP, 1)
      ON CONFLICT(authorization_id) DO NOTHING
    `).run(authorizationId);

    return result.changes === 1;
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
  }

  getDatabase(): DatabaseSync {
    return this.db;
  }

  getPolicyStore(): SQLitePolicyStore {
    return new SQLitePolicyStore(this.db, this.clock);
  }

  getKeyStore(): SQLiteKeyStore {
    return new SQLiteKeyStore(this.db, this.clock);
  }

  getAuthorizationRecord(authorizationId: string): {
    authorizationId: string;
    bindingDigest: string | null;
    state: "issued" | "consumed" | "legacy_void" | "cancelled";
    consumedAt: string | null;
    artifactVersion: number;
    keyId: string | null;
    issuedAtSeconds: number | null;
  } | null {
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
  }

  close(): void {
    this.db.close();
  }
}
