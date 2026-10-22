import { DatabaseSync } from "node:sqlite";

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
 */
export interface BoundAuthorizationIdStore extends AuthorizationIdStore {
  issueBound(authorizationId: string, bindingDigest: string): boolean;
  consumeBound(authorizationId: string, bindingDigest: string): boolean;
}

function addColumnIfMissing(db: DatabaseSync, sql: string): void {
  try {
    db.exec(sql);
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.toLowerCase().includes("duplicate column name")
    ) {
      return;
    }

    throw error;
  }
}

/**
 * Persistent, atomic authorization-ID reservation.
 * The database must be stored on a durable local filesystem and shared by
 * every caller that needs common replay protection.
 */
export class SQLiteAuthorizationStore implements BoundAuthorizationIdStore {
  private readonly db: DatabaseSync;

  constructor(databasePath: string) {
    this.db = new DatabaseSync(databasePath);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS consumed_authorization_ids (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT,
        state TEXT NOT NULL DEFAULT 'consumed'
          CHECK (state IN ('issued', 'consumed')),
        consumed_at TEXT
      )
    `);

    const columns = this.db.prepare(
      "PRAGMA table_info(consumed_authorization_ids)",
    ).all() as Array<{ name: string; notnull: number }>;
    const consumedAtCol = columns.find((c) => c.name === "consumed_at");

    // Legacy tables defined consumed_at as NOT NULL DEFAULT CURRENT_TIMESTAMP.
    // Migrate existing tables so consumed_at is nullable, allowing issued rows
    // to have consumed_at = NULL until atomic consumption.
    if (consumedAtCol && consumedAtCol.notnull === 1) {
      const hasBindingDigest = columns.some((c) => c.name === "binding_digest");
      const hasState = columns.some((c) => c.name === "state");
      const bindingExpr = hasBindingDigest ? "binding_digest" : "NULL";
      const stateExpr = hasState ? "COALESCE(state, 'consumed')" : "'consumed'";

      this.db.exec(`
        CREATE TABLE consumed_authorization_ids_v2 (
          authorization_id TEXT PRIMARY KEY,
          binding_digest TEXT,
          state TEXT NOT NULL DEFAULT 'consumed'
            CHECK (state IN ('issued', 'consumed')),
          consumed_at TEXT
        );
        INSERT INTO consumed_authorization_ids_v2 (
          authorization_id, binding_digest, state, consumed_at
        ) SELECT authorization_id, ${bindingExpr}, ${stateExpr}, consumed_at
          FROM consumed_authorization_ids;
        DROP TABLE consumed_authorization_ids;
        ALTER TABLE consumed_authorization_ids_v2 RENAME TO consumed_authorization_ids;
      `);
    } else {
      addColumnIfMissing(
        this.db,
        "ALTER TABLE consumed_authorization_ids ADD COLUMN binding_digest TEXT",
      );
      addColumnIfMissing(
        this.db,
        "ALTER TABLE consumed_authorization_ids ADD COLUMN state TEXT NOT NULL DEFAULT 'consumed'",
      );
      this.db.exec(`
        UPDATE consumed_authorization_ids
        SET state = 'consumed'
        WHERE state IS NULL
      `);
    }
  }

  /**
   * Returns true only when this call reserves a previously unused ID.
   */
  reserve(authorizationId: string): boolean {
    const result = this.db.prepare(`
      INSERT INTO consumed_authorization_ids (authorization_id, state, consumed_at)
      VALUES (?, 'consumed', CURRENT_TIMESTAMP)
      ON CONFLICT(authorization_id) DO NOTHING
    `).run(authorizationId);

    return result.changes === 1;
  }

  /**
   * Persist a previously unused authorization ID and its expected binding.
   * A newly issued authorization has consumed_at = NULL.
   */
  issueBound(authorizationId: string, bindingDigest: string): boolean {
    const result = this.db.prepare(`
      INSERT INTO consumed_authorization_ids (
        authorization_id, binding_digest, state, consumed_at
      ) VALUES (?, ?, 'issued', NULL)
      ON CONFLICT(authorization_id) DO NOTHING
    `).run(authorizationId, bindingDigest);

    return result.changes === 1;
  }

  /**
   * Atomically consume one issued ID only when its binding matches exactly.
   * Sets consumed_at = CURRENT_TIMESTAMP upon successful transition.
   */
  consumeBound(authorizationId: string, bindingDigest: string): boolean {
    const result = this.db.prepare(`
      UPDATE consumed_authorization_ids
      SET state = 'consumed', consumed_at = CURRENT_TIMESTAMP
      WHERE authorization_id = ?
        AND binding_digest = ?
        AND state = 'issued'
    `).run(authorizationId, bindingDigest);

    return result.changes === 1;
  }

  close(): void {
    this.db.close();
  }
}
