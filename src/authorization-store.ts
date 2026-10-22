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
 *
 * The optional version discriminator enforces artifact-version isolation:
 * a v1 consumption request only consumes records issued for v1, and a v2
 * consumption request only consumes records issued for v2. Defaults to 1.
 */
export interface BoundAuthorizationIdStore extends AuthorizationIdStore {
  issueBound(authorizationId: string, bindingDigest: string, version?: number): boolean;
  consumeBound(authorizationId: string, bindingDigest: string, version?: number): boolean;
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
 * Persistent, atomic authorization-ID reservation with artifact-version discrimination.
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
        consumed_at TEXT,
        artifact_version INTEGER NOT NULL DEFAULT 1
      )
    `);

    const columns = this.db.prepare(
      "PRAGMA table_info(consumed_authorization_ids)",
    ).all() as Array<{ name: string; notnull: number }>;
    const consumedAtCol = columns.find((c) => c.name === "consumed_at");

    // Legacy tables defined consumed_at as NOT NULL DEFAULT CURRENT_TIMESTAMP.
    // Migrate existing tables so consumed_at is nullable, allowing issued rows
    // to have consumed_at = NULL until atomic consumption, and ensure artifact_version
    // is present with default = 1.
    if (consumedAtCol && consumedAtCol.notnull === 1) {
      const hasBindingDigest = columns.some((c) => c.name === "binding_digest");
      const hasState = columns.some((c) => c.name === "state");
      const hasVersion = columns.some((c) => c.name === "artifact_version");
      const bindingExpr = hasBindingDigest ? "binding_digest" : "NULL";
      const stateExpr = hasState ? "COALESCE(state, 'consumed')" : "'consumed'";
      const versionExpr = hasVersion ? "COALESCE(artifact_version, 1)" : "1";

      this.db.exec(`
        CREATE TABLE consumed_authorization_ids_v2 (
          authorization_id TEXT PRIMARY KEY,
          binding_digest TEXT,
          state TEXT NOT NULL DEFAULT 'consumed'
            CHECK (state IN ('issued', 'consumed')),
          consumed_at TEXT,
          artifact_version INTEGER NOT NULL DEFAULT 1
        );
        INSERT INTO consumed_authorization_ids_v2 (
          authorization_id, binding_digest, state, consumed_at, artifact_version
        ) SELECT authorization_id, ${bindingExpr}, ${stateExpr}, consumed_at, ${versionExpr}
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
      addColumnIfMissing(
        this.db,
        "ALTER TABLE consumed_authorization_ids ADD COLUMN artifact_version INTEGER NOT NULL DEFAULT 1",
      );
      this.db.exec(`
        UPDATE consumed_authorization_ids
        SET state = 'consumed'
        WHERE state IS NULL
      `);
      this.db.exec(`
        UPDATE consumed_authorization_ids
        SET artifact_version = 1
        WHERE artifact_version IS NULL
      `);
    }
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
   * Persist a previously unused authorization ID, expected binding, and artifact version.
   * A newly issued authorization has consumed_at = NULL.
   */
  issueBound(authorizationId: string, bindingDigest: string, version: number = 1): boolean {
    const result = this.db.prepare(`
      INSERT INTO consumed_authorization_ids (
        authorization_id, binding_digest, state, consumed_at, artifact_version
      ) VALUES (?, ?, 'issued', NULL, ?)
      ON CONFLICT(authorization_id) DO NOTHING
    `).run(authorizationId, bindingDigest, version);

    return result.changes === 1;
  }

  /**
   * Atomically consume one issued ID only when its binding and artifact version match exactly.
   * Sets consumed_at = CURRENT_TIMESTAMP upon successful transition.
   */
  consumeBound(authorizationId: string, bindingDigest: string, version: number = 1): boolean {
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

  close(): void {
    this.db.close();
  }
}
