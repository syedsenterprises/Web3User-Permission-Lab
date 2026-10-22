import { DatabaseSync } from "node:sqlite";

export interface AuthorizationIdStore {
  reserve(authorizationId: string): boolean;
  close(): void;
}

/**
 * Persistent, atomic authorization-ID reservation.
 * The database must be stored on a durable local filesystem.
 */
export class SQLiteAuthorizationStore implements AuthorizationIdStore {
  private readonly db: DatabaseSync;

  constructor(databasePath: string) {
    this.db = new DatabaseSync(databasePath);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS consumed_authorization_ids (
        authorization_id TEXT PRIMARY KEY,
        consumed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
  }

  /**
   * Returns true only when this call reserves a previously unused ID.
   */
  reserve(authorizationId: string): boolean {
    const result = this.db.prepare(`
      INSERT INTO consumed_authorization_ids (authorization_id)
      VALUES (?)
      ON CONFLICT(authorization_id) DO NOTHING
    `).run(authorizationId);

    return result.changes === 1;
  }

  close(): void {
    this.db.close();
  }
}
