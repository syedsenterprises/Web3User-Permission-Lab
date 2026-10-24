import { KeyObject } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { parseEd25519PublicKey } from "./authorization-crypto.js";
import {
  type Clock,
  systemClock,
  ClockGuard,
  type ClockCandidate,
  TestClock,
  type MonotonicClock,
} from "./clock.js";
import { type IssuerKeyMetadata, type KeyRegistry, type KeyStatus } from "./key-registry.js";
import { isFatalIOError, withImmediateTransaction } from "./sqlite-transaction.js";

export interface ImportIssuerKeyMetadata extends IssuerKeyMetadata {
  readonly retiredAtSeconds?: number;
  readonly revokedAtSeconds?: number;
}

export interface PersistedIssuerKeyMetadata extends IssuerKeyMetadata {
  readonly keyId: string;
  readonly publicKey: KeyObject;
  readonly publicKeyPem: string;
  readonly status: KeyStatus;
  readonly validFromSeconds?: number;
  readonly expiresAtSeconds?: number;
  readonly retiredAtSeconds?: number;
  readonly revokedAtSeconds?: number;
  readonly createdAt: string;
}

export type SQLiteSynchronousMode = "OFF" | "NORMAL" | "FULL" | "EXTRA";

export interface KeyStoreOptions {
  clock?: Clock;
  clockGuard?: ClockGuard;
  monotonicClock?: MonotonicClock;
  maxStartupForwardGapSeconds?: number;
  synchronous?: SQLiteSynchronousMode;
  onFatalTaint?: (reason: string) => void;
  busyTimeoutMs?: number;
}

export interface KeyStore extends KeyRegistry {
  registerKey(metadata: IssuerKeyMetadata): void;
  importKey(metadata: ImportIssuerKeyMetadata): void;
  getKey(keyId: string): PersistedIssuerKeyMetadata | null;
  getKeyStatus(keyId: string): KeyStatus | null;
  listKeys(statusFilter?: KeyStatus): PersistedIssuerKeyMetadata[];
  retireKey(keyId: string, retiredAtSeconds?: number): PersistedIssuerKeyMetadata;
  revokeKey(keyId: string, revokedAtSeconds?: number): PersistedIssuerKeyMetadata;
  getHighWaterMark(): number | null;
  close(): void;
}

export class SQLiteKeyStore implements KeyStore {
  private readonly db: DatabaseSync;
  private readonly ownsDb: boolean;
  private readonly clock: Clock;
  private readonly clockGuard: ClockGuard;
  private tainted: boolean = false;
  private taintedReason: string | undefined;
  private readonly onFatalTaint?: (reason: string) => void;

  constructor(
    database: string | DatabaseSync,
    clockOrOptions?: Clock | KeyStoreOptions,
    clockGuard?: ClockGuard,
    options?: KeyStoreOptions,
  ) {
    let resolvedClock: Clock = systemClock;
    let resolvedGuard: ClockGuard | undefined = clockGuard;
    let resolvedMonotonic: MonotonicClock | undefined;
    let resolvedGap: number | undefined;
    let resolvedSynchronous: SQLiteSynchronousMode = "FULL";
    let resolvedFatalTaint: ((reason: string) => void) | undefined = options?.onFatalTaint;
    let resolvedBusyTimeout: number | undefined = options?.busyTimeoutMs;

    if (clockOrOptions && typeof clockOrOptions === "object" && "nowSeconds" in clockOrOptions) {
      resolvedClock = clockOrOptions as Clock;
      resolvedGuard = clockGuard ?? options?.clockGuard;
      resolvedMonotonic = options?.monotonicClock;
      resolvedGap = options?.maxStartupForwardGapSeconds;
      resolvedSynchronous = options?.synchronous ?? "FULL";
      resolvedFatalTaint = options?.onFatalTaint;
      resolvedBusyTimeout = options?.busyTimeoutMs;
    } else if (clockOrOptions && typeof clockOrOptions === "object") {
      resolvedClock = clockOrOptions.clock ?? systemClock;
      resolvedGuard = clockOrOptions.clockGuard ?? clockGuard;
      resolvedMonotonic = clockOrOptions.monotonicClock;
      resolvedGap = clockOrOptions.maxStartupForwardGapSeconds;
      resolvedSynchronous = clockOrOptions.synchronous ?? options?.synchronous ?? "FULL";
      resolvedFatalTaint = clockOrOptions.onFatalTaint ?? options?.onFatalTaint;
      resolvedBusyTimeout = clockOrOptions.busyTimeoutMs ?? options?.busyTimeoutMs;
    }

    this.clock = resolvedClock;
    this.clockGuard =
      resolvedGuard ??
      new ClockGuard(this.clock, resolvedMonotonic, {
        maxStartupForwardGapSeconds: resolvedGap,
      });
    this.onFatalTaint = resolvedFatalTaint;

    if (typeof database === "string") {
      this.db = new DatabaseSync(database);
      this.ownsDb = true;
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

  getSynchronousMode(): SQLiteSynchronousMode {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteKeyStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
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
        `SQLiteKeyStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
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

  checkIntegrity(): boolean {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteKeyStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
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

  private initializeSchema(): void {
    withImmediateTransaction(
      this.db,
      () => {
        // 1. Ensure system_clock_state exists
        this.db.exec(`
          CREATE TABLE IF NOT EXISTS system_clock_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            high_water_seconds INTEGER NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
          );
        `);

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

        // 2. Ensure issuer_keys with schema inspection & migration
        this.ensureIssuerKeysTable();
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
  }

  private ensureIssuerKeysTable(): void {
    const tables = (
      this.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>
    ).map((t) => t.name);

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
      return;
    }

    // Inspect existing columns and constraints
    const cols = (
      this.db.prepare("PRAGMA table_info(issuer_keys)").all() as Array<{ name: string }>
    ).map((c) => c.name);
    const masterRow = this.db.prepare(
      "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'issuer_keys'"
    ).get() as { sql: string } | undefined;
    const sql = masterRow?.sql ?? "";

    const hasRequiredCols =
      cols.includes("key_id") &&
      cols.includes("public_key_pem") &&
      cols.includes("status") &&
      cols.includes("valid_from_seconds") &&
      cols.includes("expires_at_seconds") &&
      cols.includes("retired_at_seconds") &&
      cols.includes("revoked_at_seconds") &&
      cols.includes("created_at");

    const hasCheck = sql.includes("active") && sql.includes("retired") && sql.includes("revoked");

    if (!hasRequiredCols || !hasCheck) {
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

  private updateHighWaterMarkInternal(nowSeconds: number, candidate?: ClockCandidate): void {
    if (!Number.isSafeInteger(nowSeconds) || nowSeconds < 0) {
      throw new Error("Evaluation timestamp must be a non-negative safe integer.");
    }

    const row = this.db.prepare(
      "SELECT high_water_seconds FROM system_clock_state WHERE id = 1"
    ).get() as { high_water_seconds: number } | undefined;

    if (!row) {
      this.db.prepare(
        "INSERT INTO system_clock_state (id, high_water_seconds) VALUES (1, ?)"
      ).run(nowSeconds);
      return;
    }

    if (this.clockGuard && candidate) {
      const clockEval = this.clockGuard.evaluateCandidate(candidate, row.high_water_seconds);
      if (clockEval.decision !== "ALLOW") {
        throw new Error(clockEval.reason);
      }
    }

    if (nowSeconds < row.high_water_seconds) {
      throw new Error(
        `Clock rollback detected: current time (${nowSeconds}s) precedes persisted high-water mark (${row.high_water_seconds}s).`
      );
    }

    if (nowSeconds > row.high_water_seconds) {
      this.db.prepare(`
        UPDATE system_clock_state
        SET high_water_seconds = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = 1 AND high_water_seconds < ?
      `).run(nowSeconds, nowSeconds);
    }
  }

  advanceHighWaterMark(nowSeconds: number): void {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteKeyStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    if (this.clockGuard?.getState() === "TRIPPED_CLOSED") {
      throw new Error(
        `Store clock monitor is in a tripped state: ${this.clockGuard.getTripReason()}`,
      );
    }
    if (this.clockGuard?.getState() === "EXPIRED") {
      throw new Error(
        "Process clock anchor has expired (maximum uptime exceeded); restart required.",
      );
    }
    if (!Number.isSafeInteger(nowSeconds) || nowSeconds < 0) {
      throw new Error("Evaluation timestamp must be a non-negative safe integer.");
    }

    if (this.clockGuard && !this.clockGuard.acquireLock()) {
      throw new Error("Concurrent transaction in progress; ClockGuard lock acquisition failed.");
    }

    const prevSeconds = this.clock instanceof TestClock ? this.clock.nowSeconds() : undefined;
    const prevNanos = this.clock instanceof TestClock ? this.clock.nowNanoseconds() : undefined;

    try {
      if (this.clock instanceof TestClock && nowSeconds > this.clock.nowSeconds()) {
        this.clock.advance(nowSeconds - this.clock.nowSeconds());
      }
      const candidate: ClockCandidate | undefined = this.clockGuard
        ? {
            wallSeconds: nowSeconds,
            monotonicNanos: this.clockGuard.getMonotonicClock().nowNanoseconds(),
          }
        : undefined;

      try {
        withImmediateTransaction(
          this.db,
          () => {
            this.updateHighWaterMarkInternal(nowSeconds, candidate);
          },
          undefined,
          undefined,
          undefined,
          () => {
            if (this.clockGuard && candidate) {
              this.clockGuard.publishCandidate(candidate);
            }
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
    } catch (err) {
      if (this.clock instanceof TestClock && prevSeconds !== undefined && prevNanos !== undefined) {
        this.clock.set(prevSeconds);
        this.clock.setMonotonicNanos(prevNanos);
      }
      throw err;
    } finally {
      if (this.clockGuard) {
        this.clockGuard.releaseLock();
      }
    }
  }

  getHighWaterMark(): number | null {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteKeyStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    try {
      const row = this.db.prepare(
        "SELECT high_water_seconds FROM system_clock_state WHERE id = 1"
      ).get() as { high_water_seconds: number } | undefined;
      return row ? row.high_water_seconds : null;
    } catch (err) {
      this.handleFatalIO(err);
      throw err;
    }
  }

  registerKey(metadata: IssuerKeyMetadata | ImportIssuerKeyMetadata): void {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteKeyStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    if (this.clockGuard?.getState() === "TRIPPED_CLOSED") {
      throw new Error(
        `Store clock monitor is in a tripped state: ${this.clockGuard.getTripReason()}`,
      );
    }
    if (this.clockGuard?.getState() === "EXPIRED") {
      throw new Error(
        "Process clock anchor has expired (maximum uptime exceeded); restart required.",
      );
    }

    if (typeof metadata !== "object" || metadata === null) {
      throw new Error("Key metadata must be a non-null object.");
    }
    if (typeof metadata.keyId !== "string" || metadata.keyId.trim().length === 0) {
      throw new Error("Key ID must be a non-empty string.");
    }
    if (metadata.keyId !== metadata.keyId.trim()) {
      throw new Error("Key ID must not contain leading or trailing whitespace.");
    }
    if (metadata.keyId.length > 128) {
      throw new Error("Key ID exceeds maximum length of 128 characters.");
    }

    const status = metadata.status ?? "active";
    if (status !== "active" && status !== "retired" && status !== "revoked") {
      throw new Error(`Invalid key status: ${String(status)}`);
    }

    const importMeta = metadata as ImportIssuerKeyMetadata;
    let retiredAtSeconds: number | null = null;
    let revokedAtSeconds: number | null = null;

    if (status === "retired") {
      if (
        importMeta.retiredAtSeconds === undefined ||
        !Number.isSafeInteger(importMeta.retiredAtSeconds) ||
        importMeta.retiredAtSeconds < 0
      ) {
        throw new Error(
          `Cannot register key '${metadata.keyId}' in 'retired' status without a valid non-negative safe integer 'retiredAtSeconds'.`
        );
      }
      if (
        metadata.validFromSeconds !== undefined &&
        importMeta.retiredAtSeconds < metadata.validFromSeconds
      ) {
        throw new Error(
          `retiredAtSeconds (${importMeta.retiredAtSeconds}) cannot precede validFromSeconds (${metadata.validFromSeconds}).`
        );
      }
      retiredAtSeconds = importMeta.retiredAtSeconds;
    }

    if (status === "revoked") {
      if (
        importMeta.revokedAtSeconds === undefined ||
        !Number.isSafeInteger(importMeta.revokedAtSeconds) ||
        importMeta.revokedAtSeconds < 0
      ) {
        throw new Error(
          `Cannot register key '${metadata.keyId}' in 'revoked' status without a valid non-negative safe integer 'revokedAtSeconds'.`
        );
      }
      if (
        metadata.validFromSeconds !== undefined &&
        importMeta.revokedAtSeconds < metadata.validFromSeconds
      ) {
        throw new Error(
          `revokedAtSeconds (${importMeta.revokedAtSeconds}) cannot precede validFromSeconds (${metadata.validFromSeconds}).`
        );
      }
      revokedAtSeconds = importMeta.revokedAtSeconds;
    }

    const parsedKey = parseEd25519PublicKey(metadata.publicKey);
    if (!parsedKey) {
      throw new Error("Public key must be a valid Ed25519 public key.");
    }

    if (
      metadata.validFromSeconds !== undefined &&
      metadata.expiresAtSeconds !== undefined &&
      metadata.validFromSeconds > metadata.expiresAtSeconds
    ) {
      throw new Error("validFromSeconds cannot be greater than expiresAtSeconds.");
    }

    const pem = parsedKey.export({ type: "spki", format: "pem" }).toString();

    if (this.clockGuard && !this.clockGuard.acquireLock()) {
      throw new Error("Concurrent transaction in progress; ClockGuard lock acquisition failed.");
    }

    try {
      const nowSeconds = this.clock.nowSeconds();
      const candidate: ClockCandidate | undefined = this.clockGuard
        ? {
            wallSeconds: nowSeconds,
            monotonicNanos: this.clockGuard.getMonotonicClock().nowNanoseconds(),
          }
        : undefined;

      try {
        withImmediateTransaction(
          this.db,
          () => {
            this.updateHighWaterMarkInternal(nowSeconds, candidate);

            const existing = this.db.prepare(
              "SELECT key_id, public_key_pem, status FROM issuer_keys WHERE key_id = ?"
            ).get(metadata.keyId) as {
              key_id: string;
              public_key_pem: string;
              status: KeyStatus;
            } | undefined;

            if (existing) {
              if (existing.public_key_pem !== pem) {
                throw new Error(
                  `Key ID '${metadata.keyId}' is already registered with a different public key.`
                );
              }
              if (existing.status === "revoked") {
                throw new Error(`Cannot re-register revoked key ID '${metadata.keyId}'.`);
              }
              throw new Error(`Key ID already registered: ${metadata.keyId}`);
            }

            this.db.prepare(`
              INSERT INTO issuer_keys (
                key_id, public_key_pem, status, valid_from_seconds, expires_at_seconds,
                retired_at_seconds, revoked_at_seconds, created_at
              ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            `).run(
              metadata.keyId,
              pem,
              status,
              metadata.validFromSeconds ?? null,
              metadata.expiresAtSeconds ?? null,
              retiredAtSeconds,
              revokedAtSeconds,
            );
          },
          undefined,
          undefined,
          undefined,
          () => {
            if (this.clockGuard && candidate) {
              this.clockGuard.publishCandidate(candidate);
            }
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
      if (this.clockGuard) {
        this.clockGuard.releaseLock();
      }
    }
  }

  importKey(metadata: ImportIssuerKeyMetadata): void {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteKeyStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    this.registerKey(metadata);
  }

  getKey(keyId: string): PersistedIssuerKeyMetadata | null {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteKeyStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    try {
      const row = this.db.prepare(
        "SELECT * FROM issuer_keys WHERE key_id = ?"
      ).get(keyId) as {
        key_id: string;
        public_key_pem: string;
        status: KeyStatus;
        valid_from_seconds: number | null;
        expires_at_seconds: number | null;
        retired_at_seconds: number | null;
        revoked_at_seconds: number | null;
        created_at: string;
      } | undefined;

      if (!row) return null;

      const keyObj = parseEd25519PublicKey(row.public_key_pem);
      if (!keyObj) {
        throw new Error(`Corrupted public key in storage for key ID '${keyId}'.`);
      }

      return Object.freeze({
        keyId: row.key_id,
        publicKey: keyObj,
        publicKeyPem: row.public_key_pem,
        status: row.status,
        ...(row.valid_from_seconds !== null ? { validFromSeconds: row.valid_from_seconds } : {}),
        ...(row.expires_at_seconds !== null ? { expiresAtSeconds: row.expires_at_seconds } : {}),
        ...(row.retired_at_seconds !== null ? { retiredAtSeconds: row.retired_at_seconds } : {}),
        ...(row.revoked_at_seconds !== null ? { revokedAtSeconds: row.revoked_at_seconds } : {}),
        createdAt: row.created_at,
      });
    } catch (err) {
      this.handleFatalIO(err);
      throw err;
    }
  }

  getKeyStatus(keyId: string): KeyStatus | null {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteKeyStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    try {
      const row = this.db.prepare(
        "SELECT status FROM issuer_keys WHERE key_id = ?"
      ).get(keyId) as { status: KeyStatus } | undefined;
      return row ? row.status : null;
    } catch (err) {
      this.handleFatalIO(err);
      throw err;
    }
  }

  listKeys(statusFilter?: KeyStatus): PersistedIssuerKeyMetadata[] {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteKeyStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    try {
      let rows: Array<{ key_id: string }>;
      if (statusFilter) {
        rows = this.db.prepare(
          "SELECT key_id FROM issuer_keys WHERE status = ? ORDER BY key_id ASC"
        ).all(statusFilter) as Array<{ key_id: string }>;
      } else {
        rows = this.db.prepare(
          "SELECT key_id FROM issuer_keys ORDER BY key_id ASC"
        ).all() as Array<{ key_id: string }>;
      }

      const result: PersistedIssuerKeyMetadata[] = [];
      for (const row of rows) {
        const record = this.getKey(row.key_id);
        if (record !== null) {
          result.push(record);
        }
      }
      return result;
    } catch (err) {
      this.handleFatalIO(err);
      throw err;
    }
  }

  retireKey(keyId: string, retiredAtSeconds?: number): PersistedIssuerKeyMetadata {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteKeyStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    if (this.clockGuard?.getState() === "TRIPPED_CLOSED") {
      throw new Error(
        `Store clock monitor is in a tripped state: ${this.clockGuard.getTripReason()}`,
      );
    }
    if (this.clockGuard?.getState() === "EXPIRED") {
      throw new Error(
        "Process clock anchor has expired (maximum uptime exceeded); restart required.",
      );
    }
    if (typeof keyId !== "string" || keyId.trim().length === 0) {
      throw new Error("Key ID must be a non-empty string.");
    }

    const timestamp = retiredAtSeconds ?? this.clock.nowSeconds();
    if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
      throw new Error("Retirement timestamp must be a non-negative safe integer.");
    }

    if (this.clockGuard && !this.clockGuard.acquireLock()) {
      throw new Error("Concurrent transaction in progress; ClockGuard lock acquisition failed.");
    }

    const prevSeconds = this.clock instanceof TestClock ? this.clock.nowSeconds() : undefined;
    const prevNanos = this.clock instanceof TestClock ? this.clock.nowNanoseconds() : undefined;

    try {
      if (this.clock instanceof TestClock && timestamp > this.clock.nowSeconds()) {
        this.clock.advance(timestamp - this.clock.nowSeconds());
      }
      const candidate: ClockCandidate | undefined = this.clockGuard
        ? {
            wallSeconds: timestamp,
            monotonicNanos: this.clockGuard.getMonotonicClock().nowNanoseconds(),
          }
        : undefined;

      try {
        withImmediateTransaction(
          this.db,
          () => {
            this.updateHighWaterMarkInternal(timestamp, candidate);

            const row = this.db.prepare(
              "SELECT key_id, status FROM issuer_keys WHERE key_id = ?"
            ).get(keyId) as { key_id: string; status: KeyStatus } | undefined;

            if (!row) {
              throw new Error(`Key '${keyId}' not found.`);
            }

            if (row.status === "revoked") {
              throw new Error(`Cannot retire revoked key '${keyId}'; revocation is permanent.`);
            }

            if (row.status === "retired") {
              return;
            }

            this.db.prepare(`
              UPDATE issuer_keys
              SET status = 'retired', retired_at_seconds = ?
              WHERE key_id = ? AND status = 'active'
            `).run(timestamp, keyId);
          },
          undefined,
          undefined,
          undefined,
          () => {
            if (this.clockGuard && candidate) {
              this.clockGuard.publishCandidate(candidate);
            }
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
    } catch (err) {
      if (this.clock instanceof TestClock && prevSeconds !== undefined && prevNanos !== undefined) {
        this.clock.set(prevSeconds);
        this.clock.setMonotonicNanos(prevNanos);
      }
      throw err;
    } finally {
      if (this.clockGuard) {
        this.clockGuard.releaseLock();
      }
    }

    return this.getKey(keyId)!;
  }

  revokeKey(keyId: string, revokedAtSeconds?: number): PersistedIssuerKeyMetadata {
    if (this.isTainted()) {
      throw new Error(
        `SQLiteKeyStore database connection is tainted and unusable: ${this.getTaintedReason()}`,
      );
    }
    if (this.clockGuard?.getState() === "TRIPPED_CLOSED") {
      throw new Error(
        `Store clock monitor is in a tripped state: ${this.clockGuard.getTripReason()}`,
      );
    }
    if (this.clockGuard?.getState() === "EXPIRED") {
      throw new Error(
        "Process clock anchor has expired (maximum uptime exceeded); restart required.",
      );
    }
    if (typeof keyId !== "string" || keyId.trim().length === 0) {
      throw new Error("Key ID must be a non-empty string.");
    }

    const timestamp = revokedAtSeconds ?? this.clock.nowSeconds();
    if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
      throw new Error("Revocation timestamp must be a non-negative safe integer.");
    }

    if (this.clockGuard && !this.clockGuard.acquireLock()) {
      throw new Error("Concurrent transaction in progress; ClockGuard lock acquisition failed.");
    }

    const prevRevokeSeconds = this.clock instanceof TestClock ? this.clock.nowSeconds() : undefined;
    const prevRevokeNanos = this.clock instanceof TestClock ? this.clock.nowNanoseconds() : undefined;

    try {
      if (this.clock instanceof TestClock && timestamp > this.clock.nowSeconds()) {
        this.clock.advance(timestamp - this.clock.nowSeconds());
      }
      const candidate: ClockCandidate | undefined = this.clockGuard
        ? {
            wallSeconds: timestamp,
            monotonicNanos: this.clockGuard.getMonotonicClock().nowNanoseconds(),
          }
        : undefined;

      try {
        withImmediateTransaction(
          this.db,
          () => {
            this.updateHighWaterMarkInternal(timestamp, candidate);

            const row = this.db.prepare(
              "SELECT key_id, status FROM issuer_keys WHERE key_id = ?"
            ).get(keyId) as { key_id: string; status: KeyStatus } | undefined;

            if (!row) {
              throw new Error(`Key '${keyId}' not found.`);
            }

            if (row.status === "revoked") {
              return;
            }

            this.db.prepare(`
              UPDATE issuer_keys
              SET status = 'revoked', revoked_at_seconds = ?
              WHERE key_id = ?
            `).run(timestamp, keyId);
          },
          undefined,
          undefined,
          undefined,
          () => {
            if (this.clockGuard && candidate) {
              this.clockGuard.publishCandidate(candidate);
            }
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
    } catch (err) {
      if (this.clock instanceof TestClock && prevRevokeSeconds !== undefined && prevRevokeNanos !== undefined) {
        this.clock.set(prevRevokeSeconds);
        this.clock.setMonotonicNanos(prevRevokeNanos);
      }
      throw err;
    } finally {
      if (this.clockGuard) {
        this.clockGuard.releaseLock();
      }
    }

    return this.getKey(keyId)!;
  }

  close(): void {
    if (this.ownsDb) {
      try {
        this.db.close();
      } catch {}
    }
  }
}
