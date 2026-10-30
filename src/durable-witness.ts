/**
 * Web3User Permission Lab - SQLite Durable Monotonic Witness
 *
 * Implements an ACID-compliant, persistent monotonic witness backed by a dedicated
 * SQLite database in Write-Ahead Log (WAL) mode with synchronous=FULL.
 *
 * THREAT MODEL & SECURITY BOUNDARIES:
 * - PROTECTED:
 *   1. Normal process termination and restart (Node.js runtime shutdown).
 *   2. Operating system reboot and host power failure (subject to SQLite/OS fsync durability).
 *   3. Transaction atomicity: commit, sequence allocation, accumulator debit, and audit logging.
 *   4. Replay denial across process lifecycles via persistent tickets and tombstones.
 *   5. Quarantine of expired/ambiguous reservations without premature capacity refund.
 *
 * - STRICT LIMITATIONS (NOT PROTECTED):
 *   1. Coordinated administrative rollback of both application and witness SQLite files.
 *   2. VM / disk image snapshot restoration (requires external freshness authority or distributed consensus).
 *   3. Compromise of the local Ed25519 witness private key on host disk.
 *   4. Hostile root/administrator tampering with the SQLite database file.
 *
 * - SEQUENCE ALLOCATION INVARIANTS (SEC-M13C-05):
 *   1. Sequence numbers within an epoch are strictly increasing (monotonicity guarantee).
 *   2. No sequence number is ever reused within an epoch; duplicate assignments are rejected fail-closed.
 *   3. Sequence regression (witness sequence < local sequence) within an epoch is strictly prohibited.
 *   4. Gapless sequence numbers are NOT required: non-contiguous sequences (gaps) from expired or released
 *      reservations are normal and do not cause security failures.
 *   5. Epoch transitions are explicitly authenticated via configured transition rules.
 *
 * This implementation NEVER silently falls back to an in-memory mock if the SQLite database is unavailable.
 */

import { randomBytes, createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import {
  generateIssuerKeyPair,
  signAuthorizationPayload,
  verifyAuthorizationPayload,
  areEd25519PublicKeysEqual,
} from "./authorization-crypto.js";
import type { BudgetWindowType } from "./policy.js";
import { withImmediateTransaction, isBusyOrLockedError } from "./sqlite-transaction.js";
import {
  type WitnessTicketState,
  type WitnessBudgetWindowAllocation,
  type SignedWitnessReceipt,
  type WitnessSyncStatus,
  type WitnessReservationRequest,
  type WitnessReservationResult,
  type WitnessCommitRequest,
  type WitnessCommitResult,
  type WitnessReleaseRequest,
  type WitnessReleaseResult,
  type WitnessReconcileRequest,
  type WitnessReconcileResult,
  type UnfinalizedWitnessTicket,
  type MonotonicWitnessAdapter,
  canonicalWitnessReceiptPayload,
  verifyWitnessReceipt,
} from "./monotonic-witness.js";

// ============================================================================
// Error Types
// ============================================================================

export class DurableWitnessError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "DurableWitnessError";
  }
}

export class CorruptedWitnessDatabaseError extends DurableWitnessError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "CorruptedWitnessDatabaseError";
  }
}

export class WitnessStorageUnavailableError extends DurableWitnessError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "WitnessStorageUnavailableError";
  }
}

export class InvalidWitnessStateTransitionError extends DurableWitnessError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "InvalidWitnessStateTransitionError";
  }
}

// ============================================================================
// Options Interface
// ============================================================================

export interface SQLiteDurableWitnessOptions {
  /**
   * File path to the dedicated SQLite database, or ':memory:' for isolated testing.
   */
  readonly dbPath: string;

  /**
   * Optional custom witness identity string. Defaults to persisted value or generated UUID.
   */
  readonly witnessId?: string;

  /**
   * Optional custom epoch identity string. Defaults to persisted value or generated epoch ID.
   */
  readonly epochId?: string;

  /**
   * Optional Ed25519 keypair for receipt signing.
   * If omitted, a keypair is automatically generated and persisted in witness_meta.
   */
  readonly keyPair?: {
    readonly privateKey: KeyObject | string;
    readonly publicKey: KeyObject | string;
    readonly publicKeyPem: string;
    readonly privateKeyPem?: string;
  };

  /**
   * Default lease duration for reservations in seconds. Defaults to 30.
   */
  readonly defaultLeaseTtlSeconds?: number;

  /**
   * Optional clock override for deterministic testing.
   */
  readonly nowSeconds?: () => number;
}

// ============================================================================
// Internal Helpers
// ============================================================================

const DIGEST_REGEX = /^sha256:[a-f0-9]{64}$/;

function areBudgetWindowsEqual(
  a: ReadonlyArray<{
    readonly windowType: BudgetWindowType;
    readonly windowStart: number;
    readonly requestedAmount: string;
    readonly maxCumulativeAmount: string;
  }> | undefined,
  b: ReadonlyArray<{
    readonly windowType: BudgetWindowType;
    readonly windowStart: number;
    readonly requestedAmount: string;
    readonly maxCumulativeAmount: string;
  }> | undefined,
): boolean {
  const listA = a ?? [];
  const listB = b ?? [];
  if (listA.length !== listB.length) return false;
  for (let i = 0; i < listA.length; i++) {
    const itemA = listA[i];
    const itemB = listB[i];
    if (
      itemA.windowType !== itemB.windowType ||
      itemA.windowStart !== itemB.windowStart ||
      itemA.requestedAmount !== itemB.requestedAmount ||
      itemA.maxCumulativeAmount !== itemB.maxCumulativeAmount
    ) {
      return false;
    }
  }
  return true;
}

interface StoredTicketRow {
  readonly ticket_id: string;
  readonly authorization_id: string;
  readonly binding_digest: string;
  readonly policy_id: string;
  readonly policy_revision: number;
  readonly idempotency_key: string;
  readonly state: WitnessTicketState;
  readonly budget_windows_json: string;
  readonly reserved_at_seconds: number;
  readonly expires_at_seconds: number;
  readonly committed_at_seconds: number | null;
  readonly sequence_number: string | null;
  readonly receipt_json: string | null;
  readonly release_reason: string | null;
  readonly dispute_reason: string | null;
}

interface StoredAccumulatorRow {
  readonly committed_amount: string;
  readonly reserved_amount: string;
  readonly max_cumulative_amount: string;
}

// ============================================================================
// SQLiteDurableWitness Implementation
// ============================================================================

export class SQLiteDurableWitness implements MonotonicWitnessAdapter {
  public readonly name = "SQLiteDurableWitness";
  public readonly isTestOnlyMock = false;
  public readonly isDurable = true;

  private readonly db: DatabaseSync;
  public readonly dbPath: string;
  private readonly witnessId: string;
  private readonly epochId: string;
  private readonly privateKey: KeyObject;
  private readonly publicKey: KeyObject;
  public readonly publicKeyPem: string;
  private readonly defaultLeaseTtlSeconds: number;
  private readonly getTimeSeconds: () => number;

  private isClosed = false;

  constructor(options: SQLiteDurableWitnessOptions) {
    if (!options || typeof options.dbPath !== "string" || options.dbPath.trim().length === 0) {
      throw new DurableWitnessError("SQLiteDurableWitness requires a valid dbPath.");
    }

    this.dbPath = options.dbPath;
    this.defaultLeaseTtlSeconds = options.defaultLeaseTtlSeconds ?? 30;
    this.getTimeSeconds = options.nowSeconds ?? (() => Math.floor(Date.now() / 1000));

    try {
      this.db = new DatabaseSync(this.dbPath);
    } catch (err) {
      throw new WitnessStorageUnavailableError(
        `Failed to open SQLite witness database at '${this.dbPath}': ${err instanceof Error ? err.message : String(err)}`,
        { cause: err },
      );
    }

    // Configure storage durability
    try {
      this.db.exec("PRAGMA journal_mode = WAL;");
      this.db.exec("PRAGMA synchronous = FULL;");
      this.db.exec("PRAGMA busy_timeout = 5000;");
      this.db.exec("PRAGMA foreign_keys = ON;");
    } catch (err) {
      try {
        this.db.close();
      } catch {}
      const msg = err instanceof Error ? err.message : String(err);
      if (
        msg.includes("not a database") ||
        msg.includes("corrupt") ||
        msg.includes("malformed") ||
        msg.includes("SQLITE_CORRUPT")
      ) {
        throw new CorruptedWitnessDatabaseError(
          `Witness database is corrupted at '${this.dbPath}': ${msg}`,
          { cause: err },
        );
      }
      throw new WitnessStorageUnavailableError(`Failed to configure PRAGMAs on witness database: ${err}`);
    }

    // Integrity Verification
    this.verifyIntegrity();

    // Schema Initialization
    this.initSchema();

    // Identity and Cryptographic Key Governance
    const meta = this.initMetadata(options);
    this.witnessId = meta.witnessId;
    this.epochId = meta.epochId;
    this.publicKey = meta.publicKey;
    this.privateKey = meta.privateKey;
    this.publicKeyPem = meta.publicKeyPem;

    // Boot-time crash recovery: Sweep expired uncommitted reservations into QUARANTINED_UNCONFIRMED
    this.performStartupRecovery();
  }

  private ensureOpen(): void {
    if (this.isClosed) {
      throw new WitnessStorageUnavailableError("SQLiteDurableWitness is closed.");
    }
  }

  private verifyIntegrity(): void {
    try {
      const rows = this.db.prepare("PRAGMA integrity_check;").all() as Array<{ integrity_check?: string }>;
      const checkResult = rows[0]?.integrity_check;
      if (checkResult !== "ok") {
        throw new CorruptedWitnessDatabaseError(
          `Witness database integrity check failed at '${this.dbPath}': ${checkResult}`,
        );
      }
    } catch (err) {
      if (err instanceof CorruptedWitnessDatabaseError) throw err;
      throw new CorruptedWitnessDatabaseError(
        `Failed to execute integrity check on witness database '${this.dbPath}': ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS witness_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS witness_sequence (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        current_sequence INTEGER NOT NULL DEFAULT 0
      );

      INSERT OR IGNORE INTO witness_sequence (id, current_sequence) VALUES (1, 0);

      CREATE TABLE IF NOT EXISTS witness_tickets (
        ticket_id TEXT PRIMARY KEY,
        authorization_id TEXT NOT NULL UNIQUE,
        binding_digest TEXT NOT NULL,
        policy_id TEXT NOT NULL,
        policy_revision INTEGER NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL CHECK (state IN ('RESERVED', 'COMMITTED', 'RELEASED', 'QUARANTINED_UNCONFIRMED', 'DISPUTED')),
        budget_windows_json TEXT NOT NULL,
        reserved_at_seconds INTEGER NOT NULL,
        expires_at_seconds INTEGER NOT NULL,
        committed_at_seconds INTEGER,
        sequence_number TEXT,
        receipt_json TEXT,
        release_reason TEXT,
        dispute_reason TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_witness_tickets_auth_id ON witness_tickets (authorization_id);
      CREATE INDEX IF NOT EXISTS idx_witness_tickets_state ON witness_tickets (state);
      CREATE INDEX IF NOT EXISTS idx_witness_tickets_expires ON witness_tickets (expires_at_seconds);
      CREATE INDEX IF NOT EXISTS idx_witness_tickets_idemp ON witness_tickets (idempotency_key);

      CREATE TABLE IF NOT EXISTS witness_accumulators (
        window_key TEXT PRIMARY KEY,
        policy_id TEXT NOT NULL,
        window_type TEXT NOT NULL,
        window_start INTEGER NOT NULL,
        committed_amount TEXT NOT NULL DEFAULT '0',
        reserved_amount TEXT NOT NULL DEFAULT '0',
        max_cumulative_amount TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_witness_accumulators_policy ON witness_accumulators (policy_id);

      CREATE TABLE IF NOT EXISTS witness_revocations (
        revocation_type TEXT NOT NULL CHECK (revocation_type IN ('KEY', 'POLICY')),
        revocation_target TEXT NOT NULL,
        revoked_at_seconds INTEGER NOT NULL,
        PRIMARY KEY (revocation_type, revocation_target)
      );

      CREATE TABLE IF NOT EXISTS witness_audit_log (
        entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
        sequence_number TEXT,
        action TEXT NOT NULL,
        ticket_id TEXT NOT NULL,
        authorization_id TEXT NOT NULL,
        timestamp_seconds INTEGER NOT NULL,
        details_json TEXT
      );
    `);
  }

  private initMetadata(options: SQLiteDurableWitnessOptions): {
    witnessId: string;
    epochId: string;
    publicKey: KeyObject;
    privateKey: KeyObject;
    publicKeyPem: string;
  } {
    const metaRows = this.db.prepare("SELECT key, value FROM witness_meta;").all() as Array<{
      key: string;
      value: string;
    }>;
    const metaMap = new Map<string, string>();
    for (const r of metaRows) {
      metaMap.set(r.key, r.value);
    }

    const storedVersion = metaMap.get("schema_version");
    if (storedVersion !== undefined && storedVersion !== "1") {
      throw new DurableWitnessError(
        `Unsupported witness schema version '${storedVersion}'. Expected version '1'.`,
      );
    }

    let witnessId: string;
    let epochId: string;
    let publicKey: KeyObject;
    let privateKey: KeyObject;
    let publicKeyPem: string;

    const storedWitnessId = metaMap.get("witness_id");
    const storedEpochId = metaMap.get("epoch_id");
    const storedPublicKeyPem = metaMap.get("public_key_pem");
    const storedPrivateKeyPem = metaMap.get("private_key_pem");

    if (storedWitnessId && storedEpochId && storedPublicKeyPem && storedPrivateKeyPem) {
      // Validate configuration consistency
      if (options.witnessId && options.witnessId !== storedWitnessId) {
        throw new DurableWitnessError(
          `Configured witnessId '${options.witnessId}' conflicts with stored witnessId '${storedWitnessId}'.`,
        );
      }
      if (options.epochId && options.epochId !== storedEpochId) {
        throw new DurableWitnessError(
          `Configured epochId '${options.epochId}' conflicts with stored epochId '${storedEpochId}'.`,
        );
      }

      witnessId = storedWitnessId;
      epochId = storedEpochId;
      publicKeyPem = storedPublicKeyPem;
      publicKey = createPublicKey(storedPublicKeyPem);
      privateKey = createPrivateKey(storedPrivateKeyPem);

      if (options.keyPair) {
        const providedPub =
          typeof options.keyPair.publicKey === "string"
            ? createPublicKey(options.keyPair.publicKey)
            : options.keyPair.publicKey;
        if (!areEd25519PublicKeysEqual(providedPub, publicKey)) {
          throw new DurableWitnessError("Configured keyPair public key conflicts with persisted witness key.");
        }
      }
    } else {
      // First boot: initialize metadata
      witnessId = options.witnessId ?? `witness-${randomBytes(8).toString("hex")}`;
      epochId = options.epochId ?? `epoch-${randomBytes(8).toString("hex")}`;

      let privPem: string;
      if (options.keyPair) {
        publicKey =
          typeof options.keyPair.publicKey === "string"
            ? createPublicKey(options.keyPair.publicKey)
            : options.keyPair.publicKey;
        privateKey =
          typeof options.keyPair.privateKey === "string"
            ? createPrivateKey(options.keyPair.privateKey)
            : options.keyPair.privateKey;
        publicKeyPem = options.keyPair.publicKeyPem;
        privPem =
          options.keyPair.privateKeyPem ??
          privateKey.export({ type: "pkcs8", format: "pem" }).toString();
      } else {
        const gen = generateIssuerKeyPair();
        publicKey = gen.publicKey;
        privateKey = gen.privateKey;
        publicKeyPem = gen.publicKeyPem;
        privPem = gen.privateKeyPem;
      }

      const now = this.getTimeSeconds();
      withImmediateTransaction(this.db, () => {
        const stmt = this.db.prepare("INSERT OR REPLACE INTO witness_meta (key, value) VALUES (?, ?);");
        stmt.run("schema_version", "1");
        stmt.run("witness_id", witnessId);
        stmt.run("epoch_id", epochId);
        stmt.run("created_at_seconds", String(now));
        stmt.run("public_key_pem", publicKeyPem);
        stmt.run("private_key_pem", privPem);
      });
    }

    return { witnessId, epochId, publicKey, privateKey, publicKeyPem };
  }

  private performStartupRecovery(): void {
    const now = this.getTimeSeconds();
    withImmediateTransaction(this.db, () => {
      // Quarantine expired uncommitted reservations without releasing budget capacity
      const expiredRows = this.db
        .prepare(
          "SELECT ticket_id, authorization_id FROM witness_tickets WHERE state = 'RESERVED' AND expires_at_seconds < ?;",
        )
        .all(now) as Array<{ ticket_id: string; authorization_id: string }>;

      if (expiredRows.length > 0) {
        this.db
          .prepare(
            "UPDATE witness_tickets SET state = 'QUARANTINED_UNCONFIRMED' WHERE state = 'RESERVED' AND expires_at_seconds < ?;",
          )
          .run(now);

        const auditStmt = this.db.prepare(
          "INSERT INTO witness_audit_log (action, ticket_id, authorization_id, timestamp_seconds, details_json) VALUES ('QUARANTINE_STARTUP', ?, ?, ?, ?);",
        );
        for (const row of expiredRows) {
          auditStmt.run(
            row.ticket_id,
            row.authorization_id,
            now,
            JSON.stringify({ reason: "Expired reservation detected at startup" }),
          );
        }
      }
    });
  }

  // ============================================================================
  // MonotonicWitnessAdapter Interface Implementation
  // ============================================================================

  public isOpen(): boolean {
    return !this.isClosed;
  }

  public getWitnessId(): string {
    return this.witnessId;
  }

  public getEpochId(): string {
    return this.epochId;
  }

  public getCurrentSequence(): string {
    this.ensureOpen();
    const row = this.db
      .prepare("SELECT CAST(current_sequence AS TEXT) as seq FROM witness_sequence WHERE id = 1;")
      .get() as { seq: string } | undefined;
    return row?.seq ?? "0";
  }

  public getSyncStatus(lastSeenEpoch?: string, lastSeenSeq?: string): WitnessSyncStatus {
    this.ensureOpen();
    const currentSeqStr = this.getCurrentSequence();
    let divergenceDetected = false;
    let reason: string | undefined = undefined;

    if (lastSeenEpoch !== undefined && lastSeenEpoch !== this.epochId) {
      divergenceDetected = true;
      reason = `Epoch mismatch: expected '${this.epochId}', got '${lastSeenEpoch}'.`;
    } else if (lastSeenSeq !== undefined) {
      try {
        const lastSeq = BigInt(lastSeenSeq);
        const currentSeq = BigInt(currentSeqStr);
        if (lastSeq > currentSeq) {
          divergenceDetected = true;
          reason = `Sequence regression: witness sequence (${currentSeqStr}) is behind caller sequence (${lastSeenSeq}).`;
        }
      } catch {
        divergenceDetected = true;
        reason = `Invalid sequence number string '${lastSeenSeq}'.`;
      }
    }

    return {
      healthy: true,
      epochId: this.epochId,
      sequenceNumber: currentSeqStr,
      divergenceDetected,
      reason,
    };
  }

  public reserveTicket(request: WitnessReservationRequest): WitnessReservationResult {
    this.ensureOpen();
    const now = this.getTimeSeconds();

    // Parameter Validations
    if (
      !request ||
      typeof request.authorizationId !== "string" ||
      request.authorizationId.trim().length === 0 ||
      typeof request.bindingDigest !== "string" ||
      !DIGEST_REGEX.test(request.bindingDigest) ||
      typeof request.policyId !== "string" ||
      request.policyId.trim().length === 0 ||
      !Number.isSafeInteger(request.policyRevision) ||
      request.policyRevision < 1 ||
      typeof request.idempotencyKey !== "string" ||
      request.idempotencyKey.trim().length === 0
    ) {
      return {
        decision: "DENY",
        reasons: ["Invalid reservation request parameters."],
      };
    }

    // Check policy revocations
    const rev = this.db
      .prepare(
        "SELECT 1 FROM witness_revocations WHERE revocation_type = 'POLICY' AND revocation_target = ?;",
      )
      .get(request.policyId);
    if (rev) {
      return {
        decision: "DENY",
        reasons: [`Policy '${request.policyId}' is revoked on witness.`],
      };
    }

    return withImmediateTransaction(this.db, () => {
      // 1. Idempotency Check
      const existingTicket = this.db
        .prepare("SELECT * FROM witness_tickets WHERE idempotency_key = ?;")
        .get(request.idempotencyKey) as StoredTicketRow | undefined;

      if (existingTicket) {
        const parsedWindows = JSON.parse(existingTicket.budget_windows_json);
        if (
          existingTicket.authorization_id !== request.authorizationId ||
          existingTicket.binding_digest !== request.bindingDigest ||
          existingTicket.policy_id !== request.policyId ||
          existingTicket.policy_revision !== request.policyRevision ||
          !areBudgetWindowsEqual(parsedWindows, request.budgetWindows)
        ) {
          const mismatches: string[] = [];
          if (existingTicket.authorization_id !== request.authorizationId) mismatches.push("authorizationId mismatch");
          if (existingTicket.binding_digest !== request.bindingDigest) mismatches.push("bindingDigest mismatch");
          if (existingTicket.policy_id !== request.policyId) mismatches.push("policyId mismatch");
          if (existingTicket.policy_revision !== request.policyRevision) mismatches.push("policyRevision mismatch");
          if (!areBudgetWindowsEqual(parsedWindows, request.budgetWindows)) mismatches.push("budgetWindows mismatch");

          return {
            decision: "DENY",
            reasons: [`Conflicting payload for existing idempotency key (${mismatches.join(", ")}).`],
          };
        }

        if (existingTicket.state === "RELEASED") {
          return {
            decision: "DENY",
            reasons: ["Ticket has already been permanently released."],
          };
        }

        let effectiveState = existingTicket.state;
        if (effectiveState === "RESERVED" && now > existingTicket.expires_at_seconds) {
          this.db
            .prepare("UPDATE witness_tickets SET state = 'QUARANTINED_UNCONFIRMED' WHERE ticket_id = ?;")
            .run(existingTicket.ticket_id);
          effectiveState = "QUARANTINED_UNCONFIRMED";
        }

        return {
          decision: "ALLOW",
          ticketId: existingTicket.ticket_id,
          state: effectiveState,
          leaseExpiresAtSeconds: existingTicket.expires_at_seconds,
        };
      }

      // 2. Authorization ID Uniqueness
      const existingAuth = this.db
        .prepare("SELECT ticket_id, state FROM witness_tickets WHERE authorization_id = ?;")
        .get(request.authorizationId) as { ticket_id: string; state: WitnessTicketState } | undefined;

      if (existingAuth) {
        return {
          decision: "DENY",
          reasons: [
            `Authorization ID '${request.authorizationId}' has already been reserved or committed (ticket '${existingAuth.ticket_id}', state '${existingAuth.state}').`,
          ],
        };
      }

      // 3. Multi-Window Cumulative Budget Capacity Verification
      if (request.budgetWindows && request.budgetWindows.length > 0) {
        for (const w of request.budgetWindows) {
          const key = `${request.policyId}:${w.windowType}:${w.windowStart}`;
          const accRow = this.db
            .prepare("SELECT committed_amount, reserved_amount, max_cumulative_amount FROM witness_accumulators WHERE window_key = ?;")
            .get(key) as StoredAccumulatorRow | undefined;

          const committed = accRow ? BigInt(accRow.committed_amount) : 0n;
          const reserved = accRow ? BigInt(accRow.reserved_amount) : 0n;
          const maxCum = accRow ? BigInt(accRow.max_cumulative_amount) : BigInt(w.maxCumulativeAmount);
          const requested = BigInt(w.requestedAmount);
          const available = maxCum - (committed + reserved);

          if (requested > available) {
            return {
              decision: "DENY",
              reasons: [
                `Cumulative spending budget exceeded on witness for ${w.windowType.toLowerCase()} window (requested: ${w.requestedAmount}, available: ${available > 0n ? available.toString(10) : "0"}).`,
              ],
            };
          }
        }

        // Apply reservations atomically
        for (const w of request.budgetWindows) {
          const key = `${request.policyId}:${w.windowType}:${w.windowStart}`;
          const accRow = this.db
            .prepare("SELECT committed_amount, reserved_amount FROM witness_accumulators WHERE window_key = ?;")
            .get(key) as StoredAccumulatorRow | undefined;

          const requested = BigInt(w.requestedAmount);
          if (accRow) {
            const newReserved = (BigInt(accRow.reserved_amount) + requested).toString(10);
            this.db
              .prepare("UPDATE witness_accumulators SET reserved_amount = ?, max_cumulative_amount = ? WHERE window_key = ?;")
              .run(newReserved, w.maxCumulativeAmount, key);
          } else {
            this.db
              .prepare(
                "INSERT INTO witness_accumulators (window_key, policy_id, window_type, window_start, committed_amount, reserved_amount, max_cumulative_amount) VALUES (?, ?, ?, ?, '0', ?, ?);",
              )
              .run(key, request.policyId, w.windowType, w.windowStart, requested.toString(10), w.maxCumulativeAmount);
          }
        }
      }

      // 4. Generate Reservation Ticket
      const ticketId = `tkt-${randomBytes(16).toString("hex")}`;
      const leaseTtl = request.leaseTtlSeconds ?? this.defaultLeaseTtlSeconds;
      const expiresAtSeconds = now + leaseTtl;

      this.db
        .prepare(
          `INSERT INTO witness_tickets (
            ticket_id, authorization_id, binding_digest, policy_id, policy_revision,
            idempotency_key, state, budget_windows_json, reserved_at_seconds, expires_at_seconds
          ) VALUES (?, ?, ?, ?, ?, ?, 'RESERVED', ?, ?, ?);`,
        )
        .run(
          ticketId,
          request.authorizationId,
          request.bindingDigest,
          request.policyId,
          request.policyRevision,
          request.idempotencyKey,
          JSON.stringify(request.budgetWindows ?? []),
          now,
          expiresAtSeconds,
        );

      this.db
        .prepare(
          "INSERT INTO witness_audit_log (action, ticket_id, authorization_id, timestamp_seconds, details_json) VALUES ('RESERVE', ?, ?, ?, ?);",
        )
        .run(ticketId, request.authorizationId, now, JSON.stringify({ leaseTtl, expiresAtSeconds }));

      return {
        decision: "ALLOW",
        ticketId,
        state: "RESERVED",
        leaseExpiresAtSeconds: expiresAtSeconds,
      };
    });
  }

  public commitTicket(request: WitnessCommitRequest): WitnessCommitResult {
    this.ensureOpen();
    const now = this.getTimeSeconds();

    if (
      !request ||
      typeof request.ticketId !== "string" ||
      typeof request.authorizationId !== "string" ||
      typeof request.bindingDigest !== "string"
    ) {
      return {
        decision: "DENY",
        reasons: ["Invalid commit request parameters."],
      };
    }

    return withImmediateTransaction(this.db, () => {
      const ticket = this.db
        .prepare("SELECT * FROM witness_tickets WHERE ticket_id = ?;")
        .get(request.ticketId) as StoredTicketRow | undefined;

      if (!ticket) {
        return {
          decision: "DENY",
          reasons: [`Ticket '${request.ticketId}' not found.`],
        };
      }

      if (
        ticket.authorization_id !== request.authorizationId ||
        ticket.binding_digest !== request.bindingDigest
      ) {
        return {
          decision: "DENY",
          reasons: ["Binding digest or authorization ID mismatch on commit."],
        };
      }

      // Idempotent commit retry
      if (ticket.state === "COMMITTED") {
        const receipt = ticket.receipt_json ? (JSON.parse(ticket.receipt_json) as SignedWitnessReceipt) : undefined;
        return {
          decision: "ALLOW",
          alreadyCommitted: true,
          receipt,
        };
      }

      // Terminal release check
      if (ticket.state === "RELEASED") {
        return {
          decision: "DENY",
          reasons: ["Ticket has already been permanently released and cannot be committed."],
        };
      }

      // Terminal dispute check
      if (ticket.state === "DISPUTED") {
        return {
          decision: "DENY",
          reasons: ["Ticket is disputed and cannot be committed."],
        };
      }

      // Strictly Monotonic Sequence Allocation
      this.db.prepare("UPDATE witness_sequence SET current_sequence = current_sequence + 1 WHERE id = 1;").run();
      const seqRow = this.db
        .prepare("SELECT CAST(current_sequence AS TEXT) as seq FROM witness_sequence WHERE id = 1;")
        .get() as { seq: string };
      const sequenceStr = seqRow.seq;

      // Transition reserved budget to committed budget
      const parsedWindows = JSON.parse(ticket.budget_windows_json) as ReadonlyArray<{
        readonly windowType: BudgetWindowType;
        readonly windowStart: number;
        readonly requestedAmount: string;
      }>;
      const windowAllocations: WitnessBudgetWindowAllocation[] = [];
      let debitedAmount = "0";

      for (const w of parsedWindows) {
        const key = `${ticket.policy_id}:${w.windowType}:${w.windowStart}`;
        const accRow = this.db
          .prepare("SELECT committed_amount, reserved_amount FROM witness_accumulators WHERE window_key = ?;")
          .get(key) as StoredAccumulatorRow | undefined;

        if (accRow) {
          const reqBig = BigInt(w.requestedAmount);
          const resBig = BigInt(accRow.reserved_amount);
          const comBig = BigInt(accRow.committed_amount);

          const newReserved = resBig >= reqBig ? resBig - reqBig : 0n;
          const newCommitted = comBig + reqBig;

          this.db
            .prepare("UPDATE witness_accumulators SET reserved_amount = ?, committed_amount = ? WHERE window_key = ?;")
            .run(newReserved.toString(10), newCommitted.toString(10), key);

          windowAllocations.push({
            windowType: w.windowType,
            windowStart: w.windowStart,
            cumulativeSpentAfter: newCommitted.toString(10),
          });
        }
        debitedAmount = w.requestedAmount;
      }

      // Mint SignedWitnessReceipt
      const receiptData: Omit<SignedWitnessReceipt, "signature"> = {
        version: 1,
        witnessId: this.witnessId,
        epochId: this.epochId,
        sequenceNumber: sequenceStr,
        ticketId: ticket.ticket_id,
        authorizationId: ticket.authorization_id,
        bindingDigest: ticket.binding_digest,
        policyId: ticket.policy_id,
        policyRevision: ticket.policy_revision,
        debitedAmount,
        budgetWindows: windowAllocations,
        committedAtSeconds: now,
      };

      const payload = canonicalWitnessReceiptPayload(receiptData);
      const signature = signAuthorizationPayload(this.privateKey, payload);

      const receipt: SignedWitnessReceipt = {
        ...receiptData,
        signature,
      };

      // Cryptographic verification before persistence
      if (!verifyWitnessReceipt(this.publicKey, receipt)) {
        throw new DurableWitnessError("Cryptographic verification failed for newly minted witness receipt.");
      }

      // Persist committed state
      this.db
        .prepare(
          `UPDATE witness_tickets SET
            state = 'COMMITTED',
            committed_at_seconds = ?,
            sequence_number = ?,
            receipt_json = ?
          WHERE ticket_id = ?;`,
        )
        .run(now, sequenceStr, JSON.stringify(receipt), ticket.ticket_id);

      this.db
        .prepare(
          "INSERT INTO witness_audit_log (sequence_number, action, ticket_id, authorization_id, timestamp_seconds, details_json) VALUES (?, 'COMMIT', ?, ?, ?, ?);",
        )
        .run(sequenceStr, ticket.ticket_id, ticket.authorization_id, now, JSON.stringify({ sequenceNumber: sequenceStr }));

      return {
        decision: "ALLOW",
        receipt,
        alreadyCommitted: false,
      };
    });
  }

  public releaseTicket(request: WitnessReleaseRequest): WitnessReleaseResult {
    this.ensureOpen();
    const now = this.getTimeSeconds();

    if (
      !request ||
      typeof request.ticketId !== "string" ||
      typeof request.authorizationId !== "string" ||
      typeof request.bindingDigest !== "string"
    ) {
      return { success: false, reasons: ["Invalid release request parameters."] };
    }

    return withImmediateTransaction(this.db, () => {
      const ticket = this.db
        .prepare("SELECT * FROM witness_tickets WHERE ticket_id = ?;")
        .get(request.ticketId) as StoredTicketRow | undefined;

      if (!ticket) {
        return { success: false, reasons: [`Ticket '${request.ticketId}' not found.`] };
      }

      if (
        ticket.authorization_id !== request.authorizationId ||
        ticket.binding_digest !== request.bindingDigest
      ) {
        return {
          success: false,
          reasons: ["Binding digest or authorization ID mismatch on release."],
        };
      }

      // Idempotent release
      if (ticket.state === "RELEASED") {
        return { success: true, previousState: "RELEASED" };
      }

      // Terminal COMMITTED cannot be released
      if (ticket.state === "COMMITTED") {
        return {
          success: false,
          previousState: "COMMITTED",
          reasons: ["Ticket has already been committed and cannot be released."],
        };
      }

      // Quarantine check: Unconfirmed quarantined capacity is never released automatically
      if (ticket.state === "QUARANTINED_UNCONFIRMED") {
        return {
          success: false,
          previousState: "QUARANTINED_UNCONFIRMED",
          reasons: [
            "Cannot release unconfirmed ticket: capacity is quarantined and requires explicit reconciliation.",
          ],
        };
      }

      // Check lease expiration
      if (ticket.state === "RESERVED" && now > ticket.expires_at_seconds) {
        this.db
          .prepare("UPDATE witness_tickets SET state = 'QUARANTINED_UNCONFIRMED' WHERE ticket_id = ?;")
          .run(ticket.ticket_id);
        return {
          success: false,
          previousState: "QUARANTINED_UNCONFIRMED",
          reasons: [
            "Reservation lease expired; ticket has been quarantined and cannot be released.",
          ],
        };
      }

      // Transition to RELEASED and refund capacity
      const parsedWindows = JSON.parse(ticket.budget_windows_json) as ReadonlyArray<{
        readonly windowType: BudgetWindowType;
        readonly windowStart: number;
        readonly requestedAmount: string;
      }>;

      for (const w of parsedWindows) {
        const key = `${ticket.policy_id}:${w.windowType}:${w.windowStart}`;
        const accRow = this.db
          .prepare("SELECT reserved_amount FROM witness_accumulators WHERE window_key = ?;")
          .get(key) as { reserved_amount: string } | undefined;

        if (accRow) {
          const reqBig = BigInt(w.requestedAmount);
          const resBig = BigInt(accRow.reserved_amount);
          const newReserved = resBig >= reqBig ? resBig - reqBig : 0n;
          this.db
            .prepare("UPDATE witness_accumulators SET reserved_amount = ? WHERE window_key = ?;")
            .run(newReserved.toString(10), key);
        }
      }

      this.db
        .prepare("UPDATE witness_tickets SET state = 'RELEASED', release_reason = ? WHERE ticket_id = ?;")
        .run(request.reason, ticket.ticket_id);

      this.db
        .prepare(
          "INSERT INTO witness_audit_log (action, ticket_id, authorization_id, timestamp_seconds, details_json) VALUES ('RELEASE', ?, ?, ?, ?);",
        )
        .run(ticket.ticket_id, ticket.authorization_id, now, JSON.stringify({ reason: request.reason }));

      return {
        success: true,
        previousState: "RESERVED",
      };
    });
  }

  public reconcileTicket(request: WitnessReconcileRequest): WitnessReconcileResult {
    this.ensureOpen();
    const now = this.getTimeSeconds();

    if (!request || typeof request.ticketId !== "string") {
      return {
        ticketId: request?.ticketId ?? "unknown",
        state: "DISPUTED",
        reasons: ["Invalid reconcile request parameters."],
      };
    }

    const ticket = this.db
      .prepare("SELECT * FROM witness_tickets WHERE ticket_id = ?;")
      .get(request.ticketId) as StoredTicketRow | undefined;

    if (!ticket) {
      return {
        ticketId: request.ticketId,
        state: "DISPUTED",
        reasons: [`Ticket '${request.ticketId}' not found.`],
      };
    }

    if (request.authorizationId && ticket.authorization_id !== request.authorizationId) {
      return {
        ticketId: request.ticketId,
        state: "DISPUTED",
        reasons: ["Authorization ID mismatch on reconcile."],
      };
    }

    // Auto-quarantine expired uncommitted reservation
    let effectiveState = ticket.state;
    if (ticket.state === "RESERVED" && now > ticket.expires_at_seconds) {
      withImmediateTransaction(this.db, () => {
        this.db
          .prepare("UPDATE witness_tickets SET state = 'QUARANTINED_UNCONFIRMED' WHERE ticket_id = ? AND state = 'RESERVED';")
          .run(ticket.ticket_id);
      });
      effectiveState = "QUARANTINED_UNCONFIRMED";
    }

    const receipt = ticket.receipt_json ? (JSON.parse(ticket.receipt_json) as SignedWitnessReceipt) : undefined;

    return {
      ticketId: ticket.ticket_id,
      state: effectiveState,
      receipt,
    };
  }

  public listUnfinalizedTickets(): UnfinalizedWitnessTicket[] {
    this.ensureOpen();
    const now = this.getTimeSeconds();

    withImmediateTransaction(this.db, () => {
      this.db
        .prepare("UPDATE witness_tickets SET state = 'QUARANTINED_UNCONFIRMED' WHERE state = 'RESERVED' AND expires_at_seconds < ?;")
        .run(now);
    });

    const rows = this.db
      .prepare(
        "SELECT ticket_id, authorization_id, binding_digest, state, reserved_at_seconds, expires_at_seconds FROM witness_tickets WHERE state IN ('RESERVED', 'QUARANTINED_UNCONFIRMED') ORDER BY reserved_at_seconds ASC;",
      )
      .all() as Array<{
      ticket_id: string;
      authorization_id: string;
      binding_digest: string;
      state: WitnessTicketState;
      reserved_at_seconds: number;
      expires_at_seconds: number;
    }>;

    return rows.map((r) => ({
      ticketId: r.ticket_id,
      authorizationId: r.authorization_id,
      bindingDigest: r.binding_digest,
      state: r.state,
      reservedAtSeconds: r.reserved_at_seconds,
      expiresAtSeconds: r.expires_at_seconds,
    }));
  }

  public revokeKey(keyId: string): void {
    this.ensureOpen();
    const now = this.getTimeSeconds();
    withImmediateTransaction(this.db, () => {
      this.db
        .prepare("INSERT OR REPLACE INTO witness_revocations (revocation_type, revocation_target, revoked_at_seconds) VALUES ('KEY', ?, ?);")
        .run(keyId, now);
      this.db.prepare("UPDATE witness_sequence SET current_sequence = current_sequence + 1 WHERE id = 1;").run();
    });
  }

  public revokePolicy(policyId: string): void {
    this.ensureOpen();
    const now = this.getTimeSeconds();
    withImmediateTransaction(this.db, () => {
      this.db
        .prepare("INSERT OR REPLACE INTO witness_revocations (revocation_type, revocation_target, revoked_at_seconds) VALUES ('POLICY', ?, ?);")
        .run(policyId, now);
      this.db.prepare("UPDATE witness_sequence SET current_sequence = current_sequence + 1 WHERE id = 1;").run();
    });
  }

  public close(): void {
    if (!this.isClosed) {
      this.isClosed = true;
      try {
        this.db.close();
      } catch {}
    }
  }
}
