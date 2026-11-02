/**
 * Web3User Permission Lab - Milestone 13-D: PostgreSQL 16 Witness Storage Foundation
 *
 * Implements the relational persistence engine, ACID transaction management, SERIALIZABLE
 * isolation, deterministic row locking (FOR UPDATE NOWAIT), SQLSTATE exception routing,
 * and security invariants for Milestone 13-D Remote Durable Witness.
 *
 * MANDATORY SECURITY INVARIANTS:
 * 1. Global authorization ID uniqueness across all pods, all epochs, and all time.
 * 2. Per-epoch monotonic sequence uniqueness (witness_sequence_seq).
 * 3. Permanent sequence gaps; failed outbox intents retain sequences permanently.
 * 4. Non-negative budget balances (current_amount >= 0, held_amount >= 0).
 * 5. Cumulative budget ceiling enforcement (current_amount + held_amount <= max_limit).
 * 6. Zero duplicate sequence, receipt, or budget commitments during retries.
 * 7. Complete transaction rollback before retrying serialization failures or lock contention.
 * 8. Idempotency collisions verify immutable request identity and payload.
 * 9. Immutable receipts (enforced via database trigger) and append-only audit log.
 * 10. Fail-closed on ambiguous outcomes; zero automatic refunds on commit timeouts.
 *
 * GENESIS / BOOTSTRAP FRESHNESS BEACON INVARIANT (M13-D Phase 3 Interface Foundation):
 * In Phase 3, the external DynamoDB Freshness Beacon maintains:
 *   (epoch_height, epoch_certificate_hash, sequence_floor, receipt_chain_hash)
 * Genesis bootstrap invariant:
 *   - At cluster genesis (bootstrap), epoch_height = 1, sequence_floor = 1,
 *     receipt_chain_hash = SHA256("GENESIS:" || epoch_id).
 *   - Any subsequent epoch transition write requires prior-state 4-tuple fencing:
 *     evaluating (epoch_height = expected_prior_height AND epoch_certificate_hash = expected_prior_cert_hash
 *     AND sequence_floor = expected_prior_floor AND receipt_chain_hash = expected_prior_chain_hash
 *     AND new_height = expected_prior_height + 1).
 *   - D1 establishes the relational foundation ensuring that all committed sequences
 *     and receipts in PostgreSQL map directly to these 4-tuple beacon invariants.
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pg, { type PoolClient, type PoolConfig } from "pg";
import type { BudgetWindowType } from "../policy.js";
import type {
  WitnessTicketState,
  WitnessReservationRequest,
  WitnessReservationResult,
  WitnessCommitRequest,
  WitnessCommitResult,
  WitnessReleaseRequest,
  WitnessReleaseResult,
  WitnessReconcileRequest,
  WitnessReconcileResult,
  SignedWitnessReceipt,
  WitnessSyncStatus,
  MonotonicWitnessAdapter,
} from "../monotonic-witness.js";

const { Pool } = pg;

// ============================================================================
// SQLSTATE Error Codes
// ============================================================================

export const PG_SQLSTATE = {
  UNIQUE_VIOLATION: "23505",
  SERIALIZATION_FAILURE: "40001",
  DEADLOCK_DETECTED: "40P01",
  LOCK_NOT_AVAILABLE: "55P03",
} as const;

// ============================================================================
// Custom Witness Error Types
// ============================================================================

export class WitnessStorageError extends Error {
  constructor(message: string, readonly code?: string, readonly originalError?: unknown) {
    super(message);
    this.name = "WitnessStorageError";
  }
}

export class WitnessConflictError extends WitnessStorageError {
  constructor(message: string, originalError?: unknown) {
    super(message, PG_SQLSTATE.UNIQUE_VIOLATION, originalError);
    this.name = "WitnessConflictError";
  }
}

export class WitnessUnavailableError extends WitnessStorageError {
  constructor(message: string, originalError?: unknown) {
    super(message, PG_SQLSTATE.SERIALIZATION_FAILURE, originalError);
    this.name = "WitnessUnavailableError";
  }
}

export class WitnessDeadlockError extends WitnessStorageError {
  constructor(message: string, originalError?: unknown) {
    super(message, PG_SQLSTATE.DEADLOCK_DETECTED, originalError);
    this.name = "WitnessDeadlockError";
  }
}

export class WitnessContentionError extends WitnessStorageError {
  constructor(message: string, originalError?: unknown) {
    super(message, PG_SQLSTATE.LOCK_NOT_AVAILABLE, originalError);
    this.name = "WitnessContentionError";
  }
}

export class InvalidWitnessStateTransitionError extends WitnessStorageError {
  constructor(message: string) {
    super(message, "INVALID_STATE_TRANSITION");
    this.name = "InvalidWitnessStateTransitionError";
  }
}

// ============================================================================
// Record Types
// ============================================================================

export interface WitnessTicketRecord {
  readonly ticketId: string;
  readonly authorizationId: string;
  readonly epochId: string;
  readonly state: WitnessTicketState | "COMMITTING_SIGNING_PENDING" | "QUARANTINED_BLOCKED" | "RELEASED_AFTER_AUDIT";
  readonly bindingDigest: string;
  readonly sequenceNumber: string | null;
  readonly expiresAtSeconds: number;
  readonly createdAtSeconds: number;
  readonly updatedAtSeconds: number;
  readonly idempotencyKey: string | null;
}

export interface WitnessAccumulatorRecord {
  readonly windowId: string;
  readonly windowType: string;
  readonly windowStart: number;
  readonly currentAmount: string;
  readonly heldAmount: string;
  readonly maxLimit: string;
}

export interface WitnessOutboxRecord {
  readonly intentId: string;
  readonly ticketId: string;
  readonly epochId: string;
  readonly sequenceNumber: string;
  readonly preimage: string;
  readonly status: "PENDING" | "SIGNING" | "COMPLETED" | "FAILED";
  readonly retryCount: number;
  readonly lastError: string | null;
  readonly createdAtSeconds: number;
  readonly updatedAtSeconds: number;
}

export interface WitnessReceiptRecord {
  readonly ticketId: string;
  readonly authorizationId: string;
  readonly epochId: string;
  readonly sequenceNumber: string;
  readonly witnessTimestampSeconds: number;
  readonly bindingDigest: string;
  readonly signature: Uint8Array;
  readonly receiptJson: string;
  readonly receiptChainHash: string;
}

export interface WitnessSequenceGapRecord {
  readonly epochId: string;
  readonly sequenceNumber: string;
  readonly gapReason: string;
  readonly ticketId: string | null;
  readonly detectedAtSeconds: number;
  readonly details: Record<string, unknown> | null;
}

export interface SequenceGapReconciliationResult {
  readonly epochId: string;
  readonly sequenceCeiling: string;
  readonly totalReceipts: number;
  readonly totalOutbox: number;
  readonly existingAccountedGaps: number;
  readonly newlyDiscoveredGaps: string[];
}

export interface Phase1CommitResult {
  readonly success: boolean;
  readonly ticketId: string;
  readonly sequenceNumber: string;
  readonly intentId: string;
  readonly epochId: string;
  readonly preimage: string;
  readonly alreadyCommitted?: boolean;
}

export interface Phase3CommitResult {
  readonly success: boolean;
  readonly ticketId: string;
  readonly sequenceNumber: string;
  readonly receipt: SignedWitnessReceipt;
}

// ============================================================================
// Helper Utilities
// ============================================================================

function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============================================================================
// PostgresWitnessStore Class
// ============================================================================

export interface PostgresWitnessStoreOptions {
  readonly pool?: pg.Pool;
  readonly poolConfig?: PoolConfig;
  readonly epochId?: string;
  readonly actorId?: string;
  readonly defaultLeaseTtlSeconds?: number;
}

export class PostgresWitnessStore implements MonotonicWitnessAdapter {
  readonly name = "PostgresWitnessStore";
  readonly isTestOnlyMock = false;

  private readonly pool: pg.Pool;
  private readonly ownPool: boolean;
  private readonly epochId: string;
  private readonly actorId: string;
  private readonly defaultLeaseTtlSeconds: number;

  constructor(options: PostgresWitnessStoreOptions = {}) {
    if (options.pool) {
      this.pool = options.pool;
      this.ownPool = false;
    } else {
      const config: PoolConfig = options.poolConfig || {
        host: process.env.PGHOST || "127.0.0.1",
        port: Number(process.env.PGPORT || 5432),
        user: process.env.PGUSER || "postgres",
        password: process.env.PGPASSWORD || "postgres",
        database: process.env.PGDATABASE || "web3user_witness_test",
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000,
      };
      this.pool = new Pool(config);
      this.ownPool = true;
    }

    this.epochId = options.epochId || "epoch-001";
    this.actorId = options.actorId || `pod-${randomBytes(4).toString("hex")}`;
    this.defaultLeaseTtlSeconds = options.defaultLeaseTtlSeconds || 300;
  }

  // ==========================================================================
  // Schema Initialization & Cleanup
  // ==========================================================================

  async initializeSchema(): Promise<void> {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const schemaPath = join(__dirname, "schema.sql");
    const ddl = readFileSync(schemaPath, "utf8");

    const client = await this.pool.connect();
    try {
      await client.query(ddl);
    } finally {
      client.release();
    }
  }

  // ==========================================================================
  // Epoch Management & Per-Epoch Sequence Model (F1)
  // ==========================================================================

  /**
   * Registers an epoch in witness_epochs and initializes its per-epoch monotonic sequence.
   * Invariant: Sequences restart at 1 under each new epoch (Strict Per-Epoch Monotonicity).
   */
  async registerEpoch(epochId: string, epochHeight: number): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const client = await this.pool.connect();
    try {
      await client.query(
        `INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds)
         VALUES ($1, $2, $3)
         ON CONFLICT (epoch_id) DO NOTHING`,
        [epochId, epochHeight, now],
      );
      await client.query(`SELECT get_or_create_epoch_sequence($1)`, [epochId]);
    } finally {
      client.release();
    }
  }

  getEpochSequenceName(epochId: string): string {
    return `witness_seq_${epochId.replace(/[^a-zA-Z0-9_]/g, "_")}`;
  }

  // ==========================================================================
  // Sequence Gap Accounting & Reconciliation (F2)
  // ==========================================================================

  /**
   * Records a burned sequence gap into witness_sequence_gaps.
   * Invariant: Gaps are permanently recorded and sequence numbers are NEVER reused.
   */
  async recordSequenceGap(
    epochId: string,
    sequenceNumber: string,
    gapReason: string,
    details?: Record<string, unknown>,
    ticketId?: string,
  ): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    await this.pool.query(
      `INSERT INTO witness_sequence_gaps (epoch_id, sequence_number, gap_reason, ticket_id, detected_at_seconds, details)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (epoch_id, sequence_number) DO NOTHING`,
      [epochId, sequenceNumber, gapReason, ticketId || null, now, details ? JSON.stringify(details) : null],
    );
  }

  /**
   * Reconciles sequence continuity across an epoch by scanning up to the current sequence
   * generator ceiling. Identifies burned sequences resulting from transaction rollbacks or process
   * crashes and records them durable into witness_sequence_gaps.
   */
  async reconcileSequenceGaps(epochId: string): Promise<SequenceGapReconciliationResult> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED");

      // Coordinate with sequence allocations:
      // Lock the epoch row FOR UPDATE. This ensures that any in-flight commitTicket transactions
      // holding FOR SHARE on this epoch have completely committed or rolled back before reconciliation proceeds.
      // In READ COMMITTED, once the lock is acquired, all subsequent queries see committed rows from all
      // transactions that finished while waiting for the lock.
      // Furthermore, while this transaction holds FOR UPDATE, no new commitTicket can allocate a sequence
      // for this epoch, guaranteeing that an allocated sequence is never prematurely marked as a burned gap.
      await client.query(
        `SELECT epoch_id FROM witness_epochs WHERE epoch_id = $1 FOR UPDATE`,
        [epochId],
      );

      const seqNameRes = await client.query(`SELECT get_or_create_epoch_sequence($1) AS seq_name`, [epochId]);
      const seqName = seqNameRes.rows[0].seq_name;

      const seqState = await client.query(`SELECT last_value, is_called FROM ${seqName}`);
      const lastVal = BigInt(seqState.rows[0].last_value);
      const isCalled = seqState.rows[0].is_called;

      if (!isCalled) {
        await client.query("COMMIT");
        return {
          epochId,
          sequenceCeiling: "0",
          totalReceipts: 0,
          totalOutbox: 0,
          existingAccountedGaps: 0,
          newlyDiscoveredGaps: [],
        };
      }

      const receiptsRes = await client.query(
        `SELECT sequence_number FROM witness_receipts WHERE epoch_id = $1`,
        [epochId],
      );
      const receiptSeqs = new Set(receiptsRes.rows.map((r) => r.sequence_number.toString()));

      const outboxRes = await client.query(
        `SELECT sequence_number, status FROM witness_signing_outbox WHERE epoch_id = $1`,
        [epochId],
      );
      const outboxSeqs = new Set(outboxRes.rows.map((r) => r.sequence_number.toString()));

      const gapsRes = await client.query(
        `SELECT sequence_number FROM witness_sequence_gaps WHERE epoch_id = $1`,
        [epochId],
      );
      const existingGaps = new Set(gapsRes.rows.map((r) => r.sequence_number.toString()));

      const newlyDiscoveredGaps: string[] = [];
      const now = Math.floor(Date.now() / 1000);

      for (let s = 1n; s <= lastVal; s++) {
        const sStr = s.toString();
        if (!receiptSeqs.has(sStr) && !outboxSeqs.has(sStr) && !existingGaps.has(sStr)) {
          newlyDiscoveredGaps.push(sStr);
          await client.query(
            `INSERT INTO witness_sequence_gaps (epoch_id, sequence_number, gap_reason, ticket_id, detected_at_seconds, details)
             VALUES ($1, $2, 'TRANSACTION_ROLLBACK', NULL, $3, $4)
             ON CONFLICT (epoch_id, sequence_number) DO NOTHING`,
            [
              epochId,
              sStr,
              now,
              JSON.stringify({
                reconciledAt: now,
                reason: "Uncommitted sequence burned by aborted transaction or process crash",
              }),
            ],
          );

          await client.query(
            `INSERT INTO witness_audit_log (action, to_state, actor_id, details)
             VALUES ('RECONCILE_SEQUENCE_GAP', 'RECORDED', $1, $2)`,
            [
              this.actorId,
              JSON.stringify({ epochId, sequenceNumber: sStr, reason: "TRANSACTION_ROLLBACK" }),
            ],
          );
        }
      }

      await client.query("COMMIT");

      return {
        epochId,
        sequenceCeiling: lastVal.toString(),
        totalReceipts: receiptSeqs.size,
        totalOutbox: outboxSeqs.size,
        existingAccountedGaps: existingGaps.size,
        newlyDiscoveredGaps,
      };
    } catch (e) {
      try {
        await client.query("ROLLBACK");
      } catch {}
      throw e;
    } finally {
      client.release();
    }
  }

  async getSequenceGaps(epochId: string): Promise<WitnessSequenceGapRecord[]> {
    const res = await this.pool.query(
      `SELECT epoch_id, sequence_number, gap_reason, ticket_id, detected_at_seconds, details
       FROM witness_sequence_gaps WHERE epoch_id = $1 ORDER BY sequence_number ASC`,
      [epochId],
    );
    return res.rows.map((r) => ({
      epochId: r.epoch_id,
      sequenceNumber: r.sequence_number.toString(),
      gapReason: r.gap_reason,
      ticketId: r.ticket_id,
      detectedAtSeconds: Number(r.detected_at_seconds),
      details: r.details,
    }));
  }

  async close(): Promise<void> {
    if (this.ownPool) {
      await this.pool.end();
    }
  }

  // ==========================================================================
  // Transaction Execution & Retry Logic
  // ==========================================================================

  /**
   * Executes a callback within a SERIALIZABLE transaction with explicit SQLSTATE
   * error handling, fail-closed semantics, and bounded exponential retries.
   */
  async withSerializableTransaction<T>(
    operationName: string,
    callback: (client: PoolClient) => Promise<T>,
  ): Promise<T> {
    let contentionRetries = 0;
    const maxContentionRetries = 5;

    let serializationRetries = 0;
    const maxSerializationRetries = 5;

    let deadlockRetries = 0;
    const maxDeadlockRetries = 3;

    while (true) {
      const client = await this.pool.connect();
      try {
        await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");

        const result = await callback(client);

        await client.query("COMMIT");
        return result;
      } catch (err: unknown) {
        // ALWAYS execute clean rollback on error
        try {
          await client.query("ROLLBACK");
        } catch {
          // Ignore rollback errors if connection died
        }

        const pgErr = err as { code?: string; message?: string };
        const code = pgErr?.code;

        // 1. Lock contention: 55P03 (lock_not_available from FOR UPDATE NOWAIT)
        if (code === PG_SQLSTATE.LOCK_NOT_AVAILABLE) {
          contentionRetries++;
          if (contentionRetries > maxContentionRetries) {
            throw new WitnessContentionError(
              `[${operationName}] Contention retry budget exhausted (55P03 lock_not_available): ${pgErr.message}`,
              err,
            );
          }
          const baseDelay = 10 * Math.pow(1.8, contentionRetries - 1);
          const jitter = Math.floor(Math.random() * 20 - 10);
          const delay = Math.min(150, Math.max(5, Math.floor(baseDelay + jitter)));
          await sleep(delay);
          continue;
        }

        // 2. Serialization failure: 40001
        if (code === PG_SQLSTATE.SERIALIZATION_FAILURE) {
          serializationRetries++;
          if (serializationRetries > maxSerializationRetries) {
            throw new WitnessUnavailableError(
              `[${operationName}] Serialization retry budget exhausted (40001 serialization_failure): ${pgErr.message}`,
              err,
            );
          }
          const delay = Math.min(150, Math.floor(15 * Math.pow(1.5, serializationRetries) + Math.random() * 15));
          await sleep(delay);
          continue;
        }

        // 3. Deadlock detected: 40P01
        if (code === PG_SQLSTATE.DEADLOCK_DETECTED) {
          deadlockRetries++;
          if (deadlockRetries > maxDeadlockRetries) {
            throw new WitnessDeadlockError(
              `[${operationName}] Deadlock retry budget exhausted (40P01 deadlock_detected): ${pgErr.message}`,
              err,
            );
          }
          const delay = Math.min(200, Math.floor(20 * Math.pow(2, deadlockRetries) + Math.random() * 20));
          await sleep(delay);
          continue;
        }

        // 4. Unique violation: 23505 (Non-retryable conflict)
        if (code === PG_SQLSTATE.UNIQUE_VIOLATION) {
          // Propagate immediately for read-and-verify handling
          throw err;
        }

        // All other errors are non-retryable
        throw err;
      } finally {
        client.release();
      }
    }
  }

  // ==========================================================================
  // Adapter Core Methods: Reserve, Commit, Release, Reconcile
  // ==========================================================================

  async reserveTicket(
    request: WitnessReservationRequest,
    customActorId?: string,
  ): Promise<WitnessReservationResult> {
    const actorId = customActorId || this.actorId;
    const now = Math.floor(Date.now() / 1000);
    const ttl = request.leaseTtlSeconds || this.defaultLeaseTtlSeconds;
    const expiresAt = now + ttl;

    // Idempotency and Collision Verification
    try {
      return await this.withSerializableTransaction("reserveTicket", async (client) => {
        // Step 0: Acquire Level 1 Lock on witness_epochs FIRST (Rank 1)
        await client.query(
          `SELECT epoch_id FROM witness_epochs WHERE epoch_id = $1 FOR SHARE`,
          [this.epochId],
        );

        // Step 1: Check existing ticket for this authorization_id (global uniqueness check)
        const existingTicketRes = await client.query(
          `SELECT ticket_id, authorization_id, epoch_id, state, binding_digest, expires_at_seconds, idempotency_key
           FROM witness_tickets WHERE authorization_id = $1`,
          [request.authorizationId],
        );

        if (existingTicketRes.rows.length > 0) {
          const row = existingTicketRes.rows[0];

          // Verify immutable request payload
          if (row.binding_digest !== request.bindingDigest) {
            throw new WitnessConflictError(
              `DENY: IDEMPOTENCY_PAYLOAD_MISMATCH (authorization ${request.authorizationId} exists with different binding digest)`,
            );
          }

          if (row.state === "COMMITTED") {
            return {
              decision: "DENY",
              ticketId: row.ticket_id,
              state: "COMMITTED",
              reasons: ["DENY: AUTHORIZATION_ALREADY_COMMITTED"],
            };
          }

          if (row.state === "RESERVED") {
            // Check idempotency key
            if (row.idempotency_key && row.idempotency_key === request.idempotencyKey) {
              return {
                decision: "ALLOW",
                ticketId: row.ticket_id,
                state: "RESERVED",
                leaseExpiresAtSeconds: Number(row.expires_at_seconds),
              };
            }
            return {
              decision: "DENY",
              ticketId: row.ticket_id,
              state: "RESERVED",
              reasons: ["DENY: AUTHORIZATION_ALREADY_RESERVED"],
            };
          }

          return {
            decision: "DENY",
            ticketId: row.ticket_id,
            state: row.state as WitnessTicketState,
            reasons: [`DENY: TICKET_IN_STATE_${row.state}`],
          };
        }

        // Step 2: Lock and check budget accumulators in ascending order (canonical ordering eliminates deadlocks)
        if (request.budgetWindows && request.budgetWindows.length > 0) {
          const sortedWindows = [...request.budgetWindows].sort((a, b) => {
            const idA = `${a.windowType}:${a.windowStart}`;
            const idB = `${b.windowType}:${b.windowStart}`;
            return idA.localeCompare(idB);
          });

          for (const win of sortedWindows) {
            const windowId = `${win.windowType}:${win.windowStart}`;
            const reqAmount = BigInt(win.requestedAmount);
            const maxLimit = BigInt(win.maxCumulativeAmount);

            // Row-level lock with NOWAIT
            const accRes = await client.query(
              `SELECT window_id, current_amount, held_amount, max_limit
               FROM witness_accumulators WHERE window_id = $1 FOR UPDATE NOWAIT`,
              [windowId],
            );

            let currentAmount = 0n;
            let heldAmount = 0n;

            if (accRes.rows.length === 0) {
              // Initialize accumulator row
              await client.query(
                `INSERT INTO witness_accumulators (window_id, window_type, window_start, current_amount, held_amount, max_limit)
                 VALUES ($1, $2, $3, 0, 0, $4)`,
                [windowId, win.windowType, win.windowStart, maxLimit.toString()],
              );
            } else {
              currentAmount = BigInt(accRes.rows[0].current_amount);
              heldAmount = BigInt(accRes.rows[0].held_amount);
            }

            // Invariant: current + held + requested <= max_limit
            if (currentAmount + heldAmount + reqAmount > maxLimit) {
              await client.query(
                `INSERT INTO witness_audit_log (authorization_id, action, from_state, to_state, actor_id, details)
                 VALUES ($1, 'RESERVE_DENIED_CAPACITY', NULL, 'DENIED', $2, $3)`,
                [
                  request.authorizationId,
                  actorId,
                  JSON.stringify({
                    windowId,
                    currentAmount: currentAmount.toString(),
                    heldAmount: heldAmount.toString(),
                    requestedAmount: reqAmount.toString(),
                    maxLimit: maxLimit.toString(),
                  }),
                ],
              );
              return {
                decision: "DENY",
                reasons: [`DENY: BUDGET_EXCEEDED (window ${windowId})`],
              };
            }

            // Debit held amount
            await client.query(
              `UPDATE witness_accumulators
               SET held_amount = held_amount + $1
               WHERE window_id = $2`,
              [reqAmount.toString(), windowId],
            );
          }
        }

        // Step 3: Insert ticket into witness_tickets
        const ticketId = `tkt_${randomUUID().replace(/-/g, "")}`;
        await client.query(
          `INSERT INTO witness_tickets (
             ticket_id, authorization_id, epoch_id, state, binding_digest,
             expires_at_seconds, created_at_seconds, updated_at_seconds, idempotency_key
           ) VALUES ($1, $2, $3, 'RESERVED', $4, $5, $6, $7, $8)`,
          [
            ticketId,
            request.authorizationId,
            this.epochId,
            request.bindingDigest,
            expiresAt,
            now,
            now,
            request.idempotencyKey,
          ],
        );

        // Step 4: Record audit log entry
        await client.query(
          `INSERT INTO witness_audit_log (ticket_id, authorization_id, action, from_state, to_state, actor_id, details)
           VALUES ($1, $2, 'RESERVE', NULL, 'RESERVED', $3, $4)`,
          [
            ticketId,
            request.authorizationId,
            actorId,
            JSON.stringify({
              expiresAt,
              budgetWindows: request.budgetWindows,
              idempotencyKey: request.idempotencyKey,
            }),
          ],
        );

        return {
          decision: "ALLOW",
          ticketId,
          state: "RESERVED",
          leaseExpiresAtSeconds: expiresAt,
        };
      });
    } catch (err: unknown) {
      const pgErr = err as { code?: string; message?: string };
      // Handle race condition where another transaction won the reservation insert
      if (pgErr?.code === PG_SQLSTATE.UNIQUE_VIOLATION) {
        // Read-and-verify existing ticket
        const existing = await this.getTicketByAuthorizationId(request.authorizationId);
        if (existing) {
          if (existing.bindingDigest !== request.bindingDigest) {
            throw new WitnessConflictError(
              `DENY: IDEMPOTENCY_PAYLOAD_MISMATCH (authorization ${request.authorizationId} payload differs from existing record)`,
              err,
            );
          }
          if (existing.state === "COMMITTED") {
            return {
              decision: "DENY",
              ticketId: existing.ticketId,
              state: "COMMITTED",
              reasons: ["DENY: AUTHORIZATION_ALREADY_COMMITTED"],
            };
          }
          if (existing.state === "RESERVED") {
            if (existing.idempotencyKey === request.idempotencyKey) {
              return {
                decision: "ALLOW",
                ticketId: existing.ticketId,
                state: "RESERVED",
                leaseExpiresAtSeconds: existing.expiresAtSeconds,
              };
            }
            return {
              decision: "DENY",
              ticketId: existing.ticketId,
              state: "RESERVED",
              reasons: ["DENY: AUTHORIZATION_ALREADY_RESERVED"],
            };
          }
          return {
            decision: "DENY",
            ticketId: existing.ticketId,
            state: existing.state as WitnessTicketState,
            reasons: [`DENY: TICKET_IN_STATE_${existing.state}`],
          };
        }
      }
      throw err;
    }
  }

  // ==========================================================================
  // Phase 1 Commit: Burn Sequence, Enqueue Outbox, Shift Budget
  // ==========================================================================

  async commitTicketPhase1(
    ticketId: string,
    authorizationId: string,
    bindingDigest: string,
    preimage: string,
    debitedAmount: string = "0",
    budgetWindows: ReadonlyArray<{ windowType: BudgetWindowType; windowStart: number; requestedAmount: string }> = [],
    customActorId?: string,
  ): Promise<Phase1CommitResult> {
    const actorId = customActorId || this.actorId;
    const now = Math.floor(Date.now() / 1000);

    return await this.withSerializableTransaction("commitTicketPhase1", async (client) => {
      // Step 0: Pre-read ticket without locks to determine epoch_id, guaranteeing that
      // Level 1 witness_epochs row lock is acquired BEFORE any row lock on witness_tickets.
      const epochCheck = await client.query(
        `SELECT epoch_id FROM witness_tickets WHERE ticket_id = $1`,
        [ticketId],
      );

      if (epochCheck.rows.length === 0) {
        throw new WitnessStorageError(`Ticket not found: ${ticketId}`);
      }

      const targetEpochId = epochCheck.rows[0].epoch_id;

      // Step 1: Acquire Level 1 Lock on witness_epochs FIRST (Rank 1)
      await client.query(
        `SELECT epoch_id FROM witness_epochs WHERE epoch_id = $1 FOR SHARE`,
        [targetEpochId],
      );

      // Step 2: Acquire Level 2 Lock on witness_tickets SECOND with NOWAIT (Rank 2)
      const ticketRes = await client.query(
        `SELECT ticket_id, authorization_id, epoch_id, state, binding_digest, sequence_number, expires_at_seconds
         FROM witness_tickets WHERE ticket_id = $1 FOR UPDATE NOWAIT`,
        [ticketId],
      );

      const ticket = ticketRes.rows[0];

      // Verification of binding invariants
      if (ticket.authorization_id !== authorizationId || ticket.binding_digest !== bindingDigest) {
        throw new WitnessConflictError(
          `DENY: IDEMPOTENCY_PAYLOAD_MISMATCH for ticket ${ticketId}`,
        );
      }

      // Check terminal state: already committed
      if (ticket.state === "COMMITTED") {
        return {
          success: true,
          ticketId,
          sequenceNumber: ticket.sequence_number,
          intentId: "",
          epochId: ticket.epoch_id,
          preimage,
          alreadyCommitted: true,
        };
      }

      // Zero-trust lease cutoff check: must arrive before physical expiry
      if (now > Number(ticket.expires_at_seconds)) {
        await client.query(
          `UPDATE witness_tickets SET state = 'QUARANTINED_UNCONFIRMED', updated_at_seconds = $1 WHERE ticket_id = $2`,
          [now, ticketId],
        );
        await client.query(
          `INSERT INTO witness_audit_log (ticket_id, authorization_id, action, from_state, to_state, actor_id, details)
           VALUES ($1, $2, 'QUARANTINE_EXPIRED', $3, 'QUARANTINED_UNCONFIRMED', $4, $5)`,
          [ticketId, authorizationId, ticket.state, actorId, JSON.stringify({ expiredAt: ticket.expires_at_seconds, now })],
        );
        // Explicitly commit the quarantine transition so it persists before throwing
        await client.query("COMMIT");
        throw new WitnessConflictError("DENY: LEASE_EXPIRED");
      }

      if (ticket.state !== "RESERVED" && ticket.state !== "COMMITTING_SIGNING_PENDING") {
        throw new InvalidWitnessStateTransitionError(
          `Cannot commit ticket ${ticketId} in state ${ticket.state}`,
        );
      }

      // If already in COMMITTING_SIGNING_PENDING, check outbox for existing intent
      if (ticket.state === "COMMITTING_SIGNING_PENDING" && ticket.sequence_number) {
        const outboxRes = await client.query(
          `SELECT intent_id, sequence_number FROM witness_signing_outbox WHERE ticket_id = $1`,
          [ticketId],
        );
        if (outboxRes.rows.length > 0) {
          return {
            success: true,
            ticketId,
            sequenceNumber: ticket.sequence_number,
            intentId: outboxRes.rows[0].intent_id,
            epochId: ticket.epoch_id,
            preimage,
          };
        }
      }

      // Step 3: Allocate next monotonic sequence from the per-epoch generator
      // Note: Level 1 lock on witness_epochs was already acquired at Step 1 adhering to the global lock hierarchy.
      const seqNameRes = await client.query(`SELECT get_or_create_epoch_sequence($1) AS seq_name`, [ticket.epoch_id]);
      const seqName = seqNameRes.rows[0].seq_name;
      const seqRes = await client.query(`SELECT nextval(quote_ident($1)) AS seq`, [seqName]);
      const sequenceNumber = seqRes.rows[0].seq.toString();

      // Step 3: Compute deterministic signing intent ID
      const intentId = sha256Hex(`${ticket.epoch_id}:${sequenceNumber}:${preimage}`);

      // Step 4: Update ticket to COMMITTING_SIGNING_PENDING
      await client.query(
        `UPDATE witness_tickets
         SET state = 'COMMITTING_SIGNING_PENDING', sequence_number = $1, updated_at_seconds = $2
         WHERE ticket_id = $3`,
        [sequenceNumber, now, ticketId],
      );

      // Step 5: Insert into witness_signing_outbox
      await client.query(
        `INSERT INTO witness_signing_outbox (
           intent_id, ticket_id, epoch_id, sequence_number, preimage, status, retry_count,
           created_at_seconds, updated_at_seconds
         ) VALUES ($1, $2, $3, $4, $5, 'PENDING', 0, $6, $7)`,
        [intentId, ticketId, ticket.epoch_id, sequenceNumber, preimage, now, now],
      );

      // Step 6: Shift budget from held to committed
      if (budgetWindows.length > 0) {
        const sortedWindows = [...budgetWindows].sort((a, b) => {
          const idA = `${a.windowType}:${a.windowStart}`;
          const idB = `${b.windowType}:${b.windowStart}`;
          return idA.localeCompare(idB);
        });

        for (const win of sortedWindows) {
          const windowId = `${win.windowType}:${win.windowStart}`;
          const amount = BigInt(win.requestedAmount);

          await client.query(
            `UPDATE witness_accumulators
             SET held_amount = held_amount - $1, current_amount = current_amount + $1
             WHERE window_id = $2`,
            [amount.toString(), windowId],
          );
        }
      }

      // Step 7: Audit log
      await client.query(
        `INSERT INTO witness_audit_log (ticket_id, authorization_id, action, from_state, to_state, actor_id, details)
         VALUES ($1, $2, 'COMMIT_PHASE1', 'RESERVED', 'COMMITTING_SIGNING_PENDING', $3, $4)`,
        [
          ticketId,
          authorizationId,
          actorId,
          JSON.stringify({ sequenceNumber, intentId, debitedAmount }),
        ],
      );

      return {
        success: true,
        ticketId,
        sequenceNumber,
        intentId,
        epochId: ticket.epoch_id,
        preimage,
      };
    });
  }

  // ==========================================================================
  // Phase 3 Commit: Finalize Receipt & Mark Outbox Completed
  // ==========================================================================

  async commitTicketPhase3(
    ticketId: string,
    signature: Uint8Array,
    receiptJson: string,
    receiptChainHash: string,
    receiptObj: SignedWitnessReceipt,
    customActorId?: string,
  ): Promise<Phase3CommitResult> {
    const actorId = customActorId || this.actorId;
    const now = Math.floor(Date.now() / 1000);

    return await this.withSerializableTransaction("commitTicketPhase3", async (client) => {
      // Step 0: Pre-read ticket without locks to determine epoch_id, guaranteeing that
      // Level 1 witness_epochs row lock is acquired BEFORE any row lock on witness_tickets.
      const epochCheck = await client.query(
        `SELECT epoch_id FROM witness_tickets WHERE ticket_id = $1`,
        [ticketId],
      );

      if (epochCheck.rows.length === 0) {
        throw new WitnessStorageError(`Ticket not found: ${ticketId}`);
      }

      const targetEpochId = epochCheck.rows[0].epoch_id;

      // Step 1: Acquire Level 1 Lock on witness_epochs FIRST (Rank 1)
      await client.query(
        `SELECT epoch_id FROM witness_epochs WHERE epoch_id = $1 FOR SHARE`,
        [targetEpochId],
      );

      // Step 2: Lock ticket with NOWAIT (Rank 2)
      const ticketRes = await client.query(
        `SELECT ticket_id, authorization_id, epoch_id, state, sequence_number, binding_digest
         FROM witness_tickets WHERE ticket_id = $1 FOR UPDATE NOWAIT`,
        [ticketId],
      );

      const ticket = ticketRes.rows[0];

      if (ticket.state === "COMMITTED") {
        return {
          success: true,
          ticketId,
          sequenceNumber: ticket.sequence_number,
          receipt: receiptObj,
        };
      }

      if (ticket.state !== "COMMITTING_SIGNING_PENDING") {
        throw new InvalidWitnessStateTransitionError(
          `Cannot finalize Phase 3 for ticket in state ${ticket.state}`,
        );
      }

      const seq = ticket.sequence_number;

      // Step 2: Persist immutable witness receipt
      await client.query(
        `INSERT INTO witness_receipts (
           ticket_id, authorization_id, epoch_id, sequence_number, witness_timestamp_seconds,
           binding_digest, signature, receipt_json, receipt_chain_hash
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          ticketId,
          ticket.authorization_id,
          ticket.epoch_id,
          seq,
          now,
          ticket.binding_digest,
          Buffer.from(signature),
          receiptJson,
          receiptChainHash,
        ],
      );

      // Step 3: Transition ticket to COMMITTED
      await client.query(
        `UPDATE witness_tickets
         SET state = 'COMMITTED', updated_at_seconds = $1
         WHERE ticket_id = $2`,
        [now, ticketId],
      );

      // Step 4: Mark outbox intent COMPLETED
      await client.query(
        `UPDATE witness_signing_outbox
         SET status = 'COMPLETED', updated_at_seconds = $1
         WHERE ticket_id = $2`,
        [now, ticketId],
      );

      // Step 5: Audit log
      await client.query(
        `INSERT INTO witness_audit_log (ticket_id, authorization_id, action, from_state, to_state, actor_id, details)
         VALUES ($1, $2, 'COMMIT_PHASE3', 'COMMITTING_SIGNING_PENDING', 'COMMITTED', $3, $4)`,
        [ticketId, ticket.authorization_id, actorId, JSON.stringify({ sequenceNumber: seq, receiptChainHash })],
      );

      return {
        success: true,
        ticketId,
        sequenceNumber: seq,
        receipt: receiptObj,
      };
    });
  }

  // ==========================================================================
  // commitTicket (All-in-one / MonotonicWitnessAdapter interface)
  // ==========================================================================

  async commitTicket(request: WitnessCommitRequest): Promise<WitnessCommitResult> {
    const existing = await this.getReceipt(request.authorizationId);
    if (existing) {
      const parsedReceipt = JSON.parse(existing.receiptJson) as SignedWitnessReceipt;
      return {
        decision: "ALLOW",
        receipt: parsedReceipt,
        alreadyCommitted: true,
      };
    }

    const ticket = await this.getTicket(request.ticketId);
    if (!ticket) {
      return {
        decision: "DENY",
        reasons: [`DENY: TICKET_NOT_FOUND (${request.ticketId})`],
      };
    }

    if (ticket.authorizationId !== request.authorizationId) {
      throw new WitnessConflictError("DENY: IDEMPOTENCY_PAYLOAD_MISMATCH (authorization mismatch)");
    }

    if (ticket.state === "COMMITTED") {
      const receiptRec = await this.getReceipt(request.authorizationId);
      if (receiptRec) {
        return {
          decision: "ALLOW",
          receipt: JSON.parse(receiptRec.receiptJson) as SignedWitnessReceipt,
          alreadyCommitted: true,
        };
      }
    }

    // Execute Phase 1
    const preimage = `COMMIT:${this.epochId}:${request.authorizationId}:${request.bindingDigest}`;
    const p1 = await this.commitTicketPhase1(
      request.ticketId,
      request.authorizationId,
      request.bindingDigest,
      preimage,
    );

    if (p1.alreadyCommitted) {
      const receiptRec = await this.getReceipt(request.authorizationId);
      if (receiptRec) {
        return {
          decision: "ALLOW",
          receipt: JSON.parse(receiptRec.receiptJson) as SignedWitnessReceipt,
          alreadyCommitted: true,
        };
      }
    }

    // Create synthetic signature for D1 relational test verification
    // (Cryptographic HSM signing is decoupled and introduced in D3/D4)
    const mockSig = new Uint8Array(64);
    mockSig.fill(0xaa);
    const receiptChainHash = sha256Hex(`RECEIPT_HASH:${this.epochId}:${p1.sequenceNumber}`);

    const receiptObj: SignedWitnessReceipt = {
      version: 1,
      witnessId: this.actorId,
      epochId: this.epochId,
      sequenceNumber: p1.sequenceNumber,
      ticketId: request.ticketId,
      authorizationId: request.authorizationId,
      bindingDigest: request.bindingDigest,
      policyId: "default",
      policyRevision: 1,
      debitedAmount: "0",
      budgetWindows: [],
      committedAtSeconds: Math.floor(Date.now() / 1000),
      signature: Buffer.from(mockSig).toString("hex"),
    };

    const p3 = await this.commitTicketPhase3(
      request.ticketId,
      mockSig,
      JSON.stringify(receiptObj),
      receiptChainHash,
      receiptObj,
    );

    return {
      decision: "ALLOW",
      receipt: p3.receipt,
    };
  }

  // ==========================================================================
  // Release Ticket
  // ==========================================================================

  async releaseTicket(
    request: WitnessReleaseRequest,
    customActorId?: string,
  ): Promise<WitnessReleaseResult> {
    const actorId = customActorId || this.actorId;
    const now = Math.floor(Date.now() / 1000);

    return await this.withSerializableTransaction("releaseTicket", async (client) => {
      // Step 0: Pre-read ticket without locks to determine epoch_id, guaranteeing that
      // Level 1 witness_epochs row lock is acquired BEFORE any row lock on witness_tickets.
      const epochCheck = await client.query(
        `SELECT epoch_id FROM witness_tickets WHERE ticket_id = $1`,
        [request.ticketId],
      );

      if (epochCheck.rows.length === 0) {
        return {
          success: false,
          reasons: [`Ticket not found: ${request.ticketId}`],
        };
      }

      const targetEpochId = epochCheck.rows[0].epoch_id;

      // Step 1: Acquire Level 1 Lock on witness_epochs FIRST (Rank 1)
      await client.query(
        `SELECT epoch_id FROM witness_epochs WHERE epoch_id = $1 FOR SHARE`,
        [targetEpochId],
      );

      // Step 2: Lock ticket row with NOWAIT (Rank 2)
      const ticketRes = await client.query(
        `SELECT ticket_id, authorization_id, epoch_id, state, binding_digest
         FROM witness_tickets WHERE ticket_id = $1 FOR UPDATE NOWAIT`,
        [request.ticketId],
      );

      const ticket = ticketRes.rows[0];

      // Terminality check: COMMITTED tickets can NEVER be released
      if (ticket.state === "COMMITTED") {
        throw new InvalidWitnessStateTransitionError(
          `Cannot release a COMMITTED witness ticket; state is terminal. Zero budget refund permitted.`,
        );
      }

      if (ticket.state === "RELEASED") {
        return {
          success: true,
          previousState: "RELEASED",
          reasons: ["ALREADY_RELEASED"],
        };
      }

      if (ticket.state !== "RESERVED") {
        throw new InvalidWitnessStateTransitionError(
          `Cannot release ticket in non-reservable state: ${ticket.state}`,
        );
      }

      // Transition ticket to RELEASED
      await client.query(
        `UPDATE witness_tickets SET state = 'RELEASED', updated_at_seconds = $1 WHERE ticket_id = $2`,
        [now, request.ticketId],
      );

      // Audit log
      await client.query(
        `INSERT INTO witness_audit_log (ticket_id, authorization_id, action, from_state, to_state, actor_id, details)
         VALUES ($1, $2, 'RELEASE', 'RESERVED', 'RELEASED', $3, $4)`,
        [request.ticketId, request.authorizationId, actorId, JSON.stringify({ reason: request.reason })],
      );

      return {
        success: true,
        previousState: "RESERVED",
      };
    });
  }

  // ==========================================================================
  // Quarantine Ticket & Gap Preservation
  // ==========================================================================

  async quarantineTicket(
    ticketId: string,
    toState: "QUARANTINED_UNCONFIRMED" | "QUARANTINED_BLOCKED",
    reason: string,
    customActorId?: string,
  ): Promise<void> {
    const actorId = customActorId || this.actorId;
    const now = Math.floor(Date.now() / 1000);

    await this.withSerializableTransaction("quarantineTicket", async (client) => {
      // Step 0: Pre-read ticket without locks to determine epoch_id, guaranteeing that
      // Level 1 witness_epochs row lock is acquired BEFORE any row lock on witness_tickets.
      const epochCheck = await client.query(
        `SELECT epoch_id FROM witness_tickets WHERE ticket_id = $1`,
        [ticketId],
      );

      if (epochCheck.rows.length === 0) {
        throw new WitnessStorageError(`Ticket not found: ${ticketId}`);
      }

      const targetEpochId = epochCheck.rows[0].epoch_id;

      // Step 1: Acquire Level 1 Lock on witness_epochs FIRST (Rank 1)
      await client.query(
        `SELECT epoch_id FROM witness_epochs WHERE epoch_id = $1 FOR SHARE`,
        [targetEpochId],
      );

      // Step 2: Lock ticket row with NOWAIT (Rank 2)
      const ticketRes = await client.query(
        `SELECT ticket_id, authorization_id, epoch_id, state, sequence_number FROM witness_tickets WHERE ticket_id = $1 FOR UPDATE NOWAIT`,
        [ticketId],
      );

      const ticket = ticketRes.rows[0];

      // Mark outbox FAILED if present, but retain sequence number permanently
      await client.query(
        `UPDATE witness_signing_outbox SET status = 'FAILED', last_error = $1, updated_at_seconds = $2 WHERE ticket_id = $3`,
        [reason, now, ticketId],
      );

      // Record sequence gap if sequence was allocated
      if (ticket.sequence_number) {
        await client.query(
          `INSERT INTO witness_sequence_gaps (epoch_id, sequence_number, gap_reason, ticket_id, detected_at_seconds, details)
           VALUES ($1, $2, 'OUTBOX_FAILED', $3, $4, $5)
           ON CONFLICT (epoch_id, sequence_number) DO UPDATE
           SET gap_reason = EXCLUDED.gap_reason, details = EXCLUDED.details`,
          [ticket.epoch_id, ticket.sequence_number, ticketId, now, JSON.stringify({ reason, state: toState })],
        );
      }

      // Transition ticket
      await client.query(
        `UPDATE witness_tickets SET state = $1, updated_at_seconds = $2 WHERE ticket_id = $3`,
        [toState, now, ticketId],
      );

      // Audit log
      await client.query(
        `INSERT INTO witness_audit_log (ticket_id, authorization_id, action, from_state, to_state, actor_id, details)
         VALUES ($1, $2, 'QUARANTINE', $3, $4, $5, $6)`,
        [ticketId, ticket.authorization_id, ticket.state, toState, actorId, JSON.stringify({ reason })],
      );
    });
  }

  // ==========================================================================
  // Reconcile Ticket
  // ==========================================================================

  async reconcileTicket(request: WitnessReconcileRequest): Promise<WitnessReconcileResult> {
    const ticket = await this.getTicket(request.ticketId);
    if (!ticket) {
      return {
        ticketId: request.ticketId,
        state: "DISPUTED",
        reasons: ["TICKET_NOT_FOUND"],
      };
    }

    if (ticket.state === "COMMITTED") {
      const receiptRec = await this.getReceipt(ticket.authorizationId);
      if (receiptRec) {
        return {
          ticketId: request.ticketId,
          state: "COMMITTED",
          receipt: JSON.parse(receiptRec.receiptJson) as SignedWitnessReceipt,
        };
      }
    }

    return {
      ticketId: request.ticketId,
      state: ticket.state as WitnessTicketState,
    };
  }

  // ==========================================================================
  // Status and Inspection
  // ==========================================================================

  async getSyncStatus(lastSeenEpoch?: string, lastSeenSeq?: string): Promise<WitnessSyncStatus> {
    const client = await this.pool.connect();
    try {
      const res = await client.query(
        `SELECT COALESCE(MAX(sequence_number), 0) AS max_seq FROM witness_tickets WHERE epoch_id = $1`,
        [this.epochId],
      );
      const currentSeq = res.rows[0].max_seq.toString();

      let divergence = false;
      let reason: string | undefined;

      if (lastSeenEpoch && lastSeenEpoch === this.epochId && lastSeenSeq) {
        if (BigInt(currentSeq) < BigInt(lastSeenSeq)) {
          divergence = true;
          reason = `Sequence regression detected: witnessSeq=${currentSeq} < lastSeenSeq=${lastSeenSeq}`;
        }
      }

      return {
        healthy: true,
        epochId: this.epochId,
        sequenceNumber: currentSeq,
        divergenceDetected: divergence,
        reason,
      };
    } finally {
      client.release();
    }
  }

  async getTicket(ticketId: string): Promise<WitnessTicketRecord | null> {
    const res = await this.pool.query(
      `SELECT ticket_id, authorization_id, epoch_id, state, binding_digest,
              sequence_number, expires_at_seconds, created_at_seconds, updated_at_seconds, idempotency_key
       FROM witness_tickets WHERE ticket_id = $1`,
      [ticketId],
    );
    if (res.rows.length === 0) return null;
    const r = res.rows[0];
    return {
      ticketId: r.ticket_id,
      authorizationId: r.authorization_id,
      epochId: r.epoch_id,
      state: r.state,
      bindingDigest: r.binding_digest,
      sequenceNumber: r.sequence_number ? r.sequence_number.toString() : null,
      expiresAtSeconds: Number(r.expires_at_seconds),
      createdAtSeconds: Number(r.created_at_seconds),
      updatedAtSeconds: Number(r.updated_at_seconds),
      idempotencyKey: r.idempotency_key,
    };
  }

  async getTicketByAuthorizationId(authorizationId: string): Promise<WitnessTicketRecord | null> {
    const res = await this.pool.query(
      `SELECT ticket_id, authorization_id, epoch_id, state, binding_digest,
              sequence_number, expires_at_seconds, created_at_seconds, updated_at_seconds, idempotency_key
       FROM witness_tickets WHERE authorization_id = $1`,
      [authorizationId],
    );
    if (res.rows.length === 0) return null;
    const r = res.rows[0];
    return {
      ticketId: r.ticket_id,
      authorizationId: r.authorization_id,
      epochId: r.epoch_id,
      state: r.state,
      bindingDigest: r.binding_digest,
      sequenceNumber: r.sequence_number ? r.sequence_number.toString() : null,
      expiresAtSeconds: Number(r.expires_at_seconds),
      createdAtSeconds: Number(r.created_at_seconds),
      updatedAtSeconds: Number(r.updated_at_seconds),
      idempotencyKey: r.idempotency_key,
    };
  }

  async getReceipt(authorizationId: string): Promise<WitnessReceiptRecord | null> {
    const res = await this.pool.query(
      `SELECT ticket_id, authorization_id, epoch_id, sequence_number, witness_timestamp_seconds,
              binding_digest, signature, receipt_json, receipt_chain_hash
       FROM witness_receipts WHERE authorization_id = $1`,
      [authorizationId],
    );
    if (res.rows.length === 0) return null;
    const r = res.rows[0];
    return {
      ticketId: r.ticket_id,
      authorizationId: r.authorization_id,
      epochId: r.epoch_id,
      sequenceNumber: r.sequence_number.toString(),
      witnessTimestampSeconds: Number(r.witness_timestamp_seconds),
      bindingDigest: r.binding_digest,
      signature: new Uint8Array(r.signature),
      receiptJson: r.receipt_json,
      receiptChainHash: r.receipt_chain_hash,
    };
  }

  async getAccumulator(windowId: string): Promise<WitnessAccumulatorRecord | null> {
    const res = await this.pool.query(
      `SELECT window_id, window_type, window_start, current_amount, held_amount, max_limit
       FROM witness_accumulators WHERE window_id = $1`,
      [windowId],
    );
    if (res.rows.length === 0) return null;
    const r = res.rows[0];
    return {
      windowId: r.window_id,
      windowType: r.window_type,
      windowStart: Number(r.window_start),
      currentAmount: r.current_amount.toString(),
      heldAmount: r.held_amount.toString(),
      maxLimit: r.max_limit.toString(),
    };
  }

  async getOutbox(ticketId: string): Promise<WitnessOutboxRecord | null> {
    const res = await this.pool.query(
      `SELECT intent_id, ticket_id, epoch_id, sequence_number, preimage, status, retry_count,
              last_error, created_at_seconds, updated_at_seconds
       FROM witness_signing_outbox WHERE ticket_id = $1`,
      [ticketId],
    );
    if (res.rows.length === 0) return null;
    const r = res.rows[0];
    return {
      intentId: r.intent_id,
      ticketId: r.ticket_id,
      epochId: r.epoch_id,
      sequenceNumber: r.sequence_number.toString(),
      preimage: r.preimage,
      status: r.status,
      retryCount: Number(r.retry_count),
      lastError: r.last_error,
      createdAtSeconds: Number(r.created_at_seconds),
      updatedAtSeconds: Number(r.updated_at_seconds),
    };
  }
}
