/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.2 (Step 4)
 * PostgresConsensusStore: Two-Phase State Publication, Tier-2 Replay & Recovery
 *
 * Bridges the pure deterministic reducer (`ConsensusStateMachine`) to durable
 * PostgreSQL persistence (`witness_consensus_log`, `witness_raft_state`,
 * `witness_snapshots`) under strict ACID invariants:
 *
 * - INV-AUTH-01 (PostgreSQL Authority): Candidate state is never published in memory
 *   until the corresponding PostgreSQL transaction has committed successfully.
 * - INV-RET-01 (Durable Retention): `last_consecutive_persisted_index` advances
 *   only on contiguous, committed consensus log entries.
 * - INV-REP-01 (Two-Tier Idempotent Replay): In-memory verification for
 *   `L >= F_ret`, PostgreSQL `witness_consensus_log` lookup for `L < F_ret`.
 * - Single-writer serialization via `SELECT ... FROM witness_raft_state FOR UPDATE`.
 * - Deterministic 5-step hash-chain replay and genesis recovery.
 */

import pg, { type PoolClient, type PoolConfig } from "pg";
import {
  type ApplicationState,
  type BackpressureConfig,
  type BackpressureEvaluation,
  type BackpressureStreamState,
  type CommittedConsensusEntry,
  type ConsensusCommandType,
  type EpochInitializePayload,
  type PhysicalStreamCursor,
  type StateMachineApplyOptions,
  type StateMachineApplyStatus,
  type TicketCommitPayload,
  PayloadHashMismatchError,
  StateMachineError,
  UnverifiableHistoricalEntryError,
  HistoricalIndexConflictError,
} from "./state-machine-types.js";
import {
  BackpressurePolicy,
  ConsensusStateMachine,
  computeCanonicalPayloadHash,
  createInitialState,
} from "./state-machine.js";
import { PG_SQLSTATE } from "./postgres-store.js";

const { Pool } = pg;

// ============================================================================
// Constants & Error Types
// ============================================================================

export const GENESIS_CHAIN_HEAD_HASH =
  "0000000000000000000000000000000000000000000000000000000000000000";

export class ConsensusStoreError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly originalError?: unknown
  ) {
    super(message);
    this.name = "ConsensusStoreError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class ConsensusConflictError extends ConsensusStoreError {
  constructor(
    message: string,
    public readonly conflictKind: "PROPOSAL_ID" | "LOG_INDEX" | "UNIQUE_VIOLATION",
    originalError?: unknown
  ) {
    super(message, `CONSENSUS_CONFLICT_${conflictKind}`, originalError);
    this.name = "ConsensusConflictError";
  }
}

export class UnverifiableDurableHistoryError extends ConsensusStoreError {
  constructor(message: string, public readonly epochId: string) {
    super(message, "UNVERIFIABLE_DURABLE_HISTORY");
    this.name = "UnverifiableDurableHistoryError";
  }
}

export class StaleAuthoritativeStateError extends ConsensusStoreError {
  constructor(
    public readonly inMemoryIndex: bigint,
    public readonly databaseIndex: bigint
  ) {
    super(
      `In-memory authoritative state (index ${inMemoryIndex.toString()}) is behind PostgreSQL durable state (index ${databaseIndex.toString()}); call recover() before applying new entries`,
      "STALE_AUTHORITATIVE_STATE"
    );
    this.name = "StaleAuthoritativeStateError";
  }
}

export class ReplayVerificationError extends ConsensusStoreError {
  constructor(message: string, code = "REPLAY_VERIFICATION_FAILED", originalError?: unknown) {
    super(message, code, originalError);
    this.name = "ReplayVerificationError";
  }
}

// ============================================================================
// Options, Snapshot Loader & Result Contracts
// ============================================================================

export interface PersistedSnapshotRecord {
  readonly snapshotId: string;
  readonly clusterId: string;
  readonly epochId: string;
  readonly snapshotIndex: bigint;
  readonly snapshotHash: string;
  readonly chainHeadHash: string;
  readonly etcdRevision: bigint;
  readonly subIndex: number;
  readonly formatVersion: number;
  readonly canonicalizationVersion: 1 | 2;
  readonly storageBackend: string;
  readonly storageUri: string;
  readonly byteSize: bigint;
  readonly createdAtSeconds: number;
}

/**
 * Optional snapshot rehydrator interface used during Step 4 replay before
 * Step 5 (`SnapshotManager`) is integrated. Must verify blob integrity
 * (e.g., SHA-256 against `record.snapshotHash`) and return null if corrupt/unavailable
 * so replay can fall back to an earlier snapshot or genesis.
 */
export interface ConsensusSnapshotLoader {
  loadAndVerify(record: PersistedSnapshotRecord): Promise<ApplicationState | null>;
}

export interface PostgresConsensusStoreOptions {
  readonly pool?: pg.Pool;
  readonly poolConfig?: PoolConfig;
  readonly clusterId?: string;
  /**
   * Optional per-transaction `SET LOCAL statement_timeout` in milliseconds.
   * Defaults to 10,000 ms. Set to 0 to disable.
   */
  readonly statementTimeoutMs?: number;
  /**
   * Default retention window (W_mem) passed to `ConsensusStateMachine.apply()`.
   */
  readonly memoryRetentionWindow?: bigint;
  /**
   * Default backpressure configuration overrides.
   */
  readonly backpressureConfig?: Partial<BackpressureConfig>;
}

export interface ConsensusStoreApplyOptions extends StateMachineApplyOptions {
  /**
   * Test-only / fault-injection hook invoked strictly after PostgreSQL `COMMIT`
   * succeeds and immediately before `this.authoritativeState` is published.
   */
  readonly onAfterCommitBeforePublish?: () => void;
}

export interface ConsensusStoreApplyResult {
  readonly status: StateMachineApplyStatus;
  readonly committedToDatabase: boolean;
  readonly verifiedViaTier2: boolean;
  readonly appliedAppIndex: bigint;
  readonly appliedRaftTerm: bigint;
  readonly physicalCursor: PhysicalStreamCursor;
  readonly chainHeadHash: string;
  readonly state: ApplicationState;
  readonly rejectionReason?: string;
  readonly duplicateDetected?: boolean;
  readonly retentionFloorIndex?: bigint;
}

export interface ConsensusStoreRecoverOptions {
  readonly memoryRetentionWindow?: bigint;
  readonly enforceBacklogLimit?: boolean;
  readonly snapshotLoader?: ConsensusSnapshotLoader;
}

export interface PersistedRaftStateRecord {
  readonly clusterId: string;
  readonly epochId: string;
  readonly lastAppliedIndex: bigint;
  readonly lastAppliedTerm: bigint;
  readonly lastAppliedHash: string;
  readonly updatedAtSeconds: number;
  readonly lastAppliedEtcdRevision: bigint;
  readonly lastAppliedSubIndex: number;
  readonly lastConsecutivePersistedIndex: bigint;
  readonly lastSnapshotIndex: bigint;
  readonly lastSnapshotHash: string;
}

// ============================================================================
// Payload Serialization & Hydration Helpers
// ============================================================================

function serializePayloadToJsonb(payload: unknown): string {
  return JSON.stringify(payload, (_key, value) =>
    typeof value === "bigint" ? value.toString() : value
  );
}

function parseBigIntField(value: unknown, fieldName: string): bigint {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "string" && /^-?\d+$/.test(value)) {
    return BigInt(value);
  }
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return BigInt(value);
  }
  throw new ReplayVerificationError(
    `Invalid bigint value for payload field '${fieldName}': ${String(value)}`,
    "INVALID_PERSISTED_PAYLOAD"
  );
}

/**
 * Re-hydrates known `bigint` fields in `ConsensusPayloadMap` after reading
 * JSONB from PostgreSQL so both `ConsensusStateMachine.apply()` and
 * `computeCanonicalPayloadHash(..., 1 | 2)` observe exact domain types.
 */
function hydratePayloadFromJsonb(
  commandType: ConsensusCommandType,
  rawPayload: unknown
): unknown {
  if (rawPayload === null || typeof rawPayload !== "object" || Array.isArray(rawPayload)) {
    return rawPayload;
  }

  const record = rawPayload as Record<string, unknown>;

  if (commandType === "EPOCH_INITIALIZE") {
    return {
      ...record,
      sequenceFloor: parseBigIntField(record.sequenceFloor, "sequenceFloor"),
    } satisfies Record<string, unknown> as unknown as EpochInitializePayload;
  }

  if (commandType === "TICKET_COMMIT") {
    const hydrated: Record<string, unknown> = {
      ...record,
      debitedAmount: parseBigIntField(record.debitedAmount ?? 0, "debitedAmount"),
    };
    if (Array.isArray(record.budgetWindows)) {
      hydrated.budgetWindows = record.budgetWindows.map((win: unknown, idx: number) => {
        if (win === null || typeof win !== "object" || Array.isArray(win)) {
          return win;
        }
        const w = win as Record<string, unknown>;
        return {
          ...w,
          cumulativeSpentAfter: parseBigIntField(
            w.cumulativeSpentAfter,
            `budgetWindows[${idx}].cumulativeSpentAfter`
          ),
        };
      });
    }
    return hydrated as unknown as TicketCommitPayload;
  }

  return rawPayload;
}

function normalizeCanonVersion(raw: unknown): 1 | 2 {
  const num = Number(raw);
  if (num === 1 || num === 2) {
    return num;
  }
  throw new ReplayVerificationError(
    `Unsupported persisted canonicalization_version: ${String(raw)}`,
    "INVALID_CANONICALIZATION_VERSION"
  );
}

function getPgErrorCode(err: unknown): string | undefined {
  if (err && typeof err === "object" && "code" in err) {
    const code = (err as { code?: unknown }).code;
    return typeof code === "string" ? code : undefined;
  }
  return undefined;
}

function getPgErrorConstraint(err: unknown): string | undefined {
  if (err && typeof err === "object" && "constraint" in err) {
    const constraint = (err as { constraint?: unknown }).constraint;
    return typeof constraint === "string" ? constraint : undefined;
  }
  return undefined;
}

// ============================================================================
// PostgresConsensusStore Implementation
// ============================================================================

export class PostgresConsensusStore {
  private readonly pool: pg.Pool;
  private readonly ownPool: boolean;
  private readonly clusterId: string;
  private readonly statementTimeoutMs: number;
  private readonly defaultMemoryRetentionWindow: bigint;
  private readonly defaultBackpressureConfig?: Partial<BackpressureConfig>;
  private authoritativeState: ApplicationState;
  private closed = false;
  /**
   * FIFO in-process async mutex serializing the full transaction-to-publication
   * sequence on this `PostgresConsensusStore` instance.
   * Note: Protects a single store instance in-process; cross-process concurrency
   * is enforced by PostgreSQL `SELECT ... FOR UPDATE` on `witness_raft_state`.
   */
  private mutexTail: Promise<void> = Promise.resolve();

  constructor(options: PostgresConsensusStoreOptions = {}) {
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

    this.clusterId = options.clusterId ?? "default-cluster";
    if (!this.clusterId || this.clusterId.trim().length === 0) {
      throw new ConsensusStoreError("clusterId must be a non-empty string", "INVALID_CLUSTER_ID");
    }

    const timeout = options.statementTimeoutMs ?? 10_000;
    if (!Number.isInteger(timeout) || timeout < 0) {
      throw new ConsensusStoreError(
        "statementTimeoutMs must be a non-negative integer",
        "INVALID_STATEMENT_TIMEOUT"
      );
    }
    this.statementTimeoutMs = timeout;
    this.defaultMemoryRetentionWindow =
      options.memoryRetentionWindow ?? BackpressurePolicy.DEFAULTS.memoryRetentionWindow;
    this.defaultBackpressureConfig = options.backpressureConfig;

    this.authoritativeState = createInitialState(this.clusterId);
  }

  /**
   * Returns the currently published, PostgreSQL-backed authoritative state.
   * Uncommitted candidate states are never exposed through this accessor.
   */
  public getAuthoritativeState(): ApplicationState {
    return this.authoritativeState;
  }

  public getClusterId(): string {
    return this.clusterId;
  }

  public async close(): Promise<void> {
    this.closed = true;
    await this.mutexTail;
    if (this.ownPool) {
      await this.pool.end();
    }
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new ConsensusStoreError("PostgresConsensusStore is closed", "STORE_CLOSED");
    }
  }

  /**
   * Serializes operations on this store instance in strict FIFO order.
   * Always releases the mutex on both resolution and rejection.
   */
  private async withMutex<T>(fn: () => Promise<T>): Promise<T> {
    const prev = this.mutexTail;
    let release!: () => void;
    this.mutexTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await prev;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  /**
   * Pure delegation to Step 2 `BackpressurePolicy.evaluate()` using the currently
   * published authoritative state.
   */
  public evaluateBackpressure(
    currentStreamState: BackpressureStreamState,
    elapsedPauseSeconds = 0,
    retryAttempts = 0,
    configOverride?: Partial<BackpressureConfig>
  ): BackpressureEvaluation {
    const state = this.authoritativeState;
    return BackpressurePolicy.evaluate(
      currentStreamState,
      state.lastAppliedAppIndex,
      state.lastConsecutivePersistedAppIndex,
      BigInt(state.appliedIndices.size),
      elapsedPauseSeconds,
      retryAttempts,
      {
        memoryRetentionWindow: this.defaultMemoryRetentionWindow,
        ...this.defaultBackpressureConfig,
        ...configOverride,
      }
    );
  }

  /**
   * Reads the current `witness_raft_state` row for `(clusterId, epochId)` if present.
   */
  public async getRaftState(epochId: string): Promise<PersistedRaftStateRecord | null> {
    this.assertOpen();
    const res = await this.pool.query(
      `SELECT cluster_id, epoch_id, last_applied_index, last_applied_term, last_applied_hash,
              updated_at_seconds, last_applied_etcd_revision, last_applied_sub_index,
              last_consecutive_persisted_index, last_snapshot_index, last_snapshot_hash
       FROM witness_raft_state
       WHERE cluster_id = $1 AND epoch_id = $2`,
      [this.clusterId, epochId]
    );

    if (res.rowCount === 0) {
      return null;
    }

    return this.mapRaftStateRow(res.rows[0]);
  }

  // ==========================================================================
  // Two-Phase State Publication: applyEntry()
  // ==========================================================================

  /**
   * Applies a committed consensus entry using strict Two-Phase State Publication:
   * 1. Acquires single-writer lock on `witness_raft_state` (`FOR UPDATE`).
   * 2. Verifies in-memory state parity with PostgreSQL durable watermark.
   * 3. Evaluates `ConsensusStateMachine.apply()` into an isolated `candidateState`.
   * 4. If `HISTORICAL_RECORD_PRUNED`, performs Tier-2 verification against `witness_consensus_log`.
   * 5. If `APPLIED`, inserts into `witness_consensus_log` and updates `witness_raft_state`
   *    within a single ACID transaction.
   * 6. Only after `COMMIT` succeeds is `this.authoritativeState` updated.
   */
  public async applyEntry(
    entry: CommittedConsensusEntry,
    options: ConsensusStoreApplyOptions = {}
  ): Promise<ConsensusStoreApplyResult> {
    this.assertOpen();

    if (!entry) {
      throw new StateMachineError("Cannot apply undefined or null consensus entry", "INVALID_ARGUMENT");
    }
    if (!entry.epochId || entry.epochId.trim().length === 0) {
      throw new StateMachineError("Consensus entry epochId must be non-empty", "INVALID_EPOCH_ID");
    }
    if (!entry.proposalId || entry.proposalId.trim().length === 0) {
      throw new StateMachineError("Consensus entry proposalId must be non-empty", "INVALID_PROPOSAL_ID");
    }

    const canonVersion: 1 | 2 = entry.canonicalizationVersion ?? 1;
    const computedPayloadHash = computeCanonicalPayloadHash(entry.payload, canonVersion);
    if (entry.payloadHash && entry.payloadHash !== computedPayloadHash) {
      throw new PayloadHashMismatchError(entry.appLogIndex, entry.payloadHash, computedPayloadHash);
    }

    return this.withMutex(async () => {
      this.assertOpen();
      return this.applyEntryInternal(entry, options, canonVersion, computedPayloadHash);
    });
  }

  private async applyEntryInternal(
    entry: CommittedConsensusEntry,
    options: ConsensusStoreApplyOptions,
    canonVersion: 1 | 2,
    computedPayloadHash: string
  ): Promise<ConsensusStoreApplyResult> {
    const lockEpochId = this.resolveLockEpochId(entry);
    const client = await this.pool.connect();
    let inTransaction = false;

    try {
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED");
      inTransaction = true;

      if (this.statementTimeoutMs > 0) {
        await client.query(`SET LOCAL statement_timeout = ${this.statementTimeoutMs}`);
      }

      // 1. Atomic bootstrap + single-writer row lock on witness_raft_state
      const lockedRaftState = await this.bootstrapAndLockRaftState(client, lockEpochId);

      // 2. Fail closed if in-memory authoritative state is behind PostgreSQL
      if (
        lockedRaftState.lastConsecutivePersistedIndex >
        this.authoritativeState.lastConsecutivePersistedAppIndex
      ) {
        throw new StaleAuthoritativeStateError(
          this.authoritativeState.lastConsecutivePersistedAppIndex,
          lockedRaftState.lastConsecutivePersistedIndex
        );
      }

      // 3. Evaluate pure transition into isolated candidateState
      const memoryRetentionWindow =
        options.memoryRetentionWindow ?? this.defaultMemoryRetentionWindow;
      const applyResult = ConsensusStateMachine.apply(this.authoritativeState, entry, {
        ...options,
        memoryRetentionWindow,
        lastConsecutivePersistedAppIndex: lockedRaftState.lastConsecutivePersistedIndex,
        backpressureConfig: options.backpressureConfig ?? this.defaultBackpressureConfig,
      });

      // 4A. Tier-2 Verification (Historical entry pruned from memory)
      if (applyResult.status === "HISTORICAL_RECORD_PRUNED") {
        await this.verifyTier2HistoricalEntry(client, entry, computedPayloadHash);
        await client.query("COMMIT");
        inTransaction = false;
        return {
          status: "ALREADY_APPLIED",
          committedToDatabase: false,
          verifiedViaTier2: true,
          appliedAppIndex: this.authoritativeState.lastAppliedAppIndex,
          appliedRaftTerm: this.authoritativeState.lastAppliedRaftTerm,
          physicalCursor: this.authoritativeState.lastPhysicalCursor,
          chainHeadHash: this.authoritativeState.chainHeadHash,
          state: this.authoritativeState,
          duplicateDetected: true,
          retentionFloorIndex: this.authoritativeState.retentionFloorIndex,
        };
      }

      // 4B. Tier-1 Idempotent Duplicate or Domain Rejection (no DB write)
      if (applyResult.status === "ALREADY_APPLIED" || applyResult.status === "COMMAND_REJECTED") {
        await client.query("COMMIT");
        inTransaction = false;
        return {
          ...applyResult,
          committedToDatabase: false,
          verifiedViaTier2: false,
        };
      }

      // 5. Durable Write: witness_consensus_log + witness_raft_state in single ACID tx
      const candidateState = applyResult.state;
      const serializedPayload = serializePayloadToJsonb(entry.payload);
      const nowSeconds = Math.floor(Date.now() / 1000);

      await this.insertConsensusLogRow(
        client,
        entry,
        serializedPayload,
        computedPayloadHash,
        canonVersion
      );

      // Update witness_raft_state for lockEpochId
      await client.query(
        `UPDATE witness_raft_state
         SET last_applied_index = $1,
             last_applied_term = $2,
             last_applied_hash = $3,
             updated_at_seconds = $4,
             last_applied_etcd_revision = $5,
             last_applied_sub_index = $6,
             last_consecutive_persisted_index = $7
         WHERE cluster_id = $8 AND epoch_id = $9`,
        [
          candidateState.lastAppliedAppIndex.toString(),
          candidateState.lastAppliedRaftTerm.toString(),
          candidateState.chainHeadHash,
          nowSeconds,
          candidateState.lastPhysicalCursor.etcdRevision.toString(),
          candidateState.lastPhysicalCursor.subIndex,
          candidateState.lastAppliedAppIndex.toString(),
          this.clusterId,
          lockEpochId,
        ]
      );

      // F-STEP4-01: On EPOCH_ADVANCE, atomically seed/update witness_raft_state for the
      // target epochId within the same ACID transaction so subsequent entries in the new
      // epoch inherit the monotonic durable watermark and chain-head state.
      if (entry.commandType === "EPOCH_ADVANCE" && candidateState.epochId !== lockEpochId) {
        await client.query(
          `INSERT INTO witness_raft_state (
             cluster_id, epoch_id, last_applied_index, last_applied_term, last_applied_hash,
             updated_at_seconds, last_applied_etcd_revision, last_applied_sub_index,
             last_consecutive_persisted_index, last_snapshot_index, last_snapshot_hash
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, '')
           ON CONFLICT (cluster_id, epoch_id) DO UPDATE SET
             last_applied_index = EXCLUDED.last_applied_index,
             last_applied_term = EXCLUDED.last_applied_term,
             last_applied_hash = EXCLUDED.last_applied_hash,
             updated_at_seconds = EXCLUDED.updated_at_seconds,
             last_applied_etcd_revision = EXCLUDED.last_applied_etcd_revision,
             last_applied_sub_index = EXCLUDED.last_applied_sub_index,
             last_consecutive_persisted_index = EXCLUDED.last_consecutive_persisted_index`,
          [
            this.clusterId,
            candidateState.epochId,
            candidateState.lastAppliedAppIndex.toString(),
            candidateState.lastAppliedRaftTerm.toString(),
            candidateState.chainHeadHash,
            nowSeconds,
            candidateState.lastPhysicalCursor.etcdRevision.toString(),
            candidateState.lastPhysicalCursor.subIndex,
            candidateState.lastAppliedAppIndex.toString(),
          ]
        );
      }

      // 6. Commit PostgreSQL transaction
      await client.query("COMMIT");
      inTransaction = false;

      // Optional test hook for crash-around-commit simulation
      if (options.onAfterCommitBeforePublish) {
        options.onAfterCommitBeforePublish();
      }

      // 7. Phase 2: Publish committed candidate state in memory
      const publishedState: ApplicationState = Object.freeze({
        ...candidateState,
        lastConsecutivePersistedAppIndex: candidateState.lastAppliedAppIndex,
      });
      this.authoritativeState = publishedState;

      return {
        status: "APPLIED",
        committedToDatabase: true,
        verifiedViaTier2: false,
        appliedAppIndex: publishedState.lastAppliedAppIndex,
        appliedRaftTerm: publishedState.lastAppliedRaftTerm,
        physicalCursor: publishedState.lastPhysicalCursor,
        chainHeadHash: publishedState.chainHeadHash,
        state: publishedState,
        retentionFloorIndex: publishedState.retentionFloorIndex,
      };
    } catch (err) {
      if (inTransaction) {
        try {
          await client.query("ROLLBACK");
        } catch {
          // Best-effort rollback on connection/tx error; client will be released
        }
      }
      throw this.classifyDatabaseError(err, entry);
    } finally {
      client.release();
    }
  }

  // ==========================================================================
  // 5-Step Deterministic Replay & Recovery: recover()
  // ==========================================================================

  /**
   * Reconstructs authoritative in-memory state strictly from PostgreSQL durable
   * records (`witness_raft_state`, `witness_snapshots`, `witness_consensus_log`).
   *
   * Fails closed on any gap, missing record, hash mismatch, or chain-head mismatch.
   * Publishes the reconstructed state only after full verification succeeds.
   */
  public async recover(
    epochId: string,
    options: ConsensusStoreRecoverOptions = {}
  ): Promise<ApplicationState> {
    this.assertOpen();
    if (!epochId || epochId.trim().length === 0) {
      throw new ConsensusStoreError("epochId must be non-empty for recovery", "INVALID_EPOCH_ID");
    }

    return this.withMutex(async () => {
      this.assertOpen();
      return this.recoverInternal(epochId, options);
    });
  }

  private async recoverInternal(
    epochId: string,
    options: ConsensusStoreRecoverOptions
  ): Promise<ApplicationState> {
    const client = await this.pool.connect();
    try {
      // 1. Inspect witness_raft_state and witness_consensus_log summary
      const raftRes = await client.query(
        `SELECT cluster_id, epoch_id, last_applied_index, last_applied_term, last_applied_hash,
                updated_at_seconds, last_applied_etcd_revision, last_applied_sub_index,
                last_consecutive_persisted_index, last_snapshot_index, last_snapshot_hash
         FROM witness_raft_state
         WHERE cluster_id = $1 AND epoch_id = $2`,
        [this.clusterId, epochId]
      );

      const logStatsRes = await client.query(
        `SELECT MIN(log_index) AS min_idx,
                MAX(log_index) AS max_idx,
                COUNT(*)::BIGINT AS total_rows
         FROM witness_consensus_log
         WHERE epoch_id = $1`,
        [epochId]
      );

      const totalRows = BigInt(logStatsRes.rows[0].total_rows ?? 0);
      const maxLogIndex =
        logStatsRes.rows[0].max_idx !== null ? BigInt(logStatsRes.rows[0].max_idx) : 0n;

      // Empty epoch handling
      if (raftRes.rowCount === 0) {
        if (totalRows > 0n) {
          throw new UnverifiableDurableHistoryError(
            `witness_consensus_log contains ${totalRows.toString()} row(s) for epoch '${epochId}' but witness_raft_state row is missing`,
            epochId
          );
        }
        const emptyState = createInitialState(this.clusterId);
        this.authoritativeState = emptyState;
        return emptyState;
      }

      const raftState = this.mapRaftStateRow(raftRes.rows[0]);
      const L_c_persisted = raftState.lastConsecutivePersistedIndex;

      if (L_c_persisted === 0n) {
        if (totalRows > 0n) {
          throw new UnverifiableDurableHistoryError(
            `witness_raft_state.last_consecutive_persisted_index is 0 for epoch '${epochId}', but witness_consensus_log has ${totalRows.toString()} row(s)`,
            epochId
          );
        }
        const emptyState = createInitialState(this.clusterId);
        this.authoritativeState = emptyState;
        return emptyState;
      }

      if (maxLogIndex > L_c_persisted) {
        throw new UnverifiableDurableHistoryError(
          `witness_consensus_log max index (${maxLogIndex.toString()}) exceeds last_consecutive_persisted_index (${L_c_persisted.toString()}) for epoch '${epochId}'`,
          epochId
        );
      }

      // 2. Snapshot Selection & Validation (with Genesis Fallback)
      let baseState: ApplicationState = createInitialState(this.clusterId);
      let startIndex = 1n;

      if (options.snapshotLoader) {
        const snapRes = await client.query(
          `SELECT snapshot_id, cluster_id, epoch_id, snapshot_index, snapshot_hash,
                  chain_head_hash, etcd_revision, sub_index, format_version,
                  canonicalization_version, storage_backend, storage_uri, byte_size,
                  created_at_seconds
           FROM witness_snapshots
           WHERE cluster_id = $1 AND epoch_id = $2
             AND status = 'COMMITTED'
             AND snapshot_index <= $3
           ORDER BY snapshot_index DESC`,
          [this.clusterId, epochId, L_c_persisted.toString()]
        );

        for (const row of snapRes.rows) {
          const snapRecord: PersistedSnapshotRecord = {
            snapshotId: String(row.snapshot_id),
            clusterId: String(row.cluster_id),
            epochId: String(row.epoch_id),
            snapshotIndex: BigInt(row.snapshot_index),
            snapshotHash: String(row.snapshot_hash),
            chainHeadHash: String(row.chain_head_hash),
            etcdRevision: BigInt(row.etcd_revision),
            subIndex: Number(row.sub_index),
            formatVersion: Number(row.format_version),
            canonicalizationVersion: normalizeCanonVersion(row.canonicalization_version),
            storageBackend: String(row.storage_backend),
            storageUri: String(row.storage_uri),
            byteSize: BigInt(row.byte_size),
            createdAtSeconds: Number(row.created_at_seconds),
          };

          if (snapRecord.formatVersion !== 1) {
            continue;
          }
          if (snapRecord.clusterId !== this.clusterId || snapRecord.epochId !== epochId) {
            continue;
          }

          const loaded = await options.snapshotLoader.loadAndVerify(snapRecord);
          if (
            loaded &&
            loaded.clusterId === this.clusterId &&
            loaded.epochId === epochId &&
            loaded.lastAppliedAppIndex === snapRecord.snapshotIndex &&
            loaded.chainHeadHash === snapRecord.chainHeadHash
          ) {
            baseState = loaded;
            startIndex = loaded.lastAppliedAppIndex + 1n;
            break;
          }
        }
      }

      // 3. Build Epoch Lineage Segments [startIndex, L_c_persisted] across EPOCH_ADVANCE boundaries
      if (startIndex <= L_c_persisted) {
        const segments = await this.buildReplaySegments(client, epochId, startIndex, L_c_persisted);

        // 4. Contiguous Log Query & Cryptographic Replay per Segment
        for (const seg of segments) {
          const logRes = await client.query(
            `SELECT epoch_id, log_index, term, etcd_revision, payload_type, payload,
                    payload_hash, proposal_id, committed_at_seconds,
                    canonicalization_version, sub_index
             FROM witness_consensus_log
             WHERE epoch_id = $1 AND log_index >= $2 AND log_index <= $3
             ORDER BY log_index ASC`,
            [seg.epochId, seg.fromIndex.toString(), seg.toIndex.toString()]
          );

          const expectedCount = seg.toIndex - seg.fromIndex + 1n;
          if (BigInt(logRes.rows.length) !== expectedCount) {
            let expectedIdx = seg.fromIndex;
            for (const row of logRes.rows) {
              const actualIdx = BigInt(row.log_index);
              if (actualIdx !== expectedIdx) {
                throw new UnverifiableHistoricalEntryError(expectedIdx);
              }
              expectedIdx += 1n;
            }
            throw new UnverifiableHistoricalEntryError(expectedIdx);
          }

          let expectedIdx = seg.fromIndex;
          for (const row of logRes.rows) {
            const actualIdx = BigInt(row.log_index);
            if (actualIdx !== expectedIdx) {
              throw new UnverifiableHistoricalEntryError(expectedIdx);
            }

            const commandType = String(row.payload_type) as ConsensusCommandType;
            const canonVersion = normalizeCanonVersion(row.canonicalization_version);
            const hydratedPayload = hydratePayloadFromJsonb(commandType, row.payload);
            const computedHash = computeCanonicalPayloadHash(hydratedPayload, canonVersion);
            const storedHash = String(row.payload_hash);

            if (computedHash !== storedHash) {
              throw new PayloadHashMismatchError(actualIdx, storedHash, computedHash);
            }

            if (!row.proposal_id || String(row.proposal_id).trim().length === 0) {
              throw new UnverifiableDurableHistoryError(
                `Persisted log entry at index ${actualIdx.toString()} in epoch '${seg.epochId}' is missing proposal_id`,
                seg.epochId
              );
            }

            const entry: CommittedConsensusEntry = {
              epochId: String(row.epoch_id),
              appLogIndex: actualIdx,
              raftTerm: BigInt(row.term),
              physicalCursor: {
                etcdRevision: BigInt(row.etcd_revision),
                subIndex: Number(row.sub_index),
              },
              commandType,
              payload: hydratedPayload as CommittedConsensusEntry["payload"],
              payloadHash: storedHash,
              proposalId: String(row.proposal_id),
              committedAtSeconds: Number(row.committed_at_seconds),
              canonicalizationVersion: canonVersion,
            };

            const applyRes = ConsensusStateMachine.apply(baseState, entry, {
              lastConsecutivePersistedAppIndex: L_c_persisted,
              memoryRetentionWindow:
                options.memoryRetentionWindow ?? this.defaultMemoryRetentionWindow,
              enforceBacklogLimit: options.enforceBacklogLimit ?? true,
            });

            if (applyRes.status !== "APPLIED") {
              throw new ReplayVerificationError(
                `Replay at index ${actualIdx.toString()} yielded unexpected status '${applyRes.status}'`,
                "REPLAY_UNEXPECTED_STATUS"
              );
            }

            baseState = applyRes.state;
            expectedIdx += 1n;
          }
        }
      }

      // 5. Watermark & Chain-Head Parity Check
      if (baseState.lastAppliedAppIndex !== L_c_persisted) {
        throw new ReplayVerificationError(
          `Replayed index (${baseState.lastAppliedAppIndex.toString()}) does not match persisted watermark (${L_c_persisted.toString()})`,
          "REPLAY_WATERMARK_MISMATCH"
        );
      }

      if (
        raftState.lastAppliedIndex === L_c_persisted &&
        raftState.lastAppliedHash !== "" &&
        baseState.chainHeadHash !== raftState.lastAppliedHash
      ) {
        throw new ReplayVerificationError(
          `Replayed chainHeadHash '${baseState.chainHeadHash}' does not match witness_raft_state.last_applied_hash '${raftState.lastAppliedHash}'`,
          "REPLAY_CHAIN_HEAD_MISMATCH"
        );
      }

      // 6. Atomic Publication
      const publishedState: ApplicationState = Object.freeze({
        ...baseState,
        lastConsecutivePersistedAppIndex: L_c_persisted,
      });
      this.authoritativeState = publishedState;
      return publishedState;
    } finally {
      client.release();
    }
  }

  /**
   * Resolves ordered `(epochId, fromIndex, toIndex)` segments from `startIndex` to
   * `endIndex`, walking `EPOCH_ADVANCE` predecessors backwards when `startIndex`
   * precedes the first log index of `targetEpochId`.
   */
  private async buildReplaySegments(
    client: PoolClient,
    targetEpochId: string,
    startIndex: bigint,
    endIndex: bigint
  ): Promise<Array<{ epochId: string; fromIndex: bigint; toIndex: bigint }>> {
    const segments: Array<{ epochId: string; fromIndex: bigint; toIndex: bigint }> = [];
    const visitedEpochs = new Set<string>();
    let currentEpochId = targetEpochId;
    let currentToIndex = endIndex;

    while (currentToIndex >= startIndex) {
      if (visitedEpochs.has(currentEpochId)) {
        throw new UnverifiableDurableHistoryError(
          `Cycle detected in EPOCH_ADVANCE lineage at epoch '${currentEpochId}'`,
          targetEpochId
        );
      }
      visitedEpochs.add(currentEpochId);

      // Check if an EPOCH_ADVANCE entry in a predecessor epoch transitioned into currentEpochId
      const predRes = await client.query(
        `SELECT epoch_id, log_index
         FROM witness_consensus_log
         WHERE payload_type = 'EPOCH_ADVANCE'
           AND payload->>'toEpochId' = $1
           AND log_index <= $2
         ORDER BY log_index DESC
         LIMIT 1`,
        [currentEpochId, currentToIndex.toString()]
      );

      if (predRes.rowCount && predRes.rowCount > 0) {
        const predEpochId = String(predRes.rows[0].epoch_id);
        const advanceIndex = BigInt(predRes.rows[0].log_index);
        const segFrom = advanceIndex + 1n > startIndex ? advanceIndex + 1n : startIndex;
        if (segFrom <= currentToIndex) {
          segments.push({
            epochId: currentEpochId,
            fromIndex: segFrom,
            toIndex: currentToIndex,
          });
        }
        currentEpochId = predEpochId;
        currentToIndex = advanceIndex;
      } else {
        segments.push({
          epochId: currentEpochId,
          fromIndex: startIndex,
          toIndex: currentToIndex,
        });
        break;
      }
    }

    segments.reverse();
    return segments;
  }

  // ==========================================================================
  // Private Transactional Helpers
  // ==========================================================================

  private resolveLockEpochId(entry: CommittedConsensusEntry): string {
    if (
      this.authoritativeState.epochState !== "INITIAL" &&
      this.authoritativeState.epochId.length > 0
    ) {
      return this.authoritativeState.epochId;
    }
    return entry.epochId;
  }

  private async bootstrapAndLockRaftState(
    client: PoolClient,
    epochId: string
  ): Promise<PersistedRaftStateRecord> {
    const nowSeconds = Math.floor(Date.now() / 1000);
    await client.query(
      `INSERT INTO witness_raft_state (
         cluster_id, epoch_id, last_applied_index, last_applied_term, last_applied_hash,
         updated_at_seconds, last_applied_etcd_revision, last_applied_sub_index,
         last_consecutive_persisted_index, last_snapshot_index, last_snapshot_hash
       ) VALUES ($1, $2, 0, 0, '', $3, 0, 0, 0, 0, '')
       ON CONFLICT (cluster_id, epoch_id) DO NOTHING`,
      [this.clusterId, epochId, nowSeconds]
    );

    const lockRes = await client.query(
      `SELECT cluster_id, epoch_id, last_applied_index, last_applied_term, last_applied_hash,
              updated_at_seconds, last_applied_etcd_revision, last_applied_sub_index,
              last_consecutive_persisted_index, last_snapshot_index, last_snapshot_hash
       FROM witness_raft_state
       WHERE cluster_id = $1 AND epoch_id = $2
       FOR UPDATE`,
      [this.clusterId, epochId]
    );

    if (lockRes.rowCount === 0) {
      throw new ConsensusStoreError(
        `Failed to lock witness_raft_state row for (${this.clusterId}, ${epochId})`,
        "RAFT_STATE_LOCK_FAILED"
      );
    }

    return this.mapRaftStateRow(lockRes.rows[0]);
  }

  private async verifyTier2HistoricalEntry(
    client: PoolClient,
    entry: CommittedConsensusEntry,
    computedPayloadHash: string
  ): Promise<void> {
    const logRes = await client.query(
      `SELECT proposal_id, payload_hash, canonicalization_version
       FROM witness_consensus_log
       WHERE epoch_id = $1 AND log_index = $2`,
      [entry.epochId, entry.appLogIndex.toString()]
    );

    if (logRes.rowCount === 0) {
      throw new UnverifiableHistoricalEntryError(entry.appLogIndex);
    }

    const row = logRes.rows[0];
    const storedProposalId = row.proposal_id ? String(row.proposal_id) : "";
    const storedPayloadHash = String(row.payload_hash);

    if (storedProposalId !== entry.proposalId) {
      throw new HistoricalIndexConflictError(
        entry.appLogIndex,
        "PROPOSAL_ID",
        `Tier-2 historical index conflict at index ${entry.appLogIndex.toString()}: recorded proposalId '${storedProposalId}', replayed with '${entry.proposalId}'`
      );
    }

    if (storedPayloadHash !== computedPayloadHash) {
      throw new HistoricalIndexConflictError(
        entry.appLogIndex,
        "PAYLOAD_HASH",
        `Tier-2 historical index conflict at index ${entry.appLogIndex.toString()}: recorded payloadHash '${storedPayloadHash}', replayed with '${computedPayloadHash}'`
      );
    }

    // Verify proposal_id uniqueness across indices in this epoch
    const propRes = await client.query(
      `SELECT log_index
       FROM witness_consensus_log
       WHERE epoch_id = $1 AND proposal_id = $2`,
      [entry.epochId, entry.proposalId]
    );

    if (propRes.rowCount && propRes.rowCount > 0) {
      const recordedIdx = BigInt(propRes.rows[0].log_index);
      if (recordedIdx !== entry.appLogIndex) {
        throw new StateMachineError(
          `Proposal ID '${entry.proposalId}' was previously applied at index ${recordedIdx.toString()}, but replayed at index ${entry.appLogIndex.toString()}`,
          "PROPOSAL_ID_INDEX_CONFLICT"
        );
      }
    }
  }

  private async insertConsensusLogRow(
    client: PoolClient,
    entry: CommittedConsensusEntry,
    serializedPayload: string,
    computedPayloadHash: string,
    canonVersion: 1 | 2
  ): Promise<void> {
    await client.query(
      `INSERT INTO witness_consensus_log (
         epoch_id, log_index, term, etcd_revision, payload_type, payload,
         payload_hash, proposal_id, committed_at_seconds,
         canonicalization_version, sub_index
       ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11)`,
      [
        entry.epochId,
        entry.appLogIndex.toString(),
        entry.raftTerm.toString(),
        entry.physicalCursor.etcdRevision.toString(),
        entry.commandType,
        serializedPayload,
        computedPayloadHash,
        entry.proposalId,
        entry.committedAtSeconds,
        canonVersion,
        entry.physicalCursor.subIndex,
      ]
    );
  }

  private classifyDatabaseError(err: unknown, entry: CommittedConsensusEntry): unknown {
    const pgCode = getPgErrorCode(err);
    if (pgCode === PG_SQLSTATE.UNIQUE_VIOLATION) {
      const constraint = getPgErrorConstraint(err);
      if (constraint === "uq_consensus_log_proposal_id") {
        return new ConsensusConflictError(
          `Duplicate proposal_id '${entry.proposalId}' in epoch '${entry.epochId}'`,
          "PROPOSAL_ID",
          err
        );
      }
      if (constraint === "witness_consensus_log_pkey") {
        return new ConsensusConflictError(
          `Duplicate log_index ${entry.appLogIndex.toString()} in epoch '${entry.epochId}'`,
          "LOG_INDEX",
          err
        );
      }
      return new ConsensusConflictError(
        `Unique constraint violation (${constraint ?? "unknown"}) while persisting consensus entry`,
        "UNIQUE_VIOLATION",
        err
      );
    }
    return err;
  }

  private mapRaftStateRow(row: Record<string, unknown>): PersistedRaftStateRecord {
    return {
      clusterId: String(row.cluster_id),
      epochId: String(row.epoch_id),
      lastAppliedIndex: BigInt(row.last_applied_index as string | number),
      lastAppliedTerm: BigInt(row.last_applied_term as string | number),
      lastAppliedHash: String(row.last_applied_hash ?? ""),
      updatedAtSeconds: Number(row.updated_at_seconds),
      lastAppliedEtcdRevision: BigInt(row.last_applied_etcd_revision as string | number),
      lastAppliedSubIndex: Number(row.last_applied_sub_index),
      lastConsecutivePersistedIndex: BigInt(
        row.last_consecutive_persisted_index as string | number
      ),
      lastSnapshotIndex: BigInt(row.last_snapshot_index as string | number),
      lastSnapshotHash: String(row.last_snapshot_hash ?? ""),
    };
  }
}
