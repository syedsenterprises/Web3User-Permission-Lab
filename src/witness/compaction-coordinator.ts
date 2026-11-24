/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.2 (Step 6)
 * CompactionCoordinator: Safe Physical etcd Compaction & Telemetry-Grounded Buffer
 *
 * Implements ADR-M13D-013 and Stage 2-B.2 WP5:
 * - Non-negotiable physical compaction invariant:
 *     R_comp <= min(R_snap, R_pg_persisted) - Delta_buffer
 * - Strict dimensional separation between physical etcd MVCC revisions (bigint)
 *   and logical consensus log indices (appLogIndex).
 * - Multi-event revision safety: tip revision R_last is treated conservatively as
 *   R_last - 1 unless explicitly confirmed complete by a subsequent revision or
 *   progress notification.
 * - Automatic compaction STRICTLY DISABLED BY DEFAULT and gated on explicit
 *   24-hour operational baseline verification (`operationalBaselineVerified: true`).
 * - Cross-process coordination via PostgreSQL advisory lock (`pg_try_advisory_lock`)
 *   without holding `witness_raft_state` row locks across etcd network RPCs.
 */

import pg from "pg";
import { Etcd3 } from "etcd3";
import { type PersistedSnapshotRecord } from "./consensus-store.js";
import { SnapshotManager } from "./snapshot-manager.js";

// ============================================================================
// Constants & Errors
// ============================================================================

export const DEFAULT_MIN_SAFETY_BUFFER_REVISIONS = 1_000n;
export const DEFAULT_BUFFER_SAFETY_FACTOR = 2.0;
export const DEFAULT_MIN_COMPACTION_INTERVAL_MS = 60_000;
export const DEFAULT_COMPACTION_TIMEOUT_MS = 5_000;
export const DEFAULT_COMPACTION_MAX_RETRIES = 2;
export const DEFAULT_COMPACTION_LAG_WARNING_REVISIONS = 50_000n;

export class CompactionError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly originalError?: unknown
  ) {
    super(message);
    this.name = "CompactionError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class CompactionConfigurationError extends CompactionError {
  constructor(message: string, originalError?: unknown) {
    super(message, "COMPACTION_INVALID_CONFIGURATION", originalError);
    this.name = "CompactionConfigurationError";
  }
}

export class CompactionSafetyError extends CompactionError {
  constructor(message: string, code = "COMPACTION_SAFETY_VIOLATION", originalError?: unknown) {
    super(message, code, originalError);
    this.name = "CompactionSafetyError";
  }
}

export class CompactionExecutionError extends CompactionError {
  constructor(
    message: string,
    code:
      | "ETCD_TIMEOUT"
      | "ETCD_UNAVAILABLE"
      | "ETCD_UNCERTAIN_OUTCOME"
      | "ETCD_COMPACTION_FAILED",
    originalError?: unknown
  ) {
    super(message, code, originalError);
    this.name = "CompactionExecutionError";
  }
}

// ============================================================================
// Pure Eligibility & Dimensional Buffer Calculators
// ============================================================================

export interface CompactionEligibilityInput {
  readonly snapshotRevision: bigint | null;
  readonly pgPersistedRevision: bigint | null;
  readonly safetyBuffer: bigint;
  readonly alreadyCompactedRevision: bigint;
  readonly maxRevisionAdvancePerOp?: bigint;
}

export interface CompactionEligibilityResult {
  readonly eligible: boolean;
  readonly candidateRevision: bigint | null;
  readonly safeBoundary: bigint;
  readonly snapshotRevision: bigint | null;
  readonly pgPersistedRevision: bigint | null;
  readonly safetyBuffer: bigint;
  readonly alreadyCompactedRevision: bigint;
  readonly reason: string;
}

/**
 * Dimensional safety buffer calculator (Stage 2-B.2 Final Architecture Gate):
 *   Delta_buffer = max(Delta_buffer_min, ceil(S_f * R_rate_p99 * T_reconnect_p99))
 */
export function calculateDimensionalSafetyBuffer(params: {
  readonly revisionRateP99PerSecond: number;
  readonly reconnectP99Seconds: number;
  readonly minBufferRevisions?: bigint;
  readonly safetyFactor?: number;
}): bigint {
  const minBuf = params.minBufferRevisions ?? DEFAULT_MIN_SAFETY_BUFFER_REVISIONS;
  const factor = params.safetyFactor ?? DEFAULT_BUFFER_SAFETY_FACTOR;

  if (minBuf <= 0n) {
    throw new CompactionConfigurationError("minBufferRevisions must be strictly positive");
  }
  if (!Number.isFinite(factor) || factor < 1.0) {
    throw new CompactionConfigurationError("safetyFactor must be finite and >= 1.0");
  }
  if (!Number.isFinite(params.revisionRateP99PerSecond) || params.revisionRateP99PerSecond < 0) {
    throw new CompactionConfigurationError("revisionRateP99PerSecond must be finite and >= 0");
  }
  if (!Number.isFinite(params.reconnectP99Seconds) || params.reconnectP99Seconds < 0) {
    throw new CompactionConfigurationError("reconnectP99Seconds must be finite and >= 0");
  }

  const rawDynamic = Math.ceil(
    factor * params.revisionRateP99PerSecond * params.reconnectP99Seconds
  );
  if (!Number.isSafeInteger(rawDynamic)) {
    throw new CompactionConfigurationError(
      `Computed dynamic safety buffer (${rawDynamic}) exceeds IEEE 754 safe integer bounds`
    );
  }
  const dynamicBuf = BigInt(rawDynamic);
  return dynamicBuf > minBuf ? dynamicBuf : minBuf;
}

/**
 * Pure, deterministic compaction eligibility calculator enforcing:
 *   R_comp <= min(R_snap, R_pg_persisted) - Delta_buffer
 *
 * Rejects zero/negative revisions, underflow, unverified/missing watermarks,
 * and candidates at or below `alreadyCompactedRevision`.
 */
export function calculateCompactionEligibility(
  input: CompactionEligibilityInput
): CompactionEligibilityResult {
  if (input.safetyBuffer <= 0n) {
    throw new CompactionSafetyError(
      `Safety buffer must be strictly positive (got ${input.safetyBuffer.toString()})`,
      "INVALID_SAFETY_BUFFER"
    );
  }
  if (input.alreadyCompactedRevision < 0n) {
    throw new CompactionSafetyError(
      `alreadyCompactedRevision cannot be negative (got ${input.alreadyCompactedRevision.toString()})`,
      "INVALID_COMPACTED_REVISION"
    );
  }
  if (
    input.maxRevisionAdvancePerOp !== undefined &&
    input.maxRevisionAdvancePerOp <= 0n
  ) {
    throw new CompactionSafetyError(
      `maxRevisionAdvancePerOp must be strictly positive (got ${input.maxRevisionAdvancePerOp.toString()})`,
      "INVALID_MAX_ADVANCE"
    );
  }

  if (input.snapshotRevision === null || input.pgPersistedRevision === null) {
    return {
      eligible: false,
      candidateRevision: null,
      safeBoundary: 0n,
      snapshotRevision: input.snapshotRevision,
      pgPersistedRevision: input.pgPersistedRevision,
      safetyBuffer: input.safetyBuffer,
      alreadyCompactedRevision: input.alreadyCompactedRevision,
      reason: "MISSING_DURABLE_REVISION",
    };
  }

  if (input.snapshotRevision <= 0n || input.pgPersistedRevision <= 0n) {
    return {
      eligible: false,
      candidateRevision: null,
      safeBoundary: 0n,
      snapshotRevision: input.snapshotRevision,
      pgPersistedRevision: input.pgPersistedRevision,
      safetyBuffer: input.safetyBuffer,
      alreadyCompactedRevision: input.alreadyCompactedRevision,
      reason: "NON_POSITIVE_DURABLE_REVISION",
    };
  }

  const minDurable =
    input.snapshotRevision < input.pgPersistedRevision
      ? input.snapshotRevision
      : input.pgPersistedRevision;

  // Underflow / <= 0 guard
  if (minDurable <= input.safetyBuffer) {
    return {
      eligible: false,
      candidateRevision: null,
      safeBoundary: 0n,
      snapshotRevision: input.snapshotRevision,
      pgPersistedRevision: input.pgPersistedRevision,
      safetyBuffer: input.safetyBuffer,
      alreadyCompactedRevision: input.alreadyCompactedRevision,
      reason: "BELOW_SAFETY_BUFFER",
    };
  }

  const safeBoundary = minDurable - input.safetyBuffer;

  if (safeBoundary <= input.alreadyCompactedRevision) {
    return {
      eligible: false,
      candidateRevision: null,
      safeBoundary,
      snapshotRevision: input.snapshotRevision,
      pgPersistedRevision: input.pgPersistedRevision,
      safetyBuffer: input.safetyBuffer,
      alreadyCompactedRevision: input.alreadyCompactedRevision,
      reason: "ALREADY_COMPACTED_OR_NO_PROGRESS",
    };
  }

  let candidate = safeBoundary;
  if (input.maxRevisionAdvancePerOp !== undefined) {
    const capped = input.alreadyCompactedRevision + input.maxRevisionAdvancePerOp;
    if (capped < candidate) {
      candidate = capped;
    }
  }

  // Final defensive invariant assertion
  if (candidate <= 0n || candidate > safeBoundary || candidate <= input.alreadyCompactedRevision) {
    throw new CompactionSafetyError(
      `Calculated candidate ${candidate.toString()} violated safety invariant (safeBoundary=${safeBoundary.toString()}, compacted=${input.alreadyCompactedRevision.toString()})`
    );
  }

  return {
    eligible: true,
    candidateRevision: candidate,
    safeBoundary,
    snapshotRevision: input.snapshotRevision,
    pgPersistedRevision: input.pgPersistedRevision,
    safetyBuffer: input.safetyBuffer,
    alreadyCompactedRevision: input.alreadyCompactedRevision,
    reason: "ELIGIBLE",
  };
}

// ============================================================================
// etcd Compaction Client Abstraction & Real etcd3 Implementation
// ============================================================================

export interface EtcdClusterRevisionStatus {
  readonly currentRevision: bigint;
  readonly compactedRevision?: bigint;
}

export interface EtcdCompactResponse {
  readonly compacted: boolean;
  readonly alreadyCompacted: boolean;
  readonly currentRevision?: bigint;
}

export interface EtcdCompactionClient {
  getStatus(timeoutMs: number): Promise<EtcdClusterRevisionStatus>;
  compact(revision: bigint, timeoutMs: number): Promise<EtcdCompactResponse>;
}

/**
 * Production compaction client backed by the pinned `etcd3` v3.5.18 client API
 * (`maintenance.status()` and `kv.compact({ revision, physical: true })`).
 */
export class Etcd3CompactionClient implements EtcdCompactionClient {
  constructor(private readonly client: Etcd3) {}

  public async getStatus(timeoutMs: number): Promise<EtcdClusterRevisionStatus> {
    const status = await this.withDeadline(
      this.client.maintenance.status(),
      timeoutMs,
      "maintenance.status()"
    );
    const revStr = status.header?.revision;
    if (revStr === undefined || revStr === null) {
      throw new CompactionExecutionError(
        "etcd maintenance.status() missing header.revision",
        "ETCD_UNAVAILABLE"
      );
    }
    return {
      currentRevision: BigInt(revStr.toString()),
    };
  }

  public async compact(revision: bigint, timeoutMs: number): Promise<EtcdCompactResponse> {
    if (revision <= 0n) {
      throw new CompactionSafetyError(`Refusing to compact non-positive revision ${revision.toString()}`);
    }

    try {
      const resp = await this.withDeadline(
        this.client.kv.compact(
          { revision: revision.toString(), physical: true },
          { deadline: Date.now() + timeoutMs }
        ),
        timeoutMs,
        `kv.compact(${revision.toString()})`
      );
      return {
        compacted: true,
        alreadyCompacted: false,
        currentRevision: resp.header?.revision ? BigInt(resp.header.revision.toString()) : undefined,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message.toLowerCase() : String(err).toLowerCase();
      if (msg.includes("required revision has been compacted") || msg.includes("already compacted")) {
        return {
          compacted: false,
          alreadyCompacted: true,
        };
      }
      if (msg.includes("deadline") || msg.includes("timed out") || msg.includes("timeout")) {
        throw new CompactionExecutionError(
          `etcd compaction timed out at revision ${revision.toString()}`,
          "ETCD_TIMEOUT",
          err
        );
      }
      if (
        msg.includes("unavailable") ||
        msg.includes("econnrefused") ||
        msg.includes("leader") ||
        msg.includes("no connection")
      ) {
        throw new CompactionExecutionError(
          `etcd unavailable during compaction at revision ${revision.toString()}: ${msg}`,
          "ETCD_UNAVAILABLE",
          err
        );
      }
      throw new CompactionExecutionError(
        `etcd compaction failed at revision ${revision.toString()}: ${msg}`,
        "ETCD_COMPACTION_FAILED",
        err
      );
    }
  }

  private async withDeadline<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        promise,
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(() => {
            reject(new CompactionExecutionError(`${label} timed out after ${timeoutMs}ms`, "ETCD_TIMEOUT"));
          }, timeoutMs);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}

// ============================================================================
// CompactionCoordinator Configuration, Metrics & Run Results
// ============================================================================

export interface CompactionCoordinatorConfig {
  readonly clusterId: string;
  readonly epochId: string;
  /**
   * Automatic compaction is STRICTLY DISABLED BY DEFAULT (`false`).
   * Must remain `false` until a 24-hour operational baseline is verified.
   */
  readonly automaticCompactionEnabled?: boolean;
  /**
   * Must be explicitly `true` (confirming 24-hour Prometheus baseline calibration
   * of `etcd_debugging_mvcc_current_revision` and reconnect p99) before
   * `automaticCompactionEnabled: true` is permitted.
   */
  readonly operationalBaselineVerified?: boolean;
  readonly safetyBuffer?: bigint;
  readonly minCompactionIntervalMs?: number;
  readonly maxRevisionAdvancePerOp?: bigint;
  readonly compactionTimeoutMs?: number;
  readonly maxRetries?: number;
  readonly lagWarningThreshold?: bigint;
}

export interface CompactionCoordinatorOptions {
  readonly pool: pg.Pool;
  readonly snapshotManager: SnapshotManager;
  readonly etcdClient: EtcdCompactionClient;
  readonly config: CompactionCoordinatorConfig;
}

export interface CompactionRunOptions {
  /**
   * Highest physical etcd revision confirmed complete (e.g. by observation of
   * revision R' > R or etcd progress_notify). If omitted, tip revision R_last
   * in `witness_raft_state` is conservatively treated as `R_last - 1` so a
   * partially persisted multi-event revision is never compacted.
   */
  readonly confirmedCompleteRevision?: bigint;
  /**
   * Known compacted revision from etcd or prior observation (default: internal
   * verified `lastSuccessfulCompactionRevision` or `0n`).
   */
  readonly knownCompactedRevision?: bigint;
  readonly nowMs?: number;
  readonly onAfterEligibilityCalculated?: (eligibility: CompactionEligibilityResult) => void;
  readonly onBeforeEtcdCompact?: (candidateRevision: bigint) => void;
}

export interface CompactionRunResult {
  readonly status:
    | "COMPACTED"
    | "ALREADY_COMPACTED"
    | "NO_OP"
    | "AUTOMATIC_DISABLED"
    | "LOCK_CONTENTION"
    | "RATE_LIMITED";
  readonly eligibility?: CompactionEligibilityResult;
  readonly compactedRevision: bigint | null;
}

export interface CompactionMetricsSnapshot {
  readonly clusterId: string;
  readonly epochId: string;
  readonly currentEtcdRevision: bigint | null;
  readonly currentCompactedRevision: bigint | null;
  readonly latestVerifiedSnapshotRevision: bigint | null;
  readonly pgPersistedRevision: bigint | null;
  readonly configuredSafetyBuffer: bigint;
  readonly calculatedSafeBoundary: bigint | null;
  readonly lastSuccessfulCompactionRevision: bigint | null;
  readonly lastAttemptedCandidateRevision: bigint | null;
  readonly lastCompactionError: string | null;
  readonly automaticCompactionEnabled: boolean;
  readonly operationalBaselineVerified: boolean;
  readonly compactionLag: bigint | null;
  readonly warningTriggered: boolean;
}

// ============================================================================
// CompactionCoordinator Implementation
// ============================================================================

export class CompactionCoordinator {
  private readonly pool: pg.Pool;
  private readonly snapshotManager: SnapshotManager;
  private readonly etcdClient: EtcdCompactionClient;

  private readonly clusterId: string;
  private readonly epochId: string;
  private readonly automaticCompactionEnabled: boolean;
  private readonly operationalBaselineVerified: boolean;
  private readonly safetyBuffer: bigint;
  private readonly minCompactionIntervalMs: number;
  private readonly maxRevisionAdvancePerOp?: bigint;
  private readonly compactionTimeoutMs: number;
  private readonly maxRetries: number;
  private readonly lagWarningThreshold: bigint;

  private closed = false;
  private lastCompactionAttemptMs = 0;
  private currentEtcdRevision: bigint | null = null;
  private currentCompactedRevision: bigint | null = null;
  private latestVerifiedSnapshotRevision: bigint | null = null;
  private pgPersistedRevision: bigint | null = null;
  private calculatedSafeBoundary: bigint | null = null;
  private lastSuccessfulCompactionRevision: bigint | null = null;
  private lastAttemptedCandidateRevision: bigint | null = null;
  private lastCompactionError: string | null = null;

  constructor(options: CompactionCoordinatorOptions) {
    const cfg = options.config;
    if (!cfg.clusterId || cfg.clusterId.trim().length === 0) {
      throw new CompactionConfigurationError("clusterId must be non-empty");
    }
    if (!cfg.epochId || cfg.epochId.trim().length === 0) {
      throw new CompactionConfigurationError("epochId must be non-empty");
    }

    const autoEnabled = cfg.automaticCompactionEnabled ?? false;
    const baselineVerified = cfg.operationalBaselineVerified ?? false;
    if (autoEnabled && !baselineVerified) {
      throw new CompactionConfigurationError(
        "Automatic etcd compaction cannot be enabled before operationalBaselineVerified is true (24-hour telemetry baseline required)"
      );
    }

    const safetyBuffer = cfg.safetyBuffer ?? DEFAULT_MIN_SAFETY_BUFFER_REVISIONS;
    if (safetyBuffer <= 0n) {
      throw new CompactionConfigurationError("safetyBuffer must be strictly positive");
    }

    const minInterval = cfg.minCompactionIntervalMs ?? DEFAULT_MIN_COMPACTION_INTERVAL_MS;
    if (!Number.isInteger(minInterval) || minInterval < 0) {
      throw new CompactionConfigurationError("minCompactionIntervalMs must be a non-negative integer");
    }

    if (cfg.maxRevisionAdvancePerOp !== undefined && cfg.maxRevisionAdvancePerOp <= 0n) {
      throw new CompactionConfigurationError("maxRevisionAdvancePerOp must be strictly positive");
    }

    const timeoutMs = cfg.compactionTimeoutMs ?? DEFAULT_COMPACTION_TIMEOUT_MS;
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
      throw new CompactionConfigurationError("compactionTimeoutMs must be a positive integer");
    }

    const maxRetries = cfg.maxRetries ?? DEFAULT_COMPACTION_MAX_RETRIES;
    if (!Number.isInteger(maxRetries) || maxRetries < 0) {
      throw new CompactionConfigurationError("maxRetries must be a non-negative integer");
    }

    const lagWarn = cfg.lagWarningThreshold ?? DEFAULT_COMPACTION_LAG_WARNING_REVISIONS;
    if (lagWarn <= 0n) {
      throw new CompactionConfigurationError("lagWarningThreshold must be strictly positive");
    }

    this.pool = options.pool;
    this.snapshotManager = options.snapshotManager;
    this.etcdClient = options.etcdClient;
    this.clusterId = cfg.clusterId;
    this.epochId = cfg.epochId;
    this.automaticCompactionEnabled = autoEnabled;
    this.operationalBaselineVerified = baselineVerified;
    this.safetyBuffer = safetyBuffer;
    this.minCompactionIntervalMs = minInterval;
    this.maxRevisionAdvancePerOp = cfg.maxRevisionAdvancePerOp;
    this.compactionTimeoutMs = timeoutMs;
    this.maxRetries = maxRetries;
    this.lagWarningThreshold = lagWarn;
  }

  public close(): void {
    this.closed = true;
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new CompactionError("CompactionCoordinator is closed", "COORDINATOR_CLOSED");
    }
  }

  public getMetrics(): CompactionMetricsSnapshot {
    const compacted = this.lastSuccessfulCompactionRevision ?? this.currentCompactedRevision;
    const lag =
      this.currentEtcdRevision !== null && compacted !== null && this.currentEtcdRevision > compacted
        ? this.currentEtcdRevision - compacted
        : null;
    const warningTriggered = lag !== null && lag >= this.lagWarningThreshold;

    return Object.freeze({
      clusterId: this.clusterId,
      epochId: this.epochId,
      currentEtcdRevision: this.currentEtcdRevision,
      currentCompactedRevision: this.currentCompactedRevision,
      latestVerifiedSnapshotRevision: this.latestVerifiedSnapshotRevision,
      pgPersistedRevision: this.pgPersistedRevision,
      configuredSafetyBuffer: this.safetyBuffer,
      calculatedSafeBoundary: this.calculatedSafeBoundary,
      lastSuccessfulCompactionRevision: this.lastSuccessfulCompactionRevision,
      lastAttemptedCandidateRevision: this.lastAttemptedCandidateRevision,
      lastCompactionError: this.lastCompactionError,
      automaticCompactionEnabled: this.automaticCompactionEnabled,
      operationalBaselineVerified: this.operationalBaselineVerified,
      compactionLag: lag,
      warningTriggered,
    });
  }

  /**
   * Automatic compaction tick: returns `AUTOMATIC_DISABLED` unless both
   * `automaticCompactionEnabled` and `operationalBaselineVerified` are true.
   */
  public async runAutomaticTick(
    options: CompactionRunOptions = {}
  ): Promise<CompactionRunResult> {
    this.assertOpen();
    if (!this.automaticCompactionEnabled || !this.operationalBaselineVerified) {
      return {
        status: "AUTOMATIC_DISABLED",
        compactedRevision: null,
      };
    }

    const nowMs = options.nowMs ?? Date.now();
    if (
      this.lastCompactionAttemptMs > 0 &&
      nowMs - this.lastCompactionAttemptMs < this.minCompactionIntervalMs
    ) {
      return {
        status: "RATE_LIMITED",
        compactedRevision: null,
      };
    }

    return this.executeSafeCompaction(options);
  }

  /**
   * Manual compaction trigger: still enforces every safety invariant,
   * snapshot verification, PostgreSQL durability verification, and cross-process
   * advisory locking.
   */
  public async runManualCompaction(
    options: CompactionRunOptions = {}
  ): Promise<CompactionRunResult> {
    this.assertOpen();
    return this.executeSafeCompaction(options);
  }

  // ==========================================================================
  // Core Safe Compaction Pipeline
  // ==========================================================================

  private async executeSafeCompaction(
    options: CompactionRunOptions
  ): Promise<CompactionRunResult> {
    const lockClient = await this.pool.connect();
    let lockAcquired = false;

    try {
      const lockRes = await lockClient.query(
        `SELECT pg_try_advisory_lock(hashtext($1), hashtext($2)) AS locked`,
        [`compaction:${this.clusterId}`, this.epochId]
      );
      lockAcquired = Boolean(lockRes.rows[0]?.locked);
      if (!lockAcquired) {
        return {
          status: "LOCK_CONTENTION",
          compactedRevision: null,
        };
      }

      this.assertOpen();

      // 1. Read verified PostgreSQL durable physical revision + logical watermark
      const pgWatermark = await this.readVerifiedPgDurability(
        options.confirmedCompleteRevision
      );
      this.pgPersistedRevision = pgWatermark.pgPersistedRevision;

      // 2. Read & cryptographically verify latest eligible COMMITTED snapshot
      const snapRev = await this.readVerifiedSnapshotRevision(
        pgWatermark.lastConsecutivePersistedIndex
      );
      this.latestVerifiedSnapshotRevision = snapRev;

      // 3. Query current etcd cluster status
      const etcdStatus = await this.etcdClient.getStatus(this.compactionTimeoutMs);
      this.currentEtcdRevision = etcdStatus.currentRevision;
      if (etcdStatus.compactedRevision !== undefined) {
        this.currentCompactedRevision = etcdStatus.compactedRevision;
      }

      const baselineCompacted =
        options.knownCompactedRevision ??
        etcdStatus.compactedRevision ??
        this.lastSuccessfulCompactionRevision ??
        0n;

      // 4. Calculate pure deterministic eligibility
      const eligibility = calculateCompactionEligibility({
        snapshotRevision: snapRev,
        pgPersistedRevision: pgWatermark.pgPersistedRevision,
        safetyBuffer: this.safetyBuffer,
        alreadyCompactedRevision: baselineCompacted,
        maxRevisionAdvancePerOp: this.maxRevisionAdvancePerOp,
      });

      this.calculatedSafeBoundary = eligibility.safeBoundary;

      if (options.onAfterEligibilityCalculated) {
        options.onAfterEligibilityCalculated(eligibility);
      }

      if (!eligibility.eligible || eligibility.candidateRevision === null) {
        return {
          status: "NO_OP",
          eligibility,
          compactedRevision: null,
        };
      }

      const candidate = eligibility.candidateRevision;
      this.lastAttemptedCandidateRevision = candidate;
      this.lastCompactionAttemptMs = options.nowMs ?? Date.now();

      if (options.onBeforeEtcdCompact) {
        options.onBeforeEtcdCompact(candidate);
      }

      this.assertOpen();

      // 5. Execute compaction on etcd with bounded retries on transient errors only
      const compactResp = await this.compactWithBoundedRetry(candidate);

      if (compactResp.currentRevision !== undefined) {
        this.currentEtcdRevision = compactResp.currentRevision;
      }

      if (compactResp.alreadyCompacted) {
        this.lastCompactionError = null;
        return {
          status: "ALREADY_COMPACTED",
          eligibility,
          compactedRevision: null,
        };
      }

      // Advance compacted watermark ONLY after etcd confirms success
      this.lastSuccessfulCompactionRevision = candidate;
      this.currentCompactedRevision = candidate;
      this.lastCompactionError = null;

      return {
        status: "COMPACTED",
        eligibility,
        compactedRevision: candidate,
      };
    } catch (err) {
      this.lastCompactionError = err instanceof Error ? err.message : String(err);
      throw err;
    } finally {
      if (lockAcquired) {
        try {
          await lockClient.query(
            `SELECT pg_advisory_unlock(hashtext($1), hashtext($2))`,
            [`compaction:${this.clusterId}`, this.epochId]
          );
        } catch {
          // Session release/close will also release advisory lock
        }
      }
      lockClient.release();
    }
  }

  private async compactWithBoundedRetry(candidate: bigint): Promise<EtcdCompactResponse> {
    let attempt = 0;
    while (true) {
      this.assertOpen();
      try {
        return await this.etcdClient.compact(candidate, this.compactionTimeoutMs);
      } catch (err) {
        if (err instanceof CompactionExecutionError) {
          // Never blindly retry or assume success on uncertain timeout; fail closed!
          if (err.code === "ETCD_TIMEOUT" || err.code === "ETCD_UNCERTAIN_OUTCOME") {
            throw err;
          }
          if (err.code === "ETCD_UNAVAILABLE" && attempt < this.maxRetries) {
            attempt += 1;
            continue;
          }
        }
        throw err;
      }
    }
  }

  private async readVerifiedPgDurability(
    confirmedCompleteRevision?: bigint
  ): Promise<{ lastConsecutivePersistedIndex: bigint; pgPersistedRevision: bigint }> {
    const raftRes = await this.pool.query(
      `SELECT last_consecutive_persisted_index, last_applied_etcd_revision, last_applied_sub_index
       FROM witness_raft_state
       WHERE cluster_id = $1 AND epoch_id = $2`,
      [this.clusterId, this.epochId]
    );

    if (raftRes.rowCount === 0) {
      throw new CompactionSafetyError(
        `Missing witness_raft_state for (${this.clusterId}, ${this.epochId})`,
        "MISSING_PG_WATERMARK"
      );
    }

    const L_c_persisted = BigInt(raftRes.rows[0].last_consecutive_persisted_index);
    const R_last = BigInt(raftRes.rows[0].last_applied_etcd_revision);

    // Verify no unpersisted log gaps or log entries beyond L_c_persisted
    const logStats = await this.pool.query(
      `SELECT COALESCE(MAX(log_index), 0) AS max_idx
       FROM witness_consensus_log
       WHERE epoch_id = $1`,
      [this.epochId]
    );
    const maxLogIndex = BigInt(logStats.rows[0].max_idx ?? 0);
    if (maxLogIndex > L_c_persisted) {
      throw new CompactionSafetyError(
        `PostgreSQL log max_idx (${maxLogIndex.toString()}) exceeds last_consecutive_persisted_index (${L_c_persisted.toString()})`,
        "PG_DURABILITY_INCONSISTENT"
      );
    }

    if (L_c_persisted <= 0n || R_last <= 0n) {
      return { lastConsecutivePersistedIndex: L_c_persisted, pgPersistedRevision: 0n };
    }

    // Multi-event revision safety: R_last is complete only if confirmedCompleteRevision >= R_last
    // (otherwise conservatively treat R_last as potentially partial -> R_last - 1).
    let pgPersistedRevision: bigint;
    if (confirmedCompleteRevision !== undefined && confirmedCompleteRevision >= R_last) {
      pgPersistedRevision = R_last;
    } else {
      pgPersistedRevision = R_last > 0n ? R_last - 1n : 0n;
    }

    return {
      lastConsecutivePersistedIndex: L_c_persisted,
      pgPersistedRevision,
    };
  }

  private async readVerifiedSnapshotRevision(
    lastConsecutivePersistedIndex: bigint
  ): Promise<bigint | null> {
    if (lastConsecutivePersistedIndex <= 0n) {
      return null;
    }

    const snapRes = await this.pool.query(
      `SELECT snapshot_id, cluster_id, epoch_id, snapshot_index, snapshot_hash,
              chain_head_hash, etcd_revision, sub_index, format_version,
              canonicalization_version, storage_backend, storage_uri, byte_size,
              created_at_seconds
       FROM witness_snapshots
       WHERE cluster_id = $1 AND epoch_id = $2
         AND status = 'COMMITTED'
         AND snapshot_index <= $3
       ORDER BY snapshot_index DESC`,
      [this.clusterId, this.epochId, lastConsecutivePersistedIndex.toString()]
    );

    for (const row of snapRes.rows) {
      const canonVer = Number(row.canonicalization_version);
      if (canonVer !== 1 && canonVer !== 2) {
        continue;
      }

      const record: PersistedSnapshotRecord = {
        snapshotId: String(row.snapshot_id),
        clusterId: String(row.cluster_id),
        epochId: String(row.epoch_id),
        snapshotIndex: BigInt(row.snapshot_index),
        snapshotHash: String(row.snapshot_hash),
        chainHeadHash: String(row.chain_head_hash),
        etcdRevision: BigInt(row.etcd_revision),
        subIndex: Number(row.sub_index),
        formatVersion: Number(row.format_version),
        canonicalizationVersion: canonVer,
        storageBackend: String(row.storage_backend),
        storageUri: String(row.storage_uri),
        byteSize: BigInt(row.byte_size),
        createdAtSeconds: Number(row.created_at_seconds),
      };

      const verifiedState = await this.snapshotManager.loadAndVerify(record);
      if (
        verifiedState &&
        verifiedState.clusterId === this.clusterId &&
        verifiedState.epochId === this.epochId &&
        verifiedState.lastAppliedAppIndex === record.snapshotIndex &&
        verifiedState.lastPhysicalCursor.etcdRevision === record.etcdRevision &&
        record.etcdRevision > 0n
      ) {
        return record.etcdRevision;
      }
    }

    return null;
  }
}
