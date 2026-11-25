/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.1
 * Pure Deterministic Application State Machine Reducer
 *
 * Implements the deterministic state-machine apply layer:
 *   apply(state, committedEntry) -> StateMachineApplyResult
 *
 * GUARANTEES:
 * 1. Zero external I/O: Pure in-memory calculation; no database, etcd, KMS, or network calls.
 * 2. Strict contiguity: Requires appLogIndex === lastAppliedAppIndex + 1n.
 * 3. Idempotent replay: Replaying an already-applied entry returns ALREADY_APPLIED with no state mutation.
 * 4. Tamper detection: Verifies payload SHA-256 against entry.payloadHash.
 * 5. Full state immutability: State objects, maps, and sets are deeply frozen and throw on mutation attempts.
 * 6. Non-contiguous physical cursors: Safely consumes leaping etcd revisions and multi-event sub-indexes.
 */

import { createHash } from "node:crypto";
import {
  type ApplicationState,
  type AppliedIndexRecord,
  type BackpressureAction,
  type BackpressureAlertLevel,
  type BackpressureConfig,
  type BackpressureEvaluation,
  type BackpressureStreamState,
  type CommittedConsensusEntry,
  type CommittedTicketRecord,
  type ConsensusCommandType,
  type EpochAdvancePayload,
  type EpochInitializePayload,
  type EpochQuarantinePayload,
  type DelegationRevokePayload,
  type PhysicalStreamCursor,
  type PolicyRecord,
  type PolicyUpdatePayload,
  type StateMachineApplyOptions,
  type StateMachineApplyResult,
  type TicketCommitPayload,
  BacklogLimitExceededError,
  EpochMismatchError,
  HistoricalIndexConflictError,
  InvalidCommandPayloadError,
  LogicalIndexGapError,
  OutOfOrderIndexError,
  PayloadHashMismatchError,
  QuarantinedEpochError,
  StateMachineError,
  UnverifiableHistoricalEntryError,
} from "./state-machine-types.js";
import { computeCanonicalPayloadHash as computeTTCFPayloadHash } from "./canonical-serializer.js";

// ============================================================================
// Immutable Collection Implementations
// ============================================================================

export class ReadonlyFrozenMap<K, V> extends Map<K, V> {
  private isFrozen = false;

  constructor(entries?: Iterable<readonly [K, V]> | null) {
    super(entries ?? undefined);
    this.isFrozen = true;
    Object.freeze(this);
  }

  override set(key: K, value: V): this {
    if (this.isFrozen) {
      throw new TypeError("Cannot modify a frozen Map");
    }
    return super.set(key, value);
  }

  override delete(key: K): boolean {
    if (this.isFrozen) {
      throw new TypeError("Cannot modify a frozen Map");
    }
    return super.delete(key);
  }

  override clear(): void {
    if (this.isFrozen) {
      throw new TypeError("Cannot modify a frozen Map");
    }
    super.clear();
  }
}

export class ReadonlyFrozenSet<T> extends Set<T> {
  private isFrozen = false;

  constructor(values?: Iterable<T> | null) {
    super(values ?? undefined);
    this.isFrozen = true;
    Object.freeze(this);
  }

  override add(value: T): this {
    if (this.isFrozen) {
      throw new TypeError("Cannot modify a frozen Set");
    }
    return super.add(value);
  }

  override delete(value: T): boolean {
    if (this.isFrozen) {
      throw new TypeError("Cannot modify a frozen Set");
    }
    return super.delete(value);
  }

  override clear(): void {
    if (this.isFrozen) {
      throw new TypeError("Cannot modify a frozen Set");
    }
    super.clear();
  }
}

// ============================================================================
// Helper Utilities
// ============================================================================

function sha256(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

/**
 * Deterministically compute the SHA-256 hash of a command payload.
 * Supports version 1 (legacy Canon-v1) and version 2 (TTCF-v1 / Canon-v2).
 */
export function computeCanonicalPayloadHash(payload: unknown, version: 1 | 2 = 1): string {
  return computeTTCFPayloadHash(payload, version);
}

// ============================================================================
// Deterministic Backpressure Policy Engine (WP1 / Stage 2-B.2)
// ============================================================================

/**
 * Pure deterministic backpressure and historical retention policy engine.
 * Computes hysteresis thresholds, retention floors, and alert levels without external I/O.
 */
export class BackpressurePolicy {
  public static readonly DEFAULTS: BackpressureConfig = Object.freeze({
    memoryRetentionWindow: 10_000n,
    pauseThreshold: 1_000n,
    resumeThreshold: 500n,
    warningThreshold: 500n,
    maxBacklog: 11_000n,
    criticalAlertTimeoutSeconds: 30,
    maxRetryAttempts: 5,
  });

  /**
   * Deterministically calculates the historical retention floor index:
   *   F_ret = max(1n, min(A_app - W_mem + 1n, L_c_persisted + 1n))
   */
  public static calculateRetentionFloor(
    lastAppliedAppIndex: bigint,
    lastConsecutivePersistedAppIndex: bigint,
    memoryRetentionWindow: bigint = BackpressurePolicy.DEFAULTS.memoryRetentionWindow
  ): bigint {
    if (memoryRetentionWindow <= 0n) {
      throw new StateMachineError(
        "Memory retention window must be strictly positive",
        "INVALID_RETENTION_WINDOW"
      );
    }
    if (lastConsecutivePersistedAppIndex < 0n) {
      throw new StateMachineError(
        "Persistence watermark must be non-negative",
        "INVALID_PERSISTENCE_WATERMARK"
      );
    }

    const windowFloor = lastAppliedAppIndex - memoryRetentionWindow + 1n;
    const persistenceFloor = lastConsecutivePersistedAppIndex + 1n;
    const minFloor = windowFloor < persistenceFloor ? windowFloor : persistenceFloor;

    return minFloor > 1n ? minFloor : 1n;
  }

  /**
   * Pure evaluation of current stream state, persistence lag, and alert conditions.
   *
   * @param currentState Current stream state (STREAMING, BACKPRESSURE_PAUSED, etc.)
   * @param lastAppliedAppIndex Latest applied index in state machine (A_app)
   * @param lastConsecutivePersistedAppIndex Contiguous persistence watermark (L_c_persisted)
   * @param inMemoryEntryCount Total entries currently in memory
   * @param elapsedPauseSeconds Duration current stream state has been paused (seconds)
   * @param retryAttempts Number of failed database write attempts
   * @param configOverride Partial configuration overrides
   */
  public static evaluate(
    currentState: BackpressureStreamState,
    lastAppliedAppIndex: bigint,
    lastConsecutivePersistedAppIndex: bigint,
    inMemoryEntryCount: bigint,
    elapsedPauseSeconds: number = 0,
    retryAttempts: number = 0,
    configOverride: Partial<BackpressureConfig> = {}
  ): BackpressureEvaluation {
    const cfg: BackpressureConfig = {
      ...BackpressurePolicy.DEFAULTS,
      ...configOverride,
    };

    if (cfg.memoryRetentionWindow <= 0n) {
      throw new StateMachineError(
        "Memory retention window must be strictly positive",
        "INVALID_RETENTION_WINDOW"
      );
    }
    if (cfg.pauseThreshold <= 0n || cfg.resumeThreshold <= 0n || cfg.warningThreshold <= 0n) {
      throw new StateMachineError(
        "Backpressure thresholds must be strictly positive",
        "INVALID_BACKPRESSURE_THRESHOLD"
      );
    }
    if (cfg.resumeThreshold >= cfg.pauseThreshold) {
      throw new StateMachineError(
        `Resume threshold (${cfg.resumeThreshold.toString()}) must be strictly less than pause threshold (${cfg.pauseThreshold.toString()}) for hysteresis`,
        "INVALID_HYSTERESIS_THRESHOLDS"
      );
    }

    const persistenceLag =
      lastAppliedAppIndex > lastConsecutivePersistedAppIndex
        ? lastAppliedAppIndex - lastConsecutivePersistedAppIndex
        : 0n;

    const inMemoryBacklog = inMemoryEntryCount;
    const warningTriggered = persistenceLag >= cfg.warningThreshold;
    const retryExhausted = retryAttempts >= cfg.maxRetryAttempts;

    // Stream state transitions under hysteresis
    let streamState: BackpressureStreamState = currentState;
    let action: BackpressureAction = "CONTINUE";
    let reason: string | undefined;

    if (currentState === "STREAMING") {
      if (persistenceLag >= cfg.pauseThreshold) {
        streamState = "BACKPRESSURE_PAUSED";
        action = "PAUSE_STREAM";
        reason = `Persistence lag ${persistenceLag.toString()} exceeded pause threshold ${cfg.pauseThreshold.toString()}`;
      } else {
        action = "CONTINUE";
      }
    } else if (currentState === "BACKPRESSURE_PAUSED") {
      if (persistenceLag <= cfg.resumeThreshold) {
        streamState = "STREAMING";
        action = "RESUME_STREAM";
        reason = `Persistence lag ${persistenceLag.toString()} drained below resume threshold ${cfg.resumeThreshold.toString()}`;
      } else {
        streamState = "BACKPRESSURE_PAUSED";
        action = "CONTINUE";
        reason = `Stream remains paused: lag ${persistenceLag.toString()} > resume threshold ${cfg.resumeThreshold.toString()}`;
      }
    } else {
      action = "CONTINUE";
    }

    // Alert Level determination
    let alertLevel: BackpressureAlertLevel = "NOMINAL";
    const criticalAlertTriggered =
      (streamState === "BACKPRESSURE_PAUSED" || persistenceLag >= cfg.pauseThreshold) &&
      elapsedPauseSeconds >= cfg.criticalAlertTimeoutSeconds;

    if (criticalAlertTriggered) {
      alertLevel = "CRITICAL";
    } else if (warningTriggered) {
      alertLevel = "WARNING";
    }

    // Hard ceiling & retry overrides
    if (inMemoryBacklog > cfg.maxBacklog) {
      action = "ABORT_OVERFLOW";
      reason = `In-memory consensus backlog exceeded hard limit: ${inMemoryBacklog.toString()} > ${cfg.maxBacklog.toString()}`;
    } else if (retryExhausted) {
      action = "HALT_RETRY_EXHAUSTED";
      reason = `Persistence retries exhausted (${retryAttempts} >= ${cfg.maxRetryAttempts}); halting ingestion`;
    }

    return Object.freeze({
      streamState,
      persistenceLag,
      inMemoryBacklog,
      alertLevel,
      isPaused: streamState === "BACKPRESSURE_PAUSED",
      warningTriggered,
      criticalAlertTriggered,
      retryExhausted,
      action,
      reason,
    });
  }
}

/**
 * Deep-freeze an ApplicationState instance.
 */
function freezeState(state: ApplicationState): ApplicationState {
  Object.freeze(state.lastPhysicalCursor);
  return Object.freeze(state);
}

// ============================================================================
// Initial State Factory
// ============================================================================

export function createInitialState(clusterId = "default-cluster"): ApplicationState {
  const initial: ApplicationState = {
    clusterId,
    epochId: "",
    epochHeight: 0,
    epochState: "INITIAL",
    lastAppliedAppIndex: 0n,
    lastAppliedRaftTerm: 0n,
    lastPhysicalCursor: {
      etcdRevision: 0n,
      subIndex: 0,
    },
    chainHeadHash: "",
    lastSequenceNumber: 0n,
    committedTickets: new ReadonlyFrozenMap<string, CommittedTicketRecord>(),
    revokedAuthorizations: new ReadonlyFrozenSet<string>(),
    policies: new ReadonlyFrozenMap<string, PolicyRecord>(),
    appliedProposals: new ReadonlyFrozenMap<string, bigint>(),
    appliedIndices: new ReadonlyFrozenMap<bigint, AppliedIndexRecord>(),
    retentionFloorIndex: 1n,
    lastConsecutivePersistedAppIndex: 0n,
  };
  return freezeState(initial);
}

// ============================================================================
// Pure State Machine Reducer
// ============================================================================

export class ConsensusStateMachine {
  /**
   * Applies a committed consensus log entry to the application state.
   *
   * @param state The current immutable application state.
   * @param entry The committed consensus log entry to apply.
   * @param options Optional retention window, persistence watermark, and backpressure configurations.
   * @returns StateMachineApplyResult with the new state and execution status.
   */
  public static apply(
    state: ApplicationState,
    entry: CommittedConsensusEntry,
    options?: StateMachineApplyOptions
  ): StateMachineApplyResult {
    // ------------------------------------------------------------------------
    // 1. Basic Argument & Integrity Validation
    // ------------------------------------------------------------------------
    if (!entry) {
      throw new StateMachineError("Cannot apply undefined or null consensus entry", "INVALID_ARGUMENT");
    }

    if (entry.appLogIndex <= 0n) {
      throw new StateMachineError(
        `Invalid application log index ${entry.appLogIndex.toString()}: must be strictly positive`,
        "INVALID_LOG_INDEX"
      );
    }

    // Validate retention window options
    const W_mem = options?.memoryRetentionWindow ?? BackpressurePolicy.DEFAULTS.memoryRetentionWindow;
    if (W_mem <= 0n) {
      throw new StateMachineError(
        "Memory retention window must be strictly positive",
        "INVALID_RETENTION_WINDOW"
      );
    }

    // Validate persistence watermark options
    const L_c_persisted = options?.lastConsecutivePersistedAppIndex ?? state.lastConsecutivePersistedAppIndex;
    if (L_c_persisted < 0n) {
      throw new StateMachineError(
        "Persistence watermark must be non-negative",
        "INVALID_PERSISTENCE_WATERMARK"
      );
    }
    if (L_c_persisted < state.lastConsecutivePersistedAppIndex) {
      throw new StateMachineError(
        `Persistence watermark cannot regress backwards: received ${L_c_persisted.toString()}, current ${state.lastConsecutivePersistedAppIndex.toString()}`,
        "PERSISTENCE_WATERMARK_REGRESSION"
      );
    }

    // Version-aware payload hashing (Step 1 Canon-v1 / TTCF-v1 dual routing)
    const canonVersion = entry.canonicalizationVersion ?? 1;
    const computedPayloadHash = computeCanonicalPayloadHash(entry.payload, canonVersion);

    // Verify Payload Hash (Tamper Detection)
    if (entry.payloadHash && entry.payloadHash !== computedPayloadHash) {
      throw new PayloadHashMismatchError(entry.appLogIndex, entry.payloadHash, computedPayloadHash);
    }

    // ------------------------------------------------------------------------
    // 2. Duplicate Replay & Idempotency Check (F-03 / WP1)
    // ------------------------------------------------------------------------
    if (entry.appLogIndex <= state.lastAppliedAppIndex) {
      // Historical retention pruning check
      if (entry.appLogIndex < state.retentionFloorIndex) {
        return {
          status: "HISTORICAL_RECORD_PRUNED",
          appliedAppIndex: state.lastAppliedAppIndex,
          appliedRaftTerm: state.lastAppliedRaftTerm,
          physicalCursor: state.lastPhysicalCursor,
          chainHeadHash: state.chainHeadHash,
          state,
          rejectionReason: `Historical entry at index ${entry.appLogIndex.toString()} was pruned from in-memory history (retention floor is ${state.retentionFloorIndex.toString()})`,
          retentionFloorIndex: state.retentionFloorIndex,
        };
      }

      const historicalRecord = state.appliedIndices.get(entry.appLogIndex);
      if (!historicalRecord) {
        throw new UnverifiableHistoricalEntryError(entry.appLogIndex);
      }

      if (historicalRecord.proposalId !== entry.proposalId) {
        throw new HistoricalIndexConflictError(
          entry.appLogIndex,
          "PROPOSAL_ID",
          `Historical index conflict at index ${entry.appLogIndex.toString()}: recorded proposalId '${historicalRecord.proposalId}', replayed with '${entry.proposalId}'`
        );
      }

      if (historicalRecord.payloadHash !== computedPayloadHash) {
        throw new HistoricalIndexConflictError(
          entry.appLogIndex,
          "PAYLOAD_HASH",
          `Historical index conflict at index ${entry.appLogIndex.toString()}: recorded payloadHash '${historicalRecord.payloadHash}', replayed with '${computedPayloadHash}'`
        );
      }

      // Check proposal ID uniqueness across indices
      const recordedIndexForProposal = state.appliedProposals.get(entry.proposalId);
      if (recordedIndexForProposal !== undefined && recordedIndexForProposal !== entry.appLogIndex) {
        throw new StateMachineError(
          `Proposal ID '${entry.proposalId}' was previously applied at index ${recordedIndexForProposal.toString()}, but replayed at index ${entry.appLogIndex.toString()}`,
          "PROPOSAL_ID_INDEX_CONFLICT"
        );
      }

      // Safe idempotent duplicate replay: return existing state untouched
      return {
        status: "ALREADY_APPLIED",
        appliedAppIndex: state.lastAppliedAppIndex,
        appliedRaftTerm: state.lastAppliedRaftTerm,
        physicalCursor: state.lastPhysicalCursor,
        chainHeadHash: state.chainHeadHash,
        state,
        duplicateDetected: true,
        retentionFloorIndex: state.retentionFloorIndex,
      };
    }

    // ------------------------------------------------------------------------
    // 3. Strict Logical Index Contiguity Check (Gap Detection)
    // ------------------------------------------------------------------------
    if (entry.appLogIndex > state.lastAppliedAppIndex + 1n) {
      throw new LogicalIndexGapError(state.lastAppliedAppIndex + 1n, entry.appLogIndex);
    }

    // ------------------------------------------------------------------------
    // 4. Physical Stream Cursor Regression Check
    // ------------------------------------------------------------------------
    if (entry.physicalCursor.etcdRevision < state.lastPhysicalCursor.etcdRevision) {
      throw new StateMachineError(
        `Physical etcd revision regressed from ${state.lastPhysicalCursor.etcdRevision.toString()} to ${entry.physicalCursor.etcdRevision.toString()} at logical index ${entry.appLogIndex.toString()}`,
        "PHYSICAL_REVISION_REGRESSION"
      );
    }

    if (
      entry.physicalCursor.etcdRevision === state.lastPhysicalCursor.etcdRevision &&
      state.lastPhysicalCursor.etcdRevision > 0n &&
      entry.physicalCursor.subIndex <= state.lastPhysicalCursor.subIndex
    ) {
      throw new StateMachineError(
        `Physical sub-index did not advance on etcd revision ${entry.physicalCursor.etcdRevision.toString()}: prior was ${state.lastPhysicalCursor.subIndex}, received ${entry.physicalCursor.subIndex}`,
        "PHYSICAL_SUBINDEX_REGRESSION"
      );
    }

    // ------------------------------------------------------------------------
    // 5. Epoch Lifecycle & Isolation Validation
    // ------------------------------------------------------------------------
    if (state.epochState === "INITIAL") {
      if (entry.commandType !== "EPOCH_INITIALIZE") {
        throw new StateMachineError(
          `Initial command must be 'EPOCH_INITIALIZE'; received '${entry.commandType}'`,
          "INVALID_INITIAL_COMMAND"
        );
      }
    } else {
      if (entry.commandType === "EPOCH_ADVANCE") {
        const advPayload = entry.payload as EpochAdvancePayload;
        if (advPayload.fromEpochId !== state.epochId) {
          throw new EpochMismatchError(state.epochId, advPayload.fromEpochId);
        }
      } else {
        if (entry.epochId !== state.epochId) {
          throw new EpochMismatchError(state.epochId, entry.epochId);
        }
      }
    }

    if (state.epochState === "QUARANTINED" && entry.commandType !== "EPOCH_ADVANCE") {
      throw new QuarantinedEpochError(state.epochId);
    }

    // Check proposal ID uniqueness for new entries
    const recordedIndexForProposal = state.appliedProposals.get(entry.proposalId);
    if (recordedIndexForProposal !== undefined) {
      throw new StateMachineError(
        `Proposal ID '${entry.proposalId}' was already applied at index ${recordedIndexForProposal.toString()}`,
        "DUPLICATE_PROPOSAL_ID"
      );
    }

    // ------------------------------------------------------------------------
    // 6. Retention Floor & Backpressure Boundary (WP1 / Stage 2-B.2)
    // ------------------------------------------------------------------------
    const rawFret = BackpressurePolicy.calculateRetentionFloor(
      entry.appLogIndex,
      L_c_persisted,
      W_mem
    );
    const retentionFloorIndex = rawFret > state.retentionFloorIndex
      ? rawFret
      : state.retentionFloorIndex;

    // Execute pure command reduction
    const result = this.reduceCommand(
      state,
      entry,
      computedPayloadHash,
      retentionFloorIndex,
      L_c_persisted
    );

    // Enforce hard in-memory backlog ceiling
    const enforceBacklog = options?.enforceBacklogLimit ?? true;
    const maxBacklog =
      options?.backpressureConfig?.maxBacklog ?? BackpressurePolicy.DEFAULTS.maxBacklog;
    if (enforceBacklog && BigInt(result.state.appliedIndices.size) > maxBacklog) {
      throw new BacklogLimitExceededError(BigInt(result.state.appliedIndices.size), maxBacklog);
    }

    return result;
  }

  /**
   * Helper to record proposal ID and application index into immutable collections
   * while atomically evicting historical entries below the retention floor.
   */
  private static recordAppliedEntry(
    state: ApplicationState,
    entry: CommittedConsensusEntry,
    computedPayloadHash: string,
    retentionFloorIndex: bigint
  ): {
    nextProposals: ReadonlyFrozenMap<string, bigint>;
    nextIndices: ReadonlyFrozenMap<bigint, AppliedIndexRecord>;
  } {
    const proposals = new Map(state.appliedProposals);
    proposals.set(entry.proposalId, entry.appLogIndex);

    const indices = new Map(state.appliedIndices);
    const indexRecord: AppliedIndexRecord = Object.freeze({
      proposalId: entry.proposalId,
      payloadHash: computedPayloadHash,
    });
    indices.set(entry.appLogIndex, indexRecord);

    // Dual eviction: prune all entries below retentionFloorIndex
    for (const [idx, rec] of indices.entries()) {
      if (idx < retentionFloorIndex) {
        indices.delete(idx);
        proposals.delete(rec.proposalId);
      }
    }

    return {
      nextProposals: new ReadonlyFrozenMap(proposals),
      nextIndices: new ReadonlyFrozenMap(indices),
    };
  }

  /**
   * Internal pure reducer routing commands to transition helpers.
   */
  private static reduceCommand(
    state: ApplicationState,
    entry: CommittedConsensusEntry,
    computedPayloadHash: string,
    retentionFloorIndex: bigint,
    lastConsecutivePersistedAppIndex: bigint
  ): StateMachineApplyResult {
    switch (entry.commandType) {
      case "EPOCH_INITIALIZE":
        return this.applyEpochInitialize(
          state,
          entry,
          computedPayloadHash,
          retentionFloorIndex,
          lastConsecutivePersistedAppIndex
        );
      case "EPOCH_ADVANCE":
        return this.applyEpochAdvance(
          state,
          entry,
          computedPayloadHash,
          retentionFloorIndex,
          lastConsecutivePersistedAppIndex
        );
      case "EPOCH_QUARANTINE":
        return this.applyEpochQuarantine(
          state,
          entry,
          computedPayloadHash,
          retentionFloorIndex,
          lastConsecutivePersistedAppIndex
        );
      case "DELEGATION_REVOKE":
        return this.applyDelegationRevoke(
          state,
          entry,
          computedPayloadHash,
          retentionFloorIndex,
          lastConsecutivePersistedAppIndex
        );
      case "POLICY_UPDATE":
        return this.applyPolicyUpdate(
          state,
          entry,
          computedPayloadHash,
          retentionFloorIndex,
          lastConsecutivePersistedAppIndex
        );
      case "TICKET_COMMIT":
        return this.applyTicketCommit(
          state,
          entry,
          computedPayloadHash,
          retentionFloorIndex,
          lastConsecutivePersistedAppIndex
        );
      default: {
        const exhaustiveCheck: never = entry.commandType;
        throw new StateMachineError(`Unrecognized command type: ${String(exhaustiveCheck)}`, "UNKNOWN_COMMAND_TYPE");
      }
    }
  }

  // ==========================================================================
  // Reducer: EPOCH_INITIALIZE
  // ==========================================================================
  private static applyEpochInitialize(
    state: ApplicationState,
    entry: CommittedConsensusEntry,
    computedPayloadHash: string,
    retentionFloorIndex: bigint,
    lastConsecutivePersistedAppIndex: bigint
  ): StateMachineApplyResult {
    const p = entry.payload as EpochInitializePayload;
    if (!p.epochId || p.epochId.trim().length === 0) {
      throw new InvalidCommandPayloadError("EPOCH_INITIALIZE", "epochId is required");
    }
    if (p.epochHeight < 1) {
      throw new InvalidCommandPayloadError("EPOCH_INITIALIZE", "epochHeight must be >= 1");
    }
    if (p.sequenceFloor < 0n) {
      throw new InvalidCommandPayloadError("EPOCH_INITIALIZE", "sequenceFloor must be non-negative");
    }

    const genesisChainHash = sha256(`GENESIS:${p.epochId}:${p.epochHeight}:${p.sequenceFloor.toString()}`);
    const { nextProposals, nextIndices } = this.recordAppliedEntry(
      state,
      entry,
      computedPayloadHash,
      retentionFloorIndex
    );

    const nextState: ApplicationState = {
      ...state,
      epochId: p.epochId,
      epochHeight: p.epochHeight,
      epochState: "ACTIVE",
      lastAppliedAppIndex: entry.appLogIndex,
      lastAppliedRaftTerm: entry.raftTerm,
      lastPhysicalCursor: { ...entry.physicalCursor },
      chainHeadHash: genesisChainHash,
      lastSequenceNumber: p.sequenceFloor,
      retentionFloorIndex,
      lastConsecutivePersistedAppIndex,
      appliedProposals: nextProposals,
      appliedIndices: nextIndices,
    };

    return {
      status: "APPLIED",
      appliedAppIndex: entry.appLogIndex,
      appliedRaftTerm: entry.raftTerm,
      physicalCursor: entry.physicalCursor,
      chainHeadHash: genesisChainHash,
      state: freezeState(nextState),
      retentionFloorIndex,
    };
  }

  // ==========================================================================
  // Reducer: EPOCH_ADVANCE
  // ==========================================================================
  private static applyEpochAdvance(
    state: ApplicationState,
    entry: CommittedConsensusEntry,
    computedPayloadHash: string,
    retentionFloorIndex: bigint,
    lastConsecutivePersistedAppIndex: bigint
  ): StateMachineApplyResult {
    const p = entry.payload as EpochAdvancePayload;
    if (!p.toEpochId || p.toEpochId.trim().length === 0) {
      throw new InvalidCommandPayloadError("EPOCH_ADVANCE", "toEpochId is required");
    }
    if (p.newHeight !== state.epochHeight + 1) {
      throw new InvalidCommandPayloadError(
        "EPOCH_ADVANCE",
        `newHeight (${p.newHeight}) must be exactly prior height + 1 (${state.epochHeight + 1})`
      );
    }
    if (p.priorChainHeadHash !== state.chainHeadHash) {
      throw new InvalidCommandPayloadError(
        "EPOCH_ADVANCE",
        `priorChainHeadHash '${p.priorChainHeadHash}' does not match current chainHeadHash '${state.chainHeadHash}'`
      );
    }

    const nextChainHash = sha256(`${state.chainHeadHash}:ADVANCE:${p.toEpochId}:${p.newHeight}`);
    const { nextProposals, nextIndices } = this.recordAppliedEntry(
      state,
      entry,
      computedPayloadHash,
      retentionFloorIndex
    );

    const nextState: ApplicationState = {
      ...state,
      epochId: p.toEpochId,
      epochHeight: p.newHeight,
      epochState: "ACTIVE",
      lastAppliedAppIndex: entry.appLogIndex,
      lastAppliedRaftTerm: entry.raftTerm,
      lastPhysicalCursor: { ...entry.physicalCursor },
      chainHeadHash: nextChainHash,
      retentionFloorIndex,
      lastConsecutivePersistedAppIndex,
      appliedProposals: nextProposals,
      appliedIndices: nextIndices,
    };

    return {
      status: "APPLIED",
      appliedAppIndex: entry.appLogIndex,
      appliedRaftTerm: entry.raftTerm,
      physicalCursor: entry.physicalCursor,
      chainHeadHash: nextChainHash,
      state: freezeState(nextState),
      retentionFloorIndex,
    };
  }

  // ==========================================================================
  // Reducer: EPOCH_QUARANTINE
  // ==========================================================================
  private static applyEpochQuarantine(
    state: ApplicationState,
    entry: CommittedConsensusEntry,
    computedPayloadHash: string,
    retentionFloorIndex: bigint,
    lastConsecutivePersistedAppIndex: bigint
  ): StateMachineApplyResult {
    const p = entry.payload as EpochQuarantinePayload;
    if (!p.reason || p.reason.trim().length === 0) {
      throw new InvalidCommandPayloadError("EPOCH_QUARANTINE", "quarantine reason is required");
    }

    const nextChainHash = sha256(`${state.chainHeadHash}:QUARANTINE:${p.reason}`);
    const { nextProposals, nextIndices } = this.recordAppliedEntry(
      state,
      entry,
      computedPayloadHash,
      retentionFloorIndex
    );

    const nextState: ApplicationState = {
      ...state,
      epochState: "QUARANTINED",
      lastAppliedAppIndex: entry.appLogIndex,
      lastAppliedRaftTerm: entry.raftTerm,
      lastPhysicalCursor: { ...entry.physicalCursor },
      chainHeadHash: nextChainHash,
      retentionFloorIndex,
      lastConsecutivePersistedAppIndex,
      appliedProposals: nextProposals,
      appliedIndices: nextIndices,
    };

    return {
      status: "APPLIED",
      appliedAppIndex: entry.appLogIndex,
      appliedRaftTerm: entry.raftTerm,
      physicalCursor: entry.physicalCursor,
      chainHeadHash: nextChainHash,
      state: freezeState(nextState),
      retentionFloorIndex,
    };
  }

  // ==========================================================================
  // Reducer: DELEGATION_REVOKE
  // ==========================================================================
  private static applyDelegationRevoke(
    state: ApplicationState,
    entry: CommittedConsensusEntry,
    computedPayloadHash: string,
    retentionFloorIndex: bigint,
    lastConsecutivePersistedAppIndex: bigint
  ): StateMachineApplyResult {
    const p = entry.payload as DelegationRevokePayload;
    if (!p.authorizationId || p.authorizationId.trim().length === 0) {
      throw new InvalidCommandPayloadError("DELEGATION_REVOKE", "authorizationId is required");
    }

    const nextRevocations = new Set(state.revokedAuthorizations);
    nextRevocations.add(p.authorizationId);

    const nextChainHash = sha256(`${state.chainHeadHash}:REVOKE:${p.authorizationId}`);
    const { nextProposals, nextIndices } = this.recordAppliedEntry(
      state,
      entry,
      computedPayloadHash,
      retentionFloorIndex
    );

    const nextState: ApplicationState = {
      ...state,
      revokedAuthorizations: new ReadonlyFrozenSet(nextRevocations),
      lastAppliedAppIndex: entry.appLogIndex,
      lastAppliedRaftTerm: entry.raftTerm,
      lastPhysicalCursor: { ...entry.physicalCursor },
      chainHeadHash: nextChainHash,
      retentionFloorIndex,
      lastConsecutivePersistedAppIndex,
      appliedProposals: nextProposals,
      appliedIndices: nextIndices,
    };

    return {
      status: "APPLIED",
      appliedAppIndex: entry.appLogIndex,
      appliedRaftTerm: entry.raftTerm,
      physicalCursor: entry.physicalCursor,
      chainHeadHash: nextChainHash,
      state: freezeState(nextState),
      retentionFloorIndex,
    };
  }

  // ==========================================================================
  // Reducer: POLICY_UPDATE
  // ==========================================================================
  private static applyPolicyUpdate(
    state: ApplicationState,
    entry: CommittedConsensusEntry,
    computedPayloadHash: string,
    retentionFloorIndex: bigint,
    lastConsecutivePersistedAppIndex: bigint
  ): StateMachineApplyResult {
    const p = entry.payload as PolicyUpdatePayload;
    if (!p.policyId || p.policyId.trim().length === 0) {
      throw new InvalidCommandPayloadError("POLICY_UPDATE", "policyId is required");
    }
    if (p.revision < 1) {
      throw new InvalidCommandPayloadError("POLICY_UPDATE", "revision must be >= 1");
    }
    if (!p.policyHash || p.policyHash.trim().length === 0) {
      throw new InvalidCommandPayloadError("POLICY_UPDATE", "policyHash is required");
    }

    const existingPolicy = state.policies.get(p.policyId);
    if (existingPolicy && p.revision <= existingPolicy.revision) {
      throw new InvalidCommandPayloadError(
        "POLICY_UPDATE",
        `policy revision must advance strictly: existing is ${existingPolicy.revision}, received ${p.revision}`
      );
    }

    // F-02: Freeze individual PolicyRecord instance
    const policyRecord: PolicyRecord = Object.freeze({
      policyId: p.policyId,
      revision: p.revision,
      policyHash: p.policyHash,
      definitionJson: p.definitionJson,
    });

    const nextPolicies = new Map(state.policies);
    nextPolicies.set(p.policyId, policyRecord);

    const nextChainHash = sha256(`${state.chainHeadHash}:POLICY:${p.policyId}:${p.revision}:${p.policyHash}`);
    const { nextProposals, nextIndices } = this.recordAppliedEntry(
      state,
      entry,
      computedPayloadHash,
      retentionFloorIndex
    );

    const nextState: ApplicationState = {
      ...state,
      policies: new ReadonlyFrozenMap(nextPolicies),
      lastAppliedAppIndex: entry.appLogIndex,
      lastAppliedRaftTerm: entry.raftTerm,
      lastPhysicalCursor: { ...entry.physicalCursor },
      chainHeadHash: nextChainHash,
      retentionFloorIndex,
      lastConsecutivePersistedAppIndex,
      appliedProposals: nextProposals,
      appliedIndices: nextIndices,
    };

    return {
      status: "APPLIED",
      appliedAppIndex: entry.appLogIndex,
      appliedRaftTerm: entry.raftTerm,
      physicalCursor: entry.physicalCursor,
      chainHeadHash: nextChainHash,
      state: freezeState(nextState),
      retentionFloorIndex,
    };
  }

  // ==========================================================================
  // Reducer: TICKET_COMMIT
  // ==========================================================================
  private static applyTicketCommit(
    state: ApplicationState,
    entry: CommittedConsensusEntry,
    computedPayloadHash: string,
    retentionFloorIndex: bigint,
    lastConsecutivePersistedAppIndex: bigint
  ): StateMachineApplyResult {
    const p = entry.payload as TicketCommitPayload;
    if (!p.ticketId || p.ticketId.trim().length === 0) {
      throw new InvalidCommandPayloadError("TICKET_COMMIT", "ticketId is required");
    }
    if (!p.authorizationId || p.authorizationId.trim().length === 0) {
      throw new InvalidCommandPayloadError("TICKET_COMMIT", "authorizationId is required");
    }
    if (!p.bindingDigest || p.bindingDigest.trim().length === 0) {
      throw new InvalidCommandPayloadError("TICKET_COMMIT", "bindingDigest is required");
    }

    // Domain Check: Revocation Gate
    if (state.revokedAuthorizations.has(p.authorizationId)) {
      return {
        status: "COMMAND_REJECTED",
        rejectionReason: `Authorization '${p.authorizationId}' has been revoked`,
        appliedAppIndex: state.lastAppliedAppIndex,
        appliedRaftTerm: state.lastAppliedRaftTerm,
        physicalCursor: state.lastPhysicalCursor,
        chainHeadHash: state.chainHeadHash,
        state,
        retentionFloorIndex: state.retentionFloorIndex,
      };
    }

    // Domain Check: Duplicate Ticket Gate
    if (state.committedTickets.has(p.ticketId)) {
      return {
        status: "COMMAND_REJECTED",
        rejectionReason: `Ticket '${p.ticketId}' has already been committed`,
        appliedAppIndex: state.lastAppliedAppIndex,
        appliedRaftTerm: state.lastAppliedRaftTerm,
        physicalCursor: state.lastPhysicalCursor,
        chainHeadHash: state.chainHeadHash,
        state,
        retentionFloorIndex: state.retentionFloorIndex,
      };
    }

    // Monotonic Sequence Number Allocation
    const allocatedSeq = state.lastSequenceNumber + 1n;

    // Recursive Receipt Chain Head Hash
    const nextChainHash = sha256(
      `${state.chainHeadHash}:${state.epochId}:${allocatedSeq.toString()}:${p.ticketId}:${p.bindingDigest}`
    );

    const ticketRecord: CommittedTicketRecord = Object.freeze({
      ticketId: p.ticketId,
      epochId: state.epochId,
      authorizationId: p.authorizationId,
      bindingDigest: p.bindingDigest,
      policyId: p.policyId,
      policyRevision: p.policyRevision,
      sequenceNumber: allocatedSeq,
      debitedAmount: p.debitedAmount ?? 0n,
      committedAtSeconds: entry.committedAtSeconds,
    });

    const nextTickets = new Map(state.committedTickets);
    nextTickets.set(p.ticketId, ticketRecord);

    const { nextProposals, nextIndices } = this.recordAppliedEntry(
      state,
      entry,
      computedPayloadHash,
      retentionFloorIndex
    );

    const nextState: ApplicationState = {
      ...state,
      committedTickets: new ReadonlyFrozenMap(nextTickets),
      lastSequenceNumber: allocatedSeq,
      lastAppliedAppIndex: entry.appLogIndex,
      lastAppliedRaftTerm: entry.raftTerm,
      lastPhysicalCursor: { ...entry.physicalCursor },
      chainHeadHash: nextChainHash,
      retentionFloorIndex,
      lastConsecutivePersistedAppIndex,
      appliedProposals: nextProposals,
      appliedIndices: nextIndices,
    };

    return {
      status: "APPLIED",
      appliedAppIndex: entry.appLogIndex,
      appliedRaftTerm: entry.raftTerm,
      physicalCursor: entry.physicalCursor,
      chainHeadHash: nextChainHash,
      state: freezeState(nextState),
      retentionFloorIndex,
    };
  }
}
