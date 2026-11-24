/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.1
 * Application State Machine Domain Types & Contracts
 *
 * Provides strongly-typed, pure data models, commands, cursor definitions,
 * application state structures, and sequencing errors for the deterministic
 * application state-machine apply layer.
 *
 * STRICT CONSENSUS BOUNDARY:
 * This layer is strictly an APPLY layer for committed consensus logs.
 * It DOES NOT implement leader election, peer voting, or Raft consensus.
 * All entries processed by this layer must have been linearized and committed
 * by the authoritative etcd Raft cluster.
 */

// ============================================================================
// Physical Stream Cursor & Logical Application Index
// ============================================================================

/**
 * Physical cursor representing wire-level position in the external etcd watch stream.
 * Decoupled from application log index to handle global revision leaps and multi-event transactions.
 */
export interface PhysicalStreamCursor {
  /**
   * Cluster-wide monotonic 64-bit revision assigned by etcd.
   */
  readonly etcdRevision: bigint;
  /**
   * 0-based offset identifying the relative order of an event within a multi-event etcd transaction.
   */
  readonly subIndex: number;
}

// ============================================================================
// Command Types & Payloads
// ============================================================================

export type ConsensusCommandType =
  | "EPOCH_INITIALIZE"
  | "EPOCH_ADVANCE"
  | "EPOCH_QUARANTINE"
  | "DELEGATION_REVOKE"
  | "TICKET_COMMIT"
  | "POLICY_UPDATE";

export interface EpochInitializePayload {
  readonly epochId: string;
  readonly epochHeight: number;
  readonly sequenceFloor: bigint;
  readonly createdSeconds: number;
}

export interface EpochAdvancePayload {
  readonly fromEpochId: string;
  readonly toEpochId: string;
  readonly newHeight: number;
  readonly priorChainHeadHash: string;
  readonly advancedAtSeconds: number;
}

export interface EpochQuarantinePayload {
  readonly epochId: string;
  readonly reason: string;
  readonly quarantinedAtSeconds: number;
  readonly details?: Record<string, unknown>;
}

export interface DelegationRevokePayload {
  readonly epochId: string;
  readonly authorizationId: string;
  readonly revokedAtSeconds: number;
  readonly reason?: string;
}

export interface BudgetWindowSpend {
  readonly windowType: string;
  readonly windowStart: number;
  readonly cumulativeSpentAfter: bigint;
}

export interface TicketCommitPayload {
  readonly ticketId: string;
  readonly epochId: string;
  readonly authorizationId: string;
  readonly bindingDigest: string;
  readonly policyId: string;
  readonly policyRevision: number;
  readonly debitedAmount: bigint;
  readonly budgetWindows?: ReadonlyArray<BudgetWindowSpend>;
}

export interface PolicyUpdatePayload {
  readonly policyId: string;
  readonly revision: number;
  readonly policyHash: string;
  readonly definitionJson?: string;
}

export type ConsensusPayloadMap = {
  EPOCH_INITIALIZE: EpochInitializePayload;
  EPOCH_ADVANCE: EpochAdvancePayload;
  EPOCH_QUARANTINE: EpochQuarantinePayload;
  DELEGATION_REVOKE: DelegationRevokePayload;
  TICKET_COMMIT: TicketCommitPayload;
  POLICY_UPDATE: PolicyUpdatePayload;
};

// ============================================================================
// Committed Consensus Log Entry
// ============================================================================

export interface CommittedConsensusEntry<
  TType extends ConsensusCommandType = ConsensusCommandType,
  TPayload = TType extends keyof ConsensusPayloadMap ? ConsensusPayloadMap[TType] : unknown,
> {
  /**
   * Epoch identifier governing this log entry.
   */
  readonly epochId: string;
  /**
   * Strictly contiguous, monotonic application log index: 1, 2, 3, ...
   */
  readonly appLogIndex: bigint;
  /**
   * Raft term of the consensus cluster when the proposal was committed.
   */
  readonly raftTerm: bigint;
  /**
   * Physical wire cursor in etcd.
   */
  readonly physicalCursor: PhysicalStreamCursor;
  /**
   * Domain command type.
   */
  readonly commandType: TType;
  /**
   * Strongly-typed command payload.
   */
  readonly payload: TPayload;
  /**
   * SHA-256 digest of canonical serialized payload for tamper detection.
   */
  readonly payloadHash: string;
  /**
   * Unique client-generated idempotency token.
   */
  readonly proposalId: string;
  /**
   * Monotonic Unix timestamp (seconds) when proposal was committed in consensus.
   */
  readonly committedAtSeconds: number;
  /**
   * Canonicalization format version: 1 (Canon-v1) or 2 (TTCF-v1 / Canon-v2).
   * Defaults to 1 for backward compatibility.
   */
  readonly canonicalizationVersion?: 1 | 2;
}

// ============================================================================
// Application State Domain Models
// ============================================================================

export type EpochLifecycleState = "INITIAL" | "ACTIVE" | "QUARANTINED" | "TERMINATED";

export interface CommittedTicketRecord {
  readonly ticketId: string;
  readonly epochId: string;
  readonly authorizationId: string;
  readonly bindingDigest: string;
  readonly policyId: string;
  readonly policyRevision: number;
  readonly sequenceNumber: bigint;
  readonly debitedAmount: bigint;
  readonly committedAtSeconds: number;
}

export interface PolicyRecord {
  readonly policyId: string;
  readonly revision: number;
  readonly policyHash: string;
  readonly definitionJson?: string;
}

export interface AppliedIndexRecord {
  readonly proposalId: string;
  readonly payloadHash: string;
}

export interface ApplicationState {
  readonly clusterId: string;
  readonly epochId: string;
  readonly epochHeight: number;
  readonly epochState: EpochLifecycleState;
  readonly lastAppliedAppIndex: bigint;
  readonly lastAppliedRaftTerm: bigint;
  readonly lastPhysicalCursor: PhysicalStreamCursor;
  readonly chainHeadHash: string;
  readonly lastSequenceNumber: bigint;
  readonly committedTickets: ReadonlyMap<string, CommittedTicketRecord>;
  readonly revokedAuthorizations: ReadonlySet<string>;
  readonly policies: ReadonlyMap<string, PolicyRecord>;
  readonly appliedProposals: ReadonlyMap<string, bigint>;
  readonly appliedIndices: ReadonlyMap<bigint, AppliedIndexRecord>;
  /**
   * Earliest logical application index currently retained in memory.
   * Governed by F_ret = max(1n, min(A_app - W_mem + 1n, L_c_persisted + 1n)).
   */
  readonly retentionFloorIndex: bigint;
  /**
   * Highest contiguous application index durably persisted in PostgreSQL (L_c_persisted).
   */
  readonly lastConsecutivePersistedAppIndex: bigint;
}

// ============================================================================
// Backpressure Configuration & Evaluation Models
// ============================================================================

export type BackpressureStreamState =
  | "STREAMING"
  | "BACKPRESSURE_PAUSED"
  | "DISCONNECTED"
  | "RECONNECTING"
  | "CATCH_UP_RECOVERY";

export type BackpressureAlertLevel = "NOMINAL" | "WARNING" | "CRITICAL";

export type BackpressureAction =
  | "CONTINUE"
  | "PAUSE_STREAM"
  | "RESUME_STREAM"
  | "ABORT_OVERFLOW"
  | "HALT_RETRY_EXHAUSTED";

export interface BackpressureConfig {
  /**
   * Nominal in-memory retention window (W_mem).
   * Default: 10,000n.
   */
  readonly memoryRetentionWindow: bigint;
  /**
   * Persistence lag threshold triggering stream pause (Delta_lag_max).
   * Default: 1,000n.
   */
  readonly pauseThreshold: bigint;
  /**
   * Persistence lag threshold triggering stream resume (Delta_lag_resume).
   * Default: 500n.
   */
  readonly resumeThreshold: bigint;
  /**
   * Persistence lag threshold triggering warning (Delta_lag_warn).
   * Default: 500n.
   */
  readonly warningThreshold: bigint;
  /**
   * Hard in-memory backlog ceiling (B_max = W_mem + Delta_lag_max).
   * Default: 11,000n.
   */
  readonly maxBacklog: bigint;
  /**
   * Duration (seconds) of sustained lag/pause triggering critical alert.
   * Default: 30.
   */
  readonly criticalAlertTimeoutSeconds: number;
  /**
   * Maximum database retry attempts before failure halt.
   * Default: 5.
   */
  readonly maxRetryAttempts: number;
}

export interface BackpressureEvaluation {
  readonly streamState: BackpressureStreamState;
  readonly persistenceLag: bigint;
  readonly inMemoryBacklog: bigint;
  readonly alertLevel: BackpressureAlertLevel;
  readonly isPaused: boolean;
  readonly warningTriggered: boolean;
  readonly criticalAlertTriggered: boolean;
  readonly retryExhausted: boolean;
  readonly action: BackpressureAction;
  readonly reason?: string;
}

// ============================================================================
// Reducer Output & Apply Results
// ============================================================================

export type StateMachineApplyStatus =
  | "APPLIED"
  | "ALREADY_APPLIED"
  | "COMMAND_REJECTED"
  | "HISTORICAL_RECORD_PRUNED";

export interface StateMachineApplyOptions {
  /**
   * Contiguous application index durably persisted in PostgreSQL (L_c_persisted).
   * If not provided, defaults to state.lastConsecutivePersistedAppIndex.
   */
  readonly lastConsecutivePersistedAppIndex?: bigint;
  /**
   * Configured in-memory retention window size (W_mem).
   * Default: 10,000n.
   */
  readonly memoryRetentionWindow?: bigint;
  /**
   * Backpressure configuration override.
   */
  readonly backpressureConfig?: Partial<BackpressureConfig>;
  /**
   * Whether to enforce the hard backlog ceiling in the pure reducer.
   * Default: true.
   */
  readonly enforceBacklogLimit?: boolean;
}

export interface StateMachineApplyResult {
  readonly status: StateMachineApplyStatus;
  readonly appliedAppIndex: bigint;
  readonly appliedRaftTerm: bigint;
  readonly physicalCursor: PhysicalStreamCursor;
  readonly chainHeadHash: string;
  readonly state: ApplicationState;
  readonly rejectionReason?: string;
  readonly duplicateDetected?: boolean;
  readonly retentionFloorIndex?: bigint;
}

// ============================================================================
// State Machine Exceptions
// ============================================================================

export class StateMachineError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message);
    this.name = "StateMachineError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class LogicalIndexGapError extends StateMachineError {
  constructor(public readonly expectedIndex: bigint, public readonly receivedIndex: bigint) {
    super(
      `Consensus application index gap detected: expected index ${expectedIndex.toString()}, received ${receivedIndex.toString()}`,
      "LOGICAL_INDEX_GAP",
    );
    this.name = "LogicalIndexGapError";
  }
}

export class OutOfOrderIndexError extends StateMachineError {
  constructor(public readonly lastAppliedIndex: bigint, public readonly receivedIndex: bigint) {
    super(
      `Out-of-order consensus entry: received index ${receivedIndex.toString()} when last applied is ${lastAppliedIndex.toString()}`,
      "OUT_OF_ORDER_INDEX",
    );
    this.name = "OutOfOrderIndexError";
  }
}

export class EpochMismatchError extends StateMachineError {
  constructor(public readonly expectedEpochId: string, public readonly receivedEpochId: string) {
    super(
      `Consensus epoch mismatch: active epoch is '${expectedEpochId}', but entry belongs to '${receivedEpochId}'`,
      "EPOCH_MISMATCH",
    );
    this.name = "EpochMismatchError";
  }
}

export class PayloadHashMismatchError extends StateMachineError {
  constructor(public readonly appLogIndex: bigint, public readonly expectedHash: string, public readonly computedHash: string) {
    super(
      `Consensus payload hash mismatch at index ${appLogIndex.toString()}: expected '${expectedHash}', computed '${computedHash}'`,
      "PAYLOAD_HASH_MISMATCH",
    );
    this.name = "PayloadHashMismatchError";
  }
}

export class HistoricalIndexConflictError extends StateMachineError {
  constructor(
    public readonly appLogIndex: bigint,
    public readonly conflictType: "PROPOSAL_ID" | "PAYLOAD_HASH",
    message: string
  ) {
    super(message, `HISTORICAL_INDEX_${conflictType}_CONFLICT`);
    this.name = "HistoricalIndexConflictError";
  }
}

export class UnverifiableHistoricalEntryError extends StateMachineError {
  constructor(public readonly appLogIndex: bigint) {
    super(
      `Historical entry at index ${appLogIndex.toString()} cannot be verified against in-memory state; failing closed`,
      "UNVERIFIABLE_HISTORICAL_ENTRY"
    );
    this.name = "UnverifiableHistoricalEntryError";
  }
}

export class QuarantinedEpochError extends StateMachineError {
  constructor(public readonly epochId: string, message = `Epoch '${epochId}' is quarantined; state transitions are blocked`) {
    super(message, "EPOCH_QUARANTINED");
    this.name = "QuarantinedEpochError";
  }
}

export class InvalidCommandPayloadError extends StateMachineError {
  constructor(public readonly commandType: string, reason: string) {
    super(`Invalid consensus command payload for '${commandType}': ${reason}`, "INVALID_COMMAND_PAYLOAD");
    this.name = "InvalidCommandPayloadError";
  }
}

export class BacklogLimitExceededError extends StateMachineError {
  constructor(
    public readonly currentBacklog: bigint,
    public readonly maxBacklog: bigint
  ) {
    super(
      `In-memory consensus backlog exceeded hard limit: ${currentBacklog.toString()} entries in memory (maximum ${maxBacklog.toString()})`,
      "BACKLOG_LIMIT_EXCEEDED"
    );
    this.name = "BacklogLimitExceededError";
  }
}
