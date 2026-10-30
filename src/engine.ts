import type { KeyObject } from "node:crypto";
import {
  SQLiteAuthorizationStore,
  type SQLiteSynchronousMode,
  type CheckpointMode,
  type CheckpointResult,
  type AuthorizationRecord,
  type ListUnreconciledWitnessRecordsOptions,
  type UnreconciledWitnessRecord,
  type UnreconciledWitnessStatus,
  type WitnessStatus,
} from "./authorization-store.js";
import {
  type PolicyRecord,
  type PolicyRevisionRecord,
  type PolicyStatus,
} from "./policy-store.js";
import {
  type PersistedIssuerKeyMetadata,
} from "./key-store.js";
import type { IssuerKeyMetadata, KeyStatus } from "./key-registry.js";
import {
  issueSignedTransactionAuthorizationV3,
  consumeSignedTransactionAuthorizationV3,
  consumeSignedTransactionAuthorizationV3Async,
  cancelAuthorization,
  type V3Signer,
  type SignedTransactionAuthorizationV3,
} from "./authorization-lifecycle.js";
import {
  generateIssuerKeyPair,
  parseEd25519PublicKey,
  areEd25519PublicKeysEqual,
  type SignedAuthorizationArtifactV3,
} from "./authorization-crypto.js";
import {
  type DemoPolicy,
  type BudgetWindowType,
  BUDGET_WINDOW_SECONDS,
  calculateBudgetWindowStart,
  calculateBudgetWindowEnd,
} from "./policy.js";
import {
  createTransactionEnvelope,
  matchesTransactionEnvelope,
  type TransactionRequest,
  type TransactionEnvelope,
} from "./transaction-envelope.js";
import { isFatalIOError } from "./sqlite-transaction.js";
import type { TransactionAuthorization } from "./policy-transaction.js";
import type { Clock, MonotonicClock } from "./clock.js";
import {
  type MonotonicWitnessAdapter,
  type SignedWitnessReceipt,
  type WitnessReconcileResult,
  canonicalWitnessReceiptPayload,
  verifyWitnessReceipt,
} from "./monotonic-witness.js";

// ============================================================================
// Error Hierarchy
// ============================================================================

/**
 * Base class for all operational and validation errors thrown by the Web3User SDK.
 */
export class Web3UserError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "Web3UserError";
  }
}

/**
 * Thrown when attempting an operation on an engine instance that has been closed.
 */
export class EngineClosedError extends Web3UserError {
  constructor(message = "Web3UserEngine is closed and cannot perform operations.", options?: ErrorOptions) {
    super(message, options);
    this.name = "EngineClosedError";
  }
}

/**
 * Thrown when arguments, IDs, or configurations fail syntactic or boundary validation.
 */
export class ValidationError extends Web3UserError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "ValidationError";
  }
}

/**
 * Thrown when a storage transaction cannot acquire write locks within the configured contention retry budget.
 */
export class ContentionError extends Web3UserError {
  constructor(message = "Database is busy; transaction contention retry limit exceeded.", options?: ErrorOptions) {
    super(message, options);
    this.name = "ContentionError";
  }
}

/**
 * Thrown when ClockGuard detects backward clock rollback, excessive forward drift, or startup gap violations.
 */
export class ClockGuardError extends Web3UserError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "ClockGuardError";
  }
}

/**
 * Thrown when the database connection is quarantined/tainted due to an uncertain COMMIT or unrecoverable error.
 */
export class StoreTaintedError extends Web3UserError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "StoreTaintedError";
  }
}

/**
 * Normalize an unknown error into a typed Web3UserError subclass while preserving the message and cause.
 */
export function wrapEngineError(err: unknown): Web3UserError {
  if (err instanceof Web3UserError) {
    return err;
  }
  const message = err instanceof Error ? err.message : String(err);
  const options: ErrorOptions | undefined =
    err instanceof Error || (typeof err === "object" && err !== null)
      ? { cause: err }
      : undefined;

  if (
    message.includes("tainted and unusable") ||
    message.includes("Commit failure with uncertain outcome") ||
    message.includes("Fatal storage I/O error") ||
    message.includes("Fatal rollback failure") ||
    message.includes("SQLITE_IOERR")
  ) {
    return new StoreTaintedError(message, options);
  }
  if (
    message.includes("ClockGuard") ||
    message.includes("clock monitor is in a tripped state") ||
    message.includes("clock anchor has expired") ||
    message.includes("Clock rollback detected") ||
    message.includes("forward clock gap") ||
    message.includes("forward step")
  ) {
    return new ClockGuardError(message, options);
  }
  if (
    message.includes("contention retry limit exceeded") ||
    message.includes("SQLITE_BUSY")
  ) {
    return new ContentionError(message, options);
  }
  if (
    message.includes("must be") ||
    message.includes("exceeds maximum length") ||
    message.includes("Invalid checkpoint mode") ||
    message.includes("required") ||
    message.includes("malformed")
  ) {
    return new ValidationError(message, options);
  }
  return new Web3UserError(message, options);
}

// ============================================================================
// SDK Configuration & Parameter Interfaces
// ============================================================================

/**
 * Configuration options for opening a Web3User Authorization Engine backed by SQLite.
 */
export interface Web3UserEngineOptions {
  /**
   * Path to the SQLite database file on a durable local filesystem.
   * In-memory (e.g. ":memory:") is supported for isolated unit testing.
   */
  readonly databasePath: string;

  /**
   * Durability settings for SQLite connections.
   */
  readonly durability?: {
    /**
     * PRAGMA synchronous setting. Defaults to "FULL" for disk durability.
     */
    readonly synchronous?: SQLiteSynchronousMode;

    /**
     * SQLite busy_timeout in milliseconds. Defaults to 5000ms.
     */
    readonly busyTimeoutMs?: number;
  };

  /**
   * Clock and hardware timestamp guardrails.
   */
  readonly clock?: {
    readonly clock?: Clock;
    readonly monotonicClock?: MonotonicClock;
    /**
     * Maximum allowed forward wall-clock gap at startup. Defaults to 3600s.
     */
    readonly maxStartupForwardGapSeconds?: number;
  };

  /**
   * Callback invoked if an unrecoverable commit failure taints the database connection.
   */
  readonly onFatalTaint?: (reason: string) => void;

  /**
   * When true, allows legacy V1/V2 artifact versions.
   * Defaults to false (strict V3 only).
   */
  readonly allowLegacyArtifactVersions?: boolean;

  /**
   * Optional monotonic witness adapter for multi-node rollback resistance and witness receipts.
   */
  readonly witnessAdapter?: MonotonicWitnessAdapter;

  /**
   * Optional witness public key for verifying signed witness receipts.
   * If omitted, falls back to witnessAdapter.publicKeyPem if available.
   */
  readonly witnessPublicKey?: string | KeyObject;
}

/**
 * Parameters required to issue an Ed25519-signed V3 transaction authorization.
 */
export interface IssueAuthorizationParams {
  /**
   * Unique authorization ID (1..128 characters).
   */
  readonly authorizationId: string;

  /**
   * Identifier of the registered, active policy to bind against.
   */
  readonly policyId: string;

  /**
   * Candidate transaction request details.
   */
  readonly request: TransactionRequest;

  /**
   * Key ID and Ed25519 private key of the authorized issuer.
   *
   * SECURITY RULE: Never log, serialize, or hardcode private keys.
   * Private keys must be retrieved from secure environment variables,
   * key management services (KMS), or hardware security modules (HSM).
   */
  readonly signer: V3Signer;

  /**
   * Optional custom TTL in seconds (capped by policy and key expirations; default: 300s).
   */
  readonly ttlSeconds?: number;
}

/**
 * Parameters required to revalidate and consume an authorization.
 */
export interface ConsumeAuthorizationParams {
  /**
   * The signed V3 authorization artifact presented by the caller.
   */
  readonly artifact: unknown;

  /**
   * The candidate transaction request being submitted for execution.
   */
  readonly request: unknown;

  /**
   * Pre-calculated transaction envelope, if retained from issuance.
   * If omitted, the engine automatically calculates and verifies the envelope from the request.
   */
  readonly envelope?: unknown;

  /**
   * Optional witness adapter override for this specific consumption call.
   */
  readonly witnessAdapter?: MonotonicWitnessAdapter;

  /**
   * Optional witness public key override for verifying the returned witness receipt.
   */
  readonly witnessPublicKey?: string | KeyObject;

  /**
   * Optional idempotency key for witness reservation deduplication.
   */
  readonly idempotencyKey?: string;

  /**
   * Optional lease TTL in seconds for the witness reservation (default: 30s).
   */
  readonly leaseTtlSeconds?: number;
}

/**
 * Reconciliation outcome classifications for Web3User authorizations.
 */
export type ReconciliationOutcome =
  | "ALREADY_COMMITTED"
  | "RECONCILED"
  | "PENDING"
  | "DISPUTED"
  | "NOT_FOUND"
  | "NOT_CONSUMED"
  | "NOT_WITNESSED"
  | "UNAVAILABLE";

/**
 * Options for single-authorization reconciliation.
 */
export interface ReconcileAuthorizationOptions {
  /**
   * Optional witness adapter override. If provided, its public key must match
   * the engine's configured witness trust anchor.
   */
  readonly witnessAdapter?: MonotonicWitnessAdapter;

  /**
   * Optional witness public key override. If provided, it must match
   * the engine's configured witness trust anchor.
   */
  readonly witnessPublicKey?: string | KeyObject;
}

/**
 * Result of single-authorization reconciliation.
 */
export interface ReconcileAuthorizationResult {
  readonly authorizationId: string;
  readonly outcome: ReconciliationOutcome;
  readonly previousStatus?: WitnessStatus;
  readonly currentStatus?: WitnessStatus;
  readonly ticketId?: string;
  readonly receipt?: SignedWitnessReceipt;
  readonly reasons?: string[];
}

/**
 * Options for bounded batch reconciliation.
 */
export interface ReconcileAllOptions extends ReconcileAuthorizationOptions {
  /**
   * Filter discovery by unresolved status ('PENDING_COMMIT' | 'DISPUTED').
   * If omitted, discovers both statuses.
   */
  readonly status?: UnreconciledWitnessStatus;

  /**
   * Maximum number of unresolved records to discover and reconcile.
   * Integer between 1 and 1000. Defaults to 100.
   */
  readonly limit?: number;

  /**
   * Maximum number of concurrent reconciliation workers.
   * Integer between 1 and 10. Defaults to 4.
   */
  readonly concurrency?: number;

  /**
   * Optional AbortSignal to gracefully cancel processing of remaining authorizations in the batch.
   */
  readonly signal?: AbortSignal;

  /**
   * Optional timeout in milliseconds for the batch reconciliation.
   * When elapsed, in-flight operations settle and remaining authorizations are cancelled.
   */
  readonly timeoutMs?: number;
}

/**
 * Summary counts of reconciliation outcomes across a batch operation.
 */
export interface ReconcileAllSummary {
  readonly totalDiscovered: number;
  readonly totalProcessed: number;
  readonly reconciledCount: number;
  readonly alreadyCommittedCount: number;
  readonly pendingCount: number;
  readonly disputedCount: number;
  readonly unavailableCount: number;
  readonly errorCount: number;
}

/**
 * Result of a bounded batch reconciliation operation.
 */
export interface ReconcileAllResult {
  readonly summary: ReconcileAllSummary;
  readonly results: ReadonlyArray<ReconcileAuthorizationResult>;
  readonly aborted: boolean;
  readonly abortReason?: string;
}

// ============================================================================
// Web3UserEngine Facade Class
// ============================================================================

/**
 * Developer-facing facade for the Web3User off-chain authorization engine.
 *
 * Manages SQLite persistence, policy revision control, Ed25519 issuer keys,
 * and atomic single-use replay prevention.
 */
export class Web3UserEngine {
  private readonly store: SQLiteAuthorizationStore;
  private readonly witnessAdapter?: MonotonicWitnessAdapter;
  private readonly witnessPublicKey?: KeyObject;
  private isClosed = false;

  public constructor(options: Web3UserEngineOptions) {
    if (!options || typeof options !== "object") {
      throw new ValidationError("Web3UserEngine options must be an object.");
    }
    if (typeof options.databasePath !== "string" || options.databasePath.trim().length === 0) {
      throw new ValidationError("databasePath must be a non-empty string.");
    }

    let trustedWitnessKey: KeyObject | undefined;
    if (options.witnessPublicKey) {
      const parsed = parseEd25519PublicKey(options.witnessPublicKey);
      if (!parsed) {
        throw new ValidationError("Configured witnessPublicKey is not a valid Ed25519 public key.");
      }
      trustedWitnessKey = parsed;
    }

    if (options.witnessAdapter?.publicKeyPem) {
      const adapterKey = parseEd25519PublicKey(options.witnessAdapter.publicKeyPem);
      if (adapterKey) {
        if (trustedWitnessKey && !areEd25519PublicKeysEqual(trustedWitnessKey, adapterKey)) {
          throw new ValidationError("Configured witnessPublicKey conflicts with witnessAdapter.publicKeyPem.");
        }
        if (!trustedWitnessKey) {
          trustedWitnessKey = adapterKey;
        }
      }
    }

    this.witnessAdapter = options.witnessAdapter;
    this.witnessPublicKey = trustedWitnessKey;

    try {
      this.store = new SQLiteAuthorizationStore(options.databasePath, {
        clock: options.clock?.clock,
        monotonicClock: options.clock?.monotonicClock,
        maxStartupForwardGapSeconds: options.clock?.maxStartupForwardGapSeconds,
        synchronous: options.durability?.synchronous ?? "FULL",
        busyTimeoutMs: options.durability?.busyTimeoutMs ?? 5000,
        onFatalTaint: options.onFatalTaint,
        allowLegacyArtifactVersions: options.allowLegacyArtifactVersions ?? false,
        witnessPublicKey: this.witnessPublicKey,
      });
    } catch (err) {
      throw wrapEngineError(err);
    }
  }

  /**
   * Open a Web3User Authorization Engine backed by SQLite.
   * Runs schema initialization, WAL verification, and clock high-water synchronization.
   */
  public static open(options: Web3UserEngineOptions): Web3UserEngine {
    return new Web3UserEngine(options);
  }

  // ==========================================================================
  // Direct Authorization Operations
  // ==========================================================================

  /**
   * Evaluate a transaction request against an authoritative policy and issue a signed V3 artifact.
   * Atomically transitions authorization record state to 'issued' in SQLite.
   */
  public issue(params: IssueAuthorizationParams): SignedTransactionAuthorizationV3 {
    this.assertOpen();
    this.assertNotTainted();
    try {
      if (!params || typeof params !== "object") {
        throw new ValidationError("Issue parameters must be an object.");
      }
      if (typeof params.authorizationId !== "string" || params.authorizationId.trim().length === 0) {
        throw new ValidationError("Authorization ID must be a non-empty string.");
      }
      if (params.authorizationId.trim().length > 128) {
        throw new ValidationError("Authorization ID exceeds maximum length of 128 characters.");
      }
      if (typeof params.policyId !== "string" || params.policyId.trim().length === 0) {
        throw new ValidationError("Policy ID must be a non-empty string.");
      }
      if (!params.signer || typeof params.signer !== "object") {
        throw new ValidationError("Signer is required.");
      }
      if (!params.signer.keyId || typeof params.signer.keyId !== "string" || params.signer.keyId.trim().length === 0) {
        throw new ValidationError("Signer key ID must be a non-empty string.");
      }
      if (!params.signer.privateKey) {
        throw new ValidationError("Signer private key is required.");
      }

      return issueSignedTransactionAuthorizationV3(
        this.store,
        params.signer,
        params.authorizationId,
        params.policyId,
        params.request,
        params.ttlSeconds !== undefined ? { ttlSeconds: params.ttlSeconds } : undefined,
      );
    } catch (err) {
      this.handleError(err);
    }
  }

  /**
   * Revalidate and consume a signed V3 authorization artifact atomically.
   * Enforces single-use consumption and guarantees replay prevention.
   */
  public consume(params: ConsumeAuthorizationParams): TransactionAuthorization {
    this.assertOpen();
    this.assertNotTainted();
    try {
      if (!params || typeof params !== "object") {
        throw new ValidationError("Consume parameters must be an object.");
      }

      let envelope: TransactionEnvelope;
      if (params.envelope !== undefined && params.envelope !== null) {
        if (!matchesTransactionEnvelope(params.envelope, params.request)) {
          return {
            decision: "DENY",
            reasons: ["Transaction does not match the original envelope."],
          };
        }
        envelope = params.envelope as TransactionEnvelope;
      } else {
        const created = createTransactionEnvelope(params.request);
        if (!created.ok) {
          return {
            decision: "UNKNOWN",
            reasons: [created.reason],
          };
        }
        envelope = created.envelope;
      }

      if (params.witnessPublicKey) {
        if (!this.witnessPublicKey) {
          throw new ValidationError(
            "Cannot supply per-call witnessPublicKey: no witness trust anchor is configured on Web3UserEngine.",
          );
        }
        if (!areEd25519PublicKeysEqual(params.witnessPublicKey, this.witnessPublicKey)) {
          throw new ValidationError(
            "Supplied witnessPublicKey conflicts with configured engine witness trust anchor.",
          );
        }
      }
      if (params.witnessAdapter?.publicKeyPem) {
        if (!this.witnessPublicKey) {
          throw new ValidationError(
            "Cannot supply per-call witnessAdapter: no witness trust anchor is configured on Web3UserEngine.",
          );
        }
        if (!areEd25519PublicKeysEqual(params.witnessAdapter.publicKeyPem, this.witnessPublicKey)) {
          throw new ValidationError(
            "Supplied witnessAdapter public key conflicts with configured engine witness trust anchor.",
          );
        }
      }

      const witness = params.witnessAdapter ?? this.witnessAdapter;
      return consumeSignedTransactionAuthorizationV3(
        this.store,
        params.artifact,
        envelope,
        params.request,
        witness
          ? {
              witnessAdapter: witness,
              witnessPublicKey: this.witnessPublicKey,
              idempotencyKey: params.idempotencyKey,
              leaseTtlSeconds: params.leaseTtlSeconds,
            }
          : undefined,
      );
    } catch (err) {
      this.handleError(err);
    }
  }

  /**
   * Revalidate and consume a signed V3 authorization artifact asynchronously.
   * Supports asynchronous remote witness adapters, enforces single-use consumption,
   * and guarantees replay prevention without holding locks during remote calls.
   */
  public async consumeAsync(params: ConsumeAuthorizationParams): Promise<TransactionAuthorization> {
    this.assertOpen();
    this.assertNotTainted();
    try {
      if (!params || typeof params !== "object") {
        throw new ValidationError("Consume parameters must be an object.");
      }

      let envelope: TransactionEnvelope;
      if (params.envelope !== undefined && params.envelope !== null) {
        if (!matchesTransactionEnvelope(params.envelope, params.request)) {
          return {
            decision: "DENY",
            reasons: ["Transaction does not match the original envelope."],
          };
        }
        envelope = params.envelope as TransactionEnvelope;
      } else {
        const created = createTransactionEnvelope(params.request);
        if (!created.ok) {
          return {
            decision: "UNKNOWN",
            reasons: [created.reason],
          };
        }
        envelope = created.envelope;
      }

      if (params.witnessPublicKey) {
        if (!this.witnessPublicKey) {
          throw new ValidationError(
            "Cannot supply per-call witnessPublicKey: no witness trust anchor is configured on Web3UserEngine.",
          );
        }
        if (!areEd25519PublicKeysEqual(params.witnessPublicKey, this.witnessPublicKey)) {
          throw new ValidationError(
            "Supplied witnessPublicKey conflicts with configured engine witness trust anchor.",
          );
        }
      }
      if (params.witnessAdapter?.publicKeyPem) {
        if (!this.witnessPublicKey) {
          throw new ValidationError(
            "Cannot supply per-call witnessAdapter: no witness trust anchor is configured on Web3UserEngine.",
          );
        }
        if (!areEd25519PublicKeysEqual(params.witnessAdapter.publicKeyPem, this.witnessPublicKey)) {
          throw new ValidationError(
            "Supplied witnessAdapter public key conflicts with configured engine witness trust anchor.",
          );
        }
      }

      const witness = params.witnessAdapter ?? this.witnessAdapter;
      return await consumeSignedTransactionAuthorizationV3Async(
        this.store,
        params.artifact,
        envelope,
        params.request,
        witness
          ? {
              witnessAdapter: witness,
              witnessPublicKey: this.witnessPublicKey,
              idempotencyKey: params.idempotencyKey,
              leaseTtlSeconds: params.leaseTtlSeconds,
            }
          : undefined,
      );
    } catch (err) {
      this.handleError(err);
    }
  }

  /**
   * Cancel an issued authorization before it is consumed, preventing replay.
   * Returns true if cancelled, false if unknown, already consumed, or already cancelled.
   */
  public cancel(authorizationId: string): boolean {
    this.assertOpen();
    this.assertNotTainted();
    try {
      if (typeof authorizationId !== "string" || authorizationId.trim().length === 0) {
        throw new ValidationError("Authorization ID must be a non-empty string.");
      }
      if (authorizationId.trim().length > 128) {
        throw new ValidationError("Authorization ID exceeds maximum length of 128 characters.");
      }
      return cancelAuthorization(this.store, authorizationId);
    } catch (err) {
      this.handleError(err);
    }
  }

  /**
   * Retrieve the persisted authorization record by ID.
   */
  public getAuthorizationRecord(authorizationId: string): AuthorizationRecord | null {
    this.assertOpen();
    this.assertNotTainted();
    try {
      if (typeof authorizationId !== "string" || authorizationId.trim().length === 0) {
        throw new ValidationError("Authorization ID must be a non-empty string.");
      }
      return this.store.getAuthorizationRecord(authorizationId);
    } catch (err) {
      this.handleError(err);
    }
  }

  /**
   * Retrieves a verified, immutable witness receipt for a consumed authorization.
   * Returns null if the authorization does not exist, was not witnessed, is still
   * pending commit, is disputed, has corrupted JSON, or fails signature verification.
   *
   * @param authorizationId The authorization identifier to look up.
   * @param witnessPublicKey Optional public key override to verify the receipt signature.
   */
  public getWitnessReceipt(
    authorizationId: string,
    witnessPublicKey?: string | KeyObject,
  ): SignedWitnessReceipt | null {
    this.assertOpen();
    this.assertNotTainted();
    try {
      if (typeof authorizationId !== "string" || authorizationId.trim().length === 0) {
        throw new ValidationError("Authorization ID must be a non-empty string.");
      }
      if (witnessPublicKey) {
        if (!this.witnessPublicKey) {
          throw new ValidationError(
            "Cannot supply per-call witnessPublicKey: no witness trust anchor is configured on Web3UserEngine.",
          );
        }
        if (!areEd25519PublicKeysEqual(witnessPublicKey, this.witnessPublicKey)) {
          throw new ValidationError(
            "Supplied witnessPublicKey conflicts with configured engine witness trust anchor.",
          );
        }
      }
      if (!this.witnessPublicKey) {
        return null;
      }
      return this.store.getWitnessReceipt(authorizationId, this.witnessPublicKey);
    } catch (err) {
      this.handleError(err);
    }
  }

  /**
   * Lists unresolved witness records requiring reconciliation.
   * Delegates to the store's bounded discovery primitive with strict status and limit validation.
   *
   * @param options Filtering by status ('PENDING_COMMIT' | 'DISPUTED') and maximum records limit (1..1000).
   */
  public listUnreconciledAuthorizations(
    options?: ListUnreconciledWitnessRecordsOptions,
  ): ReadonlyArray<UnreconciledWitnessRecord> {
    this.assertOpen();
    this.assertNotTainted();
    try {
      const records = this.store.listUnreconciledWitnessRecords(options);
      return Object.freeze(records.slice());
    } catch (err) {
      this.handleError(err);
    }
  }

  /**
   * Reconciles a single consumed authorization record against the authoritative witness adapter.
   *
   * 1. Validates the authorization ID and options.
   * 2. Reads the local authorization record from SQLite.
   * 3. Returns ALREADY_COMMITTED for records with a verified persisted receipt.
   * 4. Queries the witness adapter for ticket status and receipt outside write transactions.
   * 5. Validates ticket ID, authorization ID, binding digest, policy, payload schema,
   *    and Ed25519 signature against the configured trust anchor.
   * 6. Atomically persists a valid receipt via store-level primitives (supporting PENDING_COMMIT and DISPUTED).
   * 7. Preserves PENDING_COMMIT or DISPUTED if the remote result is missing, ambiguous, unavailable, or malformed.
   * 8. Never releases a consumed ticket or overwrites a committed receipt.
   * 9. Is safe and idempotent across retries and concurrent callers.
   */
  public async reconcileAuthorization(
    authorizationId: string,
    options?: ReconcileAuthorizationOptions,
  ): Promise<ReconcileAuthorizationResult> {
    this.assertOpen();
    this.assertNotTainted();
    try {
      if (typeof authorizationId !== "string" || authorizationId.trim().length === 0) {
        throw new ValidationError("Authorization ID must be a non-empty string.");
      }
      if (authorizationId.trim().length > 128) {
        throw new ValidationError("Authorization ID exceeds maximum length of 128 characters.");
      }

      if (options !== undefined && options !== null) {
        if (typeof options !== "object") {
          throw new ValidationError("Reconcile options must be an object.");
        }
        if (options.witnessPublicKey) {
          if (!this.witnessPublicKey) {
            throw new ValidationError(
              "Cannot supply per-call witnessPublicKey: no witness trust anchor is configured on Web3UserEngine.",
            );
          }
          if (!areEd25519PublicKeysEqual(options.witnessPublicKey, this.witnessPublicKey)) {
            throw new ValidationError(
              "Supplied witnessPublicKey conflicts with configured engine witness trust anchor.",
            );
          }
        }
        if (options.witnessAdapter?.publicKeyPem) {
          if (!this.witnessPublicKey) {
            throw new ValidationError(
              "Cannot supply per-call witnessAdapter: no witness trust anchor is configured on Web3UserEngine.",
            );
          }
          if (!areEd25519PublicKeysEqual(options.witnessAdapter.publicKeyPem, this.witnessPublicKey)) {
            throw new ValidationError(
              "Supplied witnessAdapter public key conflicts with configured engine witness trust anchor.",
            );
          }
        }
      }

      const record = this.store.getAuthorizationRecord(authorizationId);
      if (!record) {
        return Object.freeze({
          authorizationId,
          outcome: "NOT_FOUND",
          reasons: [`Authorization '${authorizationId}' was not found.`],
        });
      }

      if (record.state !== "consumed") {
        return Object.freeze({
          authorizationId,
          outcome: "NOT_CONSUMED",
          reasons: [
            `Authorization '${authorizationId}' is in state '${record.state}', expected 'consumed'.`,
          ],
        });
      }

      if (record.witnessStatus === "NONE" || !record.witnessTicketId) {
        return Object.freeze({
          authorizationId,
          outcome: "NOT_WITNESSED",
          previousStatus: "NONE",
          currentStatus: "NONE",
          reasons: [`Authorization '${authorizationId}' was not witnessed.`],
        });
      }

      // Check if already COMMITTED
      if (record.witnessStatus === "COMMITTED") {
        const receipt = this.store.getWitnessReceipt(authorizationId);
        if (receipt) {
          return Object.freeze({
            authorizationId,
            outcome: "ALREADY_COMMITTED",
            previousStatus: "COMMITTED",
            currentStatus: "COMMITTED",
            ticketId: record.witnessTicketId,
            receipt,
            reasons: ["Authorization is already committed with a verified witness receipt."],
          });
        }

        // Receipt verification failed or corrupt in database
        this.store.markWitnessDisputed({
          authorizationId,
          ticketId: record.witnessTicketId,
          reason: "PERSISTED_RECEIPT_VERIFICATION_FAILED",
        });
        return Object.freeze({
          authorizationId,
          outcome: "DISPUTED",
          previousStatus: "COMMITTED",
          currentStatus: "DISPUTED",
          ticketId: record.witnessTicketId,
          reasons: [
            "Persisted receipt verification failed against configured engine trust anchor.",
          ],
        });
      }

      // Ensure configured trust anchor exists
      if (!this.witnessPublicKey) {
        return Object.freeze({
          authorizationId,
          outcome: "UNAVAILABLE",
          previousStatus: record.witnessStatus,
          currentStatus: record.witnessStatus,
          ticketId: record.witnessTicketId,
          reasons: ["No witness trust anchor is configured on Web3UserEngine."],
        });
      }

      const witness = options?.witnessAdapter ?? this.witnessAdapter;
      if (!witness) {
        return Object.freeze({
          authorizationId,
          outcome: "UNAVAILABLE",
          previousStatus: record.witnessStatus,
          currentStatus: record.witnessStatus,
          ticketId: record.witnessTicketId,
          reasons: ["No witness adapter is configured or provided for reconciliation."],
        });
      }

      // Query the authoritative witness adapter outside SQLite write transactions and mutexes
      let remoteRes: WitnessReconcileResult;
      try {
        remoteRes = await witness.reconcileTicket({
          ticketId: record.witnessTicketId,
          authorizationId,
        });
      } catch (err) {
        return Object.freeze({
          authorizationId,
          outcome: "UNAVAILABLE",
          previousStatus: record.witnessStatus,
          currentStatus: record.witnessStatus,
          ticketId: record.witnessTicketId,
          reasons: [
            `Witness adapter reconcile query failed: ${err instanceof Error ? err.message : String(err)}`,
          ],
        });
      }

      if (!remoteRes || typeof remoteRes !== "object") {
        return Object.freeze({
          authorizationId,
          outcome: "UNAVAILABLE",
          previousStatus: record.witnessStatus,
          currentStatus: record.witnessStatus,
          ticketId: record.witnessTicketId,
          reasons: ["Witness adapter returned an invalid response."],
        });
      }

      // If a signed receipt is provided, validate and persist it
      if (remoteRes.receipt) {
        const receipt = remoteRes.receipt;

        // Identity checks
        if (
          receipt.authorizationId !== authorizationId ||
          receipt.ticketId !== record.witnessTicketId ||
          (record.bindingDigest !== null && receipt.bindingDigest !== record.bindingDigest)
        ) {
          this.store.markWitnessDisputed({
            authorizationId,
            ticketId: record.witnessTicketId,
            reason: "RECONCILED_RECEIPT_IDENTITY_MISMATCH",
          });
          return Object.freeze({
            authorizationId,
            outcome: "DISPUTED",
            previousStatus: record.witnessStatus,
            currentStatus: "DISPUTED",
            ticketId: record.witnessTicketId,
            reasons: [
              "Reconciled receipt identity or binding digest does not match stored authorization record.",
            ],
          });
        }

        // Policy identity & revision structure
        if (
          typeof receipt.policyId !== "string" ||
          receipt.policyId.trim().length === 0 ||
          typeof receipt.policyRevision !== "number" ||
          !Number.isSafeInteger(receipt.policyRevision) ||
          receipt.policyRevision < 1
        ) {
          this.store.markWitnessDisputed({
            authorizationId,
            ticketId: record.witnessTicketId,
            reason: "RECONCILED_RECEIPT_INVALID_POLICY",
          });
          return Object.freeze({
            authorizationId,
            outcome: "DISPUTED",
            previousStatus: record.witnessStatus,
            currentStatus: "DISPUTED",
            ticketId: record.witnessTicketId,
            reasons: ["Reconciled receipt has invalid policy ID or revision."],
          });
        }

        // Canonical payload structure
        try {
          canonicalWitnessReceiptPayload(receipt);
        } catch {
          this.store.markWitnessDisputed({
            authorizationId,
            ticketId: record.witnessTicketId,
            reason: "RECONCILED_RECEIPT_PAYLOAD_INVALID",
          });
          return Object.freeze({
            authorizationId,
            outcome: "DISPUTED",
            previousStatus: record.witnessStatus,
            currentStatus: "DISPUTED",
            ticketId: record.witnessTicketId,
            reasons: ["Reconciled receipt payload structure is invalid."],
          });
        }

        // Cryptographic signature check against engine trust anchor
        if (!verifyWitnessReceipt(this.witnessPublicKey, receipt)) {
          this.store.markWitnessDisputed({
            authorizationId,
            ticketId: record.witnessTicketId,
            reason: "RECONCILED_RECEIPT_SIGNATURE_INVALID",
          });
          return Object.freeze({
            authorizationId,
            outcome: "DISPUTED",
            previousStatus: record.witnessStatus,
            currentStatus: "DISPUTED",
            ticketId: record.witnessTicketId,
            reasons: [
              "Reconciled receipt signature verification failed against configured engine trust anchor.",
            ],
          });
        }

        // Persist receipt atomically via store primitive
        const persistRes = this.store.persistWitnessReceipt({
          authorizationId,
          ticketId: record.witnessTicketId,
          receiptJson: JSON.stringify(receipt),
          allowDisputed: true,
        });

        if (persistRes.success) {
          if (persistRes.alreadyCommitted) {
            return Object.freeze({
              authorizationId,
              outcome: "ALREADY_COMMITTED",
              previousStatus: record.witnessStatus,
              currentStatus: "COMMITTED",
              ticketId: record.witnessTicketId,
              receipt,
              reasons: ["Receipt was already committed in store."],
            });
          }
          return Object.freeze({
            authorizationId,
            outcome: "RECONCILED",
            previousStatus: record.witnessStatus,
            currentStatus: "COMMITTED",
            ticketId: record.witnessTicketId,
            receipt,
          });
        }

        return Object.freeze({
          authorizationId,
          outcome: "DISPUTED",
          previousStatus: record.witnessStatus,
          currentStatus: "DISPUTED",
          ticketId: record.witnessTicketId,
          reasons: [`Persisting reconciled receipt failed: ${persistRes.reason}`],
        });
      }

      // No receipt provided in remote response
      if (remoteRes.state === "DISPUTED") {
        this.store.markWitnessDisputed({
          authorizationId,
          ticketId: record.witnessTicketId,
          reason: "REMOTE_WITNESS_DISPUTED",
        });
        return Object.freeze({
          authorizationId,
          outcome: "DISPUTED",
          previousStatus: record.witnessStatus,
          currentStatus: "DISPUTED",
          ticketId: record.witnessTicketId,
          reasons: remoteRes.reasons ?? ["Remote witness reported ticket is disputed."],
        });
      }

      if (remoteRes.state === "RELEASED") {
        this.store.markWitnessDisputed({
          authorizationId,
          ticketId: record.witnessTicketId,
          reason: "WITNESS_TICKET_PREMATURELY_RELEASED",
        });
        return Object.freeze({
          authorizationId,
          outcome: "DISPUTED",
          previousStatus: record.witnessStatus,
          currentStatus: "DISPUTED",
          ticketId: record.witnessTicketId,
          reasons: ["Remote witness ticket was released while authorization is marked consumed."],
        });
      }

      if (remoteRes.state === "COMMITTED") {
        // Ticket reported committed remotely, but receipt is missing.
        // Preserve existing status (PENDING_COMMIT or DISPUTED) pending receipt recovery.
        return Object.freeze({
          authorizationId,
          outcome: record.witnessStatus === "DISPUTED" ? "DISPUTED" : "PENDING",
          previousStatus: record.witnessStatus,
          currentStatus: record.witnessStatus,
          ticketId: record.witnessTicketId,
          reasons: [
            "Remote witness reported ticket COMMITTED, but receipt was not provided in response.",
          ],
        });
      }

      if (remoteRes.state === "RESERVED" || remoteRes.state === "QUARANTINED_UNCONFIRMED") {
        return Object.freeze({
          authorizationId,
          outcome: record.witnessStatus === "DISPUTED" ? "DISPUTED" : "PENDING",
          previousStatus: record.witnessStatus,
          currentStatus: record.witnessStatus,
          ticketId: record.witnessTicketId,
          reasons: [
            `Remote witness ticket is in state '${remoteRes.state}' and has not been committed.`,
          ],
        });
      }

      // Unknown or unhandled state
      return Object.freeze({
        authorizationId,
        outcome: record.witnessStatus === "DISPUTED" ? "DISPUTED" : "PENDING",
        previousStatus: record.witnessStatus,
        currentStatus: record.witnessStatus,
        ticketId: record.witnessTicketId,
        reasons: [`Remote witness reported unrecognized state '${remoteRes.state}'.`],
      });
    } catch (err) {
      this.handleError(err);
    }
  }

  /**
   * Bounded batch reconciliation of unresolved witness records.
   *
   * 1. Uses bounded discovery (`listUnreconciledAuthorizations`) with validated limit (1..1000).
   * 2. Deduplicates discovered authorization IDs while strictly preserving discovery order.
   * 3. Orchestrates execution using a bounded worker pool governed by concurrency limit (1..10, default: 4).
   * 4. Dispatches each item to the audited `reconcileAuthorization` method.
   * 5. Supports cancellation via AbortSignal and overall timeout via timeoutMs.
   * 6. Preserves deterministic result ordering matching discovery order.
   * 7. Returns an immutable aggregate result with per-authorization outcomes and summary counters.
   * 8. Isolates failures so that an individual worker/authorization failure does not abort or corrupt others.
   */
  public async reconcileAll(options?: ReconcileAllOptions): Promise<ReconcileAllResult> {
    this.assertOpen();
    this.assertNotTainted();
    try {
      if (options !== undefined && options !== null) {
        if (typeof options !== "object") {
          throw new ValidationError("ReconcileAll options must be an object.");
        }
        if (options.limit !== undefined) {
          if (
            typeof options.limit !== "number" ||
            !Number.isSafeInteger(options.limit) ||
            options.limit < 1 ||
            options.limit > 1000
          ) {
            throw new ValidationError("Limit must be a positive integer between 1 and 1000.");
          }
        }
        if (options.concurrency !== undefined) {
          if (
            typeof options.concurrency !== "number" ||
            !Number.isSafeInteger(options.concurrency) ||
            options.concurrency < 1 ||
            options.concurrency > 10
          ) {
            throw new ValidationError("Concurrency must be a positive integer between 1 and 10.");
          }
        }
        if (
          options.status !== undefined &&
          options.status !== "PENDING_COMMIT" &&
          options.status !== "DISPUTED"
        ) {
          throw new ValidationError("Invalid status filter: expected 'PENDING_COMMIT' or 'DISPUTED'.");
        }
        if (options.timeoutMs !== undefined) {
          if (
            typeof options.timeoutMs !== "number" ||
            !Number.isSafeInteger(options.timeoutMs) ||
            options.timeoutMs <= 0
          ) {
            throw new ValidationError("timeoutMs must be a positive safe integer.");
          }
        }
        if (options.signal !== undefined) {
          if (
            typeof options.signal !== "object" ||
            options.signal === null ||
            typeof options.signal.aborted !== "boolean"
          ) {
            throw new ValidationError("signal must be an instance of AbortSignal.");
          }
        }
        if (options.witnessPublicKey) {
          if (!this.witnessPublicKey) {
            throw new ValidationError(
              "Cannot supply per-call witnessPublicKey: no witness trust anchor is configured on Web3UserEngine.",
            );
          }
          if (!areEd25519PublicKeysEqual(options.witnessPublicKey, this.witnessPublicKey)) {
            throw new ValidationError(
              "Supplied witnessPublicKey conflicts with configured engine witness trust anchor.",
            );
          }
        }
        if (options.witnessAdapter?.publicKeyPem) {
          if (!this.witnessPublicKey) {
            throw new ValidationError(
              "Cannot supply per-call witnessAdapter: no witness trust anchor is configured on Web3UserEngine.",
            );
          }
          if (!areEd25519PublicKeysEqual(options.witnessAdapter.publicKeyPem, this.witnessPublicKey)) {
            throw new ValidationError(
              "Supplied witnessAdapter public key conflicts with configured engine witness trust anchor.",
            );
          }
        }
      }

      const limit = options?.limit ?? 100;
      const concurrency = options?.concurrency ?? 4;

      // 1. Discover unreconciled authorizations
      const discovered = this.listUnreconciledAuthorizations({
        status: options?.status,
        limit,
      });

      // 2. Deduplicate authorization IDs while strictly preserving discovery order
      const uniqueIds: string[] = [];
      const seen = new Set<string>();
      for (const item of discovered) {
        if (!seen.has(item.authorizationId)) {
          seen.add(item.authorizationId);
          uniqueIds.push(item.authorizationId);
        }
      }

      if (uniqueIds.length === 0) {
        const emptySummary: ReconcileAllSummary = Object.freeze({
          totalDiscovered: 0,
          totalProcessed: 0,
          reconciledCount: 0,
          alreadyCommittedCount: 0,
          pendingCount: 0,
          disputedCount: 0,
          unavailableCount: 0,
          errorCount: 0,
        });
        return Object.freeze({
          summary: emptySummary,
          results: Object.freeze([]),
          aborted: false,
        });
      }

      // 3. Setup cancellation and timeout controllers
      let isAborted = false;
      let abortReason: string | undefined;

      const abortHandler = () => {
        isAborted = true;
        abortReason = options?.signal?.reason
          ? String(options.signal.reason)
          : "Reconciliation aborted by signal.";
      };

      if (options?.signal) {
        if (options.signal.aborted) {
          isAborted = true;
          abortReason = options.signal.reason
            ? String(options.signal.reason)
            : "Reconciliation aborted by signal.";
        } else {
          options.signal.addEventListener("abort", abortHandler, { once: true });
        }
      }

      let timeoutTimer: NodeJS.Timeout | undefined;
      if (options?.timeoutMs !== undefined && !isAborted) {
        timeoutTimer = setTimeout(() => {
          isAborted = true;
          if (!abortReason) {
            abortReason = `Reconciliation batch timed out after ${options.timeoutMs}ms.`;
          }
        }, options.timeoutMs);
      }

      // 4. Bounded worker pool execution
      const results = new Array<ReconcileAuthorizationResult>(uniqueIds.length);
      let nextIndex = 0;

      const reconcileItem = async (index: number, authId: string): Promise<void> => {
        try {
          const res = await this.reconcileAuthorization(authId, {
            witnessAdapter: options?.witnessAdapter,
            witnessPublicKey: options?.witnessPublicKey,
          });
          results[index] = res;
        } catch (err) {
          results[index] = Object.freeze({
            authorizationId: authId,
            outcome: "UNAVAILABLE",
            reasons: [
              `Reconciliation worker encountered an error: ${err instanceof Error ? err.message : String(err)}`,
            ],
          });
        }
      };

      const workerCount = Math.min(concurrency, uniqueIds.length);
      const workers: Promise<void>[] = [];

      for (let w = 0; w < workerCount; w++) {
        workers.push(
          (async () => {
            while (true) {
              if (isAborted) {
                break;
              }
              const currentIndex = nextIndex++;
              if (currentIndex >= uniqueIds.length) {
                break;
              }
              await reconcileItem(currentIndex, uniqueIds[currentIndex]);
            }
          })(),
        );
      }

      await Promise.all(workers);

      // Clean up timer and listener
      if (timeoutTimer !== undefined) {
        clearTimeout(timeoutTimer);
      }
      if (options?.signal) {
        options.signal.removeEventListener("abort", abortHandler);
      }

      // 5. Fill any unstarted items due to abort
      for (let i = 0; i < uniqueIds.length; i++) {
        if (!results[i]) {
          results[i] = Object.freeze({
            authorizationId: uniqueIds[i],
            outcome: "UNAVAILABLE",
            reasons: [
              `Reconciliation aborted before execution: ${abortReason ?? "Batch cancelled."}`,
            ],
          });
        }
      }

      // 6. Aggregate summary counters
      let reconciledCount = 0;
      let alreadyCommittedCount = 0;
      let pendingCount = 0;
      let disputedCount = 0;
      let unavailableCount = 0;
      let errorCount = 0;

      for (const res of results) {
        switch (res.outcome) {
          case "RECONCILED":
            reconciledCount++;
            break;
          case "ALREADY_COMMITTED":
            alreadyCommittedCount++;
            break;
          case "PENDING":
            pendingCount++;
            break;
          case "DISPUTED":
            disputedCount++;
            break;
          case "UNAVAILABLE":
            unavailableCount++;
            break;
          default:
            errorCount++;
            break;
        }
      }

      const summary: ReconcileAllSummary = Object.freeze({
        totalDiscovered: uniqueIds.length,
        totalProcessed: results.length,
        reconciledCount,
        alreadyCommittedCount,
        pendingCount,
        disputedCount,
        unavailableCount,
        errorCount,
      });

      return Object.freeze({
        summary,
        results: Object.freeze(results),
        aborted: isAborted,
        ...(abortReason !== undefined ? { abortReason } : {}),
      });
    } catch (err) {
      this.handleError(err);
    }
  }

  // ==========================================================================
  // Governance: Policies Sub-Namespace
  // ==========================================================================

  public readonly policies = {
    register: (policy: DemoPolicy, initialRevision?: number): PolicyRecord => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getPolicyStore().registerPolicy(policy, initialRevision);
      } catch (err) {
        this.handleError(err);
      }
    },
    get: (policyId: string): PolicyRecord | null => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getPolicyStore().getPolicy(policyId);
      } catch (err) {
        this.handleError(err);
      }
    },
    getRevision: (policyId: string, revision: number): PolicyRevisionRecord | null => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getPolicyStore().getPolicyRevision(policyId, revision);
      } catch (err) {
        this.handleError(err);
      }
    },
    update: (policy: DemoPolicy, expectedCurrentRevision?: number): PolicyRecord => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getPolicyStore().updatePolicy(policy, expectedCurrentRevision);
      } catch (err) {
        this.handleError(err);
      }
    },
    revoke: (policyId: string, expectedCurrentRevision?: number): PolicyRecord => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getPolicyStore().revokePolicy(policyId, expectedCurrentRevision);
      } catch (err) {
        this.handleError(err);
      }
    },
    restore: (policyId: string, updatedPolicy?: DemoPolicy, expectedCurrentRevision?: number): PolicyRecord => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getPolicyStore().restorePolicy(policyId, updatedPolicy, expectedCurrentRevision);
      } catch (err) {
        this.handleError(err);
      }
    },
    retire: (policyId: string, expectedCurrentRevision?: number): PolicyRecord => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getPolicyStore().retirePolicy(policyId, expectedCurrentRevision);
      } catch (err) {
        this.handleError(err);
      }
    },
    delete: (policyId: string, expectedCurrentRevision?: number): boolean => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getPolicyStore().deletePolicy(policyId, expectedCurrentRevision);
      } catch (err) {
        this.handleError(err);
      }
    },
    list: (statusFilter?: PolicyStatus): PolicyRecord[] => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getPolicyStore().listPolicies(statusFilter);
      } catch (err) {
        this.handleError(err);
      }
    },
    listRevisions: (policyId: string): PolicyRevisionRecord[] => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getPolicyStore().listPolicyRevisions(policyId);
      } catch (err) {
        this.handleError(err);
      }
    },
    getBudgetStatus: (
      policyId: string,
      atSeconds?: number,
    ): {
      hasBudget: boolean;
      window?: BudgetWindowType;
      maxCumulativeAmount?: string;
      windowStart?: number;
      windowEnd?: number;
      spentAmount?: string;
      remainingAmount?: string;
    } | null => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        if (atSeconds !== undefined) {
          if (
            typeof atSeconds !== "number" ||
            !Number.isSafeInteger(atSeconds) ||
            atSeconds < 0
          ) {
            throw new Error(
              `effectiveNowSeconds must be a non-negative safe integer, received: ${atSeconds}`,
            );
          }
        }
        const policyRecord = this.store.getPolicyStore().getPolicy(policyId);
        if (!policyRecord) return null;
        const policy = policyRecord.policy;
        if (!policy.budget) {
          return { hasBudget: false };
        }
        const nowSec = atSeconds ?? this.store.getClock().nowSeconds();
        const windowStart = calculateBudgetWindowStart(nowSec, policy.budget.window);
        const windowEnd = calculateBudgetWindowEnd(nowSec, policy.budget.window);
        const accum = this.store.getPolicyBudgetAccumulator(policyId, policy.budget.window, windowStart);
        const spent = accum ? accum.spentAmount : "0";
        const maxBig = BigInt(policy.budget.maxCumulativeAmount);
        const spentBig = BigInt(spent);
        const remaining = maxBig >= spentBig ? (maxBig - spentBig).toString(10) : "0";

        return {
          hasBudget: true,
          window: policy.budget.window,
          maxCumulativeAmount: policy.budget.maxCumulativeAmount,
          windowStart,
          windowEnd,
          spentAmount: spent,
          remainingAmount: remaining,
        };
      } catch (err) {
        this.handleError(err);
      }
    },
  };

  // ==========================================================================
  // Governance: Issuer Keys Sub-Namespace
  // ==========================================================================

  public readonly keys = {
    generate: (): ReturnType<typeof generateIssuerKeyPair> => {
      return generateIssuerKeyPair();
    },
    register: (metadata: IssuerKeyMetadata): void => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        this.store.getKeyStore().registerKey(metadata);
      } catch (err) {
        this.handleError(err);
      }
    },
    get: (keyId: string): PersistedIssuerKeyMetadata | null => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getKeyStore().getKey(keyId);
      } catch (err) {
        this.handleError(err);
      }
    },
    getKeyStatus: (keyId: string): KeyStatus | null => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getKeyStore().getKeyStatus(keyId);
      } catch (err) {
        this.handleError(err);
      }
    },
    retire: (keyId: string, retiredAtSeconds?: number): PersistedIssuerKeyMetadata => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getKeyStore().retireKey(keyId, retiredAtSeconds);
      } catch (err) {
        this.handleError(err);
      }
    },
    revoke: (keyId: string, revokedAtSeconds?: number): PersistedIssuerKeyMetadata => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getKeyStore().revokeKey(keyId, revokedAtSeconds);
      } catch (err) {
        this.handleError(err);
      }
    },
    list: (statusFilter?: KeyStatus): PersistedIssuerKeyMetadata[] => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getKeyStore().listKeys(statusFilter);
      } catch (err) {
        this.handleError(err);
      }
    },
  };

  // ==========================================================================
  // Storage & Durability Sub-Namespace
  // ==========================================================================

  public readonly storage = {
    checkpoint: (mode?: CheckpointMode): CheckpointResult => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.checkpoint(mode);
      } catch (err) {
        this.handleError(err);
      }
    },
    checkIntegrity: (): boolean => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.checkIntegrity();
      } catch (err) {
        this.handleError(err);
      }
    },
    isTainted: (): boolean => {
      return this.store.isTainted();
    },
    getTaintedReason: (): string | undefined => {
      return this.store.getTaintedReason();
    },
    getHighWaterMark: (): number | null => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getHighWaterMark();
      } catch (err) {
        this.handleError(err);
      }
    },
    getSynchronousMode: (): SQLiteSynchronousMode => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getSynchronousMode();
      } catch (err) {
        this.handleError(err);
      }
    },
    getJournalMode: (): string => {
      this.assertOpen();
      this.assertNotTainted();
      try {
        return this.store.getJournalMode();
      } catch (err) {
        this.handleError(err);
      }
    },
  };

  // ==========================================================================
  // Lifecycle & Cleanup
  // ==========================================================================

  /**
   * Check whether the engine is open and operational.
   */
  public isOpen(): boolean {
    return !this.isClosed;
  }

  /**
   * Idempotently close the engine and release underlying SQLite connection and file handles.
   */
  public close(): void {
    if (!this.isClosed) {
      this.isClosed = true;
      try {
        this.store.close();
      } catch {}
    }
  }

  /**
   * TypeScript Symbol.dispose support for auto-cleanup with the 'using' keyword.
   */
  public [Symbol.dispose](): void {
    this.close();
  }

  /**
   * Access the underlying SQLiteAuthorizationStore instance.
   */
  public getStore(): SQLiteAuthorizationStore {
    this.assertOpen();
    return this.store;
  }

  private assertOpen(): void {
    if (this.isClosed) {
      throw new EngineClosedError();
    }
  }

  private assertNotTainted(): void {
    if (this.store.isTainted()) {
      throw new StoreTaintedError(
        `Web3UserEngine database connection is tainted and unusable: ${this.store.getTaintedReason() ?? "Uncertain commit outcome"}`,
      );
    }
  }

  private handleError(err: unknown): never {
    if (isFatalIOError(err) && !this.store.isTainted()) {
      const reason = `Fatal storage I/O error: ${err instanceof Error ? err.message : String(err)}`;
      this.store.markTainted(reason);
    }
    if (err instanceof StoreTaintedError) {
      throw err;
    }
    if (this.store.isTainted()) {
      const reason = this.store.getTaintedReason() ?? (err instanceof Error ? err.message : String(err));
      const options: ErrorOptions | undefined =
        err instanceof Error || (typeof err === "object" && err !== null)
          ? { cause: err }
          : undefined;
      throw new StoreTaintedError(
        `Web3UserEngine database connection is tainted and unusable: ${reason}`,
        options,
      );
    }
    throw wrapEngineError(err);
  }
}
