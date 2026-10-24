import type { KeyObject } from "node:crypto";
import {
  SQLiteAuthorizationStore,
  type SQLiteSynchronousMode,
  type CheckpointMode,
  type CheckpointResult,
  type AuthorizationRecord,
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
  cancelAuthorization,
  type V3Signer,
  type SignedTransactionAuthorizationV3,
} from "./authorization-lifecycle.js";
import {
  generateIssuerKeyPair,
  type SignedAuthorizationArtifactV3,
} from "./authorization-crypto.js";
import { type DemoPolicy } from "./policy.js";
import {
  createTransactionEnvelope,
  matchesTransactionEnvelope,
  type TransactionRequest,
  type TransactionEnvelope,
} from "./transaction-envelope.js";
import { isFatalIOError } from "./sqlite-transaction.js";
import type { TransactionAuthorization } from "./policy-transaction.js";
import type { Clock, MonotonicClock } from "./clock.js";

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
  private isClosed = false;

  public constructor(options: Web3UserEngineOptions) {
    if (!options || typeof options !== "object") {
      throw new ValidationError("Web3UserEngine options must be an object.");
    }
    if (typeof options.databasePath !== "string" || options.databasePath.trim().length === 0) {
      throw new ValidationError("databasePath must be a non-empty string.");
    }

    try {
      this.store = new SQLiteAuthorizationStore(options.databasePath, {
        clock: options.clock?.clock,
        monotonicClock: options.clock?.monotonicClock,
        maxStartupForwardGapSeconds: options.clock?.maxStartupForwardGapSeconds,
        synchronous: options.durability?.synchronous ?? "FULL",
        busyTimeoutMs: options.durability?.busyTimeoutMs ?? 5000,
        onFatalTaint: options.onFatalTaint,
        allowLegacyArtifactVersions: options.allowLegacyArtifactVersions ?? false,
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

      return consumeSignedTransactionAuthorizationV3(
        this.store,
        params.artifact,
        envelope,
        params.request,
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
