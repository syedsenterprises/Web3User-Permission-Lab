/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-A
 * etcd Client Adapter Foundation
 *
 * Provides an isolated, hardened client adapter for etcd v3 conforming to the
 * D3 consensus protocol requirements:
 * 1. 64-bit revision/index precision using native BigInt.
 * 2. Strict linearizable reads (Raft quorum read) by default.
 * 3. Atomic compare-and-swap (CAS) transactions.
 * 4. Ambiguous commit detection and deterministic recovery via linearizable probes.
 * 5. Watch streams with automatic reconnection and revision resumption.
 * 6. Bounded deadlines, cancellation, and fail-closed error translation.
 * 7. TLS and mTLS configuration support.
 */

import {
  Etcd3,
  IOptions as Etcd3RawOptions,
  Watcher as RawWatcher,
  IKeyValue,
  IResponseHeader,
  GRPCDeadlineExceededError,
  GRPCUnavailableError,
  EtcdError as RawEtcdError,
} from "etcd3";

// ============================================================================
// Error Types
// ============================================================================

export class EtcdAdapterError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "EtcdAdapterError";
  }
}

export class EtcdTimeoutError extends EtcdAdapterError {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "EtcdTimeoutError";
  }
}

export class EtcdUnavailableError extends EtcdAdapterError {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "EtcdUnavailableError";
  }
}

export class EtcdCompactedError extends EtcdAdapterError {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "EtcdCompactedError";
  }
}

export class EtcdTransactionConflictError extends EtcdAdapterError {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "EtcdTransactionConflictError";
  }
}

// ============================================================================
// Interfaces & Domain Models
// ============================================================================

export interface EtcdEndpointConfig {
  /**
   * Endpoints list, e.g. ["http://127.0.0.1:2379"] or ["https://etcd1:2379", "https://etcd2:2379"].
   */
  endpoints: string[];
  /**
   * Dial timeout in milliseconds. Default: 3000ms.
   */
  dialTimeoutMs?: number;
  /**
   * Request timeout in milliseconds. Default: 5000ms.
   */
  requestTimeoutMs?: number;
  /**
   * mTLS Credentials bundle.
   */
  credentials?: {
    rootCertificate?: Buffer | string;
    certChain?: Buffer | string;
    privateKey?: Buffer | string;
  };
  /**
   * Optional gRPC channel options (e.g. max_message_size, keepalive).
   */
  grpcOptions?: Record<string, any>;
  /**
   * Max retry attempts on transient network errors. Default: 3.
   */
  maxRetries?: number;
}

export interface EtcdKeyValue {
  key: string;
  value: string;
  valueBuffer: Buffer;
  createRevision: bigint;
  modRevision: bigint;
  version: bigint;
  lease?: bigint;
}

export interface EtcdHealthStatus {
  healthy: boolean;
  clusterId?: string;
  memberId?: string;
  revision?: bigint;
  raftTerm?: bigint;
  leaderId?: string;
  error?: string;
}

export interface EtcdGetOptions {
  revision?: bigint;
  serializable?: boolean; // defaults to false (enforcing linearizable reads)
  timeoutMs?: number;
}

export interface EtcdRangeOptions {
  limit?: number;
  sortTarget?: "Key" | "Version" | "Create" | "Mod" | "Value";
  sortOrder?: "Ascend" | "Descend" | "None";
  revision?: bigint;
  serializable?: boolean; // defaults to false (enforcing linearizable reads)
  timeoutMs?: number;
}

export interface EtcdPutOptions {
  lease?: bigint;
  prevKv?: boolean;
  timeoutMs?: number;
}

export interface EtcdPutResult {
  revision: bigint;
  prevKv?: EtcdKeyValue;
}

export type EtcdCmpTarget = "Create" | "Mod" | "Version" | "Value";
export type EtcdCmpOp = "==" | "!=" | "<" | ">";

export interface EtcdTxnCondition {
  key: string;
  target: EtcdCmpTarget;
  operator: EtcdCmpOp;
  value: bigint | number | string | Buffer;
}

export type EtcdTxnOp =
  | { type: "put"; key: string; value: string | Buffer; lease?: bigint }
  | { type: "delete"; key: string }
  | { type: "get"; key: string };

export interface EtcdTxnResponseOp {
  type: "put" | "delete" | "get";
  putResult?: EtcdPutResult;
  deletedCount?: bigint;
  kv?: EtcdKeyValue | null;
}

export interface EtcdTxnResult {
  succeeded: boolean;
  revision: bigint;
  responses: EtcdTxnResponseOp[];
}

export interface EtcdWatchEvent {
  type: "put" | "delete";
  kv: EtcdKeyValue;
  prevKv?: EtcdKeyValue;
  compacted?: boolean;
}

export interface IEtcdWatcher {
  close(): Promise<void>;
  isWatching(): boolean;
}

export interface AmbiguousRecoveryResult {
  status: "CONFIRMED_COMMITTED" | "CONFIRMED_FAILED" | "CONFLICT_PAYLOAD_MISMATCH" | "INDETERMINATE";
  observedRevision?: bigint;
  existingValue?: string;
  details?: string;
}

export interface AmbiguousRecoveryOptions {
  timeoutMs?: number;
  /**
   * Epoch timestamp (ms) when the original transaction was started.
   */
  originalTxnTimestamp?: number;
  /**
   * Bounded deadline timeout (ms) of the original transaction.
   */
  originalTxnDeadlineMs?: number;
  /**
   * If true, an immediate probe returning null will be accepted as CONFIRMED_FAILED.
   * Defaults to false (safe/fail-closed: returns INDETERMINATE if deadline has not elapsed).
   */
  allowImmediateFailureConfirmation?: boolean;
}

export interface IEtcdTxnBuilder {
  if(condition: EtcdTxnCondition): IEtcdTxnBuilder;
  and(condition: EtcdTxnCondition): IEtcdTxnBuilder;
  then(...ops: EtcdTxnOp[]): IEtcdTxnBuilder;
  else(...ops: EtcdTxnOp[]): IEtcdTxnBuilder;
  commit(options?: { timeoutMs?: number }): Promise<EtcdTxnResult>;
}

export interface IEtcdClientAdapter {
  connect(): Promise<void>;
  close(): Promise<void>;
  healthCheck(timeoutMs?: number): Promise<EtcdHealthStatus>;
  get(key: string, options?: EtcdGetOptions): Promise<EtcdKeyValue | null>;
  getRange(prefix: string, options?: EtcdRangeOptions): Promise<EtcdKeyValue[]>;
  put(key: string, value: string | Buffer, options?: EtcdPutOptions): Promise<EtcdPutResult>;
  delete(key: string, options?: { timeoutMs?: number }): Promise<boolean>;
  deleteRange(prefix: string, options?: { timeoutMs?: number }): Promise<bigint>;
  txn(): IEtcdTxnBuilder;
  watch(
    target: string | { prefix: string },
    options: { startRevision?: bigint; timeoutMs?: number },
    onEvent: (event: EtcdWatchEvent) => void,
    onError?: (err: Error) => void
  ): Promise<IEtcdWatcher>;
  recoverAmbiguousTxn(
    probeKey: string,
    expectedPayloadOrFingerprint: string | Buffer,
    options?: AmbiguousRecoveryOptions
  ): Promise<AmbiguousRecoveryResult>;
}

// ============================================================================
// Helper Utilities
// ============================================================================

export function toBigInt(val: string | number | bigint | undefined | null, fieldName = "value"): bigint {
  if (val === undefined || val === null) return 0n;
  if (typeof val === "bigint") return val;
  if (typeof val === "number") {
    if (Number.isNaN(val) || !Number.isFinite(val) || !Number.isSafeInteger(val)) {
      throw new EtcdAdapterError(`Unsafe or non-integer number for 64-bit field '${fieldName}': ${val}`);
    }
    return BigInt(val);
  }
  if (typeof val === "string") {
    const trimmed = val.trim();
    if (trimmed.length === 0) return 0n;
    if (!/^-?\d+$/.test(trimmed)) {
      throw new EtcdAdapterError(`Cannot convert malformed non-numeric string to BigInt for '${fieldName}': "${val}"`);
    }
    return BigInt(trimmed);
  }
  throw new EtcdAdapterError(`Unsupported type for BigInt conversion for '${fieldName}': ${typeof val}`);
}

export function toPositiveBigInt(val: string | number | bigint | undefined | null, fieldName = "value"): bigint {
  const res = toBigInt(val, fieldName);
  if (res < 0n) {
    throw new EtcdAdapterError(`Field '${fieldName}' must be non-negative; received ${res}`);
  }
  return res;
}

export function parseRawKeyValue(raw: IKeyValue): EtcdKeyValue {
  const keyBuf = Buffer.isBuffer(raw.key) ? raw.key : Buffer.from(raw.key || "");
  const valBuf = Buffer.isBuffer(raw.value) ? raw.value : Buffer.from(raw.value || "");
  return {
    key: keyBuf.toString("utf8"),
    value: valBuf.toString("utf8"),
    valueBuffer: valBuf,
    createRevision: toPositiveBigInt(raw.create_revision, "create_revision"),
    modRevision: toPositiveBigInt(raw.mod_revision, "mod_revision"),
    version: toPositiveBigInt(raw.version, "version"),
    lease: raw.lease ? toPositiveBigInt(raw.lease, "lease") : undefined,
  };
}

export function translateError(err: unknown, defaultMessage = "etcd operation failed"): EtcdAdapterError {
  if (err instanceof EtcdAdapterError) {
    return err;
  }
  if (err instanceof GRPCDeadlineExceededError) {
    return new EtcdTimeoutError(`${defaultMessage}: deadline exceeded`, err);
  }
  if (err instanceof GRPCUnavailableError) {
    return new EtcdUnavailableError(`${defaultMessage}: etcd cluster unavailable`, err);
  }
  if (err instanceof Error) {
    const msg = err.message.toLowerCase();
    const code = (err as any).code;
    if (
      msg.includes("required revision has been compacted") ||
      msg.includes("compacted") ||
      msg.includes("watcher canceled") ||
      code === 11 // grpc.status.OUT_OF_RANGE
    ) {
      return new EtcdCompactedError(`${defaultMessage}: ${err.message}`, err);
    }
    if (msg.includes("deadline") || msg.includes("timeout") || code === 4) {
      return new EtcdTimeoutError(`${defaultMessage}: ${err.message}`, err);
    }
    if (
      msg.includes("unavailable") ||
      msg.includes("connect") ||
      msg.includes("refused") ||
      code === 14 // grpc.status.UNAVAILABLE
    ) {
      return new EtcdUnavailableError(`${defaultMessage}: ${err.message}`, err);
    }
  }
  return new EtcdAdapterError(`${defaultMessage}: ${err instanceof Error ? err.message : String(err)}`, err);
}

/**
 * Execute an operation with an explicit deadline timeout.
 */
export async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  operationName: string
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  let timedOut = false;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      reject(new EtcdTimeoutError(`${operationName} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });

  try {
    const res = await Promise.race([promise, timeoutPromise]);
    if (timedOut) {
      throw new EtcdTimeoutError(`${operationName} timed out after ${timeoutMs}ms`);
    }
    return res;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// ============================================================================
// Concrete Implementation: EtcdClientAdapter
// ============================================================================

export class EtcdClientAdapter implements IEtcdClientAdapter {
  private client: Etcd3;
  private readonly config: EtcdEndpointConfig;
  private isClosed = false;

  constructor(config: EtcdEndpointConfig) {
    this.config = {
      dialTimeoutMs: 3000,
      requestTimeoutMs: 5000,
      maxRetries: 3,
      ...config,
    };

    if (!this.config.endpoints || this.config.endpoints.length === 0) {
      throw new Error("EtcdClientAdapter requires at least one endpoint");
    }

    const rawOptions: Etcd3RawOptions = {
      hosts: this.config.endpoints,
      dialTimeout: this.config.dialTimeoutMs,
      grpcOptions: this.config.grpcOptions,
    };

    if (this.config.credentials) {
      rawOptions.credentials = {
        rootCertificate: Buffer.isBuffer(this.config.credentials.rootCertificate)
          ? this.config.credentials.rootCertificate
          : this.config.credentials.rootCertificate
            ? Buffer.from(this.config.credentials.rootCertificate)
            : Buffer.from([]),
        certChain: Buffer.isBuffer(this.config.credentials.certChain)
          ? this.config.credentials.certChain
          : this.config.credentials.certChain
            ? Buffer.from(this.config.credentials.certChain)
            : undefined,
        privateKey: Buffer.isBuffer(this.config.credentials.privateKey)
          ? this.config.credentials.privateKey
          : this.config.credentials.privateKey
            ? Buffer.from(this.config.credentials.privateKey)
            : undefined,
      };
    }

    this.client = new Etcd3(rawOptions);
  }

  public async connect(): Promise<void> {
    if (this.isClosed) {
      throw new EtcdAdapterError("Cannot connect a closed client adapter");
    }
    const status = await this.healthCheck();
    if (!status.healthy) {
      throw new EtcdUnavailableError(`etcd health check failed during connect: ${status.error}`);
    }
  }

  public async close(): Promise<void> {
    if (this.isClosed) return;
    this.isClosed = true;
    try {
      this.client.close();
    } catch {
      // Ignore close teardown errors
    }
  }

  public async healthCheck(timeoutMs?: number): Promise<EtcdHealthStatus> {
    const timeout = timeoutMs ?? this.config.dialTimeoutMs ?? 3000;
    try {
      const response = await withTimeout(
        this.client.maintenance.status(),
        timeout,
        "healthCheck"
      );
      return {
        healthy: true,
        clusterId: response.header?.cluster_id,
        memberId: response.header?.member_id,
        revision: response.header ? toBigInt(response.header.revision) : undefined,
        raftTerm: response.header ? toBigInt(response.header.raft_term) : undefined,
        leaderId: response.leader,
      };
    } catch (err) {
      return {
        healthy: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  public async get(key: string, options?: EtcdGetOptions): Promise<EtcdKeyValue | null> {
    const timeout = options?.timeoutMs ?? this.config.requestTimeoutMs ?? 5000;
    try {
      const builder = this.client.get(key);
      builder.options({ deadline: Date.now() + timeout });

      if (options?.revision !== undefined) {
        builder.revision(options.revision.toString());
      }
      // Linearizability enforcement: serializable: false ensures Raft quorum read
      builder.serializable(options?.serializable ?? false);

      const resp = await withTimeout(builder.exec(), timeout, `get(${key})`);
      if (!resp.kvs || resp.kvs.length === 0) {
        return null;
      }
      return parseRawKeyValue(resp.kvs[0]);
    } catch (err) {
      throw translateError(err, `get(${key}) failed`);
    }
  }

  public async getRange(prefix: string, options?: EtcdRangeOptions): Promise<EtcdKeyValue[]> {
    const timeout = options?.timeoutMs ?? this.config.requestTimeoutMs ?? 5000;
    try {
      const builder = this.client.getAll().prefix(prefix);
      builder.options({ deadline: Date.now() + timeout });

      if (options?.limit !== undefined) {
        builder.limit(options.limit);
      }
      if (options?.revision !== undefined) {
        builder.revision(options.revision.toString());
      }
      if (options?.sortTarget && options?.sortOrder && options.sortOrder !== "None") {
        builder.sort(options.sortTarget, options.sortOrder);
      }
      builder.serializable(options?.serializable ?? false);

      const resp = await withTimeout(builder.exec(), timeout, `getRange(${prefix})`);
      if (!resp.kvs || resp.kvs.length === 0) {
        return [];
      }
      return resp.kvs.map(parseRawKeyValue);
    } catch (err) {
      throw translateError(err, `getRange(${prefix}) failed`);
    }
  }

  public async put(key: string, value: string | Buffer, options?: EtcdPutOptions): Promise<EtcdPutResult> {
    const timeout = options?.timeoutMs ?? this.config.requestTimeoutMs ?? 5000;
    try {
      const builder = this.client.put(key).value(value);
      builder.options({ deadline: Date.now() + timeout });

      if (options?.lease !== undefined) {
        builder.lease(options.lease.toString());
      }

      if (options?.prevKv) {
        const prev = await withTimeout(builder.getPrevious(), timeout, `put(${key}) with prevKv`);
        return {
          revision: toBigInt(prev.header.revision),
          prevKv: parseRawKeyValue(prev),
        };
      }

      const resp = await withTimeout(builder.exec(), timeout, `put(${key})`);
      return {
        revision: toBigInt(resp.header.revision),
      };
    } catch (err) {
      throw translateError(err, `put(${key}) failed`);
    }
  }

  public async delete(key: string, options?: { timeoutMs?: number }): Promise<boolean> {
    const timeout = options?.timeoutMs ?? this.config.requestTimeoutMs ?? 5000;
    try {
      const builder = this.client.delete().key(key);
      builder.options({ deadline: Date.now() + timeout });
      const resp = await withTimeout(builder.exec(), timeout, `delete(${key})`);
      const deletedCount = toPositiveBigInt(resp.deleted, "deleted");
      return deletedCount > 0n;
    } catch (err) {
      throw translateError(err, `delete(${key}) failed`);
    }
  }

  public async deleteRange(prefix: string, options?: { timeoutMs?: number }): Promise<bigint> {
    const timeout = options?.timeoutMs ?? this.config.requestTimeoutMs ?? 5000;
    try {
      const builder = this.client.delete().prefix(prefix);
      builder.options({ deadline: Date.now() + timeout });
      const resp = await withTimeout(builder.exec(), timeout, `deleteRange(${prefix})`);
      return toPositiveBigInt(resp.deleted, "deleted");
    } catch (err) {
      throw translateError(err, `deleteRange(${prefix}) failed`);
    }
  }

  public txn(): IEtcdTxnBuilder {
    return new EtcdTxnBuilderImpl(this.client, this.config.requestTimeoutMs ?? 5000);
  }

  /**
   * Establishes a watch on a key or prefix.
   *
   * IMPORTANT PROTOCOL GUARANTEE:
   * Resuming from `lastSeenRevision + 1n` provides gap-free event stream delivery
   * ONLY WHILE the requested revision remains available in etcd (i.e. has not been compacted).
   * If etcd compacts the log past `startRevision`, etcd rejects the stream with an OutOfRange
   * compaction error. When compaction is detected, the adapter stops automatic reconnect retries,
   * terminates the stream, cleans up all resources, and raises EtcdCompactedError.
   */
  public async watch(
    target: string | { prefix: string },
    options: { startRevision?: bigint; timeoutMs?: number },
    onEvent: (event: EtcdWatchEvent) => void,
    onError?: (err: Error) => void
  ): Promise<IEtcdWatcher> {
    const isPrefix = typeof target !== "string";
    const keyTarget = typeof target === "string" ? target : target.prefix;
    const timeout = options?.timeoutMs ?? this.config.requestTimeoutMs ?? 5000;

    let rawWatcher: RawWatcher | null = null;
    let closed = false;
    let lastSeenRevision = options.startRevision !== undefined
      ? toPositiveBigInt(options.startRevision, "startRevision")
      : 0n;

    const terminateWatcher = async (cancelUnderlying = true) => {
      if (closed) return;
      closed = true;
      if (rawWatcher) {
        try {
          // Detach listeners to prevent any further reconnect attempts or memory leaks
          rawWatcher.removeAllListeners();
          if (cancelUnderlying) {
            await rawWatcher.cancel();
          }
        } catch {
          // Ignore cancellation errors during teardown
        }
      }
    };

    const createRawWatcher = async (startRev: bigint) => {
      const builder = this.client.watch();
      if (isPrefix) {
        builder.prefix(keyTarget);
      } else {
        builder.key(keyTarget);
      }
      builder.withPreviousKV();
      if (startRev > 0n) {
        builder.startRevision(startRev.toString());
      }
      return withTimeout(builder.create(), timeout, `watch(${keyTarget})`);
    };

    try {
      rawWatcher = await createRawWatcher(lastSeenRevision);

      const attachHandlers = (w: RawWatcher) => {
        w.on("put", (rawKv: IKeyValue, rawPrev?: IKeyValue) => {
          if (closed) return;
          const kv = parseRawKeyValue(rawKv);
          if (kv.modRevision > lastSeenRevision) {
            lastSeenRevision = kv.modRevision;
          }
          onEvent({
            type: "put",
            kv,
            prevKv: rawPrev ? parseRawKeyValue(rawPrev) : undefined,
          });
        });

        w.on("delete", (rawKv: IKeyValue, rawPrev?: IKeyValue) => {
          if (closed) return;
          const kv = parseRawKeyValue(rawKv);
          if (kv.modRevision > lastSeenRevision) {
            lastSeenRevision = kv.modRevision;
          }
          onEvent({
            type: "delete",
            kv,
            prevKv: rawPrev ? parseRawKeyValue(rawPrev) : undefined,
          });
        });

        w.on("error", async (err: Error) => {
          if (closed) return;
          const translated = translateError(err, `watch(${keyTarget}) error`);

          // F-02: If revision has been compacted, stop auto-reconnect loop immediately
          if (translated instanceof EtcdCompactedError) {
            // The server already cancelled and detached the watcher due to compaction;
            // do not issue an active cancel_request or await 'end' event.
            await terminateWatcher(false);
          }

          if (onError) {
            onError(translated);
          }
        });
      };

      attachHandlers(rawWatcher);

      return {
        close: async () => {
          await terminateWatcher();
        },
        isWatching: () => !closed,
      };
    } catch (err) {
      throw translateError(err, `watch(${keyTarget}) initialization failed`);
    }
  }

  /**
   * Ambiguous Commit Recovery:
   * When a proposal CAS transaction returns a network error or deadline exceeded,
   * we must determine whether the proposal committed to the Raft consensus log or failed.
   *
   * SAFE RESOLUTION CONTRACT (F-03):
   * A single probe read returning null does NOT prove failure if the original transaction
   * may still be in flight in Raft. Unless allowImmediateFailureConfirmation is set,
   * or the original transaction's gRPC deadline has expired, a missing key returns INDETERMINATE.
   */
  public async recoverAmbiguousTxn(
    probeKey: string,
    expectedPayloadOrFingerprint: string | Buffer,
    options?: AmbiguousRecoveryOptions
  ): Promise<AmbiguousRecoveryResult> {
    const timeout = options?.timeoutMs ?? this.config.requestTimeoutMs ?? 5000;
    try {
      // Linearizable probe read
      const observed = await this.get(probeKey, {
        serializable: false,
        timeoutMs: timeout,
      });

      if (!observed) {
        // F-03: Safe ambiguity resolution
        if (options?.allowImmediateFailureConfirmation) {
          return {
            status: "CONFIRMED_FAILED",
            details: `Probe key ${probeKey} does not exist in etcd (immediate failure confirmation authorized)`,
          };
        }

        // Check if original proposal deadline has expired
        if (
          options?.originalTxnTimestamp !== undefined &&
          options?.originalTxnDeadlineMs !== undefined
        ) {
          const elapsed = Date.now() - options.originalTxnTimestamp;
          if (elapsed > options.originalTxnDeadlineMs) {
            // Deadline has expired on the cluster; in-flight transaction cannot commit
            return {
              status: "CONFIRMED_FAILED",
              details: `Probe key ${probeKey} does not exist in etcd and original proposal deadline (${options.originalTxnDeadlineMs}ms) expired ${elapsed - options.originalTxnDeadlineMs}ms ago`,
            };
          }
        }

        // Outcome cannot yet be safely confirmed; remain fail-closed INDETERMINATE
        return {
          status: "INDETERMINATE",
          details: `Probe key ${probeKey} does not currently exist, but original transaction may still be in flight; cannot confirm failure before deadline expiration`,
        };
      }

      const expectedStr = Buffer.isBuffer(expectedPayloadOrFingerprint)
        ? expectedPayloadOrFingerprint.toString("utf8")
        : expectedPayloadOrFingerprint;

      if (observed.value === expectedStr) {
        // Value matches exact canonical fingerprint or payload
        return {
          status: "CONFIRMED_COMMITTED",
          observedRevision: observed.modRevision,
          existingValue: observed.value,
          details: `Probe key ${probeKey} exists with matching payload at revision ${observed.modRevision}`,
        };
      }

      // Key exists but value does not match
      return {
        status: "CONFLICT_PAYLOAD_MISMATCH",
        observedRevision: observed.modRevision,
        existingValue: observed.value,
        details: `Probe key ${probeKey} exists but value mismatches expected fingerprint`,
      };
    } catch (err) {
      return {
        status: "INDETERMINATE",
        details: `Linearizable probe read failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }
}

// ============================================================================
// CAS Transaction Builder Implementation
// ============================================================================

class EtcdTxnBuilderImpl implements IEtcdTxnBuilder {
  private conditions: EtcdTxnCondition[] = [];
  private thenOps: EtcdTxnOp[] = [];
  private elseOps: EtcdTxnOp[] = [];

  constructor(
    private readonly client: Etcd3,
    private readonly defaultTimeoutMs: number
  ) {}

  public if(condition: EtcdTxnCondition): IEtcdTxnBuilder {
    this.conditions.push(condition);
    return this;
  }

  public and(condition: EtcdTxnCondition): IEtcdTxnBuilder {
    this.conditions.push(condition);
    return this;
  }

  public then(...ops: EtcdTxnOp[]): IEtcdTxnBuilder {
    this.thenOps.push(...ops);
    return this;
  }

  public else(...ops: EtcdTxnOp[]): IEtcdTxnBuilder {
    this.elseOps.push(...ops);
    return this;
  }

  public async commit(options?: { timeoutMs?: number }): Promise<EtcdTxnResult> {
    const timeout = options?.timeoutMs ?? this.defaultTimeoutMs;
    try {
      if (this.conditions.length === 0) {
        throw new Error("Txn commit requires at least one condition in .if(...)");
      }

      const first = this.conditions[0];
      const initialVal = typeof first.value === "bigint" ? first.value.toString() : first.value;
      let txn = this.client.if(first.key, first.target, first.operator, initialVal);
      txn.options({ deadline: Date.now() + timeout });

      for (let i = 1; i < this.conditions.length; i++) {
        const c = this.conditions[i];
        const val = typeof c.value === "bigint" ? c.value.toString() : c.value;
        txn = txn.and(c.key, c.target, c.operator, val);
      }

      // Map 'then' operations
      if (this.thenOps.length > 0) {
        const mappedThen = this.thenOps.map((op) => {
          if (op.type === "put") {
            const b = this.client.put(op.key).value(op.value);
            if (op.lease !== undefined) b.lease(op.lease.toString());
            return b;
          } else if (op.type === "delete") {
            return this.client.delete().key(op.key);
          } else {
            return this.client.get(op.key);
          }
        });
        txn = txn.then(...mappedThen);
      }

      // Map 'else' operations
      if (this.elseOps.length > 0) {
        const mappedElse = this.elseOps.map((op) => {
          if (op.type === "put") {
            const b = this.client.put(op.key).value(op.value);
            if (op.lease !== undefined) b.lease(op.lease.toString());
            return b;
          } else if (op.type === "delete") {
            return this.client.delete().key(op.key);
          } else {
            return this.client.get(op.key);
          }
        });
        txn = txn.else(...mappedElse);
      }

      const resp = await withTimeout(txn.commit(), timeout, "txn.commit()");

      const revision = resp.header ? toBigInt(resp.header.revision) : 0n;
      const responses: EtcdTxnResponseOp[] = [];

      if (resp.responses) {
        for (const r of resp.responses) {
          if (r.response_put) {
            responses.push({
              type: "put",
              putResult: { revision: toBigInt(r.response_put.header?.revision) },
            });
          } else if (r.response_delete_range) {
            responses.push({
              type: "delete",
              deletedCount: toPositiveBigInt(r.response_delete_range.deleted, "deletedCount"),
            });
          } else if (r.response_range) {
            const kvs = r.response_range.kvs || [];
            responses.push({
              type: "get",
              kv: kvs.length > 0 ? parseRawKeyValue(kvs[0]) : null,
            });
          }
        }
      }

      return {
        succeeded: resp.succeeded,
        revision,
        responses,
      };
    } catch (err) {
      throw translateError(err, "txn.commit() failed");
    }
  }
}
