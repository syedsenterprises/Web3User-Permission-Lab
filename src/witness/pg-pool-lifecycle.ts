/**
 * Web3User Permission Lab - Witness PostgreSQL Pool Lifecycle & Error Governance
 *
 * Provides deterministic idle-client error handling, SQLSTATE classification,
 * safe diagnostic recording (free of credentials/connection strings),
 * verified connectivity recovery, and shutdown-safe listener lifecycle for
 * component-owned `pg.Pool` instances.
 */

import type pg from "pg";

export type PoolLifecycleState = "HEALTHY" | "DEGRADED" | "CLOSING" | "CLOSED";

export type PoolErrorClassification =
  | "ADMIN_SHUTDOWN"
  | "SERVER_UNAVAILABLE"
  | "CONNECTION_ERROR"
  | "UNEXPECTED_POOL_ERROR";

export interface PoolErrorDiagnostic {
  readonly component: string;
  readonly timestampMs: number;
  readonly code: string | null;
  readonly classification: PoolErrorClassification;
  readonly message: string;
  readonly duringShutdown: boolean;
}

export interface PoolHealthStatus {
  readonly ownPool: boolean;
  readonly state: PoolLifecycleState;
  readonly healthy: boolean;
  readonly closingOrClosed: boolean;
  readonly listenerAttached: boolean;
  readonly totalPoolErrors: number;
  readonly lastPoolError: PoolErrorDiagnostic | null;
}

export type PoolErrorCallback = (diagnostic: PoolErrorDiagnostic) => void;

const CONNECTION_ERROR_CODES = new Set([
  "08000",
  "08001",
  "08003",
  "08004",
  "08006",
  "08007",
  "08P01",
  "ECONNRESET",
  "ECONNREFUSED",
  "ETIMEDOUT",
  "EPIPE",
  "ENOTFOUND",
  "EHOSTUNREACH",
]);

/**
 * Classifies a PostgreSQL / Node socket error without inspecting sensitive payload data.
 */
export function classifyPgPoolError(err: unknown): {
  code: string | null;
  classification: PoolErrorClassification;
  message: string;
} {
  let code: string | null = null;
  let message = "Unknown PostgreSQL pool error";

  if (err && typeof err === "object") {
    if ("code" in err && typeof (err as { code?: unknown }).code === "string") {
      code = (err as { code: string }).code;
    }
    if ("message" in err && typeof (err as { message?: unknown }).message === "string") {
      message = (err as { message: string }).message;
    }
  } else if (typeof err === "string") {
    message = err;
  }

  let classification: PoolErrorClassification = "UNEXPECTED_POOL_ERROR";
  if (code === "57P01") {
    classification = "ADMIN_SHUTDOWN";
  } else if (code === "57P02" || code === "57P03") {
    classification = "SERVER_UNAVAILABLE";
  } else if (code !== null && CONNECTION_ERROR_CODES.has(code)) {
    classification = "CONNECTION_ERROR";
  }

  return { code, classification, message };
}

/**
 * Manages the `"error"` EventEmitter listener and health diagnostics for a
 * component-owned `pg.Pool`.
 *
 * Lifecycle states:
 * - `HEALTHY` -> `DEGRADED` on any idle-client error during normal operation.
 * - `DEGRADED` -> `HEALTHY` only via `markVerifiedHealthy(epochBefore)` after a
 *   verified PostgreSQL query completes without any newer idle error arriving.
 *   Note: A single verified query proves at least one connection is operational,
 *   not that every idle socket in the pool is error-free.
 * - `HEALTHY` | `DEGRADED` -> `CLOSING` -> `CLOSED` during disposal.
 *   For owned pools (`ownPool === true`), the shutdown-safe `"error"` listener
 *   remains attached through `CLOSED` because `pg-pool@3.14.0` resolves
 *   `pool.end()` before closing client sockets finish draining.
 * - Externally supplied pools (`ownPool === false`) are never mutated.
 */
export class ManagedPgPoolLifecycle {
  private readonly component: string;
  private readonly pool: pg.Pool;
  private readonly ownPool: boolean;
  private readonly onPoolError?: PoolErrorCallback;

  private state: PoolLifecycleState = "HEALTHY";
  private listenerAttached = false;
  private errorEpoch = 0;
  private totalPoolErrors = 0;
  private lastPoolError: PoolErrorDiagnostic | null = null;
  private readonly listener: (err: Error) => void;

  constructor(params: {
    component: string;
    pool: pg.Pool;
    ownPool: boolean;
    onPoolError?: PoolErrorCallback;
  }) {
    this.component = params.component;
    this.pool = params.pool;
    this.ownPool = params.ownPool;
    this.onPoolError = params.onPoolError;

    this.listener = (err: Error) => {
      this.handlePoolError(err);
    };

    if (this.ownPool) {
      this.attachOnce();
    }
  }

  private attachOnce(): void {
    if (!this.ownPool || this.listenerAttached) {
      return;
    }
    this.pool.on("error", this.listener);
    this.listenerAttached = true;
  }

  private handlePoolError(err: unknown): void {
    const { code, classification, message } = classifyPgPoolError(err);
    const duringShutdown = this.state === "CLOSING" || this.state === "CLOSED";
    const diagnostic: PoolErrorDiagnostic = {
      component: this.component,
      timestampMs: Date.now(),
      code,
      classification,
      message,
      duringShutdown,
    };

    this.errorEpoch += 1;
    this.totalPoolErrors += 1;
    this.lastPoolError = diagnostic;

    const isExpectedShutdownTermination = duringShutdown && code === "57P01";
    if (!isExpectedShutdownTermination) {
      if (!duringShutdown) {
        this.state = "DEGRADED";
      }
      console.error(
        JSON.stringify({
          event: "pg_pool_idle_error",
          component: diagnostic.component,
          code: diagnostic.code,
          classification: diagnostic.classification,
          duringShutdown: diagnostic.duringShutdown,
          message: diagnostic.message,
        })
      );
    }

    if (this.onPoolError) {
      try {
        this.onPoolError(diagnostic);
      } catch {
        // Never allow diagnostic observer errors to become uncaught EventEmitter exceptions
      }
    }
  }

  public getErrorEpoch(): number {
    return this.errorEpoch;
  }

  /**
   * Transitions `DEGRADED -> HEALTHY` only if no newer idle error occurred
   * since `observedErrorEpoch` was captured and the pool is not closing/closed.
   */
  public markVerifiedHealthy(observedErrorEpoch: number): boolean {
    if (this.state !== "DEGRADED") {
      return false;
    }
    if (this.errorEpoch !== observedErrorEpoch) {
      return false;
    }
    this.state = "HEALTHY";
    return true;
  }

  /**
   * Executes a lightweight `SELECT 1` probe against the pool and restores
   * `HEALTHY` state if the probe succeeds without concurrent idle errors.
   */
  public async verifyConnectivity(): Promise<PoolHealthStatus> {
    if (this.state === "CLOSING" || this.state === "CLOSED") {
      return this.getHealth();
    }
    const epochBefore = this.errorEpoch;
    await this.pool.query("SELECT 1");
    this.markVerifiedHealthy(epochBefore);
    return this.getHealth();
  }

  public markClosing(): void {
    if (this.state !== "CLOSED") {
      this.state = "CLOSING";
    }
  }

  public markClosed(): void {
    this.state = "CLOSED";
  }

  public getHealth(): PoolHealthStatus {
    const closingOrClosed = this.state === "CLOSING" || this.state === "CLOSED";
    return {
      ownPool: this.ownPool,
      state: this.state,
      healthy: this.state === "HEALTHY",
      closingOrClosed,
      listenerAttached: this.listenerAttached,
      totalPoolErrors: this.totalPoolErrors,
      lastPoolError: this.lastPoolError,
    };
  }
}
