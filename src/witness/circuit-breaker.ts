/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Local Epoch Circuit Breaker
 *
 * Implements the operational taxonomy of the four failure regimes:
 * 1. Transient Concurrency Contention: Handled via bounded retry loops.
 * 2. Persistent Concurrency Contention: In-memory throttling per epoch (gRPC UNAVAILABLE + retry-after-ms).
 * 3. Database Connectivity / Infrastructure Failure: Fails closed locally without claiming durable freeze.
 * 4. Uncertain State / Partial Integrity Incident: Epoch quarantine and health probe trip.
 *
 * CRITICAL DISCIPLINE: A durable database freeze is strictly NEVER claimed until its
 * PostgreSQL transaction committing state = 'FROZEN' to witness_epochs returns success in WAL.
 */

export enum CircuitState {
  HEALTHY = "HEALTHY",
  CONTENTION_THROTTLED = "CONTENTION_THROTTLED",
  DATABASE_DOWN = "DATABASE_DOWN",
  INTEGRITY_QUARANTINED = "INTEGRITY_QUARANTINED",
}

export interface EpochCircuitStatus {
  state: CircuitState;
  reason?: string;
  trippedAt?: number;
  retryAfterMs?: number;
}

export class LocalEpochCircuitBreaker {
  private static instance: LocalEpochCircuitBreaker;
  private epochStates = new Map<string, EpochCircuitStatus>();
  private globalDbDown = false;
  private globalDbDownReason?: string;

  static getInstance(): LocalEpochCircuitBreaker {
    if (!LocalEpochCircuitBreaker.instance) {
      LocalEpochCircuitBreaker.instance = new LocalEpochCircuitBreaker();
    }
    return LocalEpochCircuitBreaker.instance;
  }

  // Clear all states (for testing)
  reset(): void {
    this.epochStates.clear();
    this.globalDbDown = false;
    this.globalDbDownReason = undefined;
  }

  // Check whether an epoch is permitted to accept mutating RPCs
  assertCanMutate(epochId: string): void {
    if (this.globalDbDown) {
      const err = new Error(
        `UNAVAILABLE: Database unreachable or connection pool exhausted (${this.globalDbDownReason || "INFRASTRUCTURE_FAILURE"})`,
      );
      (err as any).code = 14; // gRPC UNAVAILABLE
      throw err;
    }

    const status = this.epochStates.get(epochId);
    if (!status || status.state === CircuitState.HEALTHY) {
      return;
    }

    if (status.state === CircuitState.CONTENTION_THROTTLED) {
      const now = Date.now();
      const elapsed = now - (status.trippedAt || 0);
      const retryAfter = status.retryAfterMs || 500;
      if (elapsed < retryAfter) {
        const err = new Error(
          `UNAVAILABLE: High concurrency lock contention on epoch ${epochId}; transiently throttled`,
        );
        (err as any).code = 14; // gRPC UNAVAILABLE
        (err as any).retryAfterMs = retryAfter - elapsed;
        throw err;
      } else {
        // Cooldown elapsed, attempt half-open probe
        this.epochStates.set(epochId, { state: CircuitState.HEALTHY });
        return;
      }
    }

    if (status.state === CircuitState.INTEGRITY_QUARANTINED) {
      const err = new Error(
        `FAILED_PRECONDITION: Epoch ${epochId} is in integrity quarantine (${status.reason || "CATASTROPHIC_INTEGRITY_INCIDENT"})`,
      );
      (err as any).code = 9; // gRPC FAILED_PRECONDITION
      throw err;
    }
  }

  tripContention(epochId: string, retryAfterMs = 500): void {
    this.epochStates.set(epochId, {
      state: CircuitState.CONTENTION_THROTTLED,
      reason: "Persistent 55P03 lock contention retries exhausted",
      trippedAt: Date.now(),
      retryAfterMs,
    });
  }

  tripDatabaseDown(reason?: string): void {
    this.globalDbDown = true;
    this.globalDbDownReason = reason;
  }

  recoverDatabase(): void {
    this.globalDbDown = false;
    this.globalDbDownReason = undefined;
  }

  tripIntegrityIncident(epochId: string, reason: string): void {
    this.epochStates.set(epochId, {
      state: CircuitState.INTEGRITY_QUARANTINED,
      reason,
      trippedAt: Date.now(),
    });
  }

  getStatus(epochId: string): EpochCircuitStatus {
    if (this.globalDbDown) {
      return {
        state: CircuitState.DATABASE_DOWN,
        reason: this.globalDbDownReason,
      };
    }
    return this.epochStates.get(epochId) || { state: CircuitState.HEALTHY };
  }
}
