/**
 * Authoritative Clock abstraction for Web3User Permission Lab.
 *
 * Trust boundary:
 * The clock provides the Unix timestamp in seconds used for policy evaluation,
 * key validity checks, and artifact issuance timestamping.
 * In production, SystemClock reads the host operating system's wall clock.
 * Persisted high-water mark checks detect backward clock steps (rollbacks),
 * but cannot prevent forward clock manipulation by a compromised host.
 */

export interface Clock {
  /**
   * Returns the current Unix timestamp in whole seconds.
   */
  nowSeconds(): number;
}

export interface MonotonicClock {
  /**
   * Returns the current continuous monotonic time in nanoseconds.
   */
  nowNanoseconds(): bigint;
}

export class SystemClock implements Clock {
  nowSeconds(): number {
    return Math.floor(Date.now() / 1000);
  }
}

export class SystemMonotonicClock implements MonotonicClock {
  nowNanoseconds(): bigint {
    return process.hrtime.bigint();
  }
}

export const systemClock: Clock = new SystemClock();
export const systemMonotonicClock: MonotonicClock = new SystemMonotonicClock();

export class TestMonotonicClock implements MonotonicClock {
  private currentNanos: bigint;

  constructor(initialNanos: bigint = 0n) {
    if (initialNanos < 0n) {
      throw new Error("Initial nanoseconds must be a non-negative bigint.");
    }
    this.currentNanos = initialNanos;
  }

  set(nanos: bigint): void {
    if (nanos < 0n) {
      throw new Error("Nanoseconds must be a non-negative bigint.");
    }
    this.currentNanos = nanos;
  }

  advanceSeconds(seconds: number): void {
    if (!Number.isSafeInteger(seconds) || seconds < 0) {
      throw new Error("Advance duration must be a non-negative safe integer.");
    }
    this.currentNanos += BigInt(seconds) * 1_000_000_000n;
  }

  advanceNanos(nanos: bigint): void {
    if (nanos < 0n) {
      throw new Error("Advance nanoseconds must be non-negative.");
    }
    this.currentNanos += nanos;
  }

  nowNanoseconds(): bigint {
    return this.currentNanos;
  }
}

export class TestClock implements Clock, MonotonicClock {
  private currentSeconds: number;
  private currentMonotonicNanos: bigint;

  constructor(initialSeconds: number = 0, initialMonotonicNanos?: bigint) {
    if (!Number.isSafeInteger(initialSeconds) || initialSeconds < 0) {
      throw new Error("Initial seconds must be a non-negative safe integer.");
    }
    this.currentSeconds = initialSeconds;
    this.currentMonotonicNanos =
      initialMonotonicNanos !== undefined && initialMonotonicNanos >= 0n
        ? initialMonotonicNanos
        : BigInt(initialSeconds) * 1_000_000_000n;
  }

  set(seconds: number): void {
    if (!Number.isSafeInteger(seconds) || seconds < 0) {
      throw new Error("Seconds must be a non-negative safe integer.");
    }
    this.currentSeconds = seconds;
    this.currentMonotonicNanos = BigInt(seconds) * 1_000_000_000n;
  }

  advance(seconds: number): void {
    if (!Number.isSafeInteger(seconds) || seconds < 0) {
      throw new Error("Advance duration must be a non-negative safe integer.");
    }
    this.currentSeconds += seconds;
    this.currentMonotonicNanos += BigInt(seconds) * 1_000_000_000n;
  }

  advanceWallSeconds(seconds: number): void {
    if (!Number.isSafeInteger(seconds)) {
      throw new Error("Seconds must be a safe integer.");
    }
    if (this.currentSeconds + seconds < 0) {
      throw new Error("Resulting seconds must be non-negative.");
    }
    this.currentSeconds += seconds;
  }

  advanceMonotonicSeconds(seconds: number): void {
    if (!Number.isSafeInteger(seconds) || seconds < 0) {
      throw new Error("Advance duration must be a non-negative safe integer.");
    }
    this.currentMonotonicNanos += BigInt(seconds) * 1_000_000_000n;
  }

  advanceMonotonicNanos(nanos: bigint): void {
    if (nanos < 0n) {
      throw new Error("Advance nanoseconds must be non-negative.");
    }
    this.currentMonotonicNanos += nanos;
  }

  setMonotonicNanos(nanos: bigint): void {
    if (nanos < 0n) {
      throw new Error("Nanoseconds must be a non-negative bigint.");
    }
    this.currentMonotonicNanos = nanos;
  }

  nowSeconds(): number {
    return this.currentSeconds;
  }

  nowNanoseconds(): bigint {
    return this.currentMonotonicNanos;
  }
}

export const MAX_STARTUP_FORWARD_GAP_SECONDS = 3600;
export const MAX_FORWARD_STEP_SECONDS = 10;
export const MAX_BACKWARD_STEP_SECONDS = 5;
export const MAX_ABSOLUTE_DIVERGENCE_SECONDS = 60;
export const MAX_ANCHOR_LIFETIME_SECONDS = 86400; // 24 hours

export interface ClockCandidate {
  wallSeconds: number;
  monotonicNanos: bigint;
}

export interface ClockCandidateEvaluation {
  decision: "ALLOW" | "DENY";
  reason?: string;
}

export interface ClockGuardOptions {
  maxStartupForwardGapSeconds?: number;
  maxForwardStepSeconds?: number;
  maxBackwardStepSeconds?: number;
  maxAbsoluteDivergenceSeconds?: number;
  maxAnchorLifetimeSeconds?: number;
}

export type ClockGuardState = "UNINITIALIZED" | "ACTIVE" | "TRIPPED_CLOSED" | "EXPIRED";

export class ClockGuard {
  private state: ClockGuardState = "UNINITIALIZED";
  private tripReason: string | undefined;
  private connectionTainted: boolean = false;
  private taintedReason: string | undefined;
  private isTransactionInProgress: boolean = false;

  private initialSample: ClockCandidate | null = null;
  private publishedSample: ClockCandidate | null = null;

  private readonly monotonicClock: MonotonicClock;
  private readonly maxStartupForwardGapSeconds: number;
  private readonly maxForwardStepSeconds: number;
  private readonly maxBackwardStepSeconds: number;
  private readonly maxAbsoluteDivergenceSeconds: number;
  private readonly maxAnchorLifetimeSeconds: number;

  constructor(
    _clock: Clock = systemClock,
    monotonicClock?: MonotonicClock,
    options?: ClockGuardOptions,
  ) {
    if (monotonicClock) {
      this.monotonicClock = monotonicClock;
    } else if (_clock && "nowNanoseconds" in _clock && typeof (_clock as unknown as MonotonicClock).nowNanoseconds === "function") {
      this.monotonicClock = _clock as unknown as MonotonicClock;
    } else {
      this.monotonicClock = systemMonotonicClock;
    }

    this.maxStartupForwardGapSeconds =
      options?.maxStartupForwardGapSeconds ?? MAX_STARTUP_FORWARD_GAP_SECONDS;
    this.maxForwardStepSeconds =
      options?.maxForwardStepSeconds ?? MAX_FORWARD_STEP_SECONDS;
    this.maxBackwardStepSeconds =
      options?.maxBackwardStepSeconds ?? MAX_BACKWARD_STEP_SECONDS;
    this.maxAbsoluteDivergenceSeconds =
      options?.maxAbsoluteDivergenceSeconds ?? MAX_ABSOLUTE_DIVERGENCE_SECONDS;
    this.maxAnchorLifetimeSeconds =
      options?.maxAnchorLifetimeSeconds ?? MAX_ANCHOR_LIFETIME_SECONDS;
  }

  getMonotonicClock(): MonotonicClock {
    return this.monotonicClock;
  }

  getState(): ClockGuardState {
    return this.state;
  }

  getTripReason(): string | undefined {
    return this.tripReason;
  }

  isTainted(): boolean {
    return this.connectionTainted;
  }

  getTaintedReason(): string | undefined {
    return this.taintedReason;
  }

  getInitialSample(): Readonly<ClockCandidate> | null {
    return this.initialSample ? { ...this.initialSample } : null;
  }

  getPublishedSample(): Readonly<ClockCandidate> | null {
    return this.publishedSample ? { ...this.publishedSample } : null;
  }

  getMaxStartupForwardGapSeconds(): number {
    return this.maxStartupForwardGapSeconds;
  }

  acquireLock(): boolean {
    if (this.isTransactionInProgress) {
      return false;
    }
    this.isTransactionInProgress = true;
    return true;
  }

  releaseLock(): void {
    this.isTransactionInProgress = false;
  }

  trip(reason: string): void {
    this.state = "TRIPPED_CLOSED";
    this.tripReason = reason;
  }

  taintConnection(reason: string): void {
    this.connectionTainted = true;
    this.taintedReason = reason;
    this.trip(reason);
  }

  evaluateCandidate(candidate: ClockCandidate, sharedHighWaterSeconds: number): ClockCandidateEvaluation {
    if (this.connectionTainted) {
      return {
        decision: "DENY",
        reason: `SQLite database connection is tainted and unusable: ${this.taintedReason}`,
      };
    }

    if (this.state === "TRIPPED_CLOSED") {
      return {
        decision: "DENY",
        reason: `Store clock monitor is in a tripped state: ${this.tripReason}`,
      };
    }

    if (this.state === "EXPIRED") {
      return {
        decision: "DENY",
        reason: "Process clock anchor has expired (maximum uptime exceeded); restart required.",
      };
    }

    if (this.state === "UNINITIALIZED") {
      // 1. Startup rollback check relative to persistent high-water mark.
      // Deny without permanently tripping an otherwise healthy worker if it simply lags behind shared high-water.
      if (candidate.wallSeconds < sharedHighWaterSeconds) {
        return {
          decision: "DENY",
          reason: `Clock rollback detected: current time (${candidate.wallSeconds}s) precedes persisted high-water mark (${sharedHighWaterSeconds}s).`,
        };
      }

      // 2. Startup forward gap damage-containment check
      const startupGap = candidate.wallSeconds - sharedHighWaterSeconds;
      if (startupGap > this.maxStartupForwardGapSeconds) {
        this.trip(
          `Store startup rejected: forward clock gap of ${startupGap} seconds exceeds maximum allowed startup threshold (${this.maxStartupForwardGapSeconds}s).`,
        );
        return {
          decision: "DENY",
          reason: `Store startup rejected: forward clock gap of ${startupGap} seconds exceeds maximum allowed startup threshold (${this.maxStartupForwardGapSeconds}s).`,
        };
      }

      // Candidate is valid for initialization; anchor will be published and activated on confirmed COMMIT.
      return { decision: "ALLOW" };
    }

    // ACTIVE state validation
    const initial = this.initialSample!;
    const published = this.publishedSample!;

    // 1. Anchor lifetime check
    const elapsedMonotonicSec = Number((candidate.monotonicNanos - initial.monotonicNanos) / 1_000_000_000n);
    if (elapsedMonotonicSec > this.maxAnchorLifetimeSeconds) {
      this.state = "EXPIRED";
      return {
        decision: "DENY",
        reason: "Process clock anchor has expired (maximum uptime exceeded); restart required.",
      };
    }

    // 2. Authoritative shared high-water check (rejects candidate below shared SQLite high water)
    if (candidate.wallSeconds < sharedHighWaterSeconds) {
      return {
        decision: "DENY",
        reason: `Clock rollback detected: current time (${candidate.wallSeconds}s) precedes persisted high-water mark (${sharedHighWaterSeconds}s).`,
      };
    }

    // 3. Cumulative absolute divergence check
    const elapsedWallSec = candidate.wallSeconds - initial.wallSeconds;
    const cumulativeDivergence = Math.abs(elapsedWallSec - elapsedMonotonicSec);
    if (cumulativeDivergence > this.maxAbsoluteDivergenceSeconds) {
      this.trip(
        `Suspicious clock divergence detected: cumulative divergence of ${cumulativeDivergence}s exceeds maximum ceiling (${this.maxAbsoluteDivergenceSeconds}s).`,
      );
      return {
        decision: "DENY",
        reason: `Suspicious clock divergence detected: cumulative divergence of ${cumulativeDivergence}s exceeds maximum ceiling (${this.maxAbsoluteDivergenceSeconds}s).`,
      };
    }

    // 4. Step velocity divergence check relative to last published observation
    const stepWallSec = candidate.wallSeconds - published.wallSeconds;
    const stepMonotonicSec = Number((candidate.monotonicNanos - published.monotonicNanos) / 1_000_000_000n);
    const stepDivergence = stepWallSec - stepMonotonicSec;

    if (stepDivergence > this.maxForwardStepSeconds) {
      this.trip(
        `Suspicious forward clock jump detected: step velocity divergence of ${stepDivergence}s exceeds forward limit (${this.maxForwardStepSeconds}s).`,
      );
      return {
        decision: "DENY",
        reason: `Suspicious forward clock jump detected: step velocity divergence of ${stepDivergence}s exceeds forward limit (${this.maxForwardStepSeconds}s).`,
      };
    }

    if (stepDivergence < -this.maxBackwardStepSeconds) {
      this.trip(
        `Suspicious backward clock step detected: step velocity divergence of ${stepDivergence}s exceeds backward limit (-${this.maxBackwardStepSeconds}s).`,
      );
      return {
        decision: "DENY",
        reason: `Suspicious backward clock step detected: step velocity divergence of ${stepDivergence}s exceeds backward limit (-${this.maxBackwardStepSeconds}s).`,
      };
    }

    return { decision: "ALLOW" };
  }

  publishCandidate(candidate: ClockCandidate): void {
    if (this.connectionTainted || this.state === "TRIPPED_CLOSED" || this.state === "EXPIRED") {
      return;
    }
    if (this.state === "UNINITIALIZED") {
      this.initialSample = {
        wallSeconds: candidate.wallSeconds,
        monotonicNanos: candidate.monotonicNanos,
      };
      this.state = "ACTIVE";
    }
    this.publishedSample = {
      wallSeconds: candidate.wallSeconds,
      monotonicNanos: candidate.monotonicNanos,
    };
  }
}
