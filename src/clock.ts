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

export class SystemClock implements Clock {
  nowSeconds(): number {
    return Math.floor(Date.now() / 1000);
  }
}

export class TestClock implements Clock {
  private currentSeconds: number;

  constructor(initialSeconds: number = 0) {
    if (!Number.isSafeInteger(initialSeconds) || initialSeconds < 0) {
      throw new Error("Initial seconds must be a non-negative safe integer.");
    }
    this.currentSeconds = initialSeconds;
  }

  set(seconds: number): void {
    if (!Number.isSafeInteger(seconds) || seconds < 0) {
      throw new Error("Seconds must be a non-negative safe integer.");
    }
    this.currentSeconds = seconds;
  }

  advance(seconds: number): void {
    if (!Number.isSafeInteger(seconds) || seconds < 0) {
      throw new Error("Advance duration must be a non-negative safe integer.");
    }
    this.currentSeconds += seconds;
  }

  nowSeconds(): number {
    return this.currentSeconds;
  }
}

export const systemClock: Clock = new SystemClock();
