import type { DatabaseSync } from "node:sqlite";

export const MAX_CONTENTION_RETRIES = 5;
export const BASE_CONTENTION_DELAY_MS = 15;
export const MAX_CONTENTION_DELAY_MS = 100;
export const MAX_CONTENTION_BUDGET_MS = 250;
export const CONTENTION_RETRY_DELAY_MS = BASE_CONTENTION_DELAY_MS;

const sharedBuffer = new SharedArrayBuffer(4);
const sharedInt32 = new Int32Array(sharedBuffer);

/**
 * Non-spinning synchronous sleep using Atomics.wait.
 * Relinquishes the OS thread to avoid busy-wait CPU starvation.
 */
export function sleepSync(ms: number): void {
  if (ms <= 0) return;
  Atomics.wait(sharedInt32, 0, 0, ms);
}

export const SQLITE_BUSY = 5;
export const SQLITE_LOCKED = 6;
export const SQLITE_IOERR = 10;
export const SQLITE_CORRUPT = 11;
export const SQLITE_FULL = 13;

/**
 * Extracts the base SQLite result code from an error when available.
 * Handles both base error codes and extended result codes (masking with 0xff).
 */
export function getSqliteErrcode(err: unknown): number | undefined {
  if (typeof err === "object" && err !== null && "errcode" in err) {
    const rawCode = (err as { errcode: unknown }).errcode;
    if (typeof rawCode === "number" && Number.isInteger(rawCode)) {
      return rawCode & 0xff;
    }
  }
  return undefined;
}

/**
 * Checks if an error is an SQLite busy or locked contention error.
 * Inspects structured errcode first, falling back to message matching for compatibility.
 */
export function isBusyOrLockedError(err: unknown): boolean {
  if (!err) return false;
  const primaryCode = getSqliteErrcode(err);
  if (primaryCode === SQLITE_BUSY || primaryCode === SQLITE_LOCKED) {
    return true;
  }
  return err instanceof Error && /busy|locked/i.test(err.message);
}

/**
 * Checks if an error represents an unrecoverable, fatal SQLite I/O or storage corruption error.
 * Inspects structured errcode first, falling back to scoped message matching.
 * Excludes transient contention (SQLITE_BUSY) and recoverable capacity errors (SQLITE_FULL).
 */
export function isFatalIOError(err: unknown): boolean {
  if (!err) return false;
  const primaryCode = getSqliteErrcode(err);
  if (primaryCode === SQLITE_IOERR || primaryCode === SQLITE_CORRUPT) {
    return true;
  }
  const message = err instanceof Error ? err.message : String(err);
  return (
    message.includes("SQLITE_IOERR") ||
    message.includes("disk I/O error") ||
    message.includes("Fatal storage I/O error") ||
    message.includes("Fatal rollback failure") ||
    message.includes("SQLITE_CORRUPT")
  );
}

/**
 * Calculates bounded exponential backoff with full jitter for a given retry attempt.
 *
 * Full jitter selects uniformly from [0, ceiling], where ceiling is min(maxDelay, baseDelay * 2^(attempt-1)).
 *
 * @param attempt 1-based retry attempt number (1, 2, 3, ...)
 * @param baseDelayMs Base initial delay in milliseconds (default: 15)
 * @param maxDelayMs Maximum individual delay ceiling in milliseconds (default: 100)
 * @param randomFn Pseudo-random float generator in range [0, 1), default: Math.random
 */
export function calculateBackoffWithJitter(
  attempt: number,
  baseDelayMs: number = BASE_CONTENTION_DELAY_MS,
  maxDelayMs: number = MAX_CONTENTION_DELAY_MS,
  randomFn: () => number = Math.random,
): number {
  if (attempt <= 0) return 0;
  const expFactor = Math.pow(2, Math.max(0, attempt - 1));
  const ceiling = Math.min(maxDelayMs, Math.max(0, baseDelayMs) * expFactor);
  return Math.min(ceiling, Math.floor(randomFn() * (ceiling + 1)));
}

/**
 * Attempts to acquire an exclusive write transaction via `BEGIN IMMEDIATE;`
 * with bounded retries, exponential backoff, full jitter, and a cumulative time budget.
 *
 * Returns true if transaction was acquired successfully.
 * Returns false if retry limit was exceeded, cumulative budget was exhausted, or a busy/locked condition persists.
 * Rethrows any non-busy/locked errors immediately without retry.
 */
export function beginImmediateWithRetry(
  db: DatabaseSync,
  maxRetries: number = MAX_CONTENTION_RETRIES,
  delayMs: number = CONTENTION_RETRY_DELAY_MS,
  maxBudgetMs: number = MAX_CONTENTION_BUDGET_MS,
  randomFn: () => number = Math.random,
  sleepFn: (ms: number) => void = sleepSync,
): boolean {
  let attempt = 0;
  let elapsedBudget = 0;

  while (attempt < maxRetries) {
    attempt++;
    try {
      db.exec("BEGIN IMMEDIATE;");
      return true;
    } catch (err) {
      if (isBusyOrLockedError(err)) {
        if (attempt < maxRetries && elapsedBudget < maxBudgetMs) {
          const rawDelay = calculateBackoffWithJitter(attempt, delayMs, MAX_CONTENTION_DELAY_MS, randomFn);
          const actualDelay = Math.min(rawDelay, maxBudgetMs - elapsedBudget);
          if (actualDelay > 0) {
            sleepFn(actualDelay);
            elapsedBudget += actualDelay;
          }
          continue;
        }
        return false;
      }
      throw err;
    }
  }
  return false;
}

/**
 * Executes a function inside an immediate SQLite transaction with bounded contention retries.
 * Automatically rolls back on error.
 * If transaction acquisition fails due to contention, throws a typed contention error.
 */
export function withImmediateTransaction<T>(
  db: DatabaseSync,
  fn: () => T,
  maxRetries: number = MAX_CONTENTION_RETRIES,
  delayMs: number = CONTENTION_RETRY_DELAY_MS,
  maxBudgetMs: number = MAX_CONTENTION_BUDGET_MS,
  onCommitSuccess?: () => void,
  onCommitFailure?: (err: unknown) => void,
  onRollbackFailure?: (rollbackErr: unknown, originalErr: unknown) => void,
): T {
  if (!beginImmediateWithRetry(db, maxRetries, delayMs, maxBudgetMs)) {
    throw new Error("Database is busy; transaction contention retry limit exceeded.");
  }
  let result: T;
  try {
    result = fn();
  } catch (err) {
    try {
      db.exec("ROLLBACK;");
    } catch (rollbackErr) {
      if (isFatalIOError(rollbackErr)) {
        if (onRollbackFailure) {
          onRollbackFailure(rollbackErr, err);
        } else if (onCommitFailure) {
          onCommitFailure(rollbackErr);
        }
      }
    }
    throw err;
  }

  try {
    db.exec("COMMIT;");
  } catch (commitErr) {
    try {
      db.exec("ROLLBACK;");
    } catch {}
    if (onCommitFailure) {
      onCommitFailure(commitErr);
    }
    throw commitErr;
  }

  if (onCommitSuccess) {
    onCommitSuccess();
  }
  return result;
}
