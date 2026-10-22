import type { DatabaseSync } from "node:sqlite";

export const MAX_CONTENTION_RETRIES = 3;
export const CONTENTION_RETRY_DELAY_MS = 25;

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

/**
 * Checks if an error is an SQLite busy or locked contention error.
 */
export function isBusyOrLockedError(err: unknown): boolean {
  return err instanceof Error && /busy|locked/i.test(err.message);
}

/**
 * Attempts to acquire an exclusive write transaction via `BEGIN IMMEDIATE;`
 * with bounded retries and non-spinning backoff.
 *
 * Returns true if transaction was acquired successfully.
 * Returns false if retry limit was exceeded or a busy/locked condition persists.
 * Rethrows any non-busy/locked errors immediately without retry.
 */
export function beginImmediateWithRetry(
  db: DatabaseSync,
  maxRetries: number = MAX_CONTENTION_RETRIES,
  delayMs: number = CONTENTION_RETRY_DELAY_MS,
): boolean {
  let attempt = 0;
  while (attempt < maxRetries) {
    attempt++;
    try {
      db.exec("BEGIN IMMEDIATE;");
      return true;
    } catch (err) {
      if (isBusyOrLockedError(err) && attempt < maxRetries) {
        sleepSync(delayMs);
        continue;
      }
      if (isBusyOrLockedError(err)) {
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
): T {
  if (!beginImmediateWithRetry(db, maxRetries, delayMs)) {
    throw new Error("Database is busy; transaction contention retry limit exceeded.");
  }
  try {
    const result = fn();
    db.exec("COMMIT;");
    return result;
  } catch (err) {
    try {
      db.exec("ROLLBACK;");
    } catch {}
    throw err;
  }
}
