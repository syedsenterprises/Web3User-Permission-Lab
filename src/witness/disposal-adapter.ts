/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: PostgreSQL Connection Disposal Adapter
 *
 * Strictly isolates internal client.connection.stream extraction, severs the raw TCP socket
 * to abort in-flight backend queries, evicts the PoolClient from the pool via client.release(err)
 * with private pool._remove fallback, verifies disposal state, and executes fail-closed shutdown
 * if disposal cannot be confirmed.
 *
 * Pinned specifically to pg v8.23.1 and pg-pool v3.14.0.
 */

import type pg from "pg";

export interface DisposalConfirmation {
  socketDestroyed: boolean;
  poolClientEvicted: boolean;
  activeQueryAborted: boolean;
  disposalTimestamp: number;
}

export class PostgresConnectionDisposalAdapter {
  /**
   * Version-pinned emergency disposal adapter for pg v8.23.1 / pg-pool v3.14.0.
   *
   * Isolates internal client.connection.stream extraction, severs the raw TCP
   * socket to abort in-flight backend queries, evicts the PoolClient from the
   * pool via client.release(err) with private pool._remove fallback, verifies
   * disposal state, and executes fail-closed shutdown if disposal cannot be
   * confirmed.
   */
  static emergencyEvictAndDestroy(
    pool: pg.Pool,
    client: pg.PoolClient,
    reason: Error,
  ): DisposalConfirmation {
    let socketDestroyed = false;

    // Step 1: Duck-typed version-pinned raw stream extraction and destruction
    const stream = (client as any).connection?.stream;
    if (stream && typeof stream.destroy === "function") {
      try {
        stream.destroy();
        socketDestroyed = stream.destroyed === true;
      } catch (streamErr) {
        socketDestroyed = false;
      }
    }

    // Step 2: Pool eviction via public release(err) with private _remove fallback
    try {
      client.release(reason as any);
    } catch (releaseErr) {
      // Release failure indicates pool corruption or double-release; invoke private eviction
      try {
        (pool as any)._remove?.(client);
      } catch (removeErr) {
        // Handled by Step 4 verification
      }
    }

    // Step 3: Exact Disposal Verification
    const isSocketDead = stream
      ? socketDestroyed || stream.destroyed === true || stream.writable === false
      : true;
    const isEvictedFromPool =
      (pool as any)._clients?.indexOf(client) === -1 &&
      !((pool as any)._idle?.some((item: any) => item.client === client));

    // Step 4: Fail-Closed Behavior if Disposal Cannot be Confirmed
    if (!isSocketDead || !isEvictedFromPool) {
      console.error("FATAL: PostgresConnectionDisposalAdapter unconfirmed disposal", {
        isSocketDead,
        isEvictedFromPool,
        reason: reason.message,
      });
      // Fail-closed panic: drain pool and terminate process to prevent pooling tainted socket
      pool.end().catch(() => {});
      process.exit(1);
    }

    return {
      socketDestroyed: isSocketDead,
      poolClientEvicted: isEvictedFromPool,
      activeQueryAborted: true,
      disposalTimestamp: Date.now(),
    };
  }
}
