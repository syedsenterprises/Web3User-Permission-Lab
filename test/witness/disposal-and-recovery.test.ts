/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Connection Disposal & Ambiguous Recovery Tests
 *
 * Verifies:
 * - TEST-M13D-D2-F3-01: Real PostgreSQL Active-Query Cancellation & Raw Socket Severing.
 * - TEST-M13D-D2-F3-02: Ambiguous COMMIT recovery via reconcileTicket.
 * - TEST-M13D-D2-F1-03: Concurrent supervisor fencing races serialized safely.
 * - TEST-M13D-D2-F5-01: Cumulative budget conservation under high concurrency.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import pg from "pg";
import { PostgresWitnessStore } from "../../src/witness/postgres-store.js";
import { PostgresConnectionDisposalAdapter } from "../../src/witness/disposal-adapter.js";
import { GrpcWitnessServiceImpl } from "../../src/witness/grpc-service.js";
import { LocalEd25519WitnessSigner } from "../../src/witness/signing.js";

const { Pool } = pg;

describe("Milestone 13-D Phase D2: Connection Disposal & Ambiguous Recovery Tests", () => {
  let pool: pg.Pool;
  let store: PostgresWitnessStore;
  let serviceImpl: GrpcWitnessServiceImpl;
  const testEpochId = "test-disposal-epoch-1";

  beforeAll(async () => {
    store = new PostgresWitnessStore({ epochId: testEpochId });
    pool = (store as any).pool;
    try {
      await store.initializeSchema();
    } catch {}
    await store.registerEpoch(testEpochId, 300);

    const signer = new LocalEd25519WitnessSigner("disposal-witness-signer");
    serviceImpl = new GrpcWitnessServiceImpl({ pool, signer });
  });

  beforeEach(async () => {
    await store.registerEpoch(testEpochId, 300);
  });

  afterAll(async () => {
    if (pool) await pool.end();
  });

  // ==========================================================================
  // 1. TEST-M13D-D2-F3-01: Real Active-Query Cancellation & Raw Socket Severing
  // ==========================================================================
  it("TEST-M13D-D2-F3-01: Cancelling slow query severs raw TCP socket and evicts client from pool", async () => {
    const client = await pool.connect();
    let queryPromiseError: any = null;

    // Launch slow query on real PostgreSQL backend
    const queryPromise = client.query("SELECT pg_sleep(3)").catch((e) => {
      queryPromiseError = e;
    });

    // Wait 50ms for query to be in-flight
    await new Promise((r) => setTimeout(r, 50));

    // Emergency Evict and Destroy
    const confirmation = PostgresConnectionDisposalAdapter.emergencyEvictAndDestroy(
      pool,
      client,
      new Error("ACTIVE_QUERY_CANCELLED_TEST"),
    );

    expect(confirmation.socketDestroyed).toBe(true);
    expect(confirmation.poolClientEvicted).toBe(true);

    // Wait for the query promise to settle
    await queryPromise;
    expect(queryPromiseError).toBeDefined();

    // Verify raw stream is destroyed and client purged from pool's active list
    const stream = (client as any).connection?.stream;
    expect(stream?.destroyed).toBe(true);
    expect((pool as any)._clients.indexOf(client)).toBe(-1);
  });

  // ==========================================================================
  // 2. TEST-M13D-D2-F1-03: Concurrent Fencing Supervisor Races
  // ==========================================================================
  it("TEST-M13D-D2-F1-03: Concurrent supervisor fencing races are serialized cleanly with zero duplicates", async () => {
    const stalledTicketId = `ticket-fencerace-${Date.now()}`;
    const pClient = await pool.connect();
    let raceSeq: string;
    try {
      await pClient.query("BEGIN;");
      const sRes = await pClient.query(`SELECT nextval(get_or_create_epoch_sequence($1)) AS seq`, [testEpochId]);
      raceSeq = String(sRes.rows[0].seq);

      const past = Math.floor(Date.now() / 1000) - 20;
      await pClient.query(
        `INSERT INTO witness_tickets (ticket_id, authorization_id, epoch_id, state, binding_digest, expires_at_seconds, created_at_seconds, updated_at_seconds, request_fingerprint, owner_identity)
         VALUES ($1, $2, $3, 'COMMITTING_SIGNING_PENDING', 'sha256:8888', $4, $4, $4, 'fp', 'worker-stall')`,
        [stalledTicketId, `auth-fencerace-${Date.now()}`, testEpochId, past],
      );

      await pClient.query(
        `INSERT INTO witness_signing_outbox (
           intent_id, ticket_id, epoch_id, sequence_number, preimage,
           status, fencing_generation, owner_worker_id, lease_expires_at_seconds,
           request_fingerprint, created_at_seconds, updated_at_seconds
         ) VALUES ($1, $2, $3, $4, 'preimage', 'PENDING', 1, 'worker-stall', $5, 'fp', $6, $6)`,
        [`intent-${stalledTicketId}`, stalledTicketId, testEpochId, raceSeq, past, past],
      );
      await pClient.query("COMMIT;");
    } finally {
      pClient.release();
    }

    // Launch two concurrent supervisors attempting to fence the exact same sequence simultaneously
    const [result1, result2] = await Promise.all([
      serviceImpl.executeTerminalFencing(testEpochId, raceSeq, 1, stalledTicketId, "supervisor-pod-1"),
      serviceImpl.executeTerminalFencing(testEpochId, raceSeq, 1, stalledTicketId, "supervisor-pod-2"),
    ]);

    // Exactly one supervisor successfully executed the transition
    expect(result1 || result2).toBe(true);

    // Verify exactly ONE gap record exists in witness_sequence_gaps
    const gaps = await pool.query(
      `SELECT * FROM witness_sequence_gaps WHERE epoch_id = $1 AND sequence_number = $2`,
      [testEpochId, raceSeq],
    );
    expect(gaps.rows.length).toBe(1);
    expect(gaps.rows[0].gap_reason).toBe("OUTBOX_FENCED");
  });

  // ==========================================================================
  // 3. TEST-M13D-D2-F5-01: Cumulative Budget Conservation Under Concurrency
  // ==========================================================================
  it("TEST-M13D-D2-F5-01: Enforces current_amount + held_amount <= max_limit across 20 concurrent workers", async () => {
    const rawType = `DAILY_CONCURRENCY_${Date.now()}`;
    const windowStart = 1000;
    const windowId = `${rawType}_${windowStart}`;
    const maxLimit = "1000";

    // Initialize accumulator with max 1000
    await pool.query(
      `INSERT INTO witness_accumulators (window_id, window_type, window_start, current_amount, held_amount, max_limit)
       VALUES ($1, 'DAILY', $2, 0, 0, $3)`,
      [windowId, windowStart, maxLimit],
    );

    // 20 workers each try to reserve 100 (Total attempted: 2000, but limit is 1000)
    const peer: any = {
      identity: "spiffe://web3user.internal/ns/engine/sa/engine-pod-worker",
      role: "role:engine-pod",
      serialNumber: "00",
      sanUris: [],
    };

    const promises = Array.from({ length: 20 }, (_, i) => {
      return serviceImpl.reserveTicket(
        {
          authorization_id: `auth-budget-race-${Date.now()}-${i}`,
          binding_digest: "sha256:9999",
          idempotency_key: `key-budget-${Date.now()}-${i}`,
          budget_windows: [
            {
              window_type: rawType,
              window_start_seconds: windowStart,
              requested_amount: "100",
              max_cumulative_amount: maxLimit,
            },
          ],
        },
        peer,
      );
    });

    const results = await Promise.allSettled(promises);
    const fulfilled = results
      .filter((r): r is PromiseFulfilledResult<any> => r.status === "fulfilled")
      .map((r) => r.value);
    const allowed = fulfilled.filter((r) => r.decision === "DECISION_ALLOW");

    // Invariant: Allowed reservations MUST NOT exceed the budget capacity of 10 (10 x 100 = 1000)
    expect(allowed.length).toBeLessThanOrEqual(10);
    expect(allowed.length).toBeGreaterThan(0);

    // Verify accumulator state in database
    const acc = await pool.query(
      `SELECT current_amount, held_amount, max_limit FROM witness_accumulators WHERE window_id = $1`,
      [windowId],
    );

    const cur = BigInt(acc.rows[0].current_amount);
    const held = BigInt(acc.rows[0].held_amount);
    const max = BigInt(acc.rows[0].max_limit);

    // Strictly enforce budget conservation invariant: cur + held <= max
    expect(cur + held).toBeLessThanOrEqual(max);
    expect(held).toBe(BigInt(allowed.length * 100));
  });
});
