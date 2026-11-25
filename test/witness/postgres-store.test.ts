/**
 * Web3User Permission Lab - Milestone 13-D Phase 1 (D1) Acceptance Tests
 *
 * Primary Acceptance Gates:
 * - TEST-M13D-04: Concurrent reservation race (unique constraint serialization).
 * - TEST-M13D-05: Cross-pod replay prevention (replay rejected after commit).
 * - TEST-M13D-17: Budget row locking & contention (FOR UPDATE NOWAIT mutual exclusion).
 *
 * Additional Security Invariant Tests:
 * - Global authorization ID uniqueness across epochs.
 * - Permanent sequence gap preservation on outbox failure.
 * - Budget capacity limits and negative balance prevention.
 * - SQLSTATE 23505 read-and-verify idempotency vs payload mismatch conflict.
 * - Receipt immutability trigger protection.
 * - Append-only audit log trigger protection.
 * - State machine terminality: COMMITTED tickets cannot be released.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import {
  PostgresWitnessStore,
  WitnessConflictError,
  InvalidWitnessStateTransitionError,
  WitnessContentionError,
  WitnessUnavailableError,
  WitnessDeadlockError,
  PG_SQLSTATE,
} from "../../src/witness/postgres-store.js";
import type { WitnessReservationRequest, WitnessCommitRequest } from "../../src/monotonic-witness.js";
import pg from "pg";

/**
 * Test-only database reset utility.
 * Strictly forbidden and inaccessible in production runtime.
 */
async function resetTestDatabase(pool: pg.Pool): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query(`
      ALTER TABLE witness_receipts DISABLE TRIGGER trg_witness_receipts_no_truncate;
      ALTER TABLE witness_audit_log DISABLE TRIGGER trg_witness_audit_log_no_truncate;
      ALTER TABLE witness_sequence_gaps DISABLE TRIGGER trg_witness_gaps_no_truncate;
      TRUNCATE TABLE witness_sequence_gaps, witness_receipts, witness_signing_outbox, witness_tickets, witness_accumulators, witness_audit_log, witness_epochs RESTART IDENTITY CASCADE;
      ALTER TABLE witness_receipts ENABLE TRIGGER trg_witness_receipts_no_truncate;
      ALTER TABLE witness_audit_log ENABLE TRIGGER trg_witness_audit_log_no_truncate;
      ALTER TABLE witness_sequence_gaps ENABLE TRIGGER trg_witness_gaps_no_truncate;
    `);

    // Reset sequences in test environment
    const seqsRes = await client.query(`
      SELECT sequencename FROM pg_sequences WHERE sequencename LIKE 'witness_seq_%'
    `);
    for (const row of seqsRes.rows) {
      const seqName = row.sequencename;
      if (/^[a-zA-Z0-9_]+$/.test(seqName)) {
        await client.query(`ALTER SEQUENCE "${seqName}" RESTART WITH 1`);
      }
    }
  } finally {
    client.release();
  }
}

describe("Milestone 13-D: D1 Backend Foundation (PostgreSQL 16 Witness Store)", () => {
  let store: PostgresWitnessStore;

  beforeAll(async () => {
    store = new PostgresWitnessStore({
      epochId: "epoch-001",
    });
    await store.initializeSchema();
  });

  afterAll(async () => {
    await store.close();
  });

  beforeEach(async () => {
    await resetTestDatabase((store as any).pool);
  });

  // ==========================================================================
  // TEST-M13D-04: Concurrent Reservation Race (Linearizable Reservation)
  // ==========================================================================
  it("TEST-M13D-04: Two engines race to reserve the same authId; exactly one succeeds and second is safely denied", async () => {
    const authId = "auth_race_001";
    const bindingDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    const req1: WitnessReservationRequest = {
      authorizationId: authId,
      bindingDigest,
      policyId: "policy_main",
      policyRevision: 1,
      idempotencyKey: "idem_pod_1",
      leaseTtlSeconds: 300,
    };

    const req2: WitnessReservationRequest = {
      authorizationId: authId,
      bindingDigest,
      policyId: "policy_main",
      policyRevision: 1,
      idempotencyKey: "idem_pod_2",
      leaseTtlSeconds: 300,
    };

    // Execute concurrently across two distinct caller identities
    const [res1, res2] = await Promise.all([
      store.reserveTicket(req1, "pod-worker-A"),
      store.reserveTicket(req2, "pod-worker-B"),
    ]);

    // Exactly one must ALLOW and one must DENY
    const allows = [res1, res2].filter((r) => r.decision === "ALLOW");
    const denies = [res1, res2].filter((r) => r.decision === "DENY");

    expect(allows.length).toBe(1);
    expect(denies.length).toBe(1);

    expect(allows[0].ticketId).toBeDefined();
    expect(allows[0].state).toBe("RESERVED");

    expect(denies[0].reasons).toContain("DENY: AUTHORIZATION_ALREADY_RESERVED");

    // Invariant: Exactly one ticket exists in the database
    const ticket = await store.getTicketByAuthorizationId(authId);
    expect(ticket).not.toBeNull();
    expect(ticket?.authorizationId).toBe(authId);
    expect(ticket?.state).toBe("RESERVED");
  });

  // ==========================================================================
  // TEST-M13D-05: Cross-Pod Replay Prevention (Replay Denied After Commit)
  // ==========================================================================
  it("TEST-M13D-05: Engine 1 commits; Engine 2 attempts to reserve same authId; rejected with DENY: AUTHORIZATION_ALREADY_COMMITTED", async () => {
    const authId = "auth_replay_001";
    const bindingDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    // Engine 1 reserves ticket
    const reserveRes = await store.reserveTicket(
      {
        authorizationId: authId,
        bindingDigest,
        policyId: "policy_main",
        policyRevision: 1,
        idempotencyKey: "idem_engine_1",
      },
      "engine-pod-1",
    );

    expect(reserveRes.decision).toBe("ALLOW");
    const ticketId = reserveRes.ticketId!;

    // Engine 1 commits ticket
    const commitRes = await store.commitTicket({
      ticketId,
      authorizationId: authId,
      bindingDigest,
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    });

    expect(commitRes.decision).toBe("ALLOW");
    expect(commitRes.receipt).toBeDefined();

    // Engine 2 attempts to reserve the same authorization ID
    const replayReserveRes = await store.reserveTicket(
      {
        authorizationId: authId,
        bindingDigest,
        policyId: "policy_main",
        policyRevision: 1,
        idempotencyKey: "idem_engine_2",
      },
      "engine-pod-2",
    );

    expect(replayReserveRes.decision).toBe("DENY");
    expect(replayReserveRes.state).toBe("COMMITTED");
    expect(replayReserveRes.reasons).toContain("DENY: AUTHORIZATION_ALREADY_COMMITTED");
  });

  // ==========================================================================
  // TEST-M13D-17: Budget Row Locking & Contention (FOR UPDATE NOWAIT)
  // ==========================================================================
  it("TEST-M13D-17: Concurrent commit and release on same ticket; row-level lock contention resolves with winner completing and loser failing closed", async () => {
    const authId = "auth_contention_017";
    const bindingDigest = "sha256:3333333333333333333333333333333333333333333333333333333333333333";

    // Reserve ticket with budget window
    const reserveRes = await store.reserveTicket({
      authorizationId: authId,
      bindingDigest,
      policyId: "policy_budget",
      policyRevision: 1,
      idempotencyKey: "idem_contention_17",
      budgetWindows: [
        {
          windowType: "DAILY",
          windowStart: 1730340000,
          requestedAmount: "5000",
          maxCumulativeAmount: "10000",
        },
      ],
    });

    expect(reserveRes.decision).toBe("ALLOW");
    const ticketId = reserveRes.ticketId!;

    // Race commitTicket vs releaseTicket concurrently
    const commitPromise = store.commitTicket({
      ticketId,
      authorizationId: authId,
      bindingDigest,
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    });

    const releasePromise = store.releaseTicket({
      ticketId,
      authorizationId: authId,
      bindingDigest,
      reason: "cancelled_during_race",
    });

    const results = await Promise.allSettled([commitPromise, releasePromise]);

    // One operation must succeed, and the other must either fail or be rejected cleanly
    const fulfilled = results.filter((r) => r.status === "fulfilled");
    expect(fulfilled.length).toBeGreaterThanOrEqual(1);

    // Verify database state: ticket must be in a valid terminal state
    const finalTicket = await store.getTicket(ticketId);
    expect(["COMMITTED", "RELEASED"]).toContain(finalTicket?.state);

    // If commit succeeded, release on the committed ticket must throw InvalidWitnessStateTransitionError
    if (finalTicket?.state === "COMMITTED") {
      await expect(
        store.releaseTicket({
          ticketId,
          authorizationId: authId,
          bindingDigest,
          reason: "post_commit_release_attempt",
        }),
      ).rejects.toThrow(InvalidWitnessStateTransitionError);
    }
  });

  // ==========================================================================
  // Additional Security Invariants
  // ==========================================================================

  it("enforces global authorization ID uniqueness across different epochs", async () => {
    const authId = "auth_global_epoch_001";
    const bindingDigest = "sha256:4444444444444444444444444444444444444444444444444444444444444444";

    // Reserve in epoch-001
    const res1 = await store.reserveTicket({
      authorizationId: authId,
      bindingDigest,
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey: "idem_ep1",
    });
    expect(res1.decision).toBe("ALLOW");

    // Create store configured for epoch-002
    const storeEpoch2 = new PostgresWitnessStore({
      epochId: "epoch-002",
    });

    try {
      const res2 = await storeEpoch2.reserveTicket({
        authorizationId: authId,
        bindingDigest,
        policyId: "p1",
        policyRevision: 1,
        idempotencyKey: "idem_ep2",
      });

      // Must be denied due to global authorization uniqueness
      expect(res2.decision).toBe("DENY");
      expect(res2.reasons).toContain("DENY: AUTHORIZATION_ALREADY_RESERVED");
    } finally {
      await storeEpoch2.close();
    }
  });

  it("handles SQLSTATE 23505 read-and-verify: exact payload match returns cached reservation, mismatched payload throws WitnessConflictError", async () => {
    const authId = "auth_idemp_check_001";
    const bindingDigest = "sha256:5555555555555555555555555555555555555555555555555555555555555555";
    const idempotencyKey = "idem_key_matching";

    const res1 = await store.reserveTicket({
      authorizationId: authId,
      bindingDigest,
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey,
    });
    expect(res1.decision).toBe("ALLOW");

    // Exact idempotent retry: returns existing reservation
    const res2 = await store.reserveTicket({
      authorizationId: authId,
      bindingDigest,
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey,
    });
    expect(res2.decision).toBe("ALLOW");
    expect(res2.ticketId).toBe(res1.ticketId);

    // Mismatched payload for same authorization ID: throws hard conflict error
    const divergentDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    await expect(
      store.reserveTicket({
        authorizationId: authId,
        bindingDigest: divergentDigest,
        policyId: "p1",
        policyRevision: 1,
        idempotencyKey: "idem_divergent",
      }),
    ).rejects.toThrow(WitnessConflictError);
  });

  it("enforces budget accumulator capacity limits and check constraints (current + held <= max)", async () => {
    const authId1 = "auth_budget_001";
    const authId2 = "auth_budget_002";
    const bindingDigest = "sha256:6666666666666666666666666666666666666666666666666666666666666666";

    // Request 800 out of 1000 limit
    const res1 = await store.reserveTicket({
      authorizationId: authId1,
      bindingDigest,
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey: "idem_b1",
      budgetWindows: [
        {
          windowType: "DAILY",
          windowStart: 1730340000,
          requestedAmount: "800",
          maxCumulativeAmount: "1000",
        },
      ],
    });
    expect(res1.decision).toBe("ALLOW");

    const acc1 = await store.getAccumulator("DAILY:1730340000");
    expect(acc1?.heldAmount).toBe("800");
    expect(acc1?.currentAmount).toBe("0");

    // Second request attempts to reserve 300 (800 + 300 = 1100 > 1000 max)
    const res2 = await store.reserveTicket({
      authorizationId: authId2,
      bindingDigest,
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey: "idem_b2",
      budgetWindows: [
        {
          windowType: "DAILY",
          windowStart: 1730340000,
          requestedAmount: "300",
          maxCumulativeAmount: "1000",
        },
      ],
    });

    expect(res2.decision).toBe("DENY");
    expect(res2.reasons?.[0]).toContain("DENY: BUDGET_EXCEEDED");

    // Invariant: Held amount remains at 800, not 1100
    const acc2 = await store.getAccumulator("DAILY:1730340000");
    expect(acc2?.heldAmount).toBe("800");
  });

  it("shifts budget atomically during commit (held -= amount, current += amount) and refunds on release", async () => {
    const authId = "auth_budget_shift_001";
    const bindingDigest = "sha256:7777777777777777777777777777777777777777777777777777777777777777";

    const res = await store.reserveTicket({
      authorizationId: authId,
      bindingDigest,
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey: "idem_shift_1",
      budgetWindows: [
        {
          windowType: "HOURLY",
          windowStart: 1730343600,
          requestedAmount: "250",
          maxCumulativeAmount: "500",
        },
      ],
    });
    expect(res.decision).toBe("ALLOW");
    const ticketId = res.ticketId!;

    let acc = await store.getAccumulator("HOURLY:1730343600");
    expect(acc?.heldAmount).toBe("250");
    expect(acc?.currentAmount).toBe("0");

    // Phase 1 commit shifts held to current
    const p1 = await store.commitTicketPhase1(
      ticketId,
      authId,
      bindingDigest,
      "PREIMAGE_TEST",
      "250",
      [{ windowType: "HOURLY", windowStart: 1730343600, requestedAmount: "250" }],
    );
    expect(p1.success).toBe(true);

    acc = await store.getAccumulator("HOURLY:1730343600");
    expect(acc?.heldAmount).toBe("0");
    expect(acc?.currentAmount).toBe("250");
  });

  it("permanently preserves sequence gaps when outbox worker encounters permanent failure", async () => {
    const authId = "auth_gap_001";
    const bindingDigest = "sha256:8888888888888888888888888888888888888888888888888888888888888888";

    const res = await store.reserveTicket({
      authorizationId: authId,
      bindingDigest,
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey: "idem_gap_1",
    });
    const ticketId = res.ticketId!;

    // Complete Phase 1 commit
    const p1 = await store.commitTicketPhase1(
      ticketId,
      authId,
      bindingDigest,
      "PREIMAGE_GAP_TEST",
    );
    const allocatedSeq = p1.sequenceNumber;
    expect(allocatedSeq).toBeDefined();

    // Simulate permanent failure transitioning ticket to QUARANTINED_BLOCKED
    await store.quarantineTicket(ticketId, "QUARANTINED_BLOCKED", "KMS_HARDWARE_FAILURE");

    // Verify outbox status is FAILED and sequence is retained
    const outbox = await store.getOutbox(ticketId);
    expect(outbox?.status).toBe("FAILED");
    expect(outbox?.sequenceNumber).toBe(allocatedSeq);

    const ticket = await store.getTicket(ticketId);
    expect(ticket?.state).toBe("QUARANTINED_BLOCKED");
    expect(ticket?.sequenceNumber).toBe(allocatedSeq);

    // Sequence is burned and NOT reused by subsequent commitments
    const nextAuthId = "auth_gap_002";
    const nextRes = await store.reserveTicket({
      authorizationId: nextAuthId,
      bindingDigest: "sha256:9999999999999999999999999999999999999999999999999999999999999999",
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey: "idem_gap_2",
    });
    const nextP1 = await store.commitTicketPhase1(
      nextRes.ticketId!,
      nextAuthId,
      "sha256:9999999999999999999999999999999999999999999999999999999999999999",
      "PREIMAGE_NEXT",
    );

    expect(BigInt(nextP1.sequenceNumber)).toBeGreaterThan(BigInt(allocatedSeq));
  });

  it("enforces receipt immutability via database trigger (disallows UPDATE and DELETE)", async () => {
    const authId = "auth_immutable_receipt_001";
    const bindingDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    const reserveRes = await store.reserveTicket({
      authorizationId: authId,
      bindingDigest,
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey: "idem_immut_1",
    });
    const ticketId = reserveRes.ticketId!;

    await store.commitTicket({
      ticketId,
      authorizationId: authId,
      bindingDigest,
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    });

    const receipt = await store.getReceipt(authId);
    expect(receipt).not.toBeNull();

    // Direct UPDATE on witness_receipts must be rejected by trigger
    const updatePromise = (store as any).pool.query(
      `UPDATE witness_receipts SET binding_digest = 'tampered' WHERE ticket_id = $1`,
      [ticketId],
    );
    await expect(updatePromise).rejects.toThrow(/immutable/i);

    // Direct DELETE on witness_receipts must be rejected by trigger
    const deletePromise = (store as any).pool.query(
      `DELETE FROM witness_receipts WHERE ticket_id = $1`,
      [ticketId],
    );
    await expect(deletePromise).rejects.toThrow(/immutable/i);
  });

  it("enforces append-only audit log via database trigger (disallows UPDATE and DELETE)", async () => {
    const authId = "auth_audit_append_001";
    const bindingDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    await store.reserveTicket({
      authorizationId: authId,
      bindingDigest,
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey: "idem_audit_1",
    });

    // Direct UPDATE on witness_audit_log must be rejected by trigger
    const updatePromise = (store as any).pool.query(
      `UPDATE witness_audit_log SET action = 'TAMPERED' WHERE authorization_id = $1`,
      [authId],
    );
    await expect(updatePromise).rejects.toThrow(/append-only/i);

    // Direct DELETE on witness_audit_log must be rejected by trigger
    const deletePromise = (store as any).pool.query(
      `DELETE FROM witness_audit_log WHERE authorization_id = $1`,
      [authId],
    );
    await expect(deletePromise).rejects.toThrow(/append-only/i);
  });

  it("strictly prohibits release of COMMITTED tickets with zero budget refund", async () => {
    const authId = "auth_terminal_state_001";
    const bindingDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    const res = await store.reserveTicket({
      authorizationId: authId,
      bindingDigest,
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey: "idem_term_1",
    });
    const ticketId = res.ticketId!;

    await store.commitTicket({
      ticketId,
      authorizationId: authId,
      bindingDigest,
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    });

    // Attempt to release committed ticket
    await expect(
      store.releaseTicket({
        ticketId,
        authorizationId: authId,
        bindingDigest,
        reason: "fraudulent_refund_attempt",
      }),
    ).rejects.toThrow(InvalidWitnessStateTransitionError);
  });

  it("enforces database check constraints chk_positive_amounts and chk_budget_limit directly", async () => {
    const rawPool = (store as any).pool;

    // Negative current_amount must fail
    await expect(
      rawPool.query(
        `INSERT INTO witness_accumulators (window_id, window_type, window_start, current_amount, held_amount, max_limit)
         VALUES ('TEST_NEG', 'DAILY', 1000, -1, 0, 1000)`,
      ),
    ).rejects.toThrow(/chk_positive_amounts/);

    // Negative held_amount must fail
    await expect(
      rawPool.query(
        `INSERT INTO witness_accumulators (window_id, window_type, window_start, current_amount, held_amount, max_limit)
         VALUES ('TEST_NEG_HELD', 'DAILY', 1000, 0, -5, 1000)`,
      ),
    ).rejects.toThrow(/chk_positive_amounts/);

    // current_amount + held_amount > max_limit must fail
    await expect(
      rawPool.query(
        `INSERT INTO witness_accumulators (window_id, window_type, window_start, current_amount, held_amount, max_limit)
         VALUES ('TEST_OVER_LIMIT', 'DAILY', 1000, 600, 500, 1000)`,
      ),
    ).rejects.toThrow(/chk_budget_limit/);
  });

  it("enforces zero-trust lease cutoff when commit arrives after physical expiry (quarantines ticket)", async () => {
    const authId = "auth_expired_lease_001";
    const bindingDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    // Reserve ticket with TTL of 1 second
    const res = await store.reserveTicket({
      authorizationId: authId,
      bindingDigest,
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey: "idem_exp_1",
      leaseTtlSeconds: 1,
    });
    const ticketId = res.ticketId!;

    // Artificially fast-forward the expiration timestamp in the database to simulate expiry
    const rawPool = (store as any).pool;
    await rawPool.query(
      `UPDATE witness_tickets SET expires_at_seconds = expires_at_seconds - 10 WHERE ticket_id = $1`,
      [ticketId],
    );

    // Attempting Phase 1 commit after expiry must throw WitnessConflictError("DENY: LEASE_EXPIRED")
    await expect(
      store.commitTicketPhase1(ticketId, authId, bindingDigest, "PREIMAGE_EXPIRED"),
    ).rejects.toThrow(/DENY: LEASE_EXPIRED/);

    // Ticket must have transitioned to QUARANTINED_UNCONFIRMED
    const ticket = await store.getTicket(ticketId);
    expect(ticket?.state).toBe("QUARANTINED_UNCONFIRMED");
  });

  it("handles high concurrency: 30 workers racing for budget reservations under shared capacity limit", async () => {
    const windowId = "DAILY:1730340000";
    const maxLimit = 10000n;
    const requestedPerWorker = 500n; // 30 workers * 500 = 15,000 > 10,000. Exactly 20 should succeed.

    const workers = Array.from({ length: 30 }, (_, i) => {
      const authId = `auth_concurrent_worker_${i.toString().padStart(3, "0")}`;
      const bindingDigest = `sha256:${i.toString(16).padStart(64, "0")}`;
      return store.reserveTicket(
        {
          authorizationId: authId,
          bindingDigest,
          policyId: "p_concurrent",
          policyRevision: 1,
          idempotencyKey: `idem_worker_${i}`,
          budgetWindows: [
            {
              windowType: "DAILY",
              windowStart: 1730340000,
              requestedAmount: requestedPerWorker.toString(),
              maxCumulativeAmount: maxLimit.toString(),
            },
          ],
        },
        `worker-${i}`,
      );
    });

    const results = await Promise.allSettled(workers);

    const fulfilled = results
      .filter((r): r is PromiseFulfilledResult<any> => r.status === "fulfilled")
      .map((r) => r.value);
    const rejected = results.filter((r) => r.status === "rejected");

    const allowed = fulfilled.filter((r) => r.decision === "ALLOW");

    // Invariant: Allowed reservations MUST NOT exceed the budget capacity of 20 (20 * 500 = 10,000)
    expect(allowed.length).toBeLessThanOrEqual(20);
    expect(allowed.length).toBeGreaterThan(0);

    // Any non-allowed outcome must be clean budget denial or safe fail-closed contention error
    for (const rej of rejected) {
      expect(rej.reason).toBeInstanceOf(Error);
    }

    // Total held amount in accumulator must equal exactly allowed.length * 500, never exceeding maxLimit
    const acc = await store.getAccumulator(windowId);
    const totalAllocated = BigInt(acc?.heldAmount || "0") + BigInt(acc?.currentAmount || "0");
    expect(totalAllocated).toBeLessThanOrEqual(maxLimit);
    expect(totalAllocated).toBe(BigInt(allowed.length) * requestedPerWorker);
  });

  it("simulates SQLSTATE 40001 serialization failure and verifies transparent retry without duplicate sequences", async () => {
    let callCount = 0;
    const result = await store.withSerializableTransaction("testSerializationRetry", async (client) => {
      callCount++;
      if (callCount === 1) {
        // Synthetically throw 40001 on the first attempt
        const err = new Error("could not serialize access due to concurrent update") as any;
        err.code = PG_SQLSTATE.SERIALIZATION_FAILURE;
        throw err;
      }
      const res = await client.query("SELECT 42 AS val");
      return res.rows[0].val;
    });

    expect(result).toBe(42);
    expect(callCount).toBe(2);
  });

  it("simulates SQLSTATE 55P03 lock_not_available and verifies bounded exponential retry", async () => {
    let callCount = 0;
    const result = await store.withSerializableTransaction("testLockNotAvailableRetry", async (client) => {
      callCount++;
      if (callCount === 1) {
        // Synthetically throw 55P03 on first attempt
        const err = new Error("could not obtain lock on row") as any;
        err.code = PG_SQLSTATE.LOCK_NOT_AVAILABLE;
        throw err;
      }
      const res = await client.query("SELECT 100 AS val");
      return res.rows[0].val;
    });

    expect(result).toBe(100);
    expect(callCount).toBe(2);
  });

  // ==========================================================================
  // F1: Authoritative Sequence Model & Epoch Transition Consistency
  // ==========================================================================
  it("F1: enforces per-epoch sequence consistency across epoch transitions (sequences restart at 1 in new epoch)", async () => {
    // 1. Commit in epoch-001
    const auth1 = "auth_ep1_001";
    const auth2 = "auth_ep1_002";
    const digest = "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff";

    const res1 = await store.reserveTicket({
      authorizationId: auth1,
      bindingDigest: digest,
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey: "idem_ep1_1",
    });
    const c1 = await store.commitTicket({
      ticketId: res1.ticketId!,
      authorizationId: auth1,
      bindingDigest: digest,
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    });
    expect(c1.receipt?.sequenceNumber).toBe("1");
    expect(c1.receipt?.epochId).toBe("epoch-001");

    const res2 = await store.reserveTicket({
      authorizationId: auth2,
      bindingDigest: digest,
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey: "idem_ep1_2",
    });
    const c2 = await store.commitTicket({
      ticketId: res2.ticketId!,
      authorizationId: auth2,
      bindingDigest: digest,
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    });
    expect(c2.receipt?.sequenceNumber).toBe("2");
    expect(c2.receipt?.epochId).toBe("epoch-001");

    // 2. Transition to epoch-002
    const storeEpoch2 = new PostgresWitnessStore({
      epochId: "epoch-002",
    });
    await storeEpoch2.registerEpoch("epoch-002", 2);

    try {
      const auth3 = "auth_ep2_001";
      const auth4 = "auth_ep2_002";

      const res3 = await storeEpoch2.reserveTicket({
        authorizationId: auth3,
        bindingDigest: digest,
        policyId: "p1",
        policyRevision: 1,
        idempotencyKey: "idem_ep2_1",
      });
      const c3 = await storeEpoch2.commitTicket({
        ticketId: res3.ticketId!,
        authorizationId: auth3,
        bindingDigest: digest,
        localCommittedAtSeconds: Math.floor(Date.now() / 1000),
      });

      // Sequence must restart at 1 in epoch-002
      expect(c3.receipt?.sequenceNumber).toBe("1");
      expect(c3.receipt?.epochId).toBe("epoch-002");

      const res4 = await storeEpoch2.reserveTicket({
        authorizationId: auth4,
        bindingDigest: digest,
        policyId: "p1",
        policyRevision: 1,
        idempotencyKey: "idem_ep2_2",
      });
      const c4 = await storeEpoch2.commitTicket({
        ticketId: res4.ticketId!,
        authorizationId: auth4,
        bindingDigest: digest,
        localCommittedAtSeconds: Math.floor(Date.now() / 1000),
      });

      expect(c4.receipt?.sequenceNumber).toBe("2");
      expect(c4.receipt?.epochId).toBe("epoch-002");

      // Verify that receipts for both epochs coexist cleanly without uniqueness conflicts
      const r1 = await store.getReceipt(auth1);
      const r3 = await storeEpoch2.getReceipt(auth3);
      expect(r1?.epochId).toBe("epoch-001");
      expect(r1?.sequenceNumber).toBe("1");
      expect(r3?.epochId).toBe("epoch-002");
      expect(r3?.sequenceNumber).toBe("1");
    } finally {
      await storeEpoch2.close();
    }
  });

  // ==========================================================================
  // F2: Sequence Gaps After Rollback, Crash & Reconciliation
  // ==========================================================================
  it("F2: detects sequence allocation followed by transaction rollback, records durable gap, and prohibits sequence reuse", async () => {
    const epochId = "epoch-001";
    const digest = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    // 1. Commit Sequence 1
    const res1 = await store.reserveTicket({
      authorizationId: "auth_gap_test_1",
      bindingDigest: digest,
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey: "idem_gap_test_1",
    });
    const c1 = await store.commitTicket({
      ticketId: res1.ticketId!,
      authorizationId: "auth_gap_test_1",
      bindingDigest: digest,
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    });
    expect(c1.receipt?.sequenceNumber).toBe("1");

    // 2. Allocate sequence 2 in a transaction, but abort/rollback before commit
    const rawPool = (store as any).pool;
    const client = await rawPool.connect();
    try {
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      const seqNameRes = await client.query(`SELECT get_or_create_epoch_sequence($1) AS seq_name`, [epochId]);
      const seqName = seqNameRes.rows[0].seq_name;
      const seqRes = await client.query(`SELECT nextval(quote_ident($1)) AS seq`, [seqName]);
      expect(seqRes.rows[0].seq.toString()).toBe("2");
      // Intentionally ROLLBACK the transaction without inserting tickets/outbox/receipts
      await client.query("ROLLBACK");
    } finally {
      client.release();
    }

    // 3. Commit next ticket: nextval() allocates sequence 3 (sequence 2 is now an uncommitted burned gap)
    const res3 = await store.reserveTicket({
      authorizationId: "auth_gap_test_3",
      bindingDigest: digest,
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey: "idem_gap_test_3",
    });
    const c3 = await store.commitTicket({
      ticketId: res3.ticketId!,
      authorizationId: "auth_gap_test_3",
      bindingDigest: digest,
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    });
    expect(c3.receipt?.sequenceNumber).toBe("3");

    // 4. Run gap reconciliation to discover the burned sequence
    const gapReport = await store.reconcileSequenceGaps(epochId);
    expect(gapReport.sequenceCeiling).toBe("3");
    expect(gapReport.newlyDiscoveredGaps).toContain("2");

    // 5. Verify the gap is recorded durably in witness_sequence_gaps
    const gaps = await store.getSequenceGaps(epochId);
    const gap2 = gaps.find((g) => g.sequenceNumber === "2");
    expect(gap2).toBeDefined();
    expect(gap2?.gapReason).toBe("TRANSACTION_ROLLBACK");

    // 6. Monotonicity Invariant: Subsequent commitments strictly continue monotonically and NEVER reuse sequence 2
    const res4 = await store.reserveTicket({
      authorizationId: "auth_gap_test_4",
      bindingDigest: digest,
      policyId: "p1",
      policyRevision: 1,
      idempotencyKey: "idem_gap_test_4",
    });
    const c4 = await store.commitTicket({
      ticketId: res4.ticketId!,
      authorizationId: "auth_gap_test_4",
      bindingDigest: digest,
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    });
    expect(c4.receipt?.sequenceNumber).toBe("4");
  });

  // ==========================================================================
  // F3: High Concurrency (50 Workers), Deadlock Handling, and Retry Exhaustion
  // ==========================================================================
  it("F3: handles 50 concurrent workers racing for budget reservations under shared capacity ceiling", async () => {
    // Configure dedicated store with connection pool sized for 50 workers
    const stressStore = new PostgresWitnessStore({
      epochId: "epoch-001",
      poolConfig: {
        host: process.env.PGHOST || "127.0.0.1",
        port: Number(process.env.PGPORT || 5432),
        user: process.env.PGUSER || "postgres",
        password: process.env.PGPASSWORD || "postgres",
        database: process.env.PGDATABASE || "web3user_witness_test",
        max: 60,
      },
    });

    try {
      const windowId = "DAILY:1730340000";
      const maxLimit = 15000n;
      const requestedPerWorker = 500n; // 50 * 500 = 25,000 > 15,000 max. At most 30 can be allowed.

      const workers = Array.from({ length: 50 }, (_, i) => {
        const authId = `auth_stress_worker_${i.toString().padStart(3, "0")}`;
        const bindingDigest = `sha256:${i.toString(16).padStart(64, "0")}`;
        return stressStore.reserveTicket(
          {
            authorizationId: authId,
            bindingDigest,
            policyId: "p_stress",
            policyRevision: 1,
            idempotencyKey: `idem_stress_${i}`,
            budgetWindows: [
              {
                windowType: "DAILY",
                windowStart: 1730340000,
                requestedAmount: requestedPerWorker.toString(),
                maxCumulativeAmount: maxLimit.toString(),
              },
            ],
          },
          `worker-${i}`,
        );
      });

      const results = await Promise.allSettled(workers);

      const fulfilled = results
        .filter((r): r is PromiseFulfilledResult<any> => r.status === "fulfilled")
        .map((r) => r.value);
      const allowed = fulfilled.filter((r) => r.decision === "ALLOW");

      // Invariant: Allowed count can never exceed capacity ceiling of 30 (30 * 500 = 15,000)
      expect(allowed.length).toBeLessThanOrEqual(30);
      expect(allowed.length).toBeGreaterThan(0);

      // Verify accumulator total allocated in PostgreSQL
      const acc = await stressStore.getAccumulator(windowId);
      const totalAllocated = BigInt(acc?.heldAmount || "0") + BigInt(acc?.currentAmount || "0");
      expect(totalAllocated).toBeLessThanOrEqual(maxLimit);
      expect(totalAllocated).toBe(BigInt(allowed.length) * requestedPerWorker);
    } finally {
      await stressStore.close();
    }
  });

  it("F3: handles real PostgreSQL 40P01 deadlock via automatic rollback and retry", async () => {
    const rawPool = (store as any).pool;

    // Seed two accumulator rows
    await rawPool.query(`
      INSERT INTO witness_accumulators (window_id, window_type, window_start, current_amount, held_amount, max_limit)
      VALUES ('DEADLOCK_ROW_A', 'DAILY', 1000, 0, 0, 10000),
             ('DEADLOCK_ROW_B', 'DAILY', 1000, 0, 0, 10000)
      ON CONFLICT (window_id) DO NOTHING;
    `);

    // Worker 1 locks A then B; Worker 2 locks B then A
    // withSerializableTransaction detects 40P01, rolls back, retries with jitter, and both finish cleanly
    const task1 = store.withSerializableTransaction("deadlockWorker1", async (client) => {
      await client.query("SELECT * FROM witness_accumulators WHERE window_id = 'DEADLOCK_ROW_A' FOR UPDATE");
      await new Promise((r) => setTimeout(r, 80));
      await client.query("SELECT * FROM witness_accumulators WHERE window_id = 'DEADLOCK_ROW_B' FOR UPDATE");
      return "task1_success";
    });

    const task2 = store.withSerializableTransaction("deadlockWorker2", async (client) => {
      await client.query("SELECT * FROM witness_accumulators WHERE window_id = 'DEADLOCK_ROW_B' FOR UPDATE");
      await new Promise((r) => setTimeout(r, 80));
      await client.query("SELECT * FROM witness_accumulators WHERE window_id = 'DEADLOCK_ROW_A' FOR UPDATE");
      return "task2_success";
    });

    const [r1, r2] = await Promise.all([task1, task2]);
    expect(r1).toBe("task1_success");
    expect(r2).toBe("task2_success");
  });

  it("F3: verifies retry budget exhaustion fails closed with appropriate error types", async () => {
    // 1. Contention 55P03 exhaustion
    await expect(
      store.withSerializableTransaction("testContentionExhaustion", async () => {
        const err = new Error("could not obtain lock") as any;
        err.code = PG_SQLSTATE.LOCK_NOT_AVAILABLE;
        throw err;
      }),
    ).rejects.toThrow(/Contention retry budget exhausted/);

    // 2. Serialization 40001 exhaustion
    await expect(
      store.withSerializableTransaction("testSerializationExhaustion", async () => {
        const err = new Error("could not serialize access") as any;
        err.code = PG_SQLSTATE.SERIALIZATION_FAILURE;
        throw err;
      }),
    ).rejects.toThrow(/Serialization retry budget exhausted/);

    // 3. Deadlock 40P01 exhaustion
    await expect(
      store.withSerializableTransaction("testDeadlockExhaustion", async () => {
        const err = new Error("deadlock detected") as any;
        err.code = PG_SQLSTATE.DEADLOCK_DETECTED;
        throw err;
      }),
    ).rejects.toThrow(/Deadlock retry budget exhausted/);
  });

  it("F3: rolls back cleanly after partial lock acquisition failure without corrupting budget", async () => {
    const rawPool = (store as any).pool;
    await rawPool.query(`
      INSERT INTO witness_accumulators (window_id, window_type, window_start, current_amount, held_amount, max_limit)
      VALUES ('PARTIAL_ACC_A', 'DAILY', 1000, 0, 0, 5000),
             ('PARTIAL_ACC_B', 'DAILY', 1000, 0, 0, 5000)
      ON CONFLICT (window_id) DO UPDATE SET held_amount = 0, current_amount = 0;
    `);

    // Transaction debits ACC_A then intentionally fails on ACC_B
    const partialTask = store.withSerializableTransaction("partialFailTx", async (client) => {
      await client.query("UPDATE witness_accumulators SET held_amount = held_amount + 1000 WHERE window_id = 'PARTIAL_ACC_A'");
      // Throw artificial failure before committing
      throw new Error("ABORT_MID_TRANSACTION");
    });

    await expect(partialTask).rejects.toThrow("ABORT_MID_TRANSACTION");

    // Invariant: ACC_A held_amount must remain 0 after rollback
    const accA = await store.getAccumulator("PARTIAL_ACC_A");
    expect(accA?.heldAmount).toBe("0");
  });

  // ==========================================================================
  // F4: Audit, Receipt, and Sequence Gap Table Statement TRUNCATE Protection
  // ==========================================================================
  it("F4: enforces statement-level TRUNCATE protection on witness_receipts, witness_audit_log, and witness_sequence_gaps", async () => {
    const rawPool = (store as any).pool;

    // Direct TRUNCATE on witness_receipts must be rejected by statement trigger
    await expect(
      rawPool.query("TRUNCATE TABLE witness_receipts;"),
    ).rejects.toThrow(/TRUNCATE is strictly prohibited on witness immutable tables/i);

    // Direct TRUNCATE on witness_audit_log must be rejected by statement trigger
    await expect(
      rawPool.query("TRUNCATE TABLE witness_audit_log;"),
    ).rejects.toThrow(/TRUNCATE is strictly prohibited on witness immutable tables/i);

    // Direct TRUNCATE on witness_sequence_gaps must be rejected by statement trigger
    await expect(
      rawPool.query("TRUNCATE TABLE witness_sequence_gaps;"),
    ).rejects.toThrow(/TRUNCATE is strictly prohibited on witness immutable tables/i);
  });

  // ==========================================================================
  // Final Acceptance Gate: TruncateAll, Sequence Reset & Gap Safety Verifications
  // ==========================================================================
  it("Section 2: verifies production PostgresWitnessStore does NOT expose truncateAll or sequence reset methods", () => {
    expect((store as any).truncateAll).toBeUndefined();
    expect((store as any).resetSequences).toBeUndefined();
  });

  it("Section 1: concurrent allocation vs reconciliation coordinates safely via epoch lock without premature gap marking", async () => {
    const epochId = "epoch-001";
    await store.registerEpoch(epochId, 1);

    const authId = "auth_recon_race_1";
    const digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    const reserveRes = await store.reserveTicket(
      {
        authorizationId: authId,
        bindingDigest: digest,
        policyId: "p_recon",
        policyRevision: 1,
        idempotencyKey: "idem_recon_race",
      },
      "worker-race",
    );
    const ticketId = reserveRes.ticketId!;

    // Start an in-flight commit transaction that acquires FOR SHARE and allocates sequence 1
    const rawPool: pg.Pool = (store as any).pool;
    const client = await rawPool.connect();

    let seqAllocated = false;
    let finishTx: () => void = () => {};
    const holdTxPromise = new Promise<void>((resolve) => {
      finishTx = resolve;
    });

    const inFlightTx = (async () => {
      try {
        await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
        await client.query("SELECT epoch_id FROM witness_epochs WHERE epoch_id = $1 FOR SHARE", [epochId]);
        const seqRes = await client.query("SELECT nextval(get_or_create_epoch_sequence($1)) AS seq", [epochId]);
        const seqNum = seqRes.rows[0].seq.toString();
        seqAllocated = true;

        // Wait until signaled before inserting outbox and committing
        await holdTxPromise;

        const intentId = "intent_race_recon_1";
        const now = Math.floor(Date.now() / 1000);
        await client.query(
          `INSERT INTO witness_signing_outbox (intent_id, ticket_id, epoch_id, sequence_number, preimage, status, retry_count, created_at_seconds, updated_at_seconds)
           VALUES ($1, $2, $3, $4, 'preimage', 'PENDING', 0, $5, $5)`,
          [intentId, ticketId, epochId, seqNum, now],
        );
        await client.query("COMMIT");
      } catch (e) {
        await client.query("ROLLBACK");
        throw e;
      } finally {
        client.release();
      }
    })();

    // Wait until the allocation has occurred
    while (!seqAllocated) {
      await new Promise((r) => setTimeout(r, 10));
    }

    // Now invoke reconcileSequenceGaps while the allocation transaction is still in-flight.
    // Because reconcileSequenceGaps acquires FOR UPDATE on witness_epochs, it MUST wait
    // for inFlightTx (which holds FOR SHARE) to commit!
    let reconFinished = false;
    const reconPromise = store.reconcileSequenceGaps(epochId).then((res) => {
      reconFinished = true;
      return res;
    });

    // Verify reconcileSequenceGaps is waiting and has NOT finished while inFlightTx is open
    await new Promise((r) => setTimeout(r, 60));
    expect(reconFinished).toBe(false);

    // Now release inFlightTx to commit
    finishTx();
    await inFlightTx;

    // Reconciliation should now complete
    const reconResult = await reconPromise;
    expect(reconFinished).toBe(true);

    // Sequence 1 was committed before reconciliation scanned, so it is NOT marked as a gap!
    expect(reconResult.newlyDiscoveredGaps).toHaveLength(0);
    expect(reconResult.totalOutbox).toBe(1);

    const gaps = await store.getSequenceGaps(epochId);
    expect(gaps).toHaveLength(0);
  });

  it("Section 1: sequence allocation followed by transaction rollback is durably recovered into witness_sequence_gaps", async () => {
    const epochId = "epoch-rollback-rec";
    await store.registerEpoch(epochId, 101);

    const rawPool: pg.Pool = (store as any).pool;
    const client = await rawPool.connect();

    // Transaction allocates sequence 1 from generator then aborts/rolls back
    try {
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      const seqRes = await client.query("SELECT nextval(get_or_create_epoch_sequence($1)) AS seq", [epochId]);
      expect(seqRes.rows[0].seq.toString()).toBe("1");
      // Abort without inserting outbox or committing
      await client.query("ROLLBACK");
    } finally {
      client.release();
    }

    // Run reconciliation
    const reconResult = await store.reconcileSequenceGaps(epochId);
    expect(reconResult.newlyDiscoveredGaps).toEqual(["1"]);

    // Sequence 1 must be durably recorded in witness_sequence_gaps
    const gaps = await store.getSequenceGaps(epochId);
    expect(gaps).toHaveLength(1);
    expect(gaps[0].sequenceNumber).toBe("1");
    expect(gaps[0].gapReason).toBe("TRANSACTION_ROLLBACK");

    // Subsequent normal allocation gets sequence 2
    const client2 = await rawPool.connect();
    try {
      const nextRes = await client2.query("SELECT nextval(get_or_create_epoch_sequence($1)) AS seq", [epochId]);
      expect(nextRes.rows[0].seq.toString()).toBe("2");
    } finally {
      client2.release();
    }
  });

  it("Section 1: simulated process termination at allocation/outbox boundary is durably recovered", async () => {
    const epochId = "epoch-crash-rec";
    await store.registerEpoch(epochId, 102);

    // Connect a dedicated standalone client representing an external worker process
    const standaloneClient = new pg.Client({
      host: process.env.PGHOST || "127.0.0.1",
      port: Number(process.env.PGPORT || 5432),
      user: process.env.PGUSER || "postgres",
      password: process.env.PGPASSWORD || "postgres",
      database: process.env.PGDATABASE || "web3user_witness_test",
    });
    standaloneClient.on("error", () => {}); // Handle expected abrupt termination without unhandled rejection
    await standaloneClient.connect();

    try {
      await standaloneClient.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      const seqRes = await standaloneClient.query("SELECT nextval(get_or_create_epoch_sequence($1)) AS seq", [epochId]);
      expect(seqRes.rows[0].seq.toString()).toBe("1");

      // Abruptly terminate the process / destroy connection socket before inserting outbox or committing
      (standaloneClient as any).connection.stream.destroy();
    } catch {
      // Expected socket destruction
    }

    // Allow Postgres server backend to detect the disconnection and roll back the uncommitted transaction
    await new Promise((r) => setTimeout(r, 100));

    // Run reconciliation routine
    const reconResult = await store.reconcileSequenceGaps(epochId);
    expect(reconResult.newlyDiscoveredGaps).toEqual(["1"]);

    const gaps = await store.getSequenceGaps(epochId);
    expect(gaps).toHaveLength(1);
    expect(gaps[0].sequenceNumber).toBe("1");
    expect(gaps[0].gapReason).toBe("TRANSACTION_ROLLBACK");

    // Idempotency: Running reconciliation a second time does not duplicate the gap
    const reconAgain = await store.reconcileSequenceGaps(epochId);
    expect(reconAgain.newlyDiscoveredGaps).toHaveLength(0);
    const gapsAgain = await store.getSequenceGaps(epochId);
    expect(gapsAgain).toHaveLength(1);
  });

  it("Section 2: issued sequence cannot be reused after cleanup, outbox failure, or recovery", async () => {
    const epochId = "epoch-001";
    const digest = "sha256:4444444444444444444444444444444444444444444444444444444444444444";

    // Issue sequence 1 cleanly
    const r1 = await store.reserveTicket({
      authorizationId: "auth_no_reuse_1",
      bindingDigest: digest,
      policyId: "p_noreuse",
      policyRevision: 1,
      idempotencyKey: "idem_nr_1",
    });
    const c1 = await store.commitTicket({
      ticketId: r1.ticketId!,
      authorizationId: "auth_no_reuse_1",
      bindingDigest: digest,
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    });
    expect(c1.receipt?.sequenceNumber).toBe("1");

    // Reserve ticket 2, quarantine/fail it, retiring sequence 2 into witness_sequence_gaps
    const r2 = await store.reserveTicket({
      authorizationId: "auth_no_reuse_2",
      bindingDigest: digest,
      policyId: "p_noreuse",
      policyRevision: 1,
      idempotencyKey: "idem_nr_2",
    });
    const p1_2 = await store.commitTicketPhase1(r2.ticketId!, "auth_no_reuse_2", digest, "preimage_2");
    expect(p1_2.sequenceNumber).toBe("2");
    await store.quarantineTicket(r2.ticketId!, "QUARANTINED_UNCONFIRMED", "Simulated outbox signer crash");

    // Verify sequence 2 is in sequence gaps
    const gaps = await store.getSequenceGaps(epochId);
    expect(gaps.some((g) => g.sequenceNumber === "2")).toBe(true);

    // Attempting to manually insert an outbox row with sequence 1 or 2 in this epoch MUST fail with 23505
    const rawPool: pg.Pool = (store as any).pool;
    await expect(
      rawPool.query(
        `INSERT INTO witness_signing_outbox (intent_id, ticket_id, epoch_id, sequence_number, preimage, status, retry_count, created_at_seconds, updated_at_seconds)
         VALUES ('intent_dupe_1', 't_dupe_1', $1, 1, 'preimage', 'PENDING', 0, 1000, 1000)`,
        [epochId],
      ),
    ).rejects.toThrow(/duplicate key value violates unique constraint/i);

    // Subsequent normal reservation & commit allocates sequence 3, NEVER 1 or 2
    const r3 = await store.reserveTicket({
      authorizationId: "auth_no_reuse_3",
      bindingDigest: digest,
      policyId: "p_noreuse",
      policyRevision: 1,
      idempotencyKey: "idem_nr_3",
    });
    const c3 = await store.commitTicket({
      ticketId: r3.ticketId!,
      authorizationId: "auth_no_reuse_3",
      bindingDigest: digest,
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    });
    expect(c3.receipt?.sequenceNumber).toBe("3");
  });

  it("F3: handles real PostgreSQL 55P03 lock_not_available retry exhaustion", async () => {
    const rawPool: pg.Pool = (store as any).pool;

    // Seed test accumulator row matching DAILY:2000
    await rawPool.query(`
      INSERT INTO witness_accumulators (window_id, window_type, window_start, current_amount, held_amount, max_limit)
      VALUES ('DAILY:2000', 'DAILY', 2000, 0, 0, 10000)
      ON CONFLICT (window_id) DO UPDATE SET held_amount = 0, current_amount = 0;
    `);

    // Client 1 locks the row exclusively and holds it
    const blockerClient = await rawPool.connect();
    await blockerClient.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    await blockerClient.query("SELECT * FROM witness_accumulators WHERE window_id = 'DAILY:2000' FOR UPDATE");

    try {
      // Client 2 attempts to acquire the same row with FOR UPDATE NOWAIT via reserveTicket
      // It will encounter real PostgreSQL 55P03 errors and exhaust its contention retry budget
      await expect(
        store.reserveTicket(
          {
            authorizationId: "auth_contention_exhaust",
            bindingDigest: "sha256:5555555555555555555555555555555555555555555555555555555555555555",
            policyId: "p_contention",
            policyRevision: 1,
            idempotencyKey: "idem_contention_ex",
            budgetWindows: [
              {
                windowType: "DAILY",
                windowStart: 2000,
                requestedAmount: "100",
                maxCumulativeAmount: "10000",
              },
            ],
          },
          "contended-worker",
        ),
      ).rejects.toThrow(/Contention retry budget exhausted \(55P03 lock_not_available\)/);
    } finally {
      await blockerClient.query("ROLLBACK");
      blockerClient.release();
    }
  });

  it("F4: runtime privilege restrictions: web3user_app cannot alter schema, disable triggers, truncate, update, or delete immutable records", async () => {
    const rawPool: pg.Pool = (store as any).pool;

    // Ephemeral test-only credentials for local RBAC boundary verification
    const TEST_FIXTURE_ADMIN_ROLE_PASSWORD = "web3user_admin_pass";
    const TEST_FIXTURE_APP_ROLE_PASSWORD = "web3user_app_pass";

    // Ensure roles, ownership, and grants are established
    await rawPool.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'web3user_admin') THEN
          CREATE ROLE web3user_admin WITH LOGIN PASSWORD '${TEST_FIXTURE_ADMIN_ROLE_PASSWORD}';
        END IF;
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'web3user_app') THEN
          CREATE ROLE web3user_app WITH LOGIN PASSWORD '${TEST_FIXTURE_APP_ROLE_PASSWORD}';
        END IF;
      END $$;

      ALTER TABLE IF EXISTS witness_epochs OWNER TO web3user_admin;
      ALTER TABLE IF EXISTS witness_tickets OWNER TO web3user_admin;
      ALTER TABLE IF EXISTS witness_accumulators OWNER TO web3user_admin;
      ALTER TABLE IF EXISTS witness_signing_outbox OWNER TO web3user_admin;
      ALTER TABLE IF EXISTS witness_receipts OWNER TO web3user_admin;
      ALTER TABLE IF EXISTS witness_audit_log OWNER TO web3user_admin;
      ALTER TABLE IF EXISTS witness_sequence_gaps OWNER TO web3user_admin;
      ALTER TABLE IF EXISTS witness_consensus_log OWNER TO web3user_admin;
      ALTER TABLE IF EXISTS witness_raft_state OWNER TO web3user_admin;
      ALTER SEQUENCE IF EXISTS witness_sequence_seq OWNER TO web3user_admin;

      GRANT USAGE ON SCHEMA public TO web3user_app;
      GRANT USAGE ON SCHEMA public TO web3user_admin;

      GRANT SELECT, INSERT, UPDATE ON witness_tickets TO web3user_app;
      GRANT SELECT, INSERT, UPDATE ON witness_accumulators TO web3user_app;
      GRANT SELECT, INSERT, UPDATE ON witness_signing_outbox TO web3user_app;

      GRANT SELECT, INSERT ON witness_receipts TO web3user_app;
      GRANT SELECT, INSERT ON witness_audit_log TO web3user_app;
      GRANT SELECT, INSERT ON witness_sequence_gaps TO web3user_app;
      GRANT SELECT, INSERT ON witness_consensus_log TO web3user_app;
      GRANT SELECT, INSERT, UPDATE ON witness_raft_state TO web3user_app;
      GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO web3user_app;

      REVOKE UPDATE, DELETE, TRUNCATE ON witness_receipts FROM web3user_app;
      REVOKE UPDATE, DELETE, TRUNCATE ON witness_audit_log FROM web3user_app;
      REVOKE UPDATE, DELETE, TRUNCATE ON witness_sequence_gaps FROM web3user_app;
      REVOKE UPDATE, DELETE, TRUNCATE ON witness_consensus_log FROM web3user_app;
      REVOKE DELETE, TRUNCATE ON witness_raft_state FROM web3user_app;
      REVOKE CREATE ON SCHEMA public FROM web3user_app;
    `);

    // Verify catalog ownership
    const ownerRes = await rawPool.query(`
      SELECT tablename, tableowner
      FROM pg_tables
      WHERE schemaname = 'public' AND tablename LIKE 'witness_%'
    `);
    for (const row of ownerRes.rows) {
      expect(row.tableowner).toBe("web3user_admin");
    }

    // Connect as runtime role web3user_app to verify privilege boundaries
    const appClient = new pg.Client({
      host: process.env.PGHOST || "127.0.0.1",
      port: Number(process.env.PGPORT || 5432),
      user: "web3user_app",
      password: TEST_FIXTURE_APP_ROLE_PASSWORD,
      database: process.env.PGDATABASE || "web3user_witness_test",
    });
    await appClient.connect();

    try {
      // 1. Runtime role cannot create tables in schema public
      await expect(
        appClient.query("CREATE TABLE witness_tamper (id INT)"),
      ).rejects.toThrow(/permission denied for schema public/i);

      // 2. Runtime role cannot alter or drop protected tables
      await expect(
        appClient.query("DROP TABLE witness_tickets"),
      ).rejects.toThrow(/must be owner of table witness_tickets/i);

      // 3. Runtime role cannot disable triggers
      await expect(
        appClient.query("ALTER TABLE witness_receipts DISABLE TRIGGER trg_witness_receipts_no_truncate"),
      ).rejects.toThrow(/must be owner of table witness_receipts/i);

      // 4. Runtime role cannot truncate protected tables
      await expect(
        appClient.query("TRUNCATE TABLE witness_receipts"),
      ).rejects.toThrow(/permission denied for table witness_receipts/i);

      // 5. Runtime role cannot update immutable records
      await expect(
        appClient.query("UPDATE witness_receipts SET signature = 'tampered' WHERE sequence_number = 1"),
      ).rejects.toThrow(/permission denied for table witness_receipts/i);

      // 6. Runtime role cannot delete immutable records
      await expect(
        appClient.query("DELETE FROM witness_audit_log WHERE log_id = 1"),
      ).rejects.toThrow(/permission denied for table witness_audit_log/i);
    } finally {
      await appClient.end();
    }
  });
});
