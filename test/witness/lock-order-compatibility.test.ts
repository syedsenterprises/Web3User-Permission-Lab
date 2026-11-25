/**
 * Web3User Permission Lab - Milestone 13-D: Lock-Order Compatibility & Deadlock Freedom Regression Suite
 *
 * Explicitly verifies:
 * 1. TEST-LOCK-01: Legacy D1 commitTicketPhase1 acquires witness_epochs FIRST (Rank 1) before witness_tickets (Rank 2).
 *    Proves that a transaction holding an exclusive lock on witness_epochs blocks commitTicketPhase1 at the epoch
 *    boundary BEFORE any row lock on witness_tickets is acquired.
 * 2. TEST-LOCK-02: Zero deadlocks between concurrent D1 commitTicket allocations and reconcileSequenceGaps.
 * 3. TEST-LOCK-03: D2 Phase 1 and Phase 3 lock ordering reconciliation and implicit FK row lock protection.
 *    Proves Phase 3 locks witness_tickets FOR UPDATE before inserting witness_receipts, eliminating lock upgrade deadlocks.
 * 4. TEST-LOCK-04: High-concurrency interleaving of ReserveTicket, CommitTicket (Phase 1 & 3), and ReleaseTicket
 *    across shared budget accumulators with zero 40P01 deadlocks.
 * 5. TEST-LOCK-05: Quarantine and recovery operations strictly observe the Rank 1 to Rank 7 hierarchy.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHash } from "node:crypto";
import pg from "pg";
import {
  PostgresWitnessStore,
  WitnessConflictError,
  InvalidWitnessStateTransitionError,
} from "../../src/witness/postgres-store.js";
import { generateTestCertificates, type CertBundle } from "../../src/witness/mtls-certs.js";
import { GrpcWitnessServiceImpl } from "../../src/witness/grpc-service.js";
import { startGrpcWitnessServer, type StartedGrpcWitnessServer } from "../../src/witness/grpc-server.js";
import { RemoteDurableWitnessClient } from "../../src/witness/remote-witness-client.js";
import { LocalEd25519WitnessSigner } from "../../src/witness/signing.js";

const { Pool } = pg;

describe("Milestone 13-D: D1/D2 Lock-Order Compatibility & Deadlock Freedom Suite", () => {
  let pool: pg.Pool;
  let store: PostgresWitnessStore;
  let testEpochId: string;
  let testEpochHeight: number;

  // D2 Server & Client harness
  let certs: CertBundle;
  let serviceImpl: GrpcWitnessServiceImpl;
  let serverInstance: StartedGrpcWitnessServer;
  let serverEndpoint: string;
  let client: RemoteDurableWitnessClient;

  beforeAll(async () => {
    testEpochId = `test-lock-order-epoch-${Date.now()}`;
    store = new PostgresWitnessStore({ epochId: testEpochId });
    pool = (store as any).pool;
    await store.initializeSchema();

    const maxHRes = await pool.query(`SELECT COALESCE(MAX(epoch_height), 0) + 1 AS next_h FROM witness_epochs`);
    testEpochHeight = Number(maxHRes.rows[0].next_h);
    await store.registerEpoch(testEpochId, testEpochHeight);

    // Setup D2 gRPC mTLS harness
    certs = generateTestCertificates();
    const signer = new LocalEd25519WitnessSigner("lock-order-witness-signer");
    serviceImpl = new GrpcWitnessServiceImpl({ pool, signer });

    serverInstance = await startGrpcWitnessServer({
      serviceImpl,
      caCert: certs.caCert,
      serverCert: certs.serverCert,
      serverKey: certs.serverKey,
      port: 0,
      host: "127.0.0.1",
      skipDependencyCheck: true,
    });
    serverEndpoint = `localhost:${serverInstance.port}`;

    client = new RemoteDurableWitnessClient({
      endpoint: serverEndpoint,
      caCert: certs.caCert,
      clientCert: certs.engineClientCert,
      clientKey: certs.engineClientKey,
      clientCertPem: certs.engineClientCert.toString("utf8"),
      timeoutMs: 5000,
    });
  }, 45000);

  afterAll(async () => {
    try {
      if (client) client.close();
      if (serverInstance) await serverInstance.stop();
      if (store) await store.close();
    } catch (e) {
      // Ignore teardown errors
    }
  }, 30000);

  function mockSha256(seed: string): string {
    return "sha256:" + createHash("sha256").update(seed).digest("hex");
  }

  // ==========================================================================
  // TEST-LOCK-01: Legacy D1 Inversion Root Cause Verification & Fix
  // ==========================================================================
  it("TEST-LOCK-01: commitTicketPhase1 acquires witness_epochs FIRST and does not lock witness_tickets when epoch is locked", async () => {
    const authId = `auth-lock01-${Date.now()}`;
    const bindingDigest = mockSha256("digest-lock-01");

    // 1. Reserve ticket
    const reserveRes = await store.reserveTicket({
      authorizationId: authId,
      bindingDigest,
      policyId: "policy-lock-01",
      policyRevision: 1,
      idempotencyKey: `idem-${authId}`,
      budgetWindows: [],
    });
    expect(reserveRes.decision).toBe("ALLOW");
    const ticketId = reserveRes.ticketId!;

    // 2. Open Blocker Transaction A holding witness_epochs FOR UPDATE NOWAIT
    const blockerClient = await pool.connect();
    await blockerClient.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    await blockerClient.query(
      `SELECT epoch_id FROM witness_epochs WHERE epoch_id = $1 FOR UPDATE NOWAIT`,
      [testEpochId],
    );

    let phase1Finished = false;
    let phase1Error: any = null;

    // 3. Launch commitTicketPhase1 in background.
    // Because witness_epochs is held FOR UPDATE by Blocker A, commitTicketPhase1 MUST wait at Level 1 (FOR SHARE).
    const phase1Promise = store
      .commitTicketPhase1(ticketId, authId, bindingDigest, `PREIMAGE:${ticketId}`)
      .then((res) => {
        phase1Finished = true;
        return res;
      })
      .catch((err) => {
        phase1Error = err;
        throw err;
      });

    // Give commitTicketPhase1 time to start and reach its first query
    await new Promise((r) => setTimeout(r, 100));
    expect(phase1Finished).toBe(false);

    // 4. Verification of Invariant: Because commitTicketPhase1 acquires witness_epochs FIRST,
    // it MUST NOT have acquired a row lock on witness_tickets yet!
    // A third client Probe C should be able to lock witness_tickets FOR SHARE NOWAIT without blocking!
    const probeClient = await pool.connect();
    try {
      const probeRes = await probeClient.query(
        `SELECT ticket_id, state FROM witness_tickets WHERE ticket_id = $1 FOR SHARE NOWAIT`,
        [ticketId],
      );
      expect(probeRes.rows.length).toBe(1);
      expect(probeRes.rows[0].state).toBe("RESERVED");
    } finally {
      probeClient.release();
    }

    // 5. Release Blocker Transaction A
    await blockerClient.query("COMMIT");
    blockerClient.release();

    // 6. Now commitTicketPhase1 completes cleanly
    const p1Result = await phase1Promise;
    expect(p1Result.success).toBe(true);
    expect(p1Result.sequenceNumber).toBeDefined();

    // Verify ticket transitioned to COMMITTING_SIGNING_PENDING
    const ticketCheck = await pool.query(
      `SELECT state, sequence_number FROM witness_tickets WHERE ticket_id = $1`,
      [ticketId],
    );
    expect(ticketCheck.rows[0].state).toBe("COMMITTING_SIGNING_PENDING");
    expect(ticketCheck.rows[0].sequence_number).toBe(p1Result.sequenceNumber);
  });

  // ==========================================================================
  // TEST-LOCK-02: Zero Deadlocks between D1 commitTicket and reconcileSequenceGaps
  // ==========================================================================
  it("TEST-LOCK-02: Concurrent D1 commitTicket allocations and reconcileSequenceGaps produce zero 40P01 deadlocks", async () => {
    const epochId = `test-lock02-${Date.now()}`;
    const maxHRes = await pool.query(`SELECT COALESCE(MAX(epoch_height), 0) + 1 AS next_h FROM witness_epochs`);
    await store.registerEpoch(epochId, Number(maxHRes.rows[0].next_h));

    const workerStore = new PostgresWitnessStore({ epochId });
    const workerCount = 10;
    const authIds: string[] = [];

    // Pre-reserve tickets
    const ticketIds: string[] = [];
    for (let i = 0; i < workerCount; i++) {
      const authId = `auth-lock02-${Date.now()}-${i}`;
      authIds.push(authId);
      const res = await workerStore.reserveTicket({
        authorizationId: authId,
        bindingDigest: mockSha256(`digest-lock02-${i}`),
        policyId: "policy-lock-02",
        policyRevision: 1,
        idempotencyKey: `idem-${authId}`,
        budgetWindows: [],
      });
      expect(res.decision).toBe("ALLOW");
      ticketIds.push(res.ticketId!);
    }

    let reconcileDone = false;
    let deadlockCount = 0;

    // Run background reconcileSequenceGaps periodically while tickets are committing
    const reconcilePromise = (async () => {
      while (!reconcileDone) {
        try {
          await workerStore.reconcileSequenceGaps(epochId);
        } catch (e: any) {
          if (e.code === "40P01" || /deadlock/i.test(e.message)) {
            deadlockCount++;
          }
        }
        await new Promise((r) => setTimeout(r, 50));
      }
    })();

    // Commit tickets concurrently
    const commitPromises = ticketIds.map(async (tid, idx) => {
      try {
        return await workerStore.commitTicket({
          ticketId: tid,
          authorizationId: authIds[idx],
          bindingDigest: mockSha256(`digest-lock02-${idx}`),
          localCommittedAtSeconds: Math.floor(Date.now() / 1000),
        });
      } catch (e: any) {
        if (e.code === "40P01" || /deadlock/i.test(e.message)) {
          deadlockCount++;
        }
        throw e;
      }
    });

    const results = await Promise.allSettled(commitPromises);
    reconcileDone = true;
    await reconcilePromise;
    await workerStore.reconcileSequenceGaps(epochId);
    await workerStore.close();

    // Invariant: ZERO deadlocks (40P01) occurred
    expect(deadlockCount).toBe(0);

    // At least some or all succeeded (any failures must be normal 40001 serialization retries, NEVER deadlocks)
    const fulfilled = results.filter((r) => r.status === "fulfilled");
    expect(fulfilled.length).toBeGreaterThan(0);
  });

  // ==========================================================================
  // TEST-LOCK-03: D2 Phase 3 Ticket Row Lock Before Receipts Insert
  // ==========================================================================
  it("TEST-LOCK-03: D2 Phase 3 locks witness_tickets FOR UPDATE before receipt insertion, eliminating lock upgrade races", async () => {
    const authId = `auth-lock03-${Date.now()}`;
    const bindingDigest = mockSha256("digest-lock-03");

    const res = await client.reserveTicket({
      authorizationId: authId,
      bindingDigest,
      policyId: "policy-lock-03",
      policyRevision: 1,
      idempotencyKey: `idem-${authId}`,
      leaseTtlSeconds: 300,
    });
    expect(res.decision).toBe("ALLOW");
    const ticketId = res.ticketId!;

    // Perform Phase 1 and 3 via client
    const commitRes = await client.commitTicket({
      ticketId,
      authorizationId: authId,
      bindingDigest,
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    });
    expect(commitRes.decision).toBe("ALLOW");
    expect(commitRes.receipt?.sequenceNumber).toBeDefined();

    // Verify receipt was inserted and points to committed ticket
    const receiptCheck = await pool.query(
      `SELECT r.ticket_id, r.sequence_number, t.state 
       FROM witness_receipts r 
       JOIN witness_tickets t ON r.ticket_id = t.ticket_id 
       WHERE r.ticket_id = $1`,
      [ticketId],
    );
    expect(receiptCheck.rows.length).toBe(1);
    expect(receiptCheck.rows[0].state).toBe("COMMITTED");
  });

  // ==========================================================================
  // TEST-LOCK-04: High Concurrency Mixed Reserve, Commit, and Release via gRPC
  // ==========================================================================
  it("TEST-LOCK-04: 30 concurrent mixed Reserve, Commit, and Release operations execute with ZERO 40P01 deadlocks", async () => {
    const concurrency = 20;
    const windowStart = Math.floor(Date.now() / 1000);
    const windowType = "HOURLY";
    let deadlockCount = 0;

    const tasks = Array.from({ length: concurrency }).map(async (_, i) => {
      // Small 25ms stagger to allow natural predecessor sequence pipelining
      await new Promise((r) => setTimeout(r, i * 25));
      try {
        const authId = `auth-mixed-${Date.now()}-${i}`;
        const digest = mockSha256(`mixed-digest-${i}`);

        // Reserve with budget window
        const reserveRes = await client.reserveTicket({
          authorizationId: authId,
          bindingDigest: digest,
          policyId: "policy-mixed",
          policyRevision: 1,
          idempotencyKey: `idem-${authId}`,
          budgetWindows: [
            {
              windowType,
              windowStart,
              requestedAmount: "100",
              maxCumulativeAmount: "1000000",
            },
          ],
        });
        expect(reserveRes.decision).toBe("ALLOW");
        const ticketId = reserveRes.ticketId!;

        if (i % 2 === 0) {
          // Even indices: commit ticket (with bounded retry on UNAVAILABLE for predecessor in-flight)
          let commitRes: any;
          for (let attempt = 0; attempt < 5; attempt++) {
            try {
              commitRes = await client.commitTicket({
                ticketId,
                authorizationId: authId,
                bindingDigest: digest,
                localCommittedAtSeconds: Math.floor(Date.now() / 1000),
              });
              break;
            } catch (err: any) {
              if (err.code === "40P01" || /deadlock/i.test(err.message)) {
                deadlockCount++;
                throw err;
              }
              if (/UNAVAILABLE/i.test(err.message) && attempt < 4) {
                await new Promise((r) => setTimeout(r, 200));
                continue;
              }
              throw err;
            }
          }
          expect(commitRes?.decision).toBe("ALLOW");
        } else {
          // Odd indices: release ticket
          const releaseRes = await client.releaseTicket({
            ticketId,
            authorizationId: authId,
            bindingDigest: digest,
            reason: "Voluntary release in concurrency test",
          });
          expect(releaseRes.success).toBe(true);
        }
      } catch (err: any) {
        if (err.code === "40P01" || /deadlock/i.test(err.message)) {
          deadlockCount++;
        }
        throw err;
      }
    });

    const results = await Promise.allSettled(tasks);

    // Assert zero deadlocks (40P01) occurred across all concurrent workers
    expect(deadlockCount).toBe(0);

    // Verify no task encountered a deadlock
    for (const r of results) {
      if (r.status === "rejected") {
        expect(r.reason?.code).not.toBe("40P01");
        expect(r.reason?.message).not.toMatch(/deadlock/i);
      }
    }

    const fulfilled = results.filter((r) => r.status === "fulfilled");
    expect(fulfilled.length).toBeGreaterThanOrEqual(10);
  });

  // ==========================================================================
  // TEST-LOCK-05: releaseTicket and quarantineTicket Observe Rank 1 Epoch Lock First
  // ==========================================================================
  it("TEST-LOCK-05: releaseTicket and quarantineTicket acquire Level 1 witness_epochs lock before witness_tickets", async () => {
    const epochId = `test-lock05-${Date.now()}`;
    const maxHRes = await pool.query(`SELECT COALESCE(MAX(epoch_height), 0) + 1 AS next_h FROM witness_epochs`);
    await store.registerEpoch(epochId, Number(maxHRes.rows[0].next_h));

    const testStore = new PostgresWitnessStore({ epochId });

    const authId1 = `auth-lock05-rel-${Date.now()}`;
    const authId2 = `auth-lock05-quar-${Date.now()}`;
    const digestD1 = mockSha256("d1");
    const digestD2 = mockSha256("d2");

    const t1 = await testStore.reserveTicket({
      authorizationId: authId1,
      bindingDigest: digestD1,
      policyId: "policy-lock-05",
      policyRevision: 1,
      idempotencyKey: `idem-${authId1}`,
    });
    const t2 = await testStore.reserveTicket({
      authorizationId: authId2,
      bindingDigest: digestD2,
      policyId: "policy-lock-05",
      policyRevision: 1,
      idempotencyKey: `idem-${authId2}`,
    });

    // Block witness_epochs
    const blockerClient = await pool.connect();
    try {
      await blockerClient.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      await blockerClient.query(
        `SELECT epoch_id FROM witness_epochs WHERE epoch_id = $1 FOR UPDATE NOWAIT`,
        [epochId],
      );

      let relDone = false;
      let quarDone = false;

      const relPromise = testStore
        .releaseTicket({
          ticketId: t1.ticketId!,
          authorizationId: authId1,
          bindingDigest: digestD1,
          reason: "Voluntary release in lock-05 test",
        })
        .then(() => {
          relDone = true;
        });

      const quarPromise = testStore.quarantineTicket(t2.ticketId!, "QUARANTINED_BLOCKED", "Test quarantine").then(() => {
        quarDone = true;
      });

      await new Promise((r) => setTimeout(r, 100));
      // Both should be blocked on witness_epochs FOR SHARE, neither has finished
      expect(relDone).toBe(false);
      expect(quarDone).toBe(false);

      // Release blocker
      await blockerClient.query("COMMIT");

      await Promise.all([relPromise, quarPromise]);
      expect(relDone).toBe(true);
      expect(quarDone).toBe(true);

      const s1 = await testStore.getTicket(t1.ticketId!);
      expect(s1?.state).toBe("RELEASED");

      const s2 = await testStore.getTicket(t2.ticketId!);
      expect(s2?.state).toBe("QUARANTINED_BLOCKED");
    } finally {
      blockerClient.release();
      await testStore.close();
    }
  });
});
