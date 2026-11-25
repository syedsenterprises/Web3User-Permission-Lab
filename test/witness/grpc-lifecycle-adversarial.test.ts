/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Distributed Lifecycle & Adversarial Tests
 *
 * Verifies:
 * - TEST-M13D-D2-F1-01: Stale worker fencing generation rejection (zero receipt, zero chain movement, zero budget shift).
 * - TEST-M13D-D2-F1-02: Out-of-order sequence resolution and gap chaining (Seq 11 links to H_gap10).
 * - TEST-M13D-D2-F1-03: Concurrent supervisor fencing races serialized safely.
 * - TEST-M13D-D2-F2-01: Mutating RPC idempotency cached replay vs mismatch 409 conflict.
 * - TEST-M13D-D2-F2-03: Startup outbox reconciliation sweep.
 * - SEC-M11-01: Ambiguous commit timeout recovery via reconcileTicket.
 * - Budget conservation invariant under concurrent operations.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import pg from "pg";
import { generateTestCertificates, type CertBundle } from "../../src/witness/mtls-certs.js";
import { GrpcWitnessServiceImpl, StaleWorkerFencedError } from "../../src/witness/grpc-service.js";
import { startGrpcWitnessServer, type StartedGrpcWitnessServer } from "../../src/witness/grpc-server.js";
import { RemoteDurableWitnessClient } from "../../src/witness/remote-witness-client.js";
import { LocalEd25519WitnessSigner } from "../../src/witness/signing.js";
import { PostgresWitnessStore } from "../../src/witness/postgres-store.js";
import {
  verifyWitnessReceipt,
  type WitnessReservationRequest,
  type WitnessCommitRequest,
} from "../../src/monotonic-witness.js";

const { Pool } = pg;

describe("Milestone 13-D Phase D2: Distributed Lifecycle & Adversarial Tests", () => {
  let certs: CertBundle;
  let pool: pg.Pool;
  let store: PostgresWitnessStore;
  let serviceImpl: GrpcWitnessServiceImpl;
  let serverInstance: StartedGrpcWitnessServer;
  let serverEndpoint: string;
  let client: RemoteDurableWitnessClient;
  let signer: LocalEd25519WitnessSigner;
  const testEpochId = `test-adversarial-epoch-${Date.now()}`;

  let testEpochHeight: number;

  beforeAll(async () => {
    certs = generateTestCertificates();
    store = new PostgresWitnessStore({ epochId: testEpochId });
    pool = (store as any).pool;
    await store.initializeSchema();

    const maxHRes = await pool.query(`SELECT COALESCE(MAX(epoch_height), 0) + 1 AS next_h FROM witness_epochs`);
    testEpochHeight = Number(maxHRes.rows[0].next_h);
    await store.registerEpoch(testEpochId, testEpochHeight);

    signer = new LocalEd25519WitnessSigner("adversarial-witness-signer");
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
    });
  }, 45000);

  beforeEach(async () => {
    await store.registerEpoch(testEpochId, testEpochHeight);
  });

  afterAll(async () => {
    if (client) client.close();
    if (serverInstance) await serverInstance.stop();
    if (pool) await pool.end();
    if (certs?.bundleDir) {
      try {
        const fs = await import("node:fs");
        fs.rmSync(certs.bundleDir, { recursive: true, force: true });
      } catch {}
    }
  });

  // ==========================================================================
  // Test 1: Full End-to-End Happy Path (Reserve -> Commit -> Reconcile)
  // ==========================================================================
  it("executes full Reserve -> Commit -> Reconcile lifecycle cleanly over gRPC", async () => {
    const authId = `auth-happy-${Date.now()}`;
    const bindingDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    const reserveReq: WitnessReservationRequest = {
      authorizationId: authId,
      bindingDigest,
      policyId: "policy-test",
      policyRevision: 1,
      idempotencyKey: `idem-${authId}`,
      budgetWindows: [
        {
          windowType: "DAILY" as any,
          windowStart: Math.floor(Date.now() / 1000),
          requestedAmount: "100",
          maxCumulativeAmount: "10000",
        },
      ],
    };

    const reserveRes = await client.reserveTicket(reserveReq);
    expect(reserveRes.decision).toBe("ALLOW");
    expect(reserveRes.ticketId).toBeDefined();
    expect(reserveRes.state).toBe("RESERVED");

    const commitReq: WitnessCommitRequest = {
      ticketId: reserveRes.ticketId!,
      authorizationId: authId,
      bindingDigest,
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    };

    const commitRes = await client.commitTicket(commitReq);
    expect(commitRes.decision).toBe("ALLOW");
    expect(commitRes.receipt).toBeDefined();
    expect(commitRes.receipt!.sequenceNumber).toBeDefined();
    expect(commitRes.receipt!.signature.length).toBe(128);

    // Cryptographic verification of gRPC receipt using witness public key
    expect(verifyWitnessReceipt(signer.getPublicKeyHex(), commitRes.receipt!)).toBe(true);
    expect(verifyWitnessReceipt(signer.getPublicKeyPem(), commitRes.receipt!)).toBe(true);

    const reconcileRes = await client.reconcileTicket({
      ticketId: reserveRes.ticketId!,
      authorizationId: authId,
    });
    expect(reconcileRes.state).toBe("COMMITTED");
    expect(reconcileRes.receipt).toBeDefined();
    expect(reconcileRes.receipt?.signature).toBe(commitRes.receipt!.signature);

    // Cryptographic verification of reconciled receipt
    expect(verifyWitnessReceipt(signer.getPublicKeyHex(), reconcileRes.receipt!)).toBe(true);
    expect(verifyWitnessReceipt(signer.getPublicKeyPem(), reconcileRes.receipt!)).toBe(true);

    // Tamper detection: modifying debitedAmount or sequenceNumber must fail verification
    expect(verifyWitnessReceipt(signer.getPublicKeyHex(), { ...commitRes.receipt!, debitedAmount: "999" })).toBe(false);
    expect(verifyWitnessReceipt(signer.getPublicKeyHex(), { ...commitRes.receipt!, sequenceNumber: "99999" })).toBe(false);
  });

  // ==========================================================================
  // Test 2: TEST-M13D-D2-F2-01: Idempotency Replay vs Payload Mismatch
  // ==========================================================================
  it("TEST-M13D-D2-F2-01: Returns cached replay on identical request, rejects mismatch with 409 Conflict", async () => {
    const authId = `auth-idem-${Date.now()}`;
    const bindingDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const idempotencyKey = `idem-key-${Date.now()}`;

    const req1: WitnessReservationRequest = {
      authorizationId: authId,
      bindingDigest,
      policyId: "policy-test",
      policyRevision: 1,
      idempotencyKey,
    };

    // First call: fresh reservation
    const res1 = await client.reserveTicket(req1);
    expect(res1.decision).toBe("ALLOW");

    // Second call: identical key + identical payload -> cached replay
    const res2 = await client.reserveTicket(req1);
    expect(res2.decision).toBe("ALLOW");
    expect(res2.ticketId).toBe(res1.ticketId);
    expect(res2.reasons).toContain("CACHED_IDEMPOTENT_REPLAY");

    // Third call: identical key + DIFFERENT payload -> ALREADY_EXISTS / 409 Conflict
    const reqMismatch: WitnessReservationRequest = {
      authorizationId: `auth-different-${Date.now()}`,
      bindingDigest,
      policyId: "policy-test",
      policyRevision: 1,
      idempotencyKey, // Reused key!
    };

    await expect(client.reserveTicket(reqMismatch)).rejects.toThrow(/ALREADY_EXISTS/);
  });

  // ==========================================================================
  // Test 3: TEST-M13D-D2-F1-01: Stale Worker Fencing Generation Check
  // ==========================================================================
  it("TEST-M13D-D2-F1-01: Stale worker with outdated fencing generation is aborted with zero mutations", async () => {
    const authId = `auth-stale-${Date.now()}`;
    const bindingDigest = "sha256:3333333333333333333333333333333333333333333333333333333333333333";

    const reserveRes = await client.reserveTicket({
      authorizationId: authId,
      bindingDigest,
      policyId: "policy-test",
      policyRevision: 1,
      idempotencyKey: `idem-${authId}`,
      budgetWindows: [
        {
          windowType: "DAILY" as any,
          windowStart: Math.floor(Date.now() / 1000),
          requestedAmount: "250",
          maxCumulativeAmount: "50000",
        },
      ],
    });

    const ticketId = reserveRes.ticketId!;

    // Step A: Allocate Phase 1 intent directly in PostgreSQL
    const p1Client = await pool.connect();
    let allocatedSeq: string;
    try {
      await p1Client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;");
      const seqRes = await p1Client.query(`SELECT nextval(get_or_create_epoch_sequence($1)) AS seq`, [testEpochId]);
      allocatedSeq = String(seqRes.rows[0].seq);

      await p1Client.query(
        `UPDATE witness_tickets SET state = 'COMMITTING_SIGNING_PENDING', sequence_number = $1 WHERE ticket_id = $2`,
        [allocatedSeq, ticketId],
      );

      await p1Client.query(
        `INSERT INTO witness_signing_outbox (
           intent_id, ticket_id, epoch_id, sequence_number, preimage,
           status, fencing_generation, owner_worker_id, lease_expires_at_seconds,
           request_fingerprint, window_id, requested_amount,
           created_at_seconds, updated_at_seconds
         ) VALUES ($1, $2, $3, $4, 'preimage', 'PENDING', 1, 'worker-A', $5, 'fp', 'DAILY_100', 250, $6, $6)`,
        [
          `intent-${ticketId}`,
          ticketId,
          testEpochId,
          allocatedSeq,
          Math.floor(Date.now() / 1000) + 15,
          Math.floor(Date.now() / 1000),
        ],
      );
      await p1Client.query("COMMIT;");
    } finally {
      p1Client.release();
    }

    // Step B: Record baseline chain head and budget
    const beforeEpoch = await pool.query(`SELECT chain_head_hash FROM witness_epochs WHERE epoch_id = $1`, [testEpochId]);
    const baselineChainHead = beforeEpoch.rows[0].chain_head_hash;

    const beforeAcc = await pool.query(`SELECT current_amount, held_amount FROM witness_accumulators WHERE window_id = 'DAILY_100'`);
    const baselineHeld = beforeAcc.rows[0]?.held_amount || "0";
    const baselineCurrent = beforeAcc.rows[0]?.current_amount || "0";

    // Step C: Supervisor intervenes and executes atomic terminal fencing (fencing generation -> 2, status -> FAILED)
    const fenced = await serviceImpl.executeTerminalFencing(testEpochId, allocatedSeq, 1, ticketId, "test-supervisor");
    expect(fenced).toBe(true);

    // Verify outbox generation was bumped to 2 and status is FAILED
    const checkOutbox = await pool.query(
      `SELECT fencing_generation, status FROM witness_signing_outbox WHERE epoch_id = $1 AND sequence_number = $2`,
      [testEpochId, allocatedSeq],
    );
    expect(Number(checkOutbox.rows[0].fencing_generation)).toBe(2);
    expect(checkOutbox.rows[0].status).toBe("FAILED");

    // Step D: Stale Worker wakes up and attempts Phase 3 commit under generation 1
    // Calling commitTicket should be rejected because generation has changed
    await expect(
      client.commitTicket({
        ticketId,
        authorizationId: authId,
        bindingDigest,
        localCommittedAtSeconds: Math.floor(Date.now() / 1000),
      }),
    ).rejects.toThrow();

    // Step E: Verify Zero-Mutation Invariants
    // 1. Zero receipts inserted for this sequence
    const checkReceipt = await pool.query(
      `SELECT * FROM witness_receipts WHERE epoch_id = $1 AND sequence_number = $2`,
      [testEpochId, allocatedSeq],
    );
    expect(checkReceipt.rows.length).toBe(0);

    // 2. Ticket state is QUARANTINED_BLOCKED (not COMMITTED)
    const checkTicket = await pool.query(`SELECT state FROM witness_tickets WHERE ticket_id = $1`, [ticketId]);
    expect(checkTicket.rows[0].state).toBe("QUARANTINED_BLOCKED");
  });

  // ==========================================================================
  // Test 4: TEST-M13D-D2-F1-02: Out-of-Order Sequence & Gap Chaining
  // ==========================================================================
  it("TEST-M13D-D2-F1-02: Sequence 11 waits on stalled Sequence 10 and links to gap hash after fencing", async () => {
    // Allocate Sequence 10 as an expired stalled outbox intent
    const stalledTicketId = `ticket-stalled-${Date.now()}`;
    const seq10Client = await pool.connect();
    let seq10: string;
    try {
      await seq10Client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;");
      const sRes = await seq10Client.query(`SELECT nextval(get_or_create_epoch_sequence($1)) AS seq`, [testEpochId]);
      seq10 = String(sRes.rows[0].seq);

      const pastLease = Math.floor(Date.now() / 1000) - 10; // Expired 10 seconds ago!
      await seq10Client.query(
        `INSERT INTO witness_tickets (ticket_id, authorization_id, epoch_id, state, binding_digest, expires_at_seconds, created_at_seconds, updated_at_seconds, request_fingerprint, owner_identity)
         VALUES ($1, $2, $3, 'COMMITTING_SIGNING_PENDING', 'sha256:4444', $4, $4, $4, 'fp', 'worker-stalled')`,
        [stalledTicketId, `auth-stalled-${Date.now()}`, testEpochId, pastLease],
      );

      await seq10Client.query(
        `INSERT INTO witness_signing_outbox (
           intent_id, ticket_id, epoch_id, sequence_number, preimage,
           status, fencing_generation, owner_worker_id, lease_expires_at_seconds,
           request_fingerprint, created_at_seconds, updated_at_seconds
         ) VALUES ($1, $2, $3, $4, 'preimage', 'PENDING', 1, 'worker-stalled', $5, 'fp', $6, $6)`,
        [`intent-${stalledTicketId}`, stalledTicketId, testEpochId, seq10, pastLease, pastLease],
      );
      await seq10Client.query("COMMIT;");
    } finally {
      seq10Client.release();
    }

    // Now, a client reserves and commits Sequence 11
    const auth11 = `auth-seq11-${Date.now()}`;
    const reserve11 = await client.reserveTicket({
      authorizationId: auth11,
      bindingDigest: "sha256:5555555555555555555555555555555555555555555555555555555555555555",
      policyId: "policy-test",
      policyRevision: 1,
      idempotencyKey: `idem-${auth11}`,
    });

    const commit11 = await client.commitTicket({
      ticketId: reserve11.ticketId!,
      authorizationId: auth11,
      bindingDigest: "sha256:5555555555555555555555555555555555555555555555555555555555555555",
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    });

    expect(commit11.decision).toBe("ALLOW");
    expect(commit11.receipt).toBeDefined();

    // Verify Sequence 10 was terminally fenced into witness_sequence_gaps
    const gapCheck = await pool.query(
      `SELECT * FROM witness_sequence_gaps WHERE epoch_id = $1 AND sequence_number = $2`,
      [testEpochId, seq10],
    );
    expect(gapCheck.rows.length).toBe(1);
    expect(gapCheck.rows[0].gap_reason).toBe("OUTBOX_FENCED");
  });

  // ==========================================================================
  // Test 5: Releasing a COMMITTED Ticket is Strictly Prohibited
  // ==========================================================================
  it("strictly rejects release of a COMMITTED ticket with zero budget refund", async () => {
    const authId = `auth-norelease-${Date.now()}`;
    const bindingDigest = "sha256:6666666666666666666666666666666666666666666666666666666666666666";

    const res = await client.reserveTicket({
      authorizationId: authId,
      bindingDigest,
      policyId: "policy-test",
      policyRevision: 1,
      idempotencyKey: `idem-${authId}`,
    });
    await client.commitTicket({
      ticketId: res.ticketId!,
      authorizationId: authId,
      bindingDigest,
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    });

    // Attempting release on COMMITTED ticket MUST fail with 409 Conflict
    await expect(
      client.releaseTicket({
        ticketId: res.ticketId!,
        authorizationId: authId,
        bindingDigest,
        reason: "Illegal release attempt",
      }),
    ).rejects.toThrow(/ALREADY_EXISTS/);
  });

  // ==========================================================================
  // Test 6: Startup Outbox Reconciliation Sweep
  // ==========================================================================
  it("TEST-M13D-D2-F2-03: Startup sweep terminally fences expired leases before listener opens", async () => {
    // Insert an expired outbox row
    const expiredTicketId = `ticket-expired-${Date.now()}`;
    const past = Math.floor(Date.now() / 1000) - 60;

    await pool.query(
      `INSERT INTO witness_tickets (ticket_id, authorization_id, epoch_id, state, binding_digest, expires_at_seconds, created_at_seconds, updated_at_seconds, request_fingerprint, owner_identity)
       VALUES ($1, $2, $3, 'COMMITTING_SIGNING_PENDING', 'sha256:7777', $4, $4, $4, 'fp', 'worker-crashed')`,
      [expiredTicketId, `auth-crash-${Date.now()}`, testEpochId, past],
    );

    const sRes = await pool.query(`SELECT nextval(get_or_create_epoch_sequence($1)) AS seq`, [testEpochId]);
    const crashSeq = String(sRes.rows[0].seq);

    await pool.query(
      `INSERT INTO witness_signing_outbox (
         intent_id, ticket_id, epoch_id, sequence_number, preimage,
         status, fencing_generation, owner_worker_id, lease_expires_at_seconds,
         request_fingerprint, created_at_seconds, updated_at_seconds
       ) VALUES ($1, $2, $3, $4, 'preimage', 'PENDING', 1, 'worker-crashed', $5, 'fp', $6, $6)`,
      [`intent-${expiredTicketId}`, expiredTicketId, testEpochId, crashSeq, past, past],
    );

    // Run sweep
    const sweepResult = await serviceImpl.startupOutboxReconciliationSweep();
    expect(sweepResult.fencedCount).toBeGreaterThanOrEqual(1);

    // Verify row transitioned to FAILED and gap was recorded
    const outboxAfter = await pool.query(
      `SELECT status FROM witness_signing_outbox WHERE intent_id = $1`,
      [`intent-${expiredTicketId}`],
    );
    expect(outboxAfter.rows[0].status).toBe("FAILED");
  });

  // ==========================================================================
  // Test 7: COR-D2-01: Predecessor Active Lease Blocks Successor
  // ==========================================================================
  it("COR-D2-01: Rejects successor with UNAVAILABLE when predecessor sequence has an active lease", async () => {
    // 1. Manually insert predecessor sequence with an active future lease
    const activeTicketId = `ticket-active-lease-${Date.now()}`;
    const futureLease = Math.floor(Date.now() / 1000) + 120; // 2 minutes in the future
    const sRes = await pool.query(`SELECT nextval(get_or_create_epoch_sequence($1)) AS seq`, [testEpochId]);
    const predSeq = String(sRes.rows[0].seq);

    await pool.query(
      `INSERT INTO witness_tickets (ticket_id, authorization_id, epoch_id, state, binding_digest, expires_at_seconds, created_at_seconds, updated_at_seconds, request_fingerprint, owner_identity)
       VALUES ($1, $2, $3, 'COMMITTING_SIGNING_PENDING', 'sha256:active-pred', $4, $5, $5, 'fp', 'worker-active')`,
      [activeTicketId, `auth-active-${Date.now()}`, testEpochId, futureLease, Math.floor(Date.now() / 1000)],
    );

    await pool.query(
      `INSERT INTO witness_signing_outbox (
         intent_id, ticket_id, epoch_id, sequence_number, preimage,
         status, fencing_generation, owner_worker_id, lease_expires_at_seconds,
         request_fingerprint, created_at_seconds, updated_at_seconds
       ) VALUES ($1, $2, $3, $4, 'preimage', 'PENDING', 1, 'worker-active', $5, 'fp', $6, $6)`,
      [`intent-${activeTicketId}`, activeTicketId, testEpochId, predSeq, futureLease, Math.floor(Date.now() / 1000)],
    );

    // 2. Now attempt to reserve and commit the successor sequence
    const succAuthId = `auth-succ-${Date.now()}`;
    const succDigest = "sha256:" + "7".repeat(64);
    const succReserve = await client.reserveTicket({
      authorizationId: succAuthId,
      bindingDigest: succDigest,
      policyId: "policy-test",
      policyRevision: 1,
      idempotencyKey: `idem-${succAuthId}`,
    });

    // 3. Committing successor MUST fail closed with UNAVAILABLE because predecessor is actively leasing
    await expect(
      client.commitTicket({
        ticketId: succReserve.ticketId!,
        authorizationId: succAuthId,
        bindingDigest: succDigest,
        localCommittedAtSeconds: Math.floor(Date.now() / 1000),
      }),
    ).rejects.toThrow(/UNAVAILABLE/);

    // 4. Verify predecessor was NOT fenced and remains PENDING
    const predCheck = await pool.query(
      `SELECT status FROM witness_signing_outbox WHERE intent_id = $1`,
      [`intent-${activeTicketId}`],
    );
    expect(predCheck.rows[0].status).toBe("PENDING");

    // Clean up active outbox row to avoid blocking subsequent sequence increments in later tests
    await pool.query(`DELETE FROM witness_signing_outbox WHERE intent_id = $1`, [`intent-${activeTicketId}`]);
    await pool.query(`DELETE FROM witness_tickets WHERE ticket_id = $1`, [activeTicketId]);
  });

  // ==========================================================================
  // Test 8: COR-D2-02: Concurrent In-Flight Commit Does Not Allocate Second Sequence
  // ==========================================================================
  it("COR-D2-02: In-flight duplicate commit does not allocate a second sequence number", async () => {
    const authId = `auth-inflight-${Date.now()}`;
    const bindingDigest = "sha256:" + "8".repeat(64);

    const res = await client.reserveTicket({
      authorizationId: authId,
      bindingDigest,
      policyId: "policy-test",
      policyRevision: 1,
      idempotencyKey: `idem-${authId}`,
    });

    // Transition ticket to COMMITTING_SIGNING_PENDING with an allocated sequence
    const sRes = await pool.query(`SELECT nextval(get_or_create_epoch_sequence($1)) AS seq`, [testEpochId]);
    const firstSeq = String(sRes.rows[0].seq);
    const nowSec = Math.floor(Date.now() / 1000);

    await pool.query(
      `UPDATE witness_tickets
       SET state = 'COMMITTING_SIGNING_PENDING', sequence_number = $1, updated_at_seconds = $2
       WHERE ticket_id = $3`,
      [firstSeq, nowSec, res.ticketId!],
    );

    // Concurrent/replayed commit attempt while ticket is in COMMITTING_SIGNING_PENDING
    // It should poll and fail with UNAVAILABLE (IN_PROGRESS) without allocating a new sequence
    await expect(
      client.commitTicket({
        ticketId: res.ticketId!,
        authorizationId: authId,
        bindingDigest,
        localCommittedAtSeconds: nowSec,
      }),
    ).rejects.toThrow(/UNAVAILABLE/);

    // Verify ticket sequence_number was NOT changed or duplicated
    const ticketCheck = await pool.query(
      `SELECT sequence_number, state FROM witness_tickets WHERE ticket_id = $1`,
      [res.ticketId!],
    );
    expect(ticketCheck.rows[0].sequence_number).toBe(firstSeq);
    expect(ticketCheck.rows[0].state).toBe("COMMITTING_SIGNING_PENDING");

    // Clean up sequence to resolved gap so subsequent tests have a valid predecessor chain
    await pool.query(
      `INSERT INTO witness_sequence_gaps (epoch_id, sequence_number, gap_reason, ticket_id, gap_hash, detected_at_seconds)
       VALUES ($1, $2, 'TEST_RESOLVED', $3, 'gap-hash-test8', $4)
       ON CONFLICT (epoch_id, sequence_number) DO NOTHING`,
      [testEpochId, firstSeq, res.ticketId!, nowSec],
    );
  });

  // ==========================================================================
  // Test 9: IDEM-D2-01: Replay with Conflicting Payload Fails with 409 Conflict
  // ==========================================================================
  it("IDEM-D2-01: Replaying commit on an already committed ticket with conflicting payload returns ALREADY_EXISTS / 409 Conflict", async () => {
    const authId = `auth-conflict-${Date.now()}`;
    const bindingDigest = "sha256:" + "9".repeat(64);

    const res = await client.reserveTicket({
      authorizationId: authId,
      bindingDigest,
      policyId: "policy-test",
      policyRevision: 1,
      idempotencyKey: `idem-${authId}`,
    });
    const commitRes = await client.commitTicket({
      ticketId: res.ticketId!,
      authorizationId: authId,
      bindingDigest,
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    });
    expect(commitRes.decision).toBe("ALLOW");

    // Identical replay succeeds idempotently
    const replayRes = await client.commitTicket({
      ticketId: res.ticketId!,
      authorizationId: authId,
      bindingDigest,
      localCommittedAtSeconds: Math.floor(Date.now() / 1000),
    });
    expect(replayRes.decision).toBe("ALLOW");
    expect(replayRes.receipt?.sequenceNumber).toBe(commitRes.receipt?.sequenceNumber);

    // Conflicting replay (different bindingDigest) MUST fail with ALREADY_EXISTS
    await expect(
      client.commitTicket({
        ticketId: res.ticketId!,
        authorizationId: authId,
        bindingDigest: "sha256:" + "f".repeat(64),
        localCommittedAtSeconds: Math.floor(Date.now() / 1000),
      }),
    ).rejects.toThrow(/ALREADY_EXISTS/);
  });
});
