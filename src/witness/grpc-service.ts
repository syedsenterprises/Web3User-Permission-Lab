/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Core gRPC Witness Service Implementation
 *
 * Implements the 6 RPC handlers with strict ACID guarantees, global Level 1 epoch row locking,
 * monotonic fencing generations, out-of-order sequence resolution, recursive hash chaining,
 * and fail-closed budget conservation.
 */

import { createHash, randomUUID } from "node:crypto";
import type pg from "pg";
import { LocalEpochCircuitBreaker } from "./circuit-breaker.js";
import { IdempotencyFingerprinter } from "./idempotency.js";
import { PeerAuthorizer, type AuthenticatedPeer } from "./auth.js";
import { PostgresConnectionDisposalAdapter } from "./disposal-adapter.js";
import type { WitnessSigner, ReceiptPreimageData } from "./signing.js";
import { formatCanonicalPreimage, normalizeBudgetWindowType } from "./signing.js";
import { PG_SQLSTATE } from "./postgres-store.js";

export class StaleWorkerFencedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StaleWorkerFencedError";
  }
}

export interface GrpcWitnessServiceConfig {
  pool: pg.Pool;
  signer: WitnessSigner;
  circuitBreaker?: LocalEpochCircuitBreaker;
}

export class GrpcWitnessServiceImpl {
  private pool: pg.Pool;
  private signer: WitnessSigner;
  private circuitBreaker: LocalEpochCircuitBreaker;

  constructor(config: GrpcWitnessServiceConfig) {
    this.pool = config.pool;
    this.signer = config.signer;
    this.circuitBreaker = config.circuitBreaker || LocalEpochCircuitBreaker.getInstance();
  }

  // ==========================================================================
  // Helper: SHA-256
  // ==========================================================================
  private sha256(data: string | Buffer): string {
    return createHash("sha256").update(data).digest("hex");
  }

  // ==========================================================================
  // Helper: Bounded Retry for Transient Concurrency Contention (Section 1.5.2)
  // ==========================================================================
  private async executeWithRetry<T>(
    operationName: string,
    epochId: string,
    fn: (client: pg.PoolClient) => Promise<T>,
    maxRetries = 10,
  ): Promise<T> {
    let attempt = 0;
    while (true) {
      attempt++;
      const client = await this.pool.connect();
      try {
        const result = await fn(client);
        return result;
      } catch (err: any) {
        const isTainted =
          !(client as any)._queryable ||
          Boolean((client as any)._ending) ||
          Boolean((client as any).connection?.stream?.destroyed);

        if (isTainted) {
          PostgresConnectionDisposalAdapter.emergencyEvictAndDestroy(this.pool, client, err);
        } else {
          try {
            await client.query("ROLLBACK");
          } catch (rbErr: any) {
            PostgresConnectionDisposalAdapter.emergencyEvictAndDestroy(this.pool, client, rbErr);
          }
        }

        const code = err?.code;
        if (
          code === PG_SQLSTATE.LOCK_NOT_AVAILABLE ||
          code === PG_SQLSTATE.SERIALIZATION_FAILURE ||
          code === PG_SQLSTATE.DEADLOCK_DETECTED
        ) {
          if (attempt <= maxRetries) {
            const delay = Math.min(250, Math.floor(15 * Math.pow(1.5, attempt - 1) + Math.random() * 30));
            await new Promise((r) => setTimeout(r, delay));
            continue;
          } else {
            this.circuitBreaker.tripContention(epochId, 500);
          }
        }
        throw err;
      } finally {
        if ((client as any)._queryable && !((client as any).connection?.stream?.destroyed)) {
          client.release();
        }
      }
    }
  }

  // ==========================================================================
  // 1. GetSyncStatus
  // ==========================================================================
  async getSyncStatus(call: any, peer: AuthenticatedPeer): Promise<any> {
    PeerAuthorizer.assertRolePermission(peer, "GetSyncStatus");
    const req = call.request || call;

    const client = await this.pool.connect();
    try {
      const res = await client.query(
        `SELECT epoch_id, epoch_height, chain_head_hash, last_sequence_number, state 
         FROM witness_epochs 
         ORDER BY epoch_height DESC 
         LIMIT 1`,
      );

      if (res.rows.length === 0) {
        return {
          healthy: false,
          epoch_id: "",
          sequence_number: "0",
          divergence_detected: false,
          reason: "NO_ACTIVE_EPOCHS_FOUND",
        };
      }

      const row = res.rows[0];
      const epochId = row.epoch_id;
      const currentSeq = String(row.last_sequence_number || "0");
      let divergenceDetected = false;
      let reason = "HEALTHY";

      if (req.last_seen_epoch_id && req.last_seen_epoch_id !== epochId) {
        divergenceDetected = true;
        reason = `EPOCH_MISMATCH: Server on ${epochId}, client on ${req.last_seen_epoch_id}`;
      } else if (
        req.last_seen_sequence_number &&
        BigInt(req.last_seen_sequence_number) > BigInt(currentSeq)
      ) {
        divergenceDetected = true;
        reason = `CLIENT_AHEAD_OF_SERVER: Client seq ${req.last_seen_sequence_number} > server seq ${currentSeq}`;
      }

      return {
        healthy: row.state === "ACTIVE",
        epoch_id: epochId,
        sequence_number: currentSeq,
        divergence_detected: divergenceDetected,
        reason,
      };
    } finally {
      client.release();
    }
  }

  // ==========================================================================
  // 2. ReserveTicket
  // ==========================================================================
  async reserveTicket(call: any, peer: AuthenticatedPeer): Promise<any> {
    PeerAuthorizer.assertRolePermission(peer, "ReserveTicket");
    const req = call.request || call;

    if (!req.idempotency_key) {
      const err = new Error("INVALID_ARGUMENT: idempotency_key is mandatory for ReserveTicket");
      (err as any).code = 3; // INVALID_ARGUMENT
      throw err;
    }

    const fingerprint = IdempotencyFingerprinter.computeReserveFingerprint({
      authorizationId: req.authorization_id,
      bindingDigest: req.binding_digest,
      policyId: req.policy_id,
      policyRevision: req.policy_revision,
      budgetWindows: req.budget_windows?.map((w: any) => ({
        windowType: w.window_type,
        windowStartSeconds: w.window_start_seconds,
        requestedAmount: w.requested_amount,
        maxCumulativeAmount: w.max_cumulative_amount,
      })),
      idempotencyKey: req.idempotency_key,
      leaseTtlSeconds: req.lease_ttl_seconds,
    });

    return await this.executeWithRetry("ReserveTicket", "unknown", async (client) => {
      // Step A: Check existing ticket by authorization_id or idempotency_key
      const existing = await client.query(
        `SELECT ticket_id, authorization_id, state, expires_at_seconds, request_fingerprint, owner_identity
         FROM witness_tickets
         WHERE authorization_id = $1 OR idempotency_key = $2`,
        [req.authorization_id, req.idempotency_key],
      );

      if (existing.rows.length > 0) {
        const row = existing.rows[0];
        if (row.request_fingerprint === fingerprint) {
          // Exact match: return cached replay
          return {
            decision: "DECISION_ALLOW",
            ticket_id: row.ticket_id,
            state: row.state,
            reasons: ["CACHED_IDEMPOTENT_REPLAY"],
            lease_expires_at_seconds: Number(row.expires_at_seconds),
          };
        } else {
          // Payload mismatch under same idempotency key or duplicate authId
          const err = new Error(
            "ALREADY_EXISTS: Idempotency key or authorization ID already bound to different payload",
          );
          (err as any).code = 6; // ALREADY_EXISTS
          throw err;
        }
      }

      // Step B: Fresh reservation inside SERIALIZABLE transaction
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE; SET lock_timeout = '2500ms';");

      // 1. Get active epoch (Level 1 Lock)
      const epochRes = await client.query(
        `SELECT epoch_id, state FROM witness_epochs ORDER BY epoch_height DESC LIMIT 1 FOR SHARE`,
      );
      if (epochRes.rows.length === 0) {
        await client.query("ROLLBACK");
        const err = new Error("FAILED_PRECONDITION: No active epoch registered in witness database");
        (err as any).code = 9;
        throw err;
      }
      const epochId = epochRes.rows[0].epoch_id;
      this.circuitBreaker.assertCanMutate(epochId);

      // 2. Budget window validation & reservation (Level 3 Lock on witness_accumulators)
      let requestedAmt = "0";
      let windowId: string | null = null;
      if (req.budget_windows && req.budget_windows.length > 0) {
        const bw = req.budget_windows[0];
        windowId = `${bw.window_type}_${bw.window_start_seconds}`;
        requestedAmt = String(bw.requested_amount || "0");
        const maxLimit = String(bw.max_cumulative_amount || "1000000000");

        // Ensure accumulator exists
        await client.query(
          `INSERT INTO witness_accumulators (window_id, window_type, window_start, current_amount, held_amount, max_limit)
           VALUES ($1, $2, $3, 0, 0, $4)
           ON CONFLICT (window_id) DO NOTHING`,
          [windowId, String(bw.window_type), bw.window_start_seconds, maxLimit],
        );

        // Lock accumulator row
        const accRes = await client.query(
          `SELECT current_amount, held_amount, max_limit 
           FROM witness_accumulators 
           WHERE window_id = $1 
           FOR UPDATE NOWAIT`,
          [windowId],
        );

        const acc = accRes.rows[0];
        const cur = BigInt(acc.current_amount);
        const held = BigInt(acc.held_amount);
        const max = BigInt(acc.max_limit);
        const reqBig = BigInt(requestedAmt);

        if (cur + held + reqBig > max) {
          await client.query("ROLLBACK");
          return {
            decision: "DECISION_DENY",
            ticket_id: "",
            state: "TICKET_STATE_UNSPECIFIED",
            reasons: ["BUDGET_CAPACITY_EXCEEDED"],
            lease_expires_at_seconds: 0,
          };
        }

        // Increment held budget
        await client.query(
          `UPDATE witness_accumulators 
           SET held_amount = held_amount + $1 
           WHERE window_id = $2`,
          [requestedAmt, windowId],
        );
      }

      // 3. Insert fresh ticket into witness_tickets
      const ticketId = randomUUID();
      const now = Math.floor(Date.now() / 1000);
      const ttl = req.lease_ttl_seconds ? Number(req.lease_ttl_seconds) : 300;
      const expiresAt = now + ttl;

      await client.query(
        `INSERT INTO witness_tickets (
           ticket_id, authorization_id, epoch_id, state, binding_digest,
           expires_at_seconds, created_at_seconds, updated_at_seconds,
           idempotency_key, request_fingerprint, owner_identity,
           policy_id, policy_revision, window_id, requested_amount
         ) VALUES ($1, $2, $3, 'RESERVED', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
        [
          ticketId,
          req.authorization_id,
          epochId,
          req.binding_digest,
          expiresAt,
          now,
          now,
          req.idempotency_key,
          fingerprint,
          peer.identity,
          req.policy_id || null,
          req.policy_revision || null,
          windowId,
          requestedAmt,
        ],
      );

      // 4. Audit Log
      await client.query(
        `INSERT INTO witness_audit_log (ticket_id, authorization_id, action, from_state, to_state, actor_id, details)
         VALUES ($1, $2, 'ReserveTicket', NULL, 'RESERVED', $3, $4)`,
        [ticketId, req.authorization_id, peer.identity, JSON.stringify({ windowId, requestedAmt })],
      );

      await client.query("COMMIT");

      return {
        decision: "DECISION_ALLOW",
        ticket_id: ticketId,
        state: "TICKET_STATE_RESERVED",
        reasons: ["RESERVATION_GRANTED"],
        lease_expires_at_seconds: expiresAt,
      };
    });
  }

  // ==========================================================================
  // 3. CommitTicket (Phase 1 Intent, Phase 2 Sign, Phase 3 Finalize)
  // ==========================================================================
  async commitTicket(call: any, peer: AuthenticatedPeer): Promise<any> {
    PeerAuthorizer.assertRolePermission(peer, "CommitTicket");
    const req = call.request || call;

    if (!req.idempotency_key) {
      const err = new Error("INVALID_ARGUMENT: idempotency_key is mandatory for CommitTicket");
      (err as any).code = 3;
      throw err;
    }

    const fingerprint = IdempotencyFingerprinter.computeCommitFingerprint({
      ticketId: req.ticket_id,
      authorizationId: req.authorization_id,
      bindingDigest: req.binding_digest,
      idempotencyKey: req.idempotency_key,
    });

    // Check if ticket is already COMMITTED (IDEM-D2-01) or in-progress (COR-D2-02)
    const preCheckClient = await this.pool.connect();
    let preTicket: any;
    try {
      const receiptRes = await preCheckClient.query(
        `SELECT receipt_json, authorization_id, binding_digest FROM witness_receipts WHERE ticket_id = $1`,
        [req.ticket_id],
      );
      if (receiptRes.rows.length > 0) {
        const row = receiptRes.rows[0];
        const parsed = JSON.parse(row.receipt_json);
        if (
          row.authorization_id !== req.authorization_id ||
          row.binding_digest !== req.binding_digest
        ) {
          const err = new Error(
            `ALREADY_EXISTS: Ticket ${req.ticket_id} is already committed with conflicting authorization ID or binding digest`,
          );
          (err as any).code = 6; // gRPC ALREADY_EXISTS / 409 Conflict
          throw err;
        }
        return {
          decision: "DECISION_ALLOW",
          receipt: parsed,
          reasons: ["CACHED_RECEIPT_REPLAY"],
          already_committed: true,
        };
      }

      // Pre-check ticket state, identity, and fingerprint
      const ticketPreCheck = await preCheckClient.query(
        `SELECT ticket_id, authorization_id, epoch_id, state, binding_digest, expires_at_seconds,
                owner_identity, policy_id, policy_revision, window_id, requested_amount, sequence_number
         FROM witness_tickets
         WHERE ticket_id = $1`,
        [req.ticket_id],
      );

      if (ticketPreCheck.rows.length === 0) {
        const err = new Error(`NOT_FOUND: Ticket ${req.ticket_id} does not exist`);
        (err as any).code = 5;
        throw err;
      }

      preTicket = ticketPreCheck.rows[0];
      PeerAuthorizer.assertTicketOwnership(peer, preTicket.owner_identity);

      if (
        preTicket.authorization_id !== req.authorization_id ||
        preTicket.binding_digest !== req.binding_digest
      ) {
        const err = new Error(
          `ALREADY_EXISTS: Ticket ${req.ticket_id} is bound to a conflicting authorization ID or binding digest`,
        );
        (err as any).code = 6;
        throw err;
      }

      if (preTicket.state === "COMMITTING_SIGNING_PENDING") {
        // COR-D2-02: Ticket is actively IN_PROGRESS. Do NOT allocate a new sequence!
        const outboxCheck = await preCheckClient.query(
          `SELECT intent_id, sequence_number, status, request_fingerprint, lease_expires_at_seconds
           FROM witness_signing_outbox
           WHERE ticket_id = $1`,
          [req.ticket_id],
        );

        if (
          outboxCheck.rows.length > 0 &&
          outboxCheck.rows[0].request_fingerprint &&
          outboxCheck.rows[0].request_fingerprint !== fingerprint
        ) {
          const err = new Error(
            `ALREADY_EXISTS: In-progress commit request fingerprint mismatch for ticket ${req.ticket_id}`,
          );
          (err as any).code = 6;
          throw err;
        }

        // Bounded poll up to 500ms for concurrent worker Phase 3 resolution
        const startPoll = Date.now();
        while (Date.now() - startPoll < 500) {
          await new Promise((r) => setTimeout(r, 50));
          const rCheck = await preCheckClient.query(
            `SELECT receipt_json FROM witness_receipts WHERE ticket_id = $1`,
            [req.ticket_id],
          );
          if (rCheck.rows.length > 0) {
            const parsed = JSON.parse(rCheck.rows[0].receipt_json);
            return {
              decision: "DECISION_ALLOW",
              receipt: parsed,
              reasons: ["CACHED_RECEIPT_REPLAY"],
              already_committed: true,
            };
          }
        }

        // Still in progress: return retryable UNAVAILABLE with retry-after-ms: 250
        const inProgErr = new Error(
          `UNAVAILABLE: Ticket ${req.ticket_id} commitment is actively IN_PROGRESS under sequence ${preTicket.sequence_number}`,
        );
        (inProgErr as any).code = 14;
        (inProgErr as any).retryAfterMs = 250;
        throw inProgErr;
      }

      if (preTicket.state !== "RESERVED") {
        const err = new Error(`FAILED_PRECONDITION: Ticket in invalid state ${preTicket.state} for commit`);
        (err as any).code = 9;
        throw err;
      }
    } finally {
      preCheckClient.release();
    }

    // PHASE 1: Durable Intent & Sequence Allocation
    let allocatedSeq: string;
    let epochId = preTicket.epoch_id;
    let windowId: string | null = preTicket.window_id || null;
    let requestedAmt: string = String(preTicket.requested_amount || "0");
    let intentId = randomUUID();
    const fencingGen = 1;

    const phase1Result = await this.executeWithRetry("CommitTicketPhase1", epochId, async (phase1Client) => {
      await phase1Client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE; SET lock_timeout = '2500ms';");

      // ARC-D2-01: Acquire Level 1 Lock on witness_epochs FIRST
      await phase1Client.query(
        `SELECT epoch_id FROM witness_epochs WHERE epoch_id = $1 FOR SHARE`,
        [epochId],
      );

      // ARC-D2-01: Acquire Level 4 Lock on witness_tickets SECOND
      const ticketRes = await phase1Client.query(
        `SELECT ticket_id, authorization_id, epoch_id, state, binding_digest, expires_at_seconds,
                owner_identity, policy_id, policy_revision, window_id, requested_amount
         FROM witness_tickets
         WHERE ticket_id = $1
         FOR UPDATE NOWAIT`,
        [req.ticket_id],
      );

      if (ticketRes.rows.length === 0) {
        const err = new Error(`NOT_FOUND: Ticket ${req.ticket_id} does not exist`);
        (err as any).code = 5;
        throw err;
      }

      const ticket = ticketRes.rows[0];
      PeerAuthorizer.assertTicketOwnership(peer, ticket.owner_identity);

      if (ticket.state !== "RESERVED") {
        const err = new Error(`FAILED_PRECONDITION: Ticket in invalid state ${ticket.state} for commit`);
        (err as any).code = 9;
        throw err;
      }

      const now = Math.floor(Date.now() / 1000);
      if (now > Number(ticket.expires_at_seconds)) {
        return {
          denied: true,
          denyResponse: {
            decision: "DECISION_DENY",
            receipt: null,
            reasons: ["LEASE_EXPIRED"],
            already_committed: false,
          },
        };
      }

      this.circuitBreaker.assertCanMutate(epochId);

      // Allocate per-epoch sequence
      const seqNameRes = await phase1Client.query(`SELECT get_or_create_epoch_sequence($1)`, [epochId]);
      const seqName = seqNameRes.rows[0].get_or_create_epoch_sequence;
      const seqRes = await phase1Client.query(`SELECT nextval($1) AS seq`, [seqName]);
      const currentAllocatedSeq = String(seqRes.rows[0].seq);

      // Update ticket to COMMITTING_SIGNING_PENDING
      await phase1Client.query(
        `UPDATE witness_tickets 
         SET state = 'COMMITTING_SIGNING_PENDING',
             sequence_number = $1,
             updated_at_seconds = $2
         WHERE ticket_id = $3`,
        [currentAllocatedSeq, now, req.ticket_id],
      );

      // PERF-D2-01: Direct budget window retrieval from ticket, with indexed audit log fallback
      let resolvedWindowId = windowId;
      let resolvedRequestedAmt = requestedAmt;
      if (!resolvedWindowId && ticket.window_id) {
        resolvedWindowId = ticket.window_id;
        resolvedRequestedAmt = String(ticket.requested_amount || "0");
      }
      if (!resolvedWindowId) {
        const auditRes = await phase1Client.query(
          `SELECT details FROM witness_audit_log WHERE ticket_id = $1 AND action = 'ReserveTicket' ORDER BY log_id DESC LIMIT 1`,
          [req.ticket_id],
        );
        if (auditRes.rows.length > 0 && auditRes.rows[0].details) {
          resolvedWindowId = auditRes.rows[0].details.windowId || null;
          resolvedRequestedAmt = String(auditRes.rows[0].details.requestedAmt || "0");
        }
      }

      const resolvedPolicyId = ticket.policy_id || "default-policy";
      const resolvedPolicyRevision = ticket.policy_revision ? Number(ticket.policy_revision) : 1;

      let resolvedWindowType: string | number = 1;
      let resolvedWindowStart = now;
      let cumulativeSpentAfter = resolvedRequestedAmt;
      if (resolvedWindowId) {
        const accRes = await phase1Client.query(
          `SELECT window_type, window_start, current_amount, held_amount FROM witness_accumulators WHERE window_id = $1`,
          [resolvedWindowId],
        );
        if (accRes.rows.length > 0) {
          resolvedWindowType = accRes.rows[0].window_type;
          resolvedWindowStart = Number(accRes.rows[0].window_start);
          cumulativeSpentAfter = (BigInt(accRes.rows[0].current_amount) + BigInt(resolvedRequestedAmt)).toString();
        }
      }

      const leaseExpiresAt = now + 15;
      const preimageData: ReceiptPreimageData = {
        version: 1,
        witness_id: this.signer.getWitnessId(),
        epoch_id: epochId,
        sequence_number: currentAllocatedSeq,
        ticket_id: req.ticket_id,
        authorization_id: req.authorization_id,
        binding_digest: req.binding_digest,
        policy_id: resolvedPolicyId,
        policy_revision: resolvedPolicyRevision,
        debited_amount: resolvedRequestedAmt,
        budget_windows: resolvedWindowId
          ? [
              {
                window_type: resolvedWindowType,
                window_start_seconds: resolvedWindowStart,
                cumulative_spent_after: cumulativeSpentAfter,
              },
            ]
          : [],
        committed_at_seconds: now,
      };

      const canonicalPreimage = formatCanonicalPreimage(preimageData);

      // Insert outbox intent
      await phase1Client.query(
        `INSERT INTO witness_signing_outbox (
           intent_id, ticket_id, epoch_id, sequence_number, preimage,
           status, fencing_generation, owner_worker_id, lease_expires_at_seconds,
           request_fingerprint, window_id, requested_amount,
           created_at_seconds, updated_at_seconds
         ) VALUES ($1, $2, $3, $4, $5, 'PENDING', $6, $7, $8, $9, $10, $11, $12, $13)`,
        [
          intentId,
          req.ticket_id,
          epochId,
          currentAllocatedSeq,
          canonicalPreimage,
          fencingGen,
          peer.identity,
          leaseExpiresAt,
          fingerprint,
          resolvedWindowId,
          resolvedRequestedAmt,
          now,
          now,
        ],
      );

      await phase1Client.query("COMMIT");

      return {
        denied: false,
        allocatedSeq: currentAllocatedSeq,
        windowId: resolvedWindowId,
        requestedAmt: resolvedRequestedAmt,
        policyId: resolvedPolicyId,
        policyRevision: resolvedPolicyRevision,
        preimageData,
        canonicalPreimage,
        nowCommitted: now,
      };
    }, 10);

    if (phase1Result.denied) {
      return phase1Result.denyResponse;
    }

    allocatedSeq = phase1Result.allocatedSeq!;
    windowId = phase1Result.windowId!;
    requestedAmt = phase1Result.requestedAmt!;
    const preimageData = phase1Result.preimageData!;
    const canonicalPreimage = phase1Result.canonicalPreimage!;
    const nowCommitted = phase1Result.nowCommitted!;

    // PHASE 2: Signature Generation
    const { signatureHex, generation: signedGen } = await this.signer.signReceipt(
      canonicalPreimage,
      fencingGen,
    );

    // PHASE 3: Receipt Finalization & Recursive Hash-Chain Advancement
    const finalReceipt = {
      version: 1,
      witness_id: this.signer.getWitnessId(),
      epoch_id: epochId,
      sequence_number: allocatedSeq,
      ticket_id: req.ticket_id,
      authorization_id: req.authorization_id,
      binding_digest: req.binding_digest,
      policy_id: preimageData.policy_id,
      policy_revision: preimageData.policy_revision,
      debited_amount: requestedAmt,
      budget_windows: preimageData.budget_windows,
      committed_at_seconds: nowCommitted,
      signature: signatureHex,
      // camelCase fields for direct SDK and cryptographic verification
      witnessId: this.signer.getWitnessId(),
      epochId,
      sequenceNumber: allocatedSeq,
      ticketId: req.ticket_id,
      authorizationId: req.authorization_id,
      bindingDigest: req.binding_digest,
      policyId: preimageData.policy_id,
      policyRevision: preimageData.policy_revision,
      debitedAmount: requestedAmt,
      budgetWindows: (preimageData.budget_windows || []).map((bw: any) => ({
        windowType: normalizeBudgetWindowType(bw.window_type ?? bw.windowType),
        windowStart: Number(bw.window_start_seconds ?? bw.windowStart ?? 0),
        cumulativeSpentAfter: String(bw.cumulative_spent_after ?? bw.cumulativeSpentAfter ?? "0"),
      })),
      committedAtSeconds: nowCommitted,
    };

    // Ensure predecessor resolution and chain ordering
    await this.resolvePredecessorSequence(epochId, BigInt(allocatedSeq));

    // Execute Phase 3 Transaction with bounded retry on transient contention
    return await this.executeWithRetry("CommitTicketPhase3", epochId, async (phase3Client) => {
      await phase3Client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE; SET lock_timeout = '2500ms';");

      // Step 1 (Rank 1 Lock): Lock epoch row
      const epochLockRes = await phase3Client.query(
        `SELECT epoch_id, chain_head_hash, last_sequence_number 
         FROM witness_epochs 
         WHERE epoch_id = $1 
         FOR UPDATE NOWAIT`,
        [epochId],
      );
      const priorChainHead = epochLockRes.rows[0].chain_head_hash;

      // Step 2 (Rank 2 Lock): Lock ticket row with NOWAIT BEFORE inserting receipt.
      // This strictly unifies sub-table locking order (Rank 2 witness_tickets BEFORE Rank 3 witness_signing_outbox)
      // and eliminates implicit FK lock upgrade deadlocks (fk_receipt_ticket) by ensuring the ticket
      // is ALREADY held exclusively FOR UPDATE prior to INSERT INTO witness_receipts.
      const ticketRes = await phase3Client.query(
        `SELECT ticket_id, authorization_id, epoch_id, state, sequence_number, binding_digest
         FROM witness_tickets
         WHERE ticket_id = $1
         FOR UPDATE NOWAIT`,
        [req.ticket_id],
      );

      if (ticketRes.rows.length === 0) {
        const err = new Error(`NOT_FOUND: Ticket ${req.ticket_id} does not exist`);
        (err as any).code = 5;
        throw err;
      }

      const ticketRow = ticketRes.rows[0];
      if (ticketRow.state === "COMMITTED") {
        const receiptCheck = await phase3Client.query(
          `SELECT receipt_json FROM witness_receipts WHERE ticket_id = $1`,
          [req.ticket_id],
        );
        await phase3Client.query("COMMIT");
        if (receiptCheck.rows.length > 0) {
          return {
            decision: "DECISION_ALLOW",
            receipt: JSON.parse(receiptCheck.rows[0].receipt_json),
            reasons: ["CACHED_RECEIPT_REPLAY"],
            already_committed: true,
          };
        }
      }

      if (ticketRow.state !== "COMMITTING_SIGNING_PENDING") {
        const err = new Error(`FAILED_PRECONDITION: Cannot finalize Phase 3 for ticket in state ${ticketRow.state}`);
        (err as any).code = 9;
        throw err;
      }

      // Step 3 (Rank 3 Lock): Lock outbox row & validate fencing generation
      const outboxRes = await phase3Client.query(
        `SELECT intent_id, fencing_generation, status, ticket_id
         FROM witness_signing_outbox
         WHERE epoch_id = $1 AND sequence_number = $2
         FOR UPDATE NOWAIT`,
        [epochId, allocatedSeq],
      );

      if (outboxRes.rows.length === 0) {
        throw new StaleWorkerFencedError("FENCED: Outbox row vanished");
      }

      const outboxRow = outboxRes.rows[0];
      if (
        Number(outboxRow.fencing_generation) !== signedGen ||
        (outboxRow.status !== "PENDING" && outboxRow.status !== "SIGNING")
      ) {
        // Worker was fenced! Strict rollback and zero mutation!
        throw new StaleWorkerFencedError(
          `FENCED: Outbox fencing generation changed (expected ${signedGen}, got ${outboxRow.fencing_generation}, status ${outboxRow.status})`,
        );
      }

      // Step 4: Compute recursive chain hash H_s = SHA256(priorChainHead || canonicalReceipt)
      const receiptJson = JSON.stringify(finalReceipt);
      const receiptChainHash = this.sha256(`${priorChainHead}:${receiptJson}`);

      // Step 5: Durably insert receipt (Rank 5).
      // Both witness_epochs and witness_tickets are ALREADY locked exclusively FOR UPDATE,
      // completely eliminating implicit FK lock promotion races on foreign keys.
      await phase3Client.query(
        `INSERT INTO witness_receipts (
           ticket_id, authorization_id, epoch_id, sequence_number,
           witness_timestamp_seconds, binding_digest, signature,
           receipt_json, receipt_chain_hash
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          req.ticket_id,
          req.authorization_id,
          epochId,
          allocatedSeq,
          nowCommitted,
          req.binding_digest,
          Buffer.from(signatureHex, "hex"),
          receiptJson,
          receiptChainHash,
        ],
      );

      // Step 6: Advance epoch chain-head hash (Rank 1)
      await phase3Client.query(
        `UPDATE witness_epochs
         SET chain_head_hash = $1,
             last_sequence_number = $2,
             updated_at_seconds = $3
         WHERE epoch_id = $4`,
        [receiptChainHash, allocatedSeq, nowCommitted, epochId],
      );

      // Step 7: Shift budget from held to committed (Rank 4)
      if (windowId && BigInt(requestedAmt) > 0n) {
        await phase3Client.query(
          `UPDATE witness_accumulators
           SET held_amount = held_amount - $1,
               current_amount = current_amount + $1
           WHERE window_id = $2`,
          [requestedAmt, windowId],
        );
      }

      // Step 8: Transition ticket to COMMITTED (Rank 2)
      await phase3Client.query(
        `UPDATE witness_tickets
         SET state = 'COMMITTED',
             updated_at_seconds = $1
         WHERE ticket_id = $2`,
        [nowCommitted, req.ticket_id],
      );

      // Step 9: Mark outbox COMPLETED (Rank 3)
      await phase3Client.query(
        `UPDATE witness_signing_outbox
         SET status = 'COMPLETED',
             updated_at_seconds = $1
         WHERE epoch_id = $2 AND sequence_number = $3 AND fencing_generation = $4`,
        [nowCommitted, epochId, allocatedSeq, signedGen],
      );

      // Step 10: Audit Log (Rank 7)
      await phase3Client.query(
        `INSERT INTO witness_audit_log (ticket_id, authorization_id, action, from_state, to_state, actor_id, details)
         VALUES ($1, $2, 'CommitTicket', 'COMMITTING_SIGNING_PENDING', 'COMMITTED', $3, $4)`,
        [req.ticket_id, req.authorization_id, peer.identity, JSON.stringify({ sequenceNumber: allocatedSeq, receiptChainHash })],
      );

      await phase3Client.query("COMMIT");

      return {
        decision: "DECISION_ALLOW",
        receipt: finalReceipt,
        reasons: ["AUTHORIZATION_COMMITTED"],
        already_committed: false,
      };
    }, 8);
  }

  // ==========================================================================
  // Helper: Predecessor Resolution & Successor Wait / Terminal Fencing (COR-D2-01)
  // ==========================================================================
  private async resolvePredecessorSequence(epochId: string, currentSeq: bigint): Promise<void> {
    if (currentSeq <= 1n) {
      return; // Genesis sequence 1 has no predecessor
    }

    const predecessorSeq = currentSeq - 1n;
    const client = await this.pool.connect();
    try {
      const isTerminal = async (): Promise<boolean> => {
        const receiptRes = await client.query(
          `SELECT sequence_number FROM witness_receipts WHERE epoch_id = $1 AND sequence_number = $2`,
          [epochId, predecessorSeq.toString()],
        );
        if (receiptRes.rows.length > 0) return true;

        const gapRes = await client.query(
          `SELECT sequence_number FROM witness_sequence_gaps WHERE epoch_id = $1 AND sequence_number = $2`,
          [epochId, predecessorSeq.toString()],
        );
        return gapRes.rows.length > 0;
      };

      if (await isTerminal()) {
        return;
      }

      // Predecessor is still in-flight. Wait up to 500ms (bounded successor wait).
      const startTime = Date.now();
      while (Date.now() - startTime < 500) {
        await new Promise((r) => setTimeout(r, 50));
        if (await isTerminal()) return;
      }

      // 500ms wait expired! Trigger recovery evaluation for predecessor sequence.
      const outboxRes = await client.query(
        `SELECT intent_id, ticket_id, fencing_generation, lease_expires_at_seconds, status
         FROM witness_signing_outbox
         WHERE epoch_id = $1 AND sequence_number = $2`,
        [epochId, predecessorSeq.toString()],
      );

      if (outboxRes.rows.length > 0) {
        const row = outboxRes.rows[0];
        const now = Math.floor(Date.now() / 1000);
        // Only fence if lease has physically expired!
        if (now > Number(row.lease_expires_at_seconds)) {
          await this.executeTerminalFencing(
            epochId,
            predecessorSeq.toString(),
            Number(row.fencing_generation),
            row.ticket_id,
            "SUCCESSOR_WAIT_TIMEOUT_LEASE_EXPIRED",
          );
          if (await isTerminal()) return;
        } else {
          // COR-D2-01: Lease has NOT expired. Unexpired predecessor MUST NOT be skipped!
          const remainingLease = Number(row.lease_expires_at_seconds) - now;
          const err = new Error(
            `UNAVAILABLE: Predecessor sequence ${predecessorSeq} is in-flight with active lease (${remainingLease}s remaining); successor sequence ${currentSeq} cannot finalize out-of-order`,
          );
          (err as any).code = 14; // gRPC UNAVAILABLE
          (err as any).retryAfterMs = Math.min(500, Math.max(100, remainingLease * 1000));
          throw err;
        }
      }

      // If predecessor is still not terminal, fail closed with UNAVAILABLE
      if (!(await isTerminal())) {
        const err = new Error(
          `UNAVAILABLE: Predecessor sequence ${predecessorSeq} is unresolved; successor sequence ${currentSeq} cannot finalize out-of-order`,
        );
        (err as any).code = 14; // gRPC UNAVAILABLE
        (err as any).retryAfterMs = 250;
        throw err;
      }
    } finally {
      client.release();
    }
  }

  // ==========================================================================
  // Atomic Terminal Fencing Transaction (Deliverable 3 & Section 1.3)
  // ==========================================================================
  async executeTerminalFencing(
    epochId: string,
    sequenceNumber: string,
    expectedGeneration: number,
    ticketId?: string,
    fencedBy = "supervisor-recovery",
  ): Promise<boolean> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE; SET lock_timeout = '2500ms';");

      // Level 1 Lock on witness_epochs
      const epochRes = await client.query(
        `SELECT epoch_id, chain_head_hash, last_sequence_number 
         FROM witness_epochs 
         WHERE epoch_id = $1 
         FOR UPDATE NOWAIT`,
        [epochId],
      );
      if (epochRes.rows.length === 0) {
        await client.query("ROLLBACK");
        return false;
      }
      const priorChainHead = epochRes.rows[0].chain_head_hash;

      // Level 2 Lock on witness_signing_outbox
      const outboxRes = await client.query(
        `SELECT intent_id, fencing_generation, status, ticket_id, window_id, requested_amount
         FROM witness_signing_outbox
         WHERE epoch_id = $1 AND sequence_number = $2
         FOR UPDATE NOWAIT`,
        [epochId, sequenceNumber],
      );

      if (outboxRes.rows.length === 0) {
        await client.query("ROLLBACK");
        return false;
      }

      const outbox = outboxRes.rows[0];
      if (outbox.status !== "PENDING" && outbox.status !== "SIGNING") {
        // Already resolved or previously fenced
        await client.query("ROLLBACK");
        return false;
      }

      // ARC-D2-01 Level 3 Lock on witness_accumulators (if budget window attributed)
      if (outbox.window_id && BigInt(outbox.requested_amount || "0") > 0n) {
        await client.query(
          `SELECT current_amount, held_amount FROM witness_accumulators WHERE window_id = $1 FOR UPDATE NOWAIT`,
          [outbox.window_id],
        );
      }

      // ARC-D2-01 Level 4 Lock on witness_tickets
      const actualTicketId = outbox.ticket_id || ticketId;
      if (actualTicketId) {
        await client.query(
          `SELECT state FROM witness_tickets WHERE ticket_id = $1 FOR UPDATE NOWAIT`,
          [actualTicketId],
        );
      }

      const newGen = Number(outbox.fencing_generation) + 1;
      const now = Math.floor(Date.now() / 1000);

      // Step 2: Atomic generation increment & FAILED transition (Level 2)
      await client.query(
        `UPDATE witness_signing_outbox
         SET status = 'FAILED',
             fencing_generation = $1,
             last_error = $2,
             updated_at_seconds = $3
         WHERE epoch_id = $4 AND sequence_number = $5 AND status IN ('PENDING', 'SIGNING')`,
        [newGen, `FENCED: ${fencedBy}`, now, epochId, sequenceNumber],
      );

      // Step 3: Insert sequence gap record linked to predecessor chain head (Level 5)
      const gapHash = this.sha256(`${priorChainHead}:GAP:${epochId}:${sequenceNumber}`);
      await client.query(
        `INSERT INTO witness_sequence_gaps (
           epoch_id, sequence_number, gap_reason, ticket_id, gap_hash, detected_at_seconds, details
         ) VALUES ($1, $2, 'OUTBOX_FENCED', $3, $4, $5, $6)
         ON CONFLICT (epoch_id, sequence_number) DO NOTHING`,
        [
          epochId,
          sequenceNumber,
          outbox.ticket_id || ticketId,
          gapHash,
          now,
          JSON.stringify({ fencedGeneration: newGen, fencedBy }),
        ],
      );

      // Step 4: Advance epoch chain-head to the gap hash (Level 1)
      await client.query(
        `UPDATE witness_epochs
         SET chain_head_hash = $1,
             last_sequence_number = $2,
             updated_at_seconds = $3
         WHERE epoch_id = $4`,
        [gapHash, sequenceNumber, now, epochId],
      );

      // Step 5: Refund held budget (Level 3)
      if (outbox.window_id && BigInt(outbox.requested_amount || "0") > 0n) {
        await client.query(
          `UPDATE witness_accumulators
           SET held_amount = held_amount - $1
           WHERE window_id = $2`,
          [outbox.requested_amount, outbox.window_id],
        );
      }

      // Step 6: Quarantine ticket to QUARANTINED_BLOCKED (Level 4)
      if (actualTicketId) {
        await client.query(
          `UPDATE witness_tickets
           SET state = 'QUARANTINED_BLOCKED',
               updated_at_seconds = $1
           WHERE ticket_id = $2`,
          [now, actualTicketId],
        );
      }

      await client.query("COMMIT");
      return true;
    } catch (err: any) {
      const isTainted =
        !(client as any)._queryable ||
        Boolean((client as any)._ending) ||
        Boolean((client as any).connection?.stream?.destroyed);

      if (isTainted) {
        PostgresConnectionDisposalAdapter.emergencyEvictAndDestroy(this.pool, client, err);
      } else {
        try {
          await client.query("ROLLBACK");
        } catch (rbErr: any) {
          PostgresConnectionDisposalAdapter.emergencyEvictAndDestroy(this.pool, client, rbErr);
        }
      }
      return false;
    } finally {
      if ((client as any)._queryable && !((client as any).connection?.stream?.destroyed)) {
        client.release();
      }
    }
  }

  // ==========================================================================
  // 4. ReleaseTicket (ARC-D2-01, PERF-D2-01, SAF-D2-01)
  // ==========================================================================
  async releaseTicket(call: any, peer: AuthenticatedPeer): Promise<any> {
    PeerAuthorizer.assertRolePermission(peer, "ReleaseTicket");
    const req = call.request || call;

    if (!req.ticket_id) {
      const err = new Error("INVALID_ARGUMENT: ticket_id is mandatory for ReleaseTicket");
      (err as any).code = 3;
      throw err;
    }

    return await this.executeWithRetry("ReleaseTicket", "unknown", async (client) => {
      // Non-locking pre-read of ticket to determine epoch and budget window
      const preRes = await client.query(
        `SELECT ticket_id, authorization_id, epoch_id, state, owner_identity, window_id, requested_amount
         FROM witness_tickets
         WHERE ticket_id = $1`,
        [req.ticket_id],
      );

      if (preRes.rows.length === 0) {
        const err = new Error(`NOT_FOUND: Ticket ${req.ticket_id} does not exist`);
        (err as any).code = 5;
        throw err;
      }

      const preTicket = preRes.rows[0];
      PeerAuthorizer.assertTicketOwnership(peer, preTicket.owner_identity);

      if (preTicket.state === "COMMITTED") {
        const err = new Error("ALREADY_EXISTS: Ticket is already COMMITTED; cannot release committed authorization");
        (err as any).code = 6;
        throw err;
      }

      if (preTicket.state === "RELEASED") {
        return {
          success: true,
          previous_state: "TICKET_STATE_RELEASED",
          reasons: ["ALREADY_RELEASED"],
        };
      }

      // PERF-D2-01: Direct budget window attribution from ticket, indexed audit log fallback
      let windowId = preTicket.window_id;
      let requestedAmt = String(preTicket.requested_amount || "0");
      if (!windowId) {
        const auditRes = await client.query(
          `SELECT details FROM witness_audit_log WHERE ticket_id = $1 AND action = 'ReserveTicket' ORDER BY log_id DESC LIMIT 1`,
          [req.ticket_id],
        );
        if (auditRes.rows.length > 0 && auditRes.rows[0].details) {
          windowId = auditRes.rows[0].details.windowId || null;
          requestedAmt = String(auditRes.rows[0].details.requestedAmt || "0");
        }
      }

      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE; SET lock_timeout = '2500ms';");

      // Step 1 (Rank 1 Lock): Acquire Level 1 Lock on witness_epochs
      await client.query(
        `SELECT epoch_id FROM witness_epochs WHERE epoch_id = $1 FOR SHARE`,
        [preTicket.epoch_id],
      );

      // Step 2 (Rank 2 Lock): Acquire Level 2 Lock on witness_tickets BEFORE accumulators
      const ticketRes = await client.query(
        `SELECT ticket_id, authorization_id, state, window_id, requested_amount
         FROM witness_tickets
         WHERE ticket_id = $1
         FOR UPDATE NOWAIT`,
        [req.ticket_id],
      );

      if (ticketRes.rows.length === 0) {
        await client.query("ROLLBACK");
        const err = new Error(`NOT_FOUND: Ticket ${req.ticket_id} does not exist`);
        (err as any).code = 5;
        throw err;
      }

      const ticket = ticketRes.rows[0];

      if (ticket.state === "COMMITTED") {
        await client.query("ROLLBACK");
        const err = new Error("ALREADY_EXISTS: Ticket is already COMMITTED; cannot release committed authorization");
        (err as any).code = 6;
        throw err;
      }

      // Step 3 (Rank 4 Lock): Budget Refund on witness_accumulators using locked ticket attribution
      const effectiveWindowId = ticket.window_id || windowId;
      const effectiveRequestedAmt = ticket.requested_amount ? String(ticket.requested_amount) : requestedAmt;

      if (effectiveWindowId && BigInt(effectiveRequestedAmt || "0") > 0n) {
        await client.query(
          `SELECT current_amount, held_amount FROM witness_accumulators WHERE window_id = $1 FOR UPDATE NOWAIT`,
          [effectiveWindowId],
        );
        await client.query(
          `UPDATE witness_accumulators 
           SET held_amount = held_amount - $1 
           WHERE window_id = $2`,
          [effectiveRequestedAmt, effectiveWindowId],
        );
      }

      const now = Math.floor(Date.now() / 1000);
      await client.query(
        `UPDATE witness_tickets 
         SET state = 'RELEASED', updated_at_seconds = $1 
         WHERE ticket_id = $2`,
        [now, req.ticket_id],
      );

      await client.query(
        `INSERT INTO witness_audit_log (ticket_id, authorization_id, action, from_state, to_state, actor_id, details)
         VALUES ($1, $2, 'ReleaseTicket', $3, 'RELEASED', $4, $5)`,
        [req.ticket_id, ticket.authorization_id, ticket.state, peer.identity, JSON.stringify({ reason: req.reason })],
      );

      await client.query("COMMIT");

      return {
        success: true,
        previous_state: `TICKET_STATE_${ticket.state}`,
        reasons: ["TICKET_VOLUNTARILY_RELEASED"],
      };
    });
  }

  // ==========================================================================
  // 5. ReconcileTicket
  // ==========================================================================
  async reconcileTicket(call: any, peer: AuthenticatedPeer): Promise<any> {
    PeerAuthorizer.assertRolePermission(peer, "ReconcileTicket");
    const req = call.request || call;

    const client = await this.pool.connect();
    try {
      const ticketRes = await client.query(
        `SELECT ticket_id, authorization_id, state, owner_identity, sequence_number
         FROM witness_tickets
         WHERE ticket_id = $1 OR authorization_id = $2`,
        [req.ticket_id, req.authorization_id],
      );

      if (ticketRes.rows.length === 0) {
        const err = new Error("NOT_FOUND: Ticket not found for reconciliation");
        (err as any).code = 5;
        throw err;
      }

      const ticket = ticketRes.rows[0];
      PeerAuthorizer.assertTicketOwnership(peer, ticket.owner_identity);

      // Check if receipt exists
      const receiptRes = await client.query(
        `SELECT receipt_json FROM witness_receipts WHERE ticket_id = $1`,
        [ticket.ticket_id],
      );

      let receipt = null;
      if (receiptRes.rows.length > 0) {
        receipt = JSON.parse(receiptRes.rows[0].receipt_json);
      }

      return {
        ticket_id: ticket.ticket_id,
        state: `TICKET_STATE_${ticket.state}`,
        receipt,
        reasons: ["RECONCILIATION_QUERY_SUCCESSFUL"],
      };
    } finally {
      client.release();
    }
  }

  // ==========================================================================
  // 6. ListUnfinalizedTickets
  // ==========================================================================
  async listUnfinalizedTickets(call: any, peer: AuthenticatedPeer): Promise<any> {
    PeerAuthorizer.assertRolePermission(peer, "ListUnfinalizedTickets");
    const req = call.request || call;

    const limit = Math.min(Number(req.limit || 100), 500);
    const cursorTime = Number(req.cursor_created_at_seconds || 0);
    const cursorId = req.cursor_ticket_id || "";

    const client = await this.pool.connect();
    try {
      const res = await client.query(
        `SELECT ticket_id, authorization_id, epoch_id, binding_digest, state,
                created_at_seconds, expires_at_seconds, owner_identity
         FROM witness_tickets
         WHERE state IN ('RESERVED', 'COMMITTING_SIGNING_PENDING', 'QUARANTINED_UNCONFIRMED')
           AND (created_at_seconds > $1 OR (created_at_seconds = $1 AND ticket_id > $2))
         ORDER BY created_at_seconds ASC, ticket_id ASC
         LIMIT $3`,
        [cursorTime, cursorId, limit + 1],
      );

      const hasMore = res.rows.length > limit;
      const rows = res.rows.slice(0, limit);

      const tickets = rows.map((r) => ({
        ticket_id: r.ticket_id,
        authorization_id: r.authorization_id,
        epoch_id: r.epoch_id,
        binding_digest: r.binding_digest,
        state: `TICKET_STATE_${r.state}`,
        reserved_at_seconds: Number(r.created_at_seconds),
        expires_at_seconds: Number(r.expires_at_seconds),
        owner_identity: r.owner_identity,
      }));

      const last = rows[rows.length - 1];
      return {
        tickets,
        next_cursor_created_at_seconds: last ? Number(last.created_at_seconds) : 0,
        next_cursor_ticket_id: last ? last.ticket_id : "",
        has_more: hasMore,
      };
    } finally {
      client.release();
    }
  }

  // ==========================================================================
  // Startup Outbox Reconciliation Sweep
  // ==========================================================================
  async startupOutboxReconciliationSweep(): Promise<{ reconciledCount: number; fencedCount: number }> {
    let reconciledCount = 0;
    let fencedCount = 0;

    const client = await this.pool.connect();
    try {
      const now = Math.floor(Date.now() / 1000);
      const unfinalized = await client.query(
        `SELECT intent_id, ticket_id, epoch_id, sequence_number, fencing_generation, lease_expires_at_seconds
         FROM witness_signing_outbox
         WHERE status IN ('PENDING', 'SIGNING')
         ORDER BY sequence_number ASC`,
      );

      for (const row of unfinalized.rows) {
        if (now > Number(row.lease_expires_at_seconds)) {
          // Expired lease: terminally fence
          const success = await this.executeTerminalFencing(
            row.epoch_id,
            String(row.sequence_number),
            Number(row.fencing_generation),
            row.ticket_id,
            "STARTUP_OUTBOX_RECONCILIATION_SWEEP",
          );
          if (success) fencedCount++;
        } else {
          reconciledCount++;
        }
      }
    } finally {
      client.release();
    }

    return { reconciledCount, fencedCount };
  }
}
