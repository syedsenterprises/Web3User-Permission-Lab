import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mkdirSync, rmSync } from "node:fs";
import { randomBytes } from "node:crypto";
import {
  Web3UserEngine,
  LocalDeterministicWitness,
  canonicalWitnessReceiptPayload,
  verifyWitnessReceipt,
  generateIssuerKeyPair,
  createTransactionEnvelope,
  type SignedWitnessReceipt,
  type WitnessReservationRequest,
  type DemoPolicy,
  type TransactionRequest,
  type MonotonicWitnessAdapter,
} from "../src/index.js";

const TEST_KEY_PAIR = generateIssuerKeyPair();

function createTestDirectory(): string {
  const dir = join(tmpdir(), `web3user-m11-witness-test-${Date.now()}-${randomBytes(4).toString("hex")}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

const SAMPLE_TRANSFER_CALLDATA =
  "0xa9059cbb" +
  "000000000000000000000000" +
  "4444444444444444444444444444444444444444" +
  "0000000000000000000000000000000000000000000000000de0b6b3a7640000"; // 1.0 token

const SAMPLE_TX_REQUEST: TransactionRequest = {
  chainId: "1",
  sender: "0x3333333333333333333333333333333333333333",
  target: "0x1111111111111111111111111111111111111111",
  calldata: SAMPLE_TRANSFER_CALLDATA,
  value: "0",
};

const SAMPLE_POLICY: DemoPolicy = {
  version: 1,
  policyId: "pol_witness_demo_01",
  allowedTarget: "0x1111111111111111111111111111111111111111",
  allowedRecipient: "0x4444444444444444444444444444444444444444",
  allowedSelector: "0xa9059cbb",
  maxAmount: "2000000000000000000", // 2 tokens
  validFrom: 0,
  expiresAt: 2000000000,
  revoked: false,
  budget: {
    window: "HOURLY",
    maxCumulativeAmount: "5000000000000000000", // 5 tokens
  },
};

describe("Milestone 11 Phase 3A: Monotonic Witness Protocol & LocalDeterministicWitness", () => {
  let testDir: string;
  let dbPath: string;

  beforeEach(() => {
    testDir = createTestDirectory();
    dbPath = join(testDir, "test-witness.sqlite3");
  });

  afterEach(() => {
    try {
      rmSync(testDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors on Windows
    }
  });

  describe("Canonical Receipt Serialization & Ed25519 Cryptographic Verification", () => {
    it("serializes receipt data deterministically with length prefixing and verifies Ed25519 signature", () => {
      const witness = new LocalDeterministicWitness({
        witnessId: "witness-core-01",
        epochId: "epoch-2026-10",
        initialSequence: 100n,
        keyPair: TEST_KEY_PAIR,
      });

      const res = witness.reserveTicket({
        authorizationId: "auth-canon-01",
        bindingDigest: "sha256:" + "a".repeat(64),
        policyId: "pol_test_01",
        policyRevision: 1,
        idempotencyKey: "idemp-01",
      });

      expect(res.decision).toBe("ALLOW");
      expect(res.ticketId).toBeDefined();

      const commit = witness.commitTicket({
        ticketId: res.ticketId!,
        authorizationId: "auth-canon-01",
        bindingDigest: "sha256:" + "a".repeat(64),
        localCommittedAtSeconds: 1700000000,
      });

      expect(commit.decision).toBe("ALLOW");
      expect(commit.receipt).toBeDefined();

      const receipt = commit.receipt!;
      expect(receipt.version).toBe(1);
      expect(receipt.witnessId).toBe("witness-core-01");
      expect(receipt.epochId).toBe("epoch-2026-10");
      expect(receipt.sequenceNumber).toBe("102"); // 100 -> 101 (reserve) -> 102 (commit)
      expect(receipt.signature).toMatch(/^[a-f0-9]{128}$/);

      // Verify canonical signature using public key
      const isValid = verifyWitnessReceipt(TEST_KEY_PAIR.publicKeyPem, receipt);
      expect(isValid).toBe(true);

      // Verify serialization output is deterministic
      const payload1 = canonicalWitnessReceiptPayload(receipt);
      const payload2 = canonicalWitnessReceiptPayload(receipt);
      expect(payload1).toBe(payload2);
      expect(payload1.startsWith("web3user-witness-receipt-v1\n")).toBe(true);
    });

    it("rejects receipt verification when signature is tampered", () => {
      const witness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const res = witness.reserveTicket({
        authorizationId: "auth-tamper-sig",
        bindingDigest: "sha256:" + "b".repeat(64),
        policyId: "pol_test_01",
        policyRevision: 1,
        idempotencyKey: "idemp-tamper-sig",
      });
      const commit = witness.commitTicket({
        ticketId: res.ticketId!,
        authorizationId: "auth-tamper-sig",
        bindingDigest: "sha256:" + "b".repeat(64),
        localCommittedAtSeconds: 1700000000,
      });

      const receipt = commit.receipt!;
      // Flip one character of hex signature
      const tamperedSig = (receipt.signature[0] === "a" ? "b" : "a") + receipt.signature.slice(1);
      const tamperedReceipt: SignedWitnessReceipt = { ...receipt, signature: tamperedSig };

      expect(verifyWitnessReceipt(TEST_KEY_PAIR.publicKeyPem, tamperedReceipt)).toBe(false);
    });

    it("rejects receipt verification when payload fields are modified post-signature", () => {
      const witness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const res = witness.reserveTicket({
        authorizationId: "auth-tamper-fields",
        bindingDigest: "sha256:" + "c".repeat(64),
        policyId: "pol_test_01",
        policyRevision: 1,
        idempotencyKey: "idemp-tamper-fields",
      });
      const commit = witness.commitTicket({
        ticketId: res.ticketId!,
        authorizationId: "auth-tamper-fields",
        bindingDigest: "sha256:" + "c".repeat(64),
        localCommittedAtSeconds: 1700000000,
      });

      const receipt = commit.receipt!;

      // Modifying sequence number must fail verification
      expect(verifyWitnessReceipt(TEST_KEY_PAIR.publicKeyPem, { ...receipt, sequenceNumber: "99999" })).toBe(false);
      // Modifying debitedAmount must fail verification
      expect(verifyWitnessReceipt(TEST_KEY_PAIR.publicKeyPem, { ...receipt, debitedAmount: "1000000" })).toBe(false);
      // Modifying epochId must fail verification
      expect(verifyWitnessReceipt(TEST_KEY_PAIR.publicKeyPem, { ...receipt, epochId: "epoch-tampered" })).toBe(false);
      // Modifying bindingDigest must fail verification
      expect(verifyWitnessReceipt(TEST_KEY_PAIR.publicKeyPem, { ...receipt, bindingDigest: "sha256:" + "f".repeat(64) })).toBe(false);
    });
  });

  describe("Witness State Machine & Terminal State Protection", () => {
    it("transitions RESERVED -> COMMITTED and enforces that COMMITTED tickets cannot be released", () => {
      const witness = new LocalDeterministicWitness();
      const res = witness.reserveTicket({
        authorizationId: "auth-term-commit",
        bindingDigest: "sha256:" + "1".repeat(64),
        policyId: "pol_01",
        policyRevision: 1,
        idempotencyKey: "idemp-term-1",
      });
      expect(res.decision).toBe("ALLOW");

      const commit = witness.commitTicket({
        ticketId: res.ticketId!,
        authorizationId: "auth-term-commit",
        bindingDigest: "sha256:" + "1".repeat(64),
        localCommittedAtSeconds: 1700000000,
      });
      expect(commit.decision).toBe("ALLOW");

      // Attempting to release a COMMITTED ticket must fail closed
      const releaseAttempt = witness.releaseTicket({
        ticketId: res.ticketId!,
        authorizationId: "auth-term-commit",
        bindingDigest: "sha256:" + "1".repeat(64),
        reason: "RACE_CONDITION_ATTEMPT",
      });
      expect(releaseAttempt.success).toBe(false);
      expect(releaseAttempt.reasons?.[0]).toContain("already been committed and cannot be released");
    });

    it("transitions RESERVED -> RELEASED and enforces that RELEASED tickets cannot be committed", () => {
      const witness = new LocalDeterministicWitness();
      const res = witness.reserveTicket({
        authorizationId: "auth-term-release",
        bindingDigest: "sha256:" + "2".repeat(64),
        policyId: "pol_01",
        policyRevision: 1,
        idempotencyKey: "idemp-term-2",
      });
      expect(res.decision).toBe("ALLOW");

      const release = witness.releaseTicket({
        ticketId: res.ticketId!,
        authorizationId: "auth-term-release",
        bindingDigest: "sha256:" + "2".repeat(64),
        reason: "TRANSACTION_CANCELLED",
      });
      expect(release.success).toBe(true);
      expect(release.previousState).toBe("RESERVED");

      // Attempting to commit a RELEASED ticket must fail closed
      const commitAttempt = witness.commitTicket({
        ticketId: res.ticketId!,
        authorizationId: "auth-term-release",
        bindingDigest: "sha256:" + "2".repeat(64),
        localCommittedAtSeconds: 1700000000,
      });
      expect(commitAttempt.decision).toBe("DENY");
      expect(commitAttempt.reasons?.[0]).toContain("permanently released and cannot be committed");
    });

    it("auto-quarantines expired uncommitted reservations without releasing budget capacity", () => {
      let currentTime = 1700000000;
      const witness = new LocalDeterministicWitness({
        nowSeconds: () => currentTime,
        defaultLeaseTtlSeconds: 10,
      });

      const res = witness.reserveTicket({
        authorizationId: "auth-quarantine-01",
        bindingDigest: "sha256:" + "3".repeat(64),
        policyId: "pol_quar",
        policyRevision: 1,
        idempotencyKey: "idemp-quar-1",
        leaseTtlSeconds: 10,
        budgetWindows: [
          {
            windowType: "HOURLY",
            windowStart: 1700000000,
            requestedAmount: "1000",
            maxCumulativeAmount: "1500",
          },
        ],
      });
      expect(res.decision).toBe("ALLOW");

      // Advance clock past lease expiration (10s)
      currentTime += 20;

      // Reconcile ticket
      const rec = witness.reconcileTicket({ ticketId: res.ticketId! });
      expect(rec.state).toBe("QUARANTINED_UNCONFIRMED");

      // Budget capacity was NOT reclaimed: second reservation asking for 1000 should exceed max 1500
      const res2 = witness.reserveTicket({
        authorizationId: "auth-quarantine-02",
        bindingDigest: "sha256:" + "4".repeat(64),
        policyId: "pol_quar",
        policyRevision: 1,
        idempotencyKey: "idemp-quar-2",
        budgetWindows: [
          {
            windowType: "HOURLY",
            windowStart: 1700000000,
            requestedAmount: "1000",
            maxCumulativeAmount: "1500",
          },
        ],
      });
      expect(res2.decision).toBe("DENY");
      expect(res2.reasons?.[0]).toContain("Cumulative spending budget exceeded on witness");
    });
  });

  describe("Multi-Window Cumulative Budget Enforcement on Witness", () => {
    it("enforces capacity across multiple windows atomically and reclaims capacity upon release", () => {
      const witness = new LocalDeterministicWitness();

      // Reserve 3 tokens against an hourly window (max 5) and daily window (max 10)
      const res1 = witness.reserveTicket({
        authorizationId: "auth-budget-01",
        bindingDigest: "sha256:" + "5".repeat(64),
        policyId: "pol_budget_multi",
        policyRevision: 1,
        idempotencyKey: "idemp-multi-1",
        budgetWindows: [
          {
            windowType: "HOURLY",
            windowStart: 1700000000,
            requestedAmount: "3000000000000000000",
            maxCumulativeAmount: "5000000000000000000",
          },
          {
            windowType: "DAILY",
            windowStart: 1699920000,
            requestedAmount: "3000000000000000000",
            maxCumulativeAmount: "10000000000000000000",
          },
        ],
      });
      expect(res1.decision).toBe("ALLOW");

      // Attempt to reserve 3 more tokens in same hourly window (3 + 3 = 6 > max 5) -> must be denied!
      const res2 = witness.reserveTicket({
        authorizationId: "auth-budget-02",
        bindingDigest: "sha256:" + "6".repeat(64),
        policyId: "pol_budget_multi",
        policyRevision: 1,
        idempotencyKey: "idemp-multi-2",
        budgetWindows: [
          {
            windowType: "HOURLY",
            windowStart: 1700000000,
            requestedAmount: "3000000000000000000",
            maxCumulativeAmount: "5000000000000000000",
          },
        ],
      });
      expect(res2.decision).toBe("DENY");
      expect(res2.reasons?.[0]).toContain("Cumulative spending budget exceeded on witness for hourly window");

      // Release ticket 1 (e.g. local transaction aborted)
      const rel = witness.releaseTicket({
        ticketId: res1.ticketId!,
        authorizationId: "auth-budget-01",
        bindingDigest: "sha256:" + "5".repeat(64),
        reason: "TRANSACTION_ABORTED",
      });
      expect(rel.success).toBe(true);

      // Now reservation 2 with 3 tokens should succeed because capacity was reclaimed!
      const res3 = witness.reserveTicket({
        authorizationId: "auth-budget-03",
        bindingDigest: "sha256:" + "6".repeat(64),
        policyId: "pol_budget_multi",
        policyRevision: 1,
        idempotencyKey: "idemp-multi-3",
        budgetWindows: [
          {
            windowType: "HOURLY",
            windowStart: 1700000000,
            requestedAmount: "3000000000000000000",
            maxCumulativeAmount: "5000000000000000000",
          },
        ],
      });
      expect(res3.decision).toBe("ALLOW");
    });
  });

  describe("Idempotency & Divergence Detection", () => {
    it("returns identical ticket on duplicate reservation request with matching payload", () => {
      const witness = new LocalDeterministicWitness();
      const req: WitnessReservationRequest = {
        authorizationId: "auth-idemp-01",
        bindingDigest: "sha256:" + "7".repeat(64),
        policyId: "pol_idemp",
        policyRevision: 1,
        idempotencyKey: "unique-key-xyz",
      };

      const res1 = witness.reserveTicket(req);
      expect(res1.decision).toBe("ALLOW");

      const res2 = witness.reserveTicket(req);
      expect(res2.decision).toBe("ALLOW");
      expect(res2.ticketId).toBe(res1.ticketId);
    });

    it("rejects duplicate reservation request with conflicting payload under same idempotency key", () => {
      const witness = new LocalDeterministicWitness();
      witness.reserveTicket({
        authorizationId: "auth-idemp-orig",
        bindingDigest: "sha256:" + "7".repeat(64),
        policyId: "pol_idemp",
        policyRevision: 1,
        idempotencyKey: "shared-key-123",
      });

      const resConflict = witness.reserveTicket({
        authorizationId: "auth-idemp-DIFFERENT",
        bindingDigest: "sha256:" + "7".repeat(64),
        policyId: "pol_idemp",
        policyRevision: 1,
        idempotencyKey: "shared-key-123",
      });
      expect(resConflict.decision).toBe("DENY");
      expect(resConflict.reasons?.[0]).toContain("Conflicting payload for existing idempotency key");
    });

    it("detects epoch divergence and sequence regression via getSyncStatus", () => {
      const witness = new LocalDeterministicWitness({
        epochId: "epoch-prod-2026",
        initialSequence: 50n,
      });

      // Matching status
      const syncMatch = witness.getSyncStatus("epoch-prod-2026", "50");
      expect(syncMatch.healthy).toBe(true);
      expect(syncMatch.divergenceDetected).toBe(false);

      // Epoch mismatch
      const syncEpochMismatch = witness.getSyncStatus("epoch-old-2025", "50");
      expect(syncEpochMismatch.healthy).toBe(false);
      expect(syncEpochMismatch.divergenceDetected).toBe(true);
      expect(syncEpochMismatch.reason).toContain("Epoch divergence detected");

      // Sequence regression (caller recorded seq 100, but witness sequence is 50)
      const syncSeqRegression = witness.getSyncStatus("epoch-prod-2026", "100");
      expect(syncSeqRegression.healthy).toBe(false);
      expect(syncSeqRegression.divergenceDetected).toBe(true);
      expect(syncSeqRegression.reason).toContain("Sequence regression detected");
    });
  });

  describe("Full SDK Pipeline Integration (Web3UserEngine + LocalDeterministicWitness)", () => {
    it("successfully issues, consumes with witness adapter, and attaches verified witness receipt", () => {
      const witness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: witness,
      });

      // Register key and policy
      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_v3_test_01",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      // Issue authorization
      const issued = engine.issue({
        authorizationId: "auth-full-pipeline-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_v3_test_01",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;
      expect(issued.artifact.authorizationId).toBe("auth-full-pipeline-01");

      // Consume authorization
      const result = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(result.decision).toBe("ALLOW");
      if (result.decision === "ALLOW") {
        expect(result.witnessReceipt).toBeDefined();
        const receipt = result.witnessReceipt!;
        expect(receipt.authorizationId).toBe("auth-full-pipeline-01");
        expect(receipt.policyId).toBe(SAMPLE_POLICY.policyId);
        expect(receipt.debitedAmount).toBe("1000000000000000000"); // 1.0 token

        // Cryptographically verify the receipt using witness public key
        const validReceipt = verifyWitnessReceipt(TEST_KEY_PAIR.publicKeyPem, receipt);
        expect(validReceipt).toBe(true);
      }

      // Replay must be blocked by SQLite single-use constraint
      const replay = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(replay.decision).toBe("DENY");
      expect(replay.reasons?.[0]).toContain("Transaction authorization has already been consumed");

      engine.close();
    });

    it("releases reserved ticket when local SQLite consumption is denied due to budget exceedance", () => {
      const witness = new LocalDeterministicWitness();
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: witness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_v3_test_02",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      // Policy with single-tx limit of 1.0 token and cumulative budget of 1.5 tokens
      engine.policies.register({
        ...SAMPLE_POLICY,
        policyId: "pol_tight_budget",
        maxAmount: "1000000000000000000", // 1.0 token max per tx
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: "1500000000000000000", // 1.5 tokens cumulative
        },
      });

      // 1. First authorization of 1.0 token succeeds
      const issued1 = engine.issue({
        authorizationId: "auth-budget-first",
        policyId: "pol_tight_budget",
        request: SAMPLE_TX_REQUEST, // 1.0 token
        signer: {
          keyId: "key_v3_test_02",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued1.decision).toBe("ALLOW");
      if (issued1.decision !== "ALLOW") return;

      const res1 = engine.consume({
        artifact: issued1.artifact,
        envelope: issued1.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(res1.decision).toBe("ALLOW");

      // 2. Second authorization of 1.0 token is issued (1.0 <= maxAmount of 1.0)
      const issued2 = engine.issue({
        authorizationId: "auth-budget-second",
        policyId: "pol_tight_budget",
        request: SAMPLE_TX_REQUEST, // 1.0 token
        signer: {
          keyId: "key_v3_test_02",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued2.decision).toBe("ALLOW");
      if (issued2.decision !== "ALLOW") return;

      // Consumption should be denied by local SQLite budget check (1.0 + 1.0 = 2.0 > 1.5)
      const res2 = engine.consume({
        artifact: issued2.artifact,
        envelope: issued2.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(res2.decision).toBe("DENY");
      expect(res2.reasons?.[0]).toContain("Cumulative spending budget exceeded");

      // Verify that the second reservation was cleanly RELEASED on witness, not left hanging in RESERVED!
      const unfinalized = witness.listUnfinalizedTickets();
      expect(unfinalized.length).toBe(0);

      engine.close();
    });

    it("denies reservation at witness level when witness budget is exhausted without touching SQLite", () => {
      const witness = new LocalDeterministicWitness();
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: witness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_v3_test_03",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      // Consume 5 separate authorizations of 1 token each
      // The budget is 5 tokens, so the 6th must fail
      for (let i = 1; i <= 5; i++) {
        const issued = engine.issue({
          authorizationId: `auth-exhaust-${i}`,
          policyId: SAMPLE_POLICY.policyId,
          request: SAMPLE_TX_REQUEST,
          signer: {
            keyId: "key_v3_test_03",
            privateKey: keypair.privateKey,
          },
        });
        expect(issued.decision).toBe("ALLOW");
        if (issued.decision !== "ALLOW") return;

        const res = engine.consume({
          artifact: issued.artifact,
          envelope: issued.envelope,
          request: SAMPLE_TX_REQUEST,
        });
        expect(res.decision).toBe("ALLOW");
      }

      // 6th attempt: should be rejected by witness budget check
      const issued6 = engine.issue({
        authorizationId: "auth-exhaust-6",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_v3_test_03",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued6.decision).toBe("ALLOW");
      if (issued6.decision !== "ALLOW") return;

      const res6 = engine.consume({
        artifact: issued6.artifact,
        envelope: issued6.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(res6.decision).toBe("DENY");
      expect(res6.reasons?.[0]).toContain("Cumulative spending budget exceeded on witness");

      engine.close();
    });
  });

  describe("Milestone 11 Phase 3B: Remediated Witness Commit/Release Safety & Idempotency", () => {
    let testDir: string;
    let dbPath: string;

    beforeEach(() => {
      testDir = createTestDirectory();
      dbPath = join(testDir, "test-witness-p3b.sqlite3");
    });

    afterEach(() => {
      try {
        rmSync(testDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors on Windows
      }
    });

    // Test 1: SQLite commit succeeds; commitTicket throws; releaseTicket is NOT called
    it("SEC-M11-01: when SQLite commit succeeds but witness commitTicket throws, does NOT call releaseTicket, returns UNKNOWN with witnessTicketId, leaves record consumed", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let releaseCalled = false;
      const witnessProxy: MonotonicWitnessAdapter = {
        name: "test-proxy-1",
        isTestOnlyMock: true,
        getSyncStatus: (epoch, seq) => baseWitness.getSyncStatus(epoch, seq),
        reserveTicket: (req) => baseWitness.reserveTicket(req),
        commitTicket: (_req) => {
          throw new Error("Simulated network outage during witness commitTicket");
        },
        releaseTicket: (req) => {
          releaseCalled = true;
          return baseWitness.releaseTicket(req);
        },
        reconcileTicket: (req) => baseWitness.reconcileTicket(req),
        listUnfinalizedTickets: () => baseWitness.listUnfinalizedTickets(),
      };

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: witnessProxy,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_p3b_01",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-p3b-commit-throw",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_p3b_01",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const res = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      // Assert fail-closed UNKNOWN decision and reconciliation ticket ID
      expect(res.decision).toBe("UNKNOWN");
      expect(res.witnessTicketId).toBeDefined();
      expect(res.reasons?.[0]).toContain("Local SQLite transaction committed, but witness commitment threw an error");
      expect(res.reasons?.[0]).toContain(`Ticket '${res.witnessTicketId}' requires reconciliation.`);

      // CRITICAL: releaseTicket MUST NOT have been called!
      expect(releaseCalled).toBe(false);

      // Verify SQLite state: record is permanently marked 'consumed'
      const record = engine.getAuthorizationRecord("auth-p3b-commit-throw");
      expect(record).not.toBeNull();
      expect(record?.state).toBe("consumed");

      // Verify witness state: ticket remains RESERVED (capacity held), NOT RELEASED
      const unfinalized = baseWitness.listUnfinalizedTickets();
      expect(unfinalized.length).toBe(1);
      expect(unfinalized[0].ticketId).toBe(res.witnessTicketId);
      expect(unfinalized[0].state).toBe("RESERVED");

      // Verify subsequent replay attempt is denied by SQLite single-use constraint
      const replay = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(replay.decision).toBe("DENY");
      expect(replay.reasons?.[0]).toContain("Transaction authorization has already been consumed");

      engine.close();
    });

    // Test 2: SQLite commit succeeds; commitTicket returns uncertain/failure; releaseTicket is NOT called
    it("SEC-M11-01: when SQLite commit succeeds but witness commitTicket returns DENY, does NOT call releaseTicket, returns UNKNOWN with witnessTicketId, leaves record consumed", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let releaseCalled = false;
      const witnessProxy: MonotonicWitnessAdapter = {
        name: "test-proxy-2",
        isTestOnlyMock: true,
        getSyncStatus: (epoch, seq) => baseWitness.getSyncStatus(epoch, seq),
        reserveTicket: (req) => baseWitness.reserveTicket(req),
        commitTicket: (_req) => ({
          decision: "DENY",
          reasons: ["Simulated witness Byzantine commit failure / hardware error"],
        }),
        releaseTicket: (req) => {
          releaseCalled = true;
          return baseWitness.releaseTicket(req);
        },
        reconcileTicket: (req) => baseWitness.reconcileTicket(req),
        listUnfinalizedTickets: () => baseWitness.listUnfinalizedTickets(),
      };

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: witnessProxy,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_p3b_02",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-p3b-commit-deny",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_p3b_02",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const res = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      // Assert fail-closed UNKNOWN decision and reconciliation ticket ID
      expect(res.decision).toBe("UNKNOWN");
      expect(res.witnessTicketId).toBeDefined();
      expect(res.reasons?.[0]).toContain("Local SQLite transaction committed, but witness commitment failed (Simulated witness Byzantine commit failure / hardware error)");
      expect(res.reasons?.[0]).toContain(`Ticket '${res.witnessTicketId}' requires reconciliation.`);

      // CRITICAL: releaseTicket MUST NOT have been called!
      expect(releaseCalled).toBe(false);

      // Verify SQLite state: record is permanently marked 'consumed'
      const record = engine.getAuthorizationRecord("auth-p3b-commit-deny");
      expect(record).not.toBeNull();
      expect(record?.state).toBe("consumed");

      // Capacity remains held on the witness
      const unfinalized = baseWitness.listUnfinalizedTickets();
      expect(unfinalized.length).toBe(1);
      expect(unfinalized[0].ticketId).toBe(res.witnessTicketId);

      engine.close();
    });

    // Test 3: Pre-commit failure follows intended cleanup path without consuming authorization
    it("cleans up witness reservation on pre-commit failure without consuming authorization in SQLite", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let releaseCalled = false;
      let releaseReason: string | undefined;
      const witnessProxy: MonotonicWitnessAdapter = {
        name: "test-proxy-3",
        isTestOnlyMock: true,
        getSyncStatus: (epoch, seq) => baseWitness.getSyncStatus(epoch, seq),
        reserveTicket: (req) => baseWitness.reserveTicket(req),
        commitTicket: (req) => baseWitness.commitTicket(req),
        releaseTicket: (req) => {
          releaseCalled = true;
          releaseReason = req.reason;
          return baseWitness.releaseTicket(req);
        },
        reconcileTicket: (req) => baseWitness.reconcileTicket(req),
        listUnfinalizedTickets: () => baseWitness.listUnfinalizedTickets(),
      };

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: witnessProxy,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_p3b_03",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      // Issue authorization
      const issued = engine.issue({
        authorizationId: "auth-p3b-precommit-revoke",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_p3b_03",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Revoke the policy before consumption (witness is not aware of local revocation)
      engine.policies.revoke(SAMPLE_POLICY.policyId);

      // Consumption should succeed in reserving on witness, then fail during SQLite revalidation
      const res = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(res.decision).toBe("DENY");
      expect(res.reasons?.[0]).toContain("Policy has been revoked");

      // Verify that releaseTicket was called with the rollback denial reason
      expect(releaseCalled).toBe(true);
      expect(releaseReason).toBe("Policy has been revoked.");

      // Authorization in SQLite remains 'issued' (unconsumed)
      const record = engine.getAuthorizationRecord("auth-p3b-precommit-revoke");
      expect(record).not.toBeNull();
      expect(record?.state).toBe("issued");

      // Unfinalized tickets list on witness has no hanging reservations
      const unfinalized = baseWitness.listUnfinalizedTickets();
      expect(unfinalized.length).toBe(0);

      engine.close();
    });

    // Test 4: Retry with same idempotency key but different policyId is rejected
    it("SEC-M11-02: rejects reservation retry with same idempotencyKey but differing policyId", () => {
      const witness = new LocalDeterministicWitness();
      const res1 = witness.reserveTicket({
        authorizationId: "auth-sec-m11-02-pol-id",
        bindingDigest: "sha256:" + "a".repeat(64),
        policyId: "policy_alpha",
        policyRevision: 1,
        idempotencyKey: "idemp_sec_m11_02_policy_id",
      });
      expect(res1.decision).toBe("ALLOW");
      expect(res1.ticketId).toBeDefined();

      const res2 = witness.reserveTicket({
        authorizationId: "auth-sec-m11-02-pol-id",
        bindingDigest: "sha256:" + "a".repeat(64),
        policyId: "policy_beta_changed",
        policyRevision: 1,
        idempotencyKey: "idemp_sec_m11_02_policy_id",
      });
      expect(res2.decision).toBe("DENY");
      expect(res2.reasons?.[0]).toContain("Conflicting payload for existing idempotency key");
      expect(res2.reasons?.[0]).toContain("policyId mismatch");
    });

    // Test 5: Retry with same idempotency key but different policyRevision is rejected
    it("SEC-M11-02: rejects reservation retry with same idempotencyKey but differing policyRevision", () => {
      const witness = new LocalDeterministicWitness();
      const res1 = witness.reserveTicket({
        authorizationId: "auth-sec-m11-02-pol-rev",
        bindingDigest: "sha256:" + "b".repeat(64),
        policyId: "policy_gamma",
        policyRevision: 1,
        idempotencyKey: "idemp_sec_m11_02_policy_rev",
      });
      expect(res1.decision).toBe("ALLOW");
      expect(res1.ticketId).toBeDefined();

      const res2 = witness.reserveTicket({
        authorizationId: "auth-sec-m11-02-pol-rev",
        bindingDigest: "sha256:" + "b".repeat(64),
        policyId: "policy_gamma",
        policyRevision: 2, // Modified revision
        idempotencyKey: "idemp_sec_m11_02_policy_rev",
      });
      expect(res2.decision).toBe("DENY");
      expect(res2.reasons?.[0]).toContain("Conflicting payload for existing idempotency key");
      expect(res2.reasons?.[0]).toContain("policyRevision mismatch");
    });

    // Test 6: Retry with changed budget amount/window constraints is rejected
    it("SEC-M11-02: rejects reservation retry with same idempotencyKey but altered budget constraints", () => {
      const witness = new LocalDeterministicWitness();
      const initialWindows = [
        {
          windowType: "HOURLY" as const,
          windowStart: 1700000000,
          requestedAmount: "1000000000000000000",
          maxCumulativeAmount: "5000000000000000000",
        },
      ];

      const res1 = witness.reserveTicket({
        authorizationId: "auth-sec-m11-02-budget",
        bindingDigest: "sha256:" + "c".repeat(64),
        policyId: "policy_delta",
        policyRevision: 1,
        idempotencyKey: "idemp_sec_m11_02_budget",
        budgetWindows: initialWindows,
      });
      expect(res1.decision).toBe("ALLOW");

      // 6a: Altered requestedAmount
      const resDiffAmount = witness.reserveTicket({
        authorizationId: "auth-sec-m11-02-budget",
        bindingDigest: "sha256:" + "c".repeat(64),
        policyId: "policy_delta",
        policyRevision: 1,
        idempotencyKey: "idemp_sec_m11_02_budget",
        budgetWindows: [
          {
            ...initialWindows[0],
            requestedAmount: "2000000000000000000",
          },
        ],
      });
      expect(resDiffAmount.decision).toBe("DENY");
      expect(resDiffAmount.reasons?.[0]).toContain("budgetWindows mismatch");

      // 6b: Altered windowType
      const resDiffType = witness.reserveTicket({
        authorizationId: "auth-sec-m11-02-budget",
        bindingDigest: "sha256:" + "c".repeat(64),
        policyId: "policy_delta",
        policyRevision: 1,
        idempotencyKey: "idemp_sec_m11_02_budget",
        budgetWindows: [
          {
            ...initialWindows[0],
            windowType: "DAILY" as const,
          },
        ],
      });
      expect(resDiffType.decision).toBe("DENY");
      expect(resDiffType.reasons?.[0]).toContain("budgetWindows mismatch");

      // 6c: Altered windowStart
      const resDiffStart = witness.reserveTicket({
        authorizationId: "auth-sec-m11-02-budget",
        bindingDigest: "sha256:" + "c".repeat(64),
        policyId: "policy_delta",
        policyRevision: 1,
        idempotencyKey: "idemp_sec_m11_02_budget",
        budgetWindows: [
          {
            ...initialWindows[0],
            windowStart: 1700003600,
          },
        ],
      });
      expect(resDiffStart.decision).toBe("DENY");
      expect(resDiffStart.reasons?.[0]).toContain("budgetWindows mismatch");

      // 6d: Altered maxCumulativeAmount
      const resDiffMax = witness.reserveTicket({
        authorizationId: "auth-sec-m11-02-budget",
        bindingDigest: "sha256:" + "c".repeat(64),
        policyId: "policy_delta",
        policyRevision: 1,
        idempotencyKey: "idemp_sec_m11_02_budget",
        budgetWindows: [
          {
            ...initialWindows[0],
            maxCumulativeAmount: "9000000000000000000",
          },
        ],
      });
      expect(resDiffMax.decision).toBe("DENY");
      expect(resDiffMax.reasons?.[0]).toContain("budgetWindows mismatch");

      // 6e: Omitted budgetWindows entirely
      const resOmitted = witness.reserveTicket({
        authorizationId: "auth-sec-m11-02-budget",
        bindingDigest: "sha256:" + "c".repeat(64),
        policyId: "policy_delta",
        policyRevision: 1,
        idempotencyKey: "idemp_sec_m11_02_budget",
      });
      expect(resOmitted.decision).toBe("DENY");
      expect(resOmitted.reasons?.[0]).toContain("budgetWindows mismatch");
    });

    // Test 7: Concurrent retry and commit/release paths do not permit contradictory terminal states
    it("strictly prohibits contradictory terminal state transitions (COMMITTED -> RELEASED or RELEASED -> COMMITTED)", () => {
      const witness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });

      // Path A: A committed ticket can never transition to RELEASED
      const rA = witness.reserveTicket({
        authorizationId: "auth-p3b-term-A",
        bindingDigest: "sha256:" + "e".repeat(64),
        policyId: "pol_terminal",
        policyRevision: 1,
        idempotencyKey: "idemp_terminal_A",
      });
      expect(rA.decision).toBe("ALLOW");
      const cA = witness.commitTicket({
        ticketId: rA.ticketId!,
        authorizationId: "auth-p3b-term-A",
        bindingDigest: "sha256:" + "e".repeat(64),
        localCommittedAtSeconds: 1700000000,
        idempotencyKey: "idemp_terminal_A",
      });
      expect(cA.decision).toBe("ALLOW");

      // Attempt to release after commit
      const relA = witness.releaseTicket({
        ticketId: rA.ticketId!,
        authorizationId: "auth-p3b-term-A",
        bindingDigest: "sha256:" + "e".repeat(64),
        reason: "adversarial_post_commit_release_attempt",
      });
      expect(relA.success).toBe(false);
      expect(relA.reasons?.[0]).toContain("already been committed");

      // Path B: A released ticket can never transition to COMMITTED
      const rB = witness.reserveTicket({
        authorizationId: "auth-p3b-term-B",
        bindingDigest: "sha256:" + "f".repeat(64),
        policyId: "pol_terminal",
        policyRevision: 1,
        idempotencyKey: "idemp_terminal_B",
      });
      expect(rB.decision).toBe("ALLOW");
      const relB = witness.releaseTicket({
        ticketId: rB.ticketId!,
        authorizationId: "auth-p3b-term-B",
        bindingDigest: "sha256:" + "f".repeat(64),
        reason: "valid_pre_commit_abort",
      });
      expect(relB.success).toBe(true);

      // Attempt to commit after release
      const cB = witness.commitTicket({
        ticketId: rB.ticketId!,
        authorizationId: "auth-p3b-term-B",
        bindingDigest: "sha256:" + "f".repeat(64),
        localCommittedAtSeconds: 1700000000,
        idempotencyKey: "idemp_terminal_B",
      });
      expect(cB.decision).toBe("DENY");
      expect(cB.reasons?.[0]).toContain("already been permanently released");

      // Path C: Commit attempt with mismatched idempotencyKey is rejected
      const rC = witness.reserveTicket({
        authorizationId: "auth-p3b-term-C",
        bindingDigest: "sha256:" + "7".repeat(64),
        policyId: "pol_terminal",
        policyRevision: 1,
        idempotencyKey: "idemp_terminal_C_expected",
      });
      expect(rC.decision).toBe("ALLOW");
      const cC = witness.commitTicket({
        ticketId: rC.ticketId!,
        authorizationId: "auth-p3b-term-C",
        bindingDigest: "sha256:" + "7".repeat(64),
        localCommittedAtSeconds: 1700000000,
        idempotencyKey: "idemp_terminal_C_mismatched",
      });
      expect(cC.decision).toBe("DENY");
      expect(cC.reasons?.[0]).toContain("idempotency key mismatch");
    });
  });

  describe("Milestone 11 Phase 3C: SEC-M11-03 Retry-Path Remediation & Capacity Protection", () => {
    let testDir: string;
    let dbPath: string;

    beforeEach(() => {
      testDir = createTestDirectory();
      dbPath = join(testDir, "test-witness-p3c.sqlite3");
    });

    afterEach(() => {
      try {
        rmSync(testDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors on Windows
      }
    });

    // Test 1: Exact reproduction of SEC-M11-03
    it("SEC-M11-03: retrying consume after UNKNOWN post-commit failure does NOT release witness reservation or refund capacity", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let releaseCalled = false;
      const witnessProxy: MonotonicWitnessAdapter = {
        name: "test-proxy-p3c-1",
        isTestOnlyMock: true,
        getSyncStatus: (epoch, seq) => baseWitness.getSyncStatus(epoch, seq),
        reserveTicket: (req) => baseWitness.reserveTicket(req),
        commitTicket: (_req) => {
          throw new Error("Simulated network drop on witness commitTicket");
        },
        releaseTicket: (req) => {
          releaseCalled = true;
          return baseWitness.releaseTicket(req);
        },
        reconcileTicket: (req) => baseWitness.reconcileTicket(req),
        listUnfinalizedTickets: () => baseWitness.listUnfinalizedTickets(),
      };

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: witnessProxy,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_p3c_01",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-p3c-repro-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_p3c_01",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // 1. Initial consumption attempt: SQLite commits, commitTicket throws
      const res1 = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(res1.decision).toBe("UNKNOWN");
      expect(res1.witnessTicketId).toBeDefined();
      expect(releaseCalled).toBe(false);

      // Verify witness state: ticket is in RESERVED state (capacity held)
      const unfinalized1 = baseWitness.listUnfinalizedTickets();
      expect(unfinalized1.length).toBe(1);
      expect(unfinalized1[0].ticketId).toBe(res1.witnessTicketId);
      expect(unfinalized1[0].state).toBe("RESERVED");

      // Verify SQLite state: record is marked 'consumed'
      const record1 = engine.getAuthorizationRecord("auth-p3c-repro-01");
      expect(record1).not.toBeNull();
      expect(record1?.state).toBe("consumed");

      // Reset release tracker before retry
      releaseCalled = false;

      // 2. Retry consumption attempt: Client retries after receiving UNKNOWN
      const res2 = engine.consume({
        artifact: issued.artifact,
        request: SAMPLE_TX_REQUEST,
      });

      // Assert replay is denied by SQLite single-use constraint
      expect(res2.decision).toBe("DENY");
      expect(res2.reasons?.[0]).toContain("Bound transaction authorization is unknown, consumed, or mismatched.");

      // CRITICAL INVARIANT: releaseTicket MUST NOT have been called on retry!
      expect(releaseCalled).toBe(false);

      // Witness ticket MUST still be RESERVED and capacity MUST remain held!
      const unfinalized2 = baseWitness.listUnfinalizedTickets();
      expect(unfinalized2.length).toBe(1);
      expect(unfinalized2[0].ticketId).toBe(res1.witnessTicketId);
      expect(unfinalized2[0].state).toBe("RESERVED");

      const ticketStatus = baseWitness.reconcileTicket({ ticketId: res1.witnessTicketId! });
      expect(ticketStatus.state).toBe("RESERVED");

      // SQLite record remains 'consumed'
      const record2 = engine.getAuthorizationRecord("auth-p3c-repro-01");
      expect(record2?.state).toBe("consumed");

      engine.close();
    });

    // Test 2: Repeated retries after UNKNOWN
    it("safely handles repeated retries after UNKNOWN without leaking capacity or releasing witness reservation", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let releaseCallCount = 0;
      const witnessProxy: MonotonicWitnessAdapter = {
        name: "test-proxy-p3c-2",
        isTestOnlyMock: true,
        getSyncStatus: (epoch, seq) => baseWitness.getSyncStatus(epoch, seq),
        reserveTicket: (req) => baseWitness.reserveTicket(req),
        commitTicket: (_req) => {
          throw new Error("Persistent timeout on witness commitTicket");
        },
        releaseTicket: (req) => {
          releaseCallCount++;
          return baseWitness.releaseTicket(req);
        },
        reconcileTicket: (req) => baseWitness.reconcileTicket(req),
        listUnfinalizedTickets: () => baseWitness.listUnfinalizedTickets(),
      };

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: witnessProxy,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_p3c_02",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-p3c-repeat-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_p3c_02",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Initial consumption: UNKNOWN
      const resInitial = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(resInitial.decision).toBe("UNKNOWN");
      expect(releaseCallCount).toBe(0);

      // Perform 3 sequential retries
      for (let i = 1; i <= 3; i++) {
        const retryRes = engine.consume({
          artifact: issued.artifact,
          request: SAMPLE_TX_REQUEST,
        });
        expect(retryRes.decision).toBe("DENY");
        expect(retryRes.reasons?.[0]).toContain("Bound transaction authorization is unknown, consumed, or mismatched.");
        expect(releaseCallCount).toBe(0);
      }

      // Verify unfinalized tickets still holds the reservation
      const unfinalized = baseWitness.listUnfinalizedTickets();
      expect(unfinalized.length).toBe(1);
      expect(unfinalized[0].ticketId).toBe(resInitial.witnessTicketId);

      engine.close();
    });

    // Test 3: Pre-commit abort still releases tickets when provably safe
    it("releases witness reservation cleanly on provable pre-commit revalidation failure", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let releaseCalled = false;
      let releaseReason: string | undefined;
      const witnessProxy: MonotonicWitnessAdapter = {
        name: "test-proxy-p3c-3",
        isTestOnlyMock: true,
        getSyncStatus: (epoch, seq) => baseWitness.getSyncStatus(epoch, seq),
        reserveTicket: (req) => baseWitness.reserveTicket(req),
        commitTicket: (req) => baseWitness.commitTicket(req),
        releaseTicket: (req) => {
          releaseCalled = true;
          releaseReason = req.reason;
          return baseWitness.releaseTicket(req);
        },
        reconcileTicket: (req) => baseWitness.reconcileTicket(req),
        listUnfinalizedTickets: () => baseWitness.listUnfinalizedTickets(),
      };

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: witnessProxy,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_p3c_03",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-p3c-precommit-abort",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_p3c_03",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Revoke the policy before consumption
      engine.policies.revoke(SAMPLE_POLICY.policyId);

      // Consume: witness reservation succeeds, but SQLite revalidation fails on revoked policy
      const res = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(res.decision).toBe("DENY");
      expect(res.reasons?.[0]).toContain("Policy has been revoked");

      // Verify releaseTicket WAS called with the revocation reason
      expect(releaseCalled).toBe(true);
      expect(releaseReason).toBe("Policy has been revoked.");

      // SQLite record remains 'issued'
      const record = engine.getAuthorizationRecord("auth-p3c-precommit-abort");
      expect(record?.state).toBe("issued");

      // Witness capacity was reclaimed
      expect(baseWitness.listUnfinalizedTickets().length).toBe(0);

      engine.close();
    });

    // Test 4: In-lock replay check preserves witness reservation when pre-check is bypassed
    it("preserves witness reservation under write lock when authorization was consumed concurrently", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let releaseCalled = false;
      const witnessProxy: MonotonicWitnessAdapter = {
        name: "test-proxy-p3c-4",
        isTestOnlyMock: true,
        getSyncStatus: (epoch, seq) => baseWitness.getSyncStatus(epoch, seq),
        reserveTicket: (req) => baseWitness.reserveTicket(req),
        commitTicket: (_req) => {
          throw new Error("Witness commit failed");
        },
        releaseTicket: (req) => {
          releaseCalled = true;
          return baseWitness.releaseTicket(req);
        },
        reconcileTicket: (req) => baseWitness.reconcileTicket(req),
        listUnfinalizedTickets: () => baseWitness.listUnfinalizedTickets(),
      };

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: witnessProxy,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_p3c_04",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-p3c-race-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_p3c_04",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Consume attempt 1 -> UNKNOWN
      const res1 = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(res1.decision).toBe("UNKNOWN");
      expect(releaseCalled).toBe(false);

      // Construct fresh valid envelope matching request
      const envelopeCreated = createTransactionEnvelope(SAMPLE_TX_REQUEST);
      expect(envelopeCreated.ok).toBe(true);
      if (!envelopeCreated.ok) return;

      releaseCalled = false;
      const res2 = engine.consume({
        artifact: issued.artifact,
        envelope: envelopeCreated.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(res2.decision).toBe("DENY");
      expect(res2.reasons?.[0]).toContain("Bound transaction authorization is unknown, consumed, or mismatched.");

      // Verify releaseTicket was NOT called
      expect(releaseCalled).toBe(false);

      // Capacity remains held
      const unfinalized = baseWitness.listUnfinalizedTickets();
      expect(unfinalized.length).toBe(1);
      expect(unfinalized[0].ticketId).toBe(res1.witnessTicketId);

      engine.close();
    });

    // Test 5: Storage failure during write transaction does NOT release reservation
    it("fails closed without releasing witness reservation when transaction commit fails with uncertain outcome", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let releaseCalled = false;
      const witnessProxy: MonotonicWitnessAdapter = {
        name: "test-proxy-p3c-5",
        isTestOnlyMock: true,
        getSyncStatus: (epoch, seq) => baseWitness.getSyncStatus(epoch, seq),
        reserveTicket: (req) => baseWitness.reserveTicket(req),
        commitTicket: (req) => baseWitness.commitTicket(req),
        releaseTicket: (req) => {
          releaseCalled = true;
          return baseWitness.releaseTicket(req);
        },
        reconcileTicket: (req) => baseWitness.reconcileTicket(req),
        listUnfinalizedTickets: () => baseWitness.listUnfinalizedTickets(),
      };

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: witnessProxy,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_p3c_05",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-p3c-taint-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_p3c_05",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Mock db.exec to throw on COMMIT
      const db = (engine as any).store.db;
      const origExec = db.exec.bind(db);
      db.exec = (sql: string) => {
        if (typeof sql === "string" && sql.includes("COMMIT;")) {
          throw new Error("Disk I/O error during SQLite COMMIT;");
        }
        return origExec(sql);
      };

      // Consume should throw or fail, taints the store
      expect(() => {
        engine.consume({
          artifact: issued.artifact,
          envelope: issued.envelope,
          request: SAMPLE_TX_REQUEST,
        });
      }).toThrow(/Disk I\/O error during SQLite COMMIT;/);

      // Verify releaseTicket was NOT called because store was tainted and commit was uncertain
      expect(releaseCalled).toBe(false);

      // Restore exec
      db.exec = origExec;
      engine.close();
    });
  });
});
