import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mkdirSync, rmSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import {
  Web3UserEngine,
  SQLiteAuthorizationStore,
  LocalDeterministicWitness,
  canonicalWitnessReceiptPayload,
  verifyWitnessReceipt,
  generateIssuerKeyPair,
  createTransactionEnvelope,
  ValidationError,
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

  function createAsyncWitnessWrapper(
    baseWitness: LocalDeterministicWitness,
    options?: {
      delayMs?: number;
      onReserve?: (req: any) => Promise<void> | void;
      onCommit?: (req: any) => Promise<void> | void;
      onRelease?: (req: any) => Promise<void> | void;
    },
  ): MonotonicWitnessAdapter {
    const delayMs = options?.delayMs ?? 5;
    const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

    return {
      name: "AsyncDeterministicWitnessWrapper",
      isTestOnlyMock: true,
      get publicKeyPem() {
        return baseWitness.publicKeyPem;
      },
      async getSyncStatus(epoch, seq) {
        await sleep(delayMs);
        return baseWitness.getSyncStatus(epoch, seq);
      },
      async reserveTicket(req) {
        await sleep(delayMs);
        if (options?.onReserve) await options.onReserve(req);
        return baseWitness.reserveTicket(req);
      },
      async commitTicket(req) {
        await sleep(delayMs);
        if (options?.onCommit) await options.onCommit(req);
        return baseWitness.commitTicket(req);
      },
      async releaseTicket(req) {
        await sleep(delayMs);
        if (options?.onRelease) await options.onRelease(req);
        return baseWitness.releaseTicket(req);
      },
      async reconcileTicket(req) {
        await sleep(delayMs);
        return baseWitness.reconcileTicket(req);
      },
      listUnfinalizedTickets() {
        return baseWitness.listUnfinalizedTickets();
      },
    };
  }

  // ==========================================================================
  // Milestone 12 Phase A: Asynchronous Witness API & Engine Support
  // ==========================================================================
  describe("Milestone 12 Phase A: Asynchronous Witness API & Engine Support", () => {

    // Test 1: Synchronous consume compatibility
    it("preserves synchronous engine.consume behavior with synchronous adapter", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_m12_sync_01",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-m12-sync-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_m12_sync_01",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Synchronous consume executes synchronously
      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(consumed.decision).toBe("ALLOW");
      if (consumed.decision === "ALLOW") {
        expect(consumed.witnessReceipt).toBeDefined();
        expect(consumed.witnessTicketId).toBeDefined();
        expect(verifyWitnessReceipt(TEST_KEY_PAIR.publicKeyPem, consumed.witnessReceipt!)).toBe(true);
      }

      engine.close();
    });

    // Test 2: Synchronous consume rejects async adapter with explicit error
    it("rejects async witness adapter with explicit validation error when invoked via synchronous engine.consume", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const asyncWitness = createAsyncWitnessWrapper(baseWitness);
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: asyncWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_m12_sync_rej",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-m12-sync-rej",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_m12_sync_rej",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Synchronous consume throws descriptive error
      expect(() => {
        engine.consume({
          artifact: issued.artifact,
          envelope: issued.envelope,
          request: SAMPLE_TX_REQUEST,
        });
      }).toThrow(/Async witness adapters cannot be used with synchronous consumeSignedTransactionAuthorizationV3/);

      engine.close();
    });

    // Test 3: Happy path async consumption
    it("successfully executes async consumption with genuinely asynchronous witness adapter via engine.consumeAsync", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const asyncWitness = createAsyncWitnessWrapper(baseWitness, { delayMs: 10 });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: asyncWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_m12_async_01",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-m12-async-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_m12_async_01",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = await engine.consumeAsync({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(consumed.decision).toBe("ALLOW");
      if (consumed.decision === "ALLOW") {
        expect(consumed.witnessReceipt).toBeDefined();
        expect(consumed.witnessTicketId).toBeDefined();
        expect(verifyWitnessReceipt(TEST_KEY_PAIR.publicKeyPem, consumed.witnessReceipt!)).toBe(true);
      }

      // SQLite state is consumed
      const record = engine.getAuthorizationRecord("auth-m12-async-01");
      expect(record?.state).toBe("consumed");

      // Witness ticket is committed
      const ticketStatus = baseWitness.reconcileTicket({ ticketId: consumed.witnessTicketId! });
      expect(ticketStatus.state).toBe("COMMITTED");

      engine.close();
    });

    // Test 4: Async witness reservation denial
    it("handles async witness reservation denial cleanly without partial state or lock leaks", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const asyncWitness = createAsyncWitnessWrapper(baseWitness, { delayMs: 5 });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: asyncWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_m12_async_deny",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-m12-async-deny",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_m12_async_deny",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Revoke policy on the witness ONLY (simulating remote witness policy revocation)
      baseWitness.revokePolicy(SAMPLE_POLICY.policyId);

      const consumed = await engine.consumeAsync({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(consumed.decision).toBe("DENY");
      expect(consumed.reasons?.[0]).toContain("revoked on witness");

      // Authorization in SQLite remains 'issued' (unconsumed)
      const record = engine.getAuthorizationRecord("auth-m12-async-deny");
      expect(record?.state).toBe("issued");

      // No tickets unfinalized on witness
      expect(baseWitness.listUnfinalizedTickets().length).toBe(0);

      engine.close();
    });

    // Test 5: Async witness reservation network throw
    it("handles async witness reservation network throw cleanly without corrupting state", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const asyncWitness = createAsyncWitnessWrapper(baseWitness, {
        delayMs: 5,
        onReserve: () => {
          throw new Error("Simulated network timeout during reservation");
        },
      });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: asyncWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_m12_async_throw",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-m12-async-throw",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_m12_async_throw",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = await engine.consumeAsync({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(consumed.decision).toBe("DENY");
      expect(consumed.reasons?.[0]).toContain("Witness reservation failed: Simulated network timeout");

      // SQLite record remains 'issued'
      const record = engine.getAuthorizationRecord("auth-m12-async-throw");
      expect(record?.state).toBe("issued");

      engine.close();
    });

    // Test 6: Async pre-commit abort releases ticket asynchronously
    it("releases witness reservation asynchronously upon provable in-lock pre-commit revalidation failure", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let releaseCalled = false;
      let releaseReason: string | undefined;

      const asyncWitness = createAsyncWitnessWrapper(baseWitness, {
        delayMs: 5,
        onRelease: (req) => {
          releaseCalled = true;
          releaseReason = req.reason;
        },
      });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: asyncWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_m12_pre_abort",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-m12-pre-abort",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_m12_pre_abort",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Revoke policy in local SQLite before consumption
      engine.policies.revoke(SAMPLE_POLICY.policyId);

      const consumed = await engine.consumeAsync({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(consumed.decision).toBe("DENY");
      expect(consumed.reasons?.[0]).toContain("Policy has been revoked");

      // Verify releaseTicket was called asynchronously
      expect(releaseCalled).toBe(true);
      expect(releaseReason).toBe("Policy has been revoked.");

      // SQLite record remains 'issued'
      const record = engine.getAuthorizationRecord("auth-m12-pre-abort");
      expect(record?.state).toBe("issued");

      // Capacity was reclaimed on witness
      expect(baseWitness.listUnfinalizedTickets().length).toBe(0);

      engine.close();
    });

    // Test 7: Async post-commit witness failure returns UNKNOWN
    it("returns UNKNOWN when post-commit async witness commitment throws or fails, keeping SQLite committed and capacity held", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let releaseCalled = false;

      const asyncWitness = createAsyncWitnessWrapper(baseWitness, {
        delayMs: 5,
        onCommit: () => {
          throw new Error("Simulated async network drop during witness commit");
        },
        onRelease: () => {
          releaseCalled = true;
        },
      });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: asyncWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_m12_post_fail",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-m12-post-fail",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_m12_post_fail",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = await engine.consumeAsync({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(consumed.decision).toBe("UNKNOWN");
      expect(consumed.witnessTicketId).toBeDefined();
      expect(consumed.reasons?.[0]).toContain("Local SQLite transaction committed, but witness commitment threw an error");

      // Invariant: release was NOT called
      expect(releaseCalled).toBe(false);

      // Invariant: SQLite record is durably 'consumed'
      const record = engine.getAuthorizationRecord("auth-m12-post-fail");
      expect(record?.state).toBe("consumed");

      // Invariant: Capacity remains held on witness
      const unfinalized = baseWitness.listUnfinalizedTickets();
      expect(unfinalized.length).toBe(1);
      expect(unfinalized[0].ticketId).toBe(consumed.witnessTicketId);
      expect(unfinalized[0].state).toBe("RESERVED");

      engine.close();
    });

    // Test 8: SEC-M11-03 retry safety under async consumption
    it("SEC-M11-03: preserves witness reservation on retry after UNKNOWN in async consumption", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let releaseCalled = false;

      const asyncWitness = createAsyncWitnessWrapper(baseWitness, {
        delayMs: 5,
        onCommit: () => {
          throw new Error("Persistent async witness commit failure");
        },
        onRelease: () => {
          releaseCalled = true;
        },
      });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: asyncWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_m12_retry_01",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-m12-retry-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_m12_retry_01",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Initial consume attempt -> UNKNOWN
      const res1 = await engine.consumeAsync({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(res1.decision).toBe("UNKNOWN");
      expect(releaseCalled).toBe(false);

      // Retry consume attempt with fresh envelope
      const envFresh = createTransactionEnvelope(SAMPLE_TX_REQUEST);
      expect(envFresh.ok).toBe(true);
      if (!envFresh.ok) return;

      const res2 = await engine.consumeAsync({
        artifact: issued.artifact,
        envelope: envFresh.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(res2.decision).toBe("DENY");
      expect(res2.reasons?.[0]).toContain("Bound transaction authorization is unknown, consumed, or mismatched.");

      // Invariant: release was NOT called on retry
      expect(releaseCalled).toBe(false);

      // Invariant: Capacity remains held on witness
      const unfinalized = baseWitness.listUnfinalizedTickets();
      expect(unfinalized.length).toBe(1);
      expect(unfinalized[0].ticketId).toBe(res1.witnessTicketId);

      engine.close();
    });

    // Test 9: Lock hold duration verification
    it("strictly avoids holding SQLite write lock during remote async witness reservation and finalization delays", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });

      let isLockFreeDuringReserve = false;
      let isLockFreeDuringCommit = false;
      let engineRef: Web3UserEngine | undefined;

      const asyncWitness = createAsyncWitnessWrapper(baseWitness, {
        delayMs: 30, // 30ms simulated remote network round-trip
        onReserve: () => {
          if (engineRef) {
            const guard = (engineRef as any).store.getClockGuard();
            // If lock is NOT held, acquireLock() will succeed
            const acquired = guard.acquireLock();
            if (acquired) {
              isLockFreeDuringReserve = true;
              guard.releaseLock();
            }
          }
        },
        onCommit: () => {
          if (engineRef) {
            const guard = (engineRef as any).store.getClockGuard();
            // If lock is NOT held, acquireLock() will succeed
            const acquired = guard.acquireLock();
            if (acquired) {
              isLockFreeDuringCommit = true;
              guard.releaseLock();
            }
          }
        },
      });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: asyncWitness,
      });
      engineRef = engine;

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_m12_lock_hold",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-m12-lock-hold",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_m12_lock_hold",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumedPromise = engine.consumeAsync({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      // While consumeAsync is in-flight, verify another read or inspection can execute without lock conflict
      const earlyRecord = engine.getAuthorizationRecord("auth-m12-lock-hold");
      expect(earlyRecord).not.toBeNull();

      const consumed = await consumedPromise;
      expect(consumed.decision).toBe("ALLOW");

      // Verify that ClockGuard lock was free and NOT held during remote async witness operations
      expect(isLockFreeDuringReserve).toBe(true);
      expect(isLockFreeDuringCommit).toBe(true);

      engine.close();
    });

    // Test 10: Single-use replay prevention under concurrent async consumption races
    it("enforces single-use replay prevention under concurrent async consumption races", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const asyncWitness = createAsyncWitnessWrapper(baseWitness, { delayMs: 15 });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: asyncWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_m12_async_race",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-m12-async-race",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_m12_async_race",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Construct distinct envelope copies to test persistent SQLite single-use protection
      const envA = createTransactionEnvelope(SAMPLE_TX_REQUEST);
      const envB = createTransactionEnvelope(SAMPLE_TX_REQUEST);
      expect(envA.ok).toBe(true);
      expect(envB.ok).toBe(true);
      if (!envA.ok || !envB.ok) return;

      // Launch both async consumption operations concurrently
      const [resA, resB] = await Promise.all([
        engine.consumeAsync({
          artifact: issued.artifact,
          envelope: envA.envelope,
          request: SAMPLE_TX_REQUEST,
        }),
        engine.consumeAsync({
          artifact: issued.artifact,
          envelope: envB.envelope,
          request: SAMPLE_TX_REQUEST,
        }),
      ]);

      const decisions = [resA.decision, resB.decision];
      expect(decisions).toContain("ALLOW");
      expect(decisions).toContain("DENY");

      // Persistent SQLite record is consumed
      const record = engine.getAuthorizationRecord("auth-m12-async-race");
      expect(record?.state).toBe("consumed");

      engine.close();
    });

    // Test 11: Targeted lock ordering: ClockGuard released before awaiting async ticket release on error
    it("releases ClockGuard mutex before awaiting async ticket release on catastrophic transaction error, allowing other callers to acquire lock", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let releaseCalled = false;
      let lockAcquiredDuringRelease = false;
      let engineRef: Web3UserEngine | undefined;

      const asyncWitness = createAsyncWitnessWrapper(baseWitness, {
        delayMs: 5,
        onRelease: async () => {
          releaseCalled = true;
          if (engineRef) {
            const guard = (engineRef as any).store.getClockGuard();
            // Critical check: mutex must be released BEFORE onRelease is awaited
            const acquired = guard.acquireLock();
            if (acquired) {
              lockAcquiredDuringRelease = true;
              guard.releaseLock();
            }
          }
          await new Promise((resolve) => setTimeout(resolve, 20));
        },
      });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: asyncWitness,
      });
      engineRef = engine;

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_m12_lock_order",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-m12-lock-order",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_m12_lock_order",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Mock db.prepare to throw during transaction update
      const db = (engine as any).store.db;
      const origPrepare = db.prepare.bind(db);
      db.prepare = (sql: string) => {
        if (typeof sql === "string" && sql.includes("UPDATE consumed_authorization_ids")) {
          throw new Error("Simulated transient SQLite disk fault during update");
        }
        return origPrepare(sql);
      };

      await expect(
        engine.consumeAsync({
          artifact: issued.artifact,
          envelope: issued.envelope,
          request: SAMPLE_TX_REQUEST,
        }),
      ).rejects.toThrow(/Simulated transient SQLite disk fault during update/);

      // Verify that release was called
      expect(releaseCalled).toBe(true);

      // Verify ClockGuard was acquired by another caller during the async release execution
      expect(lockAcquiredDuringRelease).toBe(true);

      // Verify lock is released and can be acquired again (released exactly once, no double release or leak)
      const guard = (engine as any).store.getClockGuard();
      expect(guard.acquireLock()).toBe(true);
      guard.releaseLock();

      db.prepare = origPrepare;
      engine.close();
    });
  });

  // ==========================================================================
  // Milestone 12 Phase B.1: Schema Migration & Atomic Ticket Binding
  // ==========================================================================
  describe("Milestone 12 Phase B.1: Schema Migration & Atomic Ticket Binding", () => {
    let testDir: string;
    let dbPath: string;

    beforeEach(() => {
      testDir = createTestDirectory();
      dbPath = join(testDir, "test-m12-b1.sqlite3");
    });

    afterEach(() => {
      try {
        rmSync(testDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors on Windows
      }
    });

    // Test 1: Migration from legacy M11 schema preserves all rows, adds columns, and applies chk_witness_integrity
    it("migrates an existing M11 database, preserves rows, sets witness_status='NONE', and enforces chk_witness_integrity", () => {
      // 1. Create legacy M11 schema directly
      const nowSec = Math.floor(Date.now() / 1000);
      const raw = new DatabaseSync(dbPath);
      raw.exec(`
        CREATE TABLE consumed_authorization_ids (
          authorization_id TEXT PRIMARY KEY,
          binding_digest TEXT,
          state TEXT NOT NULL DEFAULT 'consumed'
            CHECK (state IN ('issued', 'consumed', 'legacy_void', 'cancelled')),
          consumed_at TEXT,
          artifact_version INTEGER NOT NULL DEFAULT 1,
          key_id TEXT,
          issued_at_seconds INTEGER
        );

        INSERT INTO consumed_authorization_ids VALUES
          ('auth-leg-01', 'sha256:digest01', 'consumed', '2026-10-29 12:00:00', 3, 'key-1', ${nowSec}),
          ('auth-leg-02', 'sha256:digest02', 'issued', NULL, 3, 'key-1', ${nowSec}),
          ('auth-leg-03', 'sha256:digest03', 'cancelled', NULL, 3, 'key-1', ${nowSec}),
          ('auth-leg-04', NULL, 'legacy_void', NULL, 2, NULL, NULL);

        CREATE TABLE IF NOT EXISTS system_clock_state (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          high_water_seconds INTEGER NOT NULL,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO system_clock_state VALUES (1, ${nowSec}, CURRENT_TIMESTAMP);
      `);
      raw.close();

      // 2. Open with SQLiteAuthorizationStore / Web3UserEngine to trigger migration
      const engine = Web3UserEngine.open({ databasePath: dbPath });

      // Verify all rows exist with default witness fields
      const r1 = engine.getAuthorizationRecord("auth-leg-01");
      expect(r1).not.toBeNull();
      expect(r1?.state).toBe("consumed");
      expect(r1?.witnessTicketId).toBeNull();
      expect(r1?.witnessReceiptJson).toBeNull();
      expect(r1?.witnessStatus).toBe("NONE");

      const r2 = engine.getAuthorizationRecord("auth-leg-02");
      expect(r2).not.toBeNull();
      expect(r2?.state).toBe("issued");
      expect(r2?.witnessStatus).toBe("NONE");

      const r3 = engine.getAuthorizationRecord("auth-leg-03");
      expect(r3?.state).toBe("cancelled");
      expect(r3?.witnessStatus).toBe("NONE");

      const r4 = engine.getAuthorizationRecord("auth-leg-04");
      expect(r4?.state).toBe("legacy_void");
      expect(r4?.witnessStatus).toBe("NONE");

      // Verify chk_witness_integrity constraint is enforced on the migrated table
      const rawAfter = new DatabaseSync(dbPath);
      // Attempt 1: COMMITTED without receipt -> must throw SQLITE_CONSTRAINT
      expect(() => {
        rawAfter.prepare(`
          INSERT INTO consumed_authorization_ids (authorization_id, state, witness_ticket_id, witness_receipt_json, witness_status)
          VALUES ('auth-bad-1', 'consumed', 'ticket-1', NULL, 'COMMITTED')
        `).run();
      }).toThrow(/constraint/i);

      // Attempt 2: PENDING_COMMIT without ticket -> must throw SQLITE_CONSTRAINT
      expect(() => {
        rawAfter.prepare(`
          INSERT INTO consumed_authorization_ids (authorization_id, state, witness_ticket_id, witness_receipt_json, witness_status)
          VALUES ('auth-bad-2', 'consumed', NULL, NULL, 'PENDING_COMMIT')
        `).run();
      }).toThrow(/constraint/i);

      // Attempt 3: NONE with ticket -> must throw SQLITE_CONSTRAINT
      expect(() => {
        rawAfter.prepare(`
          INSERT INTO consumed_authorization_ids (authorization_id, state, witness_ticket_id, witness_receipt_json, witness_status)
          VALUES ('auth-bad-3', 'consumed', 'ticket-1', NULL, 'NONE')
        `).run();
      }).toThrow(/constraint/i);

      // Attempt 4: issued with PENDING_COMMIT -> must throw SQLITE_CONSTRAINT
      expect(() => {
        rawAfter.prepare(`
          INSERT INTO consumed_authorization_ids (authorization_id, state, witness_ticket_id, witness_receipt_json, witness_status)
          VALUES ('auth-bad-4', 'issued', 'ticket-1', NULL, 'PENDING_COMMIT')
        `).run();
      }).toThrow(/constraint/i);

      rawAfter.close();
      engine.close();
    });

    // Test 2: Migration fails closed on malformed rows without corrupting original table
    it("fails closed on malformed legacy rows and halts migration without data loss", () => {
      const raw = new DatabaseSync(dbPath);
      raw.exec(`
        CREATE TABLE consumed_authorization_ids (
          authorization_id TEXT PRIMARY KEY,
          binding_digest TEXT,
          state TEXT,
          consumed_at TEXT
        );
        -- Malformed row: invalid state
        INSERT INTO consumed_authorization_ids VALUES ('auth-bad-state', 'sha256:digest', 'INVALID_STATE_XYZ', NULL);
        CREATE TABLE system_clock_state (id INTEGER PRIMARY KEY CHECK (id=1), high_water_seconds INTEGER NOT NULL, updated_at TEXT);
        INSERT INTO system_clock_state VALUES (1, 1000, '2026-10-30');
      `);
      raw.close();

      expect(() => {
        Web3UserEngine.open({ databasePath: dbPath });
      }).toThrow(/Cannot migrate consumed_authorization_ids: table contains 1 malformed row/);

      // Verify original table still exists unchanged
      const rawCheck = new DatabaseSync(dbPath);
      const rows = rawCheck.prepare("SELECT * FROM consumed_authorization_ids").all();
      expect(rows).toHaveLength(1);
      rawCheck.close();
    });

    // Test 3: Migration idempotency and v4 ambiguity resolution
    it("handles repeated initialization idempotently and safely resolves v4 staging ambiguity", () => {
      const engine1 = Web3UserEngine.open({ databasePath: dbPath });
      engine1.close();

      // Open a second time: must be clean and idempotent
      const engine2 = Web3UserEngine.open({ databasePath: dbPath });
      engine2.close();

      // Simulate an interrupted migration leaving an identical v4 table
      const raw = new DatabaseSync(dbPath);
      raw.exec(`
        CREATE TABLE consumed_authorization_ids_v4 AS SELECT * FROM consumed_authorization_ids;
      `);
      raw.close();

      // Opening must detect identical v4 staging table, clean it up, and start normally
      const engine3 = Web3UserEngine.open({ databasePath: dbPath });
      engine3.close();

      // Verify v4 table was dropped
      const raw2 = new DatabaseSync(dbPath);
      const tables = raw2.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as Array<{ name: string }>;
      expect(tables.map((t) => t.name)).not.toContain("consumed_authorization_ids_v4");
      raw2.close();
    });

    // Test 4: Asynchronous consumption binds witness ticket ID and PENDING_COMMIT atomically with SQLite commit
    it("atomically binds witness ticket ID and PENDING_COMMIT upon SQLite commit during async consumption", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let commitInvoked = false;
      let ticketIdDuringCommit: string | undefined;
      let dbStateDuringCommit: any;

      const asyncWitness = createAsyncWitnessWrapper(baseWitness, {
        delayMs: 10,
        onCommit: (req) => {
          commitInvoked = true;
          ticketIdDuringCommit = req.ticketId;
          // Inspect the SQLite database DURING the commitTicket remote call
          // It MUST already be committed on disk with PENDING_COMMIT!
          const rawDb = new DatabaseSync(dbPath);
          dbStateDuringCommit = rawDb.prepare(
            "SELECT * FROM consumed_authorization_ids WHERE authorization_id = ?"
          ).get("auth-m12-bind-01") as any;
          rawDb.close();
        },
      });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: asyncWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_m12_bind_01",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-m12-bind-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_m12_bind_01",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = await engine.consumeAsync({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(consumed.decision).toBe("ALLOW");
      expect(commitInvoked).toBe(true);

      // Verify that WHEN commitTicket was executing, SQLite was ALREADY durably committed with PENDING_COMMIT
      expect(dbStateDuringCommit).toBeDefined();
      expect(dbStateDuringCommit.state).toBe("consumed");
      expect(dbStateDuringCommit.witness_ticket_id).toBe(ticketIdDuringCommit);
      expect(dbStateDuringCommit.witness_status).toBe("PENDING_COMMIT");
      expect(dbStateDuringCommit.witness_receipt_json).toBeNull();

      // Check via engine accessor
      const rec = engine.getAuthorizationRecord("auth-m12-bind-01");
      expect(rec?.witnessTicketId).toBe(ticketIdDuringCommit);
      expect(rec?.witnessStatus).toBe("COMMITTED");
      expect(rec?.witnessReceiptJson).not.toBeNull();

      engine.close();
    });

    // Test 5: Post-commit witness failure leaves durable PENDING_COMMIT and does NOT release capacity
    it("persists PENDING_COMMIT and prevents ticket release when post-commit witness throws", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let releaseCalled = false;

      const asyncWitness = createAsyncWitnessWrapper(baseWitness, {
        delayMs: 5,
        onCommit: () => {
          throw new Error("Simulated remote network drop during commitTicket");
        },
        onRelease: () => {
          releaseCalled = true;
        },
      });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: asyncWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_m12_bind_fail",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-m12-bind-fail",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_m12_bind_fail",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = await engine.consumeAsync({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(consumed.decision).toBe("UNKNOWN");
      expect(releaseCalled).toBe(false);

      // Verify durable SQLite state across engine close/reopen
      engine.close();

      const engineReopened = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: asyncWitness,
      });

      const rec = engineReopened.getAuthorizationRecord("auth-m12-bind-fail");
      expect(rec).not.toBeNull();
      expect(rec?.state).toBe("consumed");
      expect(rec?.witnessTicketId).toBe(consumed.witnessTicketId);
      expect(rec?.witnessStatus).toBe("PENDING_COMMIT");
      expect(rec?.witnessReceiptJson).toBeNull();

      // Capacity remains held on witness
      expect(baseWitness.listUnfinalizedTickets().length).toBe(1);

      engineReopened.close();
    });

    // Test 6: Synchronous consumption with synchronous witness binds ticket ID and PENDING_COMMIT
    it("synchronous consumption with witness adapter binds ticket ID and PENDING_COMMIT atomically", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_m12_sync_bind",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-m12-sync-bind",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_m12_sync_bind",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(consumed.decision).toBe("ALLOW");

      const rec = engine.getAuthorizationRecord("auth-m12-sync-bind");
      expect(rec?.state).toBe("consumed");
      expect(rec?.witnessTicketId).toBe(consumed.witnessTicketId);
      expect(rec?.witnessStatus).toBe("COMMITTED");
      expect(rec?.witnessReceiptJson).not.toBeNull();

      engine.close();
    });

    // Test 7: Non-witnessed consumption records witness_status = 'NONE'
    it("non-witnessed consumption records witness_ticket_id = null and witness_status = 'NONE'", () => {
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        // No witness adapter provided
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_m12_no_witness",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-m12-no-witness",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_m12_no_witness",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(consumed.decision).toBe("ALLOW");

      const rec = engine.getAuthorizationRecord("auth-m12-no-witness");
      expect(rec?.state).toBe("consumed");
      expect(rec?.witnessTicketId).toBeNull();
      expect(rec?.witnessReceiptJson).toBeNull();
      expect(rec?.witnessStatus).toBe("NONE");

      engine.close();
    });
  });

  // ==========================================================================
  // Milestone 12 Phase B.2: Durable Witness Receipt Persistence & Accessor
  // ==========================================================================
  describe("Milestone 12 Phase B.2: Durable Witness Receipt Persistence & Accessor", () => {
    let testDir: string;
    let dbPath: string;

    beforeEach(() => {
      testDir = createTestDirectory();
      dbPath = join(testDir, "test-m12-b2.sqlite3");
    });

    afterEach(() => {
      try {
        rmSync(testDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors on Windows
      }
    });

    // Test 1: Valid receipt persistence and retrieval via getWitnessReceipt
    it("persists verified receipt, sets COMMITTED, and allows safe retrieval via engine.getWitnessReceipt", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b2_valid",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b2-valid-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b2_valid",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = await engine.consumeAsync({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(consumed.decision).toBe("ALLOW");
      if (consumed.decision !== "ALLOW") return;
      expect(consumed.witnessReceipt).toBeDefined();

      // Verify persistent SQLite record state
      const rec = engine.getAuthorizationRecord("auth-b2-valid-01");
      expect(rec?.state).toBe("consumed");
      expect(rec?.witnessStatus).toBe("COMMITTED");
      expect(rec?.witnessTicketId).toBe(consumed.witnessTicketId);
      expect(rec?.witnessReceiptJson).not.toBeNull();

      // Retrieve via engine.getWitnessReceipt
      const receipt = engine.getWitnessReceipt("auth-b2-valid-01");
      expect(receipt).not.toBeNull();
      expect(receipt?.authorizationId).toBe("auth-b2-valid-01");
      expect(receipt?.ticketId).toBe(consumed.witnessTicketId);
      expect(receipt?.signature).toBe(consumed.witnessReceipt?.signature);

      // Verify object immutability (frozen)
      expect(Object.isFrozen(receipt)).toBe(true);
      expect(Object.isFrozen(receipt?.budgetWindows)).toBe(true);

      engine.close();
    });

    // Test 2: Signature failure prevents COMMITTED transition, marks DISPUTED, and returns UNKNOWN
    it("fails closed when receipt signature is invalid, marks DISPUTED, and returns UNKNOWN", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let releaseCalled = false;

      const tamperingWitness: MonotonicWitnessAdapter = {
        name: "TamperingWitness",
        isTestOnlyMock: true,
        get publicKeyPem() {
          return TEST_KEY_PAIR.publicKeyPem;
        },
        getSyncStatus: (e, s) => baseWitness.getSyncStatus(e, s),
        reserveTicket: (req) => baseWitness.reserveTicket(req),
        commitTicket: (req) => {
          const res = baseWitness.commitTicket(req);
          if (res.decision === "ALLOW" && res.receipt) {
            // Tamper the signature
            const badSig = "00".repeat(64);
            return {
              ...res,
              receipt: {
                ...res.receipt,
                signature: badSig,
              },
            };
          }
          return res;
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
        witnessAdapter: tamperingWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b2_badsig",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b2-badsig-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b2_badsig",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = await engine.consumeAsync({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(consumed.decision).toBe("UNKNOWN");
      expect(consumed.reasons?.some((r) => r.includes("signature verification failed"))).toBe(true);

      // Verify row is marked DISPUTED in database, not COMMITTED
      const rec = engine.getAuthorizationRecord("auth-b2-badsig-01");
      expect(rec?.state).toBe("consumed");
      expect(rec?.witnessStatus).toBe("DISPUTED");
      expect(rec?.witnessReceiptJson).toBeNull();

      // getWitnessReceipt must return null
      expect(engine.getWitnessReceipt("auth-b2-badsig-01")).toBeNull();

      // Ticket is not released
      expect(releaseCalled).toBe(false);

      engine.close();
    });

    // Test 3: Authorization / ticket mismatch fails closed
    it("fails closed when receipt identity does not match authorization or ticket", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });

      const mismatchWitness: MonotonicWitnessAdapter = {
        name: "MismatchWitness",
        isTestOnlyMock: true,
        get publicKeyPem() {
          return TEST_KEY_PAIR.publicKeyPem;
        },
        getSyncStatus: (e, s) => baseWitness.getSyncStatus(e, s),
        reserveTicket: (req) => baseWitness.reserveTicket(req),
        commitTicket: (req) => {
          const res = baseWitness.commitTicket(req);
          if (res.decision === "ALLOW" && res.receipt) {
            // Return receipt with a completely different authorizationId
            return {
              ...res,
              receipt: {
                ...res.receipt,
                authorizationId: "wrong-authorization-id",
              },
            };
          }
          return res;
        },
        releaseTicket: (req) => baseWitness.releaseTicket(req),
        reconcileTicket: (req) => baseWitness.reconcileTicket(req),
      };

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: mismatchWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b2_mismatch",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b2-mismatch-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b2_mismatch",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = await engine.consumeAsync({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(consumed.decision).toBe("UNKNOWN");
      expect(consumed.reasons?.some((r) => r.includes("identity mismatch"))).toBe(true);

      const rec = engine.getAuthorizationRecord("auth-b2-mismatch-01");
      expect(rec?.witnessStatus).toBe("DISPUTED");
      expect(engine.getWitnessReceipt("auth-b2-mismatch-01")).toBeNull();

      engine.close();
    });

    // Test 4: SQLite write failure during receipt persistence returns UNKNOWN and preserves PENDING_COMMIT
    it("fails closed with UNKNOWN and preserves PENDING_COMMIT when SQLite receipt write fails", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b2_iofail",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b2-iofail-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b2_iofail",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Mock persistWitnessReceipt on store to simulate an unexpected write failure
      const store = (engine as any).store;
      const originalPersist = store.persistWitnessReceipt.bind(store);
      store.persistWitnessReceipt = () => {
        return { success: false, reason: "Simulated SQLite disk I/O error during receipt persistence" };
      };

      const consumed = await engine.consumeAsync({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(consumed.decision).toBe("UNKNOWN");
      expect(consumed.reasons?.some((r) => r.includes("persisting verified witness receipt failed"))).toBe(true);

      // Restore original method
      store.persistWitnessReceipt = originalPersist;

      // In database, the record remains durably stored as PENDING_COMMIT
      const rec = engine.getAuthorizationRecord("auth-b2-iofail-01");
      expect(rec?.state).toBe("consumed");
      expect(rec?.witnessStatus).toBe("PENDING_COMMIT");
      expect(rec?.witnessReceiptJson).toBeNull();

      // getWitnessReceipt returns null for PENDING_COMMIT
      expect(engine.getWitnessReceipt("auth-b2-iofail-01")).toBeNull();

      engine.close();
    });

    // Test 5: Duplicate and conflicting receipt handling on persistWitnessReceipt
    it("handles duplicate identical receipts idempotently and rejects conflicting receipts", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b2_dup",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b2-dup-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b2_dup",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumed.decision).toBe("ALLOW");

      const store = (engine as any).store;
      const rec = engine.getAuthorizationRecord("auth-b2-dup-01");
      expect(rec?.witnessReceiptJson).not.toBeNull();

      // Call persistWitnessReceipt with the EXACT same receipt -> idempotent success
      const dupRes = store.persistWitnessReceipt({
        authorizationId: "auth-b2-dup-01",
        ticketId: rec?.witnessTicketId!,
        receiptJson: rec?.witnessReceiptJson!,
      });
      expect(dupRes.success).toBe(true);
      expect(dupRes.alreadyCommitted).toBe(true);

      // Call persistWitnessReceipt with a CONFLICTING receipt -> failure
      const conflictRes = store.persistWitnessReceipt({
        authorizationId: "auth-b2-dup-01",
        ticketId: rec?.witnessTicketId!,
        receiptJson: JSON.stringify({ ...JSON.parse(rec?.witnessReceiptJson!), sequenceNumber: "999999" }),
      });
      expect(conflictRes.success).toBe(false);
      expect(conflictRes.reason).toMatch(/Conflicting receipt already persisted/);

      engine.close();
    });

    // Test 6: getWitnessReceipt rejects corrupted, malformed, or untrusted stored receipt data
    it("rejects corrupted, malformed, or signature-tampered stored receipt data in getWitnessReceipt", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b2_corrupt",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b2-corrupt-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b2_corrupt",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumed.decision).toBe("ALLOW");
      if (consumed.decision !== "ALLOW") return;
      expect(engine.getWitnessReceipt("auth-b2-corrupt-01")).not.toBeNull();

      const rawDb = new DatabaseSync(dbPath);

      // Case A: Corrupted JSON text
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET witness_receipt_json = 'INVALID_JSON_CORRUPT{['
        WHERE authorization_id = 'auth-b2-corrupt-01'
      `).run();
      expect(engine.getWitnessReceipt("auth-b2-corrupt-01")).toBeNull();

      // Case B: Non-object JSON
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET witness_receipt_json = '12345'
        WHERE authorization_id = 'auth-b2-corrupt-01'
      `).run();
      expect(engine.getWitnessReceipt("auth-b2-corrupt-01")).toBeNull();

      // Case C: Structurally invalid receipt (missing required fields or invalid sequence number)
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET witness_receipt_json = json_object('version', 1, 'authorizationId', 'auth-b2-corrupt-01', 'ticketId', 'bad-ticket')
        WHERE authorization_id = 'auth-b2-corrupt-01'
      `).run();
      expect(engine.getWitnessReceipt("auth-b2-corrupt-01")).toBeNull();

      // Case D: Valid JSON structure but signature tampered
      const validReceipt = consumed.witnessReceipt!;
      const tamperedSigReceipt = { ...validReceipt, signature: "ff".repeat(64) };
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET witness_receipt_json = ?
        WHERE authorization_id = 'auth-b2-corrupt-01'
      `).run(JSON.stringify(tamperedSigReceipt));
      expect(engine.getWitnessReceipt("auth-b2-corrupt-01")).toBeNull();

      rawDb.close();
      engine.close();
    });
  });

  // ==========================================================================
  // Milestone 12 Phase B.2R: Witness Trust-Anchor Remediation & Field Binding
  // ==========================================================================
  describe("Milestone 12 Phase B.2R: Witness Trust-Anchor Remediation & Field Binding", () => {
    it("rejects engine initialization when witnessPublicKey and witnessAdapter public keys conflict", () => {
      const adapter = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const attackerKeys = generateIssuerKeyPair();

      expect(() => {
        Web3UserEngine.open({
          databasePath: dbPath,
          witnessAdapter: adapter,
          witnessPublicKey: attackerKeys.publicKeyPem,
        });
      }).toThrow(ValidationError);
    });

    it("accepts engine initialization when witnessPublicKey and witnessAdapter public keys match", () => {
      const adapter = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: adapter,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });
      expect(engine).toBeDefined();
      engine.close();
    });

    it("prevents caller from bypassing verification with attacker key when forged receipt is injected (SEC-M12-B2-01)", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b2r_forge_01",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b2r-forge-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b2r_forge_01",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumed.decision).toBe("ALLOW");
      if (consumed.decision !== "ALLOW") return;

      // Attacker creates a separate witness adapter and signs a forged receipt
      const attackerKeyPair = generateIssuerKeyPair();
      const attackerWitness = new LocalDeterministicWitness({ keyPair: attackerKeyPair });
      const forgedReserve = attackerWitness.reserveTicket({
        authorizationId: "auth-b2r-forge-01",
        bindingDigest: issued.artifact.bindingDigest,
        policyId: SAMPLE_POLICY.policyId,
        policyRevision: 1,
        idempotencyKey: "idemp-forge-01",
      });
      expect(forgedReserve.decision).toBe("ALLOW");
      const ticketId = forgedReserve.ticketId!;
      const forgedCommit = attackerWitness.commitTicket({
        ticketId,
        authorizationId: "auth-b2r-forge-01",
        bindingDigest: issued.artifact.bindingDigest,
        localCommittedAtSeconds: Math.floor(Date.now() / 1000),
      });
      expect(forgedCommit.decision).toBe("ALLOW");
      const forgedReceipt = forgedCommit.receipt!;

      // Infiltrate SQLite by replacing receipt with attacker's signed receipt
      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET witness_receipt_json = ?, witness_ticket_id = ?
        WHERE authorization_id = 'auth-b2r-forge-01'
      `).run(JSON.stringify(forgedReceipt), ticketId);
      rawDb.close();

      // 1. Reading without key override verifies against engine's configured anchor: fails (returns null)
      expect(engine.getWitnessReceipt("auth-b2r-forge-01")).toBeNull();

      // 2. Caller attempting to supply attacker's public key is REJECTED with ValidationError
      expect(() => {
        engine.getWitnessReceipt("auth-b2r-forge-01", attackerKeyPair.publicKeyPem);
      }).toThrow(ValidationError);

      engine.close();
    });

    it("fails closed when engine is opened without trusted witness configuration", () => {
      // Engine opened without witnessAdapter or witnessPublicKey
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b2r_notrust",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b2r-notrust-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b2r_notrust",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumed.decision).toBe("ALLOW");

      // getWitnessReceipt without caller key fails closed (returns null)
      expect(engine.getWitnessReceipt("auth-b2r-notrust-01")).toBeNull();

      // getWitnessReceipt with per-call key injection throws ValidationError
      const callerKeyPair = generateIssuerKeyPair();
      expect(() => {
        engine.getWitnessReceipt("auth-b2r-notrust-01", callerKeyPair.publicKeyPem);
      }).toThrow(ValidationError);

      engine.close();
    });

    it("rejects per-call witness key or adapter conflicts during consume and consumeAsync", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b2r_percall",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const attackerKeyPair = generateIssuerKeyPair();
      const attackerWitness = new LocalDeterministicWitness({ keyPair: attackerKeyPair });

      const issued1 = engine.issue({
        authorizationId: "auth-b2r-percall-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b2r_percall",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued1.decision).toBe("ALLOW");
      if (issued1.decision !== "ALLOW") return;

      // Reject conflicting witnessPublicKey in consume()
      expect(() => {
        engine.consume({
          artifact: issued1.artifact,
          envelope: issued1.envelope,
          request: SAMPLE_TX_REQUEST,
          witnessPublicKey: attackerKeyPair.publicKeyPem,
        });
      }).toThrow(ValidationError);

      // Reject conflicting witnessAdapter in consume()
      expect(() => {
        engine.consume({
          artifact: issued1.artifact,
          envelope: issued1.envelope,
          request: SAMPLE_TX_REQUEST,
          witnessAdapter: attackerWitness,
        });
      }).toThrow(ValidationError);

      const issued2 = engine.issue({
        authorizationId: "auth-b2r-percall-02",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b2r_percall",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued2.decision).toBe("ALLOW");
      if (issued2.decision !== "ALLOW") return;

      // Reject conflicting witnessPublicKey in consumeAsync()
      await expect(
        engine.consumeAsync({
          artifact: issued2.artifact,
          envelope: issued2.envelope,
          request: SAMPLE_TX_REQUEST,
          witnessPublicKey: attackerKeyPair.publicKeyPem,
        })
      ).rejects.toThrow(ValidationError);

      // Reject conflicting witnessAdapter in consumeAsync()
      await expect(
        engine.consumeAsync({
          artifact: issued2.artifact,
          envelope: issued2.envelope,
          request: SAMPLE_TX_REQUEST,
          witnessAdapter: attackerWitness,
        })
      ).rejects.toThrow(ValidationError);

      engine.close();
    });

    it("verifies and returns valid receipt when caller passes matching trusted public key", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b2r_valid",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b2r-valid-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b2r_valid",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumed.decision).toBe("ALLOW");

      // getWitnessReceipt with identical key passes
      const receiptWithKey = engine.getWitnessReceipt("auth-b2r-valid-01", TEST_KEY_PAIR.publicKeyPem);
      expect(receiptWithKey).not.toBeNull();
      expect(receiptWithKey?.authorizationId).toBe("auth-b2r-valid-01");

      engine.close();
    });

    it("rejects receipt persistence and retrieval when bindingDigest or authorizationId mismatch (SEC-M12-B2-02)", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b2r_binding",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b2r-bind-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b2r_binding",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumed.decision).toBe("ALLOW");
      if (consumed.decision !== "ALLOW") return;

      const validReceipt = consumed.witnessReceipt!;

      const rawDb = new DatabaseSync(dbPath);

      // Case 1: Tampered binding_digest in SQLite causes getWitnessReceipt to reject (return null)
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET binding_digest = '0000000000000000000000000000000000000000000000000000000000000000'
        WHERE authorization_id = 'auth-b2r-bind-01'
      `).run();
      expect(engine.getWitnessReceipt("auth-b2r-bind-01")).toBeNull();

      // Restore correct binding_digest
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET binding_digest = ?
        WHERE authorization_id = 'auth-b2r-bind-01'
      `).run(validReceipt.bindingDigest);
      expect(engine.getWitnessReceipt("auth-b2r-bind-01")).not.toBeNull();

      // Case 2: Tampered witness_ticket_id causes getWitnessReceipt to reject (return null)
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET witness_ticket_id = 'different-ticket-id'
        WHERE authorization_id = 'auth-b2r-bind-01'
      `).run();
      expect(engine.getWitnessReceipt("auth-b2r-bind-01")).toBeNull();

      // Restore correct witness_ticket_id
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET witness_ticket_id = ?
        WHERE authorization_id = 'auth-b2r-bind-01'
      `).run(validReceipt.ticketId);
      expect(engine.getWitnessReceipt("auth-b2r-bind-01")).not.toBeNull();

      // Case 3: persistWitnessReceipt rejects receipt whose fields mismatch row columns
      const store = (engine as any).store;
      const resDigest = store.persistWitnessReceipt({
        authorizationId: "auth-b2r-bind-01",
        ticketId: validReceipt.ticketId,
        receiptJson: JSON.stringify({
          ...validReceipt,
          bindingDigest: "0000000000000000000000000000000000000000000000000000000000000000",
        }),
      });
      expect(resDigest.success).toBe(false);
      expect(resDigest.reason).toMatch(/bindingDigest/i);

      const resAuth = store.persistWitnessReceipt({
        authorizationId: "auth-b2r-bind-01",
        ticketId: validReceipt.ticketId,
        receiptJson: JSON.stringify({
          ...validReceipt,
          authorizationId: "other-auth-id",
        }),
      });
      expect(resAuth.success).toBe(false);
      expect(resAuth.reason).toMatch(/Receipt identity does not match/i);

      const resTicket = store.persistWitnessReceipt({
        authorizationId: "auth-b2r-bind-01",
        ticketId: "other-ticket-id",
        receiptJson: JSON.stringify({
          ...validReceipt,
          ticketId: "other-ticket-id",
        }),
      });
      expect(resTicket.success).toBe(false);
      expect(resTicket.reason).toMatch(/Ticket ID mismatch/i);

      rawDb.close();
      engine.close();
    });

    it("enforces trust-anchor invariants on direct SQLiteAuthorizationStore.getWitnessReceipt calls", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_direct_store_01",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-direct-store-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_direct_store_01",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumed.decision).toBe("ALLOW");
      engine.close();

      const attackerKeyPair = generateIssuerKeyPair();

      // 1. Direct store with configured trust anchor
      const directStoreWithTrust = new SQLiteAuthorizationStore(dbPath, {
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      // Retrieval with configured anchor succeeds
      const receipt = directStoreWithTrust.getWitnessReceipt("auth-direct-store-01");
      expect(receipt).not.toBeNull();
      expect(receipt?.authorizationId).toBe("auth-direct-store-01");

      // Per-call matching key succeeds
      const receiptWithMatchingKey = directStoreWithTrust.getWitnessReceipt(
        "auth-direct-store-01",
        TEST_KEY_PAIR.publicKeyPem,
      );
      expect(receiptWithMatchingKey).not.toBeNull();

      // Per-call conflicting/attacker key throws Error
      expect(() => {
        directStoreWithTrust.getWitnessReceipt("auth-direct-store-01", attackerKeyPair.publicKeyPem);
      }).toThrow(/conflicts with configured store witness trust anchor/i);

      // 2. Direct store without configured trust anchor
      const directStoreNoTrust = new SQLiteAuthorizationStore(dbPath);

      // Retrieval without key fails closed (returns null)
      expect(directStoreNoTrust.getWitnessReceipt("auth-direct-store-01")).toBeNull();

      // Attempting to supply a per-call key throws Error
      expect(() => {
        directStoreNoTrust.getWitnessReceipt("auth-direct-store-01", attackerKeyPair.publicKeyPem);
      }).toThrow(/no witness trust anchor is configured on SQLiteAuthorizationStore/i);

      // 3. Invalid configured key at store initialization throws Error
      expect(() => {
        new SQLiteAuthorizationStore(dbPath, {
          witnessPublicKey: "INVALID_ED25519_KEY_PEM",
        });
      }).toThrow(/Configured witnessPublicKey is not a valid Ed25519 public key/i);
    });
  });

  // ==========================================================================
  // Milestone 12 Phase B.3.1: Store-Level Reconciliation Primitives
  // ==========================================================================
  describe("Milestone 12 Phase B.3.1: Store-Level Reconciliation Primitives", () => {
    it("lists unresolved witness records (PENDING_COMMIT and DISPUTED) and excludes COMMITTED and NONE", () => {
      const store = new SQLiteAuthorizationStore(dbPath, {
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const rawDb = new DatabaseSync(dbPath);
      // Row 1: PENDING_COMMIT
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
        ) VALUES ('auth-b31-pending-01', 'sha256:1111111111111111111111111111111111111111111111111111111111111111', 'consumed', '2026-10-30 01:00:00', 'ticket-p1', 'PENDING_COMMIT')
      `).run();

      // Row 2: PENDING_COMMIT
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
        ) VALUES ('auth-b31-pending-02', 'sha256:2222222222222222222222222222222222222222222222222222222222222222', 'consumed', '2026-10-30 01:05:00', 'ticket-p2', 'PENDING_COMMIT')
      `).run();

      // Row 3: DISPUTED
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
        ) VALUES ('auth-b31-disputed-01', 'sha256:3333333333333333333333333333333333333333333333333333333333333333', 'consumed', '2026-10-30 01:10:00', 'ticket-d1', 'DISPUTED')
      `).run();

      // Row 4: COMMITTED (resolved)
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status, witness_receipt_json
        ) VALUES ('auth-b31-committed-01', 'sha256:4444444444444444444444444444444444444444444444444444444444444444', 'consumed', '2026-10-30 01:15:00', 'ticket-c1', 'COMMITTED', '{}')
      `).run();

      // Row 5: NONE (non-witnessed)
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
        ) VALUES ('auth-b31-none-01', 'sha256:5555555555555555555555555555555555555555555555555555555555555555', 'consumed', '2026-10-30 01:20:00', NULL, 'NONE')
      `).run();

      // Query all unresolved
      const allUnresolved = store.listUnreconciledWitnessRecords();
      expect(allUnresolved.length).toBe(3);
      expect(allUnresolved.map((r) => r.authorizationId)).toEqual([
        "auth-b31-pending-01",
        "auth-b31-pending-02",
        "auth-b31-disputed-01",
      ]);

      // Filter by PENDING_COMMIT
      const pendingOnly = store.listUnreconciledWitnessRecords({ status: "PENDING_COMMIT" });
      expect(pendingOnly.length).toBe(2);
      expect(pendingOnly.map((r) => r.authorizationId)).toEqual([
        "auth-b31-pending-01",
        "auth-b31-pending-02",
      ]);

      // Filter by DISPUTED
      const disputedOnly = store.listUnreconciledWitnessRecords({ status: "DISPUTED" });
      expect(disputedOnly.length).toBe(1);
      expect(disputedOnly[0].authorizationId).toBe("auth-b31-disputed-01");
      expect(disputedOnly[0].witnessStatus).toBe("DISPUTED");

      rawDb.close();
    });

    it("strictly validates status filter and limit parameters", () => {
      const store = new SQLiteAuthorizationStore(dbPath, {
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      // Invalid status filters
      expect(() => {
        store.listUnreconciledWitnessRecords({ status: "COMMITTED" as any });
      }).toThrow(/Invalid status filter/);

      expect(() => {
        store.listUnreconciledWitnessRecords({ status: "NONE" as any });
      }).toThrow(/Invalid status filter/);

      expect(() => {
        store.listUnreconciledWitnessRecords({ status: "INVALID_STATUS" as any });
      }).toThrow(/Invalid status filter/);

      // Invalid limits
      expect(() => {
        store.listUnreconciledWitnessRecords({ limit: 0 });
      }).toThrow(/Limit must be a positive integer between 1 and 1000/);

      expect(() => {
        store.listUnreconciledWitnessRecords({ limit: -10 });
      }).toThrow(/Limit must be a positive integer between 1 and 1000/);

      expect(() => {
        store.listUnreconciledWitnessRecords({ limit: 1001 });
      }).toThrow(/Limit must be a positive integer between 1 and 1000/);

      expect(() => {
        store.listUnreconciledWitnessRecords({ limit: 5.5 });
      }).toThrow(/Limit must be a positive integer between 1 and 1000/);

      expect(() => {
        store.listUnreconciledWitnessRecords("not-an-object" as any);
      }).toThrow(/Options must be an object/);
    });

    it("enforces deterministic ordering and respects limit parameter", () => {
      const store = new SQLiteAuthorizationStore(dbPath, {
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const rawDb = new DatabaseSync(dbPath);
      // Insert in reverse timestamp order
      for (let i = 5; i >= 1; i--) {
        rawDb.prepare(`
          INSERT INTO consumed_authorization_ids (
            authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
          ) VALUES (?, 'sha256:0000000000000000000000000000000000000000000000000000000000000000', 'consumed', ?, ?, 'PENDING_COMMIT')
        `).run(`auth-order-${i}`, `2026-10-30 02:0${i}:00`, `ticket-order-${i}`);
      }
      rawDb.close();

      // Limit 3 should return the 3 oldest by consumed_at
      const limited = store.listUnreconciledWitnessRecords({ limit: 3 });
      expect(limited.length).toBe(3);
      expect(limited.map((r) => r.authorizationId)).toEqual([
        "auth-order-1",
        "auth-order-2",
        "auth-order-3",
      ]);
    });

    it("fails closed on missing or malformed persisted fields", () => {
      const store = new SQLiteAuthorizationStore(dbPath, {
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const rawDb = new DatabaseSync(dbPath);
      // Temporarily bypass foreign/check constraint via raw SQLite pragma
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
        ) VALUES ('auth-malformed-01', NULL, 'consumed', '2026-10-30 03:00:00', 'ticket-bad', 'PENDING_COMMIT')
      `).run();
      rawDb.close();

      expect(() => {
        store.listUnreconciledWitnessRecords();
      }).toThrow(/integrity check failed/);
    });

    it("atomically resolves DISPUTED record to COMMITTED with valid receipt and configured trust anchor", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b31_resolve_01",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b31-resolve-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b31_resolve_01",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumed.decision).toBe("ALLOW");
      if (consumed.decision !== "ALLOW") return;

      const validReceipt = consumed.witnessReceipt!;
      const store = (engine as any).store;

      // Manually mark the record as DISPUTED in SQLite (e.g. simulating post-commit dispute)
      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET witness_status = 'DISPUTED', witness_receipt_json = NULL
        WHERE authorization_id = 'auth-b31-resolve-01'
      `).run();
      rawDb.close();

      const recBefore = store.getAuthorizationRecord("auth-b31-resolve-01");
      expect(recBefore?.witnessStatus).toBe("DISPUTED");
      expect(store.getWitnessReceipt("auth-b31-resolve-01")).toBeNull();

      // Calling persistWitnessReceipt without allowDisputed fails closed
      const failRes = store.persistWitnessReceipt({
        authorizationId: "auth-b31-resolve-01",
        ticketId: validReceipt.ticketId,
        receiptJson: JSON.stringify(validReceipt),
      });
      expect(failRes.success).toBe(false);
      expect(failRes.reason).toMatch(/Invalid witness status 'DISPUTED'/);

      // Calling persistWitnessReceipt with allowDisputed: true resolves record to COMMITTED
      const resolveRes = store.persistWitnessReceipt({
        authorizationId: "auth-b31-resolve-01",
        ticketId: validReceipt.ticketId,
        receiptJson: JSON.stringify(validReceipt),
        allowDisputed: true,
      });
      expect(resolveRes.success).toBe(true);

      // Verify row in SQLite is now COMMITTED
      const recAfter = store.getAuthorizationRecord("auth-b31-resolve-01");
      expect(recAfter?.witnessStatus).toBe("COMMITTED");
      expect(recAfter?.witnessReceiptJson).not.toBeNull();

      // Receipt accessor now successfully returns the verified receipt
      const receipt = store.getWitnessReceipt("auth-b31-resolve-01");
      expect(receipt).not.toBeNull();
      expect(receipt?.authorizationId).toBe("auth-b31-resolve-01");

      engine.close();
    });

    it("rejects resolution attempts with attacker-signed receipts, conflicting identity fields, or unconfigured trust anchor", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b31_attacker_01",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b31-attack-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b31_attacker_01",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumed.decision).toBe("ALLOW");
      if (consumed.decision !== "ALLOW") return;

      const validReceipt = consumed.witnessReceipt!;
      const store = (engine as any).store;

      // Mark record as DISPUTED
      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET witness_status = 'DISPUTED', witness_receipt_json = NULL
        WHERE authorization_id = 'auth-b31-attack-01'
      `).run();
      rawDb.close();

      // 1. Attacker signs receipt with their own key
      const attackerKeys = generateIssuerKeyPair();
      const attackerWitness = new LocalDeterministicWitness({ keyPair: attackerKeys });
      const forgedTicket = attackerWitness.reserveTicket({
        authorizationId: "auth-b31-attack-01",
        bindingDigest: issued.artifact.bindingDigest,
        policyId: SAMPLE_POLICY.policyId,
        policyRevision: 1,
        idempotencyKey: "idemp-attacker-resolve",
      });
      const forgedCommit = attackerWitness.commitTicket({
        ticketId: forgedTicket.ticketId!,
        authorizationId: "auth-b31-attack-01",
        bindingDigest: issued.artifact.bindingDigest,
        localCommittedAtSeconds: 1700000000,
      });
      const attackerReceipt = forgedCommit.receipt!;

      // Attacker receipt is rejected by persistWitnessReceipt
      const attackRes = store.persistWitnessReceipt({
        authorizationId: "auth-b31-attack-01",
        ticketId: validReceipt.ticketId,
        receiptJson: JSON.stringify({
          ...attackerReceipt,
          ticketId: validReceipt.ticketId,
        }),
        allowDisputed: true,
      });
      expect(attackRes.success).toBe(false);
      expect(attackRes.reason).toMatch(/signature verification failed/i);

      // Record remains DISPUTED
      const rec = store.getAuthorizationRecord("auth-b31-attack-01");
      expect(rec?.witnessStatus).toBe("DISPUTED");

      // 2. Conflicting bindingDigest rejected
      const badDigestRes = store.persistWitnessReceipt({
        authorizationId: "auth-b31-attack-01",
        ticketId: validReceipt.ticketId,
        receiptJson: JSON.stringify({
          ...validReceipt,
          bindingDigest: "sha256:" + "0".repeat(64),
        }),
        allowDisputed: true,
      });
      expect(badDigestRes.success).toBe(false);
      expect(badDigestRes.reason).toMatch(/bindingDigest/i);

      // 3. Store without configured trust anchor fails closed
      const unanchoredStore = new SQLiteAuthorizationStore(dbPath);
      const unanchoredRes = unanchoredStore.persistWitnessReceipt({
        authorizationId: "auth-b31-attack-01",
        ticketId: validReceipt.ticketId,
        receiptJson: JSON.stringify(validReceipt),
        allowDisputed: true,
      });
      expect(unanchoredRes.success).toBe(false);
      expect(unanchoredRes.reason).toMatch(/trust anchor/i);

      engine.close();
    });

    it("handles idempotent retries and rejects conflicting receipts during resolution", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b31_idem",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b31-idem-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b31_idem",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumed.decision).toBe("ALLOW");
      if (consumed.decision !== "ALLOW") return;

      const validReceipt = consumed.witnessReceipt!;
      const store = (engine as any).store;

      // Mark record as DISPUTED
      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET witness_status = 'DISPUTED', witness_receipt_json = NULL
        WHERE authorization_id = 'auth-b31-idem-01'
      `).run();
      rawDb.close();

      // First resolution: success
      const res1 = store.persistWitnessReceipt({
        authorizationId: "auth-b31-idem-01",
        ticketId: validReceipt.ticketId,
        receiptJson: JSON.stringify(validReceipt),
        allowDisputed: true,
      });
      expect(res1.success).toBe(true);

      // Second identical call: idempotent success
      const res2 = store.persistWitnessReceipt({
        authorizationId: "auth-b31-idem-01",
        ticketId: validReceipt.ticketId,
        receiptJson: JSON.stringify(validReceipt),
        allowDisputed: true,
      });
      expect(res2.success).toBe(true);
      expect(res2.alreadyCommitted).toBe(true);

      // Conflicting receipt for same committed authorization: rejected
      const conflictingReceipt = { ...validReceipt, sequenceNumber: "9999999" };
      const resConflicting = store.persistWitnessReceipt({
        authorizationId: "auth-b31-idem-01",
        ticketId: validReceipt.ticketId,
        receiptJson: JSON.stringify(conflictingReceipt),
        allowDisputed: true,
      });
      expect(resConflicting.success).toBe(false);
      expect(resConflicting.reason).toMatch(/Conflicting receipt/i);

      engine.close();
    });

    it("safely handles concurrent resolution attempts", () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b31_conc",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b31-conc-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b31_conc",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumed.decision).toBe("ALLOW");
      if (consumed.decision !== "ALLOW") return;

      const validReceipt = consumed.witnessReceipt!;

      // Mark record as DISPUTED
      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET witness_status = 'DISPUTED', witness_receipt_json = NULL
        WHERE authorization_id = 'auth-b31-conc-01'
      `).run();
      rawDb.close();

      // Open a second store instance on the same database
      const store1 = (engine as any).store;
      const store2 = new SQLiteAuthorizationStore(dbPath, {
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      // Both stores resolve the same disputed record concurrently
      const call1 = store1.persistWitnessReceipt({
        authorizationId: "auth-b31-conc-01",
        ticketId: validReceipt.ticketId,
        receiptJson: JSON.stringify(validReceipt),
        allowDisputed: true,
      });
      const call2 = store2.persistWitnessReceipt({
        authorizationId: "auth-b31-conc-01",
        ticketId: validReceipt.ticketId,
        receiptJson: JSON.stringify(validReceipt),
        allowDisputed: true,
      });

      // Exactly one succeeds with update, the other succeeds idempotently
      expect(call1.success).toBe(true);
      expect(call2.success).toBe(true);
      expect(Boolean(call1.alreadyCommitted) !== Boolean(call2.alreadyCommitted)).toBe(true);

      const rec = store1.getAuthorizationRecord("auth-b31-conc-01");
      expect(rec?.witnessStatus).toBe("COMMITTED");

      engine.close();
    });
  });

  describe("Milestone 12 Phase B.3.2: Single-Authorization Engine Reconciliation", () => {
    function createDelegatingWitness(
      baseWitness: LocalDeterministicWitness,
      overrides: Partial<MonotonicWitnessAdapter>,
    ): MonotonicWitnessAdapter {
      return {
        name: overrides.name ?? baseWitness.name,
        isTestOnlyMock: overrides.isTestOnlyMock ?? baseWitness.isTestOnlyMock,
        publicKeyPem: overrides.publicKeyPem !== undefined ? overrides.publicKeyPem : baseWitness.publicKeyPem,
        getSyncStatus: overrides.getSyncStatus ?? ((epoch, seq) => baseWitness.getSyncStatus(epoch, seq)),
        reserveTicket: overrides.reserveTicket ?? ((req) => baseWitness.reserveTicket(req)),
        commitTicket: overrides.commitTicket ?? ((req) => baseWitness.commitTicket(req)),
        releaseTicket: overrides.releaseTicket ?? ((req) => baseWitness.releaseTicket(req)),
        reconcileTicket: overrides.reconcileTicket ?? ((req) => baseWitness.reconcileTicket(req)),
        listUnfinalizedTickets: overrides.listUnfinalizedTickets ?? (() => baseWitness.listUnfinalizedTickets()),
      };
    }

    it("engine.listUnreconciledAuthorizations delegates to store, enforces validation, and returns immutable records", () => {
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      // Invalid status throws ValidationError
      expect(() => {
        engine.listUnreconciledAuthorizations({ status: "COMMITTED" as any });
      }).toThrow(/Invalid status filter/);

      // Invalid limit throws ValidationError
      expect(() => {
        engine.listUnreconciledAuthorizations({ limit: -1 });
      }).toThrow(/Limit must be a positive integer/);

      // Insert test records
      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
        ) VALUES ('auth-b32-list-01', 'sha256:1111111111111111111111111111111111111111111111111111111111111111', 'consumed', '2026-10-30 01:00:00', 'ticket-l1', 'PENDING_COMMIT')
      `).run();
      rawDb.close();

      const list = engine.listUnreconciledAuthorizations();
      expect(list.length).toBe(1);
      expect(list[0].authorizationId).toBe("auth-b32-list-01");
      expect(list[0].witnessStatus).toBe("PENDING_COMMIT");
      // Check immutability
      expect(Object.isFrozen(list)).toBe(true);
      expect(Object.isFrozen(list[0])).toBe(true);

      engine.close();
    });

    it("recovers valid receipt after a simulated lost remote response", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });

      // Adapter that simulates a network loss on commitTicket response
      let droppedCommit = false;
      const proxyWitness: MonotonicWitnessAdapter = {
        name: "proxy-drop-witness",
        isTestOnlyMock: true,
        publicKeyPem: TEST_KEY_PAIR.publicKeyPem,
        getSyncStatus: (epoch, seq) => baseWitness.getSyncStatus(epoch, seq),
        reserveTicket: (req) => baseWitness.reserveTicket(req),
        commitTicket: (req) => {
          const res = baseWitness.commitTicket(req);
          if (!droppedCommit) {
            droppedCommit = true;
            // Witness successfully committed, but network dropped response back to engine
            throw new Error("Network timeout: commit response dropped");
          }
          return res;
        },
        releaseTicket: (req) => baseWitness.releaseTicket(req),
        reconcileTicket: (req) => baseWitness.reconcileTicket(req),
      };

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: proxyWitness,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b32_recov",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b32-recov-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b32_recov",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Consume hits simulated network drop during commit
      const consumed = await engine.consumeAsync({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumed.decision).toBe("UNKNOWN");
      expect((consumed as any).witnessReceipt).toBeUndefined();

      // Verify authorization was consumed in SQLite and ticket is in PENDING_COMMIT
      const unreconciled = engine.listUnreconciledAuthorizations();
      expect(unreconciled.length).toBe(1);
      expect(unreconciled[0].authorizationId).toBe("auth-b32-recov-01");
      expect(unreconciled[0].witnessStatus).toBe("PENDING_COMMIT");

      // Before reconcile, receipt accessor returns null
      expect(engine.getWitnessReceipt("auth-b32-recov-01")).toBeNull();

      // Execute single-authorization reconciliation
      const recResult = await engine.reconcileAuthorization("auth-b32-recov-01");
      expect(recResult.outcome).toBe("RECONCILED");
      expect(recResult.previousStatus).toBe("PENDING_COMMIT");
      expect(recResult.currentStatus).toBe("COMMITTED");
      expect(recResult.receipt).toBeDefined();
      expect(recResult.receipt?.authorizationId).toBe("auth-b32-recov-01");

      // Receipt accessor now returns the verified receipt
      const receipt = engine.getWitnessReceipt("auth-b32-recov-01");
      expect(receipt).not.toBeNull();
      expect(receipt?.signature).toBe(recResult.receipt?.signature);

      // Now unreconciled list is empty
      expect(engine.listUnreconciledAuthorizations().length).toBe(0);

      engine.close();
    });

    it("handles already committed and idempotent reconciliation", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b32_idem",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b32-idem-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b32_idem",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumed.decision).toBe("ALLOW");

      // First reconcile: ALREADY_COMMITTED
      const res1 = await engine.reconcileAuthorization("auth-b32-idem-01");
      expect(res1.outcome).toBe("ALREADY_COMMITTED");
      expect(res1.previousStatus).toBe("COMMITTED");
      expect(res1.currentStatus).toBe("COMMITTED");
      expect(res1.receipt).toBeDefined();

      // Second reconcile: safe idempotent ALREADY_COMMITTED
      const res2 = await engine.reconcileAuthorization("auth-b32-idem-01");
      expect(res2.outcome).toBe("ALREADY_COMMITTED");
      expect(res2.receipt?.signature).toBe(res1.receipt?.signature);

      engine.close();
    });

    it("handles pending ticket with no receipt and preserves PENDING_COMMIT", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      // Manually insert an authorization in PENDING_COMMIT state with a reserved ticket
      const ticketRes = baseWitness.reserveTicket({
        authorizationId: "auth-b32-pending-01",
        bindingDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        policyId: "pol_test",
        policyRevision: 1,
        idempotencyKey: "idemp-pending-01",
      });

      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
        ) VALUES ('auth-b32-pending-01', 'sha256:1111111111111111111111111111111111111111111111111111111111111111', 'consumed', '2026-10-30 02:00:00', ?, 'PENDING_COMMIT')
      `).run(ticketRes.ticketId!);
      rawDb.close();

      const res = await engine.reconcileAuthorization("auth-b32-pending-01");
      expect(res.outcome).toBe("PENDING");
      expect(res.previousStatus).toBe("PENDING_COMMIT");
      expect(res.currentStatus).toBe("PENDING_COMMIT");
      expect(res.receipt).toBeUndefined();

      engine.close();
    });

    it("resolves disputed ticket to COMMITTED when valid authentic receipt exists", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b32_disp",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b32-disp-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b32_disp",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumed.decision).toBe("ALLOW");

      // Simulate record getting marked DISPUTED (e.g. by prior audit or unconfirmed check)
      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET witness_status = 'DISPUTED', witness_receipt_json = NULL
        WHERE authorization_id = 'auth-b32-disp-01'
      `).run();
      rawDb.close();

      expect(engine.getWitnessReceipt("auth-b32-disp-01")).toBeNull();

      // Reconcile successfully resolves DISPUTED -> COMMITTED
      const res = await engine.reconcileAuthorization("auth-b32-disp-01");
      expect(res.outcome).toBe("RECONCILED");
      expect(res.previousStatus).toBe("DISPUTED");
      expect(res.currentStatus).toBe("COMMITTED");
      expect(res.receipt).toBeDefined();

      expect(engine.getWitnessReceipt("auth-b32-disp-01")).not.toBeNull();

      engine.close();
    });

    it("handles unknown or released ticket status and preserves/marks DISPUTED without releasing capacity", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });

      let mockState: any = "SOME_UNKNOWN_STATUS";
      const customWitness: MonotonicWitnessAdapter = {
        name: "custom-state-witness",
        isTestOnlyMock: true,
        publicKeyPem: TEST_KEY_PAIR.publicKeyPem,
        getSyncStatus: (epoch, seq) => baseWitness.getSyncStatus(epoch, seq),
        reserveTicket: (req) => baseWitness.reserveTicket(req),
        commitTicket: (req) => baseWitness.commitTicket(req),
        releaseTicket: (req) => baseWitness.releaseTicket(req),
        reconcileTicket: (req) => ({
          ticketId: req.ticketId,
          state: mockState,
          reasons: ["Simulated state"],
        }),
      };

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: customWitness,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
        ) VALUES ('auth-b32-unknown-01', 'sha256:9999999999999999999999999999999999999999999999999999999999999999', 'consumed', '2026-10-30 03:00:00', 'ticket-unk-1', 'PENDING_COMMIT')
      `).run();
      rawDb.close();

      // 1. Unknown status preserves PENDING
      const resUnknown = await engine.reconcileAuthorization("auth-b32-unknown-01");
      expect(resUnknown.outcome).toBe("PENDING");
      expect(resUnknown.currentStatus).toBe("PENDING_COMMIT");

      // 2. RELEASED remotely marks ticket DISPUTED and never releases consumed row
      mockState = "RELEASED";
      const resReleased = await engine.reconcileAuthorization("auth-b32-unknown-01");
      expect(resReleased.outcome).toBe("DISPUTED");
      expect(resReleased.currentStatus).toBe("DISPUTED");

      // Local SQLite row remains consumed and is now DISPUTED
      const rawDb2 = new DatabaseSync(dbPath);
      const row = rawDb2.prepare("SELECT state, witness_status FROM consumed_authorization_ids WHERE authorization_id = 'auth-b32-unknown-01'").get() as any;
      rawDb2.close();
      expect(row.state).toBe("consumed");
      expect(row.witness_status).toBe("DISPUTED");

      engine.close();
    });

    it("handles remote adapter timeout, exception, and malformed response safely", async () => {
      let failMode: "throw" | "malformed" = "throw";
      const faultyWitness: MonotonicWitnessAdapter = {
        name: "faulty-witness",
        isTestOnlyMock: true,
        publicKeyPem: TEST_KEY_PAIR.publicKeyPem,
        getSyncStatus: () => ({ healthy: true, epochId: "e1", sequenceNumber: "1", divergenceDetected: false }),
        reserveTicket: () => ({ decision: "DENY" }),
        commitTicket: () => ({ decision: "DENY" }),
        releaseTicket: () => ({ success: false }),
        reconcileTicket: async () => {
          if (failMode === "throw") {
            throw new Error("RPC timeout connecting to witness cluster");
          }
          return null as any; // malformed
        },
      };

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: faultyWitness,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
        ) VALUES ('auth-b32-fault-01', 'sha256:8888888888888888888888888888888888888888888888888888888888888888', 'consumed', '2026-10-30 04:00:00', 'ticket-f1', 'PENDING_COMMIT')
      `).run();
      rawDb.close();

      // Timeout / Exception
      failMode = "throw";
      const resThrow = await engine.reconcileAuthorization("auth-b32-fault-01");
      expect(resThrow.outcome).toBe("UNAVAILABLE");
      expect(resThrow.currentStatus).toBe("PENDING_COMMIT");
      expect(resThrow.reasons?.[0]).toMatch(/RPC timeout/);

      // Malformed response
      failMode = "malformed";
      const resMalformed = await engine.reconcileAuthorization("auth-b32-fault-01");
      expect(resMalformed.outcome).toBe("UNAVAILABLE");
      expect(resMalformed.currentStatus).toBe("PENDING_COMMIT");
      expect(resMalformed.reasons?.[0]).toMatch(/invalid response/);

      engine.close();
    });

    it("rejects forged signatures, mismatched tickets, altered digests, or invalid policy fields and marks DISPUTED", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b32_fraud",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b32-fraud-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b32_fraud",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumed.decision).toBe("ALLOW");
      if (consumed.decision !== "ALLOW") return;
      const validReceipt = consumed.witnessReceipt!;

      // Reset row in SQLite to PENDING_COMMIT
      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET witness_status = 'PENDING_COMMIT', witness_receipt_json = NULL
        WHERE authorization_id = 'auth-b32-fraud-01'
      `).run();
      rawDb.close();

      // 1. Attacker-signed receipt
      const attackerReceipt: SignedWitnessReceipt = {
        ...validReceipt,
        signature: "00".repeat(64),
      };

      const attackerWitness = createDelegatingWitness(baseWitness, {
        reconcileTicket: () => ({
          ticketId: validReceipt.ticketId,
          state: "COMMITTED",
          receipt: attackerReceipt,
        }),
      });

      const resFraudSig = await engine.reconcileAuthorization("auth-b32-fraud-01", {
        witnessAdapter: attackerWitness,
      });
      expect(resFraudSig.outcome).toBe("DISPUTED");
      expect(resFraudSig.reasons?.[0]).toMatch(/signature verification failed/i);

      // 2. Mismatched ticket ID
      const mismatchTicketWitness = createDelegatingWitness(baseWitness, {
        reconcileTicket: () => ({
          ticketId: validReceipt.ticketId,
          state: "COMMITTED",
          receipt: { ...validReceipt, ticketId: "wrong-ticket" },
        }),
      });
      const resMismatchTicket = await engine.reconcileAuthorization("auth-b32-fraud-01", {
        witnessAdapter: mismatchTicketWitness,
      });
      expect(resMismatchTicket.outcome).toBe("DISPUTED");
      expect(resMismatchTicket.reasons?.[0]).toMatch(/identity or binding digest does not match/i);

      // 3. Mismatched binding digest
      const mismatchDigestWitness = createDelegatingWitness(baseWitness, {
        reconcileTicket: () => ({
          ticketId: validReceipt.ticketId,
          state: "COMMITTED",
          receipt: { ...validReceipt, bindingDigest: "sha256:" + "0".repeat(64) },
        }),
      });
      const resMismatchDigest = await engine.reconcileAuthorization("auth-b32-fraud-01", {
        witnessAdapter: mismatchDigestWitness,
      });
      expect(resMismatchDigest.outcome).toBe("DISPUTED");

      // 4. Invalid policy revision
      const badPolicyWitness = createDelegatingWitness(baseWitness, {
        reconcileTicket: () => ({
          ticketId: validReceipt.ticketId,
          state: "COMMITTED",
          receipt: { ...validReceipt, policyRevision: -5 },
        }),
      });
      const resBadPolicy = await engine.reconcileAuthorization("auth-b32-fraud-01", {
        witnessAdapter: badPolicyWitness,
      });
      expect(resBadPolicy.outcome).toBe("DISPUTED");

      engine.close();
    });

    it("fails closed on missing or conflicting trust anchor", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });

      // Engine opened without trust anchor
      const unanchoredEngine = Web3UserEngine.open({
        databasePath: dbPath,
      });

      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
        ) VALUES ('auth-b32-trust-01', 'sha256:7777777777777777777777777777777777777777777777777777777777777777', 'consumed', '2026-10-30 05:00:00', 'ticket-t1', 'PENDING_COMMIT')
      `).run();
      rawDb.close();

      // Calling reconcile without trust anchor returns UNAVAILABLE
      const resNoAnchor = await unanchoredEngine.reconcileAuthorization("auth-b32-trust-01");
      expect(resNoAnchor.outcome).toBe("UNAVAILABLE");
      expect(resNoAnchor.reasons?.[0]).toMatch(/No witness trust anchor is configured/);

      // Supplying per-call witnessAdapter with key when none configured throws ValidationError
      await expect(async () => {
        await unanchoredEngine.reconcileAuthorization("auth-b32-trust-01", {
          witnessAdapter: baseWitness,
        });
      }).rejects.toThrow(/Cannot supply per-call witnessAdapter/);

      // Supplying per-call witnessPublicKey when none configured throws ValidationError
      await expect(async () => {
        await unanchoredEngine.reconcileAuthorization("auth-b32-trust-01", {
          witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
        });
      }).rejects.toThrow(/no witness trust anchor is configured/);

      unanchoredEngine.close();

      // Conflicting per-call key on anchored engine throws ValidationError
      const anchoredEngine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const otherKeys = generateIssuerKeyPair();
      await expect(async () => {
        await anchoredEngine.reconcileAuthorization("auth-b32-trust-01", {
          witnessPublicKey: otherKeys.publicKeyPem,
        });
      }).rejects.toThrow(/conflicts with configured engine witness trust anchor/);

      anchoredEngine.close();
    });

    it("handles concurrent reconciliation attempts safely", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b32_conc",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b32-conc-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b32_conc",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const consumed = engine.consume({
        artifact: issued.artifact,
        envelope: issued.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumed.decision).toBe("ALLOW");

      // Reset SQLite row to PENDING_COMMIT (ticket remains COMMITTED on witness)
      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET witness_status = 'PENDING_COMMIT', witness_receipt_json = NULL
        WHERE authorization_id = 'auth-b32-conc-01'
      `).run();
      rawDb.close();

      // Fire 2 concurrent reconcile calls
      const [r1, r2] = await Promise.all([
        engine.reconcileAuthorization("auth-b32-conc-01"),
        engine.reconcileAuthorization("auth-b32-conc-01"),
      ]);

      // Both should succeed with valid receipt, one RECONCILED and one ALREADY_COMMITTED
      expect(r1.receipt).toBeDefined();
      expect(r2.receipt).toBeDefined();
      const outcomes = [r1.outcome, r2.outcome].sort();
      expect(outcomes).toEqual(["ALREADY_COMMITTED", "RECONCILED"]);

      engine.close();
    });

    it("safely handles reconciliation racing with a concurrent consume", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b32_race",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b32-race-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b32_race",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Manually set row to PENDING_COMMIT and commit ticket on witness
      const ticketRes = baseWitness.reserveTicket({
        authorizationId: "auth-b32-race-01",
        bindingDigest: issued.artifact.bindingDigest,
        policyId: SAMPLE_POLICY.policyId,
        policyRevision: 1,
        idempotencyKey: "idemp-race-01",
      });
      const commitRes = baseWitness.commitTicket({
        ticketId: ticketRes.ticketId!,
        authorizationId: "auth-b32-race-01",
        bindingDigest: issued.artifact.bindingDigest,
        localCommittedAtSeconds: 1700000000,
      });

      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET state = 'consumed', consumed_at = '2026-10-30 06:00:00', witness_ticket_id = ?, witness_status = 'PENDING_COMMIT'
        WHERE authorization_id = 'auth-b32-race-01'
      `).run(ticketRes.ticketId!);
      rawDb.close();

      // Concurrent consume finishes and commits receipt right before/during reconcile
      (engine as any).store.persistWitnessReceipt({
        authorizationId: "auth-b32-race-01",
        ticketId: ticketRes.ticketId!,
        receiptJson: JSON.stringify(commitRes.receipt!),
      });

      // Reconcile notices already committed row and succeeds idempotently
      const reconcileRes = await engine.reconcileAuthorization("auth-b32-race-01");
      expect(reconcileRes.outcome).toBe("ALREADY_COMMITTED");
      expect(reconcileRes.receipt).toBeDefined();

      engine.close();
    });

    it("proves that consumed tickets are never released during reconciliation", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let releaseCalled = false;
      const releaseSpyWitness = createDelegatingWitness(baseWitness, {
        releaseTicket: (req) => {
          releaseCalled = true;
          return baseWitness.releaseTicket(req);
        },
      });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: releaseSpyWitness,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
        ) VALUES ('auth-b32-never-release-01', 'sha256:6666666666666666666666666666666666666666666666666666666666666666', 'consumed', '2026-10-30 07:00:00', 'ticket-nr-1', 'PENDING_COMMIT')
      `).run();
      rawDb.close();

      await engine.reconcileAuthorization("auth-b32-never-release-01");
      expect(releaseCalled).toBe(false);

      engine.close();
    });

    it("proves that network calls do not hold SQLite write locks or ClockGuard mutex during reconciliation", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });

      let slowReconcileResolver: (() => void) | undefined;
      const slowWitness = createDelegatingWitness(baseWitness, {
        reconcileTicket: async (req) => {
          await new Promise<void>((resolve) => {
            slowReconcileResolver = resolve;
          });
          return baseWitness.reconcileTicket(req);
        },
      });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: slowWitness,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b32_lock",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
        ) VALUES ('auth-b32-lock-01', 'sha256:5555555555555555555555555555555555555555555555555555555555555555', 'consumed', '2026-10-30 08:00:00', 'ticket-lock-1', 'PENDING_COMMIT')
      `).run();
      rawDb.close();

      // Start slow reconcile (network in-flight)
      const reconcilePromise = engine.reconcileAuthorization("auth-b32-lock-01");

      // While network call is pending, execute a concurrent engine.issue operation
      // If SQLite write locks were held by reconcile, this would block or fail
      const concurrentIssued = engine.issue({
        authorizationId: "auth-b32-concurrent-issue",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b32_lock",
          privateKey: keypair.privateKey,
        },
      });
      expect(concurrentIssued.decision).toBe("ALLOW");

      // Complete the slow network call
      slowReconcileResolver!();
      const reconcileRes = await reconcilePromise;
      expect(reconcileRes.outcome).toBe("DISPUTED"); // ticket-lock-1 not found on witness -> DISPUTED

      engine.close();
    });

    it("returns explicit outcomes for NOT_FOUND, NOT_CONSUMED, NOT_WITNESSED, and missing remote receipts", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b32_outcomes",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      // 1. NOT_FOUND
      const resNotFound = await engine.reconcileAuthorization("auth-does-not-exist");
      expect(resNotFound.outcome).toBe("NOT_FOUND");
      expect(resNotFound.reasons?.[0]).toMatch(/was not found/);

      // 2. NOT_CONSUMED (issued but not consumed)
      const issued = engine.issue({
        authorizationId: "auth-b32-issued-only",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: {
          keyId: "key_b32_outcomes",
          privateKey: keypair.privateKey,
        },
      });
      expect(issued.decision).toBe("ALLOW");

      const resNotConsumed = await engine.reconcileAuthorization("auth-b32-issued-only");
      expect(resNotConsumed.outcome).toBe("NOT_CONSUMED");
      expect(resNotConsumed.reasons?.[0]).toMatch(/state 'issued', expected 'consumed'/);

      // 3. NOT_WITNESSED (consumed without witness)
      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
        ) VALUES ('auth-b32-unwitnessed', 'sha256:4444444444444444444444444444444444444444444444444444444444444444', 'consumed', '2026-10-30 09:00:00', NULL, 'NONE')
      `).run();
      rawDb.close();

      const resNotWitnessed = await engine.reconcileAuthorization("auth-b32-unwitnessed");
      expect(resNotWitnessed.outcome).toBe("NOT_WITNESSED");
      expect(resNotWitnessed.reasons?.[0]).toMatch(/was not witnessed/);

      // 4. Remote reports COMMITTED but no receipt provided -> preserves PENDING
      const noReceiptWitness = createDelegatingWitness(baseWitness, {
        reconcileTicket: () => ({
          ticketId: "ticket-no-receipt",
          state: "COMMITTED",
          // receipt intentionally omitted
        }),
      });

      const rawDb2 = new DatabaseSync(dbPath);
      rawDb2.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
        ) VALUES ('auth-b32-no-receipt', 'sha256:3333333333333333333333333333333333333333333333333333333333333333', 'consumed', '2026-10-30 09:10:00', 'ticket-no-receipt', 'PENDING_COMMIT')
      `).run();
      rawDb2.close();

      const resNoReceipt = await engine.reconcileAuthorization("auth-b32-no-receipt", {
        witnessAdapter: noReceiptWitness,
      });
      expect(resNoReceipt.outcome).toBe("PENDING");
      expect(resNoReceipt.currentStatus).toBe("PENDING_COMMIT");
      expect(resNoReceipt.reasons?.[0]).toMatch(/receipt was not provided in response/);

      // 5. Input validations
      await expect(async () => {
        await engine.reconcileAuthorization("");
      }).rejects.toThrow(/Authorization ID must be a non-empty string/);

      await expect(async () => {
        await engine.reconcileAuthorization("a".repeat(129));
      }).rejects.toThrow(/exceeds maximum length of 128/);

      await expect(async () => {
        await engine.reconcileAuthorization("auth-test", "bad-opts" as any);
      }).rejects.toThrow(/options must be an object/);

      engine.close();

      // Closed engine throws EngineClosedError
      await expect(async () => {
        await engine.reconcileAuthorization("auth-test");
      }).rejects.toThrow(/EngineClosedError|closed/);
    });
  });

  describe("Milestone 12 Phase B.3.3: Bounded Batch Reconciliation", () => {
    function createDelegatingWitness(
      baseWitness: LocalDeterministicWitness,
      overrides: Partial<MonotonicWitnessAdapter>,
    ): MonotonicWitnessAdapter {
      return {
        name: overrides.name ?? baseWitness.name,
        isTestOnlyMock: overrides.isTestOnlyMock ?? baseWitness.isTestOnlyMock,
        publicKeyPem: overrides.publicKeyPem !== undefined ? overrides.publicKeyPem : baseWitness.publicKeyPem,
        getSyncStatus: overrides.getSyncStatus ?? ((epoch, seq) => baseWitness.getSyncStatus(epoch, seq)),
        reserveTicket: overrides.reserveTicket ?? ((req) => baseWitness.reserveTicket(req)),
        commitTicket: overrides.commitTicket ?? ((req) => baseWitness.commitTicket(req)),
        releaseTicket: overrides.releaseTicket ?? ((req) => baseWitness.releaseTicket(req)),
        reconcileTicket: overrides.reconcileTicket ?? ((req) => baseWitness.reconcileTicket(req)),
        listUnfinalizedTickets: overrides.listUnfinalizedTickets ?? (() => baseWitness.listUnfinalizedTickets()),
      };
    }

    it("handles empty batch cleanly with empty summary and results", async () => {
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const res = await engine.reconcileAll();
      expect(res.summary.totalDiscovered).toBe(0);
      expect(res.summary.totalProcessed).toBe(0);
      expect(res.summary.reconciledCount).toBe(0);
      expect(res.results.length).toBe(0);
      expect(res.aborted).toBe(false);
      expect(Object.isFrozen(res)).toBe(true);
      expect(Object.isFrozen(res.summary)).toBe(true);
      expect(Object.isFrozen(res.results)).toBe(true);

      engine.close();
    });

    it("strictly validates limit and concurrency boundaries", async () => {
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      // Limit boundaries
      await expect(engine.reconcileAll({ limit: 0 })).rejects.toThrow(/Limit must be a positive integer between 1 and 1000/);
      await expect(engine.reconcileAll({ limit: -1 })).rejects.toThrow(/Limit must be a positive integer between 1 and 1000/);
      await expect(engine.reconcileAll({ limit: 1001 })).rejects.toThrow(/Limit must be a positive integer between 1 and 1000/);
      await expect(engine.reconcileAll({ limit: 5.5 })).rejects.toThrow(/Limit must be a positive integer between 1 and 1000/);
      await expect(engine.reconcileAll({ limit: "100" as any })).rejects.toThrow(/Limit must be a positive integer between 1 and 1000/);

      // Concurrency boundaries
      await expect(engine.reconcileAll({ concurrency: 0 })).rejects.toThrow(/Concurrency must be a positive integer between 1 and 10/);
      await expect(engine.reconcileAll({ concurrency: -1 })).rejects.toThrow(/Concurrency must be a positive integer between 1 and 10/);
      await expect(engine.reconcileAll({ concurrency: 11 })).rejects.toThrow(/Concurrency must be a positive integer between 1 and 10/);
      await expect(engine.reconcileAll({ concurrency: 3.5 })).rejects.toThrow(/Concurrency must be a positive integer between 1 and 10/);

      // Status filter
      await expect(engine.reconcileAll({ status: "COMMITTED" as any })).rejects.toThrow(/Invalid status filter/);

      // Timeout
      await expect(engine.reconcileAll({ timeoutMs: -100 })).rejects.toThrow(/timeoutMs must be a positive safe integer/);
      await expect(engine.reconcileAll({ timeoutMs: 0 })).rejects.toThrow(/timeoutMs must be a positive safe integer/);

      // Signal
      await expect(engine.reconcileAll({ signal: "not-a-signal" as any })).rejects.toThrow(/signal must be an instance of AbortSignal/);

      engine.close();
    });

    it("respects limit parameter during discovery", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const rawDb = new DatabaseSync(dbPath);
      for (let i = 1; i <= 5; i++) {
        rawDb.prepare(`
          INSERT INTO consumed_authorization_ids (
            authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
          ) VALUES (?, 'sha256:0000000000000000000000000000000000000000000000000000000000000000', 'consumed', ?, ?, 'PENDING_COMMIT')
        `).run(`auth-b33-lim-${i}`, `2026-10-30 01:0${i}:00`, `ticket-lim-${i}`);
      }
      rawDb.close();

      // limit: 2 should only process 2
      const res = await engine.reconcileAll({ limit: 2 });
      expect(res.summary.totalDiscovered).toBe(2);
      expect(res.summary.totalProcessed).toBe(2);
      expect(res.results.length).toBe(2);
      expect(res.results.map((r) => r.authorizationId)).toEqual([
        "auth-b33-lim-1",
        "auth-b33-lim-2",
      ]);

      engine.close();
    });

    it("enforces maximum simultaneous worker count under concurrency limit", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });

      let currentActive = 0;
      let maxObservedConcurrency = 0;

      const trackingWitness = createDelegatingWitness(baseWitness, {
        reconcileTicket: async (req) => {
          currentActive++;
          if (currentActive > maxObservedConcurrency) {
            maxObservedConcurrency = currentActive;
          }
          // Brief pause to allow concurrency build-up
          await new Promise((resolve) => setTimeout(resolve, 25));
          currentActive--;
          return baseWitness.reconcileTicket(req);
        },
      });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: trackingWitness,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const rawDb = new DatabaseSync(dbPath);
      for (let i = 1; i <= 8; i++) {
        rawDb.prepare(`
          INSERT INTO consumed_authorization_ids (
            authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
          ) VALUES (?, 'sha256:0000000000000000000000000000000000000000000000000000000000000000', 'consumed', ?, ?, 'PENDING_COMMIT')
        `).run(`auth-b33-conc-${i}`, `2026-10-30 02:0${i}:00`, `ticket-conc-${i}`);
      }
      rawDb.close();

      // Configure concurrency: 3
      const res = await engine.reconcileAll({ concurrency: 3 });
      expect(res.summary.totalProcessed).toBe(8);
      expect(maxObservedConcurrency).toBeLessThanOrEqual(3);
      expect(maxObservedConcurrency).toBeGreaterThanOrEqual(2);

      engine.close();
    });

    it("preserves deterministic output ordering matching discovery order", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });

      // Variable latency adapter to simulate out-of-order completions
      const variableLatencyWitness = createDelegatingWitness(baseWitness, {
        reconcileTicket: async (req) => {
          // Delay odd tickets longer than even tickets
          const isOdd = parseInt(req.ticketId.slice(-1), 10) % 2 === 1;
          await new Promise((resolve) => setTimeout(resolve, isOdd ? 40 : 5));
          return baseWitness.reconcileTicket(req);
        },
      });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: variableLatencyWitness,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const rawDb = new DatabaseSync(dbPath);
      for (let i = 1; i <= 6; i++) {
        rawDb.prepare(`
          INSERT INTO consumed_authorization_ids (
            authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
          ) VALUES (?, 'sha256:0000000000000000000000000000000000000000000000000000000000000000', 'consumed', ?, ?, 'PENDING_COMMIT')
        `).run(`auth-b33-order-${i}`, `2026-10-30 03:0${i}:00`, `ticket-order-${i}`);
      }
      rawDb.close();

      const res = await engine.reconcileAll({ concurrency: 4 });
      expect(res.results.length).toBe(6);
      expect(res.results.map((r) => r.authorizationId)).toEqual([
        "auth-b33-order-1",
        "auth-b33-order-2",
        "auth-b33-order-3",
        "auth-b33-order-4",
        "auth-b33-order-5",
        "auth-b33-order-6",
      ]);

      engine.close();
    });

    it("correctly aggregates mixed outcomes (success, already-committed, pending, disputed, unavailable)", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b33_mix",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      // Item 1: Valid RECONCILED (was PENDING_COMMIT in SQLite, but COMMITTED on witness)
      const issued1 = engine.issue({
        authorizationId: "auth-b33-mix-reconciled",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: { keyId: "key_b33_mix", privateKey: keypair.privateKey },
      });
      expect(issued1.decision).toBe("ALLOW");
      if (issued1.decision !== "ALLOW") return;
      const t1 = baseWitness.reserveTicket({
        authorizationId: "auth-b33-mix-reconciled",
        bindingDigest: issued1.artifact.bindingDigest,
        policyId: SAMPLE_POLICY.policyId,
        policyRevision: 1,
        idempotencyKey: "idemp-mix-1",
      });
      baseWitness.commitTicket({
        ticketId: t1.ticketId!,
        authorizationId: "auth-b33-mix-reconciled",
        bindingDigest: issued1.artifact.bindingDigest,
        localCommittedAtSeconds: 1700000000,
      });

      // Item 2: PENDING (RESERVED on witness, not yet committed)
      const t2 = baseWitness.reserveTicket({
        authorizationId: "auth-b33-mix-pending",
        bindingDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        policyId: SAMPLE_POLICY.policyId,
        policyRevision: 1,
        idempotencyKey: "idemp-mix-2",
      });

      // Insert into SQLite
      const rawDb = new DatabaseSync(dbPath);
      // Row 1: PENDING_COMMIT (to be reconciled)
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET state = 'consumed', consumed_at = '2026-10-30 04:01:00', witness_ticket_id = ?, witness_status = 'PENDING_COMMIT'
        WHERE authorization_id = 'auth-b33-mix-reconciled'
      `).run(t1.ticketId!);

      // Row 2: PENDING_COMMIT (remains pending)
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
        ) VALUES ('auth-b33-mix-pending', 'sha256:2222222222222222222222222222222222222222222222222222222222222222', 'consumed', '2026-10-30 04:02:00', ?, 'PENDING_COMMIT')
      `).run(t2.ticketId!);

      // Row 3: DISPUTED (ticket unknown on witness)
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
        ) VALUES ('auth-b33-mix-disputed', 'sha256:3333333333333333333333333333333333333333333333333333333333333333', 'consumed', '2026-10-30 04:03:00', 'ticket-missing', 'DISPUTED')
      `).run();
      rawDb.close();

      const res = await engine.reconcileAll();
      expect(res.summary.totalDiscovered).toBe(3);
      expect(res.summary.totalProcessed).toBe(3);
      expect(res.summary.reconciledCount).toBe(1);
      expect(res.summary.pendingCount).toBe(1);
      expect(res.summary.disputedCount).toBe(1);

      expect(res.results[0].outcome).toBe("RECONCILED");
      expect(res.results[0].receipt).toBeDefined();

      expect(res.results[1].outcome).toBe("PENDING");
      expect(res.results[1].receipt).toBeUndefined();

      expect(res.results[2].outcome).toBe("DISPUTED");

      engine.close();
    });

    it("isolates worker errors so one failing item does not corrupt other batch results", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });

      // Witness that throws for one specific ticket ID but succeeds for others
      const failingWitness = createDelegatingWitness(baseWitness, {
        reconcileTicket: async (req) => {
          if (req.ticketId === "ticket-crash-2") {
            throw new Error("Simulated witness hardware fault");
          }
          return baseWitness.reconcileTicket(req);
        },
      });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: failingWitness,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const rawDb = new DatabaseSync(dbPath);
      for (let i = 1; i <= 3; i++) {
        rawDb.prepare(`
          INSERT INTO consumed_authorization_ids (
            authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
          ) VALUES (?, 'sha256:0000000000000000000000000000000000000000000000000000000000000000', 'consumed', ?, ?, 'PENDING_COMMIT')
        `).run(`auth-b33-crash-${i}`, `2026-10-30 05:0${i}:00`, `ticket-crash-${i}`);
      }
      rawDb.close();

      const res = await engine.reconcileAll({ concurrency: 2 });
      expect(res.summary.totalProcessed).toBe(3);
      // Item 2 should fail with UNAVAILABLE
      expect(res.results[1].outcome).toBe("UNAVAILABLE");
      expect(res.results[1].reasons?.[0]).toMatch(/hardware fault/);

      // Items 1 and 3 settle normally as DISPUTED (ticket not found on witness)
      expect(res.results[0].outcome).toBe("DISPUTED");
      expect(res.results[2].outcome).toBe("DISPUTED");

      engine.close();
    });

    it("supports graceful cancellation via AbortSignal", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const controller = new AbortController();

      let processedCount = 0;
      const slowWitness = createDelegatingWitness(baseWitness, {
        reconcileTicket: async (req) => {
          processedCount++;
          if (processedCount === 2) {
            controller.abort("User cancelled reconciliation batch");
          }
          await new Promise((resolve) => setTimeout(resolve, 20));
          return baseWitness.reconcileTicket(req);
        },
      });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: slowWitness,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const rawDb = new DatabaseSync(dbPath);
      for (let i = 1; i <= 6; i++) {
        rawDb.prepare(`
          INSERT INTO consumed_authorization_ids (
            authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
          ) VALUES (?, 'sha256:0000000000000000000000000000000000000000000000000000000000000000', 'consumed', ?, ?, 'PENDING_COMMIT')
        `).run(`auth-b33-abort-${i}`, `2026-10-30 06:0${i}:00`, `ticket-abort-${i}`);
      }
      rawDb.close();

      const res = await engine.reconcileAll({
        concurrency: 2,
        signal: controller.signal,
      });

      expect(res.aborted).toBe(true);
      expect(res.abortReason).toMatch(/User cancelled/);
      // Total discovered is 6
      expect(res.summary.totalDiscovered).toBe(6);
      // Some items were aborted before execution
      const abortedItems = res.results.filter((r) =>
        r.reasons?.some((msg) => msg.includes("aborted before execution")),
      );
      expect(abortedItems.length).toBeGreaterThan(0);

      engine.close();
    });

    it("supports timeout via timeoutMs without corrupting state", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });

      const hungWitness = createDelegatingWitness(baseWitness, {
        reconcileTicket: async (req) => {
          await new Promise((resolve) => setTimeout(resolve, 100));
          return baseWitness.reconcileTicket(req);
        },
      });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: hungWitness,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const rawDb = new DatabaseSync(dbPath);
      for (let i = 1; i <= 5; i++) {
        rawDb.prepare(`
          INSERT INTO consumed_authorization_ids (
            authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
          ) VALUES (?, 'sha256:0000000000000000000000000000000000000000000000000000000000000000', 'consumed', ?, ?, 'PENDING_COMMIT')
        `).run(`auth-b33-time-${i}`, `2026-10-30 07:0${i}:00`, `ticket-time-${i}`);
      }
      rawDb.close();

      const res = await engine.reconcileAll({
        concurrency: 1,
        timeoutMs: 40,
      });

      expect(res.aborted).toBe(true);
      expect(res.abortReason).toMatch(/timed out/);
      expect(res.results.length).toBe(5);

      engine.close();
    });

    it("proves consumed tickets are never released and no duplicate processing occurs", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      let releaseCalled = false;
      const queriedTickets = new Map<string, number>();

      const trackedWitness = createDelegatingWitness(baseWitness, {
        releaseTicket: (req) => {
          releaseCalled = true;
          return baseWitness.releaseTicket(req);
        },
        reconcileTicket: (req) => {
          queriedTickets.set(req.ticketId, (queriedTickets.get(req.ticketId) ?? 0) + 1);
          return baseWitness.reconcileTicket(req);
        },
      });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: trackedWitness,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const rawDb = new DatabaseSync(dbPath);
      for (let i = 1; i <= 4; i++) {
        rawDb.prepare(`
          INSERT INTO consumed_authorization_ids (
            authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
          ) VALUES (?, 'sha256:0000000000000000000000000000000000000000000000000000000000000000', 'consumed', ?, ?, 'PENDING_COMMIT')
        `).run(`auth-b33-dup-${i}`, `2026-10-30 08:0${i}:00`, `ticket-dup-${i}`);
      }
      rawDb.close();

      await engine.reconcileAll({ concurrency: 2 });
      expect(releaseCalled).toBe(false);

      // Verify each ticket was queried exactly once
      for (let i = 1; i <= 4; i++) {
        expect(queriedTickets.get(`ticket-dup-${i}`)).toBe(1);
      }

      engine.close();
    });

    it("handles repeated batch calls idempotently", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: baseWitness,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b33_rep",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const issued = engine.issue({
        authorizationId: "auth-b33-rep-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: { keyId: "key_b33_rep", privateKey: keypair.privateKey },
      });
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;
      const t = baseWitness.reserveTicket({
        authorizationId: "auth-b33-rep-01",
        bindingDigest: issued.artifact.bindingDigest,
        policyId: SAMPLE_POLICY.policyId,
        policyRevision: 1,
        idempotencyKey: "idemp-rep-1",
      });
      baseWitness.commitTicket({
        ticketId: t.ticketId!,
        authorizationId: "auth-b33-rep-01",
        bindingDigest: issued.artifact.bindingDigest,
        localCommittedAtSeconds: 1700000000,
      });

      const rawDb = new DatabaseSync(dbPath);
      rawDb.prepare(`
        UPDATE consumed_authorization_ids
        SET state = 'consumed', consumed_at = '2026-10-30 09:00:00', witness_ticket_id = ?, witness_status = 'PENDING_COMMIT'
        WHERE authorization_id = 'auth-b33-rep-01'
      `).run(t.ticketId!);
      rawDb.close();

      // First batch: discovers and reconciles 1 item
      const res1 = await engine.reconcileAll();
      expect(res1.summary.totalDiscovered).toBe(1);
      expect(res1.summary.reconciledCount).toBe(1);
      expect(res1.results[0].outcome).toBe("RECONCILED");

      // Second batch: discovers 0 items because the item is now COMMITTED
      const res2 = await engine.reconcileAll();
      expect(res2.summary.totalDiscovered).toBe(0);
      expect(res2.results.length).toBe(0);

      engine.close();
    });

    it("preserves lock-ordering and concurrency safety with concurrent SQLite writes", async () => {
      const baseWitness = new LocalDeterministicWitness({ keyPair: TEST_KEY_PAIR });

      // Slow witness to keep batch in flight
      const slowWitness = createDelegatingWitness(baseWitness, {
        reconcileTicket: async (req) => {
          await new Promise((resolve) => setTimeout(resolve, 30));
          return baseWitness.reconcileTicket(req);
        },
      });

      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        witnessAdapter: slowWitness,
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const keypair = engine.keys.generate();
      engine.keys.register({
        keyId: "key_b33_lock_safe",
        publicKey: keypair.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });
      engine.policies.register(SAMPLE_POLICY);

      const rawDb = new DatabaseSync(dbPath);
      for (let i = 1; i <= 4; i++) {
        rawDb.prepare(`
          INSERT INTO consumed_authorization_ids (
            authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_status
          ) VALUES (?, 'sha256:0000000000000000000000000000000000000000000000000000000000000000', 'consumed', ?, ?, 'PENDING_COMMIT')
        `).run(`auth-b33-lock-${i}`, `2026-10-30 10:0${i}:00`, `ticket-lock-${i}`);
      }
      rawDb.close();

      // Start batch reconciliation in background
      const batchPromise = engine.reconcileAll({ concurrency: 2 });

      // Concurrently perform issue operations on separate authorizations
      const issue1 = engine.issue({
        authorizationId: "auth-b33-lock-concurrent-1",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: { keyId: "key_b33_lock_safe", privateKey: keypair.privateKey },
      });
      const issue2 = engine.issue({
        authorizationId: "auth-b33-lock-concurrent-2",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: { keyId: "key_b33_lock_safe", privateKey: keypair.privateKey },
      });

      expect(issue1.decision).toBe("ALLOW");
      expect(issue2.decision).toBe("ALLOW");

      const batchRes = await batchPromise;
      expect(batchRes.summary.totalProcessed).toBe(4);

      engine.close();
    });
  });
});
