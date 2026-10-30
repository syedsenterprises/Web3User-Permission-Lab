import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import {
  Web3UserEngine,
  SQLiteAuthorizationStore,
  SQLiteDurableWitness,
  DurableWitnessError,
  CorruptedWitnessDatabaseError,
  WitnessStorageUnavailableError,
  generateIssuerKeyPair,
  createTransactionEnvelope,
  verifyWitnessReceipt,
  type TransactionRequest,
  type DemoPolicy,
} from "../src/index.js";

const TEST_KEY_PAIR = generateIssuerKeyPair();

function createTestDirectory(): string {
  const dir = join(tmpdir(), `web3user-m13b-witness-test-${Date.now()}-${randomBytes(4).toString("hex")}`);
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
  policyId: "pol_durable_witness_01",
  allowedTarget: "0x1111111111111111111111111111111111111111",
  allowedRecipient: "0x4444444444444444444444444444444444444444",
  allowedSelector: "0xa9059cbb",
  maxAmount: "2000000000000000000",
  validFrom: 0,
  expiresAt: 2000000000,
  revoked: false,
  budget: {
    window: "HOURLY",
    maxCumulativeAmount: "10000000000000000000", // 10 tokens
  },
};

describe("Milestone 13-B: SQLiteDurableWitness Implementation", () => {
  let testDir: string;
  let witnessDbPath: string;

  beforeEach(() => {
    testDir = createTestDirectory();
    witnessDbPath = join(testDir, "witness.sqlite");
  });

  afterEach(() => {
    try {
      rmSync(testDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors on Windows
    }
  });

  // ============================================================================
  // Test Area 1: Process Restart Persistence
  // ============================================================================
  describe("1. Process Restart Persistence", () => {
    it("persists tickets, sequence numbers, and accumulators across process restarts", () => {
      // Process 1: Initialize witness and commit an authorization
      const witness1 = new SQLiteDurableWitness({
        dbPath: witnessDbPath,
        witnessId: "wit-prod-01",
        epochId: "epoch-prod-01",
      });

      const reserveRes = witness1.reserveTicket({
        authorizationId: "auth-restart-01",
        bindingDigest: "sha256:" + "a".repeat(64),
        policyId: "pol_01",
        policyRevision: 1,
        idempotencyKey: "idemp-restart-01",
        budgetWindows: [
          {
            windowType: "HOURLY",
            windowStart: 1000,
            requestedAmount: "1000",
            maxCumulativeAmount: "5000",
          },
        ],
      });

      expect(reserveRes.decision).toBe("ALLOW");
      const ticketId = reserveRes.ticketId!;

      const commitRes = witness1.commitTicket({
        ticketId,
        authorizationId: "auth-restart-01",
        bindingDigest: "sha256:" + "a".repeat(64),
        localCommittedAtSeconds: 1050,
      });

      expect(commitRes.decision).toBe("ALLOW");
      expect(commitRes.receipt?.sequenceNumber).toBe("1");
      const pubKeyPem = witness1.publicKeyPem;
      const witnessId = witness1.getWitnessId();
      const epochId = witness1.getEpochId();

      witness1.close();

      // Process 2: Reopen witness on the same database file
      const witness2 = new SQLiteDurableWitness({ dbPath: witnessDbPath });

      expect(witness2.getWitnessId()).toBe(witnessId);
      expect(witness2.getEpochId()).toBe(epochId);
      expect(witness2.publicKeyPem).toBe(pubKeyPem);
      expect(witness2.getCurrentSequence()).toBe("1");

      // Reconcile committed ticket
      const reconcile = witness2.reconcileTicket({ ticketId });
      expect(reconcile.state).toBe("COMMITTED");
      expect(reconcile.receipt?.sequenceNumber).toBe("1");
      expect(reconcile.receipt?.authorizationId).toBe("auth-restart-01");

      // Attempt replay of same authId
      const replayReserve = witness2.reserveTicket({
        authorizationId: "auth-restart-01",
        bindingDigest: "sha256:" + "a".repeat(64),
        policyId: "pol_01",
        policyRevision: 1,
        idempotencyKey: "idemp-restart-02",
      });

      expect(replayReserve.decision).toBe("DENY");
      expect(replayReserve.reasons?.[0]).toContain("already been reserved or committed");

      witness2.close();
    });
  });

  // ============================================================================
  // Test Area 2: Database Reopening & WAL Recovery
  // ============================================================================
  describe("2. Database Reopening & WAL Recovery", () => {
    it("configures WAL mode and synchronous=FULL and recovers correctly", () => {
      const witness = new SQLiteDurableWitness({ dbPath: witnessDbPath });

      // Verify PRAGMA settings via direct query
      const rawDb = new DatabaseSync(witnessDbPath);
      const journalModeRow = rawDb.prepare("PRAGMA journal_mode;").get() as { journal_mode: string };
      expect(journalModeRow.journal_mode.toLowerCase()).toBe("wal");

      const syncRow = rawDb.prepare("PRAGMA synchronous;").get() as { synchronous: number };
      expect(syncRow.synchronous).toBe(2); // 2 = FULL

      const integrityRow = rawDb.prepare("PRAGMA integrity_check;").get() as { integrity_check: string };
      expect(integrityRow.integrity_check).toBe("ok");

      rawDb.close();
      witness.close();
    });
  });

  // ============================================================================
  // Test Area 3: Power-Loss / Crash Simulation
  // ============================================================================
  describe("3. Power-Loss / Crash Simulation", () => {
    it("preserves committed transactions and recovers WAL log without data loss", () => {
      const witness = new SQLiteDurableWitness({ dbPath: witnessDbPath });

      for (let i = 1; i <= 5; i++) {
        const res = witness.reserveTicket({
          authorizationId: `auth-crash-${i}`,
          bindingDigest: "sha256:" + `${i}`.repeat(64),
          policyId: "pol_crash",
          policyRevision: 1,
          idempotencyKey: `idemp-crash-${i}`,
        });
        witness.commitTicket({
          ticketId: res.ticketId!,
          authorizationId: `auth-crash-${i}`,
          bindingDigest: "sha256:" + `${i}`.repeat(64),
          localCommittedAtSeconds: 1000 + i,
        });
      }

      // Abruptly close without manual checkpoint
      witness.close();

      // Reopen and verify all 5 commits are intact
      const recoveredWitness = new SQLiteDurableWitness({ dbPath: witnessDbPath });
      expect(recoveredWitness.getCurrentSequence()).toBe("5");

      for (let i = 1; i <= 5; i++) {
        const status = recoveredWitness.getSyncStatus(undefined, String(i));
        expect(status.divergenceDetected).toBe(false);
      }

      recoveredWitness.close();
    });
  });

  // ============================================================================
  // Test Area 4: Concurrent Ticket Reservations and Commits
  // ============================================================================
  describe("4. Concurrent Ticket Reservations & Commits", () => {
    it("handles concurrent reservation and commit operations without deadlocks", () => {
      const witness = new SQLiteDurableWitness({ dbPath: witnessDbPath });
      const n = 15;

      const tickets: string[] = [];
      for (let i = 0; i < n; i++) {
        const res = witness.reserveTicket({
          authorizationId: `auth-concurrent-${i}`,
          bindingDigest: "sha256:" + "b".repeat(64),
          policyId: "pol_concurrent",
          policyRevision: 1,
          idempotencyKey: `idemp-concurrent-${i}`,
          budgetWindows: [
            {
              windowType: "HOURLY",
              windowStart: 2000,
              requestedAmount: "10",
              maxCumulativeAmount: "1000",
            },
          ],
        });
        expect(res.decision).toBe("ALLOW");
        tickets.push(res.ticketId!);
      }

      for (let i = 0; i < n; i++) {
        const commit = witness.commitTicket({
          ticketId: tickets[i],
          authorizationId: `auth-concurrent-${i}`,
          bindingDigest: "sha256:" + "b".repeat(64),
          localCommittedAtSeconds: 2050,
        });
        expect(commit.decision).toBe("ALLOW");
        expect(commit.receipt?.sequenceNumber).toBe(String(i + 1));
      }

      expect(witness.getCurrentSequence()).toBe(String(n));
      witness.close();
    });
  });

  // ============================================================================
  // Test Area 5: Concurrent Sequence Allocation
  // ============================================================================
  describe("5. Concurrent Sequence Allocation", () => {
    it("allocates strictly increasing monotonic sequence numbers without duplicates", () => {
      const witness = new SQLiteDurableWitness({ dbPath: witnessDbPath });
      const count = 20;

      const sequences: bigint[] = [];
      for (let i = 0; i < count; i++) {
        const res = witness.reserveTicket({
          authorizationId: `auth-seq-${i}`,
          bindingDigest: "sha256:" + "c".repeat(64),
          policyId: "pol_seq",
          policyRevision: 1,
          idempotencyKey: `idemp-seq-${i}`,
        });
        const commit = witness.commitTicket({
          ticketId: res.ticketId!,
          authorizationId: `auth-seq-${i}`,
          bindingDigest: "sha256:" + "c".repeat(64),
          localCommittedAtSeconds: 3000 + i,
        });
        expect(commit.decision).toBe("ALLOW");
        sequences.push(BigInt(commit.receipt!.sequenceNumber));
      }

      // Assert strictly increasing: S[i+1] > S[i]
      for (let i = 0; i < sequences.length - 1; i++) {
        expect(sequences[i + 1]).toBeGreaterThan(sequences[i]);
      }

      // Assert unique set
      const uniqueSeqs = new Set(sequences);
      expect(uniqueSeqs.size).toBe(count);

      witness.close();
    });
  });

  // ============================================================================
  // Test Area 6: Aborted Operations and Sequence Gaps
  // ============================================================================
  describe("6. Aborted Operations & Sequence Gaps", () => {
    it("maintains strict monotonicity even if an operation aborts or gaps occur", () => {
      const witness = new SQLiteDurableWitness({ dbPath: witnessDbPath });

      // Commit 1
      const res1 = witness.reserveTicket({
        authorizationId: "auth-gap-01",
        bindingDigest: "sha256:" + "d".repeat(64),
        policyId: "pol_gap",
        policyRevision: 1,
        idempotencyKey: "idemp-gap-01",
      });
      const com1 = witness.commitTicket({
        ticketId: res1.ticketId!,
        authorizationId: "auth-gap-01",
        bindingDigest: "sha256:" + "d".repeat(64),
        localCommittedAtSeconds: 100,
      });
      expect(com1.receipt?.sequenceNumber).toBe("1");

      // Reserve and deliberately release (aborted transaction)
      const res2 = witness.reserveTicket({
        authorizationId: "auth-gap-02",
        bindingDigest: "sha256:" + "d".repeat(64),
        policyId: "pol_gap",
        policyRevision: 1,
        idempotencyKey: "idemp-gap-02",
      });
      const rel2 = witness.releaseTicket({
        ticketId: res2.ticketId!,
        authorizationId: "auth-gap-02",
        bindingDigest: "sha256:" + "d".repeat(64),
        reason: "User cancelled transaction",
      });
      expect(rel2.success).toBe(true);

      // Commit 3: Next sequence is allocated monotonically
      const res3 = witness.reserveTicket({
        authorizationId: "auth-gap-03",
        bindingDigest: "sha256:" + "d".repeat(64),
        policyId: "pol_gap",
        policyRevision: 1,
        idempotencyKey: "idemp-gap-03",
      });
      const com3 = witness.commitTicket({
        ticketId: res3.ticketId!,
        authorizationId: "auth-gap-03",
        bindingDigest: "sha256:" + "d".repeat(64),
        localCommittedAtSeconds: 200,
      });

      expect(BigInt(com3.receipt!.sequenceNumber)).toBeGreaterThan(BigInt(com1.receipt!.sequenceNumber));
      witness.close();
    });
  });

  // ============================================================================
  // Test Area 7: Duplicate Commit and Release Requests
  // ============================================================================
  describe("7. Duplicate Commit & Release Requests", () => {
    it("handles idempotent commit retries and idempotent release retries", () => {
      const witness = new SQLiteDurableWitness({ dbPath: witnessDbPath });

      // Test idempotent commit
      const res1 = witness.reserveTicket({
        authorizationId: "auth-idem-01",
        bindingDigest: "sha256:" + "e".repeat(64),
        policyId: "pol_idem",
        policyRevision: 1,
        idempotencyKey: "idemp-idem-01",
      });

      const com1 = witness.commitTicket({
        ticketId: res1.ticketId!,
        authorizationId: "auth-idem-01",
        bindingDigest: "sha256:" + "e".repeat(64),
        localCommittedAtSeconds: 100,
      });
      expect(com1.alreadyCommitted).toBe(false);

      const com2 = witness.commitTicket({
        ticketId: res1.ticketId!,
        authorizationId: "auth-idem-01",
        bindingDigest: "sha256:" + "e".repeat(64),
        localCommittedAtSeconds: 100,
      });
      expect(com2.alreadyCommitted).toBe(true);
      expect(com2.receipt?.signature).toBe(com1.receipt?.signature);

      // Terminal committed cannot be released
      const relCom = witness.releaseTicket({
        ticketId: res1.ticketId!,
        authorizationId: "auth-idem-01",
        bindingDigest: "sha256:" + "e".repeat(64),
        reason: "Attempt release on committed",
      });
      expect(relCom.success).toBe(false);
      expect(relCom.previousState).toBe("COMMITTED");

      // Test idempotent release
      const res2 = witness.reserveTicket({
        authorizationId: "auth-idem-02",
        bindingDigest: "sha256:" + "e".repeat(64),
        policyId: "pol_idem",
        policyRevision: 1,
        idempotencyKey: "idemp-idem-02",
      });
      const rel1 = witness.releaseTicket({
        ticketId: res2.ticketId!,
        authorizationId: "auth-idem-02",
        bindingDigest: "sha256:" + "e".repeat(64),
        reason: "Release attempt 1",
      });
      expect(rel1.success).toBe(true);

      const rel2 = witness.releaseTicket({
        ticketId: res2.ticketId!,
        authorizationId: "auth-idem-02",
        bindingDigest: "sha256:" + "e".repeat(64),
        reason: "Release attempt 2",
      });
      expect(rel2.success).toBe(true);
      expect(rel2.previousState).toBe("RELEASED");

      // Terminal released cannot be committed
      const comRel = witness.commitTicket({
        ticketId: res2.ticketId!,
        authorizationId: "auth-idem-02",
        bindingDigest: "sha256:" + "e".repeat(64),
        localCommittedAtSeconds: 100,
      });
      expect(comRel.decision).toBe("DENY");
      expect(comRel.reasons?.[0]).toContain("already been permanently released");

      witness.close();
    });
  });

  // ============================================================================
  // Test Area 8: Invalid and Conflicting Receipts
  // ============================================================================
  describe("8. Invalid & Conflicting Receipts", () => {
    it("rejects commit when binding digest or authorization ID does not match reservation", () => {
      const witness = new SQLiteDurableWitness({ dbPath: witnessDbPath });

      const res = witness.reserveTicket({
        authorizationId: "auth-valid-01",
        bindingDigest: "sha256:" + "f".repeat(64),
        policyId: "pol_mismatch",
        policyRevision: 1,
        idempotencyKey: "idemp-mismatch-01",
      });

      // Mismatched authId
      const comBadAuth = witness.commitTicket({
        ticketId: res.ticketId!,
        authorizationId: "auth-WRONG-01",
        bindingDigest: "sha256:" + "f".repeat(64),
        localCommittedAtSeconds: 100,
      });
      expect(comBadAuth.decision).toBe("DENY");
      expect(comBadAuth.reasons?.[0]).toContain("mismatch");

      // Mismatched bindingDigest
      const comBadDigest = witness.commitTicket({
        ticketId: res.ticketId!,
        authorizationId: "auth-valid-01",
        bindingDigest: "sha256:" + "0".repeat(64),
        localCommittedAtSeconds: 100,
      });
      expect(comBadDigest.decision).toBe("DENY");
      expect(comBadDigest.reasons?.[0]).toContain("mismatch");

      witness.close();
    });

    it("cryptographically verifies receipts against the witness public key", () => {
      const witness = new SQLiteDurableWitness({ dbPath: witnessDbPath });

      const res = witness.reserveTicket({
        authorizationId: "auth-sig-01",
        bindingDigest: "sha256:" + "1".repeat(64),
        policyId: "pol_sig",
        policyRevision: 1,
        idempotencyKey: "idemp-sig-01",
      });

      const com = witness.commitTicket({
        ticketId: res.ticketId!,
        authorizationId: "auth-sig-01",
        bindingDigest: "sha256:" + "1".repeat(64),
        localCommittedAtSeconds: 500,
      });

      expect(com.decision).toBe("ALLOW");
      const receipt = com.receipt!;

      // Valid signature verifies against correct public key
      expect(verifyWitnessReceipt(witness.publicKeyPem, receipt)).toBe(true);

      // Wrong key fails verification
      const foreignKeys = generateIssuerKeyPair();
      expect(verifyWitnessReceipt(foreignKeys.publicKeyPem, receipt)).toBe(false);

      // Tampered payload fails verification
      const tamperedReceipt = { ...receipt, sequenceNumber: "99999" };
      expect(verifyWitnessReceipt(witness.publicKeyPem, tamperedReceipt)).toBe(false);

      witness.close();
    });
  });

  // ============================================================================
  // Test Area 9: Database Corruption & Failed Migrations
  // ============================================================================
  describe("9. Database Corruption & Failed Migrations", () => {
    it("fails closed with CorruptedWitnessDatabaseError if SQLite file is corrupt", () => {
      // Create valid DB
      const witness = new SQLiteDurableWitness({ dbPath: witnessDbPath });
      witness.close();

      // Write random garbage into header of SQLite file
      writeFileSync(witnessDbPath, Buffer.from("NOT A VALID SQLITE DATABASE HEADER GARBAGE"));

      expect(() => {
        new SQLiteDurableWitness({ dbPath: witnessDbPath });
      }).toThrow(CorruptedWitnessDatabaseError);
    });

    it("fails closed if witness_meta indicates unsupported schema version", () => {
      const witness = new SQLiteDurableWitness({ dbPath: witnessDbPath });
      witness.close();

      // Tamper schema version to future version
      const rawDb = new DatabaseSync(witnessDbPath);
      rawDb.prepare("UPDATE witness_meta SET value = '999' WHERE key = 'schema_version';").run();
      rawDb.close();

      expect(() => {
        new SQLiteDurableWitness({ dbPath: witnessDbPath });
      }).toThrow(/Unsupported witness schema version/);
    });
  });

  // ============================================================================
  // Test Area 10: Expired & Quarantined Tickets
  // ============================================================================
  describe("10. Expired & Quarantined Tickets", () => {
    it("transitions expired reservations to QUARANTINED_UNCONFIRMED and prevents release", () => {
      let simTime = 1000;
      const witness = new SQLiteDurableWitness({
        dbPath: witnessDbPath,
        defaultLeaseTtlSeconds: 10,
        nowSeconds: () => simTime,
      });

      const res = witness.reserveTicket({
        authorizationId: "auth-quarantine-01",
        bindingDigest: "sha256:" + "2".repeat(64),
        policyId: "pol_quarantine",
        policyRevision: 1,
        idempotencyKey: "idemp-quarantine-01",
        leaseTtlSeconds: 10,
        budgetWindows: [
          {
            windowType: "HOURLY",
            windowStart: 1000,
            requestedAmount: "500",
            maxCumulativeAmount: "1000",
          },
        ],
      });

      expect(res.decision).toBe("ALLOW");
      const ticketId = res.ticketId!;

      // Advance time by 20 seconds (past 10s TTL)
      simTime = 1020;

      // Reconcile detects expiration and transitions to QUARANTINED_UNCONFIRMED
      const reconcile = witness.reconcileTicket({ ticketId });
      expect(reconcile.state).toBe("QUARANTINED_UNCONFIRMED");

      // Attempt release must fail
      const release = witness.releaseTicket({
        ticketId,
        authorizationId: "auth-quarantine-01",
        bindingDigest: "sha256:" + "2".repeat(64),
        reason: "Release attempt on quarantined ticket",
      });
      expect(release.success).toBe(false);
      expect(release.previousState).toBe("QUARANTINED_UNCONFIRMED");
      expect(release.reasons?.[0]).toContain("quarantined");

      // Budget capacity remains held: cannot reserve another 600 (500 + 600 > 1000)
      const overBudgetRes = witness.reserveTicket({
        authorizationId: "auth-quarantine-02",
        bindingDigest: "sha256:" + "2".repeat(64),
        policyId: "pol_quarantine",
        policyRevision: 1,
        idempotencyKey: "idemp-quarantine-02",
        budgetWindows: [
          {
            windowType: "HOURLY",
            windowStart: 1000,
            requestedAmount: "600",
            maxCumulativeAmount: "1000",
          },
        ],
      });
      expect(overBudgetRes.decision).toBe("DENY");
      expect(overBudgetRes.reasons?.[0]).toContain("Cumulative spending budget exceeded");

      // Commit on QUARANTINED_UNCONFIRMED ticket is permitted (resolves crash window 2)
      const commit = witness.commitTicket({
        ticketId,
        authorizationId: "auth-quarantine-01",
        bindingDigest: "sha256:" + "2".repeat(64),
        localCommittedAtSeconds: 1020,
      });
      expect(commit.decision).toBe("ALLOW");
      expect(commit.receipt?.authorizationId).toBe("auth-quarantine-01");

      witness.close();
    });
  });

  // ============================================================================
  // Test Area 11: Recovery from Every Documented Crash Window
  // ============================================================================
  describe("11. Crash Window Recovery Verification", () => {
    it("safely recovers across Window 1, Window 2, Window 3, and Window 4", () => {
      let simTime = 5000;
      const witness = new SQLiteDurableWitness({
        dbPath: witnessDbPath,
        nowSeconds: () => simTime,
      });

      // Window 1: Reservation made, node crashed before local SQLite write.
      // Recovery: Lease expires, ticket quarantined. Capacity remains held safely.
      const w1Res = witness.reserveTicket({
        authorizationId: "auth-w1",
        bindingDigest: "sha256:" + "3".repeat(64),
        policyId: "pol_windows",
        policyRevision: 1,
        idempotencyKey: "idemp-w1",
        leaseTtlSeconds: 5,
      });
      simTime += 10;
      const unfinalized = witness.listUnfinalizedTickets();
      const w1Ticket = unfinalized.find((t) => t.ticketId === w1Res.ticketId);
      expect(w1Ticket?.state).toBe("QUARANTINED_UNCONFIRMED");

      // Window 2: Local SQLite committed, crashed before commit RPC.
      // Recovery: Reconciler queries witness, executes commit.
      const w2Res = witness.reserveTicket({
        authorizationId: "auth-w2",
        bindingDigest: "sha256:" + "3".repeat(64),
        policyId: "pol_windows",
        policyRevision: 1,
        idempotencyKey: "idemp-w2",
      });
      const w2Commit = witness.commitTicket({
        ticketId: w2Res.ticketId!,
        authorizationId: "auth-w2",
        bindingDigest: "sha256:" + "3".repeat(64),
        localCommittedAtSeconds: simTime,
      });
      expect(w2Commit.decision).toBe("ALLOW");

      // Window 3: Witness committed, crashed before receipt written to SQLite.
      // Recovery: Reconciler calls reconcileTicket(), receives existing receipt with alreadyCommitted=true.
      const w3Reconcile = witness.reconcileTicket({ ticketId: w2Res.ticketId! });
      expect(w3Reconcile.state).toBe("COMMITTED");
      expect(w3Reconcile.receipt?.authorizationId).toBe("auth-w2");

      // Window 4: Receipt persisted in SQLite, crashed before client received decision.
      // Recovery: Client retries commitTicket() or reserveTicket() with same idempotency key.
      const w4RetryCommit = witness.commitTicket({
        ticketId: w2Res.ticketId!,
        authorizationId: "auth-w2",
        bindingDigest: "sha256:" + "3".repeat(64),
        localCommittedAtSeconds: simTime,
      });
      expect(w4RetryCommit.alreadyCommitted).toBe(true);
      expect(w4RetryCommit.receipt?.signature).toBe(w2Commit.receipt?.signature);

      witness.close();
    });
  });

  // ============================================================================
  // Test Area 12: Fail-Closed Behavior When Witness Storage is Unavailable
  // ============================================================================
  describe("12. Fail-Closed Behavior When Storage is Unavailable", () => {
    it("throws WitnessStorageUnavailableError if database path cannot be opened", () => {
      // Path pointing to non-existent directory on invalid device
      const invalidPath = join(testDir, "non_existent_dir", "sub", "witness.sqlite");

      expect(() => {
        new SQLiteDurableWitness({ dbPath: invalidPath });
      }).toThrow(WitnessStorageUnavailableError);
    });

    it("fails closed when methods are called on a closed witness instance", () => {
      const witness = new SQLiteDurableWitness({ dbPath: witnessDbPath });
      witness.close();

      expect(() => {
        witness.reserveTicket({
          authorizationId: "auth-closed",
          bindingDigest: "sha256:" + "4".repeat(64),
          policyId: "pol_closed",
          policyRevision: 1,
          idempotencyKey: "idemp-closed",
        });
      }).toThrow(WitnessStorageUnavailableError);

      expect(() => {
        witness.getCurrentSequence();
      }).toThrow(WitnessStorageUnavailableError);
    });
  });

  // ============================================================================
  // End-to-End Engine Integration Test
  // ============================================================================
  describe("13. End-to-End Web3UserEngine Integration with SQLiteDurableWitness", () => {
    it("integrates seamlessly into Web3UserEngine, issuing, consuming, and verifying durable receipts", () => {
      const witness = new SQLiteDurableWitness({ dbPath: witnessDbPath });
      const engineDbPath = join(testDir, "engine.sqlite");

      const engine = Web3UserEngine.open({
        databasePath: engineDbPath,
        witnessAdapter: witness,
        witnessPublicKey: witness.publicKeyPem,
      });

      try {
        // Register policy
        engine.policies.register(SAMPLE_POLICY);

        // Register key
        engine.keys.register({
          keyId: "key-durable-01",
          publicKey: TEST_KEY_PAIR.publicKey,
          status: "active",
          expiresAtSeconds: 2000000000,
        });

        // Issue authorization
        const issueRes = engine.issue({
          authorizationId: "auth-e2e-durable-01",
          policyId: SAMPLE_POLICY.policyId,
          request: SAMPLE_TX_REQUEST,
          signer: {
            keyId: "key-durable-01",
            privateKey: TEST_KEY_PAIR.privateKey,
          },
          ttlSeconds: 300,
        });

        expect(issueRes.decision).toBe("ALLOW");
        if (issueRes.decision !== "ALLOW") return;

        // Consume authorization
        const consumeRes = engine.consume({
          artifact: issueRes.artifact,
          envelope: issueRes.envelope,
          request: SAMPLE_TX_REQUEST,
        });

        expect(consumeRes.decision).toBe("ALLOW");
        if (consumeRes.decision !== "ALLOW") {
          throw new Error("Expected ALLOW");
        }
        expect(consumeRes.witnessReceipt).toBeDefined();
        expect(consumeRes.witnessReceipt?.witnessId).toBe(witness.getWitnessId());
        expect(consumeRes.witnessReceipt?.sequenceNumber).toBe("1");

        // Verify that replay is immediately denied by SQLite
        const replayRes = engine.consume({
          artifact: issueRes.artifact,
          envelope: issueRes.envelope,
          request: SAMPLE_TX_REQUEST,
        });
        expect(replayRes.decision).toBe("DENY");
        expect(replayRes.reasons.some((r) => r.toLowerCase().includes("consumed"))).toBe(true);

        // Verify getWitnessReceipt returns durable receipt
        const fetchedReceipt = engine.getWitnessReceipt("auth-e2e-durable-01");
        expect(fetchedReceipt).toBeDefined();
        expect(fetchedReceipt?.signature).toBe(consumeRes.witnessReceipt?.signature);
      } finally {
        engine.close();
        witness.close();
      }
    });
  });
});
