import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mkdirSync, rmSync, copyFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import {
  Web3UserEngine,
  SQLiteDurableWitness,
  SQLiteAuthorizationStore,
  WitnessUnavailableError,
  EpochDivergenceError,
  SequenceRegressionError,
  EngineInRecoveryModeError,
  generateIssuerKeyPair,
  type TransactionRequest,
  type DemoPolicy,
  type MonotonicWitnessAdapter,
} from "../src/index.js";

const TEST_KEY_PAIR = generateIssuerKeyPair();

function createTestDirectory(): string {
  const dir = join(tmpdir(), `web3user-m13c-engine-test-${Date.now()}-${randomBytes(4).toString("hex")}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

const SAMPLE_TRANSFER_CALLDATA =
  "0xa9059cbb" +
  "000000000000000000000000" +
  "4444444444444444444444444444444444444444" +
  "0000000000000000000000000000000000000000000000000de0b6b3a7640000";

const SAMPLE_TX_REQUEST: TransactionRequest = {
  chainId: "1",
  sender: "0x3333333333333333333333333333333333333333",
  target: "0x1111111111111111111111111111111111111111",
  calldata: SAMPLE_TRANSFER_CALLDATA,
  value: "0",
};

const SAMPLE_POLICY: DemoPolicy = {
  version: 1,
  policyId: "pol_m13c_integration",
  allowedTarget: "0x1111111111111111111111111111111111111111",
  allowedRecipient: "0x4444444444444444444444444444444444444444",
  allowedSelector: "0xa9059cbb",
  maxAmount: "2000000000000000000",
  validFrom: 0,
  expiresAt: 2000000000,
  revoked: false,
  budget: {
    window: "HOURLY",
    maxCumulativeAmount: "10000000000000000000",
  },
};

describe("Milestone 13-C: Durable Witness Engine Integration", () => {
  let testDir: string;
  let engineDbPath: string;
  let witnessDbPath: string;

  beforeEach(() => {
    testDir = createTestDirectory();
    engineDbPath = join(testDir, "engine.sqlite");
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
  // Test 1: Normal startup with consistent witness state
  // ============================================================================
  it("1. Normal startup with consistent witness state: transitions to READY, issues and consumes with witness receipt", () => {
    const witness = new SQLiteDurableWitness({
      dbPath: witnessDbPath,
      witnessId: "wit-m13c-01",
      epochId: "epoch-m13c-01",
      keyPair: TEST_KEY_PAIR,
    });

    const engine = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
      closeWitnessOnShutdown: true,
    });

    expect(engine.getState()).toBe("READY");
    expect(engine.isReady()).toBe(true);
    expect(engine.isRecoveryOnly()).toBe(false);

    engine.policies.register(SAMPLE_POLICY);
    const key = engine.keys.generate();
    engine.keys.register({
      keyId: "issuer_key_01",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 0,
      expiresAtSeconds: 2000000000,
    });

    const issueRes = engine.issue({
      authorizationId: "auth-m13c-01",
      policyId: SAMPLE_POLICY.policyId,
      request: SAMPLE_TX_REQUEST,
      signer: { keyId: "issuer_key_01", privateKey: key.privateKey },
    });
    if (issueRes.decision !== "ALLOW") throw new Error("Expected ALLOW");

    const consumeRes = engine.consume({
      artifact: issueRes.artifact,
      envelope: issueRes.envelope,
      request: SAMPLE_TX_REQUEST,
    });

    expect(consumeRes.decision).toBe("ALLOW");
    if (consumeRes.decision !== "ALLOW") throw new Error("Expected ALLOW");
    expect(consumeRes.witnessReceipt).toBeDefined();
    expect(consumeRes.witnessReceipt?.epochId).toBe("epoch-m13c-01");
    expect(consumeRes.witnessReceipt?.sequenceNumber).toBe("1");

    engine.close();
  });

  // ============================================================================
  // Test 2: Startup rejection when witness is unavailable
  // ============================================================================
  it("2. Startup rejection when witness is unavailable: fails closed with WitnessUnavailableError", () => {
    // Sub-case A: requireDurableWitness is true, but no witnessAdapter provided
    expect(() => {
      Web3UserEngine.open({
        databasePath: engineDbPath,
        requireDurableWitness: true,
      });
    }).toThrow(WitnessUnavailableError);

    // Sub-case B: witnessAdapter throws on getSyncStatus
    const failingWitness: MonotonicWitnessAdapter = {
      name: "FailingWitness",
      isTestOnlyMock: true,
      publicKeyPem: TEST_KEY_PAIR.publicKeyPem,
      getSyncStatus: () => {
        throw new Error("RPC Network Timeout");
      },
      reserveTicket: () => ({ decision: "DENY" }),
      commitTicket: () => ({ decision: "DENY" }),
      releaseTicket: () => ({ success: false }),
      reconcileTicket: () => ({ ticketId: "t1", state: "DISPUTED" }),
    };

    expect(() => {
      Web3UserEngine.open({
        databasePath: engineDbPath,
        witnessAdapter: failingWitness,
      });
    }).toThrow(WitnessUnavailableError);
  });

  // ============================================================================
  // Test 3: Sequence regression rejection
  // ============================================================================
  it("3. Sequence regression rejection: throws SequenceRegressionError when witness sequence rewinds", () => {
    // Step 1: Run engine and consume authorization up to sequence 1
    const witness1 = new SQLiteDurableWitness({
      dbPath: witnessDbPath,
      witnessId: "wit-m13c-03",
      epochId: "epoch-m13c-03",
      keyPair: TEST_KEY_PAIR,
    });

    const engine1 = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness1,
      closeWitnessOnShutdown: true,
    });

    engine1.policies.register(SAMPLE_POLICY);
    const key = engine1.keys.generate();
    engine1.keys.register({
      keyId: "issuer_key_03",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 0,
      expiresAtSeconds: 2000000000,
    });

    const issueRes = engine1.issue({
      authorizationId: "auth-m13c-03",
      policyId: SAMPLE_POLICY.policyId,
      request: SAMPLE_TX_REQUEST,
      signer: { keyId: "issuer_key_03", privateKey: key.privateKey },
    });
    if (issueRes.decision !== "ALLOW") throw new Error("Expected ALLOW");

    const consumeRes = engine1.consume({
      artifact: issueRes.artifact,
      envelope: issueRes.envelope,
      request: SAMPLE_TX_REQUEST,
    });
    expect(consumeRes.decision).toBe("ALLOW");
    engine1.close();

    // Step 2: Simulate witness rewind/rollback by providing a mock witness that reports sequence 0
    const rewoundWitness: MonotonicWitnessAdapter = {
      name: "RewoundWitness",
      isTestOnlyMock: true,
      publicKeyPem: TEST_KEY_PAIR.publicKeyPem,
      getSyncStatus: () => ({
        healthy: true,
        epochId: "epoch-m13c-03",
        sequenceNumber: "0",
        divergenceDetected: false,
      }),
      reserveTicket: () => ({ decision: "DENY" }),
      commitTicket: () => ({ decision: "DENY" }),
      releaseTicket: () => ({ success: false }),
      reconcileTicket: () => ({ ticketId: "t1", state: "DISPUTED" }),
    };

    expect(() => {
      Web3UserEngine.open({
        databasePath: engineDbPath,
        witnessAdapter: rewoundWitness,
      });
    }).toThrow(SequenceRegressionError);
  });

  // ============================================================================
  // Test 4: Epoch mismatch rejection and allowed transition with rule
  // ============================================================================
  it("4. Epoch mismatch rejection and allowed transition: throws EpochDivergenceError or accepts with allowedEpochTransitions rule", () => {
    // Step 1: Establish local receipt in epoch-1
    const witness1 = new SQLiteDurableWitness({
      dbPath: witnessDbPath,
      witnessId: "wit-m13c-04",
      epochId: "epoch-1",
      keyPair: TEST_KEY_PAIR,
    });

    const engine1 = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness1,
      closeWitnessOnShutdown: true,
    });

    engine1.policies.register(SAMPLE_POLICY);
    const key = engine1.keys.generate();
    engine1.keys.register({
      keyId: "issuer_key_04",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 0,
      expiresAtSeconds: 2000000000,
    });

    const issueRes = engine1.issue({
      authorizationId: "auth-m13c-04",
      policyId: SAMPLE_POLICY.policyId,
      request: SAMPLE_TX_REQUEST,
      signer: { keyId: "issuer_key_04", privateKey: key.privateKey },
    });
    if (issueRes.decision !== "ALLOW") throw new Error("Expected ALLOW");

    engine1.consume({
      artifact: issueRes.artifact,
      envelope: issueRes.envelope,
      request: SAMPLE_TX_REQUEST,
    });
    engine1.close();

    // Step 2: Open with witness in epoch-2 without transition rule -> Throws EpochDivergenceError
    const witness2Path = join(testDir, "witness2.sqlite");
    const witness2 = new SQLiteDurableWitness({
      dbPath: witness2Path,
      witnessId: "wit-m13c-04",
      epochId: "epoch-2",
      keyPair: TEST_KEY_PAIR,
    });

    expect(() => {
      Web3UserEngine.open({
        databasePath: engineDbPath,
        witnessAdapter: witness2,
      });
    }).toThrow(EpochDivergenceError);

    // Step 3: Open with explicit allowedEpochTransitions -> Succeeds
    const engine2 = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness2,
      allowedEpochTransitions: [
        { fromEpochId: "epoch-1", toEpochId: "epoch-2", reason: "Scheduled key and epoch rollover" },
      ],
      closeWitnessOnShutdown: true,
    });

    expect(engine2.getState()).toBe("READY");
    engine2.close();
  });

  // ============================================================================
  // Test 5: Positive sequence divergence entering RECOVERY_RECONCILE_ONLY
  // ============================================================================
  it("5. Positive sequence divergence entering RECOVERY_RECONCILE_ONLY", () => {
    // Step 1: Local DB has committed receipt at seq 1
    const witness = new SQLiteDurableWitness({
      dbPath: witnessDbPath,
      witnessId: "wit-m13c-05",
      epochId: "epoch-m13c-05",
      keyPair: TEST_KEY_PAIR,
    });

    const engine1 = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
    });

    engine1.policies.register(SAMPLE_POLICY);
    const key = engine1.keys.generate();
    engine1.keys.register({
      keyId: "issuer_key_05",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 0,
      expiresAtSeconds: 2000000000,
    });

    const issueRes = engine1.issue({
      authorizationId: "auth-m13c-05",
      policyId: SAMPLE_POLICY.policyId,
      request: SAMPLE_TX_REQUEST,
      signer: { keyId: "issuer_key_05", privateKey: key.privateKey },
    });
    if (issueRes.decision !== "ALLOW") throw new Error("Expected ALLOW");

    engine1.consume({
      artifact: issueRes.artifact,
      envelope: issueRes.envelope,
      request: SAMPLE_TX_REQUEST,
    });
    engine1.close();

    // Step 2: Advance witness independently to sequence 2
    const res = witness.reserveTicket({
      authorizationId: "auth-other-client",
      bindingDigest: "sha256:" + "b".repeat(64),
      policyId: SAMPLE_POLICY.policyId,
      policyRevision: 1,
      idempotencyKey: "idemp-other",
    });
    witness.commitTicket({
      ticketId: res.ticketId!,
      authorizationId: "auth-other-client",
      bindingDigest: "sha256:" + "b".repeat(64),
      localCommittedAtSeconds: 1000,
    });

    // Step 3: Open engine with local DB (max seq = 1) and advanced witness (seq = 2)
    const engine2 = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
      closeWitnessOnShutdown: true,
    });

    expect(engine2.getState()).toBe("RECOVERY_RECONCILE_ONLY");
    expect(engine2.isReady()).toBe(false);
    expect(engine2.isRecoveryOnly()).toBe(true);

    engine2.close();
  });

  // ============================================================================
  // Test 6: Historical application database restoration entering RECOVERY_RECONCILE_ONLY
  // ============================================================================
  it("6. Historical application database restoration entering RECOVERY_RECONCILE_ONLY", () => {
    const witness = new SQLiteDurableWitness({
      dbPath: witnessDbPath,
      witnessId: "wit-m13c-06",
      epochId: "epoch-m13c-06",
      keyPair: TEST_KEY_PAIR,
    });

    const engine = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
    });

    engine.policies.register(SAMPLE_POLICY);
    const key = engine.keys.generate();
    engine.keys.register({
      keyId: "issuer_key_06",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 0,
      expiresAtSeconds: 2000000000,
    });

    const issueRes1 = engine.issue({
      authorizationId: "auth-m13c-06-a",
      policyId: SAMPLE_POLICY.policyId,
      request: SAMPLE_TX_REQUEST,
      signer: { keyId: "issuer_key_06", privateKey: key.privateKey },
    });
    if (issueRes1.decision !== "ALLOW") throw new Error("Expected ALLOW");

    engine.consume({
      artifact: issueRes1.artifact,
      envelope: issueRes1.envelope,
      request: SAMPLE_TX_REQUEST,
    });
    engine.close();

    // Snapshot SQLite database at seq = 1
    const backupDbPath = join(testDir, "engine_backup.sqlite");
    copyFileSync(engineDbPath, backupDbPath);

    // Consume second authorization on current DB (advancing witness to seq = 2)
    const engineReopened = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
    });
    const issueRes2 = engineReopened.issue({
      authorizationId: "auth-m13c-06-b",
      policyId: SAMPLE_POLICY.policyId,
      request: SAMPLE_TX_REQUEST,
      signer: { keyId: "issuer_key_06", privateKey: key.privateKey },
    });
    if (issueRes2.decision !== "ALLOW") throw new Error("Expected ALLOW");

    engineReopened.consume({
      artifact: issueRes2.artifact,
      envelope: issueRes2.envelope,
      request: SAMPLE_TX_REQUEST,
    });
    engineReopened.close();

    // Restore backup DB (which only has seq = 1), while witness is at seq = 2
    copyFileSync(backupDbPath, engineDbPath);

    const restoredEngine = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
      closeWitnessOnShutdown: true,
    });

    expect(restoredEngine.getState()).toBe("RECOVERY_RECONCILE_ONLY");
    expect(restoredEngine.isRecoveryOnly()).toBe(true);

    restoredEngine.close();
  });

  // ============================================================================
  // Test 7: Missing local receipt with authoritative witness commitment
  // ============================================================================
  it("7. Missing local receipt with authoritative witness commitment: reconciles and transitions to READY", async () => {
    const witness = new SQLiteDurableWitness({
      dbPath: witnessDbPath,
      witnessId: "wit-m13c-07",
      epochId: "epoch-m13c-07",
      keyPair: TEST_KEY_PAIR,
    });

    // Initialize engine database first
    const setupEngine = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
    });
    setupEngine.policies.register(SAMPLE_POLICY);
    const key = setupEngine.keys.generate();
    setupEngine.keys.register({
      keyId: "issuer_key_07",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 0,
      expiresAtSeconds: 2000000000,
    });
    setupEngine.close();

    // Reserve ticket and commit on witness
    const bindingDigest = "sha256:" + "c".repeat(64);
    const res = witness.reserveTicket({
      authorizationId: "auth-m13c-07",
      bindingDigest,
      policyId: SAMPLE_POLICY.policyId,
      policyRevision: 1,
      idempotencyKey: "idemp-07",
    });

    witness.commitTicket({
      ticketId: res.ticketId!,
      authorizationId: "auth-m13c-07",
      bindingDigest,
      localCommittedAtSeconds: 1000,
    });

    // Insert into SQLite as PENDING_COMMIT (crash simulation before local receipt persistence)
    const rawDb = new DatabaseSync(engineDbPath);
    rawDb.prepare(`
      INSERT INTO consumed_authorization_ids (
        authorization_id, state, witness_status, witness_ticket_id, binding_digest, key_id, consumed_at
      ) VALUES (?, 'consumed', 'PENDING_COMMIT', ?, ?, 'issuer_key_07', '2026-10-30T00:00:00.000Z');
    `).run("auth-m13c-07", res.ticketId!, bindingDigest);
    rawDb.close();

    // Engine startup detects unreconciled record and enters RECOVERY_RECONCILE_ONLY
    const engine = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
      closeWitnessOnShutdown: true,
    });

    expect(engine.getState()).toBe("RECOVERY_RECONCILE_ONLY");
    expect(engine.isRecoveryOnly()).toBe(true);

    // Reconcile via reconcileAll()
    const reconRes = await engine.reconcileAll();
    expect(reconRes.summary.reconciledCount).toBe(1);
    expect(reconRes.summary.totalDiscovered).toBe(1);

    // Engine is automatically unlocked to READY
    expect(engine.getState()).toBe("READY");
    expect(engine.isReady()).toBe(true);

    engine.close();
  });

  // ============================================================================
  // Test 8: Conflicting or invalid receipt keeping engine in recovery mode
  // ============================================================================
  it("8. Conflicting or invalid receipt keeping engine in recovery mode", async () => {
    // Mock witness that returns a receipt with corrupted signature
    const invalidReceiptWitness: MonotonicWitnessAdapter = {
      name: "CorruptReceiptWitness",
      isTestOnlyMock: true,
      publicKeyPem: TEST_KEY_PAIR.publicKeyPem,
      getSyncStatus: () => ({
        healthy: true,
        epochId: "epoch-m13c-08",
        sequenceNumber: "1",
        divergenceDetected: false,
      }),
      reserveTicket: () => ({ decision: "DENY" }),
      commitTicket: () => ({ decision: "DENY" }),
      releaseTicket: () => ({ success: false }),
      reconcileTicket: () => ({
        ticketId: "wit-08:epoch-m13c-08:0",
        state: "COMMITTED" as const,
        receipt: {
          version: 1,
          witnessId: "wit-08",
          epochId: "epoch-m13c-08",
          sequenceNumber: "1",
          ticketId: "wit-08:epoch-m13c-08:0",
          authorizationId: "auth-m13c-08",
          bindingDigest: "sha256:" + "d".repeat(64),
          policyId: SAMPLE_POLICY.policyId,
          policyRevision: 1,
          debitedAmount: "0",
          budgetWindows: [],
          committedAtSeconds: 1000,
          signature: "00".repeat(64), // Invalid signature
        },
      }),
    };

    // Initialize database schema properly via engine
    const initEngine = Web3UserEngine.open({
      databasePath: engineDbPath,
    });
    initEngine.policies.register(SAMPLE_POLICY);
    initEngine.close();

    const rawDb = new DatabaseSync(engineDbPath);
    rawDb.prepare(`
      INSERT INTO consumed_authorization_ids (
        authorization_id, state, witness_status, witness_ticket_id, binding_digest, key_id, consumed_at
      ) VALUES ('auth-m13c-08', 'consumed', 'PENDING_COMMIT', 'wit-08:epoch-m13c-08:0', 'sha256:${"d".repeat(64)}', 'key_08', '2026-10-30T00:00:00.000Z');
    `).run();
    rawDb.close();

    const engine = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: invalidReceiptWitness,
      witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
    });

    expect(engine.getState()).toBe("RECOVERY_RECONCILE_ONLY");

    const reconRes = await engine.reconcileAll();
    expect(reconRes.summary.disputedCount).toBe(1);

    // Engine remains locked in recovery mode because invalid receipt marked record DISPUTED
    expect(engine.getState()).toBe("RECOVERY_RECONCILE_ONLY");
    expect(engine.isReady()).toBe(false);

    engine.close();
  });

  // ============================================================================
  // Test 9: Pending commit reconciliation via reconcileAll() unlocking to READY
  // ============================================================================
  it("9. Pending commit reconciliation via reconcileAll() unlocking to READY", async () => {
    const witness = new SQLiteDurableWitness({
      dbPath: witnessDbPath,
      witnessId: "wit-m13c-09",
      epochId: "epoch-m13c-09",
      keyPair: TEST_KEY_PAIR,
    });

    const engine = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
    });

    engine.policies.register(SAMPLE_POLICY);
    const key = engine.keys.generate();
    engine.keys.register({
      keyId: "issuer_key_09",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 0,
      expiresAtSeconds: 2000000000,
    });

    const issueRes = engine.issue({
      authorizationId: "auth-m13c-09",
      policyId: SAMPLE_POLICY.policyId,
      request: SAMPLE_TX_REQUEST,
      signer: { keyId: "issuer_key_09", privateKey: key.privateKey },
    });
    if (issueRes.decision !== "ALLOW") throw new Error("Expected ALLOW");

    const consumeRes = engine.consume({
      artifact: issueRes.artifact,
      envelope: issueRes.envelope,
      request: SAMPLE_TX_REQUEST,
    });
    expect(consumeRes.decision).toBe("ALLOW");

    // Force the consumed record into PENDING_COMMIT in local store (simulating crash before receipt persistence)
    const store = engine.getStore();
    (store as any).db.prepare(`
      UPDATE consumed_authorization_ids SET witness_status = 'PENDING_COMMIT', witness_receipt_json = NULL WHERE authorization_id = 'auth-m13c-09';
    `).run();

    engine.close();

    // Reopen: engine must detect PENDING_COMMIT and start in RECOVERY_RECONCILE_ONLY
    const reopened = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
      closeWitnessOnShutdown: true,
    });

    expect(reopened.getState()).toBe("RECOVERY_RECONCILE_ONLY");

    const reconResult = await reopened.reconcileAll();
    expect(reconResult.summary.reconciledCount).toBe(1);

    // Must transition to READY
    expect(reopened.getState()).toBe("READY");
    expect(reopened.isReady()).toBe(true);

    reopened.close();
  });

  // ============================================================================
  // Test 10: Disputed and quarantined records preventing unlock
  // ============================================================================
  it("10. Disputed and quarantined records preventing unlock", async () => {
    const witness = new SQLiteDurableWitness({
      dbPath: witnessDbPath,
      witnessId: "wit-m13c-10",
      epochId: "epoch-m13c-10",
      keyPair: TEST_KEY_PAIR,
    });

    const engine = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
    });

    engine.policies.register(SAMPLE_POLICY);
    const key = engine.keys.generate();
    engine.keys.register({
      keyId: "issuer_key_10",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 0,
      expiresAtSeconds: 2000000000,
    });

    const issueRes = engine.issue({
      authorizationId: "auth-m13c-10",
      policyId: SAMPLE_POLICY.policyId,
      request: SAMPLE_TX_REQUEST,
      signer: { keyId: "issuer_key_10", privateKey: key.privateKey },
    });
    if (issueRes.decision !== "ALLOW") throw new Error("Expected ALLOW");

    const consumeRes = engine.consume({
      artifact: issueRes.artifact,
      envelope: issueRes.envelope,
      request: SAMPLE_TX_REQUEST,
    });
    expect(consumeRes.decision).toBe("ALLOW");

    // Mark the record DISPUTED in local store
    const store = engine.getStore();
    (store as any).db.prepare(`
      UPDATE consumed_authorization_ids SET witness_status = 'DISPUTED' WHERE authorization_id = 'auth-m13c-10';
    `).run();

    engine.close();

    // Reopen: Engine starts in RECOVERY_RECONCILE_ONLY
    const reopened = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
      closeWitnessOnShutdown: true,
    });

    expect(reopened.getState()).toBe("RECOVERY_RECONCILE_ONLY");

    const unlocked = await reopened.verifyAndUnlockRecovery();
    expect(unlocked).toBe(false);
    expect(reopened.getState()).toBe("RECOVERY_RECONCILE_ONLY");

    reopened.close();
  });

  // ============================================================================
  // Test 11: Authorization issue() and consume() blocked in recovery mode
  // ============================================================================
  it("11. Authorization issue() and consume() blocked in recovery mode (EngineInRecoveryModeError)", () => {
    const witness = new SQLiteDurableWitness({
      dbPath: witnessDbPath,
      witnessId: "wit-m13c-11",
      epochId: "epoch-m13c-11",
      keyPair: TEST_KEY_PAIR,
    });

    // Step 1: Normal commit up to seq = 1
    const engine1 = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
    });

    engine1.policies.register(SAMPLE_POLICY);
    const key = engine1.keys.generate();
    engine1.keys.register({
      keyId: "issuer_key_11",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 0,
      expiresAtSeconds: 2000000000,
    });

    const issueRes = engine1.issue({
      authorizationId: "auth-m13c-11-base",
      policyId: SAMPLE_POLICY.policyId,
      request: SAMPLE_TX_REQUEST,
      signer: { keyId: "issuer_key_11", privateKey: key.privateKey },
    });
    if (issueRes.decision !== "ALLOW") throw new Error("Expected ALLOW");

    engine1.consume({
      artifact: issueRes.artifact,
      envelope: issueRes.envelope,
      request: SAMPLE_TX_REQUEST,
    });
    engine1.close();

    // Step 2: Advance witness sequence to 2 independently
    const res = witness.reserveTicket({
      authorizationId: "auth-m13c-11-independent",
      bindingDigest: "sha256:" + "e".repeat(64),
      policyId: SAMPLE_POLICY.policyId,
      policyRevision: 1,
      idempotencyKey: "idemp-m13c-11",
    });
    witness.commitTicket({
      ticketId: res.ticketId!,
      authorizationId: "auth-m13c-11-independent",
      bindingDigest: "sha256:" + "e".repeat(64),
      localCommittedAtSeconds: 1000,
    });

    // Step 3: Open engine with DB at seq 1 and witness at seq 2 -> RECOVERY_RECONCILE_ONLY
    const engine2 = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
      closeWitnessOnShutdown: true,
    });

    expect(engine2.getState()).toBe("RECOVERY_RECONCILE_ONLY");

    // issue() MUST throw EngineInRecoveryModeError
    expect(() => {
      engine2.issue({
        authorizationId: "auth-blocked-01",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: { keyId: "issuer_key_11", privateKey: key.privateKey },
      });
    }).toThrow(EngineInRecoveryModeError);

    // consume() MUST throw EngineInRecoveryModeError
    expect(() => {
      engine2.consume({
        artifact: {} as any,
        request: SAMPLE_TX_REQUEST,
      });
    }).toThrow(EngineInRecoveryModeError);

    engine2.close();
  });

  // ============================================================================
  // Test 12: Authorization blocked after incomplete recovery
  // ============================================================================
  it("12. Authorization blocked after incomplete recovery", async () => {
    const witness = new SQLiteDurableWitness({
      dbPath: witnessDbPath,
      witnessId: "wit-m13c-12",
      epochId: "epoch-m13c-12",
      keyPair: TEST_KEY_PAIR,
    });

    const initEngine = Web3UserEngine.open({ databasePath: engineDbPath });
    initEngine.policies.register(SAMPLE_POLICY);
    initEngine.close();

    const rawDb = new DatabaseSync(engineDbPath);
    rawDb.prepare(`
      INSERT INTO consumed_authorization_ids (
        authorization_id, state, witness_status, witness_ticket_id, binding_digest, key_id, consumed_at
      ) VALUES 
        ('auth-recon-1', 'consumed', 'DISPUTED', 'ticket-dispute-1', 'sha256:${"1".repeat(64)}', 'key_12', '2026-10-30T00:00:00.000Z'),
        ('auth-recon-2', 'consumed', 'DISPUTED', 'ticket-dispute-2', 'sha256:${"2".repeat(64)}', 'key_12', '2026-10-30T00:00:00.000Z');
    `).run();
    rawDb.close();

    const engine = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
      closeWitnessOnShutdown: true,
    });

    expect(engine.getState()).toBe("RECOVERY_RECONCILE_ONLY");

    // Batch reconcile with limit 1
    await engine.reconcileAll({ limit: 1 });

    // Since unresolved records still remain, engine remains in recovery mode
    expect(engine.getState()).toBe("RECOVERY_RECONCILE_ONLY");

    const key = engine.keys.generate();
    engine.keys.register({
      keyId: "issuer_key_12",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 0,
      expiresAtSeconds: 2000000000,
    });

    expect(() => {
      engine.issue({
        authorizationId: "auth-blocked-12",
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: { keyId: "issuer_key_12", privateKey: key.privateKey },
      });
    }).toThrow(EngineInRecoveryModeError);

    engine.close();
  });

  // ============================================================================
  // Test 13: Authorization enabled only after verified recovery
  // ============================================================================
  it("13. Authorization enabled only after verified recovery", async () => {
    const witness = new SQLiteDurableWitness({
      dbPath: witnessDbPath,
      witnessId: "wit-m13c-13",
      epochId: "epoch-m13c-13",
      keyPair: TEST_KEY_PAIR,
    });

    // Initialize database schema first
    const initEngine = Web3UserEngine.open({ databasePath: engineDbPath });
    initEngine.policies.register(SAMPLE_POLICY);
    const key = initEngine.keys.generate();
    initEngine.keys.register({
      keyId: "issuer_key_13",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 0,
      expiresAtSeconds: 2000000000,
    });
    initEngine.close();

    const bindingDigest = "sha256:" + "f".repeat(64);
    const res = witness.reserveTicket({
      authorizationId: "auth-m13c-13-pending",
      bindingDigest,
      policyId: SAMPLE_POLICY.policyId,
      policyRevision: 1,
      idempotencyKey: "idemp-13",
    });
    witness.commitTicket({
      ticketId: res.ticketId!,
      authorizationId: "auth-m13c-13-pending",
      bindingDigest,
      localCommittedAtSeconds: 1000,
    });

    const rawDb = new DatabaseSync(engineDbPath);
    rawDb.prepare(`
      INSERT INTO consumed_authorization_ids (
        authorization_id, state, witness_status, witness_ticket_id, binding_digest, key_id, consumed_at
      ) VALUES ('auth-m13c-13-pending', 'consumed', 'PENDING_COMMIT', '${res.ticketId!}', '${bindingDigest}', 'issuer_key_13', '2026-10-30T00:00:00.000Z');
    `).run();
    rawDb.close();

    const engine = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
      closeWitnessOnShutdown: true,
    });

    expect(engine.isReady()).toBe(false);

    // Reconcile pending commit
    const reconcileRes = await engine.reconcileAll();
    expect(reconcileRes.summary.reconciledCount).toBe(1);

    // Verify recovery gate unlocked
    expect(engine.isReady()).toBe(true);
    expect(engine.getState()).toBe("READY");

    // Normal authorization operations now succeed
    const issueRes = engine.issue({
      authorizationId: "auth-m13c-13-success",
      policyId: SAMPLE_POLICY.policyId,
      request: SAMPLE_TX_REQUEST,
      signer: { keyId: "issuer_key_13", privateKey: key.privateKey },
    });
    if (issueRes.decision !== "ALLOW") throw new Error("Expected ALLOW");

    const consumeRes = engine.consume({
      artifact: issueRes.artifact,
      envelope: issueRes.envelope,
      request: SAMPLE_TX_REQUEST,
    });
    expect(consumeRes.decision).toBe("ALLOW");

    engine.close();
  });

  // ============================================================================
  // Test 14: Concurrent startup and authorization attempts
  // ============================================================================
  it("14. Concurrent startup and authorization attempts", async () => {
    const witness = new SQLiteDurableWitness({
      dbPath: witnessDbPath,
      witnessId: "wit-m13c-14",
      epochId: "epoch-m13c-14",
      keyPair: TEST_KEY_PAIR,
    });

    const engine = await Web3UserEngine.openAsync({
      databasePath: engineDbPath,
      witnessAdapter: witness,
      closeWitnessOnShutdown: true,
    });

    engine.policies.register(SAMPLE_POLICY);
    const key = engine.keys.generate();
    engine.keys.register({
      keyId: "issuer_key_14",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 0,
      expiresAtSeconds: 2000000000,
    });

    // Concurrent issuance
    const issuePromises = Array.from({ length: 10 }, (_, i) =>
      Promise.resolve().then(() => {
        const res = engine.issue({
          authorizationId: `auth-m13c-14-${i}`,
          policyId: SAMPLE_POLICY.policyId,
          request: SAMPLE_TX_REQUEST,
          signer: { keyId: "issuer_key_14", privateKey: key.privateKey },
        });
        if (res.decision !== "ALLOW") throw new Error("Expected ALLOW");
        return res;
      }),
    );

    const issueResults = await Promise.all(issuePromises);
    expect(issueResults.length).toBe(10);

    // Concurrent consumption
    const consumePromises = issueResults.map((res) =>
      engine.consumeAsync({
        artifact: res.artifact,
        envelope: res.envelope,
        request: SAMPLE_TX_REQUEST,
      }),
    );

    const results = await Promise.all(consumePromises);
    expect(results.every((r) => r.decision === "ALLOW")).toBe(true);

    engine.close();
  });

  // ============================================================================
  // Test 15: Repeated startup and recovery idempotency
  // ============================================================================
  it("15. Repeated startup and recovery idempotency across restarts", async () => {
    const witness = new SQLiteDurableWitness({
      dbPath: witnessDbPath,
      witnessId: "wit-m13c-15",
      epochId: "epoch-m13c-15",
      keyPair: TEST_KEY_PAIR,
    });

    // Run 3 startup and shutdown cycles on the same database
    for (let cycle = 1; cycle <= 3; cycle++) {
      const engine = Web3UserEngine.open({
        databasePath: engineDbPath,
        witnessAdapter: witness,
      });

      expect(engine.getState()).toBe("READY");

      if (cycle === 1) {
        engine.policies.register(SAMPLE_POLICY);
        const key = engine.keys.generate();
        engine.keys.register({
          keyId: "issuer_key_15",
          publicKey: key.publicKey,
          status: "active",
          validFromSeconds: 0,
          expiresAtSeconds: 2000000000,
        });

        const issueRes = engine.issue({
          authorizationId: "auth-m13c-15",
          policyId: SAMPLE_POLICY.policyId,
          request: SAMPLE_TX_REQUEST,
          signer: { keyId: "issuer_key_15", privateKey: key.privateKey },
        });
        if (issueRes.decision !== "ALLOW") throw new Error("Expected ALLOW");

        const consumeRes = engine.consume({
          artifact: issueRes.artifact,
          envelope: issueRes.envelope,
          request: SAMPLE_TX_REQUEST,
        });
        expect(consumeRes.decision).toBe("ALLOW");
      }

      // Reconcile should find 0 unreconciled records
      const recon = await engine.reconcileAll();
      expect(recon.summary.totalDiscovered).toBe(0);
      expect(engine.getState()).toBe("READY");

      engine.close();
    }

    witness.close();
  });

  // ============================================================================
  // Test 16: Engine shutdown and witness resource lifecycle
  // ============================================================================
  it("16. Engine shutdown and witness resource lifecycle (closeWitnessOnShutdown)", () => {
    const witness = new SQLiteDurableWitness({
      dbPath: witnessDbPath,
      witnessId: "wit-m13c-16",
      epochId: "epoch-m13c-16",
      keyPair: TEST_KEY_PAIR,
    });

    expect(witness.isOpen()).toBe(true);

    const engine = Web3UserEngine.open({
      databasePath: engineDbPath,
      witnessAdapter: witness,
      closeWitnessOnShutdown: true,
    });

    expect(engine.isOpen()).toBe(true);
    expect(witness.isOpen()).toBe(true);

    engine.close();

    expect(engine.isOpen()).toBe(false);
    expect(engine.getState()).toBe("CLOSED");
    expect(witness.isOpen()).toBe(false);
  });

  // ============================================================================
  // SEC-M13C-01: Epoch Rollover Metadata & Multi-Epoch Scoping
  // ============================================================================
  describe("SEC-M13C-01: Critical — Epoch rollover metadata & multi-epoch scoping", () => {
    it("handles previous epoch seq 100, new epoch seq 1 without shadowing", () => {
      const store = new SQLiteAuthorizationStore(engineDbPath, {
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
        allowedEpochTransitions: [{ fromEpochId: "epoch-1", toEpochId: "epoch-2" }],
      });

      // Insert committed receipt in epoch-1 at sequence 100 and epoch-2 at sequence 1
      const rawDb = new DatabaseSync(engineDbPath);
      const receiptEpoch1 = {
        version: 1,
        witnessId: "wit-test",
        epochId: "epoch-1",
        sequenceNumber: "100",
        ticketId: "t-1",
        authorizationId: "auth-ep1",
        bindingDigest: "sha256:" + "1".repeat(64),
        policyId: "pol_test",
        policyRevision: 1,
        debitedAmount: "100",
        budgetWindows: [],
        committedAtSeconds: 1000,
        signature: "a".repeat(128),
      };
      const receiptEpoch2 = {
        version: 1,
        witnessId: "wit-test",
        epochId: "epoch-2",
        sequenceNumber: "1",
        ticketId: "t-2",
        authorizationId: "auth-ep2",
        bindingDigest: "sha256:" + "2".repeat(64),
        policyId: "pol_test",
        policyRevision: 1,
        debitedAmount: "100",
        budgetWindows: [],
        committedAtSeconds: 1001,
        signature: "b".repeat(128),
      };

      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_receipt_json, witness_status
        ) VALUES 
          ('auth-ep1', ?, 'consumed', '2026-10-30 00:00:00', 't-1', ?, 'COMMITTED'),
          ('auth-ep2', ?, 'consumed', '2026-10-30 00:01:00', 't-2', ?, 'COMMITTED');
      `).run(
        receiptEpoch1.bindingDigest, JSON.stringify(receiptEpoch1),
        receiptEpoch2.bindingDigest, JSON.stringify(receiptEpoch2),
      );
      rawDb.close();

      const meta = store.getLatestWitnessReceiptMetadata();
      expect(meta.latestEpochId).toBe("epoch-2");
      expect(meta.maxSequenceNumber).toBe("1"); // Not shadowed by 100 in epoch-1!
      expect(meta.witnessId).toBe("wit-test");

      store.close();
    });

    it("handles multiple chained epoch transitions (epoch-1 -> epoch-2 -> epoch-3)", () => {
      const store = new SQLiteAuthorizationStore(engineDbPath, {
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
        allowedEpochTransitions: [
          { fromEpochId: "epoch-1", toEpochId: "epoch-2" },
          { fromEpochId: "epoch-2", toEpochId: "epoch-3" },
        ],
      });

      const rawDb = new DatabaseSync(engineDbPath);
      const makeReceipt = (epochId: string, seq: string, authId: string) => ({
        version: 1,
        witnessId: "wit-chain",
        epochId,
        sequenceNumber: seq,
        ticketId: `t-${authId}`,
        authorizationId: authId,
        bindingDigest: "sha256:" + "3".repeat(64),
        policyId: "pol_test",
        policyRevision: 1,
        debitedAmount: "100",
        budgetWindows: [],
        committedAtSeconds: 1000,
        signature: "c".repeat(128),
      });

      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_receipt_json, witness_status
        ) VALUES 
          ('auth-1', 'd1', 'consumed', '2026-10-30', 't-1', ?, 'COMMITTED'),
          ('auth-2', 'd2', 'consumed', '2026-10-30', 't-2', ?, 'COMMITTED'),
          ('auth-3', 'd3', 'consumed', '2026-10-30', 't-3', ?, 'COMMITTED');
      `).run(
        JSON.stringify(makeReceipt("epoch-1", "50", "auth-1")),
        JSON.stringify(makeReceipt("epoch-2", "20", "auth-2")),
        JSON.stringify(makeReceipt("epoch-3", "5", "auth-3")),
      );
      rawDb.close();

      const meta = store.getLatestWitnessReceiptMetadata();
      expect(meta.latestEpochId).toBe("epoch-3");
      expect(meta.maxSequenceNumber).toBe("5");

      store.close();
    });

    it("fails closed on restart after unauthorized epoch transition", () => {
      const store = new SQLiteAuthorizationStore(engineDbPath, {
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
        allowedEpochTransitions: [], // No transition rules!
      });

      const rawDb = new DatabaseSync(engineDbPath);
      const makeReceipt = (epochId: string, seq: string, authId: string) => ({
        version: 1,
        witnessId: "wit-unauth",
        epochId,
        sequenceNumber: seq,
        ticketId: `t-${authId}`,
        authorizationId: authId,
        bindingDigest: "sha256:" + "4".repeat(64),
        policyId: "pol_test",
        policyRevision: 1,
        debitedAmount: "100",
        budgetWindows: [],
        committedAtSeconds: 1000,
        signature: "d".repeat(128),
      });

      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_receipt_json, witness_status
        ) VALUES 
          ('auth-1', 'd1', 'consumed', '2026-10-30', 't-1', ?, 'COMMITTED'),
          ('auth-2', 'd2', 'consumed', '2026-10-30', 't-2', ?, 'COMMITTED');
      `).run(
        JSON.stringify(makeReceipt("epoch-1", "10", "auth-1")),
        JSON.stringify(makeReceipt("epoch-unauth", "1", "auth-2")),
      );
      rawDb.close();

      expect(() => {
        store.getLatestWitnessReceiptMetadata();
      }).toThrow(/multiple epochs present/);

      store.close();
    });

    it("fails closed on invalid, cyclical or branching epoch transition metadata", () => {
      const store = new SQLiteAuthorizationStore(engineDbPath, {
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
        allowedEpochTransitions: [
          { fromEpochId: "epoch-A", toEpochId: "epoch-B" },
          { fromEpochId: "epoch-B", toEpochId: "epoch-A" }, // Cycle!
        ],
      });

      const rawDb = new DatabaseSync(engineDbPath);
      const makeReceipt = (epochId: string, seq: string, authId: string) => ({
        version: 1,
        witnessId: "wit-cycle",
        epochId,
        sequenceNumber: seq,
        ticketId: `t-${authId}`,
        authorizationId: authId,
        bindingDigest: "sha256:" + "5".repeat(64),
        policyId: "pol_test",
        policyRevision: 1,
        debitedAmount: "100",
        budgetWindows: [],
        committedAtSeconds: 1000,
        signature: "e".repeat(128),
      });

      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_receipt_json, witness_status
        ) VALUES 
          ('auth-1', 'd1', 'consumed', '2026-10-30', 't-1', ?, 'COMMITTED'),
          ('auth-2', 'd2', 'consumed', '2026-10-30', 't-2', ?, 'COMMITTED');
      `).run(
        JSON.stringify(makeReceipt("epoch-A", "10", "auth-1")),
        JSON.stringify(makeReceipt("epoch-B", "5", "auth-2")),
      );
      rawDb.close();

      expect(() => {
        store.getLatestWitnessReceiptMetadata();
      }).toThrow(/Cycle detected/);

      store.close();
    });
  });

  // ============================================================================
  // SEC-M13C-02: Empty Local Database with Advanced Witness
  // ============================================================================
  describe("SEC-M13C-02: High — Empty local database with advanced witness", () => {
    it("enters RECOVERY_RECONCILE_ONLY when local DB is empty and witness sequence > 0", () => {
      const witness = new SQLiteDurableWitness({
        dbPath: witnessDbPath,
        witnessId: "wit-empty-adv",
        epochId: "epoch-empty-adv",
        keyPair: TEST_KEY_PAIR,
      });

      // Advance witness to seq 1 on external authorization
      const res = witness.reserveTicket({
        authorizationId: "auth-ext-01",
        bindingDigest: "sha256:" + "a".repeat(64),
        policyId: SAMPLE_POLICY.policyId,
        policyRevision: 1,
        idempotencyKey: "idemp-ext-01",
      });
      witness.commitTicket({
        ticketId: res.ticketId!,
        authorizationId: "auth-ext-01",
        bindingDigest: "sha256:" + "a".repeat(64),
        localCommittedAtSeconds: 1000,
      });

      // Open engine on fresh/empty local database
      const engine = Web3UserEngine.open({
        databasePath: engineDbPath,
        witnessAdapter: witness,
      });

      expect(engine.getState()).toBe("RECOVERY_RECONCILE_ONLY");
      expect(engine.isReady()).toBe(false);
      expect(engine.isRecoveryOnly()).toBe(true);

      // Normal authorization operations must be rejected
      engine.policies.register(SAMPLE_POLICY);
      const key = engine.keys.generate();
      engine.keys.register({
        keyId: "issuer_key_empty",
        publicKey: key.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });

      expect(() => {
        engine.issue({
          authorizationId: "auth-blocked-01",
          policyId: SAMPLE_POLICY.policyId,
          request: SAMPLE_TX_REQUEST,
          signer: { keyId: "issuer_key_empty", privateKey: key.privateKey },
        });
      }).toThrow(EngineInRecoveryModeError);

      engine.close();
      witness.close();
    });

    it("enters READY when local DB is empty and witness sequence is zero", () => {
      const witness = new SQLiteDurableWitness({
        dbPath: witnessDbPath,
        witnessId: "wit-empty-zero",
        epochId: "epoch-empty-zero",
        keyPair: TEST_KEY_PAIR,
      });

      const engine = Web3UserEngine.open({
        databasePath: engineDbPath,
        witnessAdapter: witness,
      });

      expect(engine.getState()).toBe("READY");
      expect(engine.isReady()).toBe(true);
      expect(engine.isRecoveryOnly()).toBe(false);

      engine.close();
      witness.close();
    });

    it("cannot unlock recovery when local records are missing (insufficient information)", async () => {
      const witness = new SQLiteDurableWitness({
        dbPath: witnessDbPath,
        witnessId: "wit-insufficient",
        epochId: "epoch-insufficient",
        keyPair: TEST_KEY_PAIR,
      });

      // Advance witness to seq 5
      for (let i = 1; i <= 5; i++) {
        const r = witness.reserveTicket({
          authorizationId: `auth-adv-${i}`,
          bindingDigest: `sha256:${i.toString().padStart(64, "0")}`,
          policyId: SAMPLE_POLICY.policyId,
          policyRevision: 1,
          idempotencyKey: `idemp-adv-${i}`,
        });
        witness.commitTicket({
          ticketId: r.ticketId!,
          authorizationId: `auth-adv-${i}`,
          bindingDigest: `sha256:${i.toString().padStart(64, "0")}`,
          localCommittedAtSeconds: 1000 + i,
        });
      }

      const engine = Web3UserEngine.open({
        databasePath: engineDbPath,
        witnessAdapter: witness,
      });

      expect(engine.getState()).toBe("RECOVERY_RECONCILE_ONLY");

      // Attempt unlocking recovery
      const unlocked = await engine.verifyAndUnlockRecovery();
      expect(unlocked).toBe(false);
      expect(engine.getState()).toBe("RECOVERY_RECONCILE_ONLY");

      // Repeated startup after incomplete recovery stays in recovery mode
      engine.close();

      const engineRestart = Web3UserEngine.open({
        databasePath: engineDbPath,
        witnessAdapter: witness,
      });
      expect(engineRestart.getState()).toBe("RECOVERY_RECONCILE_ONLY");

      engineRestart.close();
      witness.close();
    });
  });

  // ============================================================================
  // SEC-M13C-03: INITIALIZING State Gating
  // ============================================================================
  describe("SEC-M13C-03: High — INITIALIZING state gating", () => {
    it("strictly blocks issue, consume, and cancel while startup sync is pending", async () => {
      let resolveSync!: (value: any) => void;
      const syncPromise = new Promise((resolve) => {
        resolveSync = resolve;
      });

      const delayedWitness: MonotonicWitnessAdapter = {
        name: "DelayedWitness",
        isTestOnlyMock: true,
        publicKeyPem: TEST_KEY_PAIR.publicKeyPem,
        getSyncStatus: () => syncPromise as any,
        reserveTicket: () => ({ decision: "DENY" }),
        commitTicket: () => ({ decision: "DENY" }),
        releaseTicket: () => ({ success: false }),
        reconcileTicket: () => ({ ticketId: "t1", state: "DISPUTED" }),
      };

      const engine = Web3UserEngine.open({
        databasePath: engineDbPath,
        witnessAdapter: delayedWitness,
      });

      expect(engine.getState()).toBe("INITIALIZING");
      expect(engine.isReady()).toBe(false);

      // Verify assertReady blocks issue()
      expect(() => {
        engine.issue({
          authorizationId: "auth-init-block",
          policyId: SAMPLE_POLICY.policyId,
          request: SAMPLE_TX_REQUEST,
          signer: { keyId: "key1", privateKey: TEST_KEY_PAIR.privateKey },
        });
      }).toThrow(WitnessUnavailableError);

      // Verify assertReady blocks consume()
      expect(() => {
        engine.consume({
          artifact: {} as any,
          request: SAMPLE_TX_REQUEST,
        });
      }).toThrow(WitnessUnavailableError);

      // Verify assertReady blocks cancel()
      expect(() => {
        engine.cancel("auth-init-block");
      }).toThrow(WitnessUnavailableError);

      // Resolve the handshake
      resolveSync({
        healthy: true,
        epochId: "epoch-init-01",
        sequenceNumber: "0",
        divergenceDetected: false,
      });

      // Allow event loop to process promise resolution
      await new Promise((r) => setTimeout(r, 10));

      expect(engine.getState()).toBe("READY");
      expect(engine.isReady()).toBe(true);

      engine.close();
    });
  });

  // ============================================================================
  // SEC-M13C-04: Closed Engine Terminal State Protection
  // ============================================================================
  describe("SEC-M13C-04: Medium — Closed engine resurrection prevention", () => {
    it("delayed getSyncStatus resolution does NOT change closed engine state to READY", async () => {
      let resolveSync!: (value: any) => void;
      const syncPromise = new Promise((resolve) => {
        resolveSync = resolve;
      });

      const delayedWitness: MonotonicWitnessAdapter = {
        name: "DelayedWitnessRace",
        isTestOnlyMock: true,
        publicKeyPem: TEST_KEY_PAIR.publicKeyPem,
        getSyncStatus: () => syncPromise as any,
        reserveTicket: () => ({ decision: "DENY" }),
        commitTicket: () => ({ decision: "DENY" }),
        releaseTicket: () => ({ success: false }),
        reconcileTicket: () => ({ ticketId: "t1", state: "DISPUTED" }),
      };

      const engine = Web3UserEngine.open({
        databasePath: engineDbPath,
        witnessAdapter: delayedWitness,
      });

      expect(engine.getState()).toBe("INITIALIZING");

      // Close the engine before sync resolves
      engine.close();
      expect(engine.getState()).toBe("CLOSED");
      expect(engine.isOpen()).toBe(false);

      // Now resolve the in-flight sync promise
      resolveSync({
        healthy: true,
        epochId: "epoch-race-01",
        sequenceNumber: "0",
        divergenceDetected: false,
      });

      await new Promise((r) => setTimeout(r, 20));

      // Engine must remain strictly CLOSED, never resurrected to READY
      expect(engine.getState()).toBe("CLOSED");
      expect(engine.isOpen()).toBe(false);

      // Repeated close remains idempotent
      engine.close();
      expect(engine.getState()).toBe("CLOSED");
    });
  });

  // ============================================================================
  // SEC-M13C-05: Sequence Monotonicity and Duplicate Rejection
  // ============================================================================
  describe("SEC-M13C-05: Low — Sequence monotonicity and duplicate rejection", () => {
    it("rejects duplicate sequence number assignments within the same epoch", () => {
      const store = new SQLiteAuthorizationStore(engineDbPath, {
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const rawDb = new DatabaseSync(engineDbPath);
      const makeReceipt = (authId: string, seq: string) => ({
        version: 1,
        witnessId: "wit-dup",
        epochId: "epoch-dup-test",
        sequenceNumber: seq,
        ticketId: `t-${authId}`,
        authorizationId: authId,
        bindingDigest: "sha256:" + "d".repeat(64),
        policyId: "pol_test",
        policyRevision: 1,
        debitedAmount: "100",
        budgetWindows: [],
        committedAtSeconds: 1000,
        signature: "f".repeat(128),
      });

      // Insert two distinct authorizations with identical sequence number 5 in same epoch
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_receipt_json, witness_status
        ) VALUES 
          ('auth-dup-1', 'd1', 'consumed', '2026-10-30', 't-1', ?, 'COMMITTED'),
          ('auth-dup-2', 'd2', 'consumed', '2026-10-30', 't-2', ?, 'COMMITTED');
      `).run(
        JSON.stringify(makeReceipt("auth-dup-1", "5")),
        JSON.stringify(makeReceipt("auth-dup-2", "5")),
      );
      rawDb.close();

      expect(() => {
        store.getLatestWitnessReceiptMetadata();
      }).toThrow(/duplicate sequence number '5'/);

      store.close();
    });

    it("permits sequence gaps without causing false security failures", () => {
      const store = new SQLiteAuthorizationStore(engineDbPath, {
        witnessPublicKey: TEST_KEY_PAIR.publicKeyPem,
      });

      const rawDb = new DatabaseSync(engineDbPath);
      const makeReceipt = (authId: string, seq: string) => ({
        version: 1,
        witnessId: "wit-gap",
        epochId: "epoch-gap-test",
        sequenceNumber: seq,
        ticketId: `t-${authId}`,
        authorizationId: authId,
        bindingDigest: "sha256:" + "e".repeat(64),
        policyId: "pol_test",
        policyRevision: 1,
        debitedAmount: "100",
        budgetWindows: [],
        committedAtSeconds: 1000,
        signature: "g".repeat(128),
      });

      // Insert non-consecutive sequence numbers: 1, 5, 12
      rawDb.prepare(`
        INSERT INTO consumed_authorization_ids (
          authorization_id, binding_digest, state, consumed_at, witness_ticket_id, witness_receipt_json, witness_status
        ) VALUES 
          ('auth-gap-1', 'd1', 'consumed', '2026-10-30', 't-1', ?, 'COMMITTED'),
          ('auth-gap-2', 'd2', 'consumed', '2026-10-30', 't-2', ?, 'COMMITTED'),
          ('auth-gap-3', 'd3', 'consumed', '2026-10-30', 't-3', ?, 'COMMITTED');
      `).run(
        JSON.stringify(makeReceipt("auth-gap-1", "1")),
        JSON.stringify(makeReceipt("auth-gap-2", "5")),
        JSON.stringify(makeReceipt("auth-gap-3", "12")),
      );
      rawDb.close();

      const meta = store.getLatestWitnessReceiptMetadata();
      expect(meta.latestEpochId).toBe("epoch-gap-test");
      expect(meta.maxSequenceNumber).toBe("12");

      store.close();
    });
  });
});
