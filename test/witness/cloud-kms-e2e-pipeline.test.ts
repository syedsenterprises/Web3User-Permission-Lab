/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Cloud KMS E2E Pipeline & Recovery Suite
 *
 * Verifies:
 * - Substep 4.1: Hermetic End-to-End Pipeline Verification
 *   - Web3UserEngine -> RemoteDurableWitnessClient -> GrpcWitnessServiceImpl -> AwsKmsWitnessSigner / GcpKmsWitnessSigner -> Receipt Verification.
 *   - Isolated, test-owned local PostgreSQL instance (no mock DB substitute).
 *   - Persistent SQLite store for engine lifecycle and transaction commit.
 *   - Dual-Path Recovery:
 *     - Path B1: Direct duplicate CommitTicket replay returns cached receipt with CACHED_RECEIPT_REPLAY (zero KMS re-signing).
 *     - Path B2: Post-crash engine reconciliation sweep (reconcileAll) discovers PENDING_COMMIT, reconciles via ReconcileTicket, commits to SQLite (zero KMS re-signing).
 *   - Historical Receipt Verification & Single-Key Trust-Anchor Boundary:
 *     - Keypair A & B generation; Engine A & B self-receipt verification.
 *     - Standalone verifyWitnessReceipt(pubA, receiptA) and verifyWitnessReceipt(pubB, receiptB).
 *     - Standalone cross-key failure verifyWitnessReceipt(pubB, receiptA) === false.
 *     - Conflicting per-call override rejection: positional getWitnessReceipt(authIdB, pubA) and options reconcileAll({ witnessPublicKey: pubA }).
 * - Substep 4.2: Production Guardrail & Adversarial Testing
 *   - Signer factory production mode guardrails (local forbidden, mandatory fingerprint).
 *   - Listener non-binding boundary tests (abort before socket binding, no process.exit).
 *   - Adversarial error code mappings (AWS DisabledException/KeyUnavailable, GCP FAILED_PRECONDITION/CRC32C corruption).
 *
 * Reference: FN-SEC-01 Step 4 (Production Readiness & Operational Closure)
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mkdirSync, rmSync } from "node:fs";
import { generateKeyPairSync, createHash, randomBytes, type KeyObject } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import pg from "pg";

import {
  Web3UserEngine,
  generateIssuerKeyPair,
  verifyWitnessReceipt,
  ValidationError,
  type TransactionRequest,
  type DemoPolicy,
} from "../../src/index.js";
import { PostgresWitnessStore } from "../../src/witness/postgres-store.js";
import { startGrpcWitnessServer, type StartedGrpcWitnessServer } from "../../src/witness/grpc-server.js";
import { GrpcWitnessServiceImpl } from "../../src/witness/grpc-service.js";
import { RemoteDurableWitnessClient } from "../../src/witness/remote-witness-client.js";
import { generateTestCertificates, type CertBundle } from "../../src/witness/mtls-certs.js";
import { AwsKmsWitnessSigner } from "../../src/witness/aws-kms-signer.js";
import { GcpKmsWitnessSigner } from "../../src/witness/gcp-kms-signer.js";
import {
  createWitnessSignerFromConfig,
  loadWitnessSignerConfigFromEnv,
} from "../../src/witness/signer-factory.js";
import {
  KmsConfigurationError,
  KmsKeyValidationError,
  calculateCrc32c,
  type AwsKmsSignerConfig,
  type GcpKmsSignerConfig,
} from "../../src/witness/cloud-kms-signer.js";

// ============================================================================
// Test Fixtures & Constants
// ============================================================================

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
  policyId: "pol_e2e_kms_pipeline",
  allowedTarget: "0x1111111111111111111111111111111111111111",
  allowedRecipient: "0x4444444444444444444444444444444444444444",
  allowedSelector: "0xa9059cbb",
  maxAmount: "2000000000000000000",
  validFrom: 0,
  expiresAt: 2000000000,
  revoked: false,
  budget: {
    window: "HOURLY",
    maxCumulativeAmount: "1000000000000000000000000",
  },
};

function createTestDirectory(): string {
  const dir = join(tmpdir(), `web3user-step4-e2e-${Date.now()}-${randomBytes(4).toString("hex")}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function computeCanonicalFingerprint(publicKey: KeyObject): {
  spkiDer: Buffer;
  spkiPem: string;
  rawKeyBytes: Buffer;
  fingerprint: string;
} {
  const spkiDer = publicKey.export({ type: "spki", format: "der" });
  const spkiPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  // Trailing 32 bytes contain the raw RFC 8032 Ed25519 public key point
  const rawKeyBytes = spkiDer.subarray(spkiDer.length - 32);
  const fingerprint = createHash("sha256").update(rawKeyBytes).digest("hex").toLowerCase();
  return { spkiDer, spkiPem, rawKeyBytes, fingerprint };
}

// ============================================================================
// Main Suite
// ============================================================================

describe("Milestone 13-D Phase D2: Cloud KMS E2E Pipeline & Recovery Suite (FN-SEC-01 Step 4)", () => {
  let certs: CertBundle;
  let pool: pg.Pool;
  let store: PostgresWitnessStore;

  async function createFreshEpoch(): Promise<string> {
    const maxHRes = await pool.query(
      `SELECT COALESCE(MAX(epoch_height), 0) + 1 AS next_h FROM witness_epochs`,
    );
    const nextH = Number(maxHRes.rows[0].next_h);
    const epochId = `epoch-step4-${Date.now()}-${randomBytes(4).toString("hex")}`;
    await store.registerEpoch(epochId, nextH);
    return epochId;
  }

  beforeAll(async () => {
    certs = generateTestCertificates();
    store = new PostgresWitnessStore();
    pool = (store as any).pool;

    // Verify local PostgreSQL test database connection and schema
    await store.initializeSchema();
    await createFreshEpoch();
  });

  afterAll(async () => {
    if (pool) {
      await pool.end();
    }
  });

  // ==========================================================================
  // Substep 4.1: Hermetic End-to-End Pipeline Integration
  // ==========================================================================
  describe("Substep 4.1: Hermetic Engine-Witness E2E Integration", () => {
    let testDir: string;

    beforeEach(async () => {
      testDir = createTestDirectory();
      // Ensure each test has a fresh epoch with last_sequence_number = 0
      await createFreshEpoch();
      // Reset budget accumulators to prevent test pollution
      await pool.query("TRUNCATE TABLE witness_accumulators");
    });

    afterEach(() => {
      try {
        rmSync(testDir, { recursive: true, force: true });
      } catch {}
    });

    it("executes complete authorization, reserve, commit, sign, and verify pipeline with AWS KMS mock", async () => {
      const keyPair = generateKeyPairSync("ed25519");
      const { spkiDer, fingerprint } = computeCanonicalFingerprint(keyPair.publicKey);

      let awsSignCallCount = 0;
      const mockAwsClient: any = {
        send: async (cmd: any) => {
          if (cmd.constructor.name === "GetPublicKeyCommand") {
            return {
              KeySpec: "ECC_NIST_EDWARDS25519",
              PublicKey: new Uint8Array(spkiDer),
            };
          }
          if (cmd.constructor.name === "SignCommand") {
            awsSignCallCount++;
            const crypto = await import("node:crypto");
            const sig = crypto.sign(null, Buffer.from(cmd.input.Message), keyPair.privateKey);
            return {
              Signature: new Uint8Array(sig),
            };
          }
          throw new Error(`Unexpected AWS command: ${cmd.constructor.name}`);
        },
      };

      const awsSigner = new AwsKmsWitnessSigner(
        {
          provider: "aws",
          witnessId: "witness-aws-e2e-1",
          keyId: "arn:aws:kms:us-east-1:123456789012:key/test-ed25519-e2e",
          region: "us-east-1",
          expectedKeyFingerprint: fingerprint,
        },
        mockAwsClient,
      );

      const service = new GrpcWitnessServiceImpl({ pool, signer: awsSigner });
      const serverInstance = await startGrpcWitnessServer({
        serviceImpl: service,
        caCert: certs.caCert,
        serverCert: certs.serverCert,
        serverKey: certs.serverKey,
        port: 0,
        host: "127.0.0.1",
        skipDependencyCheck: true,
      });

      const witnessClient = new RemoteDurableWitnessClient({
        endpoint: `127.0.0.1:${serverInstance.port}`,
        caCert: certs.caCert,
        clientCert: certs.engineClientCert,
        clientKey: certs.engineClientKey,
      });

      const engineDbPath = join(testDir, "engine-aws-e2e.sqlite");
      const engine = await Web3UserEngine.openAsync({
        databasePath: engineDbPath,
        witnessAdapter: witnessClient,
        witnessPublicKey: keyPair.publicKey,
        closeWitnessOnShutdown: false,
      });

      try {
        expect(engine.getState()).toBe("READY");

        engine.policies.register(SAMPLE_POLICY);
        const issuerKey = engine.keys.generate();
        engine.keys.register({
          keyId: "issuer_aws_e2e_01",
          publicKey: issuerKey.publicKey,
          status: "active",
          validFromSeconds: 0,
          expiresAtSeconds: 2000000000,
        });

        // 1. Issue authorization
        const authId = `auth-aws-e2e-${Date.now()}`;
        const issueRes = engine.issue({
          authorizationId: authId,
          policyId: SAMPLE_POLICY.policyId,
          request: SAMPLE_TX_REQUEST,
          signer: { keyId: "issuer_aws_e2e_01", privateKey: issuerKey.privateKey },
        });
        expect(issueRes.decision).toBe("ALLOW");
        if (issueRes.decision !== "ALLOW") throw new Error("Expected ALLOW for issue");

        // 2. Consume authorization through the full E2E pipeline
        const consumeRes = await engine.consumeAsync({
          artifact: issueRes.artifact,
          envelope: issueRes.envelope,
          request: SAMPLE_TX_REQUEST,
        });

        expect(consumeRes.decision).toBe("ALLOW");
        if (consumeRes.decision !== "ALLOW") throw new Error("Expected ALLOW for consume");
        expect(consumeRes.witnessReceipt).toBeDefined();
        expect(consumeRes.witnessReceipt?.witnessId).toBe("witness-aws-e2e-1");
        expect(consumeRes.witnessReceipt?.signature).toBeDefined();
        expect(awsSignCallCount).toBe(1);

        // 3. Verify receipt signature cryptographically against engine trust anchor
        const isReceiptValid = verifyWitnessReceipt(keyPair.publicKey, consumeRes.witnessReceipt!);
        expect(isReceiptValid).toBe(true);

        // 4. Verify SQLite storage state
        const storedAuth = engine.getAuthorizationRecord(authId);
        expect(storedAuth).toBeDefined();
        expect(storedAuth?.state).toBe("consumed");
        expect(storedAuth?.witnessStatus).toBe("COMMITTED");

        // 5. Query stored receipt via engine API
        const storedReceipt = engine.getWitnessReceipt(authId);
        expect(storedReceipt).toBeDefined();
        expect(storedReceipt?.sequenceNumber).toBe(consumeRes.witnessReceipt?.sequenceNumber);
      } finally {
        engine.close();
        witnessClient.close();
        await serverInstance.stop();
      }
    });

    it("executes complete authorization, reserve, commit, sign, and verify pipeline with GCP Cloud KMS mock", async () => {
      const keyPair = generateKeyPairSync("ed25519");
      const { spkiPem, fingerprint } = computeCanonicalFingerprint(keyPair.publicKey);
      const validCrc = calculateCrc32c(Buffer.from(spkiPem, "utf8"));
      const gcpKeyName =
        "projects/test-proj/locations/us-central1/keyRings/ring-1/cryptoKeys/key-1/cryptoKeyVersions/1";

      let gcpSignCallCount = 0;
      const mockGcpClient: any = {
        getCryptoKeyVersion: async () => [
          {
            name: gcpKeyName,
            state: "ENABLED",
            protectionLevel: "SOFTWARE",
            algorithm: "EC_SIGN_ED25519",
          },
        ],
        getPublicKey: async () => [
          {
            name: gcpKeyName,
            algorithm: "EC_SIGN_ED25519",
            pem: spkiPem,
            pemCrc32c: { value: validCrc },
          },
        ],
        asymmetricSign: async (req: any) => {
          gcpSignCallCount++;
          const crypto = await import("node:crypto");
          const sig = crypto.sign(null, Buffer.from(req.data), keyPair.privateKey);
          return [{ signature: new Uint8Array(sig) }];
        },
      };

      const gcpSigner = new GcpKmsWitnessSigner(
        {
          provider: "gcp",
          witnessId: "witness-gcp-e2e-1",
          keyVersionName: gcpKeyName,
          expectedKeyFingerprint: fingerprint,
        },
        mockGcpClient,
      );

      const service = new GrpcWitnessServiceImpl({ pool, signer: gcpSigner });
      const serverInstance = await startGrpcWitnessServer({
        serviceImpl: service,
        caCert: certs.caCert,
        serverCert: certs.serverCert,
        serverKey: certs.serverKey,
        port: 0,
        host: "127.0.0.1",
        skipDependencyCheck: true,
      });

      const witnessClient = new RemoteDurableWitnessClient({
        endpoint: `127.0.0.1:${serverInstance.port}`,
        caCert: certs.caCert,
        clientCert: certs.engineClientCert,
        clientKey: certs.engineClientKey,
      });

      const engineDbPath = join(testDir, "engine-gcp-e2e.sqlite");
      const engine = await Web3UserEngine.openAsync({
        databasePath: engineDbPath,
        witnessAdapter: witnessClient,
        witnessPublicKey: keyPair.publicKey,
        closeWitnessOnShutdown: false,
      });

      try {
        expect(engine.getState()).toBe("READY");

        engine.policies.register(SAMPLE_POLICY);
        const issuerKey = engine.keys.generate();
        engine.keys.register({
          keyId: "issuer_gcp_e2e_01",
          publicKey: issuerKey.publicKey,
          status: "active",
          validFromSeconds: 0,
          expiresAtSeconds: 2000000000,
        });

        // 1. Issue authorization
        const authId = `auth-gcp-e2e-${Date.now()}`;
        const issueRes = engine.issue({
          authorizationId: authId,
          policyId: SAMPLE_POLICY.policyId,
          request: SAMPLE_TX_REQUEST,
          signer: { keyId: "issuer_gcp_e2e_01", privateKey: issuerKey.privateKey },
        });
        expect(issueRes.decision).toBe("ALLOW");
        if (issueRes.decision !== "ALLOW") throw new Error("Expected ALLOW for issue");

        // 2. Consume authorization through the full E2E pipeline
        const consumeRes = await engine.consumeAsync({
          artifact: issueRes.artifact,
          envelope: issueRes.envelope,
          request: SAMPLE_TX_REQUEST,
        });

        expect(consumeRes.decision).toBe("ALLOW");
        if (consumeRes.decision !== "ALLOW") throw new Error("Expected ALLOW for consume");
        expect(consumeRes.witnessReceipt).toBeDefined();
        expect(consumeRes.witnessReceipt?.witnessId).toBe("witness-gcp-e2e-1");
        expect(gcpSignCallCount).toBe(1);

        // 3. Verify receipt signature cryptographically
        const isReceiptValid = verifyWitnessReceipt(keyPair.publicKey, consumeRes.witnessReceipt!);
        expect(isReceiptValid).toBe(true);

        // 4. Verify SQLite storage state
        const storedAuth = engine.getAuthorizationRecord(authId);
        expect(storedAuth?.state).toBe("consumed");
        expect(storedAuth?.witnessStatus).toBe("COMMITTED");
      } finally {
        engine.close();
        witnessClient.close();
        await serverInstance.stop();
      }
    });

    // ========================================================================
    // Dual-Path Recovery Verification (Non-Substitutable)
    // ========================================================================

    it("Dual-Path Recovery Path B1: direct duplicate CommitTicket replay returns cached receipt without invoking KMS re-signing", async () => {
      const keyPair = generateKeyPairSync("ed25519");
      const { spkiDer, fingerprint } = computeCanonicalFingerprint(keyPair.publicKey);

      let kmsSignCallCount = 0;
      const mockAwsClient: any = {
        send: async (cmd: any) => {
          if (cmd.constructor.name === "GetPublicKeyCommand") {
            return {
              KeySpec: "ECC_NIST_EDWARDS25519",
              PublicKey: new Uint8Array(spkiDer),
            };
          }
          if (cmd.constructor.name === "SignCommand") {
            kmsSignCallCount++;
            const crypto = await import("node:crypto");
            const sig = crypto.sign(null, Buffer.from(cmd.input.Message), keyPair.privateKey);
            return { Signature: new Uint8Array(sig) };
          }
          throw new Error(`Unexpected AWS command: ${cmd.constructor.name}`);
        },
      };

      const signer = new AwsKmsWitnessSigner(
        {
          provider: "aws",
          witnessId: "witness-replay-b1",
          keyId: "arn:aws:kms:us-east-1:123456789012:key/test-replay-b1",
          region: "us-east-1",
          expectedKeyFingerprint: fingerprint,
        },
        mockAwsClient,
      );

      const service = new GrpcWitnessServiceImpl({ pool, signer });
      const serverInstance = await startGrpcWitnessServer({
        serviceImpl: service,
        caCert: certs.caCert,
        serverCert: certs.serverCert,
        serverKey: certs.serverKey,
        port: 0,
        host: "127.0.0.1",
        skipDependencyCheck: true,
      });

      const client = new RemoteDurableWitnessClient({
        endpoint: `127.0.0.1:${serverInstance.port}`,
        caCert: certs.caCert,
        clientCert: certs.engineClientCert,
        clientKey: certs.engineClientKey,
      });

      try {
        const authId = `auth-replay-b1-${Date.now()}`;
        const bindingDigest = "sha256:" + createHash("sha256").update(authId).digest("hex");

        // 1. Reserve Ticket
        const reserveRes = await client.reserveTicket({
          authorizationId: authId,
          bindingDigest,
          policyId: "test-policy",
          policyRevision: 1,
          idempotencyKey: `idem-${authId}`,
        });
        expect(reserveRes.decision).toBe("ALLOW");
        const ticketId = reserveRes.ticketId!;

        // 2. Commit Ticket (First invocation)
        const commitRes1 = await client.commitTicket({
          ticketId,
          authorizationId: authId,
          bindingDigest,
          localCommittedAtSeconds: Math.floor(Date.now() / 1000),
        });
        expect(commitRes1.decision).toBe("ALLOW");
        expect(commitRes1.receipt).toBeDefined();
        expect(kmsSignCallCount).toBe(1);

        // 3. Replay Commit Ticket directly (Duplicate replay - Path B1)
        const commitRes2 = await client.commitTicket({
          ticketId,
          authorizationId: authId,
          bindingDigest,
          localCommittedAtSeconds: Math.floor(Date.now() / 1000),
        });

        // 4. Assert cached receipt returned with CACHED_RECEIPT_REPLAY
        expect(commitRes2.decision).toBe("ALLOW");
        expect(commitRes2.receipt).toEqual(commitRes1.receipt);
        expect(commitRes2.reasons).toContain("CACHED_RECEIPT_REPLAY");
        expect((commitRes2 as any).alreadyCommitted ?? (commitRes2 as any).already_committed).toBe(true);

        // 5. Assert zero additional KMS signing calls
        expect(kmsSignCallCount).toBe(1);
      } finally {
        client.close();
        await serverInstance.stop();
      }
    });

    it("Dual-Path Recovery Path B2: post-crash engine reconciliation sweep (reconcileAll) discovers PENDING_COMMIT and recovers receipt without KMS re-signing", async () => {
      const keyPair = generateKeyPairSync("ed25519");
      const { spkiDer, fingerprint } = computeCanonicalFingerprint(keyPair.publicKey);

      let kmsSignCallCount = 0;
      const mockAwsClient: any = {
        send: async (cmd: any) => {
          if (cmd.constructor.name === "GetPublicKeyCommand") {
            return {
              KeySpec: "ECC_NIST_EDWARDS25519",
              PublicKey: new Uint8Array(spkiDer),
            };
          }
          if (cmd.constructor.name === "SignCommand") {
            kmsSignCallCount++;
            const crypto = await import("node:crypto");
            const sig = crypto.sign(null, Buffer.from(cmd.input.Message), keyPair.privateKey);
            return { Signature: new Uint8Array(sig) };
          }
          throw new Error(`Unexpected AWS command: ${cmd.constructor.name}`);
        },
      };

      const signer = new AwsKmsWitnessSigner(
        {
          provider: "aws",
          witnessId: "witness-reconcile-b2",
          keyId: "arn:aws:kms:us-east-1:123456789012:key/test-reconcile-b2",
          region: "us-east-1",
          expectedKeyFingerprint: fingerprint,
        },
        mockAwsClient,
      );

      const service = new GrpcWitnessServiceImpl({ pool, signer });
      const serverInstance = await startGrpcWitnessServer({
        serviceImpl: service,
        caCert: certs.caCert,
        serverCert: certs.serverCert,
        serverKey: certs.serverKey,
        port: 0,
        host: "127.0.0.1",
        skipDependencyCheck: true,
      });

      const witnessClient = new RemoteDurableWitnessClient({
        endpoint: `127.0.0.1:${serverInstance.port}`,
        caCert: certs.caCert,
        clientCert: certs.engineClientCert,
        clientKey: certs.engineClientKey,
      });

      const engineDbPath = join(testDir, "engine-reconcile-b2.sqlite");

      // Phase 1: Normal transaction issuance and consumption in Engine 1
      const engine1 = await Web3UserEngine.openAsync({
        databasePath: engineDbPath,
        witnessAdapter: witnessClient,
        witnessPublicKey: keyPair.publicKey,
        closeWitnessOnShutdown: false,
      });

      engine1.policies.register(SAMPLE_POLICY);
      const issuerKey = engine1.keys.generate();
      engine1.keys.register({
        keyId: "issuer_b2",
        publicKey: issuerKey.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });

      const authId = `auth-reconcile-b2-${Date.now()}`;
      const issueRes = engine1.issue({
        authorizationId: authId,
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: { keyId: "issuer_b2", privateKey: issuerKey.privateKey },
      });
      if (issueRes.decision !== "ALLOW") throw new Error("Expected ALLOW for issue");

      const consumeRes = await engine1.consumeAsync({
        artifact: issueRes.artifact,
        envelope: issueRes.envelope,
        request: SAMPLE_TX_REQUEST,
      });

      expect(consumeRes.decision).toBe("ALLOW");
      if (consumeRes.decision !== "ALLOW") throw new Error("Expected ALLOW for consume");
      expect(kmsSignCallCount).toBe(1);
      const originalReceipt = consumeRes.witnessReceipt!;

      // Close Engine 1
      engine1.close();

      // Phase 2: Simulate abnormal crash in SQLite before local receipt persistence
      // Force witness_status back to PENDING_COMMIT and clear witness_receipt_json
      const sqlite = new DatabaseSync(engineDbPath);
      sqlite
        .prepare(
          "UPDATE consumed_authorization_ids SET witness_status = 'PENDING_COMMIT', witness_receipt_json = NULL WHERE authorization_id = ?",
        )
        .run(authId);
      sqlite.close();

      // Phase 3: Open brand new Engine 2 on the same persistent SQLite database
      const engine2 = await Web3UserEngine.openAsync({
        databasePath: engineDbPath,
        witnessAdapter: witnessClient,
        witnessPublicKey: keyPair.publicKey,
        closeWitnessOnShutdown: false,
      });

      try {
        // Engine 2 detects unresolved PENDING_COMMIT and enters RECOVERY_RECONCILE_ONLY
        expect(engine2.getState()).toBe("RECOVERY_RECONCILE_ONLY");
        expect(engine2.isRecoveryOnly()).toBe(true);

        // Execute bounded batch recovery sweep via reconcileAll()
        const sweepResult = await engine2.reconcileAll();
        expect(sweepResult.summary.totalDiscovered).toBe(1);
        expect(sweepResult.summary.reconciledCount).toBe(1);
        expect(sweepResult.summary.disputedCount).toBe(0);

        // Verify that the receipt in SQLite has been restored and matches original
        const recoveredReceipt = engine2.getWitnessReceipt(authId);
        expect(recoveredReceipt).toBeDefined();
        expect(recoveredReceipt?.sequenceNumber).toBe(originalReceipt.sequenceNumber);
        expect(recoveredReceipt?.signature).toBe(originalReceipt.signature);

        // Verify engine unlocks to READY
        const unlocked = await engine2.verifyAndUnlockRecovery();
        expect(unlocked).toBe(true);
        expect(engine2.getState()).toBe("READY");

        // CRITICAL INVARIANT: KMS signer was NOT invoked a second time during reconciliation
        expect(kmsSignCallCount).toBe(1);
      } finally {
        engine2.close();
        witnessClient.close();
        await serverInstance.stop();
      }
    });

    // ========================================================================
    // Independent Test 3: Key Rotation & Historical Receipt Verification
    // ========================================================================

    it("Independent Test 3: verifies historical receipts post-rotation, enforces cross-key rejection, and confirms per-call trust-anchor immutability", async () => {
      // 1. Generate Keypair A and Keypair B within test mock wrappers
      const keyPairA = generateKeyPairSync("ed25519");
      const keyPairB = generateKeyPairSync("ed25519");

      const keyA = computeCanonicalFingerprint(keyPairA.publicKey);
      const keyB = computeCanonicalFingerprint(keyPairB.publicKey);

      // Active mock key reference for rotating witness server
      let activeKeyPair = keyPairA;
      let activeKeyMeta = keyA;

      const mockRotatingAwsClient: any = {
        send: async (cmd: any) => {
          if (cmd.constructor.name === "GetPublicKeyCommand") {
            return {
              KeySpec: "ECC_NIST_EDWARDS25519",
              PublicKey: new Uint8Array(activeKeyMeta.spkiDer),
            };
          }
          if (cmd.constructor.name === "SignCommand") {
            const crypto = await import("node:crypto");
            const sig = crypto.sign(null, Buffer.from(cmd.input.Message), activeKeyPair.privateKey);
            return { Signature: new Uint8Array(sig) };
          }
          throw new Error(`Unexpected AWS command: ${cmd.constructor.name}`);
        },
      };

      // Helper to start witness server with a specific signer
      const createWitnessServer = async (witnessId: string, fingerprint: string) => {
        const signer = new AwsKmsWitnessSigner(
          {
            provider: "aws",
            witnessId,
            keyId: `arn:aws:kms:us-east-1:123456789012:key/${witnessId}`,
            region: "us-east-1",
            expectedKeyFingerprint: fingerprint,
          },
          mockRotatingAwsClient,
        );

        const service = new GrpcWitnessServiceImpl({ pool, signer });
        const serverInstance = await startGrpcWitnessServer({
          serviceImpl: service,
          caCert: certs.caCert,
          serverCert: certs.serverCert,
          serverKey: certs.serverKey,
          port: 0,
          host: "127.0.0.1",
          skipDependencyCheck: true,
        });

        const client = new RemoteDurableWitnessClient({
          endpoint: `127.0.0.1:${serverInstance.port}`,
          caCert: certs.caCert,
          clientCert: certs.engineClientCert,
          clientKey: certs.engineClientKey,
        });

        return { serverInstance, client };
      };

      // Step 1: Witness daemon starts configured with Mock Signer A
      const daemonA = await createWitnessServer("witness-rotation-a", keyA.fingerprint);

      const engineDbPathA = join(testDir, "engine-rotation-a.sqlite");
      const engineA = await Web3UserEngine.openAsync({
        databasePath: engineDbPathA,
        witnessAdapter: daemonA.client,
        witnessPublicKey: keyPairA.publicKey,
        closeWitnessOnShutdown: false,
      });

      engineA.policies.register(SAMPLE_POLICY);
      const issuerKeyA = engineA.keys.generate();
      engineA.keys.register({
        keyId: "issuer_a",
        publicKey: issuerKeyA.publicKey,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 2000000000,
      });

      const authIdA = `auth-rotation-a-${Date.now()}`;
      const issueResA = engineA.issue({
        authorizationId: authIdA,
        policyId: SAMPLE_POLICY.policyId,
        request: SAMPLE_TX_REQUEST,
        signer: { keyId: "issuer_a", privateKey: issuerKeyA.privateKey },
      });
      if (issueResA.decision !== "ALLOW") throw new Error("Expected ALLOW for issue A");

      const consumeResA = await engineA.consumeAsync({
        artifact: issueResA.artifact,
        envelope: issueResA.envelope,
        request: SAMPLE_TX_REQUEST,
      });
      expect(consumeResA.decision).toBe("ALLOW");
      if (consumeResA.decision !== "ALLOW") throw new Error("Expected ALLOW for consume A");
      const receiptA = consumeResA.witnessReceipt!;

      // Engine A verifies its own receipt internally
      expect(verifyWitnessReceipt(keyPairA.publicKey, receiptA)).toBe(true);

      // Shut down daemon A and engine A
      engineA.close();
      daemonA.client.close();
      await daemonA.serverInstance.stop();

      // Step 2: Rotate witness to Mock Signer B
      // Register a fresh epoch for daemon B so sequence is clean
      await createFreshEpoch();
      activeKeyPair = keyPairB;
      activeKeyMeta = keyB;

      const daemonB = await createWitnessServer("witness-rotation-b", keyB.fingerprint);

      const engineDbPathB = join(testDir, "engine-rotation-b.sqlite");
      const engineB = await Web3UserEngine.openAsync({
        databasePath: engineDbPathB,
        witnessAdapter: daemonB.client,
        witnessPublicKey: keyPairB.publicKey,
        closeWitnessOnShutdown: false,
      });

      try {
        engineB.policies.register(SAMPLE_POLICY);
        const issuerKeyB = engineB.keys.generate();
        engineB.keys.register({
          keyId: "issuer_b",
          publicKey: issuerKeyB.publicKey,
          status: "active",
          validFromSeconds: 0,
          expiresAtSeconds: 2000000000,
        });

        const authIdB = `auth-rotation-b-${Date.now()}`;
        const issueResB = engineB.issue({
          authorizationId: authIdB,
          policyId: SAMPLE_POLICY.policyId,
          request: SAMPLE_TX_REQUEST,
          signer: { keyId: "issuer_b", privateKey: issuerKeyB.privateKey },
        });
        if (issueResB.decision !== "ALLOW") throw new Error("Expected ALLOW for issue B");

        const consumeResB = await engineB.consumeAsync({
          artifact: issueResB.artifact,
          envelope: issueResB.envelope,
          request: SAMPLE_TX_REQUEST,
        });
        expect(consumeResB.decision).toBe("ALLOW");
        if (consumeResB.decision !== "ALLOW") throw new Error("Expected ALLOW for consume B");
        const receiptB = consumeResB.witnessReceipt!;

        // Engine B verifies its own receipt internally
        expect(verifyWitnessReceipt(keyPairB.publicKey, receiptB)).toBe(true);

        // Step 3: Standalone Historical Verification (Documented Public API)
        // verifyWitnessReceipt(pubA, receiptA) and verifyWitnessReceipt(pubB, receiptB) succeed offline
        expect(verifyWitnessReceipt(keyPairA.publicKey, receiptA)).toBe(true);
        expect(verifyWitnessReceipt(keyPairB.publicKey, receiptB)).toBe(true);

        // Step 4: Standalone Cross-Key Verification Failure
        // verifyWitnessReceipt(pubB, receiptA) MUST return false
        expect(verifyWitnessReceipt(keyPairB.publicKey, receiptA)).toBe(false);
        expect(verifyWitnessReceipt(keyPairA.publicKey, receiptB)).toBe(false);

        // Step 5: Conflicting Per-Call Override Rejection
        // A) Options-object invocation: engineB.reconcileAll({ witnessPublicKey: pubA })
        // Must reject asynchronously with exact ValidationError
        await expect(
          engineB.reconcileAll({ witnessPublicKey: keyPairA.publicKey }),
        ).rejects.toThrow(
          new ValidationError(
            "Supplied witnessPublicKey conflicts with configured engine witness trust anchor.",
          ),
        );

        // B) Positional invocation: engineB.getWitnessReceipt(authIdB, pubA)
        // Must throw synchronously with exact ValidationError
        expect(() => {
          engineB.getWitnessReceipt(authIdB, keyPairA.publicKey);
        }).toThrow(
          new ValidationError(
            "Supplied witnessPublicKey conflicts with configured engine witness trust anchor.",
          ),
        );
      } finally {
        engineB.close();
        daemonB.client.close();
        await daemonB.serverInstance.stop();
      }
    });
  });

  // ==========================================================================
  // Substep 4.2: Production Guardrail & Adversarial Testing
  // ==========================================================================
  describe("Substep 4.2: Production Guardrail & Adversarial Testing", () => {
    it("enforces signer factory production mode guardrails (rejects local without allowInProduction; requires 64-hex fingerprint)", () => {
      const origEnv = process.env.NODE_ENV;
      try {
        process.env.NODE_ENV = "production";

        // 1. Local signer without allowInProduction throws KmsConfigurationError with SECURITY_VIOLATION
        expect(() => {
          createWitnessSignerFromConfig({
            provider: "local",
            witnessId: "wit-prod-local",
          });
        }).toThrow(/SECURITY_VIOLATION: Local Ed25519 signer is strictly prohibited in production mode/);

        // 2. AWS config missing expectedKeyFingerprint in production throws KmsConfigurationError
        expect(() => {
          createWitnessSignerFromConfig({
            provider: "aws",
            witnessId: "wit-prod-aws",
            keyId: "arn:aws:kms:us-east-1:123456789012:key/test",
            region: "us-east-1",
          } as AwsKmsSignerConfig);
        }).toThrow(/SECURITY_VIOLATION: expectedKeyFingerprint.*is strictly mandatory in production mode/);

        // 3. GCP config missing expectedKeyFingerprint in production throws KmsConfigurationError
        expect(() => {
          createWitnessSignerFromConfig({
            provider: "gcp",
            witnessId: "wit-prod-gcp",
            keyVersionName:
              "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
          } as GcpKmsSignerConfig);
        }).toThrow(/SECURITY_VIOLATION: expectedKeyFingerprint.*is strictly mandatory in production mode/);

        // 4. loadWitnessSignerConfigFromEnv enforces mandatory fingerprint in production
        expect(() => {
          loadWitnessSignerConfigFromEnv({
            WITNESS_SIGNER_PROVIDER: "aws",
            WITNESS_ID: "wit-env-aws",
            WITNESS_AWS_KEY_ID: "arn:aws:kms:us-east-1:123456789012:key/test",
            WITNESS_AWS_REGION: "us-east-1",
          });
        }).toThrow(/SECURITY_VIOLATION: WITNESS_EXPECTED_KEY_FINGERPRINT.*is strictly mandatory in production mode/);
      } finally {
        process.env.NODE_ENV = origEnv;
      }
    });

    it("verifies listener non-binding boundary: invalid signer configuration or fingerprint mismatch rejects before socket binding without invoking process.exit", async () => {
      const keyPair = generateKeyPairSync("ed25519");
      const { spkiDer } = computeCanonicalFingerprint(keyPair.publicKey);
      const mismatchedFingerprint = "00".repeat(32);

      const mockAwsClient: any = {
        send: async (cmd: any) => {
          if (cmd.constructor.name === "GetPublicKeyCommand") {
            return {
              KeySpec: "ECC_NIST_EDWARDS25519",
              PublicKey: new Uint8Array(spkiDer),
            };
          }
          throw new Error("Sign should not be called on probe mismatch");
        },
      };

      const signerWithMismatchedFp = new AwsKmsWitnessSigner(
        {
          provider: "aws",
          witnessId: "witness-mismatch",
          keyId: "arn:aws:kms:us-east-1:123456789012:key/test-mismatch",
          region: "us-east-1",
          expectedKeyFingerprint: mismatchedFingerprint,
        },
        mockAwsClient,
      );

      const service = new GrpcWitnessServiceImpl({ pool, signer: signerWithMismatchedFp });

      // Ensure process.exit was never called
      const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
        throw new Error("process.exit must NEVER be called in tests!");
      }) as any);

      try {
        await expect(
          startGrpcWitnessServer({
            serviceImpl: service,
            caCert: certs.caCert,
            serverCert: certs.serverCert,
            serverKey: certs.serverKey,
            port: 0,
            host: "127.0.0.1",
            skipDependencyCheck: true,
          }),
        ).rejects.toThrow(KmsKeyValidationError);

        expect(exitSpy).not.toHaveBeenCalled();
      } finally {
        exitSpy.mockRestore();
      }
    });

    it("adversarial error code mapping: maps AWS DisabledException and KeyUnavailableException to fail-closed error codes", async () => {
      const keyPair = generateKeyPairSync("ed25519");
      const { spkiDer, fingerprint } = computeCanonicalFingerprint(keyPair.publicKey);

      // 1. DisabledException during doInitialize
      const disabledAwsClient: any = {
        send: async () => {
          const err: any = new Error("Key is disabled");
          err.name = "DisabledException";
          throw err;
        },
      };

      const disabledSigner = new AwsKmsWitnessSigner(
        {
          provider: "aws",
          witnessId: "wit-disabled",
          keyId: "arn:aws:kms:us-east-1:123456789012:key/test-disabled",
          region: "us-east-1",
          expectedKeyFingerprint: fingerprint,
        },
        disabledAwsClient,
      );

      await expect(disabledSigner.initialize()).rejects.toThrow(/AWS KMS initialization failed: Key is disabled/);
      expect(disabledSigner.getState()).toBe("FAILED");

      // 2. KeyUnavailableException during sign
      const unavailableAwsClient: any = {
        send: async (cmd: any) => {
          if (cmd.constructor.name === "GetPublicKeyCommand") {
            return {
              KeySpec: "ECC_NIST_EDWARDS25519",
              PublicKey: new Uint8Array(spkiDer),
            };
          }
          const err: any = new Error("KMS service temporarily unavailable");
          err.name = "KeyUnavailableException";
          throw err;
        },
      };

      const unavailableSigner = new AwsKmsWitnessSigner(
        {
          provider: "aws",
          witnessId: "wit-unavail",
          keyId: "arn:aws:kms:us-east-1:123456789012:key/test-unavail",
          region: "us-east-1",
          expectedKeyFingerprint: fingerprint,
        },
        unavailableAwsClient,
      );

      await unavailableSigner.initialize();
      expect(unavailableSigner.getState()).toBe("READY");

      await expect(
        unavailableSigner.signReceipt("deadbeef", 1),
      ).rejects.toThrow(/KMS service temporarily unavailable/);
    });

    it("adversarial error code mapping: maps GCP FAILED_PRECONDITION and CRC32C corruption to fail-closed error codes", async () => {
      const keyPair = generateKeyPairSync("ed25519");
      const { spkiPem, fingerprint } = computeCanonicalFingerprint(keyPair.publicKey);
      const gcpKeyName =
        "projects/test-proj/locations/us-central1/keyRings/ring-1/cryptoKeys/key-1/cryptoKeyVersions/1";

      // 1. FAILED_PRECONDITION during initialization (key version destroyed or disabled)
      const destroyedGcpClient: any = {
        getCryptoKeyVersion: async () => [
          {
            name: gcpKeyName,
            state: "DESTROYED",
            protectionLevel: "SOFTWARE",
            algorithm: "EC_SIGN_ED25519",
          },
        ],
        getPublicKey: async () => [
          {
            name: gcpKeyName,
            algorithm: "EC_SIGN_ED25519",
            pem: spkiPem,
            pemCrc32c: { value: calculateCrc32c(Buffer.from(spkiPem, "utf8")) },
          },
        ],
      };

      const destroyedSigner = new GcpKmsWitnessSigner(
        {
          provider: "gcp",
          witnessId: "wit-destroyed",
          keyVersionName: gcpKeyName,
          expectedKeyFingerprint: fingerprint,
        },
        destroyedGcpClient,
      );

      await expect(destroyedSigner.initialize()).rejects.toThrow(KmsKeyValidationError);
      expect(destroyedSigner.getState()).toBe("FAILED");

      // 2. CRC32C corruption in GCP getPublicKey response
      const corruptCrcGcpClient: any = {
        getCryptoKeyVersion: async () => [
          {
            name: gcpKeyName,
            state: "ENABLED",
            protectionLevel: "SOFTWARE",
            algorithm: "EC_SIGN_ED25519",
          },
        ],
        getPublicKey: async () => [
          {
            name: gcpKeyName,
            algorithm: "EC_SIGN_ED25519",
            pem: spkiPem,
            pemCrc32c: { value: 999999999 }, // Corrupted CRC32C
          },
        ],
      };

      const corruptCrcSigner = new GcpKmsWitnessSigner(
        {
          provider: "gcp",
          witnessId: "wit-crc-corrupt",
          keyVersionName: gcpKeyName,
          expectedKeyFingerprint: fingerprint,
        },
        corruptCrcGcpClient,
      );

      await expect(corruptCrcSigner.initialize()).rejects.toThrow(/CRC32C checksum mismatch/);
      expect(corruptCrcSigner.getState()).toBe("FAILED");
    });
  });
});
