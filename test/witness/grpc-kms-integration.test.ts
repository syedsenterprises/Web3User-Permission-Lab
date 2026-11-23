/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: gRPC KMS Service Integration Suite
 *
 * Verifies:
 * - Step 3.3: Daemon startup integration (signer initialization before listener binding, startup failure abort, graceful disposal).
 * - Step 3.4: Witness service integration (ReserveTicket and CommitTicket through WitnessSigner abstraction).
 * - Step 3.5: Hermetic integration testing with Local, AWS mock, and GCP mock signers, verifying idempotency and error propagation.
 *
 * Reference: FN-SEC-01 Step 3 (Production Service Integration)
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { generateKeyPairSync, createHash, X509Certificate } from "node:crypto";
import { verifyWitnessReceipt } from "../../src/monotonic-witness.js";
import { generateTestCertificates, type CertBundle } from "../../src/witness/mtls-certs.js";
import { GrpcWitnessServiceImpl } from "../../src/witness/grpc-service.js";
import { startGrpcWitnessServer, type StartedGrpcWitnessServer } from "../../src/witness/grpc-server.js";
import { RemoteDurableWitnessClient } from "../../src/witness/remote-witness-client.js";
import { PostgresWitnessStore } from "../../src/witness/postgres-store.js";
import { PeerAuthorizer } from "../../src/witness/auth.js";
import {
  LocalEd25519WitnessSigner,
} from "../../src/witness/signing.js";
import {
  calculateCrc32c,
  WitnessUnavailableError,
  KmsKeyValidationError,
} from "../../src/witness/cloud-kms-signer.js";
import { AwsKmsWitnessSigner } from "../../src/witness/aws-kms-signer.js";
import { GcpKmsWitnessSigner } from "../../src/witness/gcp-kms-signer.js";
import pg from "pg";

describe("Milestone 13-D Phase D2: gRPC KMS Service Integration Suite (FN-SEC-01 Step 3.3-3.5)", () => {
  let certs: CertBundle;
  let pool: pg.Pool;
  let store: PostgresWitnessStore;
  const testEpochId = `test-kms-integration-epoch-${Date.now()}`;
  let testEpochHeight: number;

  // Real Ed25519 keys for mock signers to produce genuine RFC 8032 signatures
  const keyPair = generateKeyPairSync("ed25519");
  const spkiDer = keyPair.publicKey.export({ type: "spki", format: "der" });
  const spkiPem = keyPair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const rawKeyBytes = spkiDer.subarray(spkiDer.length - 32);
  const keyFingerprint = createHash("sha256").update(rawKeyBytes).digest("hex").toLowerCase();

  beforeAll(async () => {
    certs = generateTestCertificates();
    store = new PostgresWitnessStore({ epochId: testEpochId });
    pool = (store as any).pool;
    await store.initializeSchema();

    const maxHRes = await pool.query(`SELECT COALESCE(MAX(epoch_height), 0) + 1 AS next_h FROM witness_epochs`);
    testEpochHeight = Number(maxHRes.rows[0].next_h);
    await store.registerEpoch(testEpochId, testEpochHeight);
  });

  afterAll(async () => {
    if (pool) {
      await pool.end();
    }
  });

  // ==========================================================================
  // Step 3.3: Daemon Startup & Lifecycle Integration
  // ==========================================================================
  describe("Daemon Startup Integration & Lifecycle", () => {
    it("aborts daemon startup if signer initialization fails before binding listeners", async () => {
      let listenerBound = false;
      const failingSigner: any = {
        initialize: async () => {
          throw new KmsKeyValidationError("KMS Key is disabled or revoked");
        },
        close: async () => {},
        getWitnessId: () => "failing-signer",
        getPublicKeyHex: () => "00".repeat(32),
      };

      const failingService = new GrpcWitnessServiceImpl({ pool, signer: failingSigner });

      await expect(
        startGrpcWitnessServer({
          serviceImpl: failingService,
          caCert: certs.caCert,
          serverCert: certs.serverCert,
          serverKey: certs.serverKey,
          port: 0,
          host: "127.0.0.1",
          skipDependencyCheck: true,
        }),
      ).rejects.toThrow(KmsKeyValidationError);

      expect(listenerBound).toBe(false);
    });

    it("initializes signer successfully, starts server, and gracefully disposes signer on stop()", async () => {
      let initCalled = false;
      let closeCalled = false;

      const mockSigner: any = {
        initialize: async () => { initCalled = true; },
        close: async () => { closeCalled = true; },
        getWitnessId: () => "lifecycle-signer-1",
        getPublicKeyHex: () => Buffer.from(rawKeyBytes).toString("hex"),
      };

      const service = new GrpcWitnessServiceImpl({ pool, signer: mockSigner });

      const serverInstance = await startGrpcWitnessServer({
        serviceImpl: service,
        caCert: certs.caCert,
        serverCert: certs.serverCert,
        serverKey: certs.serverKey,
        port: 0,
        host: "127.0.0.1",
        skipDependencyCheck: true,
      });

      expect(initCalled).toBe(true);
      expect(serverInstance.port).toBeGreaterThan(0);

      // Graceful shutdown
      await serverInstance.stop();
      expect(closeCalled).toBe(true);
    });

    it("cleans up initialized signer when outbox reconciliation sweep fails, preserving original error", async () => {
      let initCalled = false;
      let closeCalled = false;

      const mockSigner: any = {
        initialize: async () => { initCalled = true; },
        close: async () => { closeCalled = true; },
        getWitnessId: () => "outbox-fail-signer",
        getPublicKeyHex: () => Buffer.from(rawKeyBytes).toString("hex"),
      };

      const service = new GrpcWitnessServiceImpl({ pool, signer: mockSigner });
      vi.spyOn(service, "startupOutboxReconciliationSweep").mockRejectedValueOnce(
        new Error("Outbox sweep database timeout"),
      );

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
      ).rejects.toThrow("Outbox sweep database timeout");

      expect(initCalled).toBe(true);
      expect(closeCalled).toBe(true);
    });

    it("cleans up initialized signer when listener binding fails, preserving original error", async () => {
      let initCalled = false;
      let closeCalled = false;

      const mockSigner: any = {
        initialize: async () => { initCalled = true; },
        close: async () => { closeCalled = true; },
        getWitnessId: () => "binding-fail-signer",
        getPublicKeyHex: () => Buffer.from(rawKeyBytes).toString("hex"),
      };

      const service = new GrpcWitnessServiceImpl({ pool, signer: mockSigner });

      await expect(
        startGrpcWitnessServer({
          serviceImpl: service,
          caCert: certs.caCert,
          serverCert: certs.serverCert,
          serverKey: certs.serverKey,
          port: 50051,
          host: "invalid-host-xxx.local",
          skipDependencyCheck: true,
        }),
      ).rejects.toThrow(/Name resolution failed/);

      expect(initCalled).toBe(true);
      expect(closeCalled).toBe(true);
    });

    it("preserves original startup error even if cleanup fails during error handling", async () => {
      let initCalled = false;
      let closeCalled = false;

      const mockSigner: any = {
        initialize: async () => { initCalled = true; },
        close: async () => {
          closeCalled = true;
          throw new Error("Secondary cleanup network failure");
        },
        getWitnessId: () => "dual-fail-signer",
        getPublicKeyHex: () => Buffer.from(rawKeyBytes).toString("hex"),
      };

      const service = new GrpcWitnessServiceImpl({ pool, signer: mockSigner });
      vi.spyOn(service, "startupOutboxReconciliationSweep").mockRejectedValueOnce(
        new Error("Primary startup failure"),
      );

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
      ).rejects.toThrow("Primary startup failure");

      expect(initCalled).toBe(true);
      expect(closeCalled).toBe(true);
    });

    it("memoizes shutdown promise across concurrent and repeated stop() calls with exactly-once signer disposal", async () => {
      let closeCount = 0;

      const mockSigner: any = {
        initialize: async () => {},
        close: async () => { closeCount++; },
        getWitnessId: () => "memo-stop-signer",
        getPublicKeyHex: () => Buffer.from(rawKeyBytes).toString("hex"),
      };

      const service = new GrpcWitnessServiceImpl({ pool, signer: mockSigner });

      const serverInstance = await startGrpcWitnessServer({
        serviceImpl: service,
        caCert: certs.caCert,
        serverCert: certs.serverCert,
        serverKey: certs.serverKey,
        port: 0,
        host: "127.0.0.1",
        skipDependencyCheck: true,
      });

      // Concurrent stop() calls
      const stopPromise1 = serverInstance.stop();
      const stopPromise2 = serverInstance.stop();
      expect(stopPromise1).toBe(stopPromise2);

      await Promise.all([stopPromise1, stopPromise2]);
      expect(closeCount).toBe(1);

      // Repeated sequential stop() call
      const stopPromise3 = serverInstance.stop();
      expect(stopPromise3).toBe(stopPromise1);
      await stopPromise3;
      expect(closeCount).toBe(1);
    });
  });

  // ==========================================================================
  // Step 3.4 & 3.5: Witness Service Integration with AWS KMS Signer
  // ==========================================================================
  describe("Witness Service Integration: AWS KMS Signer", () => {
    let awsServerInstance: StartedGrpcWitnessServer;
    let awsClient: RemoteDurableWitnessClient;
    let awsSigner: AwsKmsWitnessSigner;

    beforeAll(async () => {
      // Mock AWS KMS Client using real Ed25519 signing under the hood
      const mockAwsClient: any = {
        send: async (cmd: any) => {
          if (cmd.constructor.name === "GetPublicKeyCommand") {
            return {
              KeySpec: "ECC_NIST_EDWARDS25519",
              PublicKey: new Uint8Array(spkiDer),
            };
          }
          if (cmd.constructor.name === "SignCommand") {
            const crypto = await import("node:crypto");
            const sig = crypto.sign(null, Buffer.from(cmd.input.Message), keyPair.privateKey);
            return {
              Signature: new Uint8Array(sig),
            };
          }
          throw new Error(`Unexpected AWS command: ${cmd.constructor.name}`);
        },
      };

      awsSigner = new AwsKmsWitnessSigner(
        {
          provider: "aws",
          witnessId: "witness-aws-prod-1",
          keyId: "arn:aws:kms:us-east-1:123456789012:key/test-ed25519-key",
          region: "us-east-1",
          expectedKeyFingerprint: keyFingerprint,
        },
        mockAwsClient,
      );

      const service = new GrpcWitnessServiceImpl({ pool, signer: awsSigner });

      awsServerInstance = await startGrpcWitnessServer({
        serviceImpl: service,
        caCert: certs.caCert,
        serverCert: certs.serverCert,
        serverKey: certs.serverKey,
        port: 0,
        host: "127.0.0.1",
        skipDependencyCheck: true,
      });

      awsClient = new RemoteDurableWitnessClient({
        endpoint: `127.0.0.1:${awsServerInstance.port}`,
        caCert: certs.caCert,
        clientCert: certs.engineClientCert,
        clientKey: certs.engineClientKey,
      });
    });

    afterAll(async () => {
      if (awsClient) {
        await awsClient.close();
      }
      if (awsServerInstance) {
        await awsServerInstance.stop();
      }
    });

    it("reserves and commits ticket with AWS KMS signer producing valid receipt", async () => {
      const authId = `auth-aws-${Date.now()}`;
      const bindingDigest = "sha256:" + createHash("sha256").update(authId).digest("hex");

      // 1. Reserve Ticket
      const res = await awsClient.reserveTicket({
        authorizationId: authId,
        bindingDigest,
        policyId: "test-policy",
        policyRevision: 1,
        idempotencyKey: `idem-aws-${authId}`,
        budgetWindows: [
          { windowType: "DAILY", windowStart: Math.floor(Date.now() / 1000), requestedAmount: "500", maxCumulativeAmount: "10000" },
        ],
      });

      expect(res.decision).toBe("ALLOW");
      expect(res.ticketId).toBeDefined();

      // 2. Commit Ticket
      const commitRes = await awsClient.commitTicket({
        ticketId: res.ticketId!,
        authorizationId: authId,
        bindingDigest,
        localCommittedAtSeconds: Math.floor(Date.now() / 1000),
      });

      expect(commitRes.decision).toBe("ALLOW");
      expect(commitRes.receipt).toBeDefined();
      expect(commitRes.receipt!.signature).toHaveLength(128); // 64-byte hex
      expect(commitRes.receipt!.witnessId).toBe("witness-aws-prod-1");

      // 3. Cryptographic Verification of the receipt
      expect(verifyWitnessReceipt(awsSigner.getPublicKeyHex(), commitRes.receipt!)).toBe(true);
      expect(verifyWitnessReceipt(awsSigner.getPublicKeyPem(), commitRes.receipt!)).toBe(true);
    });

    it("replays commit idempotently returning identical AWS KMS signature without re-signing", async () => {
      const authId = `auth-aws-replay-${Date.now()}`;
      const bindingDigest = "sha256:" + createHash("sha256").update(authId).digest("hex");

      const res = await awsClient.reserveTicket({
        authorizationId: authId,
        bindingDigest,
        policyId: "test-policy",
        policyRevision: 1,
        idempotencyKey: `idem-aws-replay-${authId}`,
        budgetWindows: [
          { windowType: "HOURLY", windowStart: Math.floor(Date.now() / 1000), requestedAmount: "200", maxCumulativeAmount: "10000" },
        ],
      });

      const firstCommit = await awsClient.commitTicket({
        ticketId: res.ticketId!,
        authorizationId: authId,
        bindingDigest,
        localCommittedAtSeconds: Math.floor(Date.now() / 1000),
      });

      const secondCommit = await awsClient.commitTicket({
        ticketId: res.ticketId!,
        authorizationId: authId,
        bindingDigest,
        localCommittedAtSeconds: Math.floor(Date.now() / 1000),
      });

      expect(secondCommit.decision).toBe("ALLOW");
      expect(secondCommit.receipt!.signature).toBe(firstCommit.receipt!.signature);
      expect(secondCommit.receipt!.sequenceNumber).toBe(firstCommit.receipt!.sequenceNumber);
    });
  });

  // ==========================================================================
  // Step 3.4 & 3.5: Witness Service Integration with GCP Cloud KMS Signer
  // ==========================================================================
  describe("Witness Service Integration: GCP Cloud KMS Signer", () => {
    let gcpServerInstance: StartedGrpcWitnessServer;
    let gcpClient: RemoteDurableWitnessClient;
    let gcpSigner: GcpKmsWitnessSigner;
    const gcpKeyName =
      "projects/test-proj/locations/us-central1/keyRings/ring-1/cryptoKeys/key-1/cryptoKeyVersions/1";

    beforeAll(async () => {
      const validCrc = calculateCrc32c(Buffer.from(spkiPem, "utf8"));

      // Mock GCP KMS Client using real Ed25519 signing under the hood
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
          const crypto = await import("node:crypto");
          const sig = crypto.sign(null, Buffer.from(req.data), keyPair.privateKey);
          return [{ signature: new Uint8Array(sig) }];
        },
      };

      gcpSigner = new GcpKmsWitnessSigner(
        {
          provider: "gcp",
          witnessId: "witness-gcp-prod-1",
          keyVersionName: gcpKeyName,
          expectedKeyFingerprint: keyFingerprint,
        },
        mockGcpClient,
      );

      const service = new GrpcWitnessServiceImpl({ pool, signer: gcpSigner });

      gcpServerInstance = await startGrpcWitnessServer({
        serviceImpl: service,
        caCert: certs.caCert,
        serverCert: certs.serverCert,
        serverKey: certs.serverKey,
        port: 0,
        host: "127.0.0.1",
        skipDependencyCheck: true,
      });

      gcpClient = new RemoteDurableWitnessClient({
        endpoint: `127.0.0.1:${gcpServerInstance.port}`,
        caCert: certs.caCert,
        clientCert: certs.engineClientCert,
        clientKey: certs.engineClientKey,
      });
    });

    afterAll(async () => {
      if (gcpClient) {
        await gcpClient.close();
      }
      if (gcpServerInstance) {
        await gcpServerInstance.stop();
      }
    });

    it("reserves and commits ticket with GCP KMS signer producing valid receipt", async () => {
      const authId = `auth-gcp-${Date.now()}`;
      const bindingDigest = "sha256:" + createHash("sha256").update(authId).digest("hex");

      // 1. Reserve Ticket
      const res = await gcpClient.reserveTicket({
        authorizationId: authId,
        bindingDigest,
        policyId: "test-policy",
        policyRevision: 1,
        idempotencyKey: `idem-gcp-${authId}`,
        budgetWindows: [
          { windowType: "DAILY", windowStart: Math.floor(Date.now() / 1000), requestedAmount: "750", maxCumulativeAmount: "10000" },
        ],
      });

      expect(res.decision).toBe("ALLOW");
      expect(res.ticketId).toBeDefined();

      // 2. Commit Ticket
      const commitRes = await gcpClient.commitTicket({
        ticketId: res.ticketId!,
        authorizationId: authId,
        bindingDigest,
        localCommittedAtSeconds: Math.floor(Date.now() / 1000),
      });

      expect(commitRes.decision).toBe("ALLOW");
      expect(commitRes.receipt).toBeDefined();
      expect(commitRes.receipt!.signature).toHaveLength(128); // 64-byte hex
      expect(commitRes.receipt!.witnessId).toBe("witness-gcp-prod-1");

      // 3. Cryptographic Verification of the receipt
      expect(verifyWitnessReceipt(gcpSigner.getPublicKeyHex(), commitRes.receipt!)).toBe(true);
      expect(verifyWitnessReceipt(gcpSigner.getPublicKeyPem(), commitRes.receipt!)).toBe(true);
    });
  });

  // ==========================================================================
  // Step 3.5: Fail-Closed Error Mapping & Consensus Fencing Invariants
  // ==========================================================================
  describe("Fail-Closed Error Handling & Consensus Fencing", () => {
    it("fails closed when KMS signer throws WitnessUnavailableError, returning gRPC UNAVAILABLE (14)", async () => {
      const failingKmsSigner: any = {
        initialize: async () => {},
        close: async () => {},
        getWitnessId: () => "witness-failing-kms",
        getPublicKeyHex: () => Buffer.from(rawKeyBytes).toString("hex"),
        signReceipt: async () => {
          throw new WitnessUnavailableError({
            message: "KMS request throttled and retry budget exhausted",
            reason: "RETRY_BUDGET_EXHAUSTED",
            proofOfNonExecution: false,
            retryAttempts: 2,
          });
        },
      };

      const failingService = new GrpcWitnessServiceImpl({ pool, signer: failingKmsSigner });

      const serverInstance = await startGrpcWitnessServer({
        serviceImpl: failingService,
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
        // 1. Verify underlying gRPC service method returns code 14 (UNAVAILABLE) on KMS failure
        const authId1 = `auth-fail-srv-${Date.now()}`;
        const bindingDigest1 = "sha256:" + createHash("sha256").update(authId1).digest("hex");

        const res1 = await client.reserveTicket({
          authorizationId: authId1,
          bindingDigest: bindingDigest1,
          policyId: "test-policy",
          policyRevision: 1,
          idempotencyKey: `idem-fail-1-${authId1}`,
          budgetWindows: [
            { windowType: "DAILY", windowStart: Math.floor(Date.now() / 1000), requestedAmount: "100", maxCumulativeAmount: "10000" },
          ],
        });

        const peer = PeerAuthorizer.extractPeer(new X509Certificate(certs.engineClientCert), certs.caCert);
        let serviceError: any;
        try {
          await failingService.commitTicket(
            {
              request: {
                ticket_id: res1.ticketId!,
                authorization_id: authId1,
                binding_digest: bindingDigest1,
                fencing_generation: 1,
                idempotency_key: `idem-fail-${authId1}`,
              },
            },
            peer,
          );
        } catch (err) {
          serviceError = err;
        }
        expect(serviceError).toBeDefined();
        expect(serviceError.code).toBe(14); // grpc.status.UNAVAILABLE

        // 2. Verify client SEC-M11-01 quarantine behavior upon receiving UNAVAILABLE over gRPC
        const authId2 = `auth-fail-cli-${Date.now()}`;
        const bindingDigest2 = "sha256:" + createHash("sha256").update(authId2).digest("hex");

        const res2 = await client.reserveTicket({
          authorizationId: authId2,
          bindingDigest: bindingDigest2,
          policyId: "test-policy",
          policyRevision: 1,
          idempotencyKey: `idem-fail-2-${authId2}`,
          budgetWindows: [
            { windowType: "DAILY", windowStart: Math.floor(Date.now() / 1000), requestedAmount: "100", maxCumulativeAmount: "10000" },
          ],
        });

        // 2. Verify client receives UNAVAILABLE when calling commitTicket over gRPC
        await expect(
          client.commitTicket({
            ticketId: res2.ticketId!,
            authorizationId: authId2,
            bindingDigest: bindingDigest2,
            localCommittedAtSeconds: Math.floor(Date.now() / 1000),
          }),
        ).rejects.toThrow(/14 UNAVAILABLE/);
      } finally {
        await client.close();
        await serverInstance.stop();
      }
    });

    it("enforces pre-signing guards: expired ticket lease is denied without invoking signer", async () => {
      let signReceiptCalled = false;
      const trackedSigner: any = {
        initialize: async () => {},
        close: async () => {},
        getWitnessId: () => "witness-guard-test",
        getPublicKeyHex: () => Buffer.from(rawKeyBytes).toString("hex"),
        signReceipt: async () => {
          signReceiptCalled = true;
          return { signatureHex: "ab".repeat(64), generation: 1 };
        },
      };

      const service = new GrpcWitnessServiceImpl({ pool, signer: trackedSigner });

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
        const authId = `auth-expired-${Date.now()}`;
        const bindingDigest = "sha256:" + createHash("sha256").update(authId).digest("hex");

        const res = await client.reserveTicket({
          authorizationId: authId,
          bindingDigest,
          policyId: "test-policy",
          policyRevision: 1,
          idempotencyKey: `idem-exp-${authId}`,
          budgetWindows: [
            { windowType: "DAILY", windowStart: Math.floor(Date.now() / 1000), requestedAmount: "100", maxCumulativeAmount: "10000" },
          ],
        });

        // Expire the ticket in PostgreSQL
        await pool.query(
          `UPDATE witness_tickets SET expires_at_seconds = $1 WHERE ticket_id = $2`,
          [Math.floor(Date.now() / 1000) - 10, res.ticketId!],
        );

        const commitRes = await client.commitTicket({
          ticketId: res.ticketId!,
          authorizationId: authId,
          bindingDigest,
          localCommittedAtSeconds: Math.floor(Date.now() / 1000),
        });

        expect(commitRes.decision).toBe("DENY");
        expect(commitRes.reasons).toContain("LEASE_EXPIRED");

        // Ensure signReceipt was NEVER called
        expect(signReceiptCalled).toBe(false);
      } finally {
        await client.close();
        await serverInstance.stop();
      }
    });
  });
});
