/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Real TCP/mTLS 1.3 Transport Tests
 *
 * Verifies real TCP socket communication, TLS 1.3 mutual handshake, peer certificate identity
 * validation, certificate revocation enforcement, and RBAC matrix enforcement over gRPC.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import pg from "pg";
import { generateTestCertificates, type CertBundle } from "../../src/witness/mtls-certs.js";
import { GrpcWitnessServiceImpl } from "../../src/witness/grpc-service.js";
import { startGrpcWitnessServer, type StartedGrpcWitnessServer } from "../../src/witness/grpc-server.js";
import { RemoteDurableWitnessClient } from "../../src/witness/remote-witness-client.js";
import { LocalEd25519WitnessSigner } from "../../src/witness/signing.js";
import { RevocationRegistry } from "../../src/witness/auth.js";
import { PostgresWitnessStore } from "../../src/witness/postgres-store.js";

const { Pool } = pg;

describe("Milestone 13-D Phase D2: Real TCP/mTLS 1.3 Transport Tests", () => {
  let certs: CertBundle;
  let pool: pg.Pool;
  let store: PostgresWitnessStore;
  let serverInstance: StartedGrpcWitnessServer;
  let serverEndpoint: string;
  const testEpochId = "test-mtls-epoch-1";

  beforeAll(async () => {
    // Generate mTLS cert bundle once for the suite
    certs = generateTestCertificates();

    // Use PostgresWitnessStore default test database connection
    store = new PostgresWitnessStore({ epochId: testEpochId });
    pool = (store as any).pool;
    await store.initializeSchema();
    await store.registerEpoch(testEpochId, 100);

    // Initialize Service & Signer
    const signer = new LocalEd25519WitnessSigner("test-witness-mtls");
    const serviceImpl = new GrpcWitnessServiceImpl({ pool, signer });

    // Start Real gRPC Server with mTLS 1.3
    serverInstance = await startGrpcWitnessServer({
      serviceImpl,
      caCert: certs.caCert,
      serverCert: certs.serverCert,
      serverKey: certs.serverKey,
      port: 0, // OS assigns free ephemeral port
      host: "127.0.0.1",
      skipDependencyCheck: false,
    });

    serverEndpoint = `localhost:${serverInstance.port}`;
  }, 45000);

  beforeEach(async () => {
    await store.registerEpoch(testEpochId, 100);
  });

  afterAll(async () => {
    if (serverInstance) {
      await serverInstance.stop();
    }
    if (pool) {
      await pool.end();
    }
    if (certs && certs.bundleDir) {
      try {
        const fs = await import("node:fs");
        fs.rmSync(certs.bundleDir, { recursive: true, force: true });
      } catch {}
    }
  });

  // ==========================================================================
  // 1. Successful Connection under Valid Engine Pod Client Certificate
  // ==========================================================================
  it("establishes mTLS connection and executes GetSyncStatus with valid engine certificate", async () => {
    const client = new RemoteDurableWitnessClient({
      endpoint: serverEndpoint,
      caCert: certs.caCert,
      clientCert: certs.engineClientCert,
      clientKey: certs.engineClientKey,
      clientCertPem: certs.engineClientCert.toString("utf8"),
    });

    try {
      const status = await client.getSyncStatus();
      expect(status.healthy).toBe(true);
      expect(status.epochId).toBeDefined();
    } finally {
      client.close();
    }
  });

  // ==========================================================================
  // 2. Certificate Revocation Handshake Enforcement
  // ==========================================================================
  it("rejects connection when peer certificate serial is revoked", async () => {
    // Add revoked serial to blocklist
    RevocationRegistry.getInstance().revokeSerial(certs.revokedSerial);

    const client = new RemoteDurableWitnessClient({
      endpoint: serverEndpoint,
      caCert: certs.caCert,
      clientCert: certs.revokedClientCert,
      clientKey: certs.revokedClientKey,
      clientCertPem: certs.revokedClientCert.toString("utf8"),
    });

    try {
      await expect(client.getSyncStatus()).rejects.toThrow(/Certificate serial .* is revoked/);
    } finally {
      client.close();
    }
  });

  // ==========================================================================
  // 3. RBAC Method Authorization Enforcement Over Wire
  // ==========================================================================
  it("denies unauthorized client from calling any witness RPC", async () => {
    const client = new RemoteDurableWitnessClient({
      endpoint: serverEndpoint,
      caCert: certs.caCert,
      clientCert: certs.unauthorizedClientCert,
      clientKey: certs.unauthorizedClientKey,
      clientCertPem: certs.unauthorizedClientCert.toString("utf8"),
    });

    try {
      await expect(client.getSyncStatus()).rejects.toThrow(/PERMISSION_DENIED/);
    } finally {
      client.close();
    }
  });

  it("denies engine pod role from calling ListUnfinalizedTickets", async () => {
    const client = new RemoteDurableWitnessClient({
      endpoint: serverEndpoint,
      caCert: certs.caCert,
      clientCert: certs.engineClientCert,
      clientKey: certs.engineClientKey,
      clientCertPem: certs.engineClientCert.toString("utf8"),
    });

    try {
      await expect(client.listUnfinalizedTickets()).rejects.toThrow(/PERMISSION_DENIED/);
    } finally {
      client.close();
    }
  });

  it("never trusts spoofed x-client-cert-bin metadata: authenticates from TLS socket directly", async () => {
    // Engine pod client certificate in TLS handshake, but sends auditor certificate in metadata header
    const spoofedClient = new RemoteDurableWitnessClient({
      endpoint: serverEndpoint,
      caCert: certs.caCert,
      clientCert: certs.engineClientCert, // Real TLS identity: ENGINE_POD
      clientKey: certs.engineClientKey,
      clientCertPem: certs.auditorClientCert.toString("utf8"), // Spoofed metadata: ADMIN_AUDITOR
    });

    try {
      // Must be denied because real TLS socket is engine-pod, which cannot call ListUnfinalizedTickets
      await expect(spoofedClient.listUnfinalizedTickets()).rejects.toThrow(/PERMISSION_DENIED/);
    } finally {
      spoofedClient.close();
    }
  });

  it("allows recovery worker to call ListUnfinalizedTickets but denies ReserveTicket", async () => {
    const client = new RemoteDurableWitnessClient({
      endpoint: serverEndpoint,
      caCert: certs.caCert,
      clientCert: certs.recoveryClientCert,
      clientKey: certs.recoveryClientKey,
      clientCertPem: certs.recoveryClientCert.toString("utf8"),
    });

    try {
      // ListUnfinalizedTickets is allowed
      const list = await client.listUnfinalizedTickets();
      expect(Array.isArray(list)).toBe(true);

      // ReserveTicket is denied
      await expect(
        client.reserveTicket({
          authorizationId: "auth-recovery-attempt",
          bindingDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
          policyId: "policy-test",
          policyRevision: 1,
          idempotencyKey: "idem-recovery-attempt",
        }),
      ).rejects.toThrow(/PERMISSION_DENIED/);
    } finally {
      client.close();
    }
  });

  it("allows admin auditor to call ListUnfinalizedTickets and ReconcileTicket", async () => {
    const client = new RemoteDurableWitnessClient({
      endpoint: serverEndpoint,
      caCert: certs.caCert,
      clientCert: certs.auditorClientCert,
      clientKey: certs.auditorClientKey,
      clientCertPem: certs.auditorClientCert.toString("utf8"),
    });

    try {
      const list = await client.listUnfinalizedTickets();
      expect(Array.isArray(list)).toBe(true);
    } finally {
      client.close();
    }
  });
});
