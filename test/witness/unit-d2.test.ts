/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Unit Verification Suite
 *
 * Tests:
 * 1. DependencyPinValidator (Version verification, prototype shapes, fail-closed drift).
 * 2. PostgresConnectionDisposalAdapter (Socket severing, pool eviction, disposal confirmation).
 * 3. IdempotencyFingerprinter (Deterministic ordering, payload mismatch detection).
 * 4. PeerAuthorizer & RBAC (SPIFFE URIs, roles, method authorization, ticket ownership).
 * 5. RevocationRegistry (30-second freshness bound, fail-closed outage, revoked serials).
 * 6. LocalEpochCircuitBreaker (4 regimes: transient, persistent contention, db down, integrity).
 */

import { describe, it, expect, beforeEach } from "vitest";
import { X509Certificate } from "node:crypto";
import { DependencyPinValidator } from "../../src/witness/dependency-validator.js";
import { PostgresConnectionDisposalAdapter } from "../../src/witness/disposal-adapter.js";
import { IdempotencyFingerprinter } from "../../src/witness/idempotency.js";
import {
  PeerAuthorizer,
  RevocationRegistry,
  WitnessRole,
} from "../../src/witness/auth.js";
import {
  LocalEpochCircuitBreaker,
  CircuitState,
} from "../../src/witness/circuit-breaker.js";
import { generateTestCertificates } from "../../src/witness/mtls-certs.js";
import { LocalEd25519WitnessSigner } from "../../src/witness/signing.js";

describe("Milestone 13-D Phase D2: Unit Verification Suite", () => {
  // ==========================================================================
  // 1. DependencyPinValidator Tests
  // ==========================================================================
  describe("DependencyPinValidator", () => {
    it("asserts installed driver versions match exact pins (pg@8.23.1, pg-pool@3.14.0)", () => {
      expect(() => {
        DependencyPinValidator.assertPinnedDependencies();
      }).not.toThrow();
    });

    it("verifies expected constants", () => {
      expect(DependencyPinValidator.EXPECTED_PG_VERSION).toBe("8.23.1");
      expect(DependencyPinValidator.EXPECTED_PG_POOL_VERSION).toBe("3.14.0");
    });
  });

  // ==========================================================================
  // 2. PostgresConnectionDisposalAdapter Tests
  // ==========================================================================
  describe("PostgresConnectionDisposalAdapter", () => {
    it("severs raw socket, evicts client from pool, and confirms disposal", () => {
      let streamDestroyed = false;
      let streamWritable = true;
      let clientEnded = false;
      let clientReleased = false;

      const mockStream = {
        get destroyed() {
          return streamDestroyed;
        },
        get writable() {
          return streamWritable;
        },
        destroy() {
          streamDestroyed = true;
          streamWritable = false;
        },
      };

      const mockClient: any = {
        connection: { stream: mockStream },
        _queryable: true,
        release: (err: any) => {
          clientReleased = true;
          mockClient._queryable = false;
          // pg-pool invokes _remove
          mockPool._remove(mockClient);
        },
        end: () => {
          clientEnded = true;
        },
      };

      const mockPool: any = {
        _clients: [mockClient],
        _idle: [],
        _remove: (c: any) => {
          mockPool._clients = mockPool._clients.filter((client: any) => client !== c);
          c.end();
        },
        end: async () => {},
      };

      const confirmation = PostgresConnectionDisposalAdapter.emergencyEvictAndDestroy(
        mockPool,
        mockClient,
        new Error("TEST_ACTIVE_QUERY_CANCELLED"),
      );

      expect(confirmation.socketDestroyed).toBe(true);
      expect(confirmation.poolClientEvicted).toBe(true);
      expect(confirmation.activeQueryAborted).toBe(true);
      expect(mockStream.destroyed).toBe(true);
      expect(mockPool._clients).not.toContain(mockClient);
      expect(clientReleased).toBe(true);
      expect(clientEnded).toBe(true);
    });
  });

  // ==========================================================================
  // 3. IdempotencyFingerprinter Tests
  // ==========================================================================
  describe("IdempotencyFingerprinter", () => {
    it("computes identical fingerprint for identical reserve request regardless of budget window ordering", () => {
      const fp1 = IdempotencyFingerprinter.computeReserveFingerprint({
        authorizationId: "auth-123",
        bindingDigest: "sha256:aaaa",
        policyId: "policy-1",
        policyRevision: 1,
        idempotencyKey: "key-1",
        budgetWindows: [
          { windowType: "DAILY", windowStartSeconds: 100, requestedAmount: "50" },
          { windowType: "HOURLY", windowStartSeconds: 200, requestedAmount: "20" },
        ],
      });

      const fp2 = IdempotencyFingerprinter.computeReserveFingerprint({
        authorizationId: "auth-123",
        bindingDigest: "sha256:aaaa",
        policyId: "policy-1",
        policyRevision: 1,
        idempotencyKey: "key-1",
        budgetWindows: [
          { windowType: "HOURLY", windowStartSeconds: 200, requestedAmount: "20" },
          { windowType: "DAILY", windowStartSeconds: 100, requestedAmount: "50" },
        ],
      });

      expect(fp1).toBe(fp2);
      expect(fp1.length).toBe(64);
    });

    it("produces distinct fingerprint when payload changes under same idempotency key", () => {
      const fp1 = IdempotencyFingerprinter.computeReserveFingerprint({
        authorizationId: "auth-123",
        bindingDigest: "sha256:aaaa",
        idempotencyKey: "key-1",
      });

      const fp2 = IdempotencyFingerprinter.computeReserveFingerprint({
        authorizationId: "auth-999", // Different auth ID!
        bindingDigest: "sha256:aaaa",
        idempotencyKey: "key-1",
      });

      expect(fp1).not.toBe(fp2);
    });

    it("computes deterministic commit and release fingerprints", () => {
      const commitFp = IdempotencyFingerprinter.computeCommitFingerprint({
        ticketId: "t-1",
        authorizationId: "auth-1",
        bindingDigest: "sha256:bbbb",
        idempotencyKey: "commit-key-1",
      });
      expect(commitFp.length).toBe(64);

      const releaseFp = IdempotencyFingerprinter.computeReleaseFingerprint({
        ticketId: "t-1",
        authorizationId: "auth-1",
        bindingDigest: "sha256:bbbb",
        reason: "User cancelled",
        idempotencyKey: "rel-key-1",
      });
      expect(releaseFp.length).toBe(64);
    });
  });

  // ==========================================================================
  // 4. PeerAuthorizer & RBAC Tests
  // ==========================================================================
  describe("PeerAuthorizer & RBAC Matrix", () => {
    let certs: ReturnType<typeof generateTestCertificates>;

    beforeEach(() => {
      RevocationRegistry.getInstance().reset();
      certs = generateTestCertificates();
    });

    it("extracts SPIFFE ID and maps to ENGINE_POD role", () => {
      const peer = PeerAuthorizer.extractPeer(certs.engineClientCert, certs.caCert);
      expect(peer.role).toBe(WitnessRole.ENGINE_POD);
      expect(peer.identity).toBe(
        "spiffe://web3user.internal/ns/engine/sa/engine-pod-worker",
      );
    });

    it("rejects forged self-signed certificate when verified against Root CA", () => {
      // Use another generated CA bundle to simulate an attacker's self-signed / unauthorized cert
      const attackerBundle = generateTestCertificates();
      expect(() => {
        PeerAuthorizer.extractPeer(attackerBundle.engineClientCert, certs.caCert);
      }).toThrow(/UNAUTHENTICATED: Certificate signature cannot be verified against trusted Witness CA/);
    });

    it("rejects malformed peer certificates cleanly without unhandled parser crash", () => {
      expect(() => {
        PeerAuthorizer.extractPeer("NOT_A_VALID_PEM_CERTIFICATE", certs.caCert);
      }).toThrow(/UNAUTHENTICATED: Invalid X.509 peer certificate format/);
    });

    it("extracts recovery worker identity and maps to RECOVERY_WORKER role", () => {
      const peer = PeerAuthorizer.extractPeer(certs.recoveryClientCert);
      expect(peer.role).toBe(WitnessRole.RECOVERY_WORKER);
    });

    it("extracts admin auditor identity and maps to ADMIN_AUDITOR role", () => {
      const peer = PeerAuthorizer.extractPeer(certs.auditorClientCert);
      expect(peer.role).toBe(WitnessRole.ADMIN_AUDITOR);
    });

    it("maps unrecognized SPIFFE ID to UNAUTHORIZED_CLIENT role", () => {
      const peer = PeerAuthorizer.extractPeer(certs.unauthorizedClientCert);
      expect(peer.role).toBe(WitnessRole.UNAUTHORIZED_CLIENT);
    });

    it("enforces RBAC matrix: engine-pod allowed mutating RPCs but denied ListUnfinalizedTickets", () => {
      const peer = PeerAuthorizer.extractPeer(certs.engineClientCert);

      expect(() => PeerAuthorizer.assertRolePermission(peer, "GetSyncStatus")).not.toThrow();
      expect(() => PeerAuthorizer.assertRolePermission(peer, "ReserveTicket")).not.toThrow();
      expect(() => PeerAuthorizer.assertRolePermission(peer, "CommitTicket")).not.toThrow();
      expect(() => PeerAuthorizer.assertRolePermission(peer, "ReleaseTicket")).not.toThrow();
      expect(() => PeerAuthorizer.assertRolePermission(peer, "ReconcileTicket")).not.toThrow();

      // ListUnfinalizedTickets DENIED to regular engine pod
      expect(() =>
        PeerAuthorizer.assertRolePermission(peer, "ListUnfinalizedTickets"),
      ).toThrow(/PERMISSION_DENIED/);
    });

    it("enforces RBAC matrix: recovery worker allowed ListUnfinalizedTickets but denied Reserve/Commit", () => {
      const peer = PeerAuthorizer.extractPeer(certs.recoveryClientCert);

      expect(() => PeerAuthorizer.assertRolePermission(peer, "GetSyncStatus")).not.toThrow();
      expect(() => PeerAuthorizer.assertRolePermission(peer, "ListUnfinalizedTickets")).not.toThrow();
      expect(() => PeerAuthorizer.assertRolePermission(peer, "ReconcileTicket")).not.toThrow();

      expect(() => PeerAuthorizer.assertRolePermission(peer, "ReserveTicket")).toThrow(
        /PERMISSION_DENIED/,
      );
      expect(() => PeerAuthorizer.assertRolePermission(peer, "CommitTicket")).toThrow(
        /PERMISSION_DENIED/,
      );
    });

    it("enforces ticket ownership: rejects commit/release by different engine identity", () => {
      const engine1 = PeerAuthorizer.extractPeer(certs.engineClientCert);
      const engine2 = PeerAuthorizer.extractPeer(certs.engine2ClientCert);

      // Same engine: allowed
      expect(() =>
        PeerAuthorizer.assertTicketOwnership(engine1, engine1.identity),
      ).not.toThrow();

      // Different engine: denied
      expect(() =>
        PeerAuthorizer.assertTicketOwnership(engine2, engine1.identity),
      ).toThrow(/PERMISSION_DENIED: Caller identity .* does not own ticket/);

      // Recovery worker or admin: allowed to reconcile any ticket
      const recovery = PeerAuthorizer.extractPeer(certs.recoveryClientCert);
      expect(() =>
        PeerAuthorizer.assertTicketOwnership(recovery, engine1.identity),
      ).not.toThrow();
    });
  });

  // ==========================================================================
  // 5. RevocationRegistry Tests
  // ==========================================================================
  describe("RevocationRegistry", () => {
    let certs: ReturnType<typeof generateTestCertificates>;
    let registry: RevocationRegistry;

    beforeEach(() => {
      registry = RevocationRegistry.getInstance();
      registry.reset();
      certs = generateTestCertificates();
    });

    it("rejects certificates with serial on revocation blocklist", () => {
      registry.revokeSerial(certs.revokedSerial);
      expect(registry.isRevoked(certs.revokedSerial)).toBe(true);

      const revokedCert = new X509Certificate(certs.revokedClientCert);
      expect(() => {
        registry.verifyPeerCertificate(revokedCert);
      }).toThrow(/UNAUTHENTICATED: Certificate serial .* is revoked/);
    });

    it("enforces strict 30-second freshness bound (fail-closed outage)", () => {
      // Simulate revocation sync timestamp 35 seconds ago
      registry.setLastSyncTime(Date.now() - 35000);

      const validCert = new X509Certificate(certs.engineClientCert);
      expect(() => {
        registry.verifyPeerCertificate(validCert);
      }).toThrow(/INTERNAL: Certificate revocation bus freshness bound exceeded/);
    });

    it("permits valid certificates when revocation bus is fresh and serial unrevoked", () => {
      registry.setLastSyncTime(Date.now() - 2000); // 2 seconds ago: fresh
      const validCert = new X509Certificate(certs.engineClientCert);
      expect(() => {
        registry.verifyPeerCertificate(validCert);
      }).not.toThrow();
    });
  });

  // ==========================================================================
  // 6. LocalEpochCircuitBreaker Tests
  // ==========================================================================
  describe("LocalEpochCircuitBreaker", () => {
    let cb: LocalEpochCircuitBreaker;

    beforeEach(() => {
      cb = LocalEpochCircuitBreaker.getInstance();
      cb.reset();
    });

    it("allows mutating operations when healthy", () => {
      expect(() => cb.assertCanMutate("epoch-1")).not.toThrow();
      expect(cb.getStatus("epoch-1").state).toBe(CircuitState.HEALTHY);
    });

    it("throttles mutating operations when tripped by persistent contention", () => {
      cb.tripContention("epoch-1", 500);
      expect(cb.getStatus("epoch-1").state).toBe(CircuitState.CONTENTION_THROTTLED);

      expect(() => cb.assertCanMutate("epoch-1")).toThrow(
        /UNAVAILABLE: High concurrency lock contention/,
      );
    });

    it("fails closed across all epochs when database connectivity fails", () => {
      cb.tripDatabaseDown("ECONNREFUSED");
      expect(cb.getStatus("epoch-1").state).toBe(CircuitState.DATABASE_DOWN);

      expect(() => cb.assertCanMutate("epoch-1")).toThrow(
        /UNAVAILABLE: Database unreachable/,
      );
      expect(() => cb.assertCanMutate("epoch-2")).toThrow(
        /UNAVAILABLE: Database unreachable/,
      );

      cb.recoverDatabase();
      expect(() => cb.assertCanMutate("epoch-1")).not.toThrow();
    });

    it("quarantines epoch when catastrophic integrity incident occurs", () => {
      cb.tripIntegrityIncident("epoch-1", "INCONSISTENT_RECEIPT_CHAIN_HASH");
      expect(cb.getStatus("epoch-1").state).toBe(CircuitState.INTEGRITY_QUARANTINED);

      expect(() => cb.assertCanMutate("epoch-1")).toThrow(
        /FAILED_PRECONDITION: Epoch epoch-1 is in integrity quarantine/,
      );
    });
  });

  // ==========================================================================
  // 7. LocalEd25519WitnessSigner Production Guard (CFG-D2-01)
  // ==========================================================================
  describe("LocalEd25519WitnessSigner Production Guard (CFG-D2-01)", () => {
    const originalEnv = process.env.NODE_ENV;

    beforeEach(() => {
      process.env.NODE_ENV = originalEnv;
    });

    it("strictly prohibits initialization in NODE_ENV === 'production' unless explicitly allowed", () => {
      process.env.NODE_ENV = "production";

      expect(() => {
        new LocalEd25519WitnessSigner("prod-test-signer");
      }).toThrow(/SECURITY_VIOLATION: LocalEd25519WitnessSigner/);

      // Verify explicit opt-in works for testing harnesses
      expect(() => {
        new LocalEd25519WitnessSigner("prod-test-signer", undefined, undefined, true);
      }).not.toThrow();
    });

    it("permits instantiation when NODE_ENV is development or test", () => {
      process.env.NODE_ENV = "test";
      expect(() => {
        new LocalEd25519WitnessSigner("test-signer");
      }).not.toThrow();
    });
  });
});
