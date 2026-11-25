/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Authentication & RBAC Authorization
 *
 * Implements mTLS peer certificate extraction, strict 30-second certificate revocation
 * freshness bounds, RBAC method authorization matrix, and ticket ownership enforcement.
 */

import { X509Certificate } from "node:crypto";

export enum WitnessRole {
  ENGINE_POD = "role:engine-pod",
  RECOVERY_WORKER = "role:recovery-worker",
  ADMIN_AUDITOR = "role:admin-auditor",
  UNAUTHORIZED_CLIENT = "role:unauthorized-client",
}

export interface AuthenticatedPeer {
  identity: string; // SPIFFE ID or CN
  role: WitnessRole;
  serialNumber: string;
  sanUris: string[];
  rawCertPem?: string;
}

export class RevocationRegistry {
  private static instance: RevocationRegistry;
  private revokedSerials = new Set<string>();
  private lastSyncTimestamp: number = Date.now();
  private maxFreshnessSeconds = 30; // Strict fail-closed bound: 30 seconds

  static getInstance(): RevocationRegistry {
    if (!RevocationRegistry.instance) {
      RevocationRegistry.instance = new RevocationRegistry();
    }
    return RevocationRegistry.instance;
  }

  reset(): void {
    this.revokedSerials.clear();
    this.lastSyncTimestamp = Date.now();
  }

  setLastSyncTime(timestampMs: number): void {
    this.lastSyncTimestamp = timestampMs;
  }

  revokeSerial(serialHex: string): void {
    this.revokedSerials.add(serialHex.toLowerCase().replace(/^0x/, ""));
    this.lastSyncTimestamp = Date.now();
  }

  isRevoked(serialHex: string): boolean {
    const clean = serialHex.toLowerCase().replace(/^0x/, "");
    return this.revokedSerials.has(clean);
  }

  assertFreshness(): void {
    const ageSeconds = (Date.now() - this.lastSyncTimestamp) / 1000;
    if (ageSeconds > this.maxFreshnessSeconds) {
      const err = new Error(
        `INTERNAL: Certificate revocation bus freshness bound exceeded (${ageSeconds.toFixed(1)}s > ${this.maxFreshnessSeconds}s); failing closed`,
      );
      (err as any).code = 13; // gRPC INTERNAL
      throw err;
    }
  }

  verifyPeerCertificate(cert: X509Certificate): void {
    this.assertFreshness();
    const serial = cert.serialNumber.toLowerCase();
    if (this.isRevoked(serial)) {
      const err = new Error(`UNAUTHENTICATED: Certificate serial ${serial} is revoked`);
      (err as any).code = 16; // gRPC UNAUTHENTICATED
      throw err;
    }
  }
}

export class PeerAuthorizer {
  static extractPeer(
    certRaw: Buffer | string | X509Certificate,
    caCert?: Buffer | string | X509Certificate,
  ): AuthenticatedPeer {
    let cert: X509Certificate;
    try {
      cert = certRaw instanceof X509Certificate ? certRaw : new X509Certificate(certRaw);
    } catch (err: any) {
      const authErr = new Error(`UNAUTHENTICATED: Invalid X.509 peer certificate format: ${err.message}`);
      (authErr as any).code = 16; // gRPC UNAUTHENTICATED
      throw authErr;
    }

    // 1. Verify certificate chain against configured Root CA if provided
    if (caCert) {
      let ca: X509Certificate;
      try {
        ca = caCert instanceof X509Certificate ? caCert : new X509Certificate(caCert);
      } catch (err: any) {
        const caErr = new Error(`INTERNAL: Invalid Root CA certificate format: ${err.message}`);
        (caErr as any).code = 13; // gRPC INTERNAL
        throw caErr;
      }

      if (!cert.verify(ca.publicKey)) {
        const authErr = new Error("UNAUTHENTICATED: Certificate signature cannot be verified against trusted Witness CA");
        (authErr as any).code = 16; // gRPC UNAUTHENTICATED
        throw authErr;
      }
    }

    // 2. Verify temporal validity window (validFrom / validTo)
    const now = Date.now();
    const validFrom = new Date(cert.validFrom).getTime();
    const validTo = new Date(cert.validTo).getTime();
    if (now < validFrom) {
      const authErr = new Error(`UNAUTHENTICATED: Certificate is not yet valid (validFrom: ${cert.validFrom})`);
      (authErr as any).code = 16;
      throw authErr;
    }
    if (now > validTo) {
      const authErr = new Error(`UNAUTHENTICATED: Certificate has expired (validTo: ${cert.validTo})`);
      (authErr as any).code = 16;
      throw authErr;
    }

    // 3. Verify certificate revocation status and 30-second freshness bound
    RevocationRegistry.getInstance().verifyPeerCertificate(cert);

    const serialNumber = cert.serialNumber.toLowerCase();
    const sanUris: string[] = [];

    // Parse subjectAltName for URI:spiffe://... or DNS:...
    const san = cert.subjectAltName || "";
    for (const part of san.split(",")) {
      const trimmed = part.trim();
      if (trimmed.startsWith("URI:")) {
        sanUris.push(trimmed.slice(4));
      }
    }

    let identity = sanUris[0];
    if (!identity) {
      // Fallback to CN
      const subject = cert.subject;
      const cnMatch = subject.match(/CN=([^,\n]+)/);
      identity = cnMatch ? cnMatch[1] : subject;
    }

    // Role mapping based on SPIFFE ID or CN
    let role = WitnessRole.UNAUTHORIZED_CLIENT;
    if (identity.includes("/ns/engine/") || identity.includes("engine-pod")) {
      role = WitnessRole.ENGINE_POD;
    } else if (identity.includes("/ns/recovery/") || identity.includes("recovery-worker")) {
      role = WitnessRole.RECOVERY_WORKER;
    } else if (identity.includes("/ns/admin/") || identity.includes("admin-auditor")) {
      role = WitnessRole.ADMIN_AUDITOR;
    }

    return {
      identity,
      role,
      serialNumber,
      sanUris,
    };
  }

  static assertRolePermission(peer: AuthenticatedPeer, method: string): void {
    const m = method.replace(/^\//, "").split("/").pop() || method;

    switch (m) {
      case "GetSyncStatus":
        if (
          peer.role === WitnessRole.ENGINE_POD ||
          peer.role === WitnessRole.RECOVERY_WORKER ||
          peer.role === WitnessRole.ADMIN_AUDITOR
        ) {
          return;
        }
        break;

      case "ReserveTicket":
      case "CommitTicket":
      case "ReleaseTicket":
        if (peer.role === WitnessRole.ENGINE_POD) {
          return;
        }
        break;

      case "ReconcileTicket":
        if (
          peer.role === WitnessRole.ENGINE_POD ||
          peer.role === WitnessRole.RECOVERY_WORKER ||
          peer.role === WitnessRole.ADMIN_AUDITOR
        ) {
          return;
        }
        break;

      case "ListUnfinalizedTickets":
        if (
          peer.role === WitnessRole.RECOVERY_WORKER ||
          peer.role === WitnessRole.ADMIN_AUDITOR
        ) {
          return;
        }
        break;
    }

    const err = new Error(
      `PERMISSION_DENIED: Role ${peer.role} (${peer.identity}) is not authorized to invoke ${m}`,
    );
    (err as any).code = 7; // gRPC PERMISSION_DENIED
    throw err;
  }

  static assertTicketOwnership(peer: AuthenticatedPeer, ticketOwnerIdentity: string): void {
    // Recovery workers or admins may reconcile/audit any ticket
    if (
      peer.role === WitnessRole.RECOVERY_WORKER ||
      peer.role === WitnessRole.ADMIN_AUDITOR
    ) {
      return;
    }

    if (peer.identity !== ticketOwnerIdentity) {
      const err = new Error(
        `PERMISSION_DENIED: Caller identity ${peer.identity} does not own ticket (reserved by ${ticketOwnerIdentity})`,
      );
      (err as any).code = 7; // gRPC PERMISSION_DENIED
      throw err;
    }
  }
}
