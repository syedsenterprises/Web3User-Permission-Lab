/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Idempotency Protocol & Fingerprinting
 *
 * Implements deterministic canonical SHA-256 request fingerprinting, payload mismatch detection,
 * and cached replay resolution across worker restarts.
 */

import { createHash } from "node:crypto";

export function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

export interface CanonicalBudgetWindow {
  windowType: string | number;
  windowStartSeconds: number | string;
  requestedAmount: string;
  maxCumulativeAmount?: string;
}

export interface CanonicalReserveRequest {
  authorizationId: string;
  bindingDigest: string;
  policyId?: string;
  policyRevision?: number | string;
  budgetWindows?: CanonicalBudgetWindow[];
  idempotencyKey: string;
  leaseTtlSeconds?: number | string;
}

export interface CanonicalCommitRequest {
  ticketId: string;
  authorizationId: string;
  bindingDigest: string;
  idempotencyKey: string;
}

export interface CanonicalReleaseRequest {
  ticketId: string;
  authorizationId: string;
  bindingDigest: string;
  reason?: string;
  idempotencyKey: string;
}

export class IdempotencyFingerprinter {
  /**
   * Computes SHA-256 fingerprint for ReserveTicketRequest.
   * Deterministically orders budget windows.
   */
  static computeReserveFingerprint(req: CanonicalReserveRequest): string {
    const sortedWindows = [...(req.budgetWindows || [])]
      .map((w) => ({
        type: String(w.windowType),
        start: String(w.windowStartSeconds),
        requested: String(w.requestedAmount),
        max: String(w.maxCumulativeAmount || "0"),
      }))
      .sort((a, b) => a.type.localeCompare(b.type) || a.start.localeCompare(b.start));

    const canonical = JSON.stringify({
      authId: req.authorizationId,
      bindingDigest: req.bindingDigest,
      policyId: req.policyId || "",
      policyRevision: String(req.policyRevision || "0"),
      windows: sortedWindows,
    });

    return sha256Hex(`ReserveTicket:${req.idempotencyKey}:${canonical}`);
  }

  /**
   * Computes SHA-256 fingerprint for CommitTicketRequest.
   * Note: Excludes client local_committed_at_seconds as it is untrusted diagnostic metadata.
   */
  static computeCommitFingerprint(req: CanonicalCommitRequest): string {
    const canonical = JSON.stringify({
      ticketId: req.ticketId,
      authId: req.authorizationId,
      bindingDigest: req.bindingDigest,
    });

    return sha256Hex(`CommitTicket:${req.idempotencyKey}:${canonical}`);
  }

  /**
   * Computes SHA-256 fingerprint for ReleaseTicketRequest.
   */
  static computeReleaseFingerprint(req: CanonicalReleaseRequest): string {
    const canonical = JSON.stringify({
      ticketId: req.ticketId,
      authId: req.authorizationId,
      bindingDigest: req.bindingDigest,
      reason: req.reason || "",
    });

    return sha256Hex(`ReleaseTicket:${req.idempotencyKey}:${canonical}`);
  }
}
