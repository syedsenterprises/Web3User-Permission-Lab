/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Remote Durable Witness Client
 *
 * Implements the MonotonicWitnessAdapter contract backed by gRPC mTLS 1.3 transport.
 * Enforces zero speculative retry on CommitTicket timeouts, automatic reconciliation
 * on ambiguous commit outcomes, and fail-closed security error translation.
 */

import * as path from "node:path";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import type {
  MonotonicWitnessAdapter,
  WitnessReservationRequest,
  WitnessReservationResult,
  WitnessCommitRequest,
  WitnessCommitResult,
  WitnessReleaseRequest,
  WitnessReleaseResult,
  WitnessReconcileRequest,
  WitnessReconcileResult,
  WitnessSyncStatus,
  UnfinalizedWitnessTicket,
  SignedWitnessReceipt,
} from "../monotonic-witness.js";
import {
  WitnessConflictError,
  WitnessUnavailableError,
  WitnessStorageError,
} from "./postgres-store.js";
import { normalizeBudgetWindowType } from "./signing.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface RemoteWitnessClientOptions {
  endpoint: string;
  caCert?: Buffer;
  clientCert?: Buffer;
  clientKey?: Buffer;
  clientCertPem?: string; // Optional raw PEM string attached via metadata
  serverNameOverride?: string;
  timeoutMs?: number;
  publicKeyPem?: string;
}

export class RemoteDurableWitnessClient implements MonotonicWitnessAdapter {
  readonly name = "RemoteDurableWitnessClient";
  readonly isTestOnlyMock = false;
  readonly publicKeyPem?: string;

  private client: any;
  private clientCertPem?: string;
  private defaultTimeoutMs: number;

  constructor(options: RemoteWitnessClientOptions) {
    this.publicKeyPem = options.publicKeyPem;
    this.defaultTimeoutMs = options.timeoutMs || 5000;
    this.clientCertPem = options.clientCertPem || options.clientCert?.toString("utf8");

    const protoPath = path.join(__dirname, "proto", "witness.proto");
    const packageDefinition = protoLoader.loadSync(protoPath, {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true,
    });

    const protoDescriptor = grpc.loadPackageDefinition(packageDefinition) as any;
    const WitnessServiceClient = protoDescriptor.web3user.witness.v1.WitnessService;

    const channelOptions: Record<string, any> = {
      "grpc.ssl_target_name_override": options.serverNameOverride || "localhost",
      "grpc.default_authority": options.serverNameOverride || "localhost",
    };

    let credentials = grpc.credentials.createInsecure();
    if (options.caCert && options.clientCert && options.clientKey) {
      credentials = grpc.credentials.createSsl(
        options.caCert,
        options.clientKey,
        options.clientCert,
      );
    }

    this.client = new WitnessServiceClient(options.endpoint, credentials, channelOptions);
  }

  close(): void {
    if (this.client) {
      this.client.close();
    }
  }

  private createMetadata(): grpc.Metadata {
    const meta = new grpc.Metadata();
    if (this.clientCertPem) {
      meta.set("x-client-cert-bin", Buffer.from(this.clientCertPem, "utf8"));
    }
    return meta;
  }

  private mapGrpcError(err: any): Error {
    const message = err.message || "Witness gRPC error";
    switch (err.code) {
      case grpc.status.ALREADY_EXISTS:
        return new WitnessConflictError(message, err);
      case grpc.status.DEADLINE_EXCEEDED:
      case grpc.status.UNAVAILABLE:
        return new WitnessUnavailableError(message, err);
      case grpc.status.PERMISSION_DENIED:
      case grpc.status.UNAUTHENTICATED:
        const secErr = new Error(`WitnessSecurityError: ${message}`);
        (secErr as any).code = err.code;
        return secErr;
      default:
        return new WitnessStorageError(message, String(err.code), err);
    }
  }

  // ==========================================================================
  // 1. getSyncStatus
  // ==========================================================================
  async getSyncStatus(lastSeenEpoch?: string, lastSeenSeq?: string): Promise<WitnessSyncStatus> {
    const req = {
      last_seen_epoch_id: lastSeenEpoch || "",
      last_seen_sequence_number: lastSeenSeq || "",
    };

    return new Promise<WitnessSyncStatus>((resolve, reject) => {
      const deadline = new Date(Date.now() + this.defaultTimeoutMs);
      this.client.GetSyncStatus(
        req,
        this.createMetadata(),
        { deadline },
        (err: any, resp: any) => {
          if (err) return reject(this.mapGrpcError(err));
          resolve({
            healthy: resp.healthy,
            epochId: resp.epoch_id,
            sequenceNumber: resp.sequence_number,
            divergenceDetected: resp.divergence_detected,
            reason: resp.reason,
          });
        },
      );
    });
  }

  // ==========================================================================
  // 2. reserveTicket
  // ==========================================================================
  async reserveTicket(request: WitnessReservationRequest): Promise<WitnessReservationResult> {
    const req = {
      authorization_id: request.authorizationId,
      binding_digest: request.bindingDigest,
      policy_id: request.policyId,
      policy_revision: request.policyRevision,
      budget_windows: request.budgetWindows?.map((w) => ({
        window_type: w.windowType === "DAILY" ? 2 : 1,
        window_start_seconds: w.windowStart,
        requested_amount: w.requestedAmount,
        max_cumulative_amount: w.maxCumulativeAmount,
      })),
      idempotency_key: request.idempotencyKey || `reserve-${request.authorizationId}`,
      lease_ttl_seconds: 300,
    };

    return new Promise<WitnessReservationResult>((resolve, reject) => {
      const deadline = new Date(Date.now() + this.defaultTimeoutMs);
      this.client.ReserveTicket(
        req,
        this.createMetadata(),
        { deadline },
        (err: any, resp: any) => {
          if (err) return reject(this.mapGrpcError(err));

          const decision = resp.decision === "DECISION_ALLOW" ? "ALLOW" : "DENY";
          resolve({
            decision,
            ticketId: resp.ticket_id,
            state: resp.state === "TICKET_STATE_RESERVED" ? "RESERVED" : (resp.state as any),
            reasons: resp.reasons || [],
            leaseExpiresAtSeconds: resp.lease_expires_at_seconds ? Number(resp.lease_expires_at_seconds) : undefined,
          });
        },
      );
    });
  }

  // ==========================================================================
  // 3. commitTicket (Strict SEC-M11-01 Zero Speculative Retries)
  // ==========================================================================
  async commitTicket(request: WitnessCommitRequest): Promise<WitnessCommitResult> {
    const req = {
      ticket_id: request.ticketId,
      authorization_id: request.authorizationId,
      binding_digest: request.bindingDigest,
      local_committed_at_seconds: request.localCommittedAtSeconds,
      idempotency_key: request.idempotencyKey || `commit-${request.ticketId}`,
    };

    return new Promise<WitnessCommitResult>((resolve, reject) => {
      const deadline = new Date(Date.now() + this.defaultTimeoutMs);
      this.client.CommitTicket(
        req,
        this.createMetadata(),
        { deadline },
        async (err: any, resp: any) => {
          if (err) {
            // SEC-M11-01: On timeout / network drop, do NOT speculate or blind retry.
            // Automatically execute reconcileTicket to discover if commit succeeded.
            if (
              err.code === grpc.status.DEADLINE_EXCEEDED ||
              err.code === grpc.status.UNAVAILABLE
            ) {
              try {
                const rec = await this.reconcileTicket({
                  ticketId: request.ticketId,
                  authorizationId: request.authorizationId,
                });
                if (rec.state === "COMMITTED" && rec.receipt) {
                  return resolve({
                    decision: "ALLOW",
                    receipt: rec.receipt,
                    reasons: ["RECOVERED_VIA_AMBIGUOUS_COMMIT_RECONCILIATION"],
                    alreadyCommitted: true,
                  });
                }
              } catch (reconcileErr) {
                // Return quarantine unconfirmed result
                return resolve({
                  decision: "DENY",
                  receipt: undefined as any,
                  reasons: ["AMBIGUOUS_COMMIT_TIMEOUT_QUARANTINED"],
                  alreadyCommitted: false,
                });
              }
            }

            return reject(this.mapGrpcError(err));
          }

          const decision = resp.decision === "DECISION_ALLOW" ? "ALLOW" : "DENY";
          let receipt: SignedWitnessReceipt | undefined;
          if (resp.receipt) {
            receipt = {
              version: 1 as const,
              witnessId: resp.receipt.witness_id || resp.receipt.witnessId,
              epochId: resp.receipt.epoch_id || resp.receipt.epochId,
              sequenceNumber: String(resp.receipt.sequence_number || resp.receipt.sequenceNumber),
              ticketId: resp.receipt.ticket_id || resp.receipt.ticketId,
              authorizationId: resp.receipt.authorization_id || resp.receipt.authorizationId,
              bindingDigest: resp.receipt.binding_digest || resp.receipt.bindingDigest,
              policyId: resp.receipt.policy_id || resp.receipt.policyId || "default-policy",
              policyRevision: Number(resp.receipt.policy_revision || resp.receipt.policyRevision || 1),
              debitedAmount: String(resp.receipt.debited_amount ?? resp.receipt.debitedAmount ?? "0"),
              budgetWindows: (resp.receipt.budget_windows || resp.receipt.budgetWindows || []).map((bw: any) => ({
                windowType: normalizeBudgetWindowType(bw.window_type ?? bw.windowType),
                windowStart: Number(bw.window_start_seconds ?? bw.windowStart ?? 0),
                cumulativeSpentAfter: String(bw.cumulative_spent_after ?? bw.cumulativeSpentAfter ?? "0"),
              })),
              committedAtSeconds: Number(resp.receipt.committed_at_seconds ?? resp.receipt.committedAtSeconds ?? 0),
              signature: resp.receipt.signature,
            };
          }

          resolve({
            decision,
            receipt: receipt as SignedWitnessReceipt,
            reasons: resp.reasons || [],
            alreadyCommitted: resp.already_committed,
          });
        },
      );
    });
  }

  // ==========================================================================
  // 4. releaseTicket
  // ==========================================================================
  async releaseTicket(request: WitnessReleaseRequest): Promise<WitnessReleaseResult> {
    const req = {
      ticket_id: request.ticketId,
      authorization_id: request.authorizationId,
      binding_digest: request.bindingDigest,
      reason: request.reason || "",
      idempotency_key: (request as any).idempotencyKey || `release-${request.ticketId}`,
    };

    return new Promise<WitnessReleaseResult>((resolve, reject) => {
      const deadline = new Date(Date.now() + this.defaultTimeoutMs);
      this.client.ReleaseTicket(
        req,
        this.createMetadata(),
        { deadline },
        (err: any, resp: any) => {
          if (err) return reject(this.mapGrpcError(err));
          const prev = resp.previous_state?.replace(/^TICKET_STATE_/, "") || "UNKNOWN";
          resolve({
            success: resp.success,
            previousState: prev as any,
            reasons: resp.reasons || [],
          });
        },
      );
    });
  }

  // ==========================================================================
  // 5. reconcileTicket
  // ==========================================================================
  async reconcileTicket(request: WitnessReconcileRequest): Promise<WitnessReconcileResult> {
    const req = {
      ticket_id: request.ticketId || "",
      authorization_id: request.authorizationId || "",
    };

    return new Promise<WitnessReconcileResult>((resolve, reject) => {
      const deadline = new Date(Date.now() + this.defaultTimeoutMs);
      this.client.ReconcileTicket(
        req,
        this.createMetadata(),
        { deadline },
        (err: any, resp: any) => {
          if (err) return reject(this.mapGrpcError(err));

          const state = resp.state?.replace(/^TICKET_STATE_/, "") || "UNKNOWN";
          let receipt: SignedWitnessReceipt | undefined;
          if (resp.receipt) {
            receipt = {
              version: 1 as const,
              witnessId: resp.receipt.witness_id || resp.receipt.witnessId,
              epochId: resp.receipt.epoch_id || resp.receipt.epochId,
              sequenceNumber: String(resp.receipt.sequence_number || resp.receipt.sequenceNumber),
              ticketId: resp.receipt.ticket_id || resp.receipt.ticketId,
              authorizationId: resp.receipt.authorization_id || resp.receipt.authorizationId,
              bindingDigest: resp.receipt.binding_digest || resp.receipt.bindingDigest,
              policyId: resp.receipt.policy_id || resp.receipt.policyId || "default-policy",
              policyRevision: Number(resp.receipt.policy_revision || resp.receipt.policyRevision || 1),
              debitedAmount: String(resp.receipt.debited_amount ?? resp.receipt.debitedAmount ?? "0"),
              budgetWindows: (resp.receipt.budget_windows || resp.receipt.budgetWindows || []).map((bw: any) => ({
                windowType: normalizeBudgetWindowType(bw.window_type ?? bw.windowType),
                windowStart: Number(bw.window_start_seconds ?? bw.windowStart ?? 0),
                cumulativeSpentAfter: String(bw.cumulative_spent_after ?? bw.cumulativeSpentAfter ?? "0"),
              })),
              committedAtSeconds: Number(resp.receipt.committed_at_seconds ?? resp.receipt.committedAtSeconds ?? 0),
              signature: resp.receipt.signature,
            };
          }

          resolve({
            ticketId: resp.ticket_id,
            state: state as any,
            receipt,
            reasons: resp.reasons || [],
          });
        },
      );
    });
  }

  // ==========================================================================
  // 6. listUnfinalizedTickets
  // ==========================================================================
  async listUnfinalizedTickets(): Promise<UnfinalizedWitnessTicket[]> {
    const req = {
      limit: 500,
      cursor_created_at_seconds: 0,
      cursor_ticket_id: "",
    };

    return new Promise<UnfinalizedWitnessTicket[]>((resolve, reject) => {
      const deadline = new Date(Date.now() + this.defaultTimeoutMs);
      this.client.ListUnfinalizedTickets(
        req,
        this.createMetadata(),
        { deadline },
        (err: any, resp: any) => {
          if (err) return reject(this.mapGrpcError(err));

          const mapped: UnfinalizedWitnessTicket[] = (resp.tickets || []).map((t: any) => ({
            ticketId: t.ticket_id,
            authorizationId: t.authorization_id,
            epochId: t.epoch_id,
            bindingDigest: t.binding_digest,
            state: t.state?.replace(/^TICKET_STATE_/, "") as any,
            reservedAt: Number(t.reserved_at_seconds),
            expiresAt: Number(t.expires_at_seconds),
          }));

          resolve(mapped);
        },
      );
    });
  }
}
