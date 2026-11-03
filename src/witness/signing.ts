/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Ed25519 Signer & Outbox Dispatcher
 *
 * Implements canonical receipt preimage generation, Ed25519 signing, and generation-bound
 * signing intents. Strictly prohibits unverified test signer fallback in production environments.
 */

import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import {
  canonicalWitnessReceiptPayload,
  type SignedWitnessReceipt,
  type WitnessBudgetWindowAllocation,
} from "../monotonic-witness.js";
import type { BudgetWindowType } from "../policy.js";

export interface ReceiptPreimageData {
  version: number;
  witness_id?: string;
  witnessId?: string;
  epoch_id?: string;
  epochId?: string;
  sequence_number?: string;
  sequenceNumber?: string;
  ticket_id?: string;
  ticketId?: string;
  authorization_id?: string;
  authorizationId?: string;
  binding_digest?: string;
  bindingDigest?: string;
  policy_id?: string;
  policyId?: string;
  policy_revision?: number;
  policyRevision?: number;
  debited_amount?: string;
  debitedAmount?: string;
  budget_windows?: Array<{
    window_type?: number | string;
    windowType?: BudgetWindowType | string | number;
    window_start_seconds?: number;
    windowStart?: number;
    cumulative_spent_after?: string;
    cumulativeSpentAfter?: string;
  }>;
  budgetWindows?: ReadonlyArray<WitnessBudgetWindowAllocation>;
  committed_at_seconds?: number;
  committedAtSeconds?: number;
}

/**
 * SEC-01: Strict budget window normalization with fail-closed semantics.
 *
 * Supported Cadences:
 * - HOURLY (numeric 1, string "1", "HOURLY", "BUDGET_WINDOW_TYPE_HOURLY")
 * - DAILY  (numeric 2, string "2", "DAILY",  "BUDGET_WINDOW_TYPE_DAILY")
 *
 * Unspecified, 0, null, undefined, empty strings, and protobuf enum cadences (WEEKLY = 3, MONTHLY = 4)
 * that are unsupported by the current SDK receipt specification are strictly rejected.
 */
export function normalizeBudgetWindowType(type: unknown): BudgetWindowType {
  if (type === "HOURLY" || type === "BUDGET_WINDOW_TYPE_HOURLY" || type === 1 || type === "1") {
    return "HOURLY";
  }
  if (type === "DAILY" || type === "BUDGET_WINDOW_TYPE_DAILY" || type === 2 || type === "2") {
    return "DAILY";
  }
  if (
    type === "WEEKLY" ||
    type === "BUDGET_WINDOW_TYPE_WEEKLY" ||
    type === 3 ||
    type === "3" ||
    type === "MONTHLY" ||
    type === "BUDGET_WINDOW_TYPE_MONTHLY" ||
    type === 4 ||
    type === "4"
  ) {
    throw new Error(
      `Unsupported budget window type: ${String(type)} (WEEKLY/MONTHLY cadences defined in protobuf are unsupported by current SDK receipt specification)`,
    );
  }
  if (
    type === undefined ||
    type === null ||
    type === "" ||
    type === 0 ||
    type === "0" ||
    type === "BUDGET_WINDOW_TYPE_UNSPECIFIED"
  ) {
    throw new Error(
      `Invalid budget window type: ${String(type)} (UNSPECIFIED or empty window type is strictly prohibited; must be explicit HOURLY or DAILY)`,
    );
  }
  throw new Error(`Invalid budget window type: ${String(type)}`);
}

/**
 * SEC-04 & SEC-03: Authoritative Receipt Preimage Conversion & Contradictory Dual-Casing Protection
 *
 * Enforces:
 * 1. Exact semantic parity when both snake_case (gRPC/outbox) and camelCase (SDK) properties exist.
 *    Any mismatch between dual-cased fields immediately throws a fail-closed exception.
 * 2. Pure length-prefixed canonical representation conforming to the "web3user-witness-receipt-v1\n" contract.
 */
export function toCanonicalWitnessReceiptData(
  data: ReceiptPreimageData | Omit<SignedWitnessReceipt, "signature">,
): Omit<SignedWitnessReceipt, "signature"> {
  const version = Number(data.version);
  if (version !== 1) {
    throw new Error(`Unsupported witness receipt version: ${version}`);
  }

  const d = data as any;

  // SEC-04: Contradictory dual-casing checks
  if (d.witness_id !== undefined && d.witnessId !== undefined && String(d.witness_id) !== String(d.witnessId)) {
    throw new Error(`Contradictory receipt fields: witness_id ('${d.witness_id}') does not match witnessId ('${d.witnessId}')`);
  }
  if (d.epoch_id !== undefined && d.epochId !== undefined && String(d.epoch_id) !== String(d.epochId)) {
    throw new Error(`Contradictory receipt fields: epoch_id ('${d.epoch_id}') does not match epochId ('${d.epochId}')`);
  }
  if (d.sequence_number !== undefined && d.sequenceNumber !== undefined && String(d.sequence_number) !== String(d.sequenceNumber)) {
    throw new Error(`Contradictory receipt fields: sequence_number ('${d.sequence_number}') does not match sequenceNumber ('${d.sequenceNumber}')`);
  }
  if (d.ticket_id !== undefined && d.ticketId !== undefined && String(d.ticket_id) !== String(d.ticketId)) {
    throw new Error(`Contradictory receipt fields: ticket_id ('${d.ticket_id}') does not match ticketId ('${d.ticketId}')`);
  }
  if (d.authorization_id !== undefined && d.authorizationId !== undefined && String(d.authorization_id) !== String(d.authorizationId)) {
    throw new Error(`Contradictory receipt fields: authorization_id ('${d.authorization_id}') does not match authorizationId ('${d.authorizationId}')`);
  }
  if (d.binding_digest !== undefined && d.bindingDigest !== undefined && String(d.binding_digest) !== String(d.bindingDigest)) {
    throw new Error(`Contradictory receipt fields: binding_digest ('${d.binding_digest}') does not match bindingDigest ('${d.bindingDigest}')`);
  }
  if (d.policy_id !== undefined && d.policyId !== undefined && String(d.policy_id) !== String(d.policyId)) {
    throw new Error(`Contradictory receipt fields: policy_id ('${d.policy_id}') does not match policyId ('${d.policyId}')`);
  }
  if (d.policy_revision !== undefined && d.policyRevision !== undefined && Number(d.policy_revision) !== Number(d.policyRevision)) {
    throw new Error(`Contradictory receipt fields: policy_revision (${d.policy_revision}) does not match policyRevision (${d.policyRevision})`);
  }
  if (d.debited_amount !== undefined && d.debitedAmount !== undefined && String(d.debited_amount) !== String(d.debitedAmount)) {
    throw new Error(`Contradictory receipt fields: debited_amount ('${d.debited_amount}') does not match debitedAmount ('${d.debitedAmount}')`);
  }
  if (d.committed_at_seconds !== undefined && d.committedAtSeconds !== undefined && Number(d.committed_at_seconds) !== Number(d.committedAtSeconds)) {
    throw new Error(`Contradictory receipt fields: committed_at_seconds (${d.committed_at_seconds}) does not match committedAtSeconds (${d.committedAtSeconds})`);
  }

  // Compare budget_windows vs budgetWindows semantically
  if (d.budget_windows !== undefined && d.budgetWindows !== undefined) {
    const listA = Array.isArray(d.budget_windows) ? d.budget_windows : [];
    const listB = Array.isArray(d.budgetWindows) ? d.budgetWindows : [];
    if (listA.length !== listB.length) {
      throw new Error(`Contradictory receipt fields: budget_windows count (${listA.length}) does not match budgetWindows count (${listB.length})`);
    }
    for (let i = 0; i < listA.length; i++) {
      const itemA = listA[i];
      const itemB = listB[i];
      const typeA = normalizeBudgetWindowType(itemA.window_type ?? itemA.windowType);
      const typeB = normalizeBudgetWindowType(itemB.windowType ?? itemB.window_type);
      if (typeA !== typeB) {
        throw new Error(`Contradictory receipt fields: budget window [${i}] type mismatch (${typeA} vs ${typeB})`);
      }
      const startA = Number(itemA.window_start_seconds ?? itemA.windowStart ?? itemA.window_start ?? 0);
      const startB = Number(itemB.windowStart ?? itemB.window_start_seconds ?? itemB.window_start ?? 0);
      if (startA !== startB) {
        throw new Error(`Contradictory receipt fields: budget window [${i}] start mismatch (${startA} vs ${startB})`);
      }
      const spentA = String(itemA.cumulative_spent_after ?? itemA.cumulativeSpentAfter ?? "0");
      const spentB = String(itemB.cumulativeSpentAfter ?? itemB.cumulative_spent_after ?? "0");
      if (spentA !== spentB) {
        throw new Error(`Contradictory receipt fields: budget window [${i}] cumulative spent mismatch (${spentA} vs ${spentB})`);
      }
    }
  }

  const witnessId = d.witnessId ?? d.witness_id;
  const epochId = d.epochId ?? d.epoch_id;
  const sequenceNumber = String(d.sequenceNumber ?? d.sequence_number ?? "");
  const ticketId = d.ticketId ?? d.ticket_id;
  const authorizationId = d.authorizationId ?? d.authorization_id;
  const bindingDigest = d.bindingDigest ?? d.binding_digest;
  const policyId = d.policyId ?? d.policy_id ?? "default-policy";
  const policyRevision = Number(d.policyRevision ?? d.policy_revision ?? 1);
  const debitedAmount = String(d.debitedAmount ?? d.debited_amount ?? "0");
  const committedAtSeconds = Number(d.committedAtSeconds ?? d.committed_at_seconds ?? 0);

  const rawWindows = d.budgetWindows ?? d.budget_windows ?? [];
  const budgetWindows: WitnessBudgetWindowAllocation[] = (rawWindows as any[]).map((w) => {
    const rawType = w.windowType ?? w.window_type;
    const windowType = normalizeBudgetWindowType(rawType);
    const windowStart = Number(w.windowStart ?? w.window_start_seconds ?? w.window_start ?? 0);
    const cumulativeSpentAfter = String(w.cumulativeSpentAfter ?? w.cumulative_spent_after ?? "0");
    return {
      windowType,
      windowStart,
      cumulativeSpentAfter,
    };
  });

  return {
    version: 1,
    witnessId: String(witnessId ?? ""),
    epochId: String(epochId ?? ""),
    sequenceNumber,
    ticketId: String(ticketId ?? ""),
    authorizationId: String(authorizationId ?? ""),
    bindingDigest: String(bindingDigest ?? ""),
    policyId: String(policyId),
    policyRevision,
    debitedAmount,
    budgetWindows,
    committedAtSeconds,
  };
}

export function formatCanonicalPreimage(
  data: ReceiptPreimageData | Omit<SignedWitnessReceipt, "signature">,
): string {
  const canonicalData = toCanonicalWitnessReceiptData(data);
  return canonicalWitnessReceiptPayload(canonicalData);
}

export interface WitnessSigner {
  signReceipt(preimage: string, fencingGeneration: number): Promise<{ signatureHex: string; generation: number }>;
  getPublicKeyHex(): string;
  getPublicKeyPem?(): string;
  getWitnessId(): string;
}

/**
 * In-Memory Ed25519 Signer for local tests and developmental environments.
 */
export class LocalEd25519WitnessSigner implements WitnessSigner {
  private privateKey: KeyObject;
  private publicKey: KeyObject;
  private witnessId: string;

  constructor(
    witnessId = "witness-node-local-1",
    privateKey?: KeyObject,
    publicKey?: KeyObject,
    allowInProduction = false,
  ) {
    if (process.env.NODE_ENV === "production" && !allowInProduction) {
      throw new Error(
        "SECURITY_VIOLATION: LocalEd25519WitnessSigner (in-memory ephemeral key) is strictly forbidden in production mode. A hardware-backed CloudHSM/KMS signer is required.",
      );
    }
    this.witnessId = witnessId;
    if (privateKey && publicKey) {
      this.privateKey = privateKey;
      this.publicKey = publicKey;
    } else {
      const keys = generateKeyPairSync("ed25519");
      this.privateKey = keys.privateKey;
      this.publicKey = keys.publicKey;
    }
  }

  async signReceipt(
    preimage: string,
    fencingGeneration: number,
  ): Promise<{ signatureHex: string; generation: number }> {
    const signatureBuffer = sign(null, Buffer.from(preimage, "utf8"), this.privateKey);
    return {
      signatureHex: signatureBuffer.toString("hex").toLowerCase(),
      generation: fencingGeneration,
    };
  }

  getPublicKeyHex(): string {
    const exported = this.publicKey.export({ type: "spki", format: "der" });
    // In SPKI Ed25519, raw public key is the trailing 32 bytes
    return exported.subarray(exported.length - 32).toString("hex").toLowerCase();
  }

  getPublicKeyPem(): string {
    return this.publicKey.export({ type: "spki", format: "pem" }).toString();
  }

  getPublicKeyObject(): KeyObject {
    return this.publicKey;
  }

  getWitnessId(): string {
    return this.witnessId;
  }
}
