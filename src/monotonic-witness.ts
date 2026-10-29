/**
 * Web3User Permission Lab - Monotonic Witness Protocol & Local Deterministic Witness
 *
 * Implements the SDK-only witness adapter interface, canonical receipt serialization,
 * deterministic verification, and a test-only in-process witness (LocalDeterministicWitness).
 *
 * NOTE: LocalDeterministicWitness is an in-process mock designed strictly for development,
 * integration, and deterministic adversarial testing. It does NOT claim or provide protection
 * against full-system host rollback, simultaneous database rewinds, or infrastructure compromise.
 */

import { randomBytes, type KeyObject } from "node:crypto";
import {
  generateIssuerKeyPair,
  signAuthorizationPayload,
  verifyAuthorizationPayload,
} from "./authorization-crypto.js";
import type { BudgetWindowType } from "./policy.js";

// ============================================================================
// Types & Core State Machine
// ============================================================================

export type WitnessTicketState =
  | "RESERVED"
  | "COMMITTED"
  | "RELEASED"
  | "QUARANTINED_UNCONFIRMED"
  | "DISPUTED";

export interface WitnessBudgetWindowAllocation {
  readonly windowType: BudgetWindowType;
  readonly windowStart: number;
  readonly cumulativeSpentAfter: string;
}

/**
 * Immutable cryptographic receipt issued by the witness upon durable commitment.
 */
export interface SignedWitnessReceipt {
  readonly version: 1;
  readonly witnessId: string;
  readonly epochId: string;
  readonly sequenceNumber: string; // 64-bit integer formatted as canonical decimal string
  readonly ticketId: string;
  readonly authorizationId: string;
  readonly bindingDigest: string; // SHA-256 digest of canonical transaction request
  readonly policyId: string;
  readonly policyRevision: number;
  readonly debitedAmount: string; // Canonical decimal uint256 string
  readonly budgetWindows: ReadonlyArray<WitnessBudgetWindowAllocation>;
  readonly committedAtSeconds: number;
  readonly signature: string; // 128-character lowercase hex Ed25519 signature
}

export interface WitnessSyncStatus {
  readonly healthy: boolean;
  readonly epochId: string;
  readonly sequenceNumber: string;
  readonly divergenceDetected: boolean;
  readonly reason?: string;
}

export interface WitnessReservationRequest {
  readonly authorizationId: string;
  readonly bindingDigest: string;
  readonly policyId: string;
  readonly policyRevision: number;
  readonly budgetWindows?: ReadonlyArray<{
    readonly windowType: BudgetWindowType;
    readonly windowStart: number;
    readonly requestedAmount: string;
    readonly maxCumulativeAmount: string;
  }>;
  readonly idempotencyKey: string;
  readonly leaseTtlSeconds?: number;
}

export interface WitnessReservationResult {
  readonly decision: "ALLOW" | "DENY";
  readonly ticketId?: string;
  readonly state?: WitnessTicketState;
  readonly reasons?: string[];
  readonly leaseExpiresAtSeconds?: number;
}

export interface WitnessCommitRequest {
  readonly ticketId: string;
  readonly authorizationId: string;
  readonly bindingDigest: string;
  readonly localCommittedAtSeconds: number;
  readonly idempotencyKey?: string;
}

export interface WitnessCommitResult {
  readonly decision: "ALLOW" | "DENY";
  readonly receipt?: SignedWitnessReceipt;
  readonly reasons?: string[];
  readonly alreadyCommitted?: boolean;
}

export interface WitnessReleaseRequest {
  readonly ticketId: string;
  readonly authorizationId: string;
  readonly bindingDigest: string;
  readonly reason: string;
}

export interface WitnessReleaseResult {
  readonly success: boolean;
  readonly previousState?: WitnessTicketState;
  readonly reasons?: string[];
}

export interface WitnessReconcileRequest {
  readonly ticketId: string;
  readonly authorizationId?: string;
}

export interface WitnessReconcileResult {
  readonly ticketId: string;
  readonly state: WitnessTicketState;
  readonly receipt?: SignedWitnessReceipt;
  readonly reasons?: string[];
}

export interface UnfinalizedWitnessTicket {
  readonly ticketId: string;
  readonly authorizationId: string;
  readonly bindingDigest: string;
  readonly state: WitnessTicketState;
  readonly reservedAtSeconds: number;
  readonly expiresAtSeconds: number;
}

/**
 * Abstract pluggable witness adapter interface.
 */
export interface MonotonicWitnessAdapter {
  readonly name: string;
  readonly isTestOnlyMock: boolean;

  getSyncStatus(lastSeenEpoch?: string, lastSeenSeq?: string): Promise<WitnessSyncStatus> | WitnessSyncStatus;

  reserveTicket(request: WitnessReservationRequest): Promise<WitnessReservationResult> | WitnessReservationResult;

  commitTicket(request: WitnessCommitRequest): Promise<WitnessCommitResult> | WitnessCommitResult;

  releaseTicket(request: WitnessReleaseRequest): Promise<WitnessReleaseResult> | WitnessReleaseResult;

  reconcileTicket(request: WitnessReconcileRequest): Promise<WitnessReconcileResult> | WitnessReconcileResult;

  listUnfinalizedTickets?(): Promise<UnfinalizedWitnessTicket[]> | UnfinalizedWitnessTicket[];
}

// ============================================================================
// Canonical Encoding & Cryptographic Verification
// ============================================================================

const DIGEST_REGEX = /^sha256:[a-f0-9]{64}$/;
const UINT256_DECIMAL_REGEX = /^(0|[1-9][0-9]{0,77})$/;

function areBudgetWindowsEqual(
  a: ReadonlyArray<{
    readonly windowType: BudgetWindowType;
    readonly windowStart: number;
    readonly requestedAmount: string;
    readonly maxCumulativeAmount: string;
  }> | undefined,
  b: ReadonlyArray<{
    readonly windowType: BudgetWindowType;
    readonly windowStart: number;
    readonly requestedAmount: string;
    readonly maxCumulativeAmount: string;
  }> | undefined,
): boolean {
  const listA = a ?? [];
  const listB = b ?? [];
  if (listA.length !== listB.length) return false;
  for (let i = 0; i < listA.length; i++) {
    const itemA = listA[i];
    const itemB = listB[i];
    if (
      itemA.windowType !== itemB.windowType ||
      itemA.windowStart !== itemB.windowStart ||
      itemA.requestedAmount !== itemB.requestedAmount ||
      itemA.maxCumulativeAmount !== itemB.maxCumulativeAmount
    ) {
      return false;
    }
  }
  return true;
}

function encodeField(name: string, value: string): string {
  return `${name}:${Buffer.byteLength(value, "utf8")}:${value}\n`;
}

/**
 * Deterministically serialize a witness receipt payload for signing and verification.
 */
export function canonicalWitnessReceiptPayload(receipt: Omit<SignedWitnessReceipt, "signature">): string {
  if (
    receipt.version !== 1 ||
    typeof receipt.witnessId !== "string" ||
    receipt.witnessId.trim().length === 0 ||
    typeof receipt.epochId !== "string" ||
    receipt.epochId.trim().length === 0 ||
    typeof receipt.sequenceNumber !== "string" ||
    !UINT256_DECIMAL_REGEX.test(receipt.sequenceNumber) ||
    typeof receipt.ticketId !== "string" ||
    receipt.ticketId.trim().length === 0 ||
    typeof receipt.authorizationId !== "string" ||
    receipt.authorizationId.trim().length === 0 ||
    typeof receipt.bindingDigest !== "string" ||
    !DIGEST_REGEX.test(receipt.bindingDigest) ||
    typeof receipt.policyId !== "string" ||
    receipt.policyId.trim().length === 0 ||
    !Number.isSafeInteger(receipt.policyRevision) ||
    receipt.policyRevision < 1 ||
    typeof receipt.debitedAmount !== "string" ||
    !UINT256_DECIMAL_REGEX.test(receipt.debitedAmount) ||
    !Array.isArray(receipt.budgetWindows) ||
    !Number.isSafeInteger(receipt.committedAtSeconds) ||
    receipt.committedAtSeconds < 0
  ) {
    throw new Error("Invalid parameters for canonicalWitnessReceiptPayload.");
  }

  const encodedWindows = receipt.budgetWindows
    .map((w) => {
      if (
        (w.windowType !== "HOURLY" && w.windowType !== "DAILY") ||
        !Number.isSafeInteger(w.windowStart) ||
        w.windowStart < 0 ||
        typeof w.cumulativeSpentAfter !== "string" ||
        !UINT256_DECIMAL_REGEX.test(w.cumulativeSpentAfter)
      ) {
        throw new Error("Invalid budget window in receipt.");
      }
      return `${w.windowType}:${w.windowStart}:${w.cumulativeSpentAfter}`;
    })
    .join(";");

  return [
    "web3user-witness-receipt-v1\n",
    encodeField("witness.version", String(receipt.version)),
    encodeField("witness.witnessId", receipt.witnessId),
    encodeField("witness.epochId", receipt.epochId),
    encodeField("witness.sequenceNumber", receipt.sequenceNumber),
    encodeField("ticket.ticketId", receipt.ticketId),
    encodeField("artifact.authorizationId", receipt.authorizationId),
    encodeField("artifact.bindingDigest", receipt.bindingDigest),
    encodeField("policy.policyId", receipt.policyId),
    encodeField("policy.policyRevision", String(receipt.policyRevision)),
    encodeField("budget.debitedAmount", receipt.debitedAmount),
    encodeField("budget.windows", encodedWindows),
    encodeField("witness.committedAtSeconds", String(receipt.committedAtSeconds)),
  ].join("");
}

/**
 * Verify a SignedWitnessReceipt using the witness public key.
 */
export function verifyWitnessReceipt(
  publicKey: KeyObject | string,
  receipt: SignedWitnessReceipt,
): boolean {
  try {
    const payload = canonicalWitnessReceiptPayload(receipt);
    return verifyAuthorizationPayload(publicKey, payload, receipt.signature);
  } catch {
    return false;
  }
}

// ============================================================================
// Local Deterministic Witness Implementation (Test-Only Mock)
// ============================================================================

interface InternalTicketRecord {
  readonly ticketId: string;
  readonly authorizationId: string;
  readonly bindingDigest: string;
  readonly policyId: string;
  readonly policyRevision: number;
  readonly idempotencyKey: string;
  state: WitnessTicketState;
  readonly budgetWindows: ReadonlyArray<{
    readonly windowType: BudgetWindowType;
    readonly windowStart: number;
    readonly requestedAmount: string;
    readonly maxCumulativeAmount: string;
  }>;
  readonly reservedAtSeconds: number;
  expiresAtSeconds: number;
  receipt?: SignedWitnessReceipt;
  releaseReason?: string;
}

export interface LocalDeterministicWitnessOptions {
  readonly witnessId?: string;
  readonly epochId?: string;
  readonly keyPair?: {
    readonly privateKey: KeyObject | string;
    readonly publicKeyPem: string;
  };
  readonly defaultLeaseTtlSeconds?: number;
  readonly nowSeconds?: () => number;
  readonly initialSequence?: bigint;
}

/**
 * In-process deterministic mock witness.
 *
 * Implements strict CAS ticket transitions, multi-window budget caps, permanent tombstones,
 * and quarantine handling for deterministic adversarial testing.
 */
export class LocalDeterministicWitness implements MonotonicWitnessAdapter {
  public readonly name = "LocalDeterministicWitness";
  public readonly isTestOnlyMock = true;

  private readonly witnessId: string;
  private readonly epochId: string;
  private readonly privateKey: KeyObject | string;
  public readonly publicKeyPem: string;
  private readonly defaultLeaseTtlSeconds: number;
  private readonly getTimeSeconds: () => number;

  private sequence: bigint;
  private readonly tickets = new Map<string, InternalTicketRecord>();
  private readonly idempotencyIndex = new Map<string, string>(); // idempotencyKey -> ticketId
  private readonly authIdIndex = new Map<string, string>(); // authorizationId -> ticketId
  private readonly revokedKeys = new Set<string>();
  private readonly revokedPolicies = new Set<string>();

  // Map of `${policyId}:${windowType}:${windowStart}` -> balances
  private readonly accumulators = new Map<
    string,
    { committed: bigint; reserved: bigint; maxCumulative: bigint }
  >();

  constructor(options?: LocalDeterministicWitnessOptions) {
    this.witnessId = options?.witnessId ?? "local-mock-witness-01";
    this.epochId = options?.epochId ?? "epoch-local-01";
    this.defaultLeaseTtlSeconds = options?.defaultLeaseTtlSeconds ?? 15;
    this.getTimeSeconds = options?.nowSeconds ?? (() => Math.floor(Date.now() / 1000));
    this.sequence = options?.initialSequence ?? 1n;

    if (options?.keyPair) {
      this.privateKey = options.keyPair.privateKey;
      this.publicKeyPem = options.keyPair.publicKeyPem;
    } else {
      const generated = generateIssuerKeyPair();
      this.privateKey = generated.privateKey;
      this.publicKeyPem = generated.publicKeyPem;
    }
  }

  public getWitnessId(): string {
    return this.witnessId;
  }

  public getEpochId(): string {
    return this.epochId;
  }

  public getCurrentSequence(): string {
    return this.sequence.toString(10);
  }

  public revokeKey(keyId: string): void {
    this.revokedKeys.add(keyId);
    this.sequence += 1n;
  }

  public revokePolicy(policyId: string): void {
    this.revokedPolicies.add(policyId);
    this.sequence += 1n;
  }

  public getSyncStatus(lastSeenEpoch?: string, lastSeenSeq?: string): WitnessSyncStatus {
    const currentSeqStr = this.sequence.toString(10);

    if (lastSeenEpoch !== undefined && lastSeenEpoch !== this.epochId) {
      return {
        healthy: false,
        epochId: this.epochId,
        sequenceNumber: currentSeqStr,
        divergenceDetected: true,
        reason: `Epoch divergence detected: local recorded '${lastSeenEpoch}', witness active '${this.epochId}'.`,
      };
    }

    if (lastSeenSeq !== undefined && BigInt(lastSeenSeq) > this.sequence) {
      return {
        healthy: false,
        epochId: this.epochId,
        sequenceNumber: currentSeqStr,
        divergenceDetected: true,
        reason: `Sequence regression detected: local recorded sequence ${lastSeenSeq} exceeds witness sequence ${currentSeqStr}.`,
      };
    }

    return {
      healthy: true,
      epochId: this.epochId,
      sequenceNumber: currentSeqStr,
      divergenceDetected: false,
    };
  }

  public reserveTicket(request: WitnessReservationRequest): WitnessReservationResult {
    const now = this.getTimeSeconds();

    if (this.revokedPolicies.has(request.policyId)) {
      return {
        decision: "DENY",
        reasons: [`Policy '${request.policyId}' is revoked on witness.`],
      };
    }

    // 1. Idempotency Check
    const existingTicketId = this.idempotencyIndex.get(request.idempotencyKey);
    if (existingTicketId) {
      const ticket = this.tickets.get(existingTicketId);
      if (!ticket) {
        return { decision: "DENY", reasons: ["Corrupted idempotency index."] };
      }

      if (
        ticket.authorizationId !== request.authorizationId ||
        ticket.bindingDigest !== request.bindingDigest ||
        ticket.policyId !== request.policyId ||
        ticket.policyRevision !== request.policyRevision ||
        !areBudgetWindowsEqual(ticket.budgetWindows, request.budgetWindows)
      ) {
        const mismatches: string[] = [];
        if (ticket.authorizationId !== request.authorizationId) mismatches.push("authorizationId mismatch");
        if (ticket.bindingDigest !== request.bindingDigest) mismatches.push("bindingDigest mismatch");
        if (ticket.policyId !== request.policyId) mismatches.push("policyId mismatch");
        if (ticket.policyRevision !== request.policyRevision) mismatches.push("policyRevision mismatch");
        if (!areBudgetWindowsEqual(ticket.budgetWindows, request.budgetWindows)) mismatches.push("budgetWindows mismatch");
        return {
          decision: "DENY",
          reasons: [
            `Conflicting payload for existing idempotency key (${mismatches.join(", ")}).`,
          ],
        };
      }

      // Check if ticket is in terminal or active state
      if (ticket.state === "RELEASED") {
        return {
          decision: "DENY",
          reasons: ["Ticket has already been permanently released."],
        };
      }

      return {
        decision: "ALLOW",
        ticketId: ticket.ticketId,
        state: ticket.state,
        leaseExpiresAtSeconds: ticket.expiresAtSeconds,
      };
    }

    // 2. Authorization ID Single-Use Check
    const existingAuthTicketId = this.authIdIndex.get(request.authorizationId);
    if (existingAuthTicketId) {
      const ticket = this.tickets.get(existingAuthTicketId);
      return {
        decision: "DENY",
        reasons: [
          `Authorization ID '${request.authorizationId}' has already been reserved or committed (ticket '${existingAuthTicketId}', state '${ticket?.state ?? "unknown"}').`,
        ],
      };
    }

    // 3. Multi-Window Cumulative Budget Capacity Verification
    if (request.budgetWindows && request.budgetWindows.length > 0) {
      for (const w of request.budgetWindows) {
        const key = `${request.policyId}:${w.windowType}:${w.windowStart}`;
        const acc = this.accumulators.get(key) ?? {
          committed: 0n,
          reserved: 0n,
          maxCumulative: BigInt(w.maxCumulativeAmount),
        };

        const requested = BigInt(w.requestedAmount);
        const available = acc.maxCumulative - (acc.committed + acc.reserved);

        if (requested > available) {
          return {
            decision: "DENY",
            reasons: [
              `Cumulative spending budget exceeded on witness for ${w.windowType.toLowerCase()} window (requested: ${w.requestedAmount}, available: ${available > 0n ? available.toString(10) : "0"}).`,
            ],
          };
        }
      }

      // Apply reservations across all windows atomically
      for (const w of request.budgetWindows) {
        const key = `${request.policyId}:${w.windowType}:${w.windowStart}`;
        let acc = this.accumulators.get(key);
        if (!acc) {
          acc = {
            committed: 0n,
            reserved: 0n,
            maxCumulative: BigInt(w.maxCumulativeAmount),
          };
          this.accumulators.set(key, acc);
        }
        acc.reserved += BigInt(w.requestedAmount);
      }
    }

    // 4. Generate Reservation Ticket
    this.sequence += 1n;
    const ticketId = `ticket-${this.sequence.toString(10)}-${randomBytes(8).toString("hex")}`;
    const leaseTtl = request.leaseTtlSeconds ?? this.defaultLeaseTtlSeconds;
    const expiresAtSeconds = now + leaseTtl;

    const record: InternalTicketRecord = {
      ticketId,
      authorizationId: request.authorizationId,
      bindingDigest: request.bindingDigest,
      policyId: request.policyId,
      policyRevision: request.policyRevision,
      idempotencyKey: request.idempotencyKey,
      state: "RESERVED",
      budgetWindows: request.budgetWindows ?? [],
      reservedAtSeconds: now,
      expiresAtSeconds,
    };

    this.tickets.set(ticketId, record);
    this.idempotencyIndex.set(request.idempotencyKey, ticketId);
    this.authIdIndex.set(request.authorizationId, ticketId);

    return {
      decision: "ALLOW",
      ticketId,
      state: "RESERVED",
      leaseExpiresAtSeconds: expiresAtSeconds,
    };
  }

  public commitTicket(request: WitnessCommitRequest): WitnessCommitResult {
    const now = this.getTimeSeconds();
    const ticket = this.tickets.get(request.ticketId);

    if (!ticket) {
      return { decision: "DENY", reasons: [`Ticket '${request.ticketId}' not found.`] };
    }

    // Assert immutable payload bindings
    if (
      ticket.authorizationId !== request.authorizationId ||
      ticket.bindingDigest !== request.bindingDigest ||
      (request.idempotencyKey !== undefined && ticket.idempotencyKey !== request.idempotencyKey)
    ) {
      return {
        decision: "DENY",
        reasons: ["Binding digest, authorization ID, or idempotency key mismatch on commit."],
      };
    }

    // Idempotent commit retry
    if (ticket.state === "COMMITTED") {
      return {
        decision: "ALLOW",
        alreadyCommitted: true,
        receipt: ticket.receipt,
      };
    }

    // Terminal RELEASED check
    if (ticket.state === "RELEASED") {
      return {
        decision: "DENY",
        reasons: ["Ticket has already been permanently released and cannot be committed."],
      };
    }

    // Update state to COMMITTED
    this.sequence += 1n;
    const sequenceStr = this.sequence.toString(10);

    // Convert reserved budget to committed budget
    const windowAllocations: WitnessBudgetWindowAllocation[] = [];
    let debitedAmount = "0";

    for (const w of ticket.budgetWindows) {
      const key = `${ticket.policyId}:${w.windowType}:${w.windowStart}`;
      const acc = this.accumulators.get(key);
      if (acc) {
        const reqBig = BigInt(w.requestedAmount);
        if (ticket.state === "RESERVED" || ticket.state === "QUARANTINED_UNCONFIRMED") {
          acc.reserved = acc.reserved >= reqBig ? acc.reserved - reqBig : 0n;
        }
        acc.committed += reqBig;
        windowAllocations.push({
          windowType: w.windowType,
          windowStart: w.windowStart,
          cumulativeSpentAfter: acc.committed.toString(10),
        });
      }
      debitedAmount = w.requestedAmount;
    }

    const receiptData: Omit<SignedWitnessReceipt, "signature"> = {
      version: 1,
      witnessId: this.witnessId,
      epochId: this.epochId,
      sequenceNumber: sequenceStr,
      ticketId: ticket.ticketId,
      authorizationId: ticket.authorizationId,
      bindingDigest: ticket.bindingDigest,
      policyId: ticket.policyId,
      policyRevision: ticket.policyRevision,
      debitedAmount,
      budgetWindows: windowAllocations,
      committedAtSeconds: now,
    };

    const payload = canonicalWitnessReceiptPayload(receiptData);
    const signature = signAuthorizationPayload(this.privateKey, payload);

    const receipt: SignedWitnessReceipt = {
      ...receiptData,
      signature,
    };

    ticket.state = "COMMITTED";
    ticket.receipt = receipt;

    return {
      decision: "ALLOW",
      receipt,
      alreadyCommitted: false,
    };
  }

  public releaseTicket(request: WitnessReleaseRequest): WitnessReleaseResult {
    const ticket = this.tickets.get(request.ticketId);

    if (!ticket) {
      return { success: false, reasons: [`Ticket '${request.ticketId}' not found.`] };
    }

    if (
      ticket.authorizationId !== request.authorizationId ||
      ticket.bindingDigest !== request.bindingDigest
    ) {
      return {
        success: false,
        reasons: ["Binding digest or authorization ID mismatch on release."],
      };
    }

    // Idempotent release
    if (ticket.state === "RELEASED") {
      return { success: true, previousState: "RELEASED" };
    }

    // Terminal COMMITTED cannot be released
    if (ticket.state === "COMMITTED") {
      return {
        success: false,
        previousState: "COMMITTED",
        reasons: ["Ticket has already been committed and cannot be released."],
      };
    }

    this.sequence += 1n;
    const prevState = ticket.state;
    ticket.state = "RELEASED";
    ticket.releaseReason = request.reason;

    // Reclaim reserved budget
    for (const w of ticket.budgetWindows) {
      const key = `${ticket.policyId}:${w.windowType}:${w.windowStart}`;
      const acc = this.accumulators.get(key);
      if (acc) {
        const reqBig = BigInt(w.requestedAmount);
        acc.reserved = acc.reserved >= reqBig ? acc.reserved - reqBig : 0n;
      }
    }

    return {
      success: true,
      previousState: prevState,
    };
  }

  public reconcileTicket(request: WitnessReconcileRequest): WitnessReconcileResult {
    const now = this.getTimeSeconds();
    const ticket = this.tickets.get(request.ticketId);

    if (!ticket) {
      return {
        ticketId: request.ticketId,
        state: "DISPUTED",
        reasons: [`Ticket '${request.ticketId}' not found.`],
      };
    }

    // Auto-quarantine expired uncommitted reservations
    if (ticket.state === "RESERVED" && now > ticket.expiresAtSeconds) {
      ticket.state = "QUARANTINED_UNCONFIRMED";
      // Budget is NOT reclaimed; it remains quarantined!
    }

    return {
      ticketId: ticket.ticketId,
      state: ticket.state,
      receipt: ticket.receipt,
    };
  }

  public listUnfinalizedTickets(): UnfinalizedWitnessTicket[] {
    const unfinalized: UnfinalizedWitnessTicket[] = [];
    const now = this.getTimeSeconds();

    for (const ticket of this.tickets.values()) {
      if (ticket.state === "RESERVED" || ticket.state === "QUARANTINED_UNCONFIRMED") {
        if (ticket.state === "RESERVED" && now > ticket.expiresAtSeconds) {
          ticket.state = "QUARANTINED_UNCONFIRMED";
        }
        unfinalized.push({
          ticketId: ticket.ticketId,
          authorizationId: ticket.authorizationId,
          bindingDigest: ticket.bindingDigest,
          state: ticket.state,
          reservedAtSeconds: ticket.reservedAtSeconds,
          expiresAtSeconds: ticket.expiresAtSeconds,
        });
      }
    }

    return unfinalized;
  }
}
