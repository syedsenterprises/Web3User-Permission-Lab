
/**
 * Web3User Permission Lab â€” transaction authorization envelope.
 *
 * SECURITY CONTRACT:
 * - Envelopes are recognized only if created by this module instance.
 * - The request is a frozen, canonical snapshot.
 * - This module does not connect to a wallet or execute transactions.
 * - Callers must revalidate immediately before any future submission.
 * - This is an in-process integrity check, not cryptographic authorization.
 */

export interface TransactionRequest {
  /** Positive EVM chain ID, represented as a decimal string. */
  chainId: string;
  /** Transaction sender address. */
  sender: string;
  /** Destination contract address. */
  target: string;
  /** Complete transaction calldata. */
  calldata: string;
  /** Native token value in base-10 wei. */
  value: string;
}

export interface TransactionEnvelope {
  readonly request: Readonly<TransactionRequest>;
}

export type EnvelopeResult =
  | { ok: true; envelope: TransactionEnvelope }
  | { ok: false; reason: string };

const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
export const MAX_CALLDATA_HEX_LENGTH = 131074; // 0x + 64KB (131072 hex characters)
const HEX_DATA = /^0x(?:[a-fA-F0-9]{2})*$/;
const UINT = /^(0|[1-9][0-9]*)$/;
const MAX_UINT256 = (1n << 256n) - 1n;

/**
 * Only envelope objects created by this module instance are accepted.
 * WeakSet tracking does not keep envelopes alive by itself.
 */
const issuedEnvelopes = new WeakSet<object>();

function isUint256(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    !UINT.test(value) ||
    value.length > 78
  ) {
    return false;
  }

  try {
    return BigInt(value) <= MAX_UINT256;
  } catch {
    return false;
  }
}

function isValidChainId(value: unknown): value is string {
  if (!isUint256(value)) return false;

  try {
    return BigInt(value) > 0n;
  } catch {
    return false;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

/**
 * Validate and snapshot a transaction request.
 *
 * Hexadecimal casing is normalized. Decimal strings must already
 * use canonical base-10 notation.
 */
export function createTransactionEnvelope(
  input: unknown,
): EnvelopeResult {
  if (!isRecord(input)) {
    return {
      ok: false,
      reason: "Transaction request must be an object.",
    };
  }

  const { chainId, sender, target, calldata, value } = input;

  if (!isValidChainId(chainId)) {
    return {
      ok: false,
      reason: "Chain ID must be a positive uint256 decimal string.",
    };
  }

  if (typeof sender !== "string" || !ADDRESS.test(sender)) {
    return { ok: false, reason: "Sender address is invalid." };
  }

  if (typeof target !== "string" || !ADDRESS.test(target)) {
    return { ok: false, reason: "Target address is invalid." };
  }

  if (typeof calldata !== "string") {
    return {
      ok: false,
      reason: "Calldata must be 0x-prefixed, even-length hexadecimal data.",
    };
  }

  if (calldata.length > MAX_CALLDATA_HEX_LENGTH) {
    return {
      ok: false,
      reason: `Calldata exceeds maximum allowed length of ${MAX_CALLDATA_HEX_LENGTH} characters.`,
    };
  }

  if (!HEX_DATA.test(calldata)) {
    return {
      ok: false,
      reason: "Calldata must be 0x-prefixed, even-length hexadecimal data.",
    };
  }

  if (!isUint256(value)) {
    return {
      ok: false,
      reason: "Transaction value must be a uint256 decimal string.",
    };
  }

  const request: Readonly<TransactionRequest> = Object.freeze({
    chainId,
    sender: sender.toLowerCase(),
    target: target.toLowerCase(),
    calldata: calldata.toLowerCase(),
    value,
  });

  const envelope: TransactionEnvelope = Object.freeze({ request });

  issuedEnvelopes.add(envelope);

  return { ok: true, envelope };
}

/**
 * Check whether a candidate request matches an envelope issued by
 * this module instance. Invalid candidates fail closed.
 */
export function matchesTransactionEnvelope(
  envelope: unknown,
  candidate: unknown,
): envelope is TransactionEnvelope {
  if (
    !isRecord(envelope) ||
    !issuedEnvelopes.has(envelope) ||
    !isRecord(envelope.request)
  ) {
    return false;
  }

  const validated = createTransactionEnvelope(candidate);
  if (!validated.ok) return false;

  const approved = envelope.request;
  const current = validated.envelope.request;

  return (
    approved.chainId === current.chainId &&
    approved.sender === current.sender &&
    approved.target === current.target &&
    approved.calldata === current.calldata &&
    approved.value === current.value
  );
}
