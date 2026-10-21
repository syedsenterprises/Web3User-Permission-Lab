import {
  revalidateTransactionAuthorization,
  type TransactionAuthorization,
} from "./policy-transaction.js";
import type { TransactionEnvelope } from "./transaction-envelope.js";

const consumedEnvelopes = new WeakSet<object>();

function isObject(value: unknown): value is object {
  return typeof value === "object" && value !== null;
}

/**
 * Revalidate and consume an approved envelope exactly once per process.
 *
 * This operation is synchronous: checking and recording consumption happen
 * without an asynchronous gap. It does not sign or submit a transaction.
 *
 * The registry is process-local and is not durable across restarts.
 */
export function consumeTransactionAuthorization(
  policyInput: unknown,
  envelopeInput: unknown,
  candidateInput: unknown,
  contextInput: unknown,
): TransactionAuthorization {
  if (isObject(envelopeInput) && consumedEnvelopes.has(envelopeInput)) {
    return {
      decision: "DENY",
      reasons: ["Transaction authorization has already been consumed."],
    };
  }

  const result = revalidateTransactionAuthorization(
    policyInput,
    envelopeInput,
    candidateInput,
    contextInput,
  );

  if (result.decision !== "ALLOW") {
    return result;
  }

  const envelope: TransactionEnvelope = result.envelope;

  // Defensive check: this should always hold for a genuine approved envelope.
  if (consumedEnvelopes.has(envelope)) {
    return {
      decision: "DENY",
      reasons: ["Transaction authorization has already been consumed."],
    };
  }

  consumedEnvelopes.add(envelope);
  return result;
}
