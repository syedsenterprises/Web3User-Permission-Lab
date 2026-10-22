import {
  revalidateTransactionAuthorization,
  type TransactionAuthorization,
} from "./policy-transaction.js";
import type { TransactionEnvelope } from "./transaction-envelope.js";

const consumedEnvelopes = new WeakSet<object>();
const consumedAuthorizationIds = new Set<string>();

function isObject(value: unknown): value is object {
  return typeof value === "object" && value !== null;
}

function deny(reason: string): TransactionAuthorization {
  return {
    decision: "DENY",
    reasons: [reason],
  };
}

/**
 * Revalidate and consume an authorization synchronously.
 *
 * Envelope consumption and optional authorization-ID consumption share
 * the same internal path. State is process-local and is not durable
 * across restarts or shared across processes.
 */
function consume(
  policyInput: unknown,
  envelopeInput: unknown,
  candidateInput: unknown,
  contextInput: unknown,
  authorizationId?: string,
): TransactionAuthorization {
  if (authorizationId !== undefined &&
      consumedAuthorizationIds.has(authorizationId)) {
    return deny("Transaction authorization ID has already been consumed.");
  }

  if (isObject(envelopeInput) && consumedEnvelopes.has(envelopeInput)) {
    return deny("Transaction authorization has already been consumed.");
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

  // Defensive check before reserving either identifier.
  if (consumedEnvelopes.has(envelope)) {
    return deny("Transaction authorization has already been consumed.");
  }

  if (authorizationId !== undefined) {
    consumedAuthorizationIds.add(authorizationId);
  }

  consumedEnvelopes.add(envelope);
  return result;
}

/**
 * Revalidate and consume an approved envelope exactly once per process.
 * This does not sign or submit a transaction.
 */
export function consumeTransactionAuthorization(
  policyInput: unknown,
  envelopeInput: unknown,
  candidateInput: unknown,
  contextInput: unknown,
): TransactionAuthorization {
  return consume(
    policyInput,
    envelopeInput,
    candidateInput,
    contextInput,
  );
}

/**
 * Consume an authorization using a stable ID from a trusted issuer.
 *
 * A successful ID is reserved only after policy revalidation succeeds.
 * IDs and envelope consumption are process-local; this is not durable
 * or distributed replay protection.
 */
export function consumeTransactionAuthorizationById(
  authorizationIdInput: unknown,
  policyInput: unknown,
  envelopeInput: unknown,
  candidateInput: unknown,
  contextInput: unknown,
): TransactionAuthorization {
  if (
    typeof authorizationIdInput !== "string" ||
    authorizationIdInput.trim().length === 0
  ) {
    return deny("A non-empty authorization ID is required.");
  }

  return consume(
    policyInput,
    envelopeInput,
    candidateInput,
    contextInput,
    authorizationIdInput.trim(),
  );
}
