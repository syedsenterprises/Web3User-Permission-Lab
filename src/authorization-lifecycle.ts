import type { AuthorizationIdStore } from "./authorization-store.js";
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
 * Authorization IDs are trimmed, non-empty strings. Comparison is
 * case-sensitive; the caller is responsible for issuing and binding IDs.
 */
function normalizeAuthorizationId(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const normalized = input.trim();
  return normalized.length > 0 ? normalized : null;
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
 * Consume an authorization using an ID supplied by the caller.
 *
 * IDs are trimmed and compared case-sensitively. A successful ID is
 * reserved only after policy revalidation succeeds. Replay state is
 * process-local and is lost on restart; this API is not durable or shared
 * across processes. The caller is responsible for ID issuance and binding.
 */
export function consumeTransactionAuthorizationById(
  authorizationIdInput: unknown,
  policyInput: unknown,
  envelopeInput: unknown,
  candidateInput: unknown,
  contextInput: unknown,
): TransactionAuthorization {
  const authorizationId = normalizeAuthorizationId(authorizationIdInput);
  if (authorizationId === null) {
    return deny("A non-empty authorization ID is required.");
  }

  return consume(
    policyInput,
    envelopeInput,
    candidateInput,
    contextInput,
    authorizationId,
  );
}

/**
 * Persistent authorization-consumption boundary.
 *
 * Revalidates request binding and current policy/context before atomically
 * reserving the normalized ID. All callers that need shared replay
 * protection must use the same durable database. IDs are trimmed and
 * compared case-sensitively; the caller remains responsible for ID
 * issuance and binding. Storage errors propagate to the caller; this
 * function never falls back to process-local reservation on storage error.
 * This does not sign or submit a transaction.
 */
export function consumeTransactionAuthorizationWithStore(
  store: AuthorizationIdStore,
  authorizationIdInput: unknown,
  policyInput: unknown,
  envelopeInput: unknown,
  candidateInput: unknown,
  contextInput: unknown,
): TransactionAuthorization {
  const authorizationId = normalizeAuthorizationId(authorizationIdInput);
  if (authorizationId === null) {
    return deny("A non-empty authorization ID is required.");
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

  // SQLite or custom-store errors intentionally propagate. No success result
  // is returned unless persistent reservation has completed successfully.
  if (!store.reserve(authorizationId)) {
    return deny("Transaction authorization ID has already been consumed.");
  }

  consumedEnvelopes.add(result.envelope);
  return result;
}
