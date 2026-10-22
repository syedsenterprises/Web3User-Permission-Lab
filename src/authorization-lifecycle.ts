import type { KeyObject } from "node:crypto";
import type { AuthorizationIdStore } from "./authorization-store.js";
import {
  revalidateTransactionAuthorization,
  type TransactionAuthorization,
} from "./policy-transaction.js";
import type { TransactionEnvelope } from "./transaction-envelope.js";
import type { BoundAuthorizationIdStore } from "./authorization-store.js";
import {
  BOUND_AUTHORIZATION_ARTIFACT_VERSION,
  createAuthorizationBindingDigest,
  isBoundAuthorizationArtifact,
  type BoundAuthorizationArtifact,
} from "./authorization-binding.js";
import {
  SIGNED_AUTHORIZATION_ARTIFACT_VERSION,
  canonicalSignedPayload,
  isSignedAuthorizationArtifact,
  signAuthorizationPayload,
  verifyAuthorizationPayload,
  type SignedAuthorizationArtifact,
} from "./authorization-crypto.js";
import type { KeyRegistry } from "./key-registry.js";
import { prepareTransactionAuthorization } from "./policy-transaction.js";
import { normalizeDemoPolicy, type Evaluation } from "./policy.js";

const consumedEnvelopes = new WeakSet<object>();
const consumedAuthorizationIds = new Set<string>();

function isObject(value: unknown): value is object {
  return typeof value === "object" && value !== null;
}

function deny(reason: string): Evaluation & { decision: "DENY" } {
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

export type BoundTransactionAuthorization =
  | (Evaluation & {
      decision: "ALLOW";
      envelope: TransactionEnvelope;
      artifact: BoundAuthorizationArtifact;
    })
  | (Evaluation & {
      decision: "DENY" | "UNKNOWN";
    });

export type SignedTransactionAuthorization =
  | (Evaluation & {
      decision: "ALLOW";
      envelope: TransactionEnvelope;
      artifact: SignedAuthorizationArtifact;
    })
  | (Evaluation & {
      decision: "DENY" | "UNKNOWN";
    });

function parseArtifact(input: unknown): BoundAuthorizationArtifact | null {
  if (!isBoundAuthorizationArtifact(input)) return null;

  const authorizationId = normalizeAuthorizationId(input.authorizationId);
  if (authorizationId === null || authorizationId !== input.authorizationId) {
    return null;
  }

  return input;
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

/**
 * Issue a serializable, versioned artifact whose ID is persisted together
 * with a digest of the canonical policy and request. The caller must be a
 * trusted issuer; the digest itself does not prove issuer identity.
 */
export function issueBoundTransactionAuthorizationWithStore(
  store: BoundAuthorizationIdStore,
  authorizationIdInput: unknown,
  policyInput: unknown,
  requestInput: unknown,
  contextInput: unknown,
): BoundTransactionAuthorization {
  const authorizationId = normalizeAuthorizationId(authorizationIdInput);
  if (authorizationId === null) {
    return deny("A non-empty authorization ID is required.");
  }

  const prepared = prepareTransactionAuthorization(
    policyInput,
    requestInput,
    contextInput,
  );

  if (prepared.decision !== "ALLOW") {
    return prepared;
  }

  const policy = normalizeDemoPolicy(policyInput);
  if (policy === null) {
    return {
      decision: "UNKNOWN",
      reasons: ["Policy is malformed or unsupported."],
    };
  }

  const bindingDigest = createAuthorizationBindingDigest(
    policy,
    prepared.envelope.request,
  );

  if (!store.issueBound(authorizationId, bindingDigest, BOUND_AUTHORIZATION_ARTIFACT_VERSION)) {
    return deny("Transaction authorization ID has already been issued or consumed.");
  }

  return {
    ...prepared,
    artifact: Object.freeze({
      version: BOUND_AUTHORIZATION_ARTIFACT_VERSION,
      authorizationId,
      bindingDigest,
    }),
  };
}

/**
 * Revalidate an artifact's policy and envelope binding before atomically
 * consuming the matching issued ID. This never falls back to in-memory state.
 * Enforces artifact_version = 1 in the storage transition.
 */
export function consumeBoundTransactionAuthorizationWithStore(
  store: BoundAuthorizationIdStore,
  artifactInput: unknown,
  policyInput: unknown,
  envelopeInput: unknown,
  candidateInput: unknown,
  contextInput: unknown,
): TransactionAuthorization {
  const artifact = parseArtifact(artifactInput);
  if (artifact === null) {
    return deny("Bound transaction authorization artifact is invalid.");
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

  const policy = normalizeDemoPolicy(policyInput);
  if (policy === null) {
    return {
      decision: "UNKNOWN",
      reasons: ["Policy is malformed or unsupported."],
    };
  }

  const bindingDigest = createAuthorizationBindingDigest(
    policy,
    result.envelope.request,
  );

  if (bindingDigest !== artifact.bindingDigest) {
    return deny("Transaction does not match the bound authorization artifact.");
  }

  if (!store.consumeBound(artifact.authorizationId, bindingDigest, artifact.version)) {
    return deny("Bound transaction authorization is unknown, consumed, or mismatched.");
  }

  return result;
}

/**
 * Issue a versioned, cryptographically signed authorization artifact whose ID
 * is persisted with the canonical request and policy binding digest.
 * An Ed25519 signature is computed over the artifact version, authorization ID,
 * key ID, and binding digest.
 */
export function issueSignedTransactionAuthorizationWithStore(
  store: BoundAuthorizationIdStore,
  keyRegistry: KeyRegistry,
  signer: {
    readonly keyId: string;
    readonly privateKey: KeyObject | string;
  },
  authorizationIdInput: unknown,
  policyInput: unknown,
  requestInput: unknown,
  contextInput: unknown,
): SignedTransactionAuthorization {
  const authorizationId = normalizeAuthorizationId(authorizationIdInput);
  if (authorizationId === null) {
    return deny("A non-empty authorization ID is required.");
  }

  if (typeof signer !== "object" || signer === null) {
    return deny("Signer specification is required.");
  }

  const keyId = normalizeAuthorizationId(signer.keyId);
  if (keyId === null) {
    return deny("A non-empty key ID is required.");
  }

  const keyMeta = keyRegistry.getKey(keyId);
  if (keyMeta === null) {
    return deny("Issuer key is unknown.");
  }

  if (keyMeta.status === "revoked") {
    return deny("Issuer key has been revoked.");
  }

  if (keyMeta.status === "retired") {
    return deny("Issuer key is retired and cannot issue new authorizations.");
  }

  if (keyMeta.status !== "active") {
    return deny("Issuer key is not active.");
  }

  if (
    typeof contextInput === "object" &&
    contextInput !== null &&
    "nowSeconds" in contextInput &&
    typeof (contextInput as { nowSeconds: unknown }).nowSeconds === "number"
  ) {
    const now = (contextInput as { nowSeconds: number }).nowSeconds;
    if (keyMeta.validFromSeconds !== undefined && now < keyMeta.validFromSeconds) {
      return deny("Issuer key is not yet valid.");
    }
    if (keyMeta.expiresAtSeconds !== undefined && now >= keyMeta.expiresAtSeconds) {
      return deny("Issuer key has expired.");
    }
  }

  const prepared = prepareTransactionAuthorization(
    policyInput,
    requestInput,
    contextInput,
  );

  if (prepared.decision !== "ALLOW") {
    return prepared;
  }

  const policy = normalizeDemoPolicy(policyInput);
  if (policy === null) {
    return {
      decision: "UNKNOWN",
      reasons: ["Policy is malformed or unsupported."],
    };
  }

  const bindingDigest = createAuthorizationBindingDigest(
    policy,
    prepared.envelope.request,
  );

  const payload = canonicalSignedPayload(
    SIGNED_AUTHORIZATION_ARTIFACT_VERSION,
    authorizationId,
    keyId,
    bindingDigest,
  );

  let signature: string;
  try {
    signature = signAuthorizationPayload(signer.privateKey, payload);
  } catch {
    return deny("Failed to sign authorization payload.");
  }

  // Pre-flight correspondence verification: ensure the private key corresponds to the registered public key
  const isValidKeypair = verifyAuthorizationPayload(
    keyMeta.publicKey,
    payload,
    signature,
  );

  if (!isValidKeypair) {
    return deny("Signer private key does not match the registered public key.");
  }

  if (!store.issueBound(authorizationId, bindingDigest, SIGNED_AUTHORIZATION_ARTIFACT_VERSION)) {
    return deny("Transaction authorization ID has already been issued or consumed.");
  }

  return {
    ...prepared,
    artifact: Object.freeze({
      version: SIGNED_AUTHORIZATION_ARTIFACT_VERSION,
      authorizationId,
      keyId,
      bindingDigest,
      signature,
    }),
  };
}

/**
 * Revalidate an Ed25519-signed artifact's cryptographic signature, key status,
 * policy, and envelope binding before atomically consuming the issued ID in SQLite.
 *
 * CRITICAL INVARIANT: Format parsing, key status verification, and Ed25519
 * signature verification occur BEFORE policy revalidation and BEFORE calling
 * the database. Forged, tampered, or invalid signatures fail closed immediately
 * without touching SQLite storage.
 * Enforces artifact_version = 2 in the storage transition.
 */
export function consumeSignedTransactionAuthorizationWithStore(
  store: BoundAuthorizationIdStore,
  keyRegistry: KeyRegistry,
  artifactInput: unknown,
  policyInput: unknown,
  envelopeInput: unknown,
  candidateInput: unknown,
  contextInput: unknown,
): TransactionAuthorization {
  if (!isSignedAuthorizationArtifact(artifactInput)) {
    return deny("Signed transaction authorization artifact is invalid.");
  }

  const artifact: SignedAuthorizationArtifact = artifactInput;

  const keyMeta = keyRegistry.getKey(artifact.keyId);
  if (keyMeta === null) {
    return deny("Issuer key is unknown.");
  }

  if (keyMeta.status === "revoked") {
    return deny("Issuer key has been revoked.");
  }

  if (keyMeta.status !== "active" && keyMeta.status !== "retired") {
    return deny("Issuer key status does not permit verification.");
  }

  if (
    typeof contextInput === "object" &&
    contextInput !== null &&
    "nowSeconds" in contextInput &&
    typeof (contextInput as { nowSeconds: unknown }).nowSeconds === "number"
  ) {
    const now = (contextInput as { nowSeconds: number }).nowSeconds;
    if (keyMeta.validFromSeconds !== undefined && now < keyMeta.validFromSeconds) {
      return deny("Issuer key is not yet valid.");
    }
    if (keyMeta.expiresAtSeconds !== undefined && now >= keyMeta.expiresAtSeconds) {
      return deny("Issuer key has expired.");
    }
  }

  const payload = canonicalSignedPayload(
    artifact.version,
    artifact.authorizationId,
    artifact.keyId,
    artifact.bindingDigest,
  );

  const isValidSignature = verifyAuthorizationPayload(
    keyMeta.publicKey,
    payload,
    artifact.signature,
  );

  if (!isValidSignature) {
    return deny("Invalid authorization artifact signature.");
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

  const policy = normalizeDemoPolicy(policyInput);
  if (policy === null) {
    return {
      decision: "UNKNOWN",
      reasons: ["Policy is malformed or unsupported."],
    };
  }

  const bindingDigest = createAuthorizationBindingDigest(
    policy,
    result.envelope.request,
  );

  if (bindingDigest !== artifact.bindingDigest) {
    return deny("Transaction does not match the bound authorization artifact.");
  }

  if (!store.consumeBound(artifact.authorizationId, bindingDigest, artifact.version)) {
    return deny("Bound transaction authorization is unknown, consumed, or mismatched.");
  }

  return result;
}
