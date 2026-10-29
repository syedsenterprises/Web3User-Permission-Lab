import type { KeyObject } from "node:crypto";
import type { AuthorizationIdStore } from "./authorization-store.js";
import { type ClockCandidate } from "./clock.js";
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
  SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3,
  canonicalSignedPayload,
  canonicalSignedPayloadV3,
  isSignedAuthorizationArtifact,
  isSignedAuthorizationArtifactV3,
  parseEd25519PublicKey,
  signAuthorizationPayload,
  verifyAuthorizationPayload,
  type SignedAuthorizationArtifact,
  type SignedAuthorizationArtifactV3,
} from "./authorization-crypto.js";
import { SQLiteAuthorizationStore } from "./authorization-store.js";
import {
  beginImmediateWithRetry,
  isFatalIOError,
  CONTENTION_RETRY_DELAY_MS,
  MAX_CONTENTION_RETRIES,
} from "./sqlite-transaction.js";
import type { KeyRegistry } from "./key-registry.js";
import { prepareTransactionAuthorization } from "./policy-transaction.js";
import {
  normalizeDemoPolicy,
  decodeTransfer,
  BUDGET_WINDOW_SECONDS,
  calculateBudgetWindowStart,
  type BudgetWindowType,
  type Evaluation,
} from "./policy.js";
import {
  type MonotonicWitnessAdapter,
  type SignedWitnessReceipt,
} from "./monotonic-witness.js";

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

export const MAX_AUTHORIZATION_ID_LENGTH = 128;
export const MAX_PROCESS_LOCAL_CONSUMED_IDS = 10_000;

export function getConsumedAuthorizationIdsCount(): number {
  return consumedAuthorizationIds.size;
}

/**
 * Validates an authorization ID, ensuring it is a non-empty string of bounded length.
 */
export function validateAuthorizationId(
  input: unknown,
): { ok: true; id: string } | { ok: false; reason: string } {
  if (typeof input !== "string") {
    return { ok: false, reason: "A non-empty authorization ID is required." };
  }
  const normalized = input.trim();
  if (normalized.length === 0) {
    return { ok: false, reason: "A non-empty authorization ID is required." };
  }
  if (normalized.length > MAX_AUTHORIZATION_ID_LENGTH) {
    return {
      ok: false,
      reason: `Authorization ID exceeds maximum length of ${MAX_AUTHORIZATION_ID_LENGTH} characters.`,
    };
  }
  return { ok: true, id: normalized };
}

/**
 * Authorization IDs are trimmed, non-empty strings of at most 128 characters.
 * Comparison is case-sensitive; the caller is responsible for issuing and binding IDs.
 */
function normalizeAuthorizationId(input: unknown): string | null {
  const result = validateAuthorizationId(input);
  return result.ok ? result.id : null;
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
  if (authorizationId !== undefined) {
    if (consumedAuthorizationIds.has(authorizationId)) {
      return deny("Transaction authorization ID has already been consumed.");
    }
    if (consumedAuthorizationIds.size >= MAX_PROCESS_LOCAL_CONSUMED_IDS) {
      return deny("Process-local authorization capacity exceeded; durable storage is required for long-running replay protection.");
    }
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
    if (consumedAuthorizationIds.size >= MAX_PROCESS_LOCAL_CONSUMED_IDS) {
      return deny("Process-local authorization capacity exceeded; durable storage is required for long-running replay protection.");
    }
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
  const authValidation = validateAuthorizationId(authorizationIdInput);
  if (!authValidation.ok) {
    return deny(authValidation.reason);
  }
  const authorizationId = authValidation.id;

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
  const authValidation = validateAuthorizationId(authorizationIdInput);
  if (!authValidation.ok) {
    return deny(authValidation.reason);
  }
  const authorizationId = authValidation.id;

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
  const authValidation = validateAuthorizationId(authorizationIdInput);
  if (!authValidation.ok) {
    return deny(authValidation.reason);
  }
  const authorizationId = authValidation.id;

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
  const authValidation = validateAuthorizationId(authorizationIdInput);
  if (!authValidation.ok) {
    return deny(authValidation.reason);
  }
  const authorizationId = authValidation.id;

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


export const DEFAULT_AUTHORIZATION_TTL_SECONDS = 300;

export interface IssueAuthorizationV3Options {
  /**
   * Desired authorization time-to-live in seconds.
   * If omitted, defaults to DEFAULT_AUTHORIZATION_TTL_SECONDS (300).
   * Bounded by policy expiry and key expiry.
   */
  readonly ttlSeconds?: number;
}


export type SignedTransactionAuthorizationV3 =
  | (Evaluation & {
      decision: "ALLOW";
      envelope: TransactionEnvelope;
      artifact: SignedAuthorizationArtifactV3;
    })
  | (Evaluation & {
      decision: "DENY" | "UNKNOWN";
    });

export interface V3Signer {
  readonly keyId: string;
  readonly privateKey: KeyObject | string;
}

/**
 * Issue an Ed25519-signed authorization artifact v3 bound to authoritative
 * SQLite governance state.
 *
 * Atomically verifies the authoritative policy revision and active status,
 * verifies the issuer key status and validity window, validates the transaction
 * request, signs the canonical V3 payload with explicit expiration deadline,
 * and persists the issued record.
 */
export function issueSignedTransactionAuthorizationV3(
  storeInput: SQLiteAuthorizationStore | { store: SQLiteAuthorizationStore },
  signer: V3Signer,
  authorizationIdInput: unknown,
  policyIdInput: unknown,
  requestInput: unknown,
  options?: IssueAuthorizationV3Options,
): SignedTransactionAuthorizationV3 {
  const store = storeInput instanceof SQLiteAuthorizationStore ? storeInput : storeInput.store;
  if (!store || !(store instanceof SQLiteAuthorizationStore)) {
    return deny("A valid SQLiteAuthorizationStore instance is required.");
  }

  const authValidation = validateAuthorizationId(authorizationIdInput);
  if (!authValidation.ok) {
    return deny(authValidation.reason);
  }
  const authorizationId = authValidation.id;

  if (typeof signer !== "object" || signer === null) {
    return deny("Signer specification is required.");
  }

  const keyId = normalizeAuthorizationId(signer.keyId);
  if (keyId === null) {
    return deny("A non-empty key ID is required.");
  }

  let policyId: string | null = null;
  if (typeof policyIdInput === "string") {
    policyId = normalizeAuthorizationId(policyIdInput);
  } else if (typeof policyIdInput === "object" && policyIdInput !== null && "policyId" in policyIdInput) {
    policyId = normalizeAuthorizationId((policyIdInput as { policyId: unknown }).policyId);
  }
  if (policyId === null) {
    return deny("A non-empty policy ID is required.");
  }

  // 1. Check tainted store state and acquire in-process lock
  if (store.isTainted()) {
    return deny(
      `SQLiteAuthorizationStore database connection is tainted and unusable: ${store.getTaintedReason()}`,
    );
  }

  const guard = store.getClockGuard();
  if (!guard.acquireLock()) {
    return deny("Concurrent transaction in progress within same process; operation serialized.");
  }

  let db: ReturnType<typeof store.getDatabase>;
  try {
    db = store.getDatabase();
  } catch (err) {
    guard.releaseLock();
    return deny(err instanceof Error ? err.message : String(err));
  }

  try {
    if (!beginImmediateWithRetry(db)) {
      guard.releaseLock();
      return deny("Database is busy; transaction contention retry limit exceeded.");
    }
  } catch (err) {
    guard.releaseLock();
    throw err;
  }

  let candidate: ClockCandidate;

  try {
    // 2. Validate candidate time against guard and persisted high-water mark inside write lock
    const clock = store.getClock();
    candidate = {
      wallSeconds: clock.nowSeconds(),
      monotonicNanos: guard.getMonotonicClock().nowNanoseconds(),
    };

    const clockRow = db.prepare(
      "SELECT high_water_seconds FROM system_clock_state WHERE id = 1"
    ).get() as { high_water_seconds: number } | undefined;

    if (!clockRow) {
      db.exec("ROLLBACK;");
      return deny("System clock state is missing or corrupted.");
    }

    const highWaterSeconds = clockRow.high_water_seconds;

    const clockEval = guard.evaluateCandidate(candidate, highWaterSeconds);
    if (clockEval.decision !== "ALLOW") {
      db.exec("ROLLBACK;");
      return deny(clockEval.reason ?? "Clock evaluation failed.");
    }

    const currentNow = candidate.wallSeconds;
    const effectiveNowSeconds = Math.max(currentNow, highWaterSeconds);

    if (effectiveNowSeconds > highWaterSeconds) {
      db.prepare(`
        UPDATE system_clock_state
        SET high_water_seconds = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
      `).run(effectiveNowSeconds);
    }

    // 3. Load authoritative policy and revision from SQLite
    const polRow = db.prepare(
      "SELECT current_revision, status, policy_json FROM policies WHERE policy_id = ?"
    ).get(policyId) as {
      current_revision: number;
      status: string;
      policy_json: string;
    } | undefined;

    if (!polRow) {
      db.exec("ROLLBACK;");
      return deny(`Policy '${policyId}' not found.`);
    }

    if (polRow.status === "revoked") {
      db.exec("ROLLBACK;");
      return deny("Policy has been revoked.");
    }
    if (polRow.status === "retired") {
      db.exec("ROLLBACK;");
      return deny("Policy has been retired.");
    }
    if (polRow.status !== "active") {
      db.exec("ROLLBACK;");
      return deny("Policy is not active.");
    }

    const authoritativePolicy = normalizeDemoPolicy(JSON.parse(polRow.policy_json));
    if (!authoritativePolicy) {
      db.exec("ROLLBACK;");
      return {
        decision: "UNKNOWN",
        reasons: ["Authoritative policy is malformed."],
      };
    }
    const currentRevision = polRow.current_revision;

    // 4. Load issuer key and verify status and validity window
    const keyRow = db.prepare(
      "SELECT public_key_pem, status, valid_from_seconds, expires_at_seconds, retired_at_seconds, revoked_at_seconds FROM issuer_keys WHERE key_id = ?"
    ).get(keyId) as {
      public_key_pem: string;
      status: string;
      valid_from_seconds: number | null;
      expires_at_seconds: number | null;
      retired_at_seconds: number | null;
      revoked_at_seconds: number | null;
    } | undefined;

    if (!keyRow) {
      db.exec("ROLLBACK;");
      return deny("Issuer key is unknown.");
    }

    if (keyRow.status === "revoked") {
      db.exec("ROLLBACK;");
      return deny("Issuer key has been revoked.");
    }
    if (keyRow.status === "retired") {
      db.exec("ROLLBACK;");
      return deny("Issuer key is retired and cannot issue new authorizations.");
    }
    if (keyRow.status !== "active") {
      db.exec("ROLLBACK;");
      return deny("Issuer key is not active.");
    }

    if (keyRow.valid_from_seconds !== null && effectiveNowSeconds < keyRow.valid_from_seconds) {
      db.exec("ROLLBACK;");
      return deny("Issuer key is not yet valid.");
    }
    if (keyRow.expires_at_seconds !== null && effectiveNowSeconds >= keyRow.expires_at_seconds) {
      db.exec("ROLLBACK;");
      return deny("Issuer key has expired.");
    }

    const publicKey = parseEd25519PublicKey(keyRow.public_key_pem);
    if (!publicKey) {
      db.exec("ROLLBACK;");
      return deny("Corrupted issuer public key in storage.");
    }

    // 5. Establish authorization TTL and compute effective expiration deadline
    let ttlSeconds = DEFAULT_AUTHORIZATION_TTL_SECONDS;
    if (options !== undefined && options !== null) {
      if (typeof options !== "object" || Array.isArray(options)) {
        db.exec("ROLLBACK;");
        return deny("Options must be an object.");
      }
      const optObj = options as { ttlSeconds?: unknown };
      if (optObj.ttlSeconds !== undefined) {
        if (
          typeof optObj.ttlSeconds !== "number" ||
          !Number.isSafeInteger(optObj.ttlSeconds) ||
          optObj.ttlSeconds <= 0
        ) {
          db.exec("ROLLBACK;");
          return deny("Authorization TTL must be a positive safe integer.");
        }
        ttlSeconds = optObj.ttlSeconds;
      }
    }

    // Determine ceiling deadline across policy, issuer key, and maximum safe integer
    let maxAllowedExpiresAt = Number.MAX_SAFE_INTEGER;
    if (authoritativePolicy.expiresAt !== undefined && authoritativePolicy.expiresAt !== null) {
      maxAllowedExpiresAt = Math.min(maxAllowedExpiresAt, authoritativePolicy.expiresAt);
    }
    if (keyRow.expires_at_seconds !== null) {
      maxAllowedExpiresAt = Math.min(maxAllowedExpiresAt, keyRow.expires_at_seconds);
    }

    if (maxAllowedExpiresAt <= effectiveNowSeconds) {
      db.exec("ROLLBACK;");
      return deny("Authorization validity interval is empty: policy or issuer key has already expired.");
    }

    // Compute effective expiration without unsafe integer addition overflow:
    // If the requested TTL exceeds the remaining time until the deadline, cap at maxAllowedExpiresAt.
    // Otherwise, effectiveNowSeconds + ttlSeconds is guaranteed to be strictly within safe integer limits.
    const remainingValidSeconds = maxAllowedExpiresAt - effectiveNowSeconds;
    const effectiveExpiresAt =
      ttlSeconds >= remainingValidSeconds
        ? maxAllowedExpiresAt
        : effectiveNowSeconds + ttlSeconds;

    if (
      !Number.isSafeInteger(effectiveExpiresAt) ||
      effectiveExpiresAt < 0 ||
      effectiveExpiresAt <= effectiveNowSeconds
    ) {
      db.exec("ROLLBACK;");
      return deny("Authorization validity interval is empty: policy or issuer key has already expired.");
    }

    const expiresAtSeconds = effectiveExpiresAt;

    // 6. Validate transaction envelope against authoritative policy
    const prepared = prepareTransactionAuthorization(
      authoritativePolicy,
      requestInput,
      { nowSeconds: effectiveNowSeconds },
    );

    if (prepared.decision !== "ALLOW") {
      db.exec("ROLLBACK;");
      return prepared;
    }

    // 7. Bind authorization to exact request, policy ID, policy revision, key ID, issuance time, and expiry deadline
    const bindingDigest = createAuthorizationBindingDigest(
      authoritativePolicy,
      prepared.envelope.request,
    );

    const payload = canonicalSignedPayloadV3({
      version: SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3,
      authorizationId,
      keyId,
      issuedAtSeconds: effectiveNowSeconds,
      expiresAtSeconds,
      policyId: authoritativePolicy.policyId,
      policyRevision: currentRevision,
      bindingDigest,
    });

    // 8. Sign canonical payload
    let signature: string;
    try {
      signature = signAuthorizationPayload(signer.privateKey, payload);
    } catch {
      db.exec("ROLLBACK;");
      return deny("Failed to sign authorization payload.");
    }

    // Verify keypair correspondence
    if (!verifyAuthorizationPayload(publicKey, payload, signature)) {
      db.exec("ROLLBACK;");
      return deny("Signer private key does not match the registered public key.");
    }

    // 9. Persist authorization atomically
    const insertRes = db.prepare(`
      INSERT INTO consumed_authorization_ids (
        authorization_id, binding_digest, state, consumed_at, artifact_version, key_id, issued_at_seconds
      ) VALUES (?, ?, 'issued', NULL, ?, ?, ?)
      ON CONFLICT(authorization_id) DO NOTHING
    `).run(
      authorizationId,
      bindingDigest,
      SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3,
      keyId,
      effectiveNowSeconds,
    );

    if (insertRes.changes !== 1) {
      db.exec("ROLLBACK;");
      return deny("Transaction authorization ID has already been issued or consumed.");
    }

    try {
      db.exec("COMMIT;");
      guard.publishCandidate(candidate);
    } catch (commitErr) {
      const reason = `Commit failure with uncertain outcome: ${commitErr instanceof Error ? commitErr.message : String(commitErr)}`;
      store.markTainted(reason);
      throw commitErr;
    }

    return {
      ...prepared,
      artifact: Object.freeze({
        version: SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3,
        authorizationId,
        keyId,
        issuedAtSeconds: effectiveNowSeconds,
        expiresAtSeconds,
        policyId: authoritativePolicy.policyId,
        policyRevision: currentRevision,
        bindingDigest,
        signature,
      }),
    };
  } catch (err) {
    let rollbackFatalErr: unknown;
    try {
      db.exec("ROLLBACK;");
    } catch (rollbackErr) {
      if (isFatalIOError(rollbackErr)) {
        rollbackFatalErr = rollbackErr;
      }
    }
    if (rollbackFatalErr) {
      const reason = `Fatal rollback failure: ${rollbackFatalErr instanceof Error ? rollbackFatalErr.message : String(rollbackFatalErr)}`;
      store.markTainted(reason);
    } else if (isFatalIOError(err)) {
      const reason = `Fatal storage I/O error: ${err instanceof Error ? err.message : String(err)}`;
      store.markTainted(reason);
    }
    throw err;
  } finally {
    guard.releaseLock();
  }
}

export interface ConsumeSignedAuthorizationV3Options {
  readonly witnessAdapter?: MonotonicWitnessAdapter;
  readonly idempotencyKey?: string;
  readonly leaseTtlSeconds?: number;
}

function releaseWitnessTicket(
  adapter: MonotonicWitnessAdapter | undefined,
  authorizationId: string,
  bindingDigest: string,
  ticketId: string | undefined,
  reason: string,
): void {
  if (!adapter || !ticketId) return;
  try {
    const res = adapter.releaseTicket({
      ticketId,
      authorizationId,
      bindingDigest,
      reason,
    });
    if (res instanceof Promise) {
      res.catch(() => {});
    }
  } catch {
    // Suppress release error to preserve original denial reason
  }
}

/**
 * Revalidate and consume an Ed25519-signed authorization artifact v3 atomically
 * in SQLite.
 *
 * Performs cryptographic pre-verification of the Ed25519 signature outside the exclusive write
 * transaction to minimize lock hold duration and contention, then revalidates all mutable
 * governance and replay state (key status, revocation, policy revision, clock high-water, and
 * budget accumulators) transactionally within `BEGIN IMMEDIATE;` to guarantee strict TOCTOU safety.
 */
export function consumeSignedTransactionAuthorizationV3(
  storeInput: SQLiteAuthorizationStore | { store: SQLiteAuthorizationStore },
  artifactInput: unknown,
  envelopeInput: unknown,
  candidateInput: unknown,
  options?: ConsumeSignedAuthorizationV3Options,
): TransactionAuthorization {
  const store = storeInput instanceof SQLiteAuthorizationStore ? storeInput : storeInput.store;
  if (!store || !(store instanceof SQLiteAuthorizationStore)) {
    return deny("A valid SQLiteAuthorizationStore instance is required.");
  }

  // 1. Verify artifact version and format
  if (!isSignedAuthorizationArtifactV3(artifactInput)) {
    return deny("Signed transaction authorization artifact is invalid or malformed.");
  }
  const artifact: SignedAuthorizationArtifactV3 = artifactInput;

  // 2. Check tainted store state
  if (store.isTainted()) {
    return deny(
      `SQLiteAuthorizationStore database connection is tainted and unusable: ${store.getTaintedReason()}`,
    );
  }

  // Check in-process duplicate before acquiring locks
  if (isObject(envelopeInput) && consumedEnvelopes.has(envelopeInput)) {
    return deny("Transaction authorization has already been consumed.");
  }

  let db: ReturnType<typeof store.getDatabase>;
  try {
    db = store.getDatabase();
  } catch (err) {
    return deny(err instanceof Error ? err.message : String(err));
  }

  // 3. Pre-verification Step (outside exclusive write lock and ClockGuard mutex):
  // Read issuer key from storage for cryptographic pre-verification
  let preKeyRow: {
    public_key_pem: string;
    status: string;
    valid_from_seconds: number | null;
    expires_at_seconds: number | null;
    retired_at_seconds: number | null;
    revoked_at_seconds: number | null;
  } | undefined;

  try {
    preKeyRow = db.prepare(
      "SELECT public_key_pem, status, valid_from_seconds, expires_at_seconds, retired_at_seconds, revoked_at_seconds FROM issuer_keys WHERE key_id = ?"
    ).get(artifact.keyId) as typeof preKeyRow;
  } catch (err) {
    return deny(err instanceof Error ? err.message : String(err));
  }

  if (!preKeyRow) {
    return deny("Issuer key is unknown.");
  }

  if (preKeyRow.status === "revoked") {
    return deny("Issuer key has been revoked.");
  }

  if (preKeyRow.status !== "active" && preKeyRow.status !== "retired") {
    return deny("Issuer key status does not permit verification.");
  }

  // Post-retirement forgery rule (pre-check):
  // A retired key may validate only artifacts whose signed issuance time is strictly before retirement time
  if (preKeyRow.status === "retired") {
    if (preKeyRow.retired_at_seconds !== null && artifact.issuedAtSeconds >= preKeyRow.retired_at_seconds) {
      return deny("Authorization was issued after issuer key was retired.");
    }
  }

  // Key validity windows (pre-check based on signed issuance time)
  if (preKeyRow.valid_from_seconds !== null && artifact.issuedAtSeconds < preKeyRow.valid_from_seconds) {
    return deny("Issuer key was not yet valid at authorization issuance time.");
  }
  if (preKeyRow.expires_at_seconds !== null && artifact.issuedAtSeconds >= preKeyRow.expires_at_seconds) {
    return deny("Issuer key had expired at authorization issuance time.");
  }

  const prePublicKey = parseEd25519PublicKey(preKeyRow.public_key_pem);
  if (!prePublicKey) {
    return deny("Corrupted issuer public key in storage.");
  }

  // Verify Ed25519 cryptographic signature outside the exclusive write lock
  let payload: string;
  try {
    payload = canonicalSignedPayloadV3({
      version: artifact.version,
      authorizationId: artifact.authorizationId,
      keyId: artifact.keyId,
      issuedAtSeconds: artifact.issuedAtSeconds,
      expiresAtSeconds: artifact.expiresAtSeconds,
      policyId: artifact.policyId,
      policyRevision: artifact.policyRevision,
      bindingDigest: artifact.bindingDigest,
    });
  } catch {
    return deny("Failed to construct canonical signed payload.");
  }

  if (!verifyAuthorizationPayload(prePublicKey, payload, artifact.signature)) {
    return deny("Invalid authorization artifact signature.");
  }

  // Capture initial clock snapshot prior to lock acquisition.
  // Models caller-side pre-lock time and establishes the baseline for SEC-63-01 TOCTOU race testing.
  const initialNow = store.getClock().nowSeconds();
  void initialNow;

  // 3a. Replay & Single-Use Fast-Path Check (outside exclusive write lock)
  // Prevents reserving or looking up witness tickets for authorizations that are already consumed.
  if (isObject(envelopeInput) && consumedEnvelopes.has(envelopeInput)) {
    return deny("Transaction authorization has already been consumed.");
  }

  try {
    const earlyAuthRow = db.prepare(
      "SELECT state FROM consumed_authorization_ids WHERE authorization_id = ?"
    ).get(artifact.authorizationId) as { state: string } | undefined;

    if (earlyAuthRow && earlyAuthRow.state === "consumed") {
      return deny("Bound transaction authorization is unknown, consumed, or mismatched.");
    }
  } catch {
    // Non-fatal pre-check read error; proceed to strict in-lock enforcement
  }

  // 3b. Witness Pre-Reservation Step (outside exclusive write lock)
  let witnessTicketId: string | undefined;
  if (options?.witnessAdapter) {
    let budgetWindows: Array<{
      windowType: BudgetWindowType;
      windowStart: number;
      requestedAmount: string;
      maxCumulativeAmount: string;
    }> | undefined;

    let candidateAmount: bigint | undefined;
    let reqCalldata: string | undefined;
    if (isObject(candidateInput) && "calldata" in candidateInput && typeof (candidateInput as any).calldata === "string") {
      reqCalldata = (candidateInput as any).calldata;
    } else if (isObject(envelopeInput) && "request" in envelopeInput && isObject((envelopeInput as any).request) && typeof (envelopeInput as any).request.calldata === "string") {
      reqCalldata = (envelopeInput as any).request.calldata;
    }
    if (reqCalldata) {
      const decoded = decodeTransfer(reqCalldata);
      if (decoded) {
        candidateAmount = decoded.amount;
      }
    }

    try {
      const prePolRow = db.prepare(
        "SELECT current_revision, status, policy_json FROM policies WHERE policy_id = ?"
      ).get(artifact.policyId) as { current_revision: number; status: string; policy_json: string } | undefined;
      if (prePolRow && prePolRow.status === "active") {
        const pol = JSON.parse(prePolRow.policy_json);
        if (pol && pol.budget && candidateAmount !== undefined) {
          const nowSec = store.getClock().nowSeconds();
          const winStart = calculateBudgetWindowStart(nowSec, pol.budget.window);
          budgetWindows = [
            {
              windowType: pol.budget.window,
              windowStart: winStart,
              requestedAmount: candidateAmount.toString(10),
              maxCumulativeAmount: BigInt(pol.budget.maxCumulativeAmount).toString(10),
            },
          ];
        }
      }
    } catch {
      // Ignore pre-check read errors
    }

    const idempKey = options.idempotencyKey ?? `idemp-${artifact.authorizationId}-${artifact.bindingDigest.slice(-16)}`;
    const reserveResult = options.witnessAdapter.reserveTicket({
      authorizationId: artifact.authorizationId,
      bindingDigest: artifact.bindingDigest,
      policyId: artifact.policyId,
      policyRevision: artifact.policyRevision,
      budgetWindows,
      idempotencyKey: idempKey,
      leaseTtlSeconds: options.leaseTtlSeconds,
    });

    if (reserveResult instanceof Promise) {
      throw new Error(
        "Async witness adapters cannot be used with synchronous consumeSignedTransactionAuthorizationV3. Provide a synchronous witness adapter.",
      );
    }

    if (reserveResult.decision !== "ALLOW") {
      return {
        decision: "DENY",
        reasons: reserveResult.reasons ?? ["Witness reservation was denied."],
      };
    }

    witnessTicketId = reserveResult.ticketId;
  }

  const canReleaseWitnessOnPreLockAbort = (): boolean => {
    try {
      const row = db.prepare(
        "SELECT state FROM consumed_authorization_ids WHERE authorization_id = ?"
      ).get(artifact.authorizationId) as { state: string } | undefined;
      return !row || row.state !== "consumed";
    } catch {
      return false; // Fail-closed: do not release if state cannot be confirmed
    }
  };

  // 4. Acquire in-process lock and SQLite exclusive write lock
  const guard = store.getClockGuard();
  if (!guard.acquireLock()) {
    if (canReleaseWitnessOnPreLockAbort()) {
      releaseWitnessTicket(options?.witnessAdapter, artifact.authorizationId, artifact.bindingDigest, witnessTicketId, "IN_PROCESS_LOCK_CONTENTION");
    }
    return deny("Concurrent transaction in progress within same process; operation serialized.");
  }

  try {
    if (!beginImmediateWithRetry(db)) {
      if (canReleaseWitnessOnPreLockAbort()) {
        releaseWitnessTicket(options?.witnessAdapter, artifact.authorizationId, artifact.bindingDigest, witnessTicketId, "DATABASE_BUSY_CONTENTION");
      }
      guard.releaseLock();
      return deny("Database is busy; transaction contention retry limit exceeded.");
    }
  } catch (err) {
    if (canReleaseWitnessOnPreLockAbort()) {
      releaseWitnessTicket(options?.witnessAdapter, artifact.authorizationId, artifact.bindingDigest, witnessTicketId, "DATABASE_BEGIN_ERROR");
    }
    guard.releaseLock();
    throw err;
  }

  let candidate: ClockCandidate;
  let localCommitted = false;
  let effectiveNowSeconds = 0;
  let approvedRevalResult: (Evaluation & { decision: "ALLOW"; envelope: TransactionEnvelope }) | undefined;

  try {
    const rollbackAndDeny = (reason: string | string[], isUnknown = false): TransactionAuthorization => {
      // Monotonic Witness Safety (SEC-M11-03):
      // A witness ticket may ONLY be released if this authorization is provably unconsumed in SQLite.
      // If the authorization was committed locally or its state is uncertain, capacity must remain held.
      let canRelease = !localCommitted && !store.isTainted();
      if (canRelease) {
        try {
          const check = db.prepare(
            "SELECT state FROM consumed_authorization_ids WHERE authorization_id = ?"
          ).get(artifact.authorizationId) as { state: string } | undefined;
          if (check && check.state === "consumed") {
            canRelease = false;
          }
        } catch {
          canRelease = false;
        }
      }

      if (canRelease) {
        releaseWitnessTicket(
          options?.witnessAdapter,
          artifact.authorizationId,
          artifact.bindingDigest,
          witnessTicketId,
          Array.isArray(reason) ? reason.join("; ") : reason,
        );
      }
      db.exec("ROLLBACK;");
      if (isUnknown) {
        return {
          decision: "UNKNOWN",
          reasons: Array.isArray(reason) ? reason : [reason],
          ...(witnessTicketId ? { witnessTicketId } : {}),
        };
      }
      return {
        decision: "DENY",
        reasons: Array.isArray(reason) ? reason : [reason],
        ...(witnessTicketId ? { witnessTicketId } : {}),
      };
    };

    // 5. Validate candidate time against guard and persisted high-water mark inside write lock
    const clock = store.getClock();
    candidate = {
      wallSeconds: clock.nowSeconds(),
      monotonicNanos: guard.getMonotonicClock().nowNanoseconds(),
    };

    const clockRow = db.prepare(
      "SELECT high_water_seconds FROM system_clock_state WHERE id = 1"
    ).get() as { high_water_seconds: number } | undefined;

    if (!clockRow) {
      return rollbackAndDeny("System clock state is missing or corrupted.");
    }

    const highWaterSeconds = clockRow.high_water_seconds;

    const clockEval = guard.evaluateCandidate(candidate, highWaterSeconds);
    if (clockEval.decision !== "ALLOW") {
      return rollbackAndDeny(clockEval.reason ?? "Clock evaluation failed.");
    }

    const currentNow = candidate.wallSeconds;
    effectiveNowSeconds = Math.max(currentNow, highWaterSeconds);

    if (effectiveNowSeconds > highWaterSeconds) {
      db.prepare(`
        UPDATE system_clock_state
        SET high_water_seconds = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
      `).run(effectiveNowSeconds);
    }

    // Check in-process duplicate and persisted replay state under write lock
    if (isObject(envelopeInput) && consumedEnvelopes.has(envelopeInput)) {
      db.exec("ROLLBACK;");
      return {
        decision: "DENY",
        reasons: ["Transaction authorization has already been consumed."],
        ...(witnessTicketId ? { witnessTicketId } : {}),
      };
    }

    const currentAuthRow = db.prepare(
      "SELECT state FROM consumed_authorization_ids WHERE authorization_id = ?"
    ).get(artifact.authorizationId) as { state: string } | undefined;

    if (currentAuthRow && currentAuthRow.state === "consumed") {
      db.exec("ROLLBACK;");
      return {
        decision: "DENY",
        reasons: ["Bound transaction authorization is unknown, consumed, or mismatched."],
        ...(witnessTicketId ? { witnessTicketId } : {}),
      };
    }

    // 6. TOCTOU Re-validation: Verify issuer key status under write lock
    const keyRow = db.prepare(
      "SELECT public_key_pem, status, valid_from_seconds, expires_at_seconds, retired_at_seconds, revoked_at_seconds FROM issuer_keys WHERE key_id = ?"
    ).get(artifact.keyId) as {
      public_key_pem: string;
      status: string;
      valid_from_seconds: number | null;
      expires_at_seconds: number | null;
      retired_at_seconds: number | null;
      revoked_at_seconds: number | null;
    } | undefined;

    if (!keyRow) {
      return rollbackAndDeny("Issuer key is unknown.");
    }

    if (keyRow.status === "revoked") {
      return rollbackAndDeny("Issuer key has been revoked.");
    }

    if (keyRow.status !== "active" && keyRow.status !== "retired") {
      return rollbackAndDeny("Issuer key status does not permit verification.");
    }

    // Post-retirement forgery rule:
    // A retired key may validate only artifacts whose signed issuance time is strictly before retirement time
    if (keyRow.status === "retired") {
      if (keyRow.retired_at_seconds !== null && artifact.issuedAtSeconds >= keyRow.retired_at_seconds) {
        return rollbackAndDeny("Authorization was issued after issuer key was retired.");
      }
    }

    // Key validity windows
    if (keyRow.valid_from_seconds !== null && artifact.issuedAtSeconds < keyRow.valid_from_seconds) {
      return rollbackAndDeny("Issuer key was not yet valid at authorization issuance time.");
    }
    if (keyRow.expires_at_seconds !== null && artifact.issuedAtSeconds >= keyRow.expires_at_seconds) {
      return rollbackAndDeny("Issuer key had expired at authorization issuance time.");
    }
    if (keyRow.expires_at_seconds !== null && effectiveNowSeconds >= keyRow.expires_at_seconds) {
      return rollbackAndDeny("Issuer key has expired.");
    }

    // Guard against key tampering in storage: verify public key PEM is unchanged
    if (keyRow.public_key_pem !== preKeyRow.public_key_pem) {
      return rollbackAndDeny("Issuer key was modified concurrently.");
    }

    // 5. Load authoritative policy and reject stale revisions or revoked/retired policies
    const polRow = db.prepare(
      "SELECT current_revision, status, policy_json FROM policies WHERE policy_id = ?"
    ).get(artifact.policyId) as {
      current_revision: number;
      status: string;
      policy_json: string;
    } | undefined;

    if (!polRow) {
      return rollbackAndDeny(`Authoritative policy '${artifact.policyId}' not found.`);
    }

    if (polRow.status === "revoked") {
      return rollbackAndDeny("Policy has been revoked.");
    }
    if (polRow.status === "retired") {
      return rollbackAndDeny("Policy has been retired.");
    }
    if (polRow.status !== "active") {
      return rollbackAndDeny("Policy is not active.");
    }

    if (polRow.current_revision !== artifact.policyRevision) {
      return rollbackAndDeny(
        `Policy revision mismatch: artifact bound to revision ${artifact.policyRevision}, but current policy revision is ${polRow.current_revision}.`
      );
    }

    const authoritativePolicy = normalizeDemoPolicy(JSON.parse(polRow.policy_json));
    if (!authoritativePolicy) {
      return rollbackAndDeny("Authoritative policy is malformed.", true);
    }

    // 6. Enforce anti-time-travel check and signed authorization expiry/boundaries
    if (artifact.issuedAtSeconds > currentNow) {
      return rollbackAndDeny("Authorization issuance timestamp is in the future relative to current clock.");
    }

    // Exact expiry boundary: consumption at effectiveNowSeconds >= expiresAtSeconds is DENIED
    if (effectiveNowSeconds >= artifact.expiresAtSeconds) {
      return rollbackAndDeny("Signed transaction authorization has expired.");
    }

    // Signed expiry must not exceed authoritative policy expiry boundary
    if (authoritativePolicy.expiresAt !== undefined && authoritativePolicy.expiresAt !== null && artifact.expiresAtSeconds > authoritativePolicy.expiresAt) {
      return rollbackAndDeny("Authorization expiry exceeds authoritative policy expiry boundary.");
    }

    // Signed expiry must not exceed applicable issuer key expiry boundary
    if (keyRow.expires_at_seconds !== null && artifact.expiresAtSeconds > keyRow.expires_at_seconds) {
      return rollbackAndDeny("Authorization expiry exceeds issuer key expiry boundary.");
    }

    // 7. Revalidate transaction envelope against authoritative policy
    const revalResult = revalidateTransactionAuthorization(
      authoritativePolicy,
      envelopeInput,
      candidateInput,
      { nowSeconds: effectiveNowSeconds },
    );

    if (revalResult.decision !== "ALLOW") {
      return rollbackAndDeny(
        revalResult.reasons ?? ["Revalidation denied"],
        revalResult.decision === "UNKNOWN",
      );
    }

    approvedRevalResult = revalResult;

    // 8. Verify binding digest
    const computedBindingDigest = createAuthorizationBindingDigest(
      authoritativePolicy,
      revalResult.envelope.request,
    );

    if (computedBindingDigest !== artifact.bindingDigest) {
      return rollbackAndDeny("Transaction does not match the bound authorization artifact.");
    }

    // 8b. Milestone 8: Enforce Cumulative Spending Budget (if configured on authoritative policy)
    if (authoritativePolicy.budget) {
      const { window: budgetWindow, maxCumulativeAmount } = authoritativePolicy.budget;
      const windowStart = calculateBudgetWindowStart(effectiveNowSeconds, budgetWindow);

      const accumRow = db.prepare(`
        SELECT spent_amount
        FROM policy_budget_accumulators
        WHERE policy_id = ? AND window_type = ? AND window_start = ?
      `).get(authoritativePolicy.policyId, budgetWindow, windowStart) as { spent_amount: string } | undefined;

      const currentSpent = accumRow ? BigInt(accumRow.spent_amount) : 0n;
      const decoded = decodeTransfer(revalResult.envelope.request.calldata);
      if (!decoded) {
        return rollbackAndDeny("ERC-20 transfer calldata could not be decoded safely for budget check.", true);
      }

      const actionAmount = decoded.amount;
      const newSpent = currentSpent + actionAmount;
      const maxCumulative = BigInt(maxCumulativeAmount);

      if (newSpent > maxCumulative) {
        const available = maxCumulative >= currentSpent ? (maxCumulative - currentSpent).toString(10) : "0";
        return rollbackAndDeny(
          `Cumulative spending budget exceeded for ${budgetWindow.toLowerCase()} window (requested: ${actionAmount.toString(10)}, available: ${available}).`,
        );
      }

      // Upsert accumulator row atomically inside the write lock
      db.prepare(`
        INSERT INTO policy_budget_accumulators (policy_id, window_type, window_start, spent_amount, last_updated_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT (policy_id, window_type, window_start)
        DO UPDATE SET spent_amount = excluded.spent_amount, last_updated_at = CURRENT_TIMESTAMP
      `).run(authoritativePolicy.policyId, budgetWindow, windowStart, newSpent.toString(10));
    }

    // 9. Atomically consume the issued authorization record
    const updateRes = db.prepare(`
      UPDATE consumed_authorization_ids
      SET state = 'consumed', consumed_at = CURRENT_TIMESTAMP
      WHERE authorization_id = ?
        AND binding_digest = ?
        AND state = 'issued'
        AND artifact_version = ?
        AND key_id = ?
        AND issued_at_seconds = ?
    `).run(
      artifact.authorizationId,
      artifact.bindingDigest,
      artifact.version,
      artifact.keyId,
      artifact.issuedAtSeconds,
    );

    if (updateRes.changes !== 1) {
      const checkRow = db.prepare(
        "SELECT state FROM consumed_authorization_ids WHERE authorization_id = ?"
      ).get(artifact.authorizationId) as { state: string } | undefined;

      if (checkRow && checkRow.state === "consumed") {
        db.exec("ROLLBACK;");
        return {
          decision: "DENY",
          reasons: ["Bound transaction authorization is unknown, consumed, or mismatched."],
          ...(witnessTicketId ? { witnessTicketId } : {}),
        };
      }

      return rollbackAndDeny("Bound transaction authorization is unknown, consumed, or mismatched.");
    }

    try {
      db.exec("COMMIT;");
      localCommitted = true;
      guard.publishCandidate(candidate);
    } catch (commitErr) {
      const reason = `Commit failure with uncertain outcome: ${commitErr instanceof Error ? commitErr.message : String(commitErr)}`;
      store.markTainted(reason);
      throw commitErr;
    }
  } catch (err) {
    let rollbackFatalErr: unknown;
    try {
      if (!localCommitted) {
        db.exec("ROLLBACK;");
      }
    } catch (rollbackErr) {
      if (isFatalIOError(rollbackErr)) {
        rollbackFatalErr = rollbackErr;
      }
    }
    if (rollbackFatalErr) {
      const reason = `Fatal rollback failure: ${rollbackFatalErr instanceof Error ? rollbackFatalErr.message : String(rollbackFatalErr)}`;
      store.markTainted(reason);
    } else if (isFatalIOError(err)) {
      const reason = `Fatal storage I/O error: ${err instanceof Error ? err.message : String(err)}`;
      store.markTainted(reason);
    }

    if (!localCommitted && !store.isTainted() && !rollbackFatalErr) {
      let canRelease = true;
      try {
        const check = db.prepare(
          "SELECT state FROM consumed_authorization_ids WHERE authorization_id = ?"
        ).get(artifact.authorizationId) as { state: string } | undefined;
        if (check && check.state === "consumed") {
          canRelease = false;
        }
      } catch {
        canRelease = false;
      }

      if (canRelease) {
        releaseWitnessTicket(
          options?.witnessAdapter,
          artifact.authorizationId,
          artifact.bindingDigest,
          witnessTicketId,
          "LOCAL_SQLITE_TRANSACTION_FAILED",
        );
      }
    }
    throw err;
  } finally {
    guard.releaseLock();
  }

  // --- POST-COMMIT WITNESS FINALIZATION ---
  // Reached strictly after successful SQLite COMMIT; (localCommitted is guaranteed true).
  // The SQLite write lock is released.
  if (!approvedRevalResult) {
    return deny("Internal transaction state inconsistent.");
  }

  let witnessReceipt: SignedWitnessReceipt | undefined;
  if (witnessTicketId && options?.witnessAdapter) {
    try {
      const commitRes = options.witnessAdapter.commitTicket({
        ticketId: witnessTicketId,
        authorizationId: artifact.authorizationId,
        bindingDigest: artifact.bindingDigest,
        localCommittedAtSeconds: effectiveNowSeconds,
        idempotencyKey: options.idempotencyKey,
      });

      if (commitRes instanceof Promise) {
        throw new Error("Async witness commit is not supported in synchronous consume.");
      }

      if (commitRes.decision === "ALLOW" && commitRes.receipt) {
        witnessReceipt = commitRes.receipt;
      } else {
        const failureReason = commitRes.reasons?.join("; ") ?? "witness denied commit";
        consumedEnvelopes.add(approvedRevalResult.envelope);
        return {
          decision: "UNKNOWN",
          reasons: [
            `Local SQLite transaction committed, but witness commitment failed (${failureReason}). Ticket '${witnessTicketId}' requires reconciliation.`,
          ],
          witnessTicketId,
        };
      }
    } catch (witnessErr) {
      consumedEnvelopes.add(approvedRevalResult.envelope);
      return {
        decision: "UNKNOWN",
        reasons: [
          `Local SQLite transaction committed, but witness commitment threw an error: ${witnessErr instanceof Error ? witnessErr.message : String(witnessErr)}. Ticket '${witnessTicketId}' requires reconciliation.`,
        ],
        witnessTicketId,
      };
    }
  }

  consumedEnvelopes.add(approvedRevalResult.envelope);
  return {
    ...approvedRevalResult,
    ...(witnessReceipt ? { witnessReceipt } : {}),
    ...(witnessTicketId ? { witnessTicketId } : {}),
  };
}

/**
 * Asserts store infrastructure health before processing cancellation.
 * Ensures tainted connections or tripped/expired clock guards fail closed with explicit
 * errors rather than masking infrastructure failure as false or invalid ID outcomes.
 */
function assertStoreHealthForCancellation(store: unknown): void {
  if (!store || typeof store !== "object") return;
  const s = store as Partial<SQLiteAuthorizationStore>;
  if (typeof s.isTainted === "function" && s.isTainted()) {
    throw new Error(
      `SQLiteAuthorizationStore database connection is tainted and unusable: ${s.getTaintedReason?.()}`,
    );
  }
  if (typeof s.getClockGuard === "function") {
    const guard = s.getClockGuard();
    if (guard) {
      if (guard.getState() === "TRIPPED_CLOSED") {
        throw new Error(
          `Store clock monitor is in a tripped state: ${guard.getTripReason()}`,
        );
      }
      if (guard.getState() === "EXPIRED") {
        throw new Error(
          "Process clock anchor has expired (maximum uptime exceeded); restart required.",
        );
      }
    }
  }
}

/**
 * Atomically cancels an issued, unconsumed transaction authorization.
 *
 * Enforces store health precedence, then validates authorization ID format and delegates
 * to the persistent store's atomic cancelAuthorization method. Returns true if
 * cancellation succeeded, false if unknown, already consumed, already cancelled,
 * or invalid ID on a healthy store.
 */
export function cancelAuthorization(
  storeInput:
    | SQLiteAuthorizationStore
    | BoundAuthorizationIdStore
    | { store: SQLiteAuthorizationStore | BoundAuthorizationIdStore },
  authorizationIdInput: unknown,
): boolean {
  const store =
    typeof storeInput === "object" && storeInput !== null && "store" in storeInput
      ? (storeInput as { store: SQLiteAuthorizationStore | BoundAuthorizationIdStore }).store
      : storeInput;

  assertStoreHealthForCancellation(store);

  const authValidation = validateAuthorizationId(authorizationIdInput);
  if (!authValidation.ok) {
    return false;
  }

  if (store && typeof (store as SQLiteAuthorizationStore).cancelAuthorization === "function") {
    return (store as SQLiteAuthorizationStore).cancelAuthorization(authValidation.id);
  }

  return false;
}

export const cancelSignedTransactionAuthorizationV3 = cancelAuthorization;
