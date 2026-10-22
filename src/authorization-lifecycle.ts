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


export const DEFAULT_AUTHORIZATION_TTL_SECONDS = 300;

export interface IssueAuthorizationV3Options {
  /**
   * Desired authorization time-to-live in seconds.
   * If omitted, defaults to DEFAULT_AUTHORIZATION_TTL_SECONDS (300).
   * Bounded by policy expiry and key expiry.
   */
  readonly ttlSeconds?: number;
}

const MAX_CONTENTION_RETRIES = 3;
const CONTENTION_RETRY_DELAY_MS = 25;

function sleepSync(ms: number): void {
  const start = Date.now();
  while (Date.now() - start < ms) {
    // busy wait
  }
}

function beginImmediateWithRetry(db: import("node:sqlite").DatabaseSync): boolean {
  let attempt = 0;
  while (attempt < MAX_CONTENTION_RETRIES) {
    attempt++;
    try {
      db.exec("BEGIN IMMEDIATE;");
      return true;
    } catch (err) {
      if (err instanceof Error && /busy|locked/i.test(err.message) && attempt < MAX_CONTENTION_RETRIES) {
        sleepSync(CONTENTION_RETRY_DELAY_MS);
        continue;
      }
      return false;
    }
  }
  return false;
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

  let policyId: string | null = null;
  if (typeof policyIdInput === "string") {
    policyId = normalizeAuthorizationId(policyIdInput);
  } else if (typeof policyIdInput === "object" && policyIdInput !== null && "policyId" in policyIdInput) {
    policyId = normalizeAuthorizationId((policyIdInput as { policyId: unknown }).policyId);
  }
  if (policyId === null) {
    return deny("A non-empty policy ID is required.");
  }

  // 1. Capture trusted clock snapshot
  const clock = store.getClock();
  const nowSeconds = clock.nowSeconds();

  // 2. Advance/check high-water mark
  try {
    store.advanceHighWaterMark(nowSeconds);
  } catch (err) {
    if (err instanceof Error && /busy|locked/i.test(err.message)) {
      return deny("Database is busy; transaction contention retry limit exceeded.");
    }
    return deny(err instanceof Error ? err.message : "Clock rollback detected.");
  }

  const db = store.getDatabase();
  if (!beginImmediateWithRetry(db)) {
    return deny("Database is busy; transaction contention retry limit exceeded.");
  }

  try {
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

    if (keyRow.valid_from_seconds !== null && nowSeconds < keyRow.valid_from_seconds) {
      db.exec("ROLLBACK;");
      return deny("Issuer key is not yet valid.");
    }
    if (keyRow.expires_at_seconds !== null && nowSeconds >= keyRow.expires_at_seconds) {
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

    let effectiveExpiresAt = nowSeconds + ttlSeconds;
    if (authoritativePolicy.expiresAt !== undefined && authoritativePolicy.expiresAt !== null) {
      effectiveExpiresAt = Math.min(effectiveExpiresAt, authoritativePolicy.expiresAt);
    }
    if (keyRow.expires_at_seconds !== null) {
      effectiveExpiresAt = Math.min(effectiveExpiresAt, keyRow.expires_at_seconds);
    }

    if (effectiveExpiresAt <= nowSeconds) {
      db.exec("ROLLBACK;");
      return deny("Authorization validity interval is empty: policy or issuer key has already expired.");
    }

    const expiresAtSeconds = effectiveExpiresAt;

    // 6. Validate transaction envelope against authoritative policy
    const prepared = prepareTransactionAuthorization(
      authoritativePolicy,
      requestInput,
      { nowSeconds },
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
      issuedAtSeconds: nowSeconds,
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
      nowSeconds,
    );

    if (insertRes.changes !== 1) {
      db.exec("ROLLBACK;");
      return deny("Transaction authorization ID has already been issued or consumed.");
    }

    db.exec("COMMIT;");

    return {
      ...prepared,
      artifact: Object.freeze({
        version: SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3,
        authorizationId,
        keyId,
        issuedAtSeconds: nowSeconds,
        expiresAtSeconds,
        policyId: authoritativePolicy.policyId,
        policyRevision: currentRevision,
        bindingDigest,
        signature,
      }),
    };
  } catch (err) {
    try {
      db.exec("ROLLBACK;");
    } catch {}
    throw err;
  }
}

/**
 * Revalidate and consume an Ed25519-signed authorization artifact v3 atomically
 * in SQLite.
 *
 * Verifies artifact structure, captures trusted clock snapshot, checks high-water mark,
 * loads issuer key (enforcing retirement rules and permanent revocation), verifies
 * cryptographic signature, loads authoritative policy from SQLite (enforcing active status
 * and revision match), enforces signed authorization expiration boundary and policy/key
 * boundary limits, revalidates request binding, and transitions storage state
 * from 'issued' to 'consumed' within a single SQLite write transaction.
 */
export function consumeSignedTransactionAuthorizationV3(
  storeInput: SQLiteAuthorizationStore | { store: SQLiteAuthorizationStore },
  artifactInput: unknown,
  envelopeInput: unknown,
  candidateInput: unknown,
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

  // 2. Capture trusted clock & rollback check
  const clock = store.getClock();
  const nowSeconds = clock.nowSeconds();

  try {
    store.advanceHighWaterMark(nowSeconds);
  } catch (err) {
    if (err instanceof Error && /busy|locked/i.test(err.message)) {
      return deny("Database is busy; transaction contention retry limit exceeded.");
    }
    return deny(err instanceof Error ? err.message : "Clock rollback detected.");
  }

  const db = store.getDatabase();
  if (!beginImmediateWithRetry(db)) {
    return deny("Database is busy; transaction contention retry limit exceeded.");
  }

  try {
    // Check in-process duplicate
    if (isObject(envelopeInput) && consumedEnvelopes.has(envelopeInput)) {
      db.exec("ROLLBACK;");
      return deny("Transaction authorization has already been consumed.");
    }

    // 3. Verify issuer key status and issuance-time rule
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
      db.exec("ROLLBACK;");
      return deny("Issuer key is unknown.");
    }

    if (keyRow.status === "revoked") {
      db.exec("ROLLBACK;");
      return deny("Issuer key has been revoked.");
    }

    if (keyRow.status !== "active" && keyRow.status !== "retired") {
      db.exec("ROLLBACK;");
      return deny("Issuer key status does not permit verification.");
    }

    // Post-retirement forgery rule:
    // A retired key may validate only artifacts whose signed issuance time is strictly before retirement time
    if (keyRow.status === "retired") {
      if (keyRow.retired_at_seconds !== null && artifact.issuedAtSeconds >= keyRow.retired_at_seconds) {
        db.exec("ROLLBACK;");
        return deny("Authorization was issued after issuer key was retired.");
      }
    }

    // Key validity windows
    if (keyRow.valid_from_seconds !== null && artifact.issuedAtSeconds < keyRow.valid_from_seconds) {
      db.exec("ROLLBACK;");
      return deny("Issuer key was not yet valid at authorization issuance time.");
    }
    if (keyRow.expires_at_seconds !== null && artifact.issuedAtSeconds >= keyRow.expires_at_seconds) {
      db.exec("ROLLBACK;");
      return deny("Issuer key had expired at authorization issuance time.");
    }
    if (keyRow.expires_at_seconds !== null && nowSeconds >= keyRow.expires_at_seconds) {
      db.exec("ROLLBACK;");
      return deny("Issuer key has expired.");
    }

    const publicKey = parseEd25519PublicKey(keyRow.public_key_pem);
    if (!publicKey) {
      db.exec("ROLLBACK;");
      return deny("Corrupted issuer public key in storage.");
    }

    // 4. Verify Ed25519 signature
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
      db.exec("ROLLBACK;");
      return deny("Failed to construct canonical signed payload.");
    }

    if (!verifyAuthorizationPayload(publicKey, payload, artifact.signature)) {
      db.exec("ROLLBACK;");
      return deny("Invalid authorization artifact signature.");
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
      db.exec("ROLLBACK;");
      return deny(`Authoritative policy '${artifact.policyId}' not found.`);
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

    if (polRow.current_revision !== artifact.policyRevision) {
      db.exec("ROLLBACK;");
      return deny(
        `Policy revision mismatch: artifact bound to revision ${artifact.policyRevision}, but current policy revision is ${polRow.current_revision}.`
      );
    }

    const authoritativePolicy = normalizeDemoPolicy(JSON.parse(polRow.policy_json));
    if (!authoritativePolicy) {
      db.exec("ROLLBACK;");
      return {
        decision: "UNKNOWN",
        reasons: ["Authoritative policy is malformed."],
      };
    }

    // 6. Enforce signed authorization expiry and boundaries
    // Exact expiry boundary: consumption at nowSeconds >= expiresAtSeconds is DENIED
    if (nowSeconds >= artifact.expiresAtSeconds) {
      db.exec("ROLLBACK;");
      return deny("Signed transaction authorization has expired.");
    }

    // Signed expiry must not exceed authoritative policy expiry boundary
    if (authoritativePolicy.expiresAt !== undefined && authoritativePolicy.expiresAt !== null && artifact.expiresAtSeconds > authoritativePolicy.expiresAt) {
      db.exec("ROLLBACK;");
      return deny("Authorization expiry exceeds authoritative policy expiry boundary.");
    }

    // Signed expiry must not exceed applicable issuer key expiry boundary
    if (keyRow.expires_at_seconds !== null && artifact.expiresAtSeconds > keyRow.expires_at_seconds) {
      db.exec("ROLLBACK;");
      return deny("Authorization expiry exceeds issuer key expiry boundary.");
    }

    // 7. Revalidate transaction envelope against authoritative policy
    const revalResult = revalidateTransactionAuthorization(
      authoritativePolicy,
      envelopeInput,
      candidateInput,
      { nowSeconds },
    );

    if (revalResult.decision !== "ALLOW") {
      db.exec("ROLLBACK;");
      return revalResult;
    }

    // 8. Verify binding digest
    const computedBindingDigest = createAuthorizationBindingDigest(
      authoritativePolicy,
      revalResult.envelope.request,
    );

    if (computedBindingDigest !== artifact.bindingDigest) {
      db.exec("ROLLBACK;");
      return deny("Transaction does not match the bound authorization artifact.");
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
      db.exec("ROLLBACK;");
      return deny("Bound transaction authorization is unknown, consumed, or mismatched.");
    }

    db.exec("COMMIT;");
    consumedEnvelopes.add(revalResult.envelope);
    return revalResult;
  } catch (err) {
    try {
      db.exec("ROLLBACK;");
    } catch {}
    throw err;
  }
}
