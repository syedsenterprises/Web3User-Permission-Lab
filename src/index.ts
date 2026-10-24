/**
 * Web3User Permission Lab - Public SDK Entrypoint
 *
 * Provides a minimal, secure off-chain authorization engine with SQLite persistence,
 * revision-controlled policies, cryptographic key governance, and atomic single-use replay protection.
 */

// ============================================================================
// Primary Engine Facade & Configuration
// ============================================================================
export {
  Web3UserEngine,
  type Web3UserEngineOptions,
  type IssueAuthorizationParams,
  type ConsumeAuthorizationParams,
  // Typed Error Contract
  Web3UserError,
  EngineClosedError,
  ValidationError,
  ContentionError,
  ClockGuardError,
  StoreTaintedError,
  wrapEngineError,
} from "./engine.js";

// ============================================================================
// Core Stores & Storage Options
// ============================================================================
export {
  SQLiteAuthorizationStore,
  type SQLiteAuthorizationStoreOptions,
  type SQLiteSynchronousMode,
  type CheckpointMode,
  type CheckpointResult,
  type BoundAuthorizationIdStore,
  type AuthorizationIdStore,
  type AuthorizationRecord,
  type AuthorizationState,
} from "./authorization-store.js";

export {
  SQLitePolicyStore,
  type PolicyStore,
  type PolicyStoreOptions,
  type PolicyRecord,
  type PolicyRevisionRecord,
  type PolicyStatus,
} from "./policy-store.js";

export {
  SQLiteKeyStore,
  type KeyStore,
  type KeyStoreOptions,
  type PersistedIssuerKeyMetadata,
  type ImportIssuerKeyMetadata,
} from "./key-store.js";

export {
  type KeyStatus,
  type IssuerKeyMetadata,
  type KeyRegistry,
} from "./key-registry.js";

// ============================================================================
// V3 Authorization Lifecycle & Cryptography
// ============================================================================
export {
  issueSignedTransactionAuthorizationV3,
  consumeSignedTransactionAuthorizationV3,
  cancelAuthorization,
  cancelSignedTransactionAuthorizationV3,
  DEFAULT_AUTHORIZATION_TTL_SECONDS,
  MAX_AUTHORIZATION_ID_LENGTH,
  type V3Signer,
  type IssueAuthorizationV3Options,
  type SignedTransactionAuthorizationV3,
} from "./authorization-lifecycle.js";

export {
  generateIssuerKeyPair,
  parseEd25519PublicKey,
  parseEd25519PrivateKey,
  signAuthorizationPayload,
  verifyAuthorizationPayload,
  canonicalSignedPayloadV3,
  isSignedAuthorizationArtifactV3,
  SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3,
  type SignedAuthorizationArtifactV3,
} from "./authorization-crypto.js";

// ============================================================================
// Policy Evaluation & Transaction Envelopes
// ============================================================================
export {
  type DemoPolicy,
  type ProposedAction,
  type EvaluationContext,
  type Evaluation,
  type Decision,
  normalizeDemoPolicy,
  evaluate,
} from "./policy.js";

export {
  type TransactionRequest,
  type TransactionEnvelope,
  type EnvelopeResult,
  createTransactionEnvelope,
  matchesTransactionEnvelope,
  MAX_CALLDATA_HEX_LENGTH,
} from "./transaction-envelope.js";

export {
  type TransactionAuthorization,
  prepareTransactionAuthorization,
  revalidateTransactionAuthorization,
} from "./policy-transaction.js";

// ============================================================================
// Hardware & Clock Safeguards
// ============================================================================
export {
  type Clock,
  type MonotonicClock,
  SystemClock,
  SystemMonotonicClock,
  systemClock,
  systemMonotonicClock,
  TestClock,
  TestMonotonicClock,
  ClockGuard,
  type ClockGuardOptions,
  type ClockGuardState,
  type ClockCandidate,
  type ClockCandidateEvaluation,
  MAX_STARTUP_FORWARD_GAP_SECONDS,
  MAX_FORWARD_STEP_SECONDS,
  MAX_BACKWARD_STEP_SECONDS,
  MAX_ABSOLUTE_DIVERGENCE_SECONDS,
  MAX_ANCHOR_LIFETIME_SECONDS,
} from "./clock.js";
