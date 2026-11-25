/**
 * Web3User Permission Lab - Milestone 13-D: Witness Foundation Module
 * Complete exports for D1 storage engine and D2 gRPC mTLS 1.3 architecture.
 */

export * from "./postgres-store.js";
export * from "./pg-pool-lifecycle.js";
export * from "./disposal-adapter.js";
export * from "./dependency-validator.js";
export * from "./circuit-breaker.js";
export * from "./idempotency.js";
export * from "./auth.js";
export * from "./signing.js";
export * from "./grpc-service.js";
export * from "./grpc-server.js";
export * from "./remote-witness-client.js";
export * from "./mtls-certs.js";
export {
  DEFAULT_TOTAL_TIMEOUT_MS,
  HARD_MAX_TIMEOUT_MS,
  MAX_PER_ATTEMPT_DEADLINE_MS,
  MAX_TOTAL_ATTEMPTS,
  MAX_RETRIES,
  BASE_BACKOFF_MS,
  MAX_BACKOFF_MS,
  MIN_REMAINING_BUDGET_FOR_RETRY_MS,
  ED25519_SPKI_HEADER,
  WitnessSignerError,
  WitnessNotReadyError,
  WitnessClosedError,
  KmsConfigurationError,
  KmsKeyValidationError,
  KmsSignerUnavailableError,
  WitnessUnavailableError as KmsWitnessUnavailableError,
  type BaseCloudKmsSignerConfig,
  type AwsKmsSignerConfig,
  type GcpKmsSignerConfig,
  type CloudKmsSignerConfig,
  type SignerLifecycleState,
  CloudKmsWitnessSigner,
  calculateCrc32c,
  parseAndValidateCrc32cValue,
  verifyGcpPublicKeyCrc32c,
  parseSpkiPemToDer,
  extractRawEd25519PublicKey,
  computeKeyFingerprint,
} from "./cloud-kms-signer.js";
export * from "./aws-kms-signer.js";
export * from "./gcp-kms-signer.js";
export * from "./signer-factory.js";
