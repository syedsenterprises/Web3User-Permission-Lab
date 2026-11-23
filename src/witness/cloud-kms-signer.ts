/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Cloud KMS Witness Signer Abstraction
 *
 * Provides base types, error hierarchies, Castagnoli CRC32C parsing with upfront Proxy rejection,
 * ASN.1 DER SPKI wire-format decoding, and monotonic deadline management for cloud KMS signing adapters.
 *
 * Reference: FN-SEC-01 (Cloud KMS/HSM Signing Adapter)
 */

import { types } from "node:util";
import { createHash } from "node:crypto";
import Long from "long";
import type { WitnessSigner } from "./signing.js";

// ============================================================================
// Timing & Operational Constants
// ============================================================================

export const DEFAULT_TOTAL_TIMEOUT_MS = 5000;
export const HARD_MAX_TIMEOUT_MS = 8000;
export const MAX_PER_ATTEMPT_DEADLINE_MS = 2500;
export const MAX_TOTAL_ATTEMPTS = 2;
export const MAX_RETRIES = 1;
export const BASE_BACKOFF_MS = 150;
export const MAX_BACKOFF_MS = 300;
export const MIN_REMAINING_BUDGET_FOR_RETRY_MS = 500;

// Exact 12-byte ASN.1 DER SubjectPublicKeyInfo prefix for Ed25519 (OID 1.3.101.112)
export const ED25519_SPKI_HEADER = Buffer.from("302a300506032b6570032100", "hex");

// ============================================================================
// Error Hierarchy
// ============================================================================

export class WitnessSignerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class WitnessNotReadyError extends WitnessSignerError {
  readonly code: number = 14; // grpc.status.UNAVAILABLE
  constructor(message = "Witness signer is not ready (initialization required)") {
    super(message);
  }
}

export class WitnessClosedError extends WitnessSignerError {
  readonly code: number = 14; // grpc.status.UNAVAILABLE
  constructor(message = "Witness signer is closed") {
    super(message);
  }
}

export class KmsConfigurationError extends WitnessSignerError {
  readonly code: number = 9; // grpc.status.FAILED_PRECONDITION
  constructor(message: string) {
    super(message);
  }
}

export class KmsKeyValidationError extends WitnessSignerError {
  readonly code: number = 9; // grpc.status.FAILED_PRECONDITION
  constructor(message: string) {
    super(message);
  }
}

export class WitnessUnavailableError extends WitnessSignerError {
  readonly code: number = 14; // grpc.status.UNAVAILABLE
  readonly reason: string;
  readonly proofOfNonExecution: boolean;
  readonly retryAttempts: number;

  constructor(options: {
    message: string;
    reason: string;
    proofOfNonExecution: boolean;
    retryAttempts: number;
    cause?: unknown;
  }) {
    super(options.message);
    this.reason = options.reason;
    this.proofOfNonExecution = options.proofOfNonExecution;
    this.retryAttempts = options.retryAttempts;
    if (options.cause) {
      (this as any).cause = options.cause;
    }
  }
}

export const KmsSignerUnavailableError = WitnessUnavailableError;

// ============================================================================
// Configuration Interfaces
// ============================================================================

export interface BaseCloudKmsSignerConfig {
  witnessId: string;
  expectedKeyFingerprint?: string; // Mandatory in production (NODE_ENV === 'production')
  totalTimeoutMs?: number;         // Default: 5000, Max: 8000
  maxRetries?: number;             // Default: 1, Max: 1
}

export interface AwsKmsSignerConfig extends BaseCloudKmsSignerConfig {
  provider: "aws";
  keyId: string;                   // Key ID or Key ARN
  region: string;
  useFipsEndpoint?: boolean;       // Default: true in production
  credentials?: {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken?: string;
  };
}

export interface GcpKmsSignerConfig extends BaseCloudKmsSignerConfig {
  provider: "gcp";
  keyVersionName: string;          // projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*
}

export type CloudKmsSignerConfig = AwsKmsSignerConfig | GcpKmsSignerConfig;

// ============================================================================
// CRC32C Castagnoli Engine & Representation Parser
// ============================================================================

const CRC32C_POLYNOMIAL = 0x82f63b78;
const CRC32C_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) {
    c = (c & 1) ? (c >>> 1) ^ CRC32C_POLYNOMIAL : (c >>> 1);
  }
  CRC32C_TABLE[i] = c;
}

export function calculateCrc32c(buffer: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buffer.length; i++) {
    crc = CRC32C_TABLE[(crc ^ buffer[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Validates and derives an unsigned 32-bit CRC32C checksum from GCP KMS metadata.
 *
 * Enforces:
 * 1. P-1 & P-2: Upfront util.types.isProxy rejection before any trap-triggering inspection.
 * 2. Strict primitive integer range [0, 4294967295].
 * 3. Strict decimal string parsing matching /^\d+$/.
 * 4. Genuine Long instance verification (raw instanceof Long && Object.getPrototypeOf(raw) === Long.prototype).
 * 5. Own data descriptor extraction for low/high words without calling getters or methods.
 * 6. Nonzero high word rejection and low >>> 0 derivation.
 */
export function parseAndValidateCrc32cValue(raw: unknown): number {
  if (raw === null || raw === undefined) {
    throw new KmsKeyValidationError("Missing required pemCrc32c integrity checksum in GCP KMS response");
  }

  // P-1 & P-2: Upfront Proxy rejection before ANY operation that could trigger Proxy traps
  if (types.isProxy(raw)) {
    throw new KmsKeyValidationError("Proxy objects are strictly prohibited as CRC32C metadata");
  }

  // 1. Primitive Number Validation
  if (typeof raw === "number") {
    if (!Number.isFinite(raw) || !Number.isInteger(raw) || raw < 0 || raw > 0xffffffff) {
      throw new KmsKeyValidationError(
        `CRC32C number out of unsigned 32-bit integer range [0, 4294967295]: ${raw}`,
      );
    }
    return raw;
  }

  // 2. Decimal String Validation
  if (typeof raw === "string") {
    if (!/^\d+$/.test(raw)) {
      throw new KmsKeyValidationError(`Malformed CRC32C decimal string: "${raw}"`);
    }
    const val = BigInt(raw);
    if (val < 0n || val > 0xffffffffn) {
      throw new KmsKeyValidationError(
        `CRC32C decimal string out of unsigned 32-bit integer range [0, 4294967295]: "${raw}"`,
      );
    }
    return Number(val);
  }

  // 3. Genuine Protobuf Long Representation Validation
  if (typeof raw === "object" && raw !== null && (raw instanceof Long)) {
    // Validate exact direct prototype membership
    if (Object.getPrototypeOf(raw) !== Long.prototype) {
      throw new KmsKeyValidationError("Malformed Long representation: non-matching prototype");
    }

    // Retrieve own property descriptors for low and high bitfields (does not invoke getters)
    const lowDesc = Object.getOwnPropertyDescriptor(raw, "low");
    const highDesc = Object.getOwnPropertyDescriptor(raw, "high");

    // Both descriptors must exist
    if (!lowDesc || !highDesc) {
      throw new KmsKeyValidationError(
        "Malformed Long representation: missing own property descriptors for low/high",
      );
    }

    // Both descriptors must be data descriptors (must have 'value', must not have getters or setters)
    if (
      !("value" in lowDesc) ||
      !("value" in highDesc) ||
      lowDesc.get !== undefined ||
      lowDesc.set !== undefined ||
      highDesc.get !== undefined ||
      highDesc.set !== undefined
    ) {
      throw new KmsKeyValidationError(
        "Malformed Long representation: accessor descriptor detected for low/high bitfields",
      );
    }

    // Read the primitive values directly from the descriptor objects (never accessing raw.low or raw.high)
    const low = lowDesc.value;
    const high = highDesc.value;

    // Validate bitfield finiteness and integer types
    if (
      typeof low !== "number" ||
      typeof high !== "number" ||
      !Number.isFinite(low) ||
      !Number.isFinite(high) ||
      !Number.isInteger(low) ||
      !Number.isInteger(high)
    ) {
      throw new KmsKeyValidationError("Malformed Long representation: non-integer or non-finite bitfields");
    }

    // Low word must reside within signed 32-bit integer bounds [-2147483648, 2147483647]
    if (low < -2147483648 || low > 2147483647) {
      throw new KmsKeyValidationError(
        `Malformed Long representation: low word outside signed 32-bit integer range: ${low}`,
      );
    }

    // High word must be in signed 32-bit range AND must be exactly 0 for an unsigned 32-bit CRC32C
    if (high !== 0) {
      throw new KmsKeyValidationError(
        `Malformed Long representation: nonzero high word (${high}) for 32-bit CRC32C`,
      );
    }

    // Derive checksum strictly from descriptor low word using unsigned 32-bit right-shift.
    // NEVER invoke raw.toString(), raw.toNumber(), or any conversion methods.
    return (low >>> 0);
  }

  // 4. Strict Rejection of All Other Representations (including forged { __isLong__: true } objects)
  throw new KmsKeyValidationError(
    `Unsupported CRC32C representation: expected number, decimal string, or genuine Long instance, received ${typeof raw}`,
  );
}

export function verifyGcpPublicKeyCrc32c(
  pem: string,
  pemCrc32c: unknown,
): void {
  const crcTarget = (pemCrc32c && typeof pemCrc32c === "object" && "value" in (pemCrc32c as any))
    ? (pemCrc32c as any).value
    : pemCrc32c;

  const expectedCrc = parseAndValidateCrc32cValue(crcTarget);
  const calculatedCrc = calculateCrc32c(Buffer.from(pem, "utf8"));

  if (calculatedCrc !== expectedCrc) {
    throw new KmsKeyValidationError(
      `CRC32C checksum mismatch for GCP public key: expected ${expectedCrc}, calculated ${calculatedCrc}`,
    );
  }
}

// ============================================================================
// SPKI ASN.1 DER Wire Format & Cryptographic Key Helpers
// ============================================================================

export function parseSpkiPemToDer(pem: string): Uint8Array {
  const stripped = pem
    .replace(/-----BEGIN[^-]+-----/g, "")
    .replace(/-----END[^-]+-----/g, "")
    .replace(/\s+/g, "");
  return new Uint8Array(Buffer.from(stripped, "base64"));
}

export function extractRawEd25519PublicKey(spkiDerBytes: Uint8Array): Uint8Array {
  if (spkiDerBytes.byteLength !== 44) {
    throw new KmsKeyValidationError(
      `Invalid SPKI DER length for Ed25519: expected 44 bytes, received ${spkiDerBytes.byteLength}`,
    );
  }

  const derBuffer = Buffer.from(spkiDerBytes);
  if (!derBuffer.subarray(0, 12).equals(ED25519_SPKI_HEADER)) {
    throw new KmsKeyValidationError(
      "Invalid SPKI header: expected Ed25519 OID 1.3.101.112 (hex: 302a300506032b6570032100)",
    );
  }

  // Trailing 32 bytes contain the raw RFC 8032 Ed25519 public key
  return new Uint8Array(derBuffer.subarray(12, 44));
}

export function computeKeyFingerprint(rawKeyBytes: Uint8Array): string {
  return createHash("sha256").update(rawKeyBytes).digest("hex").toLowerCase();
}

// ============================================================================
// Abstract Base CloudKmsWitnessSigner
// ============================================================================

export type SignerLifecycleState = "UNINITIALIZED" | "INITIALIZING" | "READY" | "FAILED" | "CLOSED";

export abstract class CloudKmsWitnessSigner<TConfig extends BaseCloudKmsSignerConfig = BaseCloudKmsSignerConfig> implements WitnessSigner {
  protected state: SignerLifecycleState = "UNINITIALIZED";
  protected readonly config: TConfig;
  protected rawPublicKeyBytes: Uint8Array | null = null;
  protected publicKeyHex: string | null = null;
  protected publicKeyPem: string | null = null;
  protected activeSignatures = 0;
  protected initPromise: Promise<void> | null = null;

  constructor(config: TConfig) {
    if (!config.witnessId || typeof config.witnessId !== "string" || config.witnessId.trim() === "") {
      throw new KmsConfigurationError("Invalid witnessId: must be a non-empty string");
    }

    if (process.env.NODE_ENV === "production") {
      if (!config.expectedKeyFingerprint || typeof config.expectedKeyFingerprint !== "string" || !/^[0-9a-f]{64}$/i.test(config.expectedKeyFingerprint)) {
        throw new KmsConfigurationError(
          "SECURITY_VIOLATION: expectedKeyFingerprint (64-char lowercase SHA-256 hex) is strictly mandatory in production mode",
        );
      }
    } else if (config.expectedKeyFingerprint) {
      if (!/^[0-9a-f]{64}$/i.test(config.expectedKeyFingerprint)) {
        throw new KmsConfigurationError("Invalid expectedKeyFingerprint: must be a 64-character hexadecimal SHA-256 string");
      }
    }

    const totalTimeout = config.totalTimeoutMs ?? DEFAULT_TOTAL_TIMEOUT_MS;
    if (totalTimeout < 500 || totalTimeout > HARD_MAX_TIMEOUT_MS) {
      throw new KmsConfigurationError(
        `Invalid totalTimeoutMs: must be between 500 and ${HARD_MAX_TIMEOUT_MS}ms, received ${totalTimeout}`,
      );
    }

    const maxRetries = config.maxRetries ?? MAX_RETRIES;
    if (maxRetries < 0 || maxRetries > MAX_RETRIES) {
      throw new KmsConfigurationError(`Invalid maxRetries: must be 0 or 1, received ${maxRetries}`);
    }

    this.config = {
      ...config,
      totalTimeoutMs: totalTimeout,
      maxRetries,
      expectedKeyFingerprint: config.expectedKeyFingerprint?.toLowerCase(),
    };
  }

  getState(): SignerLifecycleState {
    return this.state;
  }

  getWitnessId(): string {
    return this.config.witnessId;
  }

  getPublicKeyHex(): string {
    if (this.state !== "READY" || !this.publicKeyHex) {
      throw new WitnessNotReadyError(`Cannot get public key: signer is in state ${this.state}`);
    }
    return this.publicKeyHex;
  }

  getPublicKeyPem(): string {
    if (this.state !== "READY" || !this.publicKeyPem) {
      throw new WitnessNotReadyError(`Cannot get public key PEM: signer is in state ${this.state}`);
    }
    return this.publicKeyPem;
  }

  async initialize(): Promise<void> {
    if (this.state === "CLOSED") {
      throw new WitnessClosedError("Cannot initialize a closed signer");
    }
    if (this.state === "READY") {
      return;
    }
    if (this.initPromise) {
      return this.initPromise;
    }

    this.state = "INITIALIZING";
    this.initPromise = (async () => {
      try {
        await this.doInitialize();
        this.state = "READY";
      } catch (err) {
        this.state = "FAILED";
        throw err;
      } finally {
        this.initPromise = null;
      }
    })();

    return this.initPromise;
  }

  async close(drainTimeoutMs = 2500): Promise<void> {
    if (this.state === "CLOSED") {
      return;
    }
    this.state = "CLOSED";

    // Drain in-flight signatures up to drainTimeoutMs
    const start = performance.now();
    while (this.activeSignatures > 0 && (performance.now() - start) < drainTimeoutMs) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }

    await this.doClose();
  }

  async signReceipt(
    preimage: string,
    fencingGeneration: number,
  ): Promise<{ signatureHex: string; generation: number }> {
    if (this.state === "CLOSED") {
      throw new WitnessClosedError("Cannot sign receipt: signer is closed");
    }
    if (this.state !== "READY") {
      throw new WitnessNotReadyError(`Cannot sign receipt: signer is in state ${this.state}`);
    }

    this.activeSignatures++;
    try {
      const signatureHex = await this.doSignReceipt(Buffer.from(preimage, "utf8"));
      return {
        signatureHex,
        generation: fencingGeneration,
      };
    } finally {
      this.activeSignatures--;
    }
  }

  protected validateFingerprint(rawKeyBytes: Uint8Array): void {
    const computed = computeKeyFingerprint(rawKeyBytes);
    if (this.config.expectedKeyFingerprint && computed !== this.config.expectedKeyFingerprint) {
      throw new KmsKeyValidationError(
        `KMS Public Key Fingerprint mismatch: expected ${this.config.expectedKeyFingerprint}, computed ${computed}`,
      );
    }
    this.rawPublicKeyBytes = rawKeyBytes;
    this.publicKeyHex = Buffer.from(rawKeyBytes).toString("hex").toLowerCase();
  }

  protected abstract doInitialize(): Promise<void>;
  protected abstract doSignReceipt(preimageBytes: Buffer): Promise<string>;
  protected abstract doClose(): Promise<void>;
}
