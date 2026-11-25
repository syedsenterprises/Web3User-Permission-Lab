/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Witness Signer Factory & Configuration
 *
 * Implements centralized factory instantiation, environment variable parsing, strict schema validation,
 * conflicting-variable rejection, and credential protection for Local, AWS KMS, and GCP Cloud KMS signers.
 *
 * Reference: FN-SEC-01 Step 3 (Production Service Integration)
 */

import type { KeyObject } from "node:crypto";
import type { KMSClient } from "@aws-sdk/client-kms";
import type { KeyManagementServiceClient } from "@google-cloud/kms";
import {
  type WitnessSigner,
  LocalEd25519WitnessSigner,
} from "./signing.js";
import {
  type AwsKmsSignerConfig,
  type GcpKmsSignerConfig,
  KmsConfigurationError,
  KmsKeyValidationError,
  computeKeyFingerprint,
} from "./cloud-kms-signer.js";
import { AwsKmsWitnessSigner } from "./aws-kms-signer.js";
import { GcpKmsWitnessSigner } from "./gcp-kms-signer.js";

// ============================================================================
// Configuration Types & Interfaces
// ============================================================================

export type WitnessSignerProvider = "local" | "aws" | "gcp";

export interface BaseWitnessSignerConfig {
  witnessId: string;
  expectedKeyFingerprint?: string;
  totalTimeoutMs?: number;
  maxRetries?: number;
}

export interface LocalSignerConfig extends BaseWitnessSignerConfig {
  provider: "local";
  allowInProduction?: boolean;
  privateKey?: KeyObject;
  publicKey?: KeyObject;
}

export type WitnessSignerConfig =
  | LocalSignerConfig
  | AwsKmsSignerConfig
  | GcpKmsSignerConfig;

export interface WitnessSignerOverrides {
  awsKmsClient?: KMSClient;
  gcpKmsClient?: KeyManagementServiceClient;
  localPrivateKey?: KeyObject;
  localPublicKey?: KeyObject;
}

// ============================================================================
// Helper: Boolean Environment Parser
// ============================================================================

function parseBooleanEnv(value: string | undefined): boolean | undefined {
  if (value === undefined || value === "") {
    return undefined;
  }
  const lower = value.trim().toLowerCase();
  if (lower === "true" || lower === "1" || lower === "yes") {
    return true;
  }
  if (lower === "false" || lower === "0" || lower === "no") {
    return false;
  }
  throw new KmsConfigurationError(`Invalid boolean environment value: '${value}'`);
}

// ============================================================================
// Step 3.2: Environment Variable Configuration Loader
// ============================================================================

/**
 * Loads and strictly validates a WitnessSignerConfig from process environment variables.
 *
 * Enforces:
 * 1. Required WITNESS_SIGNER_PROVIDER ('local', 'aws', or 'gcp').
 * 2. Mandatory WITNESS_EXPECTED_KEY_FINGERPRINT in production mode.
 * 3. Strict rejection of conflicting provider environment variables.
 * 4. Safe credential handling (credentials are never logged or attached to errors).
 */
export function loadWitnessSignerConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): WitnessSignerConfig {
  const rawProvider = env.WITNESS_SIGNER_PROVIDER ?? env.WITNESS_SIGNER_TYPE;
  if (!rawProvider || rawProvider.trim() === "") {
    throw new KmsConfigurationError(
      "Missing required environment variable: WITNESS_SIGNER_PROVIDER (must be 'local', 'aws', or 'gcp')",
    );
  }

  const provider = rawProvider.trim().toLowerCase();
  if (provider !== "local" && provider !== "aws" && provider !== "gcp") {
    throw new KmsConfigurationError(
      `Invalid WITNESS_SIGNER_PROVIDER '${rawProvider}': must be 'local', 'aws', or 'gcp'`,
    );
  }

  const witnessId = (env.WITNESS_ID ?? "witness-node-1").trim();
  if (witnessId === "") {
    throw new KmsConfigurationError("Invalid WITNESS_ID: must be a non-empty string");
  }

  const rawFp1 = env.WITNESS_EXPECTED_KEY_FINGERPRINT?.trim();
  const rawFp2 = env.WITNESS_KMS_EXPECTED_FINGERPRINT?.trim();

  let expectedKeyFingerprint: string | undefined;

  if (rawFp1 && rawFp2) {
    if (rawFp1.toLowerCase() !== rawFp2.toLowerCase()) {
      throw new KmsConfigurationError(
        "Conflicting configuration: WITNESS_EXPECTED_KEY_FINGERPRINT and WITNESS_KMS_EXPECTED_FINGERPRINT are both set but do not match",
      );
    }
    expectedKeyFingerprint = rawFp1.toLowerCase();
  } else if (rawFp1) {
    expectedKeyFingerprint = rawFp1.toLowerCase();
  } else if (rawFp2) {
    expectedKeyFingerprint = rawFp2.toLowerCase();
  }

  if (process.env.NODE_ENV === "production") {
    if (!expectedKeyFingerprint || !/^[0-9a-f]{64}$/.test(expectedKeyFingerprint)) {
      throw new KmsConfigurationError(
        "SECURITY_VIOLATION: WITNESS_EXPECTED_KEY_FINGERPRINT / WITNESS_KMS_EXPECTED_FINGERPRINT (64-char lowercase SHA-256 hex) is strictly mandatory in production mode",
      );
    }
  } else if (expectedKeyFingerprint) {
    if (!/^[0-9a-f]{64}$/.test(expectedKeyFingerprint)) {
      throw new KmsConfigurationError(
        "Invalid expected key fingerprint: must be a 64-character hexadecimal SHA-256 string",
      );
    }
  }

  let totalTimeoutMs: number | undefined;
  if (env.WITNESS_TOTAL_TIMEOUT_MS) {
    totalTimeoutMs = Number(env.WITNESS_TOTAL_TIMEOUT_MS);
    if (!Number.isInteger(totalTimeoutMs) || totalTimeoutMs < 500 || totalTimeoutMs > 8000) {
      throw new KmsConfigurationError(
        `Invalid WITNESS_TOTAL_TIMEOUT_MS: must be an integer between 500 and 8000, received '${env.WITNESS_TOTAL_TIMEOUT_MS}'`,
      );
    }
  }

  let maxRetries: number | undefined;
  if (env.WITNESS_MAX_RETRIES) {
    maxRetries = Number(env.WITNESS_MAX_RETRIES);
    if (!Number.isInteger(maxRetries) || (maxRetries !== 0 && maxRetries !== 1)) {
      throw new KmsConfigurationError(
        `Invalid WITNESS_MAX_RETRIES: must be 0 or 1, received '${env.WITNESS_MAX_RETRIES}'`,
      );
    }
  }

  // Provider-specific parsing and conflict detection
  if (provider === "aws") {
    // Conflict check
    if (env.WITNESS_GCP_KEY_VERSION_NAME) {
      throw new KmsConfigurationError(
        "Conflicting configuration: WITNESS_GCP_KEY_VERSION_NAME is set while WITNESS_SIGNER_PROVIDER is 'aws'",
      );
    }

    const keyId = env.WITNESS_AWS_KEY_ID?.trim();
    if (!keyId) {
      throw new KmsConfigurationError("Missing required environment variable: WITNESS_AWS_KEY_ID for AWS provider");
    }

    const region = env.WITNESS_AWS_REGION?.trim();
    if (!region) {
      throw new KmsConfigurationError("Missing required environment variable: WITNESS_AWS_REGION for AWS provider");
    }

    const useFipsEndpoint = parseBooleanEnv(env.WITNESS_AWS_USE_FIPS);

    // Optional credentials parsing
    let credentials: { accessKeyId: string; secretAccessKey: string; sessionToken?: string } | undefined;
    const accessKeyId = env.WITNESS_AWS_ACCESS_KEY_ID?.trim();
    const secretAccessKey = env.WITNESS_AWS_SECRET_ACCESS_KEY?.trim();
    const sessionToken = env.WITNESS_AWS_SESSION_TOKEN?.trim();

    if (accessKeyId || secretAccessKey) {
      if (!accessKeyId || !secretAccessKey) {
        throw new KmsConfigurationError(
          "Incomplete AWS credentials: both WITNESS_AWS_ACCESS_KEY_ID and WITNESS_AWS_SECRET_ACCESS_KEY must be provided",
        );
      }
      credentials = {
        accessKeyId,
        secretAccessKey,
        ...(sessionToken ? { sessionToken } : {}),
      };
    }

    return {
      provider: "aws",
      witnessId,
      expectedKeyFingerprint,
      keyId,
      region,
      useFipsEndpoint,
      credentials,
      totalTimeoutMs,
      maxRetries,
    };
  }

  if (provider === "gcp") {
    // Conflict check
    if (env.WITNESS_AWS_KEY_ID || env.WITNESS_AWS_REGION) {
      throw new KmsConfigurationError(
        "Conflicting configuration: AWS environment variables are set while WITNESS_SIGNER_PROVIDER is 'gcp'",
      );
    }

    const keyVersionName = env.WITNESS_GCP_KEY_VERSION_NAME?.trim();
    if (!keyVersionName) {
      throw new KmsConfigurationError(
        "Missing required environment variable: WITNESS_GCP_KEY_VERSION_NAME for GCP provider",
      );
    }

    return {
      provider: "gcp",
      witnessId,
      expectedKeyFingerprint,
      keyVersionName,
      totalTimeoutMs,
      maxRetries,
    };
  }

  // provider === "local"
  if (env.WITNESS_AWS_KEY_ID || env.WITNESS_GCP_KEY_VERSION_NAME) {
    throw new KmsConfigurationError(
      "Conflicting configuration: Cloud KMS environment variables are set while WITNESS_SIGNER_PROVIDER is 'local'",
    );
  }

  const allowInProduction = parseBooleanEnv(env.WITNESS_ALLOW_LOCAL_IN_PRODUCTION) ?? false;

  return {
    provider: "local",
    witnessId,
    expectedKeyFingerprint,
    allowInProduction,
    totalTimeoutMs,
    maxRetries,
  };
}

// ============================================================================
// Step 3.1: Signer Factory
// ============================================================================

/**
 * Creates and validates a WitnessSigner instance from configuration.
 *
 * Enforces:
 * 1. Strict provider routing ('local', 'aws', 'gcp').
 * 2. Production prohibition of local signer unless explicitly permitted.
 * 3. Pre-initialization validation of configuration parameters.
 * 4. Injection of mock clients / key overrides for hermetic integration testing.
 */
export function createWitnessSignerFromConfig(
  config: WitnessSignerConfig,
  overrides?: WitnessSignerOverrides,
): WitnessSigner {
  if (!config || typeof config !== "object") {
    throw new KmsConfigurationError("Invalid signer configuration: expected configuration object");
  }

  if (!config.provider) {
    throw new KmsConfigurationError("Invalid signer configuration: missing 'provider'");
  }

  const provider = (config.provider as string).toLowerCase();

  if (provider === "local") {
    const localConfig = config as LocalSignerConfig;
    if (process.env.NODE_ENV === "production" && !localConfig.allowInProduction) {
      throw new KmsConfigurationError(
        "SECURITY_VIOLATION: Local Ed25519 signer is strictly prohibited in production mode. A hardware-backed CloudHSM/KMS signer is required.",
      );
    }

    const privKey = overrides?.localPrivateKey ?? localConfig.privateKey;
    const pubKey = overrides?.localPublicKey ?? localConfig.publicKey;

    return new LocalEd25519WitnessSigner(
      localConfig.witnessId,
      privKey,
      pubKey,
      localConfig.allowInProduction,
      localConfig.expectedKeyFingerprint,
    );
  }

  if (provider === "aws") {
    return new AwsKmsWitnessSigner(config as AwsKmsSignerConfig, overrides?.awsKmsClient);
  }

  if (provider === "gcp") {
    return new GcpKmsWitnessSigner(config as GcpKmsSignerConfig, overrides?.gcpKmsClient);
  }

  throw new KmsConfigurationError(
    `Unsupported signer provider '${config.provider}': must be 'local', 'aws', or 'gcp'`,
  );
}
