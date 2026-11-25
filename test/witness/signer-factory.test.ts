/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Signer Factory & Env Config Suite
 *
 * Verifies:
 * - Step 3.1: createWitnessSignerFromConfig routing, overrides, and production security rules.
 * - Step 3.2: loadWitnessSignerConfigFromEnv parsing, validation, conflict detection, and credential protection.
 *
 * Reference: FN-SEC-01 Step 3
 */

import { describe, it, expect, beforeEach } from "vitest";
import { generateKeyPairSync, createHash } from "node:crypto";
import {
  createWitnessSignerFromConfig,
  loadWitnessSignerConfigFromEnv,
} from "../../src/witness/signer-factory.js";
import {
  LocalEd25519WitnessSigner,
} from "../../src/witness/signing.js";
import { AwsKmsWitnessSigner } from "../../src/witness/aws-kms-signer.js";
import { GcpKmsWitnessSigner } from "../../src/witness/gcp-kms-signer.js";
import {
  KmsConfigurationError,
} from "../../src/witness/cloud-kms-signer.js";

describe("Milestone 13-D Phase D2: Signer Factory & Configuration Suite (FN-SEC-01 Step 3.1 & 3.2)", () => {
  const originalEnv = { ...process.env };

  const testKeys = generateKeyPairSync("ed25519");
  const testSpkiDer = testKeys.publicKey.export({ type: "spki", format: "der" });
  const testRawKeyBytes = testSpkiDer.subarray(testSpkiDer.length - 32);
  const testFingerprint = createHash("sha256").update(testRawKeyBytes).digest("hex").toLowerCase();

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  // ==========================================================================
  // Step 3.1: createWitnessSignerFromConfig
  // ==========================================================================
  describe("createWitnessSignerFromConfig", () => {
    it("instantiates LocalEd25519WitnessSigner in non-production", () => {
      process.env.NODE_ENV = "test";
      const signer = createWitnessSignerFromConfig({
        provider: "local",
        witnessId: "witness-local-1",
      });

      expect(signer).toBeInstanceOf(LocalEd25519WitnessSigner);
      expect(signer.getWitnessId()).toBe("witness-local-1");
      expect(signer.getPublicKeyHex()).toHaveLength(64);
    });

    it("prohibits LocalEd25519WitnessSigner in production unless allowInProduction is true", () => {
      process.env.NODE_ENV = "production";

      expect(() => {
        createWitnessSignerFromConfig({
          provider: "local",
          witnessId: "witness-local-1",
          expectedKeyFingerprint: testFingerprint,
        });
      }).toThrow(KmsConfigurationError);

      expect(() => {
        createWitnessSignerFromConfig({
          provider: "local",
          witnessId: "witness-local-1",
          expectedKeyFingerprint: testFingerprint,
        });
      }).toThrow(/Local Ed25519 signer is strictly prohibited in production mode/);

      // Allowed when allowInProduction: true and matching fingerprint
      const allowed = createWitnessSignerFromConfig({
        provider: "local",
        witnessId: "witness-local-1",
        allowInProduction: true,
        expectedKeyFingerprint: testFingerprint,
        privateKey: testKeys.privateKey,
        publicKey: testKeys.publicKey,
      });
      expect(allowed).toBeInstanceOf(LocalEd25519WitnessSigner);
    });

    it("validates expectedKeyFingerprint for LocalEd25519WitnessSigner", () => {
      process.env.NODE_ENV = "test";
      // Matching fingerprint
      expect(() => {
        createWitnessSignerFromConfig({
          provider: "local",
          witnessId: "witness-local-1",
          expectedKeyFingerprint: testFingerprint,
          privateKey: testKeys.privateKey,
          publicKey: testKeys.publicKey,
        });
      }).not.toThrow();

      // Mismatched fingerprint
      const mismatchedFp = "0".repeat(64);
      expect(() => {
        createWitnessSignerFromConfig({
          provider: "local",
          witnessId: "witness-local-1",
          expectedKeyFingerprint: mismatchedFp,
          privateKey: testKeys.privateKey,
          publicKey: testKeys.publicKey,
        });
      }).toThrow(/Local Witness Public Key Fingerprint mismatch/);
    });

    it("instantiates AwsKmsWitnessSigner with client override", () => {
      const mockAwsClient: any = { send: async () => ({}) };
      const signer = createWitnessSignerFromConfig(
        {
          provider: "aws",
          witnessId: "witness-aws-1",
          keyId: "arn:aws:kms:us-east-1:123456789012:key/test-key-id",
          region: "us-east-1",
          expectedKeyFingerprint: testFingerprint,
        },
        { awsKmsClient: mockAwsClient },
      );

      expect(signer).toBeInstanceOf(AwsKmsWitnessSigner);
      expect(signer.getWitnessId()).toBe("witness-aws-1");
    });

    it("instantiates GcpKmsWitnessSigner with client override", () => {
      const mockGcpClient: any = {};
      const validGcpName =
        "projects/test-proj/locations/us-central1/keyRings/ring-1/cryptoKeys/key-1/cryptoKeyVersions/1";
      const signer = createWitnessSignerFromConfig(
        {
          provider: "gcp",
          witnessId: "witness-gcp-1",
          keyVersionName: validGcpName,
          expectedKeyFingerprint: testFingerprint,
        },
        { gcpKmsClient: mockGcpClient },
      );

      expect(signer).toBeInstanceOf(GcpKmsWitnessSigner);
      expect(signer.getWitnessId()).toBe("witness-gcp-1");
    });

    it("rejects invalid or unsupported provider types", () => {
      expect(() => {
        createWitnessSignerFromConfig({ provider: "azure" as any, witnessId: "w1" });
      }).toThrow(KmsConfigurationError);
      expect(() => {
        createWitnessSignerFromConfig({ provider: "" as any, witnessId: "w1" });
      }).toThrow(/missing 'provider'/);
    });
  });

  // ==========================================================================
  // Step 3.2: loadWitnessSignerConfigFromEnv
  // ==========================================================================
  describe("loadWitnessSignerConfigFromEnv", () => {
    it("loads local signer configuration with defaults", () => {
      const env = {
        WITNESS_SIGNER_PROVIDER: "local",
        WITNESS_ID: "node-local-42",
      };
      const config = loadWitnessSignerConfigFromEnv(env);
      expect(config.provider).toBe("local");
      expect(config.witnessId).toBe("node-local-42");
      expect((config as any).allowInProduction).toBe(false);
    });

    it("loads local signer with WITNESS_SIGNER_TYPE fallback", () => {
      const env = {
        WITNESS_SIGNER_TYPE: "LOCAL",
      };
      const config = loadWitnessSignerConfigFromEnv(env);
      expect(config.provider).toBe("local");
      expect(config.witnessId).toBe("witness-node-1");
    });

    it("loads AWS configuration with full credentials and parameters", () => {
      const env = {
        WITNESS_SIGNER_PROVIDER: "aws",
        WITNESS_ID: "aws-witness-node",
        WITNESS_AWS_KEY_ID: "arn:aws:kms:us-east-1:123456789012:key/k1",
        WITNESS_AWS_REGION: "us-east-1",
        WITNESS_AWS_USE_FIPS: "true",
        WITNESS_AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE",
        WITNESS_AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        WITNESS_AWS_SESSION_TOKEN: "AQoDYXdzEJr1EXAMPLE",
        WITNESS_TOTAL_TIMEOUT_MS: "4000",
        WITNESS_MAX_RETRIES: "1",
      };
      const config = loadWitnessSignerConfigFromEnv(env) as any;
      expect(config.provider).toBe("aws");
      expect(config.witnessId).toBe("aws-witness-node");
      expect(config.keyId).toBe("arn:aws:kms:us-east-1:123456789012:key/k1");
      expect(config.region).toBe("us-east-1");
      expect(config.useFipsEndpoint).toBe(true);
      expect(config.credentials.accessKeyId).toBe("AKIAIOSFODNN7EXAMPLE");
      expect(config.credentials.secretAccessKey).toBe("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
      expect(config.credentials.sessionToken).toBe("AQoDYXdzEJr1EXAMPLE");
      expect(config.totalTimeoutMs).toBe(4000);
      expect(config.maxRetries).toBe(1);
    });

    it("loads GCP configuration with timeouts", () => {
      const validGcpName =
        "projects/test-proj/locations/us-central1/keyRings/ring-1/cryptoKeys/key-1/cryptoKeyVersions/1";
      const env = {
        WITNESS_SIGNER_PROVIDER: "gcp",
        WITNESS_ID: "gcp-witness-node",
        WITNESS_GCP_KEY_VERSION_NAME: validGcpName,
        WITNESS_TOTAL_TIMEOUT_MS: "3000",
        WITNESS_MAX_RETRIES: "0",
      };
      const config = loadWitnessSignerConfigFromEnv(env) as any;
      expect(config.provider).toBe("gcp");
      expect(config.keyVersionName).toBe(validGcpName);
      expect(config.totalTimeoutMs).toBe(3000);
      expect(config.maxRetries).toBe(0);
    });

    it("throws KmsConfigurationError if WITNESS_SIGNER_PROVIDER is missing", () => {
      expect(() => loadWitnessSignerConfigFromEnv({})).toThrow(KmsConfigurationError);
      expect(() => loadWitnessSignerConfigFromEnv({})).toThrow(/Missing required environment variable: WITNESS_SIGNER_PROVIDER/);
    });

    it("throws KmsConfigurationError if WITNESS_SIGNER_PROVIDER is invalid", () => {
      expect(() => loadWitnessSignerConfigFromEnv({ WITNESS_SIGNER_PROVIDER: "vault" })).toThrow(
        /Invalid WITNESS_SIGNER_PROVIDER 'vault'/,
      );
    });

    it("throws KmsConfigurationError on invalid timeout bounds", () => {
      expect(() =>
        loadWitnessSignerConfigFromEnv({
          WITNESS_SIGNER_PROVIDER: "local",
          WITNESS_TOTAL_TIMEOUT_MS: "400",
        }),
      ).toThrow(/Invalid WITNESS_TOTAL_TIMEOUT_MS/);

      expect(() =>
        loadWitnessSignerConfigFromEnv({
          WITNESS_SIGNER_PROVIDER: "local",
          WITNESS_TOTAL_TIMEOUT_MS: "10000",
        }),
      ).toThrow(/Invalid WITNESS_TOTAL_TIMEOUT_MS/);
    });

    it("throws KmsConfigurationError on invalid maxRetries", () => {
      expect(() =>
        loadWitnessSignerConfigFromEnv({
          WITNESS_SIGNER_PROVIDER: "local",
          WITNESS_MAX_RETRIES: "3",
        }),
      ).toThrow(/Invalid WITNESS_MAX_RETRIES/);
    });

    it("rejects incomplete AWS credentials without leaking secrets in errors", () => {
      const env = {
        WITNESS_SIGNER_PROVIDER: "aws",
        WITNESS_AWS_KEY_ID: "key-1",
        WITNESS_AWS_REGION: "us-east-1",
        WITNESS_AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE",
        // Missing WITNESS_AWS_SECRET_ACCESS_KEY
      };
      let thrown: any;
      try {
        loadWitnessSignerConfigFromEnv(env);
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(KmsConfigurationError);
      expect(thrown.message).toContain("both WITNESS_AWS_ACCESS_KEY_ID and WITNESS_AWS_SECRET_ACCESS_KEY must be provided");
      expect(thrown.message).not.toContain("AKIAIOSFODNN7EXAMPLE");
    });

    it("rejects conflicting AWS and GCP environment variables", () => {
      // AWS with GCP key version
      expect(() =>
        loadWitnessSignerConfigFromEnv({
          WITNESS_SIGNER_PROVIDER: "aws",
          WITNESS_AWS_KEY_ID: "key-1",
          WITNESS_AWS_REGION: "us-east-1",
          WITNESS_GCP_KEY_VERSION_NAME: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        }),
      ).toThrow(/Conflicting configuration.*WITNESS_GCP_KEY_VERSION_NAME.*is set while WITNESS_SIGNER_PROVIDER is 'aws'/);

      // GCP with AWS key ID
      expect(() =>
        loadWitnessSignerConfigFromEnv({
          WITNESS_SIGNER_PROVIDER: "gcp",
          WITNESS_GCP_KEY_VERSION_NAME: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
          WITNESS_AWS_KEY_ID: "key-1",
        }),
      ).toThrow(/Conflicting configuration.*AWS environment variables are set while WITNESS_SIGNER_PROVIDER is 'gcp'/);

      // Local with AWS variable
      expect(() =>
        loadWitnessSignerConfigFromEnv({
          WITNESS_SIGNER_PROVIDER: "local",
          WITNESS_AWS_KEY_ID: "key-1",
        }),
      ).toThrow(/Conflicting configuration.*Cloud KMS environment variables are set while WITNESS_SIGNER_PROVIDER is 'local'/);
    });

    it("enforces mandatory expectedKeyFingerprint in production mode with dual-alias support", () => {
      process.env.NODE_ENV = "production";

      // 1. Missing both variables in production throws
      expect(() =>
        loadWitnessSignerConfigFromEnv({
          WITNESS_SIGNER_PROVIDER: "aws",
          WITNESS_AWS_KEY_ID: "key-1",
          WITNESS_AWS_REGION: "us-east-1",
        }),
      ).toThrow(/WITNESS_EXPECTED_KEY_FINGERPRINT \/ WITNESS_KMS_EXPECTED_FINGERPRINT.*is strictly mandatory in production mode/);

      // 2. Malformed fingerprint in production throws
      expect(() =>
        loadWitnessSignerConfigFromEnv({
          WITNESS_SIGNER_PROVIDER: "aws",
          WITNESS_AWS_KEY_ID: "key-1",
          WITNESS_AWS_REGION: "us-east-1",
          WITNESS_EXPECTED_KEY_FINGERPRINT: "not-a-valid-sha256-hex",
        }),
      ).toThrow(/SECURITY_VIOLATION: WITNESS_EXPECTED_KEY_FINGERPRINT \/ WITNESS_KMS_EXPECTED_FINGERPRINT/);

      // 3. WITNESS_EXPECTED_KEY_FINGERPRINT succeeds
      const cfg1 = loadWitnessSignerConfigFromEnv({
        WITNESS_SIGNER_PROVIDER: "aws",
        WITNESS_AWS_KEY_ID: "key-1",
        WITNESS_AWS_REGION: "us-east-1",
        WITNESS_EXPECTED_KEY_FINGERPRINT: testFingerprint,
      });
      expect(cfg1.expectedKeyFingerprint).toBe(testFingerprint);

      // 4. WITNESS_KMS_EXPECTED_FINGERPRINT succeeds (backward compatibility)
      const cfg2 = loadWitnessSignerConfigFromEnv({
        WITNESS_SIGNER_PROVIDER: "aws",
        WITNESS_AWS_KEY_ID: "key-1",
        WITNESS_AWS_REGION: "us-east-1",
        WITNESS_KMS_EXPECTED_FINGERPRINT: testFingerprint,
      });
      expect(cfg2.expectedKeyFingerprint).toBe(testFingerprint);

      // 5. Both set and matching succeeds
      const cfg3 = loadWitnessSignerConfigFromEnv({
        WITNESS_SIGNER_PROVIDER: "aws",
        WITNESS_AWS_KEY_ID: "key-1",
        WITNESS_AWS_REGION: "us-east-1",
        WITNESS_EXPECTED_KEY_FINGERPRINT: testFingerprint,
        WITNESS_KMS_EXPECTED_FINGERPRINT: testFingerprint.toUpperCase(),
      });
      expect(cfg3.expectedKeyFingerprint).toBe(testFingerprint);

      // 6. Conflicting fingerprint values are rejected
      const conflictingFp = "1".repeat(64);
      expect(() =>
        loadWitnessSignerConfigFromEnv({
          WITNESS_SIGNER_PROVIDER: "aws",
          WITNESS_AWS_KEY_ID: "key-1",
          WITNESS_AWS_REGION: "us-east-1",
          WITNESS_EXPECTED_KEY_FINGERPRINT: testFingerprint,
          WITNESS_KMS_EXPECTED_FINGERPRINT: conflictingFp,
        }),
      ).toThrow(/Conflicting configuration: WITNESS_EXPECTED_KEY_FINGERPRINT and WITNESS_KMS_EXPECTED_FINGERPRINT are both set but do not match/);
    });
  });
});
