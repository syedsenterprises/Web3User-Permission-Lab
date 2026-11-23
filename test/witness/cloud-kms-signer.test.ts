/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Cloud KMS Signer Verification Suite
 *
 * Comprehensive tests for:
 * 1. CRC32C Castagnoli parsing, upfront Proxy rejection, and descriptor-based validation (D-1 to D-7, B-1 to B-10, P-1 to P-3).
 * 2. SPKI ASN.1 DER wire format parsing, 44-byte Ed25519 key extraction, and fingerprint calculation.
 * 3. AwsKmsWitnessSigner (ECC_NIST_EDWARDS25519, maxAttempts: 1, throttling retry, fail-closed boundaries).
 * 4. GcpKmsWitnessSigner (EC_SIGN_ED25519, SOFTWARE protection, retry: null, dual-RPC init, fail-closed boundaries).
 *
 * Reference: FN-SEC-01 (Cloud KMS/HSM Signing Adapter)
 */

import { describe, it, expect, beforeEach } from "vitest";
import { generateKeyPairSync, createHash } from "node:crypto";
import Long from "long";
import {
  calculateCrc32c,
  parseAndValidateCrc32cValue,
  verifyGcpPublicKeyCrc32c,
  parseSpkiPemToDer,
  extractRawEd25519PublicKey,
  computeKeyFingerprint,
  KmsKeyValidationError,
  KmsConfigurationError,
  WitnessNotReadyError,
  WitnessClosedError,
  WitnessUnavailableError,
  ED25519_SPKI_HEADER,
} from "../../src/witness/cloud-kms-signer.js";
import { AwsKmsWitnessSigner } from "../../src/witness/aws-kms-signer.js";
import { GcpKmsWitnessSigner } from "../../src/witness/gcp-kms-signer.js";

describe("Milestone 13-D Phase D2: Cloud KMS Witness Signer Suite (FN-SEC-01)", () => {
  // Generate a legitimate Ed25519 key pair for tests
  const testKeys = generateKeyPairSync("ed25519");
  const testSpkiDer = testKeys.publicKey.export({ type: "spki", format: "der" });
  const testSpkiPem = testKeys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const testRawKeyBytes = testSpkiDer.subarray(testSpkiDer.length - 32);
  const testFingerprint = createHash("sha256").update(testRawKeyBytes).digest("hex").toLowerCase();

  // ==========================================================================
  // 1. Mandatory 17 Cases & 3 Proxy Tests (Step 2A.4.6 & Step 2A.4.7)
  // ==========================================================================
  describe("CRC32C Input Validation & Upfront Proxy Rejection", () => {
    // ------------------------------------------------------------------------
    // P-1, P-2, P-3: Proxy Diagnostic Tests
    // ------------------------------------------------------------------------
    it("P-1: Proxy rejection occurs upfront before any Proxy trap executes", () => {
      let trapExecuted = false;
      const proxy = new Proxy({}, {
        get: () => { trapExecuted = true; return undefined; },
        has: () => { trapExecuted = true; return false; },
        getPrototypeOf: () => { trapExecuted = true; return Long.prototype; },
        getOwnPropertyDescriptor: () => { trapExecuted = true; return undefined; },
      });

      expect(() => parseAndValidateCrc32cValue(proxy)).toThrow(KmsKeyValidationError);
      expect(() => parseAndValidateCrc32cValue(proxy)).toThrow(/Proxy objects are strictly prohibited/);
      expect(trapExecuted).toBe(false);
    });

    it("P-2: Accessor-producing Proxy is rejected by upfront check without invoking its descriptor trap", () => {
      let descriptorTrapExecuted = false;
      let getterExecuted = false;
      const accessorProxy = new Proxy({}, {
        getPrototypeOf: () => Long.prototype,
        getOwnPropertyDescriptor: (target, prop) => {
          descriptorTrapExecuted = true;
          return {
            get: () => { getterExecuted = true; return 1; },
            enumerable: true,
            configurable: true,
          };
        },
      });

      expect(() => parseAndValidateCrc32cValue(accessorProxy)).toThrow(KmsKeyValidationError);
      expect(descriptorTrapExecuted).toBe(false);
      expect(getterExecuted).toBe(false);
    });

    it("P-3: Genuine inputs bypass Proxy check and verify subsequent CRC32C and key fingerprint", () => {
      const validCrc = calculateCrc32c(Buffer.from(testSpkiPem, "utf8"));
      expect(() => {
        verifyGcpPublicKeyCrc32c(testSpkiPem, validCrc);
      }).not.toThrow();

      const extracted = extractRawEd25519PublicKey(parseSpkiPemToDer(testSpkiPem));
      const computedFp = computeKeyFingerprint(extracted);
      expect(computedFp).toBe(testFingerprint);
    });

    // ------------------------------------------------------------------------
    // D-1 to D-7: Descriptor & Prototype Integrity Cases (Step 2A.4.6)
    // ------------------------------------------------------------------------
    it("D-1: Genuine Long with ordinary own data properties is accepted", () => {
      const genuineLong = Long.fromNumber(3808825987, true);
      const res = parseAndValidateCrc32cValue(genuineLong);
      expect(res).toBe(3808825987);
    });

    it("D-2: Genuine Long with own getter descriptor for low is rejected without calling getter", () => {
      let getterCalled = false;
      const fake = Object.create(Long.prototype);
      Object.defineProperty(fake, "low", {
        get: () => { getterCalled = true; return -486141309; },
        enumerable: true,
        configurable: true,
      });
      Object.defineProperty(fake, "high", {
        value: 0,
        writable: true,
        enumerable: true,
        configurable: true,
      });

      expect(() => parseAndValidateCrc32cValue(fake)).toThrow(KmsKeyValidationError);
      expect(() => parseAndValidateCrc32cValue(fake)).toThrow(/accessor descriptor detected/);
      expect(getterCalled).toBe(false);
    });

    it("D-3: Genuine Long with own getter descriptor for high is rejected without calling getter", () => {
      let getterCalled = false;
      const fake = Object.create(Long.prototype);
      Object.defineProperty(fake, "low", {
        value: -486141309,
        writable: true,
        enumerable: true,
        configurable: true,
      });
      Object.defineProperty(fake, "high", {
        get: () => { getterCalled = true; return 0; },
        enumerable: true,
        configurable: true,
      });

      expect(() => parseAndValidateCrc32cValue(fake)).toThrow(KmsKeyValidationError);
      expect(() => parseAndValidateCrc32cValue(fake)).toThrow(/accessor descriptor detected/);
      expect(getterCalled).toBe(false);
    });

    it("D-4: Genuine Long with own getter/setter descriptor is rejected", () => {
      const fake = Object.create(Long.prototype);
      Object.defineProperty(fake, "low", {
        get: () => 1,
        set: () => {},
        enumerable: true,
        configurable: true,
      });
      Object.defineProperty(fake, "high", {
        value: 0,
        writable: true,
        enumerable: true,
        configurable: true,
      });

      expect(() => parseAndValidateCrc32cValue(fake)).toThrow(KmsKeyValidationError);
      expect(() => parseAndValidateCrc32cValue(fake)).toThrow(/accessor descriptor detected/);
    });

    it("D-5: Genuine Long with valid data descriptors and overridden toString() derives correct checksum", () => {
      const genuineLong = Long.fromNumber(3808825987, true);
      genuineLong.toString = () => "malicious-string";
      const res = parseAndValidateCrc32cValue(genuineLong);
      expect(res).toBe(3808825987);
    });

    it("D-6: Object.create(Long.prototype) without own descriptors is rejected", () => {
      const fake = Object.create(Long.prototype);
      expect(() => parseAndValidateCrc32cValue(fake)).toThrow(KmsKeyValidationError);
      expect(() => parseAndValidateCrc32cValue(fake)).toThrow(/missing own property descriptors/);
    });

    it("D-7: Object.create(Long.prototype) with plausible own numeric data descriptors is accepted safely", () => {
      const fake = Object.create(Long.prototype);
      Object.defineProperty(fake, "low", {
        value: -486141309,
        writable: true,
        enumerable: true,
        configurable: true,
      });
      Object.defineProperty(fake, "high", {
        value: 0,
        writable: true,
        enumerable: true,
        configurable: true,
      });

      const res = parseAndValidateCrc32cValue(fake);
      expect(res).toBe(3808825987);
    });

    // ------------------------------------------------------------------------
    // B-1 to B-10: Baseline Cases (Step 2A.4.5)
    // ------------------------------------------------------------------------
    it("B-1: Genuine Long zero is accepted", () => {
      const genuineZero = Long.fromNumber(0, true);
      expect(parseAndValidateCrc32cValue(genuineZero)).toBe(0);
    });

    it("B-2: Genuine Long max (0xFFFFFFFF) is accepted", () => {
      const genuineMax = Long.fromNumber(0xffffffff, true);
      expect(parseAndValidateCrc32cValue(genuineMax)).toBe(4294967295);
    });

    it("B-3: Long with nonzero high word is rejected", () => {
      const nonzeroHigh = Long.fromBits(10, 1, true);
      expect(() => parseAndValidateCrc32cValue(nonzeroHigh)).toThrow(KmsKeyValidationError);
      expect(() => parseAndValidateCrc32cValue(nonzeroHigh)).toThrow(/nonzero high word/);
    });

    it("B-4: Long with non-integer or non-finite bitfields is rejected", () => {
      const fake = Object.create(Long.prototype);
      Object.defineProperty(fake, "low", { value: NaN, writable: true, enumerable: true, configurable: true });
      Object.defineProperty(fake, "high", { value: 0, writable: true, enumerable: true, configurable: true });

      expect(() => parseAndValidateCrc32cValue(fake)).toThrow(KmsKeyValidationError);
      expect(() => parseAndValidateCrc32cValue(fake)).toThrow(/non-integer or non-finite bitfields/);

      const fakeFloat = Object.create(Long.prototype);
      Object.defineProperty(fakeFloat, "low", { value: 12.34, writable: true, enumerable: true, configurable: true });
      Object.defineProperty(fakeFloat, "high", { value: 0, writable: true, enumerable: true, configurable: true });
      expect(() => parseAndValidateCrc32cValue(fakeFloat)).toThrow(/non-integer or non-finite bitfields/);
    });

    it("B-5: Forged marker object { __isLong__: true } is rejected", () => {
      expect(() => parseAndValidateCrc32cValue({ __isLong__: true })).toThrow(KmsKeyValidationError);
      expect(() => parseAndValidateCrc32cValue({ __isLong__: true })).toThrow(/Unsupported CRC32C representation/);
    });

    it("B-6: Forged marker object { __isLong__: true, low, high } with malicious toString() is rejected", () => {
      const forged = {
        __isLong__: true,
        low: -486141309,
        high: 0,
        toString: () => "3808825987",
      };
      expect(() => parseAndValidateCrc32cValue(forged)).toThrow(KmsKeyValidationError);
      expect(() => parseAndValidateCrc32cValue(forged)).toThrow(/Unsupported CRC32C representation/);
    });

    it("B-7: Primitive numbers: valid accepted, negative, float, and out-of-range rejected", () => {
      expect(parseAndValidateCrc32cValue(3808825987)).toBe(3808825987);
      expect(parseAndValidateCrc32cValue(0)).toBe(0);
      expect(parseAndValidateCrc32cValue(4294967295)).toBe(4294967295);

      expect(() => parseAndValidateCrc32cValue(-1)).toThrow(/out of unsigned 32-bit integer range/);
      expect(() => parseAndValidateCrc32cValue(12.34)).toThrow(/out of unsigned 32-bit integer range/);
      expect(() => parseAndValidateCrc32cValue(4294967296)).toThrow(/out of unsigned 32-bit integer range/);
      expect(() => parseAndValidateCrc32cValue(NaN)).toThrow(/out of unsigned 32-bit integer range/);
      expect(() => parseAndValidateCrc32cValue(Infinity)).toThrow(/out of unsigned 32-bit integer range/);
    });

    it("B-8: Decimal strings: valid accepted, malformed and out-of-range rejected", () => {
      expect(parseAndValidateCrc32cValue("3808825987")).toBe(3808825987);
      expect(parseAndValidateCrc32cValue("0")).toBe(0);
      expect(parseAndValidateCrc32cValue("4294967295")).toBe(4294967295);

      expect(() => parseAndValidateCrc32cValue("abc")).toThrow(/Malformed CRC32C decimal string/);
      expect(() => parseAndValidateCrc32cValue("0x1234")).toThrow(/Malformed CRC32C decimal string/);
      expect(() => parseAndValidateCrc32cValue("-1")).toThrow(/Malformed CRC32C decimal string/);
      expect(() => parseAndValidateCrc32cValue("4294967296")).toThrow(/out of unsigned 32-bit integer range/);
      expect(() => parseAndValidateCrc32cValue("")).toThrow(/Malformed CRC32C decimal string/);
    });

    it("B-9: Missing checksum metadata (null, undefined) is rejected", () => {
      expect(() => parseAndValidateCrc32cValue(null)).toThrow(/Missing required pemCrc32c/);
      expect(() => parseAndValidateCrc32cValue(undefined)).toThrow(/Missing required pemCrc32c/);
    });

    it("B-10: Standard Castagnoli test vector and corrupted PEM detection", () => {
      const vectorAscii = "123456789";
      const expectedVectorCrc = 0xe3069283; // 3808825987 unsigned decimal
      expect(calculateCrc32c(Buffer.from(vectorAscii, "utf8"))).toBe(expectedVectorCrc);

      // Verify CRC32C matching
      const validCrc = calculateCrc32c(Buffer.from(testSpkiPem, "utf8"));
      expect(() => verifyGcpPublicKeyCrc32c(testSpkiPem, validCrc)).not.toThrow();

      // Corrupt a single byte in PEM string
      const corruptedPem = testSpkiPem.replace("M", "N");
      expect(() => verifyGcpPublicKeyCrc32c(corruptedPem, validCrc)).toThrow(KmsKeyValidationError);
      expect(() => verifyGcpPublicKeyCrc32c(corruptedPem, validCrc)).toThrow(/CRC32C checksum mismatch/);
    });
  });

  // ==========================================================================
  // 2. SPKI ASN.1 DER Wire Format & Public Key Extraction
  // ==========================================================================
  describe("SPKI ASN.1 DER Decoding", () => {
    it("extracts raw 32-byte Ed25519 public key from 44-byte SPKI structure", () => {
      expect(testSpkiDer.byteLength).toBe(44);
      expect(Buffer.from(testSpkiDer).subarray(0, 12).equals(ED25519_SPKI_HEADER)).toBe(true);

      const rawKey = extractRawEd25519PublicKey(testSpkiDer);
      expect(rawKey.byteLength).toBe(32);
      expect(Buffer.from(rawKey).toString("hex")).toBe(Buffer.from(testRawKeyBytes).toString("hex"));
    });

    it("rejects SPKI DER payload with invalid length", () => {
      const shortDer = testSpkiDer.subarray(0, 43);
      expect(() => extractRawEd25519PublicKey(shortDer)).toThrow(KmsKeyValidationError);
      expect(() => extractRawEd25519PublicKey(shortDer)).toThrow(/expected 44 bytes/);

      const longDer = Buffer.concat([testSpkiDer, Buffer.from([0x00])]);
      expect(() => extractRawEd25519PublicKey(longDer)).toThrow(KmsKeyValidationError);
      expect(() => extractRawEd25519PublicKey(longDer)).toThrow(/expected 44 bytes/);
    });

    it("rejects SPKI DER payload with invalid OID prefix", () => {
      const corruptedDer = Buffer.from(testSpkiDer);
      corruptedDer[6] = 0x99; // Corrupt OID byte
      expect(() => extractRawEd25519PublicKey(corruptedDer)).toThrow(KmsKeyValidationError);
      expect(() => extractRawEd25519PublicKey(corruptedDer)).toThrow(/Invalid SPKI header/);
    });

    it("computes lowercase SHA-256 fingerprint", () => {
      const fp = computeKeyFingerprint(testRawKeyBytes);
      expect(fp).toBe(testFingerprint);
      expect(fp).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  // ==========================================================================
  // 3. AwsKmsWitnessSigner Unit Tests
  // ==========================================================================
  describe("AwsKmsWitnessSigner", () => {
    const originalEnv = process.env.NODE_ENV;

    beforeEach(() => {
      process.env.NODE_ENV = originalEnv;
    });

    it("enforces mandatory expectedKeyFingerprint in production mode", () => {
      process.env.NODE_ENV = "production";

      expect(() => {
        new AwsKmsWitnessSigner({
          provider: "aws",
          witnessId: "witness-aws-1",
          keyId: "arn:aws:kms:us-east-1:123456789012:key/test-key-id",
          region: "us-east-1",
        });
      }).toThrow(KmsConfigurationError);
      expect(() => {
        new AwsKmsWitnessSigner({
          provider: "aws",
          witnessId: "witness-aws-1",
          keyId: "arn:aws:kms:us-east-1:123456789012:key/test-key-id",
          region: "us-east-1",
        });
      }).toThrow(/expectedKeyFingerprint.*is strictly mandatory in production mode/);

      // Instantiation succeeds with valid 64-char fingerprint
      expect(() => {
        new AwsKmsWitnessSigner({
          provider: "aws",
          witnessId: "witness-aws-1",
          keyId: "arn:aws:kms:us-east-1:123456789012:key/test-key-id",
          region: "us-east-1",
          expectedKeyFingerprint: testFingerprint,
        });
      }).not.toThrow();
    });

    it("initializes with GetPublicKey, asserts ECC_NIST_EDWARDS25519, and caches keys", async () => {
      let getPublicKeyCalled = false;

      const mockClient: any = {
        send: async (cmd: any) => {
          if (cmd.constructor.name === "GetPublicKeyCommand") {
            getPublicKeyCalled = true;
            return {
              KeySpec: "ECC_NIST_EDWARDS25519",
              PublicKey: new Uint8Array(testSpkiDer),
            };
          }
          throw new Error("Unexpected command");
        },
      };

      const signer = new AwsKmsWitnessSigner(
        {
          provider: "aws",
          witnessId: "witness-aws-1",
          keyId: "test-key-id",
          region: "us-east-1",
          expectedKeyFingerprint: testFingerprint,
        },
        mockClient,
      );

      expect(signer.getState()).toBe("UNINITIALIZED");
      await signer.initialize();
      expect(signer.getState()).toBe("READY");
      expect(getPublicKeyCalled).toBe(true);
      expect(signer.getPublicKeyHex()).toBe(Buffer.from(testRawKeyBytes).toString("hex").toLowerCase());
      expect(signer.getPublicKeyPem()).toContain("-----BEGIN PUBLIC KEY-----");
    });

    it("rejects non-Ed25519 KeySpec during initialization", async () => {
      const mockClient: any = {
        send: async () => ({
          KeySpec: "ECC_NIST_P256",
          PublicKey: new Uint8Array(testSpkiDer),
        }),
      };

      const signer = new AwsKmsWitnessSigner(
        {
          provider: "aws",
          witnessId: "witness-aws-1",
          keyId: "test-key-id",
          region: "us-east-1",
        },
        mockClient,
      );

      await expect(signer.initialize()).rejects.toThrow(KmsKeyValidationError);
      await expect(signer.initialize()).rejects.toThrow(/expected 'ECC_NIST_EDWARDS25519', received 'ECC_NIST_P256'/);
      expect(signer.getState()).toBe("FAILED");
    });

    it("signs receipt canonically using PureEd25519 RAW MessageType", async () => {
      let capturedSignArgs: any = null;
      const fakeSignature = Buffer.alloc(64, 0xab);

      const mockClient: any = {
        send: async (cmd: any) => {
          if (cmd.constructor.name === "GetPublicKeyCommand") {
            return {
              KeySpec: "ECC_NIST_EDWARDS25519",
              PublicKey: new Uint8Array(testSpkiDer),
            };
          }
          if (cmd.constructor.name === "SignCommand") {
            capturedSignArgs = cmd.input;
            return {
              Signature: new Uint8Array(fakeSignature),
            };
          }
          throw new Error("Unexpected command");
        },
      };

      const signer = new AwsKmsWitnessSigner(
        {
          provider: "aws",
          witnessId: "witness-aws-1",
          keyId: "test-key-id",
          region: "us-east-1",
        },
        mockClient,
      );

      await signer.initialize();

      const preimage = "web3user-witness-receipt-v1\nticket-12345";
      const result = await signer.signReceipt(preimage, 42);

      expect(capturedSignArgs).not.toBeNull();
      expect(capturedSignArgs.SigningAlgorithm).toBe("ED25519_SHA_512");
      expect(capturedSignArgs.MessageType).toBe("RAW");
      expect(Buffer.from(capturedSignArgs.Message).toString("utf8")).toBe(preimage);

      expect(result.signatureHex).toBe(fakeSignature.toString("hex").toLowerCase());
      expect(result.generation).toBe(42);
    });

    it("retries on ThrottlingException when remaining budget >= 500ms, succeeding on attempt 2", async () => {
      let signAttempts = 0;
      const fakeSignature = Buffer.alloc(64, 0xfe);

      const mockClient: any = {
        send: async (cmd: any) => {
          if (cmd.constructor.name === "GetPublicKeyCommand") {
            return { KeySpec: "ECC_NIST_EDWARDS25519", PublicKey: new Uint8Array(testSpkiDer) };
          }
          if (cmd.constructor.name === "SignCommand") {
            signAttempts++;
            if (signAttempts === 1) {
              const throttleErr: any = new Error("Rate exceeded");
              throttleErr.name = "ThrottlingException";
              throttleErr.$metadata = { httpStatusCode: 400 };
              throw throttleErr;
            }
            return { Signature: new Uint8Array(fakeSignature) };
          }
          throw new Error("Unexpected command");
        },
      };

      const signer = new AwsKmsWitnessSigner(
        {
          provider: "aws",
          witnessId: "witness-aws-1",
          keyId: "test-key-id",
          region: "us-east-1",
          totalTimeoutMs: 5000,
          maxRetries: 1,
        },
        mockClient,
      );

      await signer.initialize();
      const res = await signer.signReceipt("preimage", 10);
      expect(signAttempts).toBe(2);
      expect(res.signatureHex).toBe(fakeSignature.toString("hex"));
    });

    it("fails closed immediately on ambiguous KMSInternalException without retrying", async () => {
      let signAttempts = 0;

      const mockClient: any = {
        send: async (cmd: any) => {
          if (cmd.constructor.name === "GetPublicKeyCommand") {
            return { KeySpec: "ECC_NIST_EDWARDS25519", PublicKey: new Uint8Array(testSpkiDer) };
          }
          if (cmd.constructor.name === "SignCommand") {
            signAttempts++;
            const internalErr: any = new Error("Internal failure");
            internalErr.name = "KMSInternalException";
            internalErr.$metadata = { httpStatusCode: 500 };
            throw internalErr;
          }
          throw new Error("Unexpected command");
        },
      };

      const signer = new AwsKmsWitnessSigner(
        {
          provider: "aws",
          witnessId: "witness-aws-1",
          keyId: "test-key-id",
          region: "us-east-1",
          maxRetries: 1,
        },
        mockClient,
      );

      await signer.initialize();
      await expect(signer.signReceipt("preimage", 1)).rejects.toThrow(WitnessUnavailableError);
      expect(signAttempts).toBe(1); // Crucial: Exactly 1 attempt, zero retries
    });

    it("enforces lifecycle: throws WitnessNotReadyError before init, WitnessClosedError after close", async () => {
      const mockClient: any = {
        send: async () => ({
          KeySpec: "ECC_NIST_EDWARDS25519",
          PublicKey: new Uint8Array(testSpkiDer),
        }),
      };

      const signer = new AwsKmsWitnessSigner(
        { provider: "aws", witnessId: "witness-aws-1", keyId: "test-key-id", region: "us-east-1" },
        mockClient,
      );

      await expect(signer.signReceipt("test", 1)).rejects.toThrow(WitnessNotReadyError);

      await signer.initialize();
      await signer.close();
      expect(signer.getState()).toBe("CLOSED");
      await expect(signer.signReceipt("test", 1)).rejects.toThrow(WitnessClosedError);
    });
  });

  // ==========================================================================
  // 4. GcpKmsWitnessSigner Unit Tests
  // ==========================================================================
  describe("GcpKmsWitnessSigner", () => {
    const originalEnv = process.env.NODE_ENV;

    beforeEach(() => {
      process.env.NODE_ENV = originalEnv;
    });

    const validKeyVersionName =
      "projects/test-proj/locations/us-central1/keyRings/ring-1/cryptoKeys/key-1/cryptoKeyVersions/1";

    it("validates keyVersionName format during instantiation", () => {
      expect(() => {
        new GcpKmsWitnessSigner({
          provider: "gcp",
          witnessId: "witness-gcp-1",
          keyVersionName: "invalid-name",
        });
      }).toThrow(KmsConfigurationError);
      expect(() => {
        new GcpKmsWitnessSigner({
          provider: "gcp",
          witnessId: "witness-gcp-1",
          keyVersionName: "invalid-name",
        });
      }).toThrow(/Invalid keyVersionName format/);
    });

    it("initializes via dual-RPC: verifies version state & protection level, verifies CRC32C, caches keys", async () => {
      let getVersionCalled = false;
      let getPublicKeyCalled = false;

      const validCrc = calculateCrc32c(Buffer.from(testSpkiPem, "utf8"));

      const mockClient: any = {
        getCryptoKeyVersion: async (req: any) => {
          getVersionCalled = true;
          return [
            {
              name: validKeyVersionName,
              state: "ENABLED",
              protectionLevel: "SOFTWARE",
              algorithm: "EC_SIGN_ED25519",
            },
          ];
        },
        getPublicKey: async (req: any) => {
          getPublicKeyCalled = true;
          return [
            {
              name: validKeyVersionName,
              algorithm: "EC_SIGN_ED25519",
              pem: testSpkiPem,
              pemCrc32c: { value: validCrc },
            },
          ];
        },
      };

      const signer = new GcpKmsWitnessSigner(
        {
          provider: "gcp",
          witnessId: "witness-gcp-1",
          keyVersionName: validKeyVersionName,
          expectedKeyFingerprint: testFingerprint,
        },
        mockClient,
      );

      await signer.initialize();
      expect(signer.getState()).toBe("READY");
      expect(getVersionCalled).toBe(true);
      expect(getPublicKeyCalled).toBe(true);
      expect(signer.getPublicKeyHex()).toBe(Buffer.from(testRawKeyBytes).toString("hex").toLowerCase());
    });

    it("rejects non-SOFTWARE protectionLevel during initialization", async () => {
      const mockClient: any = {
        getCryptoKeyVersion: async () => [
          {
            name: validKeyVersionName,
            state: "ENABLED",
            protectionLevel: "HSM", // Not supported for Ed25519 in GCP
            algorithm: "EC_SIGN_ED25519",
          },
        ],
      };

      const signer = new GcpKmsWitnessSigner(
        {
          provider: "gcp",
          witnessId: "witness-gcp-1",
          keyVersionName: validKeyVersionName,
        },
        mockClient,
      );

      await expect(signer.initialize()).rejects.toThrow(KmsKeyValidationError);
      await expect(signer.initialize()).rejects.toThrow(/expected SOFTWARE, received 'HSM'/);
      expect(signer.getState()).toBe("FAILED");
    });

    it("rejects public key when CRC32C checksum does not match", async () => {
      const mockClient: any = {
        getCryptoKeyVersion: async () => [
          {
            name: validKeyVersionName,
            state: "ENABLED",
            protectionLevel: "SOFTWARE",
            algorithm: "EC_SIGN_ED25519",
          },
        ],
        getPublicKey: async () => [
          {
            name: validKeyVersionName,
            algorithm: "EC_SIGN_ED25519",
            pem: testSpkiPem,
            pemCrc32c: { value: 999999999 }, // Mismatched checksum
          },
        ],
      };

      const signer = new GcpKmsWitnessSigner(
        {
          provider: "gcp",
          witnessId: "witness-gcp-1",
          keyVersionName: validKeyVersionName,
        },
        mockClient,
      );

      await expect(signer.initialize()).rejects.toThrow(KmsKeyValidationError);
      await expect(signer.initialize()).rejects.toThrow(/CRC32C checksum mismatch/);
    });

    it("signs receipt passing retry: null and data buffer to asymmetricSign", async () => {
      let capturedCallOptions: any = null;
      let capturedRequest: any = null;
      const fakeSig = Buffer.alloc(64, 0xcd);
      const validCrc = calculateCrc32c(Buffer.from(testSpkiPem, "utf8"));

      const mockClient: any = {
        getCryptoKeyVersion: async () => [
          { name: validKeyVersionName, state: "ENABLED", protectionLevel: "SOFTWARE", algorithm: "EC_SIGN_ED25519" },
        ],
        getPublicKey: async () => [
          { name: validKeyVersionName, algorithm: "EC_SIGN_ED25519", pem: testSpkiPem, pemCrc32c: { value: validCrc } },
        ],
        asymmetricSign: async (req: any, opts: any) => {
          capturedRequest = req;
          capturedCallOptions = opts;
          return [{ signature: new Uint8Array(fakeSig) }];
        },
      };

      const signer = new GcpKmsWitnessSigner(
        {
          provider: "gcp",
          witnessId: "witness-gcp-1",
          keyVersionName: validKeyVersionName,
        },
        mockClient,
      );

      await signer.initialize();
      const preimage = "preimage-content-v1";
      const res = await signer.signReceipt(preimage, 88);

      expect(capturedRequest.name).toBe(validKeyVersionName);
      expect(Buffer.from(capturedRequest.data).toString("utf8")).toBe(preimage);
      expect(capturedCallOptions.retry).toBeNull(); // MANDATORY: GAX retries suppressed
      expect(res.signatureHex).toBe(fakeSig.toString("hex"));
      expect(res.generation).toBe(88);
    });

    it("fails closed immediately on gRPC RESOURCE_EXHAUSTED (8) without retrying", async () => {
      let signCalls = 0;
      const validCrc = calculateCrc32c(Buffer.from(testSpkiPem, "utf8"));

      const mockClient: any = {
        getCryptoKeyVersion: async () => [
          { name: validKeyVersionName, state: "ENABLED", protectionLevel: "SOFTWARE", algorithm: "EC_SIGN_ED25519" },
        ],
        getPublicKey: async () => [
          { name: validKeyVersionName, algorithm: "EC_SIGN_ED25519", pem: testSpkiPem, pemCrc32c: { value: validCrc } },
        ],
        asymmetricSign: async () => {
          signCalls++;
          const err: any = new Error("Quota exceeded");
          err.code = 8; // RESOURCE_EXHAUSTED
          throw err;
        },
      };

      const signer = new GcpKmsWitnessSigner(
        {
          provider: "gcp",
          witnessId: "witness-gcp-1",
          keyVersionName: validKeyVersionName,
          maxRetries: 1,
        },
        mockClient,
      );

      await signer.initialize();
      await expect(signer.signReceipt("preimage", 1)).rejects.toThrow(WitnessUnavailableError);
      expect(signCalls).toBe(1); // Zero retries
    });

    it("fails closed immediately on gRPC UNAVAILABLE (14) without retrying", async () => {
      let signCalls = 0;
      const validCrc = calculateCrc32c(Buffer.from(testSpkiPem, "utf8"));

      const mockClient: any = {
        getCryptoKeyVersion: async () => [
          { name: validKeyVersionName, state: "ENABLED", protectionLevel: "SOFTWARE", algorithm: "EC_SIGN_ED25519" },
        ],
        getPublicKey: async () => [
          { name: validKeyVersionName, algorithm: "EC_SIGN_ED25519", pem: testSpkiPem, pemCrc32c: { value: validCrc } },
        ],
        asymmetricSign: async () => {
          signCalls++;
          const err: any = new Error("Stream dropped");
          err.code = 14; // UNAVAILABLE
          throw err;
        },
      };

      const signer = new GcpKmsWitnessSigner(
        {
          provider: "gcp",
          witnessId: "witness-gcp-1",
          keyVersionName: validKeyVersionName,
          maxRetries: 1,
        },
        mockClient,
      );

      await signer.initialize();
      await expect(signer.signReceipt("preimage", 1)).rejects.toThrow(WitnessUnavailableError);
      expect(signCalls).toBe(1); // Zero retries
    });
  });
});
