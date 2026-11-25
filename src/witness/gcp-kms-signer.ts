/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: GCP Cloud KMS Ed25519 Witness Signer
 *
 * Implements software-protected PureEd25519 signing using Google Cloud KMS (EC_SIGN_ED25519).
 * Strictly enforces GAX retry suppression (retry: null), dual-RPC metadata validation,
 * pre-parsing Castagnoli CRC32C integrity checking, and fail-closed error boundaries.
 *
 * Reference: FN-SEC-01 (Cloud KMS/HSM Signing Adapter)
 */

import { KeyManagementServiceClient } from "@google-cloud/kms";
import {
  CloudKmsWitnessSigner,
  type GcpKmsSignerConfig,
  KmsConfigurationError,
  KmsKeyValidationError,
  WitnessUnavailableError,
  MAX_PER_ATTEMPT_DEADLINE_MS,
  BASE_BACKOFF_MS,
  MAX_BACKOFF_MS,
  MIN_REMAINING_BUDGET_FOR_RETRY_MS,
  verifyGcpPublicKeyCrc32c,
  parseSpkiPemToDer,
  extractRawEd25519PublicKey,
} from "./cloud-kms-signer.js";

export class GcpKmsWitnessSigner extends CloudKmsWitnessSigner<GcpKmsSignerConfig> {
  private client: KeyManagementServiceClient;

  constructor(config: GcpKmsSignerConfig, clientOverride?: KeyManagementServiceClient) {
    if (!config.keyVersionName || typeof config.keyVersionName !== "string" || config.keyVersionName.trim() === "") {
      throw new KmsConfigurationError("Invalid keyVersionName: must be a non-empty GCP resource string");
    }

    // Expected format: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{cryptoKey}/cryptoKeyVersions/{version}
    const resourceRegex = /^projects\/[^/]+\/locations\/[^/]+\/keyRings\/[^/]+\/cryptoKeys\/[^/]+\/cryptoKeyVersions\/[^/]+$/;
    if (!resourceRegex.test(config.keyVersionName)) {
      throw new KmsConfigurationError(
        `Invalid keyVersionName format: expected 'projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*', received '${config.keyVersionName}'`,
      );
    }

    super(config);

    if (clientOverride) {
      this.client = clientOverride;
    } else {
      this.client = new KeyManagementServiceClient();
    }
  }

  protected override async doInitialize(): Promise<void> {
    try {
      // RPC 1: Inspect CryptoKeyVersion Metadata
      const [versionMeta] = await this.client.getCryptoKeyVersion({
        name: this.config.keyVersionName,
      });

      if (!versionMeta || versionMeta.name !== this.config.keyVersionName) {
        throw new KmsKeyValidationError(
          `Returned CryptoKeyVersion name mismatch: expected '${this.config.keyVersionName}', received '${versionMeta?.name}'`,
        );
      }

      if (versionMeta.state !== "ENABLED" && versionMeta.state !== 1) {
        throw new KmsKeyValidationError(
          `CryptoKeyVersion is not in ENABLED state: received state '${String(versionMeta.state)}'`,
        );
      }

      if (versionMeta.protectionLevel !== "SOFTWARE" && versionMeta.protectionLevel !== 1) {
        throw new KmsKeyValidationError(
          `Unexpected protectionLevel: expected SOFTWARE, received '${String(versionMeta.protectionLevel)}'`,
        );
      }

      if (versionMeta.algorithm !== "EC_SIGN_ED25519" && versionMeta.algorithm !== 40) {
        throw new KmsKeyValidationError(
          `Unexpected algorithm: expected EC_SIGN_ED25519, received '${String(versionMeta.algorithm)}'`,
        );
      }

      // RPC 2: Retrieve Public Key & Verify CRC32C Checksum
      const [publicKey] = await this.client.getPublicKey({
        name: this.config.keyVersionName,
      });

      if (!publicKey || publicKey.name !== this.config.keyVersionName) {
        throw new KmsKeyValidationError(
          `Returned PublicKey name mismatch: expected '${this.config.keyVersionName}', received '${publicKey?.name}'`,
        );
      }

      if (publicKey.algorithm !== "EC_SIGN_ED25519" && publicKey.algorithm !== 40) {
        throw new KmsKeyValidationError(
          `Unexpected PublicKey algorithm: expected EC_SIGN_ED25519, received '${String(publicKey.algorithm)}'`,
        );
      }

      if (!publicKey.pem || typeof publicKey.pem !== "string") {
        throw new KmsKeyValidationError("Missing or invalid PEM public key string in GCP KMS response");
      }

      // Pre-parsing Castagnoli CRC32C integrity check over UTF-8 PEM payload
      verifyGcpPublicKeyCrc32c(publicKey.pem, publicKey.pemCrc32c);

      // Parse SPKI DER bytes and extract trailing 32-byte Ed25519 raw key
      const derBytes = parseSpkiPemToDer(publicKey.pem);
      const rawKeyBytes = extractRawEd25519PublicKey(derBytes);

      this.publicKeyPem = publicKey.pem;

      // Validate fingerprint against expectedKeyFingerprint
      this.validateFingerprint(rawKeyBytes);
    } catch (err) {
      if (err instanceof KmsKeyValidationError || err instanceof KmsConfigurationError) {
        throw err;
      }
      throw new WitnessUnavailableError({
        message: `GCP Cloud KMS initialization failed: ${err instanceof Error ? err.message : String(err)}`,
        reason: "INITIALIZATION_FAILED",
        proofOfNonExecution: true,
        retryAttempts: 0,
        cause: err,
      });
    }
  }

  protected override async doSignReceipt(preimageBytes: Buffer): Promise<string> {
    const totalTimeout = this.config.totalTimeoutMs ?? 5000;
    const maxRetries = this.config.maxRetries ?? 1;
    const startTime = performance.now();
    let attempt = 0;

    while (attempt <= maxRetries) {
      attempt++;
      const elapsed = performance.now() - startTime;
      const remainingBudget = totalTimeout - elapsed;

      if (remainingBudget <= 0) {
        throw new WitnessUnavailableError({
          message: `GCP KMS signing timed out locally before dispatch (elapsed ${elapsed.toFixed(1)}ms >= ${totalTimeout}ms)`,
          reason: "TOTAL_TIMEOUT_EXCEEDED",
          proofOfNonExecution: true,
          retryAttempts: attempt - 1,
        });
      }

      const perAttemptDeadline = Math.min(remainingBudget, MAX_PER_ATTEMPT_DEADLINE_MS);
      const abortController = new AbortController();
      const timeoutId = setTimeout(() => abortController.abort(), perAttemptDeadline);

      try {
        const [response] = await this.client.asymmetricSign(
          {
            name: this.config.keyVersionName,
            data: preimageBytes,
          },
          {
            timeout: perAttemptDeadline,
            retry: null, // MANDATORY: Completely disables GAX SDK retries
            signal: abortController.signal,
          },
        );

        clearTimeout(timeoutId);

        if (!response.signature || !(response.signature instanceof Uint8Array)) {
          throw new WitnessUnavailableError({
            message: "Missing or invalid signature buffer in GCP KMS asymmetricSign response",
            reason: "INVALID_SIGNATURE_PAYLOAD",
            proofOfNonExecution: false,
            retryAttempts: attempt,
          });
        }

        const sigBuffer = Buffer.from(response.signature);
        if (sigBuffer.byteLength !== 64) {
          throw new WitnessUnavailableError({
            message: `Invalid Ed25519 signature length: expected 64 bytes, received ${sigBuffer.byteLength}`,
            reason: "INVALID_SIGNATURE_LENGTH",
            proofOfNonExecution: false,
            retryAttempts: attempt,
          });
        }

        return sigBuffer.toString("hex").toLowerCase();
      } catch (err: any) {
        clearTimeout(timeoutId);

        const isPreDispatchSocketError = err?.code === "ECONNREFUSED" || err?.code === "ENOTFOUND" || err?.code === "EAI_AGAIN";
        const isRetryable = isPreDispatchSocketError && attempt <= maxRetries;

        if (isRetryable) {
          const currentElapsed = performance.now() - startTime;
          const currentRemaining = totalTimeout - currentElapsed;
          const jitter = Math.floor(Math.random() * (MAX_BACKOFF_MS - BASE_BACKOFF_MS + 1));
          const backoffDelay = BASE_BACKOFF_MS + jitter;

          if (currentRemaining - backoffDelay >= MIN_REMAINING_BUDGET_FOR_RETRY_MS) {
            await new Promise((resolve) => setTimeout(resolve, backoffDelay));
            continue; // Retry
          }
        }

        // All ambiguous outcomes (including RESOURCE_EXHAUSTED = 8, UNAVAILABLE = 14, DEADLINE_EXCEEDED = 4)
        // must fail closed immediately
        const isClientAbort = err?.name === "AbortError" || abortController.signal.aborted;
        const reason = isClientAbort
          ? "ATTEMPT_TIMEOUT_EXCEEDED"
          : (err?.code ? `GRPC_${err.code}` : "GCP_KMS_SIGN_FAILED");

        throw new WitnessUnavailableError({
          message: `GCP KMS signing failed [attempt ${attempt}/${maxRetries + 1}]: ${err?.message || String(err)}`,
          reason,
          proofOfNonExecution: isPreDispatchSocketError,
          retryAttempts: attempt,
          cause: err,
        });
      }
    }

    throw new WitnessUnavailableError({
      message: "GCP KMS signing exhausted retry budget",
      reason: "RETRY_BUDGET_EXHAUSTED",
      proofOfNonExecution: false,
      retryAttempts: attempt,
    });
  }

  protected override async doClose(): Promise<void> {
    if (this.client && typeof (this.client as any).close === "function") {
      await this.client.close();
    }
  }
}
