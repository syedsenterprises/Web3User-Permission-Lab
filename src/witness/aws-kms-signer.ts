/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: AWS KMS Ed25519 Witness Signer
 *
 * Implements HSM-backed PureEd25519 signing using AWS Key Management Service (AWS KMS)
 * with ECC_NIST_EDWARDS25519 key specification and ED25519_SHA_512 RAW signing algorithm.
 * Strictly enforces SDK retry suppression (maxAttempts: 1) and fail-closed error boundaries.
 *
 * Reference: FN-SEC-01 (Cloud KMS/HSM Signing Adapter)
 */

import {
  KMSClient,
  GetPublicKeyCommand,
  SignCommand,
} from "@aws-sdk/client-kms";
import {
  CloudKmsWitnessSigner,
  type AwsKmsSignerConfig,
  KmsConfigurationError,
  KmsKeyValidationError,
  WitnessUnavailableError,
  MAX_PER_ATTEMPT_DEADLINE_MS,
  BASE_BACKOFF_MS,
  MAX_BACKOFF_MS,
  MIN_REMAINING_BUDGET_FOR_RETRY_MS,
  extractRawEd25519PublicKey,
} from "./cloud-kms-signer.js";

export class AwsKmsWitnessSigner extends CloudKmsWitnessSigner<AwsKmsSignerConfig> {
  private client: KMSClient;

  constructor(config: AwsKmsSignerConfig, clientOverride?: KMSClient) {
    if (!config.keyId || typeof config.keyId !== "string" || config.keyId.trim() === "") {
      throw new KmsConfigurationError("Invalid keyId: must be a non-empty string ARN or KeyId");
    }
    if (!config.region || typeof config.region !== "string" || config.region.trim() === "") {
      throw new KmsConfigurationError("Invalid region: must be a non-empty AWS region string");
    }

    const mergedConfig: AwsKmsSignerConfig = {
      ...config,
      useFipsEndpoint: config.useFipsEndpoint ?? (process.env.NODE_ENV === "production"),
    };

    super(mergedConfig);

    if (clientOverride) {
      this.client = clientOverride;
    } else {
      const endpoint = this.config.useFipsEndpoint
        ? `https://kms-fips.${this.config.region}.amazonaws.com`
        : undefined;

      this.client = new KMSClient({
        region: this.config.region,
        maxAttempts: 1, // MANDATORY: Completely disables internal AWS SDK retries
        endpoint,
        credentials: this.config.credentials,
      });
    }
  }

  protected override async doInitialize(): Promise<void> {
    try {
      const command = new GetPublicKeyCommand({
        KeyId: this.config.keyId,
      });

      const response = await this.client.send(command);

      // Validate KeySpec
      if (response.KeySpec !== "ECC_NIST_EDWARDS25519") {
        throw new KmsKeyValidationError(
          `Unexpected AWS KMS KeySpec: expected 'ECC_NIST_EDWARDS25519', received '${String(response.KeySpec)}'`,
        );
      }

      // Validate PublicKey bytes
      if (!response.PublicKey || !(response.PublicKey instanceof Uint8Array)) {
        throw new KmsKeyValidationError("Missing or invalid PublicKey payload in AWS KMS response");
      }

      // Extract raw 32-byte Ed25519 key from 44-byte SPKI structure
      const rawKeyBytes = extractRawEd25519PublicKey(response.PublicKey);

      // Convert SPKI to PEM format for storage/export
      const base64Spki = Buffer.from(response.PublicKey).toString("base64");
      this.publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${base64Spki.match(/.{1,64}/g)?.join("\n") ?? base64Spki}\n-----END PUBLIC KEY-----\n`;

      // Validate fingerprint against expectedKeyFingerprint
      this.validateFingerprint(rawKeyBytes);
    } catch (err) {
      if (err instanceof KmsKeyValidationError || err instanceof KmsConfigurationError) {
        throw err;
      }
      throw new WitnessUnavailableError({
        message: `AWS KMS initialization failed: ${err instanceof Error ? err.message : String(err)}`,
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
          message: `AWS KMS signing timed out locally before dispatch (elapsed ${elapsed.toFixed(1)}ms >= ${totalTimeout}ms)`,
          reason: "TOTAL_TIMEOUT_EXCEEDED",
          proofOfNonExecution: true,
          retryAttempts: attempt - 1,
        });
      }

      const perAttemptDeadline = Math.min(remainingBudget, MAX_PER_ATTEMPT_DEADLINE_MS);
      const abortController = new AbortController();
      const timeoutId = setTimeout(() => abortController.abort(), perAttemptDeadline);

      try {
        const signCommand = new SignCommand({
          KeyId: this.config.keyId,
          Message: preimageBytes,
          MessageType: "RAW",
          SigningAlgorithm: "ED25519_SHA_512",
        });

        const response = await this.client.send(signCommand, {
          abortSignal: abortController.signal,
        });

        clearTimeout(timeoutId);

        if (!response.Signature || !(response.Signature instanceof Uint8Array)) {
          throw new WitnessUnavailableError({
            message: "Missing or invalid Signature buffer in AWS KMS Sign response",
            reason: "INVALID_SIGNATURE_PAYLOAD",
            proofOfNonExecution: false,
            retryAttempts: attempt,
          });
        }

        const sigBuffer = Buffer.from(response.Signature);
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

        const isThrottling = err?.name === "ThrottlingException" || err?.$metadata?.httpStatusCode === 400 && err?.name?.includes("Throttle");
        const isPreDispatchSocketError = err?.code === "ECONNREFUSED" || err?.code === "ENOTFOUND" || err?.code === "EAI_AGAIN";
        const isRetryable = (isThrottling || isPreDispatchSocketError) && attempt <= maxRetries;

        // Check if retry is permitted
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

        // All ambiguous or non-retryable outcomes fail closed immediately
        const isClientAbort = err?.name === "AbortError" || abortController.signal.aborted;
        const reason = isClientAbort
          ? "ATTEMPT_TIMEOUT_EXCEEDED"
          : (err?.name || "AWS_KMS_SIGN_FAILED");

        throw new WitnessUnavailableError({
          message: `AWS KMS signing failed [attempt ${attempt}/${maxRetries + 1}]: ${err?.message || String(err)}`,
          reason,
          proofOfNonExecution: isPreDispatchSocketError,
          retryAttempts: attempt,
          cause: err,
        });
      }
    }

    throw new WitnessUnavailableError({
      message: "AWS KMS signing exhausted retry budget",
      reason: "RETRY_BUDGET_EXHAUSTED",
      proofOfNonExecution: false,
      retryAttempts: attempt,
    });
  }

  protected override async doClose(): Promise<void> {
    if (this.client && typeof (this.client as any).destroy === "function") {
      this.client.destroy();
    }
  }
}
