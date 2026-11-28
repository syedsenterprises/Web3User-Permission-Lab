/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.3
 * Concrete AWS S3 Object Storage Adapter (`@aws-sdk/client-s3`)
 *
 * Implements `S3ObjectStorageAdapter` with:
 * - Conditional PUT (`IfNoneMatch: "*"`) mapping HTTP 412 / `PreconditionFailed`.
 * - SHA-256 and Content-MD5 checksum enforcement on upload and SHA-256 readback check.
 * - Idempotent delete on `NoSuchKey` / HTTP 404.
 * - Paginated `ListObjectsV2` traversal with continuation-token validation.
 * - Bounded per-attempt timeouts (`AbortController`) and retries on 429/503/network faults.
 * - Zero internal SDK retries (`maxAttempts: 1`) and zero static credentials.
 */

import { createHash } from "node:crypto";
import {
  DeleteObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import {
  type S3ObjectStorageAdapter,
  SnapshotError,
  SnapshotIntegrityError,
} from "./snapshot-manager.js";

export type S3ClientLike = Pick<S3Client, "send">;

/**
 * Configuration for `AwsS3ObjectStorageAdapter`.
 * Authentication relies exclusively on the AWS SDK v3 default credential provider chain
 * (environment variables, shared config/credentials files, IAM/ECS/EC2 roles, web identity).
 * Caller-supplied static `credentials` overrides are intentionally omitted.
 */
export interface AwsS3AdapterConfig {
  readonly bucket: string;
  readonly region: string;
  readonly keyPrefix?: string;
  readonly requestTimeoutMs?: number;
  readonly maxRetries?: number;
  readonly retryBaseDelayMs?: number;
  readonly endpoint?: string;
  readonly forcePathStyle?: boolean;
}

export const DEFAULT_S3_REQUEST_TIMEOUT_MS = 5_000;
export const DEFAULT_S3_MAX_RETRIES = 2;
export const DEFAULT_S3_RETRY_BASE_DELAY_MS = 100;
const MAX_LIST_PAGES = 1_000;

const RETRYABLE_HTTP_STATUSES = new Set([408, 429, 500, 502, 503, 504]);
const RETRYABLE_ERROR_NAMES = new Set([
  "SlowDown",
  "TooManyRequestsException",
  "ServiceUnavailable",
  "InternalError",
  "RequestTimeout",
]);
const RETRYABLE_NETWORK_CODES = new Set([
  "ECONNRESET",
  "ECONNREFUSED",
  "ETIMEDOUT",
  "EPIPE",
  "EAI_AGAIN",
  "ENOTFOUND",
  "NetworkingError",
]);

interface AwsErrorShape {
  name?: string;
  code?: string;
  message?: string;
  $metadata?: { httpStatusCode?: number };
}

function getHttpStatus(err: unknown): number | undefined {
  if (typeof err === "object" && err !== null) {
    return (err as AwsErrorShape).$metadata?.httpStatusCode;
  }
  return undefined;
}

function isPreconditionFailedError(err: unknown): boolean {
  if (getHttpStatus(err) === 412) return true;
  if (typeof err === "object" && err !== null) {
    const e = err as AwsErrorShape;
    return e.name === "PreconditionFailed" || e.code === "PreconditionFailed";
  }
  return false;
}

function isNotFoundError(err: unknown): boolean {
  if (getHttpStatus(err) === 404) return true;
  if (typeof err === "object" && err !== null) {
    const e = err as AwsErrorShape;
    return e.name === "NoSuchKey" || e.name === "NotFound" || e.code === "NoSuchKey";
  }
  return false;
}

function isAbortOrTimeoutError(err: unknown): boolean {
  if (typeof err === "object" && err !== null) {
    const e = err as AwsErrorShape;
    return e.name === "AbortError" || e.name === "TimeoutError";
  }
  return false;
}

function isRetryableError(err: unknown): boolean {
  if (err instanceof SnapshotIntegrityError) return false;
  if (isPreconditionFailedError(err) || isNotFoundError(err)) return false;
  if (isAbortOrTimeoutError(err)) return true;

  const status = getHttpStatus(err);
  if (status !== undefined) {
    return RETRYABLE_HTTP_STATUSES.has(status);
  }

  if (typeof err === "object" && err !== null) {
    const e = err as AwsErrorShape;
    if (e.name && RETRYABLE_ERROR_NAMES.has(e.name)) return true;
    if (e.code && RETRYABLE_NETWORK_CODES.has(e.code)) return true;
  }
  return false;
}

function normalizeKeyPrefix(rawPrefix?: string): string {
  if (!rawPrefix) return "";
  const trimmed = rawPrefix.trim().replace(/^\/+/, "");
  if (!trimmed) return "";
  if (trimmed.includes("..") || trimmed.includes("\\") || trimmed.includes("\0")) {
    throw new SnapshotError(`Unsafe S3 keyPrefix '${rawPrefix}'`, "PATH_TRAVERSAL_REJECTED");
  }
  return trimmed.endsWith("/") ? trimmed : `${trimmed}/`;
}

function validateObjectKey(key: string): string {
  if (!key || key.trim().length === 0) {
    throw new SnapshotError("S3 object key must be a non-empty string", "INVALID_STORAGE_KEY");
  }
  if (key.startsWith("/") || key.includes("..") || key.includes("\\") || key.includes("\0")) {
    throw new SnapshotError(`Unsafe S3 object key '${key}'`, "PATH_TRAVERSAL_REJECTED");
  }
  return key;
}

interface AbortableStreamLike {
  destroy?: (error?: Error) => void;
  cancel?: (reason?: unknown) => Promise<void> | void;
}

function createAbortError(message = "S3 response body stream aborted"): Error {
  return Object.assign(new Error(message), { name: "AbortError" });
}

function destroyStreamBestEffort(stream: unknown, err: Error): void {
  if (!stream || typeof stream !== "object") return;
  const s = stream as AbortableStreamLike;
  if (typeof s.destroy === "function") {
    try {
      s.destroy(err);
    } catch {
      // Best-effort stream teardown
    }
  } else if (typeof s.cancel === "function") {
    try {
      void Promise.resolve(s.cancel(err)).catch(() => {});
    } catch {
      // Best-effort stream teardown
    }
  }
}

async function raceWithAbortSignal<T>(
  promise: Promise<T>,
  abortSignal?: AbortSignal,
  onAbort?: () => void
): Promise<T> {
  if (!abortSignal) {
    return promise;
  }
  if (abortSignal.aborted) {
    onAbort?.();
    throw createAbortError();
  }

  let handleAbort: (() => void) | undefined;
  const abortPromise = new Promise<never>((_resolve, reject) => {
    handleAbort = () => {
      onAbort?.();
      reject(createAbortError());
    };
    abortSignal.addEventListener("abort", handleAbort, { once: true });
  });

  try {
    return await Promise.race([promise, abortPromise]);
  } finally {
    if (handleAbort) {
      abortSignal.removeEventListener("abort", handleAbort);
    }
  }
}

async function readBodyToBuffer(body: unknown, abortSignal?: AbortSignal): Promise<Buffer> {
  if (!body) {
    throw new SnapshotError("S3 GetObject response missing Body", "STORAGE_MALFORMED_RESPONSE");
  }
  if (abortSignal?.aborted) {
    const abortErr = createAbortError();
    destroyStreamBestEffort(body, abortErr);
    throw abortErr;
  }
  if (Buffer.isBuffer(body)) {
    return body;
  }
  if (body instanceof Uint8Array) {
    return Buffer.from(body);
  }
  if (
    typeof body === "object" &&
    "transformToByteArray" in body &&
    typeof (body as { transformToByteArray: unknown }).transformToByteArray === "function"
  ) {
    const bytes = await raceWithAbortSignal(
      (body as { transformToByteArray: () => Promise<Uint8Array> }).transformToByteArray(),
      abortSignal,
      () => destroyStreamBestEffort(body, createAbortError())
    );
    return Buffer.from(bytes);
  }
  if (typeof body === "object" && Symbol.asyncIterator in body) {
    const iterator = (body as AsyncIterable<unknown>)[Symbol.asyncIterator]();
    const cleanupIterator = (): void => {
      destroyStreamBestEffort(body, createAbortError());
      if (typeof iterator.return === "function") {
        void Promise.resolve(iterator.return()).catch(() => {});
      }
    };

    const chunks: Buffer[] = [];
    while (true) {
      const step = await raceWithAbortSignal(iterator.next(), abortSignal, cleanupIterator);
      if (step.done) {
        break;
      }
      const chunk = step.value;
      if (Buffer.isBuffer(chunk)) {
        chunks.push(chunk);
      } else if (chunk instanceof Uint8Array) {
        chunks.push(Buffer.from(chunk));
      } else if (typeof chunk === "string") {
        chunks.push(Buffer.from(chunk));
      } else {
        cleanupIterator();
        throw new SnapshotError(
          "Unsupported chunk type in S3 GetObject Body stream",
          "STORAGE_MALFORMED_RESPONSE"
        );
      }
    }
    return Buffer.concat(chunks);
  }
  throw new SnapshotError("Unsupported S3 GetObject Body type", "STORAGE_MALFORMED_RESPONSE");
}

export class AwsS3ObjectStorageAdapter implements S3ObjectStorageAdapter {
  private readonly bucket: string;
  private readonly keyPrefix: string;
  private readonly requestTimeoutMs: number;
  private readonly maxRetries: number;
  private readonly retryBaseDelayMs: number;
  private readonly client: S3ClientLike;

  constructor(config: AwsS3AdapterConfig, clientOverride?: S3ClientLike) {
    if (!config.bucket || config.bucket.trim().length === 0) {
      throw new SnapshotError("Invalid S3 bucket: must be a non-empty string", "INVALID_CONFIGURATION");
    }
    if (!config.region || config.region.trim().length === 0) {
      throw new SnapshotError("Invalid AWS region: must be a non-empty string", "INVALID_CONFIGURATION");
    }
    if ("credentials" in config && (config as Record<string, unknown>).credentials !== undefined) {
      throw new SnapshotError(
        "Static or caller-supplied credentials are not permitted; rely on the AWS SDK default credential provider chain",
        "INVALID_CONFIGURATION"
      );
    }

    const timeoutMs = config.requestTimeoutMs ?? DEFAULT_S3_REQUEST_TIMEOUT_MS;
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
      throw new SnapshotError("requestTimeoutMs must be a positive integer", "INVALID_CONFIGURATION");
    }

    const maxRetries = config.maxRetries ?? DEFAULT_S3_MAX_RETRIES;
    if (!Number.isInteger(maxRetries) || maxRetries < 0) {
      throw new SnapshotError("maxRetries must be a non-negative integer", "INVALID_CONFIGURATION");
    }

    const retryBaseDelayMs = config.retryBaseDelayMs ?? DEFAULT_S3_RETRY_BASE_DELAY_MS;
    if (!Number.isInteger(retryBaseDelayMs) || retryBaseDelayMs < 0) {
      throw new SnapshotError("retryBaseDelayMs must be a non-negative integer", "INVALID_CONFIGURATION");
    }

    this.bucket = config.bucket.trim();
    this.keyPrefix = normalizeKeyPrefix(config.keyPrefix);
    this.requestTimeoutMs = timeoutMs;
    this.maxRetries = maxRetries;
    this.retryBaseDelayMs = retryBaseDelayMs;

    this.client =
      clientOverride ??
      new S3Client({
        region: config.region.trim(),
        maxAttempts: 1, // Disable internal SDK retries; adapter enforces bounded retries & timeouts
        endpoint: config.endpoint,
        forcePathStyle: config.forcePathStyle,
      });
  }

  private resolveKey(key: string): string {
    const clean = validateObjectKey(key);
    if (!this.keyPrefix || clean.startsWith(this.keyPrefix)) {
      return clean;
    }
    return `${this.keyPrefix}${clean}`;
  }

  private resolveListPrefix(prefix: string): string | undefined {
    if (!prefix) {
      return this.keyPrefix || undefined;
    }
    return this.resolveKey(prefix);
  }

  private async executeWithRetry<T>(
    operation: string,
    fn: (signal: AbortSignal) => Promise<T>,
    shouldRetry: (err: unknown) => boolean = () => true
  ): Promise<T> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= this.maxRetries; attempt += 1) {
      const controller = new AbortController();
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
      }, this.requestTimeoutMs);

      try {
        return await fn(controller.signal);
      } catch (err) {
        const effectiveErr = timedOut
          ? new SnapshotError(
              `S3 ${operation} timed out after ${this.requestTimeoutMs}ms`,
              "STORAGE_TIMEOUT",
              err
            )
          : err;
        lastError = effectiveErr;

        if (!isRetryableError(err) || !shouldRetry(err) || attempt === this.maxRetries) {
          throw effectiveErr;
        }

        if (this.retryBaseDelayMs > 0) {
          const delayMs = this.retryBaseDelayMs * 2 ** attempt;
          await new Promise((r) => setTimeout(r, delayMs));
        }
      } finally {
        clearTimeout(timer);
      }
    }

    throw lastError;
  }

  private translateError(operation: string, keyOrPrefix: string, err: unknown): SnapshotError {
    if (err instanceof SnapshotError) {
      return err;
    }
    if (isNotFoundError(err)) {
      return new SnapshotError(
        `S3 ${operation} object not found: '${keyOrPrefix}'`,
        "STORAGE_NOT_FOUND",
        err
      );
    }
    const status = getHttpStatus(err);
    const msg = err instanceof Error ? err.message : String(err);
    if (status === 401 || status === 403) {
      return new SnapshotError(
        `S3 ${operation} unauthorized/forbidden (${status}) for '${keyOrPrefix}': ${msg}`,
        "STORAGE_ACCESS_DENIED",
        err
      );
    }
    return new SnapshotError(
      `S3 ${operation} failed${status ? ` (HTTP ${status})` : ""} for '${keyOrPrefix}': ${msg}`,
      "STORAGE_REQUEST_FAILED",
      err
    );
  }

  public async putObject(params: {
    key: string;
    body: Buffer;
    checksumSha256Base64: string;
    contentMd5Base64: string;
    ifNoneMatch: "*";
  }): Promise<{ statusCode: number; checksumSha256Base64?: string; eTag?: string }> {
    const resolvedKey = this.resolveKey(params.key);
    if (!params.checksumSha256Base64 || !params.contentMd5Base64) {
      throw new SnapshotError(
        "putObject requires non-empty checksumSha256Base64 and contentMd5Base64",
        "INVALID_CHECKSUM"
      );
    }

    try {
      const res = await this.executeWithRetry("putObject", async (abortSignal) => {
        try {
          return await this.client.send(
            new PutObjectCommand({
              Bucket: this.bucket,
              Key: resolvedKey,
              Body: params.body,
              ChecksumSHA256: params.checksumSha256Base64,
              ContentMD5: params.contentMd5Base64,
              IfNoneMatch: params.ifNoneMatch,
            }),
            { abortSignal }
          );
        } catch (err) {
          if (isPreconditionFailedError(err)) {
            return { $metadata: { httpStatusCode: 412 } };
          }
          throw err;
        }
      });

      const statusCode = res.$metadata?.httpStatusCode ?? 200;
      if (statusCode === 412) {
        return { statusCode: 412 };
      }

      const returnedSha = "ChecksumSHA256" in res ? res.ChecksumSHA256 : undefined;
      if (returnedSha && returnedSha !== params.checksumSha256Base64) {
        throw new SnapshotIntegrityError(
          `S3 PutObject ChecksumSHA256 mismatch: expected '${params.checksumSha256Base64}', got '${returnedSha}'`
        );
      }

      return {
        statusCode,
        checksumSha256Base64: returnedSha,
        eTag: "ETag" in res ? res.ETag : undefined,
      };
    } catch (err) {
      throw this.translateError("putObject", resolvedKey, err);
    }
  }

  public async getObject(key: string): Promise<Buffer> {
    const resolvedKey = this.resolveKey(key);
    try {
      let streamReadStarted = false;
      const { data, checksumSha256 } = await this.executeWithRetry(
        "getObject",
        async (abortSignal) => {
          const res = await this.client.send(
            new GetObjectCommand({
              Bucket: this.bucket,
              Key: resolvedKey,
              ChecksumMode: "ENABLED",
            }),
            { abortSignal }
          );
          streamReadStarted = true;
          const bodyData = await readBodyToBuffer(res.Body, abortSignal);
          return { data: bodyData, checksumSha256: res.ChecksumSHA256 };
        },
        () => !streamReadStarted
      );

      if (checksumSha256) {
        const actualSha256Base64 = createHash("sha256").update(data).digest("base64");
        if (actualSha256Base64 !== checksumSha256) {
          throw new SnapshotIntegrityError(
            `S3 GetObject ChecksumSHA256 mismatch for '${resolvedKey}': expected '${checksumSha256}', got '${actualSha256Base64}'`
          );
        }
      }
      return data;
    } catch (err) {
      throw this.translateError("getObject", resolvedKey, err);
    }
  }

  public async deleteObject(key: string): Promise<void> {
    const resolvedKey = this.resolveKey(key);
    try {
      await this.executeWithRetry("deleteObject", async (abortSignal) => {
        try {
          await this.client.send(
            new DeleteObjectCommand({
              Bucket: this.bucket,
              Key: resolvedKey,
            }),
            { abortSignal }
          );
        } catch (err) {
          if (isNotFoundError(err)) {
            return;
          }
          throw err;
        }
      });
    } catch (err) {
      throw this.translateError("deleteObject", resolvedKey, err);
    }
  }

  public async listObjects(
    prefix: string
  ): Promise<ReadonlyArray<{ key: string; modifiedAtMs: number }>> {
    const resolvedPrefix = this.resolveListPrefix(prefix);
    const results: Array<{ key: string; modifiedAtMs: number }> = [];
    let continuationToken: string | undefined;

    try {
      for (let page = 0; page < MAX_LIST_PAGES; page += 1) {
        const res = await this.executeWithRetry("listObjects", (abortSignal) =>
          this.client.send(
            new ListObjectsV2Command({
              Bucket: this.bucket,
              Prefix: resolvedPrefix,
              ContinuationToken: continuationToken,
            }),
            { abortSignal }
          )
        );

        if (res.Contents) {
          for (const item of res.Contents) {
            if (!item.Key || typeof item.Key !== "string") {
              throw new SnapshotError(
                "S3 ListObjectsV2 returned entry without a valid Key",
                "STORAGE_MALFORMED_RESPONSE"
              );
            }
            results.push({
              key: item.Key,
              modifiedAtMs: item.LastModified ? item.LastModified.getTime() : 0,
            });
          }
        }

        if (!res.IsTruncated) {
          return results;
        }

        if (!res.NextContinuationToken) {
          throw new SnapshotError(
            "S3 ListObjectsV2 returned IsTruncated=true without NextContinuationToken",
            "STORAGE_MALFORMED_RESPONSE"
          );
        }
        continuationToken = res.NextContinuationToken;
      }

      throw new SnapshotError(
        `S3 ListObjectsV2 exceeded maximum page limit (${MAX_LIST_PAGES})`,
        "STORAGE_PAGINATION_LIMIT"
      );
    } catch (err) {
      throw this.translateError("listObjects", resolvedPrefix ?? "", err);
    }
  }
}
