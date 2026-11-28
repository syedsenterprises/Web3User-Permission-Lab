/**
 * Web3User Permission Lab - Milestone 13-D Stage 2-B.3 Phase 2
 * Opt-in Live AWS S3 Staging Validation Suite
 *
 * Environment-variable contract (all required unless noted):
 * - WEB3USER_S3_LIVE_TEST=1                 Explicit opt-in gate (suite skipped otherwise).
 * - WEB3USER_S3_BUCKET                      Target staging bucket (production-like names rejected).
 * - WEB3USER_S3_CONFIRM_STAGING_BUCKET      Must exactly match WEB3USER_S3_BUCKET.
 * - AWS_REGION or WEB3USER_S3_REGION        Target AWS region.
 * - WEB3USER_S3_PREFIX                      Optional base prefix (default: "stage2b3-live-tests").
 * - WEB3USER_S3_TEST_TIMEOUT_MS             Optional request timeout in ms (default: 5000).
 * - WEB3USER_S3_KMS_KEY_ID                  Optional KMS key ID/ARN; enables explicit SSE-KMS test
 *                                           (requires kms:GenerateDataKey and kms:Decrypt).
 *
 * Uses the standard AWS SDK credential provider chain (OIDC/STS, no static keys)
 * and isolates every run under a unique prefix with strict cleanup.
 *
 * Pagination note: Multi-page ContinuationToken pagination is covered by mocked tests in
 * aws-s3-adapter.test.ts; a >1,000-object live pagination stress test is excluded here and
 * can be authorized separately.
 */

import { createHash, randomUUID } from "node:crypto";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AwsS3ObjectStorageAdapter } from "../../src/witness/aws-s3-adapter.js";
import {
  S3SnapshotStorageBackend,
  SnapshotCollisionError,
  SnapshotError,
} from "../../src/witness/snapshot-manager.js";

const LIVE_ENABLED = process.env.WEB3USER_S3_LIVE_TEST === "1";
const KMS_ENABLED = Boolean(process.env.WEB3USER_S3_KMS_KEY_ID?.trim());

export interface LiveS3Config {
  bucket: string;
  region: string;
  runPrefix: string;
  timeoutMs: number;
  kmsKeyId?: string;
}

function sha256Hex(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

function sha256B64(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("base64");
}

function md5B64(buf: Buffer): string {
  return createHash("md5").update(buf).digest("base64");
}

export function loadAndValidateLiveConfig(env: NodeJS.ProcessEnv = process.env): LiveS3Config {
  const bucket = env.WEB3USER_S3_BUCKET?.trim() ?? "";
  if (!bucket) {
    throw new Error("WEB3USER_S3_BUCKET is required when WEB3USER_S3_LIVE_TEST=1");
  }
  if (/(^|[-_.])(prod|production|prd)([-_.]|$)/i.test(bucket)) {
    throw new Error(
      `Refusing to run live S3 tests against potential production bucket '${bucket}'`
    );
  }

  const confirmedBucket = env.WEB3USER_S3_CONFIRM_STAGING_BUCKET?.trim() ?? "";
  if (!confirmedBucket) {
    throw new Error(
      "WEB3USER_S3_CONFIRM_STAGING_BUCKET is required and must exactly match WEB3USER_S3_BUCKET"
    );
  }
  if (confirmedBucket !== bucket) {
    throw new Error(
      `WEB3USER_S3_CONFIRM_STAGING_BUCKET ('${confirmedBucket}') does not match WEB3USER_S3_BUCKET ('${bucket}')`
    );
  }

  const region = (env.AWS_REGION ?? env.WEB3USER_S3_REGION ?? "").trim();
  if (!region) {
    throw new Error(
      "AWS_REGION or WEB3USER_S3_REGION is required when WEB3USER_S3_LIVE_TEST=1"
    );
  }

  const rawBasePrefix = (env.WEB3USER_S3_PREFIX ?? "stage2b3-live-tests")
    .trim()
    .replace(/^\/+|\/+$/g, "");
  if (!rawBasePrefix || rawBasePrefix.includes("..")) {
    throw new Error(`Invalid WEB3USER_S3_PREFIX: '${rawBasePrefix}'`);
  }

  const rawTimeout = env.WEB3USER_S3_TEST_TIMEOUT_MS?.trim();
  const timeoutMs = rawTimeout ? Number.parseInt(rawTimeout, 10) : 5_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error(`Invalid WEB3USER_S3_TEST_TIMEOUT_MS: '${rawTimeout}'`);
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const runPrefix = `${rawBasePrefix}/run-${timestamp}-${randomUUID().slice(0, 8)}`;
  const kmsKeyId = env.WEB3USER_S3_KMS_KEY_ID?.trim() || undefined;

  return { bucket, region, runPrefix, timeoutMs, kmsKeyId };
}

describe("Live S3 config staging-bucket validation (offline)", () => {
  it("rejects missing WEB3USER_S3_CONFIRM_STAGING_BUCKET", () => {
    expect(() =>
      loadAndValidateLiveConfig({
        WEB3USER_S3_BUCKET: "web3user-staging-snaps",
        AWS_REGION: "us-east-1",
      })
    ).toThrow(/WEB3USER_S3_CONFIRM_STAGING_BUCKET is required/);
  });

  it("rejects mismatched WEB3USER_S3_CONFIRM_STAGING_BUCKET", () => {
    expect(() =>
      loadAndValidateLiveConfig({
        WEB3USER_S3_BUCKET: "web3user-staging-snaps",
        WEB3USER_S3_CONFIRM_STAGING_BUCKET: "other-staging-bucket",
        AWS_REGION: "us-east-1",
      })
    ).toThrow(/does not match WEB3USER_S3_BUCKET/);
  });

  it("rejects production-keyword buckets even when confirmation matches", () => {
    expect(() =>
      loadAndValidateLiveConfig({
        WEB3USER_S3_BUCKET: "web3user-prod-snaps",
        WEB3USER_S3_CONFIRM_STAGING_BUCKET: "web3user-prod-snaps",
        AWS_REGION: "us-east-1",
      })
    ).toThrow(/potential production bucket/);
  });

  it("accepts matching staging bucket confirmation and region", () => {
    const cfg = loadAndValidateLiveConfig({
      WEB3USER_S3_BUCKET: "web3user-staging-snaps",
      WEB3USER_S3_CONFIRM_STAGING_BUCKET: "web3user-staging-snaps",
      AWS_REGION: "us-east-1",
    });
    expect(cfg.bucket).toBe("web3user-staging-snaps");
    expect(cfg.region).toBe("us-east-1");
    expect(cfg.runPrefix).toMatch(/^stage2b3-live-tests\/run-/);
  });
});

describe.skipIf(!LIVE_ENABLED)(
  "Milestone 13-D Stage 2-B.3 Phase 2: AwsS3ObjectStorageAdapter (Live AWS S3)",
  () => {
    let config: LiveS3Config;
    let adapter: AwsS3ObjectStorageAdapter;
    let backend: S3SnapshotStorageBackend;

    beforeAll(() => {
      config = loadAndValidateLiveConfig();
      adapter = new AwsS3ObjectStorageAdapter({
        bucket: config.bucket,
        region: config.region,
        keyPrefix: config.runPrefix,
        requestTimeoutMs: config.timeoutMs,
      });
      backend = new S3SnapshotStorageBackend(config.bucket, adapter);
    });

    afterAll(async () => {
      if (!adapter || !config) return;
      const leftover = await adapter.listObjects("");
      for (const item of leftover) {
        if (!item.key.startsWith(`${config.runPrefix}/`)) {
          throw new Error(
            `Refusing to delete key outside run prefix '${config.runPrefix}': '${item.key}'`
          );
        }
        await adapter.deleteObject(item.key);
      }
      const remainingAfterCleanup = await adapter.listObjects("");
      expect(remainingAfterCleanup).toEqual([]);
    });

    it("enforces conditional PutObject and maps duplicate-key HTTP 412 to SnapshotCollisionError", async () => {
      const payload1 = Buffer.from(`live-conditional-1-${randomUUID()}`);
      const payload2 = Buffer.from(`live-conditional-2-${randomUUID()}`);
      const uri = backend.buildUri("live-cluster", "epoch-cond", `snap-${randomUUID().slice(0, 8)}`);

      const putRes = await backend.putAndVerify(uri, payload1, sha256Hex(payload1));
      expect(putRes.byteSize).toBe(payload1.byteLength);

      await expect(backend.putAndVerify(uri, payload2, sha256Hex(payload2))).rejects.toThrow(
        SnapshotCollisionError
      );

      const downloaded = await backend.get(uri);
      expect(downloaded.equals(payload1)).toBe(true);
    });

    it("allows exactly one winner in a concurrent conditional-write race", async () => {
      const uri = backend.buildUri("live-cluster", "epoch-race", `snap-${randomUUID().slice(0, 8)}`);
      const payloadA = Buffer.from(`race-writer-a-${randomUUID()}`);
      const payloadB = Buffer.from(`race-writer-b-${randomUUID()}`);

      const results = await Promise.allSettled([
        backend.putAndVerify(uri, payloadA, sha256Hex(payloadA)),
        backend.putAndVerify(uri, payloadB, sha256Hex(payloadB)),
      ]);

      const fulfilled = results.filter((r) => r.status === "fulfilled");
      const rejected = results.filter((r) => r.status === "rejected");

      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect((rejected[0] as PromiseRejectedResult).reason).toBeInstanceOf(SnapshotCollisionError);
    });

    it("validates SHA-256 and Content-MD5 on upload/readback and rejects tampered digests", async () => {
      const payload = Buffer.from(`checksum-live-${randomUUID()}`);
      const uri = backend.buildUri("live-cluster", "epoch-sha", `snap-${randomUUID().slice(0, 8)}`);

      await backend.putAndVerify(uri, payload, sha256Hex(payload));
      const readback = await backend.get(uri);
      expect(readback.equals(payload)).toBe(true);

      const badKey = `snapshots/live-cluster/epoch-sha/bad-${randomUUID().slice(0, 8)}.snap`;
      await expect(
        adapter.putObject({
          key: badKey,
          body: payload,
          checksumSha256Base64: sha256B64(Buffer.from("wrong-digest")),
          contentMd5Base64: md5B64(payload),
          ifNoneMatch: "*",
        })
      ).rejects.toThrow(SnapshotError);

      const listed = await adapter.listObjects("snapshots/live-cluster/epoch-sha/");
      expect(listed.some((item) => item.key.endsWith(badKey))).toBe(false);
    });

    it("streams larger response bodies via GetObject and verifies checksum", async () => {
      const largePayload = Buffer.alloc(512 * 1024, 0x4b);
      const uri = backend.buildUri("live-cluster", "epoch-stream", `snap-${randomUUID().slice(0, 8)}`);

      await backend.putAndVerify(uri, largePayload, sha256Hex(largePayload));
      const downloaded = await backend.get(uri);
      expect(downloaded.byteLength).toBe(largePayload.byteLength);
      expect(downloaded.equals(largePayload)).toBe(true);
    });

    it("isolates listObjects by prefix and supports idempotent deleteObject and missing-key 404", async () => {
      const keyA = `snapshots/live-cluster/iso-a/${randomUUID().slice(0, 8)}.snap`;
      const keyB = `snapshots/live-cluster/iso-b/${randomUUID().slice(0, 8)}.snap`;
      const body = Buffer.from("prefix-isolation-payload");

      await adapter.putObject({
        key: keyA,
        body,
        checksumSha256Base64: sha256B64(body),
        contentMd5Base64: md5B64(body),
        ifNoneMatch: "*",
      });
      await adapter.putObject({
        key: keyB,
        body,
        checksumSha256Base64: sha256B64(body),
        contentMd5Base64: md5B64(body),
        ifNoneMatch: "*",
      });

      const listA = await adapter.listObjects("snapshots/live-cluster/iso-a/");
      expect(listA).toHaveLength(1);
      expect(listA[0]!.key).toBe(`${config.runPrefix}/${keyA}`);

      await adapter.deleteObject(keyA);
      await expect(adapter.deleteObject(keyA)).resolves.toBeUndefined();

      await expect(adapter.getObject(keyA)).rejects.toMatchObject({
        name: "SnapshotError",
        code: "STORAGE_NOT_FOUND",
      });
    });

    it.skipIf(!KMS_ENABLED)(
      "explicitly encrypts with SSE-KMS (WEB3USER_S3_KMS_KEY_ID) and verifies KMS metadata",
      async () => {
        const kmsKeyId = config.kmsKeyId!;
        const payload = Buffer.from(`kms-live-${randomUUID()}`);
        const key = `${config.runPrefix}/snapshots/live-cluster/epoch-kms/snap-${randomUUID().slice(0, 8)}.snap`;

        const s3 = new S3Client({ region: config.region, maxAttempts: 1 });
        const putRes = await s3.send(
          new PutObjectCommand({
            Bucket: config.bucket,
            Key: key,
            Body: payload,
            ChecksumSHA256: sha256B64(payload),
            ContentMD5: md5B64(payload),
            IfNoneMatch: "*",
            ServerSideEncryption: "aws:kms",
            SSEKMSKeyId: kmsKeyId,
          })
        );

        expect(putRes.ServerSideEncryption).toBe("aws:kms");
        expect(putRes.SSEKMSKeyId).toContain(kmsKeyId);

        const downloaded = await adapter.getObject(key);
        expect(downloaded.equals(payload)).toBe(true);
      }
    );
  }
);
