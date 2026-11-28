import { describe, it, expect, vi } from "vitest";
import { createHash } from "node:crypto";
import {
  DeleteObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
} from "@aws-sdk/client-s3";
import {
  AwsS3ObjectStorageAdapter,
  type AwsS3AdapterConfig,
  type S3ClientLike,
} from "../../src/witness/aws-s3-adapter.js";
import {
  S3SnapshotStorageBackend,
  SnapshotCollisionError,
  SnapshotError,
  SnapshotIntegrityError,
} from "../../src/witness/snapshot-manager.js";

function sha256B64(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("base64");
}

function md5B64(buf: Buffer): string {
  return createHash("md5").update(buf).digest("base64");
}

function sha256Hex(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

describe("Milestone 13-D Stage 2-B.3 Phase 1: AwsS3ObjectStorageAdapter", () => {
  it("validates configuration and rejects unsafe keys or prefixes", async () => {
    const mockClient: S3ClientLike = { send: vi.fn() };

    expect(
      () => new AwsS3ObjectStorageAdapter({ bucket: "", region: "us-east-1" }, mockClient)
    ).toThrow(/Invalid S3 bucket/);
    expect(
      () => new AwsS3ObjectStorageAdapter({ bucket: "b", region: " " }, mockClient)
    ).toThrow(/Invalid AWS region/);
    expect(
      () =>
        new AwsS3ObjectStorageAdapter(
          { bucket: "b", region: "us-east-1", keyPrefix: "../escape" },
          mockClient
        )
    ).toThrow(/Unsafe S3 keyPrefix/);
    expect(
      () =>
        new AwsS3ObjectStorageAdapter(
          { bucket: "b", region: "us-east-1", requestTimeoutMs: 0 },
          mockClient
        )
    ).toThrow(/requestTimeoutMs/);

    const adapter = new AwsS3ObjectStorageAdapter(
      { bucket: "staging-bucket", region: "us-east-1", retryBaseDelayMs: 0 },
      mockClient
    );

    await expect(adapter.getObject("")).rejects.toThrow(/non-empty string/);
    await expect(adapter.getObject("/leading-slash")).rejects.toThrow(/Unsafe S3 object key/);
    await expect(adapter.getObject("snapshots/../secret")).rejects.toThrow(/Unsafe S3 object key/);
    await expect(
      adapter.putObject({
        key: "snapshots/k1.snap",
        body: Buffer.from("x"),
        checksumSha256Base64: "",
        contentMd5Base64: "abc",
        ifNoneMatch: "*",
      })
    ).rejects.toThrow(/non-empty checksumSha256Base64/);
    expect(mockClient.send).not.toHaveBeenCalled();
  });

  it("executes put, get, delete, and list with exact AWS SDK commands and S3SnapshotStorageBackend", async () => {
    const payload = Buffer.from("snapshot-payload-v1");
    const shaB64 = sha256B64(payload);
    const md5 = md5B64(payload);
    const modifiedDate = new Date("2026-11-27T12:00:00Z");

    const sendMock = vi.fn(async (cmd: unknown) => {
      if (cmd instanceof PutObjectCommand) {
        return {
          $metadata: { httpStatusCode: 200 },
          ChecksumSHA256: cmd.input.ChecksumSHA256,
          ETag: '"etag-123"',
        };
      }
      if (cmd instanceof GetObjectCommand) {
        return {
          $metadata: { httpStatusCode: 200 },
          ChecksumSHA256: shaB64,
          Body: {
            transformToByteArray: async () => new Uint8Array(payload),
          },
        };
      }
      if (cmd instanceof ListObjectsV2Command) {
        return {
          $metadata: { httpStatusCode: 200 },
          IsTruncated: false,
          Contents: [
            {
              Key: "env-a/snapshots/c1/ep1/snap1.snap",
              LastModified: modifiedDate,
            },
          ],
        };
      }
      if (cmd instanceof DeleteObjectCommand) {
        return { $metadata: { httpStatusCode: 204 } };
      }
      throw new Error("Unexpected command");
    });

    const adapter = new AwsS3ObjectStorageAdapter(
      {
        bucket: "web3user-staging-snaps",
        region: "us-east-1",
        keyPrefix: "env-a",
        retryBaseDelayMs: 0,
      },
      { send: sendMock as unknown as S3ClientLike["send"] }
    );

    const backend = new S3SnapshotStorageBackend("web3user-staging-snaps", adapter);
    const uri = backend.buildUri("c1", "ep1", "snap1");

    const putRes = await backend.putAndVerify(uri, payload, sha256Hex(payload));
    expect(putRes.byteSize).toBe(payload.byteLength);

    const putCmd = sendMock.mock.calls[0][0] as PutObjectCommand;
    expect(putCmd).toBeInstanceOf(PutObjectCommand);
    expect(putCmd.input).toEqual({
      Bucket: "web3user-staging-snaps",
      Key: "env-a/snapshots/c1/ep1/snap1.snap",
      Body: payload,
      ChecksumSHA256: shaB64,
      ContentMD5: md5,
      IfNoneMatch: "*",
    });

    const downloaded = await backend.get(uri);
    expect(downloaded.equals(payload)).toBe(true);
    const getCmd = sendMock.mock.calls[1][0] as GetObjectCommand;
    expect(getCmd.input).toEqual({
      Bucket: "web3user-staging-snaps",
      Key: "env-a/snapshots/c1/ep1/snap1.snap",
      ChecksumMode: "ENABLED",
    });

    const listed = await backend.listObjects();
    expect(listed).toEqual([
      {
        uri: "s3://web3user-staging-snaps/env-a/snapshots/c1/ep1/snap1.snap",
        snapshotId: "snap1",
        modifiedAtMs: modifiedDate.getTime(),
      },
    ]);
    const listCmd = sendMock.mock.calls[2][0] as ListObjectsV2Command;
    expect(listCmd.input.Prefix).toBe("env-a/snapshots/");

    await backend.delete(uri);
    const delCmd = sendMock.mock.calls[3][0] as DeleteObjectCommand;
    expect(delCmd.input).toEqual({
      Bucket: "web3user-staging-snaps",
      Key: "env-a/snapshots/c1/ep1/snap1.snap",
    });
  });

  it("maps HTTP 412 / PreconditionFailed to SnapshotCollisionError without retrying", async () => {
    const payload = Buffer.from("duplicate-snap");
    const err412 = Object.assign(new Error("At least one of the pre-conditions did not hold"), {
      name: "PreconditionFailed",
      $metadata: { httpStatusCode: 412 },
    });

    const sendMock = vi.fn().mockRejectedValue(err412);
    const adapter = new AwsS3ObjectStorageAdapter(
      { bucket: "b", region: "us-east-1", maxRetries: 2, retryBaseDelayMs: 0 },
      { send: sendMock }
    );
    const backend = new S3SnapshotStorageBackend("b", adapter);
    const uri = backend.buildUri("c1", "ep1", "snap1");

    await expect(backend.putAndVerify(uri, payload, sha256Hex(payload))).rejects.toThrow(
      SnapshotCollisionError
    );
    expect(sendMock).toHaveBeenCalledTimes(1);
  });

  it("handles NoSuchKey / HTTP 404: idempotent delete and STORAGE_NOT_FOUND on get", async () => {
    const err404 = Object.assign(new Error("The specified key does not exist."), {
      name: "NoSuchKey",
      $metadata: { httpStatusCode: 404 },
    });

    const sendMock = vi.fn().mockRejectedValue(err404);
    const adapter = new AwsS3ObjectStorageAdapter(
      { bucket: "b", region: "us-east-1", maxRetries: 2, retryBaseDelayMs: 0 },
      { send: sendMock }
    );

    await expect(adapter.deleteObject("snapshots/missing.snap")).resolves.toBeUndefined();
    await expect(adapter.getObject("snapshots/missing.snap")).rejects.toMatchObject({
      code: "STORAGE_NOT_FOUND",
    });
    expect(sendMock).toHaveBeenCalledTimes(2); // No retries on 404
  });

  it("rejects ChecksumSHA256 mismatches on both upload and download without retrying", async () => {
    const payload = Buffer.from("verified-bytes");
    const wrongB64 = sha256B64(Buffer.from("tampered-bytes"));

    const putMismatchClient: S3ClientLike = {
      send: vi.fn().mockResolvedValue({
        $metadata: { httpStatusCode: 200 },
        ChecksumSHA256: wrongB64,
      }),
    };
    const putAdapter = new AwsS3ObjectStorageAdapter(
      { bucket: "b", region: "us-east-1", maxRetries: 2, retryBaseDelayMs: 0 },
      putMismatchClient
    );

    await expect(
      putAdapter.putObject({
        key: "snapshots/k.snap",
        body: payload,
        checksumSha256Base64: sha256B64(payload),
        contentMd5Base64: md5B64(payload),
        ifNoneMatch: "*",
      })
    ).rejects.toThrow(SnapshotIntegrityError);
    expect(putMismatchClient.send).toHaveBeenCalledTimes(1);

    const getMismatchClient: S3ClientLike = {
      send: vi.fn().mockResolvedValue({
        $metadata: { httpStatusCode: 200 },
        ChecksumSHA256: wrongB64,
        Body: { transformToByteArray: async () => new Uint8Array(payload) },
      }),
    };
    const getAdapter = new AwsS3ObjectStorageAdapter(
      { bucket: "b", region: "us-east-1", maxRetries: 2, retryBaseDelayMs: 0 },
      getMismatchClient
    );

    await expect(getAdapter.getObject("snapshots/k.snap")).rejects.toThrow(SnapshotIntegrityError);
    expect(getMismatchClient.send).toHaveBeenCalledTimes(1);
  });

  it("paginates ListObjectsV2 across multiple continuation tokens", async () => {
    const d1 = new Date("2026-11-27T01:00:00Z");
    const d2 = new Date("2026-11-27T02:00:00Z");

    const sendMock = vi
      .fn()
      .mockResolvedValueOnce({
        IsTruncated: true,
        NextContinuationToken: "tok-page-2",
        Contents: [{ Key: "snapshots/a.snap", LastModified: d1 }],
      })
      .mockResolvedValueOnce({
        IsTruncated: false,
        Contents: [{ Key: "snapshots/b.snap", LastModified: d2 }],
      });

    const adapter = new AwsS3ObjectStorageAdapter(
      { bucket: "b", region: "us-east-1", retryBaseDelayMs: 0 },
      { send: sendMock }
    );

    const items = await adapter.listObjects("snapshots/");
    expect(items).toEqual([
      { key: "snapshots/a.snap", modifiedAtMs: d1.getTime() },
      { key: "snapshots/b.snap", modifiedAtMs: d2.getTime() },
    ]);
    expect(sendMock).toHaveBeenCalledTimes(2);
    const secondCmd = sendMock.mock.calls[1][0] as ListObjectsV2Command;
    expect(secondCmd.input.ContinuationToken).toBe("tok-page-2");
  });

  it("retries transient 429 and 503 failures within maxRetries and fails closed when exhausted", async () => {
    const err429 = Object.assign(new Error("SlowDown"), {
      name: "SlowDown",
      $metadata: { httpStatusCode: 429 },
    });
    const err503 = Object.assign(new Error("ServiceUnavailable"), {
      name: "ServiceUnavailable",
      $metadata: { httpStatusCode: 503 },
    });

    const recoveringMock = vi
      .fn()
      .mockRejectedValueOnce(err429)
      .mockRejectedValueOnce(err503)
      .mockResolvedValueOnce({ $metadata: { httpStatusCode: 204 } });

    const adapter = new AwsS3ObjectStorageAdapter(
      { bucket: "b", region: "us-east-1", maxRetries: 2, retryBaseDelayMs: 0 },
      { send: recoveringMock }
    );

    await expect(adapter.deleteObject("snapshots/retry-ok.snap")).resolves.toBeUndefined();
    expect(recoveringMock).toHaveBeenCalledTimes(3);

    const exhaustedMock = vi.fn().mockRejectedValue(err503);
    const exhaustedAdapter = new AwsS3ObjectStorageAdapter(
      { bucket: "b", region: "us-east-1", maxRetries: 1, retryBaseDelayMs: 0 },
      { send: exhaustedMock }
    );

    await expect(exhaustedAdapter.deleteObject("snapshots/retry-fail.snap")).rejects.toThrow(
      SnapshotError
    );
    expect(exhaustedMock).toHaveBeenCalledTimes(2);
  });

  it("does not retry 403 AccessDenied authorization errors", async () => {
    const err403 = Object.assign(new Error("Access Denied"), {
      name: "AccessDenied",
      $metadata: { httpStatusCode: 403 },
    });
    const sendMock = vi.fn().mockRejectedValue(err403);
    const adapter = new AwsS3ObjectStorageAdapter(
      { bucket: "b", region: "us-east-1", maxRetries: 3, retryBaseDelayMs: 0 },
      { send: sendMock }
    );

    await expect(adapter.getObject("snapshots/forbidden.snap")).rejects.toMatchObject({
      code: "STORAGE_ACCESS_DENIED",
    });
    expect(sendMock).toHaveBeenCalledTimes(1);
  });

  it("enforces per-attempt AbortController timeout on hung SDK requests", async () => {
    const sendMock = vi.fn((_cmd: unknown, opts?: { abortSignal?: AbortSignal }) => {
      return new Promise((_, reject) => {
        opts?.abortSignal?.addEventListener("abort", () => {
          const abortErr = Object.assign(new Error("Request aborted"), { name: "AbortError" });
          reject(abortErr);
        });
      });
    });

    const adapter = new AwsS3ObjectStorageAdapter(
      {
        bucket: "b",
        region: "us-east-1",
        requestTimeoutMs: 25,
        maxRetries: 1,
        retryBaseDelayMs: 0,
      },
      { send: sendMock as unknown as S3ClientLike["send"] }
    );

    await expect(adapter.getObject("snapshots/hung.snap")).rejects.toMatchObject({
      code: "STORAGE_TIMEOUT",
    });
    expect(sendMock).toHaveBeenCalledTimes(2);
  });

  it("rejects malformed or incomplete SDK responses", async () => {
    const missingBodyAdapter = new AwsS3ObjectStorageAdapter(
      { bucket: "b", region: "us-east-1", retryBaseDelayMs: 0 },
      { send: vi.fn().mockResolvedValue({ $metadata: { httpStatusCode: 200 } }) }
    );
    await expect(missingBodyAdapter.getObject("snapshots/empty.snap")).rejects.toMatchObject({
      code: "STORAGE_MALFORMED_RESPONSE",
    });

    const missingTokenAdapter = new AwsS3ObjectStorageAdapter(
      { bucket: "b", region: "us-east-1", retryBaseDelayMs: 0 },
      { send: vi.fn().mockResolvedValue({ IsTruncated: true, Contents: [] }) }
    );
    await expect(missingTokenAdapter.listObjects("snapshots/")).rejects.toMatchObject({
      code: "STORAGE_MALFORMED_RESPONSE",
    });

    const missingKeyAdapter = new AwsS3ObjectStorageAdapter(
      { bucket: "b", region: "us-east-1", retryBaseDelayMs: 0 },
      { send: vi.fn().mockResolvedValue({ IsTruncated: false, Contents: [{}] }) }
    );
    await expect(missingKeyAdapter.listObjects("snapshots/")).rejects.toMatchObject({
      code: "STORAGE_MALFORMED_RESPONSE",
    });
  });

  it("fails closed on conditional-write ambiguity when first PutObject commits, response is lost, and retry gets 412", async () => {
    const mockStore = new Map<string, Buffer>();
    const commandNames: string[] = [];
    let putAttempts = 0;

    const client: S3ClientLike = {
      send: vi.fn(async (cmd: unknown) => {
        const name = (cmd as { constructor: { name: string } }).constructor.name;
        commandNames.push(name);
        if (cmd instanceof PutObjectCommand) {
          putAttempts += 1;
          const key = cmd.input.Key!;
          expect(cmd.input.IfNoneMatch).toBe("*");

          if (putAttempts === 1) {
            // S3 commits the object, but the response is lost on the wire.
            mockStore.set(key, Buffer.from(cmd.input.Body as Uint8Array));
            throw Object.assign(new Error("socket hang up"), { code: "ECONNRESET" });
          }

          if (mockStore.has(key)) {
            throw Object.assign(new Error("At least one pre-condition you specified did not hold"), {
              name: "PreconditionFailed",
              $metadata: { httpStatusCode: 412 },
            });
          }
        }
        throw new Error(`Unexpected command: ${name}`);
      }),
    };

    const adapter = new AwsS3ObjectStorageAdapter(
      { bucket: "ambiguous-bucket", region: "us-east-1", maxRetries: 2, retryBaseDelayMs: 0 },
      client
    );
    const backend = new S3SnapshotStorageBackend("ambiguous-bucket", adapter);
    const uri = backend.buildUri("c1", "ep1", "snap-ambiguous");

    const payload = Buffer.from("snapshot-ambiguous-payload");
    const err = await backend
      .putAndVerify(uri, payload, sha256Hex(payload))
      .catch((e: unknown) => e);

    expect(putAttempts).toBe(2);
    expect(commandNames).toEqual(["PutObjectCommand", "PutObjectCommand"]);
    expect(err).toBeInstanceOf(SnapshotCollisionError);
    // The error reports the collision/precondition failure without claiming another writer created it.
    expect((err as Error).message).not.toMatch(/another writer/i);
    // Object from attempt 1 is present in S3, proving the ambiguous commit-then-412 outcome.
    expect(mockStore.get("snapshots/c1/ep1/snap-ambiguous.snap")?.equals(payload)).toBe(true);
  });

  it("reads an AsyncIterable GetObject Body stream and verifies checksum", async () => {
    const part1 = Buffer.from("async-iterable-part-1-");
    const part2 = Uint8Array.from(Buffer.from("part-2"));
    const fullPayload = Buffer.concat([part1, part2]);

    const client: S3ClientLike = {
      send: vi.fn(async (cmd: unknown) => {
        if (cmd instanceof GetObjectCommand) {
          return {
            $metadata: { httpStatusCode: 200 },
            ChecksumSHA256: sha256B64(fullPayload),
            ETag: '"etag-async-iter"',
            Body: {
              async *[Symbol.asyncIterator]() {
                yield part1;
                yield part2;
              },
            },
          };
        }
        throw new Error("Unexpected command");
      }),
    };

    const adapter = new AwsS3ObjectStorageAdapter(
      { bucket: "b", region: "us-east-1", retryBaseDelayMs: 0 },
      client
    );
    const backend = new S3SnapshotStorageBackend("b", adapter);
    const uri = backend.buildUri("c1", "ep1", "stream");
    const result = await backend.get(uri);

    expect(result.equals(fullPayload)).toBe(true);
  });

  it("classifies ECONNRESET and ETIMEDOUT as retryable with bounded retries and STORAGE_REQUEST_FAILED on exhaustion", async () => {
    let attempts = 0;
    const recoveryClient: S3ClientLike = {
      send: vi.fn(async () => {
        attempts += 1;
        if (attempts === 1) {
          throw Object.assign(new Error("read ECONNRESET"), { code: "ECONNRESET" });
        }
        if (attempts === 2) {
          throw Object.assign(new Error("connect ETIMEDOUT"), { code: "ETIMEDOUT" });
        }
        return {
          $metadata: { httpStatusCode: 200 },
          Body: Buffer.from("recovered"),
        };
      }),
    };

    const recoveringAdapter = new AwsS3ObjectStorageAdapter(
      { bucket: "b", region: "us-east-1", maxRetries: 2, retryBaseDelayMs: 0 },
      recoveryClient
    );
    const recovered = await recoveringAdapter.getObject("snapshots/retry.snap");
    expect(attempts).toBe(3);
    expect(recovered.toString("utf8")).toBe("recovered");

    for (const code of ["ECONNRESET", "ETIMEDOUT"] as const) {
      let failAttempts = 0;
      const failingClient: S3ClientLike = {
        send: vi.fn(async () => {
          failAttempts += 1;
          throw Object.assign(new Error(`network ${code}`), { code });
        }),
      };

      const failingAdapter = new AwsS3ObjectStorageAdapter(
        { bucket: "b", region: "us-east-1", maxRetries: 1, retryBaseDelayMs: 0 },
        failingClient
      );

      await expect(failingAdapter.getObject("snapshots/fail.snap")).rejects.toMatchObject({
        name: "SnapshotError",
        code: "STORAGE_REQUEST_FAILED",
      });
      expect(failAttempts).toBe(2);
    }
  });

  it("clears timeout timers on completion and aborts the AbortSignal on timeout", async () => {
    const clearTimeoutSpy = vi.spyOn(globalThis, "clearTimeout");
    try {
      const okSignals: AbortSignal[] = [];
      const okClient: S3ClientLike = {
        send: vi.fn(async (_cmd: unknown, options?: { abortSignal?: AbortSignal }) => {
          if (options?.abortSignal) {
            okSignals.push(options.abortSignal);
          }
          return {
            $metadata: { httpStatusCode: 200 },
            Body: Buffer.from("ok"),
          };
        }) as unknown as S3ClientLike["send"],
      };

      const okAdapter = new AwsS3ObjectStorageAdapter(
        { bucket: "b", region: "us-east-1", requestTimeoutMs: 5000, maxRetries: 0 },
        okClient
      );
      await okAdapter.getObject("snapshots/ok.snap");
      expect(okSignals).toHaveLength(1);
      expect(okSignals[0]!.aborted).toBe(false);
      expect(clearTimeoutSpy).toHaveBeenCalled();

      clearTimeoutSpy.mockClear();
      const timeoutSignals: AbortSignal[] = [];
      const hangingClient: S3ClientLike = {
        send: vi.fn(
          (_cmd: unknown, options?: { abortSignal?: AbortSignal }) =>
            new Promise((_resolve, reject) => {
              const signal = options?.abortSignal;
              if (signal) {
                timeoutSignals.push(signal);
                signal.addEventListener("abort", () => {
                  reject(Object.assign(new Error("Request aborted"), { name: "AbortError" }));
                });
              }
            })
        ) as unknown as S3ClientLike["send"],
      };

      const timeoutAdapter = new AwsS3ObjectStorageAdapter(
        { bucket: "b", region: "us-east-1", requestTimeoutMs: 20, maxRetries: 0 },
        hangingClient
      );
      await expect(timeoutAdapter.getObject("snapshots/hang.snap")).rejects.toMatchObject({
        name: "SnapshotError",
        code: "STORAGE_TIMEOUT",
      });
      expect(timeoutSignals).toHaveLength(1);
      expect(timeoutSignals[0]!.aborted).toBe(true);
      expect(clearTimeoutSpy).toHaveBeenCalled();
    } finally {
      clearTimeoutSpy.mockRestore();
    }
  });

  it("completes normal async stream consumption and cleans up abort listeners", async () => {
    const chunks = [Buffer.from("stream-a-"), Buffer.from("stream-b")];
    const expected = Buffer.concat(chunks);
    const seenSignals: AbortSignal[] = [];
    const addedListeners = new Map<AbortSignal, EventListenerOrEventListenerObject[]>();
    const removedListeners = new Map<AbortSignal, EventListenerOrEventListenerObject[]>();

    const addSpy = vi.spyOn(AbortSignal.prototype, "addEventListener").mockImplementation(function (
      this: AbortSignal,
      type: string,
      listener: EventListenerOrEventListenerObject | null,
      options?: boolean | AddEventListenerOptions
    ) {
      if (type === "abort" && listener) {
        const list = addedListeners.get(this) ?? [];
        list.push(listener);
        addedListeners.set(this, list);
      }
      return EventTarget.prototype.addEventListener.call(this, type, listener, options);
    });
    const removeSpy = vi.spyOn(AbortSignal.prototype, "removeEventListener").mockImplementation(
      function (
        this: AbortSignal,
        type: string,
        listener: EventListenerOrEventListenerObject | null,
        options?: boolean | EventListenerOptions
      ) {
        if (type === "abort" && listener) {
          const list = removedListeners.get(this) ?? [];
          list.push(listener);
          removedListeners.set(this, list);
        }
        return EventTarget.prototype.removeEventListener.call(this, type, listener, options);
      }
    );

    try {
      const client: S3ClientLike = {
        send: vi.fn(async (_cmd: unknown, options?: { abortSignal?: AbortSignal }) => {
          if (options?.abortSignal) {
            seenSignals.push(options.abortSignal);
          }
          return {
            $metadata: { httpStatusCode: 200 },
            ChecksumSHA256: sha256B64(expected),
            Body: {
              async *[Symbol.asyncIterator]() {
                for (const c of chunks) {
                  await new Promise((r) => setTimeout(r, 5));
                  yield c;
                }
              },
            },
          };
        }) as unknown as S3ClientLike["send"],
      };

      const adapter = new AwsS3ObjectStorageAdapter(
        { bucket: "b", region: "us-east-1", requestTimeoutMs: 500, maxRetries: 1, retryBaseDelayMs: 0 },
        client
      );
      const data = await adapter.getObject("snapshots/async-ok.snap");
      expect(data.equals(expected)).toBe(true);
      expect(seenSignals).toHaveLength(1);
      const signal = seenSignals[0]!;
      expect(signal.aborted).toBe(false);
      const added = addedListeners.get(signal) ?? [];
      const removed = removedListeners.get(signal) ?? [];
      expect(added.length).toBe(chunks.length + 1);
      expect(removed).toEqual(added);
    } finally {
      addSpy.mockRestore();
      removeSpy.mockRestore();
    }
  });

  it("rejects stream stalled after headers with STORAGE_TIMEOUT and does not retry partially consumed stream", async () => {
    const destroySpy = vi.fn();
    let sendCalls = 0;

    const client: S3ClientLike = {
      send: vi.fn(async () => {
        sendCalls += 1;
        return {
          $metadata: { httpStatusCode: 200 },
          Body: {
            destroy: destroySpy,
            transformToByteArray: () => new Promise<Uint8Array>(() => {}),
          },
        };
      }) as unknown as S3ClientLike["send"],
    };

    const adapter = new AwsS3ObjectStorageAdapter(
      { bucket: "b", region: "us-east-1", requestTimeoutMs: 25, maxRetries: 2, retryBaseDelayMs: 0 },
      client
    );

    await expect(adapter.getObject("snapshots/stalled-headers.snap")).rejects.toMatchObject({
      name: "SnapshotError",
      code: "STORAGE_TIMEOUT",
    });
    expect(sendCalls).toBe(1);
    expect(destroySpy).toHaveBeenCalledTimes(1);
  });

  it("times out during AsyncIterable body consumption, invokes iterator.return(), and cleans up timers", async () => {
    const clearTimeoutSpy = vi.spyOn(globalThis, "clearTimeout");
    const returnSpy = vi.fn(async () => ({ value: undefined, done: true as const }));
    const destroySpy = vi.fn();
    let sendCalls = 0;

    try {
      const client: S3ClientLike = {
        send: vi.fn(async () => {
          sendCalls += 1;
          let yielded = false;
          return {
            $metadata: { httpStatusCode: 200 },
            Body: {
              destroy: destroySpy,
              [Symbol.asyncIterator]() {
                return {
                  next: () => {
                    if (!yielded) {
                      yielded = true;
                      return Promise.resolve({ value: Buffer.from("partial-"), done: false });
                    }
                    return new Promise<IteratorResult<Buffer>>(() => {});
                  },
                  return: returnSpy,
                };
              },
            },
          };
        }) as unknown as S3ClientLike["send"],
      };

      const adapter = new AwsS3ObjectStorageAdapter(
        { bucket: "b", region: "us-east-1", requestTimeoutMs: 30, maxRetries: 2, retryBaseDelayMs: 0 },
        client
      );

      await expect(adapter.getObject("snapshots/mid-stream-stall.snap")).rejects.toMatchObject({
        name: "SnapshotError",
        code: "STORAGE_TIMEOUT",
      });
      expect(sendCalls).toBe(1);
      expect(destroySpy).toHaveBeenCalledTimes(1);
      expect(returnSpy).toHaveBeenCalledTimes(1);
      expect(clearTimeoutSpy).toHaveBeenCalled();
    } finally {
      clearTimeoutSpy.mockRestore();
    }
  });

  it("rejects checksum mismatch after streaming without retrying", async () => {
    const payload = Buffer.from("streamed-corrupted-body");
    let sendCalls = 0;

    const client: S3ClientLike = {
      send: vi.fn(async () => {
        sendCalls += 1;
        return {
          $metadata: { httpStatusCode: 200 },
          ChecksumSHA256: sha256B64(Buffer.from("different-payload")),
          Body: {
            async *[Symbol.asyncIterator]() {
              yield payload.subarray(0, 8);
              yield payload.subarray(8);
            },
          },
        };
      }) as unknown as S3ClientLike["send"],
    };

    const adapter = new AwsS3ObjectStorageAdapter(
      { bucket: "b", region: "us-east-1", maxRetries: 2, retryBaseDelayMs: 0 },
      client
    );

    await expect(adapter.getObject("snapshots/bad-stream-sha.snap")).rejects.toThrow(
      SnapshotIntegrityError
    );
    expect(sendCalls).toBe(1);
  });

  it("rejects malformed stream chunks and cleans up iterator and abort listeners", async () => {
    const returnSpy = vi.fn(async () => ({ value: undefined, done: true as const }));
    const seenSignals: AbortSignal[] = [];
    const addedListeners = new Map<AbortSignal, EventListenerOrEventListenerObject[]>();
    const removedListeners = new Map<AbortSignal, EventListenerOrEventListenerObject[]>();

    const addSpy = vi.spyOn(AbortSignal.prototype, "addEventListener").mockImplementation(function (
      this: AbortSignal,
      type: string,
      listener: EventListenerOrEventListenerObject | null,
      options?: boolean | AddEventListenerOptions
    ) {
      if (type === "abort" && listener) {
        const list = addedListeners.get(this) ?? [];
        list.push(listener);
        addedListeners.set(this, list);
      }
      return EventTarget.prototype.addEventListener.call(this, type, listener, options);
    });
    const removeSpy = vi.spyOn(AbortSignal.prototype, "removeEventListener").mockImplementation(
      function (
        this: AbortSignal,
        type: string,
        listener: EventListenerOrEventListenerObject | null,
        options?: boolean | EventListenerOptions
      ) {
        if (type === "abort" && listener) {
          const list = removedListeners.get(this) ?? [];
          list.push(listener);
          removedListeners.set(this, list);
        }
        return EventTarget.prototype.removeEventListener.call(this, type, listener, options);
      }
    );

    try {
      const client: S3ClientLike = {
        send: vi.fn(async (_cmd: unknown, options?: { abortSignal?: AbortSignal }) => {
          if (options?.abortSignal) {
            seenSignals.push(options.abortSignal);
          }
          return {
            $metadata: { httpStatusCode: 200 },
            Body: {
              [Symbol.asyncIterator]() {
                return {
                  next: async () => ({ value: { invalidChunk: true } as unknown, done: false }),
                  return: returnSpy,
                };
              },
            },
          };
        }) as unknown as S3ClientLike["send"],
      };

      const adapter = new AwsS3ObjectStorageAdapter(
        { bucket: "b", region: "us-east-1", maxRetries: 2, retryBaseDelayMs: 0 },
        client
      );

      await expect(adapter.getObject("snapshots/malformed-chunk.snap")).rejects.toMatchObject({
        name: "SnapshotError",
        code: "STORAGE_MALFORMED_RESPONSE",
      });
      expect(returnSpy).toHaveBeenCalledTimes(1);
      expect(seenSignals).toHaveLength(1);
      const signal = seenSignals[0]!;
      expect(removedListeners.get(signal)).toEqual(addedListeners.get(signal));
    } finally {
      addSpy.mockRestore();
      removeSpy.mockRestore();
    }
  });

  it("does not emit unhandledRejection when losing transformToByteArray or AsyncIterable rejects after timeout", async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason);
    };
    process.on("unhandledRejection", onUnhandled);

    const seenSignals: AbortSignal[] = [];
    const addedListeners = new Map<AbortSignal, EventListenerOrEventListenerObject[]>();
    const removedListeners = new Map<AbortSignal, EventListenerOrEventListenerObject[]>();
    const addSpy = vi.spyOn(AbortSignal.prototype, "addEventListener").mockImplementation(function (
      this: AbortSignal,
      type: string,
      listener: EventListenerOrEventListenerObject | null,
      options?: boolean | AddEventListenerOptions
    ) {
      if (type === "abort" && listener) {
        const list = addedListeners.get(this) ?? [];
        list.push(listener);
        addedListeners.set(this, list);
      }
      return EventTarget.prototype.addEventListener.call(this, type, listener, options);
    });
    const removeSpy = vi.spyOn(AbortSignal.prototype, "removeEventListener").mockImplementation(
      function (
        this: AbortSignal,
        type: string,
        listener: EventListenerOrEventListenerObject | null,
        options?: boolean | EventListenerOptions
      ) {
        if (type === "abort" && listener) {
          const list = removedListeners.get(this) ?? [];
          list.push(listener);
          removedListeners.set(this, list);
        }
        return EventTarget.prototype.removeEventListener.call(this, type, listener, options);
      }
    );

    try {
      // Case 1: transformToByteArray rejects asynchronously after destroy()
      const client1: S3ClientLike = {
        send: vi.fn(async (_cmd: unknown, options?: { abortSignal?: AbortSignal }) => {
          if (options?.abortSignal) seenSignals.push(options.abortSignal);
          let rejectPending!: (err: Error) => void;
          return {
            $metadata: { httpStatusCode: 200 },
            Body: {
              destroy: (err?: Error) => {
                setTimeout(() => rejectPending(err ?? new Error("destroyed")), 5);
              },
              transformToByteArray: () =>
                new Promise<Uint8Array>((_resolve, reject) => {
                  rejectPending = reject;
                }),
            },
          };
        }) as unknown as S3ClientLike["send"],
      };

      const adapter1 = new AwsS3ObjectStorageAdapter(
        { bucket: "b", region: "us-east-1", requestTimeoutMs: 20, maxRetries: 0 },
        client1
      );
      await expect(adapter1.getObject("snapshots/post-abort-reject-1.snap")).rejects.toMatchObject({
        code: "STORAGE_TIMEOUT",
      });

      // Case 2: AsyncIterable iterator.next() rejects asynchronously after destroy()/return()
      const client2: S3ClientLike = {
        send: vi.fn(async (_cmd: unknown, options?: { abortSignal?: AbortSignal }) => {
          if (options?.abortSignal) seenSignals.push(options.abortSignal);
          let rejectNext!: (err: Error) => void;
          return {
            $metadata: { httpStatusCode: 200 },
            Body: {
              destroy: (err?: Error) => {
                setTimeout(() => rejectNext(err ?? new Error("iterator destroyed")), 5);
              },
              [Symbol.asyncIterator]() {
                return {
                  next: () =>
                    new Promise<IteratorResult<Buffer>>((_resolve, reject) => {
                      rejectNext = reject;
                    }),
                  return: async () => ({ value: undefined, done: true as const }),
                };
              },
            },
          };
        }) as unknown as S3ClientLike["send"],
      };

      const adapter2 = new AwsS3ObjectStorageAdapter(
        { bucket: "b", region: "us-east-1", requestTimeoutMs: 20, maxRetries: 0 },
        client2
      );
      await expect(adapter2.getObject("snapshots/post-abort-reject-2.snap")).rejects.toMatchObject({
        code: "STORAGE_TIMEOUT",
      });

      // Allow delayed post-abort rejections to flush through microtask/macrotask queues
      await new Promise((r) => setTimeout(r, 30));
      expect(unhandled).toEqual([]);
      expect(seenSignals).toHaveLength(2);
      for (const sig of seenSignals) {
        expect(removedListeners.get(sig)).toEqual(addedListeners.get(sig));
      }
    } finally {
      process.off("unhandledRejection", onUnhandled);
      addSpy.mockRestore();
      removeSpy.mockRestore();
    }
  });

  it("rejects caller-supplied static credentials and preserves default SDK provider-chain + clientOverride", async () => {
    const fakeSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const unsafeConfig: AwsS3AdapterConfig = {
      bucket: "b",
      region: "us-east-1",
      // @ts-expect-error AwsS3AdapterConfig must not accept static credentials overrides
      credentials: { accessKeyId: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: fakeSecret },
    };

    let thrownMessage = "";
    try {
      new AwsS3ObjectStorageAdapter(unsafeConfig);
    } catch (err) {
      expect(err).toBeInstanceOf(SnapshotError);
      expect((err as SnapshotError).code).toBe("INVALID_CONFIGURATION");
      thrownMessage = (err as Error).message;
    }
    expect(thrownMessage).toContain("default credential provider chain");
    expect(thrownMessage).not.toContain(fakeSecret);
    expect(thrownMessage).not.toContain("AKIAIOSFODNN7EXAMPLE");

    // Normal SDK provider-chain construction (no credentials field, no clientOverride) remains supported
    const defaultChainAdapter = new AwsS3ObjectStorageAdapter({
      bucket: "b",
      region: "us-east-1",
      endpoint: "http://127.0.0.1:9",
      forcePathStyle: true,
    });
    expect(defaultChainAdapter).toBeInstanceOf(AwsS3ObjectStorageAdapter);

    // clientOverride remains functional
    const sendMock = vi.fn(async () => ({ $metadata: { httpStatusCode: 200 } }));
    const overrideAdapter = new AwsS3ObjectStorageAdapter(
      { bucket: "b", region: "us-east-1" },
      { send: sendMock as unknown as S3ClientLike["send"] }
    );
    await overrideAdapter.deleteObject("snapshots/cred-check.snap");
    expect(sendMock).toHaveBeenCalledTimes(1);
  });
});
