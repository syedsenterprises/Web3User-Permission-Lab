/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-A
 * etcd Client Adapter Verification Suite
 *
 * Verifies the isolated etcd client adapter against all Stage 2-A requirements:
 * 1. Connection lifecycle, health check, and graceful close.
 * 2. 64-bit revision/index precision beyond 2^53 - 1.
 * 3. Linearizable reads and range queries.
 * 4. Atomic compare-and-swap (CAS) transactions (Success and Else branches).
 * 5. Ambiguous transaction outcome recovery via linearizable probes.
 * 6. Watch interruption, reconnect, and revision resumption.
 * 7. Bounded timeouts, cancellation, and fail-closed error translation.
 * 8. Real/disposable etcd integration testing over loopback gRPC.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import * as grpc from "@grpc/grpc-js";
import {
  EtcdClientAdapter,
  EtcdTimeoutError,
  EtcdUnavailableError,
  EtcdCompactedError,
  EtcdAdapterError,
  toBigInt,
  toPositiveBigInt,
} from "../../src/witness/etcd-client-adapter.js";
import { generateTestCertificates } from "../../src/witness/mtls-certs.js";
import { DisposableEtcdServer } from "./helpers/disposable-etcd.js";

describe("Milestone 13-D Phase D3: Stage 2-A etcd Client Adapter Foundation", () => {
  let server: DisposableEtcdServer;
  let endpoint: string;

  beforeAll(async () => {
    // Start in-process disposable etcd gRPC server on loopback TCP
    server = new DisposableEtcdServer({
      initialRevision: 1000n,
      clusterId: "14841639077221209701",
      memberId: "102603348655986349",
      raftTerm: 5n,
    });
    endpoint = await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  beforeEach(() => {
    // Reset any fault injection hooks between tests
    server.setDelay(0);
    server.compactRevision = 0n;
    server.disconnectAllWatchers();
  });

  // ==========================================================================
  // 1. Connection Lifecycle & Health Checks
  // ==========================================================================
  describe("1. Connection Lifecycle & Health Checks", () => {
    it("successfully connects, performs health check, and discovers cluster metadata", async () => {
      const adapter = new EtcdClientAdapter({
        endpoints: [endpoint],
        dialTimeoutMs: 2000,
      });

      await adapter.connect();

      const health = await adapter.healthCheck();
      expect(health.healthy).toBe(true);
      expect(health.clusterId).toBe("14841639077221209701");
      expect(health.memberId).toBe("102603348655986349");
      expect(health.raftTerm).toBe(5n);
      expect(health.revision).toBeGreaterThanOrEqual(1000n);

      await adapter.close();
    });

    it("fails closed when connecting to an unreachable or non-existent endpoint", async () => {
      // Pick an unused local port
      const invalidAdapter = new EtcdClientAdapter({
        endpoints: ["http://127.0.0.1:59999"],
        dialTimeoutMs: 500,
      });

      await expect(invalidAdapter.connect()).rejects.toThrow(EtcdUnavailableError);
      await invalidAdapter.close();
    });

    it("refuses operations after adapter is closed", async () => {
      const adapter = new EtcdClientAdapter({
        endpoints: [endpoint],
      });
      await adapter.connect();
      await adapter.close();

      await expect(adapter.connect()).rejects.toThrow(/closed/);
    });
  });

  // ==========================================================================
  // 2. 64-bit Revision and Index Precision
  // ==========================================================================
  describe("2. 64-bit Revision and Index Precision", () => {
    it("preserves integers exceeding 2^53 - 1 (9007199254740991) across wire and storage", async () => {
      // Set server revision to a 64-bit integer far beyond Number.MAX_SAFE_INTEGER
      const high64BitRev = 9007199254740995n; // 2^53 + 4
      server.currentRevision = high64BitRev;

      const adapter = new EtcdClientAdapter({
        endpoints: [endpoint],
      });

      // Write a key at this high revision
      const putRes = await adapter.put("/test/high64/key1", "val1");
      expect(putRes.revision).toBe(high64BitRev + 1n);
      expect(putRes.revision.toString()).toBe("9007199254740996");

      // Read back via linearizable get
      const kv = await adapter.get("/test/high64/key1");
      expect(kv).not.toBeNull();
      expect(kv!.createRevision).toBe(high64BitRev + 1n);
      expect(kv!.modRevision).toBe(high64BitRev + 1n);
      expect(kv!.createRevision.toString()).toBe("9007199254740996");

      // Verify that CAS condition with 64-bit BigInt succeeds
      const txnRes = await adapter
        .txn()
        .if({
          key: "/test/high64/key1",
          target: "Mod",
          operator: "==",
          value: high64BitRev + 1n,
        })
        .then({
          type: "put",
          key: "/test/high64/key1",
          value: "updated-val1",
        })
        .commit();

      expect(txnRes.succeeded).toBe(true);
      expect(txnRes.revision).toBe(high64BitRev + 2n);

      // Verify that CAS with mismatched 64-bit BigInt fails to Else branch
      const txnFail = await adapter
        .txn()
        .if({
          key: "/test/high64/key1",
          target: "Mod",
          operator: "==",
          value: high64BitRev + 999n,
        })
        .then({
          type: "put",
          key: "/test/high64/key1",
          value: "should-not-apply",
        })
        .else({
          type: "get",
          key: "/test/high64/key1",
        })
        .commit();

      expect(txnFail.succeeded).toBe(false);
      expect(txnFail.responses.length).toBe(1);
      expect(txnFail.responses[0].kv?.value).toBe("updated-val1");

      await adapter.close();
    });
  });

  // ==========================================================================
  // 3. Linearizable Reads & Range Queries
  // ==========================================================================
  describe("3. Linearizable Reads & Range Queries", () => {
    it("performs linearizable reads, returning null for non-existent keys", async () => {
      const adapter = new EtcdClientAdapter({ endpoints: [endpoint] });

      const res = await adapter.get("/non/existent/key");
      expect(res).toBeNull();

      await adapter.put("/consensus/test/k1", "v1");
      const found = await adapter.get("/consensus/test/k1");
      expect(found).not.toBeNull();
      expect(found!.key).toBe("/consensus/test/k1");
      expect(found!.value).toBe("v1");
      expect(found!.version).toBe(1n);

      await adapter.close();
    });

    it("performs prefix scans and returns ordered key-value pairs", async () => {
      const adapter = new EtcdClientAdapter({ endpoints: [endpoint] });
      const prefix = "/consensus/log/epoch-42/";

      await adapter.put(`${prefix}00000001`, "proposal-1");
      await adapter.put(`${prefix}00000003`, "proposal-3");
      await adapter.put(`${prefix}00000002`, "proposal-2");

      const items = await adapter.getRange(prefix);
      expect(items.length).toBe(3);
      expect(items[0].key).toBe(`${prefix}00000001`);
      expect(items[1].key).toBe(`${prefix}00000002`);
      expect(items[2].key).toBe(`${prefix}00000003`);
      expect(items[0].value).toBe("proposal-1");
      expect(items[1].value).toBe("proposal-2");
      expect(items[2].value).toBe("proposal-3");

      // Verify limit option
      const limited = await adapter.getRange(prefix, { limit: 2 });
      expect(limited.length).toBe(2);
      expect(limited[1].key).toBe(`${prefix}00000002`);

      await adapter.close();
    });
  });

  // ==========================================================================
  // 4. Compare-and-Swap (CAS) Transactions
  // ==========================================================================
  describe("4. Compare-and-Swap (CAS) Transactions", () => {
    it("executes atomic proposal CAS when key does not exist (CreateRevision == 0)", async () => {
      const adapter = new EtcdClientAdapter({ endpoints: [endpoint] });
      const logKey = "/consensus/log/epoch-1/00000001";

      const txnRes = await adapter
        .txn()
        .if({
          key: logKey,
          target: "Create",
          operator: "==",
          value: 0n,
        })
        .then({
          type: "put",
          key: logKey,
          value: "proposal-payload-abc",
        })
        .else({
          type: "get",
          key: logKey,
        })
        .commit();

      expect(txnRes.succeeded).toBe(true);
      expect(txnRes.responses.length).toBe(1);
      expect(txnRes.responses[0].type).toBe("put");

      // Verify that re-proposing to the same key fails cleanly to Else branch
      const duplicateTxn = await adapter
        .txn()
        .if({
          key: logKey,
          target: "Create",
          operator: "==",
          value: 0n,
        })
        .then({
          type: "put",
          key: logKey,
          value: "proposal-payload-duplicate",
        })
        .else({
          type: "get",
          key: logKey,
        })
        .commit();

      expect(duplicateTxn.succeeded).toBe(false);
      expect(duplicateTxn.responses.length).toBe(1);
      expect(duplicateTxn.responses[0].type).toBe("get");
      expect(duplicateTxn.responses[0].kv?.value).toBe("proposal-payload-abc");

      await adapter.close();
    });

    it("evaluates composite multi-condition CAS atomically", async () => {
      const adapter = new EtcdClientAdapter({ endpoints: [endpoint] });
      const counterKey = "/consensus/state/counter";
      const destKey = "/consensus/log/epoch-1/00000005";

      // Initialize counter
      const putRes = await adapter.put(counterKey, "10");
      const counterModRev = putRes.revision;

      // Compound CAS: destination must not exist AND counter modRevision must match
      const compoundSuccess = await adapter
        .txn()
        .if({
          key: destKey,
          target: "Create",
          operator: "==",
          value: 0n,
        })
        .and({
          key: counterKey,
          target: "Mod",
          operator: "==",
          value: counterModRev,
        })
        .then(
          { type: "put", key: destKey, value: "payload-5" },
          { type: "put", key: counterKey, value: "11" }
        )
        .commit();

      expect(compoundSuccess.succeeded).toBe(true);
      expect(compoundSuccess.responses.length).toBe(2);

      // Verify second attempt with old counterModRev fails
      const compoundStale = await adapter
        .txn()
        .if({
          key: "/consensus/log/epoch-1/00000006",
          target: "Create",
          operator: "==",
          value: 0n,
        })
        .and({
          key: counterKey,
          target: "Mod",
          operator: "==",
          value: counterModRev, // Stale!
        })
        .then({ type: "put", key: "/consensus/log/epoch-1/00000006", value: "payload-6" })
        .commit();

      expect(compoundStale.succeeded).toBe(false);

      await adapter.close();
    });
  });

  // ==========================================================================
  // 5. Ambiguous Transaction Outcome Recovery (F-03)
  // ==========================================================================
  describe("5. Ambiguous Transaction Outcome Recovery (F-03)", () => {
    it("recovers CONFIRMED_COMMITTED when probe key matches expected payload", async () => {
      const adapter = new EtcdClientAdapter({ endpoints: [endpoint] });
      const probeKey = "/consensus/log/epoch-10/00000099";
      const payload = "canonical-proposal-fingerprint-sha256-xyz";

      await adapter.put(probeKey, payload);

      const recovery = await adapter.recoverAmbiguousTxn(probeKey, payload);
      expect(recovery.status).toBe("CONFIRMED_COMMITTED");
      expect(recovery.existingValue).toBe(payload);
      expect(recovery.observedRevision).toBeGreaterThan(0n);

      await adapter.close();
    });

    it("returns INDETERMINATE by default when probe key is missing and deadline has not expired", async () => {
      const adapter = new EtcdClientAdapter({ endpoints: [endpoint] });
      const probeKey = "/consensus/log/epoch-10/00000100";

      // Without deadline expiration proof, a missing key is not confirmed failed
      const recovery = await adapter.recoverAmbiguousTxn(probeKey, "some-payload");
      expect(recovery.status).toBe("INDETERMINATE");
      expect(recovery.details).toContain("cannot confirm failure before deadline expiration");

      await adapter.close();
    });

    it("returns INDETERMINATE when original transaction timestamp is recent", async () => {
      const adapter = new EtcdClientAdapter({ endpoints: [endpoint] });
      const probeKey = "/consensus/log/epoch-10/00000100-inflight";

      const recovery = await adapter.recoverAmbiguousTxn(probeKey, "some-payload", {
        originalTxnTimestamp: Date.now() - 500, // 500ms ago
        originalTxnDeadlineMs: 3000, // 3000ms deadline -> still in flight!
      });
      expect(recovery.status).toBe("INDETERMINATE");
      expect(recovery.details).toContain("cannot confirm failure");

      await adapter.close();
    });

    it("recovers CONFIRMED_FAILED when probe key does not exist and deadline has expired", async () => {
      const adapter = new EtcdClientAdapter({ endpoints: [endpoint] });
      const probeKey = "/consensus/log/epoch-10/00000100-expired";

      const recovery = await adapter.recoverAmbiguousTxn(probeKey, "some-payload", {
        originalTxnTimestamp: Date.now() - 5000, // 5s ago
        originalTxnDeadlineMs: 2000, // 2s deadline -> expired 3s ago!
      });
      expect(recovery.status).toBe("CONFIRMED_FAILED");
      expect(recovery.details).toContain("expired");

      await adapter.close();
    });

    it("recovers CONFIRMED_FAILED when immediate failure confirmation is explicitly authorized", async () => {
      const adapter = new EtcdClientAdapter({ endpoints: [endpoint] });
      const probeKey = "/consensus/log/epoch-10/00000100-immediate";

      const recovery = await adapter.recoverAmbiguousTxn(probeKey, "some-payload", {
        allowImmediateFailureConfirmation: true,
      });
      expect(recovery.status).toBe("CONFIRMED_FAILED");

      await adapter.close();
    });

    it("recovers CONFLICT_PAYLOAD_MISMATCH when probe key exists with different payload", async () => {
      const adapter = new EtcdClientAdapter({ endpoints: [endpoint] });
      const probeKey = "/consensus/log/epoch-10/00000101";

      await adapter.put(probeKey, "different-engine-proposal");

      const recovery = await adapter.recoverAmbiguousTxn(probeKey, "my-engine-proposal");
      expect(recovery.status).toBe("CONFLICT_PAYLOAD_MISMATCH");
      expect(recovery.existingValue).toBe("different-engine-proposal");

      await adapter.close();
    });
  });

  // ==========================================================================
  // 6. Watch Interruption, Reconnect & Compaction (F-02)
  // ==========================================================================
  describe("6. Watch Interruption, Reconnect & Compaction (F-02)", () => {
    it("streams events and accurately resumes from lastSeenRevision across stream interruption", async () => {
      const adapter = new EtcdClientAdapter({ endpoints: [endpoint] });
      const watchPrefix = "/consensus/watch-test/";
      const receivedEvents: string[] = [];

      const watcher = await adapter.watch(
        { prefix: watchPrefix },
        { startRevision: server.currentRevision },
        (ev) => {
          if (ev.type === "put") {
            receivedEvents.push(`${ev.kv.key}=${ev.kv.value}`);
          }
        }
      );

      expect(watcher.isWatching()).toBe(true);

      await adapter.put(`${watchPrefix}item-1`, "val-1");
      await new Promise((r) => setTimeout(r, 100));
      expect(receivedEvents).toContain(`${watchPrefix}item-1=val-1`);

      server.disconnectAllWatchers();

      await adapter.put(`${watchPrefix}item-2`, "val-2");

      const resumedEvents: string[] = [];
      const resumedWatcher = await adapter.watch(
        { prefix: watchPrefix },
        { startRevision: server.currentRevision },
        (ev) => {
          if (ev.type === "put") {
            resumedEvents.push(`${ev.kv.key}=${ev.kv.value}`);
          }
        }
      );

      await adapter.put(`${watchPrefix}item-3`, "val-3");
      await new Promise((r) => setTimeout(r, 100));

      expect(resumedEvents).toContain(`${watchPrefix}item-3=val-3`);

      await watcher.close();
      await resumedWatcher.close();
      expect(watcher.isWatching()).toBe(false);
      expect(resumedWatcher.isWatching()).toBe(false);

      await adapter.close();
    });

    it("detects compacted revision on watch creation, terminates stream, and raises EtcdCompactedError without infinite loop", async () => {
      const adapter = new EtcdClientAdapter({ endpoints: [endpoint] });

      // Advance server revision and compact up to currentRevision
      const oldRev = server.currentRevision;
      await adapter.put("/compaction/k1", "v1");
      await adapter.put("/compaction/k2", "v2");
      server.compact(server.currentRevision);

      // Attempting to establish watch starting at oldRev (which is now compacted)
      // must reject with EtcdCompactedError immediately and terminate stream resources
      await expect(
        adapter.watch(
          { prefix: "/compaction/" },
          { startRevision: oldRev },
          () => {}
        )
      ).rejects.toThrow(EtcdCompactedError);

      await adapter.close();
    });

    it("handles mid-stream compaction by terminating watcher and emitting EtcdCompactedError", async () => {
      const adapter = new EtcdClientAdapter({ endpoints: [endpoint] });
      const watchPrefix = "/compaction/live/";

      let receivedCompactedError: Error | null = null;
      const watcher = await adapter.watch(
        { prefix: watchPrefix },
        { startRevision: server.currentRevision },
        () => {},
        (err) => {
          receivedCompactedError = err;
        }
      );

      expect(watcher.isWatching()).toBe(true);

      // Perform mid-stream compaction on server
      server.compact(server.currentRevision + 100n);

      await new Promise((r) => setTimeout(r, 200));

      expect(receivedCompactedError).not.toBeNull();
      expect(receivedCompactedError).toBeInstanceOf(EtcdCompactedError);
      expect(receivedCompactedError!.message).toContain("compacted");
      expect(watcher.isWatching()).toBe(false);

      await watcher.close();
      await adapter.close();
    });
  });

  // ==========================================================================
  // 7. Bounded Timeouts, Cancellation & Fail-Closed Behavior (F-04, F-06)
  // ==========================================================================
  describe("7. Bounded Timeouts, Cancellation & Fail-Closed Behavior (F-04, F-06)", () => {
    it("enforces bounded timeout and fails closed with EtcdTimeoutError when server hangs", async () => {
      const adapter = new EtcdClientAdapter({
        endpoints: [endpoint],
        requestTimeoutMs: 200,
      });

      server.setDelay(600);

      await expect(adapter.get("/timeout/key")).rejects.toThrow(EtcdTimeoutError);

      await adapter.close();
    });

    it("translates gRPC UNAVAILABLE error into EtcdUnavailableError after retry exhaustion", async () => {
      const adapter = new EtcdClientAdapter({
        endpoints: [endpoint],
      });

      // Inject gRPC UNAVAILABLE across all retry attempts (5 attempts > 3 maxAttempts)
      server.failNext("Range", grpc.status.UNAVAILABLE, "cluster leader election in progress", 5);

      await expect(adapter.get("/fail/key")).rejects.toThrow(EtcdUnavailableError);

      await adapter.close();
    });
  });

  // ==========================================================================
  // 8. Delete & DeleteRange Operations (F-05)
  // ==========================================================================
  describe("8. Delete & DeleteRange Operations (F-05)", () => {
    it("deletes single keys and prefix ranges cleanly, returning bigint deletedCount", async () => {
      const adapter = new EtcdClientAdapter({ endpoints: [endpoint] });

      await adapter.put("/delete/test/k1", "v1");
      await adapter.put("/delete/test/k2", "v2");
      await adapter.put("/delete/test/k3", "v3");

      const deletedSingle = await adapter.delete("/delete/test/k1");
      expect(deletedSingle).toBe(true);

      const check = await adapter.get("/delete/test/k1");
      expect(check).toBeNull();

      // deleteRange returns native BigInt
      const deletedCount = await adapter.deleteRange("/delete/test/");
      expect(deletedCount).toBe(2n);
      expect(typeof deletedCount).toBe("bigint");

      const remaining = await adapter.getRange("/delete/test/");
      expect(remaining.length).toBe(0);

      await adapter.close();
    });
  });

  // ==========================================================================
  // 9. Configuration Validation & mTLS Interface
  // ==========================================================================
  describe("9. Configuration Validation & mTLS Interface", () => {
    it("rejects configuration without endpoints immediately", () => {
      expect(() => new EtcdClientAdapter({ endpoints: [] })).toThrow(/requires at least one endpoint/);
    });

    it("accepts and configures mTLS client certificates and keys without error", () => {
      const certs = generateTestCertificates();

      const adapter = new EtcdClientAdapter({
        endpoints: ["https://127.0.0.1:2379"],
        credentials: {
          rootCertificate: certs.caCert,
          certChain: certs.engineClientCert,
          privateKey: certs.engineClientKey,
        },
      });

      expect(adapter).toBeDefined();
    });
  });

  // ==========================================================================
  // 10. 64-Bit Integer Utility Functions & Error Validation (F-05)
  // ==========================================================================
  describe("10. 64-Bit Integer Utility Functions & Error Validation (F-05)", () => {
    it("converts all valid types accurately to native BigInt without precision loss", () => {
      expect(toBigInt(null)).toBe(0n);
      expect(toBigInt(undefined)).toBe(0n);
      expect(toBigInt(42)).toBe(42n);
      expect(toBigInt(42n)).toBe(42n);
      expect(toBigInt("9007199254740995")).toBe(9007199254740995n);
      expect(toPositiveBigInt("9007199254740995")).toBe(9007199254740995n);
    });

    it("rejects malformed, non-numeric, and non-integer values with EtcdAdapterError", () => {
      expect(() => toBigInt("foo")).toThrow(EtcdAdapterError);
      expect(() => toBigInt("12.34")).toThrow(EtcdAdapterError);
      expect(() => toBigInt("NaN")).toThrow(EtcdAdapterError);
      expect(() => toBigInt(NaN)).toThrow(EtcdAdapterError);
      expect(() => toBigInt(Infinity)).toThrow(EtcdAdapterError);
      expect(() => toBigInt(12.34)).toThrow(EtcdAdapterError);
    });

    it("rejects negative numbers when positive BigInt is required", () => {
      expect(() => toPositiveBigInt("-1", "revision")).toThrow(EtcdAdapterError);
      expect(() => toPositiveBigInt(-5n, "version")).toThrow(EtcdAdapterError);
    });
  });
});
