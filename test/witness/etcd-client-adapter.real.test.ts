/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-A.2
 * Real etcd Single-Node Integration Verification Suite
 *
 * Validates the existing production EtcdClientAdapter against an actual, pinned
 * official etcd v3.5.18 daemon running natively on Windows loopback (127.0.0.1).
 *
 * Authorized Scope:
 * 1. Connection establishment and health checks.
 * 2. Linearizable reads and range queries.
 * 3. Atomic transaction/CAS success and failure branches.
 * 4. CRUD operations and deletion.
 * 5. 64-bit revision/index precision beyond JavaScript safe integer range.
 * 6. Watch creation, interruption, reconnection, and revision resumption.
 * 7. Watch compaction behavior against real etcd.
 * 8. Ambiguous transaction outcome handling (committed, authoritatively fenced, indeterminate).
 * 9. Request deadlines, timeout behavior, and cancellation.
 * 10. Process restart with the same persistent data directory.
 * 11. Client mTLS (valid, missing, untrusted, invalid).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { execSync } from "node:child_process";
import {
  EtcdClientAdapter,
  EtcdTimeoutError,
  EtcdUnavailableError,
  EtcdCompactedError,
  EtcdAdapterError,
  toBigInt,
  toPositiveBigInt,
  EtcdWatchEvent,
} from "../../src/witness/etcd-client-adapter.js";
import { generateTestCertificates, findOpenSSL } from "../../src/witness/mtls-certs.js";
import { RealEtcdProcess, getFreePort } from "./helpers/real-etcd-process.js";

describe("Milestone 13-D Phase D3: Stage 2-A.2 Real etcd Single-Node Integration Suite", () => {
  let mainServer: RealEtcdProcess;
  let mainEndpoint: string;
  let mainAdapter: EtcdClientAdapter;

  beforeAll(async () => {
    mainServer = new RealEtcdProcess({
      name: "stage2a2-main-single-node",
    });
    await mainServer.start();
    mainEndpoint = mainServer.grpcEndpoint;

    mainAdapter = new EtcdClientAdapter({
      endpoints: [mainEndpoint],
      dialTimeoutMs: 3000,
      requestTimeoutMs: 5000,
    });
    await mainAdapter.connect();
  }, 20000);

  afterAll(async () => {
    if (mainAdapter) {
      await mainAdapter.close().catch(() => {});
    }
    if (mainServer) {
      await mainServer.stop().catch(() => {});
    }
  });

  // ==========================================================================
  // Category 1: Connection Establishment & Health Checks
  // ==========================================================================
  describe("Category 1: Connection Establishment & Health Checks", () => {
    it("connects to real etcd, queries health status, and discovers cluster metadata", async () => {
      const health = await mainAdapter.healthCheck();
      expect(health.healthy).toBe(true);
      expect(typeof health.clusterId).toBe("string");
      expect(health.clusterId!.length).toBeGreaterThan(0);
      expect(typeof health.memberId).toBe("string");
      expect(health.memberId!.length).toBeGreaterThan(0);
      expect(typeof health.raftTerm).toBe("bigint");
      expect(health.raftTerm!).toBeGreaterThan(0n);
      expect(typeof health.revision).toBe("bigint");
      expect(health.revision!).toBeGreaterThan(0n);
    });

    it("rejects operations when adapter is closed and prevents reconnection", async () => {
      const closedAdapter = new EtcdClientAdapter({
        endpoints: [mainEndpoint],
        dialTimeoutMs: 2000,
      });
      await closedAdapter.connect();
      await closedAdapter.close();

      await expect(closedAdapter.connect()).rejects.toThrow(EtcdAdapterError);
      await expect(closedAdapter.get("/any/key")).rejects.toThrow(EtcdAdapterError);
    });
  });

  // ==========================================================================
  // Category 2: Linearizable Reads & Range Queries
  // ==========================================================================
  describe("Category 2: Linearizable Reads & Range Queries", () => {
    it("enforces linearizable read consistency by default across writes", async () => {
      await mainAdapter.put("/real/lin/key1", "linear-value-1");
      const read = await mainAdapter.get("/real/lin/key1");
      expect(read).not.toBeNull();
      expect(read!.key).toBe("/real/lin/key1");
      expect(read!.value).toBe("linear-value-1");
      expect(read!.valueBuffer.toString("utf8")).toBe("linear-value-1");
      expect(typeof read!.createRevision).toBe("bigint");
      expect(typeof read!.modRevision).toBe("bigint");
      expect(typeof read!.version).toBe("bigint");
      expect(read!.modRevision).toBeGreaterThanOrEqual(read!.createRevision);
    });

    it("executes sorted, bounded range queries across common prefixes", async () => {
      await mainAdapter.put("/real/range/a", "val-a");
      await mainAdapter.put("/real/range/b", "val-b");
      await mainAdapter.put("/real/range/c", "val-c");

      const items = await mainAdapter.getRange("/real/range/", {
        limit: 2,
        sortTarget: "Key",
        sortOrder: "Ascend",
      });

      expect(items.length).toBe(2);
      expect(items[0].key).toBe("/real/range/a");
      expect(items[0].value).toBe("val-a");
      expect(items[1].key).toBe("/real/range/b");
      expect(items[1].value).toBe("val-b");
    });

    it("returns null for non-existent keys and empty array for non-existent ranges", async () => {
      const single = await mainAdapter.get("/real/nonexistent/single");
      expect(single).toBeNull();

      const range = await mainAdapter.getRange("/real/nonexistent/range/");
      expect(range).toEqual([]);
    });
  });

  // ==========================================================================
  // Category 3: Atomic Transaction/CAS Success and Failure Branches
  // ==========================================================================
  describe("Category 3: Atomic Transaction/CAS Success and Failure Branches", () => {
    it("executes the 'then' branch when CAS preconditions are satisfied", async () => {
      const putRes = await mainAdapter.put("/real/cas/key", "val-v1");
      const modRev = putRes.revision;

      const txnRes = await mainAdapter
        .txn()
        .if({
          key: "/real/cas/key",
          target: "Mod",
          operator: "==",
          value: modRev,
        })
        .then(
          { type: "put", key: "/real/cas/key", value: "val-v2" },
          { type: "put", key: "/real/cas/audit", value: "cas-success-branch" }
        )
        .else({ type: "put", key: "/real/cas/audit", value: "cas-failure-branch" })
        .commit();

      expect(txnRes.succeeded).toBe(true);
      expect(typeof txnRes.revision).toBe("bigint");

      const val = await mainAdapter.get("/real/cas/key");
      expect(val?.value).toBe("val-v2");

      const audit = await mainAdapter.get("/real/cas/audit");
      expect(audit?.value).toBe("cas-success-branch");
    });

    it("executes the 'else' branch when CAS preconditions are not satisfied", async () => {
      await mainAdapter.put("/real/cas/target", "initial-data");

      const txnRes = await mainAdapter
        .txn()
        .if({
          key: "/real/cas/target",
          target: "Value",
          operator: "==",
          value: "wrong-precondition",
        })
        .then({ type: "put", key: "/real/cas/target", value: "should-not-occur" })
        .else({ type: "put", key: "/real/cas/target", value: "else-branch-applied" })
        .commit();

      expect(txnRes.succeeded).toBe(false);

      const target = await mainAdapter.get("/real/cas/target");
      expect(target?.value).toBe("else-branch-applied");
    });
  });

  // ==========================================================================
  // Category 4: CRUD Operations and Deletion
  // ==========================================================================
  describe("Category 4: CRUD Operations and Deletion", () => {
    it("captures previous KV when prevKv option is enabled on mutation", async () => {
      await mainAdapter.put("/real/crud/prev", "initial-content");
      const overwrite = await mainAdapter.put("/real/crud/prev", "updated-content", {
        prevKv: true,
      });

      expect(overwrite.prevKv).toBeDefined();
      expect(overwrite.prevKv!.key).toBe("/real/crud/prev");
      expect(overwrite.prevKv!.value).toBe("initial-content");
      expect(overwrite.revision).toBeGreaterThan(overwrite.prevKv!.modRevision);
    });

    it("deletes single keys and returns true only if the key existed", async () => {
      await mainAdapter.put("/real/crud/del", "to-be-deleted");
      const firstDelete = await mainAdapter.delete("/real/crud/del");
      expect(firstDelete).toBe(true);

      const secondDelete = await mainAdapter.delete("/real/crud/del");
      expect(secondDelete).toBe(false);
    });

    it("deletes key ranges and returns exact deleted count as BigInt", async () => {
      await mainAdapter.put("/real/crud/bulk/1", "1");
      await mainAdapter.put("/real/crud/bulk/2", "2");
      await mainAdapter.put("/real/crud/bulk/3", "3");

      const count = await mainAdapter.deleteRange("/real/crud/bulk/");
      expect(typeof count).toBe("bigint");
      expect(count).toBe(3n);

      const remaining = await mainAdapter.getRange("/real/crud/bulk/");
      expect(remaining.length).toBe(0);
    });
  });

  // ==========================================================================
  // Category 5: 64-bit Revision / Index Precision
  // ==========================================================================
  describe("Category 5: 64-bit Revision / Index Precision", () => {
    it("preserves exact 64-bit integer values beyond Number.MAX_SAFE_INTEGER", () => {
      const hugeString = "9007199254740995"; // 2^53 + 3
      const converted = toBigInt(hugeString, "testHuge");
      expect(converted).toBe(9007199254740995n);
      expect(converted.toString()).toBe(hugeString);

      const maxUint64 = "18446744073709551615";
      const convertedMax = toBigInt(maxUint64, "maxUint64");
      expect(convertedMax).toBe(18446744073709551615n);
    });

    it("rejects non-integer, NaN, or unsafe numbers strictly", () => {
      expect(() => toBigInt(123.456, "floatVal")).toThrow(EtcdAdapterError);
      expect(() => toBigInt(NaN, "nanVal")).toThrow(EtcdAdapterError);
      expect(() => toBigInt("not-a-number", "strVal")).toThrow(EtcdAdapterError);
      expect(() => toPositiveBigInt(-5n, "negVal")).toThrow(EtcdAdapterError);
    });

    it("guarantees all revision metadata from real etcd is strictly of type bigint", async () => {
      const putRes = await mainAdapter.put("/real/precision/key", "val");
      expect(typeof putRes.revision).toBe("bigint");

      const getRes = await mainAdapter.get("/real/precision/key");
      expect(typeof getRes!.createRevision).toBe("bigint");
      expect(typeof getRes!.modRevision).toBe("bigint");
      expect(typeof getRes!.version).toBe("bigint");
    });
  });

  // ==========================================================================
  // Category 6: Watch Creation, Interruption, Reconnection & Resumption
  // ==========================================================================
  describe("Category 6: Watch Creation, Interruption, Reconnection & Resumption", () => {
    it("delivers real-time events and catches up from lastSeenRevision + 1n without gaps", async () => {
      const events: EtcdWatchEvent[] = [];
      const prefix = "/real/watch/resume/";

      const watcher = await mainAdapter.watch(
        { prefix },
        { startRevision: 0n },
        (e) => { events.push(e); }
      );
      expect(watcher.isWatching()).toBe(true);

      const put1 = await mainAdapter.put(`${prefix}1`, "ev1");
      const put2 = await mainAdapter.put(`${prefix}2`, "ev2");

      // Await delivery
      await new Promise((r) => setTimeout(r, 400));
      expect(events.length).toBeGreaterThanOrEqual(2);
      expect(events[0].kv.value).toBe("ev1");
      expect(events[1].kv.value).toBe("ev2");

      const lastSeen = events[events.length - 1].kv.modRevision;
      await watcher.close();
      expect(watcher.isWatching()).toBe(false);

      // Mutate during watcher disconnection
      const put3 = await mainAdapter.put(`${prefix}3`, "ev3");
      const resumeRevision = lastSeen + 1n;

      // Resumed watcher should immediately catch up historical event ev3
      const caughtUpEvents: EtcdWatchEvent[] = [];
      const resumedWatcher = await mainAdapter.watch(
        { prefix },
        { startRevision: resumeRevision },
        (e) => { caughtUpEvents.push(e); }
      );

      await new Promise((r) => setTimeout(r, 400));
      expect(caughtUpEvents.some((e) => e.kv.value === "ev3")).toBe(true);

      // Verify real-time continuity
      await mainAdapter.put(`${prefix}4`, "ev4");
      await new Promise((r) => setTimeout(r, 400));
      expect(caughtUpEvents.some((e) => e.kv.value === "ev4")).toBe(true);

      await resumedWatcher.close();
    });
  });

  // ==========================================================================
  // Category 7: Watch Compaction Behavior Against Real etcd
  // ==========================================================================
  describe("Category 7: Watch Compaction Behavior Against Real etcd", () => {
    it("detects real etcd compaction, halts retries, and raises EtcdCompactedError without deadlock", async () => {
      // 1. Generate revisions on real etcd
      let lastRevision = 1n;
      for (let i = 0; i < 5; i++) {
        const res = await mainAdapter.put(`/real/compact/key${i}`, `compact-val-${i}`);
        lastRevision = res.revision;
      }

      // 2. Trigger real compaction on server at lastRevision
      await mainServer.compact(lastRevision);

      // 3. Establish watch on real etcd starting at revision 1n (which is now compacted by real etcd)
      let receivedCompactedError: EtcdCompactedError | null = null;
      let closeCompleted = false;

      const watcher = await mainAdapter.watch(
        { prefix: "/real/compact/" },
        { startRevision: 1n },
        () => {},
        (err) => {
          if (err instanceof EtcdCompactedError) {
            receivedCompactedError = err;
          }
        }
      );

      // Await compaction notification from real server
      for (let i = 0; i < 30; i++) {
        if (receivedCompactedError) break;
        await new Promise((r) => setTimeout(r, 100));
      }

      expect(receivedCompactedError).not.toBeNull();
      expect(receivedCompactedError).toBeInstanceOf(EtcdCompactedError);

      // Verify terminating the watcher does not hang or deadlock
      await watcher.close();
      closeCompleted = true;
      expect(closeCompleted).toBe(true);
      expect(watcher.isWatching()).toBe(false);
    });
  });

  // ==========================================================================
  // Category 8: Ambiguous Transaction Outcome Handling
  // ==========================================================================
  describe("Category 8: Ambiguous Transaction Outcome Handling", () => {
    it("returns CONFIRMED_COMMITTED when probe key matches expected payload", async () => {
      await mainAdapter.put("/real/ambig/probe-1", "fingerprint-alpha");

      const result = await mainAdapter.recoverAmbiguousTxn(
        "/real/ambig/probe-1",
        "fingerprint-alpha"
      );

      expect(result.status).toBe("CONFIRMED_COMMITTED");
      expect(result.existingValue).toBe("fingerprint-alpha");
      expect(result.observedRevision).toBeGreaterThan(0n);
    });

    it("returns CONFLICT_PAYLOAD_MISMATCH when probe key exists with different payload", async () => {
      await mainAdapter.put("/real/ambig/probe-2", "actual-different-payload");

      const result = await mainAdapter.recoverAmbiguousTxn(
        "/real/ambig/probe-2",
        "expected-target-payload"
      );

      expect(result.status).toBe("CONFLICT_PAYLOAD_MISMATCH");
      expect(result.existingValue).toBe("actual-different-payload");
    });

    it("remains strictly fail-closed INDETERMINATE when probe key does not exist and no fencing proof exists", async () => {
      const result = await mainAdapter.recoverAmbiguousTxn(
        "/real/ambig/non-existent-probe",
        "expected-payload"
      );

      // Without deadline expiration or authoritative fencing, must remain INDETERMINATE
      expect(result.status).toBe("INDETERMINATE");
      expect(result.details).toContain("cannot confirm failure");
    });

    it("demonstrates authoritative proposal-specific fencing permanently invalidating an in-flight proposal", async () => {
      // Scenario: Proposal P was issued with precondition: epoch == 100
      await mainAdapter.put("/real/fence/epoch", "100");

      // Authoritative Fencing: Recovery controller advances epoch from 100 -> 101
      const fenceTxn = await mainAdapter
        .txn()
        .if({
          key: "/real/fence/epoch",
          target: "Value",
          operator: "==",
          value: "100",
        })
        .then({ type: "put", key: "/real/fence/epoch", value: "101" })
        .commit();
      expect(fenceTxn.succeeded).toBe(true);

      // Now, any delayed in-flight proposal P predicated on epoch == 100 is permanently unsatisfiable
      const inFlightProposalAttempt = await mainAdapter
        .txn()
        .if({
          key: "/real/fence/epoch",
          target: "Value",
          operator: "==",
          value: "100", // Proposal precondition
        })
        .then({ type: "put", key: "/real/fence/proposal-slot", value: "committed-by-old-proposal" })
        .commit();

      expect(inFlightProposalAttempt.succeeded).toBe(false);

      const slot = await mainAdapter.get("/real/fence/proposal-slot");
      expect(slot).toBeNull(); // Proposal was definitively precluded from committing
    });
  });

  // ==========================================================================
  // Category 9: Request Deadlines, Timeout Behavior & Cancellation
  // ==========================================================================
  describe("Category 9: Request Deadlines, Timeout Behavior & Cancellation", () => {
    it("fails closed within bounded deadline when targeting an unreachable endpoint", async () => {
      // Free loopback port with no listening server
      const unreachablePort = await getFreePort();
      const unreachableAdapter = new EtcdClientAdapter({
        endpoints: [`127.0.0.1:${unreachablePort}`],
        dialTimeoutMs: 300,
        requestTimeoutMs: 300,
        maxRetries: 0,
      });

      const startTime = Date.now();
      await expect(unreachableAdapter.get("/timeout/test")).rejects.toThrow();
      const elapsed = Date.now() - startTime;

      // Must fail closed quickly without hanging indefinitely
      expect(elapsed).toBeLessThan(4000);
      await unreachableAdapter.close().catch(() => {});
    });

    it("cancels active watch streams cleanly without leaking background listeners", async () => {
      let eventCount = 0;
      const watcher = await mainAdapter.watch(
        "/real/watch/cancel/",
        {},
        () => { eventCount++; }
      );

      expect(watcher.isWatching()).toBe(true);
      await watcher.close();
      expect(watcher.isWatching()).toBe(false);

      // Writes after close should not trigger callbacks
      await mainAdapter.put("/real/watch/cancel/k1", "val1");
      await new Promise((r) => setTimeout(r, 200));
      expect(eventCount).toBe(0);
    });
  });

  // ==========================================================================
  // Category 10: Process Restart with Persistent Data Directory
  // ==========================================================================
  describe("Category 10: Process Restart with Persistent Data Directory", () => {
    it("retains all committed bbolt/WAL state across ungraceful process termination and restart", async () => {
      const restartPort = await getFreePort();
      const restartPeerPort = await getFreePort();

      const restartServer = new RealEtcdProcess({
        name: "stage2a2-restart-test",
        clientPort: restartPort,
        peerPort: restartPeerPort,
      });

      await restartServer.start();
      const restartAdapter = new EtcdClientAdapter({
        endpoints: [restartServer.grpcEndpoint],
      });
      await restartAdapter.connect();

      // Write durable key
      const putRes = await restartAdapter.put("/durable/restart/key", "durable-state-v1");
      const originalRev = putRes.revision;
      await restartAdapter.close();

      // Ungraceful process termination: taskkill /F on Windows
      expect(restartServer.pid).toBeDefined();
      await restartServer.stop();

      // Start new server process instance reusing the EXACT same data directory
      const restartedServer = new RealEtcdProcess({
        name: "stage2a2-restart-test",
        clientPort: restartPort,
        peerPort: restartPeerPort,
        dataDir: restartServer.dataDir,
      });

      await restartedServer.start();

      const verifyAdapter = new EtcdClientAdapter({
        endpoints: [restartedServer.grpcEndpoint],
      });
      await verifyAdapter.connect();

      // Read key after server restart
      const durableRecord = await verifyAdapter.get("/durable/restart/key");
      expect(durableRecord).not.toBeNull();
      expect(durableRecord!.value).toBe("durable-state-v1");
      expect(durableRecord!.modRevision).toBe(originalRev);

      await verifyAdapter.close();
      await restartedServer.stop();
    });
  });

  // ==========================================================================
  // Category 11: Client mTLS Verification
  // ==========================================================================
  describe("Category 11: Client mTLS Verification", () => {
    let tlsServer: RealEtcdProcess;
    let certs: ReturnType<typeof generateTestCertificates>;
    let untrustedClientCert: Buffer;
    let untrustedClientKey: Buffer;

    beforeAll(async () => {
      certs = generateTestCertificates();

      // Create an untrusted CA and client certificate signed by that untrusted CA
      const openssl = findOpenSSL();
      const untrustedDir = fs.mkdtempSync(path.join(certs.bundleDir, "untrusted-"));
      const unCaKey = path.join(untrustedDir, "un-ca.key");
      const unCaCrt = path.join(untrustedDir, "un-ca.crt");
      const unClientKey = path.join(untrustedDir, "un-client.key");
      const unClientCsr = path.join(untrustedDir, "un-client.csr");
      const unClientCrt = path.join(untrustedDir, "un-client.crt");

      execSync(
        `"${openssl}" req -x509 -newkey rsa:2048 -nodes -keyout "${unCaKey}" -out "${unCaCrt}" -days 1 -subj "/CN=UntrustedRootCA"`,
        { stdio: "ignore" }
      );
      execSync(
        `"${openssl}" req -newkey rsa:2048 -nodes -keyout "${unClientKey}" -out "${unClientCsr}" -subj "/CN=untrusted-client"`,
        { stdio: "ignore" }
      );
      execSync(
        `"${openssl}" x509 -req -in "${unClientCsr}" -CA "${unCaCrt}" -CAkey "${unCaKey}" -CAcreateserial -out "${unClientCrt}" -days 1`,
        { stdio: "ignore" }
      );

      untrustedClientCert = fs.readFileSync(unClientCrt);
      untrustedClientKey = fs.readFileSync(unClientKey);

      // Start etcd server with strict client certificate authentication enabled
      tlsServer = new RealEtcdProcess({
        name: "stage2a2-mtls-node",
        tls: {
          caCertPath: path.join(certs.bundleDir, "ca.crt"),
          serverCertPath: path.join(certs.bundleDir, "server.crt"),
          serverKeyPath: path.join(certs.bundleDir, "server.key"),
          clientCertPath: path.join(certs.bundleDir, "engine-client.crt"),
          clientKeyPath: path.join(certs.bundleDir, "engine-client.key"),
          clientCertAuth: true,
        },
      });

      await tlsServer.start();
    }, 25000);

    afterAll(async () => {
      if (tlsServer) {
        await tlsServer.stop().catch(() => {});
      }
    });

    it("successfully connects, authenticates, and reads/writes with valid client certificate", async () => {
      const validAdapter = new EtcdClientAdapter({
        endpoints: [tlsServer.grpcEndpoint],
        credentials: {
          rootCertificate: certs.caCert,
          certChain: certs.engineClientCert,
          privateKey: certs.engineClientKey,
        },
        grpcOptions: {
          "grpc.ssl_target_name_override": "localhost",
        },
      });

      await validAdapter.connect();

      const health = await validAdapter.healthCheck();
      expect(health.healthy).toBe(true);

      await validAdapter.put("/mtls/secure", "authorized-write");
      const res = await validAdapter.get("/mtls/secure");
      expect(res?.value).toBe("authorized-write");

      await validAdapter.close();
    });

    it("rejects connection when client certificate is missing", async () => {
      const noCertAdapter = new EtcdClientAdapter({
        endpoints: [tlsServer.grpcEndpoint],
        dialTimeoutMs: 2000,
        requestTimeoutMs: 2000,
        credentials: {
          rootCertificate: certs.caCert,
          // Missing certChain and privateKey
        },
        grpcOptions: {
          "grpc.ssl_target_name_override": "localhost",
        },
      });

      await expect(noCertAdapter.connect()).rejects.toThrow();
      await noCertAdapter.close().catch(() => {});
    });

    it("rejects connection when client certificate is signed by an untrusted CA", async () => {
      const untrustedAdapter = new EtcdClientAdapter({
        endpoints: [tlsServer.grpcEndpoint],
        dialTimeoutMs: 2000,
        requestTimeoutMs: 2000,
        credentials: {
          rootCertificate: certs.caCert,
          certChain: untrustedClientCert,
          privateKey: untrustedClientKey,
        },
        grpcOptions: {
          "grpc.ssl_target_name_override": "localhost",
        },
      });

      await expect(untrustedAdapter.connect()).rejects.toThrow();
      await untrustedAdapter.close().catch(() => {});
    });

    it("rejects connection when client certificate bytes are invalid/corrupt", () => {
      expect(() => {
        new EtcdClientAdapter({
          endpoints: [tlsServer.grpcEndpoint],
          dialTimeoutMs: 2000,
          requestTimeoutMs: 2000,
          credentials: {
            rootCertificate: certs.caCert,
            certChain: Buffer.from("NOT_A_VALID_CERTIFICATE_PEM"),
            privateKey: certs.engineClientKey,
          },
          grpcOptions: {
            "grpc.ssl_target_name_override": "localhost",
          },
        });
      }).toThrow();
    });
  });
});
