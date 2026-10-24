import { fork, type ChildProcess } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import {
  SQLiteAuthorizationStore,
  withImmediateTransaction,
} from "../src/authorization-store.js";
import {
  issueSignedTransactionAuthorizationV3,
  consumeSignedTransactionAuthorizationV3,
} from "../src/authorization-lifecycle.js";
import { TestClock } from "../src/clock.js";
import { type DemoPolicy } from "../src/policy.js";
import { type TransactionRequest } from "../src/transaction-envelope.js";

describe("Milestone 6.4 — Phase 3: Persistence, Contention and Crash-Recovery Tests", () => {
  const tempDirs: string[] = [];
  const activeChildren = new Set<ChildProcess>();

  function databasePath(filename: string): string {
    const dir = mkdtempSync(join(tmpdir(), "web3user-p3-"));
    tempDirs.push(dir);
    return join(dir, filename);
  }

  afterEach(() => {
    for (const child of activeChildren) {
      if (child.exitCode === null && !child.killed) {
        try {
          child.kill("SIGKILL");
        } catch {}
      }
    }
    activeChildren.clear();

    for (const dir of tempDirs) {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {}
    }
    tempDirs.length = 0;
  });

  const basePolicy: DemoPolicy = {
    version: 1,
    policyId: "policy-phase3",
    allowedTarget: "0x1111111111111111111111111111111111111111",
    allowedRecipient: "0x2222222222222222222222222222222222222222",
    allowedSelector: "0xa9059cbb",
    maxAmount: "1000",
    validFrom: 1000,
    expiresAt: 9000,
    revoked: false,
  };

  const validRequest: TransactionRequest = {
    chainId: "1",
    sender: "0x3333333333333333333333333333333333333333",
    target: "0x1111111111111111111111111111111111111111",
    calldata:
      "0xa9059cbb" +
      "0000000000000000000000002222222222222222222222222222222222222222" +
      "0000000000000000000000000000000000000000000000000000000000000064",
    value: "0",
  };

  function createKeypair() {
    return generateKeyPairSync("ed25519");
  }

  function runSubprocess(
    code: string,
    timeoutMs = 15000,
  ): Promise<{ exitCode: number | null; stdout: string; stderr: string }> {
    return new Promise((resolvePromise, rejectPromise) => {
      let stdout = "";
      let stderr = "";
      let settled = false;

      const child = fork("-e", [code], {
        execArgv: ["--input-type=module", "--import", "tsx/esm"],
        silent: true,
      });
      activeChildren.add(child);

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        try {
          child.kill("SIGKILL");
        } catch {}
        activeChildren.delete(child);
        rejectPromise(new Error(`runSubprocess timed out after ${timeoutMs}ms.`));
      }, timeoutMs);

      child.stdout?.on("data", (d) => {
        stdout += d.toString();
      });
      child.stderr?.on("data", (d) => {
        stderr += d.toString();
      });

      child.on("exit", (code) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        activeChildren.delete(child);
        resolvePromise({ exitCode: code, stdout, stderr });
      });

      child.on("error", (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        activeChildren.delete(child);
        rejectPromise(err);
      });
    });
  }

  interface RendezvousWorkerResult {
    workerId: number;
    exitCode: number | null;
    stdout: string;
    stderr: string;
  }

  function runRendezvousWorkers(
    workerScripts: Array<{ workerId: number; code: string }>,
    timeoutMs = 20000,
  ): Promise<RendezvousWorkerResult[]> {
    return new Promise((resolvePromise, rejectPromise) => {
      const children: Array<{
        workerId: number;
        child: ReturnType<typeof fork>;
        stdout: string;
        stderr: string;
        exitCode: number | null;
      }> = [];
      const readyWorkers = new Set<number>();
      let settled = false;

      const cleanupAndKillAll = () => {
        for (const entry of children) {
          activeChildren.delete(entry.child);
          if (entry.child.exitCode === null && !entry.child.killed) {
            try {
              entry.child.kill("SIGKILL");
            } catch {}
          }
        }
      };

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        cleanupAndKillAll();
        rejectPromise(
          new Error(
            `runRendezvousWorkers timed out after ${timeoutMs}ms. Ready workers: ${readyWorkers.size}/${workerScripts.length}. Child statuses: ` +
              children
                .map(
                  (c) =>
                    `W${c.workerId}(code=${c.exitCode}, ready=${readyWorkers.has(c.workerId)})`,
                )
                .join(", "),
          ),
        );
      }, timeoutMs);

      const checkAllExited = () => {
        const allDone = children.every((c) => c.exitCode !== null);
        if (allDone && !settled) {
          settled = true;
          clearTimeout(timer);
          for (const c of children) {
            activeChildren.delete(c.child);
          }
          resolvePromise(
            children.map((c) => ({
              workerId: c.workerId,
              exitCode: c.exitCode,
              stdout: c.stdout,
              stderr: c.stderr,
            })),
          );
        }
      };

      for (const ws of workerScripts) {
        const child = fork("-e", [ws.code], {
          execArgv: ["--input-type=module", "--import", "tsx/esm"],
          silent: true,
        });
        activeChildren.add(child);

        const entry = {
          workerId: ws.workerId,
          child,
          stdout: "",
          stderr: "",
          exitCode: null as number | null,
        };
        children.push(entry);

        child.stdout?.on("data", (d) => {
          entry.stdout += d.toString();
        });
        child.stderr?.on("data", (d) => {
          entry.stderr += d.toString();
        });

        child.on("message", (msg: unknown) => {
          if (
            typeof msg === "object" &&
            msg !== null &&
            (msg as { type?: string }).type === "READY"
          ) {
            readyWorkers.add(ws.workerId);
            if (readyWorkers.size === workerScripts.length && !settled) {
              for (const c of children) {
                c.child.send("START");
              }
            }
          }
        });

        child.on("exit", (code) => {
          entry.exitCode = code;
          checkAllExited();
        });

        child.on("error", (err) => {
          entry.stderr += "\nChild process error: " + err.message;
          if (entry.exitCode === null) {
            entry.exitCode = 1;
          }
          checkAllExited();
        });
      }
    });
  }

  // =========================================================================
  // Objective A: Persistent-State Invariants
  // =========================================================================
  describe("Objective A: Persistent-State Invariants", () => {
    it("persists V3 authorization issue and consumption state across database close and reopen", () => {
      const dbFile = databasePath("persist-lifecycle.sqlite");
      const clock = new TestClock(1000);
      const key = createKeypair();

      // Step 1: Open Store 1, register policy & key, and issue V3 authorization
      const store1 = new SQLiteAuthorizationStore(dbFile, clock);
      let issued: ReturnType<typeof issueSignedTransactionAuthorizationV3>;
      try {
        store1.getPolicyStore().registerPolicy(basePolicy);
        store1.getKeyStore().registerKey({
          keyId: "key-persist-1",
          publicKey: key.publicKey,
          status: "active",
          validFromSeconds: 1000,
          expiresAtSeconds: 9000,
        });

        issued = issueSignedTransactionAuthorizationV3(
          store1,
          { keyId: "key-persist-1", privateKey: key.privateKey },
          "auth-persist-lifecycle-001",
          "policy-phase3",
          validRequest,
          { ttlSeconds: 500 },
        );
        expect(issued.decision).toBe("ALLOW");
        if (issued.decision !== "ALLOW") throw new Error("Issuance failed");

        // Verify in-store record before close
        const record1 = store1.getAuthorizationRecord("auth-persist-lifecycle-001");
        expect(record1).not.toBeNull();
        expect(record1?.state).toBe("issued");
        expect(record1?.consumedAt).toBeNull();
        expect(record1?.artifactVersion).toBe(3);
        expect(record1?.keyId).toBe("key-persist-1");
        expect(record1?.issuedAtSeconds).toBe(1000);
      } finally {
        store1.close();
      }

      // Step 2: Query raw SQLite file using independent DatabaseSync to verify durable persistence
      const rawDb1 = new DatabaseSync(dbFile);
      try {
        const rawRow1 = rawDb1
          .prepare(
            "SELECT authorization_id, binding_digest, state, consumed_at, artifact_version, key_id, issued_at_seconds FROM consumed_authorization_ids WHERE authorization_id = ?",
          )
          .get("auth-persist-lifecycle-001") as {
          authorization_id: string;
          binding_digest: string;
          state: string;
          consumed_at: string | null;
          artifact_version: number;
          key_id: string;
          issued_at_seconds: number;
        };
        expect(rawRow1).toBeDefined();
        expect(rawRow1.state).toBe("issued");
        expect(rawRow1.consumed_at).toBeNull();
        expect(rawRow1.artifact_version).toBe(3);
        expect(rawRow1.key_id).toBe("key-persist-1");
        expect(rawRow1.issued_at_seconds).toBe(1000);
      } finally {
        rawDb1.close();
      }

      // Step 3: Open fresh Store 2 on the same database file and consume the authorization
      const store2 = new SQLiteAuthorizationStore(dbFile, clock);
      try {
        const record2 = store2.getAuthorizationRecord("auth-persist-lifecycle-001");
        expect(record2?.state).toBe("issued");

        const consumed = consumeSignedTransactionAuthorizationV3(
          store2,
          issued.artifact,
          issued.envelope,
          validRequest,
        );
        expect(consumed.decision).toBe("ALLOW");
        if (consumed.decision !== "ALLOW") throw new Error("Consumption failed");

        expect(store2.getAuthorizationRecord("auth-persist-lifecycle-001")?.state).toBe("consumed");
      } finally {
        store2.close();
      }

      // Step 4: Verify raw SQLite file after consumption
      const rawDb2 = new DatabaseSync(dbFile);
      try {
        const rawRow2 = rawDb2
          .prepare(
            "SELECT authorization_id, state, consumed_at, artifact_version FROM consumed_authorization_ids WHERE authorization_id = ?",
          )
          .get("auth-persist-lifecycle-001") as {
          authorization_id: string;
          state: string;
          consumed_at: string | null;
          artifact_version: number;
        };
        expect(rawRow2.state).toBe("consumed");
        expect(rawRow2.consumed_at).not.toBeNull();
        expect(typeof rawRow2.consumed_at).toBe("string");
      } finally {
        rawDb2.close();
      }

      // Step 5: Open fresh Store 3 on the same database and attempt replay consumption
      const store3 = new SQLiteAuthorizationStore(dbFile, clock);
      try {
        const replayAttempt = consumeSignedTransactionAuthorizationV3(
          store3,
          issued.artifact,
          issued.envelope,
          validRequest,
        );
        expect(replayAttempt.decision).toBe("DENY");
        expect(replayAttempt.reasons).toEqual(
          expect.arrayContaining([
            expect.stringMatching(
              /already been consumed|unknown, consumed, or mismatched/,
            ),
          ]),
        );

        // Verify raw database state remains exactly 1 consumed row
        const rawDb3 = new DatabaseSync(dbFile);
        try {
          const countRow = rawDb3
            .prepare("SELECT COUNT(*) as c FROM consumed_authorization_ids")
            .get() as { c: number };
          expect(countRow.c).toBe(1);
        } finally {
          rawDb3.close();
        }
      } finally {
        store3.close();
      }
    });

    it("enforces persisted clock high-water invariants across multiple store instances and processes", async () => {
      const dbFile = databasePath("persist-clock-highwater.sqlite");
      const clock = new TestClock(1000);

      // Instance 1 initializes high-water mark and advances it to 3000
      const store1 = new SQLiteAuthorizationStore(dbFile, clock);
      try {
        expect(store1.getHighWaterMark()).toBe(1000);
        store1.advanceHighWaterMark(3000);
        expect(store1.getHighWaterMark()).toBe(3000);
      } finally {
        store1.close();
      }

      // Verify raw database state
      const rawDb1 = new DatabaseSync(dbFile);
      try {
        const clockRow = rawDb1
          .prepare("SELECT high_water_seconds FROM system_clock_state WHERE id = 1")
          .get() as { high_water_seconds: number };
        expect(clockRow.high_water_seconds).toBe(3000);
      } finally {
        rawDb1.close();
      }

      // Instance 2 opens with a lagging clock (2000s). Re-reads high-water as 3000.
      const store2 = new SQLiteAuthorizationStore(dbFile, new TestClock(2000));
      try {
        expect(store2.getHighWaterMark()).toBe(3000);
        expect(() => store2.advanceHighWaterMark(2000)).toThrow(
          "Clock rollback detected: current time (2000s) precedes persisted high-water mark (3000s).",
        );
      } finally {
        store2.close();
      }

      // Multi-process clock advance & rollback test:
      // Process A advances high-water mark to 5000.
      // Process B with lagging clock at 4000 attempts to rollback and must fail.
      const procA = `
        import { SQLiteAuthorizationStore } from './src/authorization-store.js';
        import { TestClock } from './src/clock.js';
        const store = new SQLiteAuthorizationStore(${JSON.stringify(dbFile)}, new TestClock(5000));
        store.advanceHighWaterMark(5000);
        console.log('PROC_A_ADVANCED:' + store.getHighWaterMark());
        store.close();
        process.exit(0);
      `;

      const procB = `
        import { SQLiteAuthorizationStore } from './src/authorization-store.js';
        import { TestClock } from './src/clock.js';
        const store = new SQLiteAuthorizationStore(${JSON.stringify(dbFile)}, new TestClock(4000));
        try {
          store.advanceHighWaterMark(4000);
          console.log('PROC_B_UNEXPECTED_SUCCESS');
          process.exit(1);
        } catch (err) {
          console.log('PROC_B_ROLLBACK_DETECTED:' + err.message);
          store.close();
          process.exit(0);
        }
      `;

      const resA = await runSubprocess(procA);
      expect(resA.exitCode).toBe(0);
      expect(resA.stdout).toContain("PROC_A_ADVANCED:5000");

      const resB = await runSubprocess(procB);
      expect(resB.exitCode).toBe(0);
      expect(resB.stdout).toContain("PROC_B_ROLLBACK_DETECTED:Clock rollback detected");

      // Verify final raw state in database is strictly 5000, never lowered
      const verifyStore = new SQLiteAuthorizationStore(dbFile, new TestClock(5000));
      try {
        expect(verifyStore.getHighWaterMark()).toBe(5000);
      } finally {
        verifyStore.close();
      }
    });

    it("leaves no partial authorization records or uncommitted state on rejected operations", () => {
      const dbFile = databasePath("persist-rejected-clean.sqlite");
      const clock = new TestClock(1000);
      const key = createKeypair();

      const store = new SQLiteAuthorizationStore(dbFile, clock);
      try {
        store.getPolicyStore().registerPolicy(basePolicy);
        store.getKeyStore().registerKey({
          keyId: "key-reject-test",
          publicKey: key.publicKey,
          status: "active",
          validFromSeconds: 1000,
          expiresAtSeconds: 9000,
        });

        // Subcase 1: Rejected issuance due to policy limit violation (amount > 1000)
        const invalidRequest: TransactionRequest = {
          ...validRequest,
          calldata:
            "0xa9059cbb" +
            "0000000000000000000000002222222222222222222222222222222222222222" +
            "000000000000000000000000000000000000000000000000000000000000ffff", // 65535 > 1000
        };

        const rejectIssuance = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-reject-test", privateKey: key.privateKey },
          "auth-rejected-amount",
          "policy-phase3",
          invalidRequest,
        );
        expect(rejectIssuance.decision).toBe("DENY");

        // Raw SQL check: no row created
        const rawDb = new DatabaseSync(dbFile);
        try {
          const rowIssuance = rawDb
            .prepare("SELECT * FROM consumed_authorization_ids WHERE authorization_id = ?")
            .get("auth-rejected-amount");
          expect(rowIssuance).toBeUndefined();
        } finally {
          rawDb.close();
        }

        // Subcase 2: Rejected issuance due to revoked key
        clock.advance(100); // advance clock to 1100
        store.getKeyStore().revokeKey("key-reject-test", 1100);
        const rejectRevokedKey = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-reject-test", privateKey: key.privateKey },
          "auth-rejected-revoked-key",
          "policy-phase3",
          validRequest,
        );
        expect(rejectRevokedKey.decision).toBe("DENY");
        expect(rejectRevokedKey.reasons).toContain("Issuer key has been revoked.");

        const rawDb2 = new DatabaseSync(dbFile);
        try {
          const rowRevoked = rawDb2
            .prepare("SELECT * FROM consumed_authorization_ids WHERE authorization_id = ?")
            .get("auth-rejected-revoked-key");
          expect(rowRevoked).toBeUndefined();
        } finally {
          rawDb2.close();
        }

        // Subcase 3: Rejected consumption leaves existing valid record intact in 'issued' state
        const key2 = createKeypair();
        store.getKeyStore().registerKey({
          keyId: "key-reject-test-2",
          publicKey: key2.publicKey,
          status: "active",
          validFromSeconds: 1000,
          expiresAtSeconds: 9000,
        });

        const validIssued = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-reject-test-2", privateKey: key2.privateKey },
          "auth-valid-for-tamper-test",
          "policy-phase3",
          validRequest,
        );
        expect(validIssued.decision).toBe("ALLOW");
        if (validIssued.decision !== "ALLOW") throw new Error("Issuance failed");

        // Verify row exists in 'issued' state
        const recordBefore = store.getAuthorizationRecord("auth-valid-for-tamper-test");
        expect(recordBefore?.state).toBe("issued");
        expect(recordBefore?.consumedAt).toBeNull();

        // Attempt consumption with tampered request target
        const tamperedRequest: TransactionRequest = {
          ...validRequest,
          target: "0x9999999999999999999999999999999999999999",
        };
        const rejectConsumption = consumeSignedTransactionAuthorizationV3(
          store,
          validIssued.artifact,
          validIssued.envelope,
          tamperedRequest,
        );
        expect(rejectConsumption.decision).toBe("DENY");

        // Raw SQL check: row remains strictly in 'issued' state, NOT consumed
        const recordAfterTamper = store.getAuthorizationRecord("auth-valid-for-tamper-test");
        expect(recordAfterTamper?.state).toBe("issued");
        expect(recordAfterTamper?.consumedAt).toBeNull();

        // Now perform valid consumption: succeeds cleanly
        const validConsumption = consumeSignedTransactionAuthorizationV3(
          store,
          validIssued.artifact,
          validIssued.envelope,
          validRequest,
        );
        expect(validConsumption.decision).toBe("ALLOW");
        expect(store.getAuthorizationRecord("auth-valid-for-tamper-test")?.state).toBe("consumed");
      } finally {
        store.close();
      }
    });

    it("preserves policy and key governance revisions and terminal states across store restart", () => {
      const dbFile = databasePath("persist-governance.sqlite");
      const clock = new TestClock(1000);
      const key1 = createKeypair();
      const key2 = createKeypair();

      // Store 1: Register policy, update policy revision, register keys, retire key 1, revoke key 2
      const store1 = new SQLiteAuthorizationStore(dbFile, clock);
      try {
        store1.getPolicyStore().registerPolicy(basePolicy);
        const updatedPolicy: DemoPolicy = {
          ...basePolicy,
          maxAmount: "5000",
        };
        store1.getPolicyStore().updatePolicy(updatedPolicy, 1);

        store1.getKeyStore().registerKey({
          keyId: "key-gov-1",
          publicKey: key1.publicKey,
          status: "active",
          validFromSeconds: 1000,
          expiresAtSeconds: 9000,
        });
        store1.getKeyStore().registerKey({
          keyId: "key-gov-2",
          publicKey: key2.publicKey,
          status: "active",
          validFromSeconds: 1000,
          expiresAtSeconds: 9000,
        });

        store1.getKeyStore().retireKey("key-gov-1", 1500);
        store1.getKeyStore().revokeKey("key-gov-2", 1800);
      } finally {
        store1.close();
      }

      // Open Store 2 on the same database file with forward clock (t=2000 >= 1800) and verify governance state survival
      const store2 = new SQLiteAuthorizationStore(dbFile, new TestClock(2000));
      try {
        const pol = store2.getPolicyStore().getPolicy("policy-phase3");
        expect(pol?.revision).toBe(2);
        expect(pol?.policy.maxAmount).toBe("5000");

        const revisions = store2.getPolicyStore().listPolicyRevisions("policy-phase3");
        expect(revisions).toHaveLength(2);
        expect(revisions[0].revision).toBe(1);
        expect(revisions[0].policy.maxAmount).toBe("1000");
        expect(revisions[1].revision).toBe(2);
        expect(revisions[1].policy.maxAmount).toBe("5000");

        const k1 = store2.getKeyStore().getKey("key-gov-1");
        expect(k1?.status).toBe("retired");
        expect(k1?.retiredAtSeconds).toBe(1500);

        const k2 = store2.getKeyStore().getKey("key-gov-2");
        expect(k2?.status).toBe("revoked");
        expect(k2?.revokedAtSeconds).toBe(1800);

        // Verify terminal status enforcement on reopened store
        expect(() => store2.getKeyStore().retireKey("key-gov-2", 2000)).toThrow(
          "Cannot retire revoked key 'key-gov-2'; revocation is permanent.",
        );

        // Verify issuance rejections against retired and revoked keys on reopened store
        const issueK1 = issueSignedTransactionAuthorizationV3(
          store2,
          { keyId: "key-gov-1", privateKey: key1.privateKey },
          "auth-retired-key",
          "policy-phase3",
          validRequest,
        );
        expect(issueK1.decision).toBe("DENY");
        expect(issueK1.reasons).toContain("Issuer key is retired and cannot issue new authorizations.");

        const issueK2 = issueSignedTransactionAuthorizationV3(
          store2,
          { keyId: "key-gov-2", privateKey: key2.privateKey },
          "auth-revoked-key",
          "policy-phase3",
          validRequest,
        );
        expect(issueK2.decision).toBe("DENY");
        expect(issueK2.reasons).toContain("Issuer key has been revoked.");
      } finally {
        store2.close();
      }
    });
  });

  // =========================================================================
  // Objective B: Contention and Retry Behavior
  // =========================================================================
  describe("Objective B: Contention and Retry Behavior", () => {
    it("resolves recoverable transaction contention within configured retry budget", async () => {
      const dbFile = databasePath("contention-recoverable.sqlite");
      const initStore = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      initStore.close();

      // Child worker acquires immediate lock, writes row 1, holds for 40ms, and commits
      const workerCode = `
        import { DatabaseSync } from 'node:sqlite';
        import { sleepSync } from './src/sqlite-transaction.js';

        const db = new DatabaseSync(${JSON.stringify(dbFile)});
        db.exec('PRAGMA busy_timeout = 5000;');
        db.exec('BEGIN IMMEDIATE;');
        db.exec("INSERT INTO consumed_authorization_ids (authorization_id, state) VALUES ('auth-worker-held', 'issued');");
        if (process.send) process.send({ type: 'LOCKED' });
        sleepSync(40);
        db.exec('COMMIT;');
        db.close();
        process.exit(0);
      `;

      const child = fork("-e", [workerCode], {
        execArgv: ["--input-type=module", "--import", "tsx/esm"],
        silent: true,
      });
      activeChildren.add(child);

      await new Promise<void>((resolvePromise) => {
        child.on("message", (msg) => {
          if (typeof msg === "object" && msg !== null && (msg as { type?: string }).type === "LOCKED") {
            resolvePromise();
          }
        });
      });

      // Foreground process attempts transaction with retry budget:
      // 5 retries * 25ms delay = 125ms total wait budget > 40ms held by child
      const mainDb = new DatabaseSync(dbFile);
      mainDb.exec("PRAGMA busy_timeout = 5000;");

      try {
        const result = withImmediateTransaction(
          mainDb,
          () => {
            mainDb.exec(
              "INSERT INTO consumed_authorization_ids (authorization_id, state) VALUES ('auth-main-retry-success', 'issued');",
            );
            return "RECOVERED";
          },
          5,
          25,
        );
        expect(result).toBe("RECOVERED");
      } finally {
        mainDb.close();
      }

      await new Promise<void>((resolvePromise) => {
        child.on("exit", () => {
          activeChildren.delete(child);
          resolvePromise();
        });
      });

      // Verify both rows exist durably
      const verifyDb = new DatabaseSync(dbFile);
      try {
        const rows = verifyDb
          .prepare("SELECT authorization_id FROM consumed_authorization_ids ORDER BY authorization_id ASC")
          .all() as Array<{ authorization_id: string }>;
        expect(rows.map((r) => r.authorization_id)).toEqual([
          "auth-main-retry-success",
          "auth-worker-held",
        ]);
      } finally {
        verifyDb.close();
      }
    });

    it("predictably fails when transaction contention exceeds configured retry limit", async () => {
      const dbFile = databasePath("contention-exhaustion.sqlite");
      const initStore = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      initStore.close();

      // Child worker holds BEGIN IMMEDIATE for 250ms
      const workerCode = `
        import { DatabaseSync } from 'node:sqlite';
        import { sleepSync } from './src/sqlite-transaction.js';

        const db = new DatabaseSync(${JSON.stringify(dbFile)});
        db.exec('BEGIN IMMEDIATE;');
        if (process.send) process.send({ type: 'LOCKED' });
        sleepSync(250);
        db.exec('COMMIT;');
        db.close();
        process.exit(0);
      `;

      const child = fork("-e", [workerCode], {
        execArgv: ["--input-type=module", "--import", "tsx/esm"],
        silent: true,
      });
      activeChildren.add(child);

      await new Promise<void>((resolvePromise) => {
        child.on("message", (msg) => {
          if (typeof msg === "object" && msg !== null && (msg as { type?: string }).type === "LOCKED") {
            resolvePromise();
          }
        });
      });

      // Foreground process configures a tight retry limit: 2 retries * 10ms = 20ms wait budget < 250ms held
      const mainDb = new DatabaseSync(dbFile);
      mainDb.exec("PRAGMA busy_timeout = 0;");

      try {
        let callbackExecuted = false;
        expect(() => {
          withImmediateTransaction(
            mainDb,
            () => {
              callbackExecuted = true;
              mainDb.exec(
                "INSERT INTO consumed_authorization_ids (authorization_id, state) VALUES ('auth-should-not-exist', 'issued');",
              );
            },
            2,
            10,
          );
        }).toThrow("Database is busy; transaction contention retry limit exceeded.");

        expect(callbackExecuted).toBe(false);

        // Wait for child worker to release lock
        await new Promise<void>((resolvePromise) => {
          child.on("exit", () => {
            activeChildren.delete(child);
            resolvePromise();
          });
        });

        // After contention clears, mainDb is completely usable and partial row is absent
        const checkRow = mainDb
          .prepare("SELECT * FROM consumed_authorization_ids WHERE authorization_id = ?")
          .get("auth-should-not-exist");
        expect(checkRow).toBeUndefined();

        // New transaction on mainDb succeeds cleanly
        expect(() => {
          withImmediateTransaction(mainDb, () => {
            mainDb.exec(
              "INSERT INTO consumed_authorization_ids (authorization_id, state) VALUES ('auth-post-contention-clean', 'issued');",
            );
          });
        }).not.toThrow();
      } finally {
        mainDb.close();
      }
    });

    it("prevents duplicate authorization issuance when multiple processes race for the same ID", async () => {
      const dbFile = databasePath("contention-duplicate-issuance.sqlite");
      const { publicKey, privateKey } = createKeypair();
      const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

      // Initialize policy and key
      const mainStore = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      try {
        mainStore.getPolicyStore().registerPolicy(basePolicy);
        mainStore.getKeyStore().registerKey({
          keyId: "key-race-issuance",
          publicKey,
          status: "active",
          validFromSeconds: 1000,
          expiresAtSeconds: 9000,
        });
      } finally {
        mainStore.close();
      }

      const makeIssuanceWorker = (workerId: number) => `
        import { createPrivateKey } from 'node:crypto';
        import { SQLiteAuthorizationStore } from './src/authorization-store.js';
        import { TestClock } from './src/clock.js';
        import { issueSignedTransactionAuthorizationV3 } from './src/authorization-lifecycle.js';

        const store = new SQLiteAuthorizationStore(${JSON.stringify(dbFile)}, new TestClock(1000));
        const privKey = createPrivateKey(${JSON.stringify(privateKeyPem)});
        const req = ${JSON.stringify(validRequest)};

        if (process.send) {
          process.send({ type: 'READY' });
        }

        process.on('message', (msg) => {
          if (msg === 'START') {
            const issued = issueSignedTransactionAuthorizationV3(
              store,
              { keyId: 'key-race-issuance', privateKey: privKey },
              'auth-race-duplicate-issuance-target',
              'policy-phase3',
              req,
            );
            store.close();
            console.log('RESULT:' + ${workerId} + ':' + issued.decision + ':' + JSON.stringify(issued.reasons ?? []));
            process.exit(0);
          }
        });
      `;

      const results = await runRendezvousWorkers([
        { workerId: 1, code: makeIssuanceWorker(1) },
        { workerId: 2, code: makeIssuanceWorker(2) },
        { workerId: 3, code: makeIssuanceWorker(3) },
        { workerId: 4, code: makeIssuanceWorker(4) },
      ]);

      const outputs = results.map((r) => r.stdout);
      const allowOutputs = outputs.filter((o) => o.includes(":ALLOW:"));
      const denyOutputs = outputs.filter((o) => o.includes(":DENY:"));

      // Exactly ONE worker succeeds in issuing the authorization ID
      expect(allowOutputs).toHaveLength(1);
      // The other THREE workers are denied because the unique ID reservation is atomic
      expect(denyOutputs).toHaveLength(3);
      for (const d of denyOutputs) {
        expect(d).toContain("Transaction authorization ID has already been issued or consumed.");
      }

      // Verify raw database state: exactly ONE row exists
      const verifyDb = new DatabaseSync(dbFile);
      try {
        const countRow = verifyDb
          .prepare(
            "SELECT COUNT(*) as c FROM consumed_authorization_ids WHERE authorization_id = 'auth-race-duplicate-issuance-target'",
          )
          .get() as { c: number };
        expect(countRow.c).toBe(1);
      } finally {
        verifyDb.close();
      }
    });

    it("guarantees database integrity and consistency with no corruption after contention failures", () => {
      const dbFile = databasePath("contention-integrity.sqlite");
      const store = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      try {
        store.getPolicyStore().registerPolicy(basePolicy);
      } finally {
        store.close();
      }

      const rawDb = new DatabaseSync(dbFile);
      try {
        const integrity = rawDb.prepare("PRAGMA integrity_check;").all() as Array<{ integrity_check: string }>;
        expect(integrity).toHaveLength(1);
        expect(integrity[0].integrity_check).toBe("ok");

        const fkCheck = rawDb.prepare("PRAGMA foreign_key_check;").all();
        expect(fkCheck).toHaveLength(0);
      } finally {
        rawDb.close();
      }
    });
  });

  // =========================================================================
  // Objective C: Crash and Recovery Behavior
  // =========================================================================
  describe("Objective C: Crash and Recovery Behavior", () => {
    it("recovers database and rolls back in-flight uncommitted transaction upon child process crash", async () => {
      const dbFile = databasePath("crash-recovery.sqlite");
      const clock = new TestClock(1000);
      const key = createKeypair();

      // Setup initial store with a committed authorization
      const setupStore = new SQLiteAuthorizationStore(dbFile, clock);
      try {
        setupStore.getPolicyStore().registerPolicy(basePolicy);
        setupStore.getKeyStore().registerKey({
          keyId: "key-crash-test",
          publicKey: key.publicKey,
          status: "active",
          validFromSeconds: 1000,
          expiresAtSeconds: 9000,
        });

        const initialIssued = issueSignedTransactionAuthorizationV3(
          setupStore,
          { keyId: "key-crash-test", privateKey: key.privateKey },
          "auth-committed-pre-crash",
          "policy-phase3",
          validRequest,
        );
        expect(initialIssued.decision).toBe("ALLOW");
        expect(setupStore.getHighWaterMark()).toBe(1000);
      } finally {
        setupStore.close();
      }

      // Child worker begins an uncommitted write and then crashes abruptly (process.exit(42) without COMMIT)
      const crashWorkerCode = `
        import { DatabaseSync } from 'node:sqlite';

        const db = new DatabaseSync(${JSON.stringify(dbFile)});
        db.exec('PRAGMA busy_timeout = 5000;');
        db.exec('BEGIN IMMEDIATE;');
        db.exec("INSERT INTO consumed_authorization_ids (authorization_id, state, artifact_version) VALUES ('auth-in-flight-crash', 'issued', 3);");
        db.exec("UPDATE system_clock_state SET high_water_seconds = 9999 WHERE id = 1;");

        // Terminate abruptly without committing or closing database
        process.exit(42);
      `;

      const childRes = await runSubprocess(crashWorkerCode);
      expect(childRes.exitCode).toBe(42);

      // Reopen database with fresh store in main process
      const reopenedStore = new SQLiteAuthorizationStore(dbFile, clock);
      try {
        // Verify PRAGMA integrity
        const rawDb = new DatabaseSync(dbFile);
        try {
          const integrity = rawDb.prepare("PRAGMA integrity_check;").all() as Array<{ integrity_check: string }>;
          expect(integrity[0].integrity_check).toBe("ok");
        } finally {
          rawDb.close();
        }

        // Verify uncommitted crash write was rolled back:
        // 'auth-committed-pre-crash' exists and is intact
        const committedRecord = reopenedStore.getAuthorizationRecord("auth-committed-pre-crash");
        expect(committedRecord).not.toBeNull();
        expect(committedRecord?.state).toBe("issued");

        // 'auth-in-flight-crash' is completely rolled back and does not exist
        const crashedRecord = reopenedStore.getAuthorizationRecord("auth-in-flight-crash");
        expect(crashedRecord).toBeNull();

        // High-water mark was NOT updated to 9999, remains at committed 1000
        expect(reopenedStore.getHighWaterMark()).toBe(1000);

        // Verify reopened store can perform full issuance and consumption without residual lock errors
        const newIssued = issueSignedTransactionAuthorizationV3(
          reopenedStore,
          { keyId: "key-crash-test", privateKey: key.privateKey },
          "auth-post-crash-success",
          "policy-phase3",
          validRequest,
        );
        expect(newIssued.decision).toBe("ALLOW");
        if (newIssued.decision !== "ALLOW") throw new Error("Post-crash issuance failed");

        const newConsumed = consumeSignedTransactionAuthorizationV3(
          reopenedStore,
          newIssued.artifact,
          newIssued.envelope,
          validRequest,
        );
        expect(newConsumed.decision).toBe("ALLOW");
        expect(reopenedStore.getAuthorizationRecord("auth-post-crash-success")?.state).toBe("consumed");
      } finally {
        reopenedStore.close();
      }
    });

    it("ensures reliable cleanup and bounded timeouts so hung workers cannot stall the test suite", async () => {
      // Worker code that enters an infinite sleep
      const hangingWorkerCode = `
        import { sleepSync } from './src/sqlite-transaction.js';
        // Hang indefinitely
        sleepSync(60000);
      `;

      // Subprocess runner configured with a short bounded timeout of 500ms
      await expect(runSubprocess(hangingWorkerCode, 500)).rejects.toThrow(
        "runSubprocess timed out after 500ms.",
      );

      // Verify no leaked child processes remain active
      expect(activeChildren.size).toBe(0);
    });
  });

  // =========================================================================
  // Objective D: Storage Recovery, Fault Injection and Checkpoint Semantics
  // =========================================================================
  describe("Objective D: Storage Recovery, Fault Injection and Checkpoint Semantics", () => {
    it("handles mid-transaction SQLITE_FULL-style failure with clean rollback and uncorrupted state", () => {
      const dbFile = databasePath("fault-mid-transaction.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLiteAuthorizationStore(dbFile, clock);

      try {
        expect(store.issueBound("auth-pre-fault", "sha256:digest1", 3)).toBe(true);
        expect(store.getHighWaterMark()).toBe(1000);

        // Simulate a disk-full failure occurring inside an immediate transaction before COMMIT
        expect(() => {
          withImmediateTransaction(store.getDatabase(), () => {
            store.getDatabase().prepare(
              "INSERT INTO consumed_authorization_ids (authorization_id, state, artifact_version) VALUES (?, 'issued', 3)"
            ).run("auth-mid-fault");
            store.getDatabase().prepare(
              "UPDATE system_clock_state SET high_water_seconds = 2000 WHERE id = 1"
            ).run();

            // Simulate SQLite throwing disk full error during query execution
            throw new Error("sqlite error: database or disk is full (SQLITE_FULL)");
          });
        }).toThrow("sqlite error: database or disk is full (SQLITE_FULL)");

        // Rollback occurred cleanly:
        // High-water mark remains 1000, not 2000
        expect(store.getHighWaterMark()).toBe(1000);
        // The uncommitted record does not exist
        expect(store.getAuthorizationRecord("auth-mid-fault")).toBeNull();
        // The pre-fault record is intact
        expect(store.getAuthorizationRecord("auth-pre-fault")?.state).toBe("issued");
        // Store is NOT tainted because rollback succeeded before COMMIT
        expect(store.isTainted()).toBe(false);

        // Subsequent valid write operations succeed
        expect(store.issueBound("auth-post-fault-success", "sha256:digest2", 3)).toBe(true);
        expect(store.getAuthorizationRecord("auth-post-fault-success")?.state).toBe("issued");
      } finally {
        store.close();
      }
    });

    it("handles ambiguous COMMIT failure (SQLITE_IOERR) with fail-closed taint propagation and connection closure", () => {
      const dbFile = databasePath("fault-uncertain-commit.sqlite");
      const clock = new TestClock(1000);
      let fatalTaintReason: string | undefined;

      const store = new SQLiteAuthorizationStore(dbFile, clock, {
        onFatalTaint: (reason) => {
          fatalTaintReason = reason;
        },
      });

      const policyStore = store.getPolicyStore();
      const keyStore = store.getKeyStore();

      try {
        expect(store.issueBound("auth-prior-commit", "sha256:digest", 3)).toBe(true);

        // Monkey-patch db.exec to simulate SQLITE_IOERR during COMMIT
        const rawDb = store.getDatabase();
        const originalExec = rawDb.exec.bind(rawDb);
        rawDb.exec = (sql: string) => {
          if (sql.includes("COMMIT")) {
            throw new Error("sqlite error: disk I/O error (SQLITE_IOERR)");
          }
          return originalExec(sql);
        };

        // Calling advanceHighWaterMark executes COMMIT which throws our simulated IOERR
        expect(() => {
          store.advanceHighWaterMark(1050);
        }).toThrow("sqlite error: disk I/O error (SQLITE_IOERR)");

        // Store and ClockGuard must be permanently tainted
        expect(store.isTainted()).toBe(true);
        expect(store.getTaintedReason()).toContain("Commit failure with uncertain outcome");
        expect(fatalTaintReason).toContain("Commit failure with uncertain outcome");
        expect(store.getClockGuard().getState()).toBe("TRIPPED_CLOSED");

        // Derived PolicyStore and KeyStore share the tainted state
        expect(policyStore.isTainted()).toBe(true);
        expect(keyStore.isTainted()).toBe(true);

        // Every subsequent operation fails closed immediately with tainted error
        expect(() => store.getAuthorizationRecord("auth-prior-commit")).toThrow(
          "database connection is tainted and unusable"
        );
        expect(() => store.issueBound("auth-after-taint", "sha256:dummy", 3)).toThrow(
          "database connection is tainted and unusable"
        );
        expect(() => store.consumeBound("auth-prior-commit", "sha256:dummy", 3)).toThrow(
          "database connection is tainted and unusable"
        );
        expect(() => store.cancelAuthorization("auth-prior-commit")).toThrow(
          "database connection is tainted and unusable"
        );
        expect(() => store.advanceHighWaterMark(1060)).toThrow(
          "database connection is tainted and unusable"
        );
        expect(() => store.getDatabase()).toThrow(
          "database connection is tainted and unusable"
        );
        expect(() => policyStore.getPolicy("any")).toThrow(
          "database connection is tainted and unusable"
        );
        expect(() => keyStore.getKey("any")).toThrow(
          "database connection is tainted and unusable"
        );
      } finally {
        try { store.close(); } catch {}
      }

      // Reopen with fresh, separate store to verify database file was not corrupted
      const freshStore = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      try {
        expect(freshStore.checkIntegrity()).toBe(true);
        expect(freshStore.getAuthorizationRecord("auth-prior-commit")?.state).toBe("issued");
      } finally {
        freshStore.close();
      }
    });

    it("verifies checkpoint semantics and safe busy handling under concurrent reader contention", () => {
      const dbFile = databasePath("checkpoint-contention.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLiteAuthorizationStore(dbFile, {
        clock,
        allowLegacyArtifactVersions: true,
        busyTimeoutMs: 250,
      });

      try {
        // Issue initial batch of authorizations
        for (let i = 0; i < 5; i++) {
          expect(store.issueBound(`auth-cp-${i}`, `sha256:digest-${i}`, 3)).toBe(true);
        }
        expect(store.checkIntegrity()).toBe(true);

        // Open a separate reader connection that begins an active read transaction
        const readerDb = new DatabaseSync(dbFile);
        try {
          readerDb.exec("BEGIN;");
          readerDb.prepare("SELECT * FROM consumed_authorization_ids;").all();

          // Write more authorizations while reader is active, populating additional WAL frames
          for (let i = 5; i < 10; i++) {
            expect(store.issueBound(`auth-cp-${i}`, `sha256:digest-${i}`, 3)).toBe(true);
          }

          // Checkpoint with PASSIVE mode succeeds without blocking the reader
          const passiveResult = store.checkpoint("PASSIVE");
          expect(passiveResult.busy).toBe(false);
          expect(passiveResult.logFrames).toBeGreaterThan(0);

          // Checkpoint with TRUNCATE mode returns busy = true because the reader holds a read lock on earlier frames
          const truncateResult = store.checkpoint("TRUNCATE");
          expect(truncateResult.busy).toBe(true);
          expect(truncateResult.logFrames).toBeGreaterThan(0);

          // Database integrity remains intact despite contention
          expect(store.checkIntegrity()).toBe(true);

          // Commit and close reader
          readerDb.exec("COMMIT;");
        } finally {
          readerDb.close();
        }

        // Once the reader releases its read transaction, TRUNCATE completes and resets log frames to 0
        const postReaderResult = store.checkpoint("TRUNCATE");
        expect(postReaderResult.busy).toBe(false);
        expect(postReaderResult.logFrames).toBe(0);
        expect(postReaderResult.checkpointedFrames).toBe(0);
        expect(store.checkIntegrity()).toBe(true);

        // Reopen with fresh store and verify all 10 authorizations are present and consumable
        const verifyStore = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
        try {
          expect(verifyStore.checkIntegrity()).toBe(true);
          for (let i = 0; i < 10; i++) {
            expect(verifyStore.getAuthorizationRecord(`auth-cp-${i}`)?.state).toBe("issued");
          }
        } finally {
          verifyStore.close();
        }
      } finally {
        store.close();
      }
    }, 15000);

    it("verifies WAL growth and structural integrity under stress cycles", () => {
      const dbFile = databasePath("wal-stress-integrity.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLiteAuthorizationStore(dbFile, clock);

      try {
        const policyStore = store.getPolicyStore();
        const keyStore = store.getKeyStore();
        const { publicKey } = createKeypair();

        policyStore.registerPolicy(basePolicy);
        keyStore.registerKey({
          keyId: "stress-key-01",
          publicKey,
          status: "active",
        });

        // Run multi-phase mutation stress cycle
        for (let cycle = 0; cycle < 15; cycle++) {
          const authId = `stress-auth-${cycle}`;
          expect(store.issueBound(authId, `sha256:stress-${cycle}`, 3)).toBe(true);
          expect(store.consumeBound(authId, `sha256:stress-${cycle}`, 3)).toBe(true);
        }

        // Integrity check passes during high WAL activity
        expect(store.checkIntegrity()).toBe(true);
        expect(policyStore.checkIntegrity()).toBe(true);
        expect(keyStore.checkIntegrity()).toBe(true);

        // Checkpoint consolidates WAL frames back into main database file
        const cp = store.checkpoint("FULL");
        expect(cp.busy).toBe(false);

        // Final truncate check
        const trunc = store.checkpoint("TRUNCATE");
        expect(trunc.busy).toBe(false);
        expect(trunc.logFrames).toBe(0);
        expect(store.checkIntegrity()).toBe(true);
      } finally {
        store.close();
      }
    });
  });
});
