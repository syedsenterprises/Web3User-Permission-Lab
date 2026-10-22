import { fork } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { SQLiteAuthorizationStore } from "../src/authorization-store.js";
import { TestClock } from "../src/clock.js";
import { SQLiteKeyStore } from "../src/key-store.js";
import { type DemoPolicy } from "../src/policy.js";
import { SQLitePolicyStore } from "../src/policy-store.js";

describe("Milestone 6.2 Phase 2: Genuine Multi-Process Concurrency Governance", () => {
  let directory: string | undefined;

  function databasePath(filename: string): string {
    directory ??= mkdtempSync(join(tmpdir(), "web3user-concurrency-"));
    return join(directory, filename);
  }

  afterEach(() => {
    if (directory) {
      rmSync(directory, { recursive: true, force: true });
      directory = undefined;
    }
  });

  const basePolicy: DemoPolicy = {
    version: 1,
    policyId: "policy-concurrent-race",
    allowedTarget: "0x1111111111111111111111111111111111111111",
    allowedRecipient: "0x2222222222222222222222222222222222222222",
    allowedSelector: "0xa9059cbb",
    maxAmount: "1000",
    validFrom: 1000,
    expiresAt: 9000,
    revoked: false,
  };

  function runSubprocess(code: string): Promise<{ exitCode: number | null; stdout: string; stderr: string }> {
    return new Promise((resolvePromise) => {
      let stdout = "";
      let stderr = "";
      const child = fork("-e", [code], {
        execArgv: ["--input-type=module", "--import", "tsx/esm"],
        silent: true,
      });

      child.stdout?.on("data", (d) => {
        stdout += d.toString();
      });
      child.stderr?.on("data", (d) => {
        stderr += d.toString();
      });
      child.on("exit", (code) => {
        resolvePromise({ exitCode: code, stdout, stderr });
      });
    });
  }

  // 1. Genuine concurrent startup / initialization contention across distinct OS processes
  it("handles overlapping concurrent initialization across distinct OS processes without data loss", async () => {
    const dbFile = databasePath("concurrent-init.sqlite");

    // Seed database with an unmigrated table
    const initDb = new DatabaseSync(dbFile);
    initDb.exec(`
      CREATE TABLE consumed_authorization_ids (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT,
        state TEXT NOT NULL DEFAULT 'consumed',
        consumed_at TEXT,
        artifact_version INTEGER NOT NULL DEFAULT 1
      );
      INSERT INTO consumed_authorization_ids VALUES ('auth-seed-001', 'sha256:seed', 'consumed', '2026-10-22', 1);
    `);
    initDb.close();

    // Spawn 4 separate OS child processes concurrently opening the database
    const procCode = `
      import { SQLiteAuthorizationStore } from './src/authorization-store.js';
      import { TestClock } from './src/clock.js';
      const store = new SQLiteAuthorizationStore(${JSON.stringify(dbFile)}, new TestClock(1000));
      store.close();
      process.exit(0);
    `;

    const results = await Promise.all([
      runSubprocess(procCode),
      runSubprocess(procCode),
      runSubprocess(procCode),
      runSubprocess(procCode),
    ]);

    for (const r of results) {
      expect(r.exitCode).toBe(0);
    }

    // Verify canonical database schema and record preservation
    const verifyDb = new DatabaseSync(dbFile);
    try {
      const tables = (verifyDb.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>).map((t) => t.name);
      expect(tables).toContain("consumed_authorization_ids");
      expect(tables).not.toContain("consumed_authorization_ids_v3");
      expect(tables).toContain("policies");
      expect(tables).toContain("policy_revisions");
      expect(tables).toContain("issuer_keys");

      const rows = verifyDb.prepare("SELECT * FROM consumed_authorization_ids").all() as Array<Record<string, unknown>>;
      expect(rows).toHaveLength(1);
      expect(rows[0].authorization_id).toBe("auth-seed-001");
      expect(rows[0].state).toBe("consumed");
    } finally {
      verifyDb.close();
    }
  }, 15000);

  // 2. Real concurrent policy update race: multiple processes racing on expected revision
  it("rejects stale revisions in real concurrent policy updates across separate processes", async () => {
    const dbFile = databasePath("concurrent-policy.sqlite");
    const mainStore = new SQLitePolicyStore(dbFile, new TestClock(1000));
    mainStore.registerPolicy(basePolicy); // Revision 1
    mainStore.close();

    // 4 concurrent processes all attempt to update Revision 1 to Revision 2
    const makeWorkerCode = (procId: number) => `
      import { SQLitePolicyStore } from './src/policy-store.js';
      import { TestClock } from './src/clock.js';
      const store = new SQLitePolicyStore(${JSON.stringify(dbFile)}, new TestClock(1000));
      try {
        const policy = ${JSON.stringify(basePolicy)};
        policy.maxAmount = ${JSON.stringify(String(procId * 1000))};
        store.updatePolicy(policy, 1);
        console.log('SUCCESS:' + ${procId});
      } catch (err) {
        console.log('FAILED:' + ${procId} + ':' + err.message);
      } finally {
        store.close();
      }
      process.exit(0);
    `;

    const results = await Promise.all([
      runSubprocess(makeWorkerCode(1)),
      runSubprocess(makeWorkerCode(2)),
      runSubprocess(makeWorkerCode(3)),
      runSubprocess(makeWorkerCode(4)),
    ]);

    const outputs = results.map((r) => r.stdout);
    const successes = outputs.filter((o) => o.includes("SUCCESS:"));
    const failures = outputs.filter((o) => o.includes("FAILED:"));

    // Exactly one process succeeds in transitioning Revision 1 -> Revision 2
    expect(successes).toHaveLength(1);
    // The other 3 processes fail due to stale revision
    expect(failures).toHaveLength(3);
    for (const f of failures) {
      expect(f).toContain("Stale revision for policy 'policy-concurrent-race'");
    }

    // Verify persistent state in database
    const verifyStore = new SQLitePolicyStore(dbFile, new TestClock(1000));
    try {
      const policy = verifyStore.getPolicy("policy-concurrent-race");
      expect(policy?.revision).toBe(2);

      const revisions = verifyStore.listPolicyRevisions("policy-concurrent-race");
      expect(revisions).toHaveLength(2);
      expect(revisions[0].revision).toBe(1);
      expect(revisions[1].revision).toBe(2);
    } finally {
      verifyStore.close();
    }
  }, 15000);

  // 3. Real concurrent key retirement and revocation: terminal state enforcement
  it("enforces irreversible revocation under concurrent processes racing to retire and revoke", async () => {
    const dbFile = databasePath("concurrent-key.sqlite");
    const { publicKey } = generateKeyPairSync("ed25519");
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();

    const mainStore = new SQLiteKeyStore(dbFile, new TestClock(1000));
    mainStore.registerKey({
      keyId: "race-key-001",
      publicKey,
      status: "active",
    });
    mainStore.close();

    // Process A attempts retirement at t=1200
    const retireProc = `
      import { SQLiteKeyStore } from './src/key-store.js';
      import { TestClock } from './src/clock.js';
      const store = new SQLiteKeyStore(${JSON.stringify(dbFile)}, new TestClock(1200));
      try {
        store.retireKey('race-key-001', 1200);
        console.log('RETIRED');
      } catch (err) {
        console.log('RETIRE_ERR:' + err.message);
      } finally {
        store.close();
      }
      process.exit(0);
    `;

    // Process B attempts revocation at t=1300
    const revokeProc = `
      import { SQLiteKeyStore } from './src/key-store.js';
      import { TestClock } from './src/clock.js';
      const store = new SQLiteKeyStore(${JSON.stringify(dbFile)}, new TestClock(1300));
      try {
        store.revokeKey('race-key-001', 1300);
        console.log('REVOKED');
      } catch (err) {
        console.log('REVOKE_ERR:' + err.message);
      } finally {
        store.close();
      }
      process.exit(0);
    `;

    const [retireResult, revokeResult] = await Promise.all([
      runSubprocess(retireProc),
      runSubprocess(revokeProc),
    ]);

    // Reopen with main store
    const verifyStore = new SQLiteKeyStore(dbFile, new TestClock(1500));
    try {
      const status = verifyStore.getKeyStatus("race-key-001");
      // Because revocation was run, final status must either be revoked
      // or if retire ran first then revoke ran, status is revoked.
      // If revoke ran first, retire would throw or fail.
      expect(status).toBe("revoked");
      expect(verifyStore.getKey("race-key-001")?.status).toBe("revoked");

      // Verify that no subsequent process can un-revoke or retire it
      expect(() => verifyStore.retireKey("race-key-001", 1600)).toThrow(
        "Cannot retire revoked key 'race-key-001'; revocation is permanent."
      );
    } finally {
      verifyStore.close();
    }
  }, 15000);

  // 4. Genuine multi-process V3 issuance and consumption contention
  it("handles concurrent V3 issuance and consumption across distinct OS processes without data loss or corruption", async () => {
    const dbFile = databasePath("concurrent-v3.sqlite");
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

    // Setup policy and key in main process
    const mainStore = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
    mainStore.getPolicyStore().registerPolicy(basePolicy);
    mainStore.getKeyStore().registerKey({
      keyId: "key-concurrent-v3",
      publicKey,
      status: "active",
      validFromSeconds: 1000,
      expiresAtSeconds: 9000,
    });
    mainStore.close();

    const makeWorker = (workerId: number) => `
      import { createPrivateKey } from 'node:crypto';
      import { SQLiteAuthorizationStore } from './src/authorization-store.js';
      import { TestClock } from './src/clock.js';
      import {
        issueSignedTransactionAuthorizationV3,
        consumeSignedTransactionAuthorizationV3,
      } from './src/authorization-lifecycle.js';

      const store = new SQLiteAuthorizationStore(${JSON.stringify(dbFile)}, new TestClock(1000));
      const privKey = createPrivateKey(${JSON.stringify(privateKeyPem)});
      const authId = 'auth-v3-worker-' + ${workerId};
      const req = {
        chainId: '1',
        sender: '0x3333333333333333333333333333333333333333',
        target: '0x1111111111111111111111111111111111111111',
        calldata: '0xa9059cbb' + '0000000000000000000000002222222222222222222222222222222222222222' + '0000000000000000000000000000000000000000000000000000000000000064',
        value: '0',
      };

      const issued = issueSignedTransactionAuthorizationV3(
        store,
        { keyId: 'key-concurrent-v3', privateKey: privKey },
        authId,
        'policy-concurrent-race',
        req,
      );

      if (issued.decision !== 'ALLOW') {
        console.error('ISSUE_FAIL:' + JSON.stringify(issued.reasons));
        process.exit(1);
      }

      const consumed = consumeSignedTransactionAuthorizationV3(
        store,
        issued.artifact,
        issued.envelope,
        req,
      );

      if (consumed.decision !== 'ALLOW') {
        console.error('CONSUME_FAIL:' + JSON.stringify(consumed.reasons));
        process.exit(1);
      }

      store.close();
      console.log('SUCCESS:' + ${workerId});
      process.exit(0);
    `;

    const results = await Promise.all([
      runSubprocess(makeWorker(1)),
      runSubprocess(makeWorker(2)),
      runSubprocess(makeWorker(3)),
      runSubprocess(makeWorker(4)),
    ]);

    for (const r of results) {
      if (r.exitCode !== 0) {
        console.error("Worker error:", r.stderr, r.stdout);
      }
      expect(r.exitCode).toBe(0);
      expect(r.stdout).toContain("SUCCESS:");
    }

    // Verify all 4 authorizations are consumed in database
    const verifyStore = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
    try {
      for (let i = 1; i <= 4; i++) {
        const record = verifyStore.getAuthorizationRecord(`auth-v3-worker-${i}`);
        expect(record).not.toBeNull();
        expect(record?.state).toBe("consumed");
        expect(record?.artifactVersion).toBe(3);
      }
    } finally {
      verifyStore.close();
    }
  }, 25000);
});
