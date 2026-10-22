import { fork } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
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
        execArgv: ["--import", "tsx/esm"],
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
});
