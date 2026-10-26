import { fork } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { copyFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import {
  consumeSignedTransactionAuthorizationV3,
  issueSignedTransactionAuthorizationV3,
} from "../src/authorization-lifecycle.js";
import { SQLiteAuthorizationStore } from "../src/authorization-store.js";
import {
  ClockGuard,
  TestClock,
  TestMonotonicClock,
} from "../src/clock.js";
import { Web3UserEngine } from "../src/engine.js";
import {
  calculateBudgetWindowStart,
  calculateBudgetWindowEnd,
  decodeTransfer,
  evaluate,
  isUint256String,
  normalizeDemoPolicy,
  type DemoPolicy,
} from "../src/policy.js";
import { decodeTransfer as demoDecodeTransfer } from "../website-preview/js/evaluator.js";
import {
  createTransactionEnvelope,
  type TransactionRequest,
} from "../src/transaction-envelope.js";

const MAX_UINT256 = (1n << 256n) - 1n;

describe("Milestone 9 — Phase 2: Adversarial Security Test Suite", () => {
  const openStores: SQLiteAuthorizationStore[] = [];
  const openEngines: Web3UserEngine[] = [];
  const createdDirs: string[] = [];

  function createTestDbPath(prefix = "web3user-adv-"): string {
    const dir = mkdtempSync(join(tmpdir(), prefix));
    createdDirs.push(dir);
    return join(dir, "adv-test.sqlite");
  }

  afterEach(() => {
    while (openStores.length > 0) {
      try {
        openStores.pop()?.close();
      } catch {}
    }
    while (openEngines.length > 0) {
      try {
        openEngines.pop()?.close();
      } catch {}
    }
    while (createdDirs.length > 0) {
      const dir = createdDirs.pop();
      if (dir) {
        try {
          rmSync(dir, { recursive: true, force: true });
        } catch {}
      }
    }
  });

  function createKeypair() {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    return { publicKey, privateKey, pem };
  }

  function encodeCalldata(recipient: string, amount: bigint): string {
    const selector = "0xa9059cbb";
    const recipientWord = recipient.slice(2).toLowerCase().padStart(64, "0");
    const amountWord = amount.toString(16).padStart(64, "0");
    return `${selector}${recipientWord}${amountWord}`;
  }

  const TARGET = "0x1111111111111111111111111111111111111111";
  const RECIPIENT = "0x2222222222222222222222222222222222222222";

  function setupStores(dbFile: string, clockSeconds = 1000, maxStep = 200_000) {
    const clock = new TestClock(clockSeconds);
    const clockGuard = new ClockGuard(clock, clock, {
      maxStartupForwardGapSeconds: maxStep,
      maxForwardStepSeconds: maxStep,
      maxBackwardStepSeconds: maxStep,
      maxAbsoluteDivergenceSeconds: maxStep,
      maxAnchorLifetimeSeconds: 1_000_000,
    });
    const authStore = new SQLiteAuthorizationStore(dbFile, { clock, clockGuard });
    openStores.push(authStore);
    const policyStore = authStore.getPolicyStore();
    const keyStore = authStore.getKeyStore();
    return { authStore, policyStore, keyStore, clock, clockGuard };
  }

  function issueAllow(
    store: SQLiteAuthorizationStore,
    signer: { keyId: string; privateKey: any },
    authId: string,
    policyId: string,
    req: TransactionRequest,
    options?: { ttlSeconds?: number },
  ) {
    const res = issueSignedTransactionAuthorizationV3(store, signer, authId, policyId, req, options);
    expect(res.decision).toBe("ALLOW");
    if (res.decision !== "ALLOW") {
      throw new Error(`Unexpected issuance denial: ${JSON.stringify(res.reasons)}`);
    }
    return res;
  }

  // =========================================================================
  // Scope 1: Exact Hourly and Daily Budget-Window Rollover Boundaries
  // =========================================================================
  describe("Scope 1: Exact Hourly & Daily Budget-Window Rollover Boundaries", () => {
    it("enforces exact second boundaries at 3599 and 3600 for hourly budget windows", () => {
      const dbFile = createTestDbPath("m9-scope1-hourly-");
      const { authStore, policyStore, keyStore, clock } = setupStores(dbFile, 3500);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-boundary-1",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      const hourlyPolicy: DemoPolicy = {
        version: 1,
        policyId: "pol-hourly-boundary",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: "150",
        },
      };
      policyStore.registerPolicy(hourlyPolicy);

      // Auth 1: 90 units at t = 3598
      clock.set(3598);
      const req1: TransactionRequest = {
        chainId: "1",
        sender: TARGET,
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 90n),
        value: "0",
      };
      const issue1 = issueAllow(
        authStore,
        { keyId: "k-boundary-1", privateKey },
        "auth-h-1",
        hourlyPolicy.policyId,
        req1,
        { ttlSeconds: 3000 },
      );
      expect(issue1.decision).toBe("ALLOW");

      const env1 = createTransactionEnvelope(req1);
      if (!env1.ok) throw new Error("env1 failed");
      const consume1 = consumeSignedTransactionAuthorizationV3(
        authStore,
        issue1.artifact,
        env1.envelope,
        req1,
      );
      expect(consume1.decision).toBe("ALLOW");

      // Verify accumulator at window 0..3600: spent 90
      let accum0 = authStore.getPolicyBudgetAccumulator(hourlyPolicy.policyId, "HOURLY", 0);
      expect(accum0?.spentAmount).toBe("90");

      // Auth 2: 60 units at t = 3599 (exact last second of first hour)
      clock.set(3599);
      const req2: TransactionRequest = {
        chainId: "1",
        sender: TARGET,
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 60n),
        value: "0",
      };
      const issue2 = issueAllow(
        authStore,
        { keyId: "k-boundary-1", privateKey },
        "auth-h-2",
        hourlyPolicy.policyId,
        req2,
        { ttlSeconds: 3000 },
      );
      expect(issue2.decision).toBe("ALLOW");

      const env2 = createTransactionEnvelope(req2);
      if (!env2.ok) throw new Error("env2 failed");
      const consume2 = consumeSignedTransactionAuthorizationV3(
        authStore,
        issue2.artifact,
        env2.envelope,
        req2,
      );
      expect(consume2.decision).toBe("ALLOW");

      // Window 0..3600 is now exactly full at 150
      accum0 = authStore.getPolicyBudgetAccumulator(hourlyPolicy.policyId, "HOURLY", 0);
      expect(accum0?.spentAmount).toBe("150");

      // Auth 3: 10 units at t = 3599 -> MUST BE DENIED (150 + 10 > 150)
      const req3: TransactionRequest = {
        chainId: "1",
        sender: TARGET,
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 10n),
        value: "0",
      };
      const issue3 = issueAllow(
        authStore,
        { keyId: "k-boundary-1", privateKey },
        "auth-h-3",
        hourlyPolicy.policyId,
        req3,
        { ttlSeconds: 3000 },
      );
      expect(issue3.decision).toBe("ALLOW");

      const env3 = createTransactionEnvelope(req3);
      if (!env3.ok) throw new Error("env3 failed");
      const consume3Denied = consumeSignedTransactionAuthorizationV3(
        authStore,
        issue3.artifact,
        env3.envelope,
        req3,
      );
      expect(consume3Denied.decision).toBe("DENY");
      expect(consume3Denied.reasons[0]).toContain("Cumulative spending budget exceeded for hourly window");
      expect(consume3Denied.reasons[0]).toContain("available: 0");

      // Verify Auth 3 remains in state 'issued'
      const record3 = authStore.getAuthorizationRecord("auth-h-3");
      expect(record3?.state).toBe("issued");
      expect(accum0?.spentAmount).toBe("150");

      // Rollover: advance clock to t = 3600 (exact first second of hour 1: window 3600..7200)
      clock.set(3600);

      // Retry Auth 3 at t = 3600 -> MUST SUCCEED in new window!
      const env3Retry = createTransactionEnvelope(req3);
      if (!env3Retry.ok) throw new Error("env3Retry failed");
      const consume3Success = consumeSignedTransactionAuthorizationV3(
        authStore,
        issue3.artifact,
        env3Retry.envelope,
        req3,
      );
      expect(consume3Success.decision).toBe("ALLOW");

      // Verify accumulators: window 0..3600 remains 150, window 3600..7200 is 10
      accum0 = authStore.getPolicyBudgetAccumulator(hourlyPolicy.policyId, "HOURLY", 0);
      expect(accum0?.spentAmount).toBe("150");
      const accum3600 = authStore.getPolicyBudgetAccumulator(hourlyPolicy.policyId, "HOURLY", 3600);
      expect(accum3600?.spentAmount).toBe("10");

      // Auth 4: 100 units at t = 7199 (exact last second of second hour)
      clock.set(7199);
      const req4: TransactionRequest = {
        chainId: "1",
        sender: TARGET,
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 100n),
        value: "0",
      };
      const issue4 = issueAllow(
        authStore,
        { keyId: "k-boundary-1", privateKey },
        "auth-h-4",
        hourlyPolicy.policyId,
        req4,
        { ttlSeconds: 3000 },
      );
      const env4 = createTransactionEnvelope(req4);
      if (!env4.ok) throw new Error("env4 failed");
      const consume4 = consumeSignedTransactionAuthorizationV3(
        authStore,
        issue4.artifact,
        env4.envelope,
        req4,
      );
      expect(consume4.decision).toBe("ALLOW");

      // Second hour accumulator is now 110
      const accumSecondHour = authStore.getPolicyBudgetAccumulator(hourlyPolicy.policyId, "HOURLY", 3600);
      expect(accumSecondHour?.spentAmount).toBe("110");

      // Rollover into third hour at t = 7200
      clock.set(7200);
      const engine = new Web3UserEngine({
        databasePath: dbFile,
        clock: { clock, maxStartupForwardGapSeconds: 200_000 },
      });
      openEngines.push(engine);

      const status3599 = engine.policies.getBudgetStatus(hourlyPolicy.policyId, 3599);
      expect(status3599?.windowStart).toBe(0);
      expect(status3599?.windowEnd).toBe(3600);
      expect(status3599?.spentAmount).toBe("150");
      expect(status3599?.remainingAmount).toBe("0");

      const status3600 = engine.policies.getBudgetStatus(hourlyPolicy.policyId, 3600);
      expect(status3600?.windowStart).toBe(3600);
      expect(status3600?.windowEnd).toBe(7200);
      expect(status3600?.spentAmount).toBe("110");
      expect(status3600?.remainingAmount).toBe("40");

      const status7200 = engine.policies.getBudgetStatus(hourlyPolicy.policyId, 7200);
      expect(status7200?.windowStart).toBe(7200);
      expect(status7200?.windowEnd).toBe(10800);
      expect(status7200?.spentAmount).toBe("0");
      expect(status7200?.remainingAmount).toBe("150");
    });

    it("enforces exact second boundaries at 86399 and 86400 for daily budget windows", () => {
      const dbFile = createTestDbPath("m9-scope1-daily-");
      const { authStore, policyStore, keyStore, clock } = setupStores(dbFile, 86000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-boundary-daily",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 200000,
      });

      const dailyPolicy: DemoPolicy = {
        version: 1,
        policyId: "pol-daily-boundary",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "1000",
        validFrom: 0,
        expiresAt: 200000,
        revoked: false,
        budget: {
          window: "DAILY",
          maxCumulativeAmount: "1000",
        },
      };
      policyStore.registerPolicy(dailyPolicy);

      // Spend 1000 at t = 86399 (last second of day 0)
      clock.set(86399);
      const req1: TransactionRequest = {
        chainId: "1",
        sender: TARGET,
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 1000n),
        value: "0",
      };
      const issue1 = issueAllow(
        authStore,
        { keyId: "k-boundary-daily", privateKey },
        "auth-d-1",
        dailyPolicy.policyId,
        req1,
        { ttlSeconds: 5000 },
      );
      const env1 = createTransactionEnvelope(req1);
      if (!env1.ok) throw new Error("env1 failed");
      const consume1 = consumeSignedTransactionAuthorizationV3(
        authStore,
        issue1.artifact,
        env1.envelope,
        req1,
      );
      expect(consume1.decision).toBe("ALLOW");

      // Verify Day 0 spent is 1000
      const accumDay0 = authStore.getPolicyBudgetAccumulator(dailyPolicy.policyId, "DAILY", 0);
      expect(accumDay0?.spentAmount).toBe("1000");

      // At t = 86399, another spend of 100 is DENIED
      const req2: TransactionRequest = {
        chainId: "1",
        sender: TARGET,
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 100n),
        value: "0",
      };
      const issue2 = issueAllow(
        authStore,
        { keyId: "k-boundary-daily", privateKey },
        "auth-d-2",
        dailyPolicy.policyId,
        req2,
        { ttlSeconds: 5000 },
      );
      const env2 = createTransactionEnvelope(req2);
      if (!env2.ok) throw new Error("env2 failed");
      const consume2Denied = consumeSignedTransactionAuthorizationV3(
        authStore,
        issue2.artifact,
        env2.envelope,
        req2,
      );
      expect(consume2Denied.decision).toBe("DENY");
      expect(consume2Denied.reasons[0]).toContain("Cumulative spending budget exceeded for daily window");

      // Day 1: clock advances to t = 86400 (exact first second of day 1)
      clock.set(86400);

      // Retry Auth 2 at t = 86400 -> ALLOWED!
      const env2Retry = createTransactionEnvelope(req2);
      if (!env2Retry.ok) throw new Error("env2Retry failed");
      const consume2Allowed = consumeSignedTransactionAuthorizationV3(
        authStore,
        issue2.artifact,
        env2Retry.envelope,
        req2,
      );
      expect(consume2Allowed.decision).toBe("ALLOW");

      const accumDay1 = authStore.getPolicyBudgetAccumulator(dailyPolicy.policyId, "DAILY", 86400);
      expect(accumDay1?.spentAmount).toBe("100");
      expect(authStore.getPolicyBudgetAccumulator(dailyPolicy.policyId, "DAILY", 0)?.spentAmount).toBe("1000");
    });
  });

  // =========================================================================
  // Scope 2: Multi-Process SQLite Write Contention, Busy Timeouts & Safe Failure
  // =========================================================================
  describe("Scope 2: Multi-Process SQLite Write Contention & Safe Failure Behavior", () => {
    it("fails closed cleanly with busy-timeout reason when contention exceeds retry budget without corrupting state", async () => {
      const dbFile = createTestDbPath("m9-scope2-contention-");
      const { authStore, policyStore, keyStore } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-contention-1",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      const policy: DemoPolicy = {
        version: 1,
        policyId: "pol-contention-test",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "500",
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: "1000",
        },
      };
      policyStore.registerPolicy(policy);

      const req: TransactionRequest = {
        chainId: "1",
        sender: TARGET,
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 100n),
        value: "0",
      };

      const issue = issueAllow(
        authStore,
        { keyId: "k-contention-1", privateKey },
        "auth-contention-worker",
        policy.policyId,
        req,
        { ttlSeconds: 5000 },
      );
      expect(issue.decision).toBe("ALLOW");
      authStore.close();

      // Launch Worker 1 (Lock Holder): acquires BEGIN IMMEDIATE and holds it until parent sends RELEASE
      // Launch Worker 2 (Consumer): configures low busyTimeoutMs = 10ms and attempts to consume.
      // Worker 2 will exceed its contention budget and return DENY with busy reason.
      const lockHolderScript = `
        import { DatabaseSync } from 'node:sqlite';
        const db = new DatabaseSync(${JSON.stringify(dbFile)});
        db.exec("PRAGMA busy_timeout = 5000;");

        process.on('message', (msg) => {
          if (msg === 'ACQUIRE_LOCK') {
            db.exec("BEGIN IMMEDIATE;");
            if (process.send) process.send({ type: 'LOCKED' });
          } else if (msg === 'RELEASE') {
            try {
              db.exec("ROLLBACK;");
              db.close();
            } catch {}
            process.exit(0);
          }
        });

        if (process.send) process.send({ type: 'HOLDER_READY' });

        // Fail-safe watchdog
        setTimeout(() => {
          try { db.exec("ROLLBACK;"); db.close(); } catch {}
          process.exit(1);
        }, 15000).unref();
      `;

      const consumerScript = `
        import { SQLiteAuthorizationStore } from './src/authorization-store.js';
        import { TestClock } from './src/clock.js';
        import { consumeSignedTransactionAuthorizationV3 } from './src/authorization-lifecycle.js';
        import { createTransactionEnvelope } from './src/transaction-envelope.js';

        const store = new SQLiteAuthorizationStore(${JSON.stringify(dbFile)}, {
          clock: new TestClock(1050),
          busyTimeoutMs: 10,
        });

        const artifact = ${JSON.stringify(issue.artifact)};
        const req = ${JSON.stringify(req)};
        const env = createTransactionEnvelope(req);
        if (!env.ok) {
          store.close();
          process.exit(1);
        }

        process.on('message', (msg) => {
          if (msg === 'START_CONSUME') {
            try {
              const res = consumeSignedTransactionAuthorizationV3(store, artifact, env.envelope, req);
              console.log('RESULT:' + JSON.stringify(res));
              store.close();
              process.exit(0);
            } catch (err) {
              console.error('ERROR:' + (err instanceof Error ? err.message : String(err)));
              try { store.close(); } catch {}
              process.exit(2);
            }
          }
        });

        if (process.send) process.send({ type: 'CONSUMER_READY' });
      `;

      const childHolder = fork("-e", [lockHolderScript], {
        execArgv: ["--input-type=module", "--import", "tsx/esm"],
        silent: true,
      });

      const childConsumer = fork("-e", [consumerScript], {
        execArgv: ["--input-type=module", "--import", "tsx/esm"],
        silent: true,
      });

      let consumerStdout = "";
      let consumerStderr = "";
      childConsumer.stdout?.on("data", (d) => { consumerStdout += d.toString(); });
      childConsumer.stderr?.on("data", (d) => { consumerStderr += d.toString(); });

      await new Promise<void>((resolvePromise, rejectPromise) => {
        let holderReady = false;
        let consumerReady = false;

        childHolder.on("message", (msg: any) => {
          if (msg?.type === "HOLDER_READY") {
            holderReady = true;
            if (consumerReady) {
              childHolder.send("ACQUIRE_LOCK");
            }
          } else if (msg?.type === "LOCKED") {
            childConsumer.send("START_CONSUME");
          }
        });

        childConsumer.on("message", (msg: any) => {
          if (msg?.type === "CONSUMER_READY") {
            consumerReady = true;
            if (holderReady) {
              childHolder.send("ACQUIRE_LOCK");
            }
          }
        });

        childConsumer.on("exit", (code) => {
          try { childHolder.send("RELEASE"); } catch {}
          if (code === 0) resolvePromise();
          else rejectPromise(new Error(`Consumer exited with code ${code}. Stderr: ${consumerStderr}`));
        });
      });

      // Consumer output must report DENY with contention retry limit exceeded
      expect(consumerStdout).toContain("RESULT:");
      const resultMatch = consumerStdout.match(/RESULT:(.+)/);
      expect(resultMatch).not.toBeNull();
      const outcome = JSON.parse(resultMatch![1]);
      expect(outcome.decision).toBe("DENY");
      expect(outcome.reasons[0]).toContain("Database is busy; transaction contention retry limit exceeded.");

      // Verify database state: Authorization was NOT consumed and budget was NOT spent
      const verifyStore = new SQLiteAuthorizationStore(dbFile, new TestClock(1050));
      try {
        const record = verifyStore.getAuthorizationRecord("auth-contention-worker");
        expect(record?.state).toBe("issued");
        const accum = verifyStore.getPolicyBudgetAccumulator(policy.policyId, "HOURLY", 0);
        expect(accum).toBeNull();

        // Once lock contention is cleared, consuming the exact same authorization artifact succeeds!
        const env = createTransactionEnvelope(req);
        if (!env.ok) throw new Error("env failed");
        const retryConsume = consumeSignedTransactionAuthorizationV3(
          verifyStore,
          issue.artifact,
          env.envelope,
          req,
        );
        expect(retryConsume.decision).toBe("ALLOW");

        // Now record is consumed and accumulator is updated to 100
        expect(verifyStore.getAuthorizationRecord("auth-contention-worker")?.state).toBe("consumed");
        expect(verifyStore.getPolicyBudgetAccumulator(policy.policyId, "HOURLY", 0)?.spentAmount).toBe("100");
      } finally {
        verifyStore.close();
      }
    }, 25000);
  });

  // =========================================================================
  // Scope 3: Corrupted or Malformed policy_budget_accumulators Records
  // =========================================================================
  describe("Scope 3: Corrupted or Malformed Accumulator Records", () => {
    it("enforces SQLite CHECK constraints on policy_budget_accumulators against invalid types and amounts", () => {
      const dbFile = createTestDbPath("m9-scope3-check-");
      const { authStore, policyStore } = setupStores(dbFile, 1000);

      const policy: DemoPolicy = {
        version: 1,
        policyId: "pol-check-test",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 10000,
        revoked: false,
      };
      policyStore.registerPolicy(policy);
      const rawDb = authStore.getDatabase();

      // Invalid window_type
      expect(() => {
        rawDb.prepare(`
          INSERT INTO policy_budget_accumulators (policy_id, window_type, window_start, spent_amount)
          VALUES (?, 'WEEKLY', 0, '100')
        `).run(policy.policyId);
      }).toThrow(/constraint failed/i);

      // Non-numeric spent_amount (letters appended)
      expect(() => {
        rawDb.prepare(`
          INSERT INTO policy_budget_accumulators (policy_id, window_type, window_start, spent_amount)
          VALUES (?, 'HOURLY', 0, '100abc')
        `).run(policy.policyId);
      }).toThrow(/constraint failed/i);

      // Non-numeric spent_amount (negative)
      expect(() => {
        rawDb.prepare(`
          INSERT INTO policy_budget_accumulators (policy_id, window_type, window_start, spent_amount)
          VALUES (?, 'HOURLY', 0, '-50')
        `).run(policy.policyId);
      }).toThrow(/constraint failed/i);

      // Non-numeric spent_amount (decimal dot)
      expect(() => {
        rawDb.prepare(`
          INSERT INTO policy_budget_accumulators (policy_id, window_type, window_start, spent_amount)
          VALUES (?, 'HOURLY', 0, '12.34')
        `).run(policy.policyId);
      }).toThrow(/constraint failed/i);

      // Empty spent_amount
      expect(() => {
        rawDb.prepare(`
          INSERT INTO policy_budget_accumulators (policy_id, window_type, window_start, spent_amount)
          VALUES (?, 'HOURLY', 0, '')
        `).run(policy.policyId);
      }).toThrow(/constraint failed/i);

      // spent_amount exceeding length limit of 78 characters
      const length79 = "9".repeat(79);
      expect(() => {
        rawDb.prepare(`
          INSERT INTO policy_budget_accumulators (policy_id, window_type, window_start, spent_amount)
          VALUES (?, 'HOURLY', 0, ?)
        `).run(policy.policyId, length79);
      }).toThrow(/constraint failed/i);
    });

    it("fails closed without partial state writes if accumulator contains corrupted non-integer string", () => {
      const dbFile = createTestDbPath("m9-scope3-corrupt-");
      const { authStore, policyStore, keyStore } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-corrupt-1",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      const budgetedPolicy: DemoPolicy = {
        version: 1,
        policyId: "pol-corrupt-budget",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: "200",
        },
      };
      policyStore.registerPolicy(budgetedPolicy);

      const req: TransactionRequest = {
        chainId: "1",
        sender: TARGET,
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 50n),
        value: "0",
      };
      const issue = issueAllow(
        authStore,
        { keyId: "k-corrupt-1", privateKey },
        "auth-corrupt-test",
        budgetedPolicy.policyId,
        req,
      );
      expect(issue.decision).toBe("ALLOW");

      // Inject a malformed spent_amount bypassing checks via PRAGMA ignore_check_constraints
      const rawDb = authStore.getDatabase();
      rawDb.exec("PRAGMA ignore_check_constraints = ON;");
      rawDb.prepare(`
        INSERT INTO policy_budget_accumulators (policy_id, window_type, window_start, spent_amount)
        VALUES (?, 'HOURLY', 0, 'corrupted_alphanumeric')
      `).run(budgetedPolicy.policyId);
      rawDb.exec("PRAGMA ignore_check_constraints = OFF;");

      const env = createTransactionEnvelope(req);
      if (!env.ok) throw new Error("env failed");

      // Calling consume throws SyntaxError due to BigInt("corrupted_alphanumeric") failure
      // Crucial: verify that transaction rolls back, authorization remains 'issued', and clock lock is released
      expect(() => {
        consumeSignedTransactionAuthorizationV3(
          authStore,
          issue.artifact,
          env.envelope,
          req,
        );
      }).toThrow(/Cannot convert .* to a BigInt/);

      // Verify state was NOT partially consumed
      expect(authStore.getAuthorizationRecord("auth-corrupt-test")?.state).toBe("issued");

      // Verify clock guard lock was cleanly released
      expect(authStore.getClockGuard().acquireLock()).toBe(true);
      authStore.getClockGuard().releaseLock();
    });

    it("safely handles accumulator spending exceeding maxCumulativeAmount without negative remaining amounts", () => {
      const dbFile = createTestDbPath("m9-scope3-overflow-amount-");
      const { authStore, policyStore, keyStore, clock } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-overflow-1",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      const budgetedPolicy: DemoPolicy = {
        version: 1,
        policyId: "pol-exceeded-budget",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: "200",
        },
      };
      policyStore.registerPolicy(budgetedPolicy);

      // Manually simulate accumulator spent_amount set to 300 (> 200)
      const rawDb = authStore.getDatabase();
      rawDb.prepare(`
        INSERT INTO policy_budget_accumulators (policy_id, window_type, window_start, spent_amount)
        VALUES (?, 'HOURLY', 0, '300')
      `).run(budgetedPolicy.policyId);

      const engine = new Web3UserEngine({
        databasePath: dbFile,
        clock: { clock, maxStartupForwardGapSeconds: 200_000 },
      });
      openEngines.push(engine);

      // getBudgetStatus must return remainingAmount: "0", never negative
      const status = engine.policies.getBudgetStatus(budgetedPolicy.policyId, 1000);
      expect(status?.hasBudget).toBe(true);
      expect(status?.spentAmount).toBe("300");
      expect(status?.remainingAmount).toBe("0");

      // Any consumption must be denied with available: 0
      const req: TransactionRequest = {
        chainId: "1",
        sender: TARGET,
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 10n),
        value: "0",
      };
      const issue = issueAllow(
        authStore,
        { keyId: "k-overflow-1", privateKey },
        "auth-over-budget",
        budgetedPolicy.policyId,
        req,
      );
      const env = createTransactionEnvelope(req);
      if (!env.ok) throw new Error("env failed");
      const consume = consumeSignedTransactionAuthorizationV3(
        authStore,
        issue.artifact,
        env.envelope,
        req,
      );
      expect(consume.decision).toBe("DENY");
      expect(consume.reasons[0]).toContain("available: 0");
    });
  });

  // =========================================================================
  // Scope 4: Calldata Decoder Edge Cases
  // =========================================================================
  describe("Scope 4: Calldata Decoder Edge Cases & Invariant Parity", () => {
    it("strictly rejects wrong lengths, smuggled trailing bytes, and malformed encodings", () => {
      const validRecipient = RECIPIENT.slice(2).padStart(64, "0");
      const validAmountHex = (50n).toString(16).padStart(64, "0");
      const validCalldata = `0xa9059cbb${validRecipient}${validAmountHex}`;

      // Baseline: valid calldata decodes successfully
      expect(decodeTransfer(validCalldata)).toEqual({
        recipient: RECIPIENT.toLowerCase(),
        amount: 50n,
      });
      expect(demoDecodeTransfer(validCalldata)?.recipient).toBe(RECIPIENT.toLowerCase());
      expect(demoDecodeTransfer(validCalldata)?.amount).toBe(50n);

      // 1. Non-string inputs
      expect(decodeTransfer(null as any)).toBeNull();
      expect(decodeTransfer(undefined as any)).toBeNull();
      expect(decodeTransfer(12345 as any)).toBeNull();
      expect(decodeTransfer({} as any)).toBeNull();
      expect(demoDecodeTransfer(null as any)).toBeNull();
      expect(demoDecodeTransfer(undefined as any)).toBeNull();
      expect(demoDecodeTransfer(12345 as any)).toBeNull();

      // 2. Wrong lengths
      expect(decodeTransfer("")).toBeNull();
      expect(decodeTransfer("0xa9059c")).toBeNull();
      expect(decodeTransfer("0xa9059cbb")).toBeNull(); // 10 chars
      expect(decodeTransfer(validCalldata.slice(0, 137))).toBeNull(); // 137 chars (missing 1)
      expect(decodeTransfer(`${validCalldata}0`)).toBeNull(); // 139 chars (extra 1)
      // Smuggled trailing bytes (length 146)
      const smuggledCalldata = `${validCalldata}deadbeef`;
      expect(decodeTransfer(smuggledCalldata)).toBeNull();
      expect(demoDecodeTransfer(smuggledCalldata)).toBeNull();

      // 3. Wrong selectors
      expect(decodeTransfer(`0x095ea7b3${validRecipient}${validAmountHex}`)).toBeNull(); // approve selector
      expect(decodeTransfer(`0x23b87266${validRecipient}${validAmountHex}`)).toBeNull(); // transferFrom selector
      expect(decodeTransfer(`0x00000000${validRecipient}${validAmountHex}`)).toBeNull();
      expect(decodeTransfer(validCalldata.replace("0x", ""))).toBeNull(); // missing 0x prefix

      // 4. Dirty high address bits in 12-byte zero padding
      const dirtyHigh1 = `0xa9059cbb000000000000000000000001${RECIPIENT.slice(2)}${validAmountHex}`;
      expect(decodeTransfer(dirtyHigh1)).toBeNull();
      expect(demoDecodeTransfer(dirtyHigh1)).toBeNull();

      const dirtyHigh2 = `0xa9059cbb800000000000000000000000${RECIPIENT.slice(2)}${validAmountHex}`;
      expect(decodeTransfer(dirtyHigh2)).toBeNull();
      expect(demoDecodeTransfer(dirtyHigh2)).toBeNull();

      const dirtyHighFull = `0xa9059cbbffffffffffffffffffffffff${RECIPIENT.slice(2)}${validAmountHex}`;
      expect(decodeTransfer(dirtyHighFull)).toBeNull();
      expect(demoDecodeTransfer(dirtyHighFull)).toBeNull();

      // 5. Invalid hex encodings
      const nonHexAddress = `0xa9059cbb${"0".repeat(24)}${"g".repeat(40)}${validAmountHex}`;
      expect(decodeTransfer(nonHexAddress)).toBeNull();
      expect(demoDecodeTransfer(nonHexAddress)).toBeNull();

      const nonHexAmount = `0xa9059cbb${validRecipient}${"z".repeat(64)}`;
      expect(decodeTransfer(nonHexAmount)).toBeNull();
      expect(demoDecodeTransfer(nonHexAmount)).toBeNull();

      const negativeSignAmount = `0xa9059cbb${validRecipient}-${"0".repeat(63)}`;
      expect(decodeTransfer(negativeSignAmount)).toBeNull();
      expect(demoDecodeTransfer(negativeSignAmount)).toBeNull();

      const whitespaceCalldata = `0x a9059cbb${validRecipient}${validAmountHex}`;
      expect(decodeTransfer(whitespaceCalldata)).toBeNull();
      expect(demoDecodeTransfer(whitespaceCalldata)).toBeNull();
    });

    it("verifies evaluate() fails closed on smuggled calldata or dirty high bits", () => {
      const policy: DemoPolicy = {
        version: 1,
        policyId: "pol-calldata-test",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 10000,
        revoked: false,
      };

      const validRecipient = RECIPIENT.slice(2).padStart(64, "0");
      const validAmountHex = (50n).toString(16).padStart(64, "0");
      const validCalldata = `0xa9059cbb${validRecipient}${validAmountHex}`;

      // Smuggled trailing calldata fails closed with UNKNOWN
      const evalSmuggled = evaluate(
        policy,
        { target: TARGET, calldata: `${validCalldata}deadbeef`, amount: "50" },
        { nowSeconds: 100 },
      );
      expect(evalSmuggled.decision).toBe("UNKNOWN");

      // Dirty high address bits fail closed with UNKNOWN
      const evalDirty = evaluate(
        policy,
        { target: TARGET, calldata: `0xa9059cbb000000000000000000000001${RECIPIENT.slice(2)}${validAmountHex}`, amount: "50" },
        { nowSeconds: 100 },
      );
      expect(evalDirty.decision).toBe("UNKNOWN");
    });
  });

  // =========================================================================
  // Scope 5: Maximum uint256 Values and Arithmetic Boundaries
  // =========================================================================
  describe("Scope 5: Maximum uint256 Values & Arithmetic Boundaries", () => {
    it("strictly checks uint256 validation boundaries up to 2^256 - 1", () => {
      const maxUint256Str = MAX_UINT256.toString(10);
      expect(isUint256String("0")).toBe(true);
      expect(isUint256String("1")).toBe(true);
      expect(isUint256String(maxUint256Str)).toBe(true);
      expect(maxUint256Str.length).toBe(78);

      // Boundary: 2^256 (MAX_UINT256 + 1n) must be rejected
      const overflowUint256Str = (MAX_UINT256 + 1n).toString(10);
      expect(isUint256String(overflowUint256Str)).toBe(false);

      // 79 digits must be rejected
      expect(isUint256String("1" + "0".repeat(78))).toBe(false);

      // Leading zeros, negatives, decimals, empty strings
      expect(isUint256String("01")).toBe(false);
      expect(isUint256String("-1")).toBe(false);
      expect(isUint256String("1.5")).toBe(false);
      expect(isUint256String("")).toBe(false);
      expect(isUint256String("abc")).toBe(false);

      // Verify normalizeDemoPolicy preserves identical boundaries
      const basePol = {
        version: 1,
        policyId: "pol-boundary",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 10000,
        revoked: false,
      };
      expect(normalizeDemoPolicy({ ...basePol, maxAmount: maxUint256Str })).not.toBeNull();
      expect(normalizeDemoPolicy({ ...basePol, maxAmount: overflowUint256Str })).toBeNull();
    });

    it("handles exact 2^256 - 1 cumulative budget accounting without precision loss or overflow", () => {
      const dbFile = createTestDbPath("m9-scope5-uint256-");
      const { authStore, policyStore, keyStore } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-uint256",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      const maxUint256Str = MAX_UINT256.toString(10);
      const uint256Policy: DemoPolicy = {
        version: 1,
        policyId: "pol-uint256-max",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: maxUint256Str,
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: maxUint256Str,
        },
      };
      policyStore.registerPolicy(uint256Policy);

      // Issue authorization for exact MAX_UINT256
      const reqMax: TransactionRequest = {
        chainId: "1",
        sender: TARGET,
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, MAX_UINT256),
        value: "0",
      };

      const issueMax = issueAllow(
        authStore,
        { keyId: "k-uint256", privateKey },
        "auth-uint256-max",
        uint256Policy.policyId,
        reqMax,
      );
      expect(issueMax.decision).toBe("ALLOW");

      const envMax = createTransactionEnvelope(reqMax);
      if (!envMax.ok) throw new Error("envMax failed");
      const consumeMax = consumeSignedTransactionAuthorizationV3(
        authStore,
        issueMax.artifact,
        envMax.envelope,
        reqMax,
      );
      expect(consumeMax.decision).toBe("ALLOW");

      // Verify stored accumulator is exact 78-digit MAX_UINT256 decimal string
      const accum = authStore.getPolicyBudgetAccumulator(uint256Policy.policyId, "HOURLY", 0);
      expect(accum?.spentAmount).toBe(maxUint256Str);

      // Subsequent spend of even 1 unit must be DENIED with budget exceeded (requested: 1, available: 0)
      const reqOne: TransactionRequest = {
        chainId: "1",
        sender: TARGET,
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 1n),
        value: "0",
      };
      const issueOne = issueAllow(
        authStore,
        { keyId: "k-uint256", privateKey },
        "auth-uint256-one",
        uint256Policy.policyId,
        reqOne,
      );
      const envOne = createTransactionEnvelope(reqOne);
      if (!envOne.ok) throw new Error("envOne failed");
      const consumeOne = consumeSignedTransactionAuthorizationV3(
        authStore,
        issueOne.artifact,
        envOne.envelope,
        reqOne,
      );
      expect(consumeOne.decision).toBe("DENY");
      expect(consumeOne.reasons[0]).toContain("Cumulative spending budget exceeded for hourly window");
      expect(consumeOne.reasons[0]).toContain("available: 0");

      // Accumulator remains exactly MAX_UINT256 without overflow or wrapping
      const accumAfter = authStore.getPolicyBudgetAccumulator(uint256Policy.policyId, "HOURLY", 0);
      expect(accumAfter?.spentAmount).toBe(maxUint256Str);
    });
  });

  // =========================================================================
  // Scope 6: Clock-Skew and Time-Validation Boundaries
  // =========================================================================
  describe("Scope 6: Clock-Skew & Time-Validation Boundaries", () => {
    it("tests exact step velocity boundaries on ClockGuard (+10s and -5s)", () => {
      const clock = new TestClock(1000);
      const monotonic = new TestMonotonicClock(1000_000_000_000n);
      const guard = new ClockGuard(clock, monotonic, {
        maxForwardStepSeconds: 10,
        maxBackwardStepSeconds: 5,
        maxAbsoluteDivergenceSeconds: 60,
      });

      // Initialize
      const initCandidate = { wallSeconds: 1000, monotonicNanos: 1000_000_000_000n };
      expect(guard.evaluateCandidate(initCandidate, 1000).decision).toBe("ALLOW");
      guard.publishCandidate(initCandidate);
      expect(guard.getState()).toBe("ACTIVE");

      // Forward step of exactly 10s with 0 monotonic elapsed -> ALLOWED (divergence = 10 <= 10)
      const step10 = { wallSeconds: 1010, monotonicNanos: 1000_000_000_000n };
      expect(guard.evaluateCandidate(step10, 1000).decision).toBe("ALLOW");
      guard.publishCandidate(step10);

      // Reset guard for edge test: Forward step of 11s -> TRIPPED_CLOSED (divergence = 11 > 10)
      const guard2 = new ClockGuard(clock, monotonic, {
        maxForwardStepSeconds: 10,
        maxBackwardStepSeconds: 5,
      });
      guard2.evaluateCandidate(initCandidate, 1000);
      guard2.publishCandidate(initCandidate);

      const step11 = { wallSeconds: 1011, monotonicNanos: 1000_000_000_000n };
      const eval11 = guard2.evaluateCandidate(step11, 1000);
      expect(eval11.decision).toBe("DENY");
      expect(eval11.reason).toContain("Suspicious forward clock jump detected");
      expect(guard2.getState()).toBe("TRIPPED_CLOSED");

      // Backward step boundary: step of -5s with 0 monotonic elapsed -> ALLOWED
      const guard3 = new ClockGuard(clock, monotonic, {
        maxForwardStepSeconds: 10,
        maxBackwardStepSeconds: 5,
      });
      const highSample = { wallSeconds: 1050, monotonicNanos: 1050_000_000_000n };
      guard3.evaluateCandidate(highSample, 1000);
      guard3.publishCandidate(highSample);

      const stepMinus5 = { wallSeconds: 1045, monotonicNanos: 1050_000_000_000n };
      expect(guard3.evaluateCandidate(stepMinus5, 1000).decision).toBe("ALLOW");

      // Backward step of -6s -> TRIPPED_CLOSED
      const stepMinus6 = { wallSeconds: 1044, monotonicNanos: 1050_000_000_000n };
      const evalMinus6 = guard3.evaluateCandidate(stepMinus6, 1000);
      expect(evalMinus6.decision).toBe("DENY");
      expect(evalMinus6.reason).toContain("Suspicious backward clock step detected");
      expect(guard3.getState()).toBe("TRIPPED_CLOSED");
    });

    it("tests cumulative divergence boundary of exactly 60s vs 61s", () => {
      const clock = new TestClock(1000);
      const monotonic = new TestMonotonicClock(1000_000_000_000n);
      const guard = new ClockGuard(clock, monotonic, {
        maxForwardStepSeconds: 100, // relax step limits to isolate cumulative divergence
        maxAbsoluteDivergenceSeconds: 60,
      });

      const initial = { wallSeconds: 1000, monotonicNanos: 1000_000_000_000n };
      guard.evaluateCandidate(initial, 1000);
      guard.publishCandidate(initial);

      // Wall advanced by 60s, monotonic advanced by 0s -> divergence = 60s <= 60s -> ALLOWED
      const div60 = { wallSeconds: 1060, monotonicNanos: 1000_000_000_000n };
      expect(guard.evaluateCandidate(div60, 1000).decision).toBe("ALLOW");

      // Divergence = 61s -> TRIPPED_CLOSED
      const div61 = { wallSeconds: 1061, monotonicNanos: 1000_000_000_000n };
      const eval61 = guard.evaluateCandidate(div61, 1000);
      expect(eval61.decision).toBe("DENY");
      expect(eval61.reason).toContain("Suspicious clock divergence detected");
      expect(guard.getState()).toBe("TRIPPED_CLOSED");
    });

    it("enforces exact anti-time-travel and authorization expiry boundaries in V3 lifecycle", () => {
      const dbFile = createTestDbPath("m9-scope6-expiry-");
      const { authStore, policyStore, keyStore, clock } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-expiry",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      const policy: DemoPolicy = {
        version: 1,
        policyId: "pol-expiry-test",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
      };
      policyStore.registerPolicy(policy);

      const req: TransactionRequest = {
        chainId: "1",
        sender: TARGET,
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 50n),
        value: "0",
      };

      // Issue valid artifact at t = 1000 with TTL = 60 (expires at t = 1060)
      const issue = issueAllow(
        authStore,
        { keyId: "k-expiry", privateKey },
        "auth-expiry-boundary",
        policy.policyId,
        req,
        { ttlSeconds: 60 },
      );
      expect(issue.decision).toBe("ALLOW");
      expect(issue.artifact.expiresAtSeconds).toBe(1060);

      // Create an auxiliary store to sign an artifact validly at t = 1010
      const auxDbFile = createTestDbPath("m9-scope6-aux-");
      const auxStores = setupStores(auxDbFile, 1010);
      auxStores.keyStore.registerKey({
        keyId: "k-expiry",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });
      auxStores.policyStore.registerPolicy(policy);

      const futureIssue = issueAllow(
        auxStores.authStore,
        { keyId: "k-expiry", privateKey },
        "auth-future-issuance",
        policy.policyId,
        req,
        { ttlSeconds: 60 },
      );
      expect(futureIssue.decision).toBe("ALLOW");
      expect(futureIssue.artifact.issuedAtSeconds).toBe(1010);
      auxStores.authStore.close();

      // Register the future-issued artifact in our primary database
      authStore.issueBound("auth-future-issuance", futureIssue.artifact.bindingDigest, 3);

      // Primary clock is at 1000, high-water is at 1000.
      // Candidate time (1000) < artifact.issuedAtSeconds (1010)
      // Anti-time-travel check must deny consumption with exact reason!
      const envFuture = createTransactionEnvelope(req);
      if (!envFuture.ok) throw new Error("envFuture failed");
      const consumeFuture = consumeSignedTransactionAuthorizationV3(
        authStore,
        futureIssue.artifact,
        envFuture.envelope,
        req,
      );
      expect(consumeFuture.decision).toBe("DENY");
      expect(consumeFuture.reasons[0]).toContain("Authorization issuance timestamp is in the future relative to current clock.");

      // Expiry boundary test:
      // Advance to 1059 (expiresAtSeconds - 1) -> ALLOWED!
      clock.set(1059);
      authStore.advanceHighWaterMark(1059);
      const envValid = createTransactionEnvelope(req);
      if (!envValid.ok) throw new Error("envValid failed");
      const consumeValid = consumeSignedTransactionAuthorizationV3(
        authStore,
        issue.artifact,
        envValid.envelope,
        req,
      );
      expect(consumeValid.decision).toBe("ALLOW");

      // Now issue a second auth to test exact equality at expiresAtSeconds
      const issue2 = issueAllow(
        authStore,
        { keyId: "k-expiry", privateKey },
        "auth-expiry-exact-eq",
        policy.policyId,
        req,
        { ttlSeconds: 40 }, // expires at 1059 + 40 = 1099
      );
      expect(issue2.decision).toBe("ALLOW");
      expect(issue2.artifact.expiresAtSeconds).toBe(1099);

      // Advance clock to exact equality: 1099
      clock.set(1099);
      authStore.advanceHighWaterMark(1099);
      const envExact = createTransactionEnvelope(req);
      if (!envExact.ok) throw new Error("envExact failed");
      const consumeExact = consumeSignedTransactionAuthorizationV3(
        authStore,
        issue2.artifact,
        envExact.envelope,
        req,
      );
      expect(consumeExact.decision).toBe("DENY");
      expect(consumeExact.reasons[0]).toContain("Signed transaction authorization has expired.");
      expect(authStore.getAuthorizationRecord("auth-expiry-exact-eq")?.state).toBe("issued");
    });
  });

  // =========================================================================
  // Scope 7: Key-Retirement Boundary Equality
  // =========================================================================
  describe("Scope 7: Key-Retirement Boundary Equality", () => {
    it("strictly rejects authorizations issued at or after key retirement while permitting issued before", () => {
      const dbFile = createTestDbPath("m9-scope7-key-retire-");
      const { authStore, policyStore, keyStore, clock } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-retire-boundary",
        publicKey: pem,
        status: "active",
        validFromSeconds: 500,
        expiresAtSeconds: 5000,
      });

      const policy: DemoPolicy = {
        version: 1,
        policyId: "pol-key-retire",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 5000,
        revoked: false,
      };
      policyStore.registerPolicy(policy);

      const req: TransactionRequest = {
        chainId: "1",
        sender: TARGET,
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 50n),
        value: "0",
      };

      // Auth 1 issued at t = 1999 (strictly before retirement at 2000)
      clock.set(1999);
      const issue1 = issueAllow(
        authStore,
        { keyId: "k-retire-boundary", privateKey },
        "auth-issued-before-retire",
        policy.policyId,
        req,
        { ttlSeconds: 1000 },
      );
      expect(issue1.decision).toBe("ALLOW");

      // Key retires at t = 2000
      clock.set(2000);
      authStore.advanceHighWaterMark(2000);
      keyStore.retireKey("k-retire-boundary");
      expect(keyStore.getKey("k-retire-boundary")?.status).toBe("retired");
      expect(keyStore.getKey("k-retire-boundary")?.retiredAtSeconds).toBe(2000);

      // Now construct an artifact claiming issuance at exactly t = 2000 (equality with retiredAtSeconds)
      const forgedArtifactAtRetirement = {
        ...issue1.artifact,
        authorizationId: "auth-at-retire-exact",
        issuedAtSeconds: 2000,
      };
      authStore.issueBound("auth-at-retire-exact", issue1.artifact.bindingDigest, 3);

      const envAtRetire = createTransactionEnvelope(req);
      if (!envAtRetire.ok) throw new Error("envAtRetire failed");

      // Consuming an artifact issued at retiredAtSeconds (2000) MUST BE DENIED
      clock.set(2050);
      authStore.advanceHighWaterMark(2050);
      const consumeForged = consumeSignedTransactionAuthorizationV3(
        authStore,
        forgedArtifactAtRetirement,
        envAtRetire.envelope,
        req,
      );
      expect(consumeForged.decision).toBe("DENY");
      expect(consumeForged.reasons[0]).toContain("Authorization was issued after issuer key was retired.");

      // But Auth 1 issued at t = 1999 (< 2000) MUST SUCCEED when consumed at t = 2050!
      const envBeforeRetire = createTransactionEnvelope(req);
      if (!envBeforeRetire.ok) throw new Error("envBeforeRetire failed");
      const consumeValid = consumeSignedTransactionAuthorizationV3(
        authStore,
        issue1.artifact,
        envBeforeRetire.envelope,
        req,
      );
      expect(consumeValid.decision).toBe("ALLOW");
      expect(authStore.getAuthorizationRecord("auth-issued-before-retire")?.state).toBe("consumed");
    });

    it("verifies key valid_from and expires_at boundary equality conditions", () => {
      const dbFile = createTestDbPath("m9-scope7-key-validity-");
      const { authStore, policyStore, keyStore, clock } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      // Key valid from 1000 to 2000
      keyStore.registerKey({
        keyId: "k-validity-window",
        publicKey: pem,
        status: "active",
        validFromSeconds: 1000,
        expiresAtSeconds: 2000,
      });

      const policy: DemoPolicy = {
        version: 1,
        policyId: "pol-key-window",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 5000,
        revoked: false,
      };
      policyStore.registerPolicy(policy);

      const req: TransactionRequest = {
        chainId: "1",
        sender: TARGET,
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 50n),
        value: "0",
      };

      // Issued at t = 1000 (exact equality with valid_from_seconds) -> ALLOWED
      clock.set(1000);
      const issueValidFrom = issueAllow(
        authStore,
        { keyId: "k-validity-window", privateKey },
        "auth-valid-from-eq",
        policy.policyId,
        req,
        { ttlSeconds: 500 },
      );
      expect(issueValidFrom.decision).toBe("ALLOW");

      const envValidFrom = createTransactionEnvelope(req);
      if (!envValidFrom.ok) throw new Error("envValidFrom failed");
      const consumeValidFrom = consumeSignedTransactionAuthorizationV3(
        authStore,
        issueValidFrom.artifact,
        envValidFrom.envelope,
        req,
      );
      expect(consumeValidFrom.decision).toBe("ALLOW");

      // Key expiration boundary: consumption at effectiveNowSeconds = 2000 (exact equality) -> DENIED
      clock.set(1500);
      const req2: TransactionRequest = {
        ...req,
        calldata: encodeCalldata(RECIPIENT, 40n),
      };
      const issueExpiring = issueAllow(
        authStore,
        { keyId: "k-validity-window", privateKey },
        "auth-key-expiring",
        policy.policyId,
        req2,
        { ttlSeconds: 400 },
      );
      expect(issueExpiring.decision).toBe("ALLOW");

      // Advance clock to key expiration: 2000
      clock.set(2000);
      authStore.advanceHighWaterMark(2000);
      const envExpiring = createTransactionEnvelope(req2);
      if (!envExpiring.ok) throw new Error("envExpiring failed");
      const consumeExpiredKey = consumeSignedTransactionAuthorizationV3(
        authStore,
        issueExpiring.artifact,
        envExpiring.envelope,
        req2,
      );
      expect(consumeExpiredKey.decision).toBe("DENY");
      expect(consumeExpiredKey.reasons[0]).toContain("Issuer key has expired.");
    });
  });

  // =========================================================================
  // Scope 8: SQLite Read-Only or Failed-Write Behavior
  // =========================================================================
  describe("Scope 8: SQLite Read-Only & Failed-Write Behavior", () => {
    it("ensures no partial authorization consumption or budget accounting occurs when SQLite is query-only", () => {
      const dbFile = createTestDbPath("m9-scope8-query-only-");
      const { authStore, policyStore, keyStore } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-readonly",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      const budgetedPolicy: DemoPolicy = {
        version: 1,
        policyId: "pol-readonly-test",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: "200",
        },
      };
      policyStore.registerPolicy(budgetedPolicy);

      const req: TransactionRequest = {
        chainId: "1",
        sender: TARGET,
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 50n),
        value: "0",
      };
      const issue = issueAllow(
        authStore,
        { keyId: "k-readonly", privateKey },
        "auth-readonly-test",
        budgetedPolicy.policyId,
        req,
      );
      expect(issue.decision).toBe("ALLOW");

      const env = createTransactionEnvelope(req);
      if (!env.ok) throw new Error("env failed");

      // Set SQLite to query_only = ON (write operations fail)
      const rawDb = authStore.getDatabase();
      rawDb.exec("PRAGMA query_only = ON;");

      // Attempting to consume should fail closed with readonly error
      expect(() => {
        consumeSignedTransactionAuthorizationV3(
          authStore,
          issue.artifact,
          env.envelope,
          req,
        );
      }).toThrow(/readonly|attempt to write a readonly database/i);

      // Verify that authorization remains issued, not consumed
      rawDb.exec("PRAGMA query_only = OFF;");
      const record = authStore.getAuthorizationRecord("auth-readonly-test");
      expect(record?.state).toBe("issued");

      // Verify accumulator was never created or incremented
      const accum = authStore.getPolicyBudgetAccumulator(budgetedPolicy.policyId, "HOURLY", 0);
      expect(accum).toBeNull();

      // Now retry consuming with query_only OFF -> MUST SUCCEED cleanly!
      const envRetry = createTransactionEnvelope(req);
      if (!envRetry.ok) throw new Error("envRetry failed");
      const consumeSuccess = consumeSignedTransactionAuthorizationV3(
        authStore,
        issue.artifact,
        envRetry.envelope,
        req,
      );
      expect(consumeSuccess.decision).toBe("ALLOW");

      expect(authStore.getAuthorizationRecord("auth-readonly-test")?.state).toBe("consumed");
      expect(authStore.getPolicyBudgetAccumulator(budgetedPolicy.policyId, "HOURLY", 0)?.spentAmount).toBe("50");
    });

    it("rolls back completely and records zero budget spend when mid-transaction write failure is injected", () => {
      const dbFile = createTestDbPath("m9-scope8-mid-tx-");
      const { authStore, policyStore, keyStore } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-mid-tx",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      const budgetedPolicy: DemoPolicy = {
        version: 1,
        policyId: "pol-mid-tx-test",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: "200",
        },
      };
      policyStore.registerPolicy(budgetedPolicy);

      const req: TransactionRequest = {
        chainId: "1",
        sender: TARGET,
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 50n),
        value: "0",
      };
      const issue = issueAllow(
        authStore,
        { keyId: "k-mid-tx", privateKey },
        "auth-mid-tx-fail",
        budgetedPolicy.policyId,
        req,
      );
      expect(issue.decision).toBe("ALLOW");

      const env = createTransactionEnvelope(req);
      if (!env.ok) throw new Error("env failed");

      // Monkey-patch rawDb.prepare to simulate a failure when writing to consumed_authorization_ids (Step 9)
      const rawDb = authStore.getDatabase();
      const originalPrepare = rawDb.prepare.bind(rawDb);
      rawDb.prepare = (sql: string) => {
        if (sql.includes("UPDATE consumed_authorization_ids")) {
          throw new Error("Simulated storage write error (SQLITE_FULL)");
        }
        return originalPrepare(sql);
      };

      // Consuming must throw the error, trigger rollback, release clock lock
      expect(() => {
        consumeSignedTransactionAuthorizationV3(
          authStore,
          issue.artifact,
          env.envelope,
          req,
        );
      }).toThrow("Simulated storage write error (SQLITE_FULL)");

      // Restore original prepare
      rawDb.prepare = originalPrepare;

      // Verify that accumulator was rolled back (spentAmount does not exist)
      const accum = authStore.getPolicyBudgetAccumulator(budgetedPolicy.policyId, "HOURLY", 0);
      expect(accum).toBeNull();

      // Authorization record remains issued
      const record = authStore.getAuthorizationRecord("auth-mid-tx-fail");
      expect(record?.state).toBe("issued");

      // Clock guard lock was released
      expect(authStore.getClockGuard().acquireLock()).toBe(true);
      authStore.getClockGuard().releaseLock();

      // Subsequent consumption without fault succeeds completely!
      const envRetry = createTransactionEnvelope(req);
      if (!envRetry.ok) throw new Error("envRetry failed");
      const consumeSuccess = consumeSignedTransactionAuthorizationV3(
        authStore,
        issue.artifact,
        envRetry.envelope,
        req,
      );
      expect(consumeSuccess.decision).toBe("ALLOW");
      expect(authStore.getAuthorizationRecord("auth-mid-tx-fail")?.state).toBe("consumed");
      expect(authStore.getPolicyBudgetAccumulator(budgetedPolicy.policyId, "HOURLY", 0)?.spentAmount).toBe("50");
    });
  });

  // =========================================================================
  // Scope 9: Database Snapshot Restoration, Storage Rollback & Recovery Invariants
  // =========================================================================
  describe("Scope 9: Database Snapshot Restoration, Storage Rollback & Recovery Invariants", () => {
    function snapshotDatabase(dbPath: string, snapshotPath: string): void {
      copyFileSync(dbPath, snapshotPath);
      const walPath = `${dbPath}-wal`;
      const snapshotWalPath = `${snapshotPath}-wal`;
      if (existsSync(walPath)) {
        copyFileSync(walPath, snapshotWalPath);
      }
    }

    function restoreDatabase(snapshotPath: string, dbPath: string): void {
      copyFileSync(snapshotPath, dbPath);
      const walPath = `${dbPath}-wal`;
      const shmPath = `${dbPath}-shm`;
      const snapshotWalPath = `${snapshotPath}-wal`;
      if (existsSync(snapshotWalPath)) {
        copyFileSync(snapshotWalPath, walPath);
      } else if (existsSync(walPath)) {
        rmSync(walPath, { force: true });
      }
      if (existsSync(shmPath)) {
        rmSync(shmPath, { force: true });
      }
    }

    it("demonstrates replay vulnerability when restoring a database snapshot taken after issuance but before consumption within TTL", () => {
      const dbFile = createTestDbPath("m10-scope9-replay-");
      const snapshotFile = `${dbFile}.snapshot`;
      const { authStore, policyStore, keyStore } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-snap-1",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      const policy: DemoPolicy = {
        version: 1,
        policyId: "pol-snap-replay",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: "200",
        },
      };
      policyStore.registerPolicy(policy);

      const req: TransactionRequest = {
        chainId: "1",
        sender: "0x3333333333333333333333333333333333333333",
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 50n),
        value: "0",
      };

      // 1. Issue authorization at t = 1000 with TTL = 300s (expiresAt = 1300)
      const issueRes = issueAllow(authStore, { keyId: "k-snap-1", privateKey }, "auth-snap-01", policy.policyId, req, { ttlSeconds: 300 });
      expect(authStore.getAuthorizationRecord("auth-snap-01")?.state).toBe("issued");

      // Checkpoint WAL and capture cold snapshot of database
      authStore.checkpoint("TRUNCATE");
      authStore.close();
      snapshotDatabase(dbFile, snapshotFile);

      // 2. Advance time to t = 1050, open store, and consume the authorization
      const clock2 = new TestClock(1050);
      const store2 = new SQLiteAuthorizationStore(dbFile, { clock: clock2 });
      openStores.push(store2);

      const env1 = createTransactionEnvelope(req);
      if (!env1.ok) throw new Error("env failed");
      const consume1 = consumeSignedTransactionAuthorizationV3(
        store2,
        issueRes.artifact,
        env1.envelope,
        req,
      );
      expect(consume1.decision).toBe("ALLOW");
      expect(store2.getAuthorizationRecord("auth-snap-01")?.state).toBe("consumed");
      expect(store2.getPolicyBudgetAccumulator(policy.policyId, "HOURLY", 0)?.spentAmount).toBe("50");

      // Verify that replay is prevented in the active database
      const envReplay = createTransactionEnvelope(req);
      if (!envReplay.ok) throw new Error("env failed");
      const replayAttempt1 = consumeSignedTransactionAuthorizationV3(
        store2,
        issueRes.artifact,
        envReplay.envelope,
        req,
      );
      expect(replayAttempt1.decision).toBe("DENY");
      expect(replayAttempt1.reasons[0]).toMatch(/already been consumed|unknown, consumed, or mismatched/);

      // Close store before disaster recovery
      store2.close();

      // 3. Disaster recovery simulation: Restore the cold snapshot from t = 1000 at t = 1100
      // (t = 1100 is within TTL 1300, and forward gap 1100 - 1000 = 100s <= 3600s startup limit)
      restoreDatabase(snapshotFile, dbFile);

      const clock3 = new TestClock(1100);
      const store3 = new SQLiteAuthorizationStore(dbFile, { clock: clock3 });
      openStores.push(store3);

      // In the restored database, the record has reverted to 'issued' and spend is rewound
      const restoredRecord = store3.getAuthorizationRecord("auth-snap-01");
      expect(restoredRecord?.state).toBe("issued");
      expect(store3.getPolicyBudgetAccumulator(policy.policyId, "HOURLY", 0)).toBeNull();

      // 4. Vulnerability demonstration: Resubmitting the same signed authorization succeeds again!
      const envRestored = createTransactionEnvelope(req);
      if (!envRestored.ok) throw new Error("env failed");
      const replayInRestoredDb = consumeSignedTransactionAuthorizationV3(
        store3,
        issueRes.artifact,
        envRestored.envelope,
        req,
      );

      // Proves that local SQLite alone cannot prevent replay after storage snapshot restoration
      // if current time is within TTL and within maxStartupForwardGapSeconds.
      expect(replayInRestoredDb.decision).toBe("ALLOW");
      expect(store3.getAuthorizationRecord("auth-snap-01")?.state).toBe("consumed");
      expect(store3.getPolicyBudgetAccumulator(policy.policyId, "HOURLY", 0)?.spentAmount).toBe("50");
    });

    it("demonstrates cumulative budget bypass when restoring a snapshot to rewind recorded spending within the same window", () => {
      const dbFile = createTestDbPath("m10-scope9-budget-rewind-");
      const snapshotFile = `${dbFile}.snapshot`;
      const { authStore, policyStore, keyStore } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-snap-2",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      const policy: DemoPolicy = {
        version: 1,
        policyId: "pol-snap-budget",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: "100", // Hard aggregate limit of 100 for the hour
        },
      };
      policyStore.registerPolicy(policy);

      // Snapshot taken at t = 1000 with 0 spent
      authStore.checkpoint("TRUNCATE");
      authStore.close();
      snapshotDatabase(dbFile, snapshotFile);

      // Open store at t = 1010
      const clock2 = new TestClock(1010);
      const store2 = new SQLiteAuthorizationStore(dbFile, { clock: clock2 });
      openStores.push(store2);

      const req60: TransactionRequest = {
        chainId: "1",
        sender: "0x3333333333333333333333333333333333333333",
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 60n),
        value: "0",
      };
      const issue60 = issueAllow(store2, { keyId: "k-snap-2", privateKey }, "auth-60", policy.policyId, req60);
      const env60 = createTransactionEnvelope(req60);
      if (!env60.ok) throw new Error("env failed");
      const consume60 = consumeSignedTransactionAuthorizationV3(store2, issue60.artifact, env60.envelope, req60);
      expect(consume60.decision).toBe("ALLOW");
      expect(store2.getPolicyBudgetAccumulator(policy.policyId, "HOURLY", 0)?.spentAmount).toBe("60");

      // Transaction 2: spend 30 (total = 90)
      const req30: TransactionRequest = {
        chainId: "1",
        sender: "0x3333333333333333333333333333333333333333",
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 30n),
        value: "0",
      };
      const issue30 = issueAllow(store2, { keyId: "k-snap-2", privateKey }, "auth-30", policy.policyId, req30);
      const env30 = createTransactionEnvelope(req30);
      if (!env30.ok) throw new Error("env failed");
      const consume30 = consumeSignedTransactionAuthorizationV3(store2, issue30.artifact, env30.envelope, req30);
      expect(consume30.decision).toBe("ALLOW");
      expect(store2.getPolicyBudgetAccumulator(policy.policyId, "HOURLY", 0)?.spentAmount).toBe("90");

      // Transaction 3: attempt spend 25 -> must DENY because 90 + 25 = 115 > 100
      const req25: TransactionRequest = {
        chainId: "1",
        sender: "0x3333333333333333333333333333333333333333",
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 25n),
        value: "0",
      };
      const issue25 = issueAllow(store2, { keyId: "k-snap-2", privateKey }, "auth-25", policy.policyId, req25);
      const env25 = createTransactionEnvelope(req25);
      if (!env25.ok) throw new Error("env failed");
      const consume25 = consumeSignedTransactionAuthorizationV3(store2, issue25.artifact, env25.envelope, req25);
      expect(consume25.decision).toBe("DENY");
      expect(consume25.reasons[0]).toMatch(/Cumulative spending budget exceeded/);

      store2.close();

      // Restore snapshot from t = 1000 at t = 1050 (spend is rewound to 0 in storage)
      restoreDatabase(snapshotFile, dbFile);

      const clock3 = new TestClock(1050);
      const store3 = new SQLiteAuthorizationStore(dbFile, { clock: clock3 });
      openStores.push(store3);

      expect(store3.getPolicyBudgetAccumulator(policy.policyId, "HOURLY", 0)).toBeNull();

      // In the restored database, spend is 0. An attacker or application can now issue and consume
      // an additional 80 units of spending within the same hourly window!
      const req80: TransactionRequest = {
        chainId: "1",
        sender: "0x3333333333333333333333333333333333333333",
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 80n),
        value: "0",
      };
      const issue80 = issueAllow(store3, { keyId: "k-snap-2", privateKey }, "auth-80", policy.policyId, req80);
      const env80 = createTransactionEnvelope(req80);
      if (!env80.ok) throw new Error("env failed");
      const consume80 = consumeSignedTransactionAuthorizationV3(store3, issue80.artifact, env80.envelope, req80);
      expect(consume80.decision).toBe("ALLOW");
      expect(store3.getPolicyBudgetAccumulator(policy.policyId, "HOURLY", 0)?.spentAmount).toBe("80");

      // Across reality, 60 + 30 + 80 = 170 units were authorized against a 100 unit budget cap.
      // Proves that restoring an older snapshot rewinds cumulative spending accounting.
    });

    it("verifies that ClockGuard startup gap check prevents database operation when snapshot is older than maxStartupForwardGapSeconds", () => {
      const dbFile = createTestDbPath("m10-scope9-startup-gap-");
      const snapshotFile = `${dbFile}.snapshot`;
      const { authStore } = setupStores(dbFile, 1000);

      // Snapshot taken at t = 1000 (high water mark = 1000)
      authStore.checkpoint("TRUNCATE");
      authStore.close();
      snapshotDatabase(dbFile, snapshotFile);

      // Restore the snapshot, but current wall clock has advanced to t = 5000 (gap = 4000s > default 3600s)
      restoreDatabase(snapshotFile, dbFile);

      const futureClock = new TestClock(5000);
      // Attempting to open the store with default options (maxStartupForwardGapSeconds = 3600)
      // must fail closed during schema initialization with a startup gap error
      expect(() => {
        new SQLiteAuthorizationStore(dbFile, { clock: futureClock });
      }).toThrow(/forward clock gap of 4000 seconds exceeds maximum/);
    });

    it("verifies that expired authorizations cannot be replayed after snapshot restoration even if database state was rewound", () => {
      const dbFile = createTestDbPath("m10-scope9-expired-ttl-");
      const snapshotFile = `${dbFile}.snapshot`;
      const { authStore, policyStore, keyStore } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-snap-3",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      const policy: DemoPolicy = {
        version: 1,
        policyId: "pol-snap-expiry",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
      };
      policyStore.registerPolicy(policy);

      const req: TransactionRequest = {
        chainId: "1",
        sender: "0x3333333333333333333333333333333333333333",
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 50n),
        value: "0",
      };

      // Issue with short TTL of 60 seconds (expires at t = 1060)
      const issueRes = issueAllow(authStore, { keyId: "k-snap-3", privateKey }, "auth-snap-exp", policy.policyId, req, { ttlSeconds: 60 });
      expect(issueRes.artifact.expiresAtSeconds).toBe(1060);

      // Take snapshot while in 'issued' state at t = 1000
      authStore.checkpoint("TRUNCATE");
      authStore.close();
      snapshotDatabase(dbFile, snapshotFile);

      // Consume at t = 1020 in active database
      const clock2 = new TestClock(1020);
      const store2 = new SQLiteAuthorizationStore(dbFile, { clock: clock2 });
      openStores.push(store2);
      const env = createTransactionEnvelope(req);
      if (!env.ok) throw new Error("env failed");
      const consumeRes = consumeSignedTransactionAuthorizationV3(store2, issueRes.artifact, env.envelope, req);
      expect(consumeRes.decision).toBe("ALLOW");
      expect(store2.getAuthorizationRecord("auth-snap-exp")?.state).toBe("consumed");
      store2.close();

      // Restore snapshot at t = 1100 (gap is 100s <= 3600s, so store startup succeeds, but t = 1100 > expiresAtSeconds = 1060)
      restoreDatabase(snapshotFile, dbFile);

      const clock3 = new TestClock(1100);
      const store3 = new SQLiteAuthorizationStore(dbFile, { clock: clock3 });
      openStores.push(store3);

      // Database shows 'issued', but artifact expiry is strictly enforced
      expect(store3.getAuthorizationRecord("auth-snap-exp")?.state).toBe("issued");

      const envRestored = createTransactionEnvelope(req);
      if (!envRestored.ok) throw new Error("env failed");
      const replayAttempt = consumeSignedTransactionAuthorizationV3(
        store3,
        issueRes.artifact,
        envRestored.envelope,
        req,
      );

      expect(replayAttempt.decision).toBe("DENY");
      expect(replayAttempt.reasons[0]).toMatch(/Signed transaction authorization has expired/);

      // State in database remains unconsumed
      expect(store3.getAuthorizationRecord("auth-snap-exp")?.state).toBe("issued");
    });

    it("demonstrates that emergency issuer key revocation neutralizes restored unconsumed authorizations", () => {
      const dbFile = createTestDbPath("m10-scope9-key-revoke-");
      const snapshotFile = `${dbFile}.snapshot`;
      const { authStore, policyStore, keyStore } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-snap-rev",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      const policy: DemoPolicy = {
        version: 1,
        policyId: "pol-snap-key-rev",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
      };
      policyStore.registerPolicy(policy);

      const req: TransactionRequest = {
        chainId: "1",
        sender: "0x3333333333333333333333333333333333333333",
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 50n),
        value: "0",
      };

      // Issue authorization at t = 1000 with TTL = 300s (expires at 1300)
      const issueRes = issueAllow(authStore, { keyId: "k-snap-rev", privateKey }, "auth-snap-rev-01", policy.policyId, req, { ttlSeconds: 300 });

      // Snapshot taken at t = 1000 while 'issued'
      authStore.checkpoint("TRUNCATE");
      authStore.close();
      snapshotDatabase(dbFile, snapshotFile);

      // Consumed at t = 1020 in active database
      const clock2 = new TestClock(1020);
      const store2 = new SQLiteAuthorizationStore(dbFile, { clock: clock2 });
      openStores.push(store2);
      const env = createTransactionEnvelope(req);
      if (!env.ok) throw new Error("env failed");
      expect(consumeSignedTransactionAuthorizationV3(store2, issueRes.artifact, env.envelope, req).decision).toBe("ALLOW");
      store2.close();

      // Restore snapshot at t = 1050
      restoreDatabase(snapshotFile, dbFile);

      const clock3 = new TestClock(1050);
      const store3 = new SQLiteAuthorizationStore(dbFile, { clock: clock3 });
      openStores.push(store3);

      // Safe recovery procedure: operator revokes the key that was active during the snapshot gap
      store3.getKeyStore().revokeKey("k-snap-rev", 1050);

      // Now, any attempt to replay the restored authorization fails closed!
      const envRestored = createTransactionEnvelope(req);
      if (!envRestored.ok) throw new Error("env failed");
      const replayAttempt = consumeSignedTransactionAuthorizationV3(
        store3,
        issueRes.artifact,
        envRestored.envelope,
        req,
      );

      expect(replayAttempt.decision).toBe("DENY");
      expect(replayAttempt.reasons[0]).toMatch(/Issuer key has been revoked/);
    });
  });

  // =========================================================================
  // Scope 10: Concurrency, TOCTOU State Invalidation & Pre-Verification Race Resilience (Milestone 10 Phase 2B)
  // =========================================================================
  describe("Scope 10: Concurrency, TOCTOU State Invalidation & Pre-Verification Race Resilience", () => {
    it("fails closed when issuer key is revoked between pre-verification and write-transaction execution", () => {
      const dbFile = createTestDbPath("m10-scope10-revoke-toctou-");
      const { authStore, policyStore, keyStore } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-toctou-rev",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      const policy: DemoPolicy = {
        version: 1,
        policyId: "pol-toctou-rev",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
      };
      policyStore.registerPolicy(policy);

      const req: TransactionRequest = {
        chainId: "1",
        sender: "0x3333333333333333333333333333333333333333",
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 50n),
        value: "0",
      };

      const issueRes = issueAllow(authStore, { keyId: "k-toctou-rev", privateKey }, "auth-toctou-rev-1", "pol-toctou-rev", req);
      const env = createTransactionEnvelope(req);
      if (!env.ok) throw new Error("env failed");

      // Set up a competing connection that revokes the key during the pre-transaction clock sampling hook
      const clock2 = new TestClock(1010);
      const store2 = new SQLiteAuthorizationStore(dbFile, { clock: clock2 });
      openStores.push(store2);

      let triggerRace = false;
      let snapshotCount = 0;
      const racingClock = {
        nowSeconds(): number {
          if (triggerRace) {
            snapshotCount++;
            if (snapshotCount === 1) {
              // Intervene between pre-verification and write-transaction acquisition:
              store2.getKeyStore().revokeKey("k-toctou-rev", 1010);
              return 1010;
            }
            return 1010;
          }
          return 1000;
        },
      };

      const racingStore = new SQLiteAuthorizationStore(dbFile, racingClock);
      openStores.push(racingStore);
      triggerRace = true;

      const consumeRes = consumeSignedTransactionAuthorizationV3(
        racingStore,
        issueRes.artifact,
        env.envelope,
        req,
      );

      // Must fail closed with revoked key reason!
      expect(consumeRes.decision).toBe("DENY");
      expect(consumeRes.reasons[0]).toMatch(/Issuer key has been revoked/);

      // Persistent record must remain in 'issued' state
      const record = authStore.getAuthorizationRecord("auth-toctou-rev-1");
      expect(record?.state).toBe("issued");
    });

    it("fails closed when authorization expires between pre-verification and write-transaction execution", () => {
      const dbFile = createTestDbPath("m10-scope10-exp-toctou-");
      const { authStore, policyStore, keyStore } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-toctou-exp",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      const policy: DemoPolicy = {
        version: 1,
        policyId: "pol-toctou-exp",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
      };
      policyStore.registerPolicy(policy);

      const req: TransactionRequest = {
        chainId: "1",
        sender: "0x3333333333333333333333333333333333333333",
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 50n),
        value: "0",
      };

      // Issued at t=1000 with TTL=60s -> expires at 1060
      const issueRes = issueAllow(authStore, { keyId: "k-toctou-exp", privateKey }, "auth-toctou-exp-1", "pol-toctou-exp", req, { ttlSeconds: 60 });
      expect(issueRes.artifact.expiresAtSeconds).toBe(1060);
      const env = createTransactionEnvelope(req);
      if (!env.ok) throw new Error("env failed");

      // Competing store advances clock and persistent high-water mark past 1060
      const clock2 = new TestClock(1070);
      const store2 = new SQLiteAuthorizationStore(dbFile, { clock: clock2 });
      openStores.push(store2);

      let triggerRace = false;
      let snapshotCount = 0;
      const racingClock = {
        nowSeconds(): number {
          if (triggerRace) {
            snapshotCount++;
            if (snapshotCount === 1) {
              // Competing store advances persistent high water mark past expiration boundary:
              store2.advanceHighWaterMark(1070);
              return 1050; // caller's pre-check was within 1000..1060 window
            }
            return 1070;
          }
          return 1000;
        },
      };

      const racingStore = new SQLiteAuthorizationStore(dbFile, racingClock);
      openStores.push(racingStore);
      triggerRace = true;

      const consumeRes = consumeSignedTransactionAuthorizationV3(
        racingStore,
        issueRes.artifact,
        env.envelope,
        req,
      );

      // Must fail closed with expired reason
      expect(consumeRes.decision).toBe("DENY");
      expect(consumeRes.reasons).toContain("Signed transaction authorization has expired.");

      // Record remains in 'issued' state
      const record = authStore.getAuthorizationRecord("auth-toctou-exp-1");
      expect(record?.state).toBe("issued");
    });

    it("fails closed when policy revision increments between pre-verification and write-transaction execution", () => {
      const dbFile = createTestDbPath("m10-scope10-rev-bump-");
      const { authStore, policyStore, keyStore } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-toctou-pol",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      const policy: DemoPolicy = {
        version: 1,
        policyId: "pol-toctou-bump",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
      };
      policyStore.registerPolicy(policy);

      const req: TransactionRequest = {
        chainId: "1",
        sender: "0x3333333333333333333333333333333333333333",
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 50n),
        value: "0",
      };

      // Issued for revision 1
      const issueRes = issueAllow(authStore, { keyId: "k-toctou-pol", privateKey }, "auth-toctou-bump-1", "pol-toctou-bump", req);
      expect(issueRes.artifact.policyRevision).toBe(1);
      const env = createTransactionEnvelope(req);
      if (!env.ok) throw new Error("env failed");

      // Competing store updates policy to revision 2
      const clock2 = new TestClock(1010);
      const store2 = new SQLiteAuthorizationStore(dbFile, { clock: clock2 });
      openStores.push(store2);

      let triggerRace = false;
      let snapshotCount = 0;
      const racingClock = {
        nowSeconds(): number {
          if (triggerRace) {
            snapshotCount++;
            if (snapshotCount === 1) {
              // Bump policy revision from 1 to 2 before write transaction begins
              store2.getPolicyStore().updatePolicy({
                ...policy,
                maxAmount: "150",
              });
              return 1010;
            }
            return 1010;
          }
          return 1000;
        },
      };

      const racingStore = new SQLiteAuthorizationStore(dbFile, racingClock);
      openStores.push(racingStore);
      triggerRace = true;

      const consumeRes = consumeSignedTransactionAuthorizationV3(
        racingStore,
        issueRes.artifact,
        env.envelope,
        req,
      );

      // Must fail closed with revision mismatch reason
      expect(consumeRes.decision).toBe("DENY");
      expect(consumeRes.reasons[0]).toMatch(/Policy revision mismatch: artifact bound to revision 1, but current policy revision is 2/);

      // Record remains in 'issued' state
      const record = authStore.getAuthorizationRecord("auth-toctou-bump-1");
      expect(record?.state).toBe("issued");
    });

    it("guarantees single-use serialization when multiple store connections race to consume the same authorization", () => {
      const dbFile = createTestDbPath("m10-scope10-replay-race-");
      const { authStore, policyStore, keyStore } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-race-replay",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      const policy: DemoPolicy = {
        version: 1,
        policyId: "pol-race-replay",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
      };
      policyStore.registerPolicy(policy);

      const req: TransactionRequest = {
        chainId: "1",
        sender: "0x3333333333333333333333333333333333333333",
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 40n),
        value: "0",
      };

      const issueRes = issueAllow(authStore, { keyId: "k-race-replay", privateKey }, "auth-race-replay-1", "pol-race-replay", req);

      // Create two distinct store connections to the same database
      const clockA = new TestClock(1010);
      const storeA = new SQLiteAuthorizationStore(dbFile, { clock: clockA });
      openStores.push(storeA);

      const clockB = new TestClock(1010);
      const storeB = new SQLiteAuthorizationStore(dbFile, { clock: clockB });
      openStores.push(storeB);

      const envA = createTransactionEnvelope(req);
      if (!envA.ok) throw new Error("envA failed");
      const envB = createTransactionEnvelope(req);
      if (!envB.ok) throw new Error("envB failed");

      // First consumer succeeds
      const resA = consumeSignedTransactionAuthorizationV3(storeA, issueRes.artifact, envA.envelope, req);
      expect(resA.decision).toBe("ALLOW");

      // Second consumer racing on the same authorization ID is rejected
      const resB = consumeSignedTransactionAuthorizationV3(storeB, issueRes.artifact, envB.envelope, req);
      expect(resB.decision).toBe("DENY");
      expect(resB.reasons[0]).toMatch(/Bound transaction authorization is unknown, consumed, or mismatched/);

      // Final persistent state is consumed with exactly 1 consumption record
      const record = authStore.getAuthorizationRecord("auth-race-replay-1");
      expect(record?.state).toBe("consumed");
    });

    it("strictly prevents cumulative budget overruns when distinct authorizations race against a shared budget cap", () => {
      const dbFile = createTestDbPath("m10-scope10-budget-race-");
      const { authStore, policyStore, keyStore } = setupStores(dbFile, 1000);
      const { privateKey, pem } = createKeypair();

      keyStore.registerKey({
        keyId: "k-race-budget",
        publicKey: pem,
        status: "active",
        validFromSeconds: 0,
        expiresAtSeconds: 20000,
      });

      // Policy with hourly budget cap of 100
      const policy: DemoPolicy = {
        version: 1,
        policyId: "pol-race-budget",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 0,
        expiresAt: 20000,
        revoked: false,
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: "100",
        },
      };
      policyStore.registerPolicy(policy);

      const req60: TransactionRequest = {
        chainId: "1",
        sender: "0x3333333333333333333333333333333333333333",
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 60n),
        value: "0",
      };

      const req50: TransactionRequest = {
        chainId: "1",
        sender: "0x3333333333333333333333333333333333333333",
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 50n),
        value: "0",
      };

      // Issue two distinct authorizations: one for 60, one for 50 (sum = 110 > 100)
      const issue60 = issueAllow(authStore, { keyId: "k-race-budget", privateKey }, "auth-race-60", "pol-race-budget", req60);
      const issue50 = issueAllow(authStore, { keyId: "k-race-budget", privateKey }, "auth-race-50", "pol-race-budget", req50);

      // Distinct connections
      const clock1 = new TestClock(1010);
      const store1 = new SQLiteAuthorizationStore(dbFile, { clock: clock1 });
      openStores.push(store1);

      const clock2 = new TestClock(1010);
      const store2 = new SQLiteAuthorizationStore(dbFile, { clock: clock2 });
      openStores.push(store2);

      const env60 = createTransactionEnvelope(req60);
      if (!env60.ok) throw new Error("env60 failed");
      const env50 = createTransactionEnvelope(req50);
      if (!env50.ok) throw new Error("env50 failed");

      // First transaction consumes 60 tokens -> Allowed (spent = 60 <= 100)
      const res60 = consumeSignedTransactionAuthorizationV3(store1, issue60.artifact, env60.envelope, req60);
      expect(res60.decision).toBe("ALLOW");

      // Second transaction attempts to consume 50 tokens -> Denied (60 + 50 = 110 > 100)
      const res50 = consumeSignedTransactionAuthorizationV3(store2, issue50.artifact, env50.envelope, req50);
      expect(res50.decision).toBe("DENY");
      expect(res50.reasons[0]).toMatch(/Cumulative spending budget exceeded for hourly window/);

      // Verify accumulator spent_amount is exactly 60, not 110
      const windowStart = calculateBudgetWindowStart(1010, "HOURLY");
      const accum = authStore.getPolicyBudgetAccumulator("pol-race-budget", "HOURLY", windowStart);
      expect(accum).not.toBeNull();
      expect(accum?.spentAmount).toBe("60");

      // Verify first auth is consumed, second remains issued
      expect(authStore.getAuthorizationRecord("auth-race-60")?.state).toBe("consumed");
      expect(authStore.getAuthorizationRecord("auth-race-50")?.state).toBe("issued");
    });
  });
});
