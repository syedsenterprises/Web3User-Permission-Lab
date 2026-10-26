import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import {
  consumeSignedTransactionAuthorizationV3,
  issueSignedTransactionAuthorizationV3,
} from "../src/authorization-lifecycle.js";
import { SQLiteAuthorizationStore } from "../src/authorization-store.js";
import { ClockGuard, TestClock } from "../src/clock.js";
import { Web3UserEngine } from "../src/engine.js";
import {
  calculateBudgetWindowStart,
  calculateBudgetWindowEnd,
  type DemoPolicy,
} from "../src/policy.js";
import { type TransactionRequest } from "../src/transaction-envelope.js";

describe("Milestone 8: Stateful Cumulative Budget Enforcement", () => {
  const openStores: SQLiteAuthorizationStore[] = [];
  const openEngines: Web3UserEngine[] = [];
  const createdDirs: string[] = [];

  function createTestDbPath(filename = "test.sqlite"): string {
    const dir = mkdtempSync(join(tmpdir(), "web3user-m8-"));
    createdDirs.push(dir);
    return join(dir, filename);
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

  function setupStores(dbFile: string, clockSeconds = 1_800_000_100, maxStep = 200_000) {
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
    return { authStore, policyStore, keyStore, clock };
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

  it("enforces sequential spending within an hourly cumulative budget and tracks status", () => {
    const dbFile = createTestDbPath();
    const startTime = 1_800_000_100;
    const { authStore, policyStore, keyStore, clock } = setupStores(dbFile, startTime);
    const key = createKeypair();

    const policy: DemoPolicy = {
      version: 1,
      policyId: "hourly-policy-01",
      allowedTarget: TARGET,
      allowedRecipient: RECIPIENT,
      allowedSelector: "0xa9059cbb",
      maxAmount: "100",
      validFrom: 1_800_000_000,
      expiresAt: 1_800_086_400,
      revoked: false,
      budget: {
        window: "HOURLY",
        maxCumulativeAmount: "250",
      },
    };

    policyStore.registerPolicy(policy);
    keyStore.registerKey({
      keyId: "issuer-01",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 1_800_000_000,
      expiresAtSeconds: 1_800_086_400,
    });

    const windowStart = calculateBudgetWindowStart(startTime, "HOURLY");

    // 1. First consumption: 100 units
    const req1: TransactionRequest = {
      chainId: "1",
      sender: "0x3333333333333333333333333333333333333333",
      target: TARGET,
      calldata: encodeCalldata(RECIPIENT, 100n),
      value: "0",
    };
    const issue1 = issueAllow(
      authStore,
      { keyId: "issuer-01", privateKey: key.privateKey },
      "auth-001",
      policy.policyId,
      req1,
    );

    const consume1 = consumeSignedTransactionAuthorizationV3(
      authStore,
      issue1.artifact,
      issue1.envelope,
      req1,
    );
    expect(consume1.decision).toBe("ALLOW");

    const acc1 = authStore.getPolicyBudgetAccumulator(policy.policyId, "HOURLY", windowStart);
    expect(acc1).not.toBeNull();
    expect(acc1?.spentAmount).toBe("100");

    // 2. Second consumption: 100 units (cumulative = 200)
    clock.advance(10);
    const req2: TransactionRequest = { ...req1 };
    const issue2 = issueAllow(
      authStore,
      { keyId: "issuer-01", privateKey: key.privateKey },
      "auth-002",
      policy.policyId,
      req2,
    );
    const consume2 = consumeSignedTransactionAuthorizationV3(
      authStore,
      issue2.artifact,
      issue2.envelope,
      req2,
    );
    expect(consume2.decision).toBe("ALLOW");

    const acc2 = authStore.getPolicyBudgetAccumulator(policy.policyId, "HOURLY", windowStart);
    expect(acc2?.spentAmount).toBe("200");

    // 3. Third consumption: 50 units (exact cap = 250)
    clock.advance(10);
    const req3: TransactionRequest = {
      ...req1,
      calldata: encodeCalldata(RECIPIENT, 50n),
    };
    const issue3 = issueAllow(
      authStore,
      { keyId: "issuer-01", privateKey: key.privateKey },
      "auth-003",
      policy.policyId,
      req3,
    );
    const consume3 = consumeSignedTransactionAuthorizationV3(
      authStore,
      issue3.artifact,
      issue3.envelope,
      req3,
    );
    expect(consume3.decision).toBe("ALLOW");

    const acc3 = authStore.getPolicyBudgetAccumulator(policy.policyId, "HOURLY", windowStart);
    expect(acc3?.spentAmount).toBe("250");
  });

  it("denies consumption when cumulative budget is exceeded, leaves authorization in issued state, and allows safe retry after rollover", () => {
    const dbFile = createTestDbPath();
    const startTime = 1_800_000_100;
    const { authStore, policyStore, keyStore, clock } = setupStores(dbFile, startTime);
    const key = createKeypair();

    const policy: DemoPolicy = {
      version: 1,
      policyId: "hourly-policy-retry",
      allowedTarget: TARGET,
      allowedRecipient: RECIPIENT,
      allowedSelector: "0xa9059cbb",
      maxAmount: "100",
      validFrom: 1_800_000_000,
      expiresAt: 1_800_086_400,
      revoked: false,
      budget: {
        window: "HOURLY",
        maxCumulativeAmount: "100",
      },
    };

    policyStore.registerPolicy(policy);
    keyStore.registerKey({
      keyId: "issuer-01",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 1_800_000_000,
      expiresAtSeconds: 1_800_086_400,
    });

    const windowStart1 = calculateBudgetWindowStart(startTime, "HOURLY");

    // Consume 80 units
    const req1: TransactionRequest = {
      chainId: "1",
      sender: "0x3333333333333333333333333333333333333333",
      target: TARGET,
      calldata: encodeCalldata(RECIPIENT, 80n),
      value: "0",
    };
    const issue1 = issueAllow(
      authStore,
      { keyId: "issuer-01", privateKey: key.privateKey },
      "auth-001",
      policy.policyId,
      req1,
    );
    expect(consumeSignedTransactionAuthorizationV3(authStore, issue1.artifact, issue1.envelope, req1).decision).toBe("ALLOW");

    // Issue auth-002 for 30 units with a 2-hour TTL so it remains valid into the next budget window
    const req2: TransactionRequest = {
      ...req1,
      calldata: encodeCalldata(RECIPIENT, 30n),
    };
    const issue2 = issueAllow(
      authStore,
      { keyId: "issuer-01", privateKey: key.privateKey },
      "auth-002",
      policy.policyId,
      req2,
      { ttlSeconds: 7200 },
    );

    // Attempt consumption: DENIED due to cumulative budget
    const consumeDenied = consumeSignedTransactionAuthorizationV3(
      authStore,
      issue2.artifact,
      issue2.envelope,
      req2,
    );
    expect(consumeDenied.decision).toBe("DENY");
    expect(consumeDenied.reasons[0]).toContain("Cumulative spending budget exceeded for hourly window");

    // Invariant: Accumulator spent amount is still 80 (not incremented)
    const accCurrent = authStore.getPolicyBudgetAccumulator(policy.policyId, "HOURLY", windowStart1);
    expect(accCurrent?.spentAmount).toBe("80");

    // Invariant: Authorization is still in state 'issued'
    // Retry immediately: still DENY in the same hour window
    const immediateRetry = consumeSignedTransactionAuthorizationV3(
      authStore,
      issue2.artifact,
      issue2.envelope,
      req2,
    );
    expect(immediateRetry.decision).toBe("DENY");

    // Advance clock past the hour boundary: 1,800,000,100 + 3600 = 1,800,003,700 (next hour)
    clock.advance(3600);
    const windowStart2 = calculateBudgetWindowStart(1_800_003_700, "HOURLY");
    expect(windowStart2).toBe(1_800_003_600);

    // Retry the exact same issued authorization in the new window: SUCCEEDS!
    const retryInNewWindow = consumeSignedTransactionAuthorizationV3(
      authStore,
      issue2.artifact,
      issue2.envelope,
      req2,
    );
    expect(retryInNewWindow.decision).toBe("ALLOW");

    // New window accumulator has 30 units spent
    const accNewWindow = authStore.getPolicyBudgetAccumulator(policy.policyId, "HOURLY", windowStart2);
    expect(accNewWindow?.spentAmount).toBe("30");

    // Historical window accumulator still has 80 units spent
    const accOldWindow = authStore.getPolicyBudgetAccumulator(policy.policyId, "HOURLY", windowStart1);
    expect(accOldWindow?.spentAmount).toBe("80");

    // Replay protection: Attempting to consume auth-002 AGAIN fails permanently with REPLAY DENIAL
    const replayAttempt = consumeSignedTransactionAuthorizationV3(
      authStore,
      issue2.artifact,
      issue2.envelope,
      req2,
    );
    expect(replayAttempt.decision).toBe("DENY");
    expect(replayAttempt.reasons[0]).toContain("already been consumed");
  });

  it("supports daily budget windows and deterministic day rollover", () => {
    const dbFile = createTestDbPath();
    const startTime = 1_800_000_000;
    const day1Start = calculateBudgetWindowStart(startTime, "DAILY");
    const { authStore, policyStore, keyStore, clock } = setupStores(dbFile, startTime, 200_000);
    const key = createKeypair();

    const policy: DemoPolicy = {
      version: 1,
      policyId: "daily-policy-01",
      allowedTarget: TARGET,
      allowedRecipient: RECIPIENT,
      allowedSelector: "0xa9059cbb",
      maxAmount: "500",
      validFrom: 1_700_000_000,
      expiresAt: 1_900_000_000,
      revoked: false,
      budget: {
        window: "DAILY",
        maxCumulativeAmount: "1000",
      },
    };

    policyStore.registerPolicy(policy);
    keyStore.registerKey({
      keyId: "issuer-01",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 1_700_000_000,
      expiresAtSeconds: 1_900_000_000,
    });

    const req: TransactionRequest = {
      chainId: "1",
      sender: "0x3333333333333333333333333333333333333333",
      target: TARGET,
      calldata: encodeCalldata(RECIPIENT, 500n),
      value: "0",
    };

    // Day 1, Transaction 1: 500
    const issue1 = issueAllow(
      authStore,
      { keyId: "issuer-01", privateKey: key.privateKey },
      "auth-d-1",
      policy.policyId,
      req,
    );
    expect(consumeSignedTransactionAuthorizationV3(authStore, issue1.artifact, issue1.envelope, req).decision).toBe("ALLOW");

    // Day 1, Transaction 2: 500 (Cumulative = 1000, exact daily cap)
    clock.advance(3600);
    const issue2 = issueAllow(
      authStore,
      { keyId: "issuer-01", privateKey: key.privateKey },
      "auth-d-2",
      policy.policyId,
      req,
    );
    expect(consumeSignedTransactionAuthorizationV3(authStore, issue2.artifact, issue2.envelope, req).decision).toBe("ALLOW");

    // Day 1, Transaction 3: 10 units (Exceeds daily budget)
    const reqSmall: TransactionRequest = {
      ...req,
      calldata: encodeCalldata(RECIPIENT, 10n),
    };
    clock.advance(1800);
    const issue3 = issueAllow(
      authStore,
      { keyId: "issuer-01", privateKey: key.privateKey },
      "auth-d-3",
      policy.policyId,
      reqSmall,
    );
    expect(consumeSignedTransactionAuthorizationV3(authStore, issue3.artifact, issue3.envelope, reqSmall).decision).toBe("DENY");

    // Advance clock past daily rollover (+86,400s into next day)
    clock.advance(86400);
    const day2Start = calculateBudgetWindowStart(clock.nowSeconds(), "DAILY");
    expect(day2Start).toBe(day1Start + 86400);

    // In the new day, consuming 500 units succeeds immediately!
    const issue4 = issueAllow(
      authStore,
      { keyId: "issuer-01", privateKey: key.privateKey },
      "auth-d-4",
      policy.policyId,
      req,
    );
    expect(consumeSignedTransactionAuthorizationV3(authStore, issue4.artifact, issue4.envelope, req).decision).toBe("ALLOW");

    const accumulators = authStore.listPolicyBudgetAccumulators(policy.policyId);
    expect(accumulators.length).toBe(2);
    expect(accumulators.find((a) => a.windowStart === day1Start)?.spentAmount).toBe("1000");
    expect(accumulators.find((a) => a.windowStart === day2Start)?.spentAmount).toBe("500");
  });

  it("carries forward prior spend across policy revisions and enforces window type immutability", () => {
    const dbFile = createTestDbPath();
    const startTime = 1_800_000_100;
    const { authStore, policyStore, keyStore } = setupStores(dbFile, startTime);
    const key = createKeypair();

    const policyRev1: DemoPolicy = {
      version: 1,
      policyId: "carry-forward-policy",
      allowedTarget: TARGET,
      allowedRecipient: RECIPIENT,
      allowedSelector: "0xa9059cbb",
      maxAmount: "100",
      validFrom: 1_800_000_000,
      expiresAt: 1_800_086_400,
      revoked: false,
      budget: {
        window: "HOURLY",
        maxCumulativeAmount: "200",
      },
    };

    policyStore.registerPolicy(policyRev1);
    keyStore.registerKey({
      keyId: "issuer-01",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 1_800_000_000,
      expiresAtSeconds: 1_800_086_400,
    });

    const req: TransactionRequest = {
      chainId: "1",
      sender: "0x3333333333333333333333333333333333333333",
      target: TARGET,
      calldata: encodeCalldata(RECIPIENT, 100n),
      value: "0",
    };

    // Under revision 1: Spend 100 units
    const issue1 = issueAllow(
      authStore,
      { keyId: "issuer-01", privateKey: key.privateKey },
      "auth-rev1",
      policyRev1.policyId,
      req,
    );
    expect(consumeSignedTransactionAuthorizationV3(authStore, issue1.artifact, issue1.envelope, req).decision).toBe("ALLOW");

    // Governance action: Update policy to revision 2, expanding budget cap from 200 to 500
    const policyRev2: DemoPolicy = {
      ...policyRev1,
      budget: {
        window: "HOURLY",
        maxCumulativeAmount: "500",
      },
    };
    policyStore.updatePolicy(policyRev2);

    // Invariant: Spend in current window remains 100 (carried forward across revisions)
    const windowStart = calculateBudgetWindowStart(startTime, "HOURLY");
    const acc = authStore.getPolicyBudgetAccumulator(policyRev1.policyId, "HOURLY", windowStart);
    expect(acc?.spentAmount).toBe("100");

    // Spend another 100 under revision 2: Cumulative spend becomes 200
    const issue2 = issueAllow(
      authStore,
      { keyId: "issuer-01", privateKey: key.privateKey },
      "auth-rev2",
      policyRev1.policyId,
      req,
    );
    expect(consumeSignedTransactionAuthorizationV3(authStore, issue2.artifact, issue2.envelope, req).decision).toBe("ALLOW");

    const accAfter = authStore.getPolicyBudgetAccumulator(policyRev1.policyId, "HOURLY", windowStart);
    expect(accAfter?.spentAmount).toBe("200");

    // Invariant: Window Type Immutability
    const illegalPolicyUpdate: DemoPolicy = {
      ...policyRev2,
      budget: {
        window: "DAILY",
        maxCumulativeAmount: "1000",
      },
    };
    expect(() => policyStore.updatePolicy(illegalPolicyUpdate)).toThrow(
      "Cannot change budget window type",
    );
  });

  it("strictly enforces window type immutability across intervening unbudgeted revisions and restoration (Fix 2)", () => {
    const dbFile = createTestDbPath();
    const startTime = 1_800_000_100;
    const { authStore, policyStore, keyStore } = setupStores(dbFile, startTime);
    const key = createKeypair();

    // 1. Policy registered with HOURLY window
    const policyRev1: DemoPolicy = {
      version: 1,
      policyId: "two-step-bypass-policy",
      allowedTarget: TARGET,
      allowedRecipient: RECIPIENT,
      allowedSelector: "0xa9059cbb",
      maxAmount: "100",
      validFrom: 1_800_000_000,
      expiresAt: 1_800_086_400,
      revoked: false,
      budget: {
        window: "HOURLY",
        maxCumulativeAmount: "500",
      },
    };
    policyStore.registerPolicy(policyRev1);

    keyStore.registerKey({
      keyId: "issuer-01",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 1_800_000_000,
      expiresAtSeconds: 1_800_086_400,
    });

    const req: TransactionRequest = {
      chainId: "1",
      sender: "0x3333333333333333333333333333333333333333",
      target: TARGET,
      calldata: encodeCalldata(RECIPIENT, 100n),
      value: "0",
    };

    // Spend 100 in HOURLY window
    const issue1 = issueAllow(
      authStore,
      { keyId: "issuer-01", privateKey: key.privateKey },
      "auth-001",
      policyRev1.policyId,
      req,
    );
    expect(consumeSignedTransactionAuthorizationV3(authStore, issue1.artifact, issue1.envelope, req).decision).toBe("ALLOW");

    // 2. Update policy to remove budget (Revision 2, unbudgeted) - must succeed
    const policyRev2: DemoPolicy = {
      ...policyRev1,
      budget: undefined,
    };
    policyStore.updatePolicy(policyRev2);
    expect(policyStore.getPolicy("two-step-bypass-policy")?.policy.budget).toBeUndefined();

    // 3. Attempt two-step bypass: update policy to re-introduce budget with DAILY window (Revision 3) - MUST FAIL
    const policyRev3Daily: DemoPolicy = {
      ...policyRev1,
      budget: {
        window: "DAILY",
        maxCumulativeAmount: "1000",
      },
    };
    expect(() => policyStore.updatePolicy(policyRev3Daily)).toThrow(
      /Cannot change budget window type from 'HOURLY' to 'DAILY'/,
    );

    // 4. Update policy to re-introduce budget with original HOURLY window (Revision 3) - MUST SUCCEED
    const policyRev3Hourly: DemoPolicy = {
      ...policyRev1,
      budget: {
        window: "HOURLY",
        maxCumulativeAmount: "800",
      },
    };
    const updated = policyStore.updatePolicy(policyRev3Hourly);
    expect(updated.revision).toBe(3);
    expect(updated.policy.budget?.window).toBe("HOURLY");

    // Prior spend (100) must still be preserved in the accumulator!
    const windowStart = calculateBudgetWindowStart(startTime, "HOURLY");
    const acc = authStore.getPolicyBudgetAccumulator("two-step-bypass-policy", "HOURLY", windowStart);
    expect(acc?.spentAmount).toBe("100");

    // 5. Restoration path: Revoke policy, then attempt restorePolicy with DAILY window - MUST FAIL
    policyStore.revokePolicy("two-step-bypass-policy");
    expect(() => policyStore.restorePolicy("two-step-bypass-policy", policyRev3Daily)).toThrow(
      /Cannot change budget window type from 'HOURLY' to 'DAILY'/,
    );

    // Restore with HOURLY window - MUST SUCCEED
    const restored = policyStore.restorePolicy("two-step-bypass-policy", policyRev3Hourly);
    expect(restored.status).toBe("active");
    expect(restored.policy.budget?.window).toBe("HOURLY");
  });

  it("persists cumulative budget accumulators across database close and reopen", () => {
    const dbFile = createTestDbPath();
    const startTime = 1_800_000_100;
    const windowStart = calculateBudgetWindowStart(startTime, "HOURLY");
    const key = createKeypair();

    // Session 1: Register, issue, consume
    {
      const clock = new TestClock(startTime);
      const authStore = new SQLiteAuthorizationStore(dbFile, clock);
      const policyStore = authStore.getPolicyStore();
      const keyStore = authStore.getKeyStore();

      policyStore.registerPolicy({
        version: 1,
        policyId: "persist-budget-policy",
        allowedTarget: TARGET,
        allowedRecipient: RECIPIENT,
        allowedSelector: "0xa9059cbb",
        maxAmount: "100",
        validFrom: 1_800_000_000,
        expiresAt: 1_800_086_400,
        revoked: false,
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: "300",
        },
      });

      keyStore.registerKey({
        keyId: "issuer-01",
        publicKey: key.publicKey,
        status: "active",
        validFromSeconds: 1_800_000_000,
        expiresAtSeconds: 1_800_086_400,
      });

      const req: TransactionRequest = {
        chainId: "1",
        sender: "0x3333333333333333333333333333333333333333",
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 100n),
        value: "0",
      };

      const issue = issueAllow(
        authStore,
        { keyId: "issuer-01", privateKey: key.privateKey },
        "auth-p-1",
        "persist-budget-policy",
        req,
      );
      expect(consumeSignedTransactionAuthorizationV3(authStore, issue.artifact, issue.envelope, req).decision).toBe("ALLOW");

      authStore.close();
    }

    // Session 2: Reopen from disk, verify accumulator state, and continue spending
    {
      const clock = new TestClock(startTime + 60);
      const authStore = new SQLiteAuthorizationStore(dbFile, clock);
      openStores.push(authStore);

      const acc = authStore.getPolicyBudgetAccumulator("persist-budget-policy", "HOURLY", windowStart);
      expect(acc).not.toBeNull();
      expect(acc?.spentAmount).toBe("100");

      const req: TransactionRequest = {
        chainId: "1",
        sender: "0x3333333333333333333333333333333333333333",
        target: TARGET,
        calldata: encodeCalldata(RECIPIENT, 100n),
        value: "0",
      };

      const issue = issueAllow(
        authStore,
        { keyId: "issuer-01", privateKey: key.privateKey },
        "auth-p-2",
        "persist-budget-policy",
        req,
      );
      expect(consumeSignedTransactionAuthorizationV3(authStore, issue.artifact, issue.envelope, req).decision).toBe("ALLOW");

      const accUpdated = authStore.getPolicyBudgetAccumulator("persist-budget-policy", "HOURLY", windowStart);
      expect(accUpdated?.spentAmount).toBe("200");
    }
  });

  it("handles Web3UserEngine high-level budget status API", () => {
    const dbFile = createTestDbPath();
    const now = Math.floor(Date.now() / 1000);
    const engine = Web3UserEngine.open({ databasePath: dbFile });
    openEngines.push(engine);

    const policy: DemoPolicy = {
      version: 1,
      policyId: "engine-budget-policy",
      allowedTarget: TARGET,
      allowedRecipient: RECIPIENT,
      allowedSelector: "0xa9059cbb",
      maxAmount: "100",
      validFrom: now - 1000,
      expiresAt: now + 10000,
      revoked: false,
      budget: {
        window: "HOURLY",
        maxCumulativeAmount: "500",
      },
    };

    engine.policies.register(policy);

    // Before any spending
    const statusInitial = engine.policies.getBudgetStatus("engine-budget-policy", now);
    const expectedStart = calculateBudgetWindowStart(now, "HOURLY");
    const expectedEnd = calculateBudgetWindowEnd(now, "HOURLY");

    expect(statusInitial).toEqual({
      hasBudget: true,
      window: "HOURLY",
      windowStart: expectedStart,
      windowEnd: expectedEnd,
      spentAmount: "0",
      maxCumulativeAmount: "500",
      remainingAmount: "500",
    });

    // Unbudgeted policy returns { hasBudget: false }
    const unbudgetedPolicy: DemoPolicy = {
      ...policy,
      policyId: "unbudgeted-policy",
      budget: undefined,
    };
    engine.policies.register(unbudgetedPolicy);
    expect(engine.policies.getBudgetStatus("unbudgeted-policy", now)).toEqual({
      hasBudget: false,
    });

    // Regression check (Fix 1): Rejects invalid timestamps: NaN, negative, fractional float, unsafe integer
    expect(() => engine.policies.getBudgetStatus("engine-budget-policy", NaN)).toThrow(
      /effectiveNowSeconds must be a non-negative safe integer/,
    );
    expect(() => engine.policies.getBudgetStatus("engine-budget-policy", -1)).toThrow(
      /effectiveNowSeconds must be a non-negative safe integer/,
    );
    expect(() => engine.policies.getBudgetStatus("engine-budget-policy", -3600)).toThrow(
      /effectiveNowSeconds must be a non-negative safe integer/,
    );
    expect(() => engine.policies.getBudgetStatus("engine-budget-policy", 1800000100.5)).toThrow(
      /effectiveNowSeconds must be a non-negative safe integer/,
    );
    expect(() => engine.policies.getBudgetStatus("engine-budget-policy", Number.MAX_SAFE_INTEGER + 1000)).toThrow(
      /effectiveNowSeconds must be a non-negative safe integer/,
    );
    // Consistent validation on unbudgeted policies
    expect(() => engine.policies.getBudgetStatus("unbudgeted-policy", NaN)).toThrow(
      /effectiveNowSeconds must be a non-negative safe integer/,
    );
    expect(() => engine.policies.getBudgetStatus("unbudgeted-policy", -50)).toThrow(
      /effectiveNowSeconds must be a non-negative safe integer/,
    );
  });

  it("smoothly executes additive schema initialization on existing pre-M8 databases", () => {
    const dbFile = createTestDbPath("legacy-v3.sqlite");

    // Manually create pre-M8 tables without policy_budget_accumulators
    const rawDb = new DatabaseSync(dbFile);
    rawDb.exec(`
      CREATE TABLE system_clock_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        high_water_seconds INTEGER NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      INSERT INTO system_clock_state (id, high_water_seconds) VALUES (1, 1000);
      CREATE TABLE policies (
        policy_id TEXT PRIMARY KEY,
        current_revision INTEGER NOT NULL,
        status TEXT NOT NULL,
        policy_json TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE consumed_authorization_ids (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT NOT NULL,
        state TEXT NOT NULL,
        consumed_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);
    rawDb.close();

    // Open with SQLiteAuthorizationStore: ensureGovernanceTables runs
    const clock = new TestClock(1050);
    const authStore = new SQLiteAuthorizationStore(dbFile, clock);
    openStores.push(authStore);

    // Verify policy_budget_accumulators was additively created
    const accum = authStore.getPolicyBudgetAccumulator("non-existent", "HOURLY", 0);
    expect(accum).toBeNull();

    const list = authStore.listPolicyBudgetAccumulators("non-existent");
    expect(list).toEqual([]);
  });

  it("guarantees complete transaction rollback on budget denial with zero partial writes", () => {
    const dbFile = createTestDbPath();
    const startTime = 1_800_000_100;
    const { authStore, policyStore, keyStore } = setupStores(dbFile, startTime);
    const key = createKeypair();

    const policy: DemoPolicy = {
      version: 1,
      policyId: "rollback-budget-policy",
      allowedTarget: TARGET,
      allowedRecipient: RECIPIENT,
      allowedSelector: "0xa9059cbb",
      maxAmount: "100",
      validFrom: 1_800_000_000,
      expiresAt: 1_800_086_400,
      revoked: false,
      budget: {
        window: "HOURLY",
        maxCumulativeAmount: "100",
      },
    };

    policyStore.registerPolicy(policy);
    keyStore.registerKey({
      keyId: "issuer-01",
      publicKey: key.publicKey,
      status: "active",
      validFromSeconds: 1_800_000_000,
      expiresAtSeconds: 1_800_086_400,
    });

    const windowStart = calculateBudgetWindowStart(startTime, "HOURLY");

    // Spend 60 units first
    const req1: TransactionRequest = {
      chainId: "1",
      sender: "0x3333333333333333333333333333333333333333",
      target: TARGET,
      calldata: encodeCalldata(RECIPIENT, 60n),
      value: "0",
    };
    const issue1 = issueAllow(
      authStore,
      { keyId: "issuer-01", privateKey: key.privateKey },
      "auth-001",
      policy.policyId,
      req1,
    );
    expect(consumeSignedTransactionAuthorizationV3(authStore, issue1.artifact, issue1.envelope, req1).decision).toBe("ALLOW");

    // Spend 50 units (60 + 50 = 110 > 100 max) -> DENIED
    const req2: TransactionRequest = {
      ...req1,
      calldata: encodeCalldata(RECIPIENT, 50n),
    };
    const issue2 = issueAllow(
      authStore,
      { keyId: "issuer-01", privateKey: key.privateKey },
      "auth-002",
      policy.policyId,
      req2,
    );
    const consumeDenied = consumeSignedTransactionAuthorizationV3(
      authStore,
      issue2.artifact,
      issue2.envelope,
      req2,
    );
    expect(consumeDenied.decision).toBe("DENY");

    // Direct SQLite table checks to prove zero partial writes
    const db = authStore.getDatabase();
    const authRow = db.prepare(
      "SELECT state, consumed_at FROM consumed_authorization_ids WHERE authorization_id = 'auth-002'"
    ).get() as { state: string; consumed_at: string | null };

    expect(authRow.state).toBe("issued");
    expect(authRow.consumed_at).toBeNull();

    const accumRow = db.prepare(
      "SELECT spent_amount FROM policy_budget_accumulators WHERE policy_id = ? AND window_start = ?"
    ).get(policy.policyId, windowStart) as { spent_amount: string };

    expect(accumRow.spent_amount).toBe("60");
  });
});
