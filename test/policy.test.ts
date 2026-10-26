
import { describe, expect, it } from "vitest";
import {
  evaluate,
  normalizeDemoPolicy,
  calculateBudgetWindowStart,
  calculateBudgetWindowEnd,
  BUDGET_WINDOW_SECONDS,
  type BudgetWindowType,
  type DemoPolicy,
  type EvaluationContext,
  type PolicyBudgetConfig,
  type ProposedAction,
} from "../src/policy.js";

const TARGET = "0x1111111111111111111111111111111111111111";
const OTHER_TARGET = "0x2222222222222222222222222222222222222222";

const SELECTOR = "0xa9059cbb"; // transfer(address,uint256)
const OTHER_SELECTOR = "0x095ea7b3"; // approve(address,uint256)

const RECIPIENT = "0x3333333333333333333333333333333333333333";
const OTHER_RECIPIENT = "0x4444444444444444444444444444444444444444";

const recipientWord = (address: string) =>
  address.slice(2).toLowerCase().padStart(64, "0");

const uintWord = (amount: bigint) =>
  amount.toString(16).padStart(64, "0");

const calldata = (
  selector = SELECTOR,
  amount = 50n,
  recipient = RECIPIENT,
) =>
  `0x${selector.slice(2)}${recipientWord(recipient)}${uintWord(amount)}`;

const policy: DemoPolicy = {
  version: 1,
  policyId: "demo-policy-001",
  allowedTarget: TARGET,
  allowedRecipient: RECIPIENT,
  allowedSelector: SELECTOR,
  maxAmount: "100",
  validFrom: 1_800_000_000,
  expiresAt: 1_800_086_400,
  revoked: false,
};

const action: ProposedAction = {
  target: TARGET,
  calldata: calldata(),
  amount: "50",
};

const context: EvaluationContext = {
  nowSeconds: 1_800_000_100,
};

const run = (
  p: unknown = policy,
  a: unknown = action,
  c: unknown = context,
) => evaluate(p, a, c);

describe("Web3User demo policy evaluator", () => {
  it("allows a compliant transfer", () => {
    expect(run().decision).toBe("ALLOW");
  });

  it("denies an unapproved target contract", () => {
    expect(run(policy, { ...action, target: OTHER_TARGET }).decision).toBe("DENY");
  });

  it("denies a selector not allowlisted by the policy", () => {
    expect(
      run(policy, {
        ...action,
        calldata: calldata(OTHER_SELECTOR),
      }).decision,
    ).toBe("DENY");
  });

  it("denies an excessive amount encoded in calldata", () => {
    expect(
      run(policy, {
        ...action,
        calldata: calldata(SELECTOR, 101n),
        amount: "101",
      }).decision,
    ).toBe("DENY");
  });

  it("denies a revoked policy", () => {
    expect(run({ ...policy, revoked: true }).decision).toBe("DENY");
  });

  it("allows amount zero", () => {
    expect(
      run(policy, {
        ...action,
        calldata: calldata(SELECTOR, 0n),
        amount: "0",
      }).decision,
    ).toBe("ALLOW");
  });

  it("allows the exact per-action maximum", () => {
    expect(
      run(policy, {
        ...action,
        calldata: calldata(SELECTOR, 100n),
        amount: "100",
      }).decision,
    ).toBe("ALLOW");
  });

  it("denies one unit above the per-action maximum", () => {
    expect(
      run(policy, {
        ...action,
        calldata: calldata(SELECTOR, 101n),
        amount: "101",
      }).decision,
    ).toBe("DENY");
  });

  it("allows an action exactly at validFrom", () => {
    expect(
      run(policy, action, { nowSeconds: policy.validFrom }).decision,
    ).toBe("ALLOW");
  });

  it("denies an action before validFrom", () => {
    expect(
      run(policy, action, { nowSeconds: policy.validFrom - 1 }).decision,
    ).toBe("DENY");
  });

  it("denies an action exactly at expiresAt", () => {
    expect(
      run(policy, action, { nowSeconds: policy.expiresAt }).decision,
    ).toBe("DENY");
  });

  it("denies an action after expiresAt", () => {
    expect(
      run(policy, action, { nowSeconds: policy.expiresAt + 1 }).decision,
    ).toBe("DENY");
  });

  it("returns UNKNOWN for equal policy-window endpoints", () => {
    expect(
      run({ ...policy, expiresAt: policy.validFrom }).decision,
    ).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for a reversed policy window", () => {
    expect(
      run({ ...policy, expiresAt: policy.validFrom - 1 }).decision,
    ).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for a negative policy timestamp", () => {
    expect(run({ ...policy, validFrom: -1 }).decision).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for a negative trusted timestamp", () => {
    expect(run(policy, action, { nowSeconds: -1 }).decision).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for a non-safe-integer timestamp", () => {
    expect(
      run(policy, action, {
        nowSeconds: Number.MAX_SAFE_INTEGER + 1,
      }).decision,
    ).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for a malformed policy target", () => {
    expect(run({ ...policy, allowedTarget: "bad" }).decision).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for a malformed policy recipient", () => {
    expect(run({ ...policy, allowedRecipient: "bad" }).decision).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for a malformed policy selector", () => {
    expect(run({ ...policy, allowedSelector: "0x123" }).decision).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for an unsupported policy selector", () => {
    expect(
      run({ ...policy, allowedSelector: OTHER_SELECTOR }).decision,
    ).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for a malformed policy amount limit", () => {
    expect(run({ ...policy, maxAmount: "-1" }).decision).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for a malformed action address", () => {
    expect(run(policy, { ...action, target: "bad" }).decision).toBe("UNKNOWN");
  });

  it("returns UNKNOWN when calldata is missing", () => {
    expect(
      run(policy, { target: TARGET, amount: "50" }).decision,
    ).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for malformed or odd-length calldata", () => {
    expect(
      run(policy, { ...action, calldata: "0xa9059cbbf" }).decision,
    ).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for calldata that exceeds the size limit", () => {
    expect(
      run(policy, {
        ...action,
        calldata: `0x${"aa".repeat(4097)}`,
      }).decision,
    ).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for malformed amount strings", () => {
    for (const amount of [
      "-1",
      "1.5",
      "01",
      "1e3",
      "",
      " 1",
      "0x10",
      "9".repeat(79),
    ]) {
      expect(
        run(policy, { ...action, amount }),
        `amount=${amount}`,
      ).toHaveProperty("decision", "UNKNOWN");
    }
  });

  it("returns UNKNOWN when the claimed amount differs from calldata", () => {
    expect(
      run(policy, {
        ...action,
        calldata: calldata(SELECTOR, 500n),
        amount: "10",
      }).decision,
    ).toBe("UNKNOWN");
  });

  it("denies a recipient that is not allowlisted", () => {
    expect(
      run(policy, {
        ...action,
        calldata: calldata(SELECTOR, 50n, OTHER_RECIPIENT),
        amount: "50",
      }).decision,
    ).toBe("DENY");
  });

  it("returns UNKNOWN for malformed ABI address padding", () => {
    const malformed =
      `0x${SELECTOR.slice(2)}${"1".repeat(64)}${uintWord(50n)}`;

    expect(
      run(policy, {
        ...action,
        calldata: malformed,
        amount: "50",
      }).decision,
    ).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for calldata with trailing bytes", () => {
    expect(
      run(policy, {
        ...action,
        calldata: `${calldata()}0000`,
        amount: "50",
      }).decision,
    ).toBe("UNKNOWN");
  });

  it("returns UNKNOWN when action data is missing", () => {
    expect(run(policy, { target: TARGET }).decision).toBe("UNKNOWN");
  });

  it("returns UNKNOWN when trusted context is missing", () => {
    expect(run(policy, action, null).decision).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for null, arrays, or primitive inputs", () => {
    expect(run(null, action, context).decision).toBe("UNKNOWN");
    expect(run(policy, null, context).decision).toBe("UNKNOWN");
    expect(run([], action, context).decision).toBe("UNKNOWN");
    expect(run(policy, "not an action", context).decision).toBe("UNKNOWN");
  });

  // Additional adversarial tests

  it("allows case-insensitive target and recipient addresses", () => {
    const mixedCaseTarget = `0x${TARGET.slice(2).toUpperCase()}`;
    const mixedCaseRecipient = `0x${RECIPIENT.slice(2).toUpperCase()}`;

    expect(
      run(
        {
          ...policy,
          allowedTarget: mixedCaseTarget,
          allowedRecipient: mixedCaseRecipient,
        },
        {
          ...action,
          target: TARGET,
          calldata: calldata(SELECTOR, 50n, RECIPIENT),
        },
      ).decision,
    ).toBe("ALLOW");
  });

  it("allows the maximum uint256 amount when the policy permits it", () => {
    const maxUint256 = (1n << 256n) - 1n;

    expect(
      run(
        { ...policy, maxAmount: maxUint256.toString() },
        {
          ...action,
          calldata: calldata(SELECTOR, maxUint256),
          amount: maxUint256.toString(),
        },
      ).decision,
    ).toBe("ALLOW");
  });

  it("returns UNKNOWN for a policy with an invalid version", () => {
    expect(run({ ...policy, version: 2 }).decision).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for a policy with a blank policy ID", () => {
    expect(run({ ...policy, policyId: "   " }).decision).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for non-hex calldata", () => {
    expect(
      run(policy, { ...action, calldata: `0x${"z".repeat(136)}` }).decision,
    ).toBe("UNKNOWN");
  });

  it("returns UNKNOWN for a calldata string longer than the permitted limit", () => {
    expect(
      run(policy, {
        ...action,
        calldata: `0x${"a".repeat(8194)}`,
      }).decision,
    ).toBe("UNKNOWN");
  });

  describe("Milestone 8: Stateful Cumulative Budget Invariants", () => {
    it("calculates deterministic hourly and daily window boundaries", () => {
      const t = 1_800_000_123;
      const hourlyStart = calculateBudgetWindowStart(t, "HOURLY");
      const hourlyEnd = calculateBudgetWindowEnd(t, "HOURLY");
      expect(hourlyStart).toBe(1_800_000_000);
      expect(hourlyEnd).toBe(1_800_003_600);
      expect(hourlyEnd - hourlyStart).toBe(BUDGET_WINDOW_SECONDS.HOURLY);

      const dailyStart = calculateBudgetWindowStart(t, "DAILY");
      const dailyEnd = calculateBudgetWindowEnd(t, "DAILY");
      expect(dailyStart).toBe(Math.floor(t / 86400) * 86400);
      expect(dailyEnd).toBe(dailyStart + 86400);
      expect(dailyEnd - dailyStart).toBe(BUDGET_WINDOW_SECONDS.DAILY);

      // Boundary tests
      expect(calculateBudgetWindowStart(1_800_000_000, "HOURLY")).toBe(1_800_000_000);
      expect(calculateBudgetWindowStart(1_800_003_599, "HOURLY")).toBe(1_800_000_000);
      expect(calculateBudgetWindowStart(1_800_003_600, "HOURLY")).toBe(1_800_003_600);

      // Rejects invalid timestamps or window types
      expect(() => calculateBudgetWindowStart(-1, "HOURLY")).toThrow();
      expect(() => calculateBudgetWindowStart(NaN, "HOURLY")).toThrow();
      expect(() => calculateBudgetWindowStart(100, "WEEKLY" as BudgetWindowType)).toThrow();
    });

    it("normalizes policies with valid cumulative budget configuration", () => {
      const budgeted: DemoPolicy = {
        ...policy,
        maxAmount: "500",
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: "2000",
        },
      };
      const normalized = normalizeDemoPolicy(budgeted);
      expect(normalized).not.toBeNull();
      expect(normalized?.budget).toEqual({
        window: "HOURLY",
        maxCumulativeAmount: "2000",
      });
    });

    it("rejects policies where per-action maxAmount exceeds cumulative budget", () => {
      const invalidPolicy: DemoPolicy = {
        ...policy,
        maxAmount: "2500",
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: "2000",
        },
      };
      expect(normalizeDemoPolicy(invalidPolicy)).toBeNull();
    });

    it("rejects policies with invalid budget window or maxCumulativeAmount", () => {
      expect(
        normalizeDemoPolicy({
          ...policy,
          budget: {
            window: "MONTHLY" as unknown as BudgetWindowType,
            maxCumulativeAmount: "1000",
          },
        }),
      ).toBeNull();

      expect(
        normalizeDemoPolicy({
          ...policy,
          budget: {
            window: "HOURLY",
            maxCumulativeAmount: "-50",
          },
        }),
      ).toBeNull();
    });

    it("handles currentWindowSpent context when evaluating budgeted policy", () => {
      const budgeted: DemoPolicy = {
        ...policy,
        maxAmount: "500",
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: "1000",
        },
      };
      // When context.currentWindowSpent is omitted, per-action checks are evaluated without cumulative check
      const res1 = evaluate(budgeted, action, context);
      expect(res1.decision).toBe("ALLOW");

      // Invalid currentWindowSpent returns UNKNOWN
      const res2 = evaluate(budgeted, action, { ...context, currentWindowSpent: "invalid" });
      expect(res2.decision).toBe("UNKNOWN");
      expect(res2.reasons[0]).toContain("must be a valid uint256 decimal string");
    });

    it("evaluates cumulative budget correctly against prior spend", () => {
      const budgeted: DemoPolicy = {
        ...policy,
        maxAmount: "500",
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: "1000",
        },
      };
      // action amount is 50. Prior spend 900. Total = 950 <= 1000 -> ALLOW
      const allowRes = evaluate(budgeted, action, {
        ...context,
        currentWindowSpent: "900",
      });
      expect(allowRes.decision).toBe("ALLOW");

      // Exactly at limit: Prior spend 950. 950 + 50 = 1000 <= 1000 -> ALLOW
      const boundaryRes = evaluate(budgeted, action, {
        ...context,
        currentWindowSpent: "950",
      });
      expect(boundaryRes.decision).toBe("ALLOW");

      // Exceeds limit: Prior spend 951. 951 + 50 = 1001 > 1000 -> DENY
      const denyRes = evaluate(budgeted, action, {
        ...context,
        currentWindowSpent: "951",
      });
      expect(denyRes.decision).toBe("DENY");
      expect(denyRes.reasons[0]).toContain("Amount exceeds the cumulative spending budget for the hourly window.");
    });

    it("enforces dual limit: per-action maxAmount triggers DENY even if cumulative budget has room", () => {
      const budgeted: DemoPolicy = {
        ...policy,
        maxAmount: "500",
        budget: {
          window: "HOURLY",
          maxCumulativeAmount: "10000",
        },
      };
      // Action amount 600 exceeds per-action 500, even though 0 + 600 <= 10000
      const res = evaluate(
        budgeted,
        {
          ...action,
          calldata: calldata(SELECTOR, 600n),
          amount: "600",
        },
        { ...context, currentWindowSpent: "0" },
      );
      expect(res.decision).toBe("DENY");
      expect(res.reasons[0]).toContain("Amount exceeds the per-action policy limit.");
    });
  });
});
