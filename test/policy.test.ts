
import { describe, expect, it } from "vitest";
import {
  evaluate,
  type DemoPolicy,
  type EvaluationContext,
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
});
