import { describe, expect, it } from "vitest";
import { evaluate as sdkEvaluate, type DemoPolicy, type EvaluationContext, type ProposedAction } from "../src/policy.js";
import {
  evaluate as demoEvaluate,
  evaluateDetailed,
  encodeTransferCalldata,
  type EvaluationCheck,
} from "../website-preview/js/evaluator.js";

const TARGET = "0x1111111111111111111111111111111111111111";
const OTHER_TARGET = "0x2222222222222222222222222222222222222222";
const RECIPIENT = "0x3333333333333333333333333333333333333333";
const OTHER_RECIPIENT = "0x4444444444444444444444444444444444444444";
const SELECTOR = "0xa9059cbb";
const OTHER_SELECTOR = "0x095ea7b3";

function buildCalldata(selector: string, amount: bigint, recipient: string): string {
  const recipientWord = recipient.slice(2).toLowerCase().padStart(64, "0");
  const amountWord = amount.toString(16).padStart(64, "0");
  return `0x${selector.slice(2)}${recipientWord}${amountWord}`;
}

const basePolicy: DemoPolicy = {
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

const baseAction: ProposedAction = {
  target: TARGET,
  calldata: buildCalldata(SELECTOR, 50n, RECIPIENT),
  amount: "50",
};

const baseContext: EvaluationContext = {
  nowSeconds: 1_800_000_100,
};

describe("Client Evaluator Parity with SDK src/policy.ts", () => {
  function verifyParity(policy: unknown, action: unknown, context: unknown) {
    const sdkRes = sdkEvaluate(policy, action, context);
    const demoRes = demoEvaluate(policy, action, context);
    expect(demoRes.decision).toBe(sdkRes.decision);
    expect(demoRes.reasons).toEqual(sdkRes.reasons);
  }

  it("matches SDK on compliant transfer (ALLOW)", () => {
    verifyParity(basePolicy, baseAction, baseContext);
    const detailed = evaluateDetailed(basePolicy, baseAction, baseContext);
    expect(detailed.decision).toBe("ALLOW");
    expect(detailed.checks.every((c: EvaluationCheck) => c.passed)).toBe(true);
  });

  it("matches SDK on unapproved target (DENY)", () => {
    verifyParity(basePolicy, { ...baseAction, target: OTHER_TARGET }, baseContext);
  });

  it("matches SDK on unapproved selector (DENY)", () => {
    verifyParity(
      basePolicy,
      { ...baseAction, calldata: buildCalldata(OTHER_SELECTOR, 50n, RECIPIENT) },
      baseContext,
    );
  });

  it("matches SDK on excessive amount (DENY)", () => {
    verifyParity(
      basePolicy,
      {
        ...baseAction,
        calldata: buildCalldata(SELECTOR, 101n, RECIPIENT),
        amount: "101",
      },
      baseContext,
    );
  });

  it("matches SDK on revoked policy (DENY)", () => {
    verifyParity({ ...basePolicy, revoked: true }, baseAction, baseContext);
  });

  it("matches SDK on amount zero (ALLOW)", () => {
    verifyParity(
      basePolicy,
      {
        ...baseAction,
        calldata: buildCalldata(SELECTOR, 0n, RECIPIENT),
        amount: "0",
      },
      baseContext,
    );
  });

  it("matches SDK on expired policy (DENY)", () => {
    verifyParity(basePolicy, baseAction, { nowSeconds: basePolicy.expiresAt });
    verifyParity(basePolicy, baseAction, { nowSeconds: basePolicy.expiresAt + 10 });
  });

  it("matches SDK on not-yet-valid policy (DENY)", () => {
    verifyParity(basePolicy, baseAction, { nowSeconds: basePolicy.validFrom - 1 });
  });

  it("matches SDK on unapproved recipient (DENY)", () => {
    verifyParity(
      basePolicy,
      {
        ...baseAction,
        calldata: buildCalldata(SELECTOR, 50n, OTHER_RECIPIENT),
      },
      baseContext,
    );
  });

  it("matches SDK on claimed amount vs calldata mismatch (UNKNOWN)", () => {
    verifyParity(
      basePolicy,
      {
        ...baseAction,
        amount: "99", // Calldata encodes 50n
      },
      baseContext,
    );
  });

  it("matches SDK on malformed calldata (UNKNOWN)", () => {
    verifyParity(
      basePolicy,
      {
        ...baseAction,
        calldata: "0xdeadbeef",
      },
      baseContext,
    );
  });

  it("matches SDK on malformed policy schema (UNKNOWN)", () => {
    verifyParity({ invalid: true }, baseAction, baseContext);
    verifyParity(null, baseAction, baseContext);
  });

  it("correctly encodes transfer calldata with helper", () => {
    const encoded = encodeTransferCalldata(RECIPIENT, "500000000");
    expect(encoded.slice(0, 10)).toBe("0xa9059cbb");
    expect(encoded).toBe(buildCalldata(SELECTOR, 500000000n, RECIPIENT));
  });
});
