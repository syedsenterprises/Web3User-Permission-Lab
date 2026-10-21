import { describe, expect, it } from "vitest";
import {
  prepareTransactionAuthorization,
  revalidateTransactionAuthorization,
} from "../src/policy-transaction.js";
import type { DemoPolicy } from "../src/policy.js";
import type { TransactionRequest } from "../src/transaction-envelope.js";

const target = "0x1111111111111111111111111111111111111111";
const sender = "0x2222222222222222222222222222222222222222";
const recipient = "0x3333333333333333333333333333333333333333";

const amount = 5n;
const calldata =
  "0xa9059cbb" +
  recipient.slice(2).padStart(64, "0") +
  amount.toString(16).padStart(64, "0");

const request: TransactionRequest = {
  chainId: "1",
  sender,
  target,
  calldata,
  value: "0",
};

const policy: DemoPolicy = {
  version: 1,
  policyId: "integration-test",
  allowedTarget: target,
  allowedRecipient: recipient,
  allowedSelector: "0xa9059cbb",
  maxAmount: "10",
  validFrom: 50,
  expiresAt: 200,
  revoked: false,
};

const context = { nowSeconds: 100 };

describe("policy-transaction integration", () => {
  it("approves a valid transfer and creates an envelope", () => {
    const result = prepareTransactionAuthorization(
      policy,
      request,
      context,
    );

    expect(result.decision).toBe("ALLOW");
    if (result.decision !== "ALLOW") return;

    expect(result.envelope.request).toEqual(request);
  });

  it("denies a recipient that is not allowlisted", () => {
    const result = prepareTransactionAuthorization(
      { ...policy, allowedRecipient: sender },
      request,
      context,
    );

    expect(result.decision).toBe("DENY");
  });

  it("denies a revoked policy", () => {
    const result = prepareTransactionAuthorization(
      { ...policy, revoked: true },
      request,
      context,
    );

    expect(result.decision).toBe("DENY");
  });

  it("denies an expired policy", () => {
    const result = prepareTransactionAuthorization(
      policy,
      request,
      { nowSeconds: policy.expiresAt },
    );

    expect(result.decision).toBe("DENY");
  });

  it("returns UNKNOWN for unsupported calldata", () => {
    const result = prepareTransactionAuthorization(
      policy,
      { ...request, calldata: "0x1234" },
      context,
    );

    expect(result.decision).toBe("UNKNOWN");
  });

  it("revalidates an unchanged approved transaction", () => {
    const prepared = prepareTransactionAuthorization(
      policy,
      request,
      context,
    );

    expect(prepared.decision).toBe("ALLOW");
    if (prepared.decision !== "ALLOW") return;

    const result = revalidateTransactionAuthorization(
      policy,
      prepared.envelope,
      request,
      context,
    );

    expect(result.decision).toBe("ALLOW");
  });

  it.each([
    ["chain ID", { chainId: "2" }],
    ["sender", { sender: recipient }],
    ["target", { target: sender }],
    ["calldata", { calldata: calldata.slice(0, -2) + "00" }],
    ["native value", { value: "1" }],
  ])("denies a transaction changed in its %s", (_field, change) => {
    const prepared = prepareTransactionAuthorization(
      policy,
      request,
      context,
    );

    expect(prepared.decision).toBe("ALLOW");
    if (prepared.decision !== "ALLOW") return;

    const result = revalidateTransactionAuthorization(
      policy,
      prepared.envelope,
      { ...request, ...change },
      context,
    );

    expect(result.decision).toBe("DENY");
  });

  it("denies revalidation after the policy is revoked", () => {
    const prepared = prepareTransactionAuthorization(
      policy,
      request,
      context,
    );

    expect(prepared.decision).toBe("ALLOW");
    if (prepared.decision !== "ALLOW") return;

    const result = revalidateTransactionAuthorization(
      { ...policy, revoked: true },
      prepared.envelope,
      request,
      context,
    );

    expect(result.decision).toBe("DENY");
  });

  it("denies revalidation after the policy expires", () => {
    const prepared = prepareTransactionAuthorization(
      policy,
      request,
      context,
    );

    expect(prepared.decision).toBe("ALLOW");
    if (prepared.decision !== "ALLOW") return;

    const result = revalidateTransactionAuthorization(
      policy,
      prepared.envelope,
      request,
      { nowSeconds: policy.expiresAt },
    );

    expect(result.decision).toBe("DENY");
  });

  it("denies a transfer above the policy amount limit", () => {
    const excessiveCalldata =
      "0xa9059cbb" +
      recipient.slice(2).padStart(64, "0") +
      "b".padStart(64, "0");

    const result = prepareTransactionAuthorization(
      policy,
      { ...request, calldata: excessiveCalldata },
      context,
    );

    expect(result.decision).toBe("DENY");
  });

  it("returns UNKNOWN for malformed ABI recipient padding", () => {
    const malformedCalldata =
      "0xa9059cbb" +
      "f".repeat(24) +
      recipient.slice(2) +
      amount.toString(16).padStart(64, "0");

    const result = prepareTransactionAuthorization(
      policy,
      { ...request, calldata: malformedCalldata },
      context,
    );

    expect(result.decision).toBe("UNKNOWN");
  });

  it("denies revalidation with a malformed candidate", () => {
    const prepared = prepareTransactionAuthorization(
      policy,
      request,
      context,
    );

    expect(prepared.decision).toBe("ALLOW");
    if (prepared.decision !== "ALLOW") return;

    const result = revalidateTransactionAuthorization(
      policy,
      prepared.envelope,
      null,
      context,
    );

    expect(result.decision).toBe("DENY");
  });
});
