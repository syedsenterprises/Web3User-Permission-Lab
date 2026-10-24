
import { describe, expect, it } from "vitest";
import {
  createTransactionEnvelope,
  matchesTransactionEnvelope,
  type TransactionRequest,
} from "../src/transaction-envelope.js";

const request: TransactionRequest = {
  chainId: "1",
  sender: "0x1111111111111111111111111111111111111111",
  target: "0x2222222222222222222222222222222222222222",
  calldata: "0xa9059cbb",
  value: "0",
};

function createEnvelope(input: unknown = request) {
  const result = createTransactionEnvelope(input);

  if (!result.ok) {
    throw new Error(`Test fixture is invalid: ${result.reason}`);
  }

  return result.envelope;
}

describe("Transaction authorization envelope", () => {
  it("creates an envelope for a valid request", () => {
    expect(createTransactionEnvelope(request).ok).toBe(true);
  });

  it("matches the exact approved request", () => {
    expect(matchesTransactionEnvelope(createEnvelope(), request)).toBe(true);
  });

  it("rejects a changed chain ID", () => {
    expect(
      matchesTransactionEnvelope(createEnvelope(), {
        ...request,
        chainId: "2",
      }),
    ).toBe(false);
  });

  it("rejects a changed sender", () => {
    expect(
      matchesTransactionEnvelope(createEnvelope(), {
        ...request,
        sender: "0x3333333333333333333333333333333333333333",
      }),
    ).toBe(false);
  });

  it("rejects a changed target", () => {
    expect(
      matchesTransactionEnvelope(createEnvelope(), {
        ...request,
        target: "0x4444444444444444444444444444444444444444",
      }),
    ).toBe(false);
  });

  it("rejects changed calldata", () => {
    expect(
      matchesTransactionEnvelope(createEnvelope(), {
        ...request,
        calldata: "0xdeadbeef",
      }),
    ).toBe(false);
  });

  it("rejects a changed native value", () => {
    expect(
      matchesTransactionEnvelope(createEnvelope(), {
        ...request,
        value: "1",
      }),
    ).toBe(false);
  });

  it("accepts equivalent hexadecimal casing", () => {
    const candidate = {
      ...request,
      sender: request.sender.toUpperCase().replace("0X", "0x"),
      target: request.target.toUpperCase().replace("0X", "0x"),
      calldata: request.calldata.toUpperCase().replace("0X", "0x"),
    };

    expect(matchesTransactionEnvelope(createEnvelope(), candidate)).toBe(true);
  });

  it("rejects a zero chain ID", () => {
    expect(
      createTransactionEnvelope({ ...request, chainId: "0" }).ok,
    ).toBe(false);
  });

  it("rejects malformed addresses", () => {
    expect(
      createTransactionEnvelope({ ...request, sender: "bad" }).ok,
    ).toBe(false);
  });

  it("rejects malformed calldata", () => {
    expect(
      createTransactionEnvelope({ ...request, calldata: "0xabc" }).ok,
    ).toBe(false);
  });

  it("rejects a negative native value", () => {
    expect(
      createTransactionEnvelope({ ...request, value: "-1" }).ok,
    ).toBe(false);
  });

  it("rejects a missing or invalid candidate", () => {
    const envelope = createEnvelope();

    expect(matchesTransactionEnvelope(envelope, null)).toBe(false);
    expect(matchesTransactionEnvelope(envelope, {})).toBe(false);
  });

  it("rejects a malformed envelope", () => {
    expect(matchesTransactionEnvelope(null, request)).toBe(false);
    expect(matchesTransactionEnvelope({}, request)).toBe(false);
  });

  it("does not allow mutation of the frozen request snapshot", () => {
    const envelope = createEnvelope();

    expect(Object.isFrozen(envelope)).toBe(true);
    expect(Object.isFrozen(envelope.request)).toBe(true);
  });

  it("rejects a forged envelope with matching request fields", () => {
    const genuine = createEnvelope();

    const forged = {
      request: { ...genuine.request },
    };

    expect(matchesTransactionEnvelope(forged, request)).toBe(false);
  });

  it("enforces calldata length boundaries (Item 4)", () => {
    // 131074 characters = '0x' + 131072 hex characters
    const maxCalldata = "0x" + "bb".repeat(65536);
    const validRes = createTransactionEnvelope({ ...request, calldata: maxCalldata });
    expect(validRes.ok).toBe(true);

    const oversized = maxCalldata + "00";
    const overRes = createTransactionEnvelope({ ...request, calldata: oversized });
    expect(overRes.ok).toBe(false);
    if (!overRes.ok) {
      expect(overRes.reason).toBe("Calldata exceeds maximum allowed length of 131074 characters.");
    }
  });
});
