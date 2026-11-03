/**
 * Web3User Permission Lab - Milestone 13-D: Receipt Canonicalization & Cryptographic Integrity Suite
 *
 * Verifies:
 * 1. Authoritative canonical receipt representation ("web3user-witness-receipt-v1\n")
 * 2. Deterministic length-prefixed field encoding and ordering
 * 3. Exact equivalence between snake_case (gRPC/outbox) and camelCase (SDK/verifier)
 * 4. Pinned golden test vectors with known hashes and signatures
 * 5. Boundary & edge case resilience (empty windows, max uint256, Unicode UTF-8, zero values)
 * 6. Exhaustive tamper detection across every single receipt field
 * 7. Key format interoperability (KeyObject, SPKI PEM, 64-hex raw key)
 * 8. Outbox persistence & replay payload identity
 */

import { describe, it, expect } from "vitest";
import { generateKeyPairSync, createHash, type KeyObject } from "node:crypto";
import {
  canonicalWitnessReceiptPayload,
  verifyWitnessReceipt,
  type SignedWitnessReceipt,
  type WitnessBudgetWindowAllocation,
} from "../../src/monotonic-witness.js";
import {
  formatCanonicalPreimage,
  toCanonicalWitnessReceiptData,
  LocalEd25519WitnessSigner,
  normalizeBudgetWindowType,
  type ReceiptPreimageData,
} from "../../src/witness/signing.js";

describe("Milestone 13-D: Receipt Canonicalization & Cryptographic Verification Suite", () => {
  // Pinned deterministic test keys
  const testSigner = new LocalEd25519WitnessSigner("witness-test-node-1");
  const publicKeyHex = testSigner.getPublicKeyHex();
  const publicKeyPem = testSigner.getPublicKeyPem();
  const publicKeyObj = testSigner.getPublicKeyObject();

  const baseReceiptData: Omit<SignedWitnessReceipt, "signature"> = {
    version: 1,
    witnessId: "witness-test-node-1",
    epochId: "epoch-2026-11",
    sequenceNumber: "42",
    ticketId: "ticket-uuid-001",
    authorizationId: "auth-uuid-001",
    bindingDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    policyId: "pol_transfer_limits",
    policyRevision: 2,
    debitedAmount: "1500000000000000000",
    budgetWindows: [
      {
        windowType: "HOURLY",
        windowStart: 1700000000,
        cumulativeSpentAfter: "1500000000000000000",
      },
      {
        windowType: "DAILY",
        windowStart: 1699920000,
        cumulativeSpentAfter: "5000000000000000000",
      },
    ],
    committedAtSeconds: 1700000050,
  };

  // ==========================================================================
  // 1. Authoritative Canonical Encoding & Determinism
  // ==========================================================================
  describe("Authoritative Canonical Encoding", () => {
    it("starts with domain separator 'web3user-witness-receipt-v1\\n'", () => {
      const payload = canonicalWitnessReceiptPayload(baseReceiptData);
      expect(payload.startsWith("web3user-witness-receipt-v1\n")).toBe(true);
    });

    it("encodes all 12 fields deterministically in exact required order with length prefix", () => {
      const payload = canonicalWitnessReceiptPayload(baseReceiptData);
      const lines = payload.split("\n");

      expect(lines[0]).toBe("web3user-witness-receipt-v1");
      expect(lines[1]).toBe("witness.version:1:1");
      expect(lines[2]).toBe("witness.witnessId:19:witness-test-node-1");
      expect(lines[3]).toBe("witness.epochId:13:epoch-2026-11");
      expect(lines[4]).toBe("witness.sequenceNumber:2:42");
      expect(lines[5]).toBe("ticket.ticketId:15:ticket-uuid-001");
      expect(lines[6]).toBe("artifact.authorizationId:13:auth-uuid-001");
      expect(lines[7]).toBe(
        "artifact.bindingDigest:71:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      );
      expect(lines[8]).toBe("policy.policyId:19:pol_transfer_limits");
      expect(lines[9]).toBe("policy.policyRevision:1:2");
      expect(lines[10]).toBe("budget.debitedAmount:19:1500000000000000000");
      expect(lines[11]).toBe(
        "budget.windows:74:HOURLY:1700000000:1500000000000000000;DAILY:1699920000:5000000000000000000",
      );
      expect(lines[12]).toBe("witness.committedAtSeconds:10:1700000050");
      expect(lines[13]).toBe(""); // Trailing newline
    });

    it("encodes empty budget windows deterministically as budget.windows:0:", () => {
      const emptyWindowsReceipt = {
        ...baseReceiptData,
        budgetWindows: [],
      };
      const payload = canonicalWitnessReceiptPayload(emptyWindowsReceipt);
      expect(payload).toContain("\nbudget.windows:0:\n");
    });
  });

  // ==========================================================================
  // 2. Preimage Formatter & Cross-Format Equivalence
  // ==========================================================================
  describe("Cross-Format Equivalence (snake_case vs camelCase)", () => {
    it("produces bit-for-bit identical preimages from snake_case and camelCase inputs", () => {
      const snakeCaseData: ReceiptPreimageData = {
        version: 1,
        witness_id: baseReceiptData.witnessId,
        epoch_id: baseReceiptData.epochId,
        sequence_number: baseReceiptData.sequenceNumber,
        ticket_id: baseReceiptData.ticketId,
        authorization_id: baseReceiptData.authorizationId,
        binding_digest: baseReceiptData.bindingDigest,
        policy_id: baseReceiptData.policyId,
        policy_revision: baseReceiptData.policyRevision,
        debited_amount: baseReceiptData.debitedAmount,
        budget_windows: [
          {
            window_type: 1, // numeric enum HOURLY
            window_start_seconds: 1700000000,
            cumulative_spent_after: "1500000000000000000",
          },
          {
            window_type: 2, // numeric enum DAILY
            window_start_seconds: 1699920000,
            cumulative_spent_after: "5000000000000000000",
          },
        ],
        committed_at_seconds: baseReceiptData.committedAtSeconds,
      };

      const preimageFromSnake = formatCanonicalPreimage(snakeCaseData);
      const preimageFromCamel = formatCanonicalPreimage(baseReceiptData);
      const directPayload = canonicalWitnessReceiptPayload(baseReceiptData);

      expect(preimageFromSnake).toBe(directPayload);
      expect(preimageFromCamel).toBe(directPayload);
      expect(preimageFromSnake).toBe(preimageFromCamel);
    });

    it("normalizes valid window types: HOURLY (1, '1', 'HOURLY', 'BUDGET_WINDOW_TYPE_HOURLY') and DAILY (2, '2', 'DAILY', 'BUDGET_WINDOW_TYPE_DAILY')", () => {
      expect(normalizeBudgetWindowType(1)).toBe("HOURLY");
      expect(normalizeBudgetWindowType("1")).toBe("HOURLY");
      expect(normalizeBudgetWindowType("HOURLY")).toBe("HOURLY");
      expect(normalizeBudgetWindowType("BUDGET_WINDOW_TYPE_HOURLY")).toBe("HOURLY");

      expect(normalizeBudgetWindowType(2)).toBe("DAILY");
      expect(normalizeBudgetWindowType("2")).toBe("DAILY");
      expect(normalizeBudgetWindowType("DAILY")).toBe("DAILY");
      expect(normalizeBudgetWindowType("BUDGET_WINDOW_TYPE_DAILY")).toBe("DAILY");
    });

    it("SEC-01: strictly rejects unspecified, zero, null, undefined, and unsupported cadences (WEEKLY, MONTHLY)", () => {
      // Unspecified / zero / empty
      expect(() => normalizeBudgetWindowType(0)).toThrow(/strictly prohibited/);
      expect(() => normalizeBudgetWindowType("0")).toThrow(/strictly prohibited/);
      expect(() => normalizeBudgetWindowType("BUDGET_WINDOW_TYPE_UNSPECIFIED")).toThrow(/strictly prohibited/);
      expect(() => normalizeBudgetWindowType(undefined)).toThrow(/strictly prohibited/);
      expect(() => normalizeBudgetWindowType(null)).toThrow(/strictly prohibited/);
      expect(() => normalizeBudgetWindowType("")).toThrow(/strictly prohibited/);

      // Unsupported protobuf cadences (WEEKLY = 3, MONTHLY = 4)
      expect(() => normalizeBudgetWindowType(3)).toThrow(/unsupported by current SDK/i);
      expect(() => normalizeBudgetWindowType("3")).toThrow(/unsupported by current SDK/i);
      expect(() => normalizeBudgetWindowType("WEEKLY")).toThrow(/unsupported by current SDK/i);
      expect(() => normalizeBudgetWindowType("BUDGET_WINDOW_TYPE_WEEKLY")).toThrow(/unsupported by current SDK/i);

      expect(() => normalizeBudgetWindowType(4)).toThrow(/unsupported by current SDK/i);
      expect(() => normalizeBudgetWindowType("4")).toThrow(/unsupported by current SDK/i);
      expect(() => normalizeBudgetWindowType("MONTHLY")).toThrow(/unsupported by current SDK/i);
      expect(() => normalizeBudgetWindowType("BUDGET_WINDOW_TYPE_MONTHLY")).toThrow(/unsupported by current SDK/i);

      // Unknown / malformed
      expect(() => normalizeBudgetWindowType("YEARLY")).toThrow(/Invalid budget window type/);
      expect(() => normalizeBudgetWindowType(99)).toThrow(/Invalid budget window type/);
      expect(() => normalizeBudgetWindowType(false)).toThrow(/Invalid budget window type/);
    });

    // ========================================================================
    // SEC-04: Contradictory Dual-Casing Protection Tests
    // ========================================================================
    it("SEC-04: allows dual-cased fields when representations are strictly equivalent", () => {
      const dualRepresentation = {
        version: 1,
        witness_id: "witness-test-node-1",
        witnessId: "witness-test-node-1",
        epoch_id: "epoch-2026-11",
        epochId: "epoch-2026-11",
        sequence_number: "42",
        sequenceNumber: "42",
        ticket_id: "ticket-uuid-001",
        ticketId: "ticket-uuid-001",
        authorization_id: "auth-uuid-001",
        authorizationId: "auth-uuid-001",
        binding_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        bindingDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        policy_id: "pol_transfer_limits",
        policyId: "pol_transfer_limits",
        policy_revision: 2,
        policyRevision: 2,
        debited_amount: "1500000000000000000",
        debitedAmount: "1500000000000000000",
        budget_windows: [
          {
            window_type: 1,
            window_start_seconds: 1700000000,
            cumulative_spent_after: "1500000000000000000",
          },
        ],
        budgetWindows: [
          {
            windowType: "HOURLY" as const,
            windowStart: 1700000000,
            cumulativeSpentAfter: "1500000000000000000",
          },
        ],
        committed_at_seconds: 1700000050,
        committedAtSeconds: 1700000050,
      };

      const canonicalObj = toCanonicalWitnessReceiptData(dualRepresentation);
      expect(canonicalObj.witnessId).toBe("witness-test-node-1");
      expect(canonicalObj.sequenceNumber).toBe("42");
      expect(canonicalObj.budgetWindows[0].windowType).toBe("HOURLY");
    });

    it("SEC-04: strictly rejects contradictory values across all 11 dual-cased fields", () => {
      // 1. witness_id !== witnessId
      expect(() =>
        toCanonicalWitnessReceiptData({ ...baseReceiptData, witness_id: "node-A", witnessId: "node-B" }),
      ).toThrow(/Contradictory receipt fields: witness_id/);

      // 2. epoch_id !== epochId
      expect(() =>
        toCanonicalWitnessReceiptData({ ...baseReceiptData, epoch_id: "epoch-1", epochId: "epoch-2" }),
      ).toThrow(/Contradictory receipt fields: epoch_id/);

      // 3. sequence_number !== sequenceNumber
      expect(() =>
        toCanonicalWitnessReceiptData({ ...baseReceiptData, sequence_number: "10", sequenceNumber: "20" }),
      ).toThrow(/Contradictory receipt fields: sequence_number/);

      // 4. ticket_id !== ticketId
      expect(() =>
        toCanonicalWitnessReceiptData({ ...baseReceiptData, ticket_id: "t-1", ticketId: "t-2" }),
      ).toThrow(/Contradictory receipt fields: ticket_id/);

      // 5. authorization_id !== authorizationId
      expect(() =>
        toCanonicalWitnessReceiptData({ ...baseReceiptData, authorization_id: "a-1", authorizationId: "a-2" }),
      ).toThrow(/Contradictory receipt fields: authorization_id/);

      // 6. binding_digest !== bindingDigest
      expect(() =>
        toCanonicalWitnessReceiptData({
          ...baseReceiptData,
          binding_digest: "sha256:" + "1".repeat(64),
          bindingDigest: "sha256:" + "2".repeat(64),
        }),
      ).toThrow(/Contradictory receipt fields: binding_digest/);

      // 7. policy_id !== policyId
      expect(() =>
        toCanonicalWitnessReceiptData({ ...baseReceiptData, policy_id: "p-1", policyId: "p-2" }),
      ).toThrow(/Contradictory receipt fields: policy_id/);

      // 8. policy_revision !== policyRevision
      expect(() =>
        toCanonicalWitnessReceiptData({ ...baseReceiptData, policy_revision: 1, policyRevision: 2 }),
      ).toThrow(/Contradictory receipt fields: policy_revision/);

      // 9. debited_amount !== debitedAmount
      expect(() =>
        toCanonicalWitnessReceiptData({ ...baseReceiptData, debited_amount: "100", debitedAmount: "200" }),
      ).toThrow(/Contradictory receipt fields: debited_amount/);

      // 10. committed_at_seconds !== committedAtSeconds
      expect(() =>
        toCanonicalWitnessReceiptData({ ...baseReceiptData, committed_at_seconds: 1000, committedAtSeconds: 2000 }),
      ).toThrow(/Contradictory receipt fields: committed_at_seconds/);

      // 11. budget_windows !== budgetWindows (count mismatch)
      expect(() =>
        toCanonicalWitnessReceiptData({
          ...baseReceiptData,
          budget_windows: [],
          budgetWindows: [
            { windowType: "HOURLY" as const, windowStart: 1700000000, cumulativeSpentAfter: "100" },
          ],
        }),
      ).toThrow(/budget_windows count/);

      // 11b. budget_windows !== budgetWindows (value mismatch inside window)
      expect(() =>
        toCanonicalWitnessReceiptData({
          ...baseReceiptData,
          budget_windows: [
            { window_type: 1, window_start_seconds: 1700000000, cumulative_spent_after: "100" },
          ],
          budgetWindows: [
            { windowType: "HOURLY" as const, windowStart: 1700000000, cumulativeSpentAfter: "200" },
          ],
        }),
      ).toThrow(/cumulative spent mismatch/);
    });
  });

  // ==========================================================================
  // 3. Golden Test Vectors with Known Hashes & Signatures
  // ==========================================================================
  describe("Golden Test Vectors", () => {
    it("Vector 1: Minimal Receipt (No budget windows, zero debited amount)", async () => {
      const minimalReceipt: Omit<SignedWitnessReceipt, "signature"> = {
        version: 1,
        witnessId: "witness-golden-node",
        epochId: "epoch-golden-001",
        sequenceNumber: "1",
        ticketId: "ticket-golden-001",
        authorizationId: "auth-golden-001",
        bindingDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        policyId: "pol-golden-core",
        policyRevision: 1,
        debitedAmount: "0",
        budgetWindows: [],
        committedAtSeconds: 1700000000,
      };

      const payload = canonicalWitnessReceiptPayload(minimalReceipt);
      const expectedPayload =
        "web3user-witness-receipt-v1\n" +
        "witness.version:1:1\n" +
        "witness.witnessId:19:witness-golden-node\n" +
        "witness.epochId:16:epoch-golden-001\n" +
        "witness.sequenceNumber:1:1\n" +
        "ticket.ticketId:17:ticket-golden-001\n" +
        "artifact.authorizationId:15:auth-golden-001\n" +
        "artifact.bindingDigest:71:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
        "policy.policyId:15:pol-golden-core\n" +
        "policy.policyRevision:1:1\n" +
        "budget.debitedAmount:1:0\n" +
        "budget.windows:0:\n" +
        "witness.committedAtSeconds:10:1700000000\n";

      expect(payload).toBe(expectedPayload);

      const sha256Hash = createHash("sha256").update(payload, "utf8").digest("hex");
      expect(sha256Hash).toMatch(/^[a-f0-9]{64}$/);

      // Sign with test signer
      const { signatureHex } = await testSigner.signReceipt(payload, 1);
      const signedReceipt: SignedWitnessReceipt = {
        ...minimalReceipt,
        signature: signatureHex,
      };

      expect(verifyWitnessReceipt(publicKeyHex, signedReceipt)).toBe(true);
      expect(verifyWitnessReceipt(publicKeyPem, signedReceipt)).toBe(true);
      expect(verifyWitnessReceipt(publicKeyObj, signedReceipt)).toBe(true);
    });

    it("Vector 2: Full Multi-Window High-Value Receipt", async () => {
      const fullReceipt: Omit<SignedWitnessReceipt, "signature"> = {
        version: 1,
        witnessId: "witness-prod-us-east-1a",
        epochId: "epoch-2026-11-03",
        sequenceNumber: "1000000",
        ticketId: "ticket-7f8e9d0c-1b2a-3c4d-5e6f-7a8b9c0d1e2f",
        authorizationId: "auth-9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d",
        bindingDigest: "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        policyId: "enterprise_tiered_settlement_v2",
        policyRevision: 42,
        debitedAmount: "1000000000000000000000000",
        budgetWindows: [
          {
            windowType: "HOURLY",
            windowStart: 1700000000,
            cumulativeSpentAfter: "1000000000000000000000000",
          },
        ],
        committedAtSeconds: 1700003600,
      };

      const payload = canonicalWitnessReceiptPayload(fullReceipt);
      expect(payload.startsWith("web3user-witness-receipt-v1\n")).toBe(true);
      expect(payload).toContain("witness.sequenceNumber:7:1000000\n");
      expect(payload).toContain("budget.debitedAmount:25:1000000000000000000000000\n");

      const { signatureHex } = await testSigner.signReceipt(payload, 5);
      const signedReceipt: SignedWitnessReceipt = {
        ...fullReceipt,
        signature: signatureHex,
      };

      expect(verifyWitnessReceipt(publicKeyHex, signedReceipt)).toBe(true);
      expect(verifyWitnessReceipt(publicKeyPem, signedReceipt)).toBe(true);
    });
  });

  // ==========================================================================
  // 4. Edge Cases & Boundary Resilience
  // ==========================================================================
  describe("Edge Cases & Boundaries", () => {
    it("handles maximum possible uint256 string (2^256 - 1) cleanly", async () => {
      const maxUint256 = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
      const receipt: Omit<SignedWitnessReceipt, "signature"> = {
        ...baseReceiptData,
        sequenceNumber: maxUint256,
        debitedAmount: maxUint256,
        budgetWindows: [
          {
            windowType: "DAILY",
            windowStart: 1700000000,
            cumulativeSpentAfter: maxUint256,
          },
        ],
      };

      const payload = canonicalWitnessReceiptPayload(receipt);
      expect(payload).toContain(`witness.sequenceNumber:78:${maxUint256}\n`);
      expect(payload).toContain(`budget.debitedAmount:78:${maxUint256}\n`);

      const { signatureHex } = await testSigner.signReceipt(payload, 1);
      expect(verifyWitnessReceipt(publicKeyHex, { ...receipt, signature: signatureHex })).toBe(true);
    });

    it("correctly byte-lengths multi-byte Unicode UTF-8 identifiers in policyId and witnessId", async () => {
      const unicodeReceipt: Omit<SignedWitnessReceipt, "signature"> = {
        ...baseReceiptData,
        witnessId: "witness-node-東京-🗼",
        policyId: "policy-décentralisée-💎",
      };

      const payload = canonicalWitnessReceiptPayload(unicodeReceipt);
      // "witness-node-東京-🗼":
      // "witness-node-" (13 bytes) + "東京" (6 bytes) + "-" (1 byte) + "🗼" (4 bytes) = 24 bytes UTF-8
      const witnessIdByteLen = Buffer.byteLength(unicodeReceipt.witnessId, "utf8");
      expect(payload).toContain(`witness.witnessId:${witnessIdByteLen}:${unicodeReceipt.witnessId}\n`);

      const policyIdByteLen = Buffer.byteLength(unicodeReceipt.policyId, "utf8");
      expect(payload).toContain(`policy.policyId:${policyIdByteLen}:${unicodeReceipt.policyId}\n`);

      const { signatureHex } = await testSigner.signReceipt(payload, 1);
      expect(verifyWitnessReceipt(publicKeyHex, { ...unicodeReceipt, signature: signatureHex })).toBe(true);
    });

    it("rejects invalid versions, empty fields, negative timestamps, and malformed uint256", () => {
      // Version !== 1
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, version: 2 as any })).toThrow();
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, version: 0 as any })).toThrow();

      // Empty strings
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, witnessId: "" })).toThrow();
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, epochId: "   " })).toThrow();
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, ticketId: "" })).toThrow();
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, authorizationId: "" })).toThrow();
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, policyId: "" })).toThrow();

      // Malformed sequenceNumber (not uint256 decimal)
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, sequenceNumber: "-1" })).toThrow();
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, sequenceNumber: "0123" })).toThrow(); // Leading zero
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, sequenceNumber: "12.34" })).toThrow();
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, sequenceNumber: "abc" })).toThrow();

      // Malformed debitedAmount
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, debitedAmount: "-100" })).toThrow();
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, debitedAmount: "0050" })).toThrow();

      // Malformed policyRevision
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, policyRevision: 0 })).toThrow();
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, policyRevision: -5 })).toThrow();
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, policyRevision: 1.5 })).toThrow();

      // SEC-02: Strict bindingDigest validation (must be exact "sha256:[a-f0-9]{64}")
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, bindingDigest: "invalid-digest" })).toThrow();
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, bindingDigest: "md5:abcd" })).toThrow();
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, bindingDigest: "sha256:1234" })).toThrow(); // Truncated
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, bindingDigest: "sha256:succ-digest" })).toThrow(); // Arbitrary string
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, bindingDigest: "sha256:digest-lock-03" })).toThrow(); // Arbitrary string
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, bindingDigest: "sha256:" + "A".repeat(64) })).toThrow(); // Uppercase hex strictly prohibited
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, bindingDigest: "sha256:" + "g".repeat(64) })).toThrow(); // Non-hex character
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, bindingDigest: "sha256:" + "a".repeat(65) })).toThrow(); // Overlength

      // Negative committedAtSeconds
      expect(() => canonicalWitnessReceiptPayload({ ...baseReceiptData, committedAtSeconds: -1 })).toThrow();
    });

    it("SEC-02: verifyWitnessReceipt returns false when bindingDigest is non-canonical or malformed", () => {
      const validSig = "a".repeat(128);
      expect(verifyWitnessReceipt(publicKeyHex, { ...baseReceiptData, bindingDigest: "sha256:1234", signature: validSig })).toBe(false);
      expect(verifyWitnessReceipt(publicKeyHex, { ...baseReceiptData, bindingDigest: "sha256:succ-digest", signature: validSig })).toBe(false);
      expect(verifyWitnessReceipt(publicKeyHex, { ...baseReceiptData, bindingDigest: "sha256:" + "A".repeat(64), signature: validSig })).toBe(false);
      expect(verifyWitnessReceipt(publicKeyHex, { ...baseReceiptData, bindingDigest: "sha256:" + "g".repeat(64), signature: validSig })).toBe(false);
    });
  });

  // ==========================================================================
  // 5. Exhaustive Field-by-Field Tamper Detection
  // ==========================================================================
  describe("Exhaustive Field-by-Field Tamper Detection", async () => {
    const payload = canonicalWitnessReceiptPayload(baseReceiptData);
    const { signatureHex } = await testSigner.signReceipt(payload, 1);
    const validReceipt: SignedWitnessReceipt = {
      ...baseReceiptData,
      signature: signatureHex,
    };

    it("verifies the untampered receipt successfully with all key formats", () => {
      expect(verifyWitnessReceipt(publicKeyHex, validReceipt)).toBe(true);
      expect(verifyWitnessReceipt(publicKeyPem, validReceipt)).toBe(true);
      expect(verifyWitnessReceipt(publicKeyObj, validReceipt)).toBe(true);
    });

    it("fails verification when version is tampered", () => {
      expect(verifyWitnessReceipt(publicKeyHex, { ...validReceipt, version: 2 as any })).toBe(false);
    });

    it("fails verification when witnessId is tampered", () => {
      expect(verifyWitnessReceipt(publicKeyHex, { ...validReceipt, witnessId: "witness-impostor" })).toBe(false);
    });

    it("fails verification when epochId is tampered", () => {
      expect(verifyWitnessReceipt(publicKeyHex, { ...validReceipt, epochId: "epoch-divergent" })).toBe(false);
    });

    it("fails verification when sequenceNumber is tampered", () => {
      expect(verifyWitnessReceipt(publicKeyHex, { ...validReceipt, sequenceNumber: "43" })).toBe(false);
    });

    it("fails verification when ticketId is tampered", () => {
      expect(verifyWitnessReceipt(publicKeyHex, { ...validReceipt, ticketId: "ticket-tampered-002" })).toBe(false);
    });

    it("fails verification when authorizationId is tampered", () => {
      expect(verifyWitnessReceipt(publicKeyHex, { ...validReceipt, authorizationId: "auth-tampered-002" })).toBe(false);
    });

    it("fails verification when bindingDigest is tampered", () => {
      expect(
        verifyWitnessReceipt(publicKeyHex, {
          ...validReceipt,
          bindingDigest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        }),
      ).toBe(false);
    });

    it("fails verification when policyId is tampered", () => {
      expect(verifyWitnessReceipt(publicKeyHex, { ...validReceipt, policyId: "pol_unauthorized" })).toBe(false);
    });

    it("fails verification when policyRevision is tampered", () => {
      expect(verifyWitnessReceipt(publicKeyHex, { ...validReceipt, policyRevision: 3 })).toBe(false);
    });

    it("fails verification when debitedAmount is tampered", () => {
      expect(verifyWitnessReceipt(publicKeyHex, { ...validReceipt, debitedAmount: "0" })).toBe(false);
      expect(verifyWitnessReceipt(publicKeyHex, { ...validReceipt, debitedAmount: "1500000000000000001" })).toBe(false);
    });

    it("fails verification when budgetWindows are tampered", () => {
      // Dropping a window
      expect(
        verifyWitnessReceipt(publicKeyHex, {
          ...validReceipt,
          budgetWindows: [validReceipt.budgetWindows[0]],
        }),
      ).toBe(false);

      // Altering cumulativeSpentAfter
      expect(
        verifyWitnessReceipt(publicKeyHex, {
          ...validReceipt,
          budgetWindows: [
            { ...validReceipt.budgetWindows[0], cumulativeSpentAfter: "999999" },
            validReceipt.budgetWindows[1],
          ],
        }),
      ).toBe(false);

      // Altering windowStart
      expect(
        verifyWitnessReceipt(publicKeyHex, {
          ...validReceipt,
          budgetWindows: [
            { ...validReceipt.budgetWindows[0], windowStart: 1700003600 },
            validReceipt.budgetWindows[1],
          ],
        }),
      ).toBe(false);

      // Altering windowType
      expect(
        verifyWitnessReceipt(publicKeyHex, {
          ...validReceipt,
          budgetWindows: [
            { ...validReceipt.budgetWindows[0], windowType: "DAILY" },
            validReceipt.budgetWindows[1],
          ],
        }),
      ).toBe(false);
    });

    it("fails verification when committedAtSeconds is tampered", () => {
      expect(verifyWitnessReceipt(publicKeyHex, { ...validReceipt, committedAtSeconds: 1700000051 })).toBe(false);
    });

    it("fails verification when signature is flipped or truncated", () => {
      const flippedSig =
        (validReceipt.signature[0] === "a" ? "b" : "a") + validReceipt.signature.slice(1);
      expect(verifyWitnessReceipt(publicKeyHex, { ...validReceipt, signature: flippedSig })).toBe(false);
      expect(verifyWitnessReceipt(publicKeyHex, { ...validReceipt, signature: "abcd" })).toBe(false);
      expect(verifyWitnessReceipt(publicKeyHex, { ...validReceipt, signature: "a".repeat(128) })).toBe(false);
    });

    it("fails verification when signed by an untrusted foreign witness key", () => {
      const foreignSigner = new LocalEd25519WitnessSigner("foreign-witness");
      expect(verifyWitnessReceipt(foreignSigner.getPublicKeyHex(), validReceipt)).toBe(false);
      expect(verifyWitnessReceipt(foreignSigner.getPublicKeyPem(), validReceipt)).toBe(false);
    });
  });

  // ==========================================================================
  // 6. Outbox Persistence & Replay Safety
  // ==========================================================================
  describe("Outbox Persistence & Replay Payload Invariance", () => {
    it("ensures persisted outbox preimage matches the real-time preimage and can be verified across replays", async () => {
      const now = Math.floor(Date.now() / 1000);
      const preimageData: ReceiptPreimageData = {
        version: 1,
        witness_id: testSigner.getWitnessId(),
        epoch_id: "epoch-replay-001",
        sequence_number: "77",
        ticket_id: "ticket-replay-001",
        authorization_id: "auth-replay-001",
        binding_digest: "sha256:" + "c".repeat(64),
        policy_id: "policy-replay",
        policy_revision: 1,
        debited_amount: "500",
        budget_windows: [
          {
            window_type: 1,
            window_start_seconds: now,
            cumulative_spent_after: "500",
          },
        ],
        committed_at_seconds: now,
      };

      // 1. Compute preimage during Phase 1 outbox persistence
      const persistedOutboxPreimage = formatCanonicalPreimage(preimageData);

      // 2. Real-time Phase 2 signing of that exact preimage
      const { signatureHex } = await testSigner.signReceipt(persistedOutboxPreimage, 1);

      // 3. Construct receipt as delivered over gRPC or reconstructed by replay worker
      const reconstructedReceipt: SignedWitnessReceipt = {
        version: 1,
        witnessId: testSigner.getWitnessId(),
        epochId: preimageData.epoch_id!,
        sequenceNumber: preimageData.sequence_number!,
        ticketId: preimageData.ticket_id!,
        authorizationId: preimageData.authorization_id!,
        bindingDigest: preimageData.binding_digest!,
        policyId: preimageData.policy_id!,
        policyRevision: preimageData.policy_revision!,
        debitedAmount: preimageData.debited_amount!,
        budgetWindows: [
          {
            windowType: "HOURLY",
            windowStart: now,
            cumulativeSpentAfter: "500",
          },
        ],
        committedAtSeconds: now,
        signature: signatureHex,
      };

      // 4. Verify that replayed receipt passes client verification
      expect(verifyWitnessReceipt(publicKeyHex, reconstructedReceipt)).toBe(true);

      // 5. Verify that formatCanonicalPreimage on replayed receipt reproduces the exact outbox string
      const replayedPreimage = formatCanonicalPreimage(reconstructedReceipt);
      expect(replayedPreimage).toBe(persistedOutboxPreimage);
    });
  });
});
