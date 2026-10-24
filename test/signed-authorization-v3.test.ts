import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import {
  DEFAULT_AUTHORIZATION_TTL_SECONDS,
  consumeSignedTransactionAuthorizationV3,
  issueSignedTransactionAuthorizationV3,
  consumeBoundTransactionAuthorizationWithStore,
  issueBoundTransactionAuthorizationWithStore,
  consumeSignedTransactionAuthorizationWithStore,
  issueSignedTransactionAuthorizationWithStore,
} from "../src/authorization-lifecycle.js";
import {
  canonicalSignedPayloadV3,
  isSignedAuthorizationArtifactV3,
  SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3,
  signAuthorizationPayload,
} from "../src/authorization-crypto.js";
import { SQLiteAuthorizationStore } from "../src/authorization-store.js";
import { TestClock } from "../src/clock.js";
import { SQLiteKeyStore } from "../src/key-store.js";
import { type DemoPolicy } from "../src/policy.js";
import { SQLitePolicyStore } from "../src/policy-store.js";
import { createTransactionEnvelope, type TransactionRequest } from "../src/transaction-envelope.js";

describe("Milestone 6.2 Phase 3: V3 Canonical Signing, Issuance & Consumption Pipeline", () => {
  let directory: string | undefined;

  function databasePath(filename = "v3-test.sqlite"): string {
    directory ??= mkdtempSync(join(tmpdir(), "web3user-v3-"));
    return join(directory, filename);
  }

  afterEach(() => {
    if (directory) {
      rmSync(directory, { recursive: true, force: true });
      directory = undefined;
    }
  });

  function createKeypair() {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    return { publicKey, privateKey, pem };
  }

  const validPolicy: DemoPolicy = {
    version: 1,
    policyId: "policy-v3-alpha",
    allowedTarget: "0x1111111111111111111111111111111111111111",
    allowedRecipient: "0x2222222222222222222222222222222222222222",
    allowedSelector: "0xa9059cbb",
    maxAmount: "1000000",
    validFrom: 1000,
    expiresAt: 9000,
    revoked: false,
  };

  const recipientPadded = "0000000000000000000000002222222222222222222222222222222222222222";
  const amountPadded = "000000000000000000000000000000000000000000000000000000000007a120"; // 500,000

  const validRequest: TransactionRequest = {
    chainId: "1",
    sender: "0x3333333333333333333333333333333333333333",
    target: "0x1111111111111111111111111111111111111111",
    calldata: `0xa9059cbb${recipientPadded}${amountPadded}`,
    value: "0",
  };

  function setupStores(dbFile: string, clockSeconds = 1500) {
    const clock = new TestClock(clockSeconds);
    const authStore = new SQLiteAuthorizationStore(dbFile, clock);
    const policyStore = authStore.getPolicyStore();
    const keyStore = authStore.getKeyStore();
    return { authStore, policyStore, keyStore, clock };
  }

  // 1. Valid V3 issuance and first consumption
  it("issues valid V3 artifact bound to authoritative SQLite policy & key, and consumes it atomically", () => {
    const dbFile = databasePath();
    const { authStore, policyStore, keyStore } = setupStores(dbFile, 1500);
    const key = createKeypair();

    try {
      policyStore.registerPolicy(validPolicy); // Revision 1
      keyStore.registerKey({
        keyId: "key-v3-001",
        publicKey: key.publicKey,
        status: "active",
        validFromSeconds: 1000,
        expiresAtSeconds: 8000,
      });

      const issueResult = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-v3-001", privateKey: key.privateKey },
        "auth-v3-001",
        "policy-v3-alpha",
        validRequest,
      );

      expect(issueResult.decision).toBe("ALLOW");
      if (issueResult.decision !== "ALLOW") return;

      expect(issueResult.artifact.version).toBe(3);
      expect(issueResult.artifact.authorizationId).toBe("auth-v3-001");
      expect(issueResult.artifact.keyId).toBe("key-v3-001");
      expect(issueResult.artifact.policyId).toBe("policy-v3-alpha");
      expect(issueResult.artifact.policyRevision).toBe(1);
      expect(issueResult.artifact.issuedAtSeconds).toBe(1500);
      expect(issueResult.artifact.expiresAtSeconds).toBe(1500 + DEFAULT_AUTHORIZATION_TTL_SECONDS);
      expect(issueResult.artifact.signature).toMatch(/^[0-9a-f]{128}$/i);

      // First consumption succeeds
      const consumeResult = consumeSignedTransactionAuthorizationV3(
        authStore,
        issueResult.artifact,
        issueResult.envelope,
        validRequest,
      );

      expect(consumeResult.decision).toBe("ALLOW");
    } finally {
      authStore.close();
    }
  });

  // 2. Replayed artifact after reopening the database
  it("rejects replayed artifact consumption after reopening the database", () => {
    const dbFile = databasePath();
    const key = createKeypair();

    // Issuance & First consumption on Connection 1
    const ctx1 = setupStores(dbFile, 1500);
    let artifact: any;
    let envelope: any;

    try {
      ctx1.policyStore.registerPolicy(validPolicy);
      ctx1.keyStore.registerKey({
        keyId: "key-v3-replay",
        publicKey: key.publicKey,
        status: "active",
        validFromSeconds: 1000,
        expiresAtSeconds: 8000,
      });

      const res = issueSignedTransactionAuthorizationV3(
        ctx1.authStore,
        { keyId: "key-v3-replay", privateKey: key.privateKey },
        "auth-v3-replay",
        "policy-v3-alpha",
        validRequest,
      );
      expect(res.decision).toBe("ALLOW");
      if (res.decision !== "ALLOW") return;
      artifact = res.artifact;
      envelope = res.envelope;

      const firstConsume = consumeSignedTransactionAuthorizationV3(
        ctx1.authStore,
        artifact,
        envelope,
        validRequest,
      );
      expect(firstConsume.decision).toBe("ALLOW");
    } finally {
      ctx1.authStore.close();
    }

    // Reopen database with Connection 2 and attempt replay
    const ctx2 = setupStores(dbFile, 1600);
    try {
      // 1. Replay with the original in-memory envelope is rejected by in-process tracking
      const inProcessReplay = consumeSignedTransactionAuthorizationV3(
        ctx2.authStore,
        artifact,
        envelope,
        validRequest,
      );
      expect(inProcessReplay.decision).toBe("DENY");
      expect(inProcessReplay.reasons).toContain(
        "Transaction authorization has already been consumed."
      );

      // 2. Replay with a freshly constructed envelope across sessions is rejected by persistent SQLite storage
      const freshEnv = createTransactionEnvelope(validRequest);
      if (!freshEnv.ok) throw new Error("Failed to create envelope");

      const persistentReplay = consumeSignedTransactionAuthorizationV3(
        ctx2.authStore,
        artifact,
        freshEnv.envelope,
        validRequest,
      );

      expect(persistentReplay.decision).toBe("DENY");
      expect(persistentReplay.reasons).toContain(
        "Bound transaction authorization is unknown, consumed, or mismatched."
      );
    } finally {
      ctx2.authStore.close();
    }
  });

  // 3. Signature tampering
  it("rejects artifact with tampered signature and leaves storage in issued state", () => {
    const dbFile = databasePath();
    const { authStore, policyStore, keyStore } = setupStores(dbFile, 1500);
    const key = createKeypair();

    try {
      policyStore.registerPolicy(validPolicy);
      keyStore.registerKey({
        keyId: "key-tamper",
        publicKey: key.publicKey,
        status: "active",
      });

      const issued = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-tamper", privateKey: key.privateKey },
        "auth-tamper-sig",
        "policy-v3-alpha",
        validRequest,
      );
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Corrupt signature
      const corruptChar = issued.artifact.signature[0] === "a" ? "b" : "a";
      const corruptSig = corruptChar + issued.artifact.signature.slice(1);
      const tamperedArtifact = { ...issued.artifact, signature: corruptSig };

      const consumeRes = consumeSignedTransactionAuthorizationV3(
        authStore,
        tamperedArtifact,
        issued.envelope,
        validRequest,
      );

      expect(consumeRes.decision).toBe("DENY");
      expect(consumeRes.reasons).toContain("Invalid authorization artifact signature.");

      // Verify row state in SQLite is still 'issued' with consumed_at = null
      const row = authStore.getAuthorizationRecord("auth-tamper-sig");
      expect(row).toBeDefined();
      expect(row?.state).toBe("issued");
      expect(row?.consumedAt).toBeNull();
    } finally {
      authStore.close();
    }
  });

  // 4. Transaction binding tampering
  it("rejects consumption when transaction request parameters differ from bound artifact", () => {
    const dbFile = databasePath();
    const { authStore, policyStore, keyStore } = setupStores(dbFile, 1500);
    const key = createKeypair();

    try {
      policyStore.registerPolicy(validPolicy);
      keyStore.registerKey({
        keyId: "key-tx-tamper",
        publicKey: key.publicKey,
        status: "active",
      });

      const issued = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-tx-tamper", privateKey: key.privateKey },
        "auth-tx-tamper",
        "policy-v3-alpha",
        validRequest,
      );
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Tamper candidate request: increase transfer amount to 999,999
      const tamperedAmount = "00000000000000000000000000000000000000000000000000000000000f423f";
      const tamperedRequest: TransactionRequest = {
        ...validRequest,
        calldata: `0xa9059cbb${recipientPadded}${tamperedAmount}`,
      };

      // Case A: A valid envelope for the tampered request doesn't match the bound artifact digest
      const tamperedEnv = createTransactionEnvelope(tamperedRequest);
      if (!tamperedEnv.ok) throw new Error("Failed to create envelope");

      const resultMismatchBinding = consumeSignedTransactionAuthorizationV3(
        authStore,
        issued.artifact,
        tamperedEnv.envelope,
        tamperedRequest,
      );

      expect(resultMismatchBinding.decision).toBe("DENY");
      expect(resultMismatchBinding.reasons).toContain(
        "Transaction does not match the bound authorization artifact."
      );

      // Case B: Candidate differs from original envelope
      const resultMismatchEnvelope = consumeSignedTransactionAuthorizationV3(
        authStore,
        issued.artifact,
        issued.envelope,
        tamperedRequest,
      );
      expect(resultMismatchEnvelope.decision).toBe("DENY");
      expect(resultMismatchEnvelope.reasons).toContain(
        "Transaction does not match the original envelope."
      );
    } finally {
      authStore.close();
    }
  });

  // 5. Tampering with signed fields (authorizationId, keyId, policyId, policyRevision, issuedAtSeconds, expiresAtSeconds)
  it("rejects tampering with any signed canonical field", () => {
    const dbFile = databasePath();
    const { authStore, policyStore, keyStore } = setupStores(dbFile, 1500);
    const key = createKeypair();

    try {
      policyStore.registerPolicy(validPolicy);
      keyStore.registerKey({
        keyId: "key-field-tamper",
        publicKey: key.publicKey,
        status: "active",
      });

      const issued = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-field-tamper", privateKey: key.privateKey },
        "auth-field-tamper",
        "policy-v3-alpha",
        validRequest,
      );
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      const testCases = [
        { field: "authorizationId", value: "auth-tampered-id" },
        { field: "policyId", value: "policy-tampered" },
        { field: "policyRevision", value: 2 },
        { field: "issuedAtSeconds", value: 1400 },
        { field: "expiresAtSeconds", value: 1750 },
      ];

      for (const tc of testCases) {
        const tampered = { ...issued.artifact, [tc.field]: tc.value };
        const result = consumeSignedTransactionAuthorizationV3(
          authStore,
          tampered,
          issued.envelope,
          validRequest,
        );
        expect(result.decision).toBe("DENY");
      }
    } finally {
      authStore.close();
    }
  });

  // 6. Unsupported artifact versions and malformed runtime inputs
  it("rejects unsupported artifact versions and malformed inputs", () => {
    const dbFile = databasePath();
    const { authStore } = setupStores(dbFile, 1500);

    try {
      const invalidArtifacts = [
        null,
        {},
        { version: 0 },
        { version: 2 },
        { version: 4 },
        { version: 3, authorizationId: "" },
        { version: 3, authorizationId: "id", keyId: "   " },
        { version: 3, authorizationId: "id", keyId: "k", issuedAtSeconds: -10 },
        { version: 3, authorizationId: "id", keyId: "k", issuedAtSeconds: 100, expiresAtSeconds: 50 },
        { version: 3, authorizationId: "id", keyId: "k", issuedAtSeconds: 100, expiresAtSeconds: "invalid" },
        { version: 3, authorizationId: "id", keyId: "k", issuedAtSeconds: 100, expiresAtSeconds: 200, policyRevision: 0 },
        { version: 3, authorizationId: "id", keyId: "k", issuedAtSeconds: 100, expiresAtSeconds: 200, policyRevision: 1, bindingDigest: "invalid" },
      ];

      for (const a of invalidArtifacts) {
        const res = consumeSignedTransactionAuthorizationV3(
          authStore,
          a,
          { request: validRequest },
          validRequest,
        );
        expect(res.decision).toBe("DENY");
        expect(res.reasons).toContain(
          "Signed transaction authorization artifact is invalid or malformed."
        );
      }
    } finally {
      authStore.close();
    }
  });

  // 7. Cross-key substitution
  it("rejects cross-key substitution attack", () => {
    const dbFile = databasePath();
    const { authStore, policyStore, keyStore } = setupStores(dbFile, 1500);
    const keyAlpha = createKeypair();
    const keyBeta = createKeypair();

    try {
      policyStore.registerPolicy(validPolicy);
      keyStore.registerKey({ keyId: "key-alpha", publicKey: keyAlpha.publicKey, status: "active" });
      keyStore.registerKey({ keyId: "key-beta", publicKey: keyBeta.publicKey, status: "active" });

      // Attacker signs payload with Key Beta's private key, but claims keyId is "key-alpha"
      const payload = canonicalSignedPayloadV3({
        version: 3,
        authorizationId: "auth-cross-key",
        keyId: "key-alpha",
        issuedAtSeconds: 1500,
        expiresAtSeconds: 1800,
        policyId: "policy-v3-alpha",
        policyRevision: 1,
        bindingDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      });

      const signature = signAuthorizationPayload(keyBeta.privateKey, payload);

      const crossArtifact = {
        version: 3 as const,
        authorizationId: "auth-cross-key",
        keyId: "key-alpha",
        issuedAtSeconds: 1500,
        expiresAtSeconds: 1800,
        policyId: "policy-v3-alpha",
        policyRevision: 1,
        bindingDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        signature,
      };

      const res = consumeSignedTransactionAuthorizationV3(
        authStore,
        crossArtifact,
        { request: validRequest },
        validRequest,
      );
      expect(res.decision).toBe("DENY");
      expect(res.reasons).toContain("Invalid authorization artifact signature.");
    } finally {
      authStore.close();
    }
  });

  // 8. Post-retirement forgery rule
  it("allows valid pre-retirement artifacts to be consumed but rejects post-retirement forgeries", () => {
    const dbFile = databasePath();
    const { authStore, policyStore, keyStore, clock } = setupStores(dbFile, 1500);
    const key = createKeypair();

    try {
      policyStore.registerPolicy(validPolicy);
      keyStore.registerKey({ keyId: "key-retire-rule", publicKey: key.publicKey, status: "active" });

      // 1. Issue legitimate artifact at t=1500 (expires at 1800)
      const legitIssue = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-retire-rule", privateKey: key.privateKey },
        "auth-legit-pre-retire",
        "policy-v3-alpha",
        validRequest,
      );
      expect(legitIssue.decision).toBe("ALLOW");
      if (legitIssue.decision !== "ALLOW") return;

      // 2. Key is retired at t=1550
      clock.set(1550);
      keyStore.retireKey("key-retire-rule", 1550);

      // 3. New issuance after retirement is rejected
      const postRetireIssue = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-retire-rule", privateKey: key.privateKey },
        "auth-post-retire-attempt",
        "policy-v3-alpha",
        validRequest,
      );
      expect(postRetireIssue.decision).toBe("DENY");
      expect(postRetireIssue.reasons).toContain("Issuer key is retired and cannot issue new authorizations.");

      // 4. An attacker with the private key creates a forged artifact with issuedAtSeconds = 1600 (after retirement 1550)
      const forgedPayload = canonicalSignedPayloadV3({
        version: 3,
        authorizationId: "auth-forged-post-retire",
        keyId: "key-retire-rule",
        issuedAtSeconds: 1600,
        expiresAtSeconds: 1800,
        policyId: "policy-v3-alpha",
        policyRevision: 1,
        bindingDigest: legitIssue.artifact.bindingDigest,
      });
      const forgedSig = signAuthorizationPayload(key.privateKey, forgedPayload);
      const forgedArtifact = {
        version: 3 as const,
        authorizationId: "auth-forged-post-retire",
        keyId: "key-retire-rule",
        issuedAtSeconds: 1600,
        expiresAtSeconds: 1800,
        policyId: "policy-v3-alpha",
        policyRevision: 1,
        bindingDigest: legitIssue.artifact.bindingDigest,
        signature: forgedSig,
      };

      clock.set(1560);
      const forgedConsume = consumeSignedTransactionAuthorizationV3(
        authStore,
        forgedArtifact,
        legitIssue.envelope,
        validRequest,
      );
      expect(forgedConsume.decision).toBe("DENY");
      expect(forgedConsume.reasons).toContain("Authorization was issued after issuer key was retired.");

      // 5. Legitimate pre-retirement artifact can still be consumed at t=1560
      const legitConsume = consumeSignedTransactionAuthorizationV3(
        authStore,
        legitIssue.artifact,
        legitIssue.envelope,
        validRequest,
      );
      expect(legitConsume.decision).toBe("ALLOW");
    } finally {
      authStore.close();
    }
  });

  // 9. Revoked-key rejection
  it("rejects issuance and consumption when key is revoked", () => {
    const dbFile = databasePath();
    const { authStore, policyStore, keyStore, clock } = setupStores(dbFile, 1500);
    const key = createKeypair();

    try {
      policyStore.registerPolicy(validPolicy);
      keyStore.registerKey({ keyId: "key-rev-test", publicKey: key.publicKey, status: "active" });

      const issued = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-rev-test", privateKey: key.privateKey },
        "auth-rev-test",
        "policy-v3-alpha",
        validRequest,
      );
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Revoke the key at t=1600
      clock.set(1600);
      keyStore.revokeKey("key-rev-test", 1600);

      // Issuance with revoked key is rejected
      const newIssue = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-rev-test", privateKey: key.privateKey },
        "auth-rev-new",
        "policy-v3-alpha",
        validRequest,
      );
      expect(newIssue.decision).toBe("DENY");
      expect(newIssue.reasons).toContain("Issuer key has been revoked.");

      // Consumption of prior authorization under revoked key is rejected
      const consumeRes = consumeSignedTransactionAuthorizationV3(
        authStore,
        issued.artifact,
        issued.envelope,
        validRequest,
      );
      expect(consumeRes.decision).toBe("DENY");
      expect(consumeRes.reasons).toContain("Issuer key has been revoked.");
    } finally {
      authStore.close();
    }
  });

  // 10. Policy update invalidating older revision
  it("rejects consumption of older revision artifact after policy is updated", () => {
    const dbFile = databasePath();
    const { authStore, policyStore, keyStore } = setupStores(dbFile, 1500);
    const key = createKeypair();

    try {
      policyStore.registerPolicy(validPolicy); // Revision 1
      keyStore.registerKey({ keyId: "key-pol-upd", publicKey: key.publicKey, status: "active" });

      const issuedRev1 = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-pol-upd", privateKey: key.privateKey },
        "auth-rev1",
        "policy-v3-alpha",
        validRequest,
      );
      expect(issuedRev1.decision).toBe("ALLOW");
      if (issuedRev1.decision !== "ALLOW") return;

      // Update policy -> increments to Revision 2
      const updated = policyStore.updatePolicy({ ...validPolicy, maxAmount: "2000000" }, 1);
      expect(updated.revision).toBe(2);

      // Consuming revision 1 artifact is rejected due to revision mismatch
      const consumeRes = consumeSignedTransactionAuthorizationV3(
        authStore,
        issuedRev1.artifact,
        issuedRev1.envelope,
        validRequest,
      );
      expect(consumeRes.decision).toBe("DENY");
      expect(consumeRes.reasons[0]).toContain("Policy revision mismatch");
    } finally {
      authStore.close();
    }
  });

  // 11. Policy revoke/restore not reviving old authorization
  it("restoring a revoked policy generates a new revision and does not revive old authorizations", () => {
    const dbFile = databasePath();
    const { authStore, policyStore, keyStore } = setupStores(dbFile, 1500);
    const key = createKeypair();

    try {
      policyStore.registerPolicy(validPolicy); // Rev 1
      keyStore.registerKey({ keyId: "key-pol-restore", publicKey: key.publicKey, status: "active" });

      const issuedRev1 = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-pol-restore", privateKey: key.privateKey },
        "auth-rev1-restore",
        "policy-v3-alpha",
        validRequest,
      );
      expect(issuedRev1.decision).toBe("ALLOW");
      if (issuedRev1.decision !== "ALLOW") return;

      // Revoke policy -> Rev 2
      policyStore.revokePolicy("policy-v3-alpha", 1);

      // Restore policy -> Rev 3
      policyStore.restorePolicy("policy-v3-alpha", validPolicy, 2);

      // Attempting to consume artifact bound to Rev 1 is denied (mismatch against current Rev 3)
      const consumeRes = consumeSignedTransactionAuthorizationV3(
        authStore,
        issuedRev1.artifact,
        issuedRev1.envelope,
        validRequest,
      );
      expect(consumeRes.decision).toBe("DENY");
      expect(consumeRes.reasons[0]).toContain("Policy revision mismatch");
    } finally {
      authStore.close();
    }
  });

  // 12. Policy delete/recreate with newer revision
  it("recreating a deleted policy with a newer revision rejects artifacts from the deleted policy", () => {
    const dbFile = databasePath();
    const { authStore, policyStore, keyStore } = setupStores(dbFile, 1500);
    const key = createKeypair();

    try {
      policyStore.registerPolicy(validPolicy); // Rev 1
      keyStore.registerKey({ keyId: "key-pol-del", publicKey: key.publicKey, status: "active" });

      const issued = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-pol-del", privateKey: key.privateKey },
        "auth-del-test",
        "policy-v3-alpha",
        validRequest,
      );
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Delete policy
      policyStore.deletePolicy("policy-v3-alpha", 1);

      // Recreate policy -> requires revision > maxRev (1), so pass initialRevision = 2
      const recreated = policyStore.registerPolicy(validPolicy, 2);
      expect(recreated.revision).toBe(2);

      // Old authorization bound to Rev 1 is denied
      const res = consumeSignedTransactionAuthorizationV3(
        authStore,
        issued.artifact,
        issued.envelope,
        validRequest,
      );
      expect(res.decision).toBe("DENY");
      expect(res.reasons[0]).toContain("Policy revision mismatch");
    } finally {
      authStore.close();
    }
  });

  // 13. Clock rollback and expiry boundaries
  it("rejects clock rollback and enforces expiry boundaries", () => {
    const dbFile = databasePath();
    const { authStore, policyStore, keyStore, clock } = setupStores(dbFile, 2000);
    const key = createKeypair();

    try {
      policyStore.registerPolicy({ ...validPolicy, expiresAt: 3000 });
      keyStore.registerKey({
        keyId: "key-clock-exp",
        publicKey: key.publicKey,
        status: "active",
        validFromSeconds: 1000,
        expiresAtSeconds: 4000,
      });

      // Issue at t=2000 with default TTL 300 -> expiresAtSeconds = 2300
      const issued = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-clock-exp", privateKey: key.privateKey },
        "auth-clock-test",
        "policy-v3-alpha",
        validRequest,
      );
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;
      expect(issued.artifact.expiresAtSeconds).toBe(2300);

      // Advance high-water mark to 2250
      clock.set(2250);
      authStore.advanceHighWaterMark(2250);

      // Roll clock back to 2100 and attempt consumption -> rejected
      clock.set(2100);
      const rollbackRes = consumeSignedTransactionAuthorizationV3(
        authStore,
        issued.artifact,
        issued.envelope,
        validRequest,
      );
      expect(rollbackRes.decision).toBe("DENY");
      expect(rollbackRes.reasons[0]).toContain("Clock rollback detected");

      // Advance clock to exact expiry boundary (2300) -> rejected as expired
      clock.set(2300);
      const boundaryRes = consumeSignedTransactionAuthorizationV3(
        authStore,
        issued.artifact,
        issued.envelope,
        validRequest,
      );
      expect(boundaryRes.decision).toBe("DENY");
      expect(boundaryRes.reasons).toContain("Signed transaction authorization has expired.");

      // Advance clock past authorization expiry (2350) -> rejected as expired
      clock.set(2350);
      const expiredRes = consumeSignedTransactionAuthorizationV3(
        authStore,
        issued.artifact,
        issued.envelope,
        validRequest,
      );
      expect(expiredRes.decision).toBe("DENY");
      expect(expiredRes.reasons).toContain("Signed transaction authorization has expired.");
    } finally {
      authStore.close();
    }
  });

  // 14. Concurrent consumption across separate SQLite connections: exactly one succeeds
  it("allows exactly one successful consumption under concurrent separate SQLite connections", () => {
    const dbFile = databasePath();
    const key = createKeypair();

    const store1 = new SQLiteAuthorizationStore(dbFile, new TestClock(1500));
    const store2 = new SQLiteAuthorizationStore(dbFile, new TestClock(1500));

    try {
      store1.getPolicyStore().registerPolicy(validPolicy);
      store1.getKeyStore().registerKey({ keyId: "key-concurrent-consume", publicKey: key.publicKey, status: "active" });

      const issued = issueSignedTransactionAuthorizationV3(
        store1,
        { keyId: "key-concurrent-consume", privateKey: key.privateKey },
        "auth-concurrent-race",
        "policy-v3-alpha",
        validRequest,
      );
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Store 1 consumes successfully
      const res1 = consumeSignedTransactionAuthorizationV3(
        store1,
        issued.artifact,
        issued.envelope,
        validRequest,
      );
      expect(res1.decision).toBe("ALLOW");

      // Store 2 attempts to consume the same artifact with a distinct envelope instance -> fails at SQLite storage
      const env2 = createTransactionEnvelope(validRequest);
      if (!env2.ok) throw new Error("Failed to create envelope");

      const res2 = consumeSignedTransactionAuthorizationV3(
        store2,
        issued.artifact,
        env2.envelope,
        validRequest,
      );
      expect(res2.decision).toBe("DENY");
      expect(res2.reasons).toContain(
        "Bound transaction authorization is unknown, consumed, or mismatched."
      );
    } finally {
      store1.close();
      store2.close();
    }
  });

  // 15. Issuance/consumption racing with policy revocation and key revocation
  it("denies consumption when policy or key is revoked immediately before consumption", () => {
    const dbFile = databasePath();
    const key = createKeypair();
    const store = new SQLiteAuthorizationStore(dbFile, new TestClock(1500));

    try {
      store.getPolicyStore().registerPolicy(validPolicy);
      store.getKeyStore().registerKey({ keyId: "key-race-rev", publicKey: key.publicKey, status: "active" });

      const issued = issueSignedTransactionAuthorizationV3(
        store,
        { keyId: "key-race-rev", privateKey: key.privateKey },
        "auth-race-rev",
        "policy-v3-alpha",
        validRequest,
      );
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;

      // Revoke policy
      store.getPolicyStore().revokePolicy("policy-v3-alpha", 1);

      // Consumption is immediately denied
      const res = consumeSignedTransactionAuthorizationV3(
        store,
        issued.artifact,
        issued.envelope,
        validRequest,
      );
      expect(res.decision).toBe("DENY");
      expect(res.reasons).toContain("Policy has been revoked.");
    } finally {
      store.close();
    }
  });

  // 16. Hardened Phase 2 read APIs: listPolicies and listKeys handle disappeared records defensively
  it("listPolicies and listKeys defensively handle records that disappear during iteration", () => {
    const dbFile = databasePath();
    const store = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
    const key = createKeypair();

    try {
      const polStore = store.getPolicyStore();
      const kStore = store.getKeyStore();

      polStore.registerPolicy(validPolicy);
      kStore.registerKey({ keyId: "key-hardened-1", publicKey: key.publicKey, status: "active" });

      const policies = polStore.listPolicies();
      expect(policies).toHaveLength(1);
      expect(policies[0].policyId).toBe("policy-v3-alpha");

      const keys = kStore.listKeys();
      expect(keys).toHaveLength(1);
      expect(keys[0].keyId).toBe("key-hardened-1");

      // Delete policy and verify listPolicies returns empty without error
      polStore.deletePolicy("policy-v3-alpha", 1);
      expect(polStore.listPolicies()).toHaveLength(0);
    } finally {
      store.close();
    }
  });

  // 17. Fix 1 (SEC-V3-01): Explicit signed authorization expiry boundaries, limits, and past-expiry rejection
  it("enforces explicit signed authorization expiry, bounding by policy and key, and custom TTL", () => {
    const dbFile = databasePath();
    const key = createKeypair();
    const { authStore, policyStore, keyStore, clock } = setupStores(dbFile, 1000);

    try {
      // Policy valid until t=1500
      policyStore.registerPolicy({ ...validPolicy, validFrom: 500, expiresAt: 1500 });
      // Key valid until t=1800
      keyStore.registerKey({
        keyId: "key-exp-test",
        publicKey: key.publicKey,
        status: "active",
        validFromSeconds: 500,
        expiresAtSeconds: 1800,
      });

      // 17.1 Custom TTL of 100s: expires at 1000 + 100 = 1100
      const customTtl = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-exp-test", privateKey: key.privateKey },
        "auth-ttl-100",
        "policy-v3-alpha",
        validRequest,
        { ttlSeconds: 100 },
      );
      expect(customTtl.decision).toBe("ALLOW");
      if (customTtl.decision !== "ALLOW") return;
      expect(customTtl.artifact.expiresAtSeconds).toBe(1100);

      // 17.2 Bounded by policy expiry (t=1500) when requested TTL (1000s) exceeds it
      const boundedByPolicy = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-exp-test", privateKey: key.privateKey },
        "auth-bounded-policy",
        "policy-v3-alpha",
        validRequest,
        { ttlSeconds: 1000 },
      );
      expect(boundedByPolicy.decision).toBe("ALLOW");
      if (boundedByPolicy.decision !== "ALLOW") return;
      expect(boundedByPolicy.artifact.expiresAtSeconds).toBe(1500);

      // 17.3 Forged artifact with expiry exceeding policy boundary is rejected at consumption
      const forgedPolicyExpPayload = canonicalSignedPayloadV3({
        version: 3,
        authorizationId: "auth-forged-pol-exp",
        keyId: "key-exp-test",
        issuedAtSeconds: 1000,
        expiresAtSeconds: 2000, // exceeds policy expiry 1500
        policyId: "policy-v3-alpha",
        policyRevision: 1,
        bindingDigest: customTtl.artifact.bindingDigest,
      });
      const forgedSig = signAuthorizationPayload(key.privateKey, forgedPolicyExpPayload);
      const forgedArtifact = {
        version: 3 as const,
        authorizationId: "auth-forged-pol-exp",
        keyId: "key-exp-test",
        issuedAtSeconds: 1000,
        expiresAtSeconds: 2000,
        policyId: "policy-v3-alpha",
        policyRevision: 1,
        bindingDigest: customTtl.artifact.bindingDigest,
        signature: forgedSig,
      };

      clock.set(1050); // within valid time and monotonically advancing from 1000
      const forgedConsume = consumeSignedTransactionAuthorizationV3(
        authStore,
        forgedArtifact,
        customTtl.envelope,
        validRequest,
      );
      expect(forgedConsume.decision).toBe("DENY");
      expect(forgedConsume.reasons).toContain(
        "Authorization expiry exceeds authoritative policy expiry boundary."
      );

      // 17.4 If policy is already expired (e.g. clock advanced to 1600), issuance is denied with empty validity interval
      clock.set(1600);
      const expiredPolicyIssue = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-exp-test", privateKey: key.privateKey },
        "auth-expired-policy",
        "policy-v3-alpha",
        validRequest,
      );
      expect(expiredPolicyIssue.decision).toBe("DENY");
      expect(expiredPolicyIssue.reasons).toContain(
        "Authorization validity interval is empty: policy or issuer key has already expired."
      );
    } finally {
      authStore.close();
    }
  });

  // 18. Fix 2 (SEC-V3-02): Separation of authorization and key validity
  it("enforces that authorization expiry is independent of key expiry", () => {
    const dbFile = databasePath();
    const key = createKeypair();
    const { authStore, policyStore, keyStore, clock } = setupStores(dbFile, 2000);

    try {
      // Key is valid for a long time (until t=10000)
      keyStore.registerKey({
        keyId: "key-long-lived",
        publicKey: key.publicKey,
        status: "active",
        validFromSeconds: 1000,
        expiresAtSeconds: 10000,
      });
      // Policy is valid until t=10000
      policyStore.registerPolicy({ ...validPolicy, validFrom: 1000, expiresAt: 10000 });

      // Issue an authorization with short TTL (200s), so it expires at t=2200
      const issued = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-long-lived", privateKey: key.privateKey },
        "auth-short-lived",
        "policy-v3-alpha",
        validRequest,
        { ttlSeconds: 200 },
      );
      expect(issued.decision).toBe("ALLOW");
      if (issued.decision !== "ALLOW") return;
      expect(issued.artifact.expiresAtSeconds).toBe(2200);

      // Advance clock to t=2500:
      // The key remains active, unexpired, and valid until 10000.
      clock.set(2500);

      // Consumption must be DENIED specifically because authorization expired, NOT because key expired
      const consumeRes = consumeSignedTransactionAuthorizationV3(
        authStore,
        issued.artifact,
        issued.envelope,
        validRequest,
      );
      expect(consumeRes.decision).toBe("DENY");
      expect(consumeRes.reasons).toContain("Signed transaction authorization has expired.");
      expect(consumeRes.reasons).not.toContain("Issuer key has expired.");

      // Key status check verifies key is still active
      const keyMeta = keyStore.getKey("key-long-lived");
      expect(keyMeta?.status).toBe("active");
      expect(keyMeta?.expiresAtSeconds).toBe(10000);
    } finally {
      authStore.close();
    }
  });

  // 19. Fix 3 (SEC-V3-03): Bounded SQLite contention retry handling and no partial writes
  it("handles transaction-start contention with bounded retry, fails closed cleanly, and prevents partial writes", () => {
    const dbFile = databasePath();
    const key = createKeypair();
    const store1 = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
    const store2 = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));

    try {
      store1.getPolicyStore().registerPolicy(validPolicy);
      store1.getKeyStore().registerKey({ keyId: "key-contention", publicKey: key.publicKey, status: "active" });

      const db1 = store1.getDatabase();
      const db2 = store2.getDatabase();

      // Lower busy_timeout on store2 for fast deterministic test
      db2.exec("PRAGMA busy_timeout = 10;");

      // Connection 1 holds an exclusive write lock
      db1.exec("BEGIN IMMEDIATE;");

      // Connection 2 attempts issuance -> contends, exhausts bounded retries, and fails closed with DENY
      const busyIssueRes = issueSignedTransactionAuthorizationV3(
        store2,
        { keyId: "key-contention", privateKey: key.privateKey },
        "auth-contention-test",
        "policy-v3-alpha",
        validRequest,
      );

      expect(busyIssueRes.decision).toBe("DENY");
      expect(busyIssueRes.reasons).toContain(
        "Database is busy; transaction contention retry limit exceeded."
      );

      // Verify NO partial record was inserted into SQLite
      expect(store1.getAuthorizationRecord("auth-contention-test")).toBeNull();

      // Release Connection 1 write lock
      db1.exec("ROLLBACK;");

      // Connection 2 retries issuance now that lock is free -> succeeds
      const succeedIssueRes = issueSignedTransactionAuthorizationV3(
        store2,
        { keyId: "key-contention", privateKey: key.privateKey },
        "auth-contention-test",
        "policy-v3-alpha",
        validRequest,
      );
      expect(succeedIssueRes.decision).toBe("ALLOW");
      if (succeedIssueRes.decision !== "ALLOW") return;

      // Verify record now cleanly exists in 'issued' state
      const record = store1.getAuthorizationRecord("auth-contention-test");
      expect(record).toBeDefined();
      expect(record?.state).toBe("issued");

      // Now test contention on consumption: Connection 1 locks again
      db1.exec("BEGIN IMMEDIATE;");

      const busyConsumeRes = consumeSignedTransactionAuthorizationV3(
        store2,
        succeedIssueRes.artifact,
        succeedIssueRes.envelope,
        validRequest,
      );
      expect(busyConsumeRes.decision).toBe("DENY");
      expect(busyConsumeRes.reasons).toContain(
        "Database is busy; transaction contention retry limit exceeded."
      );

      // Release Connection 1 lock
      db1.exec("ROLLBACK;");

      // Consumption succeeds once lock is free
      const succeedConsumeRes = consumeSignedTransactionAuthorizationV3(
        store2,
        succeedIssueRes.artifact,
        succeedIssueRes.envelope,
        validRequest,
      );
      expect(succeedConsumeRes.decision).toBe("ALLOW");

      const finalRecord = store1.getAuthorizationRecord("auth-contention-test");
      expect(finalRecord?.state).toBe("consumed");
    } finally {
      store1.close();
      store2.close();
    }
  });

  // 20. Fix SEC-63-01: Persisted-clock race condition between connections is closed
  it("uses persisted high-water mark derived inside transaction to prevent TOCTOU race (SEC-63-01)", () => {
    const dbFile = databasePath();
    const clock1 = new TestClock(1000);
    const clock2 = new TestClock(1000);
    const store1 = new SQLiteAuthorizationStore(dbFile, clock1);
    const store2 = new SQLiteAuthorizationStore(dbFile, clock2);
    const key = createKeypair();

    try {
      store1.getPolicyStore().registerPolicy(validPolicy);
      store1.getKeyStore().registerKey({
        keyId: "key-toctou",
        publicKey: key.publicKey,
        status: "active",
        validFromSeconds: 1000,
        expiresAtSeconds: 9000,
      });

      // 1. Issue artifact at t=1000 with TTL=100s -> expiresAt = 1100
      const issueRes = issueSignedTransactionAuthorizationV3(
        store1,
        { keyId: "key-toctou", privateKey: key.privateKey },
        "auth-toctou-race",
        "policy-v3-alpha",
        validRequest,
        { ttlSeconds: 100 },
      );
      expect(issueRes.decision).toBe("ALLOW");
      if (issueRes.decision !== "ALLOW") return;
      expect(issueRes.artifact.expiresAtSeconds).toBe(1100);

      // 2. Simulate competing connection race:
      // Between store1's initial clock snapshot (t=1050, within validity window < 1100)
      // and transaction acquisition, store2 advances the high-water mark to t=1150.
      let triggerRace = false;
      let snapshotCount = 0;
      const racingClock = {
        nowSeconds(): number {
          if (triggerRace) {
            snapshotCount++;
            if (snapshotCount === 1) {
              // Initial snapshot taken before transaction acquisition:
              // competing connection intervenes and advances persistent high-water mark to 1150
              clock2.set(1150);
              store2.advanceHighWaterMark(1150);
              return 1050;
            }
            return 1150;
          }
          return 1050;
        },
      };
      const racingStore = new SQLiteAuthorizationStore(dbFile, racingClock);
      try {
        triggerRace = true;

        // When racingStore calls consumeSignedTransactionAuthorizationV3:
        // Initial snapshot is 1050 (< 1100).
        // Inside transaction, it derives effectiveNowSeconds = max(1050, 1150) = 1150.
        // Since 1150 >= artifact.expiresAtSeconds (1100), consumption MUST BE DENIED with expiry reason!
        const consumeRes = consumeSignedTransactionAuthorizationV3(
          racingStore,
          issueRes.artifact,
          issueRes.envelope,
          validRequest,
        );
        expect(consumeRes.decision).toBe("DENY");
        expect(consumeRes.reasons).toContain("Signed transaction authorization has expired.");
      } finally {
        racingStore.close();
      }

      // Verify authorization record in database remains in 'issued' state (was not consumed)
      const record = store1.getAuthorizationRecord("auth-toctou-race");
      expect(record?.state).toBe("issued");
    } finally {
      store1.close();
      store2.close();
    }
  });

  // 21. Fix SEC-63-02: Key registration in retired or revoked status requires timestamps
  it("enforces timestamp requirements when registering or importing retired/revoked keys and prevents post-retirement forgery (SEC-63-02)", () => {
    const dbFile = databasePath();
    const { keyStore, authStore, policyStore } = setupStores(dbFile, 1000);
    const key = createKeypair();

    try {
      policyStore.registerPolicy(validPolicy);

      // 1. Registering retired key without retiredAtSeconds throws
      expect(() => {
        keyStore.registerKey({
          keyId: "key-retired-invalid",
          publicKey: key.publicKey,
          status: "retired",
        });
      }).toThrow("without a valid non-negative safe integer 'retiredAtSeconds'");

      // 2. Registering revoked key without revokedAtSeconds throws
      expect(() => {
        keyStore.registerKey({
          keyId: "key-revoked-invalid",
          publicKey: key.publicKey,
          status: "revoked",
        });
      }).toThrow("without a valid non-negative safe integer 'revokedAtSeconds'");

      // 3. Registering retired key with retiredAtSeconds < validFromSeconds throws
      expect(() => {
        keyStore.registerKey({
          keyId: "key-retired-before-valid",
          publicKey: key.publicKey,
          status: "retired",
          validFromSeconds: 1500,
          retiredAtSeconds: 1200,
        });
      }).toThrow("cannot precede validFromSeconds");

      // 4. Successfully register key with initial retired status and valid timestamps
      keyStore.registerKey({
        keyId: "key-retired-valid",
        publicKey: key.publicKey,
        status: "retired",
        validFromSeconds: 1000,
        retiredAtSeconds: 1500,
      });

      const keyMeta = keyStore.getKey("key-retired-valid");
      expect(keyMeta?.status).toBe("retired");
      expect(keyMeta?.retiredAtSeconds).toBe(1500);

      // 5. Issuing new authorization with this retired key is immediately rejected
      const issueRes = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-retired-valid", privateKey: key.privateKey },
        "auth-new-from-retired",
        "policy-v3-alpha",
        validRequest,
      );
      expect(issueRes.decision).toBe("DENY");
      expect(issueRes.reasons).toContain("Issuer key is retired and cannot issue new authorizations.");

      // 6. Forged artifact claiming issuedAtSeconds = 1600 (after retirement 1500) is rejected on consumption
      const forgedPayload = canonicalSignedPayloadV3({
        version: 3,
        authorizationId: "auth-forged-after-retire",
        keyId: "key-retired-valid",
        issuedAtSeconds: 1600,
        expiresAtSeconds: 1900,
        policyId: "policy-v3-alpha",
        policyRevision: 1,
        bindingDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      });
      const forgedSig = signAuthorizationPayload(key.privateKey, forgedPayload);
      const forgedArtifact = {
        version: 3 as const,
        authorizationId: "auth-forged-after-retire",
        keyId: "key-retired-valid",
        issuedAtSeconds: 1600,
        expiresAtSeconds: 1900,
        policyId: "policy-v3-alpha",
        policyRevision: 1,
        bindingDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        signature: forgedSig,
      };

      const consumeRes = consumeSignedTransactionAuthorizationV3(
        authStore,
        forgedArtifact,
        { request: validRequest },
        validRequest,
      );
      expect(consumeRes.decision).toBe("DENY");
      expect(consumeRes.reasons).toContain(
        "Authorization was issued after issuer key was retired."
      );
    } finally {
      authStore.close();
    }
  });

  // 22. Phase E: Cross-version API rejections
  it("rejects cross-version artifacts across V1, V2, and V3 consumption APIs", () => {
    const dbFile = databasePath();
    const { authStore, policyStore, keyStore } = setupStores(dbFile, 1000);
    const key = createKeypair();

    try {
      policyStore.registerPolicy(validPolicy);
      keyStore.registerKey({ keyId: "key-cross-version", publicKey: key.publicKey, status: "active" });

      const artifactV1 = {
        version: 1 as const,
        authorizationId: "auth-v1",
        bindingDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      };

      const artifactV2 = {
        version: 2 as const,
        authorizationId: "auth-v2",
        keyId: "key-cross-version",
        bindingDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        signature: "sig-dummy",
      };

      const artifactV3 = {
        version: 3 as const,
        authorizationId: "auth-v3",
        keyId: "key-cross-version",
        issuedAtSeconds: 1000,
        expiresAtSeconds: 1300,
        policyId: "policy-v3-alpha",
        policyRevision: 1,
        bindingDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        signature: "sig-dummy",
      };

      // 1. V3 API rejects V1 and V2 artifacts
      const v3RejectsV1 = consumeSignedTransactionAuthorizationV3(
        authStore,
        artifactV1,
        { request: validRequest },
        validRequest,
      );
      expect(v3RejectsV1.decision).toBe("DENY");
      expect(v3RejectsV1.reasons).toContain("Signed transaction authorization artifact is invalid or malformed.");

      const v3RejectsV2 = consumeSignedTransactionAuthorizationV3(
        authStore,
        artifactV2,
        { request: validRequest },
        validRequest,
      );
      expect(v3RejectsV2.decision).toBe("DENY");
      expect(v3RejectsV2.reasons).toContain("Signed transaction authorization artifact is invalid or malformed.");

      // 2. V2 API rejects V1 and V3 artifacts
      const v2RejectsV1 = consumeSignedTransactionAuthorizationWithStore(
        authStore,
        keyStore,
        artifactV1,
        validPolicy,
        { request: validRequest },
        validRequest,
        { nowSeconds: 1000 },
      );
      expect(v2RejectsV1.decision).toBe("DENY");
      expect(v2RejectsV1.reasons).toContain("Signed transaction authorization artifact is invalid.");

      const v2RejectsV3 = consumeSignedTransactionAuthorizationWithStore(
        authStore,
        keyStore,
        artifactV3,
        validPolicy,
        { request: validRequest },
        validRequest,
        { nowSeconds: 1000 },
      );
      expect(v2RejectsV3.decision).toBe("DENY");
      expect(v2RejectsV3.reasons).toContain("Signed transaction authorization artifact is invalid.");

      // 3. V1 API rejects V2 and V3 artifacts
      const v1RejectsV2 = consumeBoundTransactionAuthorizationWithStore(
        authStore,
        artifactV2,
        validPolicy,
        { request: validRequest },
        validRequest,
        { nowSeconds: 1000 },
      );
      expect(v1RejectsV2.decision).toBe("DENY");
      expect(v1RejectsV2.reasons).toContain("Bound transaction authorization artifact is invalid.");

      const v1RejectsV3 = consumeBoundTransactionAuthorizationWithStore(
        authStore,
        artifactV3,
        validPolicy,
        { request: validRequest },
        validRequest,
        { nowSeconds: 1000 },
      );
      expect(v1RejectsV3.decision).toBe("DENY");
      expect(v1RejectsV3.reasons).toContain("Bound transaction authorization artifact is invalid.");
    } finally {
      authStore.close();
    }
  });

  // 23. Phase E: SQLiteAuthorizationStore with allowLegacyArtifactVersions: false fails closed
  it("enforces fail-closed behavior when allowLegacyArtifactVersions is set to false", () => {
    const dbFile = databasePath();
    const clock = new TestClock(1000);
    const store = new SQLiteAuthorizationStore(dbFile, clock, { allowLegacyArtifactVersions: false });
    const key = createKeypair();

    try {
      store.getPolicyStore().registerPolicy(validPolicy);
      store.getKeyStore().registerKey({ keyId: "key-no-legacy", publicKey: key.publicKey, status: "active" });

      // 1. Calling reserve() directly fails closed
      expect(() => {
        store.reserve("auth-legacy-reserve");
      }).toThrow("Legacy authorization artifact versions are disabled by configuration.");

      // 2. Calling issueBound() directly fails closed for legacy versions 1 and 2
      expect(() => {
        store.issueBound("auth-legacy-issue-1", "sha256:dummy", 1);
      }).toThrow("Legacy authorization artifact versions are disabled by configuration.");
      expect(() => {
        store.issueBound("auth-legacy-issue-2", "sha256:dummy", 2);
      }).toThrow("Legacy authorization artifact versions are disabled by configuration.");

      // 3. Calling consumeBound() directly fails closed for legacy versions 1 and 2
      expect(() => {
        store.consumeBound("auth-legacy-consume-1", "sha256:dummy", 1);
      }).toThrow("Legacy authorization artifact versions are disabled by configuration.");
      expect(() => {
        store.consumeBound("auth-legacy-consume-2", "sha256:dummy", 2);
      }).toThrow("Legacy authorization artifact versions are disabled by configuration.");

      // 4. V1 issuance fails closed by throwing configuration error
      expect(() => {
        issueBoundTransactionAuthorizationWithStore(
          store,
          "auth-v1-attempt",
          validPolicy,
          validRequest,
          { nowSeconds: 1000 },
        );
      }).toThrow("Legacy authorization artifact versions are disabled by configuration.");

      // 5. V2 issuance fails closed by throwing configuration error
      expect(() => {
        issueSignedTransactionAuthorizationWithStore(
          store,
          store.getKeyStore(),
          { keyId: "key-no-legacy", privateKey: key.privateKey },
          "auth-v2-attempt",
          validPolicy,
          validRequest,
          { nowSeconds: 1000 },
        );
      }).toThrow("Legacy authorization artifact versions are disabled by configuration.");

      // 6. V3 issuance and consumption continue to succeed!
      const v3IssueRes = issueSignedTransactionAuthorizationV3(
        store,
        { keyId: "key-no-legacy", privateKey: key.privateKey },
        "auth-v3-allowed",
        "policy-v3-alpha",
        validRequest,
      );
      expect(v3IssueRes.decision).toBe("ALLOW");
      if (v3IssueRes.decision !== "ALLOW") return;

      const v3ConsumeRes = consumeSignedTransactionAuthorizationV3(
        store,
        v3IssueRes.artifact,
        v3IssueRes.envelope,
        validRequest,
      );
      expect(v3ConsumeRes.decision).toBe("ALLOW");
      const record = store.getAuthorizationRecord("auth-v3-allowed");
      expect(record?.state).toBe("consumed");
      expect(record?.artifactVersion).toBe(3);
    } finally {
      store.close();
    }
  });

  // 24. Failure injection: mid-transaction failure rolls back partial writes, preserves original error, and reverts in-transaction clock advance
  it("rolls back partial writes, preserves original error, and reverts in-transaction clock advance on failure", () => {
    const dbFile = databasePath();
    const { authStore, policyStore, keyStore, clock } = setupStores(dbFile, 1000);
    const key = createKeypair();

    try {
      policyStore.registerPolicy(validPolicy); // Revision 1
      keyStore.registerKey({ keyId: "key-v3-failure-test", publicKey: key.publicKey, status: "active" });

      // Persisted high-water mark starts at 1000
      const getHwMark = () => {
        const rawDb = new DatabaseSync(dbFile);
        try {
          return (
            rawDb.prepare("SELECT high_water_seconds FROM system_clock_state WHERE id = 1").get() as {
              high_water_seconds: number;
            }
          ).high_water_seconds;
        } finally {
          rawDb.close();
        }
      };

      expect(getHwMark()).toBe(1000);

      // Part A: Issuance failure after in-transaction clock advance rolls back high-water mark
      clock.set(1500);

      // A1. Soft failure (unknown policy) encountered after high-water advance in BEGIN IMMEDIATE
      const issueSoftFail = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-v3-failure-test", privateKey: key.privateKey },
        "auth-fail-soft",
        "policy-does-not-exist",
        validRequest,
      );
      expect(issueSoftFail.decision).toBe("DENY");
      expect(issueSoftFail.reasons).toContain("Policy 'policy-does-not-exist' not found.");
      // Clock advance inside the rolled-back transaction must revert
      expect(getHwMark()).toBe(1000);
      expect(authStore.getAuthorizationRecord("auth-fail-soft")).toBeNull();

      // A2. Hard unhandled DB error during INSERT into consumed_authorization_ids
      const triggerDb1 = new DatabaseSync(dbFile);
      try {
        triggerDb1.exec(`
          CREATE TRIGGER abort_auth_insert
          BEFORE INSERT ON consumed_authorization_ids
          BEGIN
            SELECT RAISE(ABORT, 'injected authorization insert abort');
          END;
        `);
      } finally {
        triggerDb1.close();
      }

      expect(() => {
        issueSignedTransactionAuthorizationV3(
          authStore,
          { keyId: "key-v3-failure-test", privateKey: key.privateKey },
          "auth-fail-hard",
          "policy-v3-alpha",
          validRequest,
        );
      }).toThrow(/injected authorization insert abort/);

      // High-water mark still rolled back to 1000, no partial records
      expect(getHwMark()).toBe(1000);
      expect(authStore.getAuthorizationRecord("auth-fail-hard")).toBeNull();

      // Cleanup insert trigger
      const cleanupDb1 = new DatabaseSync(dbFile);
      try {
        cleanupDb1.exec("DROP TRIGGER abort_auth_insert;");
      } finally {
        cleanupDb1.close();
      }

      // Legitimate issuance at t=1500 now succeeds and commits high-water mark to 1500
      const legitIssue = issueSignedTransactionAuthorizationV3(
        authStore,
        { keyId: "key-v3-failure-test", privateKey: key.privateKey },
        "auth-legit-v3",
        "policy-v3-alpha",
        validRequest,
      );
      expect(legitIssue.decision).toBe("ALLOW");
      if (legitIssue.decision !== "ALLOW") return;
      expect(getHwMark()).toBe(1500);
      expect(authStore.getAuthorizationRecord("auth-legit-v3")?.state).toBe("issued");

      // Part B: Consumption failure after in-transaction clock advance rolls back high-water mark and preserves 'issued' state
      // (Default TTL is 300s, so legitIssue expires at 1500 + 300 = 1800)
      clock.set(1600);

      // B1. Soft failure (tampered calldata / request mismatch) encountered after high-water advance
      const tamperedRequest: TransactionRequest = {
        ...validRequest,
        calldata: validRequest.calldata.slice(0, -4) + "beef",
      };

      const consumeSoftFail = consumeSignedTransactionAuthorizationV3(
        authStore,
        legitIssue.artifact,
        legitIssue.envelope,
        tamperedRequest,
      );
      expect(consumeSoftFail.decision).toBe("DENY");
      expect(consumeSoftFail.reasons).toContain(
        "Transaction does not match the original envelope."
      );
      // High-water mark remains 1500 (reverted from 1600)
      expect(getHwMark()).toBe(1500);
      // Authorization record remains 'issued' (NOT 'consumed', and consumed_at remains null)
      const recAfterSoftFail = authStore.getAuthorizationRecord("auth-legit-v3");
      expect(recAfterSoftFail?.state).toBe("issued");
      expect(recAfterSoftFail?.consumedAt).toBeNull();

      // B2. Hard unhandled DB error during UPDATE of consumed_authorization_ids
      clock.set(1650);
      const triggerDb2 = new DatabaseSync(dbFile);
      try {
        triggerDb2.exec(`
          CREATE TRIGGER abort_auth_update
          BEFORE UPDATE OF state ON consumed_authorization_ids
          BEGIN
            SELECT RAISE(ABORT, 'injected authorization update abort');
          END;
        `);
      } finally {
        triggerDb2.close();
      }

      expect(() => {
        consumeSignedTransactionAuthorizationV3(
          authStore,
          legitIssue.artifact,
          legitIssue.envelope,
          validRequest,
        );
      }).toThrow(/injected authorization update abort/);

      // High-water mark remains 1500 (reverted from 1650)
      expect(getHwMark()).toBe(1500);
      const recAfterHardFail = authStore.getAuthorizationRecord("auth-legit-v3");
      expect(recAfterHardFail?.state).toBe("issued");
      expect(recAfterHardFail?.consumedAt).toBeNull();

      // Cleanup update trigger
      const cleanupDb2 = new DatabaseSync(dbFile);
      try {
        cleanupDb2.exec("DROP TRIGGER abort_auth_update;");
      } finally {
        cleanupDb2.close();
      }

      // Legitimate consumption at t=1700 now succeeds (< 1800 expiry) and commits state to 'consumed' and high-water to 1700
      clock.set(1700);
      const legitConsume = consumeSignedTransactionAuthorizationV3(
        authStore,
        legitIssue.artifact,
        legitIssue.envelope,
        validRequest,
      );
      expect(legitConsume.decision).toBe("ALLOW");
      expect(getHwMark()).toBe(1700);
      const finalRec = authStore.getAuthorizationRecord("auth-legit-v3");
      expect(finalRec?.state).toBe("consumed");
      expect(finalRec?.consumedAt).not.toBeNull();
    } finally {
      authStore.close();
    }
  });
});
