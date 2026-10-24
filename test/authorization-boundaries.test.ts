import { fork } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { createAuthorizationBindingDigest } from "../src/authorization-binding.js";
import {
  canonicalSignedPayload,
  canonicalSignedPayloadV3,
  SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3,
  signAuthorizationPayload,
} from "../src/authorization-crypto.js";
import {
  cancelAuthorization,
  cancelSignedTransactionAuthorizationV3,
  consumeBoundTransactionAuthorizationWithStore,
  consumeSignedTransactionAuthorizationV3,
  consumeSignedTransactionAuthorizationWithStore,
  consumeTransactionAuthorization,
  consumeTransactionAuthorizationById,
  consumeTransactionAuthorizationWithStore,
  getConsumedAuthorizationIdsCount,
  issueBoundTransactionAuthorizationWithStore,
  issueSignedTransactionAuthorizationV3,
  issueSignedTransactionAuthorizationWithStore,
  MAX_PROCESS_LOCAL_CONSUMED_IDS,
  validateAuthorizationId,
} from "../src/authorization-lifecycle.js";
import { SQLiteAuthorizationStore } from "../src/authorization-store.js";
import { TestClock } from "../src/clock.js";
import { type DemoPolicy } from "../src/policy.js";
import { createTransactionEnvelope, type TransactionRequest } from "../src/transaction-envelope.js";

describe("Milestone 6.4 Phase 2: Authorization Boundary & Contract Hardening", () => {
  let directory: string | undefined;

  function databasePath(filename = "boundary-test.sqlite"): string {
    directory ??= mkdtempSync(join(tmpdir(), "web3user-boundary-"));
    return join(directory, filename);
  }

  function runSubprocess(code: string): Promise<{ exitCode: number | null; stdout: string; stderr: string }> {
    return new Promise((resolvePromise) => {
      let stdout = "";
      let stderr = "";
      const child = fork("-e", [code], {
        execArgv: ["--input-type=module", "--import", "tsx/esm"],
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

  const basePolicy: DemoPolicy = {
    version: 1,
    policyId: "policy-boundary",
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

  // =========================================================================
  // 1. Authorization Expiry Boundaries
  // =========================================================================
  describe("1. Authorization Expiry Boundaries", () => {
    it("strictly allows consumption immediately before expiration and rejects at and after expiration", () => {
      const dbFile = databasePath("expiry-boundaries.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLiteAuthorizationStore(dbFile, clock);
      const key = createKeypair();

      try {
        store.getPolicyStore().registerPolicy(basePolicy);
        store.getKeyStore().registerKey({
          keyId: "key-expiry-boundary",
          publicKey: key.publicKey,
          status: "active",
          validFromSeconds: 1000,
          expiresAtSeconds: 9000,
        });

        // Issue artifact with custom TTL = 500s. Issuance at t=1000 -> expiresAtSeconds = 1500
        const issued = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-expiry-boundary", privateKey: key.privateKey },
          "auth-expiry-test",
          "policy-boundary",
          validRequest,
          { ttlSeconds: 500 },
        );
        expect(issued.decision).toBe("ALLOW");
        if (issued.decision !== "ALLOW") return;
        expect(issued.artifact.expiresAtSeconds).toBe(1500);

        // Case 1: Immediately before expiration (t = 1499) -> ALLOWED
        clock.set(1499);
        const consumeBefore = consumeSignedTransactionAuthorizationV3(
          store,
          issued.artifact,
          issued.envelope,
          validRequest,
        );
        expect(consumeBefore.decision).toBe("ALLOW");
        expect(store.getAuthorizationRecord("auth-expiry-test")?.state).toBe("consumed");

        // Issue a second authorization for testing the exact boundary and post-boundary
        const issued2 = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-expiry-boundary", privateKey: key.privateKey },
          "auth-expiry-exact",
          "policy-boundary",
          validRequest,
          { ttlSeconds: 500 },
        );
        expect(issued2.decision).toBe("ALLOW");
        if (issued2.decision !== "ALLOW") return;
        // Issued at effectiveNow = 1499 (persisted high-water mark) -> expiresAtSeconds = 1999

        // Case 2: Exactly at expiration boundary (t = 1999) -> DENIED
        clock.set(1999);
        const consumeExact = consumeSignedTransactionAuthorizationV3(
          store,
          issued2.artifact,
          issued2.envelope,
          validRequest,
        );
        expect(consumeExact.decision).toBe("DENY");
        expect(consumeExact.reasons).toContain("Signed transaction authorization has expired.");

        // CRITICAL: Verify that the rejected expired authorization does NOT become consumed
        const recordExact = store.getAuthorizationRecord("auth-expiry-exact");
        expect(recordExact?.state).toBe("issued");
        expect(recordExact?.consumedAt).toBeNull();

        // Case 3: Immediately after expiration boundary (t = 2000) -> DENIED
        clock.set(2000);
        const consumeAfter = consumeSignedTransactionAuthorizationV3(
          store,
          issued2.artifact,
          issued2.envelope,
          validRequest,
        );
        expect(consumeAfter.decision).toBe("DENY");
        expect(consumeAfter.reasons).toContain("Signed transaction authorization has expired.");

        // Storage state remains strictly 'issued' and unconsumed
        const recordAfter = store.getAuthorizationRecord("auth-expiry-exact");
        expect(recordAfter?.state).toBe("issued");
        expect(recordAfter?.consumedAt).toBeNull();

        // Case 4: Even further after expiration (t = 2500) -> repeatedly DENIED, remains unconsumed
        clock.set(2500);
        const consumeLater = consumeSignedTransactionAuthorizationV3(
          store,
          issued2.artifact,
          issued2.envelope,
          validRequest,
        );
        expect(consumeLater.decision).toBe("DENY");
        expect(store.getAuthorizationRecord("auth-expiry-exact")?.state).toBe("issued");
      } finally {
        store.close();
      }
    });

    it("caps artifact expiry by authoritative policy expiry deadline", () => {
      const dbFile = databasePath("policy-expiry-cap.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLiteAuthorizationStore(dbFile, clock);
      const key = createKeypair();

      try {
        // Policy expires at t = 1300
        const policyCapped: DemoPolicy = {
          ...basePolicy,
          policyId: "policy-capped",
          expiresAt: 1300,
        };
        store.getPolicyStore().registerPolicy(policyCapped);
        store.getKeyStore().registerKey({
          keyId: "key-cap-test",
          publicKey: key.publicKey,
          status: "active",
        });

        // Request TTL = 1000 (which would reach 2000), but policy expires at 1300
        const issued = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-cap-test", privateKey: key.privateKey },
          "auth-policy-capped",
          "policy-capped",
          validRequest,
          { ttlSeconds: 1000 },
        );
        expect(issued.decision).toBe("ALLOW");
        if (issued.decision !== "ALLOW") return;
        expect(issued.artifact.expiresAtSeconds).toBe(1300);

        // Immediately before policy expiry boundary (t = 1299) -> ALLOW
        clock.set(1299);
        const consumeAllowed = consumeSignedTransactionAuthorizationV3(
          store,
          issued.artifact,
          issued.envelope,
          validRequest,
        );
        expect(consumeAllowed.decision).toBe("ALLOW");

        // Issue another capped artifact at t=1299
        const issued2 = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-cap-test", privateKey: key.privateKey },
          "auth-policy-capped-2",
          "policy-capped",
          validRequest,
          { ttlSeconds: 500 },
        );
        expect(issued2.decision).toBe("ALLOW");
        if (issued2.decision !== "ALLOW") return;
        expect(issued2.artifact.expiresAtSeconds).toBe(1300);

        // Exactly at policy expiry boundary (t = 1300) -> DENY and remains unconsumed
        clock.set(1300);
        const consumeAtExpiry = consumeSignedTransactionAuthorizationV3(
          store,
          issued2.artifact,
          issued2.envelope,
          validRequest,
        );
        expect(consumeAtExpiry.decision).toBe("DENY");
        expect(consumeAtExpiry.reasons).toContain("Signed transaction authorization has expired.");
        expect(store.getAuthorizationRecord("auth-policy-capped-2")?.state).toBe("issued");
      } finally {
        store.close();
      }
    });
  });

  // =========================================================================
  // 2. Signing-Key Validity Boundaries
  // =========================================================================
  describe("2. Signing-Key Validity Boundaries", () => {
    it("enforces key validFrom and expiresAt boundaries at issuance", () => {
      const dbFile = databasePath("key-issuance-boundaries.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLiteAuthorizationStore(dbFile, clock);
      const key = createKeypair();

      try {
        store.getPolicyStore().registerPolicy(basePolicy);
        // Key is valid strictly from t = 1200 to t = 2000
        store.getKeyStore().registerKey({
          keyId: "key-windowed",
          publicKey: key.publicKey,
          status: "active",
          validFromSeconds: 1200,
          expiresAtSeconds: 2000,
        });

        // 1. Before validFrom (t = 1199) -> DENY
        clock.set(1199);
        const beforeValid = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-windowed", privateKey: key.privateKey },
          "auth-before-valid",
          "policy-boundary",
          validRequest,
        );
        expect(beforeValid.decision).toBe("DENY");
        expect(beforeValid.reasons).toContain("Issuer key is not yet valid.");
        expect(store.getAuthorizationRecord("auth-before-valid")).toBeNull();

        // 2. Exactly at validFrom (t = 1200) -> ALLOW (inclusive boundary)
        clock.set(1200);
        const atValid = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-windowed", privateKey: key.privateKey },
          "auth-at-valid",
          "policy-boundary",
          validRequest,
        );
        expect(atValid.decision).toBe("ALLOW");
        if (atValid.decision !== "ALLOW") return;
        expect(atValid.artifact.issuedAtSeconds).toBe(1200);

        // 3. Immediately before key expiration (t = 1999) -> ALLOW (key is still valid for 1s)
        clock.set(1999);
        const beforeKeyExpiry = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-windowed", privateKey: key.privateKey },
          "auth-before-key-expiry",
          "policy-boundary",
          validRequest,
        );
        expect(beforeKeyExpiry.decision).toBe("ALLOW");
        if (beforeKeyExpiry.decision !== "ALLOW") return;
        // TTL is capped by key's expiresAtSeconds (2000)
        expect(beforeKeyExpiry.artifact.expiresAtSeconds).toBe(2000);

        // 4. Exactly at key expiration (t = 2000) -> DENY
        clock.set(2000);
        const atKeyExpiry = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-windowed", privateKey: key.privateKey },
          "auth-at-key-expiry",
          "policy-boundary",
          validRequest,
        );
        expect(atKeyExpiry.decision).toBe("DENY");
        expect(atKeyExpiry.reasons).toContain("Issuer key has expired.");
        expect(store.getAuthorizationRecord("auth-at-key-expiry")).toBeNull();

        // 5. After key expiration (t = 2001) -> DENY
        clock.set(2001);
        const afterKeyExpiry = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-windowed", privateKey: key.privateKey },
          "auth-after-key-expiry",
          "policy-boundary",
          validRequest,
        );
        expect(afterKeyExpiry.decision).toBe("DENY");
        expect(afterKeyExpiry.reasons).toContain("Issuer key has expired.");
        expect(store.getAuthorizationRecord("auth-after-key-expiry")).toBeNull();
      } finally {
        store.close();
      }
    });

    it("enforces key validity boundaries at consumption time and prevents unauthorized consumption", () => {
      const dbFile = databasePath("key-consumption-boundaries.sqlite");
      const clock = new TestClock(1200);
      const store = new SQLiteAuthorizationStore(dbFile, clock);
      const key = createKeypair();

      try {
        store.getPolicyStore().registerPolicy(basePolicy);
        // Key valid from 1200 to 2000
        store.getKeyStore().registerKey({
          keyId: "key-window-consume",
          publicKey: key.publicKey,
          status: "active",
          validFromSeconds: 1200,
          expiresAtSeconds: 2000,
        });

        // Issue valid artifact at t=1200 with TTL=600 (expires at 1800)
        const issued = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-window-consume", privateKey: key.privateKey },
          "auth-key-consume",
          "policy-boundary",
          validRequest,
          { ttlSeconds: 600 },
        );
        expect(issued.decision).toBe("ALLOW");
        if (issued.decision !== "ALLOW") return;

        // 1. Consume at validFrom boundary (t = 1200) -> ALLOW
        const consumeAtStart = consumeSignedTransactionAuthorizationV3(
          store,
          issued.artifact,
          issued.envelope,
          validRequest,
        );
        expect(consumeAtStart.decision).toBe("ALLOW");

        // Issue another artifact with TTL = 800 (capped at key expiresAt = 2000)
        const issued2 = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-window-consume", privateKey: key.privateKey },
          "auth-key-consume-2",
          "policy-boundary",
          validRequest,
          { ttlSeconds: 800 },
        );
        expect(issued2.decision).toBe("ALLOW");
        if (issued2.decision !== "ALLOW") return;
        expect(issued2.artifact.expiresAtSeconds).toBe(2000);

        // 2. Consume immediately before key expiration (t = 1999) -> ALLOW
        clock.set(1999);
        const consumeBeforeExpiry = consumeSignedTransactionAuthorizationV3(
          store,
          issued2.artifact,
          issued2.envelope,
          validRequest,
        );
        expect(consumeBeforeExpiry.decision).toBe("ALLOW");

        // Issue third artifact at t=1999 (expires at 2000)
        const issued3 = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-window-consume", privateKey: key.privateKey },
          "auth-key-consume-3",
          "policy-boundary",
          validRequest,
        );
        expect(issued3.decision).toBe("ALLOW");
        if (issued3.decision !== "ALLOW") return;

        // 3. Consume at key expiration (t = 2000) -> DENIED due to expired key
        clock.set(2000);
        const consumeAtKeyExpiry = consumeSignedTransactionAuthorizationV3(
          store,
          issued3.artifact,
          issued3.envelope,
          validRequest,
        );
        expect(consumeAtKeyExpiry.decision).toBe("DENY");
        expect(consumeAtKeyExpiry.reasons).toContain("Issuer key has expired.");
        expect(store.getAuthorizationRecord("auth-key-consume-3")?.state).toBe("issued");

        // 4. Consume after key expiration (t = 2001) -> DENIED and remains unconsumed
        clock.set(2001);
        const consumeAfterKeyExpiry = consumeSignedTransactionAuthorizationV3(
          store,
          issued3.artifact,
          issued3.envelope,
          validRequest,
        );
        expect(consumeAfterKeyExpiry.decision).toBe("DENY");
        expect(consumeAfterKeyExpiry.reasons).toContain("Issuer key has expired.");
        expect(store.getAuthorizationRecord("auth-key-consume-3")?.state).toBe("issued");
      } finally {
        store.close();
      }
    });

    it("rejects forged artifacts claiming issuance outside key validity window", () => {
      const dbFile = databasePath("forged-key-window.sqlite");
      const clock = new TestClock(1500);
      const store = new SQLiteAuthorizationStore(dbFile, clock);
      const key = createKeypair();

      try {
        store.getPolicyStore().registerPolicy(basePolicy);
        store.getKeyStore().registerKey({
          keyId: "key-window-forged",
          publicKey: key.publicKey,
          status: "active",
          validFromSeconds: 1200,
          expiresAtSeconds: 2000,
        });

        const envelopeRes = createTransactionEnvelope(validRequest);
        if (!envelopeRes.ok) throw new Error("Envelope creation failed");

        const bindingDigest = createAuthorizationBindingDigest(
          basePolicy,
          envelopeRes.envelope.request,
        );

        // Forgery A: Artifact claiming issuance at t = 1199 (before key was valid)
        const payloadBefore = canonicalSignedPayloadV3({
          version: SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3,
          authorizationId: "auth-forged-before-valid",
          keyId: "key-window-forged",
          issuedAtSeconds: 1199,
          expiresAtSeconds: 1499,
          policyId: "policy-boundary",
          policyRevision: 1,
          bindingDigest,
        });
        const sigBefore = signAuthorizationPayload(key.privateKey, payloadBefore);

        const forgedBeforeArtifact = {
          version: SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3,
          authorizationId: "auth-forged-before-valid",
          keyId: "key-window-forged",
          issuedAtSeconds: 1199,
          expiresAtSeconds: 1499,
          policyId: "policy-boundary",
          policyRevision: 1,
          bindingDigest,
          signature: sigBefore,
        };

        const consumeBefore = consumeSignedTransactionAuthorizationV3(
          store,
          forgedBeforeArtifact,
          envelopeRes.envelope,
          validRequest,
        );
        expect(consumeBefore.decision).toBe("DENY");
        expect(consumeBefore.reasons).toContain(
          "Issuer key was not yet valid at authorization issuance time.",
        );

        // Forgery B: Artifact claiming issuance at t = 2000 (at or after key expired)
        const payloadExpired = canonicalSignedPayloadV3({
          version: SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3,
          authorizationId: "auth-forged-expired-key",
          keyId: "key-window-forged",
          issuedAtSeconds: 2000,
          expiresAtSeconds: 2100,
          policyId: "policy-boundary",
          policyRevision: 1,
          bindingDigest,
        });
        const sigExpired = signAuthorizationPayload(key.privateKey, payloadExpired);

        const forgedExpiredArtifact = {
          version: SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3,
          authorizationId: "auth-forged-expired-key",
          keyId: "key-window-forged",
          issuedAtSeconds: 2000,
          expiresAtSeconds: 2100,
          policyId: "policy-boundary",
          policyRevision: 1,
          bindingDigest,
          signature: sigExpired,
        };

        const consumeExpired = consumeSignedTransactionAuthorizationV3(
          store,
          forgedExpiredArtifact,
          envelopeRes.envelope,
          validRequest,
        );
        expect(consumeExpired.decision).toBe("DENY");
        expect(consumeExpired.reasons).toContain(
          "Issuer key had expired at authorization issuance time.",
        );
      } finally {
        store.close();
      }
    });
  });

  // =========================================================================
  // 3. TTL Input Validation
  // =========================================================================
  describe("3. TTL Input Validation", () => {
    it("rejects non-object options, zero, negative, fractional, NaN, and infinite TTL values", () => {
      const dbFile = databasePath("ttl-validation.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLiteAuthorizationStore(dbFile, clock);
      const key = createKeypair();

      try {
        store.getPolicyStore().registerPolicy(basePolicy);
        store.getKeyStore().registerKey({
          keyId: "key-ttl-test",
          publicKey: key.publicKey,
          status: "active",
        });

        const signer = { keyId: "key-ttl-test", privateKey: key.privateKey };

        // 1. Non-object options inputs
        expect(
          issueSignedTransactionAuthorizationV3(store, signer, "a1", "policy-boundary", validRequest, "invalid" as any).decision,
        ).toBe("DENY");
        expect(
          issueSignedTransactionAuthorizationV3(store, signer, "a2", "policy-boundary", validRequest, 120 as any).decision,
        ).toBe("DENY");
        expect(
          issueSignedTransactionAuthorizationV3(store, signer, "a3", "policy-boundary", validRequest, true as any).decision,
        ).toBe("DENY");
        expect(
          issueSignedTransactionAuthorizationV3(store, signer, "a4", "policy-boundary", validRequest, [300] as any).decision,
        ).toBe("DENY");

        // 2. Zero TTL
        const zeroTtl = issueSignedTransactionAuthorizationV3(
          store,
          signer,
          "a-zero",
          "policy-boundary",
          validRequest,
          { ttlSeconds: 0 },
        );
        expect(zeroTtl.decision).toBe("DENY");
        expect(zeroTtl.reasons).toContain("Authorization TTL must be a positive safe integer.");

        // 3. Negative TTL
        const negTtl1 = issueSignedTransactionAuthorizationV3(
          store,
          signer,
          "a-neg-1",
          "policy-boundary",
          validRequest,
          { ttlSeconds: -1 },
        );
        expect(negTtl1.decision).toBe("DENY");
        expect(negTtl1.reasons).toContain("Authorization TTL must be a positive safe integer.");

        const negTtl2 = issueSignedTransactionAuthorizationV3(
          store,
          signer,
          "a-neg-100",
          "policy-boundary",
          validRequest,
          { ttlSeconds: -100 },
        );
        expect(negTtl2.decision).toBe("DENY");
        expect(negTtl2.reasons).toContain("Authorization TTL must be a positive safe integer.");

        // 4. Fractional TTL values
        const fracTtl1 = issueSignedTransactionAuthorizationV3(
          store,
          signer,
          "a-frac-1",
          "policy-boundary",
          validRequest,
          { ttlSeconds: 1.5 },
        );
        expect(fracTtl1.decision).toBe("DENY");
        expect(fracTtl1.reasons).toContain("Authorization TTL must be a positive safe integer.");

        const fracTtl2 = issueSignedTransactionAuthorizationV3(
          store,
          signer,
          "a-frac-2",
          "policy-boundary",
          validRequest,
          { ttlSeconds: 0.1 },
        );
        expect(fracTtl2.decision).toBe("DENY");
        expect(fracTtl2.reasons).toContain("Authorization TTL must be a positive safe integer.");

        // 5. Special values: NaN and Infinities
        const nanTtl = issueSignedTransactionAuthorizationV3(
          store,
          signer,
          "a-nan",
          "policy-boundary",
          validRequest,
          { ttlSeconds: NaN },
        );
        expect(nanTtl.decision).toBe("DENY");
        expect(nanTtl.reasons).toContain("Authorization TTL must be a positive safe integer.");

        const infTtl1 = issueSignedTransactionAuthorizationV3(
          store,
          signer,
          "a-inf-1",
          "policy-boundary",
          validRequest,
          { ttlSeconds: Infinity },
        );
        expect(infTtl1.decision).toBe("DENY");
        expect(infTtl1.reasons).toContain("Authorization TTL must be a positive safe integer.");

        const infTtl2 = issueSignedTransactionAuthorizationV3(
          store,
          signer,
          "a-inf-2",
          "policy-boundary",
          validRequest,
          { ttlSeconds: -Infinity },
        );
        expect(infTtl2.decision).toBe("DENY");
        expect(infTtl2.reasons).toContain("Authorization TTL must be a positive safe integer.");

        // 6. Unsafe integer values
        const unsafeTtl = issueSignedTransactionAuthorizationV3(
          store,
          signer,
          "a-unsafe",
          "policy-boundary",
          validRequest,
          { ttlSeconds: Number.MAX_SAFE_INTEGER + 1 },
        );
        expect(unsafeTtl.decision).toBe("DENY");
        expect(unsafeTtl.reasons).toContain("Authorization TTL must be a positive safe integer.");

        // Confirm database contains zero records from rejected attempts
        const rawDb = new DatabaseSync(dbFile);
        try {
          const count = (
            rawDb.prepare("SELECT count(*) as c FROM consumed_authorization_ids").get() as { c: number }
          ).c;
          expect(count).toBe(0);
        } finally {
          rawDb.close();
        }
      } finally {
        store.close();
      }
    });

    it("handles boundary TTL up to Number.MAX_SAFE_INTEGER and enforces safe integer boundaries", () => {
      const dbFile = databasePath("ttl-arithmetic.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLiteAuthorizationStore(dbFile, clock);
      const key = createKeypair();

      try {
        // Policy with maximum safe integer expiry
        const maxPolicy: DemoPolicy = {
          ...basePolicy,
          policyId: "policy-max-safe",
          expiresAt: Number.MAX_SAFE_INTEGER,
        };
        store.getPolicyStore().registerPolicy(maxPolicy);
        store.getKeyStore().registerKey({
          keyId: "key-ttl-open",
          publicKey: key.publicKey,
          status: "active",
          validFromSeconds: 1000,
        });

        const signer = { keyId: "key-ttl-open", privateKey: key.privateKey };

        // 1. Largest valid TTL where effectiveNowSeconds + ttlSeconds === Number.MAX_SAFE_INTEGER
        const maxValidTtl = Number.MAX_SAFE_INTEGER - 1000;
        const maxValidRes = issueSignedTransactionAuthorizationV3(
          store,
          signer,
          "auth-max-safe-ttl",
          "policy-max-safe",
          validRequest,
          { ttlSeconds: maxValidTtl },
        );
        expect(maxValidRes.decision).toBe("ALLOW");
        if (maxValidRes.decision !== "ALLOW") return;
        expect(maxValidRes.artifact.expiresAtSeconds).toBe(Number.MAX_SAFE_INTEGER);

        // 2. Passing Number.MAX_SAFE_INTEGER as ttlSeconds is valid safe integer;
        // it is clamped by policy.expiresAt to Number.MAX_SAFE_INTEGER
        const clampRes = issueSignedTransactionAuthorizationV3(
          store,
          signer,
          "auth-clamped-ttl",
          "policy-max-safe",
          validRequest,
          { ttlSeconds: Number.MAX_SAFE_INTEGER },
        );
        expect(clampRes.decision).toBe("ALLOW");
        if (clampRes.decision !== "ALLOW") return;
        expect(clampRes.artifact.expiresAtSeconds).toBe(Number.MAX_SAFE_INTEGER);

        // 3. Passing Number.MAX_SAFE_INTEGER + 1 as ttlSeconds fails isSafeInteger and is rejected
        const unsafeRes = issueSignedTransactionAuthorizationV3(
          store,
          signer,
          "auth-unsafe-ttl",
          "policy-max-safe",
          validRequest,
          { ttlSeconds: Number.MAX_SAFE_INTEGER + 1 },
        );
        expect(unsafeRes.decision).toBe("DENY");
        expect(unsafeRes.reasons).toContain("Authorization TTL must be a positive safe integer.");
        expect(store.getAuthorizationRecord("auth-unsafe-ttl")).toBeNull();

        // 4. Empty validity interval when policy has already expired
        const expiredPolicy: DemoPolicy = {
          ...basePolicy,
          policyId: "policy-already-expired",
          validFrom: 100,
          expiresAt: 500,
        };
        store.getPolicyStore().registerPolicy(expiredPolicy);
        const emptyIntervalRes = issueSignedTransactionAuthorizationV3(
          store,
          signer,
          "auth-empty-interval",
          "policy-already-expired",
          validRequest,
        );
        expect(emptyIntervalRes.decision).toBe("DENY");
        expect(emptyIntervalRes.reasons).toContain(
          "Authorization validity interval is empty: policy or issuer key has already expired.",
        );
        expect(store.getAuthorizationRecord("auth-empty-interval")).toBeNull();
      } finally {
        store.close();
      }
    });

    it("safely caps large TTL by policy expiry and signing-key expiry without unsafe integer addition", () => {
      const dbFile = databasePath("ttl-capping-safe.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLiteAuthorizationStore(dbFile, clock);
      const key = createKeypair();

      try {
        // Policy capped at t = 2500
        const policyCapped: DemoPolicy = {
          ...basePolicy,
          policyId: "policy-capped-2500",
          expiresAt: 2500,
        };
        // Policy with large safe expiry for key test
        const policyMax: DemoPolicy = {
          ...basePolicy,
          policyId: "policy-for-key-cap",
          expiresAt: Number.MAX_SAFE_INTEGER,
        };
        store.getPolicyStore().registerPolicy(policyCapped);
        store.getPolicyStore().registerPolicy(policyMax);

        // Key 1: Open-ended key (expiresAtSeconds: undefined)
        store.getKeyStore().registerKey({
          keyId: "key-open-ended",
          publicKey: key.publicKey,
          status: "active",
          validFromSeconds: 1000,
        });

        // Key 2: Key capped at t = 3500
        store.getKeyStore().registerKey({
          keyId: "key-capped-3500",
          publicKey: key.publicKey,
          status: "active",
          validFromSeconds: 1000,
          expiresAtSeconds: 3500,
        });

        const signerOpen = { keyId: "key-open-ended", privateKey: key.privateKey };
        const signerCapped = { keyId: "key-capped-3500", privateKey: key.privateKey };

        // 1. Large TTL (exceeding safe range or huge integer) safely capped by policy expiry (2500)
        // effectiveNow = 1000, ttlSeconds = 5_000_000_000 -> capped at 2500
        const policyCapRes = issueSignedTransactionAuthorizationV3(
          store,
          signerOpen,
          "auth-policy-capped-large",
          "policy-capped-2500",
          validRequest,
          { ttlSeconds: 5_000_000_000 },
        );
        expect(policyCapRes.decision).toBe("ALLOW");
        if (policyCapRes.decision !== "ALLOW") return;
        expect(policyCapRes.artifact.expiresAtSeconds).toBe(2500);
        expect(Number.isSafeInteger(policyCapRes.artifact.expiresAtSeconds)).toBe(true);

        // 2. Large TTL safely capped by signing-key expiry (3500)
        // effectiveNow = 1000, policy.expiresAt = MAX_SAFE_INTEGER, key.expiresAt = 3500
        // ttlSeconds = Number.MAX_SAFE_INTEGER -> capped at 3500
        const keyCapRes = issueSignedTransactionAuthorizationV3(
          store,
          signerCapped,
          "auth-key-capped-large",
          "policy-for-key-cap",
          validRequest,
          { ttlSeconds: Number.MAX_SAFE_INTEGER },
        );
        expect(keyCapRes.decision).toBe("ALLOW");
        if (keyCapRes.decision !== "ALLOW") return;
        expect(keyCapRes.artifact.expiresAtSeconds).toBe(3500);
        expect(Number.isSafeInteger(keyCapRes.artifact.expiresAtSeconds)).toBe(true);

        // 3. Exact boundary cases against key expiry (3500):
        // Remaining time = 3500 - 1000 = 2500
        // Boundary case A: ttlSeconds === remainingValidSeconds (2500) -> exact match at 3500
        const exactBoundaryRes = issueSignedTransactionAuthorizationV3(
          store,
          signerCapped,
          "auth-exact-boundary-ttl",
          "policy-for-key-cap",
          validRequest,
          { ttlSeconds: 2500 },
        );
        expect(exactBoundaryRes.decision).toBe("ALLOW");
        if (exactBoundaryRes.decision !== "ALLOW") return;
        expect(exactBoundaryRes.artifact.expiresAtSeconds).toBe(3500);

        // Boundary case B: ttlSeconds === remainingValidSeconds - 1 (2499) -> expires at 3499
        const subBoundaryRes = issueSignedTransactionAuthorizationV3(
          store,
          signerCapped,
          "auth-sub-boundary-ttl",
          "policy-for-key-cap",
          validRequest,
          { ttlSeconds: 2499 },
        );
        expect(subBoundaryRes.decision).toBe("ALLOW");
        if (subBoundaryRes.decision !== "ALLOW") return;
        expect(subBoundaryRes.artifact.expiresAtSeconds).toBe(3499);

        // 4. Large valid TTL when now + TTL would exceed Number.MAX_SAFE_INTEGER:
        // effectiveNow = 1000, policy.expiresAt = MAX_SAFE_INTEGER, key.expiresAt = null
        // ttlSeconds = Number.MAX_SAFE_INTEGER -> capped safely at Number.MAX_SAFE_INTEGER
        // without performing intermediate overflow addition
        const maxSafeCapRes = issueSignedTransactionAuthorizationV3(
          store,
          signerOpen,
          "auth-max-safe-overflow-safe",
          "policy-for-key-cap",
          validRequest,
          { ttlSeconds: Number.MAX_SAFE_INTEGER },
        );
        expect(maxSafeCapRes.decision).toBe("ALLOW");
        if (maxSafeCapRes.decision !== "ALLOW") return;
        expect(maxSafeCapRes.artifact.expiresAtSeconds).toBe(Number.MAX_SAFE_INTEGER);
        expect(Number.isSafeInteger(maxSafeCapRes.artifact.expiresAtSeconds)).toBe(true);
      } finally {
        store.close();
      }
    });
  });

  // =========================================================================
  // 4. Legacy Fail-Closed Mode (allowLegacyArtifactVersions: false)
  // =========================================================================
  describe("4. Legacy Fail-Closed Mode (allowLegacyArtifactVersions: false)", () => {
    it("rejects all V1 and V2 public consumption entry points when allowLegacyArtifactVersions is false", () => {
      const dbFile = databasePath("legacy-fail-closed.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLiteAuthorizationStore(dbFile, {
        clock,
        allowLegacyArtifactVersions: false,
      });
      const key = createKeypair();

      try {
        store.getPolicyStore().registerPolicy(basePolicy);
        store.getKeyStore().registerKey({
          keyId: "key-legacy-fail-test",
          publicKey: key.publicKey,
          status: "active",
        });

        const envRes = createTransactionEnvelope(validRequest);
        if (!envRes.ok) throw new Error("Envelope creation failed");

        const bindingDigest = createAuthorizationBindingDigest(
          basePolicy,
          envRes.envelope.request,
        );

        // 1. consumeTransactionAuthorizationWithStore (V1 reserve-based memory consumption)
        expect(() => {
          consumeTransactionAuthorizationWithStore(
            store,
            "auth-v1-reserve-consume",
            basePolicy,
            envRes.envelope,
            validRequest,
            { nowSeconds: 1000 },
          );
        }).toThrow("Legacy authorization artifact versions are disabled by configuration.");

        // 2. consumeBoundTransactionAuthorizationWithStore (V1 bound consumption)
        const v1Artifact = {
          version: 1,
          authorizationId: "auth-v1-bound-artifact",
          bindingDigest,
        };
        expect(() => {
          consumeBoundTransactionAuthorizationWithStore(
            store,
            v1Artifact,
            basePolicy,
            envRes.envelope,
            validRequest,
            { nowSeconds: 1000 },
          );
        }).toThrow("Legacy authorization artifact versions are disabled by configuration.");

        // 3. consumeSignedTransactionAuthorizationWithStore (V2 signed consumption)
        const v2Payload = canonicalSignedPayload(
          2,
          "auth-v2-signed-artifact",
          "key-legacy-fail-test",
          bindingDigest,
        );
        const v2Sig = signAuthorizationPayload(key.privateKey, v2Payload);
        const v2Artifact = {
          version: 2,
          authorizationId: "auth-v2-signed-artifact",
          keyId: "key-legacy-fail-test",
          bindingDigest,
          signature: v2Sig,
        };
        expect(() => {
          consumeSignedTransactionAuthorizationWithStore(
            store,
            store.getKeyStore(),
            v2Artifact,
            basePolicy,
            envRes.envelope,
            validRequest,
            { nowSeconds: 1000 },
          );
        }).toThrow("Legacy authorization artifact versions are disabled by configuration.");

        // 4. Direct store methods fail closed for legacy versions 1 and 2
        expect(() => store.reserve("legacy-id")).toThrow(
          "Legacy authorization artifact versions are disabled by configuration.",
        );
        expect(() => store.issueBound("legacy-id", "sha256:dummy", 1)).toThrow(
          "Legacy authorization artifact versions are disabled by configuration.",
        );
        expect(() => store.issueBound("legacy-id", "sha256:dummy", 2)).toThrow(
          "Legacy authorization artifact versions are disabled by configuration.",
        );
        expect(() => store.consumeBound("legacy-id", "sha256:dummy", 1)).toThrow(
          "Legacy authorization artifact versions are disabled by configuration.",
        );
        expect(() => store.consumeBound("legacy-id", "sha256:dummy", 2)).toThrow(
          "Legacy authorization artifact versions are disabled by configuration.",
        );

        // 5. Pre-existing database with V1 and V2 records in storage cannot be consumed
        const rawDb = new DatabaseSync(dbFile);
        try {
          rawDb.exec(`
            INSERT INTO consumed_authorization_ids (authorization_id, binding_digest, state, artifact_version)
            VALUES ('existing-v1-issued', 'sha256:v1digest', 'issued', 1);
            INSERT INTO consumed_authorization_ids (authorization_id, binding_digest, state, artifact_version, key_id)
            VALUES ('existing-v2-issued', 'sha256:v2digest', 'issued', 2, 'key-legacy-fail-test');
          `);
        } finally {
          rawDb.close();
        }

        expect(() => {
          store.consumeBound("existing-v1-issued", "sha256:v1digest", 1);
        }).toThrow("Legacy authorization artifact versions are disabled by configuration.");

        expect(() => {
          store.consumeBound("existing-v2-issued", "sha256:v2digest", 2, "key-legacy-fail-test");
        }).toThrow("Legacy authorization artifact versions are disabled by configuration.");

        // Both existing records remain in 'issued' state
        expect(store.getAuthorizationRecord("existing-v1-issued")?.state).toBe("issued");
        expect(store.getAuthorizationRecord("existing-v2-issued")?.state).toBe("issued");

        // 6. Valid V3 issuance and consumption continue to succeed without interference!
        const v3Issue = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-legacy-fail-test", privateKey: key.privateKey },
          "auth-v3-functional",
          "policy-boundary",
          validRequest,
        );
        expect(v3Issue.decision).toBe("ALLOW");
        if (v3Issue.decision !== "ALLOW") return;

        const v3Consume = consumeSignedTransactionAuthorizationV3(
          store,
          v3Issue.artifact,
          v3Issue.envelope,
          validRequest,
        );
        expect(v3Consume.decision).toBe("ALLOW");

        const v3Record = store.getAuthorizationRecord("auth-v3-functional");
        expect(v3Record?.state).toBe("consumed");
        expect(v3Record?.artifactVersion).toBe(3);
      } finally {
        store.close();
      }
    });
  });

  // =========================================================================
  // 5. Milestone 6.5: Input Length Boundaries (Authorization ID and Calldata)
  // =========================================================================
  describe("5. Milestone 6.5: Input Length Boundaries (Authorization ID and Calldata)", () => {
    it("enforces calldata length boundaries in createTransactionEnvelope", () => {
      // 1. Normal valid request succeeds
      const normalRes = createTransactionEnvelope(validRequest);
      expect(normalRes.ok).toBe(true);

      // 2. Exactly maximum allowed calldata (131074 characters = 0x + 131072 hex chars)
      const maxCalldata = "0x" + "a0".repeat(65536);
      expect(maxCalldata.length).toBe(131074);
      const maxRes = createTransactionEnvelope({
        ...validRequest,
        calldata: maxCalldata,
      });
      expect(maxRes.ok).toBe(true);

      // 3. One byte beyond maximum allowed calldata (131076 characters)
      const oversizedCalldata = maxCalldata + "aa";
      expect(oversizedCalldata.length).toBe(131076);
      const overRes = createTransactionEnvelope({
        ...validRequest,
        calldata: oversizedCalldata,
      });
      expect(overRes.ok).toBe(false);
      if (!overRes.ok) {
        expect(overRes.reason).toBe("Calldata exceeds maximum allowed length of 131074 characters.");
      }

      // 4. Invalid non-hex or non-prefixed calldata
      const nonHexRes = createTransactionEnvelope({
        ...validRequest,
        calldata: "0xZZZZ",
      });
      expect(nonHexRes.ok).toBe(false);
      if (!nonHexRes.ok) {
        expect(nonHexRes.reason).toBe("Calldata must be 0x-prefixed, even-length hexadecimal data.");
      }
    });

    it("enforces authorization ID length boundaries and preserves persistent and clock state", () => {
      const dbFile = databasePath("id-length-boundaries.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLiteAuthorizationStore(dbFile, clock);
      const key = createKeypair();

      try {
        store.getPolicyStore().registerPolicy(basePolicy);
        store.getKeyStore().registerKey({
          keyId: "key-length-boundary",
          publicKey: key.publicKey,
          status: "active",
        });

        const initialHighWater = store.getHighWaterMark();
        expect(initialHighWater).toBe(1000);

        // 1. Boundary: exactly 128 characters succeeds
        const maxValidId = "A".repeat(128);
        const validIssue = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-length-boundary", privateKey: key.privateKey },
          maxValidId,
          "policy-boundary",
          validRequest,
        );
        expect(validIssue.decision).toBe("ALLOW");
        if (validIssue.decision !== "ALLOW") return;

        expect(store.getAuthorizationRecord(maxValidId)).not.toBeNull();
        expect(store.getAuthorizationRecord(maxValidId)?.state).toBe("issued");

        // 2. Boundary: exactly 129 characters fails with explicit length error
        const overLimitId = "A".repeat(129);
        const overLimitIssue = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-length-boundary", privateKey: key.privateKey },
          overLimitId,
          "policy-boundary",
          validRequest,
        );
        expect(overLimitIssue.decision).toBe("DENY");
        if (overLimitIssue.decision === "DENY") {
          expect(overLimitIssue.reasons).toContain("Authorization ID exceeds maximum length of 128 characters.");
        }

        // Verify rejected ID is NOT in storage and clock mark was NOT modified
        expect(store.getAuthorizationRecord(overLimitId)).toBeNull();
        expect(store.getHighWaterMark()).toBe(initialHighWater);

        // 3. Blank or whitespace-only authorization IDs fail with non-empty error
        const blankIssue = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-length-boundary", privateKey: key.privateKey },
          "   ",
          "policy-boundary",
          validRequest,
        );
        expect(blankIssue.decision).toBe("DENY");
        if (blankIssue.decision === "DENY") {
          expect(blankIssue.reasons).toContain("A non-empty authorization ID is required.");
        }

        // 4. Direct store methods reject oversized IDs
        expect(() => store.reserve("B".repeat(129))).toThrow(
          "Authorization ID exceeds maximum length of 128 characters.",
        );
        expect(() => store.issueBound("B".repeat(129), "sha256:dummy", 3)).toThrow(
          "Authorization ID exceeds maximum length of 128 characters.",
        );
        expect(() => store.consumeBound("B".repeat(129), "sha256:dummy", 3)).toThrow(
          "Authorization ID exceeds maximum length of 128 characters.",
        );

        // 5. Cryptographic payload validation rejects oversized IDs
        expect(() => {
          canonicalSignedPayloadV3({
            version: SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3,
            authorizationId: "C".repeat(129),
            keyId: "key-length-boundary",
            issuedAtSeconds: 1000,
            expiresAtSeconds: 2000,
            policyId: "policy-boundary",
            policyRevision: 1,
            bindingDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
          });
        }).toThrow("Invalid parameters for canonicalSignedPayloadV3.");
      } finally {
        store.close();
      }
    });
  });

  // =========================================================================
  // 7. Milestone 6.7: Authorization Cancellation & Process-Local Memory Invariants
  // =========================================================================
  describe("7. Milestone 6.7: Authorization Cancellation & Process-Local Memory Invariants", () => {
    it("strictly cancels an issued authorization, transitions state to 'cancelled', and blocks replay and reissuance", () => {
      const dbFile = databasePath("cancellation-lifecycle.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLiteAuthorizationStore(dbFile, clock);
      const key = createKeypair();

      try {
        store.getPolicyStore().registerPolicy(basePolicy);
        store.getKeyStore().registerKey({
          keyId: "key-cancellation",
          publicKey: key.publicKey,
          status: "active",
        });

        const authId = "auth-cancel-test-001";
        const issued = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-cancellation", privateKey: key.privateKey },
          authId,
          "policy-boundary",
          validRequest,
        );
        expect(issued.decision).toBe("ALLOW");
        if (issued.decision !== "ALLOW") return;

        // Verify record is initially issued
        const initialRecord = store.getAuthorizationRecord(authId);
        expect(initialRecord).not.toBeNull();
        expect(initialRecord?.state).toBe("issued");
        expect(initialRecord?.consumedAt).toBeNull();

        // 1. Cancel authorization via cancelSignedTransactionAuthorizationV3 helper
        const cancelled = cancelSignedTransactionAuthorizationV3(store, authId);
        expect(cancelled).toBe(true);

        // 2. State transition verification in persistent storage
        const cancelledRecord = store.getAuthorizationRecord(authId);
        expect(cancelledRecord).not.toBeNull();
        expect(cancelledRecord?.state).toBe("cancelled");
        expect(cancelledRecord?.consumedAt).not.toBeNull();

        // 3. Repeated cancellation fails closed (idempotent return false)
        expect(cancelSignedTransactionAuthorizationV3(store, authId)).toBe(false);
        expect(store.cancelAuthorization(authId)).toBe(false);

        // 4. Cancelled authorization CANNOT be consumed
        const consumeAttempt = consumeSignedTransactionAuthorizationV3(
          store,
          issued.artifact,
          issued.envelope,
          validRequest,
        );
        expect(consumeAttempt.decision).toBe("DENY");
        if (consumeAttempt.decision === "DENY") {
          expect(consumeAttempt.reasons).toContain(
            "Bound transaction authorization is unknown, consumed, or mismatched.",
          );
        }

        // 5. Cancelled authorization CANNOT be re-issued (PRIMARY KEY conflict fails closed)
        const reissueAttempt = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-cancellation", privateKey: key.privateKey },
          authId,
          "policy-boundary",
          validRequest,
        );
        expect(reissueAttempt.decision).toBe("DENY");
        if (reissueAttempt.decision === "DENY") {
          expect(reissueAttempt.reasons).toContain(
            "Transaction authorization ID has already been issued or consumed.",
          );
        }

        // 6. Direct store methods fail closed on cancelled ID
        expect(store.issueBound(authId, "sha256:any", 3)).toBe(false);
        expect(store.consumeBound(authId, issued.artifact.bindingDigest, 3)).toBe(false);
      } finally {
        store.close();
      }
    });

    it("rejects cancellation of unknown, already-consumed, invalid, or legacy authorization IDs", () => {
      const dbFile = databasePath("cancellation-edge-cases.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLiteAuthorizationStore(dbFile, clock);
      const key = createKeypair();

      try {
        store.getPolicyStore().registerPolicy(basePolicy);
        store.getKeyStore().registerKey({
          keyId: "key-cancel-edges",
          publicKey: key.publicKey,
          status: "active",
        });

        // 1. Unknown authorization ID returns false
        expect(cancelAuthorization(store, "unknown-auth-id-999")).toBe(false);
        expect(store.cancelAuthorization("unknown-auth-id-999")).toBe(false);

        // 2. Already-consumed authorization cannot be cancelled (consumption wins)
        const authId = "auth-consume-first-001";
        const issued = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-cancel-edges", privateKey: key.privateKey },
          authId,
          "policy-boundary",
          validRequest,
        );
        expect(issued.decision).toBe("ALLOW");
        if (issued.decision !== "ALLOW") return;

        const consumed = consumeSignedTransactionAuthorizationV3(
          store,
          issued.artifact,
          issued.envelope,
          validRequest,
        );
        expect(consumed.decision).toBe("ALLOW");

        expect(store.getAuthorizationRecord(authId)?.state).toBe("consumed");
        expect(cancelAuthorization(store, authId)).toBe(false);
        expect(store.cancelAuthorization(authId)).toBe(false);

        // State remains consumed
        expect(store.getAuthorizationRecord(authId)?.state).toBe("consumed");

        // 3. Invalid authorization IDs return false
        expect(cancelAuthorization(store, "")).toBe(false);
        expect(cancelAuthorization(store, "   ")).toBe(false);
        expect(cancelAuthorization(store, null)).toBe(false);
        expect(cancelAuthorization(store, undefined)).toBe(false);
        expect(cancelAuthorization(store, 12345)).toBe(false);

        // 4. Oversized authorization ID (>128 chars) throws explicit length error
        expect(() => store.cancelAuthorization("X".repeat(129))).toThrow(
          "Authorization ID exceeds maximum length of 128 characters.",
        );

        // 5. Non-store object passed to cancelAuthorization returns false
        expect(cancelAuthorization({} as any, "some-id")).toBe(false);
      } finally {
        store.close();
      }
    });

    it("rejects cancellation of legacy artifact versions when legacy is disabled", () => {
      const dbFile = databasePath("cancellation-legacy-disabled.sqlite");
      const clock = new TestClock(1000);

      // Create store with legacy allowed to seed a legacy record
      const seedingStore = new SQLiteAuthorizationStore(dbFile, clock, {
        allowLegacyArtifactVersions: true,
      });
      seedingStore.issueBound("legacy-auth-v1", "sha256:legacy", 1);
      seedingStore.close();

      // Open store with strict legacy disabled (default)
      const strictStore = new SQLiteAuthorizationStore(dbFile, clock, {
        allowLegacyArtifactVersions: false,
      });
      try {
        expect(() => strictStore.cancelAuthorization("legacy-auth-v1")).toThrow(
          "Legacy authorization artifact versions are disabled by configuration.",
        );
      } finally {
        strictStore.close();
      }
    });

    it("enforces process-local authorization memory bounds and preserves replay protection in isolated process", async () => {
      const dbFile = databasePath("store-memory-isolation-subproc.sqlite");
      const code = `
        import {
          consumeTransactionAuthorizationById,
          getConsumedAuthorizationIdsCount,
          MAX_PROCESS_LOCAL_CONSUMED_IDS,
        } from './src/authorization-lifecycle.js';
        import { createTransactionEnvelope } from './src/transaction-envelope.js';
        import { SQLiteAuthorizationStore } from './src/authorization-store.js';
        import { issueSignedTransactionAuthorizationV3, consumeSignedTransactionAuthorizationV3 } from './src/authorization-lifecycle.js';
        import { TestClock } from './src/clock.js';
        import { generateKeyPairSync } from 'node:crypto';

        const basePolicy = ${JSON.stringify(basePolicy)};
        const validRequest = ${JSON.stringify(validRequest)};

        if (getConsumedAuthorizationIdsCount() !== 0) {
          console.error('Initial count not 0:', getConsumedAuthorizationIdsCount());
          process.exit(1);
        }

        // 1. Populate entries up to capacity - 1
        for (let i = 0; i < MAX_PROCESS_LOCAL_CONSUMED_IDS - 1; i++) {
          const env = createTransactionEnvelope(validRequest);
          if (!env.ok) { process.exit(2); }
          consumeTransactionAuthorizationById(
            'auth-isolated-fill-' + i,
            basePolicy,
            env.envelope,
            validRequest,
            { nowSeconds: 1000 },
          );
        }

        if (getConsumedAuthorizationIdsCount() !== MAX_PROCESS_LOCAL_CONSUMED_IDS - 1) {
          console.error('Count mismatch at capacity - 1:', getConsumedAuthorizationIdsCount());
          process.exit(3);
        }

        // 2. Consuming at capacity succeeds exactly once to reach limit
        const limitEnv = createTransactionEnvelope(validRequest);
        if (!limitEnv.ok) { process.exit(4); }
        const limitAllowed = consumeTransactionAuthorizationById(
          'auth-isolated-fill-final',
          basePolicy,
          limitEnv.envelope,
          validRequest,
          { nowSeconds: 1000 },
        );
        if (limitAllowed.decision !== 'ALLOW' || getConsumedAuthorizationIdsCount() !== MAX_PROCESS_LOCAL_CONSUMED_IDS) {
          console.error('Limit item not allowed or count mismatch');
          process.exit(5);
        }

        // 3. New consumption at capacity fails closed without expanding set
        const overEnv = createTransactionEnvelope(validRequest);
        if (!overEnv.ok) { process.exit(6); }
        const overLimit = consumeTransactionAuthorizationById(
          'auth-isolated-fill-overflow',
          basePolicy,
          overEnv.envelope,
          validRequest,
          { nowSeconds: 1000 },
        );
        if (overLimit.decision !== 'DENY' || !overLimit.reasons.some((r) => r.includes('capacity exceeded'))) {
          console.error('Overflow item not denied with capacity error');
          process.exit(7);
        }
        if (getConsumedAuthorizationIdsCount() !== MAX_PROCESS_LOCAL_CONSUMED_IDS) {
          console.error('Count expanded past limit');
          process.exit(8);
        }

        // 4. Replay of ANY previously consumed ID remains strictly denied (no eviction occurred!)
        const replayEnv = createTransactionEnvelope(validRequest);
        if (!replayEnv.ok) { process.exit(9); }
        const replayAttempt = consumeTransactionAuthorizationById(
          'auth-isolated-fill-0',
          basePolicy,
          replayEnv.envelope,
          validRequest,
          { nowSeconds: 1000 },
        );
        if (replayAttempt.decision !== 'DENY' || !replayAttempt.reasons.some((r) => r.includes('already been consumed'))) {
          console.error('Replay item not denied with already consumed error');
          process.exit(10);
        }

        // 5. Persistent store operations do NOT pollute process-local memory count
        const store = new SQLiteAuthorizationStore(${JSON.stringify(dbFile)}, new TestClock(1000));
        const { publicKey, privateKey } = generateKeyPairSync('ed25519');
        try {
          store.getPolicyStore().registerPolicy(basePolicy);
          store.getKeyStore().registerKey({
            keyId: 'key-mem-iso',
            publicKey,
            status: 'active',
          });

          const countBefore = getConsumedAuthorizationIdsCount();
          const issued = issueSignedTransactionAuthorizationV3(
            store,
            { keyId: 'key-mem-iso', privateKey },
            'auth-store-no-mem-leak',
            'policy-boundary',
            validRequest,
          );
          if (issued.decision === 'ALLOW') {
            consumeSignedTransactionAuthorizationV3(
              store,
              issued.artifact,
              issued.envelope,
              validRequest,
            );
          }

          if (getConsumedAuthorizationIdsCount() !== countBefore) {
            console.error('Persistent store call mutated process-local count');
            process.exit(11);
          }
        } finally {
          store.close();
        }

        console.log('CAPACITY_TEST_SUCCESS');
        process.exit(0);
      `;

      const result = await runSubprocess(code);
      if (result.exitCode !== 0) {
        console.error("Subprocess stderr:", result.stderr);
        console.error("Subprocess stdout:", result.stdout);
      }
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("CAPACITY_TEST_SUCCESS");
    }, 30000);

    it("preserves process-local replay denial after invoking all supported public APIs", () => {
      const authId = "auth-public-api-replay-check-001";
      const env1 = createTransactionEnvelope(validRequest);
      if (!env1.ok) throw new Error("Envelope creation failed");

      // 1. Initial consumption succeeds
      const first = consumeTransactionAuthorizationById(
        authId,
        basePolicy,
        env1.envelope,
        validRequest,
        { nowSeconds: 1000 },
      );
      expect(first.decision).toBe("ALLOW");

      // 2. Invoke supported public APIs
      // 2a. Direct in-memory replay attempt
      const env2 = createTransactionEnvelope(validRequest);
      if (!env2.ok) throw new Error("Envelope creation failed");
      const replay1 = consumeTransactionAuthorizationById(
        authId,
        basePolicy,
        env2.envelope,
        validRequest,
        { nowSeconds: 1000 },
      );
      expect(replay1.decision).toBe("DENY");
      if (replay1.decision === "DENY") {
        expect(replay1.reasons).toContain("Transaction authorization ID has already been consumed.");
      }

      // 2b. Envelope consumption API (without ID)
      const env3 = createTransactionEnvelope(validRequest);
      if (!env3.ok) throw new Error("Envelope creation failed");
      const envConsume = consumeTransactionAuthorization(
        basePolicy,
        env3.envelope,
        validRequest,
        { nowSeconds: 1000 },
      );
      expect(envConsume.decision).toBe("ALLOW");

      // 2c. Store cancellation APIs
      const dbFile = databasePath("public-api-check.sqlite");
      const store = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      try {
        expect(cancelAuthorization(store, authId)).toBe(false);
        expect(cancelSignedTransactionAuthorizationV3(store, authId)).toBe(false);
        expect(store.cancelAuthorization(authId)).toBe(false);
        expect(() => store.reserve("auth-unrelated-store-reserve-001")).toThrow(
          "Legacy authorization artifact versions are disabled by configuration.",
        );
      } finally {
        store.close();
      }

      // 2d. ID format validation API
      expect(validateAuthorizationId(authId)).toEqual({ ok: true, id: authId });

      // 3. Re-attempt to consume original authId with a fresh envelope: must STILL be denied!
      const env4 = createTransactionEnvelope(validRequest);
      if (!env4.ok) throw new Error("Envelope creation failed");
      const replayAfterAPIs = consumeTransactionAuthorizationById(
        authId,
        basePolicy,
        env4.envelope,
        validRequest,
        { nowSeconds: 1000 },
      );
      expect(replayAfterAPIs.decision).toBe("DENY");
      if (replayAfterAPIs.decision === "DENY") {
        expect(replayAfterAPIs.reasons).toContain("Transaction authorization ID has already been consumed.");
      }

      // 4. A distinct authorization ID succeeds cleanly
      const env5 = createTransactionEnvelope(validRequest);
      if (!env5.ok) throw new Error("Envelope creation failed");
      const distinct = consumeTransactionAuthorizationById(
        "auth-public-api-distinct-002",
        basePolicy,
        env5.envelope,
        validRequest,
        { nowSeconds: 1000 },
      );
      expect(distinct.decision).toBe("ALLOW");
    });
  });
});
