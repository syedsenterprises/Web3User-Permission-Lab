import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  consumeBoundTransactionAuthorizationWithStore,
  consumeSignedTransactionAuthorizationWithStore,
  issueBoundTransactionAuthorizationWithStore,
  issueSignedTransactionAuthorizationWithStore,
} from "../src/authorization-lifecycle.js";
import { SQLiteAuthorizationStore } from "../src/authorization-store.js";
import {
  SIGNED_AUTHORIZATION_ARTIFACT_VERSION,
  canonicalSignedPayload,
  generateIssuerKeyPair,
  isSignedAuthorizationArtifact,
  parseEd25519PrivateKey,
  parseEd25519PublicKey,
  signAuthorizationPayload,
  verifyAuthorizationPayload,
} from "../src/authorization-crypto.js";
import { InMemoryKeyRegistry, type KeyStatus } from "../src/key-registry.js";
import type { DemoPolicy } from "../src/policy.js";
import type { TransactionRequest } from "../src/transaction-envelope.js";

const target = "0x1111111111111111111111111111111111111111";
const sender = "0x2222222222222222222222222222222222222222";
const recipient = "0x3333333333333333333333333333333333333333";

function transferCalldata(amount: bigint, toAddress = recipient): string {
  return (
    "0xa9059cbb" +
    toAddress.slice(2).padStart(64, "0") +
    amount.toString(16).padStart(64, "0")
  );
}

const request: TransactionRequest = {
  chainId: "1",
  sender,
  target,
  calldata: transferCalldata(5n),
  value: "0",
};

const policy: DemoPolicy = {
  version: 1,
  policyId: "signed-authorization-test",
  allowedTarget: target,
  allowedRecipient: recipient,
  allowedSelector: "0xa9059cbb",
  maxAmount: "10",
  validFrom: 50,
  expiresAt: 200,
  revoked: false,
};

const context = { nowSeconds: 100 };

describe("cryptographic primitives (authorization-crypto)", () => {
  it("encodes signed payload deterministically with length-prefixed fields", () => {
    const payload1 = canonicalSignedPayload(2, "auth-123", "key-1", "sha256:abcd");
    const payload2 = canonicalSignedPayload(2, "auth-123", "key-1", "sha256:abcd");
    expect(payload1).toBe(payload2);
    expect(payload1).toContain("web3user-signed-authorization-v2\n");
    expect(payload1).toContain("artifact.version:1:2\n");
    expect(payload1).toContain("artifact.authorizationId:8:auth-123\n");
    expect(payload1).toContain("key.keyId:5:key-1\n");
    expect(payload1).toContain("artifact.bindingDigest:11:sha256:abcd\n");
  });

  it("signs and verifies an Ed25519 payload successfully", () => {
    const keyPair = generateIssuerKeyPair();
    const payload = canonicalSignedPayload(2, "auth-1", "key-1", "sha256:aaaa");
    const signature = signAuthorizationPayload(keyPair.privateKey, payload);

    expect(typeof signature).toBe("string");
    expect(signature.length).toBe(128); // 64 bytes = 128 hex chars

    const valid = verifyAuthorizationPayload(keyPair.publicKey, payload, signature);
    expect(valid).toBe(true);
  });

  it("verifies signatures with PEM string key representation", () => {
    const keyPair = generateIssuerKeyPair();
    const payload = canonicalSignedPayload(2, "auth-1", "key-1", "sha256:aaaa");
    const signature = signAuthorizationPayload(keyPair.privateKeyPem, payload);

    const valid = verifyAuthorizationPayload(keyPair.publicKeyPem, payload, signature);
    expect(valid).toBe(true);
  });

  it("fails verification if the public key does not match", () => {
    const keyPair1 = generateIssuerKeyPair();
    const keyPair2 = generateIssuerKeyPair();
    const payload = canonicalSignedPayload(2, "auth-1", "key-1", "sha256:aaaa");
    const signature = signAuthorizationPayload(keyPair1.privateKey, payload);

    const valid = verifyAuthorizationPayload(keyPair2.publicKey, payload, signature);
    expect(valid).toBe(false);
  });

  it("fails verification if the payload is modified", () => {
    const keyPair = generateIssuerKeyPair();
    const payload = canonicalSignedPayload(2, "auth-1", "key-1", "sha256:aaaa");
    const signature = signAuthorizationPayload(keyPair.privateKey, payload);

    const tamperedPayload = canonicalSignedPayload(2, "auth-1", "key-1", "sha256:bbbb");
    const valid = verifyAuthorizationPayload(keyPair.publicKey, tamperedPayload, signature);
    expect(valid).toBe(false);
  });

  it("fails verification if the signature is tampered or malformed", () => {
    const keyPair = generateIssuerKeyPair();
    const payload = canonicalSignedPayload(2, "auth-1", "key-1", "sha256:aaaa");
    const signature = signAuthorizationPayload(keyPair.privateKey, payload);

    // Tamper one byte
    const tamperedSig = (signature[0] === "a" ? "b" : "a") + signature.slice(1);
    expect(verifyAuthorizationPayload(keyPair.publicKey, payload, tamperedSig)).toBe(false);

    // Short signature
    expect(verifyAuthorizationPayload(keyPair.publicKey, payload, "abcd")).toBe(false);

    // Non-hex characters
    const nonHexSig = "z".repeat(128);
    expect(verifyAuthorizationPayload(keyPair.publicKey, payload, nonHexSig)).toBe(false);
  });

  it("rejects non-Ed25519 keys", () => {
    const rsaKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
    expect(parseEd25519PublicKey(rsaKeys.publicKey)).toBeNull();
    expect(parseEd25519PrivateKey(rsaKeys.privateKey)).toBeNull();

    expect(() => signAuthorizationPayload(rsaKeys.privateKey, "payload")).toThrow(
      "Invalid Ed25519 private key."
    );
    expect(verifyAuthorizationPayload(rsaKeys.publicKey, "payload", "a".repeat(128))).toBe(
      false
    );
  });

  it("strictly validates SignedAuthorizationArtifact format", () => {
    const keyPair = generateIssuerKeyPair();
    const sig = signAuthorizationPayload(keyPair.privateKey, "test");

    const validArtifact = {
      version: SIGNED_AUTHORIZATION_ARTIFACT_VERSION,
      authorizationId: "auth-001",
      keyId: "issuer-key-1",
      bindingDigest: "sha256:" + "0".repeat(64),
      signature: sig,
    };
    expect(isSignedAuthorizationArtifact(validArtifact)).toBe(true);

    // Version must be 2
    expect(isSignedAuthorizationArtifact({ ...validArtifact, version: 1 })).toBe(false);
    expect(isSignedAuthorizationArtifact({ ...validArtifact, version: 3 })).toBe(false);

    // authorizationId checks
    expect(isSignedAuthorizationArtifact({ ...validArtifact, authorizationId: "" })).toBe(false);
    expect(isSignedAuthorizationArtifact({ ...validArtifact, authorizationId: " auth-1" })).toBe(false);
    expect(isSignedAuthorizationArtifact({ ...validArtifact, authorizationId: 123 })).toBe(false);

    // keyId checks
    expect(isSignedAuthorizationArtifact({ ...validArtifact, keyId: "" })).toBe(false);
    expect(isSignedAuthorizationArtifact({ ...validArtifact, keyId: "key-1 " })).toBe(false);

    // bindingDigest checks
    expect(isSignedAuthorizationArtifact({ ...validArtifact, bindingDigest: "invalid" })).toBe(false);
    expect(isSignedAuthorizationArtifact({ ...validArtifact, bindingDigest: "sha256:1234" })).toBe(false);

    // signature checks
    expect(isSignedAuthorizationArtifact({ ...validArtifact, signature: "short" })).toBe(false);
    expect(isSignedAuthorizationArtifact({ ...validArtifact, signature: "g".repeat(128) })).toBe(false);
  });
});

describe("key registry (InMemoryKeyRegistry)", () => {
  it("registers and retrieves active keys", () => {
    const registry = new InMemoryKeyRegistry();
    const keyPair = generateIssuerKeyPair();

    registry.registerKey({
      keyId: "key-1",
      publicKey: keyPair.publicKey,
      status: "active",
    });

    const retrieved = registry.getKey("key-1");
    expect(retrieved).not.toBeNull();
    expect(retrieved?.keyId).toBe("key-1");
    expect(retrieved?.status).toBe("active");
  });

  it("rejects duplicate keyId registration", () => {
    const registry = new InMemoryKeyRegistry();
    const keyPair = generateIssuerKeyPair();

    registry.registerKey({
      keyId: "key-1",
      publicKey: keyPair.publicKey,
      status: "active",
    });

    expect(() =>
      registry.registerKey({
        keyId: "key-1",
        publicKey: keyPair.publicKey,
        status: "active",
      })
    ).toThrow("Key ID already registered");
  });

  it("rejects invalid keyId formats and whitespace", () => {
    const registry = new InMemoryKeyRegistry();
    const keyPair = generateIssuerKeyPair();

    expect(() =>
      registry.registerKey({
        keyId: "",
        publicKey: keyPair.publicKey,
        status: "active",
      })
    ).toThrow("Key ID must be a non-empty string");

    expect(() =>
      registry.registerKey({
        keyId: " key-1",
        publicKey: keyPair.publicKey,
        status: "active",
      })
    ).toThrow("Key ID must not contain leading or trailing whitespace");
  });

  it("rejects invalid or non-Ed25519 public keys", () => {
    const registry = new InMemoryKeyRegistry();
    expect(() =>
      registry.registerKey({
        keyId: "key-1",
        publicKey: "not a key",
        status: "active",
      })
    ).toThrow("Public key must be a valid Ed25519 public key");
  });

  it("updates key status via setKeyStatus", () => {
    const registry = new InMemoryKeyRegistry();
    const keyPair = generateIssuerKeyPair();

    registry.registerKey({
      keyId: "key-1",
      publicKey: keyPair.publicKey,
      status: "active",
    });

    expect(registry.setKeyStatus("key-1", "retired")).toBe(true);
    expect(registry.getKey("key-1")?.status).toBe("retired");

    expect(registry.setKeyStatus("key-1", "revoked")).toBe(true);
    expect(registry.getKey("key-1")?.status).toBe("revoked");

    expect(registry.setKeyStatus("unknown-key", "active")).toBe(false);
  });

  it("returns null for unknown keys", () => {
    const registry = new InMemoryKeyRegistry();
    expect(registry.getKey("non-existent")).toBeNull();
  });

  // M-03: Immutability tests
  it("prevents external mutation of registered key metadata and getKey return values (M-03)", () => {
    const registry = new InMemoryKeyRegistry();
    const keyPair = generateIssuerKeyPair();

    const rawMeta = {
      keyId: "immutable-test-key",
      publicKey: keyPair.publicKey,
      status: "active" as KeyStatus,
      validFromSeconds: 100,
      expiresAtSeconds: 200,
    };

    registry.registerKey(rawMeta);

    // Attempt to mutate caller-owned registration object
    rawMeta.status = "revoked";
    rawMeta.validFromSeconds = 999;

    // Registry internal state remains unchanged
    const stored = registry.getKey("immutable-test-key");
    expect(stored?.status).toBe("active");
    expect(stored?.validFromSeconds).toBe(100);

    // Attempt to mutate retrieved object
    expect(Object.isFrozen(stored)).toBe(true);
    expect(() => {
      // @ts-expect-error mutating frozen object
      stored.status = "revoked";
    }).toThrow();

    // Updating status creates a new independent frozen record
    expect(registry.setKeyStatus("immutable-test-key", "retired")).toBe(true);
    const updated = registry.getKey("immutable-test-key");
    expect(updated?.status).toBe("retired");
    expect(stored?.status).toBe("active"); // previous reference not mutated
  });
});

describe("signed authorization lifecycle", () => {
  let directory: string | undefined;
  const stores = new Set<SQLiteAuthorizationStore>();
  let keyPair: ReturnType<typeof generateIssuerKeyPair>;
  let registry: InMemoryKeyRegistry;

  function databasePath(): string {
    directory ??= mkdtempSync(join(tmpdir(), "web3user-signed-"));
    return join(directory, "signed-auth.sqlite");
  }

  function createStore(): SQLiteAuthorizationStore {
    const store = new SQLiteAuthorizationStore(databasePath());
    stores.add(store);
    return store;
  }

  function closeStore(store: SQLiteAuthorizationStore): void {
    if (stores.delete(store)) store.close();
  }

  function getRow(id: string): {
    authorization_id: string;
    binding_digest: string | null;
    state: string;
    consumed_at: string | null;
    artifact_version: number;
  } | undefined {
    const db = new DatabaseSync(databasePath());
    try {
      return db.prepare(
        "SELECT authorization_id, binding_digest, state, consumed_at, artifact_version FROM consumed_authorization_ids WHERE authorization_id = ?"
      ).get(id) as {
        authorization_id: string;
        binding_digest: string | null;
        state: string;
        consumed_at: string | null;
        artifact_version: number;
      } | undefined;
    } finally {
      db.close();
    }
  }

  beforeEach(() => {
    keyPair = generateIssuerKeyPair();
    registry = new InMemoryKeyRegistry();
    registry.registerKey({
      keyId: "test-issuer-key-1",
      publicKey: keyPair.publicKey,
      status: "active",
    });
  });

  afterEach(() => {
    for (const store of stores) closeStore(store);
    if (directory) {
      rmSync(directory, { recursive: true, force: true });
      directory = undefined;
    }
  });

  it("issues a valid signed authorization artifact and consumes it atomically", () => {
    const store = createStore();
    const id = "signed-auth-001";

    const issued = issueSignedTransactionAuthorizationWithStore(
      store,
      registry,
      { keyId: "test-issuer-key-1", privateKey: keyPair.privateKey },
      id,
      policy,
      request,
      context,
    );

    expect(issued.decision).toBe("ALLOW");
    if (issued.decision !== "ALLOW") return;

    expect(issued.artifact.version).toBe(2);
    expect(issued.artifact.authorizationId).toBe(id);
    expect(issued.artifact.keyId).toBe("test-issuer-key-1");
    expect(issued.artifact.bindingDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(issued.artifact.signature).toMatch(/^[a-f0-9]{128}$/);

    // Verify row state immediately after issuance: state = 'issued', consumed_at IS NULL, artifact_version = 2
    const rowAfterIssue = getRow(id);
    expect(rowAfterIssue).toBeDefined();
    expect(rowAfterIssue?.state).toBe("issued");
    expect(rowAfterIssue?.consumed_at).toBeNull();
    expect(rowAfterIssue?.artifact_version).toBe(2);
    expect(rowAfterIssue?.binding_digest).toBe(issued.artifact.bindingDigest);

    // Consume the artifact
    const consumed = consumeSignedTransactionAuthorizationWithStore(
      store,
      registry,
      issued.artifact,
      policy,
      issued.envelope,
      request,
      context,
    );

    expect(consumed.decision).toBe("ALLOW");

    // Verify row state after consumption: state = 'consumed', consumed_at IS NOT NULL, artifact_version = 2
    const rowAfterConsume = getRow(id);
    expect(rowAfterConsume?.state).toBe("consumed");
    expect(rowAfterConsume?.consumed_at).not.toBeNull();
    expect(rowAfterConsume?.artifact_version).toBe(2);
  });

  it("denies replay of an already-consumed signed authorization", () => {
    const store = createStore();
    const id = "signed-replay-001";

    const issued = issueSignedTransactionAuthorizationWithStore(
      store,
      registry,
      { keyId: "test-issuer-key-1", privateKey: keyPair.privateKey },
      id,
      policy,
      request,
      context,
    );
    expect(issued.decision).toBe("ALLOW");
    if (issued.decision !== "ALLOW") return;

    // First consumption succeeds
    const first = consumeSignedTransactionAuthorizationWithStore(
      store,
      registry,
      issued.artifact,
      policy,
      issued.envelope,
      request,
      context,
    );
    expect(first.decision).toBe("ALLOW");

    // Second consumption (replay) fails
    const replay = consumeSignedTransactionAuthorizationWithStore(
      store,
      registry,
      issued.artifact,
      policy,
      issued.envelope,
      request,
      context,
    );
    expect(replay.decision).toBe("DENY");
    expect(replay.reasons).toContain(
      "Bound transaction authorization is unknown, consumed, or mismatched."
    );
  });

  it("denies replay after closing and reopening the database", () => {
    const store1 = createStore();
    const id = "signed-durable-001";

    const issued = issueSignedTransactionAuthorizationWithStore(
      store1,
      registry,
      { keyId: "test-issuer-key-1", privateKey: keyPair.privateKey },
      id,
      policy,
      request,
      context,
    );
    expect(issued.decision).toBe("ALLOW");
    if (issued.decision !== "ALLOW") return;

    const first = consumeSignedTransactionAuthorizationWithStore(
      store1,
      registry,
      issued.artifact,
      policy,
      issued.envelope,
      request,
      context,
    );
    expect(first.decision).toBe("ALLOW");
    closeStore(store1);

    // Reopen store from disk
    const store2 = createStore();
    const replay = consumeSignedTransactionAuthorizationWithStore(
      store2,
      registry,
      issued.artifact,
      policy,
      issued.envelope,
      request,
      context,
    );
    expect(replay.decision).toBe("DENY");
    expect(replay.reasons).toContain(
      "Bound transaction authorization is unknown, consumed, or mismatched."
    );
  });

  it("CRITICAL INVARIANT: tampered signature fails verification before storage and leaves row in issued state", () => {
    const store = createStore();
    const id = "tampered-sig-001";

    const issued = issueSignedTransactionAuthorizationWithStore(
      store,
      registry,
      { keyId: "test-issuer-key-1", privateKey: keyPair.privateKey },
      id,
      policy,
      request,
      context,
    );
    expect(issued.decision).toBe("ALLOW");
    if (issued.decision !== "ALLOW") return;

    // Tamper the signature
    const corruptChar = issued.artifact.signature[0] === "a" ? "b" : "a";
    const corruptSignature = corruptChar + issued.artifact.signature.slice(1);
    const tamperedArtifact = {
      ...issued.artifact,
      signature: corruptSignature,
    };

    const consumed = consumeSignedTransactionAuthorizationWithStore(
      store,
      registry,
      tamperedArtifact,
      policy,
      issued.envelope,
      request,
      context,
    );

    expect(consumed.decision).toBe("DENY");
    expect(consumed.reasons).toContain("Invalid authorization artifact signature.");

    // Verify row was NOT consumed and remains in 'issued' state with consumed_at = NULL
    const row = getRow(id);
    expect(row?.state).toBe("issued");
    expect(row?.consumed_at).toBeNull();
  });

  it("CRITICAL INVARIANT: unknown key fails before storage and leaves row in issued state", () => {
    const store = createStore();
    const id = "unknown-key-001";

    const issued = issueSignedTransactionAuthorizationWithStore(
      store,
      registry,
      { keyId: "test-issuer-key-1", privateKey: keyPair.privateKey },
      id,
      policy,
      request,
      context,
    );
    expect(issued.decision).toBe("ALLOW");
    if (issued.decision !== "ALLOW") return;

    const unknownKeyArtifact = {
      ...issued.artifact,
      keyId: "unknown-issuer-key",
    };

    const consumed = consumeSignedTransactionAuthorizationWithStore(
      store,
      registry,
      unknownKeyArtifact,
      policy,
      issued.envelope,
      request,
      context,
    );

    expect(consumed.decision).toBe("DENY");
    expect(consumed.reasons).toContain("Issuer key is unknown.");

    const row = getRow(id);
    expect(row?.state).toBe("issued");
    expect(row?.consumed_at).toBeNull();
  });

  it("CRITICAL INVARIANT: revoked key fails before storage and leaves row in issued state", () => {
    const store = createStore();
    const id = "revoked-key-001";

    const issued = issueSignedTransactionAuthorizationWithStore(
      store,
      registry,
      { keyId: "test-issuer-key-1", privateKey: keyPair.privateKey },
      id,
      policy,
      request,
      context,
    );
    expect(issued.decision).toBe("ALLOW");
    if (issued.decision !== "ALLOW") return;

    // Revoke the issuer key
    registry.setKeyStatus("test-issuer-key-1", "revoked");

    const consumed = consumeSignedTransactionAuthorizationWithStore(
      store,
      registry,
      issued.artifact,
      policy,
      issued.envelope,
      request,
      context,
    );

    expect(consumed.decision).toBe("DENY");
    expect(consumed.reasons).toContain("Issuer key has been revoked.");

    // SQLite store was not touched
    const row = getRow(id);
    expect(row?.state).toBe("issued");
    expect(row?.consumed_at).toBeNull();
  });

  it("denies issuance when the issuer key is retired, but allows consumption of prior issued artifacts", () => {
    const store = createStore();
    const id = "retired-key-001";

    // Issue artifact while key is active
    const issued = issueSignedTransactionAuthorizationWithStore(
      store,
      registry,
      { keyId: "test-issuer-key-1", privateKey: keyPair.privateKey },
      id,
      policy,
      request,
      context,
    );
    expect(issued.decision).toBe("ALLOW");
    if (issued.decision !== "ALLOW") return;

    // Retire the key
    registry.setKeyStatus("test-issuer-key-1", "retired");

    // New issuance under retired key is DENIED
    const newIssue = issueSignedTransactionAuthorizationWithStore(
      store,
      registry,
      { keyId: "test-issuer-key-1", privateKey: keyPair.privateKey },
      "new-auth-under-retired",
      policy,
      request,
      context,
    );
    expect(newIssue.decision).toBe("DENY");
    expect(newIssue.reasons).toContain(
      "Issuer key is retired and cannot issue new authorizations."
    );

    // Prior issued artifact verification under retired key is ALLOWED
    const consumed = consumeSignedTransactionAuthorizationWithStore(
      store,
      registry,
      issued.artifact,
      policy,
      issued.envelope,
      request,
      context,
    );
    expect(consumed.decision).toBe("ALLOW");

    const row = getRow(id);
    expect(row?.state).toBe("consumed");
    expect(row?.consumed_at).not.toBeNull();
  });

  // M-01: Signer keypair correspondence
  it("fails closed when signer private key does not correspond to registered public key (M-01)", () => {
    const store = createStore();
    const id = "mismatched-keypair-001";

    // Key B is a completely separate valid Ed25519 keypair
    const keyPairB = generateIssuerKeyPair();

    // Attempt to issue with registered keyId "test-issuer-key-1", but signed with keyPairB's private key
    const issued = issueSignedTransactionAuthorizationWithStore(
      store,
      registry,
      { keyId: "test-issuer-key-1", privateKey: keyPairB.privateKey },
      id,
      policy,
      request,
      context,
    );

    expect(issued.decision).toBe("DENY");
    expect(issued.reasons).toContain(
      "Signer private key does not match the registered public key."
    );

    // Row was never created in SQLite
    expect(getRow(id)).toBeUndefined();

    // Authorization ID remains completely available and can be issued with the correct key
    const retry = issueSignedTransactionAuthorizationWithStore(
      store,
      registry,
      { keyId: "test-issuer-key-1", privateKey: keyPair.privateKey },
      id,
      policy,
      request,
      context,
    );
    expect(retry.decision).toBe("ALLOW");
    expect(getRow(id)?.state).toBe("issued");
  });

  // M-02: Key expiration boundary semantics
  it("enforces exact key-expiration boundary semantics across issuance and consumption (M-02)", () => {
    const registryWithTime = new InMemoryKeyRegistry();
    const timeKeyPair = generateIssuerKeyPair();
    registryWithTime.registerKey({
      keyId: "boundary-key",
      publicKey: timeKeyPair.publicKey,
      status: "active",
      validFromSeconds: 100,
      expiresAtSeconds: 200,
    });

    const store = createStore();

    // --- ISSUANCE BOUNDARIES ---
    // 1 second before validFrom: DENY
    const beforeValid = issueSignedTransactionAuthorizationWithStore(
      store,
      registryWithTime,
      { keyId: "boundary-key", privateKey: timeKeyPair.privateKey },
      "issue-before-valid",
      policy,
      request,
      { nowSeconds: 99 },
    );
    expect(beforeValid.decision).toBe("DENY");
    expect(beforeValid.reasons).toContain("Issuer key is not yet valid.");

    // Exactly at validFrom (100): ALLOW
    const atValid = issueSignedTransactionAuthorizationWithStore(
      store,
      registryWithTime,
      { keyId: "boundary-key", privateKey: timeKeyPair.privateKey },
      "issue-at-valid",
      policy,
      request,
      { nowSeconds: 100 },
    );
    expect(atValid.decision).toBe("ALLOW");

    // 1 second before expiresAt (199): ALLOW
    const beforeExpiry = issueSignedTransactionAuthorizationWithStore(
      store,
      registryWithTime,
      { keyId: "boundary-key", privateKey: timeKeyPair.privateKey },
      "issue-before-expiry",
      policy,
      request,
      { nowSeconds: 199 },
    );
    expect(beforeExpiry.decision).toBe("ALLOW");

    // Exactly at expiresAt (200): DENY
    const atExpiry = issueSignedTransactionAuthorizationWithStore(
      store,
      registryWithTime,
      { keyId: "boundary-key", privateKey: timeKeyPair.privateKey },
      "issue-at-expiry",
      policy,
      request,
      { nowSeconds: 200 },
    );
    expect(atExpiry.decision).toBe("DENY");
    expect(atExpiry.reasons).toContain("Issuer key has expired.");
    expect(getRow("issue-at-expiry")).toBeUndefined();

    // 1 second after expiresAt (201): DENY
    const afterExpiry = issueSignedTransactionAuthorizationWithStore(
      store,
      registryWithTime,
      { keyId: "boundary-key", privateKey: timeKeyPair.privateKey },
      "issue-after-expiry",
      policy,
      request,
      { nowSeconds: 201 },
    );
    expect(afterExpiry.decision).toBe("DENY");
    expect(afterExpiry.reasons).toContain("Issuer key has expired.");
    expect(getRow("issue-after-expiry")).toBeUndefined();

    // --- CONSUMPTION BOUNDARIES ---
    // Issue artifacts at nowSeconds = 150
    const issued1 = issueSignedTransactionAuthorizationWithStore(
      store,
      registryWithTime,
      { keyId: "boundary-key", privateKey: timeKeyPair.privateKey },
      "consume-before-expiry",
      policy,
      request,
      { nowSeconds: 150 },
    );
    expect(issued1.decision).toBe("ALLOW");
    if (issued1.decision !== "ALLOW") return;

    // Consume 1 second before expiry (199): ALLOW
    const consumedBefore = consumeSignedTransactionAuthorizationWithStore(
      store,
      registryWithTime,
      issued1.artifact,
      policy,
      issued1.envelope,
      request,
      { nowSeconds: 199 },
    );
    expect(consumedBefore.decision).toBe("ALLOW");

    // Issue another artifact
    const issued2 = issueSignedTransactionAuthorizationWithStore(
      store,
      registryWithTime,
      { keyId: "boundary-key", privateKey: timeKeyPair.privateKey },
      "consume-at-expiry",
      policy,
      request,
      { nowSeconds: 150 },
    );
    expect(issued2.decision).toBe("ALLOW");
    if (issued2.decision !== "ALLOW") return;

    // Consume exactly at expiry (200): DENY (exclusive boundary)
    const consumedAt = consumeSignedTransactionAuthorizationWithStore(
      store,
      registryWithTime,
      issued2.artifact,
      policy,
      issued2.envelope,
      request,
      { nowSeconds: 200 },
    );
    expect(consumedAt.decision).toBe("DENY");
    expect(consumedAt.reasons).toContain("Issuer key has expired.");
    // Row remains 'issued'
    expect(getRow("consume-at-expiry")?.state).toBe("issued");

    // Consume 1 second after expiry (201): DENY
    const consumedAfter = consumeSignedTransactionAuthorizationWithStore(
      store,
      registryWithTime,
      issued2.artifact,
      policy,
      issued2.envelope,
      request,
      { nowSeconds: 201 },
    );
    expect(consumedAfter.decision).toBe("DENY");
    expect(consumedAfter.reasons).toContain("Issuer key has expired.");
    expect(getRow("consume-at-expiry")?.state).toBe("issued");
  });

  // H-01: Cross-version authorization isolation regression tests
  it("strictly denies a v1 consumer from consuming a v2-issued signed row (H-01)", () => {
    const store = createStore();
    const id = "cross-version-v2-row";

    // Issue signed v2 authorization
    const issuedV2 = issueSignedTransactionAuthorizationWithStore(
      store,
      registry,
      { keyId: "test-issuer-key-1", privateKey: keyPair.privateKey },
      id,
      policy,
      request,
      context,
    );
    expect(issuedV2.decision).toBe("ALLOW");
    if (issuedV2.decision !== "ALLOW") return;

    const rowAfterIssue = getRow(id);
    expect(rowAfterIssue?.artifact_version).toBe(2);
    expect(rowAfterIssue?.state).toBe("issued");

    // Adversary crafts a v1 artifact with the same authorizationId and bindingDigest
    const forgedV1Artifact = {
      version: 1 as const,
      authorizationId: id,
      bindingDigest: issuedV2.artifact.bindingDigest,
    };

    // Adversary attempts to consume the v2 row via v1 consumer API
    const v1Attempt = consumeBoundTransactionAuthorizationWithStore(
      store,
      forgedV1Artifact,
      policy,
      issuedV2.envelope,
      request,
      context,
    );

    // Must be DENIED because the storage row requires artifact_version = 1
    expect(v1Attempt.decision).toBe("DENY");
    expect(v1Attempt.reasons).toContain(
      "Bound transaction authorization is unknown, consumed, or mismatched."
    );

    // The SQLite row MUST remain in 'issued' state with consumed_at = NULL and artifact_version = 2
    const rowAfterAttack = getRow(id);
    expect(rowAfterAttack?.state).toBe("issued");
    expect(rowAfterAttack?.consumed_at).toBeNull();
    expect(rowAfterAttack?.artifact_version).toBe(2);

    // Legitimate v2 signed consumer can still consume it
    const v2Consumption = consumeSignedTransactionAuthorizationWithStore(
      store,
      registry,
      issuedV2.artifact,
      policy,
      issuedV2.envelope,
      request,
      context,
    );
    expect(v2Consumption.decision).toBe("ALLOW");

    const rowAfterSuccess = getRow(id);
    expect(rowAfterSuccess?.state).toBe("consumed");
    expect(rowAfterSuccess?.consumed_at).not.toBeNull();
    expect(rowAfterSuccess?.artifact_version).toBe(2);
  });

  it("strictly denies a v2 consumer from consuming a v1-issued bound row (H-01)", () => {
    const store = createStore();
    const id = "cross-version-v1-row";

    // Issue v1 authorization
    const issuedV1 = issueBoundTransactionAuthorizationWithStore(
      store,
      id,
      policy,
      request,
      context,
    );
    expect(issuedV1.decision).toBe("ALLOW");
    if (issuedV1.decision !== "ALLOW") return;

    const rowAfterIssue = getRow(id);
    expect(rowAfterIssue?.artifact_version).toBe(1);
    expect(rowAfterIssue?.state).toBe("issued");

    // Construct a signed v2 payload and signature for the same ID and digest
    const payload = canonicalSignedPayload(
      2,
      id,
      "test-issuer-key-1",
      issuedV1.artifact.bindingDigest,
    );
    const signature = signAuthorizationPayload(keyPair.privateKey, payload);

    const forgedV2Artifact = {
      version: 2 as const,
      authorizationId: id,
      keyId: "test-issuer-key-1",
      bindingDigest: issuedV1.artifact.bindingDigest,
      signature,
    };

    // Attempt to consume v1 row via signed v2 consumer API
    const v2Attempt = consumeSignedTransactionAuthorizationWithStore(
      store,
      registry,
      forgedV2Artifact,
      policy,
      issuedV1.envelope,
      request,
      context,
    );

    // Must be DENIED because SQLite update enforces artifact_version = 2
    expect(v2Attempt.decision).toBe("DENY");
    expect(v2Attempt.reasons).toContain(
      "Bound transaction authorization is unknown, consumed, or mismatched."
    );

    // SQLite row remains intact with artifact_version = 1
    const rowAfterAttack = getRow(id);
    expect(rowAfterAttack?.state).toBe("issued");
    expect(rowAfterAttack?.consumed_at).toBeNull();
    expect(rowAfterAttack?.artifact_version).toBe(1);

    // Legitimate v1 consumer succeeds
    const v1Consumption = consumeBoundTransactionAuthorizationWithStore(
      store,
      issuedV1.artifact,
      policy,
      issuedV1.envelope,
      request,
      context,
    );
    expect(v1Consumption.decision).toBe("ALLOW");

    const rowAfterSuccess = getRow(id);
    expect(rowAfterSuccess?.state).toBe("consumed");
    expect(rowAfterSuccess?.artifact_version).toBe(1);
  });

  it("atomically enforces version discrimination under concurrent v1 and v2 attempts against a v2 row (H-01)", () => {
    const store1 = createStore();
    const store2 = createStore();
    const id = "concurrent-version-row-001";

    const issuedV2 = issueSignedTransactionAuthorizationWithStore(
      store1,
      registry,
      { keyId: "test-issuer-key-1", privateKey: keyPair.privateKey },
      id,
      policy,
      request,
      context,
    );
    expect(issuedV2.decision).toBe("ALLOW");
    if (issuedV2.decision !== "ALLOW") return;

    const forgedV1Artifact = {
      version: 1 as const,
      authorizationId: id,
      bindingDigest: issuedV2.artifact.bindingDigest,
    };

    // Competing consumption: Store 1 tries invalid v1; Store 2 tries valid v2
    const v1Result = consumeBoundTransactionAuthorizationWithStore(
      store1,
      forgedV1Artifact,
      policy,
      issuedV2.envelope,
      request,
      context,
    );

    const v2Result = consumeSignedTransactionAuthorizationWithStore(
      store2,
      registry,
      issuedV2.artifact,
      policy,
      issuedV2.envelope,
      request,
      context,
    );

    expect(v1Result.decision).toBe("DENY");
    expect(v2Result.decision).toBe("ALLOW");

    const row = getRow(id);
    expect(row?.state).toBe("consumed");
    expect(row?.artifact_version).toBe(2);
  });

  it("migrates legacy unversioned tables and preserves existing v1 rows and replay protection (H-01)", () => {
    const path = databasePath();
    const rawDb = new DatabaseSync(path);
    // Simulate legacy 5B unversioned table with an already-consumed row and an issued row
    rawDb.exec(`
      CREATE TABLE consumed_authorization_ids (
        authorization_id TEXT PRIMARY KEY,
        binding_digest TEXT,
        state TEXT NOT NULL DEFAULT 'consumed',
        consumed_at TEXT
      );
      INSERT INTO consumed_authorization_ids (authorization_id, binding_digest, state, consumed_at)
      VALUES ('legacy-migrated-consumed', 'sha256:aaa', 'consumed', '2026-01-01 00:00:00');
      INSERT INTO consumed_authorization_ids (authorization_id, binding_digest, state, consumed_at)
      VALUES ('legacy-migrated-issued', 'sha256:bbb', 'issued', NULL);
    `);
    rawDb.close();

    // Open store: migration executes
    const store = createStore();

    try {
      // Both rows must now have artifact_version = 1
      const consumedRow = getRow("legacy-migrated-consumed");
      expect(consumedRow?.artifact_version).toBe(1);
      expect(consumedRow?.state).toBe("consumed");

      const issuedRow = getRow("legacy-migrated-issued");
      expect(issuedRow?.artifact_version).toBe(1);
      expect(issuedRow?.state).toBe("issued");

      // Consumed row cannot be reissued or consumed
      expect(store.reserve("legacy-migrated-consumed")).toBe(false);
      expect(store.issueBound("legacy-migrated-consumed", "sha256:aaa")).toBe(false);
      expect(store.consumeBound("legacy-migrated-consumed", "sha256:aaa")).toBe(false);

      // Issued row can be consumed as v1
      expect(store.consumeBound("legacy-migrated-issued", "sha256:bbb", 1)).toBe(true);
      expect(getRow("legacy-migrated-issued")?.state).toBe("consumed");

      // New v2 signed authorization can be issued and consumed in the migrated store
      const issuedV2 = issueSignedTransactionAuthorizationWithStore(
        store,
        registry,
        { keyId: "test-issuer-key-1", privateKey: keyPair.privateKey },
        "migrated-v2-new",
        policy,
        request,
        context,
      );
      expect(issuedV2.decision).toBe("ALLOW");
      expect(getRow("migrated-v2-new")?.artifact_version).toBe(2);

      if (issuedV2.decision === "ALLOW") {
        const consumedV2 = consumeSignedTransactionAuthorizationWithStore(
          store,
          registry,
          issuedV2.artifact,
          policy,
          issuedV2.envelope,
          request,
          context,
        );
        expect(consumedV2.decision).toBe("ALLOW");
        expect(getRow("migrated-v2-new")?.state).toBe("consumed");
      }
    } finally {
      closeStore(store);
    }
  });

  it("denies consumption if candidate transaction parameters do not match binding", () => {
    const store = createStore();
    const id = "mismatch-tx-001";

    const issued = issueSignedTransactionAuthorizationWithStore(
      store,
      registry,
      { keyId: "test-issuer-key-1", privateKey: keyPair.privateKey },
      id,
      policy,
      request,
      context,
    );
    expect(issued.decision).toBe("ALLOW");
    if (issued.decision !== "ALLOW") return;

    // Candidate has different amount
    const mismatchedRequest: TransactionRequest = {
      ...request,
      calldata: transferCalldata(6n),
    };

    const consumed = consumeSignedTransactionAuthorizationWithStore(
      store,
      registry,
      issued.artifact,
      policy,
      issued.envelope,
      mismatchedRequest,
      context,
    );

    expect(consumed.decision).toBe("DENY");
    expect(consumed.reasons).toContain(
      "Transaction does not match the original envelope."
    );

    // Row remains in 'issued' state
    const row = getRow(id);
    expect(row?.state).toBe("issued");
    expect(row?.consumed_at).toBeNull();
  });

  it("denies consumption if policy has expired or has been revoked, without consuming the row", () => {
    const store = createStore();
    const id = "revoked-policy-001";

    const issued = issueSignedTransactionAuthorizationWithStore(
      store,
      registry,
      { keyId: "test-issuer-key-1", privateKey: keyPair.privateKey },
      id,
      policy,
      request,
      context,
    );
    expect(issued.decision).toBe("ALLOW");
    if (issued.decision !== "ALLOW") return;

    // Policy revoked
    const revokedPolicy = { ...policy, revoked: true };
    const consumed = consumeSignedTransactionAuthorizationWithStore(
      store,
      registry,
      issued.artifact,
      revokedPolicy,
      issued.envelope,
      request,
      context,
    );

    expect(consumed.decision).toBe("DENY");
    expect(consumed.reasons).toContain("Policy has been revoked.");

    // Row remains in 'issued' state
    const row = getRow(id);
    expect(row?.state).toBe("issued");
    expect(row?.consumed_at).toBeNull();
  });

  it("handles concurrent consumption across separate store instances atomically", () => {
    const store1 = createStore();
    const store2 = createStore();
    const id = "concurrent-signed-001";

    const issued = issueSignedTransactionAuthorizationWithStore(
      store1,
      registry,
      { keyId: "test-issuer-key-1", privateKey: keyPair.privateKey },
      id,
      policy,
      request,
      context,
    );
    expect(issued.decision).toBe("ALLOW");
    if (issued.decision !== "ALLOW") return;

    // Competing consumption from store1 and store2
    const res1 = consumeSignedTransactionAuthorizationWithStore(
      store1,
      registry,
      issued.artifact,
      policy,
      issued.envelope,
      request,
      context,
    );

    const res2 = consumeSignedTransactionAuthorizationWithStore(
      store2,
      registry,
      issued.artifact,
      policy,
      issued.envelope,
      request,
      context,
    );

    const decisions = [res1.decision, res2.decision];
    expect(decisions).toContain("ALLOW");
    expect(decisions).toContain("DENY");
  });

  it("maintains complete backward compatibility with v1 bound artifacts in the same database", () => {
    const store = createStore();

    // Issue v1 bound artifact
    const v1Issued = issueBoundTransactionAuthorizationWithStore(
      store,
      "v1-auth-001",
      policy,
      request,
      context,
    );
    expect(v1Issued.decision).toBe("ALLOW");
    if (v1Issued.decision !== "ALLOW") return;
    expect(v1Issued.artifact.version).toBe(1);

    // Issue v2 signed artifact in the same store
    const v2Issued = issueSignedTransactionAuthorizationWithStore(
      store,
      registry,
      { keyId: "test-issuer-key-1", privateKey: keyPair.privateKey },
      "v2-auth-001",
      policy,
      request,
      context,
    );
    expect(v2Issued.decision).toBe("ALLOW");
    if (v2Issued.decision !== "ALLOW") return;
    expect(v2Issued.artifact.version).toBe(2);

    // Consume v1
    const v1Consumed = consumeBoundTransactionAuthorizationWithStore(
      store,
      v1Issued.artifact,
      policy,
      v1Issued.envelope,
      request,
      context,
    );
    expect(v1Consumed.decision).toBe("ALLOW");

    // Consume v2
    const v2Consumed = consumeSignedTransactionAuthorizationWithStore(
      store,
      registry,
      v2Issued.artifact,
      policy,
      v2Issued.envelope,
      request,
      context,
    );
    expect(v2Consumed.decision).toBe("ALLOW");

    // Both are consumed with respective versions
    const v1Row = getRow("v1-auth-001");
    expect(v1Row?.state).toBe("consumed");
    expect(v1Row?.artifact_version).toBe(1);

    const v2Row = getRow("v2-auth-001");
    expect(v2Row?.state).toBe("consumed");
    expect(v2Row?.artifact_version).toBe(2);
  });
});
