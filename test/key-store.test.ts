import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { TestClock } from "../src/clock.js";
import { SQLiteKeyStore } from "../src/key-store.js";

describe("Milestone 6.2 Phase 2: SQLiteKeyStore Governance", () => {
  let directory: string | undefined;

  function databasePath(filename = "key-gov-test.sqlite"): string {
    directory ??= mkdtempSync(join(tmpdir(), "web3user-key-"));
    return join(directory, filename);
  }

  afterEach(() => {
    if (directory) {
      rmSync(directory, { recursive: true, force: true });
      directory = undefined;
    }
  });

  function createEd25519Keys() {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    return { publicKey, privateKey, pem };
  }

  // 9. Registration and lookup by key ID
  it("registers an issuer key and looks up metadata and lifecycle status", () => {
    const dbFile = databasePath();
    const store = new SQLiteKeyStore(dbFile, new TestClock(1000));
    const { publicKey, pem } = createEd25519Keys();

    try {
      store.registerKey({
        keyId: "issuer-key-alpha",
        publicKey,
        status: "active",
        validFromSeconds: 500,
        expiresAtSeconds: 5000,
      });

      const lookedUp = store.getKey("issuer-key-alpha");
      expect(lookedUp).not.toBeNull();
      expect(lookedUp?.keyId).toBe("issuer-key-alpha");
      expect(lookedUp?.status).toBe("active");
      expect(lookedUp?.validFromSeconds).toBe(500);
      expect(lookedUp?.expiresAtSeconds).toBe(5000);
      expect(lookedUp?.publicKeyPem).toBe(pem);
      expect(lookedUp?.createdAt).toBeDefined();

      expect(store.getKeyStatus("issuer-key-alpha")).toBe("active");

      const allKeys = store.listKeys();
      expect(allKeys).toHaveLength(1);
      expect(allKeys[0].keyId).toBe("issuer-key-alpha");

      const activeKeys = store.listKeys("active");
      expect(activeKeys).toHaveLength(1);

      const retiredKeys = store.listKeys("retired");
      expect(retiredKeys).toHaveLength(0);
    } finally {
      store.close();
    }
  });

  // 10. Duplicate key ID with a different public key is rejected
  it("rejects duplicate key ID with a different public key and duplicate registration with same key", () => {
    const dbFile = databasePath();
    const store = new SQLiteKeyStore(dbFile, new TestClock(1000));
    const keyPair1 = createEd25519Keys();
    const keyPair2 = createEd25519Keys();

    try {
      store.registerKey({
        keyId: "issuer-key-shared",
        publicKey: keyPair1.publicKey,
        status: "active",
      });

      // Different key with same keyId is rejected
      expect(() =>
        store.registerKey({
          keyId: "issuer-key-shared",
          publicKey: keyPair2.publicKey,
          status: "active",
        })
      ).toThrow(
        "Key ID 'issuer-key-shared' is already registered with a different public key."
      );

      // Same key with same keyId is rejected as duplicate
      expect(() =>
        store.registerKey({
          keyId: "issuer-key-shared",
          publicKey: keyPair1.publicKey,
          status: "active",
        })
      ).toThrow("Key ID already registered: issuer-key-shared");
    } finally {
      store.close();
    }
  });

  // 11. Retirement persists its timestamp across reopening
  it("retires a key, persists the retirement timestamp, and survives database reopening", () => {
    const dbFile = databasePath();
    const clock = new TestClock(1000);
    const store1 = new SQLiteKeyStore(dbFile, clock);
    const { publicKey } = createEd25519Keys();

    try {
      store1.registerKey({
        keyId: "issuer-key-retire-test",
        publicKey,
        status: "active",
      });

      clock.advance(500); // 1500
      const retired = store1.retireKey("issuer-key-retire-test", 1500);
      expect(retired.status).toBe("retired");
      expect(retired.retiredAtSeconds).toBe(1500);
      expect(store1.getKeyStatus("issuer-key-retire-test")).toBe("retired");

      store1.close();

      // Reopen with separate store instance
      const store2 = new SQLiteKeyStore(dbFile, new TestClock(1500));
      try {
        const reloaded = store2.getKey("issuer-key-retire-test");
        expect(reloaded?.status).toBe("retired");
        expect(reloaded?.retiredAtSeconds).toBe(1500);

        // Calling retireKey on an already retired key is idempotent
        const reRetire = store2.retireKey("issuer-key-retire-test", 1600);
        expect(reRetire.status).toBe("retired");
        expect(reRetire.retiredAtSeconds).toBe(1500);
      } finally {
        store2.close();
      }
    } finally {
      try { store1.close(); } catch {}
    }
  });

  // 12. Revocation persists across reopening
  it("revokes a key, persists revocation timestamp, and survives database reopening", () => {
    const dbFile = databasePath();
    const clock = new TestClock(2000);
    const store1 = new SQLiteKeyStore(dbFile, clock);
    const { publicKey } = createEd25519Keys();

    try {
      store1.registerKey({
        keyId: "issuer-key-revoke-test",
        publicKey,
        status: "active",
      });

      clock.advance(300); // 2300
      const revoked = store1.revokeKey("issuer-key-revoke-test", 2300);
      expect(revoked.status).toBe("revoked");
      expect(revoked.revokedAtSeconds).toBe(2300);
      expect(store1.getKeyStatus("issuer-key-revoke-test")).toBe("revoked");

      store1.close();

      const store2 = new SQLiteKeyStore(dbFile, new TestClock(2300));
      try {
        const reloaded = store2.getKey("issuer-key-revoke-test");
        expect(reloaded?.status).toBe("revoked");
        expect(reloaded?.revokedAtSeconds).toBe(2300);

        // Idempotent repeat revocation
        const repeat = store2.revokeKey("issuer-key-revoke-test", 2500);
        expect(repeat.status).toBe("revoked");
        expect(repeat.revokedAtSeconds).toBe(2300);
      } finally {
        store2.close();
      }
    } finally {
      try { store1.close(); } catch {}
    }
  });

  // 13. Revoked keys cannot be reactivated through registration or mutation
  it("permanently locks revoked keys against reactivation, retirement, or re-registration", () => {
    const dbFile = databasePath();
    const clock = new TestClock(3000);
    const store = new SQLiteKeyStore(dbFile, clock);
    const { publicKey } = createEd25519Keys();

    try {
      store.registerKey({
        keyId: "issuer-key-permanent-revoke",
        publicKey,
        status: "active",
      });

      store.revokeKey("issuer-key-permanent-revoke", 3100);

      // Cannot retire a revoked key
      expect(() => store.retireKey("issuer-key-permanent-revoke", 3200)).toThrow(
        "Cannot retire revoked key 'issuer-key-permanent-revoke'; revocation is permanent."
      );

      // Advance clock forward to 3300 so timestamp is valid
      clock.set(3300);

      // Cannot re-register the revoked key
      expect(() =>
        store.registerKey({
          keyId: "issuer-key-permanent-revoke",
          publicKey,
          status: "active",
        })
      ).toThrow("Cannot re-register revoked key ID 'issuer-key-permanent-revoke'.");

      // Even attempting re-registration with a new key is blocked
      const freshKeys = createEd25519Keys();
      expect(() =>
        store.registerKey({
          keyId: "issuer-key-permanent-revoke",
          publicKey: freshKeys.publicKey,
          status: "active",
        })
      ).toThrow(
        "Key ID 'issuer-key-permanent-revoke' is already registered with a different public key."
      );
    } finally {
      store.close();
    }
  });

  // 14. Concurrent lifecycle mutations remain serialized
  it("serializes concurrent key retirement and revocation operations across store connections", () => {
    const dbFile = databasePath();
    const clock = new TestClock(4000);
    const store1 = new SQLiteKeyStore(dbFile, clock);
    const store2 = new SQLiteKeyStore(dbFile, clock);
    const { publicKey } = createEd25519Keys();

    try {
      store1.registerKey({
        keyId: "issuer-key-concurrent-lifecycle",
        publicKey,
        status: "active",
      });

      // Store 1 revokes the key
      clock.advance(100);
      store1.revokeKey("issuer-key-concurrent-lifecycle", 4100);
      expect(store1.getKeyStatus("issuer-key-concurrent-lifecycle")).toBe("revoked");

      // Store 2 immediately observes revoked state and cannot retire it
      expect(() => store2.retireKey("issuer-key-concurrent-lifecycle", 4200)).toThrow(
        "Cannot retire revoked key 'issuer-key-concurrent-lifecycle'; revocation is permanent."
      );

      expect(store2.getKeyStatus("issuer-key-concurrent-lifecycle")).toBe("revoked");
    } finally {
      store1.close();
      store2.close();
    }
  });

  // 15. Clock rollback is rejected by persistent high-water mechanism
  it("rejects clock rollback when retiring or revoking keys", () => {
    const dbFile = databasePath();
    const clock = new TestClock(5000);
    const store = new SQLiteKeyStore(dbFile, clock);
    const { publicKey } = createEd25519Keys();

    try {
      store.registerKey({
        keyId: "issuer-key-rollback-test",
        publicKey,
        status: "active",
      });
      expect(store.getHighWaterMark()).toBe(5000);

      // Advance clock to 6000
      store.retireKey("issuer-key-rollback-test", 6000);
      expect(store.getHighWaterMark()).toBe(6000);

      // Attempting revocation at 5500 (preceding high-water mark 6000) must throw
      expect(() => store.revokeKey("issuer-key-rollback-test", 5500)).toThrow(
        "Clock rollback detected: current time (5500s) precedes persisted high-water mark (6000s)."
      );

      // Key status remains unchanged, high-water mark is not lowered
      expect(store.getKeyStatus("issuer-key-rollback-test")).toBe("retired");
      expect(store.getHighWaterMark()).toBe(6000);
    } finally {
      store.close();
    }
  });

  // 16. Older issuer_keys table schema migration preserves existing keys
  it("safely migrates pre-existing older issuer_keys table schema without dropping registered keys", () => {
    const dbFile = databasePath("older-key-schema.sqlite");
    const rawDb = new DatabaseSync(dbFile);
    const { pem } = createEd25519Keys();

    // Create older schema without retired_at_seconds and revoked_at_seconds
    rawDb.exec(`
      CREATE TABLE issuer_keys (
        key_id TEXT PRIMARY KEY,
        public_key_pem TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active'
      );
    `);
    rawDb.prepare("INSERT INTO issuer_keys VALUES (?, ?, ?)").run("legacy-key-001", pem, "active");
    rawDb.close();

    const store = new SQLiteKeyStore(dbFile, new TestClock(7000));
    try {
      const key = store.getKey("legacy-key-001");
      expect(key).not.toBeNull();
      expect(key?.keyId).toBe("legacy-key-001");
      expect(key?.status).toBe("active");
      expect(key?.retiredAtSeconds).toBeUndefined();
      expect(key?.revokedAtSeconds).toBeUndefined();

      // Verify that retiring and revoking work on the migrated table
      const retired = store.retireKey("legacy-key-001", 7500);
      expect(retired.status).toBe("retired");
      expect(retired.retiredAtSeconds).toBe(7500);
    } finally {
      store.close();
    }
  });
});
