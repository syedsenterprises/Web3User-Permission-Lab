import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SQLiteAuthorizationStore } from "../src/authorization-store.js";

describe("SQLiteAuthorizationStore", () => {
  let directory: string | undefined;
  const stores = new Set<SQLiteAuthorizationStore>();

  function createStore() {
    directory ??= mkdtempSync(join(tmpdir(), "web3user-auth-"));
    const store = new SQLiteAuthorizationStore(join(directory, "auth.sqlite"), undefined, {
      allowLegacyArtifactVersions: true,
    });
    stores.add(store);
    return store;
  }

  function closeStore(store: SQLiteAuthorizationStore) {
    if (stores.delete(store)) store.close();
  }

  afterEach(() => {
    for (const store of stores) closeStore(store);
    if (directory) {
      rmSync(directory, { recursive: true, force: true });
      directory = undefined;
    }
  });

  it("reserves an ID only once", () => {
    const store = createStore();

    try {
      expect(store.reserve("auth-001")).toBe(true);
      expect(store.reserve("auth-001")).toBe(false);
    } finally {
      closeStore(store);
    }
  });

  it("preserves consumed IDs after reopening the database", () => {
    const first = createStore();
    first.reserve("auth-persistent-001");
    closeStore(first);

    const second = createStore();

    try {
      expect(second.reserve("auth-persistent-001")).toBe(false);
      expect(second.reserve("auth-persistent-002")).toBe(true);
    } finally {
      closeStore(second);
    }
  });

  it("allows only one competing reservation from separate connections", () => {
    const first = createStore();
    const second = createStore();

    try {
      const results = [
        first.reserve("auth-duplicate-001"),
        second.reserve("auth-duplicate-001"),
      ];

      expect(results.filter(Boolean)).toHaveLength(1);
    } finally {
      closeStore(first);
      closeStore(second);
    }
  });
});

import {
  consumeTransactionAuthorizationWithStore,
} from "../src/authorization-lifecycle.js";
import {
  prepareTransactionAuthorization,
} from "../src/policy-transaction.js";
import type { DemoPolicy } from "../src/policy.js";
import type { TransactionRequest } from "../src/transaction-envelope.js";

describe("persistent authorization consumption", () => {
  let directory: string | undefined;
  const stores = new Set<SQLiteAuthorizationStore>();

  function createStore() {
    directory ??= mkdtempSync(join(tmpdir(), "web3user-lifecycle-"));
    const store = new SQLiteAuthorizationStore(join(directory, "auth.sqlite"), undefined, {
      allowLegacyArtifactVersions: true,
    });
    stores.add(store);
    return store;
  }

  function closeStore(store: SQLiteAuthorizationStore) {
    if (stores.delete(store)) store.close();
  }

  afterEach(() => {
    for (const store of stores) closeStore(store);
    if (directory) {
      rmSync(directory, { recursive: true, force: true });
      directory = undefined;
    }
  });

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
    policyId: "persistent-test",
    allowedTarget: target,
    allowedRecipient: recipient,
    allowedSelector: "0xa9059cbb",
    maxAmount: "10",
    validFrom: 50,
    expiresAt: 200,
    revoked: false,
  };

  const context = { nowSeconds: 100 };

  it("denies an ID already reserved in persistent storage", () => {
    const store = createStore();
    const first = prepareTransactionAuthorization(policy, request, context);
    const second = prepareTransactionAuthorization(policy, request, context);

    expect(first.decision).toBe("ALLOW");
    expect(second.decision).toBe("ALLOW");
    if (first.decision !== "ALLOW" || second.decision !== "ALLOW") return;

    try {
      expect(
        consumeTransactionAuthorizationWithStore(
          store, "persistent-duplicate-001", policy,
          first.envelope, request, context,
        ).decision,
      ).toBe("ALLOW");

      expect(
        consumeTransactionAuthorizationWithStore(
          store, "persistent-duplicate-001", policy,
          second.envelope, request, context,
        ).decision,
      ).toBe("DENY");
    } finally {
      closeStore(store);
    }
  });

  it("trims IDs consistently and compares the normalized value case-sensitively", () => {
    const store = createStore();
    const first = prepareTransactionAuthorization(policy, request, context);
    const second = prepareTransactionAuthorization(policy, request, context);

    expect(first.decision).toBe("ALLOW");
    expect(second.decision).toBe("ALLOW");
    if (first.decision !== "ALLOW" || second.decision !== "ALLOW") {
      closeStore(store);
      return;
    }

    try {
      expect(consumeTransactionAuthorizationWithStore(
        store, "  Auth-Normalized-001\t", policy,
        first.envelope, request, context,
      ).decision).toBe("ALLOW");
      expect(consumeTransactionAuthorizationWithStore(
        store, "Auth-Normalized-001", policy,
        second.envelope, request, context,
      ).decision).toBe("DENY");
      expect(store.reserve("auth-normalized-001")).toBe(true);
    } finally {
      closeStore(store);
    }
  });

  it("denies an authorization ID after the database is reopened", () => {
    const firstStore = createStore();
    const prepared = prepareTransactionAuthorization(policy, request, context);

    expect(prepared.decision).toBe("ALLOW");
    if (prepared.decision !== "ALLOW") {
      closeStore(firstStore);
      return;
    }

    const authorizationId = "persistent-reopen-lifecycle-001";

    try {
      expect(
        consumeTransactionAuthorizationWithStore(
          firstStore,
          authorizationId,
          policy,
          prepared.envelope,
          request,
          context,
        ).decision,
      ).toBe("ALLOW");
    } finally {
      closeStore(firstStore);
    }

    const secondStore = createStore();
    const secondPrepared = prepareTransactionAuthorization(
      policy,
      request,
      context,
    );

    expect(secondPrepared.decision).toBe("ALLOW");
    if (secondPrepared.decision !== "ALLOW") {
      closeStore(secondStore);
      return;
    }

    try {
      expect(
        consumeTransactionAuthorizationWithStore(
          secondStore,
          authorizationId,
          policy,
          secondPrepared.envelope,
          request,
          context,
        ).decision,
      ).toBe("DENY");
    } finally {
      closeStore(secondStore);
    }
  });
  it("does not reserve an ID when policy validation fails", () => {
    const store = createStore();
    const prepared = prepareTransactionAuthorization(policy, request, context);

    expect(prepared.decision).toBe("ALLOW");
    if (prepared.decision !== "ALLOW") {
      closeStore(store);
      return;
    }

    try {
      expect(
        consumeTransactionAuthorizationWithStore(
          store, "persistent-retry-001", { ...policy, revoked: true },
          prepared.envelope, request, context,
        ).decision,
      ).toBe("DENY");

      expect(store.reserve("persistent-retry-001")).toBe(true);
    } finally {
      closeStore(store);
    }
  });

  it.each([null, undefined, 42, "", " \t\n "])(
    "rejects malformed or blank persistent authorization IDs: %s",
    (authorizationId) => {
      const store = createStore();
      const prepared = prepareTransactionAuthorization(policy, request, context);
      expect(prepared.decision).toBe("ALLOW");
      if (prepared.decision !== "ALLOW") {
        closeStore(store);
        return;
      }

      try {
        expect(consumeTransactionAuthorizationWithStore(
          store, authorizationId, policy,
          prepared.envelope, request, context,
        ).decision).toBe("DENY");
        expect(store.reserve("valid-after-invalid-id")).toBe(true);
      } finally {
        closeStore(store);
      }
    },
  );

  it("propagates storage failures without returning ALLOW", () => {
    const prepared = prepareTransactionAuthorization(policy, request, context);
    expect(prepared.decision).toBe("ALLOW");
    if (prepared.decision !== "ALLOW") return;

    const failure = new Error("storage unavailable");
    const failingStore = {
      reserve: () => { throw failure; },
      close: () => {},
    };

    expect(() => consumeTransactionAuthorizationWithStore(
      failingStore, "persistent-storage-error-001", policy,
      prepared.envelope, request, context,
    )).toThrow(failure);
  });

  it("rechecks request binding, expiry, and revocation before reserving", () => {
    const store = createStore();
    const cases = [
      {
        id: "persistent-binding-recheck-001",
        candidate: { ...request, value: "1" },
        currentPolicy: policy,
        currentContext: context,
      },
      {
        id: "persistent-expiry-recheck-001",
        candidate: request,
        currentPolicy: policy,
        currentContext: { nowSeconds: policy.expiresAt },
      },
      {
        id: "persistent-revocation-recheck-001",
        candidate: request,
        currentPolicy: { ...policy, revoked: true },
        currentContext: context,
      },
    ];

    try {
      for (const item of cases) {
        const prepared = prepareTransactionAuthorization(policy, request, context);
        expect(prepared.decision).toBe("ALLOW");
        if (prepared.decision !== "ALLOW") continue;

        expect(consumeTransactionAuthorizationWithStore(
          store, item.id, item.currentPolicy,
          prepared.envelope, item.candidate, item.currentContext,
        ).decision).toBe("DENY");
        expect(store.reserve(item.id)).toBe(true);
      }
    } finally {
      closeStore(store);
    }
  });

  describe("Milestone 6.5: Fail-closed strict default artifact version enforcement", () => {
    it("enforces fail-closed default where allowLegacyArtifactVersions defaults to false", () => {
      directory ??= mkdtempSync(join(tmpdir(), "web3user-strict-default-"));
      const strictStore = new SQLiteAuthorizationStore(join(directory, "strict.sqlite"));
      stores.add(strictStore);

      try {
        expect(strictStore.getAllowLegacyArtifactVersions()).toBe(false);

        // 1. reserve() directly fails closed
        expect(() => strictStore.reserve("strict-reserve-id")).toThrow(
          "Legacy authorization artifact versions are disabled by configuration.",
        );

        // 2. issueBound() directly fails closed for versions 1 and 2
        expect(() => strictStore.issueBound("strict-issue-1", "sha256:dummy", 1)).toThrow(
          "Legacy authorization artifact versions are disabled by configuration.",
        );
        expect(() => strictStore.issueBound("strict-issue-2", "sha256:dummy", 2)).toThrow(
          "Legacy authorization artifact versions are disabled by configuration.",
        );

        // 3. consumeBound() directly fails closed for versions 1 and 2
        expect(() => strictStore.consumeBound("strict-consume-1", "sha256:dummy", 1)).toThrow(
          "Legacy authorization artifact versions are disabled by configuration.",
        );
        expect(() => strictStore.consumeBound("strict-consume-2", "sha256:dummy", 2)).toThrow(
          "Legacy authorization artifact versions are disabled by configuration.",
        );

        // 4. V3 operations succeed under the strict default
        expect(strictStore.issueBound("strict-issue-3", "sha256:dummy", 3, "key-01", 1000)).toBe(true);
        expect(strictStore.consumeBound("strict-issue-3", "sha256:dummy", 3, "key-01", 1000)).toBe(true);
      } finally {
        closeStore(strictStore);
      }
    });

    it("allows legacy operations when caller explicitly passes allowLegacyArtifactVersions: true", () => {
      directory ??= mkdtempSync(join(tmpdir(), "web3user-compat-optin-"));
      const compatStore = new SQLiteAuthorizationStore(join(directory, "compat.sqlite"), undefined, {
        allowLegacyArtifactVersions: true,
      });
      stores.add(compatStore);

      try {
        expect(compatStore.getAllowLegacyArtifactVersions()).toBe(true);
        expect(compatStore.reserve("compat-reserve-id")).toBe(true);
        expect(compatStore.issueBound("compat-issue-1", "sha256:dummy", 1)).toBe(true);
        expect(compatStore.consumeBound("compat-issue-1", "sha256:dummy", 1)).toBe(true);
      } finally {
        closeStore(compatStore);
      }
    });
  });

  describe("Milestone 6.11 Stage B: SQLite Durability and PRAGMA Configuration", () => {
    it("configures PRAGMA journal_mode = WAL and synchronous = FULL by default on SQLiteAuthorizationStore", () => {
      directory ??= mkdtempSync(join(tmpdir(), "web3user-durability-default-"));
      const store = new SQLiteAuthorizationStore(join(directory, "durability-default.sqlite"));
      stores.add(store);

      try {
        expect(store.getJournalMode()).toBe("wal");
        expect(store.getSynchronousMode()).toBe("FULL");

        // Verify raw SQLite PRAGMA return values directly from the database connection
        const db = store.getDatabase();
        const syncRow = db.prepare("PRAGMA synchronous;").get() as { synchronous: number };
        expect(syncRow.synchronous).toBe(2); // 2 == FULL

        const journalRow = db.prepare("PRAGMA journal_mode;").get() as { journal_mode: string };
        expect(journalRow.journal_mode).toBe("wal");
      } finally {
        closeStore(store);
      }
    });

    it("respects explicit synchronous configuration options across connections", () => {
      directory ??= mkdtempSync(join(tmpdir(), "web3user-durability-options-"));

      const normalStore = new SQLiteAuthorizationStore(join(directory, "durability-normal.sqlite"), undefined, {
        synchronous: "NORMAL",
      });
      stores.add(normalStore);

      const offStore = new SQLiteAuthorizationStore(join(directory, "durability-off.sqlite"), undefined, {
        synchronous: "OFF",
      });
      stores.add(offStore);

      try {
        expect(normalStore.getSynchronousMode()).toBe("NORMAL");
        expect((normalStore.getDatabase().prepare("PRAGMA synchronous;").get() as { synchronous: number }).synchronous).toBe(1);

        expect(offStore.getSynchronousMode()).toBe("OFF");
        expect((offStore.getDatabase().prepare("PRAGMA synchronous;").get() as { synchronous: number }).synchronous).toBe(0);
      } finally {
        closeStore(normalStore);
        closeStore(offStore);
      }
    });

    it("ensures derived PolicyStore and KeyStore share the configured connection durability", () => {
      directory ??= mkdtempSync(join(tmpdir(), "web3user-durability-borrowed-"));
      const store = new SQLiteAuthorizationStore(join(directory, "durability-borrowed.sqlite"), undefined, {
        synchronous: "FULL",
      });
      stores.add(store);

      try {
        const policyStore = store.getPolicyStore();
        const keyStore = store.getKeyStore();

        expect(policyStore.getSynchronousMode()).toBe("FULL");
        expect(policyStore.getJournalMode()).toBe("wal");

        expect(keyStore.getSynchronousMode()).toBe("FULL");
        expect(keyStore.getJournalMode()).toBe("wal");
      } finally {
        closeStore(store);
      }
    });
  });
});


