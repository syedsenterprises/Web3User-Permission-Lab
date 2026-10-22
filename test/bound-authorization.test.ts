import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import {
  consumeBoundTransactionAuthorizationWithStore,
  issueBoundTransactionAuthorizationWithStore,
} from "../src/authorization-lifecycle.js";
import type { BoundAuthorizationIdStore } from "../src/authorization-store.js";
import { SQLiteAuthorizationStore } from "../src/authorization-store.js";
import { prepareTransactionAuthorization } from "../src/policy-transaction.js";
import type { DemoPolicy } from "../src/policy.js";
import type { TransactionRequest } from "../src/transaction-envelope.js";

const target = "0x1111111111111111111111111111111111111111";
const sender = "0x2222222222222222222222222222222222222222";
const recipient = "0x3333333333333333333333333333333333333333";

function transferCalldata(amount: bigint): string {
  return "0xa9059cbb" +
    recipient.slice(2).padStart(64, "0") +
    amount.toString(16).padStart(64, "0");
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
  policyId: "bound-authorization-test",
  allowedTarget: target,
  allowedRecipient: recipient,
  allowedSelector: "0xa9059cbb",
  maxAmount: "10",
  validFrom: 50,
  expiresAt: 200,
  revoked: false,
};

const context = { nowSeconds: 100 };

describe("bound transaction authorization", () => {
  let directory: string | undefined;
  const stores = new Set<SQLiteAuthorizationStore>();

  function databasePath(): string {
    directory ??= mkdtempSync(join(tmpdir(), "web3user-bound-"));
    return join(directory, "auth.sqlite");
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
  } | undefined {
    const db = new DatabaseSync(databasePath());
    try {
      return db.prepare(
        "SELECT authorization_id, binding_digest, state, consumed_at FROM consumed_authorization_ids WHERE authorization_id = ?"
      ).get(id) as {
        authorization_id: string;
        binding_digest: string | null;
        state: string;
        consumed_at: string | null;
      } | undefined;
    } finally {
      db.close();
    }
  }

  afterEach(() => {
    for (const store of stores) closeStore(store);
    if (directory) {
      rmSync(directory, { recursive: true, force: true });
      directory = undefined;
    }
  });

  function issue(store: SQLiteAuthorizationStore, id = "bound-auth-001") {
    const issued = issueBoundTransactionAuthorizationWithStore(
      store, id, policy, request, context,
    );
    expect(issued.decision).toBe("ALLOW");
    if (issued.decision !== "ALLOW") throw new Error("Fixture issuance failed.");
    return issued;
  }

  it("issues and consumes a bound artifact exactly once with correct timestamp semantics", () => {
    const store = createStore();
    const issued = issue(store, "bound-timestamp-001");

    try {
      expect(issued.artifact).toEqual({
        version: 1,
        authorizationId: "bound-timestamp-001",
        bindingDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
      });

      // Immediately after issuance: state = 'issued' and consumed_at IS NULL
      const issuedRow = getRow("bound-timestamp-001");
      expect(issuedRow).toBeDefined();
      expect(issuedRow?.state).toBe("issued");
      expect(issuedRow?.consumed_at).toBeNull();
      expect(issuedRow?.binding_digest).toBe(issued.artifact.bindingDigest);

      // Successful first consumption: ALLOW
      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, policy, issued.envelope, request, context,
      ).decision).toBe("ALLOW");

      // Immediately after consumption: state = 'consumed' and consumed_at IS NOT NULL
      const consumedRow = getRow("bound-timestamp-001");
      expect(consumedRow).toBeDefined();
      expect(consumedRow?.state).toBe("consumed");
      expect(consumedRow?.consumed_at).not.toBeNull();
      expect(typeof consumedRow?.consumed_at).toBe("string");

      // Subsequent consumption: DENY
      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, policy, issued.envelope, request, context,
      ).decision).toBe("DENY");
    } finally {
      closeStore(store);
    }
  });

  it("persists issued artifacts across a database reopen", () => {
    const first = createStore();
    const issued = issue(first, "bound-reopen-001");
    closeStore(first);

    const second = createStore();
    const prepared = prepareTransactionAuthorization(policy, request, context);
    expect(prepared.decision).toBe("ALLOW");
    if (prepared.decision !== "ALLOW") return;

    try {
      expect(consumeBoundTransactionAuthorizationWithStore(
        second, issued.artifact, policy, prepared.envelope, request, context,
      ).decision).toBe("ALLOW");
    } finally {
      closeStore(second);
    }
  });

  it("denies a different otherwise-policy-valid request without consuming the artifact", () => {
    const store = createStore();
    const issued = issue(store, "bound-different-request-001");
    const changedRequest = { ...request, calldata: transferCalldata(6n) };
    const changedPrepared = prepareTransactionAuthorization(
      policy, changedRequest, context,
    );
    expect(changedPrepared.decision).toBe("ALLOW");
    if (changedPrepared.decision !== "ALLOW") return;

    try {
      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, policy, changedPrepared.envelope,
        changedRequest, context,
      ).decision).toBe("DENY");

      // Verify row state was not changed to consumed by failed attempt
      const rowAfterFailed = getRow("bound-different-request-001");
      expect(rowAfterFailed?.state).toBe("issued");
      expect(rowAfterFailed?.consumed_at).toBeNull();

      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, policy, issued.envelope, request, context,
      ).decision).toBe("ALLOW");

      const rowAfterAllowed = getRow("bound-different-request-001");
      expect(rowAfterAllowed?.state).toBe("consumed");
      expect(rowAfterAllowed?.consumed_at).not.toBeNull();
    } finally {
      closeStore(store);
    }
  });

  it.each([
    ["chain ID", { chainId: "2" }],
    ["sender", { sender: recipient }],
    ["native value", { value: "1" }],
  ])("denies a changed %s before consumption without marking it consumed", (_field, change) => {
    const store = createStore();
    const id = `bound-request-change-${String(_field)}`;
    const issued = issue(store, id);
    const changedRequest = { ...request, ...change };
    const changedPrepared = prepareTransactionAuthorization(
      policy, changedRequest, context,
    );
    expect(changedPrepared.decision).toBe("ALLOW");
    if (changedPrepared.decision !== "ALLOW") return;

    try {
      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, policy, changedPrepared.envelope,
        changedRequest, context,
      ).decision).toBe("DENY");

      const rowAfterFailed = getRow(id);
      expect(rowAfterFailed?.state).toBe("issued");
      expect(rowAfterFailed?.consumed_at).toBeNull();

      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, policy, issued.envelope, request, context,
      ).decision).toBe("ALLOW");

      const rowAfterAllowed = getRow(id);
      expect(rowAfterAllowed?.state).toBe("consumed");
      expect(rowAfterAllowed?.consumed_at).not.toBeNull();
    } finally {
      closeStore(store);
    }
  });

  it("denies a changed policy snapshot without consuming the artifact", () => {
    const store = createStore();
    const issued = issue(store, "bound-policy-change-001");
    const changedPolicy = { ...policy, maxAmount: "20" };
    const changedPrepared = prepareTransactionAuthorization(
      changedPolicy, request, context,
    );
    expect(changedPrepared.decision).toBe("ALLOW");
    if (changedPrepared.decision !== "ALLOW") return;

    try {
      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, changedPolicy, changedPrepared.envelope,
        request, context,
      ).decision).toBe("DENY");

      const rowAfterFailed = getRow("bound-policy-change-001");
      expect(rowAfterFailed?.state).toBe("issued");
      expect(rowAfterFailed?.consumed_at).toBeNull();

      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, policy, issued.envelope, request, context,
      ).decision).toBe("ALLOW");

      const rowAfterAllowed = getRow("bound-policy-change-001");
      expect(rowAfterAllowed?.state).toBe("consumed");
      expect(rowAfterAllowed?.consumed_at).not.toBeNull();
    } finally {
      closeStore(store);
    }
  });

  it("does not consume an artifact for revoked or expired policies", () => {
    const store = createStore();
    const revoked = issue(store, "bound-revoked-001");
    const expired = issue(store, "bound-expired-001");

    try {
      expect(consumeBoundTransactionAuthorizationWithStore(
        store, revoked.artifact, { ...policy, revoked: true },
        revoked.envelope, request, context,
      ).decision).toBe("DENY");
      expect(consumeBoundTransactionAuthorizationWithStore(
        store, expired.artifact, policy, expired.envelope, request,
        { nowSeconds: policy.expiresAt },
      ).decision).toBe("DENY");

      // Verify neither record was marked consumed by the failed attempt
      const revokedRow = getRow("bound-revoked-001");
      expect(revokedRow?.state).toBe("issued");
      expect(revokedRow?.consumed_at).toBeNull();

      const expiredRow = getRow("bound-expired-001");
      expect(expiredRow?.state).toBe("issued");
      expect(expiredRow?.consumed_at).toBeNull();

      // Original unrevoked/unexpired consumption still succeeds
      expect(consumeBoundTransactionAuthorizationWithStore(
        store, revoked.artifact, policy, revoked.envelope, request, context,
      ).decision).toBe("ALLOW");
      expect(consumeBoundTransactionAuthorizationWithStore(
        store, expired.artifact, policy, expired.envelope, request, context,
      ).decision).toBe("ALLOW");

      expect(getRow("bound-revoked-001")?.state).toBe("consumed");
      expect(getRow("bound-revoked-001")?.consumed_at).not.toBeNull();
      expect(getRow("bound-expired-001")?.state).toBe("consumed");
      expect(getRow("bound-expired-001")?.consumed_at).not.toBeNull();
    } finally {
      closeStore(store);
    }
  });

  it("denies invalid artifacts, unknown IDs, and mismatched digests without consuming", () => {
    const store = createStore();
    const issued = issue(store, "bound-invalid-001");
    const unknown = {
      ...issued.artifact,
      authorizationId: "bound-unknown-001",
    };
    const mismatched = {
      ...issued.artifact,
      bindingDigest: `sha256:${"0".repeat(64)}`,
    };

    try {
      for (const artifact of [null, {}, { ...issued.artifact, version: 2 },
        { ...issued.artifact, authorizationId: " " }, unknown, mismatched]) {
        expect(consumeBoundTransactionAuthorizationWithStore(
          store, artifact, policy, issued.envelope, request, context,
        ).decision).toBe("DENY");
      }

      // Record remains issued and unconsumed
      const row = getRow("bound-invalid-001");
      expect(row?.state).toBe("issued");
      expect(row?.consumed_at).toBeNull();

      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, policy, issued.envelope, request, context,
      ).decision).toBe("ALLOW");

      expect(getRow("bound-invalid-001")?.state).toBe("consumed");
      expect(getRow("bound-invalid-001")?.consumed_at).not.toBeNull();
    } finally {
      closeStore(store);
    }
  });

  it("propagates store errors during issuance and consumption", () => {
    const issuanceFailure = new Error("issuance unavailable");
    const issuingStore: BoundAuthorizationIdStore = {
      reserve: () => false,
      issueBound: () => { throw issuanceFailure; },
      consumeBound: () => false,
      close: () => {},
    };
    expect(() => issueBoundTransactionAuthorizationWithStore(
      issuingStore, "bound-issuance-error-001", policy, request, context,
    )).toThrow(issuanceFailure);

    const store = createStore();
    const issued = issue(store, "bound-consumption-error-001");
    const consumptionFailure = new Error("consumption unavailable");
    const consumingStore: BoundAuthorizationIdStore = {
      reserve: () => false,
      issueBound: () => false,
      consumeBound: () => { throw consumptionFailure; },
      close: () => {},
    };
    expect(() => consumeBoundTransactionAuthorizationWithStore(
      consumingStore, issued.artifact, policy, issued.envelope, request, context,
    )).toThrow(consumptionFailure);
    closeStore(store);
  });

  it("migrates legacy consumed IDs without allowing them to be reissued", () => {
    const path = databasePath();
    const legacy = new DatabaseSync(path);
    legacy.exec(`
      CREATE TABLE consumed_authorization_ids (
        authorization_id TEXT PRIMARY KEY,
        consumed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      INSERT INTO consumed_authorization_ids (authorization_id)
      VALUES ('legacy-consumed-001');
    `);
    legacy.close();

    const store = createStore();
    try {
      // Legacy ID cannot be reserved again
      expect(store.reserve("legacy-consumed-001")).toBe(false);
      // Legacy ID cannot be issued as a bound authorization
      expect(store.issueBound("legacy-consumed-001", "sha256:1")).toBe(false);
      // Legacy ID cannot be consumed via bound consumption
      expect(store.consumeBound("legacy-consumed-001", "sha256:1")).toBe(false);

      // New ID can be issued and consumed normally
      expect(store.issueBound("migrated-new-001", "sha256:2")).toBe(true);

      const issuedRow = getRow("migrated-new-001");
      expect(issuedRow?.state).toBe("issued");
      expect(issuedRow?.consumed_at).toBeNull();

      expect(store.consumeBound("migrated-new-001", "sha256:2")).toBe(true);

      const consumedRow = getRow("migrated-new-001");
      expect(consumedRow?.state).toBe("consumed");
      expect(consumedRow?.consumed_at).not.toBeNull();

      // Legacy row is preserved as consumed with timestamp intact
      const legacyRow = getRow("legacy-consumed-001");
      expect(legacyRow?.state).toBe("consumed");
      expect(legacyRow?.binding_digest).toBeNull();
      expect(legacyRow?.consumed_at).not.toBeNull();
    } finally {
      closeStore(store);
    }
  });

  it("denies re-issuing an authorization ID that has already been issued or consumed", () => {
    const store = createStore();
    const issued = issue(store, "bound-duplicate-issuance-001");

    try {
      // Re-issuance while still in 'issued' state
      const duplicateIssue = issueBoundTransactionAuthorizationWithStore(
        store, "bound-duplicate-issuance-001", policy, request, context,
      );
      expect(duplicateIssue.decision).toBe("DENY");
      expect(duplicateIssue.reasons).toContain(
        "Transaction authorization ID has already been issued or consumed.",
      );

      // Legacy reserve also fails on issued ID
      expect(store.reserve("bound-duplicate-issuance-001")).toBe(false);

      // Consume the issued authorization
      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, policy, issued.envelope, request, context,
      ).decision).toBe("ALLOW");

      // Re-issuance after transition to 'consumed' state
      const reissuedAfterConsumed = issueBoundTransactionAuthorizationWithStore(
        store, "bound-duplicate-issuance-001", policy, request, context,
      );
      expect(reissuedAfterConsumed.decision).toBe("DENY");
      expect(reissuedAfterConsumed.reasons).toContain(
        "Transaction authorization ID has already been issued or consumed.",
      );
    } finally {
      closeStore(store);
    }
  });

  it("normalizes policy address casing when computing the binding digest", () => {
    const store = createStore();
    const uppercasePolicy: DemoPolicy = {
      ...policy,
      allowedTarget: "0x" + policy.allowedTarget.slice(2).toUpperCase(),
      allowedRecipient: "0x" + policy.allowedRecipient.slice(2).toUpperCase(),
      allowedSelector: "0xa9059CBB",
    };

    const issued = issueBoundTransactionAuthorizationWithStore(
      store, "bound-casing-001", uppercasePolicy, request, context,
    );
    expect(issued.decision).toBe("ALLOW");
    if (issued.decision !== "ALLOW") return;

    try {
      // Consume using lowercase policy - binding digests match due to normalization
      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, policy, issued.envelope, request, context,
      ).decision).toBe("ALLOW");
    } finally {
      closeStore(store);
    }
  });

  it("rejects issuance without writing to storage when policy or request is invalid", () => {
    const store = createStore();
    const invalidRequest = { ...request, calldata: "0xdeadbeef" };

    const failed = issueBoundTransactionAuthorizationWithStore(
      store, "bound-not-persisted-001", policy, invalidRequest, context,
    );
    expect(failed.decision).toBe("UNKNOWN");

    try {
      // The ID was never persisted in store, so it is still free to reserve
      expect(store.reserve("bound-not-persisted-001")).toBe(true);
    } finally {
      closeStore(store);
    }
  });

  it("allows consumption after a temporary revocation is restored", () => {
    const store = createStore();
    const issued = issue(store, "bound-restored-policy-001");

    try {
      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, { ...policy, revoked: true },
        issued.envelope, request, context,
      ).decision).toBe("DENY");

      const rowDuringRevocation = getRow("bound-restored-policy-001");
      expect(rowDuringRevocation?.state).toBe("issued");
      expect(rowDuringRevocation?.consumed_at).toBeNull();

      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, policy, issued.envelope, request, context,
      ).decision).toBe("ALLOW");

      const rowAfterRestored = getRow("bound-restored-policy-001");
      expect(rowAfterRestored?.state).toBe("consumed");
      expect(rowAfterRestored?.consumed_at).not.toBeNull();
    } finally {
      closeStore(store);
    }
  });

  it("comprehensively verifies state and timestamp lifecycle semantics across all stages", () => {
    const store = createStore();
    const id = "lifecycle-semantics-001";

    const issued = issue(store, id);

    try {
      // Stage 1: Immediately after issuance: state = 'issued' and consumed_at IS NULL
      let row = getRow(id);
      expect(row?.state).toBe("issued");
      expect(row?.consumed_at).toBeNull();
      expect(row?.binding_digest).toBe(issued.artifact.bindingDigest);

      // Stage 2: Mismatched candidate request fails without state mutation
      const mismatchedReq = { ...request, value: "100" };
      const preparedMismatched = prepareTransactionAuthorization(policy, mismatchedReq, context);
      expect(preparedMismatched.decision).toBe("ALLOW");
      if (preparedMismatched.decision === "ALLOW") {
        expect(consumeBoundTransactionAuthorizationWithStore(
          store, issued.artifact, policy, preparedMismatched.envelope, mismatchedReq, context,
        ).decision).toBe("DENY");
      }
      row = getRow(id);
      expect(row?.state).toBe("issued");
      expect(row?.consumed_at).toBeNull();

      // Stage 3: Revoked policy fails without state mutation
      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, { ...policy, revoked: true }, issued.envelope, request, context,
      ).decision).toBe("DENY");
      row = getRow(id);
      expect(row?.state).toBe("issued");
      expect(row?.consumed_at).toBeNull();

      // Stage 4: Expired context fails without state mutation
      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, policy, issued.envelope, request, { nowSeconds: policy.expiresAt + 1 },
      ).decision).toBe("DENY");
      row = getRow(id);
      expect(row?.state).toBe("issued");
      expect(row?.consumed_at).toBeNull();

      // Stage 5: Valid consumption atomically transitions state to 'consumed' and sets timestamp
      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, policy, issued.envelope, request, context,
      ).decision).toBe("ALLOW");
      row = getRow(id);
      expect(row?.state).toBe("consumed");
      expect(row?.consumed_at).not.toBeNull();
      expect(typeof row?.consumed_at).toBe("string");
      const originalTimestamp = row?.consumed_at;

      // Stage 6: Subsequent consumption replay fails closed and leaves timestamp intact
      expect(consumeBoundTransactionAuthorizationWithStore(
        store, issued.artifact, policy, issued.envelope, request, context,
      ).decision).toBe("DENY");
      row = getRow(id);
      expect(row?.state).toBe("consumed");
      expect(row?.consumed_at).toBe(originalTimestamp);
    } finally {
      closeStore(store);
    }
  });

  it("allows only one competing issuance from separate connections against the same file", () => {
    // Both stores open the exact same database file concurrently via separate DatabaseSync connections
    const firstStore = createStore();
    const secondStore = createStore();

    try {
      const results = [
        firstStore.issueBound("competing-issue-001", "sha256:1"),
        secondStore.issueBound("competing-issue-001", "sha256:1"),
      ];
      expect(results.filter(Boolean)).toHaveLength(1);

      const row = getRow("competing-issue-001");
      expect(row?.state).toBe("issued");
      expect(row?.consumed_at).toBeNull();
    } finally {
      closeStore(firstStore);
      closeStore(secondStore);
    }
  });

  it("allows only one competing consumption from separate connections against the same file", () => {
    // firstStore and secondStore are two distinct DatabaseSync handles to the same underlying SQLite file
    const firstStore = createStore();
    const secondStore = createStore();

    const issued = issue(firstStore, "competing-consume-001");

    try {
      const firstResult = consumeBoundTransactionAuthorizationWithStore(
        firstStore, issued.artifact, policy, issued.envelope, request, context,
      );
      const secondResult = consumeBoundTransactionAuthorizationWithStore(
        secondStore, issued.artifact, policy, issued.envelope, request, context,
      );

      const decisions = [firstResult.decision, secondResult.decision];
      expect(decisions).toContain("ALLOW");
      expect(decisions).toContain("DENY");
      expect(decisions.filter((d) => d === "ALLOW")).toHaveLength(1);

      const row = getRow("competing-consume-001");
      expect(row?.state).toBe("consumed");
      expect(row?.consumed_at).not.toBeNull();
    } finally {
      closeStore(firstStore);
      closeStore(secondStore);
    }
  });
});
