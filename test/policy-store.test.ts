import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { TestClock, ClockGuard } from "../src/clock.js";
import { type DemoPolicy } from "../src/policy.js";
import { SQLitePolicyStore } from "../src/policy-store.js";
import { SQLiteAuthorizationStore } from "../src/authorization-store.js";
import {
  issueSignedTransactionAuthorizationV3,
  consumeSignedTransactionAuthorizationV3,
  cancelAuthorization,
  cancelSignedTransactionAuthorizationV3,
} from "../src/authorization-lifecycle.js";
import { type TransactionRequest } from "../src/transaction-envelope.js";

describe("Milestone 6.2 Phase 2: SQLitePolicyStore Governance", () => {
  let directory: string | undefined;

  function databasePath(filename = "policy-gov-test.sqlite"): string {
    directory ??= mkdtempSync(join(tmpdir(), "web3user-policy-"));
    return join(directory, filename);
  }

  afterEach(() => {
    if (directory) {
      rmSync(directory, { recursive: true, force: true });
      directory = undefined;
    }
  });

  const basePolicy: DemoPolicy = {
    version: 1,
    policyId: "policy-alpha",
    allowedTarget: "0x1111111111111111111111111111111111111111",
    allowedRecipient: "0x2222222222222222222222222222222222222222",
    allowedSelector: "0xa9059cbb",
    maxAmount: "1000000",
    validFrom: 1000,
    expiresAt: 5000,
    revoked: false,
  };

  // 1. Registration and authoritative retrieval
  it("registers a policy and retrieves the authoritative current revision and history", () => {
    const dbFile = databasePath();
    const store = new SQLitePolicyStore(dbFile, new TestClock(1000));

    try {
      const record = store.registerPolicy(basePolicy);
      expect(record.policyId).toBe("policy-alpha");
      expect(record.revision).toBe(1);
      expect(record.status).toBe("active");
      expect(record.policy.maxAmount).toBe("1000000");

      const retrieved = store.getPolicy("policy-alpha");
      expect(retrieved).not.toBeNull();
      expect(retrieved?.policyId).toBe("policy-alpha");
      expect(retrieved?.revision).toBe(1);
      expect(retrieved?.status).toBe("active");
      expect(retrieved?.policy.allowedTarget).toBe(basePolicy.allowedTarget.toLowerCase());

      const revisions = store.listPolicyRevisions("policy-alpha");
      expect(revisions).toHaveLength(1);
      expect(revisions[0].revision).toBe(1);
      expect(revisions[0].status).toBe("active");

      // Duplicate registration rejected
      expect(() => store.registerPolicy(basePolicy)).toThrow(
        "Policy 'policy-alpha' is already registered."
      );
    } finally {
      store.close();
    }
  });

  // 2. Successful update and rejection of stale revisions
  it("updates policy monotonically and rejects stale revisions", () => {
    const dbFile = databasePath();
    const store = new SQLitePolicyStore(dbFile, new TestClock(1000));

    try {
      store.registerPolicy(basePolicy);

      const updatedPolicy: DemoPolicy = {
        ...basePolicy,
        maxAmount: "2000000",
      };

      // Stale revision check (expecting revision 2 when current is 1)
      expect(() => store.updatePolicy(updatedPolicy, 2)).toThrow(
        "Stale revision for policy 'policy-alpha': expected revision 2, but current revision is 1."
      );

      // Successful update with matching expected revision
      const updatedRecord = store.updatePolicy(updatedPolicy, 1);
      expect(updatedRecord.revision).toBe(2);
      expect(updatedRecord.policy.maxAmount).toBe("2000000");
      expect(updatedRecord.status).toBe("active");

      // Verify current authoritative policy
      const current = store.getPolicy("policy-alpha");
      expect(current?.revision).toBe(2);
      expect(current?.policy.maxAmount).toBe("2000000");

      // Historical revision 1 is preserved immutably
      const rev1 = store.getPolicyRevision("policy-alpha", 1);
      expect(rev1?.revision).toBe(1);
      expect(rev1?.policy.maxAmount).toBe("1000000");

      // Historical revision 2 matches current
      const rev2 = store.getPolicyRevision("policy-alpha", 2);
      expect(rev2?.revision).toBe(2);
      expect(rev2?.policy.maxAmount).toBe("2000000");

      // Another update with now-stale revision 1 fails
      expect(() => store.updatePolicy({ ...updatedPolicy, maxAmount: "3000000" }, 1)).toThrow(
        "Stale revision for policy 'policy-alpha': expected revision 1, but current revision is 2."
      );
    } finally {
      store.close();
    }
  });

  // 3. Revocation immediately changing authoritative status
  it("revokes policy immediately and records the revocation in revision history", () => {
    const dbFile = databasePath();
    const store = new SQLitePolicyStore(dbFile, new TestClock(1000));

    try {
      store.registerPolicy(basePolicy);

      const revokedRecord = store.revokePolicy("policy-alpha", 1);
      expect(revokedRecord.status).toBe("revoked");
      expect(revokedRecord.revision).toBe(2);
      expect(revokedRecord.policy.revoked).toBe(true);

      const authoritative = store.getPolicy("policy-alpha");
      expect(authoritative?.status).toBe("revoked");
      expect(authoritative?.revision).toBe(2);

      // Attempting to update a revoked policy without restoring must fail
      expect(() => store.updatePolicy({ ...basePolicy, maxAmount: "999999" })).toThrow(
        "Cannot update revoked policy 'policy-alpha'; restore policy before updating."
      );

      // Repeated revocation is idempotent and does not create unnecessary revisions
      const repeatRevoke = store.revokePolicy("policy-alpha", 2);
      expect(repeatRevoke.status).toBe("revoked");
      expect(repeatRevoke.revision).toBe(2);
    } finally {
      store.close();
    }
  });

  // 4. Restoration generating a new revision
  it("restores a revoked policy generating a new revision distinct from the revoked revision", () => {
    const dbFile = databasePath();
    const store = new SQLitePolicyStore(dbFile, new TestClock(1000));

    try {
      store.registerPolicy(basePolicy); // Rev 1
      store.revokePolicy("policy-alpha", 1); // Rev 2 (revoked)

      // Restoring policy with updated limits generates Revision 3
      const updatedRestorePolicy: DemoPolicy = {
        ...basePolicy,
        maxAmount: "5000000",
      };
      const restored = store.restorePolicy("policy-alpha", updatedRestorePolicy, 2);
      expect(restored.status).toBe("active");
      expect(restored.revision).toBe(3);
      expect(restored.policy.maxAmount).toBe("5000000");
      expect(restored.policy.revoked).toBe(false);

      // Authoritative policy is now active at Rev 3
      const current = store.getPolicy("policy-alpha");
      expect(current?.status).toBe("active");
      expect(current?.revision).toBe(3);

      // Revision history holds all three revisions
      const revisions = store.listPolicyRevisions("policy-alpha");
      expect(revisions).toHaveLength(3);
      expect(revisions[0].revision).toBe(1);
      expect(revisions[0].status).toBe("active");
      expect(revisions[1].revision).toBe(2);
      expect(revisions[1].status).toBe("revoked");
      expect(revisions[2].revision).toBe(3);
      expect(revisions[2].status).toBe("active");

      // Cannot restore an already active policy
      expect(() => store.restorePolicy("policy-alpha")).toThrow(
        "Policy 'policy-alpha' is already active."
      );
    } finally {
      store.close();
    }
  });

  // 5. Retirement preventing subsequent updates or restoration
  it("retires policy permanently preventing subsequent updates, restorations, or revocations", () => {
    const dbFile = databasePath();
    const store = new SQLitePolicyStore(dbFile, new TestClock(1000));

    try {
      store.registerPolicy(basePolicy); // Rev 1
      const retired = store.retirePolicy("policy-alpha", 1); // Rev 2 (retired)

      expect(retired.status).toBe("retired");
      expect(retired.revision).toBe(2);

      const current = store.getPolicy("policy-alpha");
      expect(current?.status).toBe("retired");

      // Attempting to update a retired policy is rejected
      expect(() => store.updatePolicy({ ...basePolicy, maxAmount: "100" })).toThrow(
        "Cannot update retired policy 'policy-alpha'; retirement is terminal."
      );

      // Attempting to restore a retired policy is rejected
      expect(() => store.restorePolicy("policy-alpha")).toThrow(
        "Cannot restore retired policy 'policy-alpha'; retirement is terminal."
      );

      // Attempting to revoke a retired policy is rejected
      expect(() => store.revokePolicy("policy-alpha")).toThrow(
        "Cannot revoke retired policy 'policy-alpha'; retirement is terminal."
      );

      // Calling retirePolicy on already retired is idempotent
      const repeatRetire = store.retirePolicy("policy-alpha", 2);
      expect(repeatRetire.status).toBe("retired");
      expect(repeatRetire.revision).toBe(2);
    } finally {
      store.close();
    }
  });

  // 6. Deletion and recreation preserving monotonic revision history
  it("deletes a policy while preserving full revision history and requires strictly greater revision on recreation", () => {
    const dbFile = databasePath();
    const store = new SQLitePolicyStore(dbFile, new TestClock(1000));

    try {
      store.registerPolicy(basePolicy); // Rev 1
      store.updatePolicy({ ...basePolicy, maxAmount: "2000000" }, 1); // Rev 2

      // Delete policy from authoritative active policies table
      expect(store.deletePolicy("policy-alpha", 2)).toBe(true);

      // Authoritative lookup returns null
      expect(store.getPolicy("policy-alpha")).toBeNull();

      // Revision history remains completely intact
      const history = store.listPolicyRevisions("policy-alpha");
      expect(history).toHaveLength(2);
      expect(history[0].revision).toBe(1);
      expect(history[1].revision).toBe(2);

      // Recreating with revision <= 2 must fail
      expect(() => store.recreatePolicy(basePolicy, 1)).toThrow(
        "Cannot recreate deleted policy 'policy-alpha' with revision 1: must be strictly greater than historical maximum revision (2)."
      );
      expect(() => store.recreatePolicy(basePolicy, 2)).toThrow(
        "Cannot recreate deleted policy 'policy-alpha' with revision 2: must be strictly greater than historical maximum revision (2)."
      );

      // Recreating with revision 3 succeeds
      const recreated = store.recreatePolicy(basePolicy, 3);
      expect(recreated.policyId).toBe("policy-alpha");
      expect(recreated.revision).toBe(3);
      expect(recreated.status).toBe("active");

      // Verify that history now contains 3 revisions
      const updatedHistory = store.listPolicyRevisions("policy-alpha");
      expect(updatedHistory).toHaveLength(3);
      expect(updatedHistory[2].revision).toBe(3);
    } finally {
      store.close();
    }
  });

  // 7. Concurrent updates rejecting stale revisions
  it("concurrent updates across separate store instances reject stale revisions", () => {
    const dbFile = databasePath();
    const storeA = new SQLitePolicyStore(dbFile, new TestClock(1000));
    const storeB = new SQLitePolicyStore(dbFile, new TestClock(1000));

    try {
      storeA.registerPolicy(basePolicy); // Rev 1

      // Store A reads Rev 1 and updates to Rev 2
      const updatedA = storeA.updatePolicy({ ...basePolicy, maxAmount: "2000000" }, 1);
      expect(updatedA.revision).toBe(2);

      // Store B attempts to update assuming it was still on Rev 1
      expect(() => storeB.updatePolicy({ ...basePolicy, maxAmount: "3000000" }, 1)).toThrow(
        "Stale revision for policy 'policy-alpha': expected revision 1, but current revision is 2."
      );

      // Store B observes Rev 2 and succeeds updating to Rev 3
      const updatedB = storeB.updatePolicy({ ...basePolicy, maxAmount: "3000000" }, 2);
      expect(updatedB.revision).toBe(3);
    } finally {
      storeA.close();
      storeB.close();
    }
  });

  // 8. Rollback and data preservation after injected failures
  it("rolls back transaction and preserves existing data when validation or database failure occurs", () => {
    const dbFile = databasePath();
    const store = new SQLitePolicyStore(dbFile, new TestClock(1000));

    try {
      store.registerPolicy(basePolicy);

      // Injected validation error: invalid Ethereum address for target
      const invalidPolicy: DemoPolicy = {
        ...basePolicy,
        allowedTarget: "not-an-address",
      };

      expect(() => store.updatePolicy(invalidPolicy, 1)).toThrow(
        "Invalid policy: failed normalization."
      );

      // Current policy is unmodified
      const current = store.getPolicy("policy-alpha");
      expect(current?.revision).toBe(1);
      expect(current?.policy.maxAmount).toBe("1000000");

      // Check raw database state: exactly 1 revision exists
      const rawDb = new DatabaseSync(dbFile);
      try {
        const revCount = (
          rawDb.prepare("SELECT COUNT(*) AS c FROM policy_revisions WHERE policy_id = 'policy-alpha'").get() as { c: number }
        ).c;
        expect(revCount).toBe(1);
      } finally {
        rawDb.close();
      }
    } finally {
      store.close();
    }
  });

  // 9. Safe schema migration on older policies and policy_revisions tables
  it("safely migrates pre-existing older policies schema without dropping existing rows", () => {
    const dbFile = databasePath("older-policy-schema.sqlite");
    const rawDb = new DatabaseSync(dbFile);

    // Create an older table without updated_at column
    rawDb.exec(`
      CREATE TABLE policies (
        policy_id TEXT PRIMARY KEY,
        current_revision INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'active',
        policy_json TEXT NOT NULL
      );
      CREATE TABLE policy_revisions (
        policy_id TEXT NOT NULL,
        revision INTEGER NOT NULL,
        status TEXT NOT NULL,
        policy_json TEXT NOT NULL
      );
      INSERT INTO policies VALUES ('legacy-pol-1', 1, 'active', '${JSON.stringify(basePolicy)}');
      INSERT INTO policy_revisions VALUES ('legacy-pol-1', 1, 'active', '${JSON.stringify(basePolicy)}');
    `);
    rawDb.close();

    // Opening with SQLitePolicyStore triggers safe table rebuild migration
    const store = new SQLitePolicyStore(dbFile, new TestClock(1000));
    try {
      const pol = store.getPolicy("legacy-pol-1");
      expect(pol).not.toBeNull();
      expect(pol?.policyId).toBe("legacy-pol-1");
      expect(pol?.revision).toBe(1);
      expect(pol?.status).toBe("active");
      expect(pol?.updatedAt).toBeDefined();

      const revs = store.listPolicyRevisions("legacy-pol-1");
      expect(revs).toHaveLength(1);
      expect(revs[0].revision).toBe(1);
      expect(revs[0].createdAt).toBeDefined();

      // Ensure subsequent operations work seamlessly
      const updated = store.updatePolicy({ ...basePolicy, policyId: "legacy-pol-1", maxAmount: "888" }, 1);
      expect(updated.revision).toBe(2);
      expect(updated.policy.maxAmount).toBe("888");
    } finally {
      store.close();
    }
  });

  // 10. Mid-transaction failure rolls back partial writes, preserves original error, and keeps previous revision
  it("rolls back partial writes and preserves previous state when an error occurs mid-transaction during policy update", () => {
    const dbFile = databasePath();
    const store = new SQLitePolicyStore(dbFile, new TestClock(1000));

    try {
      store.registerPolicy(basePolicy); // Rev 1
      const initial = store.getPolicy("policy-alpha");
      expect(initial?.revision).toBe(1);

      // Install an SQLite trigger on policy_revisions that aborts when inserting revision 2
      const triggerDb = new DatabaseSync(dbFile);
      try {
        triggerDb.exec(`
          CREATE TRIGGER abort_rev_2
          BEFORE INSERT ON policy_revisions
          WHEN NEW.revision = 2
          BEGIN
            SELECT RAISE(ABORT, 'injected failure during policy_revisions insert');
          END;
        `);
      } finally {
        triggerDb.close();
      }

      // updatePolicy updates policies table first, then inserts into policy_revisions.
      // The trigger aborts mid-transaction during the second statement.
      expect(() => {
        store.updatePolicy({ ...basePolicy, maxAmount: "2000000" }, 1);
      }).toThrow(/injected failure during policy_revisions insert/);

      // Verify that policies table rolled back to revision 1 (partial write to policies did not persist)
      const afterFail = store.getPolicy("policy-alpha");
      expect(afterFail?.revision).toBe(1);
      expect(afterFail?.policy.maxAmount).toBe("1000000");

      // Verify policy_revisions has only 1 revision
      const revs = store.listPolicyRevisions("policy-alpha");
      expect(revs).toHaveLength(1);
      expect(revs[0].revision).toBe(1);

      // Drop the trigger and verify that subsequent transactions succeed cleanly
      const cleanupDb = new DatabaseSync(dbFile);
      try {
        cleanupDb.exec("DROP TRIGGER abort_rev_2;");
      } finally {
        cleanupDb.close();
      }

      const successUpdate = store.updatePolicy({ ...basePolicy, maxAmount: "2000000" }, 1);
      expect(successUpdate.revision).toBe(2);
      expect(successUpdate.policy.maxAmount).toBe("2000000");

      const finalRevs = store.listPolicyRevisions("policy-alpha");
      expect(finalRevs).toHaveLength(2);
      expect(finalRevs[1].revision).toBe(2);
    } finally {
      store.close();
    }
  });

  // =========================================================================
  // Milestone 6.10: SQLitePolicyStore Clock Guardrails & Cancellation Resiliency
  // =========================================================================
  describe("Milestone 6.10: SQLitePolicyStore Clock Guardrails & Cancellation Resiliency", () => {
    function createKeypair() {
      return generateKeyPairSync("ed25519");
    }

    const validRequest: TransactionRequest = {
      chainId: "1",
      sender: "0x3333333333333333333333333333333333333333",
      target: "0x1111111111111111111111111111111111111111",
      calldata:
        "0xa9059cbb" +
        "0000000000000000000000002222222222222222222222222222222222222222" +
        "0000000000000000000000000000000000000000000000000000000000000064",
      value: "0",
    };

    it("rejects all policy mutations (register, update, revoke, restore, retire, delete) when clock is rolled backward", () => {
      const dbFile = databasePath("policy-clock-rollback.sqlite");
      const clock = new TestClock(1000);
      const authStore = new SQLiteAuthorizationStore(dbFile, clock);
      const policyStore = authStore.getPolicyStore();

      try {
        // Advance high-water to 1050s via authStore
        authStore.advanceHighWaterMark(1050);
        expect(authStore.getHighWaterMark()).toBe(1050);
        expect(policyStore.getHighWaterMark()).toBe(1050);

        // 1. registerPolicy fails when clock is rolled backward (1020 < 1050)
        clock.set(1020);
        expect(() => policyStore.registerPolicy(basePolicy)).toThrow(
          "Clock rollback detected: current time (1020s) precedes persisted high-water mark (1050s)."
        );
        expect(policyStore.getPolicy(basePolicy.policyId)).toBeNull();
        expect(policyStore.getHighWaterMark()).toBe(1050);

        // Catch up clock and register policy successfully
        clock.set(1060);
        policyStore.registerPolicy(basePolicy);
        expect(policyStore.getPolicy(basePolicy.policyId)?.revision).toBe(1);
        expect(policyStore.getHighWaterMark()).toBe(1060);

        // 2. updatePolicy fails when clock is rolled backward (1040 < 1060)
        clock.set(1040);
        expect(() => policyStore.updatePolicy({ ...basePolicy, maxAmount: "999" }, 1)).toThrow(
          "Clock rollback detected: current time (1040s) precedes persisted high-water mark (1060s)."
        );
        expect(policyStore.getPolicy(basePolicy.policyId)?.revision).toBe(1);
        expect(policyStore.getPolicy(basePolicy.policyId)?.policy.maxAmount).toBe("1000000");

        // 3. revokePolicy fails when clock is rolled backward (1040 < 1060)
        expect(() => policyStore.revokePolicy(basePolicy.policyId, 1)).toThrow(
          "Clock rollback detected: current time (1040s) precedes persisted high-water mark (1060s)."
        );
        expect(policyStore.getPolicy(basePolicy.policyId)?.status).toBe("active");

        // Catch up clock and revoke policy successfully
        clock.set(1070);
        policyStore.revokePolicy(basePolicy.policyId, 1);
        expect(policyStore.getPolicy(basePolicy.policyId)?.status).toBe("revoked");
        expect(policyStore.getHighWaterMark()).toBe(1070);

        // 4. restorePolicy fails when clock is rolled backward (1050 < 1070)
        clock.set(1050);
        expect(() => policyStore.restorePolicy(basePolicy.policyId)).toThrow(
          "Clock rollback detected: current time (1050s) precedes persisted high-water mark (1070s)."
        );
        expect(policyStore.getPolicy(basePolicy.policyId)?.status).toBe("revoked");

        // Catch up clock and restore policy successfully
        clock.set(1080);
        policyStore.restorePolicy(basePolicy.policyId);
        expect(policyStore.getPolicy(basePolicy.policyId)?.status).toBe("active");
        expect(policyStore.getHighWaterMark()).toBe(1080);

        // 5. retirePolicy fails when clock is rolled backward (1060 < 1080)
        clock.set(1060);
        expect(() => policyStore.retirePolicy(basePolicy.policyId)).toThrow(
          "Clock rollback detected: current time (1060s) precedes persisted high-water mark (1080s)."
        );
        expect(policyStore.getPolicy(basePolicy.policyId)?.status).toBe("active");

        // 6. deletePolicy fails when clock is rolled backward (1060 < 1080)
        expect(() => policyStore.deletePolicy(basePolicy.policyId)).toThrow(
          "Clock rollback detected: current time (1060s) precedes persisted high-water mark (1080s)."
        );
        expect(policyStore.getPolicy(basePolicy.policyId)).not.toBeNull();
      } finally {
        authStore.close();
      }
    });

    it("rejects all policy mutations and trips guard on suspicious forward clock step", () => {
      const dbFile = databasePath("policy-clock-jump.sqlite");
      const clock = new TestClock(1000);
      const authStore = new SQLiteAuthorizationStore(dbFile, clock);
      const policyStore = authStore.getPolicyStore();
      const guard = authStore.getClockGuard();

      try {
        // Register initial policy
        policyStore.registerPolicy(basePolicy);
        expect(guard.getState()).toBe("ACTIVE");
        expect(policyStore.getHighWaterMark()).toBe(1000);

        // Simulate wall-clock forward jump of 50s without monotonic advance (step divergence = 50s > 10s limit)
        clock.advanceWallSeconds(50); // wall = 1050, monotonic = 1000s

        // Attempting updatePolicy trips guard
        expect(() => policyStore.updatePolicy({ ...basePolicy, maxAmount: "555" }, 1)).toThrow(
          "Suspicious forward clock jump detected: step velocity divergence of 50s exceeds forward limit (10s)."
        );

        // Guard must be tripped
        expect(guard.getState()).toBe("TRIPPED_CLOSED");
        expect(guard.getTripReason()).toContain("Suspicious forward clock jump detected");

        // High-water mark remains unchanged
        expect(policyStore.getHighWaterMark()).toBe(1000);
        // Policy was not updated
        expect(policyStore.getPolicy(basePolicy.policyId)?.policy.maxAmount).toBe("1000000");

        // Subsequent mutations fail closed immediately
        expect(() => policyStore.registerPolicy({ ...basePolicy, policyId: "policy-new" })).toThrow(
          "Store clock monitor is in a tripped state"
        );
        expect(() => policyStore.revokePolicy(basePolicy.policyId)).toThrow(
          "Store clock monitor is in a tripped state"
        );
        expect(() => policyStore.restorePolicy(basePolicy.policyId)).toThrow(
          "Store clock monitor is in a tripped state"
        );
        expect(() => policyStore.retirePolicy(basePolicy.policyId)).toThrow(
          "Store clock monitor is in a tripped state"
        );
        expect(() => policyStore.deletePolicy(basePolicy.policyId)).toThrow(
          "Store clock monitor is in a tripped state"
        );
      } finally {
        authStore.close();
      }
    });

    it("does not publish candidate or activate guard if transaction fails or rolls back", () => {
      const dbFile = databasePath("policy-init-rollback.sqlite");
      const clock = new TestClock(1000);
      const authStore = new SQLiteAuthorizationStore(dbFile, clock);
      const guard = authStore.getClockGuard();
      const policyStore = authStore.getPolicyStore();

      try {
        expect(guard.getState()).toBe("UNINITIALIZED");
        expect(guard.getInitialSample()).toBeNull();
        expect(guard.getPublishedSample()).toBeNull();

        // 1. Business validation failure (invalid policy) rolls back
        expect(() => policyStore.registerPolicy({ ...basePolicy, version: 99 as any })).toThrow(
          "Invalid policy: failed normalization."
        );
        expect(guard.getState()).toBe("UNINITIALIZED");
        expect(guard.getInitialSample()).toBeNull();
        expect(guard.getPublishedSample()).toBeNull();

        // 2. Successful transaction transitions to ACTIVE and publishes candidate
        policyStore.registerPolicy(basePolicy);
        expect(guard.getState()).toBe("ACTIVE");
        expect(guard.getInitialSample()?.wallSeconds).toBe(1000);
        expect(guard.getPublishedSample()?.wallSeconds).toBe(1000);
      } finally {
        authStore.close();
      }
    });

    it("preserves published sample and persistent high-water after business validation failure", () => {
      const dbFile = databasePath("policy-preserve-sample.sqlite");
      const clock = new TestClock(1000);
      const authStore = new SQLiteAuthorizationStore(dbFile, clock);
      const guard = authStore.getClockGuard();
      const policyStore = authStore.getPolicyStore();

      try {
        policyStore.registerPolicy(basePolicy);
        expect(guard.getState()).toBe("ACTIVE");
        expect(guard.getPublishedSample()?.wallSeconds).toBe(1000);
        expect(policyStore.getHighWaterMark()).toBe(1000);

        // Advance clock smoothly to 1005s
        clock.advance(5);

        // Attempt invalid update with stale revision (expected 99, actual 1)
        expect(() => policyStore.updatePolicy({ ...basePolicy, maxAmount: "777" }, 99)).toThrow(
          "Stale revision for policy 'policy-alpha': expected revision 99, but current revision is 1."
        );

        // Published sample must remain at 1000s, NOT advanced to 1005s
        expect(guard.getPublishedSample()?.wallSeconds).toBe(1000);
        expect(policyStore.getHighWaterMark()).toBe(1000);

        // Successful update with correct revision advances to 1005s
        policyStore.updatePolicy({ ...basePolicy, maxAmount: "777" }, 1);
        expect(guard.getPublishedSample()?.wallSeconds).toBe(1005);
        expect(policyStore.getHighWaterMark()).toBe(1005);
      } finally {
        authStore.close();
      }
    });

    it("taints PolicyStore, closes connection, and propagates taint to parent store on uncertain COMMIT", () => {
      const dbFile = databasePath("policy-commit-fail.sqlite");
      let fatalCallbackCalled = false;
      const authStore = new SQLiteAuthorizationStore(dbFile, {
        clock: new TestClock(1000),
        onFatalTaint: () => {
          fatalCallbackCalled = true;
          throw new Error("Fatal callback threw unexpectedly");
        },
      });

      const policyStore = authStore.getPolicyStore();

      try {
        // Intercept COMMIT on SQLite connection to simulate uncertain commit failure
        const db = authStore.getDatabase();
        const originalExec = db.exec.bind(db);
        db.exec = (sql: string) => {
          if (typeof sql === "string" && sql.includes("COMMIT;")) {
            throw new Error("Simulated uncertain commit failure disk I/O error");
          }
          return originalExec(sql);
        };

        expect(() => policyStore.registerPolicy(basePolicy)).toThrow(
          "Simulated uncertain commit failure disk I/O error"
        );

        // PolicyStore must be tainted
        expect(policyStore.isTainted()).toBe(true);
        expect(() => policyStore.getPolicy("policy-alpha")).toThrow("database connection is tainted and unusable");

        // Parent store must also be tainted
        expect(authStore.isTainted()).toBe(true);
        expect(authStore.getClockGuard().isTainted()).toBe(true);
        expect(() => authStore.getHighWaterMark()).toThrow("database connection is tainted and unusable");

        // Fatal callback was invoked and caught without preventing fail-closed state
        expect(fatalCallbackCalled).toBe(true);
      } finally {
        try { authStore.close(); } catch {}
      }
    });

    it("cancellation throws explicit error on tainted, tripped, or expired store while preserving boolean outcomes for ordinary states", () => {
      const dbFile = databasePath("cancellation-resiliency.sqlite");
      const clock = new TestClock(1000);
      const authStore = new SQLiteAuthorizationStore(dbFile, clock);
      const key = createKeypair();

      try {
        authStore.getPolicyStore().registerPolicy(basePolicy);
        authStore.getKeyStore().registerKey({
          keyId: "key-cancel-resil",
          publicKey: key.publicKey,
          status: "active",
        });

        // Issue an authorization
        const issued = issueSignedTransactionAuthorizationV3(
          authStore,
          { keyId: "key-cancel-resil", privateKey: key.privateKey },
          "auth-cancel-resil-1",
          basePolicy.policyId,
          validRequest,
        );
        expect(issued.decision).toBe("ALLOW");

        // 1. Normal cancellation of valid issued auth -> returns true
        expect(authStore.cancelAuthorization("auth-cancel-resil-1")).toBe(true);

        // 2. Normal repeated cancellation of already-cancelled auth -> returns false
        expect(authStore.cancelAuthorization("auth-cancel-resil-1")).toBe(false);

        // 3. Normal cancellation of unknown auth -> returns false
        expect(authStore.cancelAuthorization("unknown-auth-id")).toBe(false);

        // 4. When ClockGuard is tripped into TRIPPED_CLOSED -> throws explicit error!
        authStore.getClockGuard().trip("Simulated hypervisor pause clock jump trip");
        expect(() => authStore.cancelAuthorization("auth-cancel-resil-1")).toThrow(
          "Store clock monitor is in a tripped state: Simulated hypervisor pause clock jump trip"
        );

        // 5. When store connection is tainted -> throws explicit error!
        const taintedStore = new SQLiteAuthorizationStore(databasePath("taint-cancel.sqlite"), new TestClock(1000));
        taintedStore.markTainted("Disk corruption detected");
        expect(() => taintedStore.cancelAuthorization("auth-any")).toThrow(
          "SQLiteAuthorizationStore database connection is tainted and unusable: Disk corruption detected"
        );
      } finally {
        authStore.close();
      }
    });

    it("throws explicit clock-expiry error and preserves authorization state when ClockGuard expires", () => {
      const dbFile = databasePath("cancellation-expired.sqlite");
      const clock = new TestClock(1000);
      const clockGuard = new ClockGuard(clock, undefined, {
        maxAnchorLifetimeSeconds: 10,
      });
      const authStore = new SQLiteAuthorizationStore(dbFile, {
        clock,
        clockGuard,
      });
      const key = createKeypair();

      try {
        authStore.getPolicyStore().registerPolicy(basePolicy);
        authStore.getKeyStore().registerKey({
          keyId: "key-expire-test",
          publicKey: key.publicKey,
          status: "active",
        });

        // Issue a valid V3 authorization at t=1000
        const issued = issueSignedTransactionAuthorizationV3(
          authStore,
          { keyId: "key-expire-test", privateKey: key.privateKey },
          "auth-expire-target",
          basePolicy.policyId,
          validRequest,
        );
        expect(issued.decision).toBe("ALLOW");

        // Verify guard transitioned to ACTIVE and record is issued
        expect(authStore.getClockGuard().getState()).toBe("ACTIVE");
        expect(authStore.getAuthorizationRecord("auth-expire-target")?.state).toBe("issued");

        // Advance clock past maxAnchorLifetimeSeconds (10s) to 1015s
        clock.advance(15);

        // Put ClockGuard into genuine EXPIRED state via candidate evaluation
        expect(() => authStore.advanceHighWaterMark(1015)).toThrow(
          "Process clock anchor has expired (maximum uptime exceeded); restart required."
        );
        expect(authStore.getClockGuard().getState()).toBe("EXPIRED");

        // Assert direct cancelAuthorization throws explicit expiry error
        expect(() => authStore.cancelAuthorization("auth-expire-target")).toThrow(
          "Process clock anchor has expired (maximum uptime exceeded); restart required."
        );

        // Assert lifecycle wrapper cancelAuthorization also throws explicit expiry error
        expect(() => cancelAuthorization(authStore, "auth-expire-target")).toThrow(
          "Process clock anchor has expired (maximum uptime exceeded); restart required."
        );

        // Assert persistent authorization record state is completely UNCHANGED in SQLite
        const record = authStore.getAuthorizationRecord("auth-expire-target");
        expect(record?.state).toBe("issued");
      } finally {
        authStore.close();
      }
    });

    it("enforces store health precedence over input validation in lifecycle wrapper cancelAuthorization", () => {
      const dbFile = databasePath("cancellation-wrapper-precedence.sqlite");
      const clock = new TestClock(1000);
      const clockGuard = new ClockGuard(clock, undefined, {
        maxAnchorLifetimeSeconds: 10,
      });
      const authStore = new SQLiteAuthorizationStore(dbFile, {
        clock,
        clockGuard,
      });
      const key = createKeypair();

      try {
        authStore.getPolicyStore().registerPolicy(basePolicy);
        authStore.getKeyStore().registerKey({
          keyId: "key-wrapper-test",
          publicKey: key.publicKey,
          status: "active",
        });

        // Issue a valid authorization
        const issued = issueSignedTransactionAuthorizationV3(
          authStore,
          { keyId: "key-wrapper-test", privateKey: key.privateKey },
          "auth-valid-id",
          basePolicy.policyId,
          validRequest,
        );
        expect(issued.decision).toBe("ALLOW");

        // 1. Healthy store + invalid ID returns false (both wrapper, alias, and direct store)
        expect(cancelAuthorization(authStore, "")).toBe(false);
        expect(cancelAuthorization(authStore, "   ")).toBe(false);
        expect(cancelAuthorization(authStore, null)).toBe(false);
        expect(cancelAuthorization(authStore, 123)).toBe(false);
        expect(cancelSignedTransactionAuthorizationV3(authStore, "")).toBe(false);
        expect(authStore.cancelAuthorization("")).toBe(false);

        // 2. Tainted store + invalid ID throws (does NOT mask failure as false)
        const taintedStore = new SQLiteAuthorizationStore(databasePath("tainted-wrapper.sqlite"), new TestClock(1000));
        try {
          taintedStore.markTainted("Injected connection corruption");
          expect(() => cancelAuthorization(taintedStore, "")).toThrow(
            "SQLiteAuthorizationStore database connection is tainted and unusable: Injected connection corruption"
          );
          expect(() => cancelAuthorization(taintedStore, null)).toThrow(
            "SQLiteAuthorizationStore database connection is tainted and unusable: Injected connection corruption"
          );
          expect(() => cancelSignedTransactionAuthorizationV3(taintedStore, "")).toThrow(
            "SQLiteAuthorizationStore database connection is tainted and unusable: Injected connection corruption"
          );
          expect(() => taintedStore.cancelAuthorization("")).toThrow(
            "SQLiteAuthorizationStore database connection is tainted and unusable: Injected connection corruption"
          );
        } finally {
          try { taintedStore.close(); } catch {}
        }

        // 3. TRIPPED_CLOSED store + invalid ID throws (does NOT mask failure as false)
        const trippedStore = new SQLiteAuthorizationStore(databasePath("tripped-wrapper.sqlite"), new TestClock(1000));
        try {
          trippedStore.getClockGuard().trip("Simulated clock jump trip");
          expect(() => cancelAuthorization(trippedStore, "")).toThrow(
            "Store clock monitor is in a tripped state: Simulated clock jump trip"
          );
          expect(() => cancelAuthorization(trippedStore, null)).toThrow(
            "Store clock monitor is in a tripped state: Simulated clock jump trip"
          );
          expect(() => cancelSignedTransactionAuthorizationV3(trippedStore, "")).toThrow(
            "Store clock monitor is in a tripped state: Simulated clock jump trip"
          );
          expect(() => trippedStore.cancelAuthorization("")).toThrow(
            "Store clock monitor is in a tripped state: Simulated clock jump trip"
          );
        } finally {
          try { trippedStore.close(); } catch {}
        }

        // 4. EXPIRED store + invalid ID throws (does NOT mask failure as false)
        clock.advance(15);
        expect(() => authStore.advanceHighWaterMark(1015)).toThrow("Process clock anchor has expired");
        expect(authStore.getClockGuard().getState()).toBe("EXPIRED");

        expect(() => cancelAuthorization(authStore, "")).toThrow(
          "Process clock anchor has expired (maximum uptime exceeded); restart required."
        );
        expect(() => cancelAuthorization(authStore, null)).toThrow(
          "Process clock anchor has expired (maximum uptime exceeded); restart required."
        );
        expect(() => cancelSignedTransactionAuthorizationV3(authStore, "")).toThrow(
          "Process clock anchor has expired (maximum uptime exceeded); restart required."
        );
        expect(() => authStore.cancelAuthorization("")).toThrow(
          "Process clock anchor has expired (maximum uptime exceeded); restart required."
        );

        // 5. Existing valid-ID cancellation behavior and record state
        const freshStore = new SQLiteAuthorizationStore(databasePath("fresh-cancel.sqlite"), new TestClock(1000));
        try {
          freshStore.getPolicyStore().registerPolicy(basePolicy);
          freshStore.getKeyStore().registerKey({
            keyId: "key-fresh",
            publicKey: key.publicKey,
            status: "active",
          });
          issueSignedTransactionAuthorizationV3(
            freshStore,
            { keyId: "key-fresh", privateKey: key.privateKey },
            "auth-fresh-1",
            basePolicy.policyId,
            validRequest,
          );
          expect(cancelAuthorization(freshStore, "auth-fresh-1")).toBe(true);
          expect(cancelAuthorization(freshStore, "auth-fresh-1")).toBe(false);
          expect(cancelAuthorization(freshStore, "unknown-auth-id")).toBe(false);
          expect(freshStore.getAuthorizationRecord("auth-fresh-1")?.state).toBe("cancelled");
        } finally {
          freshStore.close();
        }
      } finally {
        authStore.close();
      }
    });

    it("V3 policy restoration increments revision and permanently invalidates prior unconsumed authorizations", () => {
      const dbFile = databasePath("policy-restoration-invalidation.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLiteAuthorizationStore(dbFile, clock);
      const key = createKeypair();

      try {
        const policyStore = store.getPolicyStore();
        policyStore.registerPolicy(basePolicy); // Revision 1
        store.getKeyStore().registerKey({
          keyId: "key-restore-test",
          publicKey: key.publicKey,
          status: "active",
        });

        // 1. Issue V3 authorization under Revision 1
        const issued = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "key-restore-test", privateKey: key.privateKey },
          "auth-rev1-target",
          basePolicy.policyId,
          validRequest,
        );
        expect(issued.decision).toBe("ALLOW");
        if (issued.decision !== "ALLOW") return;
        expect(issued.artifact.policyRevision).toBe(1);

        // 2. Revoke policy -> Revision 2
        clock.advance(5);
        const revoked = policyStore.revokePolicy(basePolicy.policyId, 1);
        expect(revoked.revision).toBe(2);
        expect(revoked.status).toBe("revoked");

        // Consumption is rejected while policy is revoked
        const tryConsumeWhileRevoked = consumeSignedTransactionAuthorizationV3(
          store,
          issued.artifact,
          issued.envelope,
          validRequest,
        );
        expect(tryConsumeWhileRevoked.decision).toBe("DENY");
        expect(tryConsumeWhileRevoked.reasons).toContain("Policy has been revoked.");

        // 3. Restore policy -> Revision 3
        clock.advance(5);
        const restored = policyStore.restorePolicy(basePolicy.policyId);
        expect(restored.revision).toBe(3);
        expect(restored.status).toBe("active");

        // 4. Attempt to consume the artifact issued under Revision 1:
        // Must be permanently rejected due to revision mismatch!
        clock.advance(5);
        const tryConsumeAfterRestore = consumeSignedTransactionAuthorizationV3(
          store,
          issued.artifact,
          issued.envelope,
          validRequest,
        );
        expect(tryConsumeAfterRestore.decision).toBe("DENY");
        expect(tryConsumeAfterRestore.reasons[0]).toContain(
          "Policy revision mismatch: artifact bound to revision 1, but current policy revision is 3."
        );

        // Record in SQLite remains in 'issued' state (was never consumed)
        const record = store.getAuthorizationRecord("auth-rev1-target");
        expect(record?.state).toBe("issued");
      } finally {
        store.close();
      }
    });
  });

  describe("Milestone 6.11 Stage A: Standalone ClockGuard & Cancellation Concurrency Safety", () => {
    it("enforces ClockGuard protections on standalone SQLitePolicyStore when constructed without an explicit guard", () => {
      const dbFile = databasePath("standalone-policy-clockguard.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLitePolicyStore(dbFile, clock);

      try {
        expect(store.getClockGuard()).toBeDefined();
        expect(store.getClockGuard().getState()).toBe("UNINITIALIZED");

        // Initial mutation registers candidate and activates ClockGuard
        store.registerPolicy({
          ...basePolicy,
          policyId: "standalone-policy-1",
        });

        expect(store.getClockGuard().getState()).toBe("ACTIVE");
        expect(store.getHighWaterMark()).toBe(1000);

        // Advance wall clock abruptly without monotonic advance (+50s step divergence > 10s ceiling)
        clock.advanceWallSeconds(50);

        expect(() => {
          store.registerPolicy({
            ...basePolicy,
            policyId: "standalone-policy-2",
          });
        }).toThrow(
          "Suspicious forward clock jump detected: step velocity divergence of 50s exceeds forward limit (10s)."
        );

        // Guard must be tripped closed
        expect(store.getClockGuard().getState()).toBe("TRIPPED_CLOSED");

        // Subsequent operations fail closed immediately
        expect(() => {
          store.getPolicy("standalone-policy-1");
        }).not.toThrow(); // read-only is allowed if untainted
        expect(() => {
          store.updatePolicy({
            ...basePolicy,
            policyId: "standalone-policy-1",
            maxAmount: "2000000",
          });
        }).toThrow("Store clock monitor is in a tripped state");

        // High-water mark remains untampered at 1000
        expect(store.getHighWaterMark()).toBe(1000);
      } finally {
        store.close();
      }
    });

    it("enforces startup forward-gap validation on standalone SQLitePolicyStore against existing databases", () => {
      const dbFile = databasePath("standalone-policy-startup-gap.sqlite");
      const clock = new TestClock(1000);
      const initStore = new SQLitePolicyStore(dbFile, clock);
      try {
        initStore.registerPolicy({
          ...basePolicy,
          policyId: "gap-policy-target",
        });
      } finally {
        initStore.close();
      }

      // Reopen with clock jumping forward by 4000s (> 3600s maxStartupForwardGapSeconds)
      const forwardClock = new TestClock(5000);
      expect(() => {
        new SQLitePolicyStore(dbFile, forwardClock);
      }).toThrow(
        "Store startup rejected: forward clock gap of 4000 seconds exceeds maximum allowed startup threshold (3600s)."
      );

      // Reopen with configured gap threshold accommodates the forward gap
      const allowedStore = new SQLitePolicyStore(dbFile, {
        clock: forwardClock,
        maxStartupForwardGapSeconds: 5000,
      });
      try {
        expect(allowedStore.getPolicy("gap-policy-target")?.policyId).toBe("gap-policy-target");
      } finally {
        allowedStore.close();
      }
    });

    it("enforces process-local mutual exclusion during cancelAuthorization when ClockGuard lock is held", () => {
      const dbFile = databasePath("cancel-lock-serialization.sqlite");
      const clock = new TestClock(1000);
      const authStore = new SQLiteAuthorizationStore(dbFile, clock);

      try {
        expect(authStore.issueBound("auth-cancel-lock-1", "sha256:digest1", 3)).toBe(true);

        // Acquire lock to simulate concurrent in-progress transaction on the same connection
        const lockAcquired = authStore.getClockGuard().acquireLock();
        expect(lockAcquired).toBe(true);

        // Direct cancelAuthorization must throw fail-closed serialization error
        expect(() => {
          authStore.cancelAuthorization("auth-cancel-lock-1");
        }).toThrow(
          "Concurrent transaction in progress within same process; ClockGuard lock acquisition failed."
        );

        // Lifecycle wrapper cancelAuthorization must also throw fail-closed serialization error
        expect(() => {
          cancelAuthorization(authStore, "auth-cancel-lock-1");
        }).toThrow(
          "Concurrent transaction in progress within same process; ClockGuard lock acquisition failed."
        );

        // Record must remain in 'issued' state
        expect(authStore.getAuthorizationRecord("auth-cancel-lock-1")?.state).toBe("issued");

        // Release the lock
        authStore.getClockGuard().releaseLock();

        // Cancellation now proceeds and succeeds
        expect(authStore.cancelAuthorization("auth-cancel-lock-1")).toBe(true);
        expect(authStore.getAuthorizationRecord("auth-cancel-lock-1")?.state).toBe("cancelled");
      } finally {
        authStore.close();
      }
    });

    it("configures PRAGMA journal_mode = WAL and synchronous = FULL by default on standalone SQLitePolicyStore", () => {
      const dbFile = databasePath("standalone-policy-durability.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLitePolicyStore(dbFile, clock);

      try {
        expect(store.getJournalMode()).toBe("wal");
        expect(store.getSynchronousMode()).toBe("FULL");
      } finally {
        store.close();
      }

      // Explicit NORMAL configuration
      const normalStore = new SQLitePolicyStore(dbFile, {
        clock,
        synchronous: "NORMAL",
      });
      try {
        expect(normalStore.getSynchronousMode()).toBe("NORMAL");
      } finally {
        normalStore.close();
      }
    });
  });
});
