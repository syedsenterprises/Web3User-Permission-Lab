import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { TestClock } from "../src/clock.js";
import { type DemoPolicy } from "../src/policy.js";
import { SQLitePolicyStore } from "../src/policy-store.js";

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
});
