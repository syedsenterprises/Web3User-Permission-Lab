import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

// Verify root index exports
import {
  Web3UserEngine,
  Web3UserError,
  EngineClosedError,
  ValidationError,
  ContentionError,
  ClockGuardError,
  StoreTaintedError,
  wrapEngineError,
  generateIssuerKeyPair,
  TestClock,
  type DemoPolicy,
  type TransactionRequest,
} from "../src/index.js";
import {
  issueSignedTransactionAuthorizationV3,
  consumeSignedTransactionAuthorizationV3,
} from "../src/authorization-lifecycle.js";
import { SQLiteAuthorizationStore } from "../src/authorization-store.js";
import { createTransactionEnvelope } from "../src/transaction-envelope.js";

describe("Milestone 6.12-A: Web3UserEngine Public SDK Foundation", () => {
  let tempDir: string | undefined;

  function databasePath(filename = "engine-test.sqlite"): string {
    tempDir ??= mkdtempSync(join(tmpdir(), "web3user-engine-"));
    return join(tempDir, filename);
  }

  afterEach(() => {
    if (tempDir) {
      rmSync(tempDir, { recursive: true, force: true });
      tempDir = undefined;
    }
  });

  const validPolicy: DemoPolicy = {
    version: 1,
    policyId: "policy-erc20-demo",
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

  // 1. Root exports and open/close lifecycle
  describe("Engine Lifecycle & Resource Ownership", () => {
    it("opens engine and initializes schema with default FULL durability", () => {
      const dbPath = databasePath();
      const engine = Web3UserEngine.open({ databasePath: dbPath });

      try {
        expect(engine.isOpen()).toBe(true);
        expect(engine.storage.isTainted()).toBe(false);
        expect(engine.storage.getSynchronousMode()).toBe("FULL");
        expect(engine.storage.getJournalMode().toLowerCase()).toBe("wal");
        expect(engine.storage.checkIntegrity()).toBe(true);
      } finally {
        engine.close();
      }
    });

    it("makes engine closure idempotent and subsequent operations throw EngineClosedError", () => {
      const dbPath = databasePath();
      const engine = Web3UserEngine.open({ databasePath: dbPath });

      expect(engine.isOpen()).toBe(true);
      engine.close();
      expect(engine.isOpen()).toBe(false);

      // Repeated close() does not throw
      expect(() => engine.close()).not.toThrow();

      // Subsequent operations fail closed with EngineClosedError
      expect(() => engine.issue({} as any)).toThrow(EngineClosedError);
      expect(() => engine.consume({} as any)).toThrow(EngineClosedError);
      expect(() => engine.cancel("auth-01")).toThrow(EngineClosedError);
      expect(() => engine.getAuthorizationRecord("auth-01")).toThrow(EngineClosedError);
      expect(() => engine.policies.get("any")).toThrow(EngineClosedError);
      expect(() => engine.keys.get("any")).toThrow(EngineClosedError);
      expect(() => engine.storage.checkIntegrity()).toThrow(EngineClosedError);
      expect(() => engine.storage.checkpoint()).toThrow(EngineClosedError);
      expect(() => engine.getStore()).toThrow(EngineClosedError);
    });

    it("supports Symbol.dispose pattern", () => {
      const dbPath = databasePath();
      let engineRef: Web3UserEngine;

      {
        const engine = Web3UserEngine.open({ databasePath: dbPath });
        engineRef = engine;
        expect(engine.isOpen()).toBe(true);
        engine[Symbol.dispose]();
      }

      expect(engineRef.isOpen()).toBe(false);
      expect(() => engineRef.policies.get("any")).toThrow(EngineClosedError);
    });
  });

  // 2. End-to-End V3 Authorization Flow through Facade
  describe("V3 Authorization Lifecycle", () => {
    it("manages complete V3 lifecycle: policy, keys, issuance, consumption, and replay denial", () => {
      const dbPath = databasePath();
      const clock = new TestClock(1500);
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        clock: { clock },
      });

      try {
        // Register policy
        const policyRecord = engine.policies.register(validPolicy);
        expect(policyRecord.policyId).toBe("policy-erc20-demo");
        expect(policyRecord.revision).toBe(1);

        // Generate and register key
        const keypair = engine.keys.generate();
        engine.keys.register({
          keyId: "key-v3-facade-01",
          publicKey: keypair.publicKey,
          status: "active",
          validFromSeconds: 1000,
          expiresAtSeconds: 8000,
        });

        // Issue authorization
        const issueResult = engine.issue({
          authorizationId: "auth-facade-001",
          policyId: "policy-erc20-demo",
          request: validRequest,
          signer: {
            keyId: "key-v3-facade-01",
            privateKey: keypair.privateKey,
          },
          ttlSeconds: 300,
        });

        expect(issueResult.decision).toBe("ALLOW");
        if (issueResult.decision !== "ALLOW") return;

        expect(issueResult.artifact.version).toBe(3);
        expect(issueResult.artifact.authorizationId).toBe("auth-facade-001");
        expect(issueResult.artifact.policyRevision).toBe(1);

        // Check persisted record
        const record = engine.getAuthorizationRecord("auth-facade-001");
        expect(record?.state).toBe("issued");

        // First consumption succeeds
        const consume1 = engine.consume({
          artifact: issueResult.artifact,
          envelope: issueResult.envelope,
          request: validRequest,
        });
        expect(consume1.decision).toBe("ALLOW");

        // Second consumption fails closed (single-use replay protection)
        const consume2 = engine.consume({
          artifact: issueResult.artifact,
          envelope: issueResult.envelope,
          request: validRequest,
        });
        expect(consume2.decision).toBe("DENY");
        expect(consume2.reasons.some((r) => r.toLowerCase().includes("consumed"))).toBe(true);

        // Record is now 'consumed'
        expect(engine.getAuthorizationRecord("auth-facade-001")?.state).toBe("consumed");
      } finally {
        engine.close();
      }
    });

    it("automatically derives transaction envelope when omitted in consume()", () => {
      const dbPath = databasePath();
      const clock = new TestClock(1500);
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        clock: { clock },
      });

      try {
        engine.policies.register(validPolicy);
        const keypair = engine.keys.generate();
        engine.keys.register({
          keyId: "key-auto-env",
          publicKey: keypair.publicKey,
          status: "active",
        });

        const issueResult = engine.issue({
          authorizationId: "auth-auto-env-001",
          policyId: "policy-erc20-demo",
          request: validRequest,
          signer: {
            keyId: "key-auto-env",
            privateKey: keypair.privateKey,
          },
        });
        expect(issueResult.decision).toBe("ALLOW");
        if (issueResult.decision !== "ALLOW") return;

        // Consume WITHOUT supplying envelope parameter
        const consumeResult = engine.consume({
          artifact: issueResult.artifact,
          request: validRequest,
        });
        expect(consumeResult.decision).toBe("ALLOW");
      } finally {
        engine.close();
      }
    });

    it("denies consumption if supplied envelope does not match candidate request", () => {
      const dbPath = databasePath();
      const clock = new TestClock(1500);
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        clock: { clock },
      });

      try {
        engine.policies.register(validPolicy);
        const keypair = engine.keys.generate();
        engine.keys.register({
          keyId: "key-mismatch-env",
          publicKey: keypair.publicKey,
          status: "active",
        });

        const issueResult = engine.issue({
          authorizationId: "auth-mismatch-env",
          policyId: "policy-erc20-demo",
          request: validRequest,
          signer: {
            keyId: "key-mismatch-env",
            privateKey: keypair.privateKey,
          },
        });
        expect(issueResult.decision).toBe("ALLOW");
        if (issueResult.decision !== "ALLOW") return;

        // Tamper with candidate request amount
        const tamperedRequest: TransactionRequest = {
          ...validRequest,
          calldata: `0xa9059cbb${recipientPadded}${"0".repeat(63)}1`, // 1 token
        };

        const consumeResult = engine.consume({
          artifact: issueResult.artifact,
          envelope: issueResult.envelope,
          request: tamperedRequest,
        });

        expect(consumeResult.decision).toBe("DENY");
        expect(consumeResult.reasons).toContain("Transaction does not match the original envelope.");
      } finally {
        engine.close();
      }
    });

    it("cancels issued authorization and blocks subsequent consumption", () => {
      const dbPath = databasePath();
      const clock = new TestClock(1500);
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        clock: { clock },
      });

      try {
        engine.policies.register(validPolicy);
        const keypair = engine.keys.generate();
        engine.keys.register({
          keyId: "key-cancel-test",
          publicKey: keypair.publicKey,
          status: "active",
        });

        const issueResult = engine.issue({
          authorizationId: "auth-to-cancel",
          policyId: "policy-erc20-demo",
          request: validRequest,
          signer: {
            keyId: "key-cancel-test",
            privateKey: keypair.privateKey,
          },
        });
        expect(issueResult.decision).toBe("ALLOW");
        if (issueResult.decision !== "ALLOW") return;

        // Cancel the authorization
        expect(engine.cancel("auth-to-cancel")).toBe(true);
        expect(engine.getAuthorizationRecord("auth-to-cancel")?.state).toBe("cancelled");

        // Attempting to consume cancelled authorization fails closed
        const consumeResult = engine.consume({
          artifact: issueResult.artifact,
          request: validRequest,
        });
        expect(consumeResult.decision).toBe("DENY");

        // Cancelling already cancelled returns false
        expect(engine.cancel("auth-to-cancel")).toBe(false);
      } finally {
        engine.close();
      }
    });
  });

  // 3. Error Contract & Validation
  describe("Error Contract & Validation Boundaries", () => {
    it("throws ValidationError for invalid input parameters", () => {
      const dbPath = databasePath();
      const engine = Web3UserEngine.open({ databasePath: dbPath });

      try {
        expect(() => engine.cancel("   ")).toThrow(ValidationError);
        expect(() => engine.cancel("a".repeat(129))).toThrow(ValidationError);
        expect(() => engine.getAuthorizationRecord("")).toThrow(ValidationError);
        expect(() => engine.issue({} as any)).toThrow(ValidationError);
        expect(() => engine.consume(null as any)).toThrow(ValidationError);
        expect(engine.consume({} as any).decision).toBe("UNKNOWN");
      } finally {
        engine.close();
      }
    });

    it("throws ClockGuardError on clock rollback attempt in policy operations", () => {
      const dbPath = databasePath();
      const clock = new TestClock(2000);
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        clock: { clock },
      });

      try {
        engine.policies.register(validPolicy);

        // Wind clock backwards
        clock.nowSeconds = () => 1000;

        // Policy mutation must fail closed and throw ClockGuardError
        expect(() => {
          engine.policies.update({
            ...validPolicy,
            maxAmount: "2000000",
          });
        }).toThrow(ClockGuardError);
      } finally {
        engine.close();
      }
    });

    it("throws StoreTaintedError consistently for repeated issue/consume calls on a tainted database", () => {
      const dbPath = databasePath();
      const clock = new TestClock(1500);
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        clock: { clock },
      });

      try {
        engine.policies.register(validPolicy);
        const keypair = engine.keys.generate();
        engine.keys.register({
          keyId: "key-taint-test",
          publicKey: keypair.publicKey,
          status: "active",
        });

        // Force fatal taint via low-level store
        engine.getStore().markTainted("Simulated commit corruption");
        expect(engine.storage.isTainted()).toBe(true);

        // Every subsequent issue, consume, cancel, and getRecord call must throw StoreTaintedError
        expect(() =>
          engine.issue({
            authorizationId: "auth-tainted-01",
            policyId: "policy-erc20-demo",
            request: validRequest,
            signer: { keyId: "key-taint-test", privateKey: keypair.privateKey },
          }),
        ).toThrow(StoreTaintedError);

        expect(() =>
          engine.issue({
            authorizationId: "auth-tainted-02",
            policyId: "policy-erc20-demo",
            request: validRequest,
            signer: { keyId: "key-taint-test", privateKey: keypair.privateKey },
          }),
        ).toThrow(StoreTaintedError);

        expect(() =>
          engine.consume({
            artifact: { version: 3 } as any,
            request: validRequest,
          }),
        ).toThrow(StoreTaintedError);

        expect(() => engine.cancel("auth-tainted-01")).toThrow(StoreTaintedError);
        expect(() => engine.getAuthorizationRecord("auth-tainted-01")).toThrow(StoreTaintedError);
        expect(() => engine.policies.get("any")).toThrow(StoreTaintedError);
        expect(() => engine.keys.get("any")).toThrow(StoreTaintedError);
        expect(() => engine.storage.checkIntegrity()).toThrow(StoreTaintedError);
      } finally {
        engine.close();
      }
    });

    it("preserves ordinary policy denials as structured results without throwing", () => {
      const dbPath = databasePath();
      const clock = new TestClock(1500);
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        clock: { clock },
      });

      try {
        engine.policies.register(validPolicy); // maxAmount is 1,000,000
        const keypair = engine.keys.generate();
        engine.keys.register({
          keyId: "key-denial-test",
          publicKey: keypair.publicKey,
          status: "active",
        });

        // Exceed policy maxAmount (amount = 2,000,000 > 1,000,000)
        const excessiveAmountHex = (2_000_000n).toString(16).padStart(64, "0");
        const excessiveRequest: TransactionRequest = {
          ...validRequest,
          calldata: `0xa9059cbb${recipientPadded}${excessiveAmountHex}`,
        };

        const result = engine.issue({
          authorizationId: "auth-exceed-amount",
          policyId: "policy-erc20-demo",
          request: excessiveRequest,
          signer: { keyId: "key-denial-test", privateKey: keypair.privateKey },
        });

        // Must return structured DENY, NOT throw
        expect(result.decision).toBe("DENY");
        expect(result.reasons.length).toBeGreaterThan(0);
        expect(engine.storage.isTainted()).toBe(false);

        // Store remains completely healthy and subsequent valid requests succeed
        const validResult = engine.issue({
          authorizationId: "auth-valid-subsequent",
          policyId: "policy-erc20-demo",
          request: validRequest,
          signer: { keyId: "key-denial-test", privateKey: keypair.privateKey },
        });
        expect(validResult.decision).toBe("ALLOW");
      } finally {
        engine.close();
      }
    });

    it("handles uncertain commit outcome with fail-closed taint and immediate StoreTaintedError", () => {
      const dbPath = databasePath();
      const clock = new TestClock(1500);
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        clock: { clock },
      });

      try {
        engine.policies.register(validPolicy);
        const keypair = engine.keys.generate();
        engine.keys.register({
          keyId: "key-uncertain-commit",
          publicKey: keypair.publicKey,
          status: "active",
        });

        // Intercept COMMIT on raw db to simulate ambiguous commit failure
        const rawDb = engine.getStore().getDatabase();
        const origExec = rawDb.exec.bind(rawDb);
        rawDb.exec = (sql: string) => {
          if (sql.includes("COMMIT")) {
            throw new Error("sqlite error: disk I/O error during commit (SQLITE_IOERR)");
          }
          return origExec(sql);
        };

        // Issuance attempt encounters ambiguous COMMIT failure and must throw StoreTaintedError
        expect(() => {
          engine.issue({
            authorizationId: "auth-commit-fail",
            policyId: "policy-erc20-demo",
            request: validRequest,
            signer: { keyId: "key-uncertain-commit", privateKey: keypair.privateKey },
          });
        }).toThrow(StoreTaintedError);

        // Engine is now permanently tainted and never blindly retries
        expect(engine.storage.isTainted()).toBe(true);
        expect(() => {
          engine.issue({
            authorizationId: "auth-retry-after-fail",
            policyId: "policy-erc20-demo",
            request: validRequest,
            signer: { keyId: "key-uncertain-commit", privateKey: keypair.privateKey },
          });
        }).toThrow(StoreTaintedError);
      } finally {
        engine.close();
      }
    });

    it("never exposes private key in error message on invalid signer or signature error", () => {
      const dbPath = databasePath();
      const engine = Web3UserEngine.open({ databasePath: dbPath });
      const secretToken = "super-secret-key-material-do-not-leak";

      try {
        engine.policies.register(validPolicy);

        const issueResult = engine.issue({
          authorizationId: "auth-secret-test",
          policyId: "policy-erc20-demo",
          request: validRequest,
          signer: {
            keyId: "unknown-key",
            privateKey: secretToken,
          },
        });

        // The issue result should DENY because key is unknown
        expect(issueResult.decision).toBe("DENY");
        // Ensure private key string is never in reasons
        const reasonsStr = issueResult.reasons.join(" ");
        expect(reasonsStr).not.toContain(secretToken);
      } finally {
        engine.close();
      }
    });
  });

  // =========================================================================
  // Milestone 6.12-D: Fatal I/O Handling, Quarantine Invariants & Fault Injection
  // =========================================================================
  describe("Milestone 6.12-D: Fatal I/O Handling, Quarantine Invariants & Fault Injection", () => {
    it("quarantines engine and throws StoreTaintedError on non-COMMIT read I/O error", () => {
      const dbPath = databasePath();
      const engine = Web3UserEngine.open({ databasePath: dbPath });

      try {
        engine.policies.register(validPolicy);
        expect(engine.storage.isTainted()).toBe(false);

        // Inject simulated SQLITE_IOERR during prepare/read
        const rawDb = engine.getStore().getDatabase();
        const originalPrepare = rawDb.prepare.bind(rawDb);
        rawDb.prepare = (sql: string) => {
          if (sql.includes("FROM policies WHERE policy_id = ?")) {
            throw new Error("sqlite error: disk I/O error during read (SQLITE_IOERR)");
          }
          return originalPrepare(sql);
        };

        // Calling policies.get encounters fatal I/O and must throw StoreTaintedError
        expect(() => {
          engine.policies.get("policy-erc20-demo");
        }).toThrow(StoreTaintedError);

        // Documented quarantine invariant MUST be genuinely satisfied:
        expect(engine.storage.isTainted()).toBe(true);
        expect(engine.getStore().isTainted()).toBe(true);
        expect(engine.storage.getTaintedReason()).toContain("Fatal storage I/O error");
        expect(engine.storage.getTaintedReason()).toContain("SQLITE_IOERR");
        expect(engine.getStore().getClockGuard().getState()).toBe("TRIPPED_CLOSED");

        // Every subsequent operation fails closed immediately with StoreTaintedError
        expect(() => engine.policies.list()).toThrow(StoreTaintedError);
        expect(() => engine.keys.list()).toThrow(StoreTaintedError);
        expect(() => engine.getAuthorizationRecord("auth-any")).toThrow(StoreTaintedError);
        expect(() => engine.cancel("auth-any")).toThrow(StoreTaintedError);
        expect(() => engine.storage.checkIntegrity()).toThrow(StoreTaintedError);
        expect(() => engine.storage.checkpoint()).toThrow(StoreTaintedError);
      } finally {
        engine.close();
      }
    });

    it("quarantines engine when fatal I/O error occurs during checkIntegrity", () => {
      const dbPath = databasePath();
      const engine = Web3UserEngine.open({ databasePath: dbPath });

      try {
        expect(engine.storage.isTainted()).toBe(false);

        // Inject simulated SQLITE_IOERR during PRAGMA integrity_check
        const rawDb = engine.getStore().getDatabase();
        const originalPrepare = rawDb.prepare.bind(rawDb);
        rawDb.prepare = (sql: string) => {
          if (sql.includes("integrity_check")) {
            throw new Error("sqlite error: disk I/O error during integrity check (SQLITE_IOERR)");
          }
          return originalPrepare(sql);
        };

        expect(() => {
          engine.storage.checkIntegrity();
        }).toThrow(StoreTaintedError);

        // Store must be genuinely quarantined
        expect(engine.storage.isTainted()).toBe(true);
        expect(engine.storage.getTaintedReason()).toContain("Fatal storage I/O error");
      } finally {
        engine.close();
      }
    });

    it("synchronizes quarantine between parent store and borrowed policy/key stores", () => {
      const dbPath = databasePath();
      const engine = Web3UserEngine.open({ databasePath: dbPath });

      try {
        engine.policies.register(validPolicy);
        const policyStore = engine.getStore().getPolicyStore();
        const keyStore = engine.getStore().getKeyStore();

        expect(engine.storage.isTainted()).toBe(false);
        expect(policyStore.isTainted()).toBe(false);
        expect(keyStore.isTainted()).toBe(false);

        // Case A: Fatal I/O on borrowed policy store marks itself and parent engine tainted
        const rawDb = engine.getStore().getDatabase();
        const originalPrepare = rawDb.prepare.bind(rawDb);
        rawDb.prepare = (sql: string) => {
          if (sql.includes("FROM policies WHERE policy_id = ?")) {
            throw new Error("sqlite error: disk I/O error (SQLITE_IOERR)");
          }
          return originalPrepare(sql);
        };

        expect(() => {
          policyStore.getPolicy("policy-erc20-demo");
        }).toThrow("SQLITE_IOERR");

        // Both borrowed stores and parent engine observe quarantine
        expect(policyStore.isTainted()).toBe(true);
        expect(keyStore.isTainted()).toBe(true);
        expect(engine.storage.isTainted()).toBe(true);
        expect(policyStore.getTaintedReason()).toContain("Fatal storage I/O error");
        expect(engine.storage.getTaintedReason()).toContain("Fatal storage I/O error");

        // Subsequent engine call fails closed with StoreTaintedError
        expect(() => engine.policies.get("policy-erc20-demo")).toThrow(StoreTaintedError);
      } finally {
        engine.close();
      }
    });

    it("preserves safe rollback when outcome is known (mid-transaction SQLITE_FULL) without tainting store", () => {
      const dbPath = databasePath();
      const clock = new TestClock(1500);
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        clock: { clock },
      });

      try {
        engine.policies.register(validPolicy);
        const keypair = engine.keys.generate();
        engine.keys.register({
          keyId: "key-full-test",
          publicKey: keypair.publicKey,
          status: "active",
        });

        // Patch prepare inside engine store database to throw SQLITE_FULL on specific table insert
        const rawDb = engine.getStore().getDatabase();
        const originalPrepare = rawDb.prepare.bind(rawDb);
        let faultTriggered = false;
        rawDb.prepare = (sql: string) => {
          if (sql.includes("INSERT INTO consumed_authorization_ids") && !faultTriggered) {
            faultTriggered = true;
            throw new Error("sqlite error: database or disk is full (SQLITE_FULL)");
          }
          return originalPrepare(sql);
        };

        // Issuance attempt throws operational Web3UserError, NOT StoreTaintedError
        expect(() => {
          engine.issue({
            authorizationId: "auth-full-fail",
            policyId: "policy-erc20-demo",
            request: validRequest,
            signer: { keyId: "key-full-test", privateKey: keypair.privateKey },
          });
        }).toThrow(Web3UserError);

        // Store is NOT tainted because rollback succeeded and outcome is known (not committed)
        expect(engine.storage.isTainted()).toBe(false);

        // Subsequent valid issuance succeeds once fault is resolved
        rawDb.prepare = originalPrepare;
        const validResult = engine.issue({
          authorizationId: "auth-full-recovery",
          policyId: "policy-erc20-demo",
          request: validRequest,
          signer: { keyId: "key-full-test", privateKey: keypair.privateKey },
        });
        expect(validResult.decision).toBe("ALLOW");
      } finally {
        engine.close();
      }
    });

    it("distinguishes reason strings between ambiguous COMMIT failure and non-COMMIT fatal I/O", () => {
      // 1. Ambiguous COMMIT failure
      const dbPath1 = databasePath("commit-diff.sqlite");
      const engine1 = Web3UserEngine.open({ databasePath: dbPath1 });
      try {
        engine1.policies.register(validPolicy);
        const rawDb1 = engine1.getStore().getDatabase();
        const origExec1 = rawDb1.exec.bind(rawDb1);
        rawDb1.exec = (sql: string) => {
          if (sql.includes("COMMIT")) {
            throw new Error("sqlite error: disk I/O error during commit (SQLITE_IOERR)");
          }
          return origExec1(sql);
        };

        expect(() => {
          engine1.policies.update({
            ...validPolicy,
            maxAmount: "5000000",
          });
        }).toThrow(StoreTaintedError);

        // Ambiguous commit reason must be explicitly labeled
        expect(engine1.storage.getTaintedReason()).toContain("Commit failure with uncertain outcome");
      } finally {
        engine1.close();
      }

      // 2. Non-COMMIT fatal I/O
      const dbPath2 = databasePath("read-diff.sqlite");
      const engine2 = Web3UserEngine.open({ databasePath: dbPath2 });
      try {
        engine2.policies.register(validPolicy);
        const rawDb2 = engine2.getStore().getDatabase();
        const origPrepare2 = rawDb2.prepare.bind(rawDb2);
        rawDb2.prepare = (sql: string) => {
          if (sql.includes("FROM policies WHERE policy_id = ?")) {
            throw new Error("sqlite error: read block corrupted (SQLITE_IOERR)");
          }
          return origPrepare2(sql);
        };

        expect(() => {
          engine2.policies.get("policy-erc20-demo");
        }).toThrow(StoreTaintedError);

        // Non-commit fatal I/O must be labeled as fatal storage I/O, NOT uncertain commit
        expect(engine2.storage.getTaintedReason()).toContain("Fatal storage I/O error");
        expect(engine2.storage.getTaintedReason()).not.toContain("Commit failure with uncertain outcome");
      } finally {
        engine2.close();
      }
    });

    it("ensures idempotent close and markTainted without masking original errors", () => {
      const dbPath = databasePath();
      const engine = Web3UserEngine.open({ databasePath: dbPath });

      try {
        const store = engine.getStore();
        store.markTainted("Primary fatal reason");
        expect(store.isTainted()).toBe(true);
        expect(store.getTaintedReason()).toBe("Primary fatal reason");

        // Repeated markTainted does not overwrite primary reason or throw
        expect(() => {
          store.markTainted("Secondary reason");
        }).not.toThrow();
        expect(store.getTaintedReason()).toBe("Primary fatal reason");

        // Repeated engine close is idempotent
        expect(() => engine.close()).not.toThrow();
        expect(() => engine.close()).not.toThrow();
      } finally {
        engine.close();
      }
    });
  });

  // =========================================================================
  // Milestone 6.12-F: Error Semantics and Quarantine Remediation
  // =========================================================================
  describe("Milestone 6.12-F: Error Semantics and Quarantine Remediation", () => {
    it("distinguishes rollback failure diagnostics from uncertain commit in store operations", () => {
      const dbPath = databasePath("rollback-diag.sqlite");
      const clock = new TestClock(1500);
      const store = new SQLiteAuthorizationStore(dbPath, clock);

      try {
        const rawDb = store.getDatabase();
        const origExec = rawDb.exec.bind(rawDb);
        const origPrepare = rawDb.prepare.bind(rawDb);

        // Force transaction body failure, and then force ROLLBACK failure with fatal I/O
        rawDb.prepare = (sql: string) => {
          if (sql.includes("system_clock_state")) {
            throw new Error("Simulated body failure prior to rollback");
          }
          return origPrepare(sql);
        };
        rawDb.exec = (sql: string) => {
          if (sql.includes("ROLLBACK")) {
            throw new Error("sqlite error: disk I/O error during rollback (SQLITE_IOERR)");
          }
          return origExec(sql);
        };

        expect(() => {
          store.advanceHighWaterMark(1600);
        }).toThrow("Simulated body failure prior to rollback");

        // The store must be quarantined with an accurately named failure path
        expect(store.isTainted()).toBe(true);
        expect(store.getTaintedReason()).toContain("Fatal rollback failure");
        // Must NOT incorrectly claim that COMMIT was attempted
        expect(store.getTaintedReason()).not.toContain("Commit failure with uncertain outcome");
      } finally {
        store.close();
      }
    });

    it("quarantines authorization store on fatal I/O during direct issueSignedTransactionAuthorizationV3 call", () => {
      const dbPath = databasePath("direct-issue-ioerr.sqlite");
      const clock = new TestClock(1500);
      const store = new SQLiteAuthorizationStore(dbPath, clock);

      try {
        store.getPolicyStore().registerPolicy(validPolicy);
        const keypair = generateIssuerKeyPair();
        store.getKeyStore().registerKey({
          keyId: "direct-key-01",
          publicKey: keypair.publicKey,
          status: "active",
        });

        expect(store.isTainted()).toBe(false);

        // Inject SQLITE_IOERR during SQL prepare inside transaction
        const rawDb = store.getDatabase();
        const origPrepare = rawDb.prepare.bind(rawDb);
        rawDb.prepare = (sql: string) => {
          if (sql.includes("FROM policies WHERE policy_id = ?")) {
            throw new Error("sqlite error: disk I/O error during policy fetch (SQLITE_IOERR)");
          }
          return origPrepare(sql);
        };

        // Calling direct lifecycle function without Web3UserEngine facade
        expect(() => {
          issueSignedTransactionAuthorizationV3(
            store,
            { keyId: "direct-key-01", privateKey: keypair.privateKey },
            "auth-direct-issue-01",
            "policy-erc20-demo",
            validRequest,
          );
        }).toThrow("SQLITE_IOERR");

        // Direct low-level call MUST quarantine the associated authorization store
        expect(store.isTainted()).toBe(true);
        expect(store.getTaintedReason()).toContain("Fatal storage I/O error");
        expect(store.getClockGuard().getState()).toBe("TRIPPED_CLOSED");
      } finally {
        store.close();
      }
    });

    it("quarantines authorization store on fatal I/O during direct consumeSignedTransactionAuthorizationV3 call", () => {
      const dbPath = databasePath("direct-consume-ioerr.sqlite");
      const clock = new TestClock(1500);
      const store = new SQLiteAuthorizationStore(dbPath, clock);

      try {
        store.getPolicyStore().registerPolicy(validPolicy);
        const keypair = generateIssuerKeyPair();
        store.getKeyStore().registerKey({
          keyId: "direct-key-02",
          publicKey: keypair.publicKey,
          status: "active",
        });

        // Issue valid artifact
        const issued = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "direct-key-02", privateKey: keypair.privateKey },
          "auth-direct-consume-01",
          "policy-erc20-demo",
          validRequest,
        );
        expect(issued.decision).toBe("ALLOW");
        if (issued.decision !== "ALLOW") return;

        expect(store.isTainted()).toBe(false);

        // Inject fatal I/O error during consumption update
        const rawDb = store.getDatabase();
        const origPrepare = rawDb.prepare.bind(rawDb);
        rawDb.prepare = (sql: string) => {
          if (sql.includes("UPDATE consumed_authorization_ids")) {
            throw new Error("sqlite error: disk I/O error during consume write (SQLITE_IOERR)");
          }
          return origPrepare(sql);
        };

        // Direct consume call without Web3UserEngine facade
        expect(() => {
          consumeSignedTransactionAuthorizationV3(
            store,
            issued.artifact,
            issued.envelope,
            validRequest,
          );
        }).toThrow("SQLITE_IOERR");

        // Store MUST be genuinely quarantined
        expect(store.isTainted()).toBe(true);
        expect(store.getTaintedReason()).toContain("Fatal storage I/O error");
      } finally {
        store.close();
      }
    });

    it("quarantines store as fatal rollback failure when rollback fails during direct lifecycle call", () => {
      const dbPath = databasePath("direct-rollback-fail.sqlite");
      const clock = new TestClock(1500);
      const store = new SQLiteAuthorizationStore(dbPath, clock);

      try {
        store.getPolicyStore().registerPolicy(validPolicy);
        const keypair = generateIssuerKeyPair();
        store.getKeyStore().registerKey({
          keyId: "direct-key-03",
          publicKey: keypair.publicKey,
          status: "active",
        });

        const rawDb = store.getDatabase();
        const origExec = rawDb.exec.bind(rawDb);
        const origPrepare = rawDb.prepare.bind(rawDb);

        // Fail query, and fail rollback with fatal I/O
        rawDb.prepare = (sql: string) => {
          if (sql.includes("FROM policies WHERE policy_id = ?")) {
            throw new Error("Initial application failure");
          }
          return origPrepare(sql);
        };
        rawDb.exec = (sql: string) => {
          if (sql.includes("ROLLBACK")) {
            throw new Error("sqlite error: disk I/O error on rollback (SQLITE_IOERR)");
          }
          return origExec(sql);
        };

        expect(() => {
          issueSignedTransactionAuthorizationV3(
            store,
            { keyId: "direct-key-03", privateKey: keypair.privateKey },
            "auth-direct-rollback-fail",
            "policy-erc20-demo",
            validRequest,
          );
        }).toThrow("Initial application failure");

        // Store must be quarantined with accurately named rollback failure reason
        expect(store.isTainted()).toBe(true);
        expect(store.getTaintedReason()).toContain("Fatal rollback failure");
      } finally {
        store.close();
      }
    });

    it("preserves original error causes across wrapEngineError and Web3UserError subclasses", () => {
      const originalCause = new Error("Native driver failure");

      // StoreTaintedError
      const taintedErr = wrapEngineError(
        new Error("sqlite error: disk I/O error (SQLITE_IOERR)"),
      );
      expect(taintedErr).toBeInstanceOf(StoreTaintedError);
      expect(taintedErr.cause).toBeDefined();

      // ClockGuardError
      const clockErr = wrapEngineError(new Error("ClockGuard: clock rollback detected"));
      expect(clockErr).toBeInstanceOf(ClockGuardError);
      expect(clockErr.cause).toBeDefined();

      // ContentionError
      const contentionErr = wrapEngineError(new Error("SQLITE_BUSY: database is locked"));
      expect(contentionErr).toBeInstanceOf(ContentionError);
      expect(contentionErr.cause).toBeDefined();

      // ValidationError
      const validationErr = wrapEngineError(new Error("authorizationId must be a non-empty string"));
      expect(validationErr).toBeInstanceOf(ValidationError);
      expect(validationErr.cause).toBeDefined();

      // Generic Web3UserError
      const genericErr = wrapEngineError(originalCause);
      expect(genericErr).toBeInstanceOf(Web3UserError);
      expect(genericErr.cause).toBe(originalCause);

      // Direct subclass construction with options
      const directTainted = new StoreTaintedError("Tainted message", { cause: originalCause });
      expect(directTainted.cause).toBe(originalCause);

      const directClosed = new EngineClosedError("Closed message", { cause: originalCause });
      expect(directClosed.cause).toBe(originalCause);

      const directValidation = new ValidationError("Invalid", { cause: originalCause });
      expect(directValidation.cause).toBe(originalCause);
    });

    it("preserves ordinary policy DENY and UNKNOWN semantics in direct lifecycle calls without tainting store", () => {
      const dbPath = databasePath("direct-deny.sqlite");
      const clock = new TestClock(1500);
      const store = new SQLiteAuthorizationStore(dbPath, clock);

      try {
        store.getPolicyStore().registerPolicy(validPolicy);
        const keypair = generateIssuerKeyPair();
        store.getKeyStore().registerKey({
          keyId: "direct-key-04",
          publicKey: keypair.publicKey,
          status: "active",
        });

        // 1. Amount exceeds policy limit
        const excessiveRequest: TransactionRequest = {
          ...validRequest,
          calldata: `0xa9059cbb${recipientPadded}${(2_000_000n).toString(16).padStart(64, "0")}`,
        };

        const issueResult = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "direct-key-04", privateKey: keypair.privateKey },
          "auth-direct-deny-01",
          "policy-erc20-demo",
          excessiveRequest,
        );

        expect(issueResult.decision).toBe("DENY");
        expect(store.isTainted()).toBe(false);

        // 2. Consume with malformed envelope input returns UNKNOWN/DENY without throwing
        const validIssue = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "direct-key-04", privateKey: keypair.privateKey },
          "auth-direct-valid-01",
          "policy-erc20-demo",
          validRequest,
        );
        expect(validIssue.decision).toBe("ALLOW");
        if (validIssue.decision !== "ALLOW") return;

        // First consumption succeeds
        const firstConsume = consumeSignedTransactionAuthorizationV3(
          store,
          validIssue.artifact,
          validIssue.envelope,
          validRequest,
        );
        expect(firstConsume.decision).toBe("ALLOW");

        // Replay consumption returns DENY, store remains untainted
        const replayConsume = consumeSignedTransactionAuthorizationV3(
          store,
          validIssue.artifact,
          validIssue.envelope,
          validRequest,
        );
        expect(replayConsume.decision).toBe("DENY");
        expect(store.isTainted()).toBe(false);
      } finally {
        store.close();
      }
    });

    it("fails closed on already-tainted store in direct lifecycle and engine facade operations", () => {
      const dbPath = databasePath("direct-already-tainted.sqlite");
      const clock = new TestClock(1500);
      const engine = Web3UserEngine.open({
        databasePath: dbPath,
        clock: { clock },
      });

      try {
        const store = engine.getStore();
        store.getPolicyStore().registerPolicy(validPolicy);
        const keypair = generateIssuerKeyPair();
        store.getKeyStore().registerKey({
          keyId: "direct-key-05",
          publicKey: keypair.publicKey,
          status: "active",
        });

        // Manually taint store
        store.markTainted("Fatal unrecoverable fault");
        expect(store.isTainted()).toBe(true);

        // Direct lifecycle call fails closed with DENY (due to clockGuard evaluateCandidate / db closed)
        const directResult = issueSignedTransactionAuthorizationV3(
          store,
          { keyId: "direct-key-05", privateKey: keypair.privateKey },
          "auth-direct-tainted",
          "policy-erc20-demo",
          validRequest,
        );
        expect(directResult.decision).toBe("DENY");
        expect(directResult.reasons[0]).toContain("tainted and unusable");

        // Engine facade throws StoreTaintedError upfront
        expect(() =>
          engine.issue({
            authorizationId: "auth-engine-tainted",
            policyId: "policy-erc20-demo",
            request: validRequest,
            signer: { keyId: "direct-key-05", privateKey: keypair.privateKey },
          }),
        ).toThrow(StoreTaintedError);
      } finally {
        engine.close();
      }
    });
  });
});
