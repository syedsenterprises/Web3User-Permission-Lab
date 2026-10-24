import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import {
  canonicalSignedPayloadV3,
  signAuthorizationPayload,
} from "../src/authorization-crypto.js";
import {
  consumeSignedTransactionAuthorizationV3,
  issueSignedTransactionAuthorizationV3,
} from "../src/authorization-lifecycle.js";
import { SQLiteAuthorizationStore } from "../src/authorization-store.js";
import {
  ClockCandidate,
  ClockGuard,
  MAX_ANCHOR_LIFETIME_SECONDS,
  MAX_FORWARD_STEP_SECONDS,
  MAX_BACKWARD_STEP_SECONDS,
  MAX_ABSOLUTE_DIVERGENCE_SECONDS,
  MAX_STARTUP_FORWARD_GAP_SECONDS,
  TestClock,
} from "../src/clock.js";
import { SQLiteKeyStore } from "../src/key-store.js";
import { type DemoPolicy } from "../src/policy.js";
import { SQLitePolicyStore } from "../src/policy-store.js";
import { withImmediateTransaction } from "../src/sqlite-transaction.js";
import { createTransactionEnvelope, type TransactionRequest } from "../src/transaction-envelope.js";

describe("Milestone 6.8 Phase 1: Clock Guardrails & Transaction Integrity", () => {
  let directory: string | undefined;

  function databasePath(filename = "clock-guardrails-test.sqlite"): string {
    directory ??= mkdtempSync(join(tmpdir(), "web3user-m68-"));
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
    policyId: "policy-m68",
    allowedTarget: "0x1111111111111111111111111111111111111111",
    allowedRecipient: "0x2222222222222222222222222222222222222222",
    allowedSelector: "0xa9059cbb",
    maxAmount: "1000000",
    validFrom: 1000,
    expiresAt: 900000,
    revoked: false,
  };

  const recipientPadded = "0000000000000000000000002222222222222222222222222222222222222222";
  const amountPadded = "0000000000000000000000000000000000000000000000000000000000001388"; // 5000

  const validRequest: TransactionRequest = {
    chainId: "1",
    sender: "0x3333333333333333333333333333333333333333",
    target: "0x1111111111111111111111111111111111111111",
    calldata: `0xa9059cbb${recipientPadded}${amountPadded}`,
    value: "0",
  };

  // 1. Multi-process high-water sequence: 1000, 1005, rejected 1003, accepted 1006
  it("enforces multi-process high-water sequence: 1000 -> 1005 -> rejected 1003 -> accepted 1006", () => {
    const dbFile = databasePath();

    // Process A initializes database at t=1000 and publishes sample
    const clockA = new TestClock(1000);
    const storeA = new SQLiteAuthorizationStore(dbFile, clockA);
    storeA.advanceHighWaterMark(1000);

    // Process B opens same database at t=1000 and publishes sample
    const clockB = new TestClock(1000);
    const storeB = new SQLiteAuthorizationStore(dbFile, clockB);
    storeB.advanceHighWaterMark(1000);

    try {
      expect(storeA.getHighWaterMark()).toBe(1000);
      expect(storeB.getHighWaterMark()).toBe(1000);
      expect(storeA.getClockGuard().getPublishedSample()?.wallSeconds).toBe(1000);
      expect(storeB.getClockGuard().getPublishedSample()?.wallSeconds).toBe(1000);

      // Process B advances to 1005 and commits
      clockB.set(1005);
      storeB.advanceHighWaterMark(1005);
      expect(storeB.getHighWaterMark()).toBe(1005);
      expect(storeA.getHighWaterMark()).toBe(1005);

      // Process A's published sample is still at 1000 (lags behind shared SQLite high-water 1005)
      expect(storeA.getClockGuard().getPublishedSample()?.wallSeconds).toBe(1000);

      // Process A advances clock to 1003 (which lags behind shared SQLite high-water 1005)
      clockA.set(1003);

      // Process A attempts advanceHighWaterMark(1003) -> MUST be rejected because candidate < shared high-water
      expect(() => storeA.advanceHighWaterMark(1003)).toThrow(
        "Clock rollback detected: current time (1003s) precedes persisted high-water mark (1005s)."
      );

      // Store A must NOT be permanently tripped into TRIPPED_CLOSED:
      expect(storeA.getClockGuard().getState()).toBe("ACTIVE");
      // Store A's published sample must remain 1000 (rejected candidate was not published)
      expect(storeA.getClockGuard().getPublishedSample()?.wallSeconds).toBe(1000);
      // High-water mark remains 1005
      expect(storeA.getHighWaterMark()).toBe(1005);

      // Process A advances clock to 1006 (>= shared high-water 1005 and within divergence bounds)
      clockA.set(1006);
      expect(() => storeA.advanceHighWaterMark(1006)).not.toThrow();

      // Process A successfully advanced high-water to 1006 and published candidate sample
      expect(storeA.getHighWaterMark()).toBe(1006);
      expect(storeA.getClockGuard().getPublishedSample()?.wallSeconds).toBe(1006);
    } finally {
      storeA.close();
      storeB.close();
    }
  });

  // 2. Local sample remains unchanged after business validation failure and confirmed rollback
  it("leaves local published sample unchanged when business validation fails inside transaction", () => {
    const dbFile = databasePath();
    const clock = new TestClock(1000);
    const store = new SQLiteAuthorizationStore(dbFile, clock);
    const policyStore = store.getPolicyStore();
    const keyStore = store.getKeyStore();
    const key = createKeypair();

    try {
      policyStore.registerPolicy(validPolicy);
      keyStore.registerKey({ keyId: "key-m68", publicKey: key.publicKey, status: "active" });

      // Issue authorization at t=1000
      const issueRes = issueSignedTransactionAuthorizationV3(
        store,
        { keyId: "key-m68", privateKey: key.privateKey },
        "auth-validation-fail-test",
        "policy-m68",
        validRequest,
        { ttlSeconds: 300 },
      );
      expect(issueRes.decision).toBe("ALLOW");
      if (issueRes.decision !== "ALLOW") return;

      const publishedAfterIssue = store.getClockGuard().getPublishedSample();
      expect(publishedAfterIssue?.wallSeconds).toBe(1000);

      // Advance clock to t=1005
      clock.advance(5);

      // Attempt consumption with mismatched request calldata (fails business evaluation)
      const invalidRequest: TransactionRequest = {
        ...validRequest,
        calldata: "0xdeadbeef",
      };

      const consumeRes = consumeSignedTransactionAuthorizationV3(
        store,
        issueRes.artifact,
        issueRes.envelope,
        invalidRequest,
      );

      expect(consumeRes.decision).toBe("DENY");
      expect(consumeRes.reasons).toContain("Transaction does not match the original envelope.");

      // Candidate 1005 must NOT have been published!
      const publishedAfterFail = store.getClockGuard().getPublishedSample();
      expect(publishedAfterFail?.wallSeconds).toBe(1000);
      expect(publishedAfterFail?.monotonicNanos).toBe(publishedAfterIssue?.monotonicNanos);

      // Authorization in database must remain in 'issued' state (unconsumed)
      expect(store.getAuthorizationRecord("auth-validation-fail-test")?.state).toBe("issued");
    } finally {
      store.close();
    }
  });

  // 3. SQLite mutation failure rolls back without publishing candidate
  it("rolls back transaction without publishing candidate when SQLite mutation fails", () => {
    const dbFile = databasePath();
    const clock = new TestClock(1000);
    const store = new SQLiteAuthorizationStore(dbFile, clock);

    try {
      // Establish initial published sample
      store.advanceHighWaterMark(1000);
      expect(store.getClockGuard().getPublishedSample()?.wallSeconds).toBe(1000);

      clock.advance(5); // t=1005

      const guard = store.getClockGuard();
      const candidate: ClockCandidate = {
        wallSeconds: 1005,
        monotonicNanos: guard.getMonotonicClock().nowNanoseconds(),
      };

      expect(() => {
        withImmediateTransaction(
          store.getDatabase(),
          () => {
            // Intentionally violate table constraint
            store.getDatabase().exec("INSERT INTO system_clock_state (id, high_water_seconds) VALUES (1, 9999);");
          },
          undefined,
          undefined,
          undefined,
          () => {
            guard.publishCandidate(candidate);
          },
        );
      }).toThrow(/UNIQUE constraint failed/i);

      // Published sample must remain 1000, NOT 1005
      expect(guard.getPublishedSample()?.wallSeconds).toBe(1000);
      expect(store.getHighWaterMark()).toBe(1000);
    } finally {
      store.close();
    }
  });

  // 4. BEGIN IMMEDIATE retry exhaustion does not falsely trip clock guard
  it("does not falsely trip clock guard when BEGIN IMMEDIATE retry is exhausted", () => {
    const dbFile = databasePath();
    const clock = new TestClock(1000);
    const store = new SQLiteAuthorizationStore(dbFile, clock);

    // Initialize store state to ACTIVE
    store.advanceHighWaterMark(1000);
    expect(store.getClockGuard().getState()).toBe("ACTIVE");

    // Configure fast busy timeout for this test
    store.getDatabase().exec("PRAGMA busy_timeout = 5;");

    // Open competing connection and hold exclusive lock
    const blocker = new DatabaseSync(dbFile);
    blocker.exec("BEGIN IMMEDIATE;");

    try {
      // Store attempts advanceHighWaterMark with fast contention timeout
      expect(() => {
        withImmediateTransaction(
          store.getDatabase(),
          () => {},
          2, // 2 retries
          5, // 5ms delay
          20, // 20ms budget
        );
      }).toThrow("Database is busy; transaction contention retry limit exceeded.");

      // Clock guard state must still be ACTIVE, NOT TRIPPED_CLOSED
      expect(store.getClockGuard().getState()).toBe("ACTIVE");
      expect(store.getClockGuard().isTainted()).toBe(false);

      // Release blocker lock
      blocker.exec("COMMIT;");

      // Next transaction must succeed cleanly
      clock.advance(5);
      expect(() => store.advanceHighWaterMark(1005)).not.toThrow();
      expect(store.getHighWaterMark()).toBe(1005);
    } finally {
      blocker.close();
      store.close();
    }
  });

  // 5. COMMIT failure taints connection and permanently prevents subsequent authorization decisions
  it("taints database connection and permanently trips clock guard when COMMIT fails with uncertain outcome", () => {
    const dbFile = databasePath();
    const clock = new TestClock(1000);
    let fatalTaintCalled = false;
    let taintReason: string | undefined;

    const store = new SQLiteAuthorizationStore(dbFile, {
      clock,
      onFatalTaint: (reason) => {
        fatalTaintCalled = true;
        taintReason = reason;
      },
    });

    try {
      store.advanceHighWaterMark(1000);
      expect(store.isTainted()).toBe(false);
      expect(store.getClockGuard().getState()).toBe("ACTIVE");

      // Mark tainted (simulating commit failure with uncertain outcome)
      store.markTainted("Injected simulated commit timeout with uncertain outcome");

      expect(store.isTainted()).toBe(true);
      expect(fatalTaintCalled).toBe(true);
      expect(taintReason).toContain("Injected simulated commit timeout");
      expect(store.getClockGuard().getState()).toBe("TRIPPED_CLOSED");
      expect(store.getClockGuard().isTainted()).toBe(true);

      // All subsequent operations must fail closed:
      // A. getDatabase throws
      expect(() => store.getDatabase()).toThrow("database connection is tainted and unusable");

      // B. advanceHighWaterMark throws
      expect(() => store.advanceHighWaterMark(1005)).toThrow("database connection is tainted and unusable");

      // C. getPolicyStore and getKeyStore throw
      expect(() => store.getPolicyStore()).toThrow("database connection is tainted and unusable");
      expect(() => store.getKeyStore()).toThrow("database connection is tainted and unusable");

      // D. cancelAuthorization throws
      expect(() => store.cancelAuthorization("auth-test")).toThrow(
        "database connection is tainted and unusable",
      );

      // E. issueSignedTransactionAuthorizationV3 returns DENY
      const key = createKeypair();
      const issueAttempt = issueSignedTransactionAuthorizationV3(
        store,
        { keyId: "key-tainted", privateKey: key.privateKey },
        "auth-tainted-attempt",
        "policy-m68",
        validRequest,
      );
      expect(issueAttempt.decision).toBe("DENY");
      expect(issueAttempt.reasons.some((r) => r.includes("tainted and unusable"))).toBe(true);
    } finally {
      try { store.close(); } catch {}
    }
  });

  // 6. Anti-time-travel check in consumption
  it("rejects consumption when authorization claims issuance in the future (anti-time-travel check)", () => {
    const dbFile = databasePath();
    const clock = new TestClock(1000);
    const store = new SQLiteAuthorizationStore(dbFile, clock);
    const policyStore = store.getPolicyStore();
    const keyStore = store.getKeyStore();
    const key = createKeypair();

    try {
      policyStore.registerPolicy(validPolicy);
      keyStore.registerKey({ keyId: "key-time-travel", publicKey: key.publicKey, status: "active" });

      // Valid issuance at t=1000
      const issueRes = issueSignedTransactionAuthorizationV3(
        store,
        { keyId: "key-time-travel", privateKey: key.privateKey },
        "auth-time-travel",
        "policy-m68",
        validRequest,
      );
      expect(issueRes.decision).toBe("ALLOW");
      if (issueRes.decision !== "ALLOW") return;

      // Sign an artifact claiming issuance in the future (t=1050) while evaluation time is 1005
      clock.advance(5); // t=1005
      const futureArtifact = {
        ...issueRes.artifact,
        issuedAtSeconds: 1050,
      };
      const canonicalFuture = canonicalSignedPayloadV3({
        version: futureArtifact.version,
        authorizationId: futureArtifact.authorizationId,
        keyId: futureArtifact.keyId,
        issuedAtSeconds: futureArtifact.issuedAtSeconds,
        expiresAtSeconds: futureArtifact.expiresAtSeconds,
        policyId: futureArtifact.policyId,
        policyRevision: futureArtifact.policyRevision,
        bindingDigest: futureArtifact.bindingDigest,
      });
      const validSignatureForFuture = signAuthorizationPayload(key.privateKey, canonicalFuture);
      const signedFutureArtifact = {
        ...futureArtifact,
        signature: validSignatureForFuture,
      };

      const consumeRes = consumeSignedTransactionAuthorizationV3(
        store,
        signedFutureArtifact,
        issueRes.envelope,
        validRequest,
      );

      expect(consumeRes.decision).toBe("DENY");
      expect(consumeRes.reasons).toContain(
        "Authorization issuance timestamp is in the future relative to current clock."
      );

      // Authorization in database must remain 'issued' (unconsumed)
      expect(store.getAuthorizationRecord("auth-time-travel")?.state).toBe("issued");
    } finally {
      store.close();
    }
  });

  // 7. Startup-gap damage-containment boundaries (3599, 3600, 3601)
  describe("Startup forward-gap boundaries", () => {
    it("allows startup gap <= 3600s and rejects startup gap > 3600s", () => {
      const dbFile = databasePath();

      // Initialize database with high-water at 1000
      const initStore = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      initStore.close();

      // Case 1: Gap of 3599s (clock = 4599) -> ALLOWED
      const store3599 = new SQLiteAuthorizationStore(dbFile, new TestClock(4599));
      expect(store3599.getHighWaterMark()).toBe(1000);
      store3599.close();

      // Case 2: Exact boundary gap of 3600s (clock = 4600) -> ALLOWED
      const store3600 = new SQLiteAuthorizationStore(dbFile, new TestClock(4600));
      expect(store3600.getHighWaterMark()).toBe(1000);
      store3600.close();

      // Case 3: Gap of 3601s (clock = 4601) -> REJECTED
      expect(() => new SQLiteAuthorizationStore(dbFile, new TestClock(4601))).toThrow(
        "Store startup rejected: forward clock gap of 3601 seconds exceeds maximum allowed startup threshold (3600s)."
      );

      // High-water in database was not corrupted or advanced
      const verifyStore = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      expect(verifyStore.getHighWaterMark()).toBe(1000);
      verifyStore.close();
    });

    it("respects custom maxStartupForwardGapSeconds option", () => {
      const dbFile = databasePath();
      const initStore = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      initStore.close();

      // Custom threshold = 600s: clock = 1601s (gap 601s) -> REJECTED
      expect(() => {
        new SQLiteAuthorizationStore(dbFile, {
          clock: new TestClock(1601),
          maxStartupForwardGapSeconds: 600,
        });
      }).toThrow("forward clock gap of 601 seconds exceeds maximum allowed startup threshold (600s).");
    });
  });

  // 8. Step velocity divergence boundaries (+10 forward, -5 backward)
  describe("Clock-step velocity boundaries", () => {
    it("enforces forward step limit (+10s allowed, +11s tripped)", () => {
      const clock = new TestClock(1000);
      const guard = new ClockGuard(clock);

      // Establish anchor at (1000, 1000s)
      const cand0: ClockCandidate = { wallSeconds: 1000, monotonicNanos: 1_000_000_000_000n };
      expect(guard.evaluateCandidate(cand0, 1000).decision).toBe("ALLOW");
      guard.publishCandidate(cand0);

      // Step forward by exactly +10s without monotonic progress (stepDivergence = 10) -> ALLOWED
      const cand10: ClockCandidate = { wallSeconds: 1010, monotonicNanos: 1_000_000_000_000n };
      expect(guard.evaluateCandidate(cand10, 1000).decision).toBe("ALLOW");
      guard.publishCandidate(cand10);

      // Step forward by +11s from published sample (stepDivergence = 11) -> DENIED and TRIPPED
      const cand21: ClockCandidate = { wallSeconds: 1021, monotonicNanos: 1_000_000_000_000n };
      const eval21 = guard.evaluateCandidate(cand21, 1000);
      expect(eval21.decision).toBe("DENY");
      expect(eval21.reason).toContain("Suspicious forward clock jump detected: step velocity divergence of 11s exceeds forward limit (10s).");
      expect(guard.getState()).toBe("TRIPPED_CLOSED");
    });

    it("enforces backward step limit (-5s allowed, -6s tripped) when above high-water", () => {
      const clock = new TestClock(2000);
      const guard = new ClockGuard(clock);

      // Establish anchor at (2000, 2000s)
      const cand0: ClockCandidate = { wallSeconds: 2000, monotonicNanos: 2_000_000_000_000n };
      expect(guard.evaluateCandidate(cand0, 1990).decision).toBe("ALLOW");
      guard.publishCandidate(cand0);

      // Step backward by -5s while monotonic advances 0s (candidate = 1995 >= high-water 1990) -> ALLOWED
      const candMinus5: ClockCandidate = { wallSeconds: 1995, monotonicNanos: 2_000_000_000_000n };
      expect(guard.evaluateCandidate(candMinus5, 1990).decision).toBe("ALLOW");
      guard.publishCandidate(candMinus5);

      // Step backward by -6s (wall = 1989, stepDivergence = -6) -> DENIED and TRIPPED
      const candMinus6: ClockCandidate = { wallSeconds: 1989, monotonicNanos: 2_000_000_000_000n };
      const evalMinus6 = guard.evaluateCandidate(candMinus6, 1980);
      expect(evalMinus6.decision).toBe("DENY");
      expect(evalMinus6.reason).toContain("Suspicious backward clock step detected: step velocity divergence of -6s exceeds backward limit (-5s).");
      expect(guard.getState()).toBe("TRIPPED_CLOSED");
    });
  });

  // 9. Cumulative divergence boundary (60 seconds)
  it("enforces cumulative absolute divergence ceiling (60s allowed, 61s tripped)", () => {
    const clock = new TestClock(1000);
    const guard = new ClockGuard(clock);

    // Initial anchor at (1000, 1000s)
    const cand0: ClockCandidate = { wallSeconds: 1000, monotonicNanos: 1_000_000_000_000n };
    expect(guard.evaluateCandidate(cand0, 1000).decision).toBe("ALLOW");
    guard.publishCandidate(cand0);

    // Make 6 gradual forward steps of +10s (within step limit) with 0 monotonic progress:
    // Cumulative divergence reaches 60s
    for (let i = 1; i <= 6; i++) {
      const cand: ClockCandidate = { wallSeconds: 1000 + i * 10, monotonicNanos: 1_000_000_000_000n };
      expect(guard.evaluateCandidate(cand, 1000).decision).toBe("ALLOW");
      guard.publishCandidate(cand);
    }

    expect(guard.getPublishedSample()?.wallSeconds).toBe(1060);
    expect(guard.getState()).toBe("ACTIVE");

    // Next step of +1s makes cumulative divergence = 61s > 60s -> DENIED and TRIPPED
    const cand61: ClockCandidate = { wallSeconds: 1061, monotonicNanos: 1_000_000_000_000n };
    const eval61 = guard.evaluateCandidate(cand61, 1000);
    expect(eval61.decision).toBe("DENY");
    expect(eval61.reason).toContain("Suspicious clock divergence detected: cumulative divergence of 61s exceeds maximum ceiling (60s).");
    expect(guard.getState()).toBe("TRIPPED_CLOSED");
  });

  // 10. Anchor lifetime boundary (86,400s = 24 hours)
  it("enforces anchor lifetime boundary (86400s active, 86401s expired)", () => {
    const clock = new TestClock(1000);
    const guard = new ClockGuard(clock);

    // Initial anchor at (1000, 1000s)
    const cand0: ClockCandidate = { wallSeconds: 1000, monotonicNanos: 1_000_000_000_000n };
    expect(guard.evaluateCandidate(cand0, 1000).decision).toBe("ALLOW");
    guard.publishCandidate(cand0);

    // 24 hours later (86400s) with 0 divergence:
    const cand24h: ClockCandidate = {
      wallSeconds: 1000 + 86400,
      monotonicNanos: 1_000_000_000_000n + 86400n * 1_000_000_000n,
    };
    expect(guard.evaluateCandidate(cand24h, 1000).decision).toBe("ALLOW");
    guard.publishCandidate(cand24h);

    // 86401 seconds later -> EXPIRED
    const candExpired: ClockCandidate = {
      wallSeconds: 1000 + 86401,
      monotonicNanos: 1_000_000_000_000n + 86401n * 1_000_000_000n,
    };
    const evalExpired = guard.evaluateCandidate(candExpired, 1000);
    expect(evalExpired.decision).toBe("DENY");
    expect(evalExpired.reason).toContain("Process clock anchor has expired (maximum uptime exceeded); restart required.");
    expect(guard.getState()).toBe("EXPIRED");
  });

  // 11. Same-process transaction concurrency serialization
  it("enforces in-process transaction serialization via acquireLock/releaseLock", () => {
    const dbFile = databasePath();
    const clock = new TestClock(1000);
    const store = new SQLiteAuthorizationStore(dbFile, clock);
    const guard = store.getClockGuard();

    try {
      // Simulate transaction holding the in-process lock
      expect(guard.acquireLock()).toBe(true);
      // Second attempt to acquire lock in same process fails
      expect(guard.acquireLock()).toBe(false);

      // Attempting an operation while lock is held fails with serialization denial
      expect(() => store.advanceHighWaterMark(1005)).toThrow(
        "Concurrent transaction in progress within same process; operation serialized."
      );

      // Releasing lock allows subsequent transaction
      guard.releaseLock();
      expect(guard.acquireLock()).toBe(true);
      guard.releaseLock();

      expect(() => store.advanceHighWaterMark(1005)).not.toThrow();
      expect(store.getHighWaterMark()).toBe(1005);
    } finally {
      store.close();
    }
  });

  // 12. Audit Finding 1.3: ClockGuard initialization deferred until confirmed COMMIT
  describe("Audit Finding 1.3: ClockGuard initialization deferred until confirmed COMMIT", () => {
    it("does not publish initial sample or transition to ACTIVE if first transaction rolls back", () => {
      const dbFile = databasePath("init-rollback.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLiteAuthorizationStore(dbFile, clock);
      const guard = store.getClockGuard();

      try {
        expect(guard.getState()).toBe("UNINITIALIZED");
        expect(guard.getInitialSample()).toBeNull();
        expect(guard.getPublishedSample()).toBeNull();

        // Simulate first transaction that evaluates candidate but fails business validation / rolls back
        expect(() => {
          withImmediateTransaction(
            store.getDatabase(),
            () => {
              const cand: ClockCandidate = {
                wallSeconds: 1000,
                monotonicNanos: guard.getMonotonicClock().nowNanoseconds(),
              };
              const evalRes = guard.evaluateCandidate(cand, 1000);
              expect(evalRes.decision).toBe("ALLOW");
              // Inside transaction before commit: state is STILL UNINITIALIZED
              expect(guard.getState()).toBe("UNINITIALIZED");
              expect(guard.getInitialSample()).toBeNull();
              expect(guard.getPublishedSample()).toBeNull();

              // Fail business validation / abort transaction
              throw new Error("Business validation failure inside first transaction");
            },
            undefined,
            undefined,
            undefined,
            () => {
              // onCommitSuccess: not called
              guard.publishCandidate({
                wallSeconds: 1000,
                monotonicNanos: guard.getMonotonicClock().nowNanoseconds(),
              });
            },
          );
        }).toThrow("Business validation failure inside first transaction");

        // After rollback: state MUST remain UNINITIALIZED and samples MUST remain null
        expect(guard.getState()).toBe("UNINITIALIZED");
        expect(guard.getInitialSample()).toBeNull();
        expect(guard.getPublishedSample()).toBeNull();

        // Subsequent successful transaction transitions to ACTIVE and sets initial/published sample
        store.advanceHighWaterMark(1000);
        expect(guard.getState()).toBe("ACTIVE");
        expect(guard.getInitialSample()?.wallSeconds).toBe(1000);
        expect(guard.getPublishedSample()?.wallSeconds).toBe(1000);
      } finally {
        store.close();
      }
    });
  });

  // 13. Audit Finding 1.2: Newly started lagging worker behavior
  describe("Audit Finding 1.2: Newly started lagging worker behavior", () => {
    it("denies lagging worker without permanently tripping; succeeds once clock catches up", () => {
      const dbFile = databasePath("lagging-worker.sqlite");

      // Worker A starts and advances shared high water to 1050
      const clockA = new TestClock(1000);
      const storeA = new SQLiteAuthorizationStore(dbFile, clockA);
      storeA.advanceHighWaterMark(1000);
      clockA.advance(50);
      storeA.advanceHighWaterMark(1050);
      expect(storeA.getHighWaterMark()).toBe(1050);

      // Worker B starts fresh with clock at 1020 (behind shared high-water 1050)
      const clockB = new TestClock(1020);
      const storeB = new SQLiteAuthorizationStore(dbFile, clockB);
      const guardB = storeB.getClockGuard();

      try {
        expect(guardB.getState()).toBe("UNINITIALIZED");

        // Attempting operation when lagging is denied
        expect(() => storeB.advanceHighWaterMark(1020)).toThrow(
          "Clock rollback detected: current time (1020s) precedes persisted high-water mark (1050s)."
        );

        // Guard B must NOT be tripped into TRIPPED_CLOSED!
        expect(guardB.getState()).toBe("UNINITIALIZED");
        expect(guardB.getTripReason()).toBeUndefined();

        // Worker B's clock advances to 1055 (ahead of shared high-water 1050)
        clockB.set(1055);
        expect(() => storeB.advanceHighWaterMark(1055)).not.toThrow();

        // Worker B is now successfully ACTIVE
        expect(guardB.getState()).toBe("ACTIVE");
        expect(guardB.getPublishedSample()?.wallSeconds).toBe(1055);
        expect(storeB.getHighWaterMark()).toBe(1055);
      } finally {
        storeA.close();
        storeB.close();
      }
    });

    it("trips newly started worker when startup gap exceeds maxStartupForwardGapSeconds", () => {
      const dbFile = databasePath("startup-gap-trip.sqlite");

      // Initialize DB at 1000
      const storeInit = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      storeInit.advanceHighWaterMark(1000);
      storeInit.close();

      // Worker C starts with clock at 5000 (gap = 4000s > 3600s threshold)
      const clockC = new TestClock(5000);
      expect(() => new SQLiteAuthorizationStore(dbFile, clockC)).toThrow(
        "Store startup rejected: forward clock gap of 4000 seconds exceeds maximum allowed startup threshold (3600s)."
      );

      // Verify direct ClockGuard evaluation trips into TRIPPED_CLOSED
      const guardC = new ClockGuard(clockC);
      const cand = { wallSeconds: 5000, monotonicNanos: guardC.getMonotonicClock().nowNanoseconds() };
      const evalRes = guardC.evaluateCandidate(cand, 1000);
      expect(evalRes.decision).toBe("DENY");
      expect(evalRes.reason).toContain("Store startup rejected: forward clock gap of 4000 seconds exceeds maximum allowed startup threshold");
      expect(guardC.getState()).toBe("TRIPPED_CLOSED");
      expect(guardC.getTripReason()).toContain("forward clock gap of 4000 seconds exceeds maximum allowed startup threshold");
    });
  });

  // 14. Audit Finding 2.2: KeyStore clock protection and ClockGuard integration
  describe("Audit Finding 2.2: KeyStore clock protection and ClockGuard integration", () => {
    it("trips ClockGuard and rejects key registration on forward clock jump", () => {
      const dbFile = databasePath("keystore-clock-trip.sqlite");
      const clock = new TestClock(1000);
      const store = new SQLiteAuthorizationStore(dbFile, clock);
      store.advanceHighWaterMark(1000);

      const keyStore = store.getKeyStore();
      const guard = store.getClockGuard();
      const key = createKeypair();

      try {
        expect(guard.getState()).toBe("ACTIVE");

        // Simulate wall-clock forward jump of 50 seconds without monotonic advance (step divergence = 50 > 10)
        clock.advanceWallSeconds(50); // wall = 1050, monotonic = 1000s

        expect(() =>
          keyStore.registerKey({
            keyId: "jump-key",
            publicKey: key.publicKey,
            status: "active",
          })
        ).toThrow("Suspicious forward clock jump detected: step velocity divergence of 50s exceeds forward limit (10s).");

        // Guard must be tripped
        expect(guard.getState()).toBe("TRIPPED_CLOSED");
        // High-water mark in SQLite must NOT have advanced to 1050
        expect(store.getHighWaterMark()).toBe(1000);
        expect(keyStore.getHighWaterMark()).toBe(1000);

        // Key must not have been registered
        expect(keyStore.getKey("jump-key")).toBeNull();

        // Subsequent key mutations must be blocked because guard is tripped
        expect(() =>
          keyStore.registerKey({
            keyId: "another-key",
            publicKey: key.publicKey,
            status: "active",
          })
        ).toThrow("Store clock monitor is in a tripped state");

        expect(() => keyStore.advanceHighWaterMark(1000)).toThrow(
          "Store clock monitor is in a tripped state"
        );
      } finally {
        store.close();
      }
    });
  });

  // 15. Audit Finding 3.2: KeyStore & PolicyStore uncertain COMMIT handling
  describe("Audit Finding 3.2: KeyStore & PolicyStore uncertain COMMIT handling", () => {
    it("taints SQLiteKeyStore, closes connection, and propagates taint to parent store on commit failure", () => {
      const dbFile = databasePath("keystore-commit-fail.sqlite");
      let fatalCallbackCalled = false;
      const store = new SQLiteAuthorizationStore(dbFile, {
        clock: new TestClock(1000),
        onFatalTaint: () => {
          fatalCallbackCalled = true;
          throw new Error("Fatal callback threw unexpectedly");
        },
      });
      store.advanceHighWaterMark(1000);

      const keyStore = store.getKeyStore();
      const key = createKeypair();

      try {
        // Intercept COMMIT on SQLite connection to simulate uncertain commit failure
        const db = store.getDatabase();
        const originalExec = db.exec.bind(db);
        db.exec = (sql: string) => {
          if (typeof sql === "string" && sql.includes("COMMIT;")) {
            throw new Error("Simulated uncertain commit failure disk I/O error");
          }
          return originalExec(sql);
        };

        // Attempt registerKey which will throw commit failure
        expect(() =>
          keyStore.registerKey({
            keyId: "fail-key",
            publicKey: key.publicKey,
            status: "active",
          })
        ).toThrow("Simulated uncertain commit failure disk I/O error");

        // KeyStore must be tainted
        expect(keyStore.isTainted()).toBe(true);
        expect(() => keyStore.getKey("fail-key")).toThrow("database connection is tainted and unusable");

        // Parent store must also be tainted
        expect(store.isTainted()).toBe(true);
        expect(store.getClockGuard().isTainted()).toBe(true);
        expect(() => store.getHighWaterMark()).toThrow("database connection is tainted and unusable");

        // Fatal callback was invoked and its throw was safely caught without preventing fail-closed state
        expect(fatalCallbackCalled).toBe(true);
      } finally {
        try { store.close(); } catch {}
      }
    });

    it("taints SQLitePolicyStore, closes connection, and propagates taint to parent store on commit failure", () => {
      const dbFile = databasePath("policystore-commit-fail.sqlite");
      const store = new SQLiteAuthorizationStore(dbFile, new TestClock(1000));
      store.advanceHighWaterMark(1000);

      const policyStore = store.getPolicyStore();

      try {
        // Intercept COMMIT on SQLite connection to simulate uncertain commit failure
        const db = store.getDatabase();
        const originalExec = db.exec.bind(db);
        db.exec = (sql: string) => {
          if (typeof sql === "string" && sql.includes("COMMIT;")) {
            throw new Error("Simulated uncertain commit failure disk I/O error");
          }
          return originalExec(sql);
        };

        expect(() => policyStore.registerPolicy(validPolicy)).toThrow(
          "Simulated uncertain commit failure disk I/O error"
        );

        // PolicyStore must be tainted
        expect(policyStore.isTainted()).toBe(true);
        expect(() => policyStore.getPolicy("policy-m68")).toThrow("database connection is tainted and unusable");

        // Parent store must also be tainted
        expect(store.isTainted()).toBe(true);
        expect(store.getClockGuard().isTainted()).toBe(true);
      } finally {
        try { store.close(); } catch {}
      }
    });
  });
});
