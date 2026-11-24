/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.1
 * Pure State Machine Contracts & Reducer Unit Test Suite
 *
 * Verifies:
 * 1. Initial state defaults, properties, and immutability.
 * 2. Valid first application entry (EPOCH_INITIALIZE).
 * 3. Sequential application entries across multiple command types.
 * 4. Duplicate entry replay and idempotent no-op behavior.
 * 5. Duplicate replay with conflicting proposal identifier.
 * 6. Logical application index gap detection (fail-closed).
 * 7. Out-of-order entry rejection.
 * 8. Epoch boundary and cross-epoch mutation isolation.
 * 9. Invalid command payload and domain violation rejection.
 * 10. Deep state immutability (frozen objects, maps, and sets).
 * 11. Non-contiguous physical etcd revision progression (leaps).
 * 12. Multiple sub-indexes sharing a single etcd revision.
 * 13. Deterministic replay and recursive hash-chain integrity.
 * 14. 64-bit integer boundary values (> Number.MAX_SAFE_INTEGER).
 * 15. Quarantined epoch state-transition locking.
 * 16. Physical revision and sub-index regression detection.
 * 17. Cryptographic payload tamper detection.
 *
 * ZERO EXTERNAL I/O:
 * Runs 100% in memory; zero database, etcd, KMS, network, or cloud dependencies.
 */

import { describe, it, expect } from "vitest";
import {
  ConsensusStateMachine,
  createInitialState,
  computeCanonicalPayloadHash,
  BackpressurePolicy,
} from "../../src/witness/state-machine.js";
import {
  type CommittedConsensusEntry,
  type EpochInitializePayload,
  type EpochAdvancePayload,
  type EpochQuarantinePayload,
  type DelegationRevokePayload,
  type PolicyUpdatePayload,
  type TicketCommitPayload,
  BacklogLimitExceededError,
  EpochMismatchError,
  HistoricalIndexConflictError,
  InvalidCommandPayloadError,
  LogicalIndexGapError,
  OutOfOrderIndexError,
  PayloadHashMismatchError,
  QuarantinedEpochError,
  StateMachineError,
  UnverifiableHistoricalEntryError,
} from "../../src/witness/state-machine-types.js";

describe("Milestone 13-D Stage 2-B.1: Pure State Machine Reducer Suite", () => {
  // Helper to build typed entries with valid hashes
  function makeEntry<T = unknown>(
    overrides: Partial<CommittedConsensusEntry<any, T>> & {
      appLogIndex: bigint;
      commandType: any;
      payload: T;
    }
  ): CommittedConsensusEntry<any, T> {
    const payloadHash = computeCanonicalPayloadHash(overrides.payload);
    return {
      epochId: overrides.epochId ?? "epoch-test-01",
      appLogIndex: overrides.appLogIndex,
      raftTerm: overrides.raftTerm ?? 1n,
      physicalCursor: overrides.physicalCursor ?? {
        etcdRevision: 100n + overrides.appLogIndex,
        subIndex: 0,
      },
      commandType: overrides.commandType,
      payload: overrides.payload,
      payloadHash: overrides.payloadHash ?? payloadHash,
      proposalId: overrides.proposalId ?? `prop-${overrides.appLogIndex.toString()}`,
      committedAtSeconds: overrides.committedAtSeconds ?? 1700000000 + Number(overrides.appLogIndex),
    };
  }

  // --------------------------------------------------------------------------
  // Test 1: Initial State
  // --------------------------------------------------------------------------
  it("1. Initial state defaults, properties, and deep immutability", () => {
    const state = createInitialState("cluster-alpha");
    expect(state.clusterId).toBe("cluster-alpha");
    expect(state.epochId).toBe("");
    expect(state.epochHeight).toBe(0);
    expect(state.epochState).toBe("INITIAL");
    expect(state.lastAppliedAppIndex).toBe(0n);
    expect(state.lastAppliedRaftTerm).toBe(0n);
    expect(state.lastPhysicalCursor.etcdRevision).toBe(0n);
    expect(state.lastPhysicalCursor.subIndex).toBe(0);
    expect(state.chainHeadHash).toBe("");
    expect(state.lastSequenceNumber).toBe(0n);
    expect(state.committedTickets.size).toBe(0);
    expect(state.revokedAuthorizations.size).toBe(0);
    expect(state.policies.size).toBe(0);
    expect(state.appliedProposals.size).toBe(0);
    expect(state.appliedIndices.size).toBe(0);

    // Deep immutability checks
    expect(Object.isFrozen(state)).toBe(true);
    expect(Object.isFrozen(state.committedTickets)).toBe(true);
    expect(Object.isFrozen(state.revokedAuthorizations)).toBe(true);
    expect(Object.isFrozen(state.policies)).toBe(true);
    expect(Object.isFrozen(state.appliedProposals)).toBe(true);
    expect(Object.isFrozen(state.appliedIndices)).toBe(true);

    // Attempting to mutate throws in strict mode
    expect(() => {
      (state.committedTickets as any).set("foo", {} as any);
    }).toThrow();
    expect(() => {
      (state.revokedAuthorizations as any).add("foo");
    }).toThrow();
    expect(() => {
      (state.appliedIndices as any).set(1n, {} as any);
    }).toThrow();
  });

  // --------------------------------------------------------------------------
  // Test 2: Valid First Application Entry
  // --------------------------------------------------------------------------
  it("2. Valid first application entry (EPOCH_INITIALIZE) bootstraps state", () => {
    const initialState = createInitialState();
    const initEntry = makeEntry<EpochInitializePayload>({
      epochId: "epoch-2026-11",
      appLogIndex: 1n,
      raftTerm: 1n,
      physicalCursor: { etcdRevision: 500n, subIndex: 0 },
      commandType: "EPOCH_INITIALIZE",
      proposalId: "prop-init-01",
      payload: {
        epochId: "epoch-2026-11",
        epochHeight: 1,
        sequenceFloor: 100n,
        createdSeconds: 1700000000,
      },
    });

    const res = ConsensusStateMachine.apply(initialState, initEntry);
    expect(res.status).toBe("APPLIED");
    expect(res.appliedAppIndex).toBe(1n);
    expect(res.appliedRaftTerm).toBe(1n);
    expect(res.physicalCursor).toEqual({ etcdRevision: 500n, subIndex: 0 });
    expect(res.state.epochId).toBe("epoch-2026-11");
    expect(res.state.epochHeight).toBe(1);
    expect(res.state.epochState).toBe("ACTIVE");
    expect(res.state.lastSequenceNumber).toBe(100n);
    expect(res.state.lastAppliedAppIndex).toBe(1n);
    expect(res.state.chainHeadHash.length).toBe(64);
    expect(res.state.appliedProposals.get("prop-init-01")).toBe(1n);
    expect(Object.isFrozen(res.state)).toBe(true);
  });

  // --------------------------------------------------------------------------
  // Test 3: Sequential Application Entries
  // --------------------------------------------------------------------------
  it("3. Sequential application entries across multiple command types advance state", () => {
    let state = createInitialState();

    // 1. Initialize Epoch
    const r1 = ConsensusStateMachine.apply(
      state,
      makeEntry<EpochInitializePayload>({
        epochId: "epoch-seq",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "epoch-seq", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
      })
    );
    state = r1.state;

    // 2. Register Policy
    const r2 = ConsensusStateMachine.apply(
      state,
      makeEntry<PolicyUpdatePayload>({
        epochId: "epoch-seq",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol_transfer", revision: 1, policyHash: "hash-pol-1" },
      })
    );
    state = r2.state;
    expect(state.policies.get("pol_transfer")?.revision).toBe(1);

    // 3. Commit Ticket
    const r3 = ConsensusStateMachine.apply(
      state,
      makeEntry<TicketCommitPayload>({
        epochId: "epoch-seq",
        appLogIndex: 3n,
        commandType: "TICKET_COMMIT",
        payload: {
          ticketId: "ticket-001",
          epochId: "epoch-seq",
          authorizationId: "auth-001",
          bindingDigest: "sha256:abcd",
          policyId: "pol_transfer",
          policyRevision: 1,
          debitedAmount: 500n,
        },
      })
    );
    state = r3.state;
    expect(state.lastSequenceNumber).toBe(1n);
    expect(state.committedTickets.get("ticket-001")?.sequenceNumber).toBe(1n);

    // 4. Revoke Delegation
    const r4 = ConsensusStateMachine.apply(
      state,
      makeEntry<DelegationRevokePayload>({
        epochId: "epoch-seq",
        appLogIndex: 4n,
        commandType: "DELEGATION_REVOKE",
        payload: { epochId: "epoch-seq", authorizationId: "auth-001", revokedAtSeconds: 1700000050 },
      })
    );
    state = r4.state;
    expect(state.revokedAuthorizations.has("auth-001")).toBe(true);
    expect(state.lastAppliedAppIndex).toBe(4n);
  });

  // --------------------------------------------------------------------------
  // Test 4: Duplicate Entry Replay
  // --------------------------------------------------------------------------
  it("4. Duplicate entry replay is idempotent with zero state mutation", () => {
    const initialState = createInitialState();
    const entry1 = makeEntry<EpochInitializePayload>({
      epochId: "epoch-dup",
      appLogIndex: 1n,
      commandType: "EPOCH_INITIALIZE",
      proposalId: "prop-dup-1",
      payload: { epochId: "epoch-dup", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
    });

    const res1 = ConsensusStateMachine.apply(initialState, entry1);
    expect(res1.status).toBe("APPLIED");

    // Replay exact same entry
    const res2 = ConsensusStateMachine.apply(res1.state, entry1);
    expect(res2.status).toBe("ALREADY_APPLIED");
    expect(res2.duplicateDetected).toBe(true);
    expect(res2.appliedAppIndex).toBe(1n);
    expect(res2.state).toBe(res1.state); // Exact object identity preserved
  });

  // --------------------------------------------------------------------------
  // Test 5: Duplicate Replay with Conflicting Proposal & Payload (F-03)
  // --------------------------------------------------------------------------
  it("5. Duplicate replay with conflicting proposal ID or payload hash throws error", () => {
    const initialState = createInitialState();
    const entry1 = makeEntry<EpochInitializePayload>({
      epochId: "epoch-conflict",
      appLogIndex: 1n,
      commandType: "EPOCH_INITIALIZE",
      proposalId: "prop-original",
      payload: { epochId: "epoch-conflict", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
    });

    const res1 = ConsensusStateMachine.apply(initialState, entry1);

    // 1. Conflicting entry with same index (1n) but different proposal ID
    const conflictingProposalEntry = makeEntry<EpochInitializePayload>({
      epochId: "epoch-conflict",
      appLogIndex: 1n,
      commandType: "EPOCH_INITIALIZE",
      proposalId: "prop-different",
      payload: { epochId: "epoch-conflict", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
    });

    expect(() => {
      ConsensusStateMachine.apply(res1.state, conflictingProposalEntry);
    }).toThrow(HistoricalIndexConflictError);

    try {
      ConsensusStateMachine.apply(res1.state, conflictingProposalEntry);
    } catch (err: any) {
      expect(err.code).toBe("HISTORICAL_INDEX_PROPOSAL_ID_CONFLICT");
      expect(err.appLogIndex).toBe(1n);
    }

    // 2. Conflicting entry with same index and same proposal ID, but different payload
    const conflictingPayloadEntry: CommittedConsensusEntry<any, EpochInitializePayload> = {
      ...entry1,
      payload: { epochId: "epoch-conflict", epochHeight: 1, sequenceFloor: 999n, createdSeconds: 1700000000 },
      payloadHash: computeCanonicalPayloadHash({
        epochId: "epoch-conflict",
        epochHeight: 1,
        sequenceFloor: 999n,
        createdSeconds: 1700000000,
      }),
    };

    expect(() => {
      ConsensusStateMachine.apply(res1.state, conflictingPayloadEntry);
    }).toThrow(HistoricalIndexConflictError);

    try {
      ConsensusStateMachine.apply(res1.state, conflictingPayloadEntry);
    } catch (err: any) {
      expect(err.code).toBe("HISTORICAL_INDEX_PAYLOAD_HASH_CONFLICT");
      expect(err.appLogIndex).toBe(1n);
    }

    // 3. Historical replay against state where historical index was not recorded fails closed
    const stateWithoutIndex = {
      ...res1.state,
      appliedIndices: new Map(), // empty historical record
    } as any;

    expect(() => {
      ConsensusStateMachine.apply(stateWithoutIndex, entry1);
    }).toThrow(UnverifiableHistoricalEntryError);

    try {
      ConsensusStateMachine.apply(stateWithoutIndex, entry1);
    } catch (err: any) {
      expect(err.code).toBe("UNVERIFIABLE_HISTORICAL_ENTRY");
      expect(err.appLogIndex).toBe(1n);
    }

    // 4. Replaying known proposal at invalid index 0n
    expect(() => {
      ConsensusStateMachine.apply(res1.state, {
        ...entry1,
        appLogIndex: 0n,
      });
    }).toThrow(StateMachineError);
  });

  // --------------------------------------------------------------------------
  // Test 6: Logical Index Gap Detection
  // --------------------------------------------------------------------------
  it("6. Logical application index gap fails closed immediately", () => {
    const initialState = createInitialState();
    const initEntry = makeEntry<EpochInitializePayload>({
      epochId: "epoch-gap",
      appLogIndex: 1n,
      commandType: "EPOCH_INITIALIZE",
      payload: { epochId: "epoch-gap", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
    });
    const s1 = ConsensusStateMachine.apply(initialState, initEntry).state;

    // Propose index 3n instead of 2n (missing 2n)
    const gapEntry = makeEntry<PolicyUpdatePayload>({
      epochId: "epoch-gap",
      appLogIndex: 3n,
      commandType: "POLICY_UPDATE",
      payload: { policyId: "p1", revision: 1, policyHash: "hash-p1" },
    });

    expect(() => {
      ConsensusStateMachine.apply(s1, gapEntry);
    }).toThrow(LogicalIndexGapError);
  });

  // --------------------------------------------------------------------------
  // Test 7: Out-of-Order Entry Rejection
  // --------------------------------------------------------------------------
  it("7. Out-of-order entry is rejected or handled as duplicate", () => {
    let state = createInitialState();
    state = ConsensusStateMachine.apply(
      state,
      makeEntry<EpochInitializePayload>({
        epochId: "epoch-ooo",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "epoch-ooo", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
      })
    ).state;

    state = ConsensusStateMachine.apply(
      state,
      makeEntry<PolicyUpdatePayload>({
        epochId: "epoch-ooo",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "p1", revision: 1, policyHash: "hash-p1" },
      })
    ).state;

    // Stale entry with index 1n arrives after 2n has already been applied
    const staleEntry = makeEntry<EpochInitializePayload>({
      epochId: "epoch-ooo",
      appLogIndex: 1n,
      commandType: "EPOCH_INITIALIZE",
      payload: { epochId: "epoch-ooo", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
    });

    const res = ConsensusStateMachine.apply(state, staleEntry);
    expect(res.status).toBe("ALREADY_APPLIED");
    expect(res.appliedAppIndex).toBe(2n);
  });

  // --------------------------------------------------------------------------
  // Test 8: Epoch Boundary and Cross-Epoch Isolation
  // --------------------------------------------------------------------------
  it("8. Epoch mismatch is strictly rejected", () => {
    const state = ConsensusStateMachine.apply(
      createInitialState(),
      makeEntry<EpochInitializePayload>({
        epochId: "epoch-A",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "epoch-A", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
      })
    ).state;

    // Entry tagged for epoch-B submitted against epoch-A state
    const wrongEpochEntry = makeEntry<PolicyUpdatePayload>({
      epochId: "epoch-B",
      appLogIndex: 2n,
      commandType: "POLICY_UPDATE",
      payload: { policyId: "p1", revision: 1, policyHash: "hash-p1" },
    });

    expect(() => {
      ConsensusStateMachine.apply(state, wrongEpochEntry);
    }).toThrow(EpochMismatchError);
  });

  // --------------------------------------------------------------------------
  // Test 9: Invalid Command Payload and Domain Violation Rejection
  // --------------------------------------------------------------------------
  it("9. Invalid command payloads are rejected and domain rules enforced", () => {
    let state = ConsensusStateMachine.apply(
      createInitialState(),
      makeEntry<EpochInitializePayload>({
        epochId: "epoch-domain",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "epoch-domain", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
      })
    ).state;

    // Revoke authorization auth-blocked
    state = ConsensusStateMachine.apply(
      state,
      makeEntry<DelegationRevokePayload>({
        epochId: "epoch-domain",
        appLogIndex: 2n,
        commandType: "DELEGATION_REVOKE",
        payload: { epochId: "epoch-domain", authorizationId: "auth-blocked", revokedAtSeconds: 1700000010 },
      })
    ).state;

    // Attempt to commit ticket for the revoked authorization -> COMMAND_REJECTED
    const ticketEntry = makeEntry<TicketCommitPayload>({
      epochId: "epoch-domain",
      appLogIndex: 3n,
      commandType: "TICKET_COMMIT",
      payload: {
        ticketId: "ticket-revoked",
        epochId: "epoch-domain",
        authorizationId: "auth-blocked",
        bindingDigest: "sha256:ffff",
        policyId: "p1",
        policyRevision: 1,
        debitedAmount: 100n,
      },
    });

    const res = ConsensusStateMachine.apply(state, ticketEntry);
    expect(res.status).toBe("COMMAND_REJECTED");
    expect(res.rejectionReason).toContain("revoked");
    // State remains at index 2n; rejected command does not advance state
    expect(res.state.lastAppliedAppIndex).toBe(2n);

    // Malformed payload (missing policyId in POLICY_UPDATE)
    const malformedEntry = makeEntry<any>({
      epochId: "epoch-domain",
      appLogIndex: 3n,
      commandType: "POLICY_UPDATE",
      payload: { revision: 1 }, // missing policyId and policyHash
    });

    expect(() => {
      ConsensusStateMachine.apply(state, malformedEntry);
    }).toThrow(InvalidCommandPayloadError);
  });

  // --------------------------------------------------------------------------
  // Test 10: Deep State Immutability
  // --------------------------------------------------------------------------
  it("10. State immutability: all returned states and collections are frozen", () => {
    let state = createInitialState();
    expect(Object.isFrozen(state)).toBe(true);

    const res = ConsensusStateMachine.apply(
      state,
      makeEntry<EpochInitializePayload>({
        epochId: "epoch-frozen",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "epoch-frozen", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
      })
    );

    const s1 = res.state;
    expect(Object.isFrozen(s1)).toBe(true);
    expect(Object.isFrozen(s1.committedTickets)).toBe(true);
    expect(Object.isFrozen(s1.revokedAuthorizations)).toBe(true);
    expect(Object.isFrozen(s1.policies)).toBe(true);
    expect(Object.isFrozen(s1.appliedProposals)).toBe(true);
    expect(Object.isFrozen(s1.appliedIndices)).toBe(true);
    expect(Object.isFrozen(s1.lastPhysicalCursor)).toBe(true);
  });

  // --------------------------------------------------------------------------
  // Test 11: Non-Contiguous Physical Revision Leaps
  // --------------------------------------------------------------------------
  it("11. Non-contiguous physical revision leaps succeed cleanly", () => {
    let state = ConsensusStateMachine.apply(
      createInitialState(),
      makeEntry<EpochInitializePayload>({
        epochId: "epoch-leap",
        appLogIndex: 1n,
        physicalCursor: { etcdRevision: 100n, subIndex: 0 },
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "epoch-leap", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
      })
    ).state;

    // Physical revision leaps from 100n to 250n (e.g. 150 unrelated keyspace writes)
    // Logical application index strictly advances from 1n to 2n
    const leapingEntry = makeEntry<PolicyUpdatePayload>({
      epochId: "epoch-leap",
      appLogIndex: 2n,
      physicalCursor: { etcdRevision: 250n, subIndex: 0 },
      commandType: "POLICY_UPDATE",
      payload: { policyId: "pol_leap", revision: 1, policyHash: "hash-leap" },
    });

    const res = ConsensusStateMachine.apply(state, leapingEntry);
    expect(res.status).toBe("APPLIED");
    expect(res.appliedAppIndex).toBe(2n);
    expect(res.physicalCursor).toEqual({ etcdRevision: 250n, subIndex: 0 });
    expect(res.state.lastPhysicalCursor.etcdRevision).toBe(250n);
  });

  // --------------------------------------------------------------------------
  // Test 12: Multiple Sub-Indexes Sharing a Single etcd Revision
  // --------------------------------------------------------------------------
  it("12. Multiple sub-indexes within a single etcd revision execute sequentially", () => {
    let state = ConsensusStateMachine.apply(
      createInitialState(),
      makeEntry<EpochInitializePayload>({
        epochId: "epoch-multi",
        appLogIndex: 1n,
        physicalCursor: { etcdRevision: 500n, subIndex: 0 },
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "epoch-multi", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
      })
    ).state;

    // Multi-event transaction at revision 600n: Event 0 (subIndex = 0)
    const event0 = makeEntry<PolicyUpdatePayload>({
      epochId: "epoch-multi",
      appLogIndex: 2n,
      physicalCursor: { etcdRevision: 600n, subIndex: 0 },
      commandType: "POLICY_UPDATE",
      payload: { policyId: "p_batch1", revision: 1, policyHash: "hash-b1" },
    });
    state = ConsensusStateMachine.apply(state, event0).state;
    expect(state.lastAppliedAppIndex).toBe(2n);
    expect(state.lastPhysicalCursor).toEqual({ etcdRevision: 600n, subIndex: 0 });

    // Multi-event transaction at revision 600n: Event 1 (subIndex = 1)
    const event1 = makeEntry<PolicyUpdatePayload>({
      epochId: "epoch-multi",
      appLogIndex: 3n,
      physicalCursor: { etcdRevision: 600n, subIndex: 1 },
      commandType: "POLICY_UPDATE",
      payload: { policyId: "p_batch2", revision: 1, policyHash: "hash-b2" },
    });
    state = ConsensusStateMachine.apply(state, event1).state;
    expect(state.lastAppliedAppIndex).toBe(3n);
    expect(state.lastPhysicalCursor).toEqual({ etcdRevision: 600n, subIndex: 1 });
  });

  // --------------------------------------------------------------------------
  // Test 13: Deterministic Replay and Recursive Hash-Chain Integrity
  // --------------------------------------------------------------------------
  it("13. Replaying an identical log sequence independently computes identical state and hash", () => {
    const entries: CommittedConsensusEntry[] = [
      makeEntry<EpochInitializePayload>({
        epochId: "epoch-det",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "epoch-det", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
      }),
      makeEntry<PolicyUpdatePayload>({
        epochId: "epoch-det",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol_A", revision: 1, policyHash: "hash-A" },
      }),
      makeEntry<TicketCommitPayload>({
        epochId: "epoch-det",
        appLogIndex: 3n,
        commandType: "TICKET_COMMIT",
        payload: {
          ticketId: "t-1",
          epochId: "epoch-det",
          authorizationId: "auth-1",
          bindingDigest: "sha256:1111",
          policyId: "pol_A",
          policyRevision: 1,
          debitedAmount: 100n,
        },
      }),
      makeEntry<DelegationRevokePayload>({
        epochId: "epoch-det",
        appLogIndex: 4n,
        commandType: "DELEGATION_REVOKE",
        payload: { epochId: "epoch-det", authorizationId: "auth-1", revokedAtSeconds: 1700000100 },
      }),
    ];

    // Node 1 applies the sequence
    let state1 = createInitialState("cluster-test");
    for (const e of entries) {
      state1 = ConsensusStateMachine.apply(state1, e).state;
    }

    // Node 2 independently applies the exact same sequence
    let state2 = createInitialState("cluster-test");
    for (const e of entries) {
      state2 = ConsensusStateMachine.apply(state2, e).state;
    }

    // Assert absolute cryptographic parity
    expect(state1.chainHeadHash).toBe(state2.chainHeadHash);
    expect(state1.lastAppliedAppIndex).toBe(4n);
    expect(state1.lastSequenceNumber).toBe(state2.lastSequenceNumber);
    expect(state1.committedTickets.size).toBe(1);
    expect(state1.revokedAuthorizations.size).toBe(1);
  });

  // --------------------------------------------------------------------------
  // Test 14: 64-Bit Integer Boundary Values (> Number.MAX_SAFE_INTEGER)
  // --------------------------------------------------------------------------
  it("14. Correctly handles 64-bit integer values exceeding 53-bit MAX_SAFE_INTEGER", () => {
    // 9007199254740991 is Number.MAX_SAFE_INTEGER; we use larger values
    const bigIndex = 9007199254740995n;
    const bigRevision = 1844674407370955161n; // large 64-bit revision
    const bigFloor = 10000000000000000000n; // large uint64

    let state = ConsensusStateMachine.apply(
      createInitialState(),
      makeEntry<EpochInitializePayload>({
        epochId: "epoch-bigint",
        appLogIndex: 1n,
        physicalCursor: { etcdRevision: bigRevision, subIndex: 0 },
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "epoch-bigint", epochHeight: 1, sequenceFloor: bigFloor, createdSeconds: 1700000000 },
      })
    ).state;

    expect(state.lastSequenceNumber).toBe(bigFloor);
    expect(state.lastPhysicalCursor.etcdRevision).toBe(bigRevision);

    // Commit ticket allocating sequence beyond MAX_SAFE_INTEGER
    const commitEntry = makeEntry<TicketCommitPayload>({
      epochId: "epoch-bigint",
      appLogIndex: 2n,
      physicalCursor: { etcdRevision: bigRevision + 1n, subIndex: 0 },
      commandType: "TICKET_COMMIT",
      payload: {
        ticketId: "t-big",
        epochId: "epoch-bigint",
        authorizationId: "auth-big",
        bindingDigest: "sha256:9999",
        policyId: "p-big",
        policyRevision: 1,
        debitedAmount: 5000000000000000000n,
      },
    });

    state = ConsensusStateMachine.apply(state, commitEntry).state;
    expect(state.lastSequenceNumber).toBe(bigFloor + 1n);
    expect(state.committedTickets.get("t-big")?.sequenceNumber).toBe(bigFloor + 1n);
  });

  // --------------------------------------------------------------------------
  // Test 15: Quarantined Epoch State-Transition Locking
  // --------------------------------------------------------------------------
  it("15. Quarantined epoch blocks domain transitions", () => {
    let state = ConsensusStateMachine.apply(
      createInitialState(),
      makeEntry<EpochInitializePayload>({
        epochId: "epoch-quar",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "epoch-quar", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
      })
    ).state;

    // Quarantine epoch
    state = ConsensusStateMachine.apply(
      state,
      makeEntry<EpochQuarantinePayload>({
        epochId: "epoch-quar",
        appLogIndex: 2n,
        commandType: "EPOCH_QUARANTINE",
        payload: { epochId: "epoch-quar", reason: "CONSENSUS_DIVERGENCE_DETECTED", quarantinedAtSeconds: 1700000020 },
      })
    ).state;
    expect(state.epochState).toBe("QUARANTINED");

    // Attempting ticket commit on quarantined epoch throws QuarantinedEpochError
    const ticketEntry = makeEntry<TicketCommitPayload>({
      epochId: "epoch-quar",
      appLogIndex: 3n,
      commandType: "TICKET_COMMIT",
      payload: {
        ticketId: "t-q",
        epochId: "epoch-quar",
        authorizationId: "auth-q",
        bindingDigest: "sha256:0000",
        policyId: "p",
        policyRevision: 1,
        debitedAmount: 10n,
      },
    });

    expect(() => {
      ConsensusStateMachine.apply(state, ticketEntry);
    }).toThrow(QuarantinedEpochError);
  });

  // --------------------------------------------------------------------------
  // Test 16: Physical Revision and Sub-Index Regression Detection
  // --------------------------------------------------------------------------
  it("16. Physical revision and sub-index regressions are detected and rejected", () => {
    let state = ConsensusStateMachine.apply(
      createInitialState(),
      makeEntry<EpochInitializePayload>({
        epochId: "epoch-regress",
        appLogIndex: 1n,
        physicalCursor: { etcdRevision: 500n, subIndex: 1 },
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "epoch-regress", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
      })
    ).state;

    // Revision regressed to 499n while logical index advances to 2n
    const regressedRevEntry = makeEntry<PolicyUpdatePayload>({
      epochId: "epoch-regress",
      appLogIndex: 2n,
      physicalCursor: { etcdRevision: 499n, subIndex: 0 },
      commandType: "POLICY_UPDATE",
      payload: { policyId: "p", revision: 1, policyHash: "h" },
    });

    expect(() => {
      ConsensusStateMachine.apply(state, regressedRevEntry);
    }).toThrow(StateMachineError);

    // Sub-index regressed within same revision (subIndex 0 <= prior 1)
    const regressedSubIndexEntry = makeEntry<PolicyUpdatePayload>({
      epochId: "epoch-regress",
      appLogIndex: 2n,
      physicalCursor: { etcdRevision: 500n, subIndex: 1 },
      commandType: "POLICY_UPDATE",
      payload: { policyId: "p", revision: 1, policyHash: "h" },
    });

    expect(() => {
      ConsensusStateMachine.apply(state, regressedSubIndexEntry);
    }).toThrow(StateMachineError);
  });

  // --------------------------------------------------------------------------
  // Test 17: Cryptographic Payload Tamper Detection
  // --------------------------------------------------------------------------
  it("17. Tampered payload with mismatched payloadHash is detected and rejected", () => {
    const initialState = createInitialState();
    const entry = makeEntry<EpochInitializePayload>({
      epochId: "epoch-tamper",
      appLogIndex: 1n,
      commandType: "EPOCH_INITIALIZE",
      payload: { epochId: "epoch-tamper", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
      payloadHash: "0000000000000000000000000000000000000000000000000000000000000000", // forged hash
    });

    expect(() => {
      ConsensusStateMachine.apply(initialState, entry);
    }).toThrow(PayloadHashMismatchError);
  });

  // --------------------------------------------------------------------------
  // Test 18: F-01 Canonical Payload Hashing Determinism and Type Safety
  // --------------------------------------------------------------------------
  it("18. [F-01] Canonical payload hashing is deterministic and order-independent for keys", () => {
    // 1. Key insertion order independence
    const objA = { b: 1, a: 2, c: "test" };
    const objB = { a: 2, c: "test", b: 1 };
    expect(computeCanonicalPayloadHash(objA)).toBe(computeCanonicalPayloadHash(objB));

    // 2. Nested objects with different key ordering
    const nestedA = { outer: { z: 10, y: 20, x: { beta: true, alpha: false } } };
    const nestedB = { outer: { x: { alpha: false, beta: true }, y: 20, z: 10 } };
    expect(computeCanonicalPayloadHash(nestedA)).toBe(computeCanonicalPayloadHash(nestedB));

    // 3. Array order preservation (arrays are sequences: order MUST matter)
    const arrA = { items: [1, 2, 3] };
    const arrB = { items: [3, 2, 1] };
    expect(computeCanonicalPayloadHash(arrA)).not.toBe(computeCanonicalPayloadHash(arrB));

    // 4. BigInt support
    const bigObjA = { count: 100000000000000000n, label: "large" };
    const bigObjB = { label: "large", count: 100000000000000000n };
    expect(computeCanonicalPayloadHash(bigObjA)).toBe(computeCanonicalPayloadHash(bigObjB));

    // 5. Non-finite numbers throw TypeError
    expect(() => computeCanonicalPayloadHash({ num: NaN })).toThrow(TypeError);
    expect(() => computeCanonicalPayloadHash({ num: Infinity })).toThrow(TypeError);
    expect(() => computeCanonicalPayloadHash({ num: -Infinity })).toThrow(TypeError);

    // 6. Unsupported types (functions, symbols) throw TypeError
    expect(() => computeCanonicalPayloadHash({ fn: () => {} })).toThrow(TypeError);
    expect(() => computeCanonicalPayloadHash({ sym: Symbol("test") })).toThrow(TypeError);

    // 7. Null and undefined
    expect(computeCanonicalPayloadHash(null)).toBe(computeCanonicalPayloadHash(undefined));
  });

  // --------------------------------------------------------------------------
  // Test 19: F-02 PolicyRecord Immutability
  // --------------------------------------------------------------------------
  it("19. [F-02] PolicyRecord stored in state.policies is deeply frozen and throws on mutation", () => {
    const initialState = createInitialState();
    const initRes = ConsensusStateMachine.apply(
      initialState,
      makeEntry<EpochInitializePayload>({
        epochId: "epoch-policy-imm",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "epoch-policy-imm", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
      })
    );

    const policyRes = ConsensusStateMachine.apply(
      initRes.state,
      makeEntry<PolicyUpdatePayload>({
        epochId: "epoch-policy-imm",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: {
          policyId: "policy-immutable-01",
          revision: 1,
          policyHash: "hash-pol-imm",
          definitionJson: JSON.stringify({ maxAmount: 1000 }),
        },
      })
    );

    const policy = policyRes.state.policies.get("policy-immutable-01");
    expect(policy).toBeDefined();
    expect(Object.isFrozen(policy)).toBe(true);

    // Mutation attempts on PolicyRecord properties throw TypeError in strict mode
    expect(() => {
      (policy as any).revision = 999;
    }).toThrow(TypeError);

    expect(() => {
      (policy as any).policyHash = "tampered-hash";
    }).toThrow(TypeError);

    expect(() => {
      (policy as any).newField = "illegal";
    }).toThrow(TypeError);
  });

  // --------------------------------------------------------------------------
  // Test 20: F-03 Multi-Step Historical Index Replay and Tamper Resistance
  // --------------------------------------------------------------------------
  it("20. [F-03] appliedIndices accurately tracks multiple entries and blocks retroactive tampering", () => {
    let state = createInitialState();

    const entry1 = makeEntry<EpochInitializePayload>({
      epochId: "epoch-h",
      appLogIndex: 1n,
      commandType: "EPOCH_INITIALIZE",
      proposalId: "p-init",
      payload: { epochId: "epoch-h", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
    });
    state = ConsensusStateMachine.apply(state, entry1).state;

    const entry2 = makeEntry<PolicyUpdatePayload>({
      epochId: "epoch-h",
      appLogIndex: 2n,
      commandType: "POLICY_UPDATE",
      proposalId: "p-pol",
      payload: { policyId: "pol-1", revision: 1, policyHash: "h-pol-1" },
    });
    state = ConsensusStateMachine.apply(state, entry2).state;

    const entry3 = makeEntry<TicketCommitPayload>({
      epochId: "epoch-h",
      appLogIndex: 3n,
      commandType: "TICKET_COMMIT",
      proposalId: "p-tkt",
      payload: {
        ticketId: "t-001",
        epochId: "epoch-h",
        authorizationId: "auth-001",
        bindingDigest: "digest-001",
        policyId: "pol-1",
        policyRevision: 1,
        debitedAmount: 250n,
      },
    });
    state = ConsensusStateMachine.apply(state, entry3).state;

    expect(state.appliedIndices.size).toBe(3);
    expect(state.appliedIndices.get(1n)?.proposalId).toBe("p-init");
    expect(state.appliedIndices.get(2n)?.proposalId).toBe("p-pol");
    expect(state.appliedIndices.get(3n)?.proposalId).toBe("p-tkt");

    // Idempotent replay of historical index 2n
    const replayRes = ConsensusStateMachine.apply(state, entry2);
    expect(replayRes.status).toBe("ALREADY_APPLIED");
    expect(replayRes.duplicateDetected).toBe(true);

    // Tampered historical replay at index 2n: differing payloadHash
    const tamperedEntry2: CommittedConsensusEntry<any, PolicyUpdatePayload> = {
      ...entry2,
      payload: { policyId: "pol-1", revision: 2, policyHash: "h-pol-tampered" },
      payloadHash: computeCanonicalPayloadHash({ policyId: "pol-1", revision: 2, policyHash: "h-pol-tampered" }),
    };

    expect(() => {
      ConsensusStateMachine.apply(state, tamperedEntry2);
    }).toThrow(HistoricalIndexConflictError);

    try {
      ConsensusStateMachine.apply(state, tamperedEntry2);
    } catch (err: any) {
      expect(err.code).toBe("HISTORICAL_INDEX_PAYLOAD_HASH_CONFLICT");
    }

    // Tampered historical replay at index 2n: differing proposalId
    const tamperedPropEntry2: CommittedConsensusEntry<any, PolicyUpdatePayload> = {
      ...entry2,
      proposalId: "p-pol-spoofed",
    };

    expect(() => {
      ConsensusStateMachine.apply(state, tamperedPropEntry2);
    }).toThrow(HistoricalIndexConflictError);

    try {
      ConsensusStateMachine.apply(state, tamperedPropEntry2);
    } catch (err: any) {
      expect(err.code).toBe("HISTORICAL_INDEX_PROPOSAL_ID_CONFLICT");
    }
  });

  // ==========================================================================
  // Milestone 13-D Phase D3: Stage 2-B.2 - Retention Boundary & Backpressure Suite
  // ==========================================================================
  describe("Milestone 13-D Stage 2-B.2: Retention Boundary & Watch Backpressure", () => {
    // Helper to generate a chain of simple entries starting after genesis
    function applySequence(
      initialState: any,
      count: number,
      options?: any,
      startIdx: bigint = 2n
    ) {
      let state = initialState;
      const entries: CommittedConsensusEntry<any, any>[] = [];

      for (let i = 0; i < count; i++) {
        const idx = startIdx + BigInt(i);
        const policyPayload: PolicyUpdatePayload = {
          policyId: `pol-${idx.toString()}`,
          revision: Number(idx),
          policyHash: `hash-${idx.toString()}`,
        };
        const entry: CommittedConsensusEntry<any, PolicyUpdatePayload> = {
          epochId: state.epochId || "epoch-test-01",
          appLogIndex: idx,
          raftTerm: 1n,
          physicalCursor: { etcdRevision: 100n + idx, subIndex: 0 },
          commandType: "POLICY_UPDATE",
          payload: policyPayload,
          payloadHash: computeCanonicalPayloadHash(policyPayload),
          proposalId: `prop-${idx.toString()}`,
          committedAtSeconds: 1700000000 + Number(idx),
        };
        entries.push(entry);
        const res = ConsensusStateMachine.apply(state, entry, options);
        state = res.state;
      }
      return { state, entries };
    }

    // ------------------------------------------------------------------------
    // 1. Genesis & Initial State
    // ------------------------------------------------------------------------
    it("21. initializes retentionFloorIndex to 1n and lastConsecutivePersistedAppIndex to 0n", () => {
      const state = createInitialState("cluster-retention-test");
      expect(state.retentionFloorIndex).toBe(1n);
      expect(state.lastConsecutivePersistedAppIndex).toBe(0n);
    });

    it("22. preserves F_ret = 1n when applying initial genesis entry (EPOCH_INITIALIZE)", () => {
      const state0 = createInitialState();
      const initPayload: EpochInitializePayload = {
        epochId: "epoch-ret-01",
        epochHeight: 1,
        sequenceFloor: 100n,
        createdSeconds: 1700000000,
      };
      const entry1: CommittedConsensusEntry<any, EpochInitializePayload> = {
        epochId: "epoch-ret-01",
        appLogIndex: 1n,
        raftTerm: 1n,
        physicalCursor: { etcdRevision: 10n, subIndex: 0 },
        commandType: "EPOCH_INITIALIZE",
        payload: initPayload,
        payloadHash: computeCanonicalPayloadHash(initPayload),
        proposalId: "p-init-01",
        committedAtSeconds: 1700000000,
      };

      const res1 = ConsensusStateMachine.apply(state0, entry1);
      expect(res1.status).toBe("APPLIED");
      expect(res1.state.retentionFloorIndex).toBe(1n);
      expect(res1.retentionFloorIndex).toBe(1n);
    });

    // ------------------------------------------------------------------------
    // 2. Retention Floor Formula Boundaries
    // ------------------------------------------------------------------------
    it("23. calculates F_ret = max(1n, min(A_app - W_mem + 1n, L_c_persisted + 1n)) correctly", () => {
      // Nominal default: W_mem = 10,000n
      // A_app = 100n, L_c_persisted = 100n -> windowFloor = -9899n <= 1n -> F_ret = 1n
      expect(BackpressurePolicy.calculateRetentionFloor(100n, 100n, 10_000n)).toBe(1n);

      // A_app = 10,000n, L_c_persisted = 10,000n -> windowFloor = 1n -> F_ret = 1n
      expect(BackpressurePolicy.calculateRetentionFloor(10_000n, 10_000n, 10_000n)).toBe(1n);

      // Persistence watermark ahead: A_app = 10,005n, L_c_persisted = 10,005n
      // windowFloor = 10005 - 10000 + 1 = 6n; persistenceFloor = 10006n -> F_ret = 6n
      expect(BackpressurePolicy.calculateRetentionFloor(10_005n, 10_005n, 10_000n)).toBe(6n);

      // Persistence watermark behind: A_app = 10,005n, L_c_persisted = 3n (stalled persistence)
      // windowFloor = 6n; persistenceFloor = 3 + 1 = 4n -> min(6, 4) = 4n -> F_ret = 4n
      expect(BackpressurePolicy.calculateRetentionFloor(10_005n, 3n, 10_000n)).toBe(4n);

      // Persistence watermark completely stalled at 0n: A_app = 10,005n, L_c_persisted = 0n
      // windowFloor = 6n; persistenceFloor = 0 + 1 = 1n -> min(6, 1) = 1n -> F_ret = 1n
      expect(BackpressurePolicy.calculateRetentionFloor(10_005n, 0n, 10_000n)).toBe(1n);
    });

    // ------------------------------------------------------------------------
    // 3. Sliding Window & Dual-Map Eviction
    // ------------------------------------------------------------------------
    it("24. prunes appliedIndices and appliedProposals atomically below F_ret", () => {
      const state0 = createInitialState();
      const initPayload: EpochInitializePayload = {
        epochId: "epoch-ret-02",
        epochHeight: 1,
        sequenceFloor: 0n,
        createdSeconds: 1700000000,
      };
      const entry1: CommittedConsensusEntry<any, EpochInitializePayload> = {
        epochId: "epoch-ret-02",
        appLogIndex: 1n,
        raftTerm: 1n,
        physicalCursor: { etcdRevision: 10n, subIndex: 0 },
        commandType: "EPOCH_INITIALIZE",
        payload: initPayload,
        payloadHash: computeCanonicalPayloadHash(initPayload),
        proposalId: "p-init-02",
        committedAtSeconds: 1700000000,
      };
      const res1 = ConsensusStateMachine.apply(state0, entry1, { memoryRetentionWindow: 5n });

      // Apply 10 more entries with small memory window W_mem = 5n and persistence watermark caught up
      // Index 2 to 11
      const { state: finalState, entries } = applySequence(
        res1.state,
        10,
        { memoryRetentionWindow: 5n, lastConsecutivePersistedAppIndex: 11n },
        2n
      );

      // At index 11n, W_mem = 5n, L_c_persisted = 11n:
      // F_ret = max(1n, min(11 - 5 + 1, 11 + 1)) = max(1n, min(7, 12)) = 7n
      expect(finalState.lastAppliedAppIndex).toBe(11n);
      expect(finalState.retentionFloorIndex).toBe(7n);

      // Indices 1 to 6 MUST be pruned
      for (let i = 1n; i <= 6n; i++) {
        expect(finalState.appliedIndices.has(i)).toBe(false);
      }

      // Proposals for indices 1 to 6 MUST be pruned
      expect(finalState.appliedProposals.has("p-init-02")).toBe(false); // from entry 1
      for (let i = 2; i <= 6; i++) {
        expect(finalState.appliedProposals.has(`prop-${i}`)).toBe(false);
      }

      // Indices 7 to 11 MUST remain present
      for (let i = 7n; i <= 11n; i++) {
        expect(finalState.appliedIndices.has(i)).toBe(true);
        expect(finalState.appliedProposals.has(`prop-${i.toString()}`)).toBe(true);
      }

      // Exactly W_mem = 5 entries in memory
      expect(finalState.appliedIndices.size).toBe(5);
      expect(finalState.appliedProposals.size).toBe(5);
    });

    it("25. blocks pruning of unpersisted entries when persistence lags behind active window (INV-RET-01)", () => {
      const state0 = createInitialState();
      const initPayload: EpochInitializePayload = {
        epochId: "epoch-ret-03",
        epochHeight: 1,
        sequenceFloor: 0n,
        createdSeconds: 1700000000,
      };
      const entry1: CommittedConsensusEntry<any, EpochInitializePayload> = {
        epochId: "epoch-ret-03",
        appLogIndex: 1n,
        raftTerm: 1n,
        physicalCursor: { etcdRevision: 10n, subIndex: 0 },
        commandType: "EPOCH_INITIALIZE",
        payload: initPayload,
        payloadHash: computeCanonicalPayloadHash(initPayload),
        proposalId: "p-init-03",
        committedAtSeconds: 1700000000,
      };
      const res1 = ConsensusStateMachine.apply(state0, entry1, { memoryRetentionWindow: 5n });

      // Apply entries up to index 11n, but persistence is stalled at index 3n!
      const { state: finalState } = applySequence(
        res1.state,
        10,
        { memoryRetentionWindow: 5n, lastConsecutivePersistedAppIndex: 3n },
        2n
      );

      // A_app = 11n, W_mem = 5n, L_c_persisted = 3n
      // windowFloor = 11 - 5 + 1 = 7n; persistenceFloor = 3 + 1 = 4n
      // min(7, 4) = 4n -> F_ret = 4n
      expect(finalState.retentionFloorIndex).toBe(4n);

      // Unpersisted entries (indices 4, 5, 6, 7, 8, 9, 10, 11) MUST NOT be pruned!
      for (let i = 4n; i <= 11n; i++) {
        expect(finalState.appliedIndices.has(i)).toBe(true);
      }

      // Only persisted entries strictly below F_ret (indices 1, 2, 3) are pruned
      expect(finalState.appliedIndices.has(1n)).toBe(false);
      expect(finalState.appliedIndices.has(2n)).toBe(false);
      expect(finalState.appliedIndices.has(3n)).toBe(false);

      // Memory holds 8 entries (5 nominal + 3 lagging unpersisted entries)
      expect(finalState.appliedIndices.size).toBe(8);
    });

    // ------------------------------------------------------------------------
    // 4. Historical Replay & Conflict Detection Under Retention
    // ------------------------------------------------------------------------
    it("26. returns HISTORICAL_RECORD_PRUNED when replaying entries below F_ret", () => {
      const state0 = createInitialState();
      const initPayload: EpochInitializePayload = {
        epochId: "epoch-ret-04",
        epochHeight: 1,
        sequenceFloor: 0n,
        createdSeconds: 1700000000,
      };
      const entry1: CommittedConsensusEntry<any, EpochInitializePayload> = {
        epochId: "epoch-ret-04",
        appLogIndex: 1n,
        raftTerm: 1n,
        physicalCursor: { etcdRevision: 10n, subIndex: 0 },
        commandType: "EPOCH_INITIALIZE",
        payload: initPayload,
        payloadHash: computeCanonicalPayloadHash(initPayload),
        proposalId: "p-init-04",
        committedAtSeconds: 1700000000,
      };
      const res1 = ConsensusStateMachine.apply(state0, entry1, { memoryRetentionWindow: 3n });

      const { state: finalState, entries } = applySequence(
        res1.state,
        5,
        { memoryRetentionWindow: 3n, lastConsecutivePersistedAppIndex: 6n },
        2n
      );

      // At index 6n with W_mem = 3n and caught up persistence:
      // F_ret = max(1n, min(6 - 3 + 1, 6 + 1)) = 4n
      expect(finalState.retentionFloorIndex).toBe(4n);

      // Replay entry 1 (pruned: 1 < 4)
      const replayRes1 = ConsensusStateMachine.apply(finalState, entry1);
      expect(replayRes1.status).toBe("HISTORICAL_RECORD_PRUNED");
      expect(replayRes1.state).toBe(finalState); // Zero state mutation

      // Replay entry 2 (pruned: 2 < 4)
      const replayRes2 = ConsensusStateMachine.apply(finalState, entries[0]); // index 2
      expect(replayRes2.status).toBe("HISTORICAL_RECORD_PRUNED");

      // Replay entry 5 (retained: 5 >= 4)
      const replayRes5 = ConsensusStateMachine.apply(finalState, entries[3]); // index 5
      expect(replayRes5.status).toBe("ALREADY_APPLIED");
      expect(replayRes5.duplicateDetected).toBe(true);
    });

    it("27. throws UnverifiableHistoricalEntryError if an entry >= F_ret is missing from in-memory state", () => {
      const state0 = createInitialState();
      const initPayload: EpochInitializePayload = {
        epochId: "epoch-ret-05",
        epochHeight: 1,
        sequenceFloor: 0n,
        createdSeconds: 1700000000,
      };
      const entry1: CommittedConsensusEntry<any, EpochInitializePayload> = {
        epochId: "epoch-ret-05",
        appLogIndex: 1n,
        raftTerm: 1n,
        physicalCursor: { etcdRevision: 10n, subIndex: 0 },
        commandType: "EPOCH_INITIALIZE",
        payload: initPayload,
        payloadHash: computeCanonicalPayloadHash(initPayload),
        proposalId: "p-init-05",
        committedAtSeconds: 1700000000,
      };
      const res1 = ConsensusStateMachine.apply(state0, entry1);
      const { state: finalState } = applySequence(res1.state, 3, {}, 2n);

      // Construct a corrupted state where index 3n is deleted from appliedIndices while F_ret is 1n
      const corruptIndices = new Map(finalState.appliedIndices);
      corruptIndices.delete(3n);
      const corruptedState = Object.freeze({
        ...finalState,
        appliedIndices: corruptIndices,
      });

      const entry3: CommittedConsensusEntry<any, any> = {
        epochId: "epoch-ret-05",
        appLogIndex: 3n,
        raftTerm: 1n,
        physicalCursor: { etcdRevision: 103n, subIndex: 0 },
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-3", revision: 3, policyHash: "hash-3" },
        payloadHash: computeCanonicalPayloadHash({ policyId: "pol-3", revision: 3, policyHash: "hash-3" }),
        proposalId: "prop-3",
        committedAtSeconds: 1700000003,
      };

      expect(() => {
        ConsensusStateMachine.apply(corruptedState as any, entry3);
      }).toThrow(UnverifiableHistoricalEntryError);
    });

    // ------------------------------------------------------------------------
    // 5. Watermark Regressions & Invalid Configuration
    // ------------------------------------------------------------------------
    it("28. rejects regressing persistence watermarks and invalid retention options", () => {
      const state0 = createInitialState();
      const initPayload: EpochInitializePayload = {
        epochId: "epoch-ret-06",
        epochHeight: 1,
        sequenceFloor: 0n,
        createdSeconds: 1700000000,
      };
      const entry1: CommittedConsensusEntry<any, EpochInitializePayload> = {
        epochId: "epoch-ret-06",
        appLogIndex: 1n,
        raftTerm: 1n,
        physicalCursor: { etcdRevision: 10n, subIndex: 0 },
        commandType: "EPOCH_INITIALIZE",
        payload: initPayload,
        payloadHash: computeCanonicalPayloadHash(initPayload),
        proposalId: "p-init-06",
        committedAtSeconds: 1700000000,
      };

      // Set watermark to 10n on apply
      const res1 = ConsensusStateMachine.apply(state0, entry1, {
        lastConsecutivePersistedAppIndex: 10n,
      });
      expect(res1.state.lastConsecutivePersistedAppIndex).toBe(10n);

      const entry2: CommittedConsensusEntry<any, any> = {
        epochId: "epoch-ret-06",
        appLogIndex: 2n,
        raftTerm: 1n,
        physicalCursor: { etcdRevision: 11n, subIndex: 0 },
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-2", revision: 2, policyHash: "hash-2" },
        payloadHash: computeCanonicalPayloadHash({ policyId: "pol-2", revision: 2, policyHash: "hash-2" }),
        proposalId: "p-pol-02",
        committedAtSeconds: 1700000002,
      };

      // Attempt to regress watermark from 10n to 5n
      expect(() => {
        ConsensusStateMachine.apply(res1.state, entry2, {
          lastConsecutivePersistedAppIndex: 5n,
        });
      }).toThrowError(/Persistence watermark cannot regress backwards/);

      // Attempt negative watermark
      expect(() => {
        ConsensusStateMachine.apply(res1.state, entry2, {
          lastConsecutivePersistedAppIndex: -1n,
        });
      }).toThrowError(/Persistence watermark must be non-negative/);

      // Attempt invalid retention window (<= 0n)
      expect(() => {
        ConsensusStateMachine.apply(res1.state, entry2, {
          memoryRetentionWindow: 0n,
        });
      }).toThrowError(/Memory retention window must be strictly positive/);

      expect(() => {
        ConsensusStateMachine.apply(res1.state, entry2, {
          memoryRetentionWindow: -5n,
        });
      }).toThrowError(/Memory retention window must be strictly positive/);
    });

    // ------------------------------------------------------------------------
    // 6. BackpressurePolicy Hysteresis & Alert Decisions
    // ------------------------------------------------------------------------
    it("29. evaluates pause/resume hysteresis thresholds accurately", () => {
      // 1. STREAMING with nominal lag (100n < 1,000n): stays STREAMING
      const eval1 = BackpressurePolicy.evaluate("STREAMING", 500n, 400n, 500n);
      expect(eval1.streamState).toBe("STREAMING");
      expect(eval1.action).toBe("CONTINUE");
      expect(eval1.isPaused).toBe(false);
      expect(eval1.alertLevel).toBe("NOMINAL");

      // 2. STREAMING with warning lag (500n <= lag < 1,000n): stays STREAMING, alert WARNING
      const eval2 = BackpressurePolicy.evaluate("STREAMING", 600n, 100n, 600n);
      expect(eval2.streamState).toBe("STREAMING");
      expect(eval2.action).toBe("CONTINUE");
      expect(eval2.isPaused).toBe(false);
      expect(eval2.warningTriggered).toBe(true);
      expect(eval2.alertLevel).toBe("WARNING");

      // 3. STREAMING with pause-threshold lag (lag = 1,000n): transitions to BACKPRESSURE_PAUSED
      const eval3 = BackpressurePolicy.evaluate("STREAMING", 1200n, 200n, 1200n);
      expect(eval3.streamState).toBe("BACKPRESSURE_PAUSED");
      expect(eval3.action).toBe("PAUSE_STREAM");
      expect(eval3.isPaused).toBe(true);

      // 4. BACKPRESSURE_PAUSED in hysteresis gap (lag = 750n, between 500n and 1,000n): remains PAUSED
      const eval4 = BackpressurePolicy.evaluate("BACKPRESSURE_PAUSED", 1000n, 250n, 1000n);
      expect(eval4.streamState).toBe("BACKPRESSURE_PAUSED");
      expect(eval4.action).toBe("CONTINUE");
      expect(eval4.isPaused).toBe(true);

      // 5. BACKPRESSURE_PAUSED drains to resume threshold (lag = 500n <= 500n): transitions to STREAMING
      const eval5 = BackpressurePolicy.evaluate("BACKPRESSURE_PAUSED", 1000n, 500n, 1000n);
      expect(eval5.streamState).toBe("STREAMING");
      expect(eval5.action).toBe("RESUME_STREAM");
      expect(eval5.isPaused).toBe(false);

      // 6. BACKPRESSURE_PAUSED sustained for >= 30 seconds: triggers CRITICAL alert
      const eval6 = BackpressurePolicy.evaluate("BACKPRESSURE_PAUSED", 2000n, 500n, 2000n, 35);
      expect(eval6.alertLevel).toBe("CRITICAL");
      expect(eval6.criticalAlertTriggered).toBe(true);
    });

    it("30. triggers ABORT_OVERFLOW on hard backlog ceiling and HALT_RETRY_EXHAUSTED", () => {
      // Hard backlog ceiling: inMemoryBacklog > 11,000n
      const evalBacklog = BackpressurePolicy.evaluate("STREAMING", 20_000n, 19_500n, 11_001n);
      expect(evalBacklog.action).toBe("ABORT_OVERFLOW");

      // Retry exhaustion: retryAttempts >= 5
      const evalRetry = BackpressurePolicy.evaluate(
        "BACKPRESSURE_PAUSED",
        5000n,
        1000n,
        4000n,
        10,
        5 // 5 retries
      );
      expect(evalRetry.action).toBe("HALT_RETRY_EXHAUSTED");
      expect(evalRetry.retryExhausted).toBe(true);
    });

    it("31. throws BacklogLimitExceededError in ConsensusStateMachine.apply when backlog ceiling breached", () => {
      const state0 = createInitialState();
      const initPayload: EpochInitializePayload = {
        epochId: "epoch-ret-07",
        epochHeight: 1,
        sequenceFloor: 0n,
        createdSeconds: 1700000000,
      };
      const entry1: CommittedConsensusEntry<any, EpochInitializePayload> = {
        epochId: "epoch-ret-07",
        appLogIndex: 1n,
        raftTerm: 1n,
        physicalCursor: { etcdRevision: 10n, subIndex: 0 },
        commandType: "EPOCH_INITIALIZE",
        payload: initPayload,
        payloadHash: computeCanonicalPayloadHash(initPayload),
        proposalId: "p-init-07",
        committedAtSeconds: 1700000000,
      };

      // Set maxBacklog to 2n
      const res1 = ConsensusStateMachine.apply(state0, entry1, {
        backpressureConfig: { maxBacklog: 2n },
      });

      const entry2: CommittedConsensusEntry<any, any> = {
        epochId: "epoch-ret-07",
        appLogIndex: 2n,
        raftTerm: 1n,
        physicalCursor: { etcdRevision: 11n, subIndex: 0 },
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-2", revision: 2, policyHash: "hash-2" },
        payloadHash: computeCanonicalPayloadHash({ policyId: "pol-2", revision: 2, policyHash: "hash-2" }),
        proposalId: "p-pol-02",
        committedAtSeconds: 1700000002,
      };
      const res2 = ConsensusStateMachine.apply(res1.state, entry2, {
        backpressureConfig: { maxBacklog: 2n },
      });
      expect(res2.state.appliedIndices.size).toBe(2);

      const entry3: CommittedConsensusEntry<any, any> = {
        epochId: "epoch-ret-07",
        appLogIndex: 3n,
        raftTerm: 1n,
        physicalCursor: { etcdRevision: 12n, subIndex: 0 },
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-3", revision: 3, policyHash: "hash-3" },
        payloadHash: computeCanonicalPayloadHash({ policyId: "pol-3", revision: 3, policyHash: "hash-3" }),
        proposalId: "p-pol-03",
        committedAtSeconds: 1700000003,
      };

      // Adding index 3n causes in-memory backlog to reach 3, exceeding maxBacklog = 2n!
      expect(() => {
        ConsensusStateMachine.apply(res2.state, entry3, {
          backpressureConfig: { maxBacklog: 2n },
          enforceBacklogLimit: true,
        });
      }).toThrow(BacklogLimitExceededError);
    });

    it("32. rejects invalid BackpressurePolicy threshold configurations", () => {
      // resumeThreshold >= pauseThreshold
      expect(() => {
        BackpressurePolicy.evaluate("STREAMING", 100n, 100n, 100n, 0, 0, {
          pauseThreshold: 500n,
          resumeThreshold: 500n,
        });
      }).toThrowError(/must be strictly less than pause threshold/);

      expect(() => {
        BackpressurePolicy.evaluate("STREAMING", 100n, 100n, 100n, 0, 0, {
          pauseThreshold: 500n,
          resumeThreshold: 600n,
        });
      }).toThrowError(/must be strictly less than pause threshold/);

      // Non-positive thresholds
      expect(() => {
        BackpressurePolicy.evaluate("STREAMING", 100n, 100n, 100n, 0, 0, {
          pauseThreshold: 0n,
        });
      }).toThrowError(/must be strictly positive/);
    });
  });
});
