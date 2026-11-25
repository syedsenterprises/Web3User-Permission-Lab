# Web3User — Milestone 13-D Phase D3: Stage 2-B.1.1
# Independent Correctness Audit Report

**Date:** 2026-11-23  
**Auditor:** Independent Technical Auditor  
**Audit Target:** Stage 2-B.1.1 Corrective Implementation (`docs/M13-D-STAGE-2B1-1-CORRECTNESS-CLOSURE.md`)  
**Scope:** `src/witness/state-machine-types.ts`, `src/witness/state-machine.ts`, `test/witness/state-machine.test.ts`  
**Prior Reference:** `docs/M13-D-STAGE-2B1-INDEPENDENT-AUDIT.md`  
**Governance:** Strict Read-Only Audit (Zero code modifications, zero Git mutations)

---

## 1. Executive Verdict

### **VERDICT: PASS WITH CONDITIONS**

The corrective implementation in Stage 2-B.1.1 resolves the three vulnerabilities identified in the initial Stage 2-B.1 audit:
1. **F-01 (Canonical Payload Hashing):** **RESOLVED.** Object keys are lexicographically sorted via recursive parsing, array sequences are preserved, and non-finite numbers/unsupported types fail closed. (See Condition 1 regarding BigInt/string type disambiguation).
2. **F-02 (PolicyRecord Immutability):** **RESOLVED.** Every instantiated `PolicyRecord` is shallow-frozen with `Object.freeze()`. Because all internal fields are primitive types (`string`, `number`, or `undefined`), shallow freezing provides complete deep immutability.
3. **F-03 (Historical Replay Integrity):** **RESOLVED.** `ApplicationState` tracks historical applications in `appliedIndices: ReadonlyMap<bigint, AppliedIndexRecord>`. Exact replays return `ALREADY_APPLIED`, conflicting proposal IDs or payload hashes throw `HistoricalIndexConflictError`, and untracked indices fail closed with `UnverifiableHistoricalEntryError`.

### Conditions for Subsequent Stages (Stage 2-B.2 / Stage 3-A)
- **Condition 1 (Memory Compaction & Retention Decision):** In-memory collections `appliedIndices` and `appliedProposals` grow strictly monotonically without bound ($O(N)$ with total consensus events). When persistent snapshotting and etcd log compaction are introduced, replaying an index pruned from memory will fail closed with `UnverifiableHistoricalEntryError`. An explicit architectural decision is required on the historical retention horizon (e.g. sliding window of the last $N$ entries or active epoch boundary) prior to long-running multi-node deployment.
- **Condition 2 (Type Disambiguation in Dynamic Payloads):** `BigInt` serialization in `canonicalizeValue` converts `100n` to `"\"100\""`, which matches string `"100"`. Within existing strictly-typed payload contracts (`EpochInitializePayload`, `TicketCommitPayload`), field types are invariant and cannot collide. If dynamically typed payloads are introduced in future revisions, BigInt should use an explicit type tag or distinct JSON scalar encoding.

---

## 2. Finding-by-Finding Detailed Audit

### 2.1 Finding F-01: Canonical Payload Hashing
**Files:** [state-machine.ts](file:///c:/Users/syeds/Projects/Web3User/src/witness/state-machine.ts#L118-L176), [state-machine.test.ts](file:///c:/Users/syeds/Projects/Web3User/test/witness/state-machine.test.ts#L793-L828)

#### Source Inspection
```typescript
function canonicalizeValue(val: unknown): string {
  if (val === null) return "null";
  if (val === undefined) throw new TypeError("Cannot canonicalize undefined value");
  const type = typeof val;
  if (type === "boolean") return val ? "true" : "false";
  if (type === "number") {
    if (!Number.isFinite(val)) throw new TypeError(`Cannot canonicalize non-finite number: ${String(val)}`);
    return JSON.stringify(val);
  }
  if (type === "bigint") return JSON.stringify((val as bigint).toString());
  if (type === "string") return JSON.stringify(val);
  if (Array.isArray(val)) {
    const elements = val.map((item) => canonicalizeValue(item));
    return `[${elements.join(",")}]`;
  }
  if (type === "object") {
    const obj = val as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const entries: string[] = [];
    for (const key of keys) {
      const v = obj[key];
      if (v !== undefined) {
        entries.push(`${JSON.stringify(key)}:${canonicalizeValue(v)}`);
      }
    }
    return `{${entries.join(",")}}`;
  }
  throw new TypeError(`Unsupported type for canonical serialization: ${type}`);
}
```

#### Detailed Verification Criteria
1. **Recursive Lexicographical Key Ordering:**
   - Lines 154-162 sort object keys via `Object.keys(obj).sort()` (lexicographical UTF-16 code unit ordering) and recursively canonicalize each property value `canonicalizeValue(v)`.
   - Verified that `{ b: 1, a: 2 }` and `{ a: 2, b: 1 }` produce identical output `{"a":2,"b":1}`.
   - Deeply nested structures recursively sort all child object keys at each nesting depth.
2. **Array Order Preservation:**
   - Lines 148-151 use `val.map(...)` over the array. Array element order is strictly preserved (`[1, 2]` produces `[1,2]`, while `[2, 1]` produces `[2,1]`).
3. **Fail-Closed Type Safety:**
   - Non-finite numbers (`NaN`, `Infinity`, `-Infinity`) throw `TypeError` (lines 137-139).
   - Direct `undefined` values throw `TypeError` (lines 129-131).
   - Functions and symbols throw `TypeError` (line 164).
4. **BigInt Serialization & Cross-Type Analysis:**
   - Line 143 serializes `BigInt` via `JSON.stringify(val.toString())`.
   - **Audit finding:** If a payload has an untyped field where object A has `{ amount: 100n }` and object B has `{ amount: "100" }`, both serialize to `{"amount":"100"}`. In the current typed schemas (`ConsensusPayloadMap`), all BigInt fields are strictly declared as `bigint` (e.g. `sequenceFloor: bigint`, `debitedAmount: bigint`, `cumulativeSpentAfter: bigint`) and string fields are strictly declared as `string`. Within the validated domain schemas, cross-type collision is impossible.
5. **Contract Compatibility:**
   - SHA-256 output is a 64-character lowercase hex string, exactly compatible with `payloadHash` expectations in `CommittedConsensusEntry`.

---

### 2.2 Finding F-02: PolicyRecord Immutability
**Files:** [state-machine.ts](file:///c:/Users/syeds/Projects/Web3User/src/witness/state-machine.ts#L618-L627), [state-machine.test.ts](file:///c:/Users/syeds/Projects/Web3User/test/witness/state-machine.test.ts#L830-L878)

#### Source Inspection
```typescript
    // F-02: Freeze individual PolicyRecord instance
    const policyRecord: PolicyRecord = Object.freeze({
      policyId: p.policyId,
      revision: p.revision,
      policyHash: p.policyHash,
      definitionJson: p.definitionJson,
    });

    const nextPolicies = new Map(state.policies);
    nextPolicies.set(p.policyId, policyRecord);
```

#### Detailed Verification Criteria
1. **Record Freezing:**
   - The instantiated `PolicyRecord` is frozen via `Object.freeze()` on line 619 before being set into `nextPolicies`.
2. **Field Depth Verification:**
   - `PolicyRecord` comprises:
     - `policyId`: `string`
     - `revision`: `number`
     - `policyHash`: `string`
     - `definitionJson`: `string | undefined`
   - Because all 4 properties are primitive values, shallow freezing via `Object.freeze()` guarantees complete deep immutability.
3. **Mutation Resistance:**
   - Property reassignment (`(policy as any).revision = 999`) throws `TypeError: Cannot assign to read only property 'revision' of object '#<Object>'`.
   - Property addition (`(policy as any).extra = 1`) throws `TypeError: Cannot add property extra, object is not extensible`.
4. **Container Isolation:**
   - `nextPolicies` is wrapped in `new ReadonlyFrozenMap(nextPolicies)` (line 634), which overrides `set()`, `delete()`, and `clear()` to throw `TypeError`.

---

### 2.3 Finding F-03: Historical Replay Integrity & Fail-Closed Validation
**Files:** [state-machine-types.ts](file:///c:/Users/syeds/Projects/Web3User/src/witness/state-machine-types.ts#L180-L184, L199, L271-290), [state-machine.ts](file:///c:/Users/syeds/Projects/Web3User/src/witness/state-machine.ts#L253-L285, L368-390), [state-machine.test.ts](file:///c:/Users/syeds/Projects/Web3User/test/witness/state-machine.test.ts#L250-L327, L880-L952)

#### Source Inspection
```typescript
    // ------------------------------------------------------------------------
    // 2. Duplicate Replay & Idempotency Check (F-03)
    // ------------------------------------------------------------------------
    if (entry.appLogIndex <= state.lastAppliedAppIndex) {
      const historicalRecord = state.appliedIndices.get(entry.appLogIndex);
      if (!historicalRecord) {
        throw new UnverifiableHistoricalEntryError(entry.appLogIndex);
      }

      if (historicalRecord.proposalId !== entry.proposalId) {
        throw new HistoricalIndexConflictError(
          entry.appLogIndex,
          "PROPOSAL_ID",
          `Historical index conflict at index ${entry.appLogIndex.toString()}: recorded proposalId '${historicalRecord.proposalId}', replayed with '${entry.proposalId}'`
        );
      }

      if (historicalRecord.payloadHash !== computedPayloadHash) {
        throw new HistoricalIndexConflictError(
          entry.appLogIndex,
          "PAYLOAD_HASH",
          `Historical index conflict at index ${entry.appLogIndex.toString()}: recorded payloadHash '${historicalRecord.payloadHash}', replayed with '${computedPayloadHash}'`
        );
      }

      // Check proposal ID uniqueness across indices
      const recordedIndexForProposal = state.appliedProposals.get(entry.proposalId);
      if (recordedIndexForProposal !== undefined && recordedIndexForProposal !== entry.appLogIndex) {
        throw new StateMachineError(
          `Proposal ID '${entry.proposalId}' was previously applied at index ${recordedIndexForProposal.toString()}, but replayed at index ${entry.appLogIndex.toString()}`,
          "PROPOSAL_ID_INDEX_CONFLICT"
        );
      }

      // Safe idempotent duplicate replay: return existing state untouched
      return {
        status: "ALREADY_APPLIED",
        appliedAppIndex: state.lastAppliedAppIndex,
        appliedRaftTerm: state.lastAppliedRaftTerm,
        physicalCursor: state.lastPhysicalCursor,
        chainHeadHash: state.chainHeadHash,
        state,
        duplicateDetected: true,
      };
    }
```

#### Detailed Verification Criteria
1. **Identity Establishment:**
   - Replay is accepted if and only if both `historicalRecord.proposalId === entry.proposalId` AND `historicalRecord.payloadHash === computedPayloadHash`.
2. **Conflicting Proposal ID Rejection:**
   - If an entry arrives with $L_{app} \le A_{app}$ where `proposalId` differs from `historicalRecord.proposalId`, `HistoricalIndexConflictError` is thrown with error code `HISTORICAL_INDEX_PROPOSAL_ID_CONFLICT`.
3. **Conflicting Payload Hash Rejection:**
   - If an entry arrives with $L_{app} \le A_{app}$ where the computed canonical payload hash differs from `historicalRecord.payloadHash`, `HistoricalIndexConflictError` is thrown with error code `HISTORICAL_INDEX_PAYLOAD_HASH_CONFLICT`.
4. **Fail-Closed Unknown Historical Index:**
   - If $L_{app} \le A_{app}$ but `state.appliedIndices.get(L_app)` returns `undefined`, the reducer throws `UnverifiableHistoricalEntryError` with error code `UNVERIFIABLE_HISTORICAL_ENTRY`. It does not guess or silently return `ALREADY_APPLIED`.
5. **Atomic Historical Recording:**
   - In `recordAppliedEntry` (lines 368-390), every successful application inserts a frozen `AppliedIndexRecord` into `state.appliedIndices` alongside `appliedProposals`.
   - The mapping is wrapped in `ReadonlyFrozenMap` and cannot be modified after application.

---

## 3. Memory Growth, Snapshots, and Compaction Analysis

### 3.1 Unbounded In-Memory Growth
In the current implementation:
- `appliedIndices: ReadonlyMap<bigint, AppliedIndexRecord>`
- `appliedProposals: ReadonlyMap<string, bigint>`

Every applied consensus entry adds one key-value pair to both maps. Under sustained execution (e.g. 10,000,000 transactions):
- `appliedIndices` stores 10 million `BigInt` keys and 10 million `AppliedIndexRecord` objects.
- `appliedProposals` stores 10 million UUID strings and `BigInt` values.
- Memory consumption increases linearly ($O(N)$), which will eventually cause V8 heap exhaustion if state is held indefinitely in memory without compaction or pruning.

### 3.2 Interplay with Compaction & Snapshots
In Stage 2-B0.1 / Stage 2-B0.2 architecture specifications:
- PostgreSQL holds durable application logs and state projections.
- etcd periodically compacts its WAL/bbolt revisions ($R < R_{comp}$).
- A recovering witness node bootstraps from a snapshot (or PostgreSQL state checkpoint) at application index $S_{app}$.

#### The Fail-Closed Conflict
If an engine restarts from a snapshot at $S_{app}$ and prunes historical entries below $S_{app}$:
- Any duplicate delivery of an old entry $L_{app} \le S_{app}$ will query `state.appliedIndices.get(L_app)`.
- Because the index was pruned, `historicalRecord` will be `undefined`.
- The reducer will throw `UnverifiableHistoricalEntryError(L_app)`.

### 3.3 Required Architecture Decision for Stage 2-B.2 / Stage 3-A
The engineering team must formally define a historical retention policy prior to Stage 3-A multi-node integration:
1. **Decision Alternative A (Epoch-Bound Anchoring):**
   - Retain full `appliedIndices` and `appliedProposals` only for the *current active epoch*.
   - When an epoch advances (`EPOCH_ADVANCE`), indices from sealed historical epochs are archived to PostgreSQL and pruned from memory.
   - Any consensus entry carrying a historical `epochId` is rejected upfront via `EpochMismatchError` before historical index lookup occurs.
2. **Decision Alternative B (Sliding Idempotency Window):**
   - Introduce a `compactionFloorIndex: bigint` into `ApplicationState`.
   - Retain `appliedIndices` for a bounded window (e.g. last 10,000 indices or active lease cutoff horizon).
   - Replays where $L_{app} \le compactionFloorIndex$ are handled according to an explicit protocol policy (e.g. verified against a Merkle root / chain head hash, or rejected with `LOG_ENTRY_COMPACTED`).

---

## 4. Test Execution & Evidence

The independent test execution was performed sequentially across all verification scopes.

### 4.1 Unit Tests (`test/witness/state-machine.test.ts`)
```
 RUN  v5.0.5 C:/Users/syeds/Projects/Web3User

 ✓ test/witness/state-machine.test.ts (20 tests) 14ms

 Test Files  1 passed (1)
      Tests  20 passed (20)
   Duration  259ms
```
**Outcome:** PASSED (20/20 tests).

### 4.2 Witness Subsystem Suite (`test/witness/`)
```
 Test Files  15 passed (15)
      Tests  266 passed (266)
   Duration  142.50s
```
**Outcome:** PASSED (15/15 files, 266/266 tests). Includes PostgreSQL 16 store tests, real etcd single-node integration, mTLS transport, gRPC KMS, and Migration 003 verification.

### 4.3 Full Repository Regression Suite (`npx vitest run`)
```
 Test Files  39 passed (39)
      Tests  806 passed (806)
   Duration  232.36s
```
**Outcome:** PASSED (39/39 files, 806/806 tests, 0 failures).

### 4.4 Build Verification (`npm run build`)
```
> web3user-permission-lab@0.1.0-rc.1 build
> tsc -p tsconfig.build.json
[Exit Code: 0]
```
**Outcome:** PASSED (0 compilation errors, clean TypeScript build).

---

## 5. File Manifest & Integrity

| File Path | SHA-256 Digest | Audit Status |
| :--- | :--- | :--- |
| `src/witness/state-machine-types.ts` | `B51B425A3EE05BDB935D9B6DA86C6EF6C3ACA97D1F5ED099EDB0F8181C102363` | Verified |
| `src/witness/state-machine.ts` | `D1B8D9DACB2E08CAF2E1CA7E5969C78FDE8DDD93830DA9DD156E013C272C4B0A` | Verified |
| `test/witness/state-machine.test.ts` | `225E61468548A97F0775536C3972DC6B92FF8805D0AD125CFC8354822A910A2C` | Verified |
| `docs/M13-D-STAGE-2B1-1-CORRECTNESS-CLOSURE.md` | `77957788F1596C2B03909978AFE5EC42C4483510E57E2E0A9851F2BEC048CC99` | Verified |

---

## 6. Git Governance Verification

- **Repository Branch:** `feature/m13-d-consensus`
- **HEAD Commit:** `694a951e9899b667d564a69bf42acde08312a04f` (unaltered)
- **Staging Index:** 0 staged files (`git status` shows zero staged files)
- **Worktree Integrity:** Untracked documentation and preview files preserved; zero unauthorized commits or pushes executed.
