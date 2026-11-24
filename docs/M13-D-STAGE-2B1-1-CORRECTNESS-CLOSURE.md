# Web3User — Milestone 13-D Phase D3: Stage 2-B.1.1
# State Machine Correctness Closure Report

**Date:** 2026-11-23  
**Status:** COMPLETED & VERIFIED  
**Target:** Remediate and close findings F-01, F-02, and F-03 from `docs/M13-D-STAGE-2B1-INDEPENDENT-AUDIT.md`  
**Authorization:** Stage 2-B.1.1 Correctness Remediation Only (No commits, no pushes, no external I/O)

---

## 1. Executive Summary

During the independent technical audit of the Stage 2-B.1 pure state machine reducer (`docs/M13-D-STAGE-2B1-INDEPENDENT-AUDIT.md`), three specific correctness vulnerabilities were identified:
1. **F-01 (Low):** `computeCanonicalPayloadHash()` relied on standard `JSON.stringify()`, which preserves object key insertion order rather than lexicographically sorting keys, creating non-deterministic hash calculations for semantically identical JSON objects.
2. **F-02 (Low):** `applyPolicyUpdate()` inserted newly instantiated `PolicyRecord` objects into `ReadonlyFrozenMap` without calling `Object.freeze()`, leaving individual record fields mutable via property assignment.
3. **F-03 (Medium):** Replay validation for already-applied indexes ($L_{app} \le A_{app}$) only checked `appliedProposals` for proposal ID collision, but did not cross-verify historical `appLogIndex` entries against their original payload hash. Replaying a conflicting payload under a previously applied index returned `ALREADY_APPLIED` rather than failing closed with an explicit conflict.

All three findings have been remediated in `src/witness/state-machine-types.ts` and `src/witness/state-machine.ts`, accompanied by rigorous unit tests in `test/witness/state-machine.test.ts`.

### Verification Highlights
- **Unit Test Suite (`test/witness/state-machine.test.ts`):** 20 passing tests (up from 17; +3 new dedicated suites).
- **Witness Test Suite (`test/witness/`):** 15 test files, 266 passing tests (100% pass rate).
- **Full Repository Regression Suite (`npx vitest run`):** 39 test files, 806 passing tests (up from 803; 0 regressions).
- **Production Build (`npm run build`):** Clean exit code 0; zero TypeScript compilation errors.
- **Git State:** Clean preservation of HEAD commit `694a951e9899b667d564a69bf42acde08312a04f` on branch `feature/m13-d-consensus`; 0 staged files; 0 commits.

---

## 2. Technical Remediation Analysis

### 2.1 Remediation of Finding F-01: Deterministic Canonical Payload Hashing

#### Root Cause
In Stage 2-B.1, `computeCanonicalPayloadHash()` passed a BigInt replacer into `JSON.stringify(payload, ...)`. In V8, `JSON.stringify` enumerates object keys in property insertion order. Consequently:
```json
// Object 1: { "b": 1, "a": 2 } -> '{"b":1,"a":2}'
// Object 2: { "a": 2, "b": 1 } -> '{"a":2,"b":1}'
```
Despite containing identical data, the SHA-256 hashes differed, leading to false-positive tamper rejections.

#### Implementation Fix
A pure, recursive canonical serializer `canonicalizeValue(val: unknown): string` was implemented in `src/witness/state-machine.ts`:
- **Lexicographical Key Sorting:** For all object records, `Object.keys(obj).sort()` guarantees uniform serialization regardless of property insertion sequence.
- **Preserved Array Ordering:** Arrays are evaluated as sequential lists where position is semantically significant; element order is preserved.
- **BigInt Serialization:** BigInt values are converted to JSON strings (`JSON.stringify(val.toString())`).
- **Strict Type Validation:** Non-finite numeric values (`NaN`, `Infinity`, `-Infinity`), functions, symbols, and direct `undefined` values throw an immediate `TypeError`.
- **Null & Primitives:** Handled according to standard RFC 8785 canonical JSON principles.

#### Test Coverage
Test 18 in `test/witness/state-machine.test.ts` asserts:
1. Object key order independence: `{ b: 1, a: 2 }` and `{ a: 2, b: 1 }` produce identical SHA-256 digests.
2. Deeply nested key order independence: `{ outer: { z: 1, y: 2 } }` and `{ outer: { y: 2, z: 1 } }` produce identical digests.
3. Array order preservation: `[1, 2]` and `[2, 1]` produce different digests.
4. Correct 64-bit BigInt handling without precision truncation.
5. Rejection of `NaN`, `Infinity`, functions, and symbols via `TypeError`.

---

### 2.2 Remediation of Finding F-02: PolicyRecord Deep Immutability

#### Root Cause
While `ReadonlyFrozenMap` prevents `.set()`, `.delete()`, and `.clear()` on the map container itself, the `PolicyRecord` value inserted in `applyPolicyUpdate()` was a plain object literal:
```typescript
nextPolicies.set(p.policyId, {
  policyId: p.policyId,
  revision: p.revision,
  policyHash: p.policyHash,
  definitionJson: p.definitionJson,
});
```
Callers retrieving `state.policies.get("pol-1")` could mutate properties (e.g. `(record as any).revision = 999`) in JavaScript environments that do not enforce read-only object wrappers.

#### Implementation Fix
`applyPolicyUpdate()` now explicitly deep-freezes every created `PolicyRecord` instance via `Object.freeze()` prior to insertion into `nextPolicies`:
```typescript
const policyRecord: PolicyRecord = Object.freeze({
  policyId: p.policyId,
  revision: p.revision,
  policyHash: p.policyHash,
  definitionJson: p.definitionJson,
});
nextPolicies.set(p.policyId, policyRecord);
```

#### Test Coverage
Test 19 in `test/witness/state-machine.test.ts` asserts:
1. `Object.isFrozen(state.policies.get("policy-immutable-01")) === true`.
2. Property reassignment (`(policy as any).revision = 999`) throws a strict-mode `TypeError`.
3. Property addition (`(policy as any).newField = "illegal"`) throws a strict-mode `TypeError`.

---

### 2.3 Remediation of Finding F-03: Historical Index Integrity & Fail-Closed Validation

#### Root Cause
When an entry with $L_{app} \le A_{app}$ was replayed, the state machine checked whether `state.appliedProposals.get(entry.proposalId)` matched $L_{app}$. However, if a caller submitted an entry with an already-applied index $L_{app}$ but with a completely different payload or tampered fields, the state machine did not track what payload hash was originally applied at that index, allowing potentially conflicting historical entries to return `ALREADY_APPLIED`.

#### Implementation Fix
1. **Contract Enhancements (`src/witness/state-machine-types.ts`):**
   - Added `AppliedIndexRecord`:
     ```typescript
     export interface AppliedIndexRecord {
       readonly proposalId: string;
       readonly payloadHash: string;
     }
     ```
   - Added `appliedIndices: ReadonlyMap<bigint, AppliedIndexRecord>` to `ApplicationState`.
   - Introduced `HistoricalIndexConflictError` with codes:
     - `HISTORICAL_INDEX_PROPOSAL_ID_CONFLICT`
     - `HISTORICAL_INDEX_PAYLOAD_HASH_CONFLICT`
   - Introduced `UnverifiableHistoricalEntryError` with code `UNVERIFIABLE_HISTORICAL_ENTRY`.

2. **Reducer Replay Validation (`src/witness/state-machine.ts`):**
   When `entry.appLogIndex <= state.lastAppliedAppIndex`:
   - Inspects `state.appliedIndices.get(entry.appLogIndex)`:
     - If record is missing: fails closed with `UnverifiableHistoricalEntryError(entry.appLogIndex)`.
     - If `record.proposalId !== entry.proposalId`: throws `HistoricalIndexConflictError(entry.appLogIndex, "PROPOSAL_ID", ...)`.
     - If `record.payloadHash !== computedPayloadHash`: throws `HistoricalIndexConflictError(entry.appLogIndex, "PAYLOAD_HASH", ...)`.
   - Verifies cross-index proposal uniqueness via `state.appliedProposals`.
   - If and only if all checks pass, returns `status: "ALREADY_APPLIED"` with `duplicateDetected: true` and state reference equality.

3. **Atomic Applied Index Tracking Helper:**
   All 6 command reducers now invoke `recordAppliedEntry(state, entry, computedPayloadHash)` to atomically update both `appliedProposals` and `appliedIndices` with frozen entries.

#### Test Coverage
- **Test 5:** Verifies that attempting duplicate replay with conflicting proposal IDs or conflicting payload hashes throws `HistoricalIndexConflictError` with exact conflict codes. Also verifies that replay against unrecorded historical indices throws `UnverifiableHistoricalEntryError`.
- **Test 20:** Evaluates a multi-step lifecycle sequence (Initialize -> PolicyUpdate -> TicketCommit), verifying that all historical indices are tracked, exact replays return `ALREADY_APPLIED`, and modified replays throw `HistoricalIndexConflictError`.

---

## 3. Verification & Quality Gates

### 3.1 Unit Test Suite (`test/witness/state-machine.test.ts`)
```
 RUN  v5.0.5 C:/Users/syeds/Projects/Web3User

 ✓ test/witness/state-machine.test.ts (20 tests) 14ms

 Test Files  1 passed (1)
      Tests  20 passed (20)
   Duration  320ms
```

### 3.2 Witness Subsystem Suite (`test/witness/`)
```
 Test Files  15 passed (15)
      Tests  266 passed (266)
   Duration  135.65s
```

### 3.3 Full Regression Suite (`npx vitest run`)
```
 Test Files  39 passed (39)
      Tests  806 passed (806)
   Duration  213.11s
```

### 3.4 Build Verification (`npm run build`)
```
> web3user-permission-lab@0.1.0-rc.1 build
> tsc -p tsconfig.build.json
[Exit Code: 0]
```

---

## 4. Cryptographic File Integrity Manifest

| File Path | SHA-256 Digest |
| :--- | :--- |
| `src/witness/state-machine-types.ts` | `B51B425A3EE05BDB935D9B6DA86C6EF6C3ACA97D1F5ED099EDB0F8181C102363` |
| `src/witness/state-machine.ts` | `D1B8D9DACB2E08CAF2E1CA7E5969C78FDE8DDD93830DA9DD156E013C272C4B0A` |
| `test/witness/state-machine.test.ts` | `225E61468548A97F0775536C3972DC6B92FF8805D0AD125CFC8354822A910A2C` |

---

## 5. Working Tree Status

```
Active Branch: feature/m13-d-consensus
HEAD Commit:   694a951e9899b667d564a69bf42acde08312a04f

Staged Changes: None (0 files staged)
Git Commits:    None created
Git Pushes:     None executed
Working Tree:   Preserved intact (website-preview/ and pre-existing docs preserved)
```

---

## 6. Closure Status & Recommendations

All findings from `docs/M13-D-STAGE-2B1-INDEPENDENT-AUDIT.md` are completely remediated and closed:
- **F-01:** CLOSED. Canonical serialization is strictly deterministic.
- **F-02:** CLOSED. `PolicyRecord` instances are explicitly frozen.
- **F-03:** CLOSED. Full historical index integrity and fail-closed validation implemented.

The application state-machine contract and reducer layer (`src/witness/state-machine.ts`) is functionally complete, mathematically sound, tamper-resistant, and ready for Stage 2-B.2 (PostgreSQL State Machine Persistence Adapter) pending user authorization.
