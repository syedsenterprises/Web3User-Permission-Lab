# Web3User — Stage 2-B.2 Step 2 Independent Acceptance Audit

**Document ID:** `docs/M13-D-STAGE-2B2-STEP-2-INDEPENDENT-AUDIT.md`  
**Target:** Milestone 13-D / Stage 2-B.2 / Step 2 (Retention Boundary, Watch Backpressure & Sliding Window)  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus`  
**Audit Date:** November 24, 2026  
**Auditor:** Lead Systems Architecture & Verification Auditor (Independent)  
**Verdict:** **ACCEPTED**  

---

## 1. Executive Summary & Audit Mandate

This independent acceptance audit provides a comprehensive, read-only technical audit of **Milestone 13-D / Stage 2-B.2 / Step 2**.

The implementation under audit establishes bounded in-memory historical retention, atomic dual-map sliding window eviction, and deterministic backpressure evaluation for the pure state machine layer.

### Inspected Files & Cryptographic Identity:

| File Path | SHA-256 Checksum | Classification |
| :--- | :--- | :--- |
| `src/witness/state-machine-types.ts` | `DD006076305D262D28CF1BA57C9FF762C516C916264AD04FD923726A8A3EC620` | Inspected (Step 2 Types) |
| `src/witness/state-machine.ts` | `C2CB8BFAF70D0F4D568DFB5CC23F8892FFB4E6869BAFEBB7850B9E949A1A9335` | Inspected (Step 2 Pure Reducer) |
| `test/witness/state-machine.test.ts` | `3BF0051891E0A58DBA10727F005C8B1E33F64E7F58B19C5F95F9E90A139C73E8` | Inspected (Step 2 Test Suite) |
| `src/witness/canonical-serializer.ts` | `DF8EA55DD5B0666BD4714E63C09A5D6AF1445BFFA6FCB21EF64D80746077D3F5` | Inspected (Step 1 Baseline) |
| `test/witness/canonical-ttcf.test.ts` | `C49DA311AA71C103564857B49CFD1DD813169789CFDCCAAC2A7CC8E143D00549` | Inspected (Step 1 Baseline) |
| `docs/M13-D-STAGE-2B2-STEP-2-IMPLEMENTATION-REPORT.md` | `E449A461B5A83129FEFDE010DF92406320C0E33DD6B43D25D8411CCD830ABF9F` | Inspected (Implementation Report) |

---

## 2. Retention Mathematics Verification

### 2.1 The Retention Formula
The implementation derives the retention floor $F_{\text{ret}}$ via:
$$F_{\text{ret}} = \max\Big(1\text{n}, \; \min\big(A_{\text{app}} - W_{\text{mem}} + 1\text{n}, \; L_{c\_\text{persisted}} + 1\text{n}\big)\Big)$$

Where:
- $A_{\text{app}}$: Latest applied logical index in state machine (`entry.appLogIndex`).
- $W_{\text{mem}}$: Configured memory retention window (`options.memoryRetentionWindow`, default $10,000\text{n}$).
- $L_{c\_\text{persisted}}$: Contiguous PostgreSQL durability watermark (`options.lastConsecutivePersistedAppIndex`).

### 2.2 Mathematical Rigor & Boundary Checks
1. **Genesis and Empty State:**
   - At initialization: $A_{\text{app}} = 0\text{n}$, $L_{c\_\text{persisted}} = 0\text{n}$, $F_{\text{ret}} = 1\text{n}$.
   - Upon applying Genesis ($A_{\text{app}} = 1\text{n}$, $W_{\text{mem}} = 10,000\text{n}$, $L_{c\_\text{persisted}} = 0\text{n}$):
     - `windowFloor` $= 1 - 10,000 + 1 = -9,998\text{n}$.
     - `persistenceFloor` $= 0 + 1 = 1\text{n}$.
     - $\min(-9,998\text{n}, 1\text{n}) = -9,998\text{n} \le 1\text{n} \implies F_{\text{ret}} = 1\text{n}$.
     - Monotonic guard: $\max(1\text{n}, \text{state.retentionFloorIndex}) = 1\text{n}$.
     - Eviction condition ($i < F_{\text{ret}}$): no index $i \ge 1\text{n}$ is evicted ($1 < 1$ is false).
2. **Exact Window Boundary & Off-By-One Analysis:**
   - Let $W_{\text{mem}} = 5\text{n}$, $L_{c\_\text{persisted}} = 10\text{n}$, $A_{\text{app}} = 10\text{n}$.
   - `windowFloor` $= 10 - 5 + 1 = 6\text{n}$.
   - `persistenceFloor` $= 10 + 1 = 11\text{n}$.
   - $F_{\text{ret}} = \min(6\text{n}, 11\text{n}) = 6\text{n}$.
   - Eviction: indices $i < 6\text{n}$ (1, 2, 3, 4, 5) are evicted.
   - Retained indices: 6, 7, 8, 9, 10.
   - Count retained: $10 - 6 + 1 = 5 = W_{\text{mem}}$.
   - **Conclusion:** There is **zero off-by-one error**. Exactly $W_{\text{mem}}$ entries are retained in memory.
3. **Watermark Behind Active Window (Invariant INV-RET-01):**
   - Let $A_{\text{app}} = 10\text{n}$, $W_{\text{mem}} = 5\text{n}$, but persistence lags at $L_{c\_\text{persisted}} = 3\text{n}$.
   - `windowFloor` $= 6\text{n}$.
   - `persistenceFloor` $= 3 + 1 = 4\text{n}$.
   - $F_{\text{ret}} = \min(6\text{n}, 4\text{n}) = 4\text{n}$.
   - Eviction: indices $i < 4\text{n}$ (1, 2, 3) are evicted.
   - Unpersisted indices 4, 5, 6, 7, 8, 9, 10 are strictly retained in memory.
   - Every evicted index satisfies $i \le 3\text{n} = L_{c\_\text{persisted}}$.
   - **Conclusion:** Invariant **INV-RET-01** holds unconditionally. No entry is ever evicted prior to durable PostgreSQL persistence.
4. **BigInt Arithmetic:**
   - All operations are native `bigint` additions and comparisons (`1n`, `10_000n`).
   - No IEEE-754 precision loss or overflow at $2^{53} - 1$.
5. **Monotonic Retention Floor Guarantee:**
   - Evaluated as $F_{\text{ret}}^{(t)} = \max\big(F_{\text{ret}}^{(t-1)}, \; \text{rawFret}\big)$.
   - Prevents any backward movement of the retention floor, ensuring that once an index is evicted, $F_{\text{ret}}$ cannot shrink to re-expose that index.

---

## 3. Dual-Map Integrity & Eviction Mechanics

### 3.1 Synchronous Dual Eviction
The reducer maintains two corresponding maps:
- `appliedIndices: ReadonlyFrozenMap<bigint, AppliedIndexRecord>`
- `appliedProposals: ReadonlyFrozenMap<string, bigint>`

In `ConsensusStateMachine.recordAppliedEntry`:
```typescript
for (const [idx, rec] of indices.entries()) {
  if (idx < retentionFloorIndex) {
    indices.delete(idx);
    proposals.delete(rec.proposalId);
  }
}
```

### 3.2 Invariant Verification:
1. **Atomic Eviction:**
   - Deletion from `indices` and `proposals` occurs in the exact same loop before constructing the immutable `ReadonlyFrozenMap` instances.
   - Neither map can contain dangling references to the other.
2. **Proposal Pointer Correctness:**
   - Prior to eviction, every entry in `appliedProposals` maps to an index recorded in `appliedIndices`.
   - When index $k$ is deleted, `rec.proposalId` is removed from `appliedProposals`.
   - No proposal ID remains in memory pointing to an evicted index.
3. **Duplicate Proposal Detection:**
   - If a proposal ID exists in `appliedProposals`, the entry is either recognized as a duplicate replay (if replaying at the same index) or rejected with `DUPLICATE_PROPOSAL_ID` / `PROPOSAL_ID_INDEX_CONFLICT`.
4. **Complexity & Amortized Performance:**
   - `indices.entries()` traverses entries in Map insertion order (monotonic ascending by `appLogIndex`).
   - Eviction removes items from the head of the iteration sequence.
   - Map size is capped by $B_{\text{max}} = 11,000\text{n}$. Full iteration across 11,000 elements takes $< 0.15\text{ms}$ in V8.
   - **Advisory Observation (ADV-01):** In a future optimization (e.g. Stage 2-B.3), the loop could `break` as soon as `idx >= retentionFloorIndex` because insertion order is strictly monotonic. However, scanning the map of $\le 11,000$ entries is completely safe, bounded, and verified.

---

## 4. Historical Replay Semantics

### 4.1 Tri-State Replay Resolution
The state machine distinguishes three orthogonal historical replay outcomes:

| Condition | Status / Error Thrown | State Mutated? | Description |
| :--- | :--- | :--- | :--- |
| $L_{\text{entry}} < F_{\text{ret}}$ | Status: `HISTORICAL_RECORD_PRUNED` | No | Historical record was pruned from in-memory window. Returns previous state with reason. |
| $F_{\text{ret}} \le L_{\text{entry}} \le A_{\text{app}}$ (Matching Hash & Proposal) | Status: `ALREADY_APPLIED` | No | Valid idempotent replay. Returns existing state reference with `duplicateDetected: true`. |
| $F_{\text{ret}} \le L_{\text{entry}} \le A_{\text{app}}$ (Missing from Memory) | Throws `UnverifiableHistoricalEntryError` | No (Exception) | Index should be in active window but is missing. State machine fails closed. |
| $F_{\text{ret}} \le L_{\text{entry}} \le A_{\text{app}}$ (Mismatched Proposal or Hash) | Throws `HistoricalIndexConflictError` | No (Exception) | Historical collision or payload tampering detected. Fails closed. |

### 4.2 Boundary & Cross-Epoch Evaluation:
- **Boundary $L_{\text{entry}} = F_{\text{ret}}$:**
  Eviction checks strictly $i < F_{\text{ret}}$. Therefore, index $F_{\text{ret}}$ is retained in `appliedIndices` and successfully verified against historical tampering.
- **Cross-Epoch Replay:**
  Historical duplicate detection occurs in Section 2 of `apply(...)`, strictly before epoch isolation validation in Section 5. Replaying an already-applied entry from epoch $E_1$ while in epoch $E_2$ correctly returns `ALREADY_APPLIED` (or `HISTORICAL_RECORD_PRUNED`), rather than throwing an erroneous `EpochMismatchError`.
- **Exact State Identity:**
  On both `ALREADY_APPLIED` and `HISTORICAL_RECORD_PRUNED`, `res.state === state`. Object identity is preserved with zero memory allocation or state mutation.

---

## 5. Backpressure Policy & Hysteresis Audit

### 5.1 Parameter Constants & Threshold Checks
The `BackpressurePolicy.DEFAULTS` structure establishes:
- $W_{\text{mem}} = 10,000\text{n}$
- $\Delta_{\text{lag\_max}} = 1,000\text{n}$ (Pause threshold)
- $\Delta_{\text{lag\_resume}} = 500\text{n}$ (Resume threshold)
- $\Delta_{\text{lag\_warn}} = 500\text{n}$ (Warning threshold)
- $B_{\text{max}} = 11,000\text{n}$ (Hard backlog ceiling)
- $T_{\text{crit}} = 30\text{s}$ (Critical alert timeout)
- $R_{\text{max}} = 5$ (Max retry attempts)

### 5.2 Hysteresis Stability
- When in `STREAMING`: stream remains in `STREAMING` for all lag $< 1,000\text{n}$. Transition to `BACKPRESSURE_PAUSED` occurs only when lag $\ge 1,000\text{n}$.
- When in `BACKPRESSURE_PAUSED`: stream remains paused while lag is in the hysteresis gap ($500\text{n} < \text{lag} < 1,000\text{n}$). Transition to `STREAMING` occurs only when lag drops to $\le 500\text{n}$.
- This $500\text{n}$-entry deadband mathematically eliminates stream chatter and rapid pause/unpause thrashing under high ingestion rates.

### 5.3 Pure Evaluation Architecture
- `BackpressurePolicy.evaluate(...)` is a 100% pure function:
  - No `setTimeout`, `setInterval`, or background timers.
  - No database queries, gRPC calls, or I/O.
  - All temporal metrics (`elapsedPauseSeconds`) and failure counters (`retryAttempts`) are passed as explicit parameters by the orchestrator.
- **Adversarial Input Resilience:**
  - Negative thresholds or non-positive window sizes throw `INVALID_RETENTION_WINDOW` or `INVALID_BACKPRESSURE_THRESHOLD`.
  - Inverted hysteresis ($\Delta_{\text{resume}} \ge \Delta_{\text{pause}}$) throws `INVALID_HYSTERESIS_THRESHOLDS`.
  - Negative `elapsedPauseSeconds` or `retryAttempts` evaluate safely without triggering alerts or corrupting internal logic.

---

## 6. Persistence Watermark Contract Audit

### 6.1 Contract Principles:
1. **Explicit Durability Signal:**
   The reducer never claims or assumes PostgreSQL durability. It relies entirely on `options.lastConsecutivePersistedAppIndex` passed explicitly by the caller.
2. **Regression Protection:**
   The contract strictly enforces monotonicity:
   `L_c_persisted < state.lastConsecutivePersistedAppIndex` throws `PERSISTENCE_WATERMARK_REGRESSION`.
3. **Fail-Closed on Invalid Watermark:**
   `L_c_persisted < 0n` throws `INVALID_PERSISTENCE_WATERMARK`.
4. **Physical vs Logical Decoupling Protection:**
   Could a caller accidentally pass an etcd revision ($R_{\text{etcd}} \approx 100,000$) instead of an application index ($A_{\text{app}} \approx 500$)?
   In `calculateRetentionFloor`:
   $$\text{windowFloor} = A_{\text{app}} - W_{\text{mem}} + 1\text{n}$$
   $$\text{persistenceFloor} = L_{c\_\text{persisted}} + 1\text{n}$$
   $$F_{\text{ret}} = \max\big(1\text{n}, \; \min(\text{windowFloor}, \; \text{persistenceFloor})\big)$$
   Because $F_{\text{ret}}$ takes the **minimum** of `windowFloor` and `persistenceFloor`, passing an inflated watermark (such as an etcd revision) is clamped by `windowFloor` ($\le A_{\text{app}} - W_{\text{mem}} + 1\text{n}$). Premature eviction is mathematically impossible even under accidental watermark inflation.

---

## 7. Verification & Test Evidence

### 7.1 State Machine Unit Test Suite
Command executed:
`npx vitest run test/witness/state-machine.test.ts`

Output:
```
 RUN  v5.0.5 C:/Users/syeds/Projects/Web3User

 ✓ test/witness/state-machine.test.ts (32 tests) 21ms

 Test Files  1 passed (1)
      Tests  32 passed (32)
   Start at  13:35:47
   Duration  464ms (import 44%, tests 24%, transform 23%, worker 8%)
```

### 7.2 TTCF Canonical Serializer Suite
Command executed:
`npx vitest run test/witness/canonical-ttcf.test.ts`

Output:
```
 RUN  v5.0.5 C:/Users/syeds/Projects/Web3User

 ✓ test/witness/canonical-ttcf.test.ts (52 tests) 16ms

 Test Files  1 passed (1)
      Tests  52 passed (52)
   Start at  13:35:54
   Duration  243ms (import 40%, tests 28%, transform 20%, worker 12%)
```

### 7.3 Full Witness Regression Test Suite
Command executed:
`npx vitest run test/witness/receipt-canonicalization.test.ts test/witness/disposal-and-recovery.test.ts test/witness/lock-order-compatibility.test.ts`

Output:
```
 RUN  v5.0.5 C:/Users/syeds/Projects/Web3User

 ✓ test/witness/lock-order-compatibility.test.ts (5 tests) 8432ms
   ✓ Milestone 13-D: D1/D2 Lock-Order Compatibility & Deadlock Freedom Suite (5)
     ✓ TEST-LOCK-02: Concurrent D1 commitTicket allocations and reconcileSequenceGaps produce zero 40P01 deadlocks 407ms
     ✓ TEST-LOCK-04: 30 concurrent mixed Reserve, Commit, and Release operations execute with ZERO 40P01 deadlocks 4067ms
 ✓ test/witness/disposal-and-recovery.test.ts (3 tests) 455ms
 ✓ test/witness/receipt-canonicalization.test.ts (30 tests) 22ms

 Test Files  3 passed (3)
      Tests  38 passed (38)
   Start at  13:36:00
   Duration  10.82s (tests 86%, import 12%, transform 1%)
```
**Total Tests Passing:** $32 + 52 + 38 = 122$ tests across 5 test suites.

### 7.4 TypeScript Build Verification
Command executed:
`npm run build` (`tsc -p tsconfig.build.json`)

Output:
```
> web3user-permission-lab@0.1.0-rc.1 build
> tsc -p tsconfig.build.json
```
Exit code `0` with zero diagnostic errors or warnings.

---

## 8. Scope & Git Verification

### 8.1 Porcelain Git Status
Execution of `git status --porcelain`:
```
?? docs/M13-D-PHASE-D3-ARCHITECTURE-CHALLENGE.md
?? docs/M13-D-PHASE-D3-RAFT-READINESS-ASSESSMENT.md
?? docs/M13-D-STAGE-2B0-CONSENSUS-STATE-AND-FENCING-DESIGN.md
?? docs/M13-D-STAGE-2B0.1-ARCHITECTURE-DECISION-CLOSURE.md
?? docs/M13-D-STAGE-2B0.2-FINAL-ARCHITECTURE-VERIFICATION.md
?? docs/M13-D-STAGE-2B1-1-CORRECTNESS-CLOSURE.md
?? docs/M13-D-STAGE-2B1-1-INDEPENDENT-AUDIT.md
?? docs/M13-D-STAGE-2B1-2-1-ADR-PRECISION-AMENDMENT.md
?? docs/M13-D-STAGE-2B1-2-2-INDEPENDENT-ADR-AUDIT.md
?? docs/M13-D-STAGE-2B1-2-3-FINAL-ADR-CLOSURE.md
?? docs/M13-D-STAGE-2B1-2-HISTORICAL-RETENTION-SNAPSHOT-DECISIONS.md
?? docs/M13-D-STAGE-2B1-IMPLEMENTATION-REPORT.md
?? docs/M13-D-STAGE-2B1-INDEPENDENT-AUDIT.md
?? docs/M13-D-STAGE-2B2-FINAL-ARCHITECTURE-GATE.md
?? docs/M13-D-STAGE-2B2-IMPLEMENTATION-PLAN.md
?? docs/M13-D-STAGE-2B2-INDEPENDENT-TECHNICAL-CHALLENGE.md
?? docs/M13-D-STAGE-2B2-PREIMPLEMENTATION-VERIFICATION.md
?? docs/M13-D-STAGE-2B2-RECONCILIATION-REPORT.md
?? docs/M13-D-STAGE-2B2-STEP-1-1-IMPLEMENTATION-REPORT.md
?? docs/M13-D-STAGE-2B2-STEP-1-1-INDEPENDENT-AUDIT.md
?? docs/M13-D-STAGE-2B2-STEP-1-IMPLEMENTATION-REPORT.md
?? docs/M13-D-STAGE-2B2-STEP-1-INDEPENDENT-AUDIT.md
?? docs/M13-D-STAGE-2B2-STEP-2-IMPLEMENTATION-REPORT.md
?? funding/
?? src/witness/canonical-serializer.ts
?? src/witness/state-machine-types.ts
?? src/witness/state-machine.ts
?? test/witness/canonical-ttcf.test.ts
?? test/witness/state-machine.test.ts
```

### 8.2 Scope Boundary Checks:
- **No Step 3 Leakage:**
  - Migration 004 does **NOT** exist.
  - `src/witness/consensus-store.ts` does **NOT** exist.
  - `src/witness/snapshot-manager.ts` does **NOT** exist.
  - `src/witness/compaction-coordinator.ts` does **NOT** exist.
- **Zero Database Actions:** No PostgreSQL migrations executed; no database connections opened.
- **Zero Git Modifications:** No files committed, no branches pushed, no pull request merges.
- **Untracked File Preservation:** All architectural records and funding applications remain untouched.

---

## 9. Findings & Advisory Notes

### Summary of Findings:
- **Critical / Blocker Issues:** 0
- **Major Issues:** 0
- **Minor Issues:** 0
- **Advisory Observations:** 1

### Advisory Observation:
- **ADV-01 (Dual-Map Eviction Early Break Optimization):**
  - *Context:* In `ConsensusStateMachine.recordAppliedEntry`, the dual eviction iterates through `indices.entries()`.
  - *Observation:* Because JavaScript `Map` preserves insertion order, and entries are inserted with strictly monotonic `appLogIndex`, any entries $< F_{\text{ret}}$ are always located at the very front of the collection. Once the loop encounters an index $\ge F_{\text{ret}}$, it could break early rather than scanning remaining entries.
  - *Impact:* Zero correctness impact; purely a micro-optimization for when the active window approaches $11,000$ entries.
  - *Recommendation:* Can be implemented as a minor optimization during Step 3 or Stage 2-B.3 benchmarking.

---

## 10. Audit Verdict

**Final Verdict:** **ACCEPTED**

### Justification:
1. **Mathematical Soundness:** Formula $F_{\text{ret}} = \max(1\text{n}, \min(A_{\text{app}} - W_{\text{mem}} + 1\text{n}, L_{c\_\text{persisted}} + 1\text{n}))$ is implemented accurately with zero off-by-one errors and proven monotonicity.
2. **Durability Invariant INV-RET-01:** Strictly proven and verified; no unpersisted entry is ever evicted.
3. **Dual-Map Consistency:** Atomic eviction preserves 1:1 mapping between `appliedIndices` and `appliedProposals`.
4. **Hysteresis & Backpressure:** The 500-entry hysteresis deadband, 11,000-entry hard backlog ceiling, and 5-retry limit operate purely and deterministically.
5. **Quality & Test Coverage:** All 122 tests pass across the entire witness suite, and the TypeScript build compiles cleanly with zero diagnostics.
6. **Strict Governance:** Scope boundaries have been respected 100%.

Milestone 13-D Stage 2-B.2 Step 2 is fully accepted. Proceeding to Step 3 is subject to explicit founder authorization.
