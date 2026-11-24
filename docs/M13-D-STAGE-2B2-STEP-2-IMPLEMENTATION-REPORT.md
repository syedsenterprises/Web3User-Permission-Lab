# Web3User — Milestone 13-D / Stage 2-B.2 / Step 2
## Retention Boundary, Watch Backpressure & Sliding Window Implementation Report

**Document ID:** `docs/M13-D-STAGE-2B2-STEP-2-IMPLEMENTATION-REPORT.md`  
**Milestone:** 13-D Consensus Engine & State Machine (Stage 2-B.2 Step 2)  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus`  
**Status:** IMPLEMENTED & VERIFIED — READY FOR INDEPENDENT AUDIT  
**Date:** November 24, 2026  

---

## 1. Executive Summary & Authorization

In accordance with explicit founder authorization for **Stage 2-B.2 / Step 2**, this implementation realizes the bounded historical retention, sliding window eviction, and deterministic watch backpressure policy for the Web3User Pure State Machine.

All requirements formulated across the architecture reconciliation and technical challenge phases have been implemented strictly in pure TypeScript, without any timers, database connections, network operations, or side effects inside the state machine core.

### Key Milestones Delivered:
1. **Historical Retention Boundary ($F_{\text{ret}}$):**
   - Implemented exact formula: $F_{\text{ret}} = \max\Big(1\text{n}, \; \min\big(A_{\text{app}} - W_{\text{mem}} + 1\text{n}, \; L_{c\_\text{persisted}} + 1\text{n}\big)\Big)$ with monotonic non-decreasing guarantees.
   - Enforced **Invariant INV-RET-01**: In-memory entries are never pruned ahead of durable PostgreSQL persistence ($L_{c\_\text{persisted}}$).
   - Atomic dual eviction: pruned indices are removed from `appliedIndices` and their corresponding `proposalId` mappings are removed from `appliedProposals`.
   - Distinct historical replay handling: replaying an index below $F_{\text{ret}}$ returns `HISTORICAL_RECORD_PRUNED`, while a missing entry within the active window ($\ge F_{\text{ret}}$) throws `UnverifiableHistoricalEntryError`.
2. **Deterministic Watch Backpressure:**
   - Standardized defaults: $B_{\text{max}} = 11,000\text{n}$, $\Delta_{\text{lag\_max}} = 1,000\text{n}$, $\Delta_{\text{lag\_resume}} = 500\text{n}$, $\Delta_{\text{lag\_warn}} = 500\text{n}$, Critical alert timeout $= 30,000\text{ms}$ ($30\text{s}$), max retries $= 5$.
   - Explicit stream states (`FLOWING`, `BACKPRESSURE_PAUSED`), alert levels (`NORMAL`, `WARNING`, `CRITICAL`), and actions (`CONTINUE`, `PAUSE_STREAM`, `RESUME_STREAM`, `ABORT_OVERFLOW`, `HALT_RETRY_EXHAUSTED`).
   - Hard backlog ceiling: throws `BacklogLimitExceededError` if $A_{\text{app}} - L_{c\_\text{persisted}} > B_{\text{max}}$.
3. **Verification & Clean Build:**
   - 32/32 tests pass in `test/witness/state-machine.test.ts`.
   - 122/122 tests pass across the full witness regression test suite.
   - TypeScript build (`tsc -p tsconfig.build.json`) compiles with zero diagnostics/errors.
   - Zero scope leakage: Step 3 (Migration 004, `consensus-store.ts`, `snapshot-manager.ts`) was not touched.

---

## 2. Source Modifications & Artifact Inventory

### Modified Source Files:
1. `src/witness/state-machine-types.ts`:
   - Added `canonicalizationVersion?: 1 | 2` to `CommittedConsensusEntry`.
   - Added `retentionFloorIndex: bigint` and `lastConsecutivePersistedAppIndex: bigint` to `ApplicationState`.
   - Added `HISTORICAL_RECORD_PRUNED` to `StateMachineApplyStatus`.
   - Added `StateMachineApplyOptions` interface supporting `lastConsecutivePersistedAppIndex`, `memoryRetentionWindow`, `backpressureConfig`, and `enforceBacklogLimit`.
   - Added `retentionFloorIndex?: bigint` to `StateMachineApplyResult`.
   - Added backpressure domain types:
     - `BackpressureStreamState` (`"FLOWING"` | `"BACKPRESSURE_PAUSED"`)
     - `BackpressureAlertLevel` (`"NORMAL"` | `"WARNING"` | `"CRITICAL"`)
     - `BackpressureAction` (`"CONTINUE"` | `"PAUSE_STREAM"` | `"RESUME_STREAM"` | `"ABORT_OVERFLOW"` | `"HALT_RETRY_EXHAUSTED"`)
     - `BackpressureConfig`
     - `BackpressureEvaluation`
   - Added typed `BacklogLimitExceededError` class.

2. `src/witness/state-machine.ts`:
   - Re-exported `computeCanonicalPayloadHash` calling `./canonical-serializer.js` with version routing.
   - Implemented `BackpressurePolicy` class providing:
     - `DEFAULTS` constant configuration matching ADR and implementation plan parameters.
     - `calculateRetentionFloor(appliedIndex, windowSize, lastPersistedIndex)` pure formula.
     - `evaluate(currentStreamState, appliedIndex, lastPersistedIndex, pausedDurationMs, retryAttempts, config)` pure evaluator.
   - Updated `createInitialState` initializing `retentionFloorIndex: 1n` and `lastConsecutivePersistedAppIndex: 0n`.
   - Updated `ConsensusStateMachine.apply(...)`:
     - Accepts optional `options?: StateMachineApplyOptions`.
     - Validates $W_{\text{mem}} > 0\text{n}$ and non-regressing $L_{c\_\text{persisted}} \ge \text{state.lastConsecutivePersistedAppIndex}$.
     - Checks historical replay: if $L_{\text{entry}} < F_{\text{ret}}$, returns `{ status: "HISTORICAL_RECORD_PRUNED", ... }`.
     - Validates deduplication within the active retention window ($\ge F_{\text{ret}}$), throwing `UnverifiableHistoricalEntryError` if index entry is missing.
     - Evaluates backpressure and enforces the hard memory backlog ceiling via `BacklogLimitExceededError`.
     - Computes updated retention floor: $F_{\text{ret}} = \max\Big(\text{state.retentionFloorIndex}, \; \max\big(1\text{n}, \min(A_{\text{app}} - W_{\text{mem}} + 1\text{n}, L_{c\_\text{persisted}} + 1\text{n})\big)\Big)$.
     - Executes synchronous dual eviction: removes entries $< F_{\text{ret}}$ from both `appliedIndices` and `appliedProposals`.
     - Propagates updated `retentionFloorIndex` and `lastConsecutivePersistedAppIndex` through all 6 event reducers (`applyEpochInitialize`, `applyEpochAdvance`, `applyEpochQuarantine`, `applyDelegationRevoke`, `applyPolicyUpdate`, `applyTicketCommit`).

3. `test/witness/state-machine.test.ts`:
   - Extended test suite from 20 to 32 tests, adding comprehensive coverage for:
     - Genesis retention floor initialization ($F_{\text{ret}} = 1\text{n}$).
     - Floor derivation when persistence leads window ($L_{c\_\text{persisted}} \ge A_{\text{app}} - W_{\text{mem}}$).
     - Floor derivation when persistence lags window ($L_{c\_\text{persisted}} < A_{\text{app}} - W_{\text{mem}}$, verifying **INV-RET-01**).
     - Sliding window pruning and dual-map eviction (`appliedIndices` + `appliedProposals`).
     - Historical replay below retention floor returning `HISTORICAL_RECORD_PRUNED`.
     - Missing in-memory entry $\ge F_{\text{ret}}$ throwing `UnverifiableHistoricalEntryError`.
     - Durability watermark regression rejection.
     - Memory window non-positive configuration rejection.
     - Backpressure hysteresis transitions (pause at lag $\ge 1,000$, resume at lag $\le 500$, hysteresis stability at 750).
     - Warning and Critical alert levels based on lag duration ($30\text{s}$ timeout).
     - Hard backlog ceiling overflow abort (`ABORT_OVERFLOW` and `BacklogLimitExceededError`).
     - Retry exhaustion limit (`HALT_RETRY_EXHAUSTED` at $\ge 5$ attempts).
     - Threshold validation in `BackpressurePolicy.evaluate`.

---

## 3. Mathematical & Architectural Derivations

### 3.1 Historical Retention Boundary Formulation

The state machine maintains in-memory tracking of applied consensus indices and proposals to guarantee idempotency and sequential execution. To bound memory while guaranteeing crash recovery, the retention floor $F_{\text{ret}}$ is derived as:

$$F_{\text{ret}} = \max\Big(1\text{n}, \; \min\big(A_{\text{app}} - W_{\text{mem}} + 1\text{n}, \; L_{c\_\text{persisted}} + 1\text{n}\big)\Big)$$

Where:
- $A_{\text{app}}$: The current highest applied logical index in the state machine (`applicationIndex`).
- $W_{\text{mem}}$: The configured in-memory retention window size (default $10,000\text{n}$).
- $L_{c\_\text{persisted}}$: The caller-supplied watermark of entries that have been contiguously and durably written to PostgreSQL.
- $F_{\text{ret}}$: The lowest logical index that remains retained in memory. All indices $i < F_{\text{ret}}$ are safely evicted.

#### Monotonic Non-Decreasing Property:
To prevent historical boundary regressions, the state machine ensures:
$$F_{\text{ret}}^{(t)} = \max\left(F_{\text{ret}}^{(t-1)}, \; \max\Big(1\text{n}, \; \min\big(A_{\text{app}} - W_{\text{mem}} + 1\text{n}, \; L_{c\_\text{persisted}} + 1\text{n}\big)\Big)\right)$$

### 3.2 Invariant INV-RET-01 (Durability Before Eviction)

**Definition:**
$$\forall i < F_{\text{ret}}, \quad i \le L_{c\_\text{persisted}}$$

**Proof:**
By definition:
$$F_{\text{ret}} \le L_{c\_\text{persisted}} + 1\text{n}$$
Therefore:
$$i < F_{\text{ret}} \implies i < L_{c\_\text{persisted}} + 1\text{n} \implies i \le L_{c\_\text{persisted}} \quad \blacksquare$$

Because eviction only deletes entries where $i < F_{\text{ret}}$, no entry can ever be evicted from memory unless it has already been durably persisted in PostgreSQL. Even if $A_{\text{app}} - W_{\text{mem}} + 1\text{n}$ advances rapidly, if PostgreSQL persistence stalls ($L_{c\_\text{persisted}}$ remains low), $F_{\text{ret}}$ is clamped to $L_{c\_\text{persisted}} + 1\text{n}$, retaining all unpersisted entries in memory.

### 3.3 Atomic Dual Eviction

When an entry is evicted from `appliedIndices`, its corresponding proposal ID must also be evicted from `appliedProposals`; otherwise, `appliedProposals` would grow without bound:
```typescript
for (const [idx, recorded] of nextAppliedIndices.entries()) {
  if (idx < newRetentionFloor) {
    nextAppliedIndices.delete(idx);
    if (recorded.proposalId && nextAppliedProposals.get(recorded.proposalId) === idx) {
      nextAppliedProposals.delete(recorded.proposalId);
    }
  }
}
```
This guarantees an exact 1:1 bound between `appliedIndices.size` and `appliedProposals.size`.

### 3.4 Replay vs Unverifiable Boundary Semantics

When a caller replays a consensus entry with logical index $L_{\text{entry}} \le A_{\text{app}}$:
1. **$L_{\text{entry}} < F_{\text{ret}}$ (Pruned History):**
   The entry is below the retention boundary. It was verified and applied in a prior state transition and subsequently pruned. The state machine returns:
   `status: "HISTORICAL_RECORD_PRUNED"`.
2. **$F_{\text{ret}} \le L_{\text{entry}} \le A_{\text{app}}$ (Active History):**
   The entry must exist in `appliedIndices`.
   - If present and matches hash/proposal: returns `status: "DUPLICATE_IGNORED"`.
   - If missing from `appliedIndices`: throws `UnverifiableHistoricalEntryError` to signal state corruption or invalid eviction.

---

## 4. Backpressure Policy & State Transition Specification

### 4.1 Parameter Definitions & Defaults

| Parameter | Type | Default Value | Description |
| :--- | :--- | :--- | :--- |
| `B_max` | `bigint` | `11,000n` | Hard backlog ceiling ($A_{\text{app}} - L_{c\_\text{persisted}}$). Exceeding this triggers `ABORT_OVERFLOW`. |
| `delta_lag_max` | `bigint` | `1,000n` | Lag threshold to pause ingestion stream (`FLOWING` $\to$ `BACKPRESSURE_PAUSED`). |
| `delta_lag_resume` | `bigint` | `500n` | Lag threshold to resume ingestion stream (`BACKPRESSURE_PAUSED` $\to$ `FLOWING`). |
| `delta_lag_warn` | `bigint` | `500n` | Lag threshold to emit `WARNING` alert level. |
| `critical_alert_timeout_ms` | `number` | `30,000` ($30\text{s}$) | Elapsed time under pause/max lag before elevating alert to `CRITICAL`. |
| `max_retry_attempts` | `number` | `5` | Maximum retry attempts before escalating to `HALT_RETRY_EXHAUSTED`. |

### 4.2 State Transition Matrix

The `BackpressurePolicy.evaluate(...)` method computes a pure transition decision:

| Current Stream State | Persistence Lag ($\Delta$) | Elapsed Paused Time ($t$) | Retry Attempts ($r$) | Next Stream State | Alert Level | Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Any | $\Delta > B_{\text{max}}$ (`11,000`) | Any | Any | `BACKPRESSURE_PAUSED` | `CRITICAL` | `ABORT_OVERFLOW` |
| Any | Any | Any | $r \ge 5$ | `BACKPRESSURE_PAUSED` | `CRITICAL` | `HALT_RETRY_EXHAUSTED` |
| `FLOWING` | $\Delta < 500$ | $0\text{ms}$ | $< 5$ | `FLOWING` | `NORMAL` | `CONTINUE` |
| `FLOWING` | $500 \le \Delta < 1,000$ | $0\text{ms}$ | $< 5$ | `FLOWING` | `WARNING` | `CONTINUE` |
| `FLOWING` | $\Delta \ge 1,000$ | $< 30,000\text{ms}$ | $< 5$ | `BACKPRESSURE_PAUSED` | `WARNING` | `PAUSE_STREAM` |
| `FLOWING` | $\Delta \ge 1,000$ | $\ge 30,000\text{ms}$ | $< 5$ | `BACKPRESSURE_PAUSED` | `CRITICAL` | `PAUSE_STREAM` |
| `BACKPRESSURE_PAUSED` | $\Delta \le 500$ | Any | $< 5$ | `FLOWING` | `NORMAL` | `RESUME_STREAM` |
| `BACKPRESSURE_PAUSED` | $500 < \Delta < 1,000$ (Hysteresis) | $< 30,000\text{ms}$ | $< 5$ | `BACKPRESSURE_PAUSED` | `WARNING` | `CONTINUE` |
| `BACKPRESSURE_PAUSED` | $500 < \Delta < 1,000$ (Hysteresis) | $\ge 30,000\text{ms}$ | $< 5$ | `BACKPRESSURE_PAUSED` | `CRITICAL` | `CONTINUE` |
| `BACKPRESSURE_PAUSED` | $\Delta \ge 1,000$ | $< 30,000\text{ms}$ | $< 5$ | `BACKPRESSURE_PAUSED` | `WARNING` | `CONTINUE` |
| `BACKPRESSURE_PAUSED` | $\Delta \ge 1,000$ | $\ge 30,000\text{ms}$ | $< 5$ | `BACKPRESSURE_PAUSED` | `CRITICAL` | `CONTINUE` |

#### Hysteresis Property:
The hysteresis gap between $1,000\text{n}$ (pause) and $500\text{n}$ (resume) prevents high-frequency oscillations (chatter) on the watch stream when persistence throughput fluctuates around the boundary.

---

## 5. Verification & Test Evidence

### 5.1 Unit Test Execution (`test/witness/state-machine.test.ts`)

```
> npx vitest run test/witness/state-machine.test.ts

 RUN  v5.0.5 C:/Users/syeds/Projects/Web3User

 ✓ test/witness/state-machine.test.ts (32 tests) 20ms

 Test Files  1 passed (1)
      Tests  32 passed (32)
   Start at  04:50:12
   Duration  281ms (transform 51%, import 25%, tests 17%, worker 7%)
```

### 5.2 Full Witness Regression Suite Execution

```
> npx vitest run test/witness/state-machine.test.ts test/witness/canonical-ttcf.test.ts test/witness/receipt-canonicalization.test.ts test/witness/lock-order-compatibility.test.ts test/witness/disposal-and-recovery.test.ts

 RUN  v5.0.5 C:/Users/syeds/Projects/Web3User

 ✓ test/witness/lock-order-compatibility.test.ts (5 tests) 8087ms
 ✓ test/witness/disposal-and-recovery.test.ts (3 tests) 519ms
 ✓ test/witness/receipt-canonicalization.test.ts (30 tests) 21ms
 ✓ test/witness/state-machine.test.ts (32 tests) 19ms
 ✓ test/witness/canonical-ttcf.test.ts (52 tests) 15ms

 Test Files  5 passed (5)
      Tests  122 passed (122)
   Start at  04:50:19
   Duration  10.09s (tests 94%, import 5%, transform 1%)
```

### 5.3 TypeScript Build Compilation

```
> npm run build
> web3user-permission-lab@0.1.0-rc.1 build
> tsc -p tsconfig.build.json
```
Compilation completed with return code `0` and zero errors or warnings.

---

## 6. SHA-256 Checksums & File Identity

The cryptographic SHA-256 checksums of the implemented and verified files:

| File Path | SHA-256 Checksum |
| :--- | :--- |
| `src/witness/state-machine-types.ts` | `DD006076305D262D28CF1BA57C9FF762C516C916264AD04FD923726A8A3EC620` |
| `src/witness/state-machine.ts` | `C2CB8BFAF70D0F4D568DFB5CC23F8892FFB4E6869BAFEBB7850B9E949A1A9335` |
| `test/witness/state-machine.test.ts` | `3BF0051891E0A58DBA10727F005C8B1E33F64E7F58B19C5F95F9E90A139C73E8` |
| `src/witness/canonical-serializer.ts` | `DF8EA55DD5B0666BD4714E63C09A5D6AF1445BFFA6FCB21EF64D80746077D3F5` |
| `test/witness/canonical-ttcf.test.ts` | `C49DA311AA71C103564857B49CFD1DD813169789CFDCCAAC2A7CC8E143D00549` |

---

## 7. Scope Boundaries & Policy Compliance

### 7.1 Scope Guardrails
- **Step 3 Separation:**
  - Migration 004 has **NOT** been authored or applied.
  - `src/witness/consensus-store.ts` has **NOT** been created.
  - `src/witness/snapshot-manager.ts` has **NOT** been created.
  - `src/witness/compaction-coordinator.ts` has **NOT** been created.
- **Database Safety:**
  - Zero PostgreSQL schema changes executed.
  - Zero database connections opened.
- **Protobuf & Wire Hygiene:**
  - Receipt schemas and protobuf interfaces remain unmodified.
- **Git Hygiene:**
  - Zero commits performed.
  - Zero pushes to origin.
  - Pull Request #1 remains untouched.
  - Untracked architectural records and funding files remain preserved.

---

## 8. Conclusion & Recommendation

Milestone 13-D / Stage 2-B.2 / Step 2 implementation is complete, mathematically proven, and fully validated against the accepted architecture. All 32 state machine tests and 122 regression tests pass with zero regressions.

**Recommended Next Step:**
Submit this implementation report for the **Stage 2-B.2 Step 2 Independent Acceptance Audit**. Do not proceed to Step 3 until the audit has formally concluded and founder approval is granted.
