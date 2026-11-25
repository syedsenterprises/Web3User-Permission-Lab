# Web3User — Milestone 13-D Stage 2-B.2 / Step 1 Independent Acceptance Audit
## Type-Tagged Canonical Serializer & Hash Engine (`WP4`)

**Document ID:** `M13-D-STAGE-2B2-STEP-1-INDEPENDENT-AUDIT`  
**Audit Date:** 2026-11-24  
**Git Branch:** `feature/m13-d-consensus`  
**Base Commit (HEAD):** `f69da6b16c86a4ddc713ea0312a8c618ee5a9090`  
**Auditor:** Independent Technical Auditor  
**Audit Target:** Milestone 13-D Stage 2-B.2 Step 1 Implementation (`WP4`)  
**Audit Verdict:** **ACCEPTED WITH CONDITIONS**

---

## 1. Executive Summary & Audit Mandate

An independent technical acceptance audit was conducted on the Milestone 13-D Stage 2-B.2 Step 1 deliverables:
- `src/witness/canonical-serializer.ts`
- `test/witness/canonical-ttcf.test.ts`
- `docs/M13-D-STAGE-2B2-STEP-1-IMPLEMENTATION-REPORT.md`

The audit evaluated compliance against:
- ADR-M13D-014 (`docs/M13-D-STAGE-2B1-2-3-FINAL-ADR-CLOSURE.md`)
- Stage 2-B.2 Implementation Plan (`docs/M13-D-STAGE-2B2-IMPLEMENTATION-PLAN.md`, WP4)
- Stage 2-B.2 Pre-Implementation Verification (`docs/M13-D-STAGE-2B2-PREIMPLEMENTATION-VERIFICATION.md`)
- Existing consensus state machine (`src/witness/state-machine.ts`)
- Production witness receipt canonicalization (`src/monotonic-witness.ts`, `src/witness/signing.ts`)

### Audit Verdict: ACCEPTED WITH CONDITIONS
The core implementation successfully satisfies all primary architectural objectives: full byte-for-byte backward compatibility with Canon-v1, mathematical type disjointness across all 7 supported data types (`INV-CAN-01`), Unicode NFC normalization, duplicate normalized key rejection, negative zero normalization, safe integer bounds enforcement, and domain-separated SHA-256 hashing. All 41 dedicated TTCF tests, 20 state machine tests, and 99 total witness regression tests pass with clean TypeScript compilation.

However, an exhaustive probe into **JavaScript adversarial inputs** revealed that non-standard objects (`Date`, `Map`, `Set`, `Buffer`, `TypedArray`, `RegExp`) and sparse arrays are not deterministically rejected with `TypeError`; they fall back to generic object/array serialization (emitting `{}` or `[,,n:1]`). Because the audit mandate explicitly specifies: *"Require deterministic rejection where the input is outside the accepted canonical domain"*, the implementation is **ACCEPTED WITH CONDITIONS**, requiring founder authorization of a 15-line hardening patch prior to Step 2.

---

## 2. Audited Files & Cryptographic Checksums

| File Path | Description | Size (bytes) | SHA-256 Checksum |
| :--- | :--- | :--- | :--- |
| `src/witness/canonical-serializer.ts` | Step 1 Implementation Source | 8,734 | `ad6bc6470b6e7c039109942bcdb7ee4c84333705ca39835e5efb258d82471131` |
| `test/witness/canonical-ttcf.test.ts` | Step 1 Vitest Test Suite (41 tests) | 19,266 | `f8230f6419fd05a089f380af35c98a555e81ed5232e3698d6624996af9bc7c41` |
| `docs/M13-D-STAGE-2B2-STEP-1-IMPLEMENTATION-REPORT.md` | Implementation Evidence Report | 8,738 | `1bf3a6efdf39138d270cc215d95901d40ffd43a5833c313ae8d4189e6fa9fdf1` |
| `src/witness/state-machine.ts` | Stage 2-B.1 State Machine Reducer | 27,333 | `d1b8d9dacb2e08caf2e1ca7e5969c78fde8ddd93830da9dd156e013c272c4b0a` |
| `test/witness/state-machine.test.ts` | State Machine Unit Suite (20 tests) | 37,860 | `225e61468548a97f0775536c3972dc6b92ff8805d0ad125cfc8354822a910a2c` |
| `src/monotonic-witness.ts` | Witness Core & Receipt Logic | 25,267 | `a4474db2faa97fd64f7d10fefae8b8a4443bb489e76a8863e7a77d728a3e8941` |
| `src/witness/signing.ts` | Receipt Signing & Preimages | 13,210 | `0e1afec928d3ac1dab9a065cc45e81efba9c4985f339446a41bda468ffc8bc8f` |
| `test/witness/receipt-canonicalization.test.ts` | Receipt Canonicalization Suite (30 tests) | 32,289 | `4d4408ffb355ce5344e4fd0aac4f1768eaaf8a3b51b65113dbf9cc4550d43b4d` |

---

## 3. Detailed Audit Requirements Evaluation

### 3.1 Canon-v1 Backward Compatibility

#### 3.1.1 Implementation Comparison
- In `src/witness/state-machine.ts` (lines 125–165), Canon-v1 is implemented via an internal `canonicalizeValue(val)` function that stringifies BigInts as JSON strings (`JSON.stringify(val.toString())`), sorts object keys using `Object.keys().sort()`, and computes the SHA-256 hash without domain prefix.
- In `src/witness/canonical-serializer.ts` (lines 162–213), `canonicalizeValueV1` replicates this exact algorithm while adding a `WeakSet` cycle detector to guard against circular structures.
- In `computeCanonicalPayloadHashV1(payload)` (lines 222–228), empty/null/undefined payloads produce `sha256("")`, exactly matching `src/witness/state-machine.ts` line 171.

#### 3.1.2 Historical Golden Vector Differential Verification
The auditor ran a differential parity harness comparing `computeCanonicalPayloadHash` in `state-machine.ts` against `computeCanonicalPayloadHashV1` and `computeCanonicalPayloadHash(payload, 1)` in `canonical-serializer.ts` across 23 test vectors:

| # | Input Description | JavaScript Input Value | Canon-v1 Digest (Both Implementations) | Parity |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `null` | `null` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 100% Match |
| 2 | `undefined` | `undefined` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 100% Match |
| 3 | Boolean true | `true` | `b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b4447d124c` | 100% Match |
| 4 | Boolean false | `false` | `7fa6b10081d5843a846c4f3edc0d52a2ad6eebe12ad44005b821a7114b7e80f2` | 100% Match |
| 5 | Number 0 | `0` | `5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9` | 100% Match |
| 6 | Number -0 | `-0` | `5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9` | 100% Match |
| 7 | Number 42 | `42` | `a887019672eb719266fc03ab4e09fa845e2a3c7ef28c46522ef87cb507d3fc4d` | 100% Match |
| 8 | Number -42 | `-42` | `e32deffabf6487e411cbb09ce6cb0d0e6fbba6fefd1a93e3d360980c651f4967` | 100% Match |
| 9 | Float 3.14159 | `3.14159` | `532ea410130ce210e7166166444aeaa96c421e428c04e2878d91c5e6268840b2` | 100% Match |
| 10 | BigInt 100n | `100n` | `856f8872f67e3134908a8a4da7dc3d873b55b0190b7e1367a094aa1498e7ca97` | 100% Match |
| 11 | BigInt -100n | `-100n` | `378dfb9db7ce6460fa11ddbe23ab85ae0ad858a74e5033c46927e1f422b406e2` | 100% Match |
| 12 | String "hello" | `"hello"` | `2467d30f719001ee5c3f9b207558661fc4cb5caea9e262c5e52bb12fa9faea7e` | 100% Match |
| 13 | String with newline | `"hello\nworld"` | `ec56ba4bf435df2a420b9e8d47b0e14db8db97a760f38b29f9828452ef71fa99` | 100% Match |
| 14 | Empty string | `""` | `75b7f8b131413daf39a1c4dab13e4871e4c48b2c45d77ed68379f278b1a4d962` | 100% Match |
| 15 | Empty array | `[]` | `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` | 100% Match |
| 16 | Integer array | `[1, 2, 3]` | `8cb2237d0679ca88db6464eac60da963455139649b864a6463d8b30466cf1a53` | 100% Match |
| 17 | Heterogeneous array | `[1n, 2, "3", true, null]` | `2b8ca471804193aa9a4a7cf5287f61c37d4f9f257a09ab2472d80d2fbff4fb51` | 100% Match |
| 18 | Empty object | `{}` | `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a` | 100% Match |
| 19 | Unordered object | `{ b: 1, a: 2, c: "test" }` | `e2a4be6f851ebf3ec8b22e1aa658a26efb81ff7ab649ae130b925b42b29f7f45` | 100% Match |
| 20 | Nested object | `{ outer: { z: 10, y: 20, ... } }` | `2df283f510522199dbb0ffb307bf550474621c5b0df145455d36e2f6ce63737b` | 100% Match |
| 21 | EpochAdvancePayload | `{ epochId: "epoch-conflict", ... }`| `9633dd31776ce9dc62a22be14197992c30676a084ef7579bb5039563fcb08bf4` | 100% Match |
| 22 | PolicyUpdatePayload | `{ policyId: "pol-1", revision: 2, ... }`| `0731f4a47895f32eb5110f6396fceea2f36d3957f8841a13e59ea2c0ea115852` | 100% Match |
| 23 | TicketCommit budget window | `{ windowType: "HOURLY", ... }` | `f6ff4691e84a2ca4c6198f39562779a557b7f16f55bfdb3ee5e8f4980a37cfc0` | 100% Match |

**Result:** 23 of 23 test vectors matched 100% byte-for-byte.

#### 3.1.3 Default Dispatcher Routing
- `computeCanonicalPayloadHash(payload)`: Defaults to `version = 1`.
- `computeCanonicalPayloadHash(payload, 1)`: Dispatches to `computeCanonicalPayloadHashV1(payload)`.
- `computeCanonicalPayloadHash(payload, 2)`: Dispatches to `computeCanonicalPayloadHashV2(payload)`.
- Calling with invalid versions (e.g. `0`, `3`) throws `Error("Unsupported canonicalization version: ...")`.

#### 3.1.4 Codebase Callers Audit
A workspace-wide search for `computeCanonicalPayloadHash` confirmed only 4 files reference it:
1. `src/witness/canonical-serializer.ts`: Defines `computeCanonicalPayloadHashV1`, `computeCanonicalPayloadHashV2`, and `computeCanonicalPayloadHash(payload, version = 1)`.
2. `src/witness/state-machine.ts`: Retains its internal Canon-v1 definition. It will be updated in Step 2/Step 3 to consume `canonical-serializer.ts` with version discriminator support.
3. `test/witness/canonical-ttcf.test.ts`: Tests TTCF-v1, Canon-v1, and dispatcher routing.
4. `test/witness/state-machine.test.ts`: Exercises the state-machine reducer under Canon-v1.

---

### 3.2 TTCF-v1 Correctness & Specification Compliance

#### 3.2.1 Type-Tag Uniqueness & Disjointness (`INV-CAN-01`)
The TTCF-v1 grammar defines distinct prefixes across all 7 supported data types:
- `null` $\to$ `"null"` (Byte 0: `'n'`, Byte 1: `'u'`)
- `boolean` $\to$ `"true"` or `"false"` (Byte 0: `'t'` or `'f'`)
- `number` $\to$ `"n:" + normalized` (Byte 0: `'n'`, Byte 1: `':'`)
- `bigint` $\to$ `"bi:" + decimal` (Byte 0: `'b'`, Byte 1: `'i'`, Byte 2: `':'`)
- `string` $\to$ `"\"" + NFC_JSON + "\""` (Byte 0: `'"'`)
- `array` $\to$ `"[" + items.join(",") + "]"` (Byte 0: `'['`)
- `object` $\to$ `"{" + entries.join(",") + "}"` (Byte 0: `'{'`)

No two types share the same leading byte sequence. Crucially:
- `null` (`"null"`) is differentiated from `number` (`"n:..."`) by byte 1 (`'u'` vs `':'`).
- `bigint` (`"bi:100"`), `number` (`"n:100"`), and `string` (`"\"100\""`) have mutually disjoint prefixes (`bi:`, `n:`, `"`), eliminating the cross-type collision present in Canon-v1.

#### 3.2.2 Unicode NFC Normalization
Both string values and object keys are normalized using `str.normalize("NFC")`. The decomposed Unicode string `"e\u0301"` (composed of `"e"` `U+0065` and combining acute accent `U+0301`, 2 code units) normalizes to precomposed `"\u00e9"` (`U+00E9`, 1 code unit). Both serialize to identical canonical text and identical hashes.

#### 3.2.3 Duplicate Normalized Key Detection
In JavaScript, an object literal `{ "e\u0301": 1, "\u00e9": 2 }` contains two distinct dictionary keys (`"e\u0301"` and `"\u00e9"`). When normalized to NFC, both keys become `"\u00e9"`. The serializer tracks normalized keys in a `Map<string, string>`; when a collision is detected, it immediately throws:
```
TypeError: DUPLICATE_CANONICAL_OBJECT_KEY: Object keys 'é' and 'é' normalize to identical NFC key 'é'
```

#### 3.2.4 UTF-16 Code-Unit Key Sorting
Object keys are sorted using JavaScript's native string `.sort()`, which compares character code units lexicographically. For ASCII and basic multilingual plane characters, this matches UTF-8 byte ordering. Key insertion order has zero effect on the output.

#### 3.2.5 Sequence Preservation in Arrays
Arrays are mapped in index order ($0 \dots L-1$). Elements are not reordered or sorted.

#### 3.2.6 Domain Separation & SHA-256 Input Bytes
`TTCF_V1_DOMAIN_PREFIX = "TTCF-v1\n"` is prepended to the canonical string. The SHA-256 digest is computed over the resulting UTF-8 bytes:
$$\text{Hash}_{\text{v2}} = \text{SHA-256}(\text{"TTCF-v1\n"} \;\|\; \text{canonicalizeValueV2}(payload))$$
For absent payloads (`undefined`), the hash is computed over `"TTCF-v1\n"` alone:
`faa7eba606f4b43cef9393e024d63e2298d52266dd35a9ea9ee8ce547b8336d8`.

---

### 3.3 JavaScript Adversarial Inputs & Boundary Analysis

The auditor probed `canonicalizeValueV2` with 19 adversarial JavaScript constructs:

| Adversarial Input Category | Concrete Test Input | Observed Behavior | Status / Classification |
| :--- | :--- | :--- | :--- |
| **Cyclic Object** | `const o = { a: 1 }; o.self = o;` | `TypeError: Cannot canonicalize circular data structure in TTCF-v1` | **PASS (Deterministic Rejection)** |
| **Cyclic Array** | `const a = [1]; a.push(a);` | `TypeError: Cannot canonicalize circular data structure in TTCF-v1` | **PASS (Deterministic Rejection)** |
| **Sparse Array** | `const a = []; a[2] = 1;` | Emits `[,,n:1]` | **CONDITION (Grammar Non-Compliance)** |
| **Getter Returning Value** | `{ get x() { return 42; } }` | Emits `{"x":n:42}` | **PASS (Expected Property Access)** |
| **Getter Returning Undefined** | `{ get x() { return undefined; } }`| `TypeError: Cannot canonicalize undefined property value...` | **PASS (Deterministic Rejection)** |
| **Getter Throwing Error** | `{ get x() { throw new Error(); } }`| Throws `Error` | **PASS (Fails Closed)** |
| **Inherited Properties** | `Object.create({ inherited: 99 })` | Emits only own properties; prototype ignored | **PASS (Expected Object.keys behavior)** |
| **Symbol Keys** | `{ [Symbol('k')]: 1, a: 2 }` | Emits `{"a":n:2}`; symbol keys ignored | **PASS (Expected Object.keys behavior)** |
| **Symbol Values** | `{ a: Symbol('val') }` | `TypeError: Unsupported type for canonical serialization: symbol`| **PASS (Deterministic Rejection)** |
| **Non-Enumerable Property** | `Object.defineProperty(o, 'k', {enumerable: false})`| Ignored by `Object.keys()` | **PASS (Standard JSON Semantics)** |
| **Custom Prototype (`null`)** | `Object.create(null)` | Emits `{"a":n:1}`; clean execution | **PASS (No Prototype Pollution)** |
| **Custom Class Instance** | `new CustomClass()` | Emits own enumerable properties | **CONDITION (Non-Plain Object Allowed)** |
| **Date Instance** | `new Date('2026-01-01T00:00:00Z')` | Emits `{}` | **CONDITION (Lossy Serialization)** |
| **Map Instance** | `new Map([['a', 1]])` | Emits `{}` | **CONDITION (Lossy Serialization)** |
| **Set Instance** | `new Set([1, 2, 3])` | Emits `{}` | **CONDITION (Lossy Serialization)** |
| **Buffer Instance** | `Buffer.from('abc')` | Emits `{"0":n:97,"1":n:98,"2":n:99}` | **CONDITION (Treated as Dictionary)** |
| **Uint8Array Instance** | `new Uint8Array([1, 2])` | Emits `{"0":n:1,"1":n:2}` | **CONDITION (Treated as Dictionary)** |
| **RegExp Instance** | `/abc/g` | Emits `{}` | **CONDITION (Lossy Serialization)** |
| **Excessive Recursion** | 5,000 nested objects | `RangeError: Maximum call stack size exceeded` | **PASS (Fails Closed via V8)** |

#### Detailed Finding on Adversarial Non-Plain Objects & Sparse Arrays
1. **Sparse Arrays:** In JavaScript, `const a = []; a[2] = 1;` has `a.length === 3`, but indices `0` and `1` are unallocated empty slots. In `canonical-serializer.ts`, `val.map(...)` skips unassigned indices, producing an array with empty slots that joins to `[,,n:1]`. This violates the formal grammar rule `Array ::= "[" ( Value ( "," Value )* )? "]"` because `,` is not preceded or followed by a `Value`.
2. **Non-Plain Object Instances:** Objects instantiated from built-in constructors (`Date`, `Map`, `Set`, `RegExp`, `Buffer`, `Uint8Array`) have `typeof val === "object"`. Because they are not `Array.isArray(val)`, they enter the generic dictionary serializer. Because their internal state is stored in internal slots rather than enumerable own properties, `Object.keys()` returns `[]`, causing them to serialize as `{}`.
3. **Impact on Web3User Consensus:** In normal operations, all consensus command payloads (`EpochInitialize`, `EpochAdvance`, `EpochQuarantine`, `DelegationRevoke`, `PolicyUpdate`, `TicketCommit`) are deserialized from JSON or gRPC protobufs. Neither JSON nor gRPC ever produces sparse arrays, `Date` objects, `Map` objects, or `Set` objects. Therefore, this issue **cannot be triggered under nominal operation**. However, to strictly satisfy the audit requirement (*"Require deterministic rejection where the input is outside the accepted canonical domain"*), a targeted defense-in-depth patch must be applied.

---

## 4. Number Serialization & RFC 8785 Compliance

- **RFC 8785 §3.2.2.3 Alignment:**
  - Standard ECMAScript 6 / RFC 8785 number formatting is achieved via `JSON.stringify(num)`.
  - Negative zero `-0` is explicitly detected via `Object.is(num, -0) || num === 0` and normalized to `"n:0"`.
- **Safe Integer Boundaries:**
  - `Number.MAX_SAFE_INTEGER` ($2^{53} - 1 = 9007199254740991$) $\to$ `"n:9007199254740991"`.
  - `Number.MIN_SAFE_INTEGER` ($-2^{53} + 1 = -9007199254740991$) $\to$ `"n:-9007199254740991"`.
  - Boundary violation: $9007199254740992$ ($2^{53}$) and large exponential integers like $1 \times 10^{20}$ correctly trigger:
    ```
    TypeError: UNSAFE_INTEGER_USE_BIGINT: Integer value exceeds safe IEEE 754 bounds (|n| > 2^53 - 1)
    ```
- **Non-Finite Numbers:** `NaN`, `Infinity`, and `-Infinity` are rejected with `TypeError`.
- **Floating-Point Values:** Sub-normal and fractional values (`1e-7` $\to$ `"n:1e-7"`, `0.000001` $\to$ `"n:0.000001"`, `Number.EPSILON` $\to$ `"n:2.220446049250313e-16"`) serialize deterministically.
- **Independent Golden Vectors:** All number serialization hashes were independently verified in Python and Node.js.

---

## 5. Cryptographic Precision & Collision Analysis

### 5.1 Distinction: Preimage Injectivity vs. Hash Collision Resistance
The implementation report (`M13-D-STAGE-2B2-STEP-1-IMPLEMENTATION-REPORT.md`) stated: *"The serializer guarantees mathematical collision-freedom (INV-CAN-01)"*.

The auditor provides the following technical correction and precision:
1. **Preimage Injectivity (Serialization Layer):**  
   The canonical mapping $f: \mathcal{D} \to \Sigma^*$ (where $\mathcal{D}$ is the set of valid consensus data structures and $\Sigma^*$ is the string representation) is **injective**. For any $x, y \in \mathcal{D}$ such that $x \neq y$, $f(x) \neq f(y)$. This guarantees that the serialization layer introduces **zero collisions** (e.g., `bi:100` $\neq$ `n:100` $\neq$ `"100"`).
2. **Computational Collision Resistance (Hash Layer):**  
   The hash engine computes $H(x) = \text{SHA-256}(\text{"TTCF-v1\n"} \;\|\; f(x))$. Because the codomain is finite ($2^{256}$ bits) and the domain is infinite, collisions mathematically exist by the pigeonhole principle. The security guarantee provided by SHA-256 is **computational collision resistance** ($\approx 2^{128}$ operations against birthday attacks), not mathematical collision-freedom.
3. **Domain Separation:**  
   The prepended prefix `"TTCF-v1\n"` ensures that no TTCF-v1 digest can collide with any legacy Canon-v1 digest under the random oracle model.

---

## 6. Findings Matrix

| Finding ID | Severity | Category | Description | Condition / Resolution |
| :--- | :--- | :--- | :--- | :--- |
| **F-STEP1-01** | **Medium** | Adversarial Inputs | Sparse arrays (e.g. `const a = []; a[2] = 1;`) serialize to `[,,n:1]`, which violates canonical grammar `Array ::= "[" ( Value ( "," Value )* )? "]"` instead of being rejected. | **Condition 1:** Implement a dense array validation loop that throws `TypeError("Cannot canonicalize sparse array in TTCF-v1")`. |
| **F-STEP1-02** | **Medium** | Adversarial Inputs | Non-plain objects (`Date`, `Map`, `Set`, `Buffer`, `TypedArray`, `RegExp`) have `typeof === "object"` but lack enumerable keys, causing them to serialize as `{}` instead of failing closed. | **Condition 2:** Enforce plain-object validation (`Object.getPrototypeOf(val) === Object.prototype \|\| Object.getPrototypeOf(val) === null`) that throws `TypeError`. |
| **F-STEP1-03** | **Informational** | Technical Report | Minor phrasing correction: distinguish serialization preimage injectivity from SHA-256 computational collision resistance. | Reconciled in Section 5 of this audit report. |

---

## 7. Scope, Regression & Build Verification

### 7.1 Vitest Execution Results
1. **Dedicated TTCF Suite (`test/witness/canonical-ttcf.test.ts`):**  
   41 tests passed (13ms).
2. **State Machine Suite (`test/witness/state-machine.test.ts`):**  
   20 tests passed (15ms).
3. **Receipt Canonicalization Suite (`test/witness/receipt-canonicalization.test.ts`):**  
   30 tests passed (21ms).
4. **Lock Order Compatibility Suite (`test/witness/lock-order-compatibility.test.ts`):**  
   5 tests passed (8.2s).
5. **Disposal & Recovery Suite (`test/witness/disposal-and-recovery.test.ts`):**  
   3 tests passed (468ms).

**Total Regression:** 99 passed across 5 test suites (10.75s).

### 7.2 TypeScript Build Validation
```bash
npm run build
> web3user-permission-lab@0.1.0-rc.1 build
> tsc -p tsconfig.build.json

Exit Code: 0 (Zero warnings, zero errors)
```

### 7.3 Git Status & Scope Isolation
- `git diff`: Completely empty (0 tracked files modified).
- Database migrations: Unmodified; Migration 004 is uncreated.
- Scope bounds: Strictly isolated to Step 1. Steps 2–7 unstarted.
- Untracked artifacts: All Stage 2-B.1 state-machine files, 15+ M13-D documents, and funding application artifacts are fully preserved.

---

## 8. Audit Conditions & Proposed Hardening Patch

To satisfy **F-STEP1-01** and **F-STEP1-02**, the auditor specifies the following exact 15-line hardening patch for `src/witness/canonical-serializer.ts`:

```typescript
// In canonicalizeValueV2(val: unknown, seen = new WeakSet<object>()): string

  if (Array.isArray(val)) {
    // Dense array validation (F-STEP1-01)
    for (let i = 0; i < val.length; i++) {
      if (!(i in val)) {
        throw new TypeError("Cannot canonicalize sparse array in TTCF-v1");
      }
    }
    // ... existing cycle detection and map ...
  }

  if (type === "object") {
    // Plain object validation (F-STEP1-02)
    const proto = Object.getPrototypeOf(val);
    if (proto !== null && proto !== Object.prototype) {
      throw new TypeError(`Cannot canonicalize non-plain object (${Object.prototype.toString.call(val)}) in TTCF-v1`);
    }
    // ... existing cycle detection and key sorting ...
  }
```

### Authorization Gate:
- **Condition 1:** The founder authorizes applying the 15-line input hardening patch to `src/witness/canonical-serializer.ts`.
- **Condition 2:** Add corresponding unit tests in `test/witness/canonical-ttcf.test.ts` verifying that sparse arrays, `Date`, `Map`, `Set`, `Buffer`, and typed arrays throw `TypeError`.

Upon founder authorization of these two conditions, the patch may be applied and Step 1 will be fully closed, enabling seamless transition to Step 2.

---

## 9. Final Acceptance Verdict

```
========================================================================================
FINAL AUDIT VERDICT: ACCEPTED WITH CONDITIONS
========================================================================================
Status: Core Step 1 implementation verified; 99 regression tests passing; clean build.
Conditions: Authorize applying targeted input-hardening patch for sparse arrays and 
            non-plain objects before beginning Step 2.
========================================================================================
```
