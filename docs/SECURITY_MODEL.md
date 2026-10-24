
# Web3User Permission Lab — Security Model

## 1. Scope

This project is a learning prototype for evaluating a demo transaction policy.
It returns one of three decisions:

- `ALLOW`: the supported action satisfies the implemented policy checks.
- `DENY`: a policy restriction is violated.
- `UNKNOWN`: required data is missing, malformed, or unsupported.

An `ALLOW` result is not transaction execution or an on-chain guarantee. It represents solely an off-chain authorization decision indicating policy compliance and recording an atomic single-use reservation in SQLite.

## 2. Supported Transaction Format

The evaluator supports only the ERC-20 function:

`transfer(address,uint256)`

Its selector is `0xa9059cbb`.

The evaluator requires exactly 68 bytes of calldata:
4 bytes for the selector and 32 bytes for each ABI argument.

It validates ABI address padding and decodes the recipient and amount
from the calldata. Other function selectors and malformed encodings
are not supported by this evaluator.

## 3. Contract and Recipient Allowlisting

The policy defines both:

- `allowedTarget`: the ERC-20 token contract address.
- `allowedRecipient`: the only recipient permitted by this policy.

The transaction target and decoded recipient must match their respective
allowlisted addresses. Address comparisons are case-insensitive.

This prototype does not establish that the target address contains a
verified or trustworthy token contract. A production system needs chain
identity and contract verification appropriate to its threat model.

## 4. Amount Validation

Amounts are unsigned decimal integer strings bounded to uint256.
`BigInt` is used to avoid floating-point precision loss.

The amount is decoded from the actual calldata. The compatibility
field `action.amount` must match the decoded amount; it is not the
authoritative amount used for the limit check.

`maxAmount` is an inclusive PER-ACTION maximum. An amount equal to
the maximum is allowed; an amount above it is denied.

This is not a cumulative spending budget. Multiple individually
permitted transfers can exceed a desired aggregate budget.

## 5. Trusted Time and Policy Validity

`EvaluationContext.nowSeconds` must be supplied by a trusted caller.
Do not accept authoritative time from an untrusted user or from the
proposed action.

Policy timestamps must be non-negative safe integers, and `expiresAt`
must be greater than `validFrom`.

The policy is valid from `validFrom`, inclusive, until `expiresAt`,
exclusive. A revoked policy is denied.

## 6. Transaction Binding and Enforcement

The caller must bind `target` and `calldata` to the exact transaction
being authorized. A production integration must also consider chain ID,
sender, native transaction value, nonce, deadline, token identity, and
any other transaction fields relevant to its threat model.

The evaluator does not submit, block, or enforce transactions. A trusted
enforcement layer must consume the decision for the same transaction
that was evaluated and must fail closed on `DENY` or `UNKNOWN`.
An `ALLOW` decision confirms policy compliance and marks the authorization
consumed off-chain; the external caller / relayer remains responsible for
obtaining the wallet's EVM transaction signature (secp256k1) and submitting
the signed transaction to an Ethereum RPC node.

The evaluator's inputs and result must not be trusted if an attacker can
alter them between evaluation and execution.

## 7. Replay Protection and Persistent Consumption

`consumeTransactionAuthorization(...)` and
`consumeTransactionAuthorizationById(...)` keep consumed envelope/ID state
in process memory. That state is lost on restart and is not shared with other
processes. These APIs remain available for compatibility, but do not provide
durable replay protection.

`consumeTransactionAuthorizationWithStore(...)` is the library's persistent
consumption boundary. It revalidates envelope-to-request binding and the
current supplied policy and context before reserving the authorization ID.
With `SQLiteAuthorizationStore`, a primary key makes reservation unique within
the database. A duplicate ID returns `DENY`.

The SQLite database must be on a durable, locally attached filesystem and retained across
restarts. Network filesystems (NFS, SMB/CIFS, AWS EFS, GlusterFS) are strictly
unsupported: SQLite WAL mode requires shared memory (`-shm`) and robust POSIX byte-range
file locking, which network filesystems do not reliably provide, risking database
corruption or locking errors (`SQLITE_BUSY`, `SQLITE_IOERR`). The database must reside
on direct local block storage (e.g. local NVMe/SSD, or dedicated block storage like AWS EBS
or GCP Persistent Disk mounted locally). Every caller that needs shared
replay protection must use the same database. Separate database files do not share replay state.
This library does not choose or verify a deployment-wide database path.

Authorization IDs are required to be nonblank strings. The APIs trim leading
and trailing whitespace, then compare IDs case-sensitively. The caller is
responsible for issuing IDs and binding them to the intended authorization;
the library cannot verify that an arbitrary supplied ID came from a trusted
issuer.

Policy data and `EvaluationContext.nowSeconds` must come from trusted sources.
The consuming caller must pass current policy state and trusted time so
revocation and expiry are checked at consumption.

Database construction and reservation errors propagate to the caller; they
are never converted to `ALLOW`. A reservation exception is not authorization
approval: the caller must fail closed and must not proceed with the protected
operation. Its outcome is indeterminate; the ID may already have been
consumed. Do not retry under a different ID. This API has no reconciliation
or reservation-status query for an uncertain outcome. Retain the original ID
and resolve the outcome through an explicitly designed recovery process
before deciding what to do next. A close error also propagates to the caller
and does not undo a reservation that already completed. Callers must not fall
back to process-local replay protection. There is no automatic database
replacement or deletion.

Replay protection is only one part of transaction enforcement. This library
does not sign or submit transactions, connect to a wallet, or enforce an
on-chain result. Cumulative or time-window budgets are not implemented.

## 8. Bound Authorization Artifacts and Additive State Model

Milestone 5B introduces versioned, serializable authorization artifacts paired
with an additive two-phase (`issued` → `consumed`) state model in SQLite.

### 8.1 Artifact Structure and Deterministic Canonical Binding

A bound authorization artifact (`BoundAuthorizationArtifact`) is a versioned,
serializable object containing:
- `version`: integer schema version (currently `1`).
- `authorizationId`: unique, non-empty, trimmed identifier.
- `bindingDigest`: SHA-256 digest formatted as `sha256:<64 hex characters>`.

The binding digest is computed by `createAuthorizationBindingDigest` over a
deterministic, canonical string encoding (`web3user-bound-authorization-v1\n`).
Each field is serialized with a length prefix (`name:length:value\n`) to eliminate
delimiter collision. The bound fields include:
- Normalized request parameters: `chainId`, `sender` (lowercase), `target` (lowercase),
  `calldata` (lowercase), and native `value`.
- Normalized policy constraints: `version`, `policyId`, `allowedTarget` (lowercase),
  `allowedRecipient` (lowercase), `allowedSelector` (lowercase), `maxAmount`,
  `validFrom`, `expiresAt`, and `revoked`.

### 8.2 Additive SQLite Migration and Two-Phase State Model

The underlying table `consumed_authorization_ids` is extended additively:
- `authorization_id TEXT PRIMARY KEY`
- `binding_digest TEXT`
- `state TEXT NOT NULL DEFAULT 'consumed' CHECK (state IN ('issued', 'consumed'))`
- `consumed_at TEXT` (nullable; set only upon consumption)

Existing databases containing legacy consumed records are upgraded additively.
Legacy records retain `state = 'consumed'`, their original `consumed_at` timestamp, and `binding_digest = NULL`.

The store supports two lifecycle models:
1. **Legacy One-Phase Reservation**: `reserve(id)` directly inserts the ID with
   `state = 'consumed'` and `consumed_at = CURRENT_TIMESTAMP`. If the ID already exists in any state, reservation fails.
2. **Bound Two-Phase Issuance and Consumption**:
   - `issueBound(id, digest)`: Atomically inserts a record in `state = 'issued'`
     with the expected `binding_digest` and `consumed_at = NULL`. If the ID already exists in either `issued`
     or `consumed` state, issuance fails closed with `DENY`.
   - `consumeBound(id, digest)`: Atomically transitions exactly one record from
     `state = 'issued'` to `state = 'consumed'`, setting `consumed_at = CURRENT_TIMESTAMP`,
     matching both the `authorization_id` and `binding_digest`. If the record is missing, already consumed, or has a
     mismatched digest, consumption fails closed with `DENY`.

### 8.3 Issuer Authentication Limitation

The binding digest establishes strict cryptographic integrity between the normalized
transaction request and the evaluated policy snapshot. However:
- **The digest does not authenticate the issuer.** The SHA-256 digest is an unkeyed
  cryptographic hash, not an HMAC or digital signature.
- Any caller with access to a policy and transaction request can compute the
  canonical binding digest.
- `issueBoundTransactionAuthorizationWithStore` relies entirely on the caller being
  an authorized, trusted issuer. An untrusted party must not be permitted to call
  the issuance boundary.

### 8.4 Bearer Capability and Interception Risks

A bound authorization artifact functions as a **bearer capability**:
- Possession of the serialized artifact (`authorizationId` and `bindingDigest`)
  along with the corresponding transaction request grants the bearer the ability to
  consume the authorization.
- If an issued artifact is intercepted or leaked before consumption, an adversary
  could submit the artifact and transaction to `consumeBoundTransactionAuthorizationWithStore`
  ahead of the intended caller. While the adversary cannot alter transaction
  parameters (such as redirecting funds to an unapproved recipient or changing the
  amount without invalidating the binding digest), they could consume the single-use
  authorization prematurely, causing a denial of service for the legitimate caller.
- Callers must safeguard artifacts in transit and at rest, and production systems
  should bind consumption to authenticated caller sessions where required.

### 8.5 Revalidation and Pre-Consumption Protection

When `consumeBoundTransactionAuthorizationWithStore` is called:
1. The artifact format and normalized ID are validated.
2. The current policy snapshot, trusted time (`EvaluationContext.nowSeconds`), and
   candidate transaction are fully revalidated against the envelope.
3. The canonical binding digest is recomputed using current normalized policy and
   request fields.
4. If the recomputed digest differs from the artifact's `bindingDigest`, the request
   is denied immediately without touching storage.
5. The storage transition (`consumeBound`) is executed only after all checks pass.
   Storage errors propagate and never result in `ALLOW` or fallback to in-memory state.
6. A failed consumption attempt due to parameter mismatch, policy violation, or
   expiry does not consume the issued record in SQLite, leaving the original
   authorization available for a legitimate matching transaction.

### 8.6 Policy Revocation Followed by Restoration (Historical V1 vs. Authoritative V3)

We explicitly distinguish the historical Milestone 5B (V1) behavior from the authoritative Milestone 6.2+ Version 3 architecture:

#### Historical Milestone 5B (Unkeyed Binding Digests / V1)
In historical Milestone 5B, callers passed in-memory policy snapshots directly to `consumeBoundTransactionAuthorizationWithStore`:
1. **Behavior During Revocation**: If an artifact is issued under policy $P$ (`revoked: false`), and $P$ is later passed with `revoked: true`, consumption attempts fail during revalidation with `DENY` ("Policy has been revoked.").
2. **State Retention**: Because revalidation fails before storage mutation, the record in SQLite remains in `state = 'issued'`.
3. **Behavior Upon Restoration**: If policy $P$ is subsequently passed with `revoked: false`, a subsequent consumption attempt with valid trusted time and matching parameters would succeed, because the recomputed digest matched the issued digest (which bound `policy.revoked: false`). Under this legacy model, revocation functioned only as a temporary, conditional block.

#### Milestone 6.2+ Version 3 (Authoritative SQLite Governance and Policy Revisions)
In Version 3, policies are managed authoritatively in SQLite (`SQLitePolicyStore`) with strict monotonic revision tracking:
1. **Monotonic Revision Advancement**: Restoring a revoked policy via `SQLitePolicyStore.restorePolicy()` increments `current_revision` (`newRevision = row.current_revision + 1`).
2. **Permanent Invalidation of Prior Authorizations**: V3 signed authorization artifacts cryptographically bind both `policy.policyId` AND `policy.policyRevision` into the canonical signed payload (`canonicalSignedPayloadV3`).
3. **Rejection After Restoration**: During consumption, `consumeSignedTransactionAuthorizationV3` verifies that `polRow.current_revision === artifact.policyRevision`. Because restoration increments the policy revision, any previously issued V3 artifact bound to the earlier revision is rejected with:
   `Policy revision mismatch: artifact bound to revision X, but current policy revision is X+1.`
4. **No Revalidation of Old Authorizations**: In V3, policy restoration does NOT revalidate old authorizations. Revocation followed by restoration permanently invalidates all authorizations issued under pre-revocation revisions, guaranteeing that compromised or superseded authorizations cannot be re-activated.

## 9. Testing and Limitations

The automated tests cover policy validation, time boundaries, amount
limits, recipient restrictions, malformed inputs, calldata mismatch, and
local SQLite reservation behavior. They do not establish deployment-wide
coordination, production durability, or production security.

Passing these tests does not constitute a security audit, formal
verification, or proof of production readiness.

## 10. Milestone 6.4 Security Model: Asymmetric Signatures, Governance, and Recovery Invariants

Milestone 6.4 represents the current locally validated security architecture (working tree verified on top of commit `f1bed7f51e6a3ccb024b17a86993faf07bc48349`, unpublished), consolidating the security architecture beyond the unkeyed binding digests of Milestone 5B. The system implements cryptographic issuer authenticity, authoritative in-database governance, transactional monotonic timekeeping, safe integer arithmetic, and verified crash-recovery invariants.

### 10.1 V3 Signed Authorization Artifacts and Canonical Serialization

Unkeyed binding digests (V1) establish transaction-to-policy integrity but do not authenticate the issuer. Milestone 6 introduces versioned asymmetric digital signatures using Ed25519 (`node:crypto`).

A Version 3 signed authorization artifact (`SignedAuthorizationArtifactV3`) comprises:
- `version`: literal integer `3`.
- `authorizationId`: non-empty, trimmed unique identifier.
- `keyId`: non-empty, trimmed identifier of the signing key.
- `issuedAtSeconds`: non-negative safe-integer Unix timestamp of issuance.
- `expiresAtSeconds`: non-negative safe-integer Unix timestamp of authorization expiry (`expiresAtSeconds > issuedAtSeconds`).
- `policyId`: non-empty, trimmed identifier of the authoritative policy.
- `policyRevision`: positive safe-integer revision number (`>= 1`).
- `bindingDigest`: SHA-256 digest formatted as `sha256:<64 hex characters>`.
- `signature`: 128-character lowercase hexadecimal Ed25519 digital signature.

To prevent delimiter injection, field swapping, and canonical ambiguity, V3 payloads are encoded using deterministic length-prefixed serialization:
- Canonical header: `web3user-signed-authorization-v3\n`
- Field format: `name:length:value\n`, where `length` is the exact UTF-8 byte count of `value`.
- Bound fields in order: `artifact.version`, `artifact.authorizationId`, `key.keyId`, `artifact.issuedAtSeconds`, `artifact.expiresAtSeconds`, `policy.policyId`, `policy.policyRevision`, and `artifact.bindingDigest`.

Signature verification is performed strictly before persistent storage operations. Any signature mismatch, malformed artifact shape, or tampered field results in immediate fail-closed rejection with `DENY`, without modifying SQLite state.

### 10.2 Cryptographic Boundaries vs. Blockchain Transaction Signing

A critical architectural distinction exists between **authorization artifact signing** and **blockchain transaction signing**:
- **Authorization Artifact Signing (Off-Chain)**: The Ed25519 signature generated by this library authenticates the policy evaluation authority. It attests that a specific transaction proposal was evaluated and approved under an authoritative policy snapshot by a recognized issuer key.
- **Blockchain Transaction Signing (On-Chain/Wallet)**: The Ethereum/EVM transaction itself must be signed by the user's or relayer's private key (typically via secp256k1 in a hardware wallet, browser extension, or account abstraction bundler). The SDK does not manage, handle, or access wallet private keys.
- **Enforcement Boundary**: The authorization artifact is an off-chain permission token. The library does NOT sign Ethereum transactions, broadcast transactions to RPC nodes, manage wallet keys, or custody assets. An integrating enforcement proxy or wallet must verify the authorization artifact before requesting the user's signature on the corresponding EVM transaction.

### 10.3 In-Database Key Registry and Governance Lifecycle

Issuer public keys are maintained in SQLite within the `issuer_keys` table, supporting dynamic governance without requiring hardcoded application keys.

1. **Governance States**:
   - `active`: Key is authorized to issue new V3 authorizations and verify unexpired authorizations.
   - `retired`: Key is safely sunset. It is strictly forbidden from signing new authorizations, but unexpired authorizations issued prior to retirement remain verifiable until their own `expiresAtSeconds`.
   - `revoked`: Key is compromised or emergency-invalidated. It is immediately forbidden from signing, and all pending or unexpired authorizations signed by this key fail closed immediately.
2. **Timestamp Invariants**:
   - Keys define safe integer boundaries: `validFromSeconds`, optional `retiredAtSeconds`, and optional `revokedAtSeconds`.
   - The key store enforces chronological integrity: `validFromSeconds <= retiredAtSeconds <= revokedAtSeconds`.
   - During issuance and consumption, the evaluator verifies that `trustedNowSeconds >= validFromSeconds` and that the key has not been revoked.

### 10.4 Authoritative Policy Revisions and Monotonic Evolution

To prevent policy confusion and unauthorized tampering:
- Policies are stored persistently in the `policies` and `policy_revisions` tables.
- Each policy change advances a monotonic revision counter (`policyRevision`).
- Revisions are immutable and auditable. Replay of obsolete policy definitions is rejected because the artifact cryptographically binds both `policyId` and `policyRevision`.
- Evaluators verify that the candidate transaction matches the exact policy revision cited in the authorization artifact.

### 10.5 Persistent Replay Protection, SQLite WAL Mode, and Two-Phase State Model

Persistent replay protection is implemented via SQLite in Write-Ahead Logging (WAL) mode (`PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;`):
- Authorizations exist in two discrete states: `issued` and `consumed` within `consumed_authorization_ids`.
- The `artifact_version` column enforces cross-version discrimination: V3 consumption queries explicitly filter `artifact_version = 3`.
- State transitions are executed inside atomic transactions:
  ```sql
  UPDATE consumed_authorization_ids
  SET state = 'consumed', consumed_at = CURRENT_TIMESTAMP
  WHERE authorization_id = ? AND binding_digest = ? AND state = 'issued' AND artifact_version = 3;
  ```
- If the record does not exist in `state = 'issued'`, has already been consumed, or contains a mismatched digest/version, `UPDATE` modifies 0 rows and consumption fails closed with `DENY`.

### 10.6 Transaction-Locked Monotonic System Clock and Rollback Detection

To defend against system clock tampering, NTP backward leaps, and time-skew replay attacks, the store enforces a transaction-locked monotonic clock high-water mark:
- Table `system_clock_state` maintains `high_water_seconds` keyed by `clock_name`.
- Within every write transaction (`BEGIN IMMEDIATE;`), the store reads the recorded high-water mark.
- If the supplied `trustedNowSeconds` is strictly less than `high_water_seconds`, the operation is aborted with an error, detecting backward wall-clock jumps.
- When `trustedNowSeconds >= high_water_seconds`, the high-water mark is updated atomically alongside the authorization state changes.
- Rollbacks of failed transactions automatically revert uncommitted high-water clock advances.

### 10.7 Bounded SQLite Contention Retries and Non-Spinning Synchronization

Under concurrent multi-process execution, SQLite write locks (`BEGIN IMMEDIATE;`) can encounter transient lock contention (`SQLITE_BUSY`):
- Operations employ a bounded retry loop (default: 5 attempts over a 250ms cumulative time budget).
- Backoff delays use exponential progression with full jitter (base delay 15ms, max per-attempt delay 100ms):
  $$\text{delay} = \text{random}(0, \min(100, 15 \times 2^{\text{attempt} - 1}))$$
- Delays are executed synchronously using `sleepSync` via `Atomics.wait` on a `SharedArrayBuffer`:
  ```typescript
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delayMs);
  ```
  This yields the OS thread and prevents CPU spin-wait starvation while preserving synchronous execution semantics.
- If contention exceeds the retry budget, the transaction fails closed, propagating a busy error rather than silently defaulting to `ALLOW` or deadlocking.

### 10.8 Subtraction-First Safe-Integer TTL Arithmetic and Overflow Prevention

In JavaScript runtimes, integer arithmetic exceeding `Number.MAX_SAFE_INTEGER` ($2^{53} - 1 = 9,007,199,254,740,991$) loses precision, causing silent bit-truncation or invalid timestamp comparisons.

When computing an authorization's expiration timestamp from a caller-specified `ttlSeconds` and current time `effectiveNowSeconds`:
1. **The Vulnerability**: Computing `effectiveNowSeconds + ttlSeconds` directly can overflow `Number.MAX_SAFE_INTEGER` if a large TTL is supplied, even when both inputs are individually safe integers.
2. **Subtraction-First Algorithm**:
   - Determine the maximum allowable expiration ceiling (`maxAllowedExpiresAt`) as the minimum of:
     - `policy.expiresAt` (if set)
     - `issuerKey.expiresAtSeconds` (if set)
     - `Number.MAX_SAFE_INTEGER`
   - If `maxAllowedExpiresAt <= effectiveNowSeconds`, the validity interval is empty and issuance is denied immediately.
   - Compute the remaining safe duration:
     $$\text{remainingValidSeconds} = \text{maxAllowedExpiresAt} - \text{effectiveNowSeconds}$$
   - If $\text{ttlSeconds} \ge \text{remainingValidSeconds}$, the expiration is clamped to $\text{maxAllowedExpiresAt}$.
   - Otherwise, $\text{effectiveExpiresAt} = \text{effectiveNowSeconds} + \text{ttlSeconds}$, which is mathematically guaranteed not to exceed $\text{maxAllowedExpiresAt} \le \text{Number.MAX_SAFE_INTEGER}$.
3. **Boundary Invariants**:
   - Expiration caps are strictly exclusive: at the exact second `nowSeconds >= expiresAtSeconds`, the authorization is expired and denied.
   - The resulting `effectiveExpiresAt` is verified to be a positive safe integer strictly greater than `effectiveNowSeconds`.

### 10.9 Process-Crash Recovery Invariants vs. Physical Power-Loss Durability

Milestone 6.4 includes automated test coverage verifying database recovery following abrupt process termination:
- **Process-Crash Testing**: Subprocess workers are terminated abruptly using `process.exit(1)` or `SIGKILL` while holding active write transactions before `COMMIT`.
- **Verified Invariants**: Upon reopening the database with a fresh store instance, SQLite's WAL log recovery automatically rolls back all partial uncommitted writes. The database remains uncorrupted, the monotonic clock high-water mark retains its last committed value, and no partial or orphaned `issued` records persist.
- **Critical Durability Qualification**: Verification of **process-crash recovery** does NOT constitute proof of **physical power-loss durability**. Protection against sudden power loss, hardware reset, or host virtualization crashes depends on underlying operating system page caches, disk controller write caches, and filesystem `fsync` / flush barriers outside the scope of this prototype library.

### 10.10 Fail-Closed Legacy Artifact Compatibility

The authorization lifecycle engine supports configurable artifact version policy:
- By default, strict mode is enforced (`allowLegacyArtifactVersions: false`). Unsigned V1 or V2 artifacts presented to V3 consumption endpoints are rejected immediately.
- Rejection of an invalid, expired, or legacy artifact fails closed before updating storage, leaving the underlying authorization record and `consumed_at` timestamp unmodified.
- Applications and legacy tests requiring backward compatibility with historical V1 or V2 artifacts must explicitly pass `{ allowLegacyArtifactVersions: true }` in store options.

### 10.11 Atomic Key Lifecycle and Clock High-Water Governance

In `SQLiteKeyStore`:
- Clock validation and high-water mark advancement (`system_clock_state`) execute inside the exact same `withImmediateTransaction` boundary as key mutations (`registerKey`, `retireKey`, `revokeKey`).
- If a mutation fails (e.g. duplicate key registration with different PEM, invalid key status, or nonexistent key ID), the entire transaction rolls back, reverting both the key change and any tentative high-water clock advance.
- An unauthenticated or malformed key operation cannot cause clock skew or denial of service by advancing the clock high-water mark ahead of true wall-clock time.

### 10.12 Defensive Length Boundaries on Identifiers and Payloads

To prevent denial of service and unbounded memory allocation during UTF-8 canonical encoding and SQLite primary-key indexing:
- `authorizationId`: strictly bounded to a maximum of 128 characters across `normalizeAuthorizationId`, `validateAuthorizationId`, `canonicalSignedPayloadV3`, `isSignedAuthorizationArtifactV3`, and `SQLiteAuthorizationStore`.
- `calldata`: `createTransactionEnvelope` enforces an early sanity bound of at most 131,074 hex characters (0x prefix + 64 KB binary data) before invoking regular expressions or allocating frozen request snapshots.
- ERC-20 transfer calldata rules in `src/policy.ts` remain strictly constrained to exact 138-character payloads (`0xa9059cbb` selector + 32-byte recipient word + 32-byte amount word).

### 10.13 Individual Authorization Cancellation and Lifecycle Transition

Milestone 6.7 introduces explicit, individual authorization cancellation before consumption:
- Entry points: `SQLiteAuthorizationStore.cancelAuthorization(authorizationId)` and `cancelSignedTransactionAuthorizationV3(store, authorizationId)`.
- Storage transition:
  ```sql
  UPDATE consumed_authorization_ids
  SET state = 'cancelled', consumed_at = CURRENT_TIMESTAMP
  WHERE authorization_id = ? AND state = 'issued';
  ```
- State invariants:
  - Only authorizations currently in state `'issued'` can transition to `'cancelled'`.
  - Non-existent authorizations return `false`.
  - Already-consumed authorizations return `false` (consumption wins; state remains `consumed`).
  - Already-cancelled authorizations return `false` (idempotent fail-closed).
  - Cancelled authorizations cannot be consumed: `consumeSignedTransactionAuthorizationV3` requires `state = 'issued'`, returning `DENY` ("Bound transaction authorization is unknown, consumed, or mismatched.").
  - Cancelled authorizations cannot be re-issued: `authorization_id` is the `PRIMARY KEY`; subsequent issuance attempts are rejected by SQLite unique constraints.
  - Multi-process concurrency: Write locks under `BEGIN IMMEDIATE;` guarantee that concurrent cancel and consume operations on the same authorization ID are strictly serialized. Exactly one operation succeeds, and the other fails closed.

### 10.14 Process-Local Memory Invariants and Anti-Replay Guardrails

To prevent unbounded process memory consumption while preserving replay protection:
- `consumedEnvelopes`: Maintained as a `WeakSet<object>`. Weak references permit the JavaScript garbage collector to automatically reclaim memory as soon as envelope object references leave caller scope. Zero memory leak occurs over long-running processes.
- `consumedAuthorizationIds`: In-memory `Set<string>` used solely by the legacy, process-local `consumeTransactionAuthorizationById` API.
- Rejection of LRU Eviction: Implementing an arbitrary LRU eviction cache for authorization IDs introduces a critical replay vulnerability. An attacker can flood distinct dummy authorizations to evict a previously consumed target ID, enabling replay of the target transaction.
- Bounded Fail-Closed Memory Model: `consumedAuthorizationIds` enforces a strict memory ceiling (`MAX_PROCESS_LOCAL_CONSUMED_IDS = 10_000`). When capacity is reached, new in-memory authorizations fail closed with `DENY` ("Process-local authorization capacity exceeded; durable storage is required for long-running replay protection."). Previously consumed IDs are never evicted, ensuring replay protection remains absolute. Persistent store callers bypass process-local sets entirely, maintaining durable SQLite-backed replay protection with constant memory overhead.

### 10.15 Milestone 6.8 Phase 1 Clock Guardrails, Multi-Process Invariants, and Residual Limitations

Milestone 6.8 Phase 1 implements a defense-in-depth clock guardrail architecture (`ClockGuard`) to prevent persistent high-water poisoning caused by untrusted host forward clock jumps without breaking legitimate idle periods or multi-process concurrency:

1. **Dual-Clock Anchoring (`process.hrtime.bigint()`)**:
   - The process initializes an in-memory anchor pairing wall-clock seconds (`clock.nowSeconds()`) with host monotonic nanoseconds (`process.hrtime.bigint()` via `MonotonicClock`).
   - Monotonic time is immune to NTP slewing, forward steps, backward steps, and manual clock alterations.
   - Comparing $\Delta t_{\text{wall}}$ against $\Delta t_{\text{mono}}$ relative to the initial anchor and the last published observation reliably isolates wall-clock step velocity and gradual drift without false positives during long idle periods.

2. **Symmetric Divergence Bounds**:
   - **Step Velocity Forward Limit (`MAX_FORWARD_STEP_SECONDS = 10`)**: An instantaneous wall-clock forward step exceeding monotonic elapsed time by more than 10 seconds triggers an immediate fail-closed trip (`TRIPPED_CLOSED`).
   - **Step Velocity Backward Limit (`MAX_BACKWARD_STEP_SECONDS = 5`)**: An instantaneous wall-clock backward step exceeding 5 seconds while remaining above high-water triggers an immediate trip (`TRIPPED_CLOSED`).
   - **Cumulative Divergence Ceiling (`MAX_ABSOLUTE_DIVERGENCE_SECONDS = 60`)**: Cumulative drift between wall time and monotonic time across the anchor lifetime cannot exceed 60 seconds, bounding long-term NTP slewing or drift.
   - **Anchor Expiration (`MAX_ANCHOR_LIFETIME_SECONDS = 86400` / 24 hours)**: In-memory anchors expire after 24 hours of process uptime, requiring a controlled process restart to re-anchor against host time.
   - **Startup Damage-Containment Threshold (`MAX_STARTUP_FORWARD_GAP_SECONDS = 3600`)**: Upon database open, if host wall-clock time exceeds the persisted SQLite high-water mark by more than 1 hour (configurable via `maxStartupForwardGapSeconds`), startup fails closed to prevent establishment of a poisoned anchor following machine restarts.

3. **Two-Phase Candidate-Sample Transaction Lifecycle**:
   - In-process transactions acquire an exclusive serialization lock (`guard.acquireLock()`) to prevent overlapping evaluation races within the same Node.js process.
   - The candidate sample (`{ wallSeconds, monotonicNanos }`) and the persistent SQLite high-water mark are validated *inside* the serialized SQLite write transaction (`BEGIN IMMEDIATE;`), strictly *before* persistent mutations.
   - The in-memory candidate sample is published (`guard.publishCandidate()`) *only after confirmed successful `COMMIT;`*.
   - If business evaluation fails or SQLite mutations throw, the transaction executes `ROLLBACK;` and the candidate sample is discarded without updating local published state.

4. **Multi-Process High-Water Invariant**:
   - Across multiple worker processes sharing a single SQLite database, a process's local published sample may lag behind the authoritative shared SQLite high-water mark ($\text{localPublishedSample} \le \text{sqlite.high\_water\_seconds}$).
   - If another worker advances SQLite high-water beyond worker A's current clock, worker A's subsequent candidate timestamp below high-water is rejected with `Clock rollback detected` without tripping worker A's in-memory anchor. Once worker A's clock reaches or exceeds the shared high-water mark, operations proceed normally.
   - **NTP Synchronization Target**: To minimize spurious rollback detections between concurrent workers sharing a database, host nodes should run an active NTP daemon (`chrony` or `systemd-timesyncd`). Maintaining clock synchronization within an operational target of ~100ms across hosts is a recommended deployment practice, rather than a formal mathematical theorem or library guarantee.

5. **Fatal Tainted-Connection Invariant**:
   - If SQLite `COMMIT;` throws or produces an uncertain outcome, the connection is treated as permanently compromised.
   - The store executes a safety rollback attempt, closes the underlying SQLite database connection, marks the store and guard as `CONNECTION_TAINTED`, and invokes the optional `onFatalTaint` callback.
   - The clock guard enters a permanent `TRIPPED_CLOSED` state.
   - All subsequent authorization reads, writes, and decision APIs (`getDatabase()`, `advanceHighWaterMark()`, `issueSignedTransactionAuthorizationV3()`, `consumeSignedTransactionAuthorizationV3()`) fail closed immediately without performing further database operations.

6. **Anti-Time-Travel Consumption Validation**:
   - Authorization artifacts are evaluated against the current candidate wall-clock timestamp: `artifact.issuedAtSeconds <= candidate.wallSeconds`.
   - Any artifact claiming issuance in the future relative to the evaluating clock is rejected immediately with a fail-closed denial.

7. **Residual Limitations**:
   - **OS / Hypervisor Suspend/Resume**: When a host virtual machine or OS is suspended, monotonic time counters may pause while wall-clock time continues to advance, or hypervisor time-sync tools may step wall-clock time upon resume. A resume gap exceeding 10 seconds step velocity or 60 seconds cumulative divergence will trip the clock guard into `TRIPPED_CLOSED`, requiring an operator-controlled process restart after verifying physical clock synchronization.
   - **Offline Startup Ambiguity**: In air-gapped or offline environments lacking authenticated external time attestations (e.g. Roughtime / NTS), a process cannot cryptographically distinguish legitimate long-term offline downtime from a forward clock jump upon fresh startup. The 3,600-second startup gap acts strictly as a damage-containment boundary, not a proof of physical time. Recovery from legitimate extended downtime exceeding the threshold requires operator mediation (e.g., explicit configuration of `maxStartupForwardGapSeconds`). Phase 1 deliberately excludes recovery APIs or schema migrations to avoid unauthenticated bypasses.

### 10.16 SQLite Durability Policy and Storage Failure Boundaries

Milestone 6.11 establishes an explicit storage durability policy across all SQLite-backed stores (`SQLiteAuthorizationStore`, `SQLitePolicyStore`, `SQLiteKeyStore`):

1. **Connection-Scoped PRAGMA Configuration**:
   - Every independent database connection explicitly initializes:
     - `PRAGMA journal_mode = WAL;`
     - `PRAGMA synchronous = FULL;` (default, or user-configured `"OFF" | "NORMAL" | "FULL" | "EXTRA"`)
     - `PRAGMA busy_timeout = 5000;`
   - Because SQLite's `synchronous` pragma is connection-scoped and not stored in the database header, every store constructor opening a database file sets it explicitly. Borrowed connections (e.g. `authStore.getPolicyStore()`, `authStore.getKeyStore()`) inherit the parent store's configured connection.

2. **Three-Tier Durability Model**:
   - **Process-Crash Recovery**: Guaranteed by SQLite WAL atomic commit logs. If a worker process crashes abruptly (`process.exit()`, unhandled exceptions, `SIGKILL`), incomplete transactions are rolled back cleanly upon subsequent open, and committed transactions remain intact.
   - **OS-Crash Durability**: Under `PRAGMA synchronous = FULL`, every transaction `COMMIT;` issues an explicit operating-system disk flush (`FlushFileBuffers` on Windows, `fsync` on POSIX). Dirty WAL frames are pushed to the storage controller prior to transaction completion. In the event of an operating-system kernel panic or unexpected reboot, acknowledged authorization consumptions, policy revisions, and clock advancements are preserved on disk.
   - **Physical Power-Loss Durability & Limits**: Software-level `fsync` requests instruct the OS and drive controller to flush data to non-volatile storage. However, physical power-loss durability remains bounded by host hardware drive characteristics. Consumer storage devices lacking power-loss protection (PLP / power-loss capacitors) may acknowledge flush requests while buffering data in volatile drive DRAM. Software tests simulate disk-level failures and OS signals, but cannot physically guarantee hardware persistence against drives that falsely acknowledge cache flushes without writing to non-volatile media. Enterprise storage controllers featuring hardware PLP are recommended for mission-critical deployments requiring physical power-loss resilience, but are not universally mandatory for non-critical, development, or battery-backed host environments.

3. **WAL Checkpointing and Concurrency Semantics**:
   - SQLite Write-Ahead Logging accumulates page changes in a companion `-wal` file.
   - The engine provides `engine.storage.checkpoint(mode?: CheckpointMode): CheckpointResult` (wrapping `PRAGMA wal_checkpoint(...)`).
   - Supported checkpoint modes:
     - `PASSIVE` (default): Transfers as many frames as possible without blocking concurrent readers or writers. Returns immediately; does not truncate the WAL file. Safe to run during live application traffic.
     - `FULL`: Checkpoints all frames up to the end of the WAL file, waiting for concurrent readers to finish reading existing frames, but does not truncate.
     - `RESTART`: Checkpoints all frames and waits for readers to finish so that subsequent writes restart at the beginning of the WAL file.
     - `TRUNCATE`: Executes like `RESTART` and additionally truncates the WAL file to zero bytes upon completion.
   - **Return Structure**: Returns `{ busy: boolean, logFrames: number, checkpointedFrames: number }`.
   - **Long-Running Reader Impact**: If active read transactions hold snapshots of older WAL frames, checkpointing cannot advance past the oldest active read transaction. In `TRUNCATE` mode, this returns `{ busy: true }` and leaves un-checkpointed frames in the WAL file without truncating.
   - **Operational Guidance**: Do not invoke `checkpoint("TRUNCATE")` unconditionally on latency-critical authorization paths. Checkpointing should be scheduled during off-peak periods or background maintenance intervals, and callers should inspect `result.busy` to determine whether all frames were successfully checkpointed and truncated.

4. **Storage Medium and Network Filesystem Restrictions**:
   - SQLite WAL mode relies fundamentally on shared-memory memory-mapped files (`-shm`) and POSIX advisory byte-range locks (or Windows equivalent locking APIs).
   - Network filesystems (NFS, SMB/CIFS, AWS EFS, Azure Files, GlusterFS) frequently provide broken, non-compliant, or high-latency locking implementations and lack coherent shared-memory support across multiple hosts.
   - Storing the SQLite database on network filesystems risks silent index corruption, stuck locks, and unexpected `SQLITE_BUSY` or `SQLITE_IOERR` failures.
   - The database file must reside on directly attached local block storage (e.g. local NVMe/SSD or dedicated cloud block storage volumes such as AWS EBS or GCP Persistent Disk mounted locally with standard journaling filesystems like ext4, XFS, or NTFS).
