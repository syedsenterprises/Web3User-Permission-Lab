
# Web3User Permission Lab — Security Model

## 1. Scope

This project is a learning prototype for evaluating a demo transaction policy.
It returns one of three decisions:

- `ALLOW`: the supported action satisfies the implemented policy checks.
- `DENY`: a policy restriction is violated.
- `UNKNOWN`: required data is missing, malformed, or unsupported.

An `ALLOW` result is not transaction execution or an on-chain guarantee.

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

The SQLite database must be on a durable local filesystem and retained across
restarts. Every caller that needs shared replay protection must use the same
database. Separate database files do not share replay state. This library
does not choose or verify a deployment-wide database path.

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

### 8.6 Policy Revocation Followed by Restoration

We explicitly investigated the behavior and security implications when a policy is
temporarily revoked and subsequently restored:

1. **Behavior During Revocation**: If an artifact is issued under policy $P$ (`revoked: false`),
   and $P$ is later marked `revoked: true`, consumption attempts fail during revalidation
   with `DENY` ("Policy has been revoked.").
2. **State Retention**: Because the revalidation fails before storage consumption,
   the record in SQLite remains in the `state = 'issued'` state.
3. **Behavior Upon Restoration**: If policy $P$ is subsequently restored (`revoked: false`),
   a subsequent consumption attempt with valid trusted time and matching parameters will
   succeed: revalidation passes, the recomputed digest matches the issued digest
   (which bound `policy.revoked: false`), and SQLite atomically transitions the state
   from `issued` to `consumed`.

**Security Implication**: Policy revocation operates as a *temporary, conditional block*
on consumption rather than an *irreversible cancellation or tombstone* of pending
issued authorizations. If an organization's security posture requires that revoking a
policy permanently and irrevocably invalidates all unconsumed authorizations previously
issued under that policy:
- Do not merely restore the existing policy.
- Instead, **rotate the `policyId`** or advance the policy version when re-enabling
  permissions. Because `policyId` is bound into the canonical digest, rotating it
  permanently invalidates all previously issued artifacts under the old `policyId`.
- Alternatively, explicitly mark all outstanding authorization IDs as consumed in
  the persistent store before restoring permissions.

## 9. Testing and Limitations

The automated tests cover policy validation, time boundaries, amount
limits, recipient restrictions, malformed inputs, calldata mismatch, and
local SQLite reservation behavior. They do not establish deployment-wide
coordination, production durability, or production security.

Passing these tests does not constitute a security audit, formal
verification, or proof of production readiness.
