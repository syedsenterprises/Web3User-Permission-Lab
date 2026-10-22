
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

## 8. Testing and Limitations

The automated tests cover policy validation, time boundaries, amount
limits, recipient restrictions, malformed inputs, calldata mismatch, and
local SQLite reservation behavior. They do not establish deployment-wide
coordination, production durability, or production security.

Passing these tests does not constitute a security audit, formal
verification, or proof of production readiness.
