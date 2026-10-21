
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

## 7. Cumulative Limits and Replay Protection

Cumulative or time-window budgets are not implemented. They require
persistent accounting, atomic updates, concurrency handling, and
replay protections in the enforcement layer.

## 8. Testing and Limitations

The automated tests cover policy validation, time boundaries, amount
limits, recipient restrictions, malformed inputs, and calldata mismatch.

Passing these tests does not constitute a security audit, formal
verification, or proof of production readiness.
