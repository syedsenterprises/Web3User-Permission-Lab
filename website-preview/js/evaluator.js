/**
 * Web3User Permission Lab — Client-side Policy Evaluator & Calldata Decoder
 *
 * Implements 100% parity with src/policy.ts for the interactive browser demo.
 * Zero external dependencies. Uses standard JavaScript BigInt, RegExp, and ES modules.
 */

export const ERC20_TRANSFER_SELECTOR = "0xa9059cbb";
export const MAX_UINT256 = (1n << 256n) - 1n;
export const MAX_POLICY_ID_LENGTH = 128;
export const MAX_CALLDATA_HEX_LENGTH = 2 + 2 * 4096;

const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const SELECTOR = /^0x[a-fA-F0-9]{8}$/;
const UINT = /^(0|[1-9][0-9]*)$/;

export function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isNonNegativeSafeInteger(value) {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

export function isUint256String(value) {
  if (typeof value !== "string" || !UINT.test(value) || value.length > 78) {
    return false;
  }
  try {
    return BigInt(value) <= MAX_UINT256;
  } catch {
    return false;
  }
}

export function normalizeDemoPolicy(input) {
  if (!isRecord(input)) return null;

  const {
    version,
    policyId,
    allowedTarget,
    allowedRecipient,
    allowedSelector,
    maxAmount,
    validFrom,
    expiresAt,
    revoked,
  } = input;

  if (
    version !== 1 ||
    typeof policyId !== "string" ||
    policyId.trim().length === 0 ||
    policyId.length > MAX_POLICY_ID_LENGTH ||
    typeof allowedTarget !== "string" ||
    !ADDRESS.test(allowedTarget) ||
    typeof allowedRecipient !== "string" ||
    !ADDRESS.test(allowedRecipient) ||
    typeof allowedSelector !== "string" ||
    !SELECTOR.test(allowedSelector) ||
    allowedSelector.toLowerCase() !== ERC20_TRANSFER_SELECTOR ||
    !isUint256String(maxAmount) ||
    !isNonNegativeSafeInteger(validFrom) ||
    !isNonNegativeSafeInteger(expiresAt) ||
    expiresAt <= validFrom ||
    typeof revoked !== "boolean"
  ) {
    return null;
  }

  return {
    version: 1,
    policyId,
    allowedTarget: allowedTarget.toLowerCase(),
    allowedRecipient: allowedRecipient.toLowerCase(),
    allowedSelector: allowedSelector.toLowerCase(),
    maxAmount,
    validFrom,
    expiresAt,
    revoked,
  };
}

export function parseAction(input) {
  if (!isRecord(input)) return null;

  const { target, calldata, amount } = input;

  if (
    typeof target !== "string" ||
    !ADDRESS.test(target) ||
    typeof calldata !== "string" ||
    calldata.length > MAX_CALLDATA_HEX_LENGTH ||
    !/^0x[a-fA-F0-9]{136}$/.test(calldata) ||
    !isUint256String(amount)
  ) {
    return null;
  }

  return { target, calldata, claimedAmount: amount };
}

export function decodeTransfer(calldata) {
  if (typeof calldata !== "string" || calldata.slice(0, 10).toLowerCase() !== ERC20_TRANSFER_SELECTOR) {
    return null;
  }

  const recipientWord = calldata.slice(10, 74);
  const amountWord = calldata.slice(74, 138);

  if (!/^0{24}[a-fA-F0-9]{40}$/.test(recipientWord)) {
    return null;
  }

  if (!/^[a-fA-F0-9]{64}$/.test(amountWord)) {
    return null;
  }

  try {
    return {
      recipient: `0x${recipientWord.slice(24)}`,
      amount: BigInt(`0x${amountWord}`),
      recipientWord,
      amountWord,
    };
  } catch {
    return null;
  }
}

export function encodeTransferCalldata(recipient, amount) {
  if (!ADDRESS.test(recipient)) {
    throw new Error("Invalid recipient address format.");
  }
  const cleanRecipient = recipient.slice(2).toLowerCase().padStart(64, "0");
  const bigAmount = BigInt(amount);
  if (bigAmount < 0n || bigAmount > MAX_UINT256) {
    throw new Error("Amount out of uint256 range.");
  }
  const hexAmount = bigAmount.toString(16).padStart(64, "0");
  return `${ERC20_TRANSFER_SELECTOR}${cleanRecipient}${hexAmount}`;
}

export function evaluate(policyInput, actionInput, contextInput) {
  const policy = normalizeDemoPolicy(policyInput);
  if (!policy) {
    return { decision: "UNKNOWN", reasons: ["Policy is malformed or unsupported."] };
  }

  const action = parseAction(actionInput);
  if (!action) {
    return {
      decision: "UNKNOWN",
      reasons: ["Action is missing required fields or has malformed transaction data."],
    };
  }

  if (!isRecord(contextInput) || !isNonNegativeSafeInteger(contextInput.nowSeconds)) {
    return { decision: "UNKNOWN", reasons: ["Trusted evaluation time is missing or invalid."] };
  }

  const nowSeconds = contextInput.nowSeconds;

  if (policy.revoked) {
    return { decision: "DENY", reasons: ["Policy has been revoked."] };
  }

  if (nowSeconds < policy.validFrom) {
    return { decision: "DENY", reasons: ["Policy is not yet valid."] };
  }

  if (nowSeconds >= policy.expiresAt) {
    return { decision: "DENY", reasons: ["Policy has expired."] };
  }

  if (action.target.toLowerCase() !== policy.allowedTarget.toLowerCase()) {
    return { decision: "DENY", reasons: ["Target contract is not allowlisted."] };
  }

  const actualSelector = action.calldata.slice(0, 10);
  if (actualSelector.toLowerCase() !== policy.allowedSelector.toLowerCase()) {
    return { decision: "DENY", reasons: ["Function selector is not allowlisted."] };
  }

  const decoded = decodeTransfer(action.calldata);
  if (!decoded) {
    return { decision: "UNKNOWN", reasons: ["ERC-20 transfer calldata could not be decoded safely."] };
  }

  if (BigInt(action.claimedAmount) !== decoded.amount) {
    return {
      decision: "UNKNOWN",
      reasons: ["Claimed amount does not match the amount encoded in calldata."],
    };
  }

  if (decoded.recipient.toLowerCase() !== policy.allowedRecipient.toLowerCase()) {
    return { decision: "DENY", reasons: ["Recipient is not allowlisted."] };
  }

  if (decoded.amount > BigInt(policy.maxAmount)) {
    return {
      decision: "DENY",
      reasons: ["Amount exceeds the per-action policy limit."],
    };
  }

  return {
    decision: "ALLOW",
    reasons: [
      "ERC-20 transfer matches this demo policy; execution is not enforced by this function.",
    ],
  };
}

/**
 * Detailed evaluation returning step-by-step audit results for interactive UI visualization.
 */
export function evaluateDetailed(policyInput, actionInput, contextInput) {
  const result = evaluate(policyInput, actionInput, contextInput);
  const policy = normalizeDemoPolicy(policyInput);
  const action = parseAction(actionInput);
  const nowSeconds = isRecord(contextInput) && isNonNegativeSafeInteger(contextInput.nowSeconds) ? contextInput.nowSeconds : null;
  const decoded = action ? decodeTransfer(action.calldata) : null;

  const checks = [
    {
      id: "policy_schema",
      name: "Policy Structure & Validation",
      passed: policy !== null,
      message: policy ? "Valid policy schema (v1, ERC-20 transfer policy)" : "Policy is malformed or invalid",
    },
    {
      id: "policy_active",
      name: "Policy Status (Not Revoked)",
      passed: policy ? !policy.revoked : false,
      message: policy && policy.revoked ? "Policy has been revoked" : (policy ? "Policy is currently active" : "Unknown"),
    },
    {
      id: "time_window",
      name: "Validity Window (validFrom <= now < expiresAt)",
      passed: policy && nowSeconds !== null ? nowSeconds >= policy.validFrom && nowSeconds < policy.expiresAt : false,
      message: policy && nowSeconds !== null
        ? (nowSeconds < policy.validFrom ? "Current time is before validFrom" : (nowSeconds >= policy.expiresAt ? "Current time has expired" : "Current timestamp is within valid window"))
        : "Timestamp or policy invalid",
    },
    {
      id: "target_contract",
      name: "Target Contract Allowlist",
      passed: policy && action ? action.target.toLowerCase() === policy.allowedTarget.toLowerCase() : false,
      message: policy && action
        ? (action.target.toLowerCase() === policy.allowedTarget.toLowerCase() ? "Target address matches allowedTarget" : "Target contract address is not allowlisted")
        : "Missing target or policy",
    },
    {
      id: "selector_check",
      name: "Function Selector (0xa9059cbb)",
      passed: policy && action ? action.calldata.slice(0, 10).toLowerCase() === policy.allowedSelector.toLowerCase() : false,
      message: policy && action
        ? (action.calldata.slice(0, 10).toLowerCase() === policy.allowedSelector.toLowerCase() ? "Selector matches ERC-20 transfer(address,uint256)" : "Selector is not allowlisted")
        : "Missing action or policy",
    },
    {
      id: "calldata_decode",
      name: "Calldata ABI Word Structure",
      passed: decoded !== null,
      message: decoded ? "Calldata decoded successfully (20-byte address, 32-byte amount)" : "Calldata cannot be decoded safely",
    },
    {
      id: "amount_match",
      name: "Claimed Amount vs Calldata Parity",
      passed: action && decoded ? BigInt(action.claimedAmount) === decoded.amount : false,
      message: action && decoded
        ? (BigInt(action.claimedAmount) === decoded.amount ? "Claimed amount matches encoded calldata amount" : "Mismatch between claimed amount and calldata amount")
        : "Cannot verify amount parity",
    },
    {
      id: "recipient_check",
      name: "Recipient Address Allowlist",
      passed: policy && decoded ? decoded.recipient.toLowerCase() === policy.allowedRecipient.toLowerCase() : false,
      message: policy && decoded
        ? (decoded.recipient.toLowerCase() === policy.allowedRecipient.toLowerCase() ? "Recipient matches allowedRecipient" : "Recipient address is not allowlisted")
        : "Missing recipient or policy",
    },
    {
      id: "amount_limit",
      name: "Per-Action Maximum Amount Ceiling",
      passed: policy && decoded ? decoded.amount <= BigInt(policy.maxAmount) : false,
      message: policy && decoded
        ? (decoded.amount <= BigInt(policy.maxAmount) ? "Transfer amount is within per-action maxAmount limit" : "Transfer amount exceeds per-action maxAmount limit")
        : "Missing amount or policy",
    },
  ];

  let calldataBreakdown = null;
  if (action && typeof action.calldata === "string" && action.calldata.startsWith("0x") && action.calldata.length >= 10) {
    const raw = action.calldata;
    calldataBreakdown = {
      selector: raw.slice(0, 10),
      recipientWord: raw.length >= 74 ? raw.slice(10, 74) : raw.slice(10),
      amountWord: raw.length >= 138 ? raw.slice(74, 138) : (raw.length > 74 ? raw.slice(74) : ""),
      decodedRecipient: decoded ? decoded.recipient : null,
      decodedAmount: decoded ? decoded.amount.toString(10) : null,
    };
  }

  return {
    decision: result.decision,
    reasons: result.reasons,
    checks,
    calldataBreakdown,
  };
}
