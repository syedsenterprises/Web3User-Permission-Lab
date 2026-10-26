
/**
 * Web3User Permission Lab — ERC-20 transfer policy evaluator.
 *
 * SECURITY CONTRACT:
 * - context.nowSeconds must come from a trusted caller.
 * - target and calldata must be bound to the exact transaction being authorized.
 * - This evaluator supports only ERC-20 transfer(address,uint256).
 * - The recipient and amount are decoded from the transaction calldata.
 * - action.amount is retained for compatibility but must match the decoded amount.
 * - maxAmount is a per-action limit, not a cumulative budget.
 * - ALLOW is a decision, not transaction enforcement.
 */

export type Decision = "ALLOW" | "DENY" | "UNKNOWN";

export type BudgetWindowType = "HOURLY" | "DAILY";

export interface PolicyBudgetConfig {
  /** Fixed time-window interval: HOURLY (3600s) or DAILY (86400s). */
  readonly window: BudgetWindowType;
  /**
   * Maximum aggregate spending permitted across all consumed transactions
   * within a single window bucket, formatted as a base-10 uint256 string.
   */
  readonly maxCumulativeAmount: string;
}

export interface DemoPolicy {
  version: 1;
  policyId: string;
  allowedTarget: string;
  allowedRecipient: string;
  allowedSelector: string;
  /** Inclusive maximum amount for one action, in base-10 uint256 units. */
  maxAmount: string;
  /** Unix timestamp in seconds. */
  validFrom: number;
  /** Exclusive expiration boundary. */
  expiresAt: number;
  revoked: boolean;
  /** Optional cumulative spending budget across transactions within a time window. */
  budget?: PolicyBudgetConfig;
}

export interface ProposedAction {
  /** Destination contract from the transaction being authorized. */
  target?: string;
  /** Full transaction calldata, including the 4-byte function selector. */
  calldata?: string;
  /**
   * Compatibility field. Must equal the amount decoded from calldata.
   * Never use this field as the authoritative transaction amount.
   */
  amount?: string;
}

export interface EvaluationContext {
  /** Trusted current Unix timestamp in seconds. */
  nowSeconds: number;
  /** Optional prior spent amount in the current window (primarily used for simulation / evaluation testing). */
  currentWindowSpent?: string;
}

export const BUDGET_WINDOW_SECONDS: Record<BudgetWindowType, number> = {
  HOURLY: 3600,
  DAILY: 86400,
};

export function calculateBudgetWindowStart(effectiveNowSeconds: number, window: BudgetWindowType): number {
  if (!isNonNegativeSafeInteger(effectiveNowSeconds)) {
    throw new Error(`effectiveNowSeconds must be a non-negative safe integer, received: ${effectiveNowSeconds}`);
  }
  const duration = BUDGET_WINDOW_SECONDS[window];
  if (!duration) {
    throw new Error(`Invalid budget window type: ${window}`);
  }
  return Math.floor(effectiveNowSeconds / duration) * duration;
}

export function calculateBudgetWindowEnd(effectiveNowSeconds: number, window: BudgetWindowType): number {
  return calculateBudgetWindowStart(effectiveNowSeconds, window) + BUDGET_WINDOW_SECONDS[window];
}

export interface Evaluation {
  decision: Decision;
  reasons: string[];
}

const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const SELECTOR = /^0x[a-fA-F0-9]{8}$/;
const UINT = /^(0|[1-9][0-9]*)$/;

const ERC20_TRANSFER_SELECTOR = "0xa9059cbb";
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_POLICY_ID_LENGTH = 128;
const MAX_CALLDATA_HEX_LENGTH = 2 + 2 * 4096;

function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

function isUint256String(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    !UINT.test(value) ||
    value.length > 78
  ) {
    return false;
  }

  try {
    return BigInt(value) <= MAX_UINT256;
  } catch {
    return false;
  }
}

function unknownResult(reason: string): Evaluation {
  return { decision: "UNKNOWN", reasons: [reason] };
}

/**
 * Validate a policy and return its canonical representation for comparison
 * and authorization binding. This does not establish that the policy came
 * from a trusted issuer.
 */
export function normalizeDemoPolicy(input: unknown): DemoPolicy | null {
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

  let normalizedBudget: PolicyBudgetConfig | undefined;
  if ("budget" in input && input.budget !== undefined && input.budget !== null) {
    if (!isRecord(input.budget)) return null;
    const { window, maxCumulativeAmount } = input.budget;
    if (window !== "HOURLY" && window !== "DAILY") return null;
    if (!isUint256String(maxCumulativeAmount)) return null;
    if (BigInt(maxAmount) > BigInt(maxCumulativeAmount)) return null;
    normalizedBudget = {
      window,
      maxCumulativeAmount,
    };
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
    ...(normalizedBudget ? { budget: normalizedBudget } : {}),
  };
}

interface ParsedAction {
  target: string;
  calldata: string;
  claimedAmount: string;
}

function parseAction(input: unknown): ParsedAction | null {
  if (!isRecord(input)) return null;

  const { target, calldata, amount } = input;

  if (
    typeof target !== "string" ||
    !ADDRESS.test(target) ||
    typeof calldata !== "string" ||
    calldata.length > MAX_CALLDATA_HEX_LENGTH ||
    // ERC-20 transfer has exactly 4 selector bytes and two 32-byte words.
    !/^0x[a-fA-F0-9]{136}$/.test(calldata) ||
    !isUint256String(amount)
  ) {
    return null;
  }

  return { target, calldata, claimedAmount: amount };
}

export interface DecodedTransfer {
  recipient: string;
  amount: bigint;
}

export function decodeTransfer(calldata: string): DecodedTransfer | null {
  if (calldata.slice(0, 10).toLowerCase() !== ERC20_TRANSFER_SELECTOR) {
    return null;
  }

  // Hex positions: 0x + 8 selector digits + 64 recipient digits + 64 amount digits.
  const recipientWord = calldata.slice(10, 74);
  const amountWord = calldata.slice(74, 138);

  // ABI addresses are 20 bytes, left-padded with 12 zero bytes.
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
    };
  } catch {
    return null;
  }
}

export function evaluate(
  policyInput: unknown,
  actionInput: unknown,
  contextInput: unknown,
): Evaluation {
  const policy = normalizeDemoPolicy(policyInput);

  if (!policy) {
    return unknownResult("Policy is malformed or unsupported.");
  }

  const action = parseAction(actionInput);

  if (!action) {
    return unknownResult(
      "Action is missing required fields or has malformed transaction data.",
    );
  }

  if (
    !isRecord(contextInput) ||
    !isNonNegativeSafeInteger(contextInput.nowSeconds)
  ) {
    return unknownResult("Trusted evaluation time is missing or invalid.");
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

  if (
    action.target.toLowerCase() !== policy.allowedTarget.toLowerCase()
  ) {
    return { decision: "DENY", reasons: ["Target contract is not allowlisted."] };
  }

  const actualSelector = action.calldata.slice(0, 10);

  if (actualSelector.toLowerCase() !== policy.allowedSelector.toLowerCase()) {
    return { decision: "DENY", reasons: ["Function selector is not allowlisted."] };
  }

  const decoded = decodeTransfer(action.calldata);

  if (!decoded) {
    return unknownResult("ERC-20 transfer calldata could not be decoded safely.");
  }

  if (BigInt(action.claimedAmount) !== decoded.amount) {
    return unknownResult(
      "Claimed amount does not match the amount encoded in calldata.",
    );
  }

  if (
    decoded.recipient.toLowerCase() !== policy.allowedRecipient.toLowerCase()
  ) {
    return { decision: "DENY", reasons: ["Recipient is not allowlisted."] };
  }

  if (decoded.amount > BigInt(policy.maxAmount)) {
    return {
      decision: "DENY",
      reasons: ["Amount exceeds the per-action policy limit."],
    };
  }

  if (
    policy.budget &&
    isRecord(contextInput) &&
    contextInput.currentWindowSpent !== undefined &&
    contextInput.currentWindowSpent !== null
  ) {
    if (
      typeof contextInput.currentWindowSpent !== "string" ||
      !isUint256String(contextInput.currentWindowSpent)
    ) {
      return unknownResult(
        "Evaluation context currentWindowSpent must be a valid uint256 decimal string.",
      );
    }
    const priorSpent = BigInt(contextInput.currentWindowSpent);
    const cumulativeLimit = BigInt(policy.budget.maxCumulativeAmount);
    if (priorSpent + decoded.amount > cumulativeLimit) {
      return {
        decision: "DENY",
        reasons: [
          `Amount exceeds the cumulative spending budget for the ${policy.budget.window.toLowerCase()} window.`,
        ],
      };
    }
  }

  return {
    decision: "ALLOW",
    reasons: [
      "ERC-20 transfer matches this demo policy; execution is not enforced by this function.",
    ],
  };
}
