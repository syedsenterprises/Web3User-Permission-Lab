import type { Decision } from "../../src/policy.js";

export const ERC20_TRANSFER_SELECTOR = "0xa9059cbb";
export const MAX_UINT256: bigint;
export const MAX_POLICY_ID_LENGTH: number;
export const MAX_CALLDATA_HEX_LENGTH: number;

export type BudgetWindowType = "HOURLY" | "DAILY";

export interface PolicyBudgetConfig {
  readonly window: BudgetWindowType;
  readonly maxCumulativeAmount: string;
}

export const BUDGET_WINDOW_SECONDS: Record<BudgetWindowType, number>;
export function calculateBudgetWindowStart(atSeconds: number, windowType: BudgetWindowType): number;
export function calculateBudgetWindowEnd(atSeconds: number, windowType: BudgetWindowType): number;

export interface NormalizedDemoPolicy {
  readonly version: 1;
  readonly policyId: string;
  readonly allowedTarget: string;
  readonly allowedRecipient: string;
  readonly allowedSelector: string;
  readonly maxAmount: string;
  readonly validFrom: number;
  readonly expiresAt: number;
  readonly revoked: boolean;
  readonly budget?: PolicyBudgetConfig;
}

export interface ParsedAction {
  readonly target: string;
  readonly calldata: string;
  readonly claimedAmount: string;
}

export interface DecodedTransfer {
  readonly recipient: string;
  readonly amount: bigint;
  readonly recipientWord: string;
  readonly amountWord: string;
}

export interface EvaluationResult {
  readonly decision: Decision;
  readonly reasons: string[];
}

export interface EvaluationCheck {
  readonly id: string;
  readonly name: string;
  readonly passed: boolean;
  readonly message: string;
}

export interface CalldataBreakdown {
  readonly selector: string;
  readonly recipientWord: string;
  readonly amountWord: string;
  readonly decodedRecipient: string | null;
  readonly decodedAmount: string | null;
}

export interface DetailedEvaluation {
  readonly decision: Decision;
  readonly reasons: string[];
  readonly checks: EvaluationCheck[];
  readonly calldataBreakdown: CalldataBreakdown | null;
}

export function isRecord(value: unknown): value is Record<string, unknown>;
export function isNonNegativeSafeInteger(value: unknown): value is number;
export function isUint256String(value: unknown): value is string;
export function normalizeDemoPolicy(input: unknown): NormalizedDemoPolicy | null;
export function parseAction(input: unknown): ParsedAction | null;
export function decodeTransfer(calldata: unknown): DecodedTransfer | null;
export function encodeTransferCalldata(recipient: string, amount: string | bigint | number): string;
export function evaluate(
  policyInput: unknown,
  actionInput: unknown,
  contextInput: unknown,
): EvaluationResult;
export function evaluateDetailed(
  policyInput: unknown,
  actionInput: unknown,
  contextInput: unknown,
): DetailedEvaluation;
