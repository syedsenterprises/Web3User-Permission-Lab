import { evaluate, type Evaluation } from "./policy.js";
import {
  createTransactionEnvelope,
  matchesTransactionEnvelope,
  type TransactionEnvelope,
  type TransactionRequest,
} from "./transaction-envelope.js";
import type { SignedWitnessReceipt } from "./monotonic-witness.js";

export type TransactionAuthorization =
  | (Evaluation & {
      decision: "ALLOW";
      envelope: TransactionEnvelope;
      witnessReceipt?: SignedWitnessReceipt;
      witnessTicketId?: string;
    })
  | (Evaluation & {
      decision: "DENY" | "UNKNOWN";
      witnessTicketId?: string;
    });

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Extract the amount word from standard ERC-20 transfer calldata.
 * The policy evaluator independently decodes and verifies this amount.
 */
function getTransferAmount(calldata: string): string | null {
  if (!/^0xa9059cbb[a-fA-F0-9]{128}$/i.test(calldata)) {
    return null;
  }

  const recipientWord = calldata.slice(10, 74);
  const amountWord = calldata.slice(74, 138);

  if (!/^0{24}[a-fA-F0-9]{40}$/.test(recipientWord)) {
    return null;
  }

  try {
    return BigInt(`0x${amountWord}`).toString(10);
  } catch {
    return null;
  }
}

function readRequest(input: unknown): TransactionRequest | null {
  if (!isRecord(input)) return null;

  const { chainId, sender, target, calldata, value } = input;

  if (
    typeof chainId !== "string" ||
    typeof sender !== "string" ||
    typeof target !== "string" ||
    typeof calldata !== "string" ||
    typeof value !== "string"
  ) {
    return null;
  }

  return { chainId, sender, target, calldata, value };
}

/**
 * Prepare a policy-approved transaction envelope.
 *
 * ALLOW means the demo policy matched the request; it does not authorize
 * wallet signing, guarantee sender/chain allowlisting, or execute a transaction.
 */
export function prepareTransactionAuthorization(
  policyInput: unknown,
  requestInput: unknown,
  contextInput: unknown,
): TransactionAuthorization {
  const created = createTransactionEnvelope(requestInput);

  if (!created.ok) {
    return {
      decision: "UNKNOWN",
      reasons: [created.reason],
    };
  }

  const request = created.envelope.request;
  const amount = getTransferAmount(request.calldata);

  if (amount === null) {
    return {
      decision: "UNKNOWN",
      reasons: ["Only safely decodable ERC-20 transfer calldata is supported."],
    };
  }

  const result = evaluate(
    policyInput,
    {
      target: request.target,
      calldata: request.calldata,
      amount,
    },
    contextInput,
  );

  if (result.decision !== "ALLOW") {
    return {
      decision: result.decision,
      reasons: result.reasons,
    };
  }

  return {
    decision: "ALLOW",
    reasons: result.reasons,
    envelope: created.envelope,
  };
}

/**
 * Re-evaluate policy and verify the candidate still matches the original
 * envelope. Fail closed if the request was altered or is malformed.
 */
export function revalidateTransactionAuthorization(
  policyInput: unknown,
  envelopeInput: unknown,
  candidateInput: unknown,
  contextInput: unknown,
): TransactionAuthorization {
  if (!matchesTransactionEnvelope(envelopeInput, candidateInput)) {
    return {
      decision: "DENY",
      reasons: ["Transaction does not match the original envelope."],
    };
  }

  const request = readRequest(candidateInput);

  if (!request) {
    return {
      decision: "UNKNOWN",
      reasons: ["Transaction request is malformed."],
    };
  }

  const amount = getTransferAmount(request.calldata);

  if (amount === null) {
    return {
      decision: "UNKNOWN",
      reasons: ["Only safely decodable ERC-20 transfer calldata is supported."],
    };
  }

  const result = evaluate(
    policyInput,
    {
      target: request.target,
      calldata: request.calldata,
      amount,
    },
    contextInput,
  );

  if (result.decision !== "ALLOW") {
    return {
      decision: result.decision,
      reasons: result.reasons,
    };
  }

  // matchesTransactionEnvelope has already validated and narrowed this envelope.
  return {
    decision: "ALLOW",
    reasons: result.reasons,
    envelope: envelopeInput,
  };
}
