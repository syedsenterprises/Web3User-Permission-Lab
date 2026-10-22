import { createHash } from "node:crypto";
import type { DemoPolicy } from "./policy.js";
import type { TransactionRequest } from "./transaction-envelope.js";

export const BOUND_AUTHORIZATION_ARTIFACT_VERSION = 1 as const;

export interface BoundAuthorizationArtifact {
  readonly version: typeof BOUND_AUTHORIZATION_ARTIFACT_VERSION;
  readonly authorizationId: string;
  readonly bindingDigest: string;
}

const DIGEST = /^sha256:[a-f0-9]{64}$/;

function encodeField(name: string, value: string): string {
  return `${name}:${Buffer.byteLength(value, "utf8")}:${value}\n`;
}

/**
 * Create a fixed-order encoding from already validated, canonical values.
 * This deliberately avoids serializing arbitrary caller-owned objects.
 */
function canonicalBinding(
  policy: DemoPolicy,
  request: Readonly<TransactionRequest>,
): string {
  return [
    "web3user-bound-authorization-v1\n",
    encodeField("request.chainId", request.chainId),
    encodeField("request.sender", request.sender),
    encodeField("request.target", request.target),
    encodeField("request.calldata", request.calldata),
    encodeField("request.value", request.value),
    encodeField("policy.version", String(policy.version)),
    encodeField("policy.policyId", policy.policyId),
    encodeField("policy.allowedTarget", policy.allowedTarget),
    encodeField("policy.allowedRecipient", policy.allowedRecipient),
    encodeField("policy.allowedSelector", policy.allowedSelector),
    encodeField("policy.maxAmount", policy.maxAmount),
    encodeField("policy.validFrom", String(policy.validFrom)),
    encodeField("policy.expiresAt", String(policy.expiresAt)),
    encodeField("policy.revoked", String(policy.revoked)),
  ].join("");
}

/**
 * The digest binds policy and request data. It does not authenticate an issuer.
 */
export function createAuthorizationBindingDigest(
  policy: DemoPolicy,
  request: Readonly<TransactionRequest>,
): string {
  const digest = createHash("sha256")
    .update(canonicalBinding(policy, request), "utf8")
    .digest("hex");
  return `sha256:${digest}`;
}

export function isBoundAuthorizationArtifact(
  input: unknown,
): input is BoundAuthorizationArtifact {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return false;
  }

  const artifact = input as Record<string, unknown>;
  return (
    artifact.version === BOUND_AUTHORIZATION_ARTIFACT_VERSION &&
    typeof artifact.authorizationId === "string" &&
    typeof artifact.bindingDigest === "string" &&
    DIGEST.test(artifact.bindingDigest)
  );
}
