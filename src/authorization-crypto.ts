import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
  sign,
  verify,
} from "node:crypto";

export const SIGNED_AUTHORIZATION_ARTIFACT_VERSION = 2 as const;

export interface SignedAuthorizationArtifact {
  readonly version: typeof SIGNED_AUTHORIZATION_ARTIFACT_VERSION;
  readonly authorizationId: string;
  readonly keyId: string;
  readonly bindingDigest: string;
  readonly signature: string;
}

const DIGEST_REGEX = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE_REGEX = /^[0-9a-f]{128}$/i;

function encodeField(name: string, value: string): string {
  return `${name}:${Buffer.byteLength(value, "utf8")}:${value}\n`;
}

/**
 * Deterministic length-prefixed canonical encoding for signed authorization payloads.
 * Binds artifact version, authorization ID, key ID, and binding digest.
 * The binding digest itself binds canonical transaction request and policy constraints.
 */
export function canonicalSignedPayload(
  version: number,
  authorizationId: string,
  keyId: string,
  bindingDigest: string,
): string {
  return [
    "web3user-signed-authorization-v2\n",
    encodeField("artifact.version", String(version)),
    encodeField("artifact.authorizationId", authorizationId),
    encodeField("key.keyId", keyId),
    encodeField("artifact.bindingDigest", bindingDigest),
  ].join("");
}

/**
 * Validates and extracts an Ed25519 public KeyObject from a KeyObject or PEM string.
 * Returns null if the key is invalid or not an Ed25519 public key.
 */
export function parseEd25519PublicKey(key: KeyObject | string): KeyObject | null {
  try {
    let keyObj: KeyObject;
    if (key instanceof KeyObject) {
      keyObj = key;
    } else if (typeof key === "string") {
      keyObj = createPublicKey(key);
    } else {
      return null;
    }

    if (keyObj.type !== "public" || keyObj.asymmetricKeyType !== "ed25519") {
      return null;
    }
    return keyObj;
  } catch {
    return null;
  }
}

/**
 * Validates and extracts an Ed25519 private KeyObject from a KeyObject or PEM string.
 * Returns null if the key is invalid or not an Ed25519 private key.
 */
export function parseEd25519PrivateKey(key: KeyObject | string): KeyObject | null {
  try {
    let keyObj: KeyObject;
    if (key instanceof KeyObject) {
      keyObj = key;
    } else if (typeof key === "string") {
      keyObj = createPrivateKey(key);
    } else {
      return null;
    }

    if (keyObj.type !== "private" || keyObj.asymmetricKeyType !== "ed25519") {
      return null;
    }
    return keyObj;
  } catch {
    return null;
  }
}

/**
 * Sign a payload with an Ed25519 private key.
 * Returns a 128-character lowercase hex string (64 bytes).
 */
export function signAuthorizationPayload(
  privateKey: KeyObject | string,
  payload: string | Buffer,
): string {
  const keyObj = parseEd25519PrivateKey(privateKey);
  if (keyObj === null) {
    throw new Error("Invalid Ed25519 private key.");
  }

  const data = typeof payload === "string" ? Buffer.from(payload, "utf8") : payload;
  const signature = sign(null, data, keyObj);
  return signature.toString("hex");
}

/**
 * Verify an Ed25519 signature against the payload using the public key.
 * Returns true if valid, false if invalid, malformed, or wrong key.
 */
export function verifyAuthorizationPayload(
  publicKey: KeyObject | string,
  payload: string | Buffer,
  signature: string,
): boolean {
  if (typeof signature !== "string" || !SIGNATURE_REGEX.test(signature)) {
    return false;
  }

  const keyObj = parseEd25519PublicKey(publicKey);
  if (keyObj === null) {
    return false;
  }

  try {
    const data = typeof payload === "string" ? Buffer.from(payload, "utf8") : payload;
    const sigBuf = Buffer.from(signature, "hex");
    return verify(null, data, keyObj, sigBuf);
  } catch {
    return false;
  }
}

/**
 * Strictly validate a signed authorization artifact format.
 */
export function isSignedAuthorizationArtifact(
  input: unknown,
): input is SignedAuthorizationArtifact {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return false;
  }

  const artifact = input as Record<string, unknown>;
  return (
    artifact.version === SIGNED_AUTHORIZATION_ARTIFACT_VERSION &&
    typeof artifact.authorizationId === "string" &&
    artifact.authorizationId.trim().length > 0 &&
    artifact.authorizationId === artifact.authorizationId.trim() &&
    typeof artifact.keyId === "string" &&
    artifact.keyId.trim().length > 0 &&
    artifact.keyId === artifact.keyId.trim() &&
    typeof artifact.bindingDigest === "string" &&
    DIGEST_REGEX.test(artifact.bindingDigest) &&
    typeof artifact.signature === "string" &&
    SIGNATURE_REGEX.test(artifact.signature)
  );
}

export const SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3 = 3 as const;

export interface SignedAuthorizationArtifactV3 {
  readonly version: typeof SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3;
  readonly authorizationId: string;
  readonly keyId: string;
  readonly issuedAtSeconds: number;
  readonly expiresAtSeconds: number;
  readonly policyId: string;
  readonly policyRevision: number;
  readonly bindingDigest: string;
  readonly signature: string;
}

/**
 * Deterministic length-prefixed canonical encoding for signed authorization payloads v3.
 * Binds artifact version (3), authorization ID, key ID, issued-at Unix timestamp,
 * authorization expiry Unix timestamp, policy ID, policy revision, and binding digest.
 */
export function canonicalSignedPayloadV3(params: {
  version: number;
  authorizationId: string;
  keyId: string;
  issuedAtSeconds: number;
  expiresAtSeconds: number;
  policyId: string;
  policyRevision: number;
  bindingDigest: string;
}): string {
  if (
    params.version !== SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3 ||
    typeof params.authorizationId !== "string" ||
    params.authorizationId.trim().length === 0 ||
    params.authorizationId !== params.authorizationId.trim() ||
    typeof params.keyId !== "string" ||
    params.keyId.trim().length === 0 ||
    params.keyId !== params.keyId.trim() ||
    !Number.isSafeInteger(params.issuedAtSeconds) ||
    params.issuedAtSeconds < 0 ||
    !Number.isSafeInteger(params.expiresAtSeconds) ||
    params.expiresAtSeconds <= params.issuedAtSeconds ||
    typeof params.policyId !== "string" ||
    params.policyId.trim().length === 0 ||
    params.policyId !== params.policyId.trim() ||
    !Number.isSafeInteger(params.policyRevision) ||
    params.policyRevision < 1 ||
    typeof params.bindingDigest !== "string" ||
    !DIGEST_REGEX.test(params.bindingDigest)
  ) {
    throw new Error("Invalid parameters for canonicalSignedPayloadV3.");
  }

  return [
    "web3user-signed-authorization-v3\n",
    encodeField("artifact.version", String(params.version)),
    encodeField("artifact.authorizationId", params.authorizationId),
    encodeField("key.keyId", params.keyId),
    encodeField("artifact.issuedAtSeconds", String(params.issuedAtSeconds)),
    encodeField("artifact.expiresAtSeconds", String(params.expiresAtSeconds)),
    encodeField("policy.policyId", params.policyId),
    encodeField("policy.policyRevision", String(params.policyRevision)),
    encodeField("artifact.bindingDigest", params.bindingDigest),
  ].join("");
}

/**
 * Strictly validate a signed authorization artifact format v3.
 */
export function isSignedAuthorizationArtifactV3(
  input: unknown,
): input is SignedAuthorizationArtifactV3 {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return false;
  }

  const artifact = input as Record<string, unknown>;
  return (
    artifact.version === SIGNED_AUTHORIZATION_ARTIFACT_VERSION_V3 &&
    typeof artifact.authorizationId === "string" &&
    artifact.authorizationId.trim().length > 0 &&
    artifact.authorizationId === artifact.authorizationId.trim() &&
    typeof artifact.keyId === "string" &&
    artifact.keyId.trim().length > 0 &&
    artifact.keyId === artifact.keyId.trim() &&
    typeof artifact.issuedAtSeconds === "number" &&
    Number.isSafeInteger(artifact.issuedAtSeconds) &&
    artifact.issuedAtSeconds >= 0 &&
    typeof artifact.expiresAtSeconds === "number" &&
    Number.isSafeInteger(artifact.expiresAtSeconds) &&
    artifact.expiresAtSeconds > artifact.issuedAtSeconds &&
    typeof artifact.policyId === "string" &&
    artifact.policyId.trim().length > 0 &&
    artifact.policyId === artifact.policyId.trim() &&
    typeof artifact.policyRevision === "number" &&
    Number.isSafeInteger(artifact.policyRevision) &&
    artifact.policyRevision >= 1 &&
    typeof artifact.bindingDigest === "string" &&
    DIGEST_REGEX.test(artifact.bindingDigest) &&
    typeof artifact.signature === "string" &&
    SIGNATURE_REGEX.test(artifact.signature)
  );
}

/**
 * Utility to generate an ephemeral or permanent Ed25519 keypair with PEM representations.
 */
export function generateIssuerKeyPair(): {
  readonly publicKey: KeyObject;
  readonly privateKey: KeyObject;
  readonly publicKeyPem: string;
  readonly privateKeyPem: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey,
    privateKey,
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}
