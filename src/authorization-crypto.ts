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
