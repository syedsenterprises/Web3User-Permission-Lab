/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: Ed25519 Signer & Outbox Dispatcher
 *
 * Implements canonical receipt preimage generation, Ed25519 signing, and generation-bound
 * signing intents. Strictly prohibits unverified test signer fallback in production environments.
 */

import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";

export interface ReceiptPreimageData {
  version: number;
  witness_id: string;
  epoch_id: string;
  sequence_number: string;
  ticket_id: string;
  authorization_id: string;
  binding_digest: string;
  policy_id: string;
  policy_revision: number;
  debited_amount: string;
  budget_windows: Array<{
    window_type: number;
    window_start_seconds: number;
    cumulative_spent_after: string;
  }>;
  committed_at_seconds: number;
}

export function formatCanonicalPreimage(data: ReceiptPreimageData): string {
  // Deterministic JSON stringification
  return JSON.stringify({
    version: data.version,
    witness_id: data.witness_id,
    epoch_id: data.epoch_id,
    sequence_number: data.sequence_number,
    ticket_id: data.ticket_id,
    authorization_id: data.authorization_id,
    binding_digest: data.binding_digest,
    policy_id: data.policy_id,
    policy_revision: data.policy_revision,
    debited_amount: data.debited_amount,
    budget_windows: data.budget_windows,
    committed_at_seconds: data.committed_at_seconds,
  });
}

export interface WitnessSigner {
  signReceipt(preimage: string, fencingGeneration: number): Promise<{ signatureHex: string; generation: number }>;
  getPublicKeyHex(): string;
  getWitnessId(): string;
}

/**
 * In-Memory Ed25519 Signer for local tests and developmental environments.
 */
export class LocalEd25519WitnessSigner implements WitnessSigner {
  private privateKey: KeyObject;
  private publicKey: KeyObject;
  private witnessId: string;

  constructor(
    witnessId = "witness-node-local-1",
    privateKey?: KeyObject,
    publicKey?: KeyObject,
    allowInProduction = false,
  ) {
    if (process.env.NODE_ENV === "production" && !allowInProduction) {
      throw new Error(
        "SECURITY_VIOLATION: LocalEd25519WitnessSigner (in-memory ephemeral key) is strictly forbidden in production mode. A hardware-backed CloudHSM/KMS signer is required.",
      );
    }
    this.witnessId = witnessId;
    if (privateKey && publicKey) {
      this.privateKey = privateKey;
      this.publicKey = publicKey;
    } else {
      const keys = generateKeyPairSync("ed25519");
      this.privateKey = keys.privateKey;
      this.publicKey = keys.publicKey;
    }
  }

  async signReceipt(
    preimage: string,
    fencingGeneration: number,
  ): Promise<{ signatureHex: string; generation: number }> {
    const signatureBuffer = sign(null, Buffer.from(preimage, "utf8"), this.privateKey);
    return {
      signatureHex: signatureBuffer.toString("hex").toLowerCase(),
      generation: fencingGeneration,
    };
  }

  getPublicKeyHex(): string {
    const exported = this.publicKey.export({ type: "spki", format: "der" });
    // In SPKI Ed25519, raw public key is the trailing 32 bytes
    return exported.subarray(exported.length - 32).toString("hex").toLowerCase();
  }

  getWitnessId(): string {
    return this.witnessId;
  }
}
