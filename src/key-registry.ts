import type { KeyObject } from "node:crypto";
import { parseEd25519PublicKey } from "./authorization-crypto.js";

export type KeyStatus = "active" | "retired" | "revoked";

export interface IssuerKeyMetadata {
  readonly keyId: string;
  readonly publicKey: KeyObject | string;
  readonly status: KeyStatus;
  readonly validFromSeconds?: number;
  readonly expiresAtSeconds?: number;
}

export interface KeyRegistry {
  getKey(keyId: string): IssuerKeyMetadata | null;
}

/**
 * In-memory implementation of KeyRegistry.
 *
 * KEY COMPROMISE & TIMING LIMITATION:
 * Without an authoritative, tamper-proof timestamp or global policy epoch,
 * the system cannot distinguish whether an artifact signed by a compromised key
 * was issued before or after the compromise occurred. Revoking a key immediately
 * fails closed and invalidates all future verifications of artifacts bearing that keyId,
 * preventing any forged consumption. However, if an attacker intercepted or created
 * artifacts prior to revocation, or if legitimate outstanding artifacts exist under
 * a revoked key, they can no longer be consumed.
 *
 * KEY STATUS SEMANTICS:
 * - 'active': Permitted for issuing new signed authorizations and verifying artifacts.
 * - 'retired': Disallowed for issuing new authorizations; permitted for verifying
 *              previously issued unexpired artifacts.
 * - 'revoked': Permanently rejected for all operations (issuance and verification).
 */
export class InMemoryKeyRegistry implements KeyRegistry {
  private readonly keys = new Map<string, IssuerKeyMetadata>();

  registerKey(metadata: IssuerKeyMetadata): void {
    if (typeof metadata !== "object" || metadata === null) {
      throw new Error("Key metadata must be a non-null object.");
    }
    if (typeof metadata.keyId !== "string" || metadata.keyId.trim().length === 0) {
      throw new Error("Key ID must be a non-empty string.");
    }
    if (metadata.keyId !== metadata.keyId.trim()) {
      throw new Error("Key ID must not contain leading or trailing whitespace.");
    }
    if (
      metadata.status !== "active" &&
      metadata.status !== "retired" &&
      metadata.status !== "revoked"
    ) {
      throw new Error(`Invalid key status: ${String(metadata.status)}`);
    }

    const parsedKey = parseEd25519PublicKey(metadata.publicKey);
    if (parsedKey === null) {
      throw new Error("Public key must be a valid Ed25519 public key.");
    }

    if (
      metadata.validFromSeconds !== undefined &&
      metadata.expiresAtSeconds !== undefined &&
      metadata.validFromSeconds > metadata.expiresAtSeconds
    ) {
      throw new Error("validFromSeconds cannot be greater than expiresAtSeconds.");
    }

    if (this.keys.has(metadata.keyId)) {
      throw new Error(`Key ID already registered: ${metadata.keyId}`);
    }

    // Defensive copy: create a decoupled, deeply immutable metadata record
    const record: IssuerKeyMetadata = Object.freeze({
      keyId: metadata.keyId,
      publicKey: parsedKey,
      status: metadata.status,
      ...(metadata.validFromSeconds !== undefined
        ? { validFromSeconds: metadata.validFromSeconds }
        : {}),
      ...(metadata.expiresAtSeconds !== undefined
        ? { expiresAtSeconds: metadata.expiresAtSeconds }
        : {}),
    });

    this.keys.set(metadata.keyId, record);
  }

  setKeyStatus(keyId: string, status: KeyStatus): boolean {
    const existing = this.keys.get(keyId);
    if (!existing) {
      return false;
    }
    if (
      status !== "active" &&
      status !== "retired" &&
      status !== "revoked"
    ) {
      throw new Error(`Invalid key status: ${String(status)}`);
    }

    // Create a new independent, deeply immutable record
    const updated: IssuerKeyMetadata = Object.freeze({
      keyId: existing.keyId,
      publicKey: existing.publicKey,
      status,
      ...(existing.validFromSeconds !== undefined
        ? { validFromSeconds: existing.validFromSeconds }
        : {}),
      ...(existing.expiresAtSeconds !== undefined
        ? { expiresAtSeconds: existing.expiresAtSeconds }
        : {}),
    });

    this.keys.set(keyId, updated);
    return true;
  }

  getKey(keyId: string): IssuerKeyMetadata | null {
    const record = this.keys.get(keyId);
    if (!record) return null;
    // Return a frozen defensive copy to prevent external mutation
    return Object.freeze({ ...record });
  }

  hasKey(keyId: string): boolean {
    return this.keys.has(keyId);
  }
}
