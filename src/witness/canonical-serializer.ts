/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.2
 * Type-Tagged Canonical Format (TTCF-v1 / Canon-v2) Serializer & Hash Engine
 *
 * Implements deterministic canonicalization and cryptographic payload hashing
 * conforming strictly to ADR-M13D-014 and the Stage 2-B.2 implementation plan.
 *
 * Architectural Invariants Enforced:
 * - INV-CAN-01: Disjoint type tagging across all 7 supported data types.
 * - Negative zero normalization (-0 -> n:0).
 * - IEEE 754 unsafe integer rejection (|n| > 2^53 - 1 -> TypeError).
 * - Unicode NFC normalization for all strings and object keys.
 * - Rejection of duplicate normalized object keys (DUPLICATE_CANONICAL_OBJECT_KEY).
 * - Strict UTF-16 code-unit lexicographical key sorting.
 * - Domain separation prefix: "TTCF-v1\n".
 * - Dual-version dispatch preserving backward compatibility with Canon-v1.
 */

import { createHash } from "node:crypto";

/**
 * Domain-separation prefix mandated by ADR-M13D-014 for TTCF-v1 payload digests.
 */
export const TTCF_V1_DOMAIN_PREFIX = "TTCF-v1\n";

/**
 * Computes a SHA-256 digest over the given UTF-8 string data.
 */
function sha256(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

// ============================================================================
// Version 2: Type-Tagged Canonical Format (TTCF-v1) Serializer
// ============================================================================

/**
 * Recursively serializes any supported JavaScript value into the Type-Tagged Canonical Format (TTCF-v1).
 *
 * Type tagging grammar:
 * - null:      "null"
 * - boolean:   "true" | "false"
 * - number:    "n:" + normalized finite number (negative zero normalized to "n:0")
 * - bigint:    "bi:" + decimal string
 * - string:    "\"" + JSON-escaped NFC-normalized string + "\""
 * - array:     "[" + items.join(",") + "]"
 * - object:    "{" + sorted_entries.join(",") + "}" where keys are NFC-normalized
 *
 * @throws {TypeError} on undefined, functions, symbols, NaN, Infinity, unsafe integers,
 *                     duplicate normalized keys, or circular structures.
 */
export function canonicalizeValueV2(val: unknown, seen = new WeakSet<object>()): string {
  if (val === null) {
    return "null";
  }

  if (val === undefined) {
    throw new TypeError("Cannot canonicalize undefined value in TTCF-v1");
  }

  const type = typeof val;

  if (type === "boolean") {
    return val ? "true" : "false";
  }

  if (type === "number") {
    const num = val as number;

    if (!Number.isFinite(num)) {
      throw new TypeError(`Cannot canonicalize non-finite number in TTCF-v1: ${String(num)}`);
    }

    // Negative zero normalization
    if (Object.is(num, -0) || num === 0) {
      return "n:0";
    }

    // IEEE 754 unsafe integer rejection
    if (Number.isInteger(num) && !Number.isSafeInteger(num)) {
      throw new TypeError("UNSAFE_INTEGER_USE_BIGINT: Integer value exceeds safe IEEE 754 bounds (|n| > 2^53 - 1)");
    }

    // Finite number formatted per standard ECMAScript / RFC 8785
    return `n:${JSON.stringify(num)}`;
  }

  if (type === "bigint") {
    return `bi:${(val as bigint).toString()}`;
  }

  if (type === "string") {
    const normalized = (val as string).normalize("NFC");
    return JSON.stringify(normalized);
  }

  if (Array.isArray(val)) {
    // Dense-array validation (rejects sparse arrays)
    for (let i = 0; i < val.length; i++) {
      if (!(i in val)) {
        throw new TypeError("Cannot canonicalize sparse array in TTCF-v1");
      }
    }

    if (seen.has(val)) {
      throw new TypeError("Cannot canonicalize circular data structure in TTCF-v1");
    }
    seen.add(val);

    const elements = val.map((item) => canonicalizeValueV2(item, seen));

    seen.delete(val);
    return `[${elements.join(",")}]`;
  }

  if (type === "object") {
    const obj = val as object;

    // Plain-object validation: accept only Object.prototype or null prototype
    const proto = Object.getPrototypeOf(obj);
    if (proto !== null && proto !== Object.prototype) {
      const tag = Object.prototype.toString.call(obj);
      const ctorName = obj.constructor?.name ?? "Unknown";
      throw new TypeError(
        `Cannot canonicalize non-plain object (${tag}, constructor: ${ctorName}) in TTCF-v1`
      );
    }

    if (seen.has(obj)) {
      throw new TypeError("Cannot canonicalize circular data structure in TTCF-v1");
    }
    seen.add(obj);

    const rawKeys = Object.keys(obj as Record<string, unknown>);
    const normalizedKeyMap = new Map<string, string>();

    // Detect duplicate keys after Unicode NFC normalization
    for (const rawKey of rawKeys) {
      const normKey = rawKey.normalize("NFC");
      if (normalizedKeyMap.has(normKey)) {
        throw new TypeError(
          `DUPLICATE_CANONICAL_OBJECT_KEY: Object keys '${normalizedKeyMap.get(normKey)}' and '${rawKey}' normalize to identical NFC key '${normKey}'`
        );
      }
      normalizedKeyMap.set(normKey, rawKey);
    }

    // Sort normalized keys strictly by UTF-16 code units
    const sortedNormKeys = Array.from(normalizedKeyMap.keys()).sort();

    const entries: string[] = [];
    for (const normKey of sortedNormKeys) {
      const originalKey = normalizedKeyMap.get(normKey)!;
      const v = (obj as Record<string, unknown>)[originalKey];

      if (v === undefined) {
        throw new TypeError(`Cannot canonicalize undefined property value for key '${normKey}' in TTCF-v1`);
      }

      entries.push(`${JSON.stringify(normKey)}:${canonicalizeValueV2(v, seen)}`);
    }

    seen.delete(obj);
    return `{${entries.join(",")}}`;
  }

  throw new TypeError(`Unsupported type for canonical serialization in TTCF-v1: ${type}`);
}

// ============================================================================
// Version 1: Legacy Canonical Serializer (Canon-v1)
// ============================================================================

/**
 * Legacy Canon-v1 recursive serializer preserved for historical replay and backward compatibility.
 * - BigInt serialized as JSON string.
 * - No type-tag prefixes.
 * - Standard Object.keys().sort() ordering.
 */
export function canonicalizeValueV1(val: unknown, seen = new WeakSet<object>()): string {
  if (val === null) {
    return "null";
  }
  if (val === undefined) {
    throw new TypeError("Cannot canonicalize undefined value");
  }
  const type = typeof val;
  if (type === "boolean") {
    return val ? "true" : "false";
  }
  if (type === "number") {
    if (!Number.isFinite(val)) {
      throw new TypeError(`Cannot canonicalize non-finite number: ${String(val)}`);
    }
    return JSON.stringify(val);
  }
  if (type === "bigint") {
    return JSON.stringify((val as bigint).toString());
  }
  if (type === "string") {
    return JSON.stringify(val);
  }
  if (Array.isArray(val)) {
    if (seen.has(val)) {
      throw new TypeError("Cannot canonicalize circular data structure");
    }
    seen.add(val);
    const elements = val.map((item) => canonicalizeValueV1(item, seen));
    seen.delete(val);
    return `[${elements.join(",")}]`;
  }
  if (type === "object") {
    const obj = val as object;
    if (seen.has(obj)) {
      throw new TypeError("Cannot canonicalize circular data structure");
    }
    seen.add(obj);
    const record = obj as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    const entries: string[] = [];
    for (const key of keys) {
      const v = record[key];
      if (v !== undefined) {
        entries.push(`${JSON.stringify(key)}:${canonicalizeValueV1(v, seen)}`);
      }
    }
    seen.delete(obj);
    return `{${entries.join(",")}}`;
  }
  throw new TypeError(`Unsupported type for canonical serialization: ${type}`);
}

// ============================================================================
// Cryptographic Hash Functions & Version Dispatch
// ============================================================================

/**
 * Computes the SHA-256 hash using legacy Canon-v1 serialization.
 */
export function computeCanonicalPayloadHashV1(payload: unknown): string {
  if (payload === undefined || payload === null) {
    return sha256("");
  }
  const canonical = canonicalizeValueV1(payload);
  return sha256(canonical);
}

/**
 * Computes the SHA-256 hash using Type-Tagged Canonical Format (TTCF-v1 / Canon-v2),
 * prefixing the byte stream with the exact domain separator "TTCF-v1\n".
 */
export function computeCanonicalPayloadHashV2(payload: unknown): string {
  if (payload === undefined) {
    return sha256(TTCF_V1_DOMAIN_PREFIX);
  }
  const canonical = canonicalizeValueV2(payload);
  return sha256(TTCF_V1_DOMAIN_PREFIX + canonical);
}

/**
 * Universal canonical payload hash dispatcher.
 * Routes to either legacy Canon-v1 (version = 1) or TTCF-v1 (version = 2).
 *
 * @param payload Command payload to serialize and hash
 * @param version Canonicalization version (default: 1 for backward compatibility)
 * @returns 64-character lowercase hexadecimal SHA-256 digest
 */
export function computeCanonicalPayloadHash(payload: unknown, version: 1 | 2 = 1): string {
  if (version === 1) {
    return computeCanonicalPayloadHashV1(payload);
  }
  if (version === 2) {
    return computeCanonicalPayloadHashV2(payload);
  }
  throw new Error(`Unsupported canonicalization version: ${String(version)}`);
}
