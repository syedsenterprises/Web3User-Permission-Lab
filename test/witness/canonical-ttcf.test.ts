/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.2
 * Unit & Golden Vector Test Suite for TTCF-v1 (Canon-v2) Canonical Serializer
 *
 * Exhaustively tests:
 * 1. Disjoint type tagging across all 7 supported data types (INV-CAN-01).
 * 2. Absolute collision-freedom between BigInt, Number, and String (e.g., bi:100 vs n:100 vs "100").
 * 3. IEEE 754 negative zero normalization (-0 -> n:0).
 * 4. IEEE 754 unsafe integer rejection (|n| > 2^53 - 1 -> TypeError).
 * 5. Unicode NFC normalization for strings and object keys.
 * 6. Duplicate key rejection when raw keys normalize to the same NFC representation.
 * 7. Lexicographical UTF-16 code-unit key sorting.
 * 8. Sequence preservation in arrays.
 * 9. Rejection of circular references and unsupported types (undefined, symbols, functions, NaN, Infinity).
 * 10. Pinned golden test vectors matching independent offline cryptographic verification.
 * 11. Legacy Canon-v1 backward compatibility and dual-version dispatcher routing.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import {
  TTCF_V1_DOMAIN_PREFIX,
  canonicalizeValueV1,
  canonicalizeValueV2,
  computeCanonicalPayloadHash,
  computeCanonicalPayloadHashV1,
  computeCanonicalPayloadHashV2,
} from "../../src/witness/canonical-serializer.js";

describe("Milestone 13-D Stage 2-B.2: Type-Tagged Canonical Format (TTCF-v1) Serializer", () => {
  // Helper for computing local reference SHA-256
  function localSha256(data: string): string {
    return createHash("sha256").update(data, "utf8").digest("hex");
  }

  // ==========================================================================
  // 1. Primitive Types & Disjoint Type Tagging (INV-CAN-01)
  // ==========================================================================
  describe("Primitive Types & Disjoint Tagging (INV-CAN-01)", () => {
    it("serializes null to 'null'", () => {
      expect(canonicalizeValueV2(null)).toBe("null");
    });

    it("serializes booleans to 'true' and 'false'", () => {
      expect(canonicalizeValueV2(true)).toBe("true");
      expect(canonicalizeValueV2(false)).toBe("false");
    });

    it("serializes numbers with 'n:' prefix", () => {
      expect(canonicalizeValueV2(0)).toBe("n:0");
      expect(canonicalizeValueV2(42)).toBe("n:42");
      expect(canonicalizeValueV2(-42)).toBe("n:-42");
      expect(canonicalizeValueV2(3.14159)).toBe("n:3.14159");
    });

    it("serializes bigints with 'bi:' prefix and decimal string", () => {
      expect(canonicalizeValueV2(0n)).toBe("bi:0");
      expect(canonicalizeValueV2(100n)).toBe("bi:100");
      expect(canonicalizeValueV2(-100n)).toBe("bi:-100");
      expect(canonicalizeValueV2(123456789012345678901234567890n)).toBe(
        "bi:123456789012345678901234567890"
      );
    });

    it("serializes strings with JSON quotation", () => {
      expect(canonicalizeValueV2("")).toBe('""');
      expect(canonicalizeValueV2("hello")).toBe('"hello"');
      expect(canonicalizeValueV2("hello\nworld")).toBe('"hello\\nworld"');
      expect(canonicalizeValueV2('"quoted"')).toBe('"\\"quoted\\""');
    });

    it("proves mutual disjointness between BigInt, Number, and String representations", () => {
      const canonBigInt = canonicalizeValueV2(100n);
      const canonNumber = canonicalizeValueV2(100);
      const canonString = canonicalizeValueV2("100");

      expect(canonBigInt).toBe("bi:100");
      expect(canonNumber).toBe("n:100");
      expect(canonString).toBe('"100"');

      // Canonical texts must all differ
      expect(canonBigInt).not.toBe(canonNumber);
      expect(canonBigInt).not.toBe(canonString);
      expect(canonNumber).not.toBe(canonString);

      // Byte 0 / Byte 1 leading byte differentiation
      expect(canonBigInt.startsWith("bi:")).toBe(true);
      expect(canonNumber.startsWith("n:")).toBe(true);
      expect(canonString.startsWith('"')).toBe(true);

      // Resulting hashes must all be mutually distinct
      const hashBigInt = computeCanonicalPayloadHashV2(100n);
      const hashNumber = computeCanonicalPayloadHashV2(100);
      const hashString = computeCanonicalPayloadHashV2("100");

      expect(hashBigInt).not.toBe(hashNumber);
      expect(hashBigInt).not.toBe(hashString);
      expect(hashNumber).not.toBe(hashString);
    });

    it("verifies leading byte disjointness across all 7 TTCF-v1 types", () => {
      const samples: [string, unknown][] = [
        ["null", null],
        ["boolean", true],
        ["number", 1],
        ["bigint", 1n],
        ["string", "1"],
        ["array", [1]],
        ["object", { a: 1 }],
      ];

      const serialized = samples.map(([type, val]) => ({
        type,
        text: canonicalizeValueV2(val),
      }));

      // Verify each serialized text starts with its unique type signature
      for (const item of serialized) {
        if (item.type === "null") expect(item.text).toBe("null");
        if (item.type === "boolean") expect(item.text).toBe("true");
        if (item.type === "number") expect(item.text.startsWith("n:")).toBe(true);
        if (item.type === "bigint") expect(item.text.startsWith("bi:")).toBe(true);
        if (item.type === "string") expect(item.text.startsWith('"')).toBe(true);
        if (item.type === "array") expect(item.text.startsWith("[")).toBe(true);
        if (item.type === "object") expect(item.text.startsWith("{")).toBe(true);
      }
    });
  });

  // ==========================================================================
  // 2. Number Normalization & Bounds Verification
  // ==========================================================================
  describe("Number Normalization & Bounds", () => {
    it("normalizes IEEE 754 negative zero (-0) to 'n:0'", () => {
      const posZero = 0;
      const negZero = -0;

      expect(Object.is(posZero, negZero)).toBe(false); // In JS, 0 !== -0 under Object.is

      const canonPos = canonicalizeValueV2(posZero);
      const canonNeg = canonicalizeValueV2(negZero);

      expect(canonPos).toBe("n:0");
      expect(canonNeg).toBe("n:0");
      expect(canonPos).toBe(canonNeg);

      expect(computeCanonicalPayloadHashV2(posZero)).toBe(computeCanonicalPayloadHashV2(negZero));
    });

    it("supports boundary safe integers up to Number.MAX_SAFE_INTEGER and MIN_SAFE_INTEGER", () => {
      expect(canonicalizeValueV2(Number.MAX_SAFE_INTEGER)).toBe("n:9007199254740991");
      expect(canonicalizeValueV2(Number.MIN_SAFE_INTEGER)).toBe("n:-9007199254740991");
    });

    it("rejects integers exceeding IEEE 754 safe integer limits (|n| > 2^53 - 1)", () => {
      const unsafePositive = 9007199254740992; // 2^53
      const unsafeNegative = -9007199254740992; // -2^53

      expect(() => canonicalizeValueV2(unsafePositive)).toThrowError(
        /UNSAFE_INTEGER_USE_BIGINT/
      );
      expect(() => canonicalizeValueV2(unsafeNegative)).toThrowError(
        /UNSAFE_INTEGER_USE_BIGINT/
      );
      expect(() => canonicalizeValueV2(9007199254740993)).toThrowError(
        /UNSAFE_INTEGER_USE_BIGINT/
      );
    });

    it("rejects non-finite numbers (NaN, Infinity, -Infinity)", () => {
      expect(() => canonicalizeValueV2(NaN)).toThrow(TypeError);
      expect(() => canonicalizeValueV2(Infinity)).toThrow(TypeError);
      expect(() => canonicalizeValueV2(-Infinity)).toThrow(TypeError);
    });
  });

  // ==========================================================================
  // 3. Unicode Normalization & Key Integrity
  // ==========================================================================
  describe("Unicode Normalization & Key Integrity", () => {
    it("normalizes decomposed Unicode strings to Canonical Composition (NFC)", () => {
      // Decomposed "e" + combining acute accent: "e\u0301"
      const decomposed = "e\u0301";
      // Precomposed "é": "\u00e9"
      const precomposed = "\u00e9";

      expect(decomposed).not.toBe(precomposed);
      expect(decomposed.length).toBe(2);
      expect(precomposed.length).toBe(1);

      const canonDecomposed = canonicalizeValueV2(decomposed);
      const canonPrecomposed = canonicalizeValueV2(precomposed);

      expect(canonDecomposed).toBe(canonPrecomposed);
      expect(canonDecomposed).toBe(JSON.stringify(precomposed));
      expect(computeCanonicalPayloadHashV2(decomposed)).toBe(
        computeCanonicalPayloadHashV2(precomposed)
      );
    });

    it("normalizes object keys to NFC before serialization", () => {
      const objDecomposed = { "e\u0301": "value" };
      const objPrecomposed = { "\u00e9": "value" };

      const canonDecomposed = canonicalizeValueV2(objDecomposed);
      const canonPrecomposed = canonicalizeValueV2(objPrecomposed);

      expect(canonDecomposed).toBe(canonPrecomposed);
      expect(canonDecomposed).toBe('{"\u00e9":"value"}');
    });

    it("rejects objects with duplicate keys after NFC normalization (INV-CAN-01)", () => {
      // Object literal with two keys that normalize to the same NFC string "\u00e9"
      const objWithDuplicateKeys = {
        "e\u0301": 1,
        "\u00e9": 2,
      };

      expect(() => canonicalizeValueV2(objWithDuplicateKeys)).toThrowError(
        /DUPLICATE_CANONICAL_OBJECT_KEY/
      );
    });

    it("sorts object keys strictly by UTF-16 code units", () => {
      const unsorted = {
        z: 10,
        a: 20,
        m: 30,
        B: 40,
        _underscore: 50,
      };

      const serialized = canonicalizeValueV2(unsorted);
      // UTF-16 order: "_" (95), "B" (66), "a" (97), "m" (109), "z" (122)
      // Wait: in ASCII/UTF-16: 'B' = 66, '_' = 95, 'a' = 97, 'm' = 109, 'z' = 122
      expect(serialized).toBe(
        '{"B":n:40,"_underscore":n:50,"a":n:20,"m":n:30,"z":n:10}'
      );
    });

    it("produces identical serialization regardless of object property insertion order", () => {
      const obj1 = { alpha: 1, beta: 2, gamma: 3 };
      const obj2 = { gamma: 3, alpha: 1, beta: 2 };
      const obj3 = { beta: 2, gamma: 3, alpha: 1 };

      const s1 = canonicalizeValueV2(obj1);
      const s2 = canonicalizeValueV2(obj2);
      const s3 = canonicalizeValueV2(obj3);

      expect(s1).toBe(s2);
      expect(s2).toBe(s3);
      expect(computeCanonicalPayloadHashV2(obj1)).toBe(computeCanonicalPayloadHashV2(obj2));
      expect(computeCanonicalPayloadHashV2(obj2)).toBe(computeCanonicalPayloadHashV2(obj3));
    });
  });

  // ==========================================================================
  // 4. Arrays, Composites & Recursion Guard
  // ==========================================================================
  describe("Arrays, Composites & Recursion Guard", () => {
    it("serializes empty array to '[]' and empty object to '{}'", () => {
      expect(canonicalizeValueV2([])).toBe("[]");
      expect(canonicalizeValueV2({})).toBe("{}");
    });

    it("preserves array element ordering strictly", () => {
      const arr1 = [1, 2, 3];
      const arr2 = [3, 2, 1];

      expect(canonicalizeValueV2(arr1)).toBe("[n:1,n:2,n:3]");
      expect(canonicalizeValueV2(arr2)).toBe("[n:3,n:2,n:1]");
      expect(computeCanonicalPayloadHashV2(arr1)).not.toBe(computeCanonicalPayloadHashV2(arr2));
    });

    it("serializes heterogeneous arrays correctly", () => {
      const mixed = [1n, 2, "3", true, null];
      expect(canonicalizeValueV2(mixed)).toBe('[bi:1,n:2,"3",true,null]');
    });

    it("serializes deeply nested data structures deterministically", () => {
      const complex = {
        meta: {
          timestamp: 1700000000,
          verified: true,
        },
        records: [
          { id: 101n, tags: ["crypto", "witness"] },
          { id: 102n, tags: ["consensus"] },
        ],
      };

      const expected =
        '{"meta":{"timestamp":n:1700000000,"verified":true},"records":[{"id":bi:101,"tags":["crypto","witness"]},{"id":bi:102,"tags":["consensus"]}]}';

      expect(canonicalizeValueV2(complex)).toBe(expected);
    });

    it("rejects circular references in objects", () => {
      const circularObj: any = { a: 1 };
      circularObj.self = circularObj;

      expect(() => canonicalizeValueV2(circularObj)).toThrow(TypeError);
    });

    it("rejects circular references in arrays", () => {
      const circularArr: any = [1, 2];
      circularArr.push(circularArr);

      expect(() => canonicalizeValueV2(circularArr)).toThrow(TypeError);
    });

    it("rejects undefined values in objects or top-level", () => {
      expect(() => canonicalizeValueV2(undefined)).toThrow(TypeError);
      expect(() => canonicalizeValueV2({ invalid: undefined })).toThrow(TypeError);
    });

    it("rejects unsupported types (functions, symbols)", () => {
      expect(() => canonicalizeValueV2(() => {})).toThrow(TypeError);
      expect(() => canonicalizeValueV2(Symbol("test"))).toThrow(TypeError);
      expect(() => canonicalizeValueV2({ fn: () => {} })).toThrow(TypeError);
    });

    // ------------------------------------------------------------------------
    // Step 1.1 Input-Hardening: Dense Array & Plain Object Enforcement
    // ------------------------------------------------------------------------
    it("rejects sparse arrays with missing slots (F-STEP1-01)", () => {
      const sparseTrailing: number[] = [];
      sparseTrailing[2] = 1;
      expect(() => canonicalizeValueV2(sparseTrailing)).toThrowError(
        /Cannot canonicalize sparse array in TTCF-v1/
      );

      const sparseConstructed = new Array(3);
      expect(() => canonicalizeValueV2(sparseConstructed)).toThrowError(
        /Cannot canonicalize sparse array in TTCF-v1/
      );

      const sparseHole = [1, , 3]; // eslint-disable-line no-sparse-arrays
      expect(() => canonicalizeValueV2(sparseHole)).toThrowError(
        /Cannot canonicalize sparse array in TTCF-v1/
      );
    });

    it("accepts dense arrays containing valid elements", () => {
      expect(canonicalizeValueV2([0, 1, 2])).toBe("[n:0,n:1,n:2]");
      expect(canonicalizeValueV2([null, false, ""])).toBe('[null,false,""]');
      expect(canonicalizeValueV2([])).toBe("[]");
    });

    it("rejects Date instances (F-STEP1-02)", () => {
      const date = new Date("2026-01-01T00:00:00.000Z");
      expect(() => canonicalizeValueV2(date)).toThrowError(
        /Cannot canonicalize non-plain object.*Date/
      );
    });

    it("rejects Map instances (F-STEP1-02)", () => {
      const map = new Map([["key", "value"]]);
      expect(() => canonicalizeValueV2(map)).toThrowError(
        /Cannot canonicalize non-plain object.*Map/
      );
    });

    it("rejects Set instances (F-STEP1-02)", () => {
      const set = new Set([1, 2, 3]);
      expect(() => canonicalizeValueV2(set)).toThrowError(
        /Cannot canonicalize non-plain object.*Set/
      );
    });

    it("rejects Buffer instances (F-STEP1-02)", () => {
      const buf = Buffer.from("hello world");
      expect(() => canonicalizeValueV2(buf)).toThrowError(
        /Cannot canonicalize non-plain object/
      );
    });

    it("rejects Uint8Array and other TypedArray instances (F-STEP1-02)", () => {
      const u8 = new Uint8Array([1, 2, 3]);
      const i32 = new Int32Array([100, 200]);
      const f64 = new Float64Array([1.5, 2.5]);

      expect(() => canonicalizeValueV2(u8)).toThrowError(/Cannot canonicalize non-plain object/);
      expect(() => canonicalizeValueV2(i32)).toThrowError(/Cannot canonicalize non-plain object/);
      expect(() => canonicalizeValueV2(f64)).toThrowError(/Cannot canonicalize non-plain object/);
    });

    it("accepts null-prototype objects created via Object.create(null)", () => {
      const nullProto = Object.create(null);
      nullProto.b = 20;
      nullProto.a = 10;
      expect(canonicalizeValueV2(nullProto)).toBe('{"a":n:10,"b":n:20}');
    });

    it("accepts ordinary plain objects created via literal or Object constructor", () => {
      const literal = { x: 1, y: 2 };
      const constructed = new Object({ x: 1, y: 2 });
      expect(canonicalizeValueV2(literal)).toBe('{"x":n:1,"y":n:2}');
      expect(canonicalizeValueV2(constructed)).toBe('{"x":n:1,"y":n:2}');
    });

    it("rejects custom class instances", () => {
      class CustomCommand {
        id = 1;
      }
      expect(() => canonicalizeValueV2(new CustomCommand())).toThrowError(
        /Cannot canonicalize non-plain object/
      );
    });

    it("rejects nested unsupported objects and sparse arrays within deep structures", () => {
      const nestedDate = { payload: { nested: { created: new Date() } } };
      expect(() => canonicalizeValueV2(nestedDate)).toThrowError(
        /Cannot canonicalize non-plain object/
      );

      const nestedBuffer = { data: [1, 2, Buffer.from("test")] };
      expect(() => canonicalizeValueV2(nestedBuffer)).toThrowError(
        /Cannot canonicalize non-plain object/
      );

      const nestedSparse = { records: [(() => { const a = []; a[2] = 1; return a; })()] };
      expect(() => canonicalizeValueV2(nestedSparse)).toThrowError(
        /Cannot canonicalize sparse array in TTCF-v1/
      );

      const nestedMap = [{ items: [new Map()] }];
      expect(() => canonicalizeValueV2(nestedMap)).toThrowError(
        /Cannot canonicalize non-plain object/
      );
    });
  });

  // ==========================================================================
  // 5. Pinned Golden Test Vectors (Cryptographic Verification)
  // ==========================================================================
  describe("Pinned Golden Test Vectors", () => {
    it("matches domain separator 'TTCF-v1\\n'", () => {
      expect(TTCF_V1_DOMAIN_PREFIX).toBe("TTCF-v1\n");
    });

    it("hashes undefined payload to sha256(TTCF_V1_DOMAIN_PREFIX)", () => {
      const expected = localSha256("TTCF-v1\n");
      expect(expected).toBe("faa7eba606f4b43cef9393e024d63e2298d52266dd35a9ea9ee8ce547b8336d8");
      expect(computeCanonicalPayloadHashV2(undefined)).toBe(expected);
    });

    it("hashes golden vector: null -> 'null'", () => {
      const expected = localSha256("TTCF-v1\nnull");
      expect(expected).toBe("cfc9df596d77851a50462a9044001b7e976e556fa2257217d02f674c97e4d8d3");
      expect(computeCanonicalPayloadHashV2(null)).toBe(expected);
    });

    it("hashes golden vector: true -> 'true'", () => {
      const expected = localSha256("TTCF-v1\ntrue");
      expect(expected).toBe("e43791ed71ffb4c19a55d4be5f370649507742e692b1cadd83ee97c41fbd278e");
      expect(computeCanonicalPayloadHashV2(true)).toBe(expected);
    });

    it("hashes golden vector: false -> 'false'", () => {
      const expected = localSha256("TTCF-v1\nfalse");
      expect(expected).toBe("3b249ad2108f966414721611e28ac35869d351d6151dd46ed4e5c44ba7f39598");
      expect(computeCanonicalPayloadHashV2(false)).toBe(expected);
    });

    it("hashes golden vector: 0 and -0 -> 'n:0'", () => {
      const expected = localSha256("TTCF-v1\nn:0");
      expect(expected).toBe("1e9323ac1290e6c3603a144c7698f2d32d4cd5db25aad2e8a31efaed4b5bb7ac");
      expect(computeCanonicalPayloadHashV2(0)).toBe(expected);
      expect(computeCanonicalPayloadHashV2(-0)).toBe(expected);
    });

    it("hashes golden vector: 100 (number) -> 'n:100'", () => {
      const expected = localSha256("TTCF-v1\nn:100");
      expect(expected).toBe("26a5ea427777225b8c33be68fa6035f7963c67cf318af83dbcb066f19cced875");
      expect(computeCanonicalPayloadHashV2(100)).toBe(expected);
    });

    it("hashes golden vector: 100n (bigint) -> 'bi:100'", () => {
      const expected = localSha256("TTCF-v1\nbi:100");
      expect(expected).toBe("4738820d469c0d2e1a54a846820354dc30ed23952746d1610509f1e4cad90670");
      expect(computeCanonicalPayloadHashV2(100n)).toBe(expected);
    });

    it("hashes golden vector: \"100\" (string) -> '\"100\"'", () => {
      const expected = localSha256('TTCF-v1\n"100"');
      expect(expected).toBe("856f8872f67e3134908a8a4da7dc3d873b55b0190b7e1367a094aa1498e7ca97");
      expect(computeCanonicalPayloadHashV2("100")).toBe(expected);
    });

    it("hashes golden vector: \"\" (empty string) -> '\"\"'", () => {
      const expected = localSha256('TTCF-v1\n""');
      expect(expected).toBe("75b7f8b131413daf39a1c4dab13e4871e4c48b2c45d77ed68379f278b1a4d962");
      expect(computeCanonicalPayloadHashV2("")).toBe(expected);
    });

    it("hashes golden vector: [] -> '[]'", () => {
      const expected = localSha256("TTCF-v1\n[]");
      expect(expected).toBe("a74364a305632dd3612db6eb952c31c08dfe180c25672a1c29aae15da21355c6");
      expect(computeCanonicalPayloadHashV2([])).toBe(expected);
    });

    it("hashes golden vector: {} -> '{}'", () => {
      const expected = localSha256("TTCF-v1\n{}");
      expect(expected).toBe("d532599a65df757a7f5c776e3842a8a52c9161cd3168b10080a34044f9102b15");
      expect(computeCanonicalPayloadHashV2({})).toBe(expected);
    });

    it("hashes golden vector: [1n, 2, \"3\", true, null] -> '[bi:1,n:2,\"3\",true,null]'", () => {
      const expected = localSha256('TTCF-v1\n[bi:1,n:2,"3",true,null]');
      expect(expected).toBe("407049cda86b8a02c732f6c72f50580ce0b7a5d95c6b1385f766a3abd404d1f4");
      expect(computeCanonicalPayloadHashV2([1n, 2, "3", true, null])).toBe(expected);
    });

    it("hashes golden vector: {\"b\": 2n, \"a\": 1} -> '{\"a\":n:1,\"b\":bi:2}'", () => {
      const expected = localSha256('TTCF-v1\n{"a":n:1,"b":bi:2}');
      expect(expected).toBe("68ba48142b85a239fd8b972c7fb8934e8b035f6f1f6476ce032da1dc4257cf27");
      expect(computeCanonicalPayloadHashV2({ b: 2n, a: 1 })).toBe(expected);
    });
  });

  // ==========================================================================
  // 6. Legacy Canon-v1 Backward Compatibility & Cross-Version Dispatcher
  // ==========================================================================
  describe("Legacy Canon-v1 & Version Dispatcher", () => {
    it("demonstrates legacy Canon-v1 stringification behavior for BigInt", () => {
      // In Canon-v1, BigInt was stringified as JSON string
      expect(canonicalizeValueV1(100n)).toBe('"100"');
      expect(canonicalizeValueV1("100")).toBe('"100"');

      // V1 had a collision between BigInt and String!
      const v1BigIntHash = computeCanonicalPayloadHashV1(100n);
      const v1StringHash = computeCanonicalPayloadHashV1("100");
      expect(v1BigIntHash).toBe(v1StringHash);

      // In V2 (TTCF-v1), this collision is permanently resolved!
      const v2BigIntHash = computeCanonicalPayloadHashV2(100n);
      const v2StringHash = computeCanonicalPayloadHashV2("100");
      expect(v2BigIntHash).not.toBe(v2StringHash);
    });

    it("routes through universal computeCanonicalPayloadHash dispatcher", () => {
      const payload = { amount: 1000n, label: "transfer" };

      // Default version parameter is 1 (legacy compatibility)
      const defaultHash = computeCanonicalPayloadHash(payload);
      const v1Hash = computeCanonicalPayloadHash(payload, 1);
      const v2Hash = computeCanonicalPayloadHash(payload, 2);

      expect(defaultHash).toBe(v1Hash);
      expect(v1Hash).toBe(computeCanonicalPayloadHashV1(payload));
      expect(v2Hash).toBe(computeCanonicalPayloadHashV2(payload));
      expect(v1Hash).not.toBe(v2Hash);
    });

    it("rejects unsupported canonicalization version numbers", () => {
      expect(() => computeCanonicalPayloadHash({ test: true }, 0 as any)).toThrow(
        /Unsupported canonicalization version: 0/
      );
      expect(() => computeCanonicalPayloadHash({ test: true }, 3 as any)).toThrow(
        /Unsupported canonicalization version: 3/
      );
    });
  });
});
