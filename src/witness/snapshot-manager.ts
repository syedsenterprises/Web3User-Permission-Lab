/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.2 (Step 5)
 * SnapshotManager: Multi-Backend Durable Snapshots, Leases, Verification & Safe Cleanup
 *
 * Implements ADR-M13D-012 and Stage 2-B.2 WP3:
 * - Lifecycle state machine: STAGED -> COMMITTED -> DELETING (enforced by Migration 004 trigger).
 * - Multi-backend storage protocols:
 *   - POSIX FS: temp write -> fsync file -> atomic rename -> fsync parent dir -> SHA-256 readback.
 *   - Amazon S3: conditional PUT (If-None-Match: *) + ChecksumSHA256 + ContentMD5.
 *   - Google Cloud Storage: generation-match precondition (0) + CRC32C verification.
 * - Active publication leases in `witness_snapshot_leases` with renewal and expiry fencing.
 * - Integration with `PostgresConsensusStore` via `ConsensusSnapshotLoader`.
 * - Race-safe, crash-resilient orphan and retention cleanup.
 */

import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import pg from "pg";
import {
  type ApplicationState,
  type AppliedIndexRecord,
  type CommittedTicketRecord,
  type EpochLifecycleState,
  type PolicyRecord,
} from "./state-machine-types.js";
import {
  ReadonlyFrozenMap,
  ReadonlyFrozenSet,
  computeCanonicalPayloadHash,
} from "./state-machine.js";
import {
  type ConsensusSnapshotLoader,
  type PersistedSnapshotRecord,
} from "./consensus-store.js";
import { calculateCrc32c } from "./cloud-kms-signer.js";

// ============================================================================
// Constants & Errors
// ============================================================================

export const SNAPSHOT_FORMAT_VERSION = 1 as const;
export const DEFAULT_LEASE_TTL_SECONDS = 600; // 10 minutes
export const DEFAULT_CLEANUP_GRACE_PERIOD_SECONDS = 3600; // 1 hour

export type SnapshotStorageBackendType = "posix_fs" | "s3" | "gcs";
export type SnapshotLifecycleStatus = "STAGED" | "COMMITTED" | "DELETING";

export class SnapshotError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly originalError?: unknown
  ) {
    super(message);
    this.name = "SnapshotError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class SnapshotCreationError extends SnapshotError {
  constructor(message: string, code = "SNAPSHOT_CREATION_FAILED", originalError?: unknown) {
    super(message, code, originalError);
    this.name = "SnapshotCreationError";
  }
}

export class SnapshotIntegrityError extends SnapshotError {
  constructor(message: string, code = "SNAPSHOT_INTEGRITY_FAILED", originalError?: unknown) {
    super(message, code, originalError);
    this.name = "SnapshotIntegrityError";
  }
}

export class SnapshotCollisionError extends SnapshotError {
  constructor(message: string, originalError?: unknown) {
    super(message, "SNAPSHOT_COLLISION", originalError);
    this.name = "SnapshotCollisionError";
  }
}

export class SnapshotLeaseError extends SnapshotError {
  constructor(message: string, code = "SNAPSHOT_LEASE_ERROR", originalError?: unknown) {
    super(message, code, originalError);
    this.name = "SnapshotLeaseError";
  }
}

// ============================================================================
// Path & Identifier Sanitization
// ============================================================================

const SAFE_SEGMENT_RE = /^[A-Za-z0-9._-]+$/;

function assertSafeIdentifier(value: string, label: string): string {
  if (
    !value ||
    value.trim().length === 0 ||
    value === "." ||
    value === ".." ||
    value.includes("..") ||
    value.includes("/") ||
    value.includes("\\") ||
    value.includes("\0") ||
    !SAFE_SEGMENT_RE.test(value)
  ) {
    throw new SnapshotError(`Unsafe or invalid ${label}: '${String(value)}'`, "INVALID_IDENTIFIER");
  }
  return value;
}

function buildSafeSnapshotId(epochId: string, snapshotIndex: bigint): string {
  const cleanEpoch = epochId.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 24);
  const idxStr = snapshotIndex.toString();
  const suffix = randomUUID().replace(/-/g, "").slice(0, 12);
  const raw = `snap_${cleanEpoch}_${idxStr}_${suffix}`;
  return raw.slice(0, 64);
}

// ============================================================================
// Snapshot Serialization & Verification (Format v1)
// ============================================================================

export interface SerializedSnapshotManifest {
  readonly formatVersion: 1;
  readonly canonicalizationVersion: 1 | 2;
  readonly clusterId: string;
  readonly epochId: string;
  readonly epochHeight: number;
  readonly epochState: EpochLifecycleState;
  readonly lastAppliedAppIndex: string;
  readonly lastAppliedRaftTerm: string;
  readonly lastPhysicalCursor: {
    readonly etcdRevision: string;
    readonly subIndex: number;
  };
  readonly chainHeadHash: string;
  readonly lastSequenceNumber: string;
  readonly retentionFloorIndex: string;
  readonly lastConsecutivePersistedAppIndex: string;
  readonly committedTickets: ReadonlyArray<
    readonly [
      string,
      {
        readonly ticketId: string;
        readonly epochId: string;
        readonly authorizationId: string;
        readonly bindingDigest: string;
        readonly policyId: string;
        readonly policyRevision: number;
        readonly sequenceNumber: string;
        readonly debitedAmount: string;
        readonly committedAtSeconds: number;
      },
    ]
  >;
  readonly revokedAuthorizations: ReadonlyArray<string>;
  readonly policies: ReadonlyArray<readonly [string, PolicyRecord]>;
  readonly appliedProposals: ReadonlyArray<readonly [string, string]>;
  readonly appliedIndices: ReadonlyArray<readonly [string, AppliedIndexRecord]>;
}

export interface SerializedSnapshotEnvelope {
  readonly manifest: SerializedSnapshotManifest;
  readonly integrityHash: string;
}

function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

function parseBigIntString(val: unknown, label: string): bigint {
  if (typeof val !== "string" || !/^-?\d+$/.test(val)) {
    throw new SnapshotIntegrityError(`Invalid bigint string for '${label}': ${String(val)}`);
  }
  return BigInt(val);
}

/**
 * Deterministically serializes an `ApplicationState` into a UTF-8 JSON envelope
 * with an embedded canonical `integrityHash` (Canon-v1 or TTCF-v1) and outer SHA-256.
 */
export function serializeApplicationStateSnapshot(
  state: ApplicationState,
  canonicalizationVersion: 1 | 2 = 2
): { bytes: Buffer; snapshotHash: string; byteSize: number; integrityHash: string } {
  if (canonicalizationVersion !== 1 && canonicalizationVersion !== 2) {
    throw new SnapshotCreationError(
      `Unsupported canonicalization version: ${String(canonicalizationVersion)}`,
      "UNSUPPORTED_CANONICALIZATION_VERSION"
    );
  }

  const committedTickets = Array.from(state.committedTickets.entries())
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(
      ([id, rec]) =>
        [
          id,
          {
            ticketId: rec.ticketId,
            epochId: rec.epochId,
            authorizationId: rec.authorizationId,
            bindingDigest: rec.bindingDigest,
            policyId: rec.policyId,
            policyRevision: rec.policyRevision,
            sequenceNumber: rec.sequenceNumber.toString(),
            debitedAmount: rec.debitedAmount.toString(),
            committedAtSeconds: rec.committedAtSeconds,
          },
        ] as const
    );

  const revokedAuthorizations = Array.from(state.revokedAuthorizations).sort((a, b) =>
    a < b ? -1 : a > b ? 1 : 0
  );

  const policies = Array.from(state.policies.entries())
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([id, rec]) => {
      const cleanPolicy: PolicyRecord = {
        policyId: rec.policyId,
        revision: rec.revision,
        policyHash: rec.policyHash,
        ...(rec.definitionJson !== undefined ? { definitionJson: rec.definitionJson } : {}),
      };
      return [id, cleanPolicy] as const;
    });

  const appliedProposals = Array.from(state.appliedProposals.entries())
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([propId, idx]) => [propId, idx.toString()] as const);

  const appliedIndices = Array.from(state.appliedIndices.entries())
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([idx, rec]) => [idx.toString(), { ...rec }] as const);

  const manifest: SerializedSnapshotManifest = {
    formatVersion: SNAPSHOT_FORMAT_VERSION,
    canonicalizationVersion,
    clusterId: state.clusterId,
    epochId: state.epochId,
    epochHeight: state.epochHeight,
    epochState: state.epochState,
    lastAppliedAppIndex: state.lastAppliedAppIndex.toString(),
    lastAppliedRaftTerm: state.lastAppliedRaftTerm.toString(),
    lastPhysicalCursor: {
      etcdRevision: state.lastPhysicalCursor.etcdRevision.toString(),
      subIndex: state.lastPhysicalCursor.subIndex,
    },
    chainHeadHash: state.chainHeadHash,
    lastSequenceNumber: state.lastSequenceNumber.toString(),
    retentionFloorIndex: state.retentionFloorIndex.toString(),
    lastConsecutivePersistedAppIndex: state.lastConsecutivePersistedAppIndex.toString(),
    committedTickets,
    revokedAuthorizations,
    policies,
    appliedProposals,
    appliedIndices,
  };

  const integrityHash = computeCanonicalPayloadHash(manifest, canonicalizationVersion);
  const envelope: SerializedSnapshotEnvelope = { manifest, integrityHash };
  const bytes = Buffer.from(JSON.stringify(envelope), "utf8");
  const snapshotHash = sha256Hex(bytes);

  return {
    bytes,
    snapshotHash,
    byteSize: bytes.byteLength,
    integrityHash,
  };
}

/**
 * Verifies raw snapshot bytes against a trusted PostgreSQL `PersistedSnapshotRecord`
 * and internal canonical `integrityHash`, then rehydrates a deeply frozen `ApplicationState`.
 */
export function verifyAndDeserializeSnapshot(
  bytes: Buffer,
  expected: PersistedSnapshotRecord
): ApplicationState {
  if (!Buffer.isBuffer(bytes) || bytes.byteLength === 0) {
    throw new SnapshotIntegrityError("Snapshot payload is empty or invalid");
  }

  if (BigInt(bytes.byteLength) !== expected.byteSize) {
    throw new SnapshotIntegrityError(
      `Snapshot byte size mismatch: expected ${expected.byteSize.toString()}, got ${bytes.byteLength}`
    );
  }

  const actualHash = sha256Hex(bytes);
  if (actualHash !== expected.snapshotHash) {
    throw new SnapshotIntegrityError(
      `Snapshot SHA-256 mismatch: expected '${expected.snapshotHash}', got '${actualHash}'`
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch (err) {
    throw new SnapshotIntegrityError("Snapshot JSON is malformed", "SNAPSHOT_MALFORMED_JSON", err);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new SnapshotIntegrityError("Snapshot envelope must be an object");
  }

  const envelope = parsed as Partial<SerializedSnapshotEnvelope>;
  const m = envelope.manifest;
  if (!m || typeof m !== "object" || Array.isArray(m) || typeof envelope.integrityHash !== "string") {
    throw new SnapshotIntegrityError("Snapshot envelope missing manifest or integrityHash");
  }

  if (m.formatVersion !== SNAPSHOT_FORMAT_VERSION || expected.formatVersion !== SNAPSHOT_FORMAT_VERSION) {
    throw new SnapshotIntegrityError(
      `Unsupported snapshot formatVersion: ${String(m.formatVersion)} (expected ${SNAPSHOT_FORMAT_VERSION})`
    );
  }

  if (m.canonicalizationVersion !== 1 && m.canonicalizationVersion !== 2) {
    throw new SnapshotIntegrityError(
      `Unsupported snapshot canonicalizationVersion: ${String(m.canonicalizationVersion)}`
    );
  }

  if (m.canonicalizationVersion !== expected.canonicalizationVersion) {
    throw new SnapshotIntegrityError(
      `Snapshot canonicalizationVersion mismatch: expected ${expected.canonicalizationVersion}, got ${m.canonicalizationVersion}`
    );
  }

  const recomputedIntegrity = computeCanonicalPayloadHash(m, m.canonicalizationVersion);
  if (recomputedIntegrity !== envelope.integrityHash) {
    throw new SnapshotIntegrityError(
      `Snapshot manifest integrityHash mismatch: expected '${envelope.integrityHash}', computed '${recomputedIntegrity}'`
    );
  }

  if (m.clusterId !== expected.clusterId) {
    throw new SnapshotIntegrityError(
      `Snapshot clusterId mismatch: expected '${expected.clusterId}', got '${String(m.clusterId)}'`
    );
  }
  if (m.epochId !== expected.epochId) {
    throw new SnapshotIntegrityError(
      `Snapshot epochId mismatch: expected '${expected.epochId}', got '${String(m.epochId)}'`
    );
  }

  const lastAppliedAppIndex = parseBigIntString(m.lastAppliedAppIndex, "lastAppliedAppIndex");
  if (lastAppliedAppIndex !== expected.snapshotIndex) {
    throw new SnapshotIntegrityError(
      `Snapshot index mismatch: expected ${expected.snapshotIndex.toString()}, got ${lastAppliedAppIndex.toString()}`
    );
  }

  if (m.chainHeadHash !== expected.chainHeadHash) {
    throw new SnapshotIntegrityError(
      `Snapshot chainHeadHash mismatch: expected '${expected.chainHeadHash}', got '${String(m.chainHeadHash)}'`
    );
  }

  const etcdRevision = parseBigIntString(
    m.lastPhysicalCursor?.etcdRevision,
    "lastPhysicalCursor.etcdRevision"
  );
  const subIndex = m.lastPhysicalCursor?.subIndex;
  if (etcdRevision !== expected.etcdRevision || subIndex !== expected.subIndex) {
    throw new SnapshotIntegrityError(
      `Snapshot physical cursor mismatch: expected (${expected.etcdRevision.toString()}, ${expected.subIndex}), got (${etcdRevision.toString()}, ${String(subIndex)})`
    );
  }

  const ticketsMap = new Map<string, CommittedTicketRecord>();
  if (!Array.isArray(m.committedTickets)) {
    throw new SnapshotIntegrityError("Snapshot committedTickets must be an array");
  }
  for (const entry of m.committedTickets) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string" || !entry[1]) {
      throw new SnapshotIntegrityError("Malformed committedTickets entry in snapshot");
    }
    const [ticketId, t] = entry;
    ticketsMap.set(
      ticketId,
      Object.freeze({
        ticketId: String(t.ticketId),
        epochId: String(t.epochId),
        authorizationId: String(t.authorizationId),
        bindingDigest: String(t.bindingDigest),
        policyId: String(t.policyId),
        policyRevision: Number(t.policyRevision),
        sequenceNumber: parseBigIntString(t.sequenceNumber, "ticket.sequenceNumber"),
        debitedAmount: parseBigIntString(t.debitedAmount, "ticket.debitedAmount"),
        committedAtSeconds: Number(t.committedAtSeconds),
      })
    );
  }

  if (!Array.isArray(m.revokedAuthorizations)) {
    throw new SnapshotIntegrityError("Snapshot revokedAuthorizations must be an array");
  }
  const revokedSet = new ReadonlyFrozenSet<string>(m.revokedAuthorizations.map(String));

  if (!Array.isArray(m.policies)) {
    throw new SnapshotIntegrityError("Snapshot policies must be an array");
  }
  const policiesMap = new Map<string, PolicyRecord>();
  for (const entry of m.policies) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string" || !entry[1]) {
      throw new SnapshotIntegrityError("Malformed policies entry in snapshot");
    }
    policiesMap.set(entry[0], Object.freeze({ ...entry[1] }));
  }

  if (!Array.isArray(m.appliedProposals)) {
    throw new SnapshotIntegrityError("Snapshot appliedProposals must be an array");
  }
  const proposalsMap = new Map<string, bigint>();
  for (const entry of m.appliedProposals) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string") {
      throw new SnapshotIntegrityError("Malformed appliedProposals entry in snapshot");
    }
    proposalsMap.set(entry[0], parseBigIntString(entry[1], "appliedProposal.index"));
  }

  if (!Array.isArray(m.appliedIndices)) {
    throw new SnapshotIntegrityError("Snapshot appliedIndices must be an array");
  }
  const indicesMap = new Map<bigint, AppliedIndexRecord>();
  for (const entry of m.appliedIndices) {
    if (!Array.isArray(entry) || entry.length !== 2 || !entry[1]) {
      throw new SnapshotIntegrityError("Malformed appliedIndices entry in snapshot");
    }
    indicesMap.set(
      parseBigIntString(entry[0], "appliedIndices.key"),
      Object.freeze({
        proposalId: String(entry[1].proposalId),
        payloadHash: String(entry[1].payloadHash),
      })
    );
  }

  const cursor = Object.freeze({ etcdRevision, subIndex });

  return Object.freeze({
    clusterId: m.clusterId,
    epochId: m.epochId,
    epochHeight: Number(m.epochHeight),
    epochState: m.epochState,
    lastAppliedAppIndex,
    lastAppliedRaftTerm: parseBigIntString(m.lastAppliedRaftTerm, "lastAppliedRaftTerm"),
    lastPhysicalCursor: cursor,
    chainHeadHash: m.chainHeadHash,
    lastSequenceNumber: parseBigIntString(m.lastSequenceNumber, "lastSequenceNumber"),
    committedTickets: new ReadonlyFrozenMap(ticketsMap),
    revokedAuthorizations: revokedSet,
    policies: new ReadonlyFrozenMap(policiesMap),
    appliedProposals: new ReadonlyFrozenMap(proposalsMap),
    appliedIndices: new ReadonlyFrozenMap(indicesMap),
    retentionFloorIndex: parseBigIntString(m.retentionFloorIndex, "retentionFloorIndex"),
    lastConsecutivePersistedAppIndex: parseBigIntString(
      m.lastConsecutivePersistedAppIndex,
      "lastConsecutivePersistedAppIndex"
    ),
  });
}

// ============================================================================
// Storage Backend Abstractions (POSIX FS, S3, GCS)
// ============================================================================

export interface StoredSnapshotObject {
  readonly uri: string;
  readonly snapshotId: string;
  readonly modifiedAtMs: number;
}

export interface SnapshotStorageBackend {
  readonly backendType: SnapshotStorageBackendType;
  buildUri(clusterId: string, epochId: string, snapshotId: string): string;
  putAndVerify(uri: string, data: Buffer, expectedSha256Hex: string): Promise<{ byteSize: number }>;
  get(uri: string): Promise<Buffer>;
  delete(uri: string): Promise<void>;
  listObjects(): Promise<ReadonlyArray<StoredSnapshotObject>>;
}

/**
 * Local POSIX filesystem backend implementing the 6-step staged atomic rename
 * and parent-directory fsync protocol (ADR-M13D-012).
 */
export class PosixSnapshotStorageBackend implements SnapshotStorageBackend {
  public readonly backendType = "posix_fs" as const;
  private readonly rootDir: string;

  constructor(rootDir: string) {
    if (!rootDir || rootDir.trim().length === 0) {
      throw new SnapshotError("POSIX rootDir must be non-empty", "INVALID_STORAGE_CONFIG");
    }
    this.rootDir = path.resolve(rootDir);
  }

  public buildUri(clusterId: string, epochId: string, snapshotId: string): string {
    const c = assertSafeIdentifier(clusterId, "clusterId");
    const e = assertSafeIdentifier(epochId, "epochId");
    const s = assertSafeIdentifier(snapshotId, "snapshotId");
    return path.join(this.rootDir, c, e, `${s}.snap`);
  }

  private resolveSafePath(uri: string): string {
    const resolved = path.resolve(uri);
    const rootWithSep = this.rootDir.endsWith(path.sep)
      ? this.rootDir
      : this.rootDir + path.sep;
    if (!resolved.startsWith(rootWithSep)) {
      throw new SnapshotError(`Path traversal rejected for URI '${uri}'`, "PATH_TRAVERSAL_REJECTED");
    }
    return resolved;
  }

  public async putAndVerify(
    uri: string,
    data: Buffer,
    expectedSha256Hex: string
  ): Promise<{ byteSize: number }> {
    const snapPath = this.resolveSafePath(uri);
    const parentDir = path.dirname(snapPath);
    fs.mkdirSync(parentDir, { recursive: true });

    const tmpPath = `${snapPath}.tmp`;
    const fd = fs.openSync(tmpPath, "w");
    try {
      let offset = 0;
      while (offset < data.byteLength) {
        offset += fs.writeSync(fd, data, offset, data.byteLength - offset);
      }
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }

    // Atomic rename within same filesystem
    fs.renameSync(tmpPath, snapPath);

    // Flush parent directory descriptor on POSIX platforms
    try {
      const dirFd = fs.openSync(parentDir, "r");
      try {
        fs.fsyncSync(dirFd);
      } finally {
        fs.closeSync(dirFd);
      }
    } catch {
      // On Windows NTFS, opening/fsyncing a directory fd can return EPERM/EINVAL;
      // file-level fsync and rename remain enforced.
    }

    // Step 5: Readback SHA-256 verification
    const readback = fs.readFileSync(snapPath);
    const readbackHash = sha256Hex(readback);
    if (readbackHash !== expectedSha256Hex || readback.byteLength !== data.byteLength) {
      try {
        fs.unlinkSync(snapPath);
      } catch {
        // Best-effort cleanup of corrupt write
      }
      throw new SnapshotIntegrityError(
        `POSIX readback verification failed for '${snapPath}'`
      );
    }

    return { byteSize: readback.byteLength };
  }

  public async get(uri: string): Promise<Buffer> {
    const snapPath = this.resolveSafePath(uri);
    return fs.readFileSync(snapPath);
  }

  public async delete(uri: string): Promise<void> {
    const snapPath = this.resolveSafePath(uri);
    try {
      fs.unlinkSync(snapPath);
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code === "ENOENT") {
        return;
      }
      throw err;
    }
  }

  public async listObjects(): Promise<ReadonlyArray<StoredSnapshotObject>> {
    if (!fs.existsSync(this.rootDir)) {
      return [];
    }
    const results: StoredSnapshotObject[] = [];
    const walk = (dir: string): void => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(full);
        } else if (entry.isFile() && (entry.name.endsWith(".snap") || entry.name.endsWith(".tmp"))) {
          const stat = fs.statSync(full);
          const base = entry.name.replace(/\.(snap|tmp)$/, "");
          results.push({
            uri: full,
            snapshotId: base,
            modifiedAtMs: stat.mtimeMs,
          });
        }
      }
    };
    walk(this.rootDir);
    return results;
  }
}

export interface S3ObjectStorageAdapter {
  putObject(params: {
    key: string;
    body: Buffer;
    checksumSha256Base64: string;
    contentMd5Base64: string;
    ifNoneMatch: "*";
  }): Promise<{ statusCode: number; checksumSha256Base64?: string; eTag?: string }>;
  getObject(key: string): Promise<Buffer>;
  deleteObject(key: string): Promise<void>;
  listObjects(prefix: string): Promise<ReadonlyArray<{ key: string; modifiedAtMs: number }>>;
}

export class S3SnapshotStorageBackend implements SnapshotStorageBackend {
  public readonly backendType = "s3" as const;

  constructor(
    private readonly bucket: string,
    private readonly adapter: S3ObjectStorageAdapter
  ) {
    assertSafeIdentifier(bucket, "bucket");
  }

  public buildUri(clusterId: string, epochId: string, snapshotId: string): string {
    const c = assertSafeIdentifier(clusterId, "clusterId");
    const e = assertSafeIdentifier(epochId, "epochId");
    const s = assertSafeIdentifier(snapshotId, "snapshotId");
    return `s3://${this.bucket}/snapshots/${c}/${e}/${s}.snap`;
  }

  private extractKey(uri: string): string {
    const prefix = `s3://${this.bucket}/`;
    if (!uri.startsWith(prefix)) {
      throw new SnapshotError(`Invalid S3 URI for bucket '${this.bucket}': '${uri}'`, "INVALID_STORAGE_URI");
    }
    const key = uri.slice(prefix.length);
    if (key.includes("..")) {
      throw new SnapshotError(`Unsafe S3 key: '${key}'`, "PATH_TRAVERSAL_REJECTED");
    }
    return key;
  }

  public async putAndVerify(
    uri: string,
    data: Buffer,
    expectedSha256Hex: string
  ): Promise<{ byteSize: number }> {
    const key = this.extractKey(uri);
    const sha256Base64 = createHash("sha256").update(data).digest("base64");
    const md5Base64 = createHash("md5").update(data).digest("base64");

    if (sha256Hex(data) !== expectedSha256Hex) {
      throw new SnapshotIntegrityError("Input buffer hash mismatch before S3 upload");
    }

    const res = await this.adapter.putObject({
      key,
      body: data,
      checksumSha256Base64: sha256Base64,
      contentMd5Base64: md5Base64,
      ifNoneMatch: "*",
    });

    if (res.statusCode === 412) {
      throw new SnapshotCollisionError(`S3 conditional PUT precondition failed for '${uri}'`);
    }
    if (res.statusCode !== 200 && res.statusCode !== 201) {
      throw new SnapshotError(`S3 PUT failed with status ${res.statusCode}`, "STORAGE_UPLOAD_FAILED");
    }
    if (res.checksumSha256Base64 && res.checksumSha256Base64 !== sha256Base64) {
      throw new SnapshotIntegrityError(
        `S3 returned ChecksumSHA256 '${res.checksumSha256Base64}' != expected '${sha256Base64}'`
      );
    }

    return { byteSize: data.byteLength };
  }

  public async get(uri: string): Promise<Buffer> {
    return this.adapter.getObject(this.extractKey(uri));
  }

  public async delete(uri: string): Promise<void> {
    await this.adapter.deleteObject(this.extractKey(uri));
  }

  public async listObjects(): Promise<ReadonlyArray<StoredSnapshotObject>> {
    const items = await this.adapter.listObjects("snapshots/");
    return items.map((item) => {
      const file = item.key.split("/").pop() ?? item.key;
      return {
        uri: `s3://${this.bucket}/${item.key}`,
        snapshotId: file.replace(/\.snap$/, ""),
        modifiedAtMs: item.modifiedAtMs,
      };
    });
  }
}

export interface GcsObjectStorageAdapter {
  uploadObject(params: {
    objectName: string;
    body: Buffer;
    ifGenerationMatch: 0;
    crc32cBase64: string;
  }): Promise<{ statusCode: number; crc32cBase64: string; byteSize: number }>;
  downloadObject(objectName: string): Promise<Buffer>;
  deleteObject(objectName: string): Promise<void>;
  listObjects(prefix: string): Promise<ReadonlyArray<{ objectName: string; modifiedAtMs: number }>>;
}

export class GcsSnapshotStorageBackend implements SnapshotStorageBackend {
  public readonly backendType = "gcs" as const;

  constructor(
    private readonly bucket: string,
    private readonly adapter: GcsObjectStorageAdapter
  ) {
    assertSafeIdentifier(bucket, "bucket");
  }

  public buildUri(clusterId: string, epochId: string, snapshotId: string): string {
    const c = assertSafeIdentifier(clusterId, "clusterId");
    const e = assertSafeIdentifier(epochId, "epochId");
    const s = assertSafeIdentifier(snapshotId, "snapshotId");
    return `gs://${this.bucket}/${c}/${e}/${s}.snap`;
  }

  private extractObjectName(uri: string): string {
    const prefix = `gs://${this.bucket}/`;
    if (!uri.startsWith(prefix)) {
      throw new SnapshotError(`Invalid GCS URI for bucket '${this.bucket}': '${uri}'`, "INVALID_STORAGE_URI");
    }
    const objName = uri.slice(prefix.length);
    if (objName.includes("..")) {
      throw new SnapshotError(`Unsafe GCS objectName: '${objName}'`, "PATH_TRAVERSAL_REJECTED");
    }
    return objName;
  }

  public async putAndVerify(
    uri: string,
    data: Buffer,
    expectedSha256Hex: string
  ): Promise<{ byteSize: number }> {
    if (sha256Hex(data) !== expectedSha256Hex) {
      throw new SnapshotIntegrityError("Input buffer hash mismatch before GCS upload");
    }
    const crcNum = calculateCrc32c(data);
    const crcBuf = Buffer.allocUnsafe(4);
    crcBuf.writeUInt32BE(crcNum, 0);
    const crc32cBase64 = crcBuf.toString("base64");

    const res = await this.adapter.uploadObject({
      objectName: this.extractObjectName(uri),
      body: data,
      ifGenerationMatch: 0,
      crc32cBase64,
    });

    if (res.statusCode === 412) {
      throw new SnapshotCollisionError(`GCS generation-match precondition failed for '${uri}'`);
    }
    if (res.statusCode !== 200 && res.statusCode !== 201) {
      throw new SnapshotError(`GCS upload failed with status ${res.statusCode}`, "STORAGE_UPLOAD_FAILED");
    }
    if (res.crc32cBase64 !== crc32cBase64 || res.byteSize !== data.byteLength) {
      throw new SnapshotIntegrityError(
        `GCS verification failed: crc32c '${res.crc32cBase64}' vs '${crc32cBase64}', size ${res.byteSize} vs ${data.byteLength}`
      );
    }

    return { byteSize: data.byteLength };
  }

  public async get(uri: string): Promise<Buffer> {
    return this.adapter.downloadObject(this.extractObjectName(uri));
  }

  public async delete(uri: string): Promise<void> {
    await this.adapter.deleteObject(this.extractObjectName(uri));
  }

  public async listObjects(): Promise<ReadonlyArray<StoredSnapshotObject>> {
    const items = await this.adapter.listObjects("");
    return items.map((item) => {
      const file = item.objectName.split("/").pop() ?? item.objectName;
      return {
        uri: `gs://${this.bucket}/${item.objectName}`,
        snapshotId: file.replace(/\.snap$/, ""),
        modifiedAtMs: item.modifiedAtMs,
      };
    });
  }
}

// ============================================================================
// SnapshotManager Options & Results
// ============================================================================

export interface SnapshotManagerOptions {
  readonly pool: pg.Pool;
  readonly storageBackend: SnapshotStorageBackend;
  readonly workerId?: string;
  readonly defaultLeaseTtlSeconds?: number;
  readonly cleanupGracePeriodSeconds?: number;
  readonly statementTimeoutMs?: number;
}

export interface CreateSnapshotOptions {
  readonly canonicalizationVersion?: 1 | 2;
  readonly leaseTtlSeconds?: number;
  readonly createdAtSeconds?: number;
  readonly onAfterStagedInsert?: (snapshotId: string) => void;
  readonly onAfterStorageUpload?: (snapshotId: string) => void;
}

export interface CleanupSnapshotsOptions {
  readonly clusterId?: string;
  readonly epochId?: string;
  readonly retainCount?: number;
  readonly gracePeriodSeconds?: number;
  readonly nowSeconds?: number;
  readonly onAfterDeletingTransition?: (snapshotId: string) => void;
  readonly onAfterStorageDelete?: (snapshotId: string) => void;
}

export interface CleanupSnapshotsResult {
  readonly purgedDbRecords: number;
  readonly purgedOrphanObjects: number;
  readonly skippedActiveOrProtected: number;
}

// ============================================================================
// SnapshotManager Implementation
// ============================================================================

export class SnapshotManager implements ConsensusSnapshotLoader {
  private readonly pool: pg.Pool;
  private readonly storage: SnapshotStorageBackend;
  private readonly workerId: string;
  private readonly defaultLeaseTtlSeconds: number;
  private readonly cleanupGracePeriodSeconds: number;
  private readonly statementTimeoutMs: number;

  constructor(options: SnapshotManagerOptions) {
    this.pool = options.pool;
    this.storage = options.storageBackend;
    this.workerId = options.workerId ?? `snapshot-worker-${randomUUID().slice(0, 8)}`;
    assertSafeIdentifier(this.workerId, "workerId");

    this.defaultLeaseTtlSeconds = options.defaultLeaseTtlSeconds ?? DEFAULT_LEASE_TTL_SECONDS;
    if (this.defaultLeaseTtlSeconds <= 0) {
      throw new SnapshotError("defaultLeaseTtlSeconds must be positive", "INVALID_CONFIG");
    }

    this.cleanupGracePeriodSeconds =
      options.cleanupGracePeriodSeconds ?? DEFAULT_CLEANUP_GRACE_PERIOD_SECONDS;
    if (this.cleanupGracePeriodSeconds < 0) {
      throw new SnapshotError("cleanupGracePeriodSeconds must be non-negative", "INVALID_CONFIG");
    }

    const timeout = options.statementTimeoutMs ?? 10_000;
    if (!Number.isInteger(timeout) || timeout < 0) {
      throw new SnapshotError("statementTimeoutMs must be a non-negative integer", "INVALID_CONFIG");
    }
    this.statementTimeoutMs = timeout;
  }

  // ==========================================================================
  // Lease Management (witness_snapshot_leases)
  // ==========================================================================

  public async acquireLease(
    snapshotId: string,
    workerId = this.workerId,
    ttlSeconds = this.defaultLeaseTtlSeconds
  ): Promise<void> {
    assertSafeIdentifier(snapshotId, "snapshotId");
    assertSafeIdentifier(workerId, "workerId");
    if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
      throw new SnapshotLeaseError("Lease TTL must be positive");
    }

    const res = await this.pool.query(
      `INSERT INTO witness_snapshot_leases (snapshot_id, worker_id, expires_at)
       VALUES ($1, $2, clock_timestamp() + ($3 * INTERVAL '1 second'))
       ON CONFLICT (snapshot_id) DO UPDATE
         SET worker_id = EXCLUDED.worker_id,
             expires_at = EXCLUDED.expires_at,
             created_at = clock_timestamp()
         WHERE witness_snapshot_leases.expires_at <= clock_timestamp()
            OR witness_snapshot_leases.worker_id = EXCLUDED.worker_id
       RETURNING snapshot_id`,
      [snapshotId, workerId, ttlSeconds]
    );

    if (res.rowCount === 0) {
      throw new SnapshotLeaseError(
        `Snapshot lease for '${snapshotId}' is currently held by another active worker`,
        "LEASE_CONTENTION"
      );
    }
  }

  public async renewLease(
    snapshotId: string,
    workerId = this.workerId,
    ttlSeconds = this.defaultLeaseTtlSeconds
  ): Promise<void> {
    assertSafeIdentifier(snapshotId, "snapshotId");
    assertSafeIdentifier(workerId, "workerId");
    if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
      throw new SnapshotLeaseError("Lease TTL must be positive");
    }

    const res = await this.pool.query(
      `UPDATE witness_snapshot_leases
       SET expires_at = clock_timestamp() + ($3 * INTERVAL '1 second')
       WHERE snapshot_id = $1
         AND worker_id = $2
         AND expires_at > clock_timestamp()
       RETURNING snapshot_id`,
      [snapshotId, workerId, ttlSeconds]
    );

    if (res.rowCount === 0) {
      throw new SnapshotLeaseError(
        `Cannot renew lease for '${snapshotId}': lease expired, missing, or owned by another worker`,
        "LEASE_LOST"
      );
    }
  }

  public async releaseLease(snapshotId: string, workerId = this.workerId): Promise<void> {
    assertSafeIdentifier(snapshotId, "snapshotId");
    assertSafeIdentifier(workerId, "workerId");
    await this.pool.query(
      `DELETE FROM witness_snapshot_leases
       WHERE snapshot_id = $1 AND worker_id = $2`,
      [snapshotId, workerId]
    );
  }

  // ==========================================================================
  // Snapshot Creation & Durable Publication (STAGED -> COMMITTED)
  // ==========================================================================

  public async createAndPublishSnapshot(
    state: ApplicationState,
    options: CreateSnapshotOptions = {}
  ): Promise<PersistedSnapshotRecord> {
    if (!state || state.epochState === "INITIAL" || state.lastAppliedAppIndex <= 0n) {
      throw new SnapshotCreationError(
        "Cannot create snapshot for uninitialized or empty epoch",
        "EMPTY_EPOCH_SNAPSHOT_FORBIDDEN"
      );
    }
    if (!state.epochId || state.epochId.trim().length === 0) {
      throw new SnapshotCreationError("ApplicationState epochId must be non-empty", "INVALID_EPOCH_ID");
    }
    if (state.lastAppliedAppIndex > state.lastConsecutivePersistedAppIndex) {
      throw new SnapshotCreationError(
        `Cannot snapshot uncommitted state at index ${state.lastAppliedAppIndex.toString()} (persisted watermark is ${state.lastConsecutivePersistedAppIndex.toString()})`,
        "UNCOMMITTED_STATE_SNAPSHOT_FORBIDDEN"
      );
    }

    assertSafeIdentifier(state.clusterId, "clusterId");
    assertSafeIdentifier(state.epochId, "epochId");

    const canonVersion: 1 | 2 = options.canonicalizationVersion ?? 2;
    const { bytes, snapshotHash, byteSize } = serializeApplicationStateSnapshot(state, canonVersion);
    const snapshotId = buildSafeSnapshotId(state.epochId, state.lastAppliedAppIndex);
    const storageUri = this.storage.buildUri(state.clusterId, state.epochId, snapshotId);
    const createdAtSeconds = options.createdAtSeconds ?? Math.floor(Date.now() / 1000);
    const leaseTtl = options.leaseTtlSeconds ?? this.defaultLeaseTtlSeconds;

    // 1. Acquire active publication lease
    await this.acquireLease(snapshotId, this.workerId, leaseTtl);

    // 2. Insert STAGED metadata row after confirming durable PostgreSQL state
    try {
      await this.insertStagedSnapshotRow(
        state,
        snapshotId,
        snapshotHash,
        canonVersion,
        storageUri,
        byteSize,
        createdAtSeconds
      );

      if (options.onAfterStagedInsert) {
        options.onAfterStagedInsert(snapshotId);
      }

      // 3. Upload and verify content on storage backend
      await this.storage.putAndVerify(storageUri, bytes, snapshotHash);

      if (options.onAfterStorageUpload) {
        options.onAfterStorageUpload(snapshotId);
      }

      // 4. Transition STAGED -> COMMITTED atomically with witness_raft_state & lease release
      await this.commitStagedSnapshot(state, snapshotId, snapshotHash);
    } catch (err) {
      try {
        await this.releaseLease(snapshotId, this.workerId);
      } catch {
        // Best-effort lease cleanup on failure; original error takes precedence
      }
      throw err;
    }

    return {
      snapshotId,
      clusterId: state.clusterId,
      epochId: state.epochId,
      snapshotIndex: state.lastAppliedAppIndex,
      snapshotHash,
      chainHeadHash: state.chainHeadHash,
      etcdRevision: state.lastPhysicalCursor.etcdRevision,
      subIndex: state.lastPhysicalCursor.subIndex,
      formatVersion: SNAPSHOT_FORMAT_VERSION,
      canonicalizationVersion: canonVersion,
      storageBackend: this.storage.backendType,
      storageUri,
      byteSize: BigInt(byteSize),
      createdAtSeconds,
    };
  }

  private async insertStagedSnapshotRow(
    state: ApplicationState,
    snapshotId: string,
    snapshotHash: string,
    canonVersion: 1 | 2,
    storageUri: string,
    byteSize: number,
    createdAtSeconds: number
  ): Promise<void> {
    const client = await this.pool.connect();
    let inTx = false;
    try {
      await client.query("BEGIN");
      inTx = true;
      if (this.statementTimeoutMs > 0) {
        await client.query(`SET LOCAL statement_timeout = ${this.statementTimeoutMs}`);
      }

      // Verify state is durably persisted in witness_raft_state
      const raftRes = await client.query(
        `SELECT last_consecutive_persisted_index, last_applied_hash
         FROM witness_raft_state
         WHERE cluster_id = $1 AND epoch_id = $2
         FOR SHARE`,
        [state.clusterId, state.epochId]
      );

      if (raftRes.rowCount === 0) {
        throw new SnapshotCreationError(
          `Cannot stage snapshot: witness_raft_state missing for (${state.clusterId}, ${state.epochId})`,
          "RAFT_STATE_MISSING"
        );
      }

      const persistedIdx = BigInt(raftRes.rows[0].last_consecutive_persisted_index);
      if (persistedIdx < state.lastAppliedAppIndex) {
        throw new SnapshotCreationError(
          `Cannot stage snapshot at index ${state.lastAppliedAppIndex.toString()}: durable watermark is ${persistedIdx.toString()}`,
          "UNCOMMITTED_STATE_SNAPSHOT_FORBIDDEN"
        );
      }

      await client.query(
        `INSERT INTO witness_snapshots (
           snapshot_id, cluster_id, epoch_id, snapshot_index, snapshot_hash,
           chain_head_hash, etcd_revision, sub_index, format_version,
           canonicalization_version, storage_backend, storage_uri, byte_size,
           created_at_seconds, status
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'STAGED')`,
        [
          snapshotId,
          state.clusterId,
          state.epochId,
          state.lastAppliedAppIndex.toString(),
          snapshotHash,
          state.chainHeadHash,
          state.lastPhysicalCursor.etcdRevision.toString(),
          state.lastPhysicalCursor.subIndex,
          SNAPSHOT_FORMAT_VERSION,
          canonVersion,
          this.storage.backendType,
          storageUri,
          byteSize,
          createdAtSeconds,
        ]
      );

      await client.query("COMMIT");
      inTx = false;
    } catch (err) {
      if (inTx) {
        try {
          await client.query("ROLLBACK");
        } catch {
          // Best-effort rollback
        }
      }
      throw err;
    } finally {
      client.release();
    }
  }

  private async commitStagedSnapshot(
    state: ApplicationState,
    snapshotId: string,
    snapshotHash: string
  ): Promise<void> {
    const client = await this.pool.connect();
    let inTx = false;
    try {
      await client.query("BEGIN");
      inTx = true;
      if (this.statementTimeoutMs > 0) {
        await client.query(`SET LOCAL statement_timeout = ${this.statementTimeoutMs}`);
      }

      // Lock order: witness_raft_state -> witness_snapshots -> witness_snapshot_leases
      await client.query(
        `SELECT last_snapshot_index
         FROM witness_raft_state
         WHERE cluster_id = $1 AND epoch_id = $2
         FOR UPDATE`,
        [state.clusterId, state.epochId]
      );

      const leaseCheck = await client.query(
        `SELECT 1 FROM witness_snapshot_leases
         WHERE snapshot_id = $1 AND worker_id = $2 AND expires_at > clock_timestamp()`,
        [snapshotId, this.workerId]
      );
      if (leaseCheck.rowCount === 0) {
        throw new SnapshotLeaseError(
          `Cannot commit snapshot '${snapshotId}': active publication lease was lost or expired`,
          "LEASE_LOST"
        );
      }

      const updateSnap = await client.query(
        `UPDATE witness_snapshots
         SET status = 'COMMITTED'
         WHERE snapshot_id = $1 AND status = 'STAGED'`,
        [snapshotId]
      );
      if (updateSnap.rowCount === 0) {
        throw new SnapshotCreationError(
          `Cannot commit snapshot '${snapshotId}': row missing or not in STAGED state`,
          "INVALID_LIFECYCLE_STATE"
        );
      }

      await client.query(
        `UPDATE witness_raft_state
         SET last_snapshot_hash = CASE
               WHEN $1::BIGINT >= last_snapshot_index THEN $2
               ELSE last_snapshot_hash
             END,
             last_snapshot_index = GREATEST(last_snapshot_index, $1::BIGINT)
         WHERE cluster_id = $3 AND epoch_id = $4`,
        [state.lastAppliedAppIndex.toString(), snapshotHash, state.clusterId, state.epochId]
      );

      await client.query(
        `DELETE FROM witness_snapshot_leases
         WHERE snapshot_id = $1 AND worker_id = $2`,
        [snapshotId, this.workerId]
      );

      await client.query("COMMIT");
      inTx = false;
    } catch (err) {
      if (inTx) {
        try {
          await client.query("ROLLBACK");
        } catch {
          // Best-effort rollback
        }
      }
      throw err;
    } finally {
      client.release();
    }
  }

  // ==========================================================================
  // Snapshot Verification & Restoration (ConsensusSnapshotLoader)
  // ==========================================================================

  /**
   * Loads, verifies, and rehydrates a COMMITTED snapshot for `PostgresConsensusStore.recover()`.
   * Returns `null` if the snapshot is not COMMITTED, missing from storage, or fails
   * cryptographic integrity verification so `recover()` can fall back to an earlier
   * snapshot or genesis.
   */
  public async loadAndVerify(record: PersistedSnapshotRecord): Promise<ApplicationState | null> {
    try {
      return await this.loadAndVerifyStrict(record);
    } catch {
      return null;
    }
  }

  /**
   * Strict variant that throws `SnapshotIntegrityError` / `SnapshotError` on any
   * metadata, storage, or integrity failure.
   */
  public async loadAndVerifyStrict(record: PersistedSnapshotRecord): Promise<ApplicationState> {
    const dbCheck = await this.pool.query(
      `SELECT status
       FROM witness_snapshots
       WHERE snapshot_id = $1 AND cluster_id = $2 AND epoch_id = $3`,
      [record.snapshotId, record.clusterId, record.epochId]
    );
    if (dbCheck.rowCount === 0 || dbCheck.rows[0].status !== "COMMITTED") {
      throw new SnapshotIntegrityError(
        `Snapshot '${record.snapshotId}' is not in COMMITTED state`,
        "SNAPSHOT_NOT_COMMITTED"
      );
    }

    const bytes = await this.storage.get(record.storageUri);
    return verifyAndDeserializeSnapshot(bytes, record);
  }

  // ==========================================================================
  // Safe Cleanup & Orphan Handling (DELETING -> Storage Delete -> DB Delete)
  // ==========================================================================

  public async cleanupSnapshots(
    options: CleanupSnapshotsOptions = {}
  ): Promise<CleanupSnapshotsResult> {
    const graceSeconds = options.gracePeriodSeconds ?? this.cleanupGracePeriodSeconds;
    const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1000);
    const retainCount = options.retainCount ?? 1;
    const cutoffSeconds = nowSeconds - graceSeconds;

    let purgedDbRecords = 0;
    let purgedOrphanObjects = 0;
    let skippedActiveOrProtected = 0;

    // 1. Clean up DB-tracked snapshots:
    //    - Any row already in 'DELETING' (resuming interrupted cleanup)
    //    - Stuck 'STAGED' rows older than gracePeriod with no active lease
    //    - Superseded 'COMMITTED' rows beyond retainCount, older than gracePeriod,
    //      and not referenced by witness_raft_state.last_snapshot_hash
    const candidateRows = await this.pool.query(
      `WITH ranked_committed AS (
         SELECT snapshot_id,
                ROW_NUMBER() OVER (PARTITION BY cluster_id, epoch_id ORDER BY snapshot_index DESC) AS rn
         FROM witness_snapshots
         WHERE status = 'COMMITTED'
       )
       SELECT s.snapshot_id, s.cluster_id, s.epoch_id, s.snapshot_index, s.snapshot_hash,
              s.storage_uri, s.status, s.created_at_seconds
       FROM witness_snapshots s
       LEFT JOIN ranked_committed rc ON rc.snapshot_id = s.snapshot_id
       WHERE ($1::VARCHAR IS NULL OR s.cluster_id = $1)
         AND ($2::VARCHAR IS NULL OR s.epoch_id = $2)
         AND (
           s.status = 'DELETING'
           OR (s.status = 'STAGED' AND s.created_at_seconds <= $3)
           OR (s.status = 'COMMITTED' AND s.created_at_seconds <= $3 AND COALESCE(rc.rn, 0) > $4)
         )
       ORDER BY s.snapshot_index ASC`,
      [options.clusterId ?? null, options.epochId ?? null, cutoffSeconds, retainCount]
    );

    for (const row of candidateRows.rows) {
      const snapshotId = String(row.snapshot_id);
      const storageUri = String(row.storage_uri);

      const transitioned = await this.transitionRowToDeletingIfEligible(
        snapshotId,
        String(row.cluster_id),
        String(row.epoch_id),
        String(row.snapshot_hash),
        cutoffSeconds
      );

      if (!transitioned) {
        skippedActiveOrProtected += 1;
        continue;
      }

      if (options.onAfterDeletingTransition) {
        options.onAfterDeletingTransition(snapshotId);
      }

      await this.storage.delete(storageUri);

      if (options.onAfterStorageDelete) {
        options.onAfterStorageDelete(snapshotId);
      }

      await this.pool.query(
        `DELETE FROM witness_snapshots
         WHERE snapshot_id = $1 AND status = 'DELETING'`,
        [snapshotId]
      );
      purgedDbRecords += 1;
    }

    // 2. Clean up orphaned storage objects lacking any DB row & active lease
    const objects = await this.storage.listObjects();
    const cutoffMs = (nowSeconds - graceSeconds) * 1000;

    for (const obj of objects) {
      if (obj.modifiedAtMs > cutoffMs) {
        skippedActiveOrProtected += 1;
        continue;
      }

      const canPurgeOrphan = await this.verifyOrphanObjectSafeToDelete(obj.snapshotId);
      if (!canPurgeOrphan) {
        skippedActiveOrProtected += 1;
        continue;
      }

      await this.storage.delete(obj.uri);
      purgedOrphanObjects += 1;
    }

    return {
      purgedDbRecords,
      purgedOrphanObjects,
      skippedActiveOrProtected,
    };
  }

  private async transitionRowToDeletingIfEligible(
    snapshotId: string,
    clusterId: string,
    epochId: string,
    snapshotHash: string,
    cutoffSeconds: number
  ): Promise<boolean> {
    const client = await this.pool.connect();
    let inTx = false;
    try {
      await client.query("BEGIN");
      inTx = true;

      // Lock witness_raft_state first if present to preserve lock order
      const raftRes = await client.query(
        `SELECT last_snapshot_hash
         FROM witness_raft_state
         WHERE cluster_id = $1 AND epoch_id = $2
         FOR SHARE`,
        [clusterId, epochId]
      );
      const activeSnapHash =
        raftRes.rowCount && raftRes.rowCount > 0 ? String(raftRes.rows[0].last_snapshot_hash) : "";

      const snapRes = await client.query(
        `SELECT status, created_at_seconds
         FROM witness_snapshots
         WHERE snapshot_id = $1
         FOR UPDATE`,
        [snapshotId]
      );

      if (snapRes.rowCount === 0) {
        await client.query("ROLLBACK");
        inTx = false;
        return false;
      }

      const currentStatus = String(snapRes.rows[0].status) as SnapshotLifecycleStatus;
      const createdAt = Number(snapRes.rows[0].created_at_seconds);

      if (currentStatus === "DELETING") {
        await client.query("COMMIT");
        inTx = false;
        return true;
      }

      if (createdAt > cutoffSeconds) {
        await client.query("ROLLBACK");
        inTx = false;
        return false;
      }

      if (currentStatus === "COMMITTED" && activeSnapHash === snapshotHash) {
        await client.query("ROLLBACK");
        inTx = false;
        return false;
      }

      const leaseRes = await client.query(
        `SELECT 1 FROM witness_snapshot_leases
         WHERE snapshot_id = $1 AND expires_at > clock_timestamp()`,
        [snapshotId]
      );
      if (leaseRes.rowCount && leaseRes.rowCount > 0) {
        await client.query("ROLLBACK");
        inTx = false;
        return false;
      }

      await client.query(
        `UPDATE witness_snapshots
         SET status = 'DELETING'
         WHERE snapshot_id = $1`,
        [snapshotId]
      );

      await client.query("COMMIT");
      inTx = false;
      return true;
    } catch (err) {
      if (inTx) {
        try {
          await client.query("ROLLBACK");
        } catch {
          // Best-effort rollback
        }
      }
      throw err;
    } finally {
      client.release();
    }
  }

  private async verifyOrphanObjectSafeToDelete(snapshotId: string): Promise<boolean> {
    const client = await this.pool.connect();
    let inTx = false;
    try {
      await client.query("BEGIN");
      inTx = true;

      // Active lease check
      const leaseRes = await client.query(
        `SELECT 1 FROM witness_snapshot_leases
         WHERE snapshot_id = $1 AND expires_at > clock_timestamp()`,
        [snapshotId]
      );
      if (leaseRes.rowCount && leaseRes.rowCount > 0) {
        await client.query("ROLLBACK");
        inTx = false;
        return false;
      }

      // Final delayed-writer re-check with FOR UPDATE
      const snapRes = await client.query(
        `SELECT 1 FROM witness_snapshots
         WHERE snapshot_id = $1
         FOR UPDATE`,
        [snapshotId]
      );
      if (snapRes.rowCount && snapRes.rowCount > 0) {
        await client.query("ROLLBACK");
        inTx = false;
        return false;
      }

      await client.query("COMMIT");
      inTx = false;
      return true;
    } catch (err) {
      if (inTx) {
        try {
          await client.query("ROLLBACK");
        } catch {
          // Best-effort rollback
        }
      }
      throw err;
    } finally {
      client.release();
    }
  }
}
