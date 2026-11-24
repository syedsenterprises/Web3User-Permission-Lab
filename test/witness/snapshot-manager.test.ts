/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.2 (Step 5)
 * SnapshotManager PostgreSQL 16 + POSIX FS + Object Storage Adapter Integration Suite
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import pg from "pg";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  SnapshotManager,
  PosixSnapshotStorageBackend,
  S3SnapshotStorageBackend,
  GcsSnapshotStorageBackend,
  SnapshotCreationError,
  SnapshotIntegrityError,
  SnapshotCollisionError,
  SnapshotLeaseError,
  SnapshotError,
  serializeApplicationStateSnapshot,
  verifyAndDeserializeSnapshot,
  type S3ObjectStorageAdapter,
  type GcsObjectStorageAdapter,
} from "../../src/witness/snapshot-manager.js";
import { PostgresConsensusStore } from "../../src/witness/consensus-store.js";
import {
  type CommittedConsensusEntry,
  type EpochAdvancePayload,
  type TicketCommitPayload,
  UnverifiableHistoricalEntryError,
} from "../../src/witness/state-machine-types.js";
import { computeCanonicalPayloadHash, createInitialState } from "../../src/witness/state-machine.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SCHEMA_FILE = path.resolve(__dirname, "../../src/witness/schema.sql");
const MIGRATION_004_FILE = path.resolve(
  __dirname,
  "../../src/witness/migrations/004_d3_consensus_persistence.sql"
);

function buildEntry<T extends CommittedConsensusEntry["commandType"]>(params: {
  epochId: string;
  appLogIndex: bigint;
  commandType: T;
  payload: CommittedConsensusEntry<T>["payload"];
  proposalId: string;
  canonicalizationVersion?: 1 | 2;
}): CommittedConsensusEntry<T> {
  const canonVersion = params.canonicalizationVersion ?? 2;
  return {
    epochId: params.epochId,
    appLogIndex: params.appLogIndex,
    raftTerm: 1n,
    physicalCursor: {
      etcdRevision: params.appLogIndex * 10n,
      subIndex: 0,
    },
    commandType: params.commandType,
    payload: params.payload,
    payloadHash: computeCanonicalPayloadHash(params.payload, canonVersion),
    proposalId: params.proposalId,
    committedAtSeconds: 1_700_000_000 + Number(params.appLogIndex),
    canonicalizationVersion: canonVersion,
  };
}

describe("Milestone 13-D Stage 2-B.2 Step 5: SnapshotManager Integration Suite", () => {
  let adminPool: pg.Pool;
  let pool: pg.Pool;
  let dbName: string;
  let tmpDir: string;
  let posixBackend: PosixSnapshotStorageBackend;
  let manager: SnapshotManager;
  let store: PostgresConsensusStore;

  beforeAll(async () => {
    adminPool = new pg.Pool({
      host: process.env.PGHOST || "127.0.0.1",
      port: Number(process.env.PGPORT || 5432),
      user: process.env.PGUSER || "postgres",
      password: process.env.PGPASSWORD || "postgres",
      database: "postgres",
    });

    dbName = `web3user_test_snap_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
    await adminPool.query(`CREATE DATABASE "${dbName}"`);

    pool = new pg.Pool({
      host: process.env.PGHOST || "127.0.0.1",
      port: Number(process.env.PGPORT || 5432),
      user: process.env.PGUSER || "postgres",
      password: process.env.PGPASSWORD || "postgres",
      database: dbName,
    });

    await pool.query(fs.readFileSync(SCHEMA_FILE, "utf-8"));
    await pool.query(fs.readFileSync(MIGRATION_004_FILE, "utf-8"));
  });

  afterAll(async () => {
    if (store) await store.close();
    if (pool) await pool.end();
    if (adminPool && dbName) {
      await adminPool.query(
        `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
        [dbName]
      );
      await adminPool.query(`DROP DATABASE IF EXISTS "${dbName}"`);
    }
    if (adminPool) await adminPool.end();
  });

  beforeEach(async () => {
    if (store) await store.close();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "web3user-snap-"));
    posixBackend = new PosixSnapshotStorageBackend(tmpDir);
    manager = new SnapshotManager({
      pool,
      storageBackend: posixBackend,
      workerId: "worker-primary",
      cleanupGracePeriodSeconds: 3600,
    });
    store = new PostgresConsensusStore({ pool, clusterId: "cluster-alpha" });

    const client = await pool.connect();
    try {
      await client.query(`
        ALTER TABLE witness_consensus_log DISABLE TRIGGER trg_witness_consensus_log_immutable;
        ALTER TABLE witness_consensus_log DISABLE TRIGGER trg_witness_consensus_log_no_truncate;
        ALTER TABLE witness_raft_state DISABLE TRIGGER trg_witness_raft_state_no_delete;
        ALTER TABLE witness_raft_state DISABLE TRIGGER trg_witness_raft_state_no_truncate;
        ALTER TABLE witness_snapshots DISABLE TRIGGER trg_witness_snapshots_lifecycle;
        ALTER TABLE witness_snapshots DISABLE TRIGGER trg_witness_snapshots_no_truncate;
        TRUNCATE TABLE witness_consensus_log, witness_raft_state, witness_snapshots, witness_snapshot_leases, witness_epochs RESTART IDENTITY CASCADE;
        ALTER TABLE witness_consensus_log ENABLE TRIGGER trg_witness_consensus_log_immutable;
        ALTER TABLE witness_consensus_log ENABLE TRIGGER trg_witness_consensus_log_no_truncate;
        ALTER TABLE witness_raft_state ENABLE TRIGGER trg_witness_raft_state_no_delete;
        ALTER TABLE witness_raft_state ENABLE TRIGGER trg_witness_raft_state_no_truncate;
        ALTER TABLE witness_snapshots ENABLE TRIGGER trg_witness_snapshots_lifecycle;
        ALTER TABLE witness_snapshots ENABLE TRIGGER trg_witness_snapshots_no_truncate;
      `);
    } finally {
      client.release();
    }
  });

  // ==========================================================================
  // 1. Snapshot Creation & Multi-Backend Publication
  // ==========================================================================
  it("creates and publishes POSIX snapshot atomically with TTCF-v1 and Canon-v1 support", async () => {
    await store.applyEntry(
      buildEntry({
        epochId: "ep-snap-1",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "ep-snap-1", epochHeight: 1, sequenceFloor: 10n, createdSeconds: 1700000000 },
        proposalId: "p-1",
      })
    );
    const ticketRes = await store.applyEntry(
      buildEntry({
        epochId: "ep-snap-1",
        appLogIndex: 2n,
        commandType: "TICKET_COMMIT",
        payload: {
          ticketId: "t-snap-1",
          epochId: "ep-snap-1",
          authorizationId: "auth-1",
          bindingDigest: "sha256:bd1",
          policyId: "pol-1",
          policyRevision: 1,
          debitedAmount: 250n,
        } satisfies TicketCommitPayload,
        proposalId: "p-2",
      })
    );

    const record = await manager.createAndPublishSnapshot(ticketRes.state, {
      canonicalizationVersion: 2,
    });
    expect(record.snapshotIndex).toBe(2n);
    expect(record.chainHeadHash).toBe(ticketRes.chainHeadHash);
    expect(record.canonicalizationVersion).toBe(2);
    expect(record.storageBackend).toBe("posix_fs");
    expect(fs.existsSync(record.storageUri)).toBe(true);

    // Lease released and DB status is COMMITTED
    const dbRow = await pool.query(`SELECT status FROM witness_snapshots WHERE snapshot_id = $1`, [
      record.snapshotId,
    ]);
    expect(dbRow.rows[0].status).toBe("COMMITTED");

    const leaseRow = await pool.query(
      `SELECT 1 FROM witness_snapshot_leases WHERE snapshot_id = $1`,
      [record.snapshotId]
    );
    expect(leaseRow.rowCount).toBe(0);

    const raft = await store.getRaftState("ep-snap-1");
    expect(raft?.lastSnapshotIndex).toBe(2n);
    expect(raft?.lastSnapshotHash).toBe(record.snapshotHash);

    // Also verify Canon-v1 snapshot serialization round-trip
    const v1Ser = serializeApplicationStateSnapshot(ticketRes.state, 1);
    const v1State = verifyAndDeserializeSnapshot(v1Ser.bytes, {
      ...record,
      snapshotHash: v1Ser.snapshotHash,
      byteSize: BigInt(v1Ser.byteSize),
      canonicalizationVersion: 1,
    });
    expect(v1State.committedTickets.get("t-snap-1")?.debitedAmount).toBe(250n);
  });

  it("rejects empty epoch, uncommitted state, and path-traversal identifiers", async () => {
    const emptyState = createInitialState("cluster-alpha");
    await expect(manager.createAndPublishSnapshot(emptyState)).rejects.toThrow(
      SnapshotCreationError
    );

    await store.applyEntry(
      buildEntry({
        epochId: "ep-uncomm",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "ep-uncomm", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
        proposalId: "p-u-1",
      })
    );
    const staleInMem = {
      ...store.getAuthoritativeState(),
      lastAppliedAppIndex: 2n,
    };
    await expect(manager.createAndPublishSnapshot(staleInMem)).rejects.toThrow(
      SnapshotCreationError
    );

    expect(() => posixBackend.buildUri("cluster-alpha", "../escape", "snap1")).toThrow(SnapshotError);
  });

  it("handles storage upload failure and crash boundaries without exposing STAGED as COMMITTED", async () => {
    const r1 = await store.applyEntry(
      buildEntry({
        epochId: "ep-fail-pub",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "ep-fail-pub", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
        proposalId: "p-fp-1",
      })
    );

    // Crash after STAGED insert
    await expect(
      manager.createAndPublishSnapshot(r1.state, {
        onAfterStagedInsert: () => {
          throw new Error("CRASH_AFTER_STAGED");
        },
      })
    ).rejects.toThrow("CRASH_AFTER_STAGED");

    const stagedRows = await pool.query(
      `SELECT status FROM witness_snapshots WHERE epoch_id = 'ep-fail-pub'`
    );
    expect(stagedRows.rowCount).toBe(1);
    expect(stagedRows.rows[0].status).toBe("STAGED");

    // Recovery ignores STAGED and replays from log cleanly
    const restarted = new PostgresConsensusStore({ pool, clusterId: "cluster-alpha" });
    try {
      const rec = await restarted.recover("ep-fail-pub", { snapshotLoader: manager });
      expect(rec.lastAppliedAppIndex).toBe(1n);
    } finally {
      await restarted.close();
    }
  });

  it("supports S3 and GCS storage adapters with conditional preconditions and checksum verification", async () => {
    const s3Objects = new Map<string, Buffer>();
    const s3Adapter: S3ObjectStorageAdapter = {
      putObject: async ({ key, body, checksumSha256Base64 }) => {
        if (s3Objects.has(key)) return { statusCode: 412 };
        s3Objects.set(key, body);
        return { statusCode: 200, checksumSha256Base64 };
      },
      getObject: async (key) => s3Objects.get(key)!,
      deleteObject: async (key) => {
        s3Objects.delete(key);
      },
      listObjects: async () => [],
    };
    const s3Backend = new S3SnapshotStorageBackend("my-bucket", s3Adapter);
    const s3Mgr = new SnapshotManager({ pool, storageBackend: s3Backend });

    const r1 = await store.applyEntry(
      buildEntry({
        epochId: "ep-s3",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "ep-s3", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
        proposalId: "p-s3-1",
      })
    );
    const s3Rec = await s3Mgr.createAndPublishSnapshot(r1.state);
    expect(s3Rec.storageBackend).toBe("s3");
    await expect(s3Backend.putAndVerify(s3Rec.storageUri, Buffer.from("x"), "")).rejects.toThrow(
      SnapshotIntegrityError
    );
    await expect(
      s3Adapter.putObject({
        key: `snapshots/cluster-alpha/ep-s3/${s3Rec.snapshotId}.snap`,
        body: Buffer.from("dup"),
        checksumSha256Base64: "",
        contentMd5Base64: "",
        ifNoneMatch: "*",
      })
    ).resolves.toMatchObject({ statusCode: 412 });

    // GCS CRC32C & 412 collision
    const gcsObjects = new Map<string, Buffer>();
    const gcsAdapter: GcsObjectStorageAdapter = {
      uploadObject: async ({ objectName, body, crc32cBase64 }) => {
        if (gcsObjects.has(objectName)) return { statusCode: 412, crc32cBase64, byteSize: 0 };
        gcsObjects.set(objectName, body);
        return { statusCode: 200, crc32cBase64, byteSize: body.byteLength };
      },
      downloadObject: async (name) => gcsObjects.get(name)!,
      deleteObject: async (name) => {
        gcsObjects.delete(name);
      },
      listObjects: async () => [],
    };
    const gcsBackend = new GcsSnapshotStorageBackend("my-gcs-bucket", gcsAdapter);
    const gcsMgr = new SnapshotManager({ pool, storageBackend: gcsBackend });
    const gcsUri = gcsBackend.buildUri("cluster-alpha", "ep-gcs", "snap-gcs-1");
    const payload = Buffer.from("hello-gcs");
    const hash = (await import("node:crypto")).createHash("sha256").update(payload).digest("hex");
    await expect(gcsBackend.putAndVerify(gcsUri, payload, hash)).resolves.toMatchObject({
      byteSize: payload.byteLength,
    });
    await expect(gcsBackend.putAndVerify(gcsUri, payload, hash)).rejects.toThrow(
      SnapshotCollisionError
    );
    expect(gcsMgr).toBeDefined();
  });

  // ==========================================================================
  // 2. Integrity, Verification & Restoration (PostgresConsensusStore)
  // ==========================================================================
  it("restores from COMMITTED snapshot + contiguous suffix replay, and fails closed on corruption or missing suffix", async () => {
    const r1 = await store.applyEntry(
      buildEntry({
        epochId: "ep-rest",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "ep-rest", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
        proposalId: "p-r-1",
      })
    );
    const r2 = await store.applyEntry(
      buildEntry({
        epochId: "ep-rest",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-r", revision: 1, policyHash: "hr1" },
        proposalId: "p-r-2",
      })
    );
    const snap1 = await manager.createAndPublishSnapshot(r1.state);
    const snap2 = await manager.createAndPublishSnapshot(r2.state);

    const r3 = await store.applyEntry(
      buildEntry({
        epochId: "ep-rest",
        appLogIndex: 3n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-r", revision: 2, policyHash: "hr2" },
        proposalId: "p-r-3",
      })
    );

    // Recover using snap2 + suffix [3]
    const recStore = new PostgresConsensusStore({ pool, clusterId: "cluster-alpha" });
    try {
      const recovered = await recStore.recover("ep-rest", { snapshotLoader: manager });
      expect(recovered.lastAppliedAppIndex).toBe(3n);
      expect(recovered.chainHeadHash).toBe(r3.chainHeadHash);
      expect(recovered.policies.get("pol-r")?.revision).toBe(2);

      // Corrupt snap2 on disk -> loadAndVerifyStrict throws, recover() falls back to snap1 + [2..3]
      fs.writeFileSync(snap2.storageUri, Buffer.from("corrupted-bytes"));
      await expect(manager.loadAndVerifyStrict(snap2)).rejects.toThrow(SnapshotIntegrityError);
      expect(await manager.loadAndVerify(snap2)).toBeNull();

      const fallbackRec = await recStore.recover("ep-rest", { snapshotLoader: manager });
      expect(fallbackRec.lastAppliedAppIndex).toBe(3n);
      expect(fallbackRec.chainHeadHash).toBe(r3.chainHeadHash);

      // Delete suffix log row 3 -> fails closed
      fs.unlinkSync(snap1.storageUri);
      await pool.query(
        `ALTER TABLE witness_consensus_log DISABLE TRIGGER trg_witness_consensus_log_immutable;
         DELETE FROM witness_consensus_log WHERE epoch_id = 'ep-rest' AND log_index = 3;
         ALTER TABLE witness_consensus_log ENABLE TRIGGER trg_witness_consensus_log_immutable;`
      );
      await expect(recStore.recover("ep-rest", { snapshotLoader: manager })).rejects.toThrow(
        UnverifiableHistoricalEntryError
      );
    } finally {
      await recStore.close();
    }
  });

  it("restores snapshot after EPOCH_ADVANCE transition", async () => {
    const r1 = await store.applyEntry(
      buildEntry({
        epochId: "ep-a1",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "ep-a1", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
        proposalId: "p-a-1",
      })
    );
    const r2 = await store.applyEntry(
      buildEntry({
        epochId: "ep-a1",
        appLogIndex: 2n,
        commandType: "EPOCH_ADVANCE",
        payload: {
          fromEpochId: "ep-a1",
          toEpochId: "ep-a2",
          newHeight: 2,
          priorChainHeadHash: r1.chainHeadHash,
          advancedAtSeconds: 1700000005,
        } satisfies EpochAdvancePayload,
        proposalId: "p-a-2",
      })
    );
    await manager.createAndPublishSnapshot(r2.state);
    const r3 = await store.applyEntry(
      buildEntry({
        epochId: "ep-a2",
        appLogIndex: 3n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-a2", revision: 1, policyHash: "ha2" },
        proposalId: "p-a-3",
      })
    );

    const recStore = new PostgresConsensusStore({ pool, clusterId: "cluster-alpha" });
    try {
      const rec = await recStore.recover("ep-a2", { snapshotLoader: manager });
      expect(rec.epochId).toBe("ep-a2");
      expect(rec.lastAppliedAppIndex).toBe(3n);
      expect(rec.chainHeadHash).toBe(r3.chainHeadHash);
    } finally {
      await recStore.close();
    }
  });

  // ==========================================================================
  // 3. Leases, Lifecycle Triggers, Cleanup & Crash Boundaries
  // ==========================================================================
  it("enforces lease contention, renewal, expiry takeover, and release", async () => {
    await manager.acquireLease("snap-lease-1", "worker-1", 60);
    await expect(manager.acquireLease("snap-lease-1", "worker-2", 60)).rejects.toThrow(
      SnapshotLeaseError
    );

    await manager.renewLease("snap-lease-1", "worker-1", 120);
    await expect(manager.renewLease("snap-lease-1", "worker-2", 60)).rejects.toThrow(
      SnapshotLeaseError
    );

    // Expire lease in DB -> worker-2 can take over
    await pool.query(
      `UPDATE witness_snapshot_leases SET expires_at = clock_timestamp() - INTERVAL '5 seconds' WHERE snapshot_id = 'snap-lease-1'`
    );
    await manager.acquireLease("snap-lease-1", "worker-2", 60);
    await manager.releaseLease("snap-lease-1", "worker-2");
  });

  it("enforces Migration 004 immutability and lifecycle triggers on witness_snapshots", async () => {
    const r1 = await store.applyEntry(
      buildEntry({
        epochId: "ep-trig",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "ep-trig", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
        proposalId: "p-tr-1",
      })
    );
    const snap = await manager.createAndPublishSnapshot(r1.state);

    // Immutable metadata update rejected
    await expect(
      pool.query(`UPDATE witness_snapshots SET snapshot_hash = 'tampered' WHERE snapshot_id = $1`, [
        snap.snapshotId,
      ])
    ).rejects.toThrow(/immutable/);

    // Invalid status transition COMMITTED -> STAGED rejected
    await expect(
      pool.query(`UPDATE witness_snapshots SET status = 'STAGED' WHERE snapshot_id = $1`, [
        snap.snapshotId,
      ])
    ).rejects.toThrow(/Invalid snapshot status transition/);

    // Direct DELETE on COMMITTED rejected
    await expect(
      pool.query(`DELETE FROM witness_snapshots WHERE snapshot_id = $1`, [snap.snapshotId])
    ).rejects.toThrow(/must be in DELETING state/);
  });

  it("safely cleans up expired/orphan snapshots while protecting active leases, grace period, and active snapshot", async () => {
    const r1 = await store.applyEntry(
      buildEntry({
        epochId: "ep-clean",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "ep-clean", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
        proposalId: "p-cl-1",
      })
    );
    const r2 = await store.applyEntry(
      buildEntry({
        epochId: "ep-clean",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "p1", revision: 1, policyHash: "h1" },
        proposalId: "p-cl-2",
      })
    );

    const oldTime = 1_700_000_000;
    const snap1 = await manager.createAndPublishSnapshot(r1.state, { createdAtSeconds: oldTime });
    const snap2 = await manager.createAndPublishSnapshot(r2.state, { createdAtSeconds: oldTime });

    // Create an old orphan file on POSIX storage
    const orphanUri = posixBackend.buildUri("cluster-alpha", "ep-clean", "snap_orphan_old");
    fs.mkdirSync(path.dirname(orphanUri), { recursive: true });
    fs.writeFileSync(orphanUri, "orphan");
    const oldTimeDate = new Date(oldTime * 1000);
    fs.utimesSync(orphanUri, oldTimeDate, oldTimeDate);

    // Within grace period -> nothing purged
    const withinGrace = await manager.cleanupSnapshots({
      retainCount: 1,
      gracePeriodSeconds: 3600,
      nowSeconds: oldTime + 100,
    });
    expect(withinGrace.purgedDbRecords).toBe(0);
    expect(withinGrace.purgedOrphanObjects).toBe(0);

    // Crash after DELETING transition before storage delete
    await expect(
      manager.cleanupSnapshots({
        retainCount: 1,
        gracePeriodSeconds: 3600,
        nowSeconds: oldTime + 7200,
        onAfterDeletingTransition: () => {
          throw new Error("CRASH_AFTER_DELETING");
        },
      })
    ).rejects.toThrow("CRASH_AFTER_DELETING");

    // Next cleanup resumes DELETING -> deletes storage + DB row, and purges orphan, while retaining snap2!
    const resumed = await manager.cleanupSnapshots({
      retainCount: 1,
      gracePeriodSeconds: 3600,
      nowSeconds: oldTime + 7200,
    });
    expect(resumed.purgedDbRecords).toBe(1);
    expect(resumed.purgedOrphanObjects).toBe(1);
    expect(fs.existsSync(snap1.storageUri)).toBe(false);
    expect(fs.existsSync(orphanUri)).toBe(false);
    expect(fs.existsSync(snap2.storageUri)).toBe(true);
  });

  it("handles crash after storage delete, active-lease protection, concurrent cleaners, and metadata mismatch rejection", async () => {
    const r1 = await store.applyEntry(
      buildEntry({
        epochId: "ep-edge",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: { epochId: "ep-edge", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
        proposalId: "p-ed-1",
      })
    );
    const r2 = await store.applyEntry(
      buildEntry({
        epochId: "ep-edge",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "p1", revision: 1, policyHash: "h1", definitionJson: "{}" },
        proposalId: "p-ed-2",
      })
    );

    const oldTime = 1_700_000_000;
    const snap1 = await manager.createAndPublishSnapshot(r1.state, { createdAtSeconds: oldTime });
    const snap2 = await manager.createAndPublishSnapshot(r2.state, { createdAtSeconds: oldTime });

    // Metadata mismatch checks in verifyAndDeserializeSnapshot
    const bytes2 = fs.readFileSync(snap2.storageUri);
    expect(() =>
      verifyAndDeserializeSnapshot(bytes2, { ...snap2, clusterId: "wrong-cluster" })
    ).toThrow(SnapshotIntegrityError);
    expect(() =>
      verifyAndDeserializeSnapshot(bytes2, { ...snap2, epochId: "wrong-epoch" })
    ).toThrow(SnapshotIntegrityError);
    expect(() =>
      verifyAndDeserializeSnapshot(bytes2, { ...snap2, snapshotIndex: 99n })
    ).toThrow(SnapshotIntegrityError);
    expect(() =>
      verifyAndDeserializeSnapshot(bytes2, { ...snap2, formatVersion: 99 })
    ).toThrow(SnapshotIntegrityError);

    // Active lease on snap1 protects it from cleanup
    await manager.acquireLease(snap1.snapshotId, "other-worker", 600);
    const protectedRes = await manager.cleanupSnapshots({
      retainCount: 1,
      gracePeriodSeconds: 3600,
      nowSeconds: oldTime + 7200,
    });
    expect(protectedRes.purgedDbRecords).toBe(0);
    expect(fs.existsSync(snap1.storageUri)).toBe(true);
    await manager.releaseLease(snap1.snapshotId, "other-worker");

    // Crash after storage delete before DB row deletion
    await expect(
      manager.cleanupSnapshots({
        retainCount: 1,
        gracePeriodSeconds: 3600,
        nowSeconds: oldTime + 7200,
        onAfterStorageDelete: () => {
          throw new Error("CRASH_AFTER_STORAGE_DELETE");
        },
      })
    ).rejects.toThrow("CRASH_AFTER_STORAGE_DELETE");
    expect(fs.existsSync(snap1.storageUri)).toBe(false);

    // Concurrent cleanup workers resume idempotently and purge DB row
    const cleanerB = new SnapshotManager({
      pool,
      storageBackend: posixBackend,
      workerId: "cleaner-b",
      cleanupGracePeriodSeconds: 3600,
    });
    const [c1, c2] = await Promise.all([
      manager.cleanupSnapshots({ retainCount: 1, gracePeriodSeconds: 3600, nowSeconds: oldTime + 7200 }),
      cleanerB.cleanupSnapshots({ retainCount: 1, gracePeriodSeconds: 3600, nowSeconds: oldTime + 7200 }),
    ]);
    expect(c1.purgedDbRecords + c2.purgedDbRecords).toBe(1);
    expect(fs.existsSync(snap2.storageUri)).toBe(true);
  });
});
