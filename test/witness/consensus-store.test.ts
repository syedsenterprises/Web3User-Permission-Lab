/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.2 (Step 4)
 * PostgresConsensusStore Integration, Two-Phase Publication & F-STEP3-01 Migration Gate Suite
 *
 * Executes against an isolated disposable PostgreSQL 16 database:
 * 1. F-STEP3-01 Gate: Applies Migration 003 baseline -> Migration 004 forward ->
 *    inspects live schema/constraints/indexes/triggers -> tests rollback safety guard ->
 *    executes Migration 004 rollback -> verifies restored Migration 003 schema ->
 *    re-applies Migration 004 cleanly.
 * 2. Persistence: append/commit, duplicate proposal, conflicting proposal, duplicate index,
 *    invalid payload/hash, DB failure & rollback, concurrent writers, epoch & cluster isolation.
 * 3. Two-phase publication: no publication before COMMIT, publication after COMMIT,
 *    failed tx leaves state unchanged, crash/restart around commit/publication, idempotent retry.
 * 4. Replay & recovery: empty epoch, contiguous history, missing index gap, conflicting replay,
 *    incorrect hash, Canon-v1, TTCF-v1 (v2), Tier-2 pruned-history verification, missing Tier-2
 *    record, watermark regression, multiple epochs, corrupt snapshot fallback.
 * 5. Retention & backpressure integration.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import pg from "pg";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  PostgresConsensusStore,
  ConsensusStoreError,
  ConsensusConflictError,
  UnverifiableDurableHistoryError,
  StaleAuthoritativeStateError,
  ReplayVerificationError,
  type ConsensusSnapshotLoader,
} from "../../src/witness/consensus-store.js";
import {
  type CommittedConsensusEntry,
  type EpochInitializePayload,
  type EpochAdvancePayload,
  type PolicyUpdatePayload,
  type DelegationRevokePayload,
  type TicketCommitPayload,
  type EpochQuarantinePayload,
  HistoricalIndexConflictError,
  PayloadHashMismatchError,
  EpochMismatchError,
  StateMachineError,
  UnverifiableHistoricalEntryError,
} from "../../src/witness/state-machine-types.js";
import { computeCanonicalPayloadHash } from "../../src/witness/state-machine.js";
import {
  createManagedTestPool,
  destroyDisposableTestDb,
  closeAdminTestPool,
} from "./helpers/pg-test-teardown.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SCHEMA_FILE = path.resolve(__dirname, "../../src/witness/schema.sql");
const MIGRATION_004_FILE = path.resolve(
  __dirname,
  "../../src/witness/migrations/004_d3_consensus_persistence.sql"
);
const ROLLBACK_004_FILE = path.resolve(
  __dirname,
  "../../src/witness/migrations/004_d3_consensus_persistence.rollback.sql"
);

function buildEntry<T extends CommittedConsensusEntry["commandType"]>(params: {
  epochId: string;
  appLogIndex: bigint;
  raftTerm?: bigint;
  etcdRevision?: bigint;
  subIndex?: number;
  commandType: T;
  payload: CommittedConsensusEntry<T>["payload"];
  proposalId: string;
  committedAtSeconds?: number;
  canonicalizationVersion?: 1 | 2;
  payloadHash?: string;
}): CommittedConsensusEntry<T> {
  const canonVersion = params.canonicalizationVersion ?? 2;
  const payloadHash =
    params.payloadHash ?? computeCanonicalPayloadHash(params.payload, canonVersion);
  return {
    epochId: params.epochId,
    appLogIndex: params.appLogIndex,
    raftTerm: params.raftTerm ?? 1n,
    physicalCursor: {
      etcdRevision: params.etcdRevision ?? params.appLogIndex * 10n,
      subIndex: params.subIndex ?? 0,
    },
    commandType: params.commandType,
    payload: params.payload,
    payloadHash,
    proposalId: params.proposalId,
    committedAtSeconds: params.committedAtSeconds ?? 1_700_000_000 + Number(params.appLogIndex),
    canonicalizationVersion: canonVersion,
  };
}

describe("Milestone 13-D Stage 2-B.2 Step 4: PostgresConsensusStore & F-STEP3-01 Gate", () => {
  let adminPool: pg.Pool;
  const createdDatabases: string[] = [];

  beforeAll(async () => {
    adminPool = createManagedTestPool({
      host: process.env.PGHOST || "127.0.0.1",
      port: Number(process.env.PGPORT || 5432),
      user: process.env.PGUSER || "postgres",
      password: process.env.PGPASSWORD || "postgres",
      database: "postgres",
    });
  });

  afterAll(async () => {
    await closeAdminTestPool(adminPool, createdDatabases);
  });

  async function createDisposableMigration004Db(
    prefix: string
  ): Promise<{ dbName: string; pool: pg.Pool }> {
    const dbName = `web3user_test_cs_${prefix}_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
    await adminPool.query(`CREATE DATABASE "${dbName}"`);
    createdDatabases.push(dbName);

    const pool = createManagedTestPool({
      host: process.env.PGHOST || "127.0.0.1",
      port: Number(process.env.PGPORT || 5432),
      user: process.env.PGUSER || "postgres",
      password: process.env.PGPASSWORD || "postgres",
      database: dbName,
    });

    const schemaSql = fs.readFileSync(SCHEMA_FILE, "utf-8");
    const migration004Sql = fs.readFileSync(MIGRATION_004_FILE, "utf-8");
    await pool.query(schemaSql);
    await pool.query(migration004Sql);

    return { dbName, pool };
  }

  async function destroyDisposableDb(dbName: string, pool: pg.Pool): Promise<void> {
    await destroyDisposableTestDb({
      adminPool,
      dbName,
      pool,
      trackedDatabases: createdDatabases,
    });
  }

  // ==========================================================================
  // 1. F-STEP3-01 Mandatory PostgreSQL Integration Gate
  // ==========================================================================
  describe("F-STEP3-01 Gate: Live Migration 004 Forward, Schema Inspection, Rollback & Re-apply", () => {
    it("applies Migration 003 baseline -> Migration 004 forward -> verifies schema -> tests rollback guard & rollback -> re-applies Migration 004", async () => {
      const dbName = `web3user_test_fstep301_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
      await adminPool.query(`CREATE DATABASE "${dbName}"`);
      createdDatabases.push(dbName);

      const pool = createManagedTestPool({
        host: process.env.PGHOST || "127.0.0.1",
        port: Number(process.env.PGPORT || 5432),
        user: process.env.PGUSER || "postgres",
        password: process.env.PGPASSWORD || "postgres",
        database: dbName,
      });

      try {
        // 1. Apply Migration 003 baseline (schema.sql)
        const schemaSql = fs.readFileSync(SCHEMA_FILE, "utf-8");
        await pool.query(schemaSql);

        // Seed an epoch + contiguous log entries to verify Migration 004 backfill
        await pool.query(
          `INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, state, is_quarantined, is_active)
           VALUES ('epoch-m04-gate', 1, 1700000000, 'ACTIVE', false, true)`
        );
        await pool.query(
          `INSERT INTO witness_consensus_log (epoch_id, log_index, term, etcd_revision, payload_type, payload, payload_hash, proposal_id, committed_at_seconds)
           VALUES
             ('epoch-m04-gate', 1, 1, 10, 'EPOCH_INITIALIZE', '{"epochId":"epoch-m04-gate"}'::jsonb, 'hash1', 'prop-1', 1700000001),
             ('epoch-m04-gate', 2, 1, 20, 'POLICY_UPDATE', '{"policyId":"p1"}'::jsonb, 'hash2', 'prop-2', 1700000002)`
        );

        // 2. Apply Migration 004 forward
        const migration004Sql = fs.readFileSync(MIGRATION_004_FILE, "utf-8");
        await pool.query(migration004Sql);

        // 3. Inspect schema, constraints, indexes, triggers, and backfilled data
        const logCols = await pool.query(
          `SELECT column_name, data_type
           FROM information_schema.columns
           WHERE table_name = 'witness_consensus_log'
             AND column_name IN ('canonicalization_version', 'sub_index')
           ORDER BY column_name`
        );
        expect(logCols.rows.map((r) => r.column_name)).toEqual([
          "canonicalization_version",
          "sub_index",
        ]);

        const raftCols = await pool.query(
          `SELECT column_name
           FROM information_schema.columns
           WHERE table_name = 'witness_raft_state'
             AND column_name IN (
               'last_applied_etcd_revision',
               'last_applied_sub_index',
               'last_consecutive_persisted_index',
               'last_snapshot_index',
               'last_snapshot_hash'
             )
           ORDER BY column_name`
        );
        expect(raftCols.rowCount).toBe(5);

        const idxRes = await pool.query(
          `SELECT indexname, indexdef
           FROM pg_indexes
           WHERE tablename = 'witness_consensus_log'
             AND indexname = 'uq_consensus_log_proposal_id'`
        );
        expect(idxRes.rowCount).toBe(1);
        expect(idxRes.rows[0].indexdef).toContain("UNIQUE INDEX");

        const snapTables = await pool.query(
          `SELECT table_name
           FROM information_schema.tables
           WHERE table_schema = 'public'
             AND table_name IN ('witness_snapshots', 'witness_snapshot_leases')
           ORDER BY table_name`
        );
        expect(snapTables.rows.map((r) => r.table_name)).toEqual([
          "witness_snapshot_leases",
          "witness_snapshots",
        ]);

        const raftBackfill = await pool.query(
          `SELECT last_consecutive_persisted_index, last_applied_etcd_revision, last_applied_sub_index
           FROM witness_raft_state
           WHERE cluster_id = 'default-cluster' AND epoch_id = 'epoch-m04-gate'`
        );
        expect(raftBackfill.rowCount).toBe(1);
        expect(Number(raftBackfill.rows[0].last_consecutive_persisted_index)).toBe(2);
        expect(Number(raftBackfill.rows[0].last_applied_etcd_revision)).toBe(20);

        // 4. Verify rollback safety guard blocks accidental rollback when Stage 2-B.2 data exists
        const rollback004Sql = fs.readFileSync(ROLLBACK_004_FILE, "utf-8");
        await expect(pool.query(rollback004Sql)).rejects.toThrow(
          /Migration 004 rollback aborted/
        );

        // 5. Execute Migration 004 rollback with explicit override
        const client = await pool.connect();
        try {
          await client.query(`SET stage2b2.allow_destructive_rollback = 'true'`);
          await client.query(rollback004Sql);
        } finally {
          client.release();
        }

        // 6. Verify restored Migration 003 schema
        const restoredTables = await pool.query(
          `SELECT table_name
           FROM information_schema.tables
           WHERE table_schema = 'public'
             AND table_name IN ('witness_snapshots', 'witness_snapshot_leases')`
        );
        expect(restoredTables.rowCount).toBe(0);

        const restoredIdx = await pool.query(
          `SELECT indexname, indexdef
           FROM pg_indexes
           WHERE tablename = 'witness_consensus_log'
             AND indexname = 'idx_consensus_log_proposal_id'`
        );
        expect(restoredIdx.rowCount).toBe(1);
        expect(restoredIdx.rows[0].indexdef).not.toContain("UNIQUE INDEX");
        expect(restoredIdx.rows[0].indexdef).toContain("(proposal_id)");

        // 7. Re-apply Migration 004 cleanly (repeatability check)
        await pool.query(migration004Sql);
        const reappliedIdx = await pool.query(
          `SELECT indexname FROM pg_indexes WHERE tablename = 'witness_consensus_log' AND indexname = 'uq_consensus_log_proposal_id'`
        );
        expect(reappliedIdx.rowCount).toBe(1);
      } finally {
        await destroyDisposableDb(dbName, pool);
      }
    });
  });

  // ==========================================================================
  // 2. Persistence, Two-Phase Publication, Replay & Backpressure Suite
  // ==========================================================================
  describe("PostgresConsensusStore Integration Suite", () => {
    let dbName: string;
    let pool: pg.Pool;
    let store: PostgresConsensusStore;

    beforeAll(async () => {
      const created = await createDisposableMigration004Db("main");
      dbName = created.dbName;
      pool = created.pool;
    });

    afterAll(async () => {
      if (store) {
        await store.close();
      }
      await destroyDisposableDb(dbName, pool);
    });

    beforeEach(async () => {
      if (store) {
        await store.close();
      }
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
      store = new PostgresConsensusStore({ pool, clusterId: "cluster-alpha" });
    });

    // ------------------------------------------------------------------------
    // Persistence Tests
    // ------------------------------------------------------------------------
    it("persists and commits entries atomically across witness_consensus_log and witness_raft_state", async () => {
      const e1 = buildEntry({
        epochId: "epoch-1",
        appLogIndex: 1n,
        raftTerm: 2n,
        etcdRevision: 100n,
        subIndex: 0,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "epoch-1",
          epochHeight: 1,
          sequenceFloor: 10n,
          createdSeconds: 1700000000,
        } satisfies EpochInitializePayload,
        proposalId: "prop-init-1",
        canonicalizationVersion: 2,
      });

      const res1 = await store.applyEntry(e1);
      expect(res1.status).toBe("APPLIED");
      expect(res1.committedToDatabase).toBe(true);
      expect(res1.appliedAppIndex).toBe(1n);
      expect(store.getAuthoritativeState().epochId).toBe("epoch-1");
      expect(store.getAuthoritativeState().lastConsecutivePersistedAppIndex).toBe(1n);

      const raft = await store.getRaftState("epoch-1");
      expect(raft).not.toBeNull();
      expect(raft!.lastAppliedIndex).toBe(1n);
      expect(raft!.lastConsecutivePersistedIndex).toBe(1n);
      expect(raft!.lastAppliedEtcdRevision).toBe(100n);
      expect(raft!.lastAppliedHash).toBe(res1.chainHeadHash);
    });

    it("handles duplicate proposal idempotently at same index and rejects proposal reuse at different index", async () => {
      const e1 = buildEntry({
        epochId: "epoch-1",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "epoch-1",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-dup-1",
      });
      await store.applyEntry(e1);

      // Replay exact same entry
      const dupRes = await store.applyEntry(e1);
      expect(dupRes.status).toBe("ALREADY_APPLIED");
      expect(dupRes.committedToDatabase).toBe(false);
      expect(dupRes.duplicateDetected).toBe(true);

      // Reuse same proposalId at index 2
      const e2 = buildEntry({
        epochId: "epoch-1",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: {
          policyId: "pol-1",
          revision: 1,
          policyHash: "abc",
        } satisfies PolicyUpdatePayload,
        proposalId: "prop-dup-1",
      });
      await expect(store.applyEntry(e2)).rejects.toThrow(/already applied/);
    });

    it("rejects conflicting proposal at already-applied index without mutating state", async () => {
      const e1 = buildEntry({
        epochId: "epoch-1",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "epoch-1",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-1",
      });
      await store.applyEntry(e1);

      const conflicting = buildEntry({
        epochId: "epoch-1",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "epoch-1",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-DIFFERENT",
      });

      await expect(store.applyEntry(conflicting)).rejects.toThrow(HistoricalIndexConflictError);
      expect(store.getAuthoritativeState().lastAppliedAppIndex).toBe(1n);
    });

    it("classifies PostgreSQL unique violation on duplicate log_index when DB already has row", async () => {
      const e1 = buildEntry({
        epochId: "epoch-1",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "epoch-1",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-1",
      });
      await store.applyEntry(e1);

      // Simulate another writer inserting log_index=2 directly into witness_consensus_log
      // without advancing witness_raft_state (or a stale in-memory store attempting index 2)
      const p2 = { policyId: "pol-1", revision: 1, policyHash: "h1" } satisfies PolicyUpdatePayload;
      await pool.query(
        `INSERT INTO witness_consensus_log (epoch_id, log_index, term, etcd_revision, payload_type, payload, payload_hash, proposal_id, committed_at_seconds, canonicalization_version, sub_index)
         VALUES ('epoch-1', 2, 1, 20, 'POLICY_UPDATE', $1::jsonb, $2, 'prop-external', 1700000002, 2, 0)`,
        [JSON.stringify(p2), computeCanonicalPayloadHash(p2, 2)]
      );

      const e2 = buildEntry({
        epochId: "epoch-1",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: p2,
        proposalId: "prop-2",
      });

      await expect(store.applyEntry(e2)).rejects.toThrow(ConsensusConflictError);
      expect(store.getAuthoritativeState().lastAppliedAppIndex).toBe(1n);
    });

    it("rejects invalid payloadHash before touching PostgreSQL", async () => {
      const e1 = buildEntry({
        epochId: "epoch-1",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "epoch-1",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-bad-hash",
        payloadHash: "0".repeat(64),
      });

      await expect(store.applyEntry(e1)).rejects.toThrow(PayloadHashMismatchError);
      const countRes = await pool.query(`SELECT COUNT(*)::INT AS c FROM witness_consensus_log`);
      expect(countRes.rows[0].c).toBe(0);
    });

    it("rolls back transaction and leaves authoritative state unchanged on database failure", async () => {
      const e1 = buildEntry({
        epochId: "epoch-1",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "epoch-1",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-ok",
      });
      await store.applyEntry(e1);
      const beforeState = store.getAuthoritativeState();

      // Inject a DB failure on COMMIT using a wrapper pool that restores client.query on release
      const failingPool = {
        connect: async () => {
          const realClient = await pool.connect();
          const origQuery = realClient.query.bind(realClient);
          const origRelease = realClient.release.bind(realClient);
          (realClient as unknown as { query: typeof realClient.query }).query = ((
            sql: unknown,
            ...args: unknown[]
          ) => {
            if (typeof sql === "string" && sql.trim().toUpperCase() === "COMMIT") {
              return Promise.reject(new Error("SIMULATED_DB_COMMIT_FAILURE"));
            }
            return (origQuery as (...a: unknown[]) => Promise<unknown>)(sql, ...args);
          }) as typeof realClient.query;
          (realClient as unknown as { release: typeof realClient.release }).release = ((
            err?: boolean | Error
          ) => {
            (realClient as unknown as { query: typeof realClient.query }).query = origQuery;
            (realClient as unknown as { release: typeof realClient.release }).release = origRelease;
            return origRelease(err);
          }) as typeof realClient.release;
          return realClient;
        },
      } as unknown as pg.Pool;

      const failingStore = new PostgresConsensusStore({
        pool: failingPool,
        clusterId: "cluster-alpha",
      });
      await failingStore.recover("epoch-1");

      const e2 = buildEntry({
        epochId: "epoch-1",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-1", revision: 1, policyHash: "h1" },
        proposalId: "prop-fail-commit",
      });

      await expect(failingStore.applyEntry(e2)).rejects.toThrow("SIMULATED_DB_COMMIT_FAILURE");

      // Authoritative state in memory AND PostgreSQL must remain at index 1
      expect(failingStore.getAuthoritativeState().lastAppliedAppIndex).toBe(
        beforeState.lastAppliedAppIndex
      );
      const logCount = await pool.query(
        `SELECT COUNT(*)::INT AS c FROM witness_consensus_log WHERE epoch_id = 'epoch-1'`
      );
      expect(logCount.rows[0].c).toBe(1);
    });

    it("serializes concurrent writers safely with zero deadlocks", async () => {
      const e1 = buildEntry({
        epochId: "epoch-conc",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "epoch-conc",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-conc-1",
      });
      await store.applyEntry(e1);

      const e2a = buildEntry({
        epochId: "epoch-conc",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-a", revision: 1, policyHash: "ha" },
        proposalId: "prop-conc-2a",
      });
      const e2b = buildEntry({
        epochId: "epoch-conc",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-b", revision: 1, policyHash: "hb" },
        proposalId: "prop-conc-2b",
      });

      const results = await Promise.allSettled([store.applyEntry(e2a), store.applyEntry(e2b)]);
      const fulfilled = results.filter((r) => r.status === "fulfilled");
      const rejected = results.filter((r) => r.status === "rejected");

      expect(fulfilled.length).toBe(1);
      expect(rejected.length).toBe(1);
      expect(store.getAuthoritativeState().lastAppliedAppIndex).toBe(2n);
    });

    it("enforces epoch isolation and cluster isolation", async () => {
      const e1 = buildEntry({
        epochId: "epoch-iso-1",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "epoch-iso-1",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-iso-1",
      });
      await store.applyEntry(e1);

      // Wrong epoch
      const wrongEpoch = buildEntry({
        epochId: "epoch-iso-2",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-1", revision: 1, policyHash: "h1" },
        proposalId: "prop-iso-wrong",
      });
      await expect(store.applyEntry(wrongEpoch)).rejects.toThrow(EpochMismatchError);

      // Separate cluster store
      const storeB = new PostgresConsensusStore({ pool, clusterId: "cluster-beta" });
      try {
        const e1B = buildEntry({
          epochId: "epoch-beta-1",
          appLogIndex: 1n,
          commandType: "EPOCH_INITIALIZE",
          payload: {
            epochId: "epoch-beta-1",
            epochHeight: 1,
            sequenceFloor: 5n,
            createdSeconds: 1700000000,
          },
          proposalId: "prop-beta-1",
        });
        await storeB.applyEntry(e1B);

        expect(store.getAuthoritativeState().clusterId).toBe("cluster-alpha");
        expect(storeB.getAuthoritativeState().clusterId).toBe("cluster-beta");
        expect(await store.getRaftState("epoch-beta-1")).toBeNull();
        expect(await storeB.getRaftState("epoch-iso-1")).toBeNull();
      } finally {
        await storeB.close();
      }
    });

    // ------------------------------------------------------------------------
    // Two-Phase Publication Tests
    // ------------------------------------------------------------------------
    it("never publishes candidate state before COMMIT and recovers deterministically on crash after COMMIT", async () => {
      const e1 = buildEntry({
        epochId: "epoch-2pc",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "epoch-2pc",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-2pc-1",
      });
      await store.applyEntry(e1);

      const e2 = buildEntry({
        epochId: "epoch-2pc",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-2pc", revision: 1, policyHash: "h2pc" },
        proposalId: "prop-2pc-2",
      });

      // Simulate process crash strictly AFTER PostgreSQL COMMIT and BEFORE in-memory publication
      await expect(
        store.applyEntry(e2, {
          onAfterCommitBeforePublish: () => {
            throw new Error("SIMULATED_CRASH_AFTER_COMMIT_BEFORE_PUBLISH");
          },
        })
      ).rejects.toThrow("SIMULATED_CRASH_AFTER_COMMIT_BEFORE_PUBLISH");

      // Crashed instance did NOT publish index 2 in memory
      expect(store.getAuthoritativeState().lastAppliedAppIndex).toBe(1n);

      // Attempting to apply index 3 on stale store fails closed
      const e3 = buildEntry({
        epochId: "epoch-2pc",
        appLogIndex: 3n,
        commandType: "DELEGATION_REVOKE",
        payload: {
          epochId: "epoch-2pc",
          authorizationId: "auth-1",
          revokedAtSeconds: 1700000010,
        } satisfies DelegationRevokePayload,
        proposalId: "prop-2pc-3",
      });
      await expect(store.applyEntry(e3)).rejects.toThrow(StaleAuthoritativeStateError);

      // Restarted store recovers deterministically from PostgreSQL
      const recoveredStore = new PostgresConsensusStore({ pool, clusterId: "cluster-alpha" });
      try {
        const recovered = await recoveredStore.recover("epoch-2pc");
        expect(recovered.lastAppliedAppIndex).toBe(2n);
        expect(recovered.lastConsecutivePersistedAppIndex).toBe(2n);
        expect(recovered.policies.get("pol-2pc")?.policyHash).toBe("h2pc");

        // Retry of e2 does not duplicate committed application
        const retryRes = await recoveredStore.applyEntry(e2);
        expect(retryRes.status).toBe("ALREADY_APPLIED");
        expect(retryRes.committedToDatabase).toBe(false);
      } finally {
        await recoveredStore.close();
      }
    });

    // ------------------------------------------------------------------------
    // Replay, Recovery & Tier-2 Verification Tests
    // ------------------------------------------------------------------------
    it("recovers empty epoch cleanly", async () => {
      const state = await store.recover("epoch-empty");
      expect(state.epochState).toBe("INITIAL");
      expect(state.lastAppliedAppIndex).toBe(0n);
      expect(state.lastConsecutivePersistedAppIndex).toBe(0n);
    });

    it("replays mixed Canon-v1 and TTCF-v1 (v2) contiguous history with bigint payload fields", async () => {
      const e1 = buildEntry({
        epochId: "epoch-mixed",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "epoch-mixed",
          epochHeight: 1,
          sequenceFloor: 100n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-m-1",
        canonicalizationVersion: 1,
      });
      const e2 = buildEntry({
        epochId: "epoch-mixed",
        appLogIndex: 2n,
        commandType: "TICKET_COMMIT",
        payload: {
          ticketId: "t-1",
          epochId: "epoch-mixed",
          authorizationId: "auth-1",
          bindingDigest: "sha256:bd1",
          policyId: "pol-1",
          policyRevision: 1,
          debitedAmount: 500n,
          budgetWindows: [
            { windowType: "DAILY", windowStart: 1700000000, cumulativeSpentAfter: 500n },
          ],
        } satisfies TicketCommitPayload,
        proposalId: "prop-m-2",
        canonicalizationVersion: 2,
      });
      const e3 = buildEntry({
        epochId: "epoch-mixed",
        appLogIndex: 3n,
        commandType: "EPOCH_QUARANTINE",
        payload: {
          epochId: "epoch-mixed",
          reason: "AUDIT_HOLD",
          quarantinedAtSeconds: 1700000010,
        } satisfies EpochQuarantinePayload,
        proposalId: "prop-m-3",
        canonicalizationVersion: 2,
      });

      await store.applyEntry(e1);
      await store.applyEntry(e2);
      const finalRes = await store.applyEntry(e3);

      const restarted = new PostgresConsensusStore({ pool, clusterId: "cluster-alpha" });
      try {
        const recovered = await restarted.recover("epoch-mixed");
        expect(recovered.lastAppliedAppIndex).toBe(3n);
        expect(recovered.chainHeadHash).toBe(finalRes.chainHeadHash);
        expect(recovered.epochState).toBe("QUARANTINED");
        expect(recovered.lastSequenceNumber).toBe(101n);
        expect(recovered.committedTickets.get("t-1")?.debitedAmount).toBe(500n);
      } finally {
        await restarted.close();
      }
    });

    it("fails closed on missing log index gap or tampered hash during replay", async () => {
      const e1 = buildEntry({
        epochId: "epoch-corrupt",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "epoch-corrupt",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-c-1",
      });
      const e2 = buildEntry({
        epochId: "epoch-corrupt",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-1", revision: 1, policyHash: "h1" },
        proposalId: "prop-c-2",
      });
      const e3 = buildEntry({
        epochId: "epoch-corrupt",
        appLogIndex: 3n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-1", revision: 2, policyHash: "h2" },
        proposalId: "prop-c-3",
      });

      await store.applyEntry(e1);
      await store.applyEntry(e2);
      await store.applyEntry(e3);

      // Delete row 2 via trigger disable to simulate missing durable record (gap)
      await pool.query(
        `ALTER TABLE witness_consensus_log DISABLE TRIGGER trg_witness_consensus_log_immutable;
         DELETE FROM witness_consensus_log WHERE epoch_id = 'epoch-corrupt' AND log_index = 2;
         ALTER TABLE witness_consensus_log ENABLE TRIGGER trg_witness_consensus_log_immutable;`
      );

      const restarted = new PostgresConsensusStore({ pool, clusterId: "cluster-alpha" });
      try {
        await expect(restarted.recover("epoch-corrupt")).rejects.toThrow(
          UnverifiableHistoricalEntryError
        );
      } finally {
        await restarted.close();
      }
    });

    it("fails closed when witness_raft_state.last_applied_hash disagrees with replayed chainHeadHash", async () => {
      const e1 = buildEntry({
        epochId: "epoch-hash-bad",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "epoch-hash-bad",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-hb-1",
      });
      await store.applyEntry(e1);

      await pool.query(
        `UPDATE witness_raft_state
         SET last_applied_hash = 'deadbeef'
         WHERE cluster_id = 'cluster-alpha' AND epoch_id = 'epoch-hash-bad'`
      );

      const restarted = new PostgresConsensusStore({ pool, clusterId: "cluster-alpha" });
      try {
        await expect(restarted.recover("epoch-hash-bad")).rejects.toThrow(ReplayVerificationError);
      } finally {
        await restarted.close();
      }
    });

    it("verifies pruned historical records via Tier-2 PostgreSQL lookup and rejects missing/conflicting Tier-2 records", async () => {
      const boundedStore = new PostgresConsensusStore({
        pool,
        clusterId: "cluster-alpha",
        memoryRetentionWindow: 2n,
      });

      try {
        const e1 = buildEntry({
          epochId: "epoch-tier2",
          appLogIndex: 1n,
          commandType: "EPOCH_INITIALIZE",
          payload: {
            epochId: "epoch-tier2",
            epochHeight: 1,
            sequenceFloor: 0n,
            createdSeconds: 1700000000,
          },
          proposalId: "prop-t2-1",
        });
        const e2 = buildEntry({
          epochId: "epoch-tier2",
          appLogIndex: 2n,
          commandType: "POLICY_UPDATE",
          payload: { policyId: "p1", revision: 1, policyHash: "h1" },
          proposalId: "prop-t2-2",
        });
        const e3 = buildEntry({
          epochId: "epoch-tier2",
          appLogIndex: 3n,
          commandType: "POLICY_UPDATE",
          payload: { policyId: "p1", revision: 2, policyHash: "h2" },
          proposalId: "prop-t2-3",
        });
        const e4 = buildEntry({
          epochId: "epoch-tier2",
          appLogIndex: 4n,
          commandType: "POLICY_UPDATE",
          payload: { policyId: "p1", revision: 3, policyHash: "h3" },
          proposalId: "prop-t2-4",
        });

        await boundedStore.applyEntry(e1);
        await boundedStore.applyEntry(e2);
        await boundedStore.applyEntry(e3);
        await boundedStore.applyEntry(e4);

        // With W_mem = 2 and A_app = 4, F_ret = 3. Index 1 is pruned from memory.
        expect(boundedStore.getAuthoritativeState().retentionFloorIndex).toBe(3n);
        expect(boundedStore.getAuthoritativeState().appliedIndices.has(1n)).toBe(false);

        // Replaying e1 succeeds via Tier-2 PostgreSQL verification
        const t2Res = await boundedStore.applyEntry(e1);
        expect(t2Res.status).toBe("ALREADY_APPLIED");
        expect(t2Res.verifiedViaTier2).toBe(true);

        // Replaying e1 with wrong proposalId fails closed via Tier-2
        const tampered = { ...e1, proposalId: "prop-t2-TAMPERED" };
        await expect(boundedStore.applyEntry(tampered)).rejects.toThrow(
          HistoricalIndexConflictError
        );

        // Delete row 1 from PostgreSQL -> Tier-2 fails closed with UnverifiableHistoricalEntryError
        await pool.query(
          `ALTER TABLE witness_consensus_log DISABLE TRIGGER trg_witness_consensus_log_immutable;
           DELETE FROM witness_consensus_log WHERE epoch_id = 'epoch-tier2' AND log_index = 1;
           ALTER TABLE witness_consensus_log ENABLE TRIGGER trg_witness_consensus_log_immutable;`
        );
        await expect(boundedStore.applyEntry(e1)).rejects.toThrow(
          UnverifiableHistoricalEntryError
        );
      } finally {
        await boundedStore.close();
      }
    });

    it("falls back to genesis when committed snapshot in witness_snapshots fails verification", async () => {
      const e1 = buildEntry({
        epochId: "epoch-snap-fb",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "epoch-snap-fb",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-sf-1",
      });
      await store.applyEntry(e1);

      await pool.query(
        `INSERT INTO witness_snapshots (
           snapshot_id, cluster_id, epoch_id, snapshot_index, snapshot_hash,
           chain_head_hash, etcd_revision, sub_index, format_version,
           canonicalization_version, storage_backend, storage_uri, byte_size,
           created_at_seconds, status
         ) VALUES (
           'snap-corrupt-1', 'cluster-alpha', 'epoch-snap-fb', 1, 'corrupthash',
           $1, 10, 0, 1, 2, 'posix_fs', '/tmp/corrupt.snap', 123, 1700000001, 'COMMITTED'
         )`,
        [store.getAuthoritativeState().chainHeadHash]
      );

      const corruptLoader: ConsensusSnapshotLoader = {
        loadAndVerify: async () => null,
      };

      const restarted = new PostgresConsensusStore({ pool, clusterId: "cluster-alpha" });
      try {
        const recovered = await restarted.recover("epoch-snap-fb", {
          snapshotLoader: corruptLoader,
        });
        expect(recovered.lastAppliedAppIndex).toBe(1n);
        expect(recovered.epochId).toBe("epoch-snap-fb");
      } finally {
        await restarted.close();
      }
    });

    it("rejects watermark regression and integrates BackpressurePolicy evaluation", async () => {
      const e1 = buildEntry({
        epochId: "epoch-bp",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "epoch-bp",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-bp-1",
      });
      await store.applyEntry(e1);

      // Simulate DB watermark regression below in-memory watermark
      await pool.query(
        `UPDATE witness_raft_state
         SET last_consecutive_persisted_index = 0
         WHERE cluster_id = 'cluster-alpha' AND epoch_id = 'epoch-bp'`
      );
      const e2 = buildEntry({
        epochId: "epoch-bp",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "p1", revision: 1, policyHash: "h1" },
        proposalId: "prop-bp-2",
      });
      await expect(store.applyEntry(e2)).rejects.toThrow(StateMachineError);

      // Evaluate backpressure using store helper
      const bpEval = store.evaluateBackpressure("STREAMING");
      expect(bpEval.streamState).toBe("STREAMING");
      expect(bpEval.persistenceLag).toBe(0n);
      expect(bpEval.action).toBe("CONTINUE");
    });

    it("fails closed on empty raft state when orphaned consensus log rows exist", async () => {
      const p1 = {
        epochId: "epoch-orphan",
        epochHeight: 1,
        sequenceFloor: 0n,
        createdSeconds: 1700000000,
      };
      await pool.query(
        `INSERT INTO witness_consensus_log (epoch_id, log_index, term, etcd_revision, payload_type, payload, payload_hash, proposal_id, committed_at_seconds, canonicalization_version, sub_index)
         VALUES ('epoch-orphan', 1, 1, 10, 'EPOCH_INITIALIZE', $1::jsonb, $2, 'prop-orphan', 1700000001, 2, 0)`,
        [
          JSON.stringify(p1, (_k, v) => (typeof v === "bigint" ? v.toString() : v)),
          computeCanonicalPayloadHash(p1, 2),
        ]
      );

      await expect(store.recover("epoch-orphan")).rejects.toThrow(
        UnverifiableDurableHistoryError
      );
    });

    // ------------------------------------------------------------------------
    // F-STEP4-01: Multi-Epoch EPOCH_ADVANCE Watermark Continuity & Recovery
    // ------------------------------------------------------------------------
    it("F-STEP4-01: supports EPOCH_ADVANCE, first entry in new epoch, multiple advances, cross-epoch isolation, and full recovery", async () => {
      const e1 = buildEntry({
        epochId: "ep-1",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "ep-1",
          epochHeight: 1,
          sequenceFloor: 10n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-ea-1",
      });
      const r1 = await store.applyEntry(e1);

      // Advance ep-1 -> ep-2
      const e2 = buildEntry({
        epochId: "ep-1",
        appLogIndex: 2n,
        commandType: "EPOCH_ADVANCE",
        payload: {
          fromEpochId: "ep-1",
          toEpochId: "ep-2",
          newHeight: 2,
          priorChainHeadHash: r1.chainHeadHash,
          advancedAtSeconds: 1700000005,
        } satisfies EpochAdvancePayload,
        proposalId: "prop-ea-2",
      });
      const r2 = await store.applyEntry(e2);
      expect(r2.state.epochId).toBe("ep-2");
      expect(r2.state.epochHeight).toBe(2);
      expect(r2.state.lastConsecutivePersistedAppIndex).toBe(2n);

      // First entry in ep-2 must succeed without PERSISTENCE_WATERMARK_REGRESSION
      const e3 = buildEntry({
        epochId: "ep-2",
        appLogIndex: 3n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-ep2", revision: 1, policyHash: "hep2" },
        proposalId: "prop-ea-3",
      });
      const r3 = await store.applyEntry(e3);
      expect(r3.status).toBe("APPLIED");
      expect(r3.appliedAppIndex).toBe(3n);

      // Delayed/conflicting entry from sealed ep-1 rejected with EpochMismatchError
      const staleEp1 = buildEntry({
        epochId: "ep-1",
        appLogIndex: 4n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-old", revision: 1, policyHash: "hold" },
        proposalId: "prop-ea-stale",
      });
      await expect(store.applyEntry(staleEp1)).rejects.toThrow(EpochMismatchError);

      // Second consecutive epoch advance ep-2 -> ep-3
      const e4 = buildEntry({
        epochId: "ep-2",
        appLogIndex: 4n,
        commandType: "EPOCH_ADVANCE",
        payload: {
          fromEpochId: "ep-2",
          toEpochId: "ep-3",
          newHeight: 3,
          priorChainHeadHash: r3.chainHeadHash,
          advancedAtSeconds: 1700000010,
        } satisfies EpochAdvancePayload,
        proposalId: "prop-ea-4",
      });
      const r4 = await store.applyEntry(e4);
      expect(r4.state.epochId).toBe("ep-3");
      expect(r4.state.epochHeight).toBe(3);

      // Recover ep-3 right after EPOCH_ADVANCE (0 rows in ep-3 log, watermark at 4)
      const restarted = new PostgresConsensusStore({ pool, clusterId: "cluster-alpha" });
      try {
        const rec3 = await restarted.recover("ep-3");
        expect(rec3.epochId).toBe("ep-3");
        expect(rec3.epochHeight).toBe(3);
        expect(rec3.lastAppliedAppIndex).toBe(4n);
        expect(rec3.lastConsecutivePersistedAppIndex).toBe(4n);
        expect(rec3.chainHeadHash).toBe(r4.chainHeadHash);
        expect(rec3.policies.get("pol-ep2")?.policyHash).toBe("hep2");

        // Watermark regression within ep-3 fails closed
        await pool.query(
          `UPDATE witness_raft_state
           SET last_consecutive_persisted_index = 1
           WHERE cluster_id = 'cluster-alpha' AND epoch_id = 'ep-3'`
        );
        const e5 = buildEntry({
          epochId: "ep-3",
          appLogIndex: 5n,
          commandType: "POLICY_UPDATE",
          payload: { policyId: "pol-ep3", revision: 1, policyHash: "hep3" },
          proposalId: "prop-ea-5",
        });
        await expect(restarted.applyEntry(e5)).rejects.toThrow(StateMachineError);
      } finally {
        await restarted.close();
      }
    });

    it("F-STEP4-01: recovers deterministically after crash following EPOCH_ADVANCE commit before in-memory publication", async () => {
      const e1 = buildEntry({
        epochId: "ep-crash-1",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "ep-crash-1",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-ec-1",
      });
      const r1 = await store.applyEntry(e1);

      const e2 = buildEntry({
        epochId: "ep-crash-1",
        appLogIndex: 2n,
        commandType: "EPOCH_ADVANCE",
        payload: {
          fromEpochId: "ep-crash-1",
          toEpochId: "ep-crash-2",
          newHeight: 2,
          priorChainHeadHash: r1.chainHeadHash,
          advancedAtSeconds: 1700000005,
        } satisfies EpochAdvancePayload,
        proposalId: "prop-ec-2",
      });

      await expect(
        store.applyEntry(e2, {
          onAfterCommitBeforePublish: () => {
            throw new Error("CRASH_AFTER_EPOCH_ADVANCE_COMMIT");
          },
        })
      ).rejects.toThrow("CRASH_AFTER_EPOCH_ADVANCE_COMMIT");

      expect(store.getAuthoritativeState().epochId).toBe("ep-crash-1");
      expect(store.getAuthoritativeState().lastAppliedAppIndex).toBe(1n);

      const restarted = new PostgresConsensusStore({ pool, clusterId: "cluster-alpha" });
      try {
        const rec = await restarted.recover("ep-crash-2");
        expect(rec.epochId).toBe("ep-crash-2");
        expect(rec.epochHeight).toBe(2);
        expect(rec.lastAppliedAppIndex).toBe(2n);
      } finally {
        await restarted.close();
      }
    });

    // ------------------------------------------------------------------------
    // F-STEP4-02: In-Process Async Serialization (Mutex)
    // ------------------------------------------------------------------------
    it("F-STEP4-02: serializes simultaneous sequential appends and concurrent EPOCH_ADVANCE cleanly without StaleAuthoritativeStateError", async () => {
      const e1 = buildEntry({
        epochId: "ep-mtx",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "ep-mtx",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-mtx-1",
      });
      const r1 = await store.applyEntry(e1);

      const e2 = buildEntry({
        epochId: "ep-mtx",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "p-mtx", revision: 1, policyHash: "hm1" },
        proposalId: "prop-mtx-2",
      });
      const e3 = buildEntry({
        epochId: "ep-mtx",
        appLogIndex: 3n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "p-mtx", revision: 2, policyHash: "hm2" },
        proposalId: "prop-mtx-3",
      });

      // Fire 2 simultaneous sequential appends -> FIFO mutex serializes them so both succeed
      const [res2, res3] = await Promise.all([store.applyEntry(e2), store.applyEntry(e3)]);
      expect(res2.status).toBe("APPLIED");
      expect(res3.status).toBe("APPLIED");
      expect(store.getAuthoritativeState().lastAppliedAppIndex).toBe(3n);

      // Concurrent EPOCH_ADVANCE + post-advance entry
      const e4 = buildEntry({
        epochId: "ep-mtx",
        appLogIndex: 4n,
        commandType: "EPOCH_ADVANCE",
        payload: {
          fromEpochId: "ep-mtx",
          toEpochId: "ep-mtx-2",
          newHeight: 2,
          priorChainHeadHash: res3.chainHeadHash,
          advancedAtSeconds: 1700000010,
        } satisfies EpochAdvancePayload,
        proposalId: "prop-mtx-4",
      });
      const e5 = buildEntry({
        epochId: "ep-mtx-2",
        appLogIndex: 5n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "p-mtx-2", revision: 1, policyHash: "hm3" },
        proposalId: "prop-mtx-5",
      });
      const [res4, res5] = await Promise.all([store.applyEntry(e4), store.applyEntry(e5)]);
      expect(res4.status).toBe("APPLIED");
      expect(res5.status).toBe("APPLIED");
      expect(store.getAuthoritativeState().epochId).toBe("ep-mtx-2");
      expect(store.getAuthoritativeState().lastAppliedAppIndex).toBe(5n);
      expect(r1.appliedAppIndex).toBe(1n);
    });

    it("F-STEP4-02: failed/rolled-back first queued operation releases mutex and does not block subsequent operations", async () => {
      const e1 = buildEntry({
        epochId: "ep-mtx-err",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "ep-mtx-err",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-me-1",
      });
      await store.applyEntry(e1);

      // First queued operation fails (gap at index 5)
      const badGap = buildEntry({
        epochId: "ep-mtx-err",
        appLogIndex: 5n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "p1", revision: 1, policyHash: "h1" },
        proposalId: "prop-me-gap",
      });
      // Second queued operation is valid (index 2)
      const validNext = buildEntry({
        epochId: "ep-mtx-err",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "p1", revision: 1, policyHash: "h1" },
        proposalId: "prop-me-2",
      });

      const [rBad, rGood] = await Promise.allSettled([
        store.applyEntry(badGap),
        store.applyEntry(validNext),
      ]);
      expect(rBad.status).toBe("rejected");
      expect(rGood.status).toBe("fulfilled");
      expect(store.getAuthoritativeState().lastAppliedAppIndex).toBe(2n);
    });

    it("F-STEP4-02 & F-STEP4-03: close() drains active work, rejects queued/subsequent calls with STORE_CLOSED", async () => {
      const e1 = buildEntry({
        epochId: "ep-close",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "ep-close",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-cl-1",
      });

      // Start first op and allow it to enter the mutex & begin DB work, queue second op, then close()
      const p1 = store.applyEntry(e1);
      await new Promise((r) => setTimeout(r, 5));
      const e2 = buildEntry({
        epochId: "ep-close",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "p1", revision: 1, policyHash: "h1" },
        proposalId: "prop-cl-2",
      });
      const p2 = store.applyEntry(e2);
      const pClose = store.close();

      const [r1, r2] = await Promise.allSettled([p1, p2]);
      await pClose;

      expect(r1.status).toBe("fulfilled");
      expect(r2.status).toBe("rejected");
      if (r2.status === "rejected") {
        expect(r2.reason).toBeInstanceOf(ConsensusStoreError);
        expect((r2.reason as ConsensusStoreError).code).toBe("STORE_CLOSED");
      }

      await expect(store.applyEntry(e2)).rejects.toMatchObject({ code: "STORE_CLOSED" });
      await expect(store.recover("ep-close")).rejects.toMatchObject({ code: "STORE_CLOSED" });
      await expect(store.getRaftState("ep-close")).rejects.toMatchObject({ code: "STORE_CLOSED" });
    });

    // ------------------------------------------------------------------------
    // F-STEP4-03: Snapshot Hit & Real PostgreSQL statementTimeoutMs
    // ------------------------------------------------------------------------
    it("F-STEP4-03: recovers from a valid ConsensusSnapshotLoader hit and replays only suffix entries", async () => {
      const e1 = buildEntry({
        epochId: "ep-snap-hit",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "ep-snap-hit",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-sh-1",
      });
      const e2 = buildEntry({
        epochId: "ep-snap-hit",
        appLogIndex: 2n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-sh", revision: 1, policyHash: "hsh1" },
        proposalId: "prop-sh-2",
      });
      const r2 = await store.applyEntry(e2 === e2 ? (await store.applyEntry(e1), e2) : e2);

      const e3 = buildEntry({
        epochId: "ep-snap-hit",
        appLogIndex: 3n,
        commandType: "POLICY_UPDATE",
        payload: { policyId: "pol-sh", revision: 2, policyHash: "hsh2" },
        proposalId: "prop-sh-3",
      });
      const r3 = await store.applyEntry(e3);

      await pool.query(
        `INSERT INTO witness_snapshots (
           snapshot_id, cluster_id, epoch_id, snapshot_index, snapshot_hash,
           chain_head_hash, etcd_revision, sub_index, format_version,
           canonicalization_version, storage_backend, storage_uri, byte_size,
           created_at_seconds, status
         ) VALUES (
           'snap-valid-2', 'cluster-alpha', 'ep-snap-hit', 2, 'validhash2',
           $1, 20, 0, 1, 2, 'posix_fs', '/tmp/valid2.snap', 256, 1700000002, 'COMMITTED'
         )`,
        [r2.chainHeadHash]
      );

      let loaderCalled = false;
      const validLoader: ConsensusSnapshotLoader = {
        loadAndVerify: async (record) => {
          loaderCalled = true;
          expect(record.snapshotId).toBe("snap-valid-2");
          return r2.state;
        },
      };

      const restarted = new PostgresConsensusStore({ pool, clusterId: "cluster-alpha" });
      try {
        const recovered = await restarted.recover("ep-snap-hit", {
          snapshotLoader: validLoader,
        });
        expect(loaderCalled).toBe(true);
        expect(recovered.lastAppliedAppIndex).toBe(3n);
        expect(recovered.chainHeadHash).toBe(r3.chainHeadHash);
        expect(recovered.policies.get("pol-sh")?.revision).toBe(2);
      } finally {
        await restarted.close();
      }
    });

    it("F-STEP4-03: enforces statementTimeoutMs against PostgreSQL lock contention and rolls back cleanly", async () => {
      const e1 = buildEntry({
        epochId: "ep-timeout",
        appLogIndex: 1n,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "ep-timeout",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "prop-to-1",
      });
      await store.applyEntry(e1);

      const blockerClient = await pool.connect();
      const timeoutStore = new PostgresConsensusStore({
        pool,
        clusterId: "cluster-alpha",
        statementTimeoutMs: 150,
      });
      await timeoutStore.recover("ep-timeout");

      try {
        await blockerClient.query("BEGIN");
        await blockerClient.query(
          `SELECT * FROM witness_raft_state WHERE cluster_id = 'cluster-alpha' AND epoch_id = 'ep-timeout' FOR UPDATE`
        );

        const e2 = buildEntry({
          epochId: "ep-timeout",
          appLogIndex: 2n,
          commandType: "POLICY_UPDATE",
          payload: { policyId: "p-to", revision: 1, policyHash: "hto" },
          proposalId: "prop-to-2",
        });

        await expect(timeoutStore.applyEntry(e2)).rejects.toThrow(/statement timeout/i);
        expect(timeoutStore.getAuthoritativeState().lastAppliedAppIndex).toBe(1n);
      } finally {
        await blockerClient.query("ROLLBACK");
        blockerClient.release();
        await timeoutStore.close();
      }
    });
  });
});
