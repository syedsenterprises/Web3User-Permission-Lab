/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.2 (Step 6)
 * CompactionCoordinator Unit & PostgreSQL 16 Fault-Injected Integration Suite
 * (Real etcd v3.5.18 integration runs in compaction-coordinator.real.test.ts)
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import pg from "pg";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CompactionCoordinator,
  CompactionConfigurationError,
  CompactionExecutionError,
  CompactionSafetyError,
  CompactionError,
  calculateCompactionEligibility,
  calculateDimensionalSafetyBuffer,
  type EtcdCompactionClient,
} from "../../src/witness/compaction-coordinator.js";
import {
  SnapshotManager,
  PosixSnapshotStorageBackend,
} from "../../src/witness/snapshot-manager.js";
import { PostgresConsensusStore } from "../../src/witness/consensus-store.js";
import { type CommittedConsensusEntry } from "../../src/witness/state-machine-types.js";
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

function buildEntry<T extends CommittedConsensusEntry["commandType"]>(params: {
  epochId: string;
  appLogIndex: bigint;
  etcdRevision: bigint;
  subIndex?: number;
  commandType: T;
  payload: CommittedConsensusEntry<T>["payload"];
  proposalId: string;
}): CommittedConsensusEntry<T> {
  return {
    epochId: params.epochId,
    appLogIndex: params.appLogIndex,
    raftTerm: 1n,
    physicalCursor: {
      etcdRevision: params.etcdRevision,
      subIndex: params.subIndex ?? 0,
    },
    commandType: params.commandType,
    payload: params.payload,
    payloadHash: computeCanonicalPayloadHash(params.payload, 2),
    proposalId: params.proposalId,
    committedAtSeconds: 1_700_000_000 + Number(params.appLogIndex),
    canonicalizationVersion: 2,
  };
}

describe("Milestone 13-D Stage 2-B.2 Step 6: CompactionCoordinator Suite", () => {
  // ==========================================================================
  // 1. Pure Eligibility & Dimensional Buffer Unit Tests
  // ==========================================================================
  describe("1. Pure Eligibility & Dimensional Buffer", () => {
    it("enforces R_comp <= min(R_snap, R_pg_persisted) - Delta_buffer across all boundary cases", () => {
      // Snapshot below PG persisted
      const r1 = calculateCompactionEligibility({
        snapshotRevision: 5_000n,
        pgPersistedRevision: 8_000n,
        safetyBuffer: 1_000n,
        alreadyCompactedRevision: 0n,
      });
      expect(r1.eligible).toBe(true);
      expect(r1.safeBoundary).toBe(4_000n);
      expect(r1.candidateRevision).toBe(4_000n);

      // PG persisted below snapshot
      const r2 = calculateCompactionEligibility({
        snapshotRevision: 9_000n,
        pgPersistedRevision: 6_500n,
        safetyBuffer: 1_000n,
        alreadyCompactedRevision: 0n,
      });
      expect(r2.eligible).toBe(true);
      expect(r2.candidateRevision).toBe(5_500n);

      // maxRevisionAdvancePerOp cap
      const rCap = calculateCompactionEligibility({
        snapshotRevision: 10_000n,
        pgPersistedRevision: 10_000n,
        safetyBuffer: 1_000n,
        alreadyCompactedRevision: 2_000n,
        maxRevisionAdvancePerOp: 1_500n,
      });
      expect(rCap.eligible).toBe(true);
      expect(rCap.safeBoundary).toBe(9_000n);
      expect(rCap.candidateRevision).toBe(3_500n);

      // Underflow / below safety buffer
      const rUnderflow = calculateCompactionEligibility({
        snapshotRevision: 1_000n,
        pgPersistedRevision: 5_000n,
        safetyBuffer: 1_000n,
        alreadyCompactedRevision: 0n,
      });
      expect(rUnderflow.eligible).toBe(false);
      expect(rUnderflow.reason).toBe("BELOW_SAFETY_BUFFER");

      // Missing / zero / already compacted
      expect(
        calculateCompactionEligibility({
          snapshotRevision: null,
          pgPersistedRevision: 5_000n,
          safetyBuffer: 1_000n,
          alreadyCompactedRevision: 0n,
        }).eligible
      ).toBe(false);
      expect(
        calculateCompactionEligibility({
          snapshotRevision: 0n,
          pgPersistedRevision: 5_000n,
          safetyBuffer: 1_000n,
          alreadyCompactedRevision: 0n,
        }).reason
      ).toBe("NON_POSITIVE_DURABLE_REVISION");
      expect(
        calculateCompactionEligibility({
          snapshotRevision: 5_000n,
          pgPersistedRevision: 5_000n,
          safetyBuffer: 1_000n,
          alreadyCompactedRevision: 4_000n,
        }).reason
      ).toBe("ALREADY_COMPACTED_OR_NO_PROGRESS");

      // 64-bit BigInt beyond MAX_SAFE_INTEGER
      const high64 = 9_007_199_254_745_000n;
      const r64 = calculateCompactionEligibility({
        snapshotRevision: high64,
        pgPersistedRevision: high64 + 500n,
        safetyBuffer: 1_000n,
        alreadyCompactedRevision: 0n,
      });
      expect(r64.eligible).toBe(true);
      expect(r64.candidateRevision).toBe(high64 - 1_000n);

      // Invalid negative / zero buffer
      expect(() =>
        calculateCompactionEligibility({
          snapshotRevision: 5_000n,
          pgPersistedRevision: 5_000n,
          safetyBuffer: 0n,
          alreadyCompactedRevision: 0n,
        })
      ).toThrow(CompactionSafetyError);
    });

    it("calculates dimensional safety buffer from telemetry bounds and rejects invalid inputs", () => {
      expect(
        calculateDimensionalSafetyBuffer({
          revisionRateP99PerSecond: 100,
          reconnectP99Seconds: 15,
        })
      ).toBe(3_000n); // 2.0 * 100 * 15

      expect(
        calculateDimensionalSafetyBuffer({
          revisionRateP99PerSecond: 1,
          reconnectP99Seconds: 5,
        })
      ).toBe(1_000n); // clamped to min 1000n

      expect(() =>
        calculateDimensionalSafetyBuffer({
          revisionRateP99PerSecond: -1,
          reconnectP99Seconds: 5,
        })
      ).toThrow(CompactionConfigurationError);
    });
  });

  // ==========================================================================
  // 2. PostgreSQL 16 + SnapshotManager + Fault-Injected etcd Tests
  // ==========================================================================
  describe("2. PostgreSQL 16 + SnapshotManager + Fault Injection", () => {
    let adminPool: pg.Pool;
    let pool: pg.Pool;
    let dbName: string;
    let tmpDir: string;
    let snapshotManager: SnapshotManager;
    let store: PostgresConsensusStore;

    beforeAll(async () => {
      adminPool = createManagedTestPool({
        host: process.env.PGHOST || "127.0.0.1",
        port: Number(process.env.PGPORT || 5432),
        user: process.env.PGUSER || "postgres",
        password: process.env.PGPASSWORD || "postgres",
        database: "postgres",
      });
      dbName = `web3user_test_comp_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
      await adminPool.query(`CREATE DATABASE "${dbName}"`);
      pool = createManagedTestPool({
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
      if (adminPool && dbName) {
        await destroyDisposableTestDb({ adminPool, dbName, pool });
      }
      if (adminPool) await closeAdminTestPool(adminPool);
    });

    beforeEach(async () => {
      if (store) await store.close();
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "web3user-comp-"));
      snapshotManager = new SnapshotManager({
        pool,
        storageBackend: new PosixSnapshotStorageBackend(tmpDir),
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

    it("disables automatic compaction by default and gates enablement on operationalBaselineVerified", async () => {
      const mockEtcd: EtcdCompactionClient = {
        getStatus: async () => ({ currentRevision: 5_000n }),
        compact: async () => ({ compacted: true, alreadyCompacted: false }),
      };

      expect(
        () =>
          new CompactionCoordinator({
            pool,
            snapshotManager,
            etcdClient: mockEtcd,
            config: {
              clusterId: "cluster-alpha",
              epochId: "ep-cfg",
              automaticCompactionEnabled: true,
              operationalBaselineVerified: false,
            },
          })
      ).toThrow(CompactionConfigurationError);

      const defaultCoord = new CompactionCoordinator({
        pool,
        snapshotManager,
        etcdClient: mockEtcd,
        config: { clusterId: "cluster-alpha", epochId: "ep-cfg" },
      });
      const autoRes = await defaultCoord.runAutomaticTick();
      expect(autoRes.status).toBe("AUTOMATIC_DISABLED");
      expect(defaultCoord.getMetrics().automaticCompactionEnabled).toBe(false);
    });

    it("rejects STAGED, DELETING, and corrupt snapshots, and protects unclosed multi-event tip revisions", async () => {
      const r1 = await store.applyEntry(
        buildEntry({
          epochId: "ep-safety",
          appLogIndex: 1n,
          etcdRevision: 5_000n,
          commandType: "EPOCH_INITIALIZE",
          payload: { epochId: "ep-safety", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
          proposalId: "p-s-1",
        })
      );
      const snap = await snapshotManager.createAndPublishSnapshot(r1.state);

      const compactedRevs: bigint[] = [];
      const mockEtcd: EtcdCompactionClient = {
        getStatus: async () => ({ currentRevision: 5_100n }),
        compact: async (rev) => {
          compactedRevs.push(rev);
          return { compacted: true, alreadyCompacted: false };
        },
      };

      const coord = new CompactionCoordinator({
        pool,
        snapshotManager,
        etcdClient: mockEtcd,
        config: {
          clusterId: "cluster-alpha",
          epochId: "ep-safety",
          safetyBuffer: 1_000n,
          lagWarningThreshold: 500n,
        },
      });

      // Tip revision 5000n unconfirmed -> conservatively R_pg = 4999n -> candidate 3999n
      const resTip = await coord.runManualCompaction();
      expect(resTip.status).toBe("COMPACTED");
      expect(resTip.compactedRevision).toBe(3_999n);
      expect(compactedRevs).toEqual([3_999n]);

      // Confirm 5000n complete -> R_pg = 5000n -> candidate 4000n
      const resConf = await coord.runManualCompaction({ confirmedCompleteRevision: 5_000n });
      expect(resConf.status).toBe("COMPACTED");
      expect(resConf.compactedRevision).toBe(4_000n);

      // Corrupt snapshot on disk -> NO_OP (never compacts!)
      fs.writeFileSync(snap.storageUri, Buffer.from("corrupt"));
      const resCorrupt = await coord.runManualCompaction({ confirmedCompleteRevision: 5_000n });
      expect(resCorrupt.status).toBe("NO_OP");
      expect(resCorrupt.eligibility?.snapshotRevision).toBeNull();

      // Transition snapshot to DELETING -> NO_OP
      await pool.query(`UPDATE witness_snapshots SET status = 'DELETING' WHERE snapshot_id = $1`, [
        snap.snapshotId,
      ]);
      const resDel = await coord.runManualCompaction({ confirmedCompleteRevision: 5_000n });
      expect(resDel.status).toBe("NO_OP");
    });

    it("handles timeouts, unavailable retries, already-compacted, and concurrent coordinator advisory locking", async () => {
      const r1 = await store.applyEntry(
        buildEntry({
          epochId: "ep-faults",
          appLogIndex: 1n,
          etcdRevision: 5_000n,
          commandType: "EPOCH_INITIALIZE",
          payload: { epochId: "ep-faults", epochHeight: 1, sequenceFloor: 0n, createdSeconds: 1700000000 },
          proposalId: "p-f-1",
        })
      );
      await snapshotManager.createAndPublishSnapshot(r1.state);

      let mode: "timeout" | "unavailable_then_ok" | "already_compacted" | "ok" = "timeout";
      let calls = 0;
      const mockEtcd: EtcdCompactionClient = {
        getStatus: async () => ({ currentRevision: 5_000n }),
        compact: async () => {
          calls += 1;
          if (mode === "timeout") {
            throw new CompactionExecutionError("timeout", "ETCD_TIMEOUT");
          }
          if (mode === "unavailable_then_ok" && calls < 2) {
            throw new CompactionExecutionError("unavailable", "ETCD_UNAVAILABLE");
          }
          if (mode === "already_compacted") {
            return { compacted: false, alreadyCompacted: true };
          }
          return { compacted: true, alreadyCompacted: false };
        },
      };

      const coord = new CompactionCoordinator({
        pool,
        snapshotManager,
        etcdClient: mockEtcd,
        config: {
          clusterId: "cluster-alpha",
          epochId: "ep-faults",
          safetyBuffer: 1_000n,
          maxRetries: 2,
          automaticCompactionEnabled: true,
          operationalBaselineVerified: true,
          minCompactionIntervalMs: 10_000,
        },
      });

      // Timeout fails closed without advancing lastSuccessfulCompactionRevision
      await expect(coord.runManualCompaction({ confirmedCompleteRevision: 5_000n })).rejects.toThrow(
        CompactionExecutionError
      );
      expect(coord.getMetrics().lastSuccessfulCompactionRevision).toBeNull();
      expect(coord.getMetrics().lastCompactionError).toContain("timeout");

      // Unavailable retries and succeeds
      mode = "unavailable_then_ok";
      calls = 0;
      const retryOk = await coord.runManualCompaction({ confirmedCompleteRevision: 5_000n });
      expect(retryOk.status).toBe("COMPACTED");
      expect(calls).toBe(2);
      expect(coord.getMetrics().lastSuccessfulCompactionRevision).toBe(4_000n);

      // Rate-limited automatic tick
      const rateLimited = await coord.runAutomaticTick({ nowMs: Date.now() });
      expect(rateLimited.status).toBe("RATE_LIMITED");

      // Already-compacted handling
      mode = "already_compacted";
      const alreadyRes = await coord.runManualCompaction({
        confirmedCompleteRevision: 5_000n,
        knownCompactedRevision: 0n,
      });
      expect(alreadyRes.status).toBe("ALREADY_COMPACTED");

      // Concurrent coordinator advisory lock contention
      const slowClient = await pool.connect();
      try {
        await slowClient.query(
          `SELECT pg_advisory_lock(hashtext($1), hashtext($2))`,
          ["compaction:cluster-alpha", "ep-faults"]
        );
        const contRes = await coord.runManualCompaction({ confirmedCompleteRevision: 5_000n });
        expect(contRes.status).toBe("LOCK_CONTENTION");
      } finally {
        await slowClient.query(
          `SELECT pg_advisory_unlock(hashtext($1), hashtext($2))`,
          ["compaction:cluster-alpha", "ep-faults"]
        );
        slowClient.release();
      }

      // Close rejects subsequent operations
      coord.close();
      await expect(coord.runManualCompaction()).rejects.toThrow(CompactionError);
    });
  });
});
