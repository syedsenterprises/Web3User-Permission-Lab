/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.2 (Step 6)
 * CompactionCoordinator Real etcd v3.5.18 + PostgreSQL 16 Integration Suite
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import pg from "pg";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Etcd3 } from "etcd3";
import {
  CompactionCoordinator,
  Etcd3CompactionClient,
} from "../../src/witness/compaction-coordinator.js";
import {
  SnapshotManager,
  PosixSnapshotStorageBackend,
} from "../../src/witness/snapshot-manager.js";
import { PostgresConsensusStore } from "../../src/witness/consensus-store.js";
import { EtcdClientAdapter, EtcdCompactedError } from "../../src/witness/etcd-client-adapter.js";
import { type CommittedConsensusEntry } from "../../src/witness/state-machine-types.js";
import { computeCanonicalPayloadHash } from "../../src/witness/state-machine.js";
import { RealEtcdProcess } from "./helpers/real-etcd-process.js";
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

describe("Milestone 13-D Stage 2-B.2 Step 6: CompactionCoordinator Real etcd v3.5.18 Suite", () => {
  // ==========================================================================
  // 3. Real etcd v3.5.18 + PostgreSQL 16.15 End-to-End Compaction Test
  // ==========================================================================
  describe("3. Real etcd v3.5.18 + PostgreSQL 16.15 Integration", () => {
    let realEtcd: RealEtcdProcess;
    let rawEtcd: Etcd3;
    let etcdAdapter: EtcdClientAdapter;
    let adminPool: pg.Pool;
    let pool: pg.Pool;
    let dbName: string;
    let tmpDir: string;

    beforeAll(async () => {
      realEtcd = new RealEtcdProcess({ name: "stage2b2-step6-compaction" });
      await realEtcd.start();
      rawEtcd = new Etcd3({ hosts: [realEtcd.grpcEndpoint] });
      etcdAdapter = new EtcdClientAdapter({
        endpoints: [realEtcd.grpcEndpoint],
        dialTimeoutMs: 3000,
        requestTimeoutMs: 5000,
      });
      await etcdAdapter.connect();

      adminPool = createManagedTestPool({
        host: process.env.PGHOST || "127.0.0.1",
        port: Number(process.env.PGPORT || 5432),
        user: process.env.PGUSER || "postgres",
        password: process.env.PGPASSWORD || "postgres",
        database: "postgres",
      });
      dbName = `web3user_test_comp_real_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
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
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "web3user-comp-real-"));
    }, 30_000);

    afterAll(async () => {
      await etcdAdapter?.close().catch(() => {});
      rawEtcd?.close();
      await realEtcd?.stop().catch(() => {});
      if (adminPool && dbName) {
        await destroyDisposableTestDb({ adminPool, dbName, pool });
      }
      if (adminPool) await closeAdminTestPool(adminPool);
    });

    it("compacts real etcd v3.5.18 safely based on verified PostgreSQL + POSIX snapshot", async () => {
      // Advance real etcd revisions to >= 15
      let tipRev = 1n;
      for (let i = 0; i < 15; i++) {
        const res = await etcdAdapter.put(`/step6/k/${i}`, `v-${i}`);
        tipRev = res.revision;
      }

      const store = new PostgresConsensusStore({ pool, clusterId: "cluster-alpha" });
      const snapMgr = new SnapshotManager({
        pool,
        storageBackend: new PosixSnapshotStorageBackend(tmpDir),
      });

      try {
        const r1 = await store.applyEntry(
          buildEntry({
            epochId: "ep-real-etcd",
            appLogIndex: 1n,
            etcdRevision: tipRev,
            commandType: "EPOCH_INITIALIZE",
            payload: {
              epochId: "ep-real-etcd",
              epochHeight: 1,
              sequenceFloor: 0n,
              createdSeconds: 1700000000,
            },
            proposalId: "p-re-1",
          })
        );
        await snapMgr.createAndPublishSnapshot(r1.state);

        const coord = new CompactionCoordinator({
          pool,
          snapshotManager: snapMgr,
          etcdClient: new Etcd3CompactionClient(rawEtcd),
          config: {
            clusterId: "cluster-alpha",
            epochId: "ep-real-etcd",
            safetyBuffer: 5n,
          },
        });

        const compRes = await coord.runManualCompaction({ confirmedCompleteRevision: tipRev });
        expect(compRes.status).toBe("COMPACTED");
        expect(compRes.compactedRevision).toBe(tipRev - 5n);
        expect(coord.getMetrics().lastSuccessfulCompactionRevision).toBe(tipRev - 5n);

        // Verify real etcd v3.5.18 rejects watch at revision 1n with EtcdCompactedError
        let compactedErr: EtcdCompactedError | null = null;
        const watcher = await etcdAdapter.watch(
          { prefix: "/step6/k/" },
          { startRevision: 1n },
          () => {},
          (err) => {
            if (err instanceof EtcdCompactedError) {
              compactedErr = err;
            }
          }
        );
        for (let i = 0; i < 30; i++) {
          if (compactedErr) break;
          await new Promise((r) => setTimeout(r, 100));
        }
        expect(compactedErr).toBeInstanceOf(EtcdCompactedError);
        await watcher.close();
      } finally {
        await store.close();
      }
    }, 20_000);
  });
});
