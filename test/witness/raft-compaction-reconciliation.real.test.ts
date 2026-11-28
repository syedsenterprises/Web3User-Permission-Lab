/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.3
 * Three-Node etcd v3.5.18 Compaction Reconciliation Under Ambiguous Responses & Leader Failover
 */

import { describe, it, expect, afterEach } from "vitest";
import pg from "pg";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Etcd3 } from "etcd3";
import {
  CompactionCoordinator,
  CompactionExecutionError,
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
import { RealEtcdCluster } from "./helpers/real-etcd-cluster.js";
import { LoopbackFaultProxy } from "./helpers/loopback-fault-proxy.js";
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

async function createIsolatedPgEnv(): Promise<{
  adminPool: pg.Pool;
  pool: pg.Pool;
  dbName: string;
  tmpDir: string;
}> {
  const adminPool = createManagedTestPool({
    host: process.env.PGHOST || "127.0.0.1",
    port: Number(process.env.PGPORT || 5432),
    user: process.env.PGUSER || "postgres",
    password: process.env.PGPASSWORD || "postgres",
    database: "postgres",
  });
  const dbName = `web3user_test_raft_comp_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
  await adminPool.query(`CREATE DATABASE "${dbName}"`);
  const pool = createManagedTestPool({
    host: process.env.PGHOST || "127.0.0.1",
    port: Number(process.env.PGPORT || 5432),
    user: process.env.PGUSER || "postgres",
    password: process.env.PGPASSWORD || "postgres",
    database: dbName,
  });
  await pool.query(fs.readFileSync(SCHEMA_FILE, "utf-8"));
  await pool.query(fs.readFileSync(MIGRATION_004_FILE, "utf-8"));
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "web3user-raft-comp-"));
  return { adminPool, pool, dbName, tmpDir };
}

describe("Milestone 13-D Stage 2-B.3: Three-Node Compaction Reconciliation & Failover", () => {
  const clusters: RealEtcdCluster[] = [];
  const proxies: LoopbackFaultProxy[] = [];
  const rawClients: Etcd3[] = [];
  const adapters: EtcdClientAdapter[] = [];
  const coordinators: CompactionCoordinator[] = [];
  const pgEnvs: Array<{ adminPool: pg.Pool; pool: pg.Pool; dbName: string; tmpDir: string }> = [];

  afterEach(async () => {
    while (coordinators.length > 0) {
      coordinators.pop()!.close();
    }
    while (adapters.length > 0) {
      await adapters.pop()!.close().catch(() => {});
    }
    while (rawClients.length > 0) {
      rawClients.pop()!.close();
    }
    while (proxies.length > 0) {
      await proxies.pop()!.stop().catch(() => {});
    }
    while (clusters.length > 0) {
      await clusters.pop()!.stop().catch(() => {});
    }
    while (pgEnvs.length > 0) {
      const env = pgEnvs.pop()!;
      await destroyDisposableTestDb({
        adminPool: env.adminPool,
        dbName: env.dbName,
        pool: env.pool,
      }).catch(() => {});
      await closeAdminTestPool(env.adminPool).catch(() => {});
      try {
        fs.rmSync(env.tmpDir, { recursive: true, force: true });
      } catch {
        // Ignore transient Windows cleanup error
      }
    }
  });

  it("reconciles lost compaction response idempotently via ALREADY_COMPACTED", async () => {
    const cluster = new RealEtcdCluster({ tls: true });
    clusters.push(cluster);
    await cluster.start(25_000);

    const pgEnv = await createIsolatedPgEnv();
    pgEnvs.push(pgEnv);

    const leaderInfo = await cluster.getLeaderInfo();
    const leaderPort = cluster.members[leaderInfo.leaderIndex].clientPort;

    const adapter = cluster.createAdapter(cluster.grpcEndpoints);
    adapters.push(adapter);
    await adapter.connect();

    let firstKeyRev = 0n;
    let tipRev = 0n;
    for (let i = 0; i < 20; i += 1) {
      const putRes = await adapter.put(`/stage2b3/ambig/k/${i}`, `v-${i}`);
      if (i === 0) firstKeyRev = putRes.revision;
      tipRev = putRes.revision;
    }

    const store = new PostgresConsensusStore({ pool: pgEnv.pool, clusterId: "cluster-2b3" });
    const snapMgr = new SnapshotManager({
      pool: pgEnv.pool,
      storageBackend: new PosixSnapshotStorageBackend(pgEnv.tmpDir),
    });

    const applied = await store.applyEntry(
      buildEntry({
        epochId: "ep-ambig-1",
        appLogIndex: 1n,
        etcdRevision: tipRev,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "ep-ambig-1",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "p-ambig-1",
      })
    );
    await snapMgr.createAndPublishSnapshot(applied.state);

    const proxy = new LoopbackFaultProxy(leaderPort);
    proxies.push(proxy);
    const proxyEndpoint = await proxy.start();

    const proxiedClient = cluster.createClient([proxyEndpoint]);
    rawClients.push(proxiedClient);

    const coord = new CompactionCoordinator({
      pool: pgEnv.pool,
      snapshotManager: snapMgr,
      etcdClient: new Etcd3CompactionClient(proxiedClient),
      config: {
        clusterId: "cluster-2b3",
        epochId: "ep-ambig-1",
        safetyBuffer: 5n,
        compactionTimeoutMs: 4_000,
        maxRetries: 0,
      },
    });
    coordinators.push(coord);

    const expectedCandidate = tipRev - 5n;

    // Step 1: Arm proxy to drop response after kv.compact() commits on etcd,
    // and drop subsequent retry connections until network is restored.
    await expect(
      coord.runManualCompaction({
        confirmedCompleteRevision: tipRev,
        onBeforeEtcdCompact: () => {
          proxy.armDropNextResponse(() => {
            proxy.setDropAll();
          });
        },
      })
    ).rejects.toThrow(CompactionExecutionError);

    const telemetry = proxy.getTelemetry();
    expect(telemetry.faultsTriggered).toBeGreaterThanOrEqual(1);
    expect(telemetry.droppedResponseBytes).toBeGreaterThan(0);

    const metricsAfterAmbiguous = coord.getMetrics();
    expect(metricsAfterAmbiguous.lastAttemptedCandidateRevision).toBe(expectedCandidate);
    expect(metricsAfterAmbiguous.lastSuccessfulCompactionRevision).toBeNull();
    expect(metricsAfterAmbiguous.lastCompactionError).toBeTruthy();

    // Confirm etcd actually committed the compaction despite lost response
    await expect(
      adapter.get("/stage2b3/ambig/k/0", { revision: firstKeyRev })
    ).rejects.toThrow(EtcdCompactedError);

    // Restore network connectivity on the proxy and reconcile via a fresh Etcd3 client -> ALREADY_COMPACTED
    proxy.setPassthrough();
    const reconcileClient = cluster.createClient([proxyEndpoint]);
    rawClients.push(reconcileClient);
    const reconcileCoord = new CompactionCoordinator({
      pool: pgEnv.pool,
      snapshotManager: snapMgr,
      etcdClient: new Etcd3CompactionClient(reconcileClient),
      config: {
        clusterId: "cluster-2b3",
        epochId: "ep-ambig-1",
        safetyBuffer: 5n,
        compactionTimeoutMs: 4_000,
        maxRetries: 0,
      },
    });
    coordinators.push(reconcileCoord);

    const rec1 = await reconcileCoord.runManualCompaction({ confirmedCompleteRevision: tipRev });
    expect(rec1.status).toBe("ALREADY_COMPACTED");
    expect(rec1.compactedRevision).toBeNull();
    expect(reconcileCoord.getMetrics().lastCompactionError).toBeNull();

    // Step 3: Repeated reconciliation is idempotent
    const rec2 = await reconcileCoord.runManualCompaction({ confirmedCompleteRevision: tipRev });
    expect(rec2.status).toBe("ALREADY_COMPACTED");
    expect(rec2.compactedRevision).toBeNull();

    // Step 4: Fresh coordinator instance (simulated process restart) reconciles idempotently
    const directClient = cluster.createClient(cluster.grpcEndpoints);
    rawClients.push(directClient);
    const restartedCoord = new CompactionCoordinator({
      pool: pgEnv.pool,
      snapshotManager: snapMgr,
      etcdClient: new Etcd3CompactionClient(directClient),
      config: {
        clusterId: "cluster-2b3",
        epochId: "ep-ambig-1",
        safetyBuffer: 5n,
        compactionTimeoutMs: 4_000,
        maxRetries: 0,
      },
    });
    coordinators.push(restartedCoord);

    const rec3 = await restartedCoord.runManualCompaction({
      confirmedCompleteRevision: tipRev,
    });
    expect(rec3.status).toBe("ALREADY_COMPACTED");
    expect(rec3.compactedRevision).toBeNull();

    // Latest uncompacted key remains intact
    const latest = await adapter.get("/stage2b3/ambig/k/19");
    expect(latest?.value).toBe("v-19");
    expect(latest?.modRevision).toBe(tipRev);
  }, 45_000);

  it("handles Raft leader failure during compaction and reconciles cleanly after failover", async () => {
    const cluster = new RealEtcdCluster({ tls: true });
    clusters.push(cluster);
    await cluster.start(25_000);

    const pgEnv = await createIsolatedPgEnv();
    pgEnvs.push(pgEnv);

    const beforeLeader = await cluster.getLeaderInfo();

    const adapter = cluster.createAdapter(cluster.grpcEndpoints);
    adapters.push(adapter);
    await adapter.connect();

    let firstKeyRev = 0n;
    let tipRev = 0n;
    for (let i = 0; i < 20; i += 1) {
      const putRes = await adapter.put(`/stage2b3/failover-comp/k/${i}`, `val-${i}`);
      if (i === 0) firstKeyRev = putRes.revision;
      tipRev = putRes.revision;
    }

    const store = new PostgresConsensusStore({ pool: pgEnv.pool, clusterId: "cluster-2b3-fo" });
    const snapMgr = new SnapshotManager({
      pool: pgEnv.pool,
      storageBackend: new PosixSnapshotStorageBackend(pgEnv.tmpDir),
    });

    const applied = await store.applyEntry(
      buildEntry({
        epochId: "ep-failover-1",
        appLogIndex: 1n,
        etcdRevision: tipRev,
        commandType: "EPOCH_INITIALIZE",
        payload: {
          epochId: "ep-failover-1",
          epochHeight: 1,
          sequenceFloor: 0n,
          createdSeconds: 1700000000,
        },
        proposalId: "p-fo-1",
      })
    );
    await snapMgr.createAndPublishSnapshot(applied.state);

    // Route leader-only compaction client through LoopbackFaultProxy so leader termination
    // occurs asynchronously ONLY AFTER kv.compact() request bytes are forwarded upstream.
    const leaderPort = cluster.members[beforeLeader.leaderIndex].clientPort;
    const proxy = new LoopbackFaultProxy(leaderPort);
    proxies.push(proxy);
    const proxyEndpoint = await proxy.start();

    const leaderOnlyClient = cluster.createClient([proxyEndpoint]);
    rawClients.push(leaderOnlyClient);

    const coord = new CompactionCoordinator({
      pool: pgEnv.pool,
      snapshotManager: snapMgr,
      etcdClient: new Etcd3CompactionClient(leaderOnlyClient),
      config: {
        clusterId: "cluster-2b3-fo",
        epochId: "ep-failover-1",
        safetyBuffer: 5n,
        compactionTimeoutMs: 4_000,
        maxRetries: 0,
      },
    });
    coordinators.push(coord);

    const expectedCandidate = tipRev - 5n;
    let stopPromise: Promise<void> | undefined;
    let forwardedRequestBytes = 0;

    await expect(
      coord.runManualCompaction({
        confirmedCompleteRevision: tipRev,
        onBeforeEtcdCompact: () => {
          proxy.armOnNextClientWrite((bytes) => {
            forwardedRequestBytes = bytes;
            // Prevent a <1ms loopback CompactResponse from beating async OS process termination,
            // ensuring the caller experiences genuine mid-flight ambiguity while the leader dies.
            proxy.setDropAll();
            setImmediate(() => {
              stopPromise = cluster.stopMember(beforeLeader.leaderIndex);
            });
          });
        },
      })
    ).rejects.toThrow(CompactionExecutionError);

    if (stopPromise) {
      await stopPromise;
    }

    // Verify kv.compact() request was genuinely forwarded upstream before leader termination
    const proxyTelemetry = proxy.getTelemetry();
    expect(proxyTelemetry.requestForwardHooksTriggered).toBe(1);
    expect(proxyTelemetry.clientBytesForwardedAfterArm).toBeGreaterThan(0);
    expect(forwardedRequestBytes).toBeGreaterThan(0);

    // No false success advancement on leader failure
    expect(coord.getMetrics().lastSuccessfulCompactionRevision).toBeNull();
    expect(coord.getMetrics().lastCompactionError).toBeTruthy();

    // Surviving 2-node quorum elects a new Raft leader
    const afterLeader = await cluster.waitForLeader({
      excludeLeaderId: beforeLeader.leaderId,
      timeoutMs: 15_000,
    });
    expect(afterLeader.leaderId).not.toBe(beforeLeader.leaderId);
    expect(afterLeader.leaderIndex).not.toBe(beforeLeader.leaderIndex);

    // Distinguish whether the forwarded kv.compact() committed before leader kill or not
    const survivorAdapter = cluster.createAdapter(cluster.activeGrpcEndpoints);
    adapters.push(survivorAdapter);
    await survivorAdapter.connect();

    let committedBeforeFailover = false;
    try {
      await survivorAdapter.get("/stage2b3/failover-comp/k/0", { revision: firstKeyRev });
    } catch (err) {
      if (err instanceof EtcdCompactedError) {
        committedBeforeFailover = true;
      } else {
        throw err;
      }
    }

    // Reconcile / complete compaction against surviving quorum
    const survivorClient = cluster.createClient(cluster.activeGrpcEndpoints);
    rawClients.push(survivorClient);

    const survivorCoord = new CompactionCoordinator({
      pool: pgEnv.pool,
      snapshotManager: snapMgr,
      etcdClient: new Etcd3CompactionClient(survivorClient),
      config: {
        clusterId: "cluster-2b3-fo",
        epochId: "ep-failover-1",
        safetyBuffer: 5n,
        compactionTimeoutMs: 4_000,
        maxRetries: 1,
      },
    });
    coordinators.push(survivorCoord);

    const postFailoverRes = await survivorCoord.runManualCompaction({
      confirmedCompleteRevision: tipRev,
    });
    if (committedBeforeFailover) {
      expect(postFailoverRes.status).toBe("ALREADY_COMPACTED");
      expect(postFailoverRes.compactedRevision).toBeNull();
    } else {
      expect(postFailoverRes.status).toBe("COMPACTED");
      expect(postFailoverRes.compactedRevision).toBe(expectedCandidate);
    }
    expect(survivorCoord.getMetrics().lastCompactionError).toBeNull();

    console.info(
      `[stage2b3-leader-failover] beforeLeader=${beforeLeader.leaderId} afterLeader=${afterLeader.leaderId} tipRev=${tipRev} candidate=${expectedCandidate} forwardedBytes=${forwardedRequestBytes} committedBeforeFailover=${committedBeforeFailover} postFailoverStatus=${postFailoverRes.status}`
    );

    // Verify physical compaction took effect and latest data remains intact
    await expect(
      survivorAdapter.get("/stage2b3/failover-comp/k/0", { revision: firstKeyRev })
    ).rejects.toThrow(EtcdCompactedError);

    const latest = await survivorAdapter.get("/stage2b3/failover-comp/k/19");
    expect(latest?.value).toBe("val-19");
    expect(latest?.modRevision).toBe(tipRev);

    // Subsequent compaction at same boundary is an idempotent NO_OP
    const repeatRes = await survivorCoord.runManualCompaction({
      confirmedCompleteRevision: tipRev,
      knownCompactedRevision: expectedCandidate,
    });
    expect(repeatRes.status).toBe("NO_OP");
  }, 50_000);
});
