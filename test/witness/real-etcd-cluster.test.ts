/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.3
 * Three-Node Real etcd v3.5.18 Bootstrap & Quorum Integration Suite
 */

import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { RealEtcdCluster } from "./helpers/real-etcd-cluster.js";
import { EtcdClientAdapter } from "../../src/witness/etcd-client-adapter.js";

describe("Milestone 13-D Stage 2-B.3: Three-Node Real etcd v3.5.18 Cluster", () => {
  const activeClusters: RealEtcdCluster[] = [];
  const activeAdapters: EtcdClientAdapter[] = [];

  afterEach(async () => {
    while (activeAdapters.length > 0) {
      const adapter = activeAdapters.pop()!;
      await adapter.close().catch(() => {});
    }
    while (activeClusters.length > 0) {
      const cluster = activeClusters.pop()!;
      await cluster.stop().catch(() => {});
    }
  });

  it("bootstraps three healthy mTLS members, agrees on membership, and elects a Raft leader", async () => {
    const cluster = new RealEtcdCluster({ tls: true });
    activeClusters.push(cluster);

    await cluster.start(25_000);

    expect(cluster.members).toHaveLength(3);
    const allPorts = new Set<number>();
    for (const member of cluster.members) {
      expect(member.pid).toBeTypeOf("number");
      expect(member.clientEndpoint).toMatch(/^https:\/\/127\.0\.0\.1:\d+$/);
      expect(member.peerEndpoint).toMatch(/^https:\/\/127\.0\.0\.1:\d+$/);
      allPorts.add(member.clientPort);
      allPorts.add(member.peerPort);
    }
    expect(allPorts.size).toBe(6);

    const expectedNames = cluster.members.map((m) => m.name).sort();
    for (let i = 0; i < 3; i += 1) {
      const members = await cluster.getMemberList(i);
      expect(members).toHaveLength(3);
      expect(members.map((m) => m.name).sort()).toEqual(expectedNames);
    }

    const status = await cluster.getClusterStatus();
    expect(status.leaderId).not.toBe("0");
    expect(status.memberStatuses).toHaveLength(3);
    for (const ms of status.memberStatuses) {
      expect(ms.leader).toBe(status.leaderId);
    }
  }, 30_000);

  it("performs quorum-backed writes and cross-member linearizable reads", async () => {
    const cluster = new RealEtcdCluster({ tls: true });
    activeClusters.push(cluster);
    await cluster.start(25_000);

    const adapter0 = cluster.createAdapter([cluster.grpcEndpoints[0]]);
    const adapter1 = cluster.createAdapter([cluster.grpcEndpoints[1]]);
    const adapter2 = cluster.createAdapter([cluster.grpcEndpoints[2]]);
    activeAdapters.push(adapter0, adapter1, adapter2);

    await adapter0.connect();
    await adapter1.connect();
    await adapter2.connect();

    // 1. Write through member 0, read back linearly through member 1
    const keyA = "/stage2b3/quorum/key-a";
    const putA = await adapter0.put(keyA, "value-from-node-1");
    expect(putA.revision > 0n).toBe(true);

    const readAFrom1 = await adapter1.get(keyA);
    expect(readAFrom1?.value).toBe("value-from-node-1");
    expect(readAFrom1?.modRevision).toBe(putA.revision);

    // 2. Write through member 2, verify consistent reads through members 0 and 1
    const keyB = "/stage2b3/quorum/key-b";
    const putB = await adapter2.put(keyB, "value-from-node-3");
    expect(putB.revision > putA.revision).toBe(true);

    const readBFrom0 = await adapter0.get(keyB);
    const readBFrom1 = await adapter1.get(keyB);
    expect(readBFrom0?.value).toBe("value-from-node-3");
    expect(readBFrom0?.modRevision).toBe(putB.revision);
    expect(readBFrom1?.value).toBe("value-from-node-3");
    expect(readBFrom1?.modRevision).toBe(putB.revision);
  }, 30_000);

  it("stops all child processes cleanly and supports idempotent repeated shutdown", async () => {
    const cluster = new RealEtcdCluster({ tls: true });
    activeClusters.push(cluster);
    await cluster.start(25_000);

    const pids = cluster.members.map((m) => m.pid!);
    const dataRoot = cluster.dataRootDir!;
    const certDir = cluster.certBundleDir!;

    expect(pids).toHaveLength(3);
    for (const pid of pids) {
      expect(pid).toBeTypeOf("number");
    }

    await cluster.stop();
    await cluster.stop(); // idempotent

    expect(cluster.members).toHaveLength(0);
    for (const pid of pids) {
      expect(() => process.kill(pid, 0)).toThrow();
    }
    expect(fs.existsSync(dataRoot)).toBe(false);
    expect(fs.existsSync(certDir)).toBe(false);
  }, 30_000);

  it("elects a new Raft leader and preserves quorum writes/reads when the current leader fails", async () => {
    const cluster = new RealEtcdCluster({ tls: true });
    activeClusters.push(cluster);
    await cluster.start(25_000);

    const before = await cluster.getLeaderInfo();
    expect(Object.keys(before.memberIds)).toHaveLength(3);
    expect(before.leaderId).toBe(before.memberIds[before.leaderName]);

    const initialAdapter = cluster.createAdapter([cluster.grpcEndpoints[before.leaderIndex]]);
    activeAdapters.push(initialAdapter);
    await initialAdapter.connect();

    const k1 = await initialAdapter.put("/stage2b3/failover/k1", "v1");
    const k2 = await initialAdapter.put("/stage2b3/failover/k2", "v2");
    const k3 = await initialAdapter.put("/stage2b3/failover/k3", "v3");
    await initialAdapter.close();

    const failedLeaderPid = cluster.members[before.leaderIndex].pid!;
    expect(failedLeaderPid).toBeTypeOf("number");

    await cluster.stopMember(before.leaderIndex);
    expect(() => process.kill(failedLeaderPid, 0)).toThrow();

    const after = await cluster.waitForLeader({
      excludeLeaderId: before.leaderId,
      timeoutMs: 15_000,
    });
    expect(after.leaderId).not.toBe(before.leaderId);
    expect(after.leaderIndex).not.toBe(before.leaderIndex);

    const survivingEndpoints = cluster.activeGrpcEndpoints;
    expect(survivingEndpoints).toHaveLength(2);

    const survivor0 = cluster.createAdapter([survivingEndpoints[0]]);
    const survivor1 = cluster.createAdapter([survivingEndpoints[1]]);
    activeAdapters.push(survivor0, survivor1);
    await survivor0.connect();
    await survivor1.connect();

    // Previously committed keys remain readable from surviving quorum
    expect((await survivor0.get("/stage2b3/failover/k1"))?.modRevision).toBe(k1.revision);
    expect((await survivor0.get("/stage2b3/failover/k2"))?.modRevision).toBe(k2.revision);
    expect((await survivor0.get("/stage2b3/failover/k3"))?.modRevision).toBe(k3.revision);

    // New writes succeed through surviving 2-node quorum and replicate to both survivors
    const k4 = await survivor0.put("/stage2b3/failover/k4", "post-failover-v4");
    expect(k4.revision > k3.revision).toBe(true);
    const readK4 = await survivor1.get("/stage2b3/failover/k4");
    expect(readK4?.value).toBe("post-failover-v4");
    expect(readK4?.modRevision).toBe(k4.revision);
  }, 35_000);

  it("allows a terminated former leader to rejoin the existing cluster and catch up", async () => {
    const cluster = new RealEtcdCluster({ tls: true });
    activeClusters.push(cluster);
    await cluster.start(25_000);

    const before = await cluster.getLeaderInfo();
    const writer = cluster.createAdapter([cluster.grpcEndpoints[before.leaderIndex]]);
    activeAdapters.push(writer);
    await writer.connect();
    await writer.put("/stage2b3/rejoin/k1", "before-stop-1");
    await writer.put("/stage2b3/rejoin/k2", "before-stop-2");
    await writer.close();

    await cluster.stopMember(before.leaderIndex);

    const afterFailover = await cluster.waitForLeader({
      excludeLeaderId: before.leaderId,
      timeoutMs: 15_000,
    });

    const survivorWriter = cluster.createAdapter(cluster.activeGrpcEndpoints);
    activeAdapters.push(survivorWriter);
    await survivorWriter.connect();
    const k3 = await survivorWriter.put("/stage2b3/rejoin/k3", "during-outage-3");
    await survivorWriter.close();

    // Restart former leader using existing dataDir and cluster configuration
    await cluster.restartMember(before.leaderIndex);
    expect(cluster.activeMemberIndices).toHaveLength(3);

    const rejoinedStatus = await cluster.waitForLeader({ timeoutMs: 15_000 });
    expect(rejoinedStatus.memberIds).toEqual(before.memberIds);
    expect(rejoinedStatus.leaderId).toBeTruthy();

    const rejoinedMemberList = await cluster.getMemberList(before.leaderIndex);
    expect(rejoinedMemberList).toHaveLength(3);
    expect(rejoinedMemberList.map((m) => m.id).sort()).toEqual(
      Object.values(before.memberIds).sort()
    );

    // Rejoined former leader serves consistent linearizable reads including outage writes
    const rejoinedReader = cluster.createAdapter([cluster.grpcEndpoints[before.leaderIndex]]);
    activeAdapters.push(rejoinedReader);
    await rejoinedReader.connect();
    expect((await rejoinedReader.get("/stage2b3/rejoin/k1"))?.value).toBe("before-stop-1");
    expect((await rejoinedReader.get("/stage2b3/rejoin/k2"))?.value).toBe("before-stop-2");
    const readK3 = await rejoinedReader.get("/stage2b3/rejoin/k3");
    expect(readK3?.value).toBe("during-outage-3");
    expect(readK3?.modRevision).toBe(k3.revision);
  }, 40_000);

  for (const failingIndex of [1, 2] as const) {
    it(`cleans up spawned processes and temp directories on member ${failingIndex} startup failure`, async () => {
      const missingCert = path.join(os.tmpdir(), `missing-ca-m${failingIndex}-${Date.now()}.crt`);
      let capturedDataRoot: string | undefined;
      let capturedCertDir: string | undefined;

      const cluster = new RealEtcdCluster({
        tls: true,
        nodeOptionsOverride: (index, base) => {
          if (!capturedDataRoot) {
            capturedDataRoot = path.dirname(base.dataDir!);
          }
          if (!capturedCertDir && base.tls) {
            capturedCertDir = path.dirname(base.tls.caCertPath);
          }
          if (index === failingIndex && base.tls) {
            return {
              ...base,
              tls: {
                ...base.tls,
                caCertPath: missingCert,
              },
            };
          }
          return base;
        },
      });
      activeClusters.push(cluster);

      await expect(cluster.start(20_000)).rejects.toThrow(/Missing tls\.caCertPath/);
      expect(cluster.cleanupPidsSnapshot.length).toBeGreaterThanOrEqual(1);
      for (const pid of cluster.cleanupPidsSnapshot) {
        expect(() => process.kill(pid, 0)).toThrow();
      }
      expect(cluster.members).toHaveLength(0);
      expect(cluster.dataRootDir).toBeUndefined();
      expect(cluster.certBundleDir).toBeUndefined();
      expect(fs.existsSync(capturedDataRoot!)).toBe(false);
      expect(fs.existsSync(capturedCertDir!)).toBe(false);
    }, 25_000);
  }

  it("cleans up all spawned processes, log streams, and temp directories if waitForClusterReady() fails", async () => {
    let capturedPids: number[] = [];
    let capturedStreams: Array<fs.WriteStream | null> = [];
    let capturedDataRoot: string | undefined;
    let capturedCertDir: string | undefined;

    const cluster = new RealEtcdCluster({
      tls: true,
      onBeforeClusterReady: (c) => {
        capturedDataRoot = c.dataRootDir;
        capturedCertDir = c.certBundleDir;
        capturedPids = c.members
          .map((m) => m.pid)
          .filter((p): p is number => typeof p === "number");
        capturedStreams = c.members.map(
          (m) => (m as unknown as { logStream: fs.WriteStream | null }).logStream
        );
        throw new Error("Simulated cluster readiness failure");
      },
    });
    activeClusters.push(cluster);

    await expect(cluster.start(20_000)).rejects.toThrow("Simulated cluster readiness failure");
    expect(capturedPids).toHaveLength(3);
    for (const pid of capturedPids) {
      expect(() => process.kill(pid, 0)).toThrow();
    }
    for (const stream of capturedStreams) {
      expect(stream).not.toBeNull();
      expect(stream!.writableEnded || stream!.closed).toBe(true);
    }
    expect(cluster.members).toHaveLength(0);
    expect(fs.existsSync(capturedDataRoot!)).toBe(false);
    expect(fs.existsSync(capturedCertDir!)).toBe(false);
  }, 25_000);
});
