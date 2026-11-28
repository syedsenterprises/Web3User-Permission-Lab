/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.3
 * Three-Node Real etcd v3.5.18 Cluster Lifecycle Manager
 *
 * Orchestrates an isolated three-member etcd v3.5.18 Raft cluster on loopback
 * (127.0.0.1) with strict client and peer mTLS, quorum readiness verification,
 * and deterministic cleanup on both normal shutdown and partial startup failure.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Etcd3, type IOptions as Etcd3Options } from "etcd3";
import {
  RealEtcdProcess,
  type RealEtcdOptions,
  type RealEtcdPeerTlsOptions,
  type RealEtcdTlsOptions,
  getFreePort,
} from "./real-etcd-process.js";
import { EtcdClientAdapter } from "../../../src/witness/etcd-client-adapter.js";
import { generateTestCertificates, type CertBundle } from "../../../src/witness/mtls-certs.js";

export interface RealEtcdClusterOptions {
  clusterName?: string;
  tls?: boolean;
  heartbeatIntervalMs?: number;
  electionTimeoutMs?: number;
  autoCompactionRetention?: string;
  baseDataDir?: string;
  /**
   * Optional test hook to customize or inject an invalid/failing option into a
   * specific member (index 0..2) before startup.
   */
  nodeOptionsOverride?: (index: number, base: RealEtcdOptions) => RealEtcdOptions;
  /**
   * Optional test hook invoked after all 3 processes have spawned and passed
   * per-node /health, right before cluster quorum readiness polling.
   */
  onBeforeClusterReady?: (cluster: RealEtcdCluster) => Promise<void> | void;
}

export interface ClusterMemberInfo {
  id: string;
  name: string;
  peerURLs: string[];
  clientURLs: string[];
}

export interface ClusterMemberStatus {
  name: string;
  grpcEndpoint: string;
  clientEndpoint: string;
  leader: string;
  revision: string;
  raftTerm: string;
}

export const CLUSTER_NODE_COUNT = 3;

export class RealEtcdCluster {
  public readonly clusterName: string;
  public readonly initialClusterToken: string;
  public readonly tlsEnabled: boolean;

  private readonly options: RealEtcdClusterOptions;
  private nodes: RealEtcdProcess[] = [];
  private stoppedIndices = new Set<number>();
  private lastCleanupPids: number[] = [];
  private certs: CertBundle | null = null;
  private ownedDataDir: string | null = null;
  private isStarted = false;

  constructor(options: RealEtcdClusterOptions = {}) {
    this.options = options;
    this.clusterName =
      options.clusterName || `stage2b3-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    this.initialClusterToken = `${this.clusterName}-token`;
    this.tlsEnabled = options.tls ?? true;
  }

  public get members(): readonly RealEtcdProcess[] {
    return this.nodes;
  }

  public get clientEndpoints(): string[] {
    return this.nodes.map((n) => n.clientEndpoint);
  }

  public get grpcEndpoints(): string[] {
    return this.nodes.map((n) => n.grpcEndpoint);
  }

  public get certBundleDir(): string | undefined {
    return this.certs?.bundleDir;
  }

  public get dataRootDir(): string | undefined {
    return this.ownedDataDir ?? this.options.baseDataDir;
  }

  public get activeMemberIndices(): number[] {
    return this.nodes
      .map((_, idx) => idx)
      .filter((idx) => !this.stoppedIndices.has(idx));
  }

  public get activeGrpcEndpoints(): string[] {
    return this.activeMemberIndices.map((idx) => this.nodes[idx].grpcEndpoint);
  }

  public get cleanupPidsSnapshot(): readonly number[] {
    return this.lastCleanupPids;
  }

  public get tlsCredentials():
    | { rootCertificate: Buffer; certChain: Buffer; privateKey: Buffer }
    | undefined {
    if (!this.certs) {
      return undefined;
    }
    return {
      rootCertificate: this.certs.caCert,
      certChain: this.certs.engineClientCert,
      privateKey: this.certs.engineClientKey,
    };
  }

  private async allocateDistinctPorts(count: number): Promise<number[]> {
    const allocated = new Set<number>();
    let attempts = 0;
    const maxAttempts = count * 10;

    while (allocated.size < count) {
      attempts += 1;
      if (attempts > maxAttempts) {
        throw new Error(`Unable to allocate ${count} distinct loopback ports after ${maxAttempts} attempts`);
      }
      const port = await getFreePort();
      if (!allocated.has(port)) {
        allocated.add(port);
      }
    }

    return Array.from(allocated);
  }

  public async start(readyTimeoutMs = 20_000): Promise<void> {
    if (this.isStarted) {
      return;
    }

    try {
      const dataRoot =
        this.options.baseDataDir ??
        fs.mkdtempSync(path.join(os.tmpdir(), "web3user-etcd-cluster-"));
      if (!this.options.baseDataDir) {
        this.ownedDataDir = dataRoot;
      } else {
        fs.mkdirSync(dataRoot, { recursive: true });
      }

      let clientTls: RealEtcdTlsOptions | undefined;
      let peerTls: RealEtcdPeerTlsOptions | undefined;
      if (this.tlsEnabled) {
        this.certs = generateTestCertificates();
        const dir = this.certs.bundleDir;
        clientTls = {
          caCertPath: path.join(dir, "ca.crt"),
          serverCertPath: path.join(dir, "server.crt"),
          serverKeyPath: path.join(dir, "server.key"),
          clientCertPath: path.join(dir, "engine-client.crt"),
          clientKeyPath: path.join(dir, "engine-client.key"),
          clientCertAuth: true,
        };
        peerTls = {
          caCertPath: path.join(dir, "ca.crt"),
          peerCertPath: path.join(dir, "server.crt"),
          peerKeyPath: path.join(dir, "server.key"),
          peerClientCertAuth: true,
        };
      }

      const ports = await this.allocateDistinctPorts(CLUSTER_NODE_COUNT * 2);
      const peerScheme = this.tlsEnabled ? "https" : "http";

      const specs = Array.from({ length: CLUSTER_NODE_COUNT }, (_, idx) => {
        const name = `${this.clusterName}-node-${idx + 1}`;
        const clientPort = ports[idx * 2];
        const peerPort = ports[idx * 2 + 1];
        return { name, clientPort, peerPort };
      });

      const initialCluster = specs
        .map((s) => `${s.name}=${peerScheme}://127.0.0.1:${s.peerPort}`)
        .join(",");

      this.nodes = specs.map((s, idx) => {
        const baseOptions: RealEtcdOptions = {
          name: s.name,
          clientPort: s.clientPort,
          peerPort: s.peerPort,
          dataDir: path.join(dataRoot, s.name),
          tls: clientTls,
          peerTls,
          initialCluster,
          initialClusterToken: this.initialClusterToken,
          heartbeatIntervalMs: this.options.heartbeatIntervalMs ?? 100,
          electionTimeoutMs: this.options.electionTimeoutMs ?? 1000,
          autoCompactionRetention: this.options.autoCompactionRetention,
        };
        const finalOptions = this.options.nodeOptionsOverride
          ? this.options.nodeOptionsOverride(idx, baseOptions)
          : baseOptions;
        return new RealEtcdProcess(finalOptions);
      });

      const results = await Promise.allSettled(this.nodes.map((node) => node.start()));
      this.lastCleanupPids = this.nodes
        .map((n) => n.pid)
        .filter((p): p is number => typeof p === "number");
      const failed = results.find((r): r is PromiseRejectedResult => r.status === "rejected");
      if (failed) {
        throw failed.reason;
      }

      if (this.options.onBeforeClusterReady) {
        await this.options.onBeforeClusterReady(this);
      }

      await this.waitForClusterReady(readyTimeoutMs);
      this.isStarted = true;
    } catch (err) {
      this.lastCleanupPids = this.nodes
        .map((n) => n.pid)
        .filter((p): p is number => typeof p === "number");
      await this.stop().catch(() => {});
      throw err;
    }
  }

  public createClient(grpcEndpoints: string[] = this.grpcEndpoints): Etcd3 {
    const opts: Etcd3Options = { hosts: grpcEndpoints };
    if (this.tlsEnabled && this.certs) {
      opts.credentials = {
        rootCertificate: this.certs.caCert,
        certChain: this.certs.engineClientCert,
        privateKey: this.certs.engineClientKey,
      };
      opts.grpcOptions = {
        "grpc.ssl_target_name_override": "localhost",
      };
    }
    return new Etcd3(opts);
  }

  public createAdapter(grpcEndpoints: string[] = this.grpcEndpoints): EtcdClientAdapter {
    return new EtcdClientAdapter({
      endpoints: grpcEndpoints,
      dialTimeoutMs: 3000,
      requestTimeoutMs: 5000,
      credentials: this.tlsCredentials,
      grpcOptions: this.tlsEnabled
        ? { "grpc.ssl_target_name_override": "localhost" }
        : undefined,
    });
  }

  public async getMemberList(memberIndex = 0): Promise<ClusterMemberInfo[]> {
    const node = this.nodes[memberIndex];
    if (!node) {
      throw new Error(`Cluster member index ${memberIndex} out of bounds`);
    }
    const client = this.createClient([node.grpcEndpoint]);
    try {
      const resp = await client.cluster.memberList({});
      return resp.members.map((m) => ({
        id: m.ID.toString(),
        name: m.name,
        peerURLs: [...m.peerURLs],
        clientURLs: [...m.clientURLs],
      }));
    } finally {
      client.close();
    }
  }

  public async getClusterStatus(): Promise<{
    leaderId: string;
    memberStatuses: ClusterMemberStatus[];
  }> {
    const memberStatuses: ClusterMemberStatus[] = [];
    for (const idx of this.activeMemberIndices) {
      const node = this.nodes[idx];
      const client = this.createClient([node.grpcEndpoint]);
      try {
        const status = await client.maintenance.status();
        memberStatuses.push({
          name: node.name,
          grpcEndpoint: node.grpcEndpoint,
          clientEndpoint: node.clientEndpoint,
          leader: status.leader.toString(),
          revision: status.header?.revision?.toString() ?? "0",
          raftTerm: status.raftTerm.toString(),
        });
      } finally {
        client.close();
      }
    }

    const leaders = new Set(memberStatuses.map((s) => s.leader).filter((l) => l !== "0"));
    if (leaders.size !== 1) {
      throw new Error(
        `Cluster does not agree on a single Raft leader (observed leaders: ${Array.from(leaders).join(", ") || "none"})`
      );
    }

    return {
      leaderId: Array.from(leaders)[0],
      memberStatuses,
    };
  }

  public async getLeaderInfo(): Promise<{
    leaderId: string;
    leaderIndex: number;
    leaderName: string;
    memberIds: Record<string, string>;
    revision: string;
  }> {
    const active = this.activeMemberIndices;
    if (active.length === 0) {
      throw new Error("No active cluster members available to query leader");
    }

    const [members, status] = await Promise.all([
      this.getMemberList(active[0]),
      this.getClusterStatus(),
    ]);

    const memberIds: Record<string, string> = {};
    let leaderName: string | undefined;
    for (const m of members) {
      memberIds[m.name] = m.id;
      if (m.id === status.leaderId) {
        leaderName = m.name;
      }
    }

    if (!leaderName) {
      throw new Error(`Leader ID ${status.leaderId} not found in 3-member cluster list`);
    }

    const leaderIndex = this.nodes.findIndex((n) => n.name === leaderName);
    if (leaderIndex === -1) {
      throw new Error(`Leader member "${leaderName}" not found in cluster nodes`);
    }

    return {
      leaderId: status.leaderId,
      leaderIndex,
      leaderName,
      memberIds,
      revision: status.memberStatuses[0]?.revision ?? "0",
    };
  }

  public async stopMember(index: number): Promise<void> {
    const node = this.nodes[index];
    if (!node) {
      throw new Error(`Cluster member index ${index} out of bounds`);
    }
    this.stoppedIndices.add(index);
    await node.stop();
  }

  public async restartMember(index: number): Promise<void> {
    const node = this.nodes[index];
    if (!node) {
      throw new Error(`Cluster member index ${index} out of bounds`);
    }
    await node.start();
    this.stoppedIndices.delete(index);
  }

  public async waitForLeader(options: {
    excludeLeaderId?: string;
    timeoutMs?: number;
  } = {}): Promise<{
    leaderId: string;
    leaderIndex: number;
    leaderName: string;
    memberIds: Record<string, string>;
    revision: string;
  }> {
    const timeoutMs = options.timeoutMs ?? 15_000;
    const deadline = Date.now() + timeoutMs;
    let lastError: unknown = null;

    while (Date.now() < deadline) {
      try {
        const info = await this.getLeaderInfo();
        if (!options.excludeLeaderId || info.leaderId !== options.excludeLeaderId) {
          return info;
        }
      } catch (err) {
        lastError = err;
      }
      await new Promise((r) => setTimeout(r, 150));
    }

    const detail = lastError instanceof Error ? lastError.message : String(lastError);
    throw new Error(`Cluster failed to elect leader within ${timeoutMs}ms: ${detail}`);
  }

  private async waitForClusterReady(timeoutMs: number): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    const expectedNames = new Set(this.nodes.map((n) => n.name));
    let lastError: unknown = null;

    while (Date.now() < deadline) {
      try {
        for (let i = 0; i < this.nodes.length; i += 1) {
          const members = await this.getMemberList(i);
          if (members.length !== CLUSTER_NODE_COUNT) {
            throw new Error(`Expected ${CLUSTER_NODE_COUNT} members, got ${members.length}`);
          }
          for (const m of members) {
            if (!expectedNames.has(m.name)) {
              throw new Error(`Unexpected cluster member "${m.name}"`);
            }
          }
        }

        const status = await this.getClusterStatus();
        if (status.leaderId && status.leaderId !== "0") {
          return;
        }
      } catch (err) {
        lastError = err;
      }
      await new Promise((r) => setTimeout(r, 150));
    }

    const detail = lastError instanceof Error ? lastError.message : String(lastError);
    throw new Error(`Three-node etcd cluster "${this.clusterName}" failed to reach quorum readiness within ${timeoutMs}ms: ${detail}`);
  }

  public async stop(): Promise<void> {
    const currentNodes = this.nodes;
    this.nodes = [];
    this.stoppedIndices.clear();
    this.isStarted = false;

    if (currentNodes.length > 0) {
      await Promise.allSettled(currentNodes.map((n) => n.stop()));
    }

    if (this.ownedDataDir) {
      try {
        fs.rmSync(this.ownedDataDir, { recursive: true, force: true });
      } catch {
        // Ignore transient Windows file-lock cleanup errors
      }
      this.ownedDataDir = null;
    }

    if (this.certs?.bundleDir) {
      try {
        fs.rmSync(this.certs.bundleDir, { recursive: true, force: true });
      } catch {
        // Ignore transient Windows file-lock cleanup errors
      }
      this.certs = null;
    }
  }
}
