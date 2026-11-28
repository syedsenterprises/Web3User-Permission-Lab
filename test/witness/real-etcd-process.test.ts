import { describe, it, expect, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { RealEtcdProcess, getFreePort } from "./helpers/real-etcd-process.js";
import { generateTestCertificates } from "../../src/witness/mtls-certs.js";

describe("RealEtcdProcess multi-node and peer TLS configuration", () => {
  const processes: RealEtcdProcess[] = [];
  const tempDirs: string[] = [];

  afterEach(async () => {
    while (processes.length > 0) {
      const proc = processes.pop()!;
      await proc.stop().catch(() => {});
    }
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop()!;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("preserves single-node defaults when multi-node options are omitted", () => {
    const proc = new RealEtcdProcess({
      name: "single-node-default",
      clientPort: 23790,
      peerPort: 23800,
    });

    expect(proc.clientEndpoint).toBe("http://127.0.0.1:23790");
    expect(proc.peerEndpoint).toBe("http://127.0.0.1:23800");
    expect(proc.grpcEndpoint).toBe("127.0.0.1:23790");

    const args = proc.getLaunchArgs();
    expect(args).toContain("--initial-cluster=single-node-default=http://127.0.0.1:23800");
    expect(args).toContain("--initial-cluster-token=cluster-single-node-default");
    expect(args.some((a) => a.startsWith("--peer-cert-file="))).toBe(false);
    expect(args.some((a) => a.startsWith("--cert-file="))).toBe(false);
  });

  it("supports custom initialCluster and initialClusterToken", () => {
    const cluster =
      "node-1=http://127.0.0.1:23801,node-2=http://127.0.0.1:23802,node-3=http://127.0.0.1:23803";
    const proc = new RealEtcdProcess({
      name: "node-2",
      clientPort: 23792,
      peerPort: 23802,
      initialCluster: cluster,
      initialClusterToken: "stage-2b3-raft-token",
    });

    const args = proc.getLaunchArgs();
    expect(args).toContain(`--initial-cluster=${cluster}`);
    expect(args).toContain("--initial-cluster-token=stage-2b3-raft-token");
  });

  it("supports separate client TLS and peer TLS configuration", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "web3user-etcd-cfg-"));
    tempDirs.push(tmpDir);

    const proc = new RealEtcdProcess({
      name: "tls-node-1",
      clientPort: 23791,
      peerPort: 23801,
      initialCluster:
        "tls-node-1=https://127.0.0.1:23801,tls-node-2=https://127.0.0.1:23802",
      initialClusterToken: "tls-cluster-token",
      tls: {
        caCertPath: path.join(tmpDir, "client-ca.crt"),
        serverCertPath: path.join(tmpDir, "server.crt"),
        serverKeyPath: path.join(tmpDir, "server.key"),
        clientCertAuth: true,
      },
      peerTls: {
        caCertPath: path.join(tmpDir, "peer-ca.crt"),
        peerCertPath: path.join(tmpDir, "peer.crt"),
        peerKeyPath: path.join(tmpDir, "peer.key"),
        peerClientCertAuth: true,
      },
    });

    expect(proc.clientEndpoint).toBe("https://127.0.0.1:23791");
    expect(proc.peerEndpoint).toBe("https://127.0.0.1:23801");

    const args = proc.getLaunchArgs();
    expect(args).toContain(`--cert-file=${path.join(tmpDir, "server.crt")}`);
    expect(args).toContain(`--trusted-ca-file=${path.join(tmpDir, "client-ca.crt")}`);
    expect(args).toContain("--client-cert-auth=true");
    expect(args).toContain(`--peer-cert-file=${path.join(tmpDir, "peer.crt")}`);
    expect(args).toContain(`--peer-key-file=${path.join(tmpDir, "peer.key")}`);
    expect(args).toContain(`--peer-trusted-ca-file=${path.join(tmpDir, "peer-ca.crt")}`);
    expect(args).toContain("--peer-client-cert-auth=true");
  });

  it("rejects invalid multi-node, port, and TLS configurations", async () => {
    expect(() => new RealEtcdProcess({ clientPort: 2379, peerPort: 2379 })).toThrow(
      /clientPort and peerPort must be distinct/
    );
    expect(() => new RealEtcdProcess({ initialClusterToken: "   " })).toThrow(
      /initialClusterToken must be a non-empty string/
    );
    expect(() => new RealEtcdProcess({ name: "node-1", initialCluster: "   " })).toThrow(
      /initialCluster must be a non-empty string/
    );
    expect(
      () =>
        new RealEtcdProcess({
          name: "node-1",
          initialCluster: "node-2=http://127.0.0.1:23802",
        })
    ).toThrow(/initialCluster must include an entry for this node/);
    expect(
      () =>
        new RealEtcdProcess({
          name: "node-1",
          initialCluster: "node-1=http://127.0.0.1:23801",
          peerTls: {
            caCertPath: "/ca.crt",
            peerCertPath: "/peer.crt",
            peerKeyPath: "/peer.key",
          },
        })
    ).toThrow(/must use "https:"/);
    expect(
      () =>
        new RealEtcdProcess({
          name: "node-1",
          initialCluster: "node-1=https://127.0.0.1:23801",
        })
    ).toThrow(/must use "http:"/);
    expect(
      () =>
        new RealEtcdProcess({
          name: "node-1",
          initialCluster: "node-1=http://127.0.0.1:23801,node-1=http://127.0.0.1:23802",
        })
    ).toThrow(/Duplicate member name "node-1"/);
    expect(
      () =>
        new RealEtcdProcess({
          name: "node-1",
          initialCluster: "node-1=http://127.0.0.1:23801,node-2=http://127.0.0.1:23801",
        })
    ).toThrow(/Duplicate peer URL/);
    expect(
      () =>
        new RealEtcdProcess({
          name: "node-1",
          initialCluster: "node-1=not-a-valid-url",
        })
    ).toThrow(/Invalid peer URL/);
    expect(
      () =>
        new RealEtcdProcess({
          name: "node-1",
          initialCluster: "node-1=http://127.0.0.1",
        })
    ).toThrow(/invalid port/);
    expect(
      () =>
        new RealEtcdProcess({
          name: "node-1",
          initialCluster: "node-1=http://127.0.0.1:23801/peer",
        })
    ).toThrow(/non-root path/);
    expect(
      () =>
        new RealEtcdProcess({
          name: "node-1",
          initialCluster: "node-1=http://127.0.0.1:23801?foo=bar",
        })
    ).toThrow(/query strings are not allowed/);
    expect(
      () =>
        new RealEtcdProcess({
          name: "node-1",
          initialCluster: "node-1=http://127.0.0.1:23801#frag",
        })
    ).toThrow(/fragments are not allowed/);
    expect(
      () =>
        new RealEtcdProcess({
          name: "node-1",
          initialCluster: "node-1=http://user:pass@127.0.0.1:23801",
        })
    ).toThrow(/embedded credentials are not allowed/);
    expect(
      () =>
        new RealEtcdProcess({
          name: "node-1",
          peerPort: 23801,
          initialCluster: "node-1=http://127.0.0.1:23999,node-2=http://127.0.0.1:23802",
        })
    ).toThrow(/does not match configured peer endpoint/);
    expect(
      () =>
        new RealEtcdProcess({
          peerTls: { caCertPath: "", peerCertPath: "/p.crt", peerKeyPath: "/p.key" },
        })
    ).toThrow(/peerTls requires non-empty/);

    const missingTlsProc = new RealEtcdProcess({
      name: "missing-files",
      tls: {
        caCertPath: path.join(os.tmpdir(), "does-not-exist-ca.crt"),
        serverCertPath: path.join(os.tmpdir(), "does-not-exist-srv.crt"),
        serverKeyPath: path.join(os.tmpdir(), "does-not-exist-srv.key"),
      },
    });
    await expect(missingTlsProc.start()).rejects.toThrow(/Missing tls\.caCertPath/);
  });

  it("starts and cleanly stops a real etcd v3.5.18 node with strict client and peer mTLS", async () => {
    const certs = generateTestCertificates();
    tempDirs.push(certs.bundleDir);
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "web3user-etcd-peer-tls-"));
    tempDirs.push(dataDir);

    const clientPort = await getFreePort();
    const peerPort = await getFreePort();
    const proc = new RealEtcdProcess({
      name: "peer-tls-real-node",
      clientPort,
      peerPort,
      dataDir,
      initialCluster: `peer-tls-real-node=https://127.0.0.1:${peerPort}`,
      initialClusterToken: "peer-tls-real-token",
      tls: {
        caCertPath: path.join(certs.bundleDir, "ca.crt"),
        serverCertPath: path.join(certs.bundleDir, "server.crt"),
        serverKeyPath: path.join(certs.bundleDir, "server.key"),
        clientCertPath: path.join(certs.bundleDir, "engine-client.crt"),
        clientKeyPath: path.join(certs.bundleDir, "engine-client.key"),
        clientCertAuth: true,
      },
      peerTls: {
        caCertPath: path.join(certs.bundleDir, "ca.crt"),
        peerCertPath: path.join(certs.bundleDir, "server.crt"),
        peerKeyPath: path.join(certs.bundleDir, "server.key"),
        peerClientCertAuth: true,
      },
    });
    processes.push(proc);

    const endpoint = await proc.start();
    expect(endpoint).toBe(`https://127.0.0.1:${clientPort}`);
    expect(proc.pid).toBeTypeOf("number");

    await proc.stop();
    await proc.stop(); // idempotent cleanup
  }, 20_000);

  it("stops spawned child process and closes log stream if readiness fails during start()", async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "web3user-etcd-fail-cleanup-"));
    tempDirs.push(dataDir);

    const proc = new RealEtcdProcess({
      name: "fail-cleanup-node",
      dataDir,
    });

    let capturedPid: number | undefined;
    let capturedLogStream: fs.WriteStream | null = null;
    const internal = proc as unknown as {
      waitForReady: (timeoutMs: number) => Promise<void>;
      logStream: fs.WriteStream | null;
    };

    const waitSpy = vi
      .spyOn(internal, "waitForReady")
      .mockImplementationOnce(async () => {
        capturedPid = proc.pid;
        capturedLogStream = internal.logStream;
        throw new Error("Simulated readiness failure");
      });

    await expect(proc.start()).rejects.toThrow("Simulated readiness failure");
    expect(waitSpy).toHaveBeenCalledTimes(1);
    expect(capturedPid).toBeTypeOf("number");
    expect(proc.pid).toBeUndefined();
    expect(internal.logStream).toBeNull();
    expect(capturedLogStream).not.toBeNull();
    expect(capturedLogStream!.writableEnded || capturedLogStream!.closed).toBe(true);

    // Verify OS process is no longer alive
    expect(() => process.kill(capturedPid!, 0)).toThrow();
  }, 15_000);
});
