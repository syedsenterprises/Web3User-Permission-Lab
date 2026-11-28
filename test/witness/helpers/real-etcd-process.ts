/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-A.2
 * Real etcd Process Lifecycle Manager
 *
 * Spawns, manages, monitors, and safely cleans up an official pinned etcd v3.5.18
 * binary instance on loopback (127.0.0.1).
 */

import { spawn, ChildProcess, execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import * as net from "node:net";
import * as http from "node:http";
import * as https from "node:https";

export const PINNED_ETCD_VERSION = "3.5.18";
const MAX_OUTPUT_BUFFER_CHARS = 8192;

export interface RealEtcdTlsOptions {
  caCertPath: string;
  serverCertPath: string;
  serverKeyPath: string;
  clientCertPath?: string;
  clientKeyPath?: string;
  clientCertAuth?: boolean;
}

export interface RealEtcdPeerTlsOptions {
  caCertPath: string;
  peerCertPath: string;
  peerKeyPath: string;
  peerClientCertAuth?: boolean;
}

export interface RealEtcdOptions {
  name?: string;
  clientPort?: number;
  peerPort?: number;
  dataDir?: string;
  tls?: RealEtcdTlsOptions;
  peerTls?: RealEtcdPeerTlsOptions;
  initialCluster?: string;
  initialClusterToken?: string;
  autoCompactionRetention?: string;
  heartbeatIntervalMs?: number;
  electionTimeoutMs?: number;
}

export async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      if (addr && typeof addr === "object") {
        const port = addr.port;
        srv.close(() => resolve(port));
      } else {
        srv.close(() => reject(new Error("Unable to obtain free loopback port")));
      }
    });
    srv.on("error", reject);
  });
}

export class RealEtcdProcess {
  public readonly etcdBinary: string;
  public readonly etcdctlBinary: string;
  public readonly name: string;
  public readonly dataDir: string;
  public clientPort: number = 0;
  public peerPort: number = 0;

  private child: ChildProcess | null = null;
  private logStream: fs.WriteStream | null = null;
  private isRunning = false;
  private readonly options: RealEtcdOptions;
  private stdoutTail = "";
  private stderrTail = "";
  private exitInfo: string | null = null;

  constructor(options: RealEtcdOptions = {}) {
    this.options = options;
    this.name = options.name || `etcd-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    this.validateOptions(options);
    this.clientPort = options.clientPort ?? 0;
    this.peerPort = options.peerPort ?? 0;

    const ext = process.platform === "win32" ? ".exe" : "";
    const binDir = process.env.ETCD_BIN_DIR
      ? path.resolve(process.env.ETCD_BIN_DIR)
      : path.resolve(process.cwd(), `.tmp/etcd-bin/v${PINNED_ETCD_VERSION}`);

    this.etcdBinary = path.join(binDir, `etcd${ext}`);
    this.etcdctlBinary = path.join(binDir, `etcdctl${ext}`);

    if (!fs.existsSync(this.etcdBinary)) {
      throw new Error(
        `Pinned etcd v${PINNED_ETCD_VERSION} binary not found at ${this.etcdBinary}. Run 'node scripts/ensure-etcd.mjs' first.`
      );
    }

    const versionOut = execFileSync(this.etcdBinary, ["--version"], {
      encoding: "utf8",
      timeout: 5000,
    });
    if (!versionOut.includes(`etcd Version: ${PINNED_ETCD_VERSION}`)) {
      throw new Error(
        `Unexpected etcd version at ${this.etcdBinary}; expected v${PINNED_ETCD_VERSION}, got:\n${versionOut}`
      );
    }

    if (options.dataDir) {
      this.dataDir = path.resolve(options.dataDir);
    } else {
      const dataParent = path.resolve(process.cwd(), ".tmp/etcd-data");
      fs.mkdirSync(dataParent, { recursive: true });
      this.dataDir = path.join(dataParent, `${this.name}.data`);
    }
  }

  public get clientEndpoint(): string {
    const scheme = this.options.tls ? "https" : "http";
    return `${scheme}://127.0.0.1:${this.clientPort}`;
  }

  public get peerEndpoint(): string {
    const scheme = this.options.peerTls ? "https" : "http";
    return `${scheme}://127.0.0.1:${this.peerPort}`;
  }

  public get grpcEndpoint(): string {
    return `127.0.0.1:${this.clientPort}`;
  }

  public get pid(): number | undefined {
    return this.child?.pid;
  }

  private validateOptions(options: RealEtcdOptions): void {
    const validatePort = (port: number | undefined, label: string) => {
      if (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65535)) {
        throw new Error(`Invalid ${label}: expected integer port 1..65535, got ${port}`);
      }
    };
    validatePort(options.clientPort, "clientPort");
    validatePort(options.peerPort, "peerPort");
    if (options.clientPort !== undefined && options.peerPort !== undefined && options.clientPort === options.peerPort) {
      throw new Error(`clientPort and peerPort must be distinct (both ${options.clientPort})`);
    }

    if (options.initialClusterToken !== undefined && options.initialClusterToken.trim().length === 0) {
      throw new Error("initialClusterToken must be a non-empty string when provided");
    }

    if (options.initialCluster !== undefined) {
      const trimmed = options.initialCluster.trim();
      if (!trimmed) {
        throw new Error("initialCluster must be a non-empty string when provided");
      }
      const expectedProtocol = options.peerTls ? "https:" : "http:";
      const entries = trimmed.split(",").map((e) => e.trim());
      const seenNames = new Set<string>();
      const seenUrls = new Set<string>();
      let containsSelf = false;

      for (const entry of entries) {
        const eqIdx = entry.indexOf("=");
        if (eqIdx <= 0 || eqIdx === entry.length - 1) {
          throw new Error(`Invalid initialCluster entry "${entry}": expected "<name>=<peerUrl>"`);
        }
        const memberName = entry.slice(0, eqIdx).trim();
        const memberUrl = entry.slice(eqIdx + 1).trim();

        if (!memberName) {
          throw new Error(`Invalid initialCluster entry "${entry}": member name must be non-empty`);
        }
        if (seenNames.has(memberName)) {
          throw new Error(`Duplicate member name "${memberName}" in initialCluster`);
        }
        seenNames.add(memberName);

        let parsed: URL;
        try {
          parsed = new URL(memberUrl);
        } catch {
          throw new Error(`Invalid peer URL "${memberUrl}" for member "${memberName}" in initialCluster`);
        }

        if (parsed.protocol !== expectedProtocol) {
          throw new Error(
            `initialCluster member "${memberName}" URL "${memberUrl}" must use "${expectedProtocol}" to match peerTls=${Boolean(options.peerTls)}`
          );
        }
        if (!parsed.hostname) {
          throw new Error(`Invalid peer URL "${memberUrl}" for member "${memberName}": missing hostname`);
        }
        if (parsed.username !== "" || parsed.password !== "") {
          throw new Error(
            `Invalid peer URL "${memberUrl}" for member "${memberName}": embedded credentials are not allowed`
          );
        }
        if (parsed.pathname !== "/") {
          throw new Error(
            `Invalid peer URL "${memberUrl}" for member "${memberName}": non-root path "${parsed.pathname}" is not allowed`
          );
        }
        if (parsed.search !== "") {
          throw new Error(
            `Invalid peer URL "${memberUrl}" for member "${memberName}": query strings are not allowed`
          );
        }
        if (parsed.hash !== "") {
          throw new Error(
            `Invalid peer URL "${memberUrl}" for member "${memberName}": fragments are not allowed`
          );
        }
        const portNum = Number(parsed.port);
        if (!parsed.port || !Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
          throw new Error(`Invalid peer URL "${memberUrl}" for member "${memberName}": invalid port`);
        }

        const normalizedOrigin = `${parsed.protocol}//${parsed.hostname}:${portNum}`;
        if (seenUrls.has(normalizedOrigin)) {
          throw new Error(`Duplicate peer URL "${memberUrl}" in initialCluster`);
        }
        seenUrls.add(normalizedOrigin);

        if (memberName === this.name) {
          containsSelf = true;
          if (options.peerPort !== undefined) {
            const expectedLocal = `${expectedProtocol}//127.0.0.1:${options.peerPort}`;
            if (normalizedOrigin !== expectedLocal) {
              throw new Error(
                `initialCluster local member "${this.name}" URL "${memberUrl}" does not match configured peer endpoint "${expectedLocal}"`
              );
            }
          }
        }
      }
      if (!containsSelf) {
        throw new Error(`initialCluster must include an entry for this node ("${this.name}=")`);
      }
    }

    if (options.tls) {
      if (!options.tls.caCertPath?.trim() || !options.tls.serverCertPath?.trim() || !options.tls.serverKeyPath?.trim()) {
        throw new Error("tls requires non-empty caCertPath, serverCertPath, and serverKeyPath");
      }
    }

    if (options.peerTls) {
      if (!options.peerTls.caCertPath?.trim() || !options.peerTls.peerCertPath?.trim() || !options.peerTls.peerKeyPath?.trim()) {
        throw new Error("peerTls requires non-empty caCertPath, peerCertPath, and peerKeyPath");
      }
    }
  }

  private validateTlsFilesExist(): void {
    const checkFile = (filePath: string | undefined, label: string) => {
      if (filePath && !fs.existsSync(filePath)) {
        throw new Error(`Missing ${label} file at ${filePath}`);
      }
    };
    if (this.options.tls) {
      checkFile(this.options.tls.caCertPath, "tls.caCertPath");
      checkFile(this.options.tls.serverCertPath, "tls.serverCertPath");
      checkFile(this.options.tls.serverKeyPath, "tls.serverKeyPath");
      checkFile(this.options.tls.clientCertPath, "tls.clientCertPath");
      checkFile(this.options.tls.clientKeyPath, "tls.clientKeyPath");
    }
    if (this.options.peerTls) {
      checkFile(this.options.peerTls.caCertPath, "peerTls.caCertPath");
      checkFile(this.options.peerTls.peerCertPath, "peerTls.peerCertPath");
      checkFile(this.options.peerTls.peerKeyPath, "peerTls.peerKeyPath");
    }
  }

  public getLaunchArgs(): string[] {
    const clientUrl = this.clientEndpoint;
    const peerUrl = this.peerEndpoint;
    const initialCluster = this.options.initialCluster?.trim() || `${this.name}=${peerUrl}`;
    const initialClusterToken = this.options.initialClusterToken?.trim() || `cluster-${this.name}`;

    const args = [
      `--name=${this.name}`,
      `--data-dir=${this.dataDir}`,
      `--listen-client-urls=${clientUrl}`,
      `--advertise-client-urls=${clientUrl}`,
      `--listen-peer-urls=${peerUrl}`,
      `--initial-advertise-peer-urls=${peerUrl}`,
      `--initial-cluster=${initialCluster}`,
      `--initial-cluster-state=new`,
      `--initial-cluster-token=${initialClusterToken}`,
      `--logger=zap`,
      `--log-outputs=stderr`,
      `--heartbeat-interval=${this.options.heartbeatIntervalMs ?? 100}`,
      `--election-timeout=${this.options.electionTimeoutMs ?? 1000}`,
    ];

    if (this.options.autoCompactionRetention) {
      args.push(`--auto-compaction-retention=${this.options.autoCompactionRetention}`);
    }

    if (this.options.tls) {
      args.push(
        `--cert-file=${this.options.tls.serverCertPath}`,
        `--key-file=${this.options.tls.serverKeyPath}`,
        `--trusted-ca-file=${this.options.tls.caCertPath}`
      );
      if (this.options.tls.clientCertAuth) {
        args.push(`--client-cert-auth=true`);
      }
    }

    if (this.options.peerTls) {
      args.push(
        `--peer-cert-file=${this.options.peerTls.peerCertPath}`,
        `--peer-key-file=${this.options.peerTls.peerKeyPath}`,
        `--peer-trusted-ca-file=${this.options.peerTls.caCertPath}`
      );
      if (this.options.peerTls.peerClientCertAuth) {
        args.push(`--peer-client-cert-auth=true`);
      }
    }

    return args;
  }

  public async start(): Promise<string> {
    if (this.isRunning) {
      return this.clientEndpoint;
    }

    this.validateTlsFilesExist();

    if (!this.clientPort) {
      this.clientPort = this.options.clientPort || (await getFreePort());
    }
    if (!this.peerPort) {
      this.peerPort = this.options.peerPort || (await getFreePort());
    }

    fs.mkdirSync(this.dataDir, { recursive: true });
    const logDir = path.resolve(process.cwd(), ".tmp/logs");
    fs.mkdirSync(logDir, { recursive: true });
    const logPath = path.join(logDir, `${this.name}.log`);
    this.logStream = fs.createWriteStream(logPath, { flags: "a" });

    const args = this.getLaunchArgs();

    this.stdoutTail = "";
    this.stderrTail = "";
    this.exitInfo = null;

    this.child = spawn(this.etcdBinary, args, {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: process.platform === "win32",
    });

    if (this.child.stderr) {
      this.child.stderr.on("data", (chunk: Buffer) => {
        this.stderrTail = (this.stderrTail + chunk.toString("utf8")).slice(-MAX_OUTPUT_BUFFER_CHARS);
      });
      if (this.logStream) {
        this.child.stderr.pipe(this.logStream);
      }
    }
    if (this.child.stdout) {
      this.child.stdout.on("data", (chunk: Buffer) => {
        this.stdoutTail = (this.stdoutTail + chunk.toString("utf8")).slice(-MAX_OUTPUT_BUFFER_CHARS);
      });
      if (this.logStream) {
        this.child.stdout.pipe(this.logStream);
      }
    }

    this.child.on("exit", (code, signal) => {
      this.isRunning = false;
      this.exitInfo = `code=${code}, signal=${signal}`;
    });

    try {
      await this.waitForReady(10000);
    } catch (err) {
      await this.stop().catch(() => {});
      throw err;
    }
    this.isRunning = true;
    return this.clientEndpoint;
  }

  public async stop(): Promise<void> {
    if (!this.child || !this.child.pid) {
      this.isRunning = false;
      return;
    }

    const child = this.child;
    const pid = child.pid;
    const waitExit = new Promise<void>((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) {
        resolve();
        return;
      }
      child.once("exit", () => resolve());
    });

    if (process.platform === "win32") {
      try {
        execFileSync("taskkill", ["/F", "/T", "/PID", String(pid)], { stdio: "ignore" });
      } catch {
        try {
          child.kill("SIGKILL");
        } catch {
          // Child may have already exited
        }
      }
      await Promise.race([waitExit, new Promise((r) => setTimeout(r, 2000))]);
    } else {
      try {
        child.kill("SIGTERM");
      } catch {
        // Child may have already exited
      }
      const graceful = await Promise.race([
        waitExit.then(() => true),
        new Promise<boolean>((r) => setTimeout(() => r(false), 1500)),
      ]);
      if (!graceful && child.exitCode === null && child.signalCode === null) {
        try {
          child.kill("SIGKILL");
        } catch {
          // Child may have already exited
        }
        await Promise.race([waitExit, new Promise((r) => setTimeout(r, 1000))]);
      }
    }

    if (this.logStream) {
      this.logStream.end();
      this.logStream = null;
    }
    this.child = null;
    this.isRunning = false;
  }

  /**
   * Builds a dedicated HTTPS agent with CA/client mTLS credentials and default
   * strict certificate validation (`rejectUnauthorized: true`) when TLS is enabled.
   */
  private createTlsAgent(): https.Agent | undefined {
    const tls = this.options.tls;
    if (!tls) {
      return undefined;
    }

    const ca =
      tls.caCertPath && fs.existsSync(tls.caCertPath)
        ? fs.readFileSync(tls.caCertPath)
        : undefined;
    const cert =
      tls.clientCertPath && fs.existsSync(tls.clientCertPath)
        ? fs.readFileSync(tls.clientCertPath)
        : undefined;
    const key =
      tls.clientKeyPath && fs.existsSync(tls.clientKeyPath)
        ? fs.readFileSync(tls.clientKeyPath)
        : undefined;

    return new https.Agent({ ca, cert, key, keepAlive: false });
  }

  public async compact(revision: bigint): Promise<void> {
    const agent = this.createTlsAgent();
    try {
      await new Promise<void>((resolve, reject) => {
        const clientModule = agent ? https : http;
        const req = clientModule.request(
          {
            hostname: "127.0.0.1",
            port: this.clientPort,
            path: "/v3/kv/compaction",
            method: "POST",
            headers: { "Content-Type": "application/json" },
            agent,
          },
          (res) => {
            let body = "";
            res.on("data", (chunk) => { body += chunk; });
            res.on("end", () => {
              if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                resolve();
              } else {
                reject(new Error(`Compaction failed with status ${res.statusCode}: ${body}`));
              }
            });
          }
        );

        req.on("error", reject);
        req.write(JSON.stringify({ revision: Number(revision), physical: true }));
        req.end();
      });
    } finally {
      agent?.destroy();
    }
  }

  private async waitForReady(timeoutMs: number): Promise<void> {
    const startTime = Date.now();
    const agent = this.createTlsAgent();

    try {
      while (Date.now() - startTime < timeoutMs) {
        try {
          const ok = await new Promise<boolean>((resolve) => {
            const checkOptions: https.RequestOptions = {
              hostname: "127.0.0.1",
              port: this.clientPort,
              path: "/health",
              method: "GET",
              timeout: 500,
              agent,
            };

            const clientModule = agent ? https : http;
            const req = clientModule.request(checkOptions, (res) => {
              let data = "";
              res.on("data", (chunk) => { data += chunk; });
              res.on("end", () => {
                try {
                  const parsed = JSON.parse(data);
                  resolve(res.statusCode === 200 && parsed.health === "true");
                } catch {
                  resolve(res.statusCode === 200);
                }
              });
            });

            req.on("error", () => resolve(false));
            req.on("timeout", () => {
              req.destroy();
              resolve(false);
            });
            req.end();
          });

          if (ok) {
            return;
          }
        } catch {
          // Retry
        }
        if (this.exitInfo) {
          throw new Error(
            `etcd instance ${this.name} exited before becoming ready (${this.exitInfo}).\nstderr:\n${this.stderrTail}\nstdout:\n${this.stdoutTail}`
          );
        }
        await new Promise((r) => setTimeout(r, 100));
      }

      throw new Error(
        `etcd instance ${this.name} failed to reach ready state within ${timeoutMs}ms.\nstderr:\n${this.stderrTail}\nstdout:\n${this.stdoutTail}`
      );
    } finally {
      agent?.destroy();
    }
  }
}
