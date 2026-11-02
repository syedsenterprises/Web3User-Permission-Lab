/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-A.2
 * Real etcd Process Lifecycle Manager
 *
 * Spawns, manages, monitors, and safely cleans up an official pinned etcd v3.5.18
 * binary instance on loopback (127.0.0.1).
 */

import { spawn, ChildProcess, execSync, execFile } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import * as net from "node:net";
import * as http from "node:http";
import * as https from "node:https";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface RealEtcdTlsOptions {
  caCertPath: string;
  serverCertPath: string;
  serverKeyPath: string;
  clientCertPath?: string;
  clientKeyPath?: string;
  clientCertAuth?: boolean;
}

export interface RealEtcdOptions {
  name?: string;
  clientPort?: number;
  peerPort?: number;
  dataDir?: string;
  tls?: RealEtcdTlsOptions;
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

  constructor(options: RealEtcdOptions = {}) {
    this.options = options;
    this.name = options.name || `etcd-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    this.etcdBinary = path.resolve(process.cwd(), ".tmp/etcd-bin/v3.5.18/etcd.exe");
    this.etcdctlBinary = path.resolve(process.cwd(), ".tmp/etcd-bin/v3.5.18/etcdctl.exe");

    if (!fs.existsSync(this.etcdBinary)) {
      throw new Error(`etcd binary not found at ${this.etcdBinary}. Verification pass failed or missing.`);
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

  public get grpcEndpoint(): string {
    return `127.0.0.1:${this.clientPort}`;
  }

  public get pid(): number | undefined {
    return this.child?.pid;
  }

  public async start(): Promise<string> {
    if (this.isRunning) {
      return this.clientEndpoint;
    }

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

    const scheme = this.options.tls ? "https" : "http";
    const clientUrl = `${scheme}://127.0.0.1:${this.clientPort}`;
    const peerUrl = `http://127.0.0.1:${this.peerPort}`;

    const args = [
      `--name=${this.name}`,
      `--data-dir=${this.dataDir}`,
      `--listen-client-urls=${clientUrl}`,
      `--advertise-client-urls=${clientUrl}`,
      `--listen-peer-urls=${peerUrl}`,
      `--initial-advertise-peer-urls=${peerUrl}`,
      `--initial-cluster=${this.name}=${peerUrl}`,
      `--initial-cluster-state=new`,
      `--initial-cluster-token=cluster-${this.name}`,
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

    this.child = spawn(this.etcdBinary, args, {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });

    if (this.child.stderr && this.logStream) {
      this.child.stderr.pipe(this.logStream);
    }
    if (this.child.stdout && this.logStream) {
      this.child.stdout.pipe(this.logStream);
    }

    this.child.on("exit", () => {
      this.isRunning = false;
    });

    await this.waitForReady(10000);
    this.isRunning = true;
    return this.clientEndpoint;
  }

  public async stop(): Promise<void> {
    if (!this.child || !this.child.pid) {
      this.isRunning = false;
      return;
    }

    const pid = this.child.pid;
    try {
      // Precise process termination on Windows
      execSync(`taskkill /F /PID ${pid}`, { stdio: "ignore" });
    } catch {
      // Child may have already exited
    }

    await new Promise<void>((resolve) => {
      if (!this.child || this.child.exitCode !== null) {
        resolve();
        return;
      }
      this.child.once("exit", () => resolve());
      setTimeout(resolve, 2000);
    });

    if (this.logStream) {
      this.logStream.end();
      this.logStream = null;
    }
    this.child = null;
    this.isRunning = false;
  }

  public async compact(revision: bigint): Promise<void> {
    const isTls = Boolean(this.options.tls);
    let caCert: Buffer | undefined;
    let clientCert: Buffer | undefined;
    let clientKey: Buffer | undefined;

    if (isTls && this.options.tls) {
      if (this.options.tls.caCertPath && fs.existsSync(this.options.tls.caCertPath)) {
        caCert = fs.readFileSync(this.options.tls.caCertPath);
      }
      if (this.options.tls.clientCertPath && fs.existsSync(this.options.tls.clientCertPath)) {
        clientCert = fs.readFileSync(this.options.tls.clientCertPath);
      }
      if (this.options.tls.clientKeyPath && fs.existsSync(this.options.tls.clientKeyPath)) {
        clientKey = fs.readFileSync(this.options.tls.clientKeyPath);
      }
    }

    await new Promise<void>((resolve, reject) => {
      const clientModule = isTls ? https : http;
      const req = clientModule.request(
        {
          hostname: "127.0.0.1",
          port: this.clientPort,
          path: "/v3/kv/compaction",
          method: "POST",
          headers: { "Content-Type": "application/json" },
          ca: caCert,
          cert: clientCert,
          key: clientKey,
          rejectUnauthorized: false,
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
  }

  private async waitForReady(timeoutMs: number): Promise<void> {
    const startTime = Date.now();
    const isTls = Boolean(this.options.tls);

    let caCert: Buffer | undefined;
    let clientCert: Buffer | undefined;
    let clientKey: Buffer | undefined;

    if (isTls && this.options.tls) {
      if (this.options.tls.caCertPath && fs.existsSync(this.options.tls.caCertPath)) {
        caCert = fs.readFileSync(this.options.tls.caCertPath);
      }
      if (this.options.tls.clientCertPath && fs.existsSync(this.options.tls.clientCertPath)) {
        clientCert = fs.readFileSync(this.options.tls.clientCertPath);
      }
      if (this.options.tls.clientKeyPath && fs.existsSync(this.options.tls.clientKeyPath)) {
        clientKey = fs.readFileSync(this.options.tls.clientKeyPath);
      }
    }

    while (Date.now() - startTime < timeoutMs) {
      try {
        const ok = await new Promise<boolean>((resolve) => {
          const checkOptions = {
            hostname: "127.0.0.1",
            port: this.clientPort,
            path: "/health",
            method: "GET",
            timeout: 500,
            ca: caCert,
            cert: clientCert,
            key: clientKey,
            rejectUnauthorized: false,
          };

          const clientModule = isTls ? https : http;
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
      await new Promise((r) => setTimeout(r, 100));
    }

    throw new Error(`etcd instance ${this.name} failed to reach ready state within ${timeoutMs}ms`);
  }
}
