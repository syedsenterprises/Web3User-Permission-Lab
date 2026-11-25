/**
 * Web3User Permission Lab - Milestone 13-D Phase D3
 * Disposable In-Process etcd gRPC Server Test Harness
 *
 * Implements a faithful, in-process gRPC server implementing etcd v3 MVCC KV,
 * Txn, Watch, and Maintenance services on loopback TCP. Used for deterministic,
 * zero-daemon integration testing of the etcd client adapter.
 */

import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import * as path from "path";

export interface StoredValue {
  key: Buffer;
  value: Buffer;
  createRevision: bigint;
  modRevision: bigint;
  version: bigint;
  lease?: bigint;
}

export interface HistoryEvent {
  revision: bigint;
  type: "Put" | "Delete";
  kv: StoredValue;
  prevKv?: StoredValue;
}

interface ActiveWatcher {
  watchId: bigint;
  key: string;
  rangeEnd: string;
  stream: grpc.ServerDuplexStream<any, any>;
}

export interface DisposableEtcdServerOptions {
  initialRevision?: bigint;
  clusterId?: string;
  memberId?: string;
  raftTerm?: bigint;
  serverCert?: Buffer | string;
  serverKey?: Buffer | string;
  caCert?: Buffer | string;
}

function matchesKeyRange(k: string, keyStr: string, rangeEndStr: string): boolean {
  if (rangeEndStr.length === 0) {
    return k === keyStr;
  }
  if (rangeEndStr === "\0") {
    return k >= keyStr;
  }
  return k >= keyStr && k < rangeEndStr;
}

export class DisposableEtcdServer {
  private server: grpc.Server;
  private port = 0;
  private endpoint = "";
  public currentRevision: bigint;
  public compactRevision = 0n;
  public readonly clusterId: string;
  public readonly memberId: string;
  public readonly raftTerm: bigint;

  private store = new Map<string, StoredValue>();
  private history: HistoryEvent[] = [];
  private watchers = new Map<bigint, ActiveWatcher>();
  private nextWatchId = 1n;

  // Fault injection hooks
  private delayMs = 0;
  private failNextMethod: string | null = null;
  private failNextError: grpc.ServiceError | null = null;
  private failAttemptsRemaining = 0;

  constructor(options?: DisposableEtcdServerOptions) {
    this.currentRevision = options?.initialRevision ?? 1000n;
    this.clusterId = options?.clusterId ?? "14841639077221209701";
    this.memberId = options?.memberId ?? "102603348655986349";
    this.raftTerm = options?.raftTerm ?? 1n;
    this.server = new grpc.Server();
  }

  public async start(): Promise<string> {
    const protoPath = path.resolve(process.cwd(), "node_modules/etcd3/proto/rpc.proto");
    const packageDefinition = protoLoader.loadSync(protoPath, {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true,
      includeDirs: [path.resolve(process.cwd(), "node_modules/etcd3/proto")],
    });

    const desc: any = grpc.loadPackageDefinition(packageDefinition);
    const etcdserverpb = desc.etcdserverpb;

    // 1. KV Service Implementation
    this.server.addService(etcdserverpb.KV.service, {
      Range: (call: any, callback: any) => this.handleRange(call, callback),
      Put: (call: any, callback: any) => this.handlePut(call, callback),
      DeleteRange: (call: any, callback: any) => this.handleDeleteRange(call, callback),
      Txn: (call: any, callback: any) => this.handleTxn(call, callback),
    });

    // 2. Watch Service Implementation
    this.server.addService(etcdserverpb.Watch.service, {
      Watch: (stream: grpc.ServerDuplexStream<any, any>) => this.handleWatchStream(stream),
    });

    // 3. Maintenance Service Implementation
    this.server.addService(etcdserverpb.Maintenance.service, {
      Status: (call: any, callback: any) => this.handleStatus(call, callback),
    });

    return new Promise((resolve, reject) => {
      this.server.bindAsync(
        "127.0.0.1:0",
        grpc.ServerCredentials.createInsecure(),
        (err, port) => {
          if (err) return reject(err);
          this.port = port;
          this.endpoint = `http://127.0.0.1:${port}`;
          resolve(this.endpoint);
        }
      );
    });
  }

  public getEndpoint(): string {
    return this.endpoint;
  }

  public getPort(): number {
    return this.port;
  }

  public async stop(): Promise<void> {
    return new Promise((resolve) => {
      this.disconnectAllWatchers();
      this.server.tryShutdown(() => resolve());
      setTimeout(() => {
        try {
          this.server.forceShutdown();
        } catch {}
        resolve();
      }, 500);
    });
  }

  // ==========================================================================
  // Fault Injection APIs
  // ==========================================================================

  public setDelay(ms: number): void {
    this.delayMs = ms;
  }

  public compact(revision: bigint): void {
    this.compactRevision = revision;
    this.history = this.history.filter((h) => h.revision >= revision);
    for (const watcher of this.watchers.values()) {
      try {
        watcher.stream.write({
          header: this.getHeader(),
          watch_id: String(watcher.watchId),
          canceled: true,
          compact_revision: String(this.compactRevision),
          cancel_reason: "etcdserver: mvcc: required revision has been compacted",
        });
      } catch {}
    }
  }

  public failNext(method: string, code: grpc.status, message: string, attempts = 5): void {
    this.failNextMethod = method;
    this.failAttemptsRemaining = attempts;
    this.failNextError = {
      name: "ServiceError",
      message,
      code,
      details: message,
      metadata: new grpc.Metadata(),
    };
  }

  public disconnectAllWatchers(): void {
    for (const watcher of this.watchers.values()) {
      try {
        watcher.stream.end();
      } catch {}
    }
    this.watchers.clear();
  }

  // ==========================================================================
  // Service Handlers
  // ==========================================================================

  private getHeader() {
    return {
      cluster_id: this.clusterId,
      member_id: this.memberId,
      revision: String(this.currentRevision),
      raft_term: String(this.raftTerm),
    };
  }

  private applyDelay(): Promise<void> {
    if (this.delayMs > 0) {
      return new Promise((resolve) => setTimeout(resolve, this.delayMs));
    }
    return Promise.resolve();
  }

  private checkFailure(method: string, callback: any): boolean {
    if (this.failNextMethod === method && this.failNextError && this.failAttemptsRemaining > 0) {
      const err = this.failNextError;
      this.failAttemptsRemaining--;
      if (this.failAttemptsRemaining <= 0) {
        this.failNextMethod = null;
        this.failNextError = null;
      }
      callback(err, null);
      return true;
    }
    return false;
  }

  private async handleStatus(call: any, callback: any): Promise<void> {
    await this.applyDelay();
    if (this.checkFailure("Status", callback)) return;
    callback(null, {
      header: this.getHeader(),
      version: "3.5.12",
      dbSize: "1024",
      leader: this.memberId,
      raftIndex: String(this.currentRevision),
      raftTerm: String(this.raftTerm),
    });
  }

  private async handleRange(call: any, callback: any): Promise<void> {
    await this.applyDelay();
    if (this.checkFailure("Range", callback)) return;

    const keyBuf = Buffer.isBuffer(call.request.key) ? call.request.key : Buffer.from(call.request.key || "");
    const keyStr = keyBuf.toString("utf8");
    const rangeEndBuf = Buffer.isBuffer(call.request.range_end) ? call.request.range_end : Buffer.from(call.request.range_end || "");
    const rangeEndStr = rangeEndBuf.toString("utf8");
    const limit = Number(call.request.limit || 0);

    const matches: StoredValue[] = [];

    for (const [k, v] of this.store.entries()) {
      if (matchesKeyRange(k, keyStr, rangeEndStr)) {
        matches.push(v);
      }
    }
    // Sort matches by key ascending
    matches.sort((a, b) => a.key.toString("utf8").localeCompare(b.key.toString("utf8")));

    const limited = limit > 0 ? matches.slice(0, limit) : matches;

    callback(null, {
      header: this.getHeader(),
      kvs: limited.map((item) => ({
        key: item.key,
        value: item.value,
        create_revision: String(item.createRevision),
        mod_revision: String(item.modRevision),
        version: String(item.version),
        lease: item.lease ? String(item.lease) : undefined,
      })),
      more: matches.length > limited.length,
      count: String(matches.length),
    });
  }

  private async handlePut(call: any, callback: any): Promise<void> {
    await this.applyDelay();
    if (this.checkFailure("Put", callback)) return;

    const keyBuf = Buffer.isBuffer(call.request.key) ? call.request.key : Buffer.from(call.request.key || "");
    const valBuf = Buffer.isBuffer(call.request.value) ? call.request.value : Buffer.from(call.request.value || "");
    const keyStr = keyBuf.toString("utf8");
    const lease = call.request.lease ? BigInt(call.request.lease) : undefined;
    const prev = this.store.get(keyStr);

    this.currentRevision += 1n;
    const newVersion = prev ? prev.version + 1n : 1n;
    const createRev = prev ? prev.createRevision : this.currentRevision;

    const stored: StoredValue = {
      key: keyBuf,
      value: valBuf,
      createRevision: createRev,
      modRevision: this.currentRevision,
      version: newVersion,
      lease,
    };

    this.store.set(keyStr, stored);

    const historyEvent: HistoryEvent = {
      revision: this.currentRevision,
      type: "Put",
      kv: stored,
      prevKv: prev,
    };
    this.history.push(historyEvent);
    this.notifyWatchers(historyEvent);

    const response: any = {
      header: this.getHeader(),
    };

    if (call.request.prev_kv && prev) {
      response.prev_kv = {
        key: prev.key,
        value: prev.value,
        create_revision: String(prev.createRevision),
        mod_revision: String(prev.modRevision),
        version: String(prev.version),
      };
    }

    callback(null, response);
  }

  private async handleDeleteRange(call: any, callback: any): Promise<void> {
    await this.applyDelay();
    if (this.checkFailure("DeleteRange", callback)) return;

    const keyBuf = Buffer.isBuffer(call.request.key) ? call.request.key : Buffer.from(call.request.key || "");
    const keyStr = keyBuf.toString("utf8");
    const rangeEndBuf = Buffer.isBuffer(call.request.range_end) ? call.request.range_end : Buffer.from(call.request.range_end || "");
    const rangeEndStr = rangeEndBuf.toString("utf8");

    const toDelete: string[] = [];

    for (const k of this.store.keys()) {
      if (matchesKeyRange(k, keyStr, rangeEndStr)) {
        toDelete.push(k);
      }
    }

    if (toDelete.length > 0) {
      this.currentRevision += 1n;
      for (const k of toDelete) {
        const prev = this.store.get(k)!;
        this.store.delete(k);
        const historyEvent: HistoryEvent = {
          revision: this.currentRevision,
          type: "Delete",
          kv: {
            key: prev.key,
            value: Buffer.from([]),
            createRevision: prev.createRevision,
            modRevision: this.currentRevision,
            version: 0n,
          },
          prevKv: prev,
        };
        this.history.push(historyEvent);
        this.notifyWatchers(historyEvent);
      }
    }

    callback(null, {
      header: this.getHeader(),
      deleted: String(toDelete.length),
    });
  }

  private async handleTxn(call: any, callback: any): Promise<void> {
    await this.applyDelay();
    if (this.checkFailure("Txn", callback)) return;

    const compares = call.request.compare || [];
    let succeeded = true;

    for (const cmp of compares) {
      const keyBuf = Buffer.isBuffer(cmp.key) ? cmp.key : Buffer.from(cmp.key || "");
      const keyStr = keyBuf.toString("utf8");
      const existing = this.store.get(keyStr);

      const target = String(cmp.target || "");
      const resultOp = String(cmp.result || "");

      let actualVal: bigint | string | Buffer = 0n;
      let expectedVal: bigint | string | Buffer = 0n;

      if (target === "Version" || target === "0") {
        actualVal = existing ? existing.version : 0n;
        expectedVal = BigInt(cmp.version || "0");
      } else if (target === "Create" || target === "1") {
        actualVal = existing ? existing.createRevision : 0n;
        expectedVal = BigInt(cmp.create_revision || "0");
      } else if (target === "Mod" || target === "2") {
        actualVal = existing ? existing.modRevision : 0n;
        expectedVal = BigInt(cmp.mod_revision || "0");
      } else if (target === "Value" || target === "3") {
        actualVal = existing ? existing.value : Buffer.from([]);
        expectedVal = Buffer.isBuffer(cmp.value) ? cmp.value : Buffer.from(cmp.value || "");
      }

      let cmpMatches = false;
      if (Buffer.isBuffer(actualVal) && Buffer.isBuffer(expectedVal)) {
        const areEq = actualVal.equals(expectedVal);
        if (resultOp === "Equal" || resultOp === "0") cmpMatches = areEq;
        else if (resultOp === "NotEqual" || resultOp === "3") cmpMatches = !areEq;
      } else {
        const a = BigInt(actualVal as any);
        const b = BigInt(expectedVal as any);
        if (resultOp === "Equal" || resultOp === "0") cmpMatches = a === b;
        else if (resultOp === "Greater" || resultOp === "1") cmpMatches = a > b;
        else if (resultOp === "Less" || resultOp === "2") cmpMatches = a < b;
        else if (resultOp === "NotEqual" || resultOp === "3") cmpMatches = a !== b;
      }

      if (!cmpMatches) {
        succeeded = false;
        break;
      }
    }

    const opsToRun = succeeded ? call.request.success || [] : call.request.failure || [];
    const responses: any[] = [];
    let mutated = false;

    for (const op of opsToRun) {
      if (op.request_put) {
        const p = op.request_put;
        const keyBuf = Buffer.isBuffer(p.key) ? p.key : Buffer.from(p.key || "");
        const valBuf = Buffer.isBuffer(p.value) ? p.value : Buffer.from(p.value || "");
        const keyStr = keyBuf.toString("utf8");
        const prev = this.store.get(keyStr);

        if (!mutated) {
          this.currentRevision += 1n;
          mutated = true;
        }

        const stored: StoredValue = {
          key: keyBuf,
          value: valBuf,
          createRevision: prev ? prev.createRevision : this.currentRevision,
          modRevision: this.currentRevision,
          version: prev ? prev.version + 1n : 1n,
        };
        this.store.set(keyStr, stored);

        const historyEvent: HistoryEvent = {
          revision: this.currentRevision,
          type: "Put",
          kv: stored,
          prevKv: prev,
        };
        this.history.push(historyEvent);
        this.notifyWatchers(historyEvent);

        responses.push({
          response_put: {
            header: this.getHeader(),
          },
        });
      } else if (op.request_delete_range) {
        const d = op.request_delete_range;
        const keyBuf = Buffer.isBuffer(d.key) ? d.key : Buffer.from(d.key || "");
        const keyStr = keyBuf.toString("utf8");
        const prev = this.store.get(keyStr);
        let deleted = 0;

        if (prev) {
          if (!mutated) {
            this.currentRevision += 1n;
            mutated = true;
          }
          this.store.delete(keyStr);
          deleted = 1;
          const historyEvent: HistoryEvent = {
            revision: this.currentRevision,
            type: "Delete",
            kv: {
              key: prev.key,
              value: Buffer.from([]),
              createRevision: prev.createRevision,
              modRevision: this.currentRevision,
              version: 0n,
            },
            prevKv: prev,
          };
          this.history.push(historyEvent);
          this.notifyWatchers(historyEvent);
        }

        responses.push({
          response_delete_range: {
            header: this.getHeader(),
            deleted: String(deleted),
          },
        });
      } else if (op.request_range) {
        const r = op.request_range;
        const keyBuf = Buffer.isBuffer(r.key) ? r.key : Buffer.from(r.key || "");
        const keyStr = keyBuf.toString("utf8");
        const existing = this.store.get(keyStr);
        const kvs = existing
          ? [
              {
                key: existing.key,
                value: existing.value,
                create_revision: String(existing.createRevision),
                mod_revision: String(existing.modRevision),
                version: String(existing.version),
              },
            ]
          : [];

        responses.push({
          response_range: {
            header: this.getHeader(),
            kvs,
            count: String(kvs.length),
          },
        });
      }
    }

    callback(null, {
      header: this.getHeader(),
      succeeded,
      responses,
    });
  }

  private handleWatchStream(stream: grpc.ServerDuplexStream<any, any>): void {
    stream.on("data", (req: any) => {
      if (req.create_request) {
        const c = req.create_request;
        const keyBuf = Buffer.isBuffer(c.key) ? c.key : Buffer.from(c.key || "");
        const keyStr = keyBuf.toString("utf8");
        const rangeEndBuf = Buffer.isBuffer(c.range_end) ? c.range_end : Buffer.from(c.range_end || "");
        const rangeEndStr = rangeEndBuf.toString("utf8");
        const startRev = c.start_revision ? BigInt(c.start_revision) : 0n;

        const watchId = this.nextWatchId++;
        const watcher: ActiveWatcher = {
          watchId,
          key: keyStr,
          rangeEnd: rangeEndStr,
          stream,
        };
        this.watchers.set(watchId, watcher);

        // Acknowledge watcher creation
        if (startRev > 0n && this.compactRevision > 0n && startRev < this.compactRevision) {
          // Official etcd compaction response (created: true, canceled: true, compact_revision)
          stream.write({
            header: this.getHeader(),
            watch_id: String(watchId),
            created: true,
            canceled: true,
            compact_revision: String(this.compactRevision),
            cancel_reason: "etcdserver: mvcc: required revision has been compacted",
          });
          return;
        }

        stream.write({
          header: this.getHeader(),
          watch_id: String(watchId),
          created: true,
        });

        // Replay history if start_revision was requested
        if (startRev > 0n) {
          const eventsToReplay = this.history.filter((h) => h.revision >= startRev);
          for (const ev of eventsToReplay) {
            const k = ev.kv.key.toString("utf8");
            if (matchesKeyRange(k, keyStr, rangeEndStr)) {
              stream.write({
                header: this.getHeader(),
                watch_id: String(watchId),
                events: [
                  {
                    type: ev.type,
                    kv: {
                      key: ev.kv.key,
                      value: ev.kv.value,
                      create_revision: String(ev.kv.createRevision),
                      mod_revision: String(ev.kv.modRevision),
                      version: String(ev.kv.version),
                    },
                    prev_kv: ev.prevKv
                      ? {
                          key: ev.prevKv.key,
                          value: ev.prevKv.value,
                          create_revision: String(ev.prevKv.createRevision),
                          mod_revision: String(ev.prevKv.modRevision),
                          version: String(ev.prevKv.version),
                        }
                      : undefined,
                  },
                ],
              });
            }
          }
        }
      } else if (req.cancel_request) {
        const watchId = BigInt(req.cancel_request.watch_id || "0");
        this.watchers.delete(watchId);
        stream.write({
          header: this.getHeader(),
          watch_id: String(watchId),
          canceled: true,
        });
      }
    });

    stream.on("end", () => {
      for (const [id, w] of this.watchers.entries()) {
        if (w.stream === stream) this.watchers.delete(id);
      }
      stream.end();
    });

    stream.on("error", () => {
      for (const [id, w] of this.watchers.entries()) {
        if (w.stream === stream) this.watchers.delete(id);
      }
    });
  }

  private notifyWatchers(ev: HistoryEvent): void {
    const k = ev.kv.key.toString("utf8");
    for (const watcher of this.watchers.values()) {
      if (matchesKeyRange(k, watcher.key, watcher.rangeEnd)) {
        try {
          watcher.stream.write({
            header: this.getHeader(),
            watch_id: String(watcher.watchId),
            events: [
              {
                type: ev.type,
                kv: {
                  key: ev.kv.key,
                  value: ev.kv.value,
                  create_revision: String(ev.kv.createRevision),
                  mod_revision: String(ev.kv.modRevision),
                  version: String(ev.kv.version),
                },
                prev_kv: ev.prevKv
                  ? {
                      key: ev.prevKv.key,
                      value: ev.prevKv.value,
                      create_revision: String(ev.prevKv.createRevision),
                      mod_revision: String(ev.prevKv.modRevision),
                      version: String(ev.prevKv.version),
                    }
                  : undefined,
              },
            ],
          });
        } catch {}
      }
    }
  }
}
