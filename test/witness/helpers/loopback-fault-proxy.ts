/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.3
 * Deterministic Loopback TCP Fault-Injection Proxy
 *
 * Forwards client-to-server traffic on 127.0.0.1 without weakening TLS, while
 * supporting deterministic fault modes (drop next server response after client
 * request bytes are forwarded, or drop all traffic) and full socket cleanup.
 */

import * as net from "node:net";

export type ProxyFaultMode =
  | "passthrough"
  | "drop_next_response"
  | "drop_all"
  | "hook_next_client_write";

export interface ProxyTelemetry {
  readonly mode: ProxyFaultMode;
  readonly connectionsOpened: number;
  readonly activeConnections: number;
  readonly bytesClientToServer: number;
  readonly bytesServerToClient: number;
  readonly faultsTriggered: number;
  readonly droppedResponseBytes: number;
  readonly requestForwardHooksTriggered: number;
  readonly clientBytesForwardedAfterArm: number;
}

export class LoopbackFaultProxy {
  public readonly targetHost: string;
  public readonly targetPort: number;
  public listenPort = 0;

  private server: net.Server | null = null;
  private mode: ProxyFaultMode = "passthrough";
  private activeSockets = new Set<net.Socket>();
  private connectionsOpened = 0;
  private bytesClientToServer = 0;
  private bytesServerToClient = 0;
  private faultsTriggered = 0;
  private droppedResponseBytes = 0;
  private clientBytesSinceArm = 0;
  private requestForwardHooksTriggered = 0;
  private clientBytesForwardedAfterArm = 0;
  private onFaultTriggered?: () => void;
  private onClientWriteForwarded?: (bytesForwarded: number) => void;

  constructor(targetPort: number, targetHost = "127.0.0.1") {
    this.targetHost = targetHost;
    this.targetPort = targetPort;
  }

  public get grpcEndpoint(): string {
    return `127.0.0.1:${this.listenPort}`;
  }

  public getTelemetry(): ProxyTelemetry {
    return {
      mode: this.mode,
      connectionsOpened: this.connectionsOpened,
      activeConnections: Math.floor(this.activeSockets.size / 2),
      bytesClientToServer: this.bytesClientToServer,
      bytesServerToClient: this.bytesServerToClient,
      faultsTriggered: this.faultsTriggered,
      droppedResponseBytes: this.droppedResponseBytes,
      requestForwardHooksTriggered: this.requestForwardHooksTriggered,
      clientBytesForwardedAfterArm: this.clientBytesForwardedAfterArm,
    };
  }

  public setPassthrough(): void {
    this.mode = "passthrough";
    this.clientBytesSinceArm = 0;
    this.onFaultTriggered = undefined;
    this.onClientWriteForwarded = undefined;
  }

  public armDropNextResponse(onFaultTriggered?: () => void): void {
    this.mode = "drop_next_response";
    this.clientBytesSinceArm = 0;
    this.onFaultTriggered = onFaultTriggered;
    this.onClientWriteForwarded = undefined;
  }

  public armOnNextClientWrite(onForwarded: (bytesForwarded: number) => void): void {
    this.mode = "hook_next_client_write";
    this.clientBytesSinceArm = 0;
    this.clientBytesForwardedAfterArm = 0;
    this.onFaultTriggered = undefined;
    this.onClientWriteForwarded = onForwarded;
  }

  public setDropAll(): void {
    this.mode = "drop_all";
    this.onFaultTriggered = undefined;
    this.onClientWriteForwarded = undefined;
  }

  public async start(): Promise<string> {
    if (this.server) {
      return this.grpcEndpoint;
    }

    this.server = net.createServer((clientSocket) => {
      if (this.mode === "drop_all") {
        this.faultsTriggered += 1;
        clientSocket.destroy();
        return;
      }

      this.connectionsOpened += 1;
      const upstreamSocket = net.createConnection({
        host: this.targetHost,
        port: this.targetPort,
      });

      this.activeSockets.add(clientSocket);
      this.activeSockets.add(upstreamSocket);

      const cleanupPair = () => {
        this.activeSockets.delete(clientSocket);
        this.activeSockets.delete(upstreamSocket);
        if (!clientSocket.destroyed) clientSocket.destroy();
        if (!upstreamSocket.destroyed) upstreamSocket.destroy();
      };

      clientSocket.on("data", (chunk: Buffer) => {
        if (this.mode === "drop_all") {
          this.faultsTriggered += 1;
          cleanupPair();
          return;
        }
        this.bytesClientToServer += chunk.length;
        if (this.mode === "drop_next_response") {
          this.clientBytesSinceArm += chunk.length;
        }
        if (this.mode === "hook_next_client_write" && this.onClientWriteForwarded) {
          const cb = this.onClientWriteForwarded;
          this.onClientWriteForwarded = undefined;
          this.mode = "passthrough";
          this.requestForwardHooksTriggered += 1;
          this.clientBytesForwardedAfterArm += chunk.length;
          if (!upstreamSocket.destroyed) {
            upstreamSocket.write(chunk, () => {
              cb(chunk.length);
            });
          }
          return;
        }
        if (!upstreamSocket.destroyed) {
          upstreamSocket.write(chunk);
        }
      });

      upstreamSocket.on("data", (chunk: Buffer) => {
        if (this.mode === "drop_all") {
          this.faultsTriggered += 1;
          cleanupPair();
          return;
        }
        if (this.mode === "drop_next_response" && this.clientBytesSinceArm > 0) {
          this.droppedResponseBytes += chunk.length;
          this.faultsTriggered += 1;
          this.mode = "passthrough";
          this.clientBytesSinceArm = 0;
          const cb = this.onFaultTriggered;
          this.onFaultTriggered = undefined;
          cleanupPair();
          cb?.();
          return;
        }
        this.bytesServerToClient += chunk.length;
        if (!clientSocket.destroyed) {
          clientSocket.write(chunk);
        }
      });

      clientSocket.on("error", cleanupPair);
      upstreamSocket.on("error", cleanupPair);
      clientSocket.on("close", cleanupPair);
      upstreamSocket.on("close", cleanupPair);
    });

    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(0, "127.0.0.1", () => {
        const addr = this.server!.address();
        if (addr && typeof addr === "object") {
          this.listenPort = addr.port;
          resolve();
        } else {
          reject(new Error("Failed to bind loopback fault proxy"));
        }
      });
    });

    return this.grpcEndpoint;
  }

  public async stop(): Promise<void> {
    for (const sock of this.activeSockets) {
      if (!sock.destroyed) {
        sock.destroy();
      }
    }
    this.activeSockets.clear();

    if (!this.server) {
      return;
    }

    const srv = this.server;
    this.server = null;
    await new Promise<void>((resolve) => {
      srv.close(() => resolve());
    });
  }
}
