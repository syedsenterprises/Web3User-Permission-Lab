/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: gRPC Server & Transport Setup
 *
 * Configures pure JavaScript @grpc/grpc-js server with mTLS 1.3, executes startup dependency
 * assertions strictly before listener binding, runs startup outbox sweep, and binds the 6 RPC handlers.
 */

import * as path from "node:path";
import * as fs from "node:fs";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { DependencyPinValidator } from "./dependency-validator.js";
import { GrpcWitnessServiceImpl } from "./grpc-service.js";
import { PeerAuthorizer, type AuthenticatedPeer } from "./auth.js";
import { X509Certificate } from "node:crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface GrpcServerOptions {
  serviceImpl: GrpcWitnessServiceImpl;
  caCert?: Buffer;
  serverCert?: Buffer;
  serverKey?: Buffer;
  port?: number;
  host?: string;
  skipDependencyCheck?: boolean;
}

export interface StartedGrpcWitnessServer {
  server: grpc.Server;
  port: number;
  host: string;
  stop: () => Promise<void>;
}

export async function startGrpcWitnessServer(
  options: GrpcServerOptions,
): Promise<StartedGrpcWitnessServer> {
  // Step 0: Strict Startup Dependency & Prototypes Assertion
  if (!options.skipDependencyCheck) {
    DependencyPinValidator.assertPinnedDependencies();
  }

  // Step 1: Execute Startup Outbox Reconciliation Sweep
  await options.serviceImpl.startupOutboxReconciliationSweep();

  // Step 2: Load Protocol Buffers Definition
  const protoPath = path.join(__dirname, "proto", "witness.proto");
  const packageDefinition = protoLoader.loadSync(protoPath, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
  });

  const protoDescriptor = grpc.loadPackageDefinition(packageDefinition) as any;
  const witnessProto = protoDescriptor.web3user.witness.v1.WitnessService;

  // Step 3: Instantiate gRPC Server
  const server = new grpc.Server();

  // Helper to extract authenticated peer strictly from actual TLS session socket
  function extractCallPeer(call: any): AuthenticatedPeer {
    const socket = call.call?.stream?.session?.socket;
    let peerCert: X509Certificate | null = null;
    if (socket && typeof socket.getPeerX509Certificate === "function") {
      try {
        peerCert = socket.getPeerX509Certificate();
      } catch {
        peerCert = null;
      }
    }

    if (!peerCert) {
      const err = new Error(
        "UNAUTHENTICATED: Mutual TLS required; peer certificate not present on TLS transport",
      );
      (err as any).code = grpc.status.UNAUTHENTICATED;
      throw err;
    }

    return PeerAuthorizer.extractPeer(peerCert, options.caCert);
  }

  // Adapter wrapping async service methods to standard gRPC callback signature
  function wrapRpc(
    fn: (call: any, peer: AuthenticatedPeer) => Promise<any>,
  ): (call: any, callback: grpc.sendUnaryData<any>) => void {
    return (call: any, callback: grpc.sendUnaryData<any>) => {
      try {
        const peer = extractCallPeer(call);
        fn(call, peer)
          .then((result) => callback(null, result))
          .catch((err) => {
            const grpcErr: grpc.ServiceError = {
              name: err.name || "ServiceError",
              message: err.message,
              code: err.code || grpc.status.INTERNAL,
              details: err.message,
              metadata: new grpc.Metadata(),
            };
            if ((err as any).retryAfterMs) {
              grpcErr.metadata.set("retry-after-ms", String((err as any).retryAfterMs));
            }
            callback(grpcErr, null);
          });
      } catch (authErr: any) {
        const grpcErr: grpc.ServiceError = {
          name: authErr.name || "AuthError",
          message: authErr.message,
          code: authErr.code || grpc.status.UNAUTHENTICATED,
          details: authErr.message,
          metadata: new grpc.Metadata(),
        };
        callback(grpcErr, null);
      }
    };
  }

  // Bind service implementation
  server.addService(witnessProto.service, {
    GetSyncStatus: wrapRpc((call, peer) => options.serviceImpl.getSyncStatus(call, peer)),
    ReserveTicket: wrapRpc((call, peer) => options.serviceImpl.reserveTicket(call, peer)),
    CommitTicket: wrapRpc((call, peer) => options.serviceImpl.commitTicket(call, peer)),
    ReleaseTicket: wrapRpc((call, peer) => options.serviceImpl.releaseTicket(call, peer)),
    ReconcileTicket: wrapRpc((call, peer) => options.serviceImpl.reconcileTicket(call, peer)),
    ListUnfinalizedTickets: wrapRpc((call, peer) => options.serviceImpl.listUnfinalizedTickets(call, peer)),
  });

  // Step 4: Configure Credentials (mTLS vs Insecure)
  let credentials = grpc.ServerCredentials.createInsecure();
  if (options.caCert && options.serverCert && options.serverKey) {
    credentials = grpc.ServerCredentials.createSsl(
      options.caCert,
      [
        {
          cert_chain: options.serverCert,
          private_key: options.serverKey,
        },
      ],
      true, // require client cert validation
    );
  }

  // Step 5: Bind Listener to Port
  const host = options.host || "127.0.0.1";
  const requestedPort = options.port !== undefined ? options.port : 0;

  return new Promise((resolve, reject) => {
    server.bindAsync(`${host}:${requestedPort}`, credentials, (err, boundPort) => {
      if (err) {
        return reject(err);
      }

      const started: StartedGrpcWitnessServer = {
        server,
        port: boundPort,
        host,
        stop: () => {
          return new Promise<void>((res) => {
            server.tryShutdown(() => res());
          });
        },
      };

      resolve(started);
    });
  });
}
