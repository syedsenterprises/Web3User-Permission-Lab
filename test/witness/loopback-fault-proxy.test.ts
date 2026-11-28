import { describe, it, expect, afterEach } from "vitest";
import * as net from "node:net";
import { LoopbackFaultProxy } from "./helpers/loopback-fault-proxy.js";

describe("LoopbackFaultProxy deterministic fault injection", () => {
  const proxies: LoopbackFaultProxy[] = [];
  const servers: net.Server[] = [];

  afterEach(async () => {
    while (proxies.length > 0) {
      await proxies.pop()!.stop().catch(() => {});
    }
    while (servers.length > 0) {
      const srv = servers.pop()!;
      await new Promise<void>((resolve) => srv.close(() => resolve()));
    }
  });

  async function startEchoServer(): Promise<number> {
    const srv = net.createServer((sock) => {
      sock.on("data", (data) => sock.write(data));
    });
    servers.push(srv);
    return new Promise((resolve) => {
      srv.listen(0, "127.0.0.1", () => {
        const addr = srv.address() as net.AddressInfo;
        resolve(addr.port);
      });
    });
  }

  it("forwards traffic in passthrough, drops next response deterministically, and cleans up sockets", async () => {
    const upstreamPort = await startEchoServer();
    const proxy = new LoopbackFaultProxy(upstreamPort);
    proxies.push(proxy);
    await proxy.start();

    // 1. Passthrough mode
    const resp1 = await new Promise<string>((resolve, reject) => {
      const c = net.createConnection({ host: "127.0.0.1", port: proxy.listenPort }, () => {
        c.write("ping-1");
      });
      c.on("data", (d) => {
        c.destroy();
        resolve(d.toString("utf8"));
      });
      c.on("error", reject);
    });
    expect(resp1).toBe("ping-1");

    // 2. Drop next response after forwarding request bytes
    let faultCallbackCalled = false;
    proxy.armDropNextResponse(() => {
      faultCallbackCalled = true;
    });

    await expect(
      new Promise<string>((resolve, reject) => {
        const c = net.createConnection({ host: "127.0.0.1", port: proxy.listenPort }, () => {
          c.write("ping-drop");
        });
        c.on("data", (d) => resolve(d.toString("utf8")));
        c.on("close", () => reject(new Error("Connection closed without response")));
        c.on("error", reject);
      })
    ).rejects.toThrow();

    expect(faultCallbackCalled).toBe(true);
    const telemetry = proxy.getTelemetry();
    expect(telemetry.faultsTriggered).toBe(1);
    expect(telemetry.droppedResponseBytes).toBeGreaterThan(0);
    expect(telemetry.mode).toBe("passthrough");

    // 3. Hook next client write after upstream flush
    let forwardedBytes = 0;
    proxy.armOnNextClientWrite((bytes) => {
      forwardedBytes = bytes;
    });

    const resp2 = await new Promise<string>((resolve, reject) => {
      const c = net.createConnection({ host: "127.0.0.1", port: proxy.listenPort }, () => {
        c.write("ping-hook");
      });
      c.on("data", (d) => {
        c.destroy();
        resolve(d.toString("utf8"));
      });
      c.on("error", reject);
    });
    expect(resp2).toBe("ping-hook");
    expect(forwardedBytes).toBe(Buffer.byteLength("ping-hook"));
    expect(proxy.getTelemetry().requestForwardHooksTriggered).toBe(1);
    expect(proxy.getTelemetry().clientBytesForwardedAfterArm).toBe(
      Buffer.byteLength("ping-hook")
    );

    // 4. Stop cleans up all sockets idempotently
    await proxy.stop();
    await proxy.stop();
    expect(proxy.getTelemetry().activeConnections).toBe(0);
  });
});
