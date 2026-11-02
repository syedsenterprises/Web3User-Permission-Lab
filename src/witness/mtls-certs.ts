/**
 * Web3User Permission Lab - Milestone 13-D Phase D2: mTLS 1.3 Certificate Generation & Management
 *
 * Provides utilities to provision Root CAs, server certificates with SANs (DNS/IP), and
 * client certificates with SPIFFE URI SANs representing engine, recovery, auditor, and unauthorized roles.
 */

import { execSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export interface CertBundle {
  caCert: Buffer;
  caKey: Buffer;
  serverCert: Buffer;
  serverKey: Buffer;
  engineClientCert: Buffer;
  engineClientKey: Buffer;
  engine2ClientCert: Buffer;
  engine2ClientKey: Buffer;
  recoveryClientCert: Buffer;
  recoveryClientKey: Buffer;
  auditorClientCert: Buffer;
  auditorClientKey: Buffer;
  unauthorizedClientCert: Buffer;
  unauthorizedClientKey: Buffer;
  revokedClientCert: Buffer;
  revokedClientKey: Buffer;
  revokedSerial: string;
  bundleDir: string;
}

export function findOpenSSL(): string {
  const candidates = [
    "C:\\Program Files\\Git\\usr\\bin\\openssl.exe",
    "openssl",
  ];

  for (const c of candidates) {
    try {
      execSync(`"${c}" version`, { stdio: "ignore" });
      return c;
    } catch {
      // try next
    }
  }

  throw new Error("OpenSSL CLI executable not found on host");
}

export function generateTestCertificates(outDir?: string): CertBundle {
  const openssl = findOpenSSL();
  const dir = outDir || fs.mkdtempSync(path.join(os.tmpdir(), "web3user-mtls-"));
  fs.mkdirSync(dir, { recursive: true });

  const caKey = path.join(dir, "ca.key");
  const caCrt = path.join(dir, "ca.crt");
  const serverKey = path.join(dir, "server.key");
  const serverCsr = path.join(dir, "server.csr");
  const serverCrt = path.join(dir, "server.crt");

  // 1. Root CA
  execSync(
    `"${openssl}" req -x509 -newkey rsa:2048 -nodes -keyout "${caKey}" -out "${caCrt}" -days 7 -subj "/CN=Web3User-Witness-RootCA"`,
    { stdio: "pipe" },
  );

  // Helper to generate signed cert with SAN
  function createSignedCert(
    name: string,
    subj: string,
    san: string,
    serialHex?: string,
  ): { certPath: string; keyPath: string; serial: string } {
    const keyPath = path.join(dir, `${name}.key`);
    const csrPath = path.join(dir, `${name}.csr`);
    const certPath = path.join(dir, `${name}.crt`);
    const extPath = path.join(dir, `${name}.ext`);

    execSync(
      `"${openssl}" req -newkey rsa:2048 -nodes -keyout "${keyPath}" -out "${csrPath}" -subj "${subj}"`,
      { stdio: "pipe" },
    );

    let extContent = `subjectAltName = ${san}\n`;
    fs.writeFileSync(extPath, extContent, "utf8");

    const serialArg = serialHex ? `-set_serial 0x${serialHex}` : "";
    execSync(
      `"${openssl}" x509 -req -in "${csrPath}" -CA "${caCrt}" -CAkey "${caKey}" -CAcreateserial -out "${certPath}" -days 7 -extfile "${extPath}" ${serialArg}`,
      { stdio: "pipe" },
    );

    // Read actual serial number from generated cert
    const serialOut = execSync(
      `"${openssl}" x509 -in "${certPath}" -noout -serial`,
      { encoding: "utf8" },
    ).trim();
    const actualSerial = serialOut.replace(/^serial=/, "").toLowerCase();

    return { certPath, keyPath, serial: actualSerial };
  }

  // 2. Server Certificate
  const server = createSignedCert(
    "server",
    "/CN=localhost",
    "DNS:localhost,IP:127.0.0.1,DNS:witness.internal.web3user.net",
  );

  // 3. Engine Pod Client (Role: engine-pod)
  const engine = createSignedCert(
    "engine-client",
    "/CN=engine-pod-worker",
    "URI:spiffe://web3user.internal/ns/engine/sa/engine-pod-worker,DNS:engine-pod-worker.internal.web3user.net",
  );

  // 4. Engine Pod 2 Client (Role: engine-pod, different worker)
  const engine2 = createSignedCert(
    "engine2-client",
    "/CN=engine-pod-worker-2",
    "URI:spiffe://web3user.internal/ns/engine/sa/engine-pod-worker-2",
  );

  // 5. Recovery Worker Client (Role: recovery-worker)
  const recovery = createSignedCert(
    "recovery-client",
    "/CN=recovery-worker",
    "URI:spiffe://web3user.internal/ns/recovery/sa/recovery-worker",
  );

  // 6. Admin Auditor Client (Role: admin-auditor)
  const auditor = createSignedCert(
    "auditor-client",
    "/CN=admin-auditor",
    "URI:spiffe://web3user.internal/ns/admin/sa/admin-auditor",
  );

  // 7. Unauthorized Client (Valid CA signature, but role has zero permissions)
  const unauthorized = createSignedCert(
    "unauthorized-client",
    "/CN=unauthorized-client",
    "URI:spiffe://web3user.internal/ns/unauthorized/sa/unauthorized-client",
  );

  // 8. Revoked Client (Known serial number)
  const revoked = createSignedCert(
    "revoked-client",
    "/CN=revoked-worker",
    "URI:spiffe://web3user.internal/ns/engine/sa/revoked-worker",
    "99AABBCCDDEEFF01",
  );

  return {
    caCert: fs.readFileSync(caCrt),
    caKey: fs.readFileSync(caKey),
    serverCert: fs.readFileSync(server.certPath),
    serverKey: fs.readFileSync(server.keyPath),
    engineClientCert: fs.readFileSync(engine.certPath),
    engineClientKey: fs.readFileSync(engine.keyPath),
    engine2ClientCert: fs.readFileSync(engine2.certPath),
    engine2ClientKey: fs.readFileSync(engine2.keyPath),
    recoveryClientCert: fs.readFileSync(recovery.certPath),
    recoveryClientKey: fs.readFileSync(recovery.keyPath),
    auditorClientCert: fs.readFileSync(auditor.certPath),
    auditorClientKey: fs.readFileSync(auditor.keyPath),
    unauthorizedClientCert: fs.readFileSync(unauthorized.certPath),
    unauthorizedClientKey: fs.readFileSync(unauthorized.keyPath),
    revokedClientCert: fs.readFileSync(revoked.certPath),
    revokedClientKey: fs.readFileSync(revoked.keyPath),
    revokedSerial: revoked.serial,
    bundleDir: dir,
  };
}
