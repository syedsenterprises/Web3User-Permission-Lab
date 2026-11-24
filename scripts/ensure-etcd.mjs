#!/usr/bin/env node
/**
 * Provision pinned official etcd v3.5.18 binary for Windows, Linux, and macOS.
 * Verifies archive SHA-256 against official upstream etcd v3.5.18 SHA256SUMS
 * before extracting into .tmp/etcd-bin/v3.5.18/.
 */

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

export const ETCD_VERSION = "3.5.18";

/**
 * Official SHA-256 digests from:
 * https://github.com/etcd-io/etcd/releases/download/v3.5.18/SHA256SUMS
 */
export const ETCD_RELEASES = {
  "win32-x64": {
    archive: "etcd-v3.5.18-windows-amd64.zip",
    sha256: "c17126fe42852d2eef181f94b17af26b6289052de9d28f8fe5edb6783f461c59",
    archiveType: "zip",
    innerDir: "etcd-v3.5.18-windows-amd64",
    ext: ".exe",
  },
  "linux-x64": {
    archive: "etcd-v3.5.18-linux-amd64.tar.gz",
    sha256: "6ddde039a7a506badf34e7edfb38e1ea90e36f05c8cfceba602045df623d86fa",
    archiveType: "tar.gz",
    innerDir: "etcd-v3.5.18-linux-amd64",
    ext: "",
  },
  "linux-arm64": {
    archive: "etcd-v3.5.18-linux-arm64.tar.gz",
    sha256: "c2bcaf465537d6d47c8bb82a69e31f786f32257050e3bca445bc4e63479ec714",
    archiveType: "tar.gz",
    innerDir: "etcd-v3.5.18-linux-arm64",
    ext: "",
  },
  "darwin-x64": {
    archive: "etcd-v3.5.18-darwin-amd64.zip",
    sha256: "9e1a184e1e6836be8152729b0ccf8bea30cc9eb6086f715f6929d76c20687c75",
    archiveType: "zip",
    innerDir: "etcd-v3.5.18-darwin-amd64",
    ext: "",
  },
  "darwin-arm64": {
    archive: "etcd-v3.5.18-darwin-arm64.zip",
    sha256: "f4e33d38b43d9e6ffa7dc3dad348bbc8660a325e666fb5f9a2ff098d876f421",
    archiveType: "zip",
    innerDir: "etcd-v3.5.18-darwin-arm64",
    ext: "",
  },
};

function verifyBinaryVersion(binaryPath) {
  if (!fs.existsSync(binaryPath)) {
    return false;
  }
  try {
    const out = execFileSync(binaryPath, ["--version"], { encoding: "utf8", timeout: 5000 });
    return out.includes(`etcd Version: ${ETCD_VERSION}`);
  } catch {
    return false;
  }
}

async function computeFileSha256(filePath) {
  const hash = createHash("sha256");
  const stream = fs.createReadStream(filePath);
  for await (const chunk of stream) {
    hash.update(chunk);
  }
  return hash.digest("hex").toLowerCase();
}

async function downloadFile(url, destPath) {
  const response = await fetch(url, { redirect: "follow" });
  if (!response.ok || !response.body) {
    throw new Error(`Failed to download ${url}: HTTP ${response.status} ${response.statusText}`);
  }
  await pipeline(Readable.fromWeb(response.body), fs.createWriteStream(destPath));
}

async function main() {
  const key = `${process.platform}-${process.arch}`;
  const spec = ETCD_RELEASES[key];
  if (!spec) {
    throw new Error(`Unsupported platform/architecture for pinned etcd v${ETCD_VERSION}: ${key}`);
  }

  const rootDir = process.cwd();
  const binDir = path.resolve(rootDir, ".tmp/etcd-bin", `v${ETCD_VERSION}`);
  const etcdPath = path.join(binDir, `etcd${spec.ext}`);
  const etcdctlPath = path.join(binDir, `etcdctl${spec.ext}`);

  if (verifyBinaryVersion(etcdPath) && fs.existsSync(etcdctlPath)) {
    console.log(`Pinned etcd v${ETCD_VERSION} already present and verified at ${binDir}`);
    return;
  }

  fs.mkdirSync(binDir, { recursive: true });
  const archivePath = path.join(binDir, spec.archive);
  const url = `https://github.com/etcd-io/etcd/releases/download/v${ETCD_VERSION}/${spec.archive}`;

  console.log(`Downloading ${url}...`);
  await downloadFile(url, archivePath);

  const actualSha = await computeFileSha256(archivePath);
  if (actualSha !== spec.sha256) {
    fs.rmSync(archivePath, { force: true });
    throw new Error(
      `SHA-256 mismatch for ${spec.archive}: expected ${spec.sha256}, got ${actualSha}`
    );
  }
  console.log(`Verified SHA-256 for ${spec.archive}: ${actualSha}`);

  const extractDir = path.join(binDir, "_extract");
  fs.rmSync(extractDir, { recursive: true, force: true });
  fs.mkdirSync(extractDir, { recursive: true });

  try {
    if (spec.archiveType === "tar.gz") {
      execFileSync("tar", ["-xzf", archivePath, "-C", extractDir], { stdio: "inherit" });
    } else if (process.platform === "win32") {
      execFileSync(
        "powershell",
        [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          `Expand-Archive -LiteralPath '${archivePath.replace(/'/g, "''")}' -DestinationPath '${extractDir.replace(/'/g, "''")}' -Force`,
        ],
        { stdio: "inherit" }
      );
    } else {
      execFileSync("unzip", ["-q", "-o", archivePath, "-d", extractDir], { stdio: "inherit" });
    }

    const extractedEtcd = path.join(extractDir, spec.innerDir, `etcd${spec.ext}`);
    const extractedEtcdctl = path.join(extractDir, spec.innerDir, `etcdctl${spec.ext}`);
    if (!fs.existsSync(extractedEtcd) || !fs.existsSync(extractedEtcdctl)) {
      throw new Error(`Extracted archive missing etcd or etcdctl in ${spec.innerDir}`);
    }

    fs.copyFileSync(extractedEtcd, etcdPath);
    fs.copyFileSync(extractedEtcdctl, etcdctlPath);

    if (process.platform !== "win32") {
      fs.chmodSync(etcdPath, 0o755);
      fs.chmodSync(etcdctlPath, 0o755);
    }
  } finally {
    fs.rmSync(extractDir, { recursive: true, force: true });
    fs.rmSync(archivePath, { force: true });
  }

  if (!verifyBinaryVersion(etcdPath)) {
    throw new Error(`Post-extract version verification failed for ${etcdPath}`);
  }
  console.log(`Provisioned and verified etcd v${ETCD_VERSION} at ${binDir}`);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
