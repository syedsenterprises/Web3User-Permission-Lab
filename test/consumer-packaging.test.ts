import { execSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");

describe("Milestone 6.13-B: SDK Packaging & Consumer Integration", () => {
  it(
    "generates clean production build output with declarations and sourcemaps",
    () => {
      // Ensure build is up-to-date
      execSync("npm run build", { cwd: repoRoot, stdio: "pipe" });

      const distDir = join(repoRoot, "dist");
      expect(existsSync(join(distDir, "index.js"))).toBe(true);
      expect(existsSync(join(distDir, "index.d.ts"))).toBe(true);
      expect(existsSync(join(distDir, "index.d.ts.map"))).toBe(true);
      expect(existsSync(join(distDir, "engine.js"))).toBe(true);
      expect(existsSync(join(distDir, "engine.d.ts"))).toBe(true);
      expect(existsSync(join(distDir, "authorization-store.d.ts"))).toBe(true);

      // Tests must NEVER be compiled into dist
      expect(existsSync(join(distDir, "test"))).toBe(false);
    },
    30000,
  );

  it("package.json defines valid export map, entrypoints, and private protection", () => {
    const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));

    expect(pkg.name).toBe("web3user-permission-lab");
    expect(pkg.private).toBe(true);
    expect(pkg.type).toBe("module");
    expect(pkg.main).toBe("./dist/index.js");
    expect(pkg.types).toBe("./dist/index.d.ts");
    expect(pkg.exports["."].types).toBe("./dist/index.d.ts");
    expect(pkg.exports["."].import).toBe("./dist/index.js");
    expect(pkg.engines?.node).toMatch(/>=22/);

    // Verify files pointed to by package.json actually exist on disk
    expect(existsSync(join(repoRoot, pkg.main))).toBe(true);
    expect(existsSync(join(repoRoot, pkg.types))).toBe(true);
  });

  it(
    "npm pack dry-run bundles only runtime files and excludes tests/assets/docs",
    () => {
      const raw = execSync("npm pack --dry-run --json", { cwd: repoRoot, encoding: "utf8" });
      const jsonStart = raw.indexOf("[");
      const parsed = JSON.parse(raw.slice(jsonStart));
      const paths: string[] = parsed[0].files.map((f: { path: string }) => f.path);

      // Must include compiled distribution
      expect(paths).toContain("dist/index.js");
      expect(paths).toContain("dist/index.d.ts");
      expect(paths).toContain("dist/engine.js");
      expect(paths).toContain("dist/engine.d.ts");
      expect(paths).toContain("README.md");
      expect(paths).toContain("package.json");

      // Must strictly EXCLUDE internal test files, docs, demo CLI, and website-preview assets
      expect(paths.some((p: string) => p.startsWith("test/"))).toBe(false);
      expect(paths.some((p: string) => p.startsWith("website-preview/"))).toBe(false);
      expect(paths.some((p: string) => p.startsWith("docs/"))).toBe(false);
      expect(paths.some((p: string) => p.startsWith("dist/demo"))).toBe(false);
    },
    30000,
  );

  it(
    "installs into an external consumer project, validates .d.ts types, and executes full authorization workflow",
    () => {
      const tempBase = mkdtempSync(join(tmpdir(), "web3user-pkg-test-"));

      try {
        // 1. Pack tarball into isolated temp dir
        execSync(`npm pack --pack-destination "${tempBase}"`, {
          cwd: repoRoot,
          stdio: "pipe",
        });

        const tarballPath = join(tempBase, "web3user-permission-lab-0.1.0.tgz");
        expect(existsSync(tarballPath)).toBe(true);

        // 2. Setup external consumer fixture
        const consumerDir = join(tempBase, "consumer-fixture");
        mkdirSync(consumerDir);

        const consumerPackageJson = {
          name: "test-external-consumer",
          version: "1.0.0",
          private: true,
          type: "module",
          dependencies: {
            "web3user-permission-lab": `file:${tarballPath}`,
          },
          devDependencies: {
            typescript: "^5.7.3",
            "@types/node": "^26.6.5",
          },
        };
        writeFileSync(
          join(consumerDir, "package.json"),
          JSON.stringify(consumerPackageJson, null, 2),
          "utf8",
        );

        // 3. Install packed tarball
        execSync("npm install", { cwd: consumerDir, stdio: "pipe" });

        // 4. Configure consumer TypeScript with skipLibCheck: false to strictly validate .d.ts
        const consumerTsConfig = {
          compilerOptions: {
            target: "ES2022",
            module: "NodeNext",
            moduleResolution: "NodeNext",
            strict: true,
            skipLibCheck: false,
            outDir: "dist",
          },
          include: ["src/**/*.ts"],
        };
        writeFileSync(
          join(consumerDir, "tsconfig.json"),
          JSON.stringify(consumerTsConfig, null, 2),
          "utf8",
        );

        // 5. Author consumer TypeScript code exercising SDK public API
        mkdirSync(join(consumerDir, "src"));
        const consumerAppCode = `
import {
  Web3UserEngine,
  type Web3UserEngineOptions,
  type IssueAuthorizationParams,
  type ConsumeAuthorizationParams,
  type AuthorizationRecord,
  type AuthorizationState,
  type DemoPolicy,
  type TransactionRequest,
  type Decision,
  Web3UserError,
  StoreTaintedError,
  ValidationError,
} from "web3user-permission-lab";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

async function run() {
  const dbDir = mkdtempSync(join(tmpdir(), "consumer-db-"));
  const dbPath = join(dbDir, "auth.sqlite");

  try {
    const engine = Web3UserEngine.open({ databasePath: dbPath });
    if (!engine.isOpen()) throw new Error("Engine should be open");

    // Register Ed25519 signing key
    const keyPair = engine.keys.generate();
    engine.keys.register({
      keyId: "consumer-key-1",
      publicKey: keyPair.publicKey,
      status: "active",
      validFromSeconds: 0,
      expiresAtSeconds: Math.floor(Date.now() / 1000) + 3600,
    });

    // Register demo policy
    const policy: DemoPolicy = {
      version: 1,
      policyId: "consumer-policy-1",
      allowedTarget: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      allowedRecipient: "0x2222222222222222222222222222222222222222",
      allowedSelector: "0xa9059cbb",
      maxAmount: "5000000000",
      validFrom: 0,
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      revoked: false,
    };
    engine.policies.register(policy, 1);

    const request: TransactionRequest = {
      chainId: "1",
      sender: "0x1111111111111111111111111111111111111111",
      target: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      calldata: "0xa9059cbb0000000000000000000000002222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000001dcd6500",
      value: "0",
    };

    // Issue authorization
    const issued = engine.issue({
      authorizationId: "consumer-auth-001",
      policyId: "consumer-policy-1",
      request,
      signer: {
        keyId: "consumer-key-1",
        privateKey: keyPair.privateKey,
      },
    });
    if (issued.decision !== "ALLOW") throw new Error("Expected ALLOW");

    // Check typed record
    const record: AuthorizationRecord | null = engine.getAuthorizationRecord("consumer-auth-001");
    if (!record || record.state !== "issued") throw new Error("Expected state 'issued'");

    // First consumption
    const firstConsume = engine.consume({
      artifact: issued.artifact,
      request,
    });
    if (firstConsume.decision !== "ALLOW") throw new Error("Expected first consume ALLOW");

    // Replay consumption
    const replayConsume = engine.consume({
      artifact: issued.artifact,
      request,
    });
    if (replayConsume.decision !== "DENY") throw new Error("Expected replay DENY");

    engine.close();
    if (engine.isOpen()) throw new Error("Engine should be closed");

    console.log("CONSUMER_VERIFICATION_PASS");
  } finally {
    try {
      rmSync(dbDir, { recursive: true, force: true });
    } catch {}
  }
}

run();
`;
        writeFileSync(join(consumerDir, "src", "index.ts"), consumerAppCode, "utf8");

        // 6. Compile consumer code with tsc
        execSync("npx tsc", { cwd: consumerDir, stdio: "pipe" });
        expect(existsSync(join(consumerDir, "dist", "index.js"))).toBe(true);

        // 7. Execute compiled consumer code
        const runOutput = execSync("node dist/index.js", {
          cwd: consumerDir,
          encoding: "utf8",
        });
        expect(runOutput).toContain("CONSUMER_VERIFICATION_PASS");
      } finally {
        try {
          rmSync(tempBase, { recursive: true, force: true });
        } catch {}
      }
    },
    60000,
  );

  it(
    "enforces persistent replay prevention across separate Node.js processes in consumer application",
    () => {
      const tempBase = mkdtempSync(join(tmpdir(), "web3user-consumer-proc-"));

      try {
        // 1. Pack tarball into isolated temp dir
        execSync(`npm pack --pack-destination "${tempBase}"`, {
          cwd: repoRoot,
          stdio: "pipe",
        });

        const tarballPath = join(tempBase, "web3user-permission-lab-0.1.0.tgz");
        expect(existsSync(tarballPath)).toBe(true);

        // 2. Setup external consumer fixture
        const consumerDir = join(tempBase, "consumer-app");
        mkdirSync(consumerDir);

        const consumerPackageJson = {
          name: "test-consumer-processes",
          version: "1.0.0",
          private: true,
          type: "module",
          dependencies: {
            "web3user-permission-lab": `file:${tarballPath}`,
          },
          devDependencies: {
            typescript: "^5.7.3",
            "@types/node": "^26.6.5",
          },
        };
        writeFileSync(
          join(consumerDir, "package.json"),
          JSON.stringify(consumerPackageJson, null, 2),
          "utf8",
        );

        // 3. Install packed tarball
        execSync("npm install", { cwd: consumerDir, stdio: "pipe" });

        // 4. Configure consumer TypeScript
        const consumerTsConfig = {
          compilerOptions: {
            target: "ES2022",
            module: "NodeNext",
            moduleResolution: "NodeNext",
            strict: true,
            skipLibCheck: false,
            outDir: "dist",
          },
          include: ["src/**/*.ts"],
        };
        writeFileSync(
          join(consumerDir, "tsconfig.json"),
          JSON.stringify(consumerTsConfig, null, 2),
          "utf8",
        );

        mkdirSync(join(consumerDir, "src"));

        const sharedDbPath = join(tempBase, "shared-auth.sqlite");
        const sharedArtifactPath = join(tempBase, "shared-artifact.json");

        // 5. Author Process A (issue, first consume, verify ALLOW, close engine)
        const processACode = `
import {
  Web3UserEngine,
  type DemoPolicy,
  type TransactionRequest,
} from "web3user-permission-lab";
import { writeFileSync } from "node:fs";

async function runProcessA() {
  const dbPath = process.argv[2];
  const artifactPath = process.argv[3];
  if (!dbPath || !artifactPath) {
    throw new Error("Missing arguments for Process A");
  }

  const engine = Web3UserEngine.open({ databasePath: dbPath });

  // Generate and register key
  const keyPair = engine.keys.generate();
  engine.keys.register({
    keyId: "proc-key-01",
    publicKey: keyPair.publicKey,
    status: "active",
    validFromSeconds: 0,
    expiresAtSeconds: Math.floor(Date.now() / 1000) + 7200,
  });

  // Register policy
  const policy: DemoPolicy = {
    version: 1,
    policyId: "proc-policy-01",
    allowedTarget: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    allowedRecipient: "0x3333333333333333333333333333333333333333",
    allowedSelector: "0xa9059cbb",
    maxAmount: "1000000000",
    validFrom: 0,
    expiresAt: Math.floor(Date.now() / 1000) + 7200,
    revoked: false,
  };
  engine.policies.register(policy, 1);

  const request: TransactionRequest = {
    chainId: "1",
    sender: "0x1111111111111111111111111111111111111111",
    target: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    calldata: "0xa9059cbb0000000000000000000000003333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000001dcd6500",
    value: "0",
  };

  const issued = engine.issue({
    authorizationId: "cross-proc-auth-001",
    policyId: "proc-policy-01",
    request,
    signer: {
      keyId: "proc-key-01",
      privateKey: keyPair.privateKey,
    },
  });

  if (issued.decision !== "ALLOW") {
    throw new Error("Process A: Expected ALLOW on issuance, got: " + issued.decision);
  }

  // Consume in Process A
  const consumed = engine.consume({
    artifact: issued.artifact,
    request,
  });

  if (consumed.decision !== "ALLOW") {
    throw new Error("Process A: Expected ALLOW on first consume, got: " + consumed.decision);
  }

  // Save artifact and request for Process B
  writeFileSync(
    artifactPath,
    JSON.stringify({ artifact: issued.artifact, request }, null, 2),
    "utf8"
  );

  engine.close();
  console.log("PROCESS_A_COMPLETE");
}

runProcessA().catch((err) => {
  console.error("Process A error:", err);
  process.exit(1);
});
`;
        writeFileSync(join(consumerDir, "src", "processA.ts"), processACode, "utf8");

        // 6. Author Process B (reopen DB, attempt replay consumption, assert DENY)
        const processBCode = `
import {
  Web3UserEngine,
  Web3UserError,
  ValidationError,
  StoreTaintedError,
} from "web3user-permission-lab";
import { readFileSync } from "node:fs";

async function runProcessB() {
  const dbPath = process.argv[2];
  const artifactPath = process.argv[3];
  if (!dbPath || !artifactPath) {
    throw new Error("Missing arguments for Process B");
  }

  // Reopen the exact same SQLite database in a brand new OS process
  const engine = Web3UserEngine.open({ databasePath: dbPath });

  const data = JSON.parse(readFileSync(artifactPath, "utf8"));
  const { artifact, request } = data;

  // Attempt replay consumption in Process B
  const replayResult = engine.consume({
    artifact,
    request,
  });

  if (replayResult.decision !== "DENY") {
    throw new Error("Process B: Expected replay DENY across process boundary, got: " + replayResult.decision);
  }

  // Verify typed error contract across package boundary
  try {
    engine.getAuthorizationRecord("   ");
    throw new Error("Process B: Expected ValidationError for blank ID");
  } catch (err) {
    if (!(err instanceof ValidationError) || !(err instanceof Web3UserError)) {
      throw new Error("Process B: Expected ValidationError instance, got: " + String(err));
    }
  }

  engine.close();
  console.log("PROCESS_B_REPLAY_DENIED_REASON:" + replayResult.reasons.join(";"));
  console.log("PROCESS_B_COMPLETE");
}

runProcessB().catch((err) => {
  console.error("Process B error:", err);
  process.exit(1);
});
`;
        writeFileSync(join(consumerDir, "src", "processB.ts"), processBCode, "utf8");

        // 7. Compile consumer TypeScript code
        execSync("npx tsc", { cwd: consumerDir, stdio: "pipe" });

        // 8. Execute Process A
        const outA = execSync(`node dist/processA.js "${sharedDbPath}" "${sharedArtifactPath}"`, {
          cwd: consumerDir,
          encoding: "utf8",
        });
        expect(outA).toContain("PROCESS_A_COMPLETE");

        // 9. Execute Process B (new process reopening the same DB)
        const outB = execSync(`node dist/processB.js "${sharedDbPath}" "${sharedArtifactPath}"`, {
          cwd: consumerDir,
          encoding: "utf8",
        });
        expect(outB).toContain("PROCESS_B_COMPLETE");
        expect(outB).toContain("PROCESS_B_REPLAY_DENIED_REASON");
        expect(outB).toMatch(/unknown, consumed, or mismatched|already been consumed/i);
      } finally {
        try {
          rmSync(tempBase, { recursive: true, force: true });
        } catch {}
      }
    },
    60000,
  );
});
