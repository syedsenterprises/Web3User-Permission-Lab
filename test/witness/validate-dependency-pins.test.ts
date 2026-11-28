import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../..");
const validatorScript = path.join(repoRoot, "scripts", "validate-dependency-pins.mjs");

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe("validate-dependency-pins.mjs", () => {
  it("passes against the repository with @aws-sdk/client-s3 exact-pinned to 3.1173.0", () => {
    const output = execFileSync(process.execPath, [validatorScript], {
      cwd: repoRoot,
      encoding: "utf8",
    });

    expect(output).toContain("@aws-sdk/client-s3 is strictly pinned to '3.1173.0'");
    expect(output).toContain("SUCCESS: All dependency pin checks PASSED.");
  });

  it("fails when @aws-sdk/client-s3 is changed to a non-exact semver range", () => {
    const tmpRoot = mkdtempSync(path.join(os.tmpdir(), "pin-check-"));
    tempDirs.push(tmpRoot);

    mkdirSync(path.join(tmpRoot, "scripts"), { recursive: true });
    const tmpScript = path.join(tmpRoot, "scripts", "validate-dependency-pins.mjs");
    copyFileSync(validatorScript, tmpScript);

    const exactPins = {
      "@aws-sdk/client-kms": "3.1173.0",
      "@aws-sdk/client-s3": "3.1173.0",
      "@google-cloud/kms": "6.3.0",
    };

    writeFileSync(
      path.join(tmpRoot, "package.json"),
      JSON.stringify(
        {
          name: "pin-check-fixture",
          version: "0.0.0",
          dependencies: {
            ...exactPins,
            "@aws-sdk/client-s3": "^3.1173.0",
          },
        },
        null,
        2
      )
    );

    const lockPackages: Record<string, { version: string }> = {};
    for (const [pkg, version] of Object.entries(exactPins)) {
      lockPackages[`node_modules/${pkg}`] = { version };
      const pkgDir = path.join(tmpRoot, "node_modules", ...pkg.split("/"));
      mkdirSync(pkgDir, { recursive: true });
      writeFileSync(
        path.join(pkgDir, "package.json"),
        JSON.stringify({ name: pkg, version, main: "index.js" })
      );
      writeFileSync(path.join(pkgDir, "index.js"), "module.exports = {};\n");
    }

    writeFileSync(
      path.join(tmpRoot, "package-lock.json"),
      JSON.stringify({ name: "pin-check-fixture", lockfileVersion: 3, packages: lockPackages }, null, 2)
    );

    let failed = false;
    let stderr = "";
    try {
      execFileSync(process.execPath, [tmpScript], {
        cwd: tmpRoot,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (err) {
      failed = true;
      stderr = String((err as { stderr?: string }).stderr ?? "");
    }

    expect(failed).toBe(true);
    expect(stderr).toContain("@aws-sdk/client-s3");
    expect(stderr).toContain("Floating semver range detected");
  });
});
