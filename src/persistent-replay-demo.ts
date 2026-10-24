import { mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import {
  consumeBoundTransactionAuthorizationWithStore,
  issueBoundTransactionAuthorizationWithStore,
} from "./authorization-lifecycle.js";
import {
  BOUND_AUTHORIZATION_ARTIFACT_VERSION,
  createAuthorizationBindingDigest,
} from "./authorization-binding.js";
import { SQLiteAuthorizationStore } from "./authorization-store.js";
import { prepareTransactionAuthorization } from "./policy-transaction.js";
import { normalizeDemoPolicy, type DemoPolicy } from "./policy.js";
import type { TransactionRequest } from "./transaction-envelope.js";

const target = "0x1111111111111111111111111111111111111111";
const sender = "0x2222222222222222222222222222222222222222";
const recipient = "0x3333333333333333333333333333333333333333";
const amount = 5n;

const request: TransactionRequest = {
  chainId: "1",
  sender,
  target,
  calldata:
    "0xa9059cbb" +
    recipient.slice(2).padStart(64, "0") +
    amount.toString(16).padStart(64, "0"),
  value: "0",
};

const policy: DemoPolicy = {
  version: 1,
  policyId: "bound-persistent-replay-demo",
  allowedTarget: target,
  allowedRecipient: recipient,
  allowedSelector: "0xa9059cbb",
  maxAmount: "10",
  validFrom: 1_700_000_000,
  expiresAt: 2_000_000_000,
  revoked: false,
};

const trustedDemoContext = { nowSeconds: 1_800_000_000 };
const authorizationId =
  process.env.DEMO_AUTHORIZATION_ID ?? "bound-replay-demo-authorization-001";
const repositoryRoot = process.cwd();
const defaultDatabasePath = resolve(
  repositoryRoot,
  ".demo-data",
  "bound-authorization-replay.sqlite",
);
const databasePath = process.env.DEMO_DATABASE_PATH
  ? resolve(repositoryRoot, process.env.DEMO_DATABASE_PATH)
  : defaultDatabasePath;

/**
 * Execute a single invocation of the bound persistent replay demo.
 *
 * On first run against a clean database:
 *   1. Issues the bound authorization artifact (state: 'issued').
 *   2. Revalidates and consumes the artifact (state: 'consumed').
 *   3. Returns ALLOW.
 *
 * On subsequent runs against the same database:
 *   1. Reconstructs the bound artifact for the transaction.
 *   2. Attempts consumption against the already consumed database record.
 *   3. Fails closed and returns DENY.
 */
function runSingleDemo(targetDbPath: string): { decision: string; lines: string[] } {
  mkdirSync(dirname(targetDbPath), { recursive: true });
  let store: SQLiteAuthorizationStore | undefined;
  const output: string[] = [];
  let finalDecision = "UNKNOWN";

  try {
    store = new SQLiteAuthorizationStore(targetDbPath, undefined, {
      allowLegacyArtifactVersions: true,
    });
    const prepared = prepareTransactionAuthorization(
      policy,
      request,
      trustedDemoContext,
    );

    if (prepared.decision !== "ALLOW") {
      finalDecision = prepared.decision;
      output.push(
        `Decision: ${prepared.decision}`,
        ...prepared.reasons.map((reason) => `Reason: ${reason}`),
      );
    } else {
      const canonicalPolicy = normalizeDemoPolicy(policy);
      if (!canonicalPolicy) {
        throw new Error("Demo policy normalization failed.");
      }
      const bindingDigest = createAuthorizationBindingDigest(
        canonicalPolicy,
        prepared.envelope.request,
      );

      // Attempt issuance. If the ID is unused, issueBound succeeds.
      const issued = issueBoundTransactionAuthorizationWithStore(
        store,
        authorizationId,
        policy,
        request,
        trustedDemoContext,
      );

      if (issued.decision === "ALLOW") {
        // Fresh issuance succeeded: consume the issued artifact atomically
        const result = consumeBoundTransactionAuthorizationWithStore(
          store,
          issued.artifact,
          policy,
          issued.envelope,
          request,
          trustedDemoContext,
        );

        finalDecision = result.decision;
        output.push(
          `Decision: ${result.decision}`,
          `Phase: Fresh issuance and first consumption`,
          `Authorization ID: ${authorizationId}`,
          `Binding Digest: ${issued.artifact.bindingDigest}`,
          ...result.reasons.map((reason) => `Reason: ${reason}`),
          `Database: ${targetDbPath}`,
          "No transaction was signed or submitted.",
        );
      } else {
        // ID was already issued or consumed in a prior run.
        // Reconstruct artifact and attempt second consumption to demonstrate replay rejection.
        const artifact = {
          version: BOUND_AUTHORIZATION_ARTIFACT_VERSION,
          authorizationId,
          bindingDigest,
        };

        const result = consumeBoundTransactionAuthorizationWithStore(
          store,
          artifact,
          policy,
          prepared.envelope,
          request,
          trustedDemoContext,
        );

        finalDecision = result.decision;
        output.push(
          `Decision: ${result.decision}`,
          `Phase: Replay consumption attempt`,
          `Authorization ID: ${authorizationId}`,
          ...result.reasons.map((reason) => `Reason: ${reason}`),
          `Database: ${targetDbPath}`,
          "No transaction was signed or submitted.",
        );
      }
    }
  } finally {
    store?.close();
  }

  return { decision: finalDecision, lines: output };
}

/**
 * Self-contained verification mode:
 * 1. Executes fresh issuance + first consumption on an isolated temporary database.
 * 2. Closes connection, reopens connection, and attempts second consumption.
 * 3. Verifies persistence of consumed state across database reopen.
 */
function runSelfVerification(): void {
  const tempDir = resolve(
    tmpdir(),
    `web3user-demo-verify-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
  );
  const tempDbPath = resolve(tempDir, "isolated-bound-demo.sqlite");

  console.log("=== Bound Authorization Replay Demo Verification ===");
  console.log(`Isolated verification database: ${tempDbPath}`);

  try {
    // Step 1: Fresh issuance and first consumption
    const step1 = runSingleDemo(tempDbPath);
    console.log("\n[Step 1: Fresh issuance & first consumption]");
    for (const line of step1.lines) console.log(line);
    if (step1.decision !== "ALLOW") {
      throw new Error(`Step 1 expected ALLOW, got ${step1.decision}`);
    }

    // Step 2: Reopen database and attempt replay consumption
    const step2 = runSingleDemo(tempDbPath);
    console.log("\n[Step 2: Reopen database & replay consumption]");
    for (const line of step2.lines) console.log(line);
    if (step2.decision !== "DENY") {
      throw new Error(`Step 2 expected DENY, got ${step2.decision}`);
    }

    console.log("\n[Verification Summary]");
    console.log("✓ Step 1 returned ALLOW on fresh database.");
    console.log("✓ Step 2 returned DENY after closing and reopening database.");
    console.log("✓ Persistent replay protection confirmed for bound authorization.");
  } finally {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best effort cleanup of temp dir
    }
  }
}

try {
  if (process.argv.includes("--verify")) {
    runSelfVerification();
  } else {
    const { lines } = runSingleDemo(databasePath);
    for (const line of lines) console.log(line);
  }
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Persistent replay demo failed: ${message}`);
  process.exitCode = 1;
}
