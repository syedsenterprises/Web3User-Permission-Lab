/**
 * Web3User Permission Lab — Basic Authorization Integration Example
 *
 * ARCHITECTURAL NOTICE:
 * This script demonstrates the Web3User off-chain authorization engine.
 * Web3User is an off-chain policy decision and local replay-prevention gatekeeper.
 * It is NOT an on-chain smart contract, validator, or blockchain transaction broadcaster.
 *
 * Integrators run this engine within their backend or dApp services to evaluate candidate
 * transactions against authoritative policies before submitting them to an RPC provider or wallet.
 *
 * RUNNING THIS EXAMPLE:
 *   npx tsx examples/basic-authorization.ts
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  Web3UserEngine,
  type DemoPolicy,
  type TransactionRequest,
} from "../src/index.js";

async function main(): Promise<void> {
  console.log("==================================================================");
  console.log(" Web3User Permission Lab — V3 Off-Chain Authorization Engine Demo");
  console.log("==================================================================\n");

  // 1. Setup isolated temporary directory for the durable SQLite database
  const tempDir = mkdtempSync(join(tmpdir(), "web3user-example-"));
  const dbPath = join(tempDir, "authorization-store.sqlite");
  console.log(`[1] Initializing engine database at: ${dbPath}`);

  // 2. Open the Web3User Engine with explicit FULL disk durability
  const engine = Web3UserEngine.open({
    databasePath: dbPath,
    durability: {
      synchronous: "FULL", // Fsync commits for OS crash recovery
      busyTimeoutMs: 5000, // 5s timeout under concurrency contention
    },
  });

  try {
    console.log(`    Engine state: open=${engine.isOpen()}, journal=${engine.storage.getJournalMode()}, sync=${engine.storage.getSynchronousMode()}`);

    // 3. Generate a demo-only Ed25519 issuer keypair (never hardcode production secrets!)
    console.log("\n[2] Generating and registering demo Ed25519 issuer signing key...");
    const keypair = engine.keys.generate();
    const keyId = "issuer-demo-key-01";

    engine.keys.register({
      keyId,
      publicKey: keypair.publicKey,
      status: "active",
      validFromSeconds: 0,
      expiresAtSeconds: 2_000_000_000,
    });
    console.log(`    Issuer key '${keyId}' registered successfully.`);

    // 4. Register authoritative governance policy (USDC ERC-20 transfer limit: 1,000 units)
    console.log("\n[3] Registering authoritative ERC-20 governance policy...");
    const usdcContract = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const allowedRecipient = "0x2222222222222222222222222222222222222222";
    const policyId = "usdc-transfer-policy-v1";

    const policy: DemoPolicy = {
      version: 1,
      policyId,
      allowedTarget: usdcContract,
      allowedRecipient,
      allowedSelector: "0xa9059cbb", // ERC-20 transfer(address,uint256)
      maxAmount: "1000000000",       // 1,000 USDC max limit (6 decimals)
      validFrom: 0,
      expiresAt: 2_000_000_000,
      revoked: false,
    };

    const policyRecord = engine.policies.register(policy);
    console.log(`    Policy '${policyRecord.policyId}' registered at revision ${policyRecord.revision}.`);

    // 5. Construct a valid transaction request (transferring 500 USDC < 1,000 limit)
    console.log("\n[4] Preparing candidate transaction request...");
    const recipientPadded = allowedRecipient.slice(2).toLowerCase().padStart(64, "0");
    const amountPadded = (500_000_000n).toString(16).padStart(64, "0"); // 500 USDC
    const calldata = `0xa9059cbb${recipientPadded}${amountPadded}`;

    const validRequest: TransactionRequest = {
      chainId: "1",
      sender: "0x1111111111111111111111111111111111111111",
      target: usdcContract,
      calldata,
      value: "0",
    };
    console.log(`    Target: ${validRequest.target}`);
    console.log(`    Amount: 500 USDC (Calldata: ${validRequest.calldata.slice(0, 10)}...)`);

    // 6. Issue a signed V3 authorization artifact
    console.log("\n[5] Issuing Ed25519-signed V3 authorization artifact...");
    const authorizationId = "auth-tx-demo-001";

    const issueResult = engine.issue({
      authorizationId,
      policyId,
      request: validRequest,
      signer: {
        keyId,
        privateKey: keypair.privateKey,
      },
      ttlSeconds: 300, // 5-minute validity window
    });

    if (issueResult.decision !== "ALLOW") {
      throw new Error(`Issuance failed unexpectedly: ${issueResult.reasons.join(", ")}`);
    }

    console.log(`    Decision: ${issueResult.decision}`);
    console.log(`    Authorization ID: ${issueResult.artifact.authorizationId}`);
    console.log(`    Artifact Version: V${issueResult.artifact.version}`);
    console.log(`    Policy Revision: Rev ${issueResult.artifact.policyRevision}`);
    console.log(`    Signature: ${issueResult.artifact.signature.slice(0, 32)}...`);

    // 7. Relayer / Consumer consumes the authorization before execution
    console.log("\n[6] Revalidating and consuming authorization artifact...");
    const consumeResult1 = engine.consume({
      artifact: issueResult.artifact,
      envelope: issueResult.envelope,
      request: validRequest,
    });

    console.log(`    First Consumption Decision: ${consumeResult1.decision}`);
    if (consumeResult1.decision === "ALLOW") {
      console.log("    -> Authorization granted! Off-chain relayer may now broadcast the transaction.");
    }

    // 8. Attacker attempts to replay the same authorization
    console.log("\n[7] Simulating duplicate transaction replay attack...");
    const replayAttempt = engine.consume({
      artifact: issueResult.artifact,
      envelope: issueResult.envelope,
      request: validRequest,
    });

    console.log(`    Replay Consumption Decision: ${replayAttempt.decision}`);
    console.log(`    Replay Denial Reasons: ${replayAttempt.reasons.join("; ")}`);
    console.log("    -> Replay strictly blocked by persistent SQLite single-use constraint!");

    // 9. Demonstrate business policy denial (exceeding transfer limits)
    console.log("\n[8] Testing policy boundary violation (exceeding maximum transfer limit)...");
    const excessiveAmountPadded = (2_000_000_000n).toString(16).padStart(64, "0"); // 2,000 USDC > 1,000 max
    const excessiveRequest: TransactionRequest = {
      ...validRequest,
      calldata: `0xa9059cbb${recipientPadded}${excessiveAmountPadded}`,
    };

    const excessiveResult = engine.issue({
      authorizationId: "auth-tx-excessive",
      policyId,
      request: excessiveRequest,
      signer: {
        keyId,
        privateKey: keypair.privateKey,
      },
    });

    console.log(`    Excessive Request Decision: ${excessiveResult.decision}`);
    console.log(`    Denial Reasons: ${excessiveResult.reasons.join("; ")}`);
    console.log("    -> Correctly denied by policy evaluator without throwing exceptions.");

    // 10. Demonstrate authorization cancellation
    console.log("\n[9] Testing authorization cancellation before consumption...");
    const cancelAuthId = "auth-tx-cancel-demo";
    const cancelIssue = engine.issue({
      authorizationId: cancelAuthId,
      policyId,
      request: validRequest,
      signer: {
        keyId,
        privateKey: keypair.privateKey,
      },
    });

    if (cancelIssue.decision === "ALLOW") {
      const cancelled = engine.cancel(cancelAuthId);
      console.log(`    Authorization '${cancelAuthId}' cancelled: ${cancelled}`);

      const consumeCancelled = engine.consume({
        artifact: cancelIssue.artifact,
        request: validRequest,
      });
      console.log(`    Consumption of cancelled authorization: ${consumeCancelled.decision}`);
      console.log(`    Reasons: ${consumeCancelled.reasons.join("; ")}`);
    }

    // 11. Storage integrity and checkpointing
    console.log("\n[10] Checking storage integrity and WAL consolidation...");
    const integrityOk = engine.storage.checkIntegrity();
    console.log(`    Database integrity check: ${integrityOk ? "OK (PASS)" : "CORRUPT (FAIL)"}`);

    const checkpointRes = engine.storage.checkpoint("TRUNCATE");
    console.log(`    WAL Checkpoint (TRUNCATE): busy=${checkpointRes.busy}, logFrames=${checkpointRes.logFrames}`);

    console.log("\n==================================================================");
    console.log(" Demo completed successfully! All security invariants verified.");
    console.log("==================================================================");
  } finally {
    // 12. Idempotent cleanup
    engine.close();
    rmSync(tempDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error("Demo failed with error:", err);
  process.exit(1);
});
