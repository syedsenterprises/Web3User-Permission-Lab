import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { consumeTransactionAuthorizationWithStore } from "./authorization-lifecycle.js";
import { SQLiteAuthorizationStore } from "./authorization-store.js";
import { prepareTransactionAuthorization } from "./policy-transaction.js";
import type { DemoPolicy } from "./policy.js";
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
  policyId: "persistent-replay-demo",
  allowedTarget: target,
  allowedRecipient: recipient,
  allowedSelector: "0xa9059cbb",
  maxAmount: "10",
  validFrom: 1_700_000_000,
  expiresAt: 2_000_000_000,
  revoked: false,
};

const trustedDemoContext = { nowSeconds: 1_800_000_000 };
const authorizationId = "persistent-replay-demo-authorization-001";
const repositoryRoot = process.cwd();
const databasePath = resolve(repositoryRoot, ".demo-data", "authorization-replay.sqlite");

function runDemo(): void {
  mkdirSync(dirname(databasePath), { recursive: true });
  let store: SQLiteAuthorizationStore | undefined;
  let output: string[] = [];

  try {
    store = new SQLiteAuthorizationStore(databasePath);
    const prepared = prepareTransactionAuthorization(
      policy,
      request,
      trustedDemoContext,
    );

    if (prepared.decision !== "ALLOW") {
      output = [
        `Decision: ${prepared.decision}`,
        ...prepared.reasons.map((reason) => `Reason: ${reason}`),
      ];
    } else {
      const result = consumeTransactionAuthorizationWithStore(
        store,
        authorizationId,
        policy,
        prepared.envelope,
        request,
        trustedDemoContext,
      );

      output = [
        `Decision: ${result.decision}`,
        ...result.reasons.map((reason) => `Reason: ${reason}`),
        `Database: ${databasePath}`,
        "No transaction was signed or submitted.",
      ];
    }
  } finally {
    store?.close();
  }

  for (const line of output) console.log(line);
}

try {
  runDemo();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Persistent replay demo failed: ${message}`);
  process.exitCode = 1;
}
