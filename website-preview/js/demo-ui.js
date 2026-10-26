/**
 * Web3User Permission Lab — Interactive Demo UI Logic
 *
 * Coordinates preset loading, live form synchronization, real-time evaluation,
 * color-coded calldata inspection, rule checklist verification, and TypeScript code generation.
 */

import {
  evaluateDetailed,
  encodeTransferCalldata,
  ERC20_TRANSFER_SELECTOR,
} from "./evaluator.js";

// Canonical USDC & demo addresses
const USDC_MAINNET = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const USDT_MAINNET = "0xdac17f958d2ee523a2206206994597c13d831ec7";
const ALLOWED_RECIPIENT = "0x2222222222222222222222222222222222222222";
const UNAPPROVED_RECIPIENT = "0x4444444444444444444444444444444444444444";
const BASE_NOW = 1800000100;

export const PRESETS = {
  compliant_transfer: {
    name: "1. Compliant Transfer",
    badge: "ALLOW",
    description: "500 USDC transfer within policy limits (1,000 max limit) to approved recipient.",
    policy: {
      version: 1,
      policyId: "usdc-transfer-policy-v1",
      allowedTarget: USDC_MAINNET,
      allowedRecipient: ALLOWED_RECIPIENT,
      allowedSelector: ERC20_TRANSFER_SELECTOR,
      maxAmount: "1000000000", // 1,000 USDC (6 decimals)
      validFrom: 1800000000,
      expiresAt: 1800086400,
      revoked: false,
    },
    action: {
      target: USDC_MAINNET,
      recipient: ALLOWED_RECIPIENT,
      amount: "500000000", // 500 USDC
      calldata: "", // Auto-generated
    },
    context: {
      nowSeconds: BASE_NOW,
    },
  },
  excessive_amount: {
    name: "2. Limit Exceeded",
    badge: "DENY",
    description: "2,000 USDC transfer exceeding the 1,000 USDC per-action policy ceiling.",
    policy: {
      version: 1,
      policyId: "usdc-transfer-policy-v1",
      allowedTarget: USDC_MAINNET,
      allowedRecipient: ALLOWED_RECIPIENT,
      allowedSelector: ERC20_TRANSFER_SELECTOR,
      maxAmount: "1000000000",
      validFrom: 1800000000,
      expiresAt: 1800086400,
      revoked: false,
    },
    action: {
      target: USDC_MAINNET,
      recipient: ALLOWED_RECIPIENT,
      amount: "2000000000", // 2,000 USDC > 1,000 max
      calldata: "",
    },
    context: {
      nowSeconds: BASE_NOW,
    },
  },
  unapproved_recipient: {
    name: "3. Unapproved Recipient",
    badge: "DENY",
    description: "Transfer to unlisted recipient 0x4444...4444 blocked by allowlist filter.",
    policy: {
      version: 1,
      policyId: "usdc-transfer-policy-v1",
      allowedTarget: USDC_MAINNET,
      allowedRecipient: ALLOWED_RECIPIENT,
      allowedSelector: ERC20_TRANSFER_SELECTOR,
      maxAmount: "1000000000",
      validFrom: 1800000000,
      expiresAt: 1800086400,
      revoked: false,
    },
    action: {
      target: USDC_MAINNET,
      recipient: UNAPPROVED_RECIPIENT,
      amount: "500000000",
      calldata: "",
    },
    context: {
      nowSeconds: BASE_NOW,
    },
  },
  unapproved_target: {
    name: "4. Unapproved Target",
    badge: "DENY",
    description: "Transfer interacting with unapproved contract (USDT) instead of allowlisted USDC.",
    policy: {
      version: 1,
      policyId: "usdc-transfer-policy-v1",
      allowedTarget: USDC_MAINNET,
      allowedRecipient: ALLOWED_RECIPIENT,
      allowedSelector: ERC20_TRANSFER_SELECTOR,
      maxAmount: "1000000000",
      validFrom: 1800000000,
      expiresAt: 1800086400,
      revoked: false,
    },
    action: {
      target: USDT_MAINNET,
      recipient: ALLOWED_RECIPIENT,
      amount: "500000000",
      calldata: "",
    },
    context: {
      nowSeconds: BASE_NOW,
    },
  },
  expired_policy: {
    name: "5. Expired Policy",
    badge: "DENY",
    description: "Evaluation time (1800100000) falls after the policy expiration timestamp.",
    policy: {
      version: 1,
      policyId: "usdc-transfer-policy-v1",
      allowedTarget: USDC_MAINNET,
      allowedRecipient: ALLOWED_RECIPIENT,
      allowedSelector: ERC20_TRANSFER_SELECTOR,
      maxAmount: "1000000000",
      validFrom: 1800000000,
      expiresAt: 1800086400,
      revoked: false,
    },
    action: {
      target: USDC_MAINNET,
      recipient: ALLOWED_RECIPIENT,
      amount: "500000000",
      calldata: "",
    },
    context: {
      nowSeconds: 1800100000, // Post-expiration
    },
  },
  revoked_policy: {
    name: "6. Revoked Policy",
    badge: "DENY",
    description: "Policy has been explicitly revoked by administrator or governance action.",
    policy: {
      version: 1,
      policyId: "usdc-transfer-policy-v1",
      allowedTarget: USDC_MAINNET,
      allowedRecipient: ALLOWED_RECIPIENT,
      allowedSelector: ERC20_TRANSFER_SELECTOR,
      maxAmount: "1000000000",
      validFrom: 1800000000,
      expiresAt: 1800086400,
      revoked: true,
    },
    action: {
      target: USDC_MAINNET,
      recipient: ALLOWED_RECIPIENT,
      amount: "500000000",
      calldata: "",
    },
    context: {
      nowSeconds: BASE_NOW,
    },
  },
  calldata_mismatch: {
    name: "7. Calldata Tampering",
    badge: "UNKNOWN",
    description: "Claimed amount (500) differs from encoded calldata amount (1,000).",
    policy: {
      version: 1,
      policyId: "usdc-transfer-policy-v1",
      allowedTarget: USDC_MAINNET,
      allowedRecipient: ALLOWED_RECIPIENT,
      allowedSelector: ERC20_TRANSFER_SELECTOR,
      maxAmount: "1000000000",
      validFrom: 1800000000,
      expiresAt: 1800086400,
      revoked: false,
    },
    action: {
      target: USDC_MAINNET,
      recipient: ALLOWED_RECIPIENT,
      amount: "500000000", // Claims 500
      // Calldata deliberately encodes 1,000,000,000 (0x3b9aca00)
      calldata: `0xa9059cbb0000000000000000000000002222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000003b9aca00`,
    },
    context: {
      nowSeconds: BASE_NOW,
    },
  },
  unsupported_selector: {
    name: "8. Invalid Selector",
    badge: "DENY",
    description: "Transaction calls approve() (0x095ea7b3) instead of transfer() (0xa9059cbb).",
    policy: {
      version: 1,
      policyId: "usdc-transfer-policy-v1",
      allowedTarget: USDC_MAINNET,
      allowedRecipient: ALLOWED_RECIPIENT,
      allowedSelector: ERC20_TRANSFER_SELECTOR,
      maxAmount: "1000000000",
      validFrom: 1800000000,
      expiresAt: 1800086400,
      revoked: false,
    },
    action: {
      target: USDC_MAINNET,
      recipient: ALLOWED_RECIPIENT,
      amount: "500000000",
      calldata: `0x095ea7b30000000000000000000000002222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000001dcd6500`,
    },
    context: {
      nowSeconds: BASE_NOW,
    },
  },
  budget_exceeded: {
    name: "9. Budget Exceeded",
    badge: "DENY",
    description: "Transfer of 400 USDC within per-action limit (1,000), but cumulative hourly spending (700 spent + 400 proposed = 1,100) exceeds 1,000 hourly budget cap.",
    policy: {
      version: 1,
      policyId: "usdc-budget-policy-v1",
      allowedTarget: USDC_MAINNET,
      allowedRecipient: ALLOWED_RECIPIENT,
      allowedSelector: ERC20_TRANSFER_SELECTOR,
      maxAmount: "1000000000",
      validFrom: 1800000000,
      expiresAt: 1800086400,
      revoked: false,
      budget: {
        window: "HOURLY",
        maxCumulativeAmount: "1000000000",
      },
    },
    action: {
      target: USDC_MAINNET,
      recipient: ALLOWED_RECIPIENT,
      amount: "400000000",
      calldata: "",
    },
    context: {
      nowSeconds: BASE_NOW,
      currentWindowSpent: "700000000",
    },
  },
};

export function initDemo(container) {
  if (!container) return;

  const els = {
    // Presets bar
    presetButtons: container.querySelector("#demo-presets"),
    presetDesc: container.querySelector("#preset-description"),

    // Policy inputs
    policyId: container.querySelector("#policy-id"),
    allowedTarget: container.querySelector("#allowed-target"),
    allowedRecipient: container.querySelector("#allowed-recipient"),
    maxAmount: container.querySelector("#max-amount"),
    validFrom: container.querySelector("#valid-from"),
    expiresAt: container.querySelector("#expires-at"),
    policyRevoked: container.querySelector("#policy-revoked"),
    budgetWindow: container.querySelector("#budget-window"),
    maxCumulativeAmount: container.querySelector("#max-cumulative-amount"),

    // Action inputs
    actionTarget: container.querySelector("#action-target"),
    actionRecipient: container.querySelector("#action-recipient"),
    actionAmount: container.querySelector("#action-amount"),
    simulatedSpent: container.querySelector("#simulated-spent"),
    actionCalldata: container.querySelector("#action-calldata"),
    syncCalldataBtn: container.querySelector("#btn-sync-calldata"),
    evalTimestamp: container.querySelector("#eval-timestamp"),
    setNowBtn: container.querySelector("#btn-set-now"),

    // Outputs
    decisionBanner: container.querySelector("#demo-decision-banner"),
    decisionBadge: container.querySelector("#demo-decision-badge"),
    decisionReasons: container.querySelector("#demo-decision-reasons"),
    checksList: container.querySelector("#demo-checklist"),
    calldataDisplay: container.querySelector("#demo-calldata-display"),
    calldataDecoded: container.querySelector("#demo-calldata-decoded"),
    tsSnippet: container.querySelector("#demo-ts-code"),
    copyBtn: container.querySelector("#btn-copy-code"),
    copyFeedback: container.querySelector("#copy-feedback"),
  };

  // Render presets buttons
  els.presetButtons.innerHTML = "";
  Object.entries(PRESETS).forEach(([key, preset]) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `demo-preset-btn preset-${preset.badge.toLowerCase()}`;
    btn.innerHTML = `<span class="preset-name">${preset.name}</span><span class="preset-tag ${preset.badge.toLowerCase()}">${preset.badge}</span>`;
    btn.addEventListener("click", () => {
      loadPreset(key);
      container.querySelectorAll(".demo-preset-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
    });
    els.presetButtons.appendChild(btn);
  });

  function loadPreset(key) {
    const p = PRESETS[key];
    if (!p) return;

    if (els.presetDesc) {
      els.presetDesc.textContent = p.description;
    }

    els.policyId.value = p.policy.policyId;
    els.allowedTarget.value = p.policy.allowedTarget;
    els.allowedRecipient.value = p.policy.allowedRecipient;
    els.maxAmount.value = p.policy.maxAmount;
    els.validFrom.value = p.policy.validFrom;
    els.expiresAt.value = p.policy.expiresAt;
    els.policyRevoked.checked = p.policy.revoked;

    if (p.policy.budget) {
      els.budgetWindow.value = p.policy.budget.window;
      els.maxCumulativeAmount.value = p.policy.budget.maxCumulativeAmount;
    } else {
      els.budgetWindow.value = "NONE";
      els.maxCumulativeAmount.value = "";
    }

    els.actionTarget.value = p.action.target;
    els.actionRecipient.value = p.action.recipient;
    els.actionAmount.value = p.action.amount;
    els.evalTimestamp.value = p.context.nowSeconds;

    if (p.context.currentWindowSpent !== undefined) {
      els.simulatedSpent.value = p.context.currentWindowSpent;
    } else {
      els.simulatedSpent.value = "";
    }

    if (p.action.calldata) {
      els.actionCalldata.value = p.action.calldata;
    } else {
      recomputeCalldata();
    }

    runEvaluation();
  }

  function recomputeCalldata() {
    try {
      const recipient = els.actionRecipient.value.trim();
      const amount = els.actionAmount.value.trim();
      const calldata = encodeTransferCalldata(recipient, amount);
      els.actionCalldata.value = calldata;
    } catch {
      // Keep existing calldata if invalid
    }
  }

  function getFormData() {
    const budgetWindow = els.budgetWindow.value;
    const policy = {
      version: 1,
      policyId: els.policyId.value.trim(),
      allowedTarget: els.allowedTarget.value.trim(),
      allowedRecipient: els.allowedRecipient.value.trim(),
      allowedSelector: ERC20_TRANSFER_SELECTOR,
      maxAmount: els.maxAmount.value.trim(),
      validFrom: parseInt(els.validFrom.value.trim(), 10) || 0,
      expiresAt: parseInt(els.expiresAt.value.trim(), 10) || 0,
      revoked: els.policyRevoked.checked,
    };

    if (budgetWindow === "HOURLY" || budgetWindow === "DAILY") {
      policy.budget = {
        window: budgetWindow,
        maxCumulativeAmount: els.maxCumulativeAmount.value.trim(),
      };
    }

    const action = {
      target: els.actionTarget.value.trim(),
      calldata: els.actionCalldata.value.trim(),
      amount: els.actionAmount.value.trim(),
    };

    const context = {
      nowSeconds: parseInt(els.evalTimestamp.value.trim(), 10) || 0,
    };

    if (policy.budget) {
      context.currentWindowSpent = els.simulatedSpent.value.trim() || "0";
    }

    return { policy, action, context };
  }

  function runEvaluation() {
    const { policy, action, context } = getFormData();
    const result = evaluateDetailed(policy, action, context);

    // Update Banner & Badge
    els.decisionBanner.className = `decision-banner status-${result.decision.toLowerCase()}`;
    els.decisionBadge.className = `decision-badge badge-${result.decision.toLowerCase()}`;
    els.decisionBadge.textContent = result.decision;

    // Update Reasons
    els.decisionReasons.innerHTML = "";
    result.reasons.forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      els.decisionReasons.appendChild(li);
    });

    // Update Checklist
    els.checksList.innerHTML = "";
    result.checks.forEach((c) => {
      const item = document.createElement("li");
      item.className = `check-item ${c.passed ? "passed" : "failed"}`;
      const icon = c.passed ? "&#10003;" : "&#10007;";
      item.innerHTML = `<span class="check-icon">${icon}</span> <div class="check-body"><strong>${c.name}</strong><span class="check-msg">${c.message}</span></div>`;
      els.checksList.appendChild(item);
    });

    // Update Calldata Inspector
    if (result.calldataBreakdown) {
      const b = result.calldataBreakdown;
      els.calldataDisplay.innerHTML = `
        <span class="cd-selector" title="Selector: ERC-20 transfer">${b.selector}</span><span class="cd-recipient" title="32-byte Padded Recipient Word">${b.recipientWord}</span><span class="cd-amount" title="32-byte Amount Word">${b.amountWord}</span>
      `;
      els.calldataDecoded.innerHTML = `
        <span><strong>Decoded Recipient:</strong> <code>${b.decodedRecipient ?? "None / Decode Error"}</code></span> &middot;
        <span><strong>Decoded Amount:</strong> <code>${b.decodedAmount ? `${b.decodedAmount} (base units)` : "Decode Error"}</code></span>
      `;
    } else {
      els.calldataDisplay.textContent = action.calldata || "(Empty calldata)";
      els.calldataDecoded.textContent = "Calldata cannot be inspected (invalid format)";
    }

    // Update Copyable Code Snippet
    updateCodeSnippet(policy, action);
  }

  function updateCodeSnippet(policy, action) {
    const budgetSnippet = policy.budget
      ? `\n  budget: {\n    window: "${policy.budget.window}",\n    maxCumulativeAmount: "${policy.budget.maxCumulativeAmount}",\n  },`
      : "";
    const code = `import { Web3UserEngine, type DemoPolicy, type TransactionRequest } from "web3user-permission-lab";

// 1. Initialize Web3User Engine with SQLite durability
const engine = Web3UserEngine.open({
  databasePath: "./authorization-store.sqlite",
});

// 2. Authoritative governance policy
const policy: DemoPolicy = {
  version: 1,
  policyId: "${policy.policyId}",
  allowedTarget: "${policy.allowedTarget}",
  allowedRecipient: "${policy.allowedRecipient}",
  allowedSelector: "0xa9059cbb", // ERC-20 transfer(address,uint256)
  maxAmount: "${policy.maxAmount}",
  validFrom: ${policy.validFrom},
  expiresAt: ${policy.expiresAt},
  revoked: ${policy.revoked},${budgetSnippet}
};
engine.policies.register(policy);

// 3. Candidate transaction request
const request: TransactionRequest = {
  chainId: "1",
  sender: "0x1111111111111111111111111111111111111111",
  target: "${action.target}",
  calldata: "${action.calldata}",
  value: "0",
};

// 4. Issue and consume with single-use replay protection
const issueResult = engine.issue({
  authorizationId: "auth-${Date.now()}",
  policyId: policy.policyId,
  request,
  signer: { keyId: "issuer-key-01", privateKey: process.env.ISSUER_KEY! },
});

if (issueResult.decision === "ALLOW") {
  const consumeResult = engine.consume({
    artifact: issueResult.artifact,
    request,
  });
  console.log("Consumption decision:", consumeResult.decision);
}`;
    els.tsSnippet.textContent = code;
  }

  // Event Listeners
  [
    els.policyId,
    els.allowedTarget,
    els.allowedRecipient,
    els.maxAmount,
    els.validFrom,
    els.expiresAt,
    els.policyRevoked,
    els.budgetWindow,
    els.maxCumulativeAmount,
    els.actionTarget,
    els.actionRecipient,
    els.actionAmount,
    els.simulatedSpent,
    els.actionCalldata,
    els.evalTimestamp,
  ].forEach((input) => {
    input.addEventListener("input", runEvaluation);
    input.addEventListener("change", runEvaluation);
  });

  els.syncCalldataBtn.addEventListener("click", () => {
    recomputeCalldata();
    runEvaluation();
  });

  els.setNowBtn.addEventListener("click", () => {
    els.evalTimestamp.value = Math.floor(Date.now() / 1000);
    runEvaluation();
  });

  els.copyBtn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(els.tsSnippet.textContent);
      els.copyFeedback.textContent = "Copied to clipboard!";
      setTimeout(() => {
        els.copyFeedback.textContent = "";
      }, 2500);
    } catch {
      els.copyFeedback.textContent = "Press Ctrl+C to copy";
    }
  });

  // Load first preset on startup
  const firstPresetBtn = els.presetButtons.querySelector("button");
  if (firstPresetBtn) {
    firstPresetBtn.click();
  } else {
    loadPreset("compliant_transfer");
  }
}
