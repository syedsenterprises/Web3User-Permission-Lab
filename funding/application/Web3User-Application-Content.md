# Web3User — .TECH Funding Application Questionnaire & Core Submission Content

**Applicant Name:** Syed Shahed  
**Organization / Entity:** Syed's Enterprises (Solo Venture &middot; [syedsenterprises.org](https://syedsenterprises.org/))  
**Email:** info@syedsenterprises.org  
**Project Name:** Web3User Permission Lab  
**Production Domain:** [https://web3user.tech](https://web3user.tech)  
**Documentation:** [https://docs.web3user.tech](https://docs.web3user.tech)  
**GitHub Repository:** `https://github.com/syedsenterprises/Web3User-Permission-Lab`  
**Application Category:** Developer Tools, Infrastructure & Blockchain Security  
**Date of Submission:** 24 November 2026 (Updated 28 November 2026)

---

## Question 1: What is Web3User and what does it do?

**Web3User Permission Lab** is an off-chain transaction authorization and policy governance SDK for Node.js and TypeScript.

It functions as an embeddable, policy-driven cryptographic guard between high-risk transaction generation (dApps, autonomous AI agents, operational backend workers, or payment systems) and signing keys. Rather than granting unconstrained signing authority to automated software processes, Web3User deterministically evaluates candidate transaction payloads against declarative policies—enforcing recipient address whitelists, per-action spending ceilings, cumulative budget caps across fixed UTC time windows (hourly and daily), and monotonic time bounds.

Once evaluated, Web3User issues single-use signed authorization envelopes (Ed25519) utilizing Cloud Key Management Systems (AWS KMS and GCP Cloud KMS) or local test signers. When Cloud KMS signers are used, master private keys remain inside the remote cloud KMS and **never enter Node.js application RAM**, returning normalized RFC 8410 raw 64-byte signatures. The SDK enforces single-use replay protection through transactional SQLite Write-Ahead Logging (WAL) and includes an independently audited pure state machine reducer designed for distributed consensus tracking.

---

## Question 2: What problem does your project solve, and why is it important now?

In traditional Web3 architectures, possession of a private key conveys total, unconstrained authority over all assets in an account. If an automated bot, API credential, or operational worker process is compromised, an attacker can transfer all funds immediately. 

Empirical blockchain security research demonstrates the dominance of key compromise and infrastructure failures:
- **TRM Labs (2026 Crypto Crime Report — 2025 Hacks & Exploits Dataset):** In its analysis of 2025 crypto hacks and exploits (`https://www.trmlabs.com/reports-and-whitepapers/2026-crypto-crime-report`), TRM Labs reported that approximately **$2.87 billion was stolen across nearly 150 hacks and exploits**, with **$2.2 billion (76%) across 45 incidents** resulting specifically from infrastructure attacks—including private key theft, seed phrase compromises, API key leaks, and access control breaches—far exceeding smart contract code bugs within hacks.
- **Chainalysis (2025–2026 Crypto Hacking & Stolen Funds Analysis):** Across all cryptocurrency theft vectors (`https://www.chainalysis.com/blog/crypto-hacking-stolen-funds-2026/`), total theft exceeded **$3.4 billion in 2025**. Separately within personal-wallet compromises, Chainalysis documented **158,000 personal-wallet compromise incidents affecting at least 80,000 unique victims in 2025** (not all $3.4B was stolen via private-key compromise alone).

Furthermore, while on-chain multi-signature smart contracts (such as Safe) provide essential custody governance for cold storage treasuries, requiring an on-chain multisig transaction for every routine automated action incurs gas fees, block latency, and manual quorum coordination. Web3User provides the missing pre-execution authorization layer: deterministic, pre-execution off-chain policy governance with hardware-isolated signing, allowing developers to enforce execution limits before transactions reach signers.

---

## Question 3: What is the current technical implementation status?

Web3User is a functioning, pre-production (`v0.1.0-rc.1`, `private: true`) TypeScript software library backed by a **historical accepted milestone baseline of 806 passing tests across 39 test files (Stage 2-B.1.1)** and a **latest PR #9 local regression result of 985 passed, 6 skipped, 0 failures across 54 test files** (where the 6 skipped tests are environment-gated live AWS S3 integration tests in `test/witness/aws-s3-adapter.real.test.ts` that require live AWS credentials/buckets). Passing tests demonstrate deterministic local/mocked behavior across Linux and Windows environments; they do **not** constitute an independent security audit or proof of production readiness.

Key completed and verified milestones include:
1. **Core Policy Engine (Milestones 0–8):** Deterministic ERC-20 transfer calldata parsing (`0xa9059cbb`), parameter normalization, address whitelisting, and per-action limit enforcement.
2. **Persistent Single-Use Replay Protection:** Transactional SQLite WAL mode (`BEGIN IMMEDIATE`) with immediate rollback and non-spinning contention handling. Multi-process concurrency tests using IPC rendezvous barriers demonstrate that under concurrent competition for the same authorization, exactly one process receives an ALLOW while concurrent attempts receive deterministic DENYs.
3. **Cumulative Spending Budgets:** Fixed UTC hourly (3,600s) and daily (86,400s) window budget tracking preventing budget exhaustion or cross-window leakage.
4. **Monotonic Clock Protection:** Subtraction-first safe integer TTL arithmetic and `ClockGuard` high-water mark anchoring preventing time-travel or system-clock skew attacks.
5. **Cloud KMS Signer Adapters (Milestone FN-SEC-01):** Production-ready signer adapters for AWS KMS and Google Cloud KMS featuring RFC 8410 DER-to-raw 64-byte Ed25519 signature normalization, algorithm contract enforcement, and automated factory instantiation. In automated CI testing, these adapters are verified against mock service contracts matching cloud API specifications (dedicated live cloud HSM testing is a planned funded milestone).
6. **Consensus Pure State Machine Reducer & Persistence (Milestone 13-D Stages 2-B.1, 2-B.2 & 2-B.3):** Stage 2-B.1 pure consensus reducer (11 action types, single-slot idempotency, atomic epoch transitions) and Stage 2-B.2 PostgreSQL consensus persistence, snapshot manager, and compaction coordinator are merged on `main` (PR #2, `BLK-01` closed). Stage 2-B.3 (PR #9) adds a 3-node real-`etcd` test harness, TCP loopback fault proxy, and AWS S3 snapshot adapter using the AWS SDK v3 default credential provider chain (test harness and adapter work only—not a production multi-node Raft deployment).
7. **Client-Side Interactive Web Playground:** Operational in-browser policy demonstration deployed at `https://web3user.tech/#demo` featuring 9 representative scenario presets, live calldata ABI decoding, rule checklist verification, and copyable TypeScript code (runs client-side in JS/browser; no hosted API).

*Boundary Note & Open Production Blockers (`BLK-02`–`BLK-12`):* On-chain smart contract verification modules (ERC-4337 / ERC-7579), production multi-node Raft clusters (Stage 3-A, `BLK-08`), revocation freshness background sync (`BLK-02`), live cloud KMS/S3 validation (`BLK-03`, `BLK-07`), air-gapped key ceremony & DR drills (`BLK-04`, `BLK-05`), Postgres HA/observability (`BLK-06`, `BLK-09`), and an independent commercial security audit (`BLK-10`) remain open production gates, not operational production services.

---

## Question 4: Who are your target users and customers?

Web3User serves four key customer segments in the decentralized ecosystem:
1. **Web3 Fintechs & Payment Gateways:** Remittance and payment providers who must enforce compliance spending ceilings and destination whitelists before broadcasting customer transactions.
2. **Autonomous AI Agents & Bot Developers:** Developers building agentic on-chain systems that need autonomous signing capability within strictly bounded operational allowances without risking master wallet drain.
3. **Institutional Asset Managers & Treasuries:** DAOs and digital asset funds managing operational disbursements and payroll without incurring costly on-chain multisig gas fees for routine daily expenses.
4. **Account Abstraction & Modular Wallet Builders (ERC-4337 / ERC-7579):** Wallet SDK developers implementing session keys and custom paymaster validation rules.

---

## Question 5: What is your business and monetization model?

Web3User follows an **Open-Core & Enterprise SDK** commercialization model:

### 1. Implemented & Verified in Core Engine (Open-Core Community Edition):
- Standalone Node.js SDK with local SQLite WAL persistence and software/KMS Ed25519 signing for indie developers, hackathons, and single-bot operators (Free & Open Source).

### 2. In-Browser Demonstration:
- Interactive Playground at `web3user.tech/#demo` providing instant client-side testing of policy evaluation and ABI calldata parsing.

### 3. Proposed Commercial Roadmap (Tiered Annual Subscription):
- **Tier 1 — Developer License ($1,200/year):** Production adapters for AWS KMS and GCP Cloud KMS with standard support.
- **Tier 2 — Growth / Fintech License ($6,000/year):** Multi-node etcd / Raft consensus persistence adapters, tamper-evident witness receipts, high-availability SLAs, and priority security patches.
- **Tier 3 — Enterprise & Regulated Financial License ($25,000/year):** Custom policy DSL development, dedicated hardware HSM provisioning support, and on-premise compliance audit trails.
- **Hosted Policy Verification & Witness Service (SaaS API):** High-availability mTLS witness cluster providing tamper-evident cryptographic authorization receipts and compliance audit trails.

### Market Sizing Derivation & Revenue Hypotheses:
- **Total Developer Pool Baseline:** ~50,000 active developers globally (Electric Capital Developer Report tracking ~20,000–25,000 monthly active open-source contributors, plus an estimated equal proprietary developer pool).
- **Eligible Developer Subset Hypothesis:** Approximately **50% (~25,000 developers)** work on backend transaction infrastructure, automated agents, payment rails, trading systems, and wallet services (excluding UI frontends, artists, and protocol core client developers).
- **Average Team Size Hypothesis:** **5 to 7 developers** per team, yielding an estimated addressable population of **~3,500 to 5,000 active protocol, dApp, and fintech engineering teams globally** ($25,000 / 7 \approx 3,571$; $25,000 / 5 = 5,000$).
- **Theoretical Addressable Niche:** At an illustrative blended ACV hypothesis of $6,000/year across tiers, $3,500\text{ teams} \times \$6,000 = \mathbf{\$21\text{ Million USD}}$ annually if 100% of these teams adopted off-chain policy governance.
- **Adoption Scenarios (Explicit Customer Mix Hypotheses — Not Realized Revenue):**
  - **Phase 1 (Years 1–2 Early Adopter Target Hypothesis: 50 to 122 teams $\to$ $151k to $600k ARR):**
    - *Lower Bound (50 teams):* 35 Tier 1 ($1.2k) + 14 Tier 2 ($6k) + 1 Tier 3 ($25k) = **$151,000 ARR**.
    - *Upper Bound (122 teams):* 75 Tier 1 ($1.2k) + 35 Tier 2 ($6k) + 12 Tier 3 ($25k) = **$600,000 ARR**.
  - **Phase 2 (Years 3–4 Growth Scale Hypothesis: 300 to 500 teams $\to$ $1.32M to $2.42M ARR):**
    - *Lower Bound (300 teams):* 180 Tier 1 ($1.2k) + 100 Tier 2 ($6k) + 20 Tier 3 ($25k) = **$1,316,000 ARR (~$1.32M)**.
    - *Upper Bound (500 teams):* 280 Tier 1 ($1.2k) + 180 Tier 2 ($6k) + 40 Tier 3 ($25k) = **$2,416,000 ARR (~$2.42M)**.

### Competitive Differentiation:
Compared to hosted institutional custody platforms like Fireblocks (which offers a developer sandbox, an Essentials plan at $999/month for up to $1M quarterly volume, embedded wallets at $249/month, and custom enterprise tiers cited from `https://www.fireblocks.com/pricing/`), Web3User is an embeddable, self-hosted Node.js SDK. Developers enforce pre-signing policies inside their own runtimes using their own AWS or GCP Cloud KMS keys, maintaining complete data sovereignty and zero custodial lock-in.

---

## Question 6: How will the .TECH Funding be allocated?

The requested funding will be directly deployed across four critical technical and operational objectives (represented as a proposed percentage allocation of received grant funds):

| Allocation Category | Proposed Percentage | Budget Purpose |
| :--- | :--- | :--- |
| **1. Independent Security Audit** | **40%** | Engaging a tier-1 blockchain/cryptographic security auditing firm to conduct formal verification of the policy reducer, signature normalization, and replay protection. |
| **2. Cloud Infrastructure & Testbeds** | **25%** | Provisioning dedicated multi-region AWS KMS and GCP Cloud KMS hardware HSM testbeds and distributed etcd benchmark clusters. |
| **3. Developer Documentation & Tooling** | **20%** | Expanding interactive developer quickstarts, creating plug-and-play SDK adapters for ethers.js, viem, and wagmi, and authoring reference architectures. |
| **4. Community & Open-Source Grants** | **15%** | Sponsoring developer bounties, hackathon integration prizes, and community feedback programs to drive developer adoption. |

*Note: Percentages represent the proposed allocation of received grant funds. No speculative total grant dollar amount is assumed.*

---

## Question 7: What are the key future milestones on your roadmap?

1. **Q1 2027 — Production Hardening & Open Blockers (`BLK-02`–`BLK-07`, `BLK-09`, `BLK-12`):** Complete revocation freshness background sync, live AWS/GCP KMS & S3 cloud validation, air-gapped backup key ceremony, cross-store DR drills, PostgreSQL HA/SSL/PITR, and observability baseline (building on Stage 2-B.2 merged on `main` and Stage 2-B.3 harness in PR #9).
2. **Q2 2027 — Stage 3-A Production Multi-Node Raft Consensus Cluster (`BLK-08`):** Production deployment and stress-testing of distributed multi-node Raft clusters with automated leader election and partition tolerance.
3. **Q3 2027 — Independent Commercial Audit & v1.0.0 Stable Release:** Complete third-party security audit and release the stable production SDK.
4. **Q4 2027 — Multi-Chain & Account Abstraction Native Modules:** Launch official ERC-4337 paymaster and ERC-7579 session key validation plugins for Ethereum, Arbitrum, Base, and Polygon.
