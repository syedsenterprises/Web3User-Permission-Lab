# Web3User — Narration Scripts & Founder Video Demonstration Guide

**Project:** Web3User Permission Lab ([web3user.tech](https://web3user.tech))  
**Founder:** Syed Shahed  
**Organization / Entity:** Syed's Enterprises (Solo Venture &middot; [syedsenterprises.org](https://syedsenterprises.org/))  
**Date:** 24 November 2026

---

## Part 1: Slide-by-Slide Narration Script (10–12 Minutes Full Deck Presentation)

### Slide 1: Cover (0:00 – 0:50)
*"Welcome, evaluators and partners. I am Syed Shahed, founder of Syed's Enterprises. Today, I am proud to present Web3User Permission Lab—an off-chain transaction authorization and policy governance SDK for Node.js and TypeScript.

In the Web3 ecosystem, software applications must move capital programmatically. Yet giving automated software direct access to unconstrained private keys creates severe security exposure. Web3User establishes deterministic, pre-execution cryptographic guardrails that enforce recipient whitelists, per-action spending limits, cumulative time budgets, and single-use replay protection before transactions are signed. You can explore our live technology right now at web3user.tech."*

### Slide 2: The Problem — The All-or-Nothing Private Key Dilemma (0:50 – 1:50)
*"Why is capital continuously lost in Web3? Empirical research reveals that the vulnerability lies predominantly at the infrastructure and control-plane layer.

According to TRM Labs, out of approximately $2.87 Billion stolen across blockchain hacks and exploits in 2025, over 76%—amounting to $2.2 Billion—resulted specifically from infrastructure attacks: private key theft, seed phrase compromises, API key leaks, and access control breaches, far exceeding smart contract coding bugs within hacks.

Furthermore, Chainalysis reports that total cryptocurrency theft surpassed $3.4 Billion in 2025 across all vectors, with personal wallet drainers and compromise campaigns generating over 158,000 individual incident reports affecting at least 80,000 unique victims.

The root cause is structural: an Ethereum or Solana private key conveys all-or-nothing power. If an automated bot or operational worker holds the key, any compromise can drain the entire balance. Meanwhile, requiring on-chain multisigs like Safe for routine automated actions incurs gas costs and block confirmation latency that are impractical for automated bots or high-frequency payouts. Web3 has lacked a programmable off-chain authorization layer."*

### Slide 3: The Solution — Deterministic Off-Chain Authorization (1:50 – 2:50)
*"Web3User solves this by placing a deterministic policy evaluation engine directly between candidate transactions and signing keys. Think of it as an embeddable cryptographic firewall for blockchain actions.

Instead of giving automated systems raw keys, they propose transactions to Web3User. The engine decodes the calldata ABI, checks expiration timestamps with monotonic clock protection, enforces per-action spending limits, verifies recipient whitelists, and calculates cumulative spend over fixed UTC hourly and daily windows. If all policy rules pass, the persistence layer uses transactional SQLite WAL mode to enforce single-use replay protection, and a Cloud KMS adapter generates a signed Ed25519 authorization envelope."*

### Slide 4: The Product — SDK, Evaluator & Interactive Playground (2:50 – 3:50)
*"Web3User is designed as a developer-first TypeScript SDK with zero runtime dependencies for core policy evaluation. Developers embed it into their Node.js applications with a few lines of code.

To demonstrate the engine's power, our live website at web3user.tech features a fully functional client-side Interactive Policy Playground. Running 100% in-browser in WebAssembly and JavaScript, evaluators can test 9 representative presets—from compliant transfers and limit breaches to calldata tampering and cumulative budget exhaustion—with real-time ALLOW and DENY decisions, rule checklists, and ABI inspection."*

### Slide 5: How It Works — The Five-Stage Authorization Pipeline (3:50 – 4:50)
*"The authorization pipeline follows five stages:
First, a candidate transaction is proposed with its target contract, recipient, amount, raw calldata, and policy ID.
Second, the policy evaluator normalizes the parameters, verifies ABI integrity, and checks cumulative budget windows.
Third, the persistence layer executes an immediate write transaction (`BEGIN IMMEDIATE`) in SQLite WAL mode, checking single-use authorization state and monotonic clock bounds.
Fourth, an Ed25519 signature is generated using a Cloud KMS key in AWS KMS or GCP Cloud KMS (or a local test software signer), normalizing DER signatures to raw RFC 8410 64-byte format.
Fifth, a signed V3 authorization envelope is returned, verifiable off-chain against the configured public key. On-chain smart contract validation and multi-node witness persistence are planned roadmap integrations."*

### Slide 6: Technology Architecture — Multi-Tiered Defense (4:50 – 5:50)
*"Under the hood, Web3User is engineered for high-concurrency workloads:
- Storage & Replay: Transactional SQLite in WAL mode with immediate locking isolates concurrent worker processes.
- Monotonic Protection: Subtraction-first safe integer TTL math and ClockGuard high-water mark anchoring prevent clock manipulation exploits.
- Cloud KMS Adapters: Production-ready adapters for AWS KMS and GCP Cloud KMS keep master private keys inside remote cloud KMS during signing.
- Pure Consensus Reducer: A verified in-memory state machine reducer handles 11 action types, single-slot idempotency, atomic epoch transitions, and monotonic indexing (Milestone 13-D Stage 2-B.1).
- Durable Witness: PostgreSQL schemas and single-node etcd integration provide historical event tracking."*

### Slide 7: Security & Validation — 806 Passing Tests Across 39 Files (5:50 – 6:50)
*"Security requires rigorous, empirical proof. In our latest accepted milestone (13-D Stage 2-B.1.1), Web3User achieved a 100% pass rate in repository regression testing: exactly 806 tests passing across 39 test files with zero failures.
This includes:
- Multi-process OS concurrency tests using deterministic IPC rendezvous barriers, demonstrating that concurrent attempts to consume the same authorization result in exactly one ALLOW and deterministic DENYs.
- Process-crash recovery tests confirming automatic SQLite WAL rollback upon uncommitted worker termination.
- Milestone FN-SEC-01 Steps 1–4 independently audited and accepted, validating AWS and GCP Cloud KMS signer adapters against mock service contracts matching cloud API specifications.
- Milestone 13-D Stage 2-B.1 pure consensus reducer independently audited and accepted."*

### Slide 8: Market Opportunity & Target Customer Segments (6:50 – 7:45)
*"Rather than using speculative top-down cybersecurity figures, we ground our market sizing in a transparent bottom-up developer model.
Based on the Electric Capital baseline of ~50,000 active developers, we assume an eligible subset of approximately 50%—or ~25,000 developers—working on transaction infrastructure, autonomous agents, payment rails, and wallet services. Assuming average team sizes of 5 to 7 developers, this yields an estimated addressable population of approximately 3,500 to 5,000 active protocol, dApp, and fintech engineering teams globally.
We focus on four key customer segments:
1. Web3 Fintechs & Payment Gateways needing corporate spending ceilings and compliance destination whitelists.
2. Autonomous AI Agents executing on-chain trading and gameplay within bounded allowances.
3. Institutional Treasuries and DAOs automating daily operational disbursements without paying gas on multisig transactions.
4. Account Abstraction Builders implementing ERC-4337 and ERC-7579 modular session keys.
At an illustrative blended ACV hypothesis of $6,000/year across tiers, the ~3,500 teams represent a $21 Million annual addressable niche opportunity.
As unvalidated operating hypotheses, our customer mix models:
- Phase 1 (50 to 122 teams): 35 Tier 1 ($1.2k), 14 Tier 2 ($6k), and 1 Tier 3 ($25k) yielding $151,000 ARR, scaling to $600,000 ARR at 122 teams.
- Phase 2 (300 to 500 teams): 180 Tier 1, 100 Tier 2, and 20 Tier 3 yielding $1.32 Million ARR, scaling to $2.42 Million ARR at 500 teams."*

### Slide 9: Business Model & Monetization Strategy (7:45 – 8:35)
*"We deploy an open-core developer distribution model:
- Open-Core Community Edition (Implemented): Free, open-source Node.js SDK with local SQLite persistence for grassroots adoption by indie developers and hackathon projects.
- Enterprise Developer License (Proposed Roadmap): Tiered annual subscription ($1,200/yr for Developer, $6,000/yr for Growth) providing Cloud KMS adapters, distributed consensus persistence, and commercial SLAs.
- Managed Witness & Audit Cloud (Proposed Roadmap): Hosted SaaS API providing cryptographic receipt recording and verifiable compliance dashboards.
- Enterprise Integration & DSL Consulting (Proposed Roadmap): Tailored policy rules and dedicated HSM provisioning for regulated financial institutions."*

### Slide 10: Competition & Objective Positioning (8:35 – 9:25)
*"We maintain objective positioning against alternatives based on published documentation:
- Full-stack custody platforms like Fireblocks provide institutional MPC custody, starting with a free developer sandbox, an Essentials plan at $999/month for up to $1M quarterly volume, and custom enterprise contracts. In contrast, Web3User is an embeddable Node.js SDK enabling developers to enforce pre-signing policies inside their own runtimes using their own Cloud KMS keys.
- On-chain multisigs like Safe are designed for cold storage treasury governance, but requiring an on-chain multisig transaction for every routine automated action incurs gas costs and block latency. Web3User provides in-process off-chain policy evaluation that can serve as a complementary guard before submitting transactions to Safe.
- Embedded wallet platforms like Turnkey offer hosted cloud enclave APIs, whereas Web3User provides an embeddable, self-hosted library where developers own local SQLite/PostgreSQL persistence.
Web3User is uniquely an open-core, developer-first SDK that embeds directly into Node.js, connects to developer-owned Cloud KMS keys, and provides verifiable policy governance."*

### Slide 11: Founder & Milestone-Based Roadmap (9:25 – 10:15)
*"I am Syed Shahed, solo founder of Syed's Enterprises. I have architected and implemented Web3User from its initial policy evaluator to hardware Cloud KMS signing adapters and consensus state reducers.
Our upcoming roadmap is strictly milestone-driven:
- Completed & Verified: Milestones 0 through 13-C.1, FN-SEC-01 (AWS/GCP KMS adapters verified in CI via mock contracts), and 13-D Stage 2-B.1 (In-Memory Consensus Reducer).
- Q1 2027: Stage 2-B.2 Consensus Persistence, etcd watch backpressure, and historical compaction.
- Q2 2027: Stage 3-A Distributed Multi-Node Raft Consensus Cluster.
- Q3 2027: Independent Commercial Security Audit and v1.0.0 Stable Production Release.
- Q4 2027: Multi-Chain Expansion and native ERC-4337 / ERC-7579 modules."*

### Slide 12: Funding Opportunity & Use of Funds (10:15 – 11:00)
*"With support from the .TECH funding program, proposed allocation of received grant funds:
- 40% for an Independent Commercial Security Audit by a premier cryptographic security firm.
- 25% for Dedicated Cloud Infrastructure (multi-region AWS/GCP hardware HSM testbeds and distributed etcd benchmark clusters).
- 20% for Developer Documentation, Quickstarts, and integrations for viem, ethers.js, and wagmi.
- 15% for Open-Source Developer Grants and hackathon bounties.
Thank you for your time and consideration. Explore our live interactive playground at web3user.tech or reach out to me directly at info@syedsenterprises.org."*

---

## Part 2: 2–3 Minute Founder Demonstration Video Script

**Title:** Web3User Permission Lab — 2.5-Minute Founder Overview & Live Demo  
**Speaker:** Syed Shahed, Founder & Lead Architect  
**Entity:** Syed's Enterprises (Solo Venture &middot; [syedsenterprises.org](https://syedsenterprises.org/))  
**Setting:** Split-screen format (Founder video in corner + crisp browser screen recording of `web3user.tech`).

---

### [0:00 – 0:35] Introduction & The Core Problem
**Visual:** Founder on camera, transitioning to `web3user.tech` hero section.  
**On-Screen Text:** *Syed Shahed &middot; Founder, Syed's Enterprises &middot; Web3User Permission Lab*  
**Founder Voiceover:**
> *"Hi, I'm Syed Shahed, founder of Syed's Enterprises. In Web3 today, security is failing predominantly at the infrastructure and control-plane layer.
> 
> According to TRM Labs, out of $2.87 Billion stolen across hacks and exploits in 2025, over 76%—or $2.2 Billion—resulted from infrastructure attacks: private key theft, seed phrase compromises, API key leaks, and access control breaches, far exceeding smart contract coding bugs within hacks. Furthermore, Chainalysis reported that total crypto theft surpassed $3.4 Billion in 2025 across all vectors, with over 158,000 individual wallet compromises.
> 
> The problem is that private keys convey absolute, all-or-nothing power. If an automated bot, API credential, or operational worker is compromised, an attacker can transfer all funds immediately. Web3User Permission Lab solves this with an off-chain transaction authorization engine that enforces strict, deterministic policy guardrails before any key signs."*

---

### [0:35 – 1:35] Live Interactive Playground Demonstration
**Visual:** Screen recording smoothly scrolling down to `#demo` (Interactive Policy Evaluator Playground).  
**Founder Voiceover:**
> *"Let's see this in action on our live production website at web3user.tech.
> 
> Here in our interactive playground, the evaluation engine runs pure TypeScript logic directly in the browser.
> 
> Let's look at Scenario 1: A compliant ERC-20 transfer. The target token address matches our whitelist, the recipient is authorized, the transfer amount of 250 USDC is below our 500 USDC per-action cap, and the timestamp is valid. When we evaluate, Web3User returns an immediate ALLOW decision, with full calldata ABI decoding and verified rule checks.
> 
> Now, let's switch to Scenario 2: Limit Exceeded. Here, the caller attempts to transfer 1,000 USDC—exceeding our 500 USDC ceiling. Immediately, the engine rejects the transaction with a deterministic DENY decision, pinpointing the exact rule violation.
> 
> We have 9 built-in presets testing expired deadlines, unapproved contracts, calldata tampering, and cumulative budget exhaustion across hourly and daily windows."*

---

### [1:35 – 2:15] Architecture & Empirical Test Validation
**Visual:** Quick cut to architecture diagram and terminal running the test suite.  
**Founder Voiceover:**
> *"Under the hood, Web3User is built for high-concurrency production:
> - It uses SQLite WAL mode with immediate locking to ensure single-use replay protection.
> - Monotonic clock guards prevent backward system clock adjustments.
> - Cloud KMS adapters for AWS and Google Cloud keep private keys inside remote cloud KMS during signing.
> - An independently audited in-memory consensus reducer tracks state transitions monotonically.
> 
> We back this up with empirical engineering rigor: exactly 806 tests passing across 39 test files in repository regression testing, including multi-process race testing and process-crash recovery."*

---

### [2:15 – 2:35] The .TECH Funding Opportunity & Close
**Visual:** Return to founder on camera with `web3user.tech` and contact details on screen.  
**Founder Voiceover:**
> *"With support from the .TECH funding program, our proposed allocation will fund an independent commercial security audit, provision dedicated AWS and GCP hardware HSM testbeds, and expand developer tooling and community grants.
> 
> Web3User bridges the gap between high-risk transaction generation and cryptographic execution. Visit web3user.tech to try the interactive evaluator today, or contact me at info@syedsenterprises.org. Thank you."*
