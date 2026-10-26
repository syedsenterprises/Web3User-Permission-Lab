# Security Policy

## Scope and Prototype Status

Web3User Permission Lab is a development-stage off-chain transaction authorization and policy evaluation engine. It validates candidate transaction parameters against declarative rules before actions proceed off-chain.

**Important Architectural Boundaries:**
- **Off-Chain Decision Engine**: Web3User is an off-chain decision engine, not an on-chain smart contract, blockchain validator, or transaction broadcaster. An `ALLOW` decision indicates off-chain policy compliance and records an atomic single-use reservation in SQLite; it does not constitute blockchain execution or funds movement.
- **Dual-Key Architecture**: Ed25519 issuer keys are used within the SDK to authenticate off-chain authorization tokens. The SDK never handles, stores, or accesses Ethereum wallet private keys (secp256k1).
- **Per-Action Ceilings & Stateful Cumulative Budgets**: `maxAmount` defines an inclusive per-action ceiling for any single transaction. In addition, policies can configure an optional cumulative spending budget (`budget: { window: "HOURLY" | "DAILY", maxCumulativeAmount: string }`). When configured, cumulative spending is tracked and enforced atomically inside the SQLite write lock during consumption. If an authorization would exceed the cumulative limit in the active window, it is denied (`DENY`), leaves the authorization in state `issued`, and allows safe retries once the budget window rolls over. For unbudgeted policies, `maxAmount` bounds each individual action without aggregate limits across multiple transactions.
- **Durable Consumption & No Automatic Reversal**: Authorization consumption is durable and permanent in SQLite (`state = 'consumed'`). If the subsequent downstream blockchain transaction fails to broadcast, reverts on-chain, or is dropped from the mempool, Web3User does **not** automatically roll back, restore, or reverse the consumed authorization. Integrating relayers must manage broadcast failures by requesting a fresh authorization under a new authorization ID.

## Operational & Storage Requirements

- **Local Block Storage Requirement (No Network Filesystems)**: The persistent SQLite store operates in Write-Ahead Logging (WAL) mode (`PRAGMA journal_mode = WAL;`), which requires POSIX advisory byte-range file locking and shared memory (`-shm`). Network-mounted filesystems—including NFS, SMB/CIFS, AWS EFS, Azure Files, and GlusterFS—are strictly unsupported. Network storage protocols frequently implement buggy, high-latency, or desynchronized file locking and lack coherent shared memory across nodes, creating severe hazards of database corruption, deadlock, and silent lost updates under multi-process concurrency. The database file must reside on directly attached local block storage (such as local NVMe/SSD or dedicated cloud block storage like AWS EBS or GCP Persistent Disk mounted locally).
- **Host Clock Synchronization for Multi-Process Deployments**: When multiple worker processes share an SQLite database, `ClockGuard` rejects any candidate timestamp that precedes the shared SQLite `high_water_seconds` (`Clock rollback detected`). Host servers should run continuous, active NTP daemons (such as `chrony` or `systemd-timesyncd`). While minimizing drift (e.g. keeping clock drift within an operational target of ~100 ms) reduces the frequency of spurious rollback denials between workers, no sub-second offset (such as 50 ms or 100 ms) constitutes a universally guaranteed safe threshold against rollback rejections under all workloads, because wall clock observations operate in integer seconds and race conditions depend on worker scheduling, latency, and interleaving.

## Supported Versions

Security updates and vulnerability triage are applied to the active development branch and latest release candidate:

| Version | Supported |
| :--- | :---: |
| `0.1.0-rc.1` (and subsequent release candidates) | :white_check_mark: |
| `main` branch | :white_check_mark: |
| Older prototyping snapshots | :x: |

## Reporting a Vulnerability

We appreciate the responsible disclosure of security vulnerabilities by researchers and contributors.

If you believe you have found a security vulnerability in Web3User Permission Lab (such as authorization bypasses, replay protection failures, cryptographic flaws, or unexpected fail-open behaviors):

1. **Do NOT report security vulnerabilities through public GitHub issues, discussions, or pull requests.**
2. **Submit via GitHub Security Advisories:** If GitHub Private Vulnerability Reporting is enabled for this repository, please report it privately via [GitHub Security Advisories](https://github.com/syedsenterprises/Web3User-Permission-Lab/security/advisories/new).
3. **Alternative Channel:** If private reporting is unavailable on GitHub, contact the repository maintainer directly through their GitHub profile at [https://github.com/syedsenterprises](https://github.com/syedsenterprises).

### What to Include

Please provide:
- A clear description of the vulnerability and its potential impact.
- Exact steps to reproduce the issue, including minimal reproduction scripts or tests.
- Details of the runtime environment (Node.js version, operating system).
- Any proposed remediation or patch, if available.

### Response and Remediation

The maintainer will review submitted reports, work to verify and resolve confirmed vulnerabilities, and coordinate disclosure timelines. Please allow reasonable time for investigation before any public disclosure.
