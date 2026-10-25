# Security Policy

## Scope and Prototype Status

Web3User Permission Lab is a development-stage off-chain transaction authorization and policy evaluation engine. It validates candidate transaction parameters against declarative rules before actions proceed off-chain.

**Important:** Web3User is an off-chain decision engine, not an on-chain smart contract, blockchain validator, or transaction broadcaster. An `ALLOW` decision indicates off-chain policy compliance and records an atomic single-use reservation in SQLite; it does not constitute blockchain execution or funds movement.

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
