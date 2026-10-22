# Web3User Permission Lab

Early-stage starter scaffold for the Web3User Protocol MVP.

## Status
Local-first prototype scaffold only. It is not deployed, audited, or an onchain enforcement mechanism.

## Requirements
- Node.js 22.13.0 or later. The persistent SQLite store uses the built-in `node:sqlite` module, which was added in Node.js 22.5.0 and is available without an experimental flag starting in 22.13.0.
- npm

## Run
```bash
npm install
npm test
npm run demo:persistent-replay
```

## Persistent replay demonstration

The demo uses a fixed local policy, transfer request, trusted demonstration time, and authorization ID. It runs the existing authorization checks and reserves the ID in SQLite. The first run prints `Decision: ALLOW`; subsequent runs against the same database print `Decision: DENY` with the duplicate-ID reason. A denial is the expected successful replay-protection result.

The dedicated demo database is stored at `.demo-data/authorization-replay.sqlite` in the repository. It is separate from application data and is ignored by Git. To reset the demonstration, stop the process and remove the `.demo-data` directory, then run the command again. The demo never removes or resets this database automatically.

This is a local authorization demonstration only. An `ALLOW` result does not mean a transaction was signed, submitted, or executed. The demo does not connect to a wallet, interact with a blockchain, move funds, or provide a production deployment.

## Scope
Deterministic demo checks for an allowlisted target and function selector, maximum amount, validity window, revocation, and unknown inputs.

## Safety
This is an off-chain simulator. It does not block or authorize blockchain transactions. Do not connect real funds or use it as a security control.
