# Initial architecture decisions

1. Local-first: no backend, database, wallet connection, or chain deployment in milestone one.
2. Deterministic core: no AI calls or network requests inside the evaluator.
3. Fail closed: missing/malformed required inputs return UNKNOWN; explicit policy violations return DENY.
4. Simulator is not enforcement: an off-chain result cannot stop a transaction.
5. No personal data onchain; if a registry is justified later, begin with minimal hashes and lifecycle events.
6. No token in MVP.
7. Bound authorization artifacts: use versioned, deterministic length-prefixed canonical encoding and SHA-256 binding digests with an additive SQLite issued -> consumed state transition to protect against parameter tampering and replay without requiring in-memory state.
