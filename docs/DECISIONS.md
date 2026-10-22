# Initial architecture decisions

1. Local-first: no backend, database, wallet connection, or chain deployment in milestone one.
2. Deterministic core: no AI calls or network requests inside the evaluator.
3. Fail closed: missing/malformed required inputs return UNKNOWN; explicit policy violations return DENY.
4. Simulator is not enforcement: an off-chain result cannot stop a transaction.
5. No personal data onchain; if a registry is justified later, begin with minimal hashes and lifecycle events.
6. No token in MVP.
7. Bound authorization artifacts: use versioned, deterministic length-prefixed canonical encoding and SHA-256 binding digests with an additive SQLite issued -> consumed state transition to protect against parameter tampering and replay without requiring in-memory state.
8. Ed25519 issuer authenticity: Signed authorization artifacts (version 2) cryptographically bind artifact version, authorization ID, issuer key ID, and binding digest using Ed25519 digital signatures (`node:crypto`) and length-prefixed canonical encoding. Verification strictly occurs before SQLite state transitions, ensuring forged or tampered artifacts fail closed without modifying storage.
9. Artifact version discriminator in persistent store: SQLite authorization store enforces an explicit `artifact_version` column (`NOT NULL DEFAULT 1`). V1 consumption matches `artifact_version = 1`, and signed V2 consumption matches `artifact_version = 2` inside the atomic `UPDATE` query. This guarantees cross-version isolation, ensuring unsigned V1 artifacts cannot consume V2-issued authorizations.
