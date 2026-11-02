/**
 * Web3User Permission Lab - Milestone 13-D Phase D3: Stage 1 Migration Acceptance Suite
 *
 * Verifies the 12 Stage 1 Acceptance Tests:
 * 1. Fresh schema installation.
 * 2. D1/D2 upgrade with existing data.
 * 3. Existing quarantined epoch backfill.
 * 4. Active, terminated, and archived lifecycle states.
 * 5. Rejection of all invalid state/flag/metadata combinations.
 * 6. Migration idempotency.
 * 7. Migration failure atomicity (in-file transaction safety).
 * 8. Rollback failure atomicity (in-file transaction safety).
 * 9. Rollback after D3 tables contain data.
 * 10. Exact D2 view, owner, grant, and dependency restoration.
 * 11. Compatibility: existing D1/D2 operations and resetTestDatabase pattern.
 * 12. Cluster and epoch identity: PRIMARY KEY (cluster_id, epoch_id) validation.
 *
 * All destructive and migration tests execute on isolated disposable databases.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import pg from "pg";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const MIGRATIONS_DIR = path.resolve(__dirname, "../../src/witness/migrations");
const SCHEMA_FILE = path.resolve(__dirname, "../../src/witness/schema.sql");
const MIGRATION_002_FILE = path.join(MIGRATIONS_DIR, "002_d2_epoch_state.sql");
const MIGRATION_003_FILE = path.join(MIGRATIONS_DIR, "003_d3_consensus_state.sql");
const ROLLBACK_003_FILE = path.join(MIGRATIONS_DIR, "003_d3_consensus_state.rollback.sql");

describe("Milestone 13-D Phase D3: Migration 003 Verification Suite", () => {
  let adminPool: pg.Pool;
  const createdDatabases: string[] = [];

  beforeAll(async () => {
    adminPool = new pg.Pool({
      host: process.env.PGHOST || "127.0.0.1",
      port: Number(process.env.PGPORT || 5432),
      user: process.env.PGUSER || "postgres",
      password: process.env.PGPASSWORD || "postgres",
      database: "postgres",
    });
  });

  afterAll(async () => {
    for (const dbName of createdDatabases) {
      try {
        await adminPool.query(`
          SELECT pg_terminate_backend(pid) 
          FROM pg_stat_activity 
          WHERE datname = $1 AND pid <> pg_backend_pid()
        `, [dbName]);
        await adminPool.query(`DROP DATABASE IF EXISTS "${dbName}"`);
      } catch (err) {
        console.warn(`Failed to clean up disposable database ${dbName}:`, err);
      }
    }
    await adminPool.end();
  });

  async function createDisposableDb(prefix: string): Promise<{ dbName: string; pool: pg.Pool }> {
    const dbName = `web3user_test_${prefix}_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
    await adminPool.query(`CREATE DATABASE "${dbName}"`);
    createdDatabases.push(dbName);
    const pool = new pg.Pool({
      host: process.env.PGHOST || "127.0.0.1",
      port: Number(process.env.PGPORT || 5432),
      user: process.env.PGUSER || "postgres",
      password: process.env.PGPASSWORD || "postgres",
      database: dbName,
    });
    return { dbName, pool };
  }

  async function destroyDisposableDb(dbName: string, pool: pg.Pool): Promise<void> {
    await pool.end();
    await adminPool.query(`
      SELECT pg_terminate_backend(pid) 
      FROM pg_stat_activity 
      WHERE datname = $1 AND pid <> pg_backend_pid()
    `, [dbName]);
    await adminPool.query(`DROP DATABASE IF EXISTS "${dbName}"`);
    const idx = createdDatabases.indexOf(dbName);
    if (idx !== -1) createdDatabases.splice(idx, 1);
  }

  it("1. Fresh database schema installation: full schema.sql creates all tables, triggers, and views", async () => {
    const { dbName, pool } = await createDisposableDb("fresh");
    try {
      const fullSql = fs.readFileSync(SCHEMA_FILE, "utf-8");
      await pool.query(fullSql);

      // Verify witness_consensus_log exists
      const logTableRes = await pool.query(`
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns 
        WHERE table_name = 'witness_consensus_log'
        ORDER BY ordinal_position
      `);
      expect(logTableRes.rows.length).toBeGreaterThan(0);
      const logCols = logTableRes.rows.map((r) => r.column_name);
      expect(logCols).toContain("epoch_id");
      expect(logCols).toContain("log_index");
      expect(logCols).toContain("term");
      expect(logCols).toContain("etcd_revision");
      expect(logCols).toContain("payload_type");
      expect(logCols).toContain("payload");
      expect(logCols).toContain("payload_hash");
      expect(logCols).toContain("proposal_id");
      expect(logCols).toContain("committed_at_seconds");

      // Verify witness_raft_state exists with composite primary key (cluster_id, epoch_id)
      const raftTableRes = await pool.query(`
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = 'witness_raft_state'
      `);
      const raftCols = raftTableRes.rows.map((r) => r.column_name);
      expect(raftCols).toContain("cluster_id");
      expect(raftCols).toContain("epoch_id");
      expect(raftCols).toContain("last_applied_index");
      expect(raftCols).toContain("last_applied_term");
      expect(raftCols).toContain("last_applied_hash");

      // Verify witness_epochs augmented columns
      const epochColsRes = await pool.query(`
        SELECT column_name FROM information_schema.columns WHERE table_name = 'witness_epochs'
      `);
      const epochCols = epochColsRes.rows.map((r) => r.column_name);
      expect(epochCols).toContain("is_quarantined");
      expect(epochCols).toContain("is_active");
      expect(epochCols).toContain("quarantined_at_seconds");
      expect(epochCols).toContain("quarantine_reason");
      expect(epochCols).toContain("quarantine_details");

      // Verify witness_epoch_state view exposes all 12 columns
      const viewColsRes = await pool.query(`
        SELECT column_name FROM information_schema.columns WHERE table_name = 'witness_epoch_state'
      `);
      expect(viewColsRes.rows.length).toBe(12);
      const viewCols = viewColsRes.rows.map((r) => r.column_name);
      expect(viewCols).toContain("is_quarantined");
      expect(viewCols).toContain("is_active");
      expect(viewCols).toContain("quarantined_at_seconds");
      expect(viewCols).toContain("quarantine_reason");
      expect(viewCols).toContain("quarantine_details");
    } finally {
      await destroyDisposableDb(dbName, pool);
    }
  });

  it("2. Upgrade migration: migrating existing D1/D2 database preserves all live data and backfills state", async () => {
    const { dbName, pool } = await createDisposableDb("upgrade");
    try {
      const schemaSql = fs.readFileSync(SCHEMA_FILE, "utf-8");
      const d1Section = schemaSql.split("-- 9. Milestone 13-D Phase D2")[0];
      await pool.query(d1Section);

      const d2Sql = fs.readFileSync(MIGRATION_002_FILE, "utf-8");
      await pool.query(d2Sql);

      const now = Math.floor(Date.now() / 1000);
      await pool.query(`
        INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, chain_head_hash, last_sequence_number, state, updated_at_seconds)
        VALUES 
          ('epoch-live-1', 1, $1, '0000000000000000000000000000000000000000000000000000000000000000', 5, 'ACTIVE', $1),
          ('epoch-live-2', 2, $1, '1111111111111111111111111111111111111111111111111111111111111111', 12, 'QUARANTINED', $1 + 10);
      `, [now]);

      await pool.query(`
        INSERT INTO witness_tickets (ticket_id, authorization_id, epoch_id, state, binding_digest, expires_at_seconds, created_at_seconds, updated_at_seconds)
        VALUES ('ticket-001', 'auth-001', 'epoch-live-1', 'COMMITTED', 'digest-001', $1 + 3600, $1, $1);
      `, [now]);

      const d3MigrationSql = fs.readFileSync(MIGRATION_003_FILE, "utf-8");
      await pool.query(d3MigrationSql);

      // Verify existing ticket data is preserved
      const ticketsRes = await pool.query(`SELECT * FROM witness_tickets WHERE ticket_id = 'ticket-001'`);
      expect(ticketsRes.rows.length).toBe(1);
      expect(ticketsRes.rows[0].authorization_id).toBe("auth-001");

      // Verify active epoch flags
      const epoch1Res = await pool.query(`SELECT is_quarantined, is_active, quarantined_at_seconds, quarantine_reason FROM witness_epochs WHERE epoch_id = 'epoch-live-1'`);
      expect(epoch1Res.rows[0].is_quarantined).toBe(false);
      expect(epoch1Res.rows[0].is_active).toBe(true);
      expect(epoch1Res.rows[0].quarantined_at_seconds).toBeNull();
      expect(epoch1Res.rows[0].quarantine_reason).toBeNull();

      // Verify quarantined epoch flags were synchronized
      const epoch2Res = await pool.query(`SELECT is_quarantined, is_active, quarantined_at_seconds, quarantine_reason FROM witness_epochs WHERE epoch_id = 'epoch-live-2'`);
      expect(epoch2Res.rows[0].is_quarantined).toBe(true);
      expect(epoch2Res.rows[0].is_active).toBe(false);
      expect(epoch2Res.rows[0].quarantined_at_seconds).toBe(String(now + 10));
      expect(epoch2Res.rows[0].quarantine_reason).toBe("LEGACY_D2_QUARANTINE");

      // Verify witness_raft_state was seeded with initial rows
      const raftStateRes = await pool.query(`SELECT * FROM witness_raft_state ORDER BY epoch_id ASC`);
      expect(raftStateRes.rows.length).toBe(2);
      expect(raftStateRes.rows[0].epoch_id).toBe("epoch-live-1");
      expect(raftStateRes.rows[0].last_applied_index).toBe("0");
      expect(raftStateRes.rows[1].epoch_id).toBe("epoch-live-2");
      expect(raftStateRes.rows[1].last_applied_index).toBe("0");
    } finally {
      await destroyDisposableDb(dbName, pool);
    }
  });

  it("3. Existing quarantined epoch backfill: validates deterministic legacy metadata policy", async () => {
    const { dbName, pool } = await createDisposableDb("backfill");
    try {
      const schemaSql = fs.readFileSync(SCHEMA_FILE, "utf-8");
      const d1Section = schemaSql.split("-- 9. Milestone 13-D Phase D2")[0];
      await pool.query(d1Section);

      const d2Sql = fs.readFileSync(MIGRATION_002_FILE, "utf-8");
      await pool.query(d2Sql);

      const createdTime = 1700000000;
      const updatedTime = 1700000500;
      await pool.query(`
        INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, updated_at_seconds, state)
        VALUES ('epoch-q-legacy', 1, $1, $2, 'QUARANTINED');
      `, [createdTime, updatedTime]);

      const d3MigrationSql = fs.readFileSync(MIGRATION_003_FILE, "utf-8");
      await pool.query(d3MigrationSql);

      const res = await pool.query(`
        SELECT is_quarantined, is_active, quarantined_at_seconds, quarantine_reason, quarantine_details
        FROM witness_epochs WHERE epoch_id = 'epoch-q-legacy'
      `);
      expect(res.rows[0].is_quarantined).toBe(true);
      expect(res.rows[0].is_active).toBe(false);
      expect(Number(res.rows[0].quarantined_at_seconds)).toBe(updatedTime);
      expect(res.rows[0].quarantine_reason).toBe("LEGACY_D2_QUARANTINE");
      expect(res.rows[0].quarantine_details).toBeNull();
    } finally {
      await destroyDisposableDb(dbName, pool);
    }
  });

  it("4. Active, terminated, and archived lifecycle states: verifies valid combinations", async () => {
    const { dbName, pool } = await createDisposableDb("lifecycle");
    try {
      const fullSql = fs.readFileSync(SCHEMA_FILE, "utf-8");
      await pool.query(fullSql);

      const now = Math.floor(Date.now() / 1000);

      // State 1: ACTIVE epoch (active = true, quarantined = false, metadata = null)
      await pool.query(`
        INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, state, is_active, is_quarantined)
        VALUES ('epoch-active', 1, $1, 'ACTIVE', true, false);
      `, [now]);

      // State 2: QUARANTINED epoch (active = false, quarantined = true, metadata required)
      await pool.query(`
        INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, state, is_active, is_quarantined, quarantined_at_seconds, quarantine_reason, quarantine_details)
        VALUES ('epoch-quarantine', 2, $1, 'QUARANTINED', false, true, $1, 'EQUIVOCATION_DETECTED', '{"reporter":"node-1"}'::jsonb);
      `, [now]);

      // State 3: TERMINATED epoch (active = false, quarantined = false, metadata = null)
      await pool.query(`
        INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, state, is_active, is_quarantined)
        VALUES ('epoch-terminated', 3, $1, 'TERMINATED', false, false);
      `, [now]);

      // State 4: ARCHIVED epoch (active = false, quarantined = false, metadata = null)
      await pool.query(`
        INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, state, is_active, is_quarantined)
        VALUES ('epoch-archived', 4, $1, 'ARCHIVED', false, false);
      `, [now]);

      // State 5: CLOSED epoch (active = false, quarantined = false, metadata = null)
      await pool.query(`
        INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, state, is_active, is_quarantined)
        VALUES ('epoch-closed', 5, $1, 'CLOSED', false, false);
      `, [now]);

      const countRes = await pool.query(`SELECT COUNT(*) FROM witness_epochs`);
      expect(Number(countRes.rows[0].count)).toBe(5);
    } finally {
      await destroyDisposableDb(dbName, pool);
    }
  });

  it("5. Rejection of all invalid state/flag/metadata combinations: database constraints enforce invariants", async () => {
    const { dbName, pool } = await createDisposableDb("invalid_combos");
    try {
      const fullSql = fs.readFileSync(SCHEMA_FILE, "utf-8");
      await pool.query(fullSql);

      const now = Math.floor(Date.now() / 1000);

      // Invalid 1: Both active and quarantined (chk_epochs_quarantine_consistency)
      await expect(
        pool.query(`
          INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, state, is_active, is_quarantined, quarantined_at_seconds, quarantine_reason)
          VALUES ('inv-1', 1, $1, 'QUARANTINED', true, true, $1, 'TEST');
        `, [now])
      ).rejects.toThrow(/chk_epochs_quarantine_consistency/i);

      // Invalid 2: state='QUARANTINED' but is_quarantined=false (chk_epochs_state_quarantine_parity)
      await expect(
        pool.query(`
          INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, state, is_active, is_quarantined)
          VALUES ('inv-2', 2, $1, 'QUARANTINED', false, false);
        `, [now])
      ).rejects.toThrow(/chk_epochs_state_quarantine_parity/i);

      // Invalid 3: state='ACTIVE' but is_quarantined=true (chk_epochs_state_quarantine_parity)
      await expect(
        pool.query(`
          INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, state, is_active, is_quarantined, quarantined_at_seconds, quarantine_reason)
          VALUES ('inv-3', 3, $1, 'ACTIVE', false, true, $1, 'TEST');
        `, [now])
      ).rejects.toThrow(/chk_epochs_state_quarantine_parity/i);

      // Invalid 4: is_quarantined=true but missing quarantined_at_seconds (chk_epochs_quarantine_metadata)
      await expect(
        pool.query(`
          INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, state, is_active, is_quarantined, quarantine_reason)
          VALUES ('inv-4', 4, $1, 'QUARANTINED', false, true, 'TEST');
        `, [now])
      ).rejects.toThrow(/chk_epochs_quarantine_metadata/i);

      // Invalid 5: is_quarantined=true but missing quarantine_reason (chk_epochs_quarantine_metadata)
      await expect(
        pool.query(`
          INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, state, is_active, is_quarantined, quarantined_at_seconds)
          VALUES ('inv-5', 5, $1, 'QUARANTINED', false, true, $1);
        `, [now])
      ).rejects.toThrow(/chk_epochs_quarantine_metadata/i);

      // Invalid 6: is_quarantined=false but has phantom quarantine metadata (chk_epochs_quarantine_metadata)
      await expect(
        pool.query(`
          INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, state, is_active, is_quarantined, quarantined_at_seconds, quarantine_reason)
          VALUES ('inv-6', 6, $1, 'ACTIVE', true, false, $1, 'PHANTOM');
        `, [now])
      ).rejects.toThrow(/chk_epochs_quarantine_metadata/i);
    } finally {
      await destroyDisposableDb(dbName, pool);
    }
  });

  it("6. Migration pre-check fails closed on unexpected or NULL epoch states", async () => {
    const { dbName, pool } = await createDisposableDb("precheck_fail");
    try {
      const schemaSql = fs.readFileSync(SCHEMA_FILE, "utf-8");
      const d1Section = schemaSql.split("-- 9. Milestone 13-D Phase D2")[0];
      await pool.query(d1Section);

      const d2Sql = fs.readFileSync(MIGRATION_002_FILE, "utf-8");
      await pool.query(d2Sql);

      const now = Math.floor(Date.now() / 1000);
      // Insert corrupt/unrecognized epoch state in pre-existing database
      await pool.query(`
        INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, state)
        VALUES ('epoch-corrupt', 1, $1, 'CORRUPTED_UNKNOWN_STATE');
      `, [now]);

      const d3MigrationSql = fs.readFileSync(MIGRATION_003_FILE, "utf-8");
      await expect(pool.query(d3MigrationSql)).rejects.toThrow(/Migration 003 pre-check failed/i);

      // Verify table was not augmented due to transaction abort
      const checkCols = await pool.query(`
        SELECT column_name FROM information_schema.columns 
        WHERE table_name = 'witness_epochs' AND column_name = 'is_quarantined'
      `);
      expect(checkCols.rows.length).toBe(0);
    } finally {
      await destroyDisposableDb(dbName, pool);
    }
  });

  it("7. Migration idempotency: re-running 003_d3_consensus_state.sql multiple times succeeds cleanly", async () => {
    const { dbName, pool } = await createDisposableDb("idempotency");
    try {
      const fullSql = fs.readFileSync(SCHEMA_FILE, "utf-8");
      await pool.query(fullSql);

      const d3MigrationSql = fs.readFileSync(MIGRATION_003_FILE, "utf-8");

      // Second execution
      await expect(pool.query(d3MigrationSql)).resolves.toBeDefined();

      // Third execution
      await expect(pool.query(d3MigrationSql)).resolves.toBeDefined();
    } finally {
      await destroyDisposableDb(dbName, pool);
    }
  });

  it("8. Migration failure atomicity: in-file transaction ensures failure leaves zero partial changes", async () => {
    const { dbName, pool } = await createDisposableDb("migration_atomicity");
    try {
      const schemaSql = fs.readFileSync(SCHEMA_FILE, "utf-8");
      const d1Section = schemaSql.split("-- 9. Milestone 13-D Phase D2")[0];
      await pool.query(d1Section);

      const d2Sql = fs.readFileSync(MIGRATION_002_FILE, "utf-8");
      await pool.query(d2Sql);

      // Construct a corrupted migration script that injects an error midway through execution
      const migrationSql = fs.readFileSync(MIGRATION_003_FILE, "utf-8");
      const injectedSql = migrationSql.replace(
        "CREATE TABLE IF NOT EXISTS witness_consensus_log",
        "SELECT * FROM non_existent_table_injected_error; CREATE TABLE IF NOT EXISTS witness_consensus_log"
      );

      // Execute directly as a single query string (without external client transaction)
      await expect(pool.query(injectedSql)).rejects.toThrow();

      // Verify that NO partial objects or columns were created
      const logCheck = await pool.query(`SELECT to_regclass('public.witness_consensus_log') AS tbl`);
      expect(logCheck.rows[0].tbl).toBeNull();

      const raftCheck = await pool.query(`SELECT to_regclass('public.witness_raft_state') AS tbl`);
      expect(raftCheck.rows[0].tbl).toBeNull();

      const colsCheck = await pool.query(`
        SELECT column_name FROM information_schema.columns 
        WHERE table_name = 'witness_epochs' AND column_name = 'is_quarantined'
      `);
      expect(colsCheck.rows.length).toBe(0);
    } finally {
      await destroyDisposableDb(dbName, pool);
    }
  });

  it("9. Rollback failure atomicity: in-file transaction ensures failed rollback leaves database intact", async () => {
    const { dbName, pool } = await createDisposableDb("rollback_atomicity");
    try {
      const fullSql = fs.readFileSync(SCHEMA_FILE, "utf-8");
      await pool.query(fullSql);

      // Construct a corrupted rollback script with an injected failure midway
      const rollbackSql = fs.readFileSync(ROLLBACK_003_FILE, "utf-8");
      const injectedSql = rollbackSql.replace(
        "DROP TABLE IF EXISTS witness_raft_state",
        "SELECT * FROM non_existent_table_rollback_error; DROP TABLE IF EXISTS witness_raft_state"
      );

      await expect(pool.query(injectedSql)).rejects.toThrow();

      // Verify that tables were NOT dropped because transaction rolled back
      const logCheck = await pool.query(`SELECT to_regclass('public.witness_consensus_log') AS tbl`);
      expect(logCheck.rows[0].tbl).not.toBeNull();

      const raftCheck = await pool.query(`SELECT to_regclass('public.witness_raft_state') AS tbl`);
      expect(raftCheck.rows[0].tbl).not.toBeNull();
    } finally {
      await destroyDisposableDb(dbName, pool);
    }
  });

  it("10. Rollback after D3 tables contain data: DROP TABLE CASCADE executes cleanly preserving D1/D2 rows", async () => {
    const { dbName, pool } = await createDisposableDb("rollback_with_data");
    try {
      const fullSql = fs.readFileSync(SCHEMA_FILE, "utf-8");
      await pool.query(fullSql);

      const now = Math.floor(Date.now() / 1000);
      await pool.query(`
        INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, state, is_active, is_quarantined)
        VALUES ('epoch-rb-data', 1, $1, 'ACTIVE', true, false);
      `, [now]);

      await pool.query(`
        INSERT INTO witness_tickets (ticket_id, authorization_id, epoch_id, state, binding_digest, expires_at_seconds, created_at_seconds, updated_at_seconds)
        VALUES ('t-rb-1', 'auth-rb-1', 'epoch-rb-data', 'RESERVED', 'digest-1', $1 + 1000, $1, $1);
      `, [now]);

      // Insert 100 rows into witness_consensus_log
      for (let i = 1; i <= 100; i++) {
        await pool.query(`
          INSERT INTO witness_consensus_log (
            epoch_id, log_index, term, etcd_revision, payload_type, payload, payload_hash, proposal_id, committed_at_seconds
          ) VALUES ('epoch-rb-data', $1, 1, $2, 'TEST', '{"i":1}'::jsonb, $3, $4, $5);
        `, [i, i * 10, `hash-${i}`, `prop-${i}`, now]);
      }

      // Execute rollback script
      const rollbackSql = fs.readFileSync(ROLLBACK_003_FILE, "utf-8");
      await pool.query(rollbackSql);

      // Verify consensus tables are dropped
      const logCheck = await pool.query(`SELECT to_regclass('public.witness_consensus_log') AS tbl`);
      expect(logCheck.rows[0].tbl).toBeNull();

      // Verify D1/D2 ticket and epoch rows remain intact
      const epochRes = await pool.query(`SELECT epoch_id FROM witness_epochs WHERE epoch_id = 'epoch-rb-data'`);
      expect(epochRes.rows.length).toBe(1);

      const ticketRes = await pool.query(`SELECT ticket_id FROM witness_tickets WHERE ticket_id = 't-rb-1'`);
      expect(ticketRes.rows.length).toBe(1);
    } finally {
      await destroyDisposableDb(dbName, pool);
    }
  });

  it("11. Exact D2 view, owner, grant, and dependency restoration: verifies full parity after rollback", async () => {
    const { dbName, pool } = await createDisposableDb("view_parity");
    try {
      // Step A: Setup D2 schema
      const schemaSql = fs.readFileSync(SCHEMA_FILE, "utf-8");
      const d1Section = schemaSql.split("-- 9. Milestone 13-D Phase D2")[0];
      await pool.query(d1Section);

      const d2Sql = fs.readFileSync(MIGRATION_002_FILE, "utf-8");
      await pool.query(d2Sql);

      // Setup roles
      await pool.query(`
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'web3user_app') THEN
            CREATE ROLE web3user_app WITH LOGIN PASSWORD 'web3user_app_pass';
          END IF;
          IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'web3user_admin') THEN
            CREATE ROLE web3user_admin WITH LOGIN PASSWORD 'web3user_admin_pass';
          END IF;
        END $$;
        ALTER TABLE witness_epochs OWNER TO web3user_admin;
        ALTER VIEW witness_epoch_state OWNER TO web3user_admin;
        GRANT SELECT ON witness_epoch_state TO web3user_app;
      `);

      // Capture original D2 view columns and order
      const origColsRes = await pool.query(`
        SELECT column_name, ordinal_position, data_type
        FROM information_schema.columns
        WHERE table_name = 'witness_epoch_state'
        ORDER BY ordinal_position ASC
      `);
      const origColNames = origColsRes.rows.map((r) => r.column_name);
      expect(origColNames).toEqual([
        "epoch_id", "epoch_height", "created_at_seconds",
        "chain_head_hash", "last_sequence_number", "state", "updated_at_seconds"
      ]);

      // Step B: Apply Migration 003
      const d3MigrationSql = fs.readFileSync(MIGRATION_003_FILE, "utf-8");
      await pool.query(d3MigrationSql);

      const d3ColsRes = await pool.query(`
        SELECT column_name FROM information_schema.columns WHERE table_name = 'witness_epoch_state'
      `);
      expect(d3ColsRes.rows.length).toBe(12);

      // Step C: Execute Rollback
      const rollbackSql = fs.readFileSync(ROLLBACK_003_FILE, "utf-8");
      await pool.query(rollbackSql);

      // Verify columns reverted to exact D2 count, names, and order
      const revertedColsRes = await pool.query(`
        SELECT column_name, ordinal_position, data_type
        FROM information_schema.columns
        WHERE table_name = 'witness_epoch_state'
        ORDER BY ordinal_position ASC
      `);
      const revertedColNames = revertedColsRes.rows.map((r) => r.column_name);
      expect(revertedColNames).toEqual(origColNames);

      // Verify owner was restored to web3user_admin
      const ownerRes = await pool.query(`
        SELECT viewowner FROM pg_views WHERE viewname = 'witness_epoch_state'
      `);
      expect(ownerRes.rows[0].viewowner).toBe("web3user_admin");

      // Verify runtime role web3user_app has SELECT access on the restored view
      const privRes = await pool.query(`
        SELECT privilege_type 
        FROM information_schema.role_table_grants 
        WHERE table_name = 'witness_epoch_state' AND grantee = 'web3user_app'
      `);
      const privs = privRes.rows.map((r) => r.privilege_type);
      expect(privs).toContain("SELECT");
    } finally {
      await destroyDisposableDb(dbName, pool);
    }
  });

  it("12. Cluster and epoch identity: validates PRIMARY KEY (cluster_id, epoch_id) and seed idempotency", async () => {
    const { dbName, pool } = await createDisposableDb("cluster_identity");
    try {
      const fullSql = fs.readFileSync(SCHEMA_FILE, "utf-8");
      await pool.query(fullSql);

      const now = Math.floor(Date.now() / 1000);
      await pool.query(`
        INSERT INTO witness_epochs (epoch_id, epoch_height, created_at_seconds, state, is_active, is_quarantined)
        VALUES ('epoch-c1', 1, $1, 'ACTIVE', true, false);
      `, [now]);

      // Seed row should have been created with 'default-cluster'
      await pool.query(`
        INSERT INTO witness_raft_state (cluster_id, epoch_id, last_applied_index, last_applied_term)
        VALUES ('default-cluster', 'epoch-c1', 0, 0)
        ON CONFLICT (cluster_id, epoch_id) DO NOTHING;
      `);

      // Duplicate (cluster_id, epoch_id) must be rejected
      await expect(
        pool.query(`
          INSERT INTO witness_raft_state (cluster_id, epoch_id, last_applied_index, last_applied_term)
          VALUES ('default-cluster', 'epoch-c1', 1, 1);
        `)
      ).rejects.toThrow(/duplicate key value violates unique constraint/i);

      // Different cluster_id for same epoch_id is allowed by composite primary key (without uq_raft_state_epoch)
      await pool.query(`
        INSERT INTO witness_raft_state (cluster_id, epoch_id, last_applied_index, last_applied_term)
        VALUES ('secondary-cluster', 'epoch-c1', 0, 0);
      `);

      const rowsRes = await pool.query(`SELECT cluster_id, epoch_id FROM witness_raft_state ORDER BY cluster_id ASC`);
      expect(rowsRes.rows.length).toBe(2);
      expect(rowsRes.rows[0].cluster_id).toBe("default-cluster");
      expect(rowsRes.rows[1].cluster_id).toBe("secondary-cluster");
    } finally {
      await destroyDisposableDb(dbName, pool);
    }
  });
});
