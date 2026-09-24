package main

import (
	"database/sql"
	"os"
	"testing"
)

// TestLegacyLedgerIsRenamedNotShadowed covers the mitigation-check →
// defense-validation rename: a ledger written under the old table name must be
// carried over, not left behind an empty table of the new name. It runs against
// the same database as the other integration tests and is skipped without one.
func TestLegacyLedgerIsRenamedNotShadowed(t *testing.T) {
	dsn := os.Getenv("DV_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("DV_TEST_DATABASE_URL is not configured")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Registered before reset so it runs after it: cleanups are LIFO.
	t.Cleanup(func() { _ = db.Close() })

	// Start from a clean slate in both names, and leave one behind.
	reset := func() {
		for _, table := range []string{"defense_validation_run", "mitigation_check_run"} {
			if _, err := db.Exec(`DROP TABLE IF EXISTS ` + table + ` CASCADE`); err != nil {
				t.Fatalf("drop %s: %v", table, err)
			}
		}
	}
	reset()
	t.Cleanup(reset)

	if _, err := db.Exec(`
		CREATE TABLE mitigation_check_run (
			run_id TEXT PRIMARY KEY, result_id TEXT NOT NULL, terminal_state TEXT NOT NULL,
			match BOOLEAN NOT NULL, created_at TIMESTAMPTZ NOT NULL,
			request JSONB NOT NULL, response JSONB NOT NULL,
			request_id TEXT, status TEXT, callback_state TEXT,
			callback_next_at TIMESTAMPTZ, callback_url TEXT, lease_expires_at TIMESTAMPTZ,
			publication_pending BOOLEAN NOT NULL DEFAULT FALSE, result_payload BYTEA);
		CREATE UNIQUE INDEX mitigation_check_run_request_id_uq
			ON mitigation_check_run(request_id) WHERE request_id IS NOT NULL;
		CREATE INDEX mitigation_check_run_worker_idx
			ON mitigation_check_run(status, lease_expires_at, created_at);
		CREATE INDEX mitigation_check_run_callback_idx
			ON mitigation_check_run(callback_state, callback_next_at) WHERE callback_url IS NOT NULL;
		INSERT INTO mitigation_check_run (run_id, result_id, terminal_state, match, created_at,
			request, response, request_id, status, result_payload)
		VALUES ('mc-run-legacy','mitigation-check-result:aaa','blocked',true,now(),
			'{}'::jsonb,'{"prose_summary":"legacy row"}'::jsonb,'legacy-req','completed',
			'{"prose_summary":"legacy row"}'::bytea)`); err != nil {
		t.Fatalf("seed legacy ledger: %v", err)
	}

	t.Setenv("DATABASE_URL", dsn)
	store, err := NewRunStore()
	if err != nil {
		t.Fatalf("open store over legacy ledger: %v", err)
	}
	t.Cleanup(store.Close)

	// The legacy table is gone and its row survived under the new name.
	var legacyStillThere bool
	if err := db.QueryRow(
		`SELECT to_regclass('mitigation_check_run') IS NOT NULL`).Scan(&legacyStillThere); err != nil {
		t.Fatal(err)
	}
	if legacyStillThere {
		t.Error("mitigation_check_run should have been renamed away")
	}
	rec, ok := store.Get("mc-run-legacy")
	if !ok {
		t.Fatal("legacy run was not readable after migration — the ledger was shadowed, not renamed")
	}
	if rec.ResultID != "mitigation-check-result:aaa" || rec.TerminalState != "blocked" {
		t.Errorf("legacy row altered: result_id=%q terminal_state=%q", rec.ResultID, rec.TerminalState)
	}

	// The indexes came across under the new names, so the lifecycle migration's
	// CREATE INDEX IF NOT EXISTS statements did not add a second copy of each.
	for _, index := range []string{
		"defense_validation_run_request_id_uq",
		"defense_validation_run_worker_idx",
		"defense_validation_run_callback_idx",
	} {
		var present bool
		if err := db.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, index).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if !present {
			t.Errorf("index %s is missing after migration", index)
		}
	}
	var indexCount int
	if err := db.QueryRow(
		`SELECT count(*) FROM pg_indexes WHERE tablename='defense_validation_run'`).Scan(&indexCount); err != nil {
		t.Fatal(err)
	}
	if indexCount != 4 { // primary key + the three carried-over indexes
		t.Errorf("expected 4 indexes on defense_validation_run, found %d", indexCount)
	}

	// Running the migration again is a no-op rather than an error.
	second, err := NewRunStore()
	if err != nil {
		t.Fatalf("second open should be a no-op: %v", err)
	}
	second.Close()
}
