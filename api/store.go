package main

// store.go is the run ledger (LLD §11.1: defense_validation_run / _result), backed
// by a PostgreSQL database (run as its own container via docker compose). Data
// durability is a property of the db container's volume, not this process.
//
// The immutable request and parsed response projection are stored as JSONB.
// Async lifecycle rows additionally retain exact canonical result bytes in
// result_payload so recovery and authoritative publication never reserialize.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// RunRecord is one ledger entry: the immutable request and its executed result.
type RunRecord struct {
	RunID         string          `json:"run_id"`
	ResultID      string          `json:"result_id"`
	TerminalState string          `json:"terminal_state"`
	CreatedAt     time.Time       `json:"created_at"`
	Request       json.RawMessage `json:"request"` // exact submitted payload, immutable
	Response      RunOutcome      `json:"response"`
}

// RunSummary is the compact form shown in the left run panel.
type RunSummary struct {
	RunID         string    `json:"run_id"`
	ResultID      string    `json:"result_id"`
	TerminalState string    `json:"terminal_state"`
	CreatedAt     time.Time `json:"created_at"`
	Summary       string    `json:"summary"`
}

type RunStore struct {
	db *sql.DB
}

// NewRunStore opens Postgres (password or Entra ID, per DATABASE_AUTH_MODE),
// waits for it to accept connections, then ensures the schema exists — unless
// DATABASE_MIGRATION_MODE=external, in which case migrations are managed outside
// the app and the in-app schema creation is skipped.
func NewRunStore() (*RunStore, error) {
	db, err := openLedgerDB()
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetConnMaxLifetime(30 * time.Minute)

	var pingErr error
	for i := 0; i < 30; i++ {
		if pingErr = db.Ping(); pingErr == nil {
			break
		}
		log.Printf("ledger: waiting for postgres… (%v)", pingErr)
		time.Sleep(2 * time.Second)
	}
	if pingErr != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres not reachable: %w", pingErr)
	}

	if strings.EqualFold(strings.TrimSpace(os.Getenv("DATABASE_MIGRATION_MODE")), "external") {
		log.Printf("ledger: DATABASE_MIGRATION_MODE=external — skipping in-app schema migration")
	} else {
		// The capability was renamed from mitigation-check to defense-validation;
		// carry an existing ledger over before the create below would shadow it
		// with an empty table.
		if err := renameLegacyLedger(db); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("rename legacy ledger: %w", err)
		}
		// The capability no longer produces a verdict, so the match column has no
		// meaning. Drop it where an older ledger still carries it.
		if _, err := db.Exec(
			`ALTER TABLE IF EXISTS defense_validation_run DROP COLUMN IF EXISTS match`); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("drop verdict column: %w", err)
		}
		if _, err := db.Exec(`
			CREATE TABLE IF NOT EXISTS defense_validation_run (
				run_id         TEXT        PRIMARY KEY,
				result_id      TEXT        NOT NULL,
				terminal_state TEXT        NOT NULL,
				created_at     TIMESTAMPTZ NOT NULL,
				request        JSONB       NOT NULL,
				response       JSONB       NOT NULL
			)`); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("create schema: %w", err)
		}
		if err := migrateLifecycle(db); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("migrate lifecycle schema: %w", err)
		}
	}

	s := &RunStore{db: db}
	log.Printf("ledger: connected to postgres (%d run(s))", s.count())
	return s, nil
}

// renameLegacyLedger moves a pre-rename mitigation_check_run table, and its
// indexes, onto the defense_validation_run names. It is a no-op once the new
// names exist, so it is safe to run on every start. A database that already
// holds both tables is left alone: the old one is then stale, and picking a
// winner is an operator decision, not this process's.
func renameLegacyLedger(db *sql.DB) error {
	_, err := db.Exec(`
		DO $$
		BEGIN
			IF to_regclass('mitigation_check_run') IS NOT NULL
			   AND to_regclass('defense_validation_run') IS NULL THEN
				ALTER TABLE mitigation_check_run RENAME TO defense_validation_run;

				IF to_regclass('mitigation_check_run_request_id_uq') IS NOT NULL
				   AND to_regclass('defense_validation_run_request_id_uq') IS NULL THEN
					ALTER INDEX mitigation_check_run_request_id_uq
						RENAME TO defense_validation_run_request_id_uq;
				END IF;
				IF to_regclass('mitigation_check_run_worker_idx') IS NOT NULL
				   AND to_regclass('defense_validation_run_worker_idx') IS NULL THEN
					ALTER INDEX mitigation_check_run_worker_idx
						RENAME TO defense_validation_run_worker_idx;
				END IF;
				IF to_regclass('mitigation_check_run_callback_idx') IS NOT NULL
				   AND to_regclass('defense_validation_run_callback_idx') IS NULL THEN
					ALTER INDEX mitigation_check_run_callback_idx
						RENAME TO defense_validation_run_callback_idx;
				END IF;

				RAISE NOTICE 'ledger: renamed mitigation_check_run to defense_validation_run';
			END IF;
		END $$`)
	return err
}

func (s *RunStore) count() int {
	var n int
	_ = s.db.QueryRow(`SELECT count(*) FROM defense_validation_run`).Scan(&n)
	return n
}

// Close releases the connection pool. The database itself lives in the db
// container and its data persists on that container's volume.
func (s *RunStore) Close() {
	if s.db != nil {
		_ = s.db.Close()
	}
}

// Add durably records a run. request is stored as-is (JSONB); response is
// marshaled to JSONB.
func (s *RunStore) Add(r *RunRecord) error {
	resp, err := json.Marshal(r.Response)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO defense_validation_run
			(run_id, result_id, terminal_state, created_at, request, response)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		r.RunID, r.ResultID, r.TerminalState, r.CreatedAt,
		[]byte(r.Request), resp)
	return err
}

func (s *RunStore) Get(id string) (*RunRecord, bool) {
	var (
		rec      RunRecord
		request  []byte
		response []byte
	)
	err := s.db.QueryRow(`
		SELECT run_id, result_id, terminal_state, created_at, request, response
		FROM defense_validation_run WHERE run_id = $1`, id).
		Scan(&rec.RunID, &rec.ResultID, &rec.TerminalState,
			&rec.CreatedAt, &request, &response)
	if err != nil {
		return nil, false
	}
	rec.Request = json.RawMessage(request)
	if err := json.Unmarshal(response, &rec.Response); err != nil {
		return nil, false
	}
	return &rec, true
}

// List returns run summaries, newest first. The summary text is read from the
// response JSONB's prose_summary field.
func (s *RunStore) List() []RunSummary {
	rows, err := s.db.Query(`
		SELECT run_id, result_id, terminal_state, created_at,
		       COALESCE(response->>'prose_summary', '')
		FROM defense_validation_run
		ORDER BY created_at DESC`)
	if err != nil {
		log.Printf("ledger: list failed: %v", err)
		return nil
	}
	defer rows.Close()

	out := []RunSummary{}
	for rows.Next() {
		var s RunSummary
		if err := rows.Scan(&s.RunID, &s.ResultID, &s.TerminalState,
			&s.CreatedAt, &s.Summary); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out
}
