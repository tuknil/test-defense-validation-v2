package main

// rule_sink.go writes the resolved rule to its own Databricks table, so the rule
// is queryable on its own rather than only as a field inside a canonical result
// blob. This is the hand-off point for pushing the rule to a third-party control
// plane: that integration reads rows from here.
//
// Env (the DSN, catalog and schema are shared with the result sink):
//
//	DATABRICKS_DSN         token:<PAT>@<host>[:443]/sql/1.0/warehouses/<id>
//	DATABRICKS_CATALOG     e.g. 36889_janus_dev
//	DATABRICKS_SCHEMA      e.g. defense_validation
//	DATABRICKS_RULE_TABLE  e.g. defense_validation_rules (default)
//
// Table:
//
//	create table defense_validation_rules(
//	  run_id string, result_id string, candidate_id string,
//	  kind string, engine string, action string,
//	  rule string, rule_sha256 string, source string, created_at timestamp,
//	  constraint rule_pk primary key(result_id)) using delta
//
// The write is an insert-only idempotent MERGE keyed by result_id: a run that is
// retried under a new lease rewrites the same row rather than duplicating it, and
// an existing row is never mutated.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/databricks/databricks-sql-go"
)

// DatabricksRuleSink writes resolved rules. A nil sink is disabled and every
// method on it is a no-op, so callers need no configuration check of their own.
type DatabricksRuleSink struct {
	db      *sql.DB
	table   string // fully-qualified `catalog`.`schema`.`table`
	catalog string
	schema  string
	name    string
}

// NewDatabricksRuleSink returns nil (disabled) when DATABRICKS_DSN or
// DATABRICKS_CATALOG is unset, matching the result sink's rules.
func NewDatabricksRuleSink() *DatabricksRuleSink {
	dsn := strings.TrimSpace(os.Getenv("DATABRICKS_DSN"))
	if dsn == "" {
		log.Printf("databricks rule sink: disabled (DATABRICKS_DSN unset)")
		return nil
	}
	catalog := strings.TrimSpace(os.Getenv("DATABRICKS_CATALOG"))
	if catalog == "" {
		log.Printf("databricks rule sink: disabled (DATABRICKS_CATALOG is required)")
		return nil
	}
	db, err := sql.Open("databricks", normalizeDatabricksDSN(dsn))
	if err != nil {
		log.Printf("databricks rule sink: disabled (open failed: %v)", err)
		return nil
	}
	db.SetMaxOpenConns(4)

	schema := firstNonEmpty(strings.TrimSpace(os.Getenv("DATABRICKS_SCHEMA")), "defense_validation")
	name := firstNonEmpty(strings.TrimSpace(os.Getenv("DATABRICKS_RULE_TABLE")), "defense_validation_rules")
	qualified := backtick(catalog) + "." + backtick(schema) + "." + backtick(name)
	log.Printf("databricks rule sink: enabled -> %s", qualified)
	return &DatabricksRuleSink{db: db, table: qualified, catalog: catalog, schema: schema, name: name}
}

// RuleRef points at the row this sink writes for a result.
func (s *DatabricksRuleSink) RuleRef(resultID string) *ResultRef {
	if s == nil {
		return nil
	}
	return &ResultRef{System: "databricks", Catalog: s.catalog, Schema: s.schema, Table: s.name, Key: resultID}
}

// WriteRule persists the rule carried on a resolved outcome. It returns nil for a
// disabled sink and for an outcome with no rule, so a caller can treat any error
// as a real write failure.
func (s *DatabricksRuleSink) WriteRule(ctx context.Context, out RunOutcome) error {
	if s == nil || s.db == nil {
		return nil
	}
	if out.Candidate == nil || strings.TrimSpace(out.Candidate.Rule) == "" {
		return nil
	}
	cand := *out.Candidate
	sum := sha256.Sum256([]byte(cand.Rule))
	ruleSHA := "sha256:" + hex.EncodeToString(sum[:])

	created := out.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}

	writeCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if _, err := s.db.ExecContext(writeCtx, ruleMergeSQL(s.table),
		out.RunID, out.ResultID, cand.RuleID, cand.Kind, cand.Engine, cand.Action,
		cand.Rule, ruleSHA, out.Detail, created); err != nil {
		return fmt.Errorf("write rule to %s: %w", s.table, err)
	}
	log.Printf("databricks rule sink: WROTE %s (result_id=%s kind=%s engine=%s)",
		s.table, out.ResultID, cand.Kind, cand.Engine)
	return nil
}

// ruleMergeSQL is insert-only: an existing row for the result_id is left exactly
// as it was, so a rewritten rule can never overwrite what was already handed off.
func ruleMergeSQL(table string) string {
	return "MERGE INTO " + table + " AS target " +
		"USING (SELECT ? AS run_id, ? AS result_id, ? AS candidate_id, ? AS kind, ? AS engine, " +
		"? AS action, ? AS rule, ? AS rule_sha256, ? AS source, ? AS created_at) AS source " +
		"ON target.result_id = source.result_id " +
		"WHEN NOT MATCHED THEN INSERT (run_id, result_id, candidate_id, kind, engine, action, rule, rule_sha256, source, created_at) " +
		"VALUES (source.run_id, source.result_id, source.candidate_id, source.kind, source.engine, " +
		"source.action, source.rule, source.rule_sha256, source.source, source.created_at)"
}

func (s *DatabricksRuleSink) Close() {
	if s != nil && s.db != nil {
		_ = s.db.Close()
	}
}
