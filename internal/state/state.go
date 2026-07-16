package state

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ DB *sql.DB }

func Open(dataDir string) (*Store, error) {
	if e := os.MkdirAll(dataDir, 0700); e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite", filepath.Join(dataDir, "labdns.db"))
	if e != nil {
		return nil, e
	}
	s := &Store{DB: db}
	if _, e = db.Exec("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;"); e != nil {
		db.Close()
		return nil, e
	}
	if e = s.migrate(); e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) Close() error { return s.DB.Close() }
func (s *Store) migrate() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, event_type TEXT NOT NULL, actor TEXT NOT NULL, provider TEXT, record_name TEXT, record_type TEXT, previous_value TEXT, new_value TEXT, result TEXT NOT NULL, reason TEXT, transaction_id TEXT, metadata TEXT); CREATE TABLE IF NOT EXISTS transactions (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, completed_at TEXT, status TEXT NOT NULL, error TEXT); CREATE TABLE IF NOT EXISTS managed_records (provider_id TEXT NOT NULL, zone TEXT NOT NULL, name TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL, service_id TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(provider_id, zone, name, type));`)
	return e
}
func (s *Store) BeginTransaction(id string) error {
	_, e := s.DB.Exec("INSERT INTO transactions(id,started_at,status) VALUES(?,?,?)", id, time.Now().UTC().Format(time.RFC3339Nano), "running")
	return e
}
func (s *Store) FinishTransaction(id, status string, err error) error {
	var msg any
	if err != nil {
		msg = err.Error()
	}
	_, e := s.DB.Exec("UPDATE transactions SET completed_at=?,status=?,error=? WHERE id=?", time.Now().UTC().Format(time.RFC3339Nano), status, msg, id)
	return e
}
func (s *Store) IntegrityCheck() error {
	var out string
	if e := s.DB.QueryRow("PRAGMA integrity_check").Scan(&out); e != nil {
		return e
	}
	if out != "ok" {
		return fmt.Errorf("SQLite integrity check: %s", out)
	}
	return nil
}
func (s *Store) MarkManaged(provider, zone, name, typ, value, serviceID string) error {
	_, e := s.DB.Exec(`INSERT INTO managed_records(provider_id,zone,name,type,value,service_id,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(provider_id,zone,name,type) DO UPDATE SET value=excluded.value,service_id=excluded.service_id,updated_at=excluded.updated_at`, provider, zone, name, typ, value, serviceID, time.Now().UTC().Format(time.RFC3339Nano))
	return e
}
func (s *Store) RemoveManaged(provider, zone, name, typ string) error {
	_, e := s.DB.Exec("DELETE FROM managed_records WHERE provider_id=? AND zone=? AND name=? AND type=?", provider, zone, name, typ)
	return e
}
func (s *Store) ApplyOwnership(provider string, records []struct {
	Zone, Name, Type string
	RecordIndex      int
}) error {
	return nil
}
func (s *Store) IsManaged(provider, zone, name, typ string) (bool, error) {
	var n int
	e := s.DB.QueryRow("SELECT COUNT(1) FROM managed_records WHERE provider_id=? AND zone=? AND name=? AND type=?", provider, zone, name, typ).Scan(&n)
	return n > 0, e
}
